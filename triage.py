"""AI triage shared by pipeline.py and backfill.py: DB schema, grouping, verdict cache, Groq calls.

Groq free tier for openai/gpt-oss-120b allows 8,000 tokens per minute (prompt + requested
completion). A batch larger than that is rejected whole (HTTP 413), so batches are collapsed,
cached, split into chunks and paced to stay under it.
"""
import json, os, sqlite3, subprocess, time
from collections import deque
from datetime import datetime, timedelta
from dotenv import load_dotenv
from groq import Groq, APIStatusError, RateLimitError

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"), max_retries=0)  # retries are done here, see call()
MODEL = "openai/gpt-oss-120b"

CONTEXT = (
    "Environment: the local host is a Kali Linux security appliance (Raspberry Pi) on a home "
    "network or phone hotspot. It regularly runs apt updates from official Kali mirrors. "
    "It runs Tailscale (VPN), which every few minutes: sends STUN binding requests to Tailscale DERP "
    "relay servers worldwide and receives their responses; connects to DERP servers over TLS; and has "
    "its port mapper probe the default gateway with UPnP/SSDP (UDP 1900) and NAT-PMP/PCP (UDP 5351). "
    "Those patterns are expected between the local host and DERP servers or the default gateway; "
    "the same signatures between other hosts still deserve scrutiny."
)


def host_context():
    """CONTEXT plus the host's current addresses (hotspot IPs change), looked up locally at call time."""
    def run(*cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
        except (OSError, subprocess.SubprocessError):
            return ""
    ips = run("hostname", "-I").split()
    gw = [l.split()[2] for l in run("ip", "route", "show", "default").splitlines() if len(l.split()) > 2]
    return (CONTEXT + f" Local host IPs: {', '.join(ips) or 'unknown'}."
            f" Default gateway: {', '.join(gw) or 'unknown'}.")

MAX_ITEMS = 25               # alerts per Groq call
CHUNK_TOKENS = 3500          # estimated prompt tokens per call
MAX_COMPLETION = 2000        # reply budget; Groq counts it against the per-minute limit
TPM_BUDGET = 7000            # stay under Groq's 8,000 tokens/minute
MAX_RETRY_SECONDS = 90       # per flush; whatever is left stays 'AI unavailable' for backfill.py
CACHE_HOURS = 6
PREVIOUS_DAYS = 7          # how far back a 'previous_verdict' hint may come from
SAMPLE = 10                  # IPs listed for a collapsed group
UNTRIAGED = ("unknown", "unknown", "AI unavailable")


def backup(db, path, why):
    bak = f"{path}.bak-{datetime.now():%Y%m%d-%H%M%S}"
    b = sqlite3.connect(bak)
    db.backup(b)
    b.close()
    print(f"backed up {path} to {bak} {why}")


def open_db(path):
    db = sqlite3.connect(path, timeout=30)  # timeout: pipeline and backfill may write at the same time
    db.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        seen_at TEXT, sid INTEGER, signature TEXT, severity INTEGER,
        src_ip TEXT, dest_ip TEXT, count INTEGER,
        verdict TEXT, priority TEXT, reason TEXT,
        detection TEXT DEFAULT 'signature', score REAL,
        n_src INTEGER, n_dest INTEGER, group_key TEXT)""")
    db.commit()
    # No migrations: add columns introduced after the table was first created,
    # backing up the DB before changing its schema.
    cols = {r[1] for r in db.execute("PRAGMA table_info(alerts)")}
    new = (("detection", "TEXT DEFAULT 'signature'"), ("score", "REAL"),
           ("n_src", "INTEGER"), ("n_dest", "INTEGER"), ("group_key", "TEXT"))
    missing = [c for c in new if c[0] not in cols]
    if missing:
        backup(db, path, f"before adding columns {[c[0] for c in missing]}")
        for name, decl in missing:
            db.execute(f"ALTER TABLE alerts ADD COLUMN {name} {decl}")
        db.commit()
    db.execute("CREATE INDEX IF NOT EXISTS alerts_cache ON alerts (sid, group_key, seen_at)")
    db.commit()
    return db


def collapse(items):
    """Merge signature alerts with the same SID that share a source or a destination.

    Per SID, group by whichever side gives fewer groups: one host contacting 70 servers
    (shared source) or 70 servers answering one host (shared destination) becomes one item,
    with n_src/n_dest counting the hosts on the other side. Anomaly items pass through:
    they are already grouped per source.
    """
    out, by_sid = [], {}
    for it in items:
        if it["detection"] == "signature":
            by_sid.setdefault(it["sid"], []).append(it)
        else:
            out.append(it)
    for group in by_sid.values():
        srcs = {it["src_ip"] for it in group}
        dests = {it["dest_ip"] for it in group}
        side, other = ("src_ip", "dest_ip") if len(srcs) <= len(dests) else ("dest_ip", "src_ip")
        by_side = {}
        for it in group:
            by_side.setdefault(it[side], []).append(it)
        for members in by_side.values():
            rep = dict(members[0])  # first event is the representative, as in pipeline grouping
            others = list(dict.fromkeys(m[other] for m in members))
            rep["count"] = sum(m["count"] for m in members)
            rep["ids"] = [i for m in members for i in m.get("ids", [])]
            rep["n_src"] = len(others) if other == "src_ip" else 1
            rep["n_dest"] = len(others) if other == "dest_ip" else 1
            if len(others) > 1:
                rep[other + "s"] = others[:SAMPLE]
                rep["group_key"] = f"*->{rep['dest_ip']}" if side == "dest_ip" else f"{rep['src_ip']}->*"
            else:
                rep["group_key"] = f"{rep['src_ip']}->{rep['dest_ip']}"
            out.append(rep)
    return out


def cache_keys(it):
    """Group keys that count as 'the same host group' for an item: its own key, and for a single
    src->dst pair also the merged groups it belongs to (src->* and *->dst)."""
    keys = [it["group_key"]]
    if (it.get("n_src") or 1) == 1 and (it.get("n_dest") or 1) == 1:
        keys += [f"{it['src_ip']}->*", f"*->{it['dest_ip']}"]
    return keys


def last_verdict(db, it, since, until):
    """Most recent real AI verdict for this rule and host group between since and until.
    Rows served from the cache are never a source, so a verdict expires CACHE_HOURS after the
    AI last judged it; the exact group key is preferred over a merged one."""
    keys = cache_keys(it)
    return db.execute(
        "SELECT verdict, priority, reason FROM alerts WHERE detection = 'signature' AND sid = ? "
        f"AND group_key IN ({','.join('?' * len(keys))}) AND seen_at >= ? AND seen_at <= ? "
        "AND verdict != 'unknown' AND reason NOT LIKE '[cached]%' "
        "ORDER BY group_key = ? DESC, seen_at DESC LIMIT 1",
        (it["sid"], *keys, since, until, it["group_key"])).fetchone()


def cached(db, items, now):
    """Reuse verdicts for signature items the AI judged in the CACHE_HOURS before `now`.

    On a miss, the last verdict from the PREVIOUS_DAYS before that is attached as
    'previous_verdict', and the prompt asks the AI to keep it unless something changed, so
    verdicts stay consistent when the cache expires. Anomalies are never cached or hinted:
    their key is just a source IP, and a new scan must not inherit an old verdict.
    """
    t = datetime.fromisoformat(now)
    since = (t - timedelta(hours=CACHE_HOURS)).isoformat()
    hits = {}
    for it in items:
        if it["detection"] != "signature":
            continue
        row = last_verdict(db, it, since, now)
        if row:
            hits[it["n"]] = (row[0], row[1], "[cached] " + row[2])
            continue
        row = last_verdict(db, it, (t - timedelta(days=PREVIOUS_DAYS)).isoformat(), since)
        if row:
            it["previous_verdict"] = f"{row[0]} | {row[1]} | {row[2]}"
    return hits


def build_prompt(items):
    hidden = ("score", "ids", "group_key")
    return (
        "You are a SOC analyst triaging grouped Suricata alerts.\n" + host_context() + "\n"
        "Suricata severity: 1 = highest, 3 = lowest. 'count' = times seen in this window.\n"
        "When one alert fired across many hosts, n_src/n_dest is how many distinct sources/destinations "
        "were involved and src_ips/dest_ips is a sample of them.\n"
        "Items with detection 'anomaly' come from an Isolation Forest model, not a signature: "
        "these flows were statistically unusual for this host. Judge them by behaviour: "
        "src_flows, src_dest_ports and src_dest_ips are what the source did in the last 60s, "
        "src_unanswered is the fraction of those flows that got no real reply. "
        "Unusual is not necessarily malicious.\n"
        "previous_verdict, if present, is what was decided earlier for the same rule and hosts: "
        "keep it for consistency unless this alert's fields show something new, and if you change it "
        "say what changed.\n"
        "Use every field plus general knowledge of well-known domains and software. "
        "Do not invent facts.\n"
        "For EACH alert output exactly one line, nothing else:\n"
        "n | verdict (benign/suspicious/malicious) | priority (low/medium/high) | short reason\n"
        "where n is the alert's 'n' field. Each reason must make sense on its own (it may be "
        "reused for later alerts): never refer to other items ('as above', 'same as', item numbers).\n\n"
        + json.dumps([{k: v for k, v in it.items() if k not in hidden} for it in items])
    )


def estimate(text):
    return len(text) // 3  # rough: JSON with IPs and digits runs about 3 characters per token


def chunks(items):
    """Split items so each call stays under MAX_ITEMS and CHUNK_TOKENS."""
    out, cur = [], []
    for it in items:
        if cur and (len(cur) >= MAX_ITEMS or estimate(build_prompt(cur + [it])) > CHUNK_TOKENS):
            out.append(cur)
            cur = []
        cur.append(it)
    if cur:
        out.append(cur)
    return out


class GiveUp(Exception):
    pass


class TooLarge(Exception):
    pass


sent = deque()  # (time, estimated tokens) of calls in the last minute


def wait_budget(tokens, deadline):
    """Sleep until this call fits in TPM_BUDGET for the last 60 seconds."""
    while True:
        now = time.monotonic()
        while sent and now - sent[0][0] > 60:
            sent.popleft()
        if not sent or sum(t for _, t in sent) + tokens <= TPM_BUDGET:
            sent.append((now, tokens))
            return
        wait = 60 - (now - sent[0][0]) + 0.5
        if now + wait > deadline:
            raise GiveUp("token budget wait would pass the retry deadline")
        time.sleep(wait)


def log_limits(headers):
    """Groq's rate-limit headers: per Groq's docs 'requests' is the daily request limit (RPD)
    and 'tokens' is the per-minute token limit (TPM); there is no daily-token header."""
    h = {k: headers.get(f"x-ratelimit-{k}") for k in
         ("remaining-requests", "limit-requests", "reset-requests",
          "remaining-tokens", "limit-tokens", "reset-tokens")}
    print(f"groq limits: requests left today {h['remaining-requests']}/{h['limit-requests']} "
          f"(reset {h['reset-requests']}), tokens left this minute {h['remaining-tokens']}/{h['limit-tokens']} "
          f"(reset {h['reset-tokens']})")


def parse(text):
    results = {}
    for line in text.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 4 and parts[0].isdigit():
            results[int(parts[0])] = (parts[1].lower(), parts[2].lower(), parts[3])
    return results


def call(items, deadline):
    """One Groq call with retries: back off on 429, signal TooLarge on 413."""
    prompt = build_prompt(items)
    tokens = estimate(prompt) + MAX_COMPLETION
    for attempt in range(3):
        wait_budget(tokens, deadline)
        try:
            raw = client.chat.completions.with_raw_response.create(
                model=MODEL, messages=[{"role": "user", "content": prompt}],
                max_completion_tokens=MAX_COMPLETION, reasoning_effort="low", temperature=0)
            log_limits(raw.headers)
            r = raw.parse()
            if r.choices[0].finish_reason == "length":
                print("AI warning: reply cut off at max_completion_tokens; missing lines stay untriaged")
            return parse(r.choices[0].message.content or "")
        except RateLimitError as err:
            log_limits(err.response.headers)
            try:
                wait = float(err.response.headers.get("retry-after"))
            except (TypeError, ValueError):
                wait = 2 ** (attempt + 1)
            print(f"AI rate limited, retrying in {wait:.0f}s")
        except APIStatusError as err:
            if err.status_code == 413:
                raise TooLarge(str(err)) from err
            raise
        if time.monotonic() + wait > deadline:
            raise GiveUp("rate limited past the retry deadline")
        time.sleep(wait)
    raise GiveUp("rate limited 3 times")


def triage_all(items):
    """Triage items in paced chunks. Returns {n: (verdict, priority, reason)}; items missing
    from the result could not be triaged and should be stored as UNTRIAGED."""
    results = {}
    deadline = time.monotonic() + MAX_RETRY_SECONDS
    todo = deque(chunks(items))
    while todo:
        c = todo.popleft()
        try:
            results.update(call(c, deadline))
        except TooLarge as err:
            if len(c) == 1:
                print("AI error: single alert too large:", err)
                continue
            half = len(c) // 2
            todo.extendleft([c[half:], c[:half]])  # extendleft reverses, so first half goes first
        except GiveUp as err:
            print(f"AI error: giving up on {sum(map(len, todo)) + len(c)} alerts: {err}")
            break
        except Exception as err:
            print("AI error:", err)
    return results
