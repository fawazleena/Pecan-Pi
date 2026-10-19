"""Pecan Pi control panel: a small Flask app for a non-technical owner, served over HTTPS.

Reads pecan.db read-only and runs as the normal user. Anything that needs root goes through
the root-owned pecan-helper (one sudoers line, fixed subcommands, argv only, never a shell).

    .venv/bin/python panel.py set-password     # store the admin password hash + secret key in .env
    .venv/bin/python panel.py make-cert        # self-signed TLS cert -> panel/tls/ (gitignored)
    .venv/bin/python panel.py serve [--host IP] [--port 8443]   # default host: the Pi's tailscale0 IP

On the Pi it runs as pecan-panel.service (gunicorn, --host 0.0.0.0): systemd's
RestrictNetworkInterfaces then decides by interface that only lo, wlan0 and tailscale0 reach it.
"""
import argparse, getpass, json, os, re, secrets, shutil, sqlite3, subprocess, sys, threading, time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from netinfo import iface_ips, load_settings, load_ip_list

HERE = Path(__file__).parent
ENV = HERE / ".env"
DB = HERE / "pecan.db"
MODEL = Path("/opt/pecan/anomaly_model.joblib")   # pipeline.py's ANOMALY_MODEL (the installed copy)
EVE = "/var/log/suricata/eve.json"
TLS = HERE / "panel" / "tls"
HELPER = "/usr/local/sbin/pecan-helper"   # installed copy of pecan-helper.py, root:root 0755
SERVICES = ("suricata", "pecan-pipeline", "pecan-honeypot")
PORT = 8443
IDLE_MINUTES = 30          # logged out after this long without a page load or change (polling doesn't count)
MAX_FAILS, FAIL_WINDOW = 5, 15 * 60   # login attempts per client IP per 15 min
FEED_ROWS = 15            # rows in the first /api/feed answer and per "Show older"
FEED_MAX = 200            # most new rows one live-feed answer carries; more -> the page starts over
STATS_TAIL = 512 * 1024    # bytes of eve.json searched for the latest stats event
DROPS_WINDOW = 10 * 60     # kernel_drops rising within this many seconds -> yellow

PLAIN_VERDICT = {"malicious": "Threat", "suspicious": "Worth a look", "benign": "Normal", "unknown": "Not reviewed yet"}
PLAIN_DETECTION = {"signature": "Rule match", "anomaly": "Unusual behaviour",
                   "honeypot": "Someone tried the trap door", "recon": "Security check result"}
NORMAL_VERDICTS = ("benign", "normal")   # hidden in Simple mode
# Also hidden in Simple mode, as one "not yet explained" line: 'unknown' covers every row without
# an AI verdict (AI unavailable, AI explanations off, unparsed answers).
UNEXPLAINED = "unknown"
# IT-mode feed filters: fixed words only, mapped to SQL here (benign covers the old 'normal').
VERDICT_FILTERS = {"malicious": ("malicious",), "suspicious": ("suspicious",),
                   "benign": NORMAL_VERDICTS, "unknown": (UNEXPLAINED,)}
# Rows where the firewall acted (honeypot.block() results) are always shown: the block stands
# whatever the AI says, or whether it said anything. COALESCE: a NULL action must count as "no".
FIREWALL_ACTED = "COALESCE(action LIKE 'blocked %' OR action = 'already blocked' OR action LIKE 'block failed%', 0)"
SWITCH_LABELS = {"signatures": "Watch for known attacks", "anomaly": "Spot unusual behaviour",
                 "auto_block": "Block intruders automatically", "ai": "Explain alerts in plain English"}
OFF_NOTES = {"signatures": "Off: alerts for known attacks are ignored. The network is still watched for unusual behaviour.",
             "anomaly": "Off: unusual behaviour is not checked.",
             "auto_block": "Off: visits to the trap door are recorded, but nobody is blocked. Existing blocks run out on their own.",
             "ai": "Off: alerts are stored without an explanation and nothing is sent to the AI service."}
CACHE_PREFIXES = ("[cached] ", "[backfill] ", "[retriage] ")
# Rule groups the owner may switch off (pecan-helper.CATEGORIES has the matching rule patterns).
RULE_CATEGORIES = {
    "info": ("Informational", "Normal but notable activity (updates, lookups). Most alerts come from here; "
             "a few useful ones too, such as program downloads."),
    "hunting": ("Broad searches", "Wide nets that catch a lot of harmless traffic."),
    "adware": ("Adware and unwanted programs", ""),
    "tor": ("Tor anonymity network", "Connections to or from Tor."),
    "p2p": ("Peer-to-peer file sharing", "BitTorrent and similar."),
    "chat": ("Chat apps", ""),
    "games": ("Online games", "")}
DISABLE_CONF = "/etc/suricata/disable.conf"             # written by pecan-helper rules-category
CUSTOM_RULES = "/var/lib/suricata/rules/pecan-custom.rules"   # written by pecan-helper custom-add/remove
RULE_TIMEOUT = 900   # suricata-update + suricata -T + reload take a minute or two on the Pi
STEP_WORDS = {"rebuilding": "Rebuilding rules", "testing": "Testing", "reloading": "Reloading"}
# Validation messages from pecan-helper start with the field they are about -> the form box.
FIELD_PREFIXES = {"protocol:": "proto", "from:": "src", "to:": "dst", "port:": "port", "name:": "name", "text:": "text"}
ONE_AT_A_TIME = "One change at a time. Please wait."
# pecan-helper's messages are technical; Simple mode shows the first matching plain sentence
# (IT mode shows the helper's own text). Order matters: more specific patterns first.
PLAIN_ERRORS = [
    ("another rule change is still running", "Another change is still being applied. Try again in a minute."),
    ("which is protected", "That address includes the admin's computer, which must always be able to reach the Pi."),
    ("which is on the trusted list", "That address is on the Trusted list. Remove it there first."),
    ("the Pi itself or its gateway", "That would cut the Pi off from its own network."),
    ("on the blocked list", "That address is on the Always blocked list. Unblock it there first."),
    ("already on the list", "That address is already on the list."),
    ("too wide", "That range of addresses is too big. Use one address or a smaller range."),
    ("not an IP address", "That doesn't look like an address. Use something like 192.168.1.20."),
    ("can't be listed", "That address can't be added."),
    ("list is full", "The list is full. Remove an entry first."),
    ("is not on the", "That entry is already gone. The list has been refreshed."),
    ("is not blocked right now", "That address isn't blocked any more."),
    ("note:", "The name is too long or has unusual characters. Use up to 40 letters and numbers."),
    ("protocol:", "Choose a protocol."),
    ("port:", "The port must be a number from 1 to 65535, and only works with TCP or UDP. Leave it empty for any."),
    ("name:", "The name needs 3 to 60 letters or numbers."),
    ("text:", "The text to look for can be at most 64 plain characters."),
    ("at most 100 custom rules", "You have the most rules allowed (100). Remove one first."),
    ("no custom rule with SID", "That rule doesn't exist any more. The list has been refreshed."),
    ("isn't set up for custom rules", "Custom rules aren't set up on this Pi yet."),
    ("nothing changed", "The Pi couldn't apply this change, so nothing was changed."),
    ("previous rules kept", "The Pi couldn't apply this change, so nothing was changed."),
    ("password is required", "The Pi isn't set up to make changes from the panel yet."),
    ("must run as root", "The Pi isn't set up to make changes from the panel yet."),
]
EDITABLE_LISTS = ("allow", "deny")   # protected.txt is installed by hand and shown locked

load_dotenv(ENV)
app = Flask(__name__, template_folder="panel/templates", static_folder="panel/static")
app.config.update(
    SECRET_KEY=os.environ.get("PANEL_SECRET_KEY"),
    SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_NAME="pecan_session", WTF_CSRF_TIME_LIMIT=None,  # token lives as long as the session
    MAX_CONTENT_LENGTH=64 * 1024)
csrf = CSRFProtect(app)

fails, fails_lock = {}, threading.Lock()   # client IP -> recent failure timestamps (in memory, reset on restart)
drops = {"last": None, "rose_at": 0}        # kernel_drops seen at the previous status check


# --- auth -------------------------------------------------------------------------------------
def locked_out(ip):
    with fails_lock:
        recent = [t for t in fails.get(ip, []) if time.time() - t < FAIL_WINDOW]
        fails[ip] = recent
        return len(recent) >= MAX_FAILS


def record_fail(ip):
    with fails_lock:
        fails.setdefault(ip, []).append(time.time())


@app.before_request
def require_login():
    if request.endpoint in ("login", "static", "favicon"):
        return
    seen = session.get("seen", 0)
    if not session.get("admin") or time.time() - seen > IDLE_MINUTES * 60:
        # Clear only an expired admin session. Clearing a not-yet-logged-in one would drop the
        # CSRF token of the login form already on screen (the browser's own /favicon.ico request
        # did exactly that: "CSRF tokens do not match").
        if session.get("admin"):
            session.clear()
        if request.path.startswith("/api/"):
            abort(401)
        return redirect(url_for("login"))
    if not request.path.startswith("/api/") or request.method != "GET":
        session["seen"] = time.time()


@app.after_request
def headers(resp):
    # No inline scripts/styles and nothing from other sites: an injected string can't run as code.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "same-origin"  # Flask-WTF checks Referer on HTTPS POSTs
    resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        ip = request.remote_addr
        if locked_out(ip):
            error = "Too many attempts. Wait 15 minutes and try again."
        elif check_password_hash(os.environ["PANEL_PASSWORD_HASH"], request.form.get("password", "")[:256]):
            session.clear()
            session.update(admin=True, seen=time.time())
            print(f"login ok from {ip}")
            return redirect(url_for("home"))
        else:
            record_fail(ip)
            print(f"login failed from {ip}")
            error = "Wrong password."
    return render_template("login.html", error=error), 200 if not error else 401


@app.get("/favicon.ico")
def favicon():
    return redirect(url_for("static", filename="favicon.svg"))


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --- status -----------------------------------------------------------------------------------
def service_states():
    out = subprocess.run(["systemctl", "is-active", *SERVICES], capture_output=True, text=True).stdout.split()
    return {s: (out[i] if i < len(out) else "unknown") for i, s in enumerate(SERVICES)}


def latest_stats():
    """The newest stats event near the end of eve.json, or {}."""
    try:
        with open(EVE, "rb") as f:
            f.seek(max(0, os.fstat(f.fileno()).st_size - STATS_TAIL))
            lines = f.read().decode(errors="replace").splitlines()
    except OSError:
        return {}
    for line in reversed(lines):
        if '"event_type":"stats"' in line:
            try:
                return json.loads(line)["stats"]
            except (ValueError, KeyError):
                continue
    return {}


def kernel_drops():
    """capture.kernel_drops from the newest stats event, or None."""
    return latest_stats().get("capture", {}).get("kernel_drops")


def query(sql, args=()):
    db = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)  # written by the root pipeline; we only read
    try:
        return db.execute(sql, args).fetchall()
    finally:
        db.close()


def plain_reason(reason):
    reason = reason or ""
    for p in CACHE_PREFIXES:
        if reason.startswith(p):
            reason = reason[len(p):]
    return reason[:1].upper() + reason[1:]


def plain_kind(detection, verdict):
    # A rule firing is not an attack by itself: say "attack" only once the AI judged it one.
    if detection == "signature" and verdict in ("suspicious", "malicious"):
        return "Known attack pattern"
    return PLAIN_DETECTION.get(detection, detection)


def switches():
    """The real state of each main switch, from /etc/pecan/settings.json."""
    settings, error = load_settings()
    out = [{"name": k, "label": SWITCH_LABELS[k], "on": settings[k], "available": True,
            "note": "" if settings[k] else OFF_NOTES[k]} for k in SWITCH_LABELS]
    if not MODEL.exists():   # the pipeline can't score without a model, whatever the setting says
        out[1].update(on=False, available=False,
                      note="Not available yet: still learning what normal looks like on this network.")
    return out, error


FEED_COLS = ("id, seen_at, detection, verdict, priority, signature, sid, severity, src_ip, dest_ip, count, "
             "score, reason, action, n_src, n_dest, group_key")


def feed_item(r):
    return {"id": r[0], "time": local_time(r[1]), "detection": r[2], "kind": plain_kind(r[2], r[3]),
            "verdict": r[3], "plain_verdict": PLAIN_VERDICT.get(r[3], r[3]), "priority": r[4],
            "signature": r[5], "sid": r[6], "severity": r[7], "src": r[8], "dst": r[9], "count": r[10],
            "score": r[11], "reason": plain_reason(r[12]), "raw_reason": r[12], "action": r[13],
            "n_src": r[14], "n_dest": r[15], "group_key": r[16]}


def feed(view, after=None, before=None, detection=None, verdict=None, search=None):
    """Feed rows, newest first. after: only rows newer than that id (the live poll); before: older
    rows ("Show older"); neither: the newest page. 'cursor' is the newest id in the table when
    this ran, so the next poll asks for rows after it even if the filters matched none."""
    where, args = [], []
    if view == "simple":   # what Simple mode hides is counted by status() instead
        normal = ",".join("?" * len(NORMAL_VERDICTS))
        where.append(f"(verdict NOT IN ({normal}, ?) OR {FIREWALL_ACTED})")
        args += [*NORMAL_VERDICTS, UNEXPLAINED]
    else:
        if detection:
            where.append("detection = ?")
            args.append(detection)
        if verdict:
            where.append(f"verdict IN ({','.join('?' * len(VERDICT_FILTERS[verdict]))})")
            args += VERDICT_FILTERS[verdict]
        if search:   # a literal substring: LIKE's own wildcards are escaped
            like = "%" + re.sub(r"([\\%_])", r"\\\1", search) + "%"
            where.append("(signature LIKE ? ESCAPE '\\' OR src_ip LIKE ? ESCAPE '\\' OR dest_ip LIKE ? ESCAPE '\\' "
                         "OR reason LIKE ? ESCAPE '\\' OR CAST(sid AS TEXT) = ?)")
            args += [like] * 4 + [search]
    (cursor,), = query("SELECT COALESCE(MAX(id), 0) FROM alerts")
    if after is not None:
        where.append("id > ? AND id <= ?")
        args += [after, cursor]
    if before is not None:
        where.append("id < ?")
        args.append(before)
    limit = FEED_MAX if after is not None else FEED_ROWS
    rows = query(f"SELECT {FEED_COLS} FROM alerts {'WHERE ' + ' AND '.join(where) if where else ''} "
                 f"ORDER BY id DESC LIMIT ?", (*args, limit + 1))
    # One row more than asked tells whether there is more: older rows, or a gap in the live feed.
    return {"rows": [feed_item(r) for r in rows[:limit]], "more": len(rows) > limit, "cursor": cursor}


def status():
    now = datetime.now(timezone.utc)
    hour, day = (now - timedelta(hours=1)).isoformat(), (now - timedelta(days=1)).isoformat()
    states = service_states()
    d = kernel_drops()
    if drops["last"] is not None and d is not None and d > drops["last"]:
        drops["rose_at"] = time.time()
    drops["last"] = d
    problems = []  # (level, plain-English sentence)
    try:
        (threats,), = query("SELECT COUNT(*) FROM alerts WHERE seen_at >= ? AND verdict='malicious' AND priority='high'", (hour,))
        (worth,), = query("SELECT COUNT(*) FROM alerts WHERE seen_at >= ? AND (verdict='suspicious' OR priority='medium')", (day,))
        normal = ",".join("?" * len(NORMAL_VERDICTS))
        (last_block,), = query(f"SELECT COALESCE(MAX(id), 0) FROM alerts WHERE action LIKE 'blocked %'")
        (hidden,), = query(f"SELECT COUNT(*) FROM alerts WHERE seen_at >= ? AND verdict IN ({normal}) "
                           f"AND NOT {FIREWALL_ACTED}",
                           (hour, *NORMAL_VERDICTS))
        (unexplained,), = query(f"SELECT COUNT(*) FROM alerts WHERE seen_at >= ? AND verdict = ? "
                                f"AND NOT {FIREWALL_ACTED}", (hour, UNEXPLAINED))
    except sqlite3.Error as err:
        threats = worth = hidden = unexplained = last_block = 0
        problems.append(("red", f"Can't read the alert database ({err})."))
    sw, settings_error = switches()
    if settings_error:
        problems.append(("yellow", "The protection settings file can't be read, so everything is left on."))
    if states["suricata"] != "active":
        problems.append(("red", "Network monitoring is stopped."))
    if states["pecan-pipeline"] != "active":
        problems.append(("red", "Alert processing is stopped."))
    if threats:
        problems.append(("red", f"{threats} serious threat{'s' * (threats > 1)} in the last hour."))
    on = {w["name"]: w["on"] for w in sw}
    if not on["signatures"]:
        problems.append(("yellow", "Watching for known attacks is switched off."))
    if not on["auto_block"]:
        problems.append(("yellow", "Automatic blocking is switched off."))
    if states["pecan-honeypot"] != "active":
        problems.append(("yellow", "The trap door (automatic blocking) is stopped."))
    if time.time() - drops["rose_at"] < DROPS_WINDOW:
        problems.append(("yellow", "The Pi was too busy to inspect some traffic in the last 10 minutes."))
    if worth:
        problems.append(("yellow", f"{worth} thing{'s' * (worth > 1)} worth a look in the last 24 hours."))
    level = "red" if any(l == "red" for l, _ in problems) else "yellow" if problems else "green"
    headline = {"green": "All good. Your network is protected.",
                "yellow": "Protected, but something needs a look.",
                "red": "Action needed."}[level]
    return {"level": level, "headline": headline, "problems": [p for _, p in problems],
            "services": states, "kernel_drops": d, "switches": sw, "settings_error": settings_error,
            "last_block": last_block, "hidden_last_hour": hidden, "unexplained_last_hour": unexplained}


def local_time(iso):
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%d %b %H:%M:%S")
    except (TypeError, ValueError):
        return str(iso)


@app.get("/")
def home():
    return render_template("home.html", s=status())


@app.get("/api/status")
def api_status():
    return jsonify(status())


@app.get("/api/feed")
def api_feed():
    a = request.args
    view, detection, verdict = a.get("view", "simple"), a.get("detection") or None, a.get("verdict") or None
    search = (a.get("q") or "").strip() or None
    after, before = a.get("after", type=int), a.get("before", type=int)
    if (view not in ("simple", "it") or (detection and detection not in PLAIN_DETECTION)
            or (verdict and verdict not in VERDICT_FILTERS) or (search and len(search) > 64)):
        abort(400)
    try:
        return jsonify(feed(view, after, before, detection, verdict, search))
    except sqlite3.Error as err:
        return jsonify(error=f"Can't read the alert database ({err})."), 503


# --- IT mode: system figures ------------------------------------------------------------------
def size(n):
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024


def system_info():
    """(group, label, value) rows for the IT-mode System card. Every figure is read without root;
    one that can't be read is shown as 'n/a' rather than failing the card."""
    rows = []
    st = latest_stats()
    cap = st.get("capture", {})
    pkts, dropped = cap.get("kernel_packets"), cap.get("kernel_drops")
    rows += [("Suricata", "uptime", f"{st['uptime'] // 3600}h {st['uptime'] % 3600 // 60}m" if "uptime" in st else "n/a"),
             ("Suricata", "packets", f"{pkts:,}" if pkts is not None else "n/a"),
             ("Suricata", "kernel_drops", f"{dropped:,}" + (f" ({100 * dropped / pkts:.2f}%)" if pkts else "")
              if dropped is not None else "n/a"),
             ("Suricata", "flows active", str(st.get("flow", {}).get("active", "n/a")))]
    pid = subprocess.run(["systemctl", "show", "suricata", "-p", "MainPID", "--value"],
                         capture_output=True, text=True).stdout.strip()
    rss = re.search(r"VmRSS:\s+(\d+) kB", read_file(f"/proc/{pid}/status")) if pid not in ("", "0") else None
    rows.append(("Suricata", "memory (RSS)", size(int(rss.group(1)) * 1024) if rss else "n/a"))
    try:
        rows.append(("Suricata", "eve.json", size(os.stat(EVE).st_size)))
    except OSError:
        rows.append(("Suricata", "eve.json", "n/a"))
    mem = dict(re.findall(r"^(\w+):\s+(\d+) kB", read_file("/proc/meminfo"), re.M))
    temp = read_file("/sys/class/thermal/thermal_zone0/temp").strip()
    disk = shutil.disk_usage("/")
    rows += [("Pi", "load (1/5/15 min)", " ".join(read_file("/proc/loadavg").split()[:3]) or "n/a"),
             ("Pi", "CPU temperature", f"{int(temp) / 1000:.1f} °C" if temp.isdigit() else "n/a"),
             ("Pi", "memory available", f"{size(int(mem['MemAvailable']) * 1024)} of {size(int(mem['MemTotal']) * 1024)}"
              if "MemAvailable" in mem else "n/a"),
             ("Pi", "disk free", f"{size(disk.free)} of {size(disk.total)}")]
    try:
        hour = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
        (total, last_hour, newest), = query("SELECT COUNT(*), SUM(seen_at >= ?), MAX(seen_at) FROM alerts", (hour,))
        rows += [("Pipeline", "alert rows", f"{total:,} ({last_hour or 0} in the last hour)"),
                 ("Pipeline", "newest row", local_time(newest) if newest else "none")]
    except sqlite3.Error:
        rows.append(("Pipeline", "alert rows", "n/a"))
    # The pipeline logs Groq's rate-limit headers on every call (needs journal access: group adm).
    line = subprocess.run(["journalctl", "-u", "pecan-pipeline", "--since", "-24h", "--grep", "groq limits",
                           "-n", "1", "-o", "short-iso", "--no-pager", "-q"], capture_output=True, text=True).stdout.strip()
    rows.append(("Pipeline", "Groq limits", f"{line.split('groq limits: ', 1)[-1]} (at {local_time(line.split()[0])})"
                 if "groq limits: " in line else "no call in the last 24 h"))
    return rows


@app.get("/api/system")
def api_system():
    return jsonify(rows=system_info())


# --- switches -------------------------------------------------------------------------------
def helper(*args):
    """Run one fixed pecan-helper subcommand as root. (ok, message). -n: never prompt for a password."""
    try:
        r = subprocess.run(["sudo", "-n", HELPER, *args], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired) as err:
        return False, str(err)
    return r.returncode == 0, (r.stdout if r.returncode == 0 else r.stderr or r.stdout).strip()


def plain_error(msg):
    for needle, plain in PLAIN_ERRORS:
        if needle in msg:
            return plain
    return "The Pi couldn't make this change. Switch to IT view for details."


def helper_error(msg, status=400, field=None):
    """Error response: a plain sentence for Simple mode, the helper's own text for IT mode, and
    the form box it is about (if any)."""
    return jsonify(error=plain_error(msg), detail=msg[:300], field=field), status


@app.post("/api/switch")
def api_switch():
    body = request.get_json(silent=True) or {}
    name, on = body.get("name"), body.get("on")
    if name not in SWITCH_LABELS or not isinstance(on, bool):   # only the four fixed names reach argv
        abort(400)
    if name == "anomaly" and not MODEL.exists():
        return jsonify(error="Not available yet: there is no trained model."), 409
    ok, msg = helper("set-switch", name, "on" if on else "off")
    print(f"switch {name}={'on' if on else 'off'} from {request.remote_addr}: {'ok' if ok else msg}")
    if not ok:
        return helper_error(msg, 500)
    return jsonify(switches=switches()[0])


# --- IP lists -------------------------------------------------------------------------------
def entries(name):
    # Single addresses without /32 or /128, as pecan-helper writes them.
    return [{"net": str(n.network_address) if n.prefixlen == n.max_prefixlen else str(n), "note": note}
            for n, note in load_ip_list(name)]


@app.get("/api/lists")
def api_lists():
    """The three lists (files are world-readable) and the honeypot's current timed blocks (root:
    asked from the helper, so only on page load and after a change, never in the 5 s poll)."""
    ok, out = helper("list-blocks")
    try:
        blocks = json.loads(out) if ok else None
    except ValueError:
        blocks = None
    return jsonify(allow=entries("allow"), deny=entries("deny"), protected=entries("protected"),
                   blocks=blocks["blocks"] if blocks else [], enforced=blocks["enforced"] if blocks else None,
                   blocks_error=None if blocks else "Couldn't ask the Pi who is blocked right now.",
                   blocks_detail=None if blocks else out[:200])


@app.post("/api/lists")
def api_lists_change():
    body = request.get_json(silent=True) or {}
    name, action, net, note = body.get("list"), body.get("action"), body.get("net"), body.get("note", "")
    # Only fixed words and short strings reach argv; pecan-helper validates the address and note again.
    if (name not in EDITABLE_LISTS or action not in ("add", "remove") or not isinstance(net, str)
            or not isinstance(note, str) or not net.strip() or len(net) > 64 or len(note) > 64):
        abort(400)
    args = [f"list-{action}", name, net.strip()] + ([note.strip()] if action == "add" and note.strip() else [])
    ok, msg = helper(*args)
    print(f"list {action} {name} {net.strip()!r} from {request.remote_addr}: {'ok' if ok else msg}")
    if not ok:
        # Everything but a full list is about what was typed: the note box or the address box.
        field = "note" if msg.startswith("note:") else None if "list is full" in msg else "net"
        return helper_error(msg, field=field if action == "add" else None)
    try:
        applied = json.loads(msg).get("applied", "")
    except ValueError:
        applied = ""
    return jsonify(ok=True, applied=applied)


@app.post("/api/unblock")
def api_unblock():
    ip = (request.get_json(silent=True) or {}).get("ip")
    if not isinstance(ip, str) or not ip or len(ip) > 64:
        abort(400)
    ok, msg = helper("unblock", ip)
    print(f"unblock {ip!r} from {request.remote_addr}: {'ok' if ok else msg}")
    if not ok:
        return helper_error(msg)
    return jsonify(ok=True)


# --- Suricata rules -------------------------------------------------------------------------
# A rule change takes up to a couple of minutes, so it runs as a background job: the POST returns
# a job id at once, the page polls /api/jobs/<id> for the current step, and only one job runs at
# a time (pecan-helper's own lock enforces that too). Jobs live in memory only.
jobs, jobs_lock = {}, threading.Lock()


def running_job():
    return next((j for j in jobs.values() if j["state"] == "running"), None)


def job_view(job):
    end = job.get("ended") or time.time()
    return {k: v for k, v in job.items() if k not in ("started", "ended")} | {"elapsed": int(end - job["started"])}


def start_job(target, args):
    """Job id, or None while another job runs."""
    with jobs_lock:
        if running_job():
            return None
        for old in sorted(jobs, key=lambda k: jobs[k]["started"])[:-20]:   # keep the last 20
            del jobs[old]
        jid = secrets.token_hex(8)
        jobs[jid] = {"id": jid, "target": target, "state": "running", "step": "Starting",
                     "started": time.time(), "summary": "", "error": "", "detail": "", "field": None}
    threading.Thread(target=run_job, args=(jid, args), daemon=True).start()
    return jid


def run_job(jid, args):
    job = jobs[jid]
    result, err = "", ""
    try:
        # Own session: Ctrl-C or a panel restart must not kill the helper halfway through a change
        # (it finishes, or rolls back, on its own).
        p = subprocess.Popen(["sudo", "-n", HELPER, *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             text=True, start_new_session=True)
        killer = threading.Timer(RULE_TIMEOUT, p.kill)
        killer.start()
        for line in p.stdout:   # "step: NAME" lines, then one JSON line
            if line.startswith("step: "):
                job["step"] = STEP_WORDS.get(line[6:].strip(), line[6:].strip())
            elif line.strip():
                result = line
        err = p.stderr.read().strip()
        p.wait()
        killer.cancel()
        ok = p.returncode == 0
    except OSError as e:
        ok, err = False, str(e)
    if ok:
        try:
            summary = json.loads(result).get("summary", "")
        except ValueError:
            summary = ""
        job.update(state="done", step="Done", summary=summary)
    else:
        err = err or "the change timed out"
        field = next((f for prefix, f in FIELD_PREFIXES.items() if err.startswith(prefix)), None)
        job.update(state="failed", step="Failed", error=plain_error(err), detail=err[:300], field=field)
    job["ended"] = time.time()
    print(f"job {' '.join(args)!r}: {job['state']} {job['summary'] or job['detail']}")


@app.get("/api/jobs/<jid>")
def api_job(jid):
    job = jobs.get(jid)
    if not job:
        abort(404)
    return jsonify(job_view(job))


def job_response(target, args):
    jid = start_job(target, args)
    print(f"rules {' '.join(args)!r} from {request.remote_addr}: {'started ' + jid if jid else 'busy'}")
    if not jid:
        return jsonify(error=ONE_AT_A_TIME), 409
    return jsonify(job=job_view(jobs[jid])), 202


def read_file(path):
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


ADDR_WORDS = {"any": "any", "$HOME_NET": "home", "$EXTERNAL_NET": "outside"}
CUSTOM_RE = re.compile(r'^(# )?alert (\S+) (\S+) any -> (\S+) (\S+) \(msg:"PECAN CUSTOM ([^"]*)"; '
                       r'(?:content:"([^"]*)"; nocase; )?sid:(\d+); rev:(\d+);\)$')


def parse_custom(line):
    """One pecan-helper custom rule -> its form fields and a plain summary, or None."""
    m = CUSTOM_RE.match(line)
    if not m:
        return None
    off, proto, src, dst, port, name, content, sid, rev = m.groups()
    src, dst = ADDR_WORDS.get(src, src), ADDR_WORDS.get(dst, dst)
    text = re.sub(r"\|([0-9A-Fa-f]{2})\|", lambda h: chr(int(h.group(1), 16)), content or "")
    summary = (f"{'Any protocol' if proto == 'ip' else proto.upper()} from {src} to {dst}"
               + (f" port {port}" if port != "any" else "") + (f' containing "{text}"' if content else ""))
    return {"sid": int(sid), "rev": int(rev), "on": not off, "name": name, "proto": proto, "src": src,
            "dst": dst, "port": port, "text": text, "summary": summary, "rule": line}


def rules_state():
    """Category switches and custom rules from the helper-written files (world-readable), plus
    what the running Suricata last loaded (eve.json stats)."""
    off = {l.split(":", 1)[1].strip() for l in read_file(DISABLE_CONF).splitlines() if l.startswith("# pecan-category:")}
    custom = [r for r in map(parse_custom, read_file(CUSTOM_RULES).splitlines()) if r]
    engine = (latest_stats().get("detect", {}).get("engines") or [{}])[0]
    job = running_job()
    return {"job": job_view(job) if job else None, "categories": [{"name": k, "label": l, "note": n, "on": k not in off} for k, (l, n) in RULE_CATEGORIES.items()],
            "custom": custom, "rules_loaded": engine.get("rules_loaded"), "rules_failed": engine.get("rules_failed"),
            "last_reload": local_time(engine["last_reload"]) if engine.get("last_reload") else None}


@app.get("/api/rules")
def api_rules():
    return jsonify(rules_state())


@app.post("/api/rules/category")
def api_rules_category():
    body = request.get_json(silent=True) or {}
    name, on = body.get("name"), body.get("on")
    if name not in RULE_CATEGORIES or not isinstance(on, bool):   # only fixed names reach argv
        abort(400)
    return job_response(f"cat:{name}", ["rules-category", name, "on" if on else "off"])


@app.post("/api/rules/custom")
def api_rules_custom():
    body = request.get_json(silent=True) or {}
    action, sid = body.get("action"), body.get("sid")
    if action != "add" and (not isinstance(sid, int) or isinstance(sid, bool)):
        abort(400)
    if action == "remove":
        args = ["custom-remove", str(sid)]
    elif action == "toggle":
        if not isinstance(body.get("on"), bool):
            abort(400)
        args = ["custom-toggle", str(sid), "on" if body["on"] else "off"]
    elif action in ("add", "edit"):
        fields = [body.get(k, "") for k in ("proto", "src", "dst", "port", "name", "text")]
        # Short strings only; pecan-helper validates every field again and builds the rule itself.
        if any(not isinstance(f, str) or len(f) > 64 for f in fields) or not fields[4].strip():
            abort(400)
        proto, src, dst, port, name = (f.strip() for f in fields[:5])
        rule = [proto, src or "any", dst or "any", port or "any", name] + ([fields[5]] if fields[5].strip() else [])
        args = ["custom-add", *rule] if action == "add" else ["custom-edit", str(sid), *rule]
    else:
        abort(400)
    # Progress shows where the click was: the form for add/edit, the rule's row otherwise.
    return job_response("form" if action in ("add", "edit") else f"rule:{sid}", args)


# --- setup commands ---------------------------------------------------------------------------
def set_env(updates):
    """Replace or append KEY='value' lines in .env, keeping everything else (GROQ_API_KEY)."""
    lines = ENV.read_file().splitlines() if ENV.exists() else []
    lines = [l for l in lines if l.split("=", 1)[0].strip() not in updates]
    # Single quotes: python-dotenv does no $-interpolation inside them (scrypt hashes contain '$').
    lines += [f"{k}='{v}'" for k, v in updates.items()]
    ENV.write_text("\n".join(lines) + "\n")
    ENV.chmod(0o600)


def cmd_set_password(a):
    pw = getpass.getpass("New admin password (min 12 chars): ")
    if len(pw) < 12:
        sys.exit("too short")
    if pw != getpass.getpass("Again: "):
        sys.exit("passwords differ")
    updates = {"PANEL_PASSWORD_HASH": generate_password_hash(pw, method="scrypt")}
    if not os.environ.get("PANEL_SECRET_KEY"):
        updates["PANEL_SECRET_KEY"] = secrets.token_hex(32)
    set_env(updates)
    print("saved to .env; restart the panel to use it")


def cmd_make_cert(a):
    TLS.mkdir(parents=True, exist_ok=True)
    TLS.chmod(0o700)
    san = ",".join(["DNS:" + os.uname().nodename, "DNS:localhost", "IP:127.0.0.1"]
                   + [f"IP:{ip}" for ip in iface_ips("tailscale0") + iface_ips("wlan0") + a.ip
                      if not ip.startswith("fe80")])
    r = subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-days", "825", "-subj", "/CN=Pecan Pi panel", "-addext", f"subjectAltName={san}",
                        "-keyout", str(TLS / "key.pem"), "-out", str(TLS / "cert.pem")],
                       capture_output=True, text=True)
    if r.returncode:
        sys.exit(r.stderr)
    (TLS / "key.pem").chmod(0o600)
    fp = subprocess.run(["openssl", "x509", "-in", str(TLS / "cert.pem"), "-noout", "-fingerprint", "-sha256"],
                        capture_output=True, text=True).stdout.strip()
    print(f"cert for {san}\n{fp}\n(compare this fingerprint with the browser's warning page)")


def cmd_serve(a):
    if not (os.environ.get("PANEL_PASSWORD_HASH") and os.environ.get("PANEL_SECRET_KEY")):
        sys.exit("no admin password yet: run  panel.py set-password")
    if not (TLS / "cert.pem").exists():
        sys.exit("no TLS cert yet: run  panel.py make-cert")
    host = a.host or next(iter(iface_ips("tailscale0")), None)
    if not host:
        sys.exit("tailscale0 has no address; pass --host")
    print(f"panel on https://{host}:{a.port}/")
    try:
        from gunicorn.app.base import BaseApplication
    except ImportError:   # e.g. on a laptop without python3-gunicorn: Werkzeug's development server
        from werkzeug.serving import run_simple
        run_simple(host, a.port, app, threaded=True,
                   ssl_context=(str(TLS / "cert.pem"), str(TLS / "key.pem")))
        return

    class Server(BaseApplication):
        # One worker process on purpose: login lockouts, the kernel_drops trend and rule-change
        # jobs live in this process's memory, so a second worker would see different state.
        # Threads serve the polling requests (status, feed, jobs) side by side.
        def load_config(self):
            for k, v in {"bind": f"{host}:{a.port}", "workers": 1, "worker_class": "gthread", "threads": 8,
                         "certfile": str(TLS / "cert.pem"), "keyfile": str(TLS / "key.pem"),
                         "timeout": 60, "graceful_timeout": 5, "errorlog": "-", "accesslog": None,
                         "control_socket_disable": True}.items():   # gunicorn >= 26 only; /run is read-only
                if k in self.cfg.settings:
                    self.cfg.set(k, v)

        def load(self):
            return app

    Server().run()


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("set-password")
    c = sub.add_parser("make-cert")
    c.add_argument("--ip", action="append", default=[], help="extra IP for the certificate (repeatable)")
    s = sub.add_parser("serve")
    s.add_argument("--host", help="address to listen on (default: tailscale0)")
    s.add_argument("--port", type=int, default=PORT)
    a = p.parse_args()
    {"set-password": cmd_set_password, "make-cert": cmd_make_cert, "serve": cmd_serve}[a.cmd](a)


if __name__ == "__main__":
    main()
