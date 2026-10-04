import json, os, time, sqlite3
from datetime import datetime, timezone
from dotenv import load_dotenv
from groq import Groq

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))
MODEL = "openai/gpt-oss-120b"
EVE = "/var/log/suricata/eve.json"
DB = "pecan.db"
BATCH_SECONDS = 30
IGNORE_SIDS = {9000001}  # ping test rule

CONTEXT = (
    "Environment: the local host is a Kali Linux security appliance on a home "
    "network. It regularly runs apt updates from official Kali mirrors."
)

db = sqlite3.connect(DB)
db.execute("""CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    seen_at TEXT, sid INTEGER, signature TEXT, severity INTEGER,
    src_ip TEXT, dest_ip TEXT, count INTEGER,
    verdict TEXT, priority TEXT, reason TEXT)""")
db.commit()

def triage(items):
    prompt = (
        "You are a SOC analyst triaging grouped Suricata alerts.\n" + CONTEXT + "\n"
        "Suricata severity: 1 = highest, 3 = lowest. 'count' = times seen in this window.\n"
        "Use every field plus general knowledge of well-known domains and software. "
        "Do not invent facts.\n"
        "For EACH alert output exactly one line, nothing else:\n"
        "n | verdict (benign/suspicious/malicious) | priority (low/medium/high) | short reason\n"
        "where n is the alert's 'n' field.\n\n" + json.dumps(items)
    )
    r = client.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": prompt}])
    results = {}
    for line in r.choices[0].message.content.splitlines():
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 4 and parts[0].isdigit():
            results[int(parts[0])] = (parts[1].lower(), parts[2].lower(), parts[3])
    return results

def flush(pending):
    items = []
    for n, (key, (e, count)) in enumerate(pending.items()):
        slim = {k: e.get(k) for k in ("src_ip", "dest_ip", "dest_port", "proto", "app_proto", "http", "tls", "dns")}
        slim.update(n=n, sid=key[0], signature=e["alert"]["signature"],
                    severity=e["alert"]["severity"], count=count)
        items.append(slim)
    try:
        results = triage(items)
    except Exception as err:
        print("AI error:", err)
        results = {}
    now = datetime.now(timezone.utc).isoformat()
    for it in items:
        verdict, priority, reason = results.get(it["n"], ("unknown", "unknown", "AI unavailable"))
        db.execute(
            "INSERT INTO alerts (seen_at, sid, signature, severity, src_ip, dest_ip, count, verdict, priority, reason) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (now, it["sid"], it["signature"], it["severity"], it["src_ip"], it["dest_ip"],
             it["count"], verdict, priority, reason))
        print(f"[{priority:>7}] {verdict:<10} {it['signature']} x{it['count']} | {reason}")
    db.commit()

def handle(line, pending):
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        return
    if e.get("event_type") == "alert" and e["alert"]["signature_id"] not in IGNORE_SIDS:
        key = (e["alert"]["signature_id"], e.get("src_ip"), e.get("dest_ip"))
        old = pending.get(key)
        pending[key] = (old[0], old[1] + 1) if old else (e, 1)

def open_eve():
    while True:
        try:
            return open(EVE)
        except FileNotFoundError:
            time.sleep(1)

def reopen_if_rotated(f, pending):
    """logrotate renames eve.json and Suricata starts a new one (inode changes),
    or the file is truncated in place (size drops below our position)."""
    try:
        st = os.stat(EVE)
    except FileNotFoundError:
        return f  # mid-rotation: keep the old handle until the new file appears
    if st.st_ino != os.fstat(f.fileno()).st_ino:
        for line in f:  # drain anything written to the old file before the switch
            handle(line, pending)
        f.close()
        print("eve.json rotated, reopening")
        return open_eve()  # new file: read from the start, everything in it is new
    if st.st_size < f.tell():
        print("eve.json truncated, rewinding")
        f.seek(0)
    return f

pending, last_flush = {}, time.time()
print("Pecan Pi pipeline running...")
f = open_eve()
f.seek(0, 2)
while True:
    line = f.readline()
    if line:
        handle(line, pending)
    else:
        f = reopen_if_rotated(f, pending)
        time.sleep(0.5)
    if pending and time.time() - last_flush >= BATCH_SECONDS:
        flush(pending)
        pending, last_flush = {}, time.time()
