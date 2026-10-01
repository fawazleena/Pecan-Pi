import json, os, time
from dotenv import load_dotenv
from groq import Groq

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))
MODEL = "openai/gpt-oss-120b"
EVE = "/var/log/suricata/eve.json"
BATCH_SECONDS = 30
IGNORE_SIDS = {9000001}  # our ping test rule

CONTEXT = (
    "Environment: the local host is a Kali Linux security appliance on a home "
    "network. It regularly runs apt updates from official Kali mirrors."
)

def triage(batch):
    items = []
    for (sid, src, dst), (e, count) in batch.items():
        slim = {k: e.get(k) for k in ("src_ip", "dest_ip", "dest_port", "proto", "app_proto", "http", "tls", "dns")}
        slim.update(sid=sid, signature=e["alert"]["signature"],
                    severity=e["alert"]["severity"], count=count)
        items.append(slim)
    prompt = (
        "You are a SOC analyst triaging grouped Suricata alerts.\n" + CONTEXT + "\n"
        "Suricata severity: 1 = highest, 3 = lowest. 'count' = times seen in this window.\n"
        "Use every field plus general knowledge of well-known domains and software. "
        "Do not invent facts.\n"
        "For EACH alert output exactly one line:\n"
        "sid | verdict (benign/suspicious/malicious) | priority (low/medium/high) | short reason\n\n"
        + json.dumps(items)
    )
    r = client.chat.completions.create(model=MODEL, messages=[{"role": "user", "content": prompt}])
    return r.choices[0].message.content

pending, last_flush = {}, time.time()
print("Pecan Pi pipeline running...")
with open(EVE) as f:
    f.seek(0, 2)
    while True:
        line = f.readline()
        if line:
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if e.get("event_type") == "alert" and e["alert"]["signature_id"] not in IGNORE_SIDS:
                key = (e["alert"]["signature_id"], e.get("src_ip"), e.get("dest_ip"))
                old = pending.get(key)
                pending[key] = (old[0], old[1] + 1) if old else (e, 1)
        else:
            time.sleep(0.5)
        if pending and time.time() - last_flush >= BATCH_SECONDS:
            print(f"\n--- {len(pending)} unique alert(s) ---")
            try:
                print(triage(pending))
            except Exception as err:
                print("AI error:", err)
            pending, last_flush = {}, time.time()
