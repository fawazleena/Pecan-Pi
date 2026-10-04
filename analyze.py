import json, os
from dotenv import load_dotenv
from groq import Groq
from triage import host_context

load_dotenv()
client = Groq(api_key=os.getenv("GROQ_API_KEY"))
MODEL = "openai/gpt-oss-120b"

alert = None
with open("/var/log/suricata/eve.json") as f:
    for line in f:
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if e.get("event_type") == "alert" and e["alert"]["signature_id"] != 9000001:
            alert = e

if not alert:
    raise SystemExit("No real alerts found yet.")

prompt = (
    "You are a SOC analyst triaging Suricata alerts.\n"
    + host_context() + "\n"
    "Suricata severity: 1 = highest, 3 = lowest.\n"
    "Use every field in the JSON (hostname, url, user agent, direction) plus "
    "general knowledge of well-known domains and software. Do not invent facts "
    "that are not in the data or widely known.\n"
    "Answer in max 4 short lines:\n"
    "1. Verdict: benign / suspicious / malicious\n"
    "2. Priority: low / medium / high\n"
    "3. Why, in one sentence\n"
    "4. Recommended action\n\n"
    + json.dumps(alert)
)

r = client.chat.completions.create(
    model=MODEL,
    messages=[{"role": "user", "content": prompt}],
)
print(r.choices[0].message.content)
