import json, time

EVE = "/var/log/suricata/eve.json"

with open(EVE) as f:
    f.seek(0, 2)  # start at the end: only new events
    while True:
        line = f.readline()
        if not line:
            time.sleep(0.5)
            continue
        try:
            e = json.loads(line)
        except json.JSONDecodeError:
            continue
        if e.get("event_type") != "alert":
            continue
        a = e["alert"]
        print(f"[sev {a['severity']}] {a['signature']} | {e['src_ip']} -> {e['dest_ip']}")
