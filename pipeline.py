import json, os, time
from datetime import datetime, timezone
from triage import open_db, collapse, cached, triage_all, UNTRIAGED

EVE = "/var/log/suricata/eve.json"
DB = "pecan.db"
BATCH_SECONDS = 30
IGNORE_SIDS = {9000001}  # ping test rule
ANOMALY_MODEL = "anomaly_model.joblib"

db = open_db(DB)

def flush(pending, anomalies):
    items = []
    for key, (e, count) in pending.items():
        slim = {k: e.get(k) for k in ("src_ip", "dest_ip", "dest_port", "proto", "app_proto", "http", "tls", "dns")}
        slim.update(detection="signature", sid=key[0], signature=e["alert"]["signature"],
                    severity=e["alert"]["severity"], count=count)
        items.append(slim)
    for g in anomalies:
        items.append({"detection": "anomaly", "signature": g["summary"], "src_ip": g["src_ip"],
                      "dest_ip": g["dest_ip"], "dest_ips": g["dest_ips_sample"], "protos": g["protos"],
                      "dest_ports": g["dest_ports_sample"], "n_dest_ports": g["n_dest_ports"],
                      "count": g["count"], "score": g["score"],
                      **{k: g[k] for k in ("src_flows", "src_dest_ports", "src_dest_ips", "src_unanswered")}})
    items = collapse(items)
    for n, it in enumerate(items):
        it["n"] = n
    now = datetime.now(timezone.utc).isoformat()
    results = cached(db, items, now)
    results.update(triage_all([it for it in items if it["n"] not in results]))
    for it in items:
        verdict, priority, reason = results.get(it["n"], UNTRIAGED)
        db.execute(
            "INSERT INTO alerts (seen_at, sid, signature, severity, src_ip, dest_ip, count, verdict, priority, reason, "
            "detection, score, n_src, n_dest, group_key) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (now, it.get("sid"), it["signature"], it.get("severity"), it["src_ip"], it["dest_ip"],
             it["count"], verdict, priority, reason, it["detection"], it.get("score"),
             it.get("n_src"), it.get("n_dest"), it.get("group_key")))
        hosts = max(it.get("n_src") or 1, it.get("n_dest") or 1)
        print(f"[{priority:>7}] {verdict:<10} {it['signature']} x{it['count']}"
              + (f" ({hosts} hosts)" if hosts > 1 else "") + f" | {reason}")
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
    elif e.get("event_type") == "flow" and scorer:
        try:
            scorer.add(e)
        except Exception as err:
            print("anomaly error:", err)

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

f = open_eve()
f.seek(0, 2)  # position first: events arriving while sklearn loads (~9s) are still read

scorer = None
if os.path.exists(ANOMALY_MODEL):
    try:
        from anomaly import Scorer
        scorer = Scorer(ANOMALY_MODEL)
        print("anomaly detection on")
    except Exception as err:
        print("anomaly detection off:", err)
else:
    print(f"anomaly detection off: no {ANOMALY_MODEL}")

pending, last_flush = {}, time.time()
print("Pecan Pi pipeline running...")
while True:
    line = f.readline()
    if line:
        handle(line, pending)
    else:
        f = reopen_if_rotated(f, pending)
        time.sleep(0.5)
    if time.time() - last_flush >= BATCH_SECONDS:
        try:
            anomalies = scorer.flush() if scorer else []
        except Exception as err:
            print("anomaly error:", err)
            anomalies = []
        if pending or anomalies:
            flush(pending, anomalies)
        pending, last_flush = {}, time.time()
