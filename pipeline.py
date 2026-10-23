import json, os, time
from datetime import datetime, timezone
from triage import open_db, collapse, cached, triage_all, UNTRIAGED, SELF_RECON_TAG
from netinfo import (host_ips, load_recon_marker, recon_covers_dest, load_settings, load_anomaly_iface,
                     model_label, REPLAY_IFACE, REPLAY_TAG)

EVE = "/var/log/suricata/eve.json"
DB = "pecan.db"
BATCH_SECONDS = 30
IGNORE_SIDS = {9000001}  # ping test rule
# Next to the code, not in the data dir: joblib files are pickles (loading one runs code), so
# the root service only loads the root-owned copy in /opt/pecan.
ANOMALY_MODEL = os.path.join(os.path.dirname(os.path.abspath(__file__)), "anomaly_model.joblib")
HONEYPOT_LOG = "/var/log/pecan/honeypot.json"  # written by honeypot.py (pecan-honeypot.service)
AI_OFF = ("unknown", "unknown", "AI explanations off")  # not 'AI unavailable': backfill.py must skip these

db = open_db(DB)

def flush(pending, anomalies, hits):
    items = []
    # While a recon scan runs, Suricata still alerts on the Pi's own nmap. Tag those (don't drop
    # them: Suricata must not be blinded and the audit trail is kept), so the TUI/report show the
    # appliance's own authorised scan. marker/ours looked up once per flush, only when a scan is active.
    marker = load_recon_marker()
    ours = host_ips() if marker else []
    for key, (e, count) in pending.items():
        slim = {k: e.get(k) for k in ("src_ip", "dest_ip", "dest_port", "proto", "app_proto", "http", "tls", "dns")}
        sig = e["alert"]["signature"]
        if marker and e.get("src_ip") in ours and recon_covers_dest(marker, e.get("dest_ip", "")):
            sig = SELF_RECON_TAG + sig
        slim.update(detection="signature", sid=key[0], signature=sig,
                    severity=e["alert"]["severity"], count=count, replay=e.get("in_iface") == REPLAY_IFACE)
        items.append(slim)
    for g in anomalies:
        items.append({"detection": "anomaly", "signature": g["summary"], "src_ip": g["src_ip"],
                      "dest_ip": g["dest_ip"], "dest_ips": g["dest_ips_sample"], "protos": g["protos"],
                      "dest_ports": g["dest_ports_sample"], "n_dest_ports": g["n_dest_ports"],
                      "count": g["count"], "score": g["score"], "replay": anomaly_iface == REPLAY_IFACE,
                      **{k: g[k] for k in ("src_flows", "src_dest_ports", "src_dest_ips", "src_unanswered")}})
    for src, (h, count) in hits.items():
        items.append({"detection": "honeypot", "signature": f"Honeypot: connection to decoy SSH port {h['dest_port']}",
                      "src_ip": src, "dest_ip": h["dest_ip"], "dest_port": h["dest_port"], "count": count,
                      "client_banner": h.get("client_banner"), "action": h.get("action")})
    items = collapse(items)
    for n, it in enumerate(items):
        it["n"] = n
    now = datetime.now(timezone.utc).isoformat()
    results = {}
    if settings["ai"]:
        results = cached(db, items, now)
        results.update(triage_all([it for it in items if it["n"] not in results]))
    for it in items:
        verdict, priority, reason = results.get(it["n"], UNTRIAGED if settings["ai"] else AI_OFF)
        if it.get("replay"):   # CIC-IDS2017 demo traffic on cic0: marked, so it is never read as the Pi's own
            reason = REPLAY_TAG + reason
        db.execute(
            "INSERT INTO alerts (seen_at, sid, signature, severity, src_ip, dest_ip, count, verdict, priority, reason, "
            "detection, score, n_src, n_dest, group_key, action) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (now, it.get("sid"), it["signature"], it.get("severity"), it["src_ip"], it["dest_ip"],
             it["count"], verdict, priority, reason, it["detection"], it.get("score"),
             it.get("n_src"), it.get("n_dest"), it.get("group_key"), it.get("action")))
        hosts = max(it.get("n_src") or 1, it.get("n_dest") or 1)
        print(f"[{priority:>7}] {verdict:<10} {it['signature']} x{it['count']}"
              + (f" ({hosts} hosts)" if hosts > 1 else "")
              + (f" [{it['action']}]" if it.get("action") else "") + f" | {reason}")
    db.commit()

def handle(line, pending):
    try:
        e = json.loads(line)
    except json.JSONDecodeError:
        return
    if e.get("event_type") == "alert" and settings["signatures"] and e["alert"]["signature_id"] not in IGNORE_SIDS:
        key = (e["alert"]["signature_id"], e.get("src_ip"), e.get("dest_ip"))
        old = pending.get(key)
        pending[key] = (old[0], old[1] + 1) if old else (e, 1)
    elif e.get("event_type") == "flow" and scorer:
        if anomaly_iface and e.get("in_iface") != anomaly_iface:
            return  # filtered before the source window, as `anomaly.py snapshot --iface` does
        try:
            scorer.add(e)
        except Exception as err:
            print("anomaly error:", err)

def handle_hit(line, hits):
    """One decoy connection; deduplicated per source IP for the batch, first hit kept."""
    try:
        h = json.loads(line)
    except json.JSONDecodeError:
        return
    if h.get("src_ip"):
        old = hits.get(h["src_ip"])
        hits[h["src_ip"]] = (old[0], old[1] + 1) if old else (h, 1)

class Tail:
    """Follow a log file from its current end, across logrotate and truncation.

    A file that does not exist yet (honeypot.json before the first hit) is opened when it
    appears and read from the start. wait=True blocks until it exists (eve.json)."""
    def __init__(self, path, handle, wait=False):
        self.path, self.handle = path, handle
        self.f = self.open()
        while wait and not self.f:
            time.sleep(1)
            self.f = self.open()
        if self.f:
            self.f.seek(0, 2)  # only events arriving after startup

    def open(self):
        try:
            return open(self.path)
        except FileNotFoundError:
            return None

    def readline(self):
        return self.f.readline() if self.f else ""

    def check(self):
        """logrotate renames the file and the writer starts a new one (inode changes),
        or the file is truncated in place (size drops below our position)."""
        if not self.f:
            self.f = self.open()  # new file: everything in it is new
            return
        try:
            st = os.stat(self.path)
        except FileNotFoundError:
            return  # mid-rotation: keep the old handle until the new file appears
        if st.st_ino != os.fstat(self.f.fileno()).st_ino:
            for line in self.f:  # drain anything written to the old file before the switch
                self.handle(line)
            self.f.close()
            print(f"{self.path} rotated, reopening")
            self.f = self.open()
        elif st.st_size < self.f.tell():
            print(f"{self.path} truncated, rewinding")
            self.f.seek(0)

pending, hits = {}, {}
# Position first: events arriving while sklearn loads (~9s) are still read.
eve = Tail(EVE, lambda line: handle(line, pending), wait=True)
honeypot = Tail(HONEYPOT_LOG, lambda line: handle_hit(line, hits))

settings, scorer, settings_error, anomaly_iface = None, None, None, None

def apply_settings():
    """Re-read the panel's switches (/etc/pecan/settings.json); log changes, load or drop the Scorer.
    Signature detection off: Suricata keeps running (its flows feed the anomaly detector), the
    pipeline just ignores its alerts. AI off: rows are stored as AI_OFF, nothing goes to Groq.
    anomaly_iface: score flows from that interface only (None = all); a change starts a fresh Scorer."""
    global settings, scorer, settings_error, anomaly_iface
    new, error = load_settings()
    if error and error != settings_error:
        print(f"settings unreadable, keeping everything on: {error}")
    settings_error = error
    new_iface = load_anomaly_iface()
    if new == settings and new_iface == anomaly_iface:
        return
    old, settings = settings, new
    iface_changed, anomaly_iface = new_iface != anomaly_iface, new_iface
    if not (old and new["anomaly"] == old["anomaly"]) or iface_changed:
        scorer = None
        if not new["anomaly"]:
            print("anomaly detection off: switched off in the panel")
        elif os.path.exists(ANOMALY_MODEL):
            try:
                from anomaly import Scorer
                scorer = Scorer(ANOMALY_MODEL)  # a fresh 60 s source window: no stale state from before
                print(f"anomaly detection on, model: {model_label(ANOMALY_MODEL)}")
            except Exception as err:
                print("anomaly detection off:", err)
        else:
            print(f"anomaly detection off: no {ANOMALY_MODEL}")
    # The switch can be on while nothing scores (no model yet): say so, or the log reads as "running".
    state = {k: "on" if v else "off" for k, v in new.items()}
    if new["anomaly"] and not scorer:
        state["anomaly"] = "on (no model loaded)"
    state["anomaly_iface"] = anomaly_iface or "all"
    print("switches: " + ", ".join(f"{k}={v}" for k, v in state.items()))

apply_settings()

last_flush = time.time()
print("Pecan Pi pipeline running...")
while True:
    line = eve.readline()
    if line:
        handle(line, pending)
    else:
        for line in iter(honeypot.readline, ""):
            handle_hit(line, hits)
        eve.check()
        honeypot.check()
        time.sleep(0.5)
    if time.time() - last_flush >= BATCH_SECONDS:
        try:
            anomalies = scorer.flush() if scorer else []
            if scorer and scorer.scored:
                print(f"anomaly: scored {scorer.scored} flows ({anomaly_iface or 'all'}), flagged {scorer.flagged}")
        except Exception as err:
            print("anomaly error:", err)
            anomalies = []
        if pending or anomalies or hits:
            flush(pending, anomalies, hits)
        pending.clear()  # cleared, not rebound: the Tail handlers hold these dicts
        hits.clear()
        apply_settings()
        last_flush = time.time()
