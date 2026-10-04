"""Anomaly detection on Suricata flow events (Isolation Forest).

Usage:
  anomaly.py snapshot --since 2026-10-05 [--until 2026-10-07T18:00] [--out baseline_flows.jsonl]
  nice -n 19 anomaly.py train [--baseline baseline_flows.jsonl] [--fp-budget 2.0] [--out anomaly_model.joblib]
  anomaly.py eval FILE [--model anomaly_model.joblib]
"""
import argparse, glob, gzip, ipaddress, json, math, os, re, sys, time
from collections import deque
from datetime import datetime

EVE = "/var/log/suricata/eve.json"
BASELINE = "baseline_flows.jsonl"
MODEL = "anomaly_model.joblib"
WINDOW = 60             # seconds of per-source history
FP_BUDGET = 2.0         # % of held-out normal flows we accept being flagged
CALIB_FRACTION = 0.2    # newest part of the baseline, held out to set the threshold
MIN_BASELINE = 2000

FEATURES = [
    # this flow
    "log_bytes_toserver", "log_bytes_toclient", "log_pkts_toserver", "log_pkts_toclient",
    "duration", "port_class", "is_tcp", "is_udp", "is_icmp",
    # this source over the last WINDOW seconds
    "src_flows", "src_dest_ports", "src_dest_ips", "src_unanswered",
]

def eve_files(path=EVE):
    """eve.json plus its logrotate copies (eve.json.1, eve.json.2.gz, ...), oldest first."""
    def n(p):
        m = re.search(r"\.(\d+)(\.gz)?$", p)
        return int(m.group(1)) if m else 0
    return sorted(glob.glob(path + ".*[0-9]") + glob.glob(path + ".*.gz") + [path], key=n, reverse=True)

def read_flows(files):
    for p in files:
        opener = gzip.open if p.endswith(".gz") else open
        try:
            with opener(p, "rt") as f:
                for line in f:
                    if '"event_type":"flow"' not in line:
                        continue
                    try:
                        yield json.loads(line)
                    except json.JSONDecodeError:
                        continue
        except FileNotFoundError:
            continue

def parse_ts(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%S.%f%z")

def is_broadcast_or_multicast(e):
    """Network chatter (DHCP, mDNS, SSDP, NetBIOS...) that depends on which network
    the Pi is on, so it is excluded from both training and scoring."""
    ip = None
    try:
        ip = ipaddress.ip_address(e.get("dest_ip", ""))
        if ip.is_multicast or str(ip) == "255.255.255.255":
            return True
    except ValueError:
        pass
    ether = e.get("ether") or {}
    macs = ether.get("dest_macs") or ([ether["dest_mac"]] if "dest_mac" in ether else [])
    if macs:
        # broadcast ff:ff:.. and multicast both have the low bit of the first octet set
        return any(int(m.split(":")[0], 16) & 1 for m in macs)
    # fallback for events logged before ethernet logging was enabled
    return isinstance(ip, ipaddress.IPv4Address) and str(ip).endswith(".255")

def port_class(port):
    """Ports are labels, not quantities, so only their range is used."""
    if port is None:
        return -1          # ICMP etc.
    return 0 if port < 1024 else 1 if port < 49152 else 2

def unanswered(e):
    """No real reply: nothing came back, or a TCP flow got at most a SYN-ACK/RST."""
    back = e["flow"].get("pkts_toclient", 0)
    return back == 0 or (e["proto"] == "TCP" and back <= 1)

class SourceWindow:
    """What each source IP did in the last WINDOW seconds, by eve timestamp,
    so training, replay and live scoring compute it identically."""

    def __init__(self, seconds=WINDOW):
        self.seconds = seconds
        self.recent = {}   # src_ip -> deque[(t, dest_ip, dest_port, unanswered)]
        self.seen = {}     # dedupe key -> t
        self.last_gc = 0

    def features(self, e):
        """Feature vector for one flow event, or None if it is a duplicate."""
        t = parse_ts(e["timestamp"]).timestamp()
        f = e["flow"]
        key = (e.get("src_ip"), e.get("src_port"), e.get("dest_ip"), e.get("dest_port"), e.get("proto"), f.get("start"))
        if key in self.seen:
            return None
        self.seen[key] = t
        q = self.recent.setdefault(e.get("src_ip"), deque())
        q.append((t, e.get("dest_ip"), e.get("dest_port"), unanswered(e)))
        while q[0][0] < t - self.seconds:
            q.popleft()
        if t - self.last_gc > self.seconds:
            self._gc(t)
        start, end = parse_ts(f["start"]), parse_ts(f["end"])
        proto = e.get("proto")
        return [
            math.log1p(f.get("bytes_toserver", 0)), math.log1p(f.get("bytes_toclient", 0)),
            math.log1p(f.get("pkts_toserver", 0)), math.log1p(f.get("pkts_toclient", 0)),
            max((end - start).total_seconds(), 0.0), port_class(e.get("dest_port")),
            proto == "TCP", proto == "UDP", proto in ("ICMP", "IPv6-ICMP"),
            len(q), len({x[2] for x in q}), len({x[1] for x in q}), sum(x[3] for x in q) / len(q),
        ]

    def _gc(self, t):
        cutoff = t - self.seconds
        self.seen = {k: v for k, v in self.seen.items() if v >= cutoff}
        self.recent = {s: q for s, q in self.recent.items() if q and q[-1][0] >= cutoff}
        self.last_gc = t

def featurize(events, window=None):
    """(event, vector) for every usable flow, in order; drops noise and duplicates."""
    window = window or SourceWindow()
    for e in events:
        if is_broadcast_or_multicast(e):
            continue
        v = window.features(e)
        if v is not None:
            yield e, v

def read_jsonl(path):
    with open(path) as f:
        for line in f:
            if line.strip():
                yield json.loads(line)

class Scorer:
    """Live scoring: add() each flow event as it arrives, flush() every batch."""

    def __init__(self, path=MODEL):
        import joblib
        b = joblib.load(path)
        if b["features"] != FEATURES:
            raise ValueError(f"{path} was trained with different features; retrain")
        self.model, self.threshold = b["model"], b["threshold"]
        self.window = SourceWindow(b["window"])
        self.buf = []

    def add(self, e):
        if is_broadcast_or_multicast(e):
            return
        v = self.window.features(e)
        if v is not None:
            self.buf.append((e, v))

    def flags(self):
        """Per-flow anomaly decisions for the current buffer (used by eval)."""
        import numpy as np
        if not self.buf:
            return []
        return list(self.model.score_samples(np.array([v for _, v in self.buf], dtype=float)) < self.threshold)

    def flush(self):
        """Score buffered flows in one call; return anomalous flows grouped by source IP
        (the features describe what a source did, so a sweep across many hosts is one group)."""
        if not self.buf:
            return []
        import numpy as np
        buf, self.buf = self.buf, []
        scores = self.model.score_samples(np.array([v for _, v in buf], dtype=float))
        groups = {}
        for (e, v), sc in zip(buf, scores):
            if sc >= self.threshold:
                continue
            g = groups.setdefault(e.get("src_ip"), {
                "src_ip": e.get("src_ip"), "count": 0, "score": 0.0,
                "protos": set(), "dest_ips": set(), "dest_ports": set(), "src_flows": 0, "src_dest_ports": 0,
                "src_dest_ips": 0, "src_unanswered": 0.0})
            g["count"] += 1
            g["score"] = min(g["score"], float(sc))
            g["protos"].add(e.get("proto"))
            g["dest_ips"].add(e.get("dest_ip"))
            if e.get("dest_port") is not None:
                g["dest_ports"].add(e["dest_port"])
            for k in ("src_flows", "src_dest_ports", "src_dest_ips", "src_unanswered"):
                g[k] = max(g[k], v[FEATURES.index(k)])
        return [summarize(g) for g in groups.values()]

def summarize(g):
    ports = sorted(g.pop("dest_ports"))
    hosts = sorted(g.pop("dest_ips"))
    g["dest_ip"] = hosts[0] if len(hosts) == 1 else f"{len(hosts)} hosts"
    g["dest_ips_sample"] = hosts[:10]
    g["protos"] = sorted(g["protos"])
    g["n_dest_ports"] = len(ports)
    g["dest_ports_sample"] = ports[:10]
    g["src_unanswered"] = round(g["src_unanswered"], 2)
    g["score"] = round(g["score"], 4)
    g["summary"] = (f"Anomaly (Isolation Forest): {g['count']} flows to {len(hosts)} host(s) / {len(ports)} port(s); "
                    f"source made {g['src_flows']} flows to {g['src_dest_ports']} ports / "
                    f"{g['src_dest_ips']} hosts, {g['src_unanswered']:.0%} unanswered in {WINDOW}s")
    return g

def local_time(s):
    d = datetime.fromisoformat(s)
    return d if d.tzinfo else d.astimezone()

def cmd_snapshot(a):
    since, until = local_time(a.since), local_time(a.until) if a.until else None
    files = eve_files()
    kept = noise = 0
    first = last = None
    with open(a.out, "w") as out:
        for e in read_flows(files):
            t = parse_ts(e["timestamp"])
            if t < since or (until and t > until):
                continue
            out.write(json.dumps(e) + "\n")
            kept += 1
            noise += is_broadcast_or_multicast(e)
            first, last = first or t, t
    print(f"read {len(files)} file(s): {', '.join(os.path.basename(p) for p in files)}")
    print(f"wrote {kept} flows to {a.out} ({kept - noise} usable, {noise} broadcast/multicast excluded)")
    if first:
        print(f"span: {first.isoformat()} -> {last.isoformat()}")

def cmd_train(a):
    """Fit on the older part of the baseline; set the threshold on the newer, held-out
    part so that fp_budget % of unseen normal flows would be flagged. Attack replays
    play no part in this; they are evaluated separately with `eval`."""
    import joblib, numpy as np, sklearn
    from sklearn.ensemble import IsolationForest
    t0 = time.time()
    events = sorted(read_jsonl(a.baseline), key=lambda e: parse_ts(e["timestamp"]))
    X = np.array([v for _, v in featurize(events)], dtype=float)  # windows stay continuous across the split
    if len(X) < 100:
        sys.exit(f"only {len(X)} usable flows in {a.baseline}; collect more")
    if len(X) < MIN_BASELINE:
        print(f"warning: {len(X)} usable flows, below the {MIN_BASELINE} target")
    cut = int(len(X) * (1 - CALIB_FRACTION))
    fit, calib = X[:cut], X[cut:]
    model = IsolationForest(n_estimators=200, max_samples=min(256, len(fit)), random_state=42, n_jobs=1)
    model.fit(fit)
    calib_scores = model.score_samples(calib)
    threshold = float(np.percentile(calib_scores, a.fp_budget))
    fit_fp = (model.score_samples(fit) < threshold).mean()
    joblib.dump({"model": model, "features": FEATURES, "threshold": threshold, "window": WINDOW,
                 "fp_budget": a.fp_budget, "sklearn": sklearn.__version__,
                 "baseline": os.path.abspath(a.baseline), "n_fit": len(fit), "n_calib": len(calib)}, a.out)
    print(f"fit on {len(fit)} flows, calibrated on {len(calib)} held-out flows, {time.time() - t0:.1f}s -> {a.out}")
    print(f"threshold {threshold:.4f}: flags {(calib_scores < threshold).mean():.1%} of held-out normal flows "
          f"(budget {a.fp_budget}%), {fit_fp:.1%} of training flows")

def cmd_eval(a):
    sc = Scorer(a.model)
    events = list(read_jsonl(a.file))
    t0 = time.time()
    for e in events:
        sc.add(e)
    n = len(sc.buf)
    synthetic = [e.get("synthetic", False) for e, _ in sc.buf]
    flags = sc.flags()
    groups = sc.flush()
    print(f"{len(events)} flows, {n} usable, {sum(flags)} anomalous in {len(groups)} group(s); "
          f"scored in {time.time() - t0:.2f}s")
    for label, want in (("real (false positives)", False), ("synthetic attack (detected)", True)):
        hits = [f for f, s in zip(flags, synthetic) if s == want]
        if hits:
            print(f"  {label}: {sum(hits)}/{len(hits)} = {sum(hits) / len(hits):.1%}")
    for g in sorted(groups, key=lambda g: g["score"])[:a.top]:
        print(f"  {g['score']:.3f}  {g['src_ip']} -> {g['dest_ip']}  {'/'.join(g['protos'])}  "
              f"ports {g['dest_ports_sample']}{'...' if g['n_dest_ports'] > 10 else ''}\n         {g['summary']}")

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("snapshot", help="copy flow events from eve.json (+ rotated files) into a baseline file")
    s.add_argument("--since", required=True, help="local time, e.g. 2026-10-05 or 2026-10-05T14:00")
    s.add_argument("--until")
    s.add_argument("--out", default=BASELINE)
    s.set_defaults(func=cmd_snapshot)
    t = sub.add_parser("train", help="fit the Isolation Forest on a baseline file")
    t.add_argument("--baseline", default=BASELINE)
    t.add_argument("--fp-budget", type=float, default=FP_BUDGET, help="%% of held-out normal flows allowed to be flagged")
    t.add_argument("--out", default=MODEL)
    t.set_defaults(func=cmd_train)
    v = sub.add_parser("eval", help="score a jsonl file of flow events with the live code path")
    v.add_argument("file")
    v.add_argument("--model", default=MODEL)
    v.add_argument("--top", type=int, default=10)
    v.set_defaults(func=cmd_eval)
    a = ap.parse_args()
    a.func(a)

if __name__ == "__main__":
    main()
