"""CIC-IDS2017 evaluation of both detectors (anomaly model + Suricata signatures).

Monday (benign) trains a SEPARATE anomaly model with the same code as the Pi's model
(anomaly.fit_model); Friday (attacks) is labelled from the official CIC schedule and
scored. Everything reads and writes under cic/ (gitignored); the live model and the
baseline files are never touched.

Usage:
  cic_eval.py verify                   # schedule vs traffic: timezone + attacker IPs; writes nothing
  nice -n 19 cic_eval.py train         # Monday -> cic/model.joblib
  nice -n 19 cic_eval.py report        # label + score Friday, both detectors -> cic/results.json
"""
import argparse, json, os, sys, time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from anomaly import FP_BUDGET, Scorer, excluded, fit_model, parse_ts, read_jsonl

DIR = "cic"
MONDAY = os.path.join(DIR, "monday_flows.jsonl.gz")
FRIDAY = os.path.join(DIR, "friday_flows.jsonl.gz")
MODEL = os.path.join(DIR, "model.joblib")
ALERTS = [("Pi config", os.path.join(DIR, "friday_alerts.jsonl.gz")),          # run (a): HOME_NET = all RFC1918
          ("LAN HOME_NET", os.path.join(DIR, "friday_alerts_lan.jsonl.gz"))]  # run (b): HOME_NET = 192.168.10.0/24
RESULTS = os.path.join(DIR, "results.json")

# Official schedule, copied from https://www.unb.ca/cic/datasets/ids-2017.html (fetched 2026-10-16).
# Times are as printed on the page: no timezone is stated, so `verify` checks them against the traffic.
# Each window covers its end minute ("14:33 - 14:33" is one minute). IPs are the page's (public) ones.
DAY = "2017-07-07"
KALI = ["205.174.165.73"]
WEB_SERVER = ["205.174.165.68", "192.168.10.50"]   # public / local IP of the same Ubuntu16 victim
SCHEDULE = [
    ("Botnet ARES", "botnet", [("10:02", "11:02")], KALI,
     ["192.168.10.15", "192.168.10.9", "192.168.10.14", "192.168.10.5", "192.168.10.8"]),
    ("PortScan (firewall on)", "portscan",
     [("13:55", "13:57"), ("13:58", "14:00"), ("14:01", "14:04"), ("14:05", "14:07"), ("14:08", "14:10"),
      ("14:11", "14:13"), ("14:14", "14:16"), ("14:17", "14:19"), ("14:20", "14:21"), ("14:22", "14:24"),
      ("14:33", "14:33"), ("14:35", "14:35")], KALI, WEB_SERVER),
] + [(f"PortScan -{flag}", "portscan", [(s, e)], KALI, WEB_SERVER) for flag, s, e in [
    ("sS", "14:51", "14:53"), ("sT", "14:54", "14:56"), ("sF", "14:57", "14:59"), ("sX", "15:00", "15:02"),
    ("sN", "15:03", "15:05"), ("sP", "15:06", "15:07"), ("sV", "15:08", "15:10"), ("sU", "15:11", "15:12"),
    ("sO", "15:13", "15:15"), ("sA", "15:16", "15:18"), ("sW", "15:19", "15:21"), ("sR", "15:22", "15:24"),
    ("sL", "15:25", "15:25"), ("sI", "15:26", "15:27"), ("b", "15:28", "15:29")]] + [
    ("DDoS LOIT", "ddos", [("15:56", "16:16")], ["205.174.165.69", "205.174.165.70", "205.174.165.71"], WEB_SERVER),
]
FIREWALL = ["205.174.165.80", "172.16.0.1"]   # outside / inside; NAT may hide attackers behind these
OFFSETS = (0, 3, 4)                           # candidate hours to ADD to page times to get UTC (ADT = UTC-3)

# Labelling decisions, taken from `verify` on 2026-10-16 (evidence in the comments):
OFFSET = 3              # page time + 3h = UTC (ADT). Scan/DDoS bursts start on the scheduled minute at +3h;
                        # at +4h 0% of DDoS flows fall in its window; both days span 08:59-17:02 local.
NAT_ATTACKER = "172.16.0.1"   # all scan + DDoS traffic to the web server arrives from the firewall's inside
                        # address (258,085 flows, 1,062 ports); the page's public attacker IPs never appear.
                        # Scan and DDoS are therefore told apart by time window only.
BOTNET_CC, BOTNET_PORT = "205.174.165.73", 8080
# Deliberate deviation from the official window: every victim <-> C&C TCP/8080 flow is Botnet, all day.
# The bots beacon every ~100s from 10:04 until the capture ends (17:01 local); only 736 of 2,199 flows fall
# inside 10:02-11:02, and 205.174.165.73 talks to no other host, so there is no benign reading of the rest.
# The in-window subset is reported separately.
ATTACKER_IPS = {NAT_ATTACKER, BOTNET_CC, *FIREWALL, "205.174.165.69", "205.174.165.70", "205.174.165.71"}
SLACK = 60              # a web-server flow starting <= 60s outside a window goes to the nearest window
ENGINE_SIDS = range(2200000, 2300000)   # "SURICATA ..." stream/decoder events, not attack signatures
IGNORE_SIDS = {9000001} # same as pipeline.IGNORE_SIDS (ping test rule); not imported: pipeline.py
                        # runs its main loop at import
BATCH = 30              # pipeline.BATCH_SECONDS: rows an analyst would see are per 30s batch

def window_utc(start, end, offset):
    """(start, end) of one schedule window in UTC, given page time + offset hours = UTC."""
    t = lambda hm: datetime.fromisoformat(f"{DAY}T{hm}").replace(tzinfo=timezone.utc) + timedelta(hours=offset)
    return t(start), t(end) + timedelta(seconds=59.999999)

def utc(s):
    return parse_ts(s).astimezone(timezone.utc)

def in_cic(path):
    """Refuse to write anywhere but cic/: the live model and baselines must stay untouched."""
    root = os.path.realpath(DIR)
    if os.path.commonpath([os.path.realpath(path), root]) != root:
        sys.exit(f"refusing to write {path}: CIC outputs must stay under {DIR}/")
    return path

def bursts(times, gap=60):
    """Merge sorted UTC times into runs separated by more than `gap` seconds: [(first, last, n)]."""
    runs = []
    for t in times:
        if runs and (t - runs[-1][1]).total_seconds() <= gap:
            runs[-1] = (runs[-1][0], t, runs[-1][2] + 1)
        else:
            runs.append((t, t, 1))
    return runs

def cmd_verify(a):
    """Show, from the traffic alone, which IPs attack the victims and when, next to the
    schedule shifted by each candidate offset. Writes nothing: the analyst decides."""
    victims = {v for *_, vs in SCHEDULE for v in vs}
    attackers = {x for *_, xs, _ in SCHEDULE for x in xs} | set(FIREWALL)
    pair_times = defaultdict(list)            # (attacker candidate, victim group) -> [flow start UTC]
    talkers = defaultdict(lambda: [0, set(), set()])   # peer of the web server -> [flows, ports, minutes]
    first = last = None
    n = 0
    for e in read_jsonl(a.friday):
        n += 1
        t = utc(e["flow"]["start"])
        first, last = min(first or t, t), max(last or t, t)
        s, d = e.get("src_ip"), e.get("dest_ip")
        for x, y in ((s, d), (d, s)):
            if y in WEB_SERVER and x not in WEB_SERVER:
                k = talkers[x]
                k[0] += 1
                k[1].add(e.get("dest_port") if y == d else e.get("src_port"))
                k[2].add(t.replace(second=0, microsecond=0))
            if x in attackers and y in victims:
                pair_times[(x, "web server" if y in WEB_SERVER else "botnet victims")].append(t)
    mon = [utc(e["flow"]["start"]) for e in read_jsonl(a.monday)]
    print(f"Friday: {n} flows, flow starts {first:%Y-%m-%d %H:%M} -> {last:%H:%M} UTC")
    print(f"Monday: {len(mon)} flows, flow starts {min(mon):%Y-%m-%d %H:%M} -> {max(mon):%H:%M} UTC")
    print(f"(CIC says each day's capture is ~9:00-17:00 local; page time + offset = UTC)\n")

    print("Top peers of the web server (192.168.10.50 / 205.174.165.68) on Friday, by distinct ports:")
    print(f"  {'peer':<40} {'flows':>8} {'ports':>6} {'active min':>10}")
    for ip, (fl, ports, mins) in sorted(talkers.items(), key=lambda kv: -len(kv[1][1]))[:10]:
        print(f"  {ip:<40} {fl:>8} {len(ports):>6} {len(mins):>10}")

    print("\nBursts per candidate pair (flow starts, gaps > 60s split a burst):")
    for (x, grp), ts in sorted(pair_times.items(), key=lambda kv: -len(kv[1])):
        ts.sort()
        runs = bursts(ts)
        print(f"  {x} <-> {grp}: {len(ts)} flows in {len(runs)} burst(s)")
        shown = runs if len(runs) <= a.max_bursts else runs[:a.max_bursts]
        for f, l, c in shown:
            print(f"     {f:%H:%M:%S}-{l:%H:%M:%S} UTC  (= page {f - timedelta(hours=3):%H:%M}-{l - timedelta(hours=3):%H:%M} if +3h)  {c} flows")
        if len(runs) > len(shown):
            print(f"     ... {len(runs) - len(shown)} more")

    print("\nShare of each candidate pair's flows that fall inside the schedule, per offset:")
    groups = defaultdict(list)                # (kind, victim group) -> windows (page time)
    for name, kind, wins, xs, vs in SCHEDULE:
        groups[(kind, "web server" if vs is WEB_SERVER else "botnet victims")] += wins
    print(f"  {'pair':<48} {'attack':<9}" + "".join(f"{'+%dh' % o:>14}" for o in OFFSETS))
    for (x, grp), ts in sorted(pair_times.items(), key=lambda kv: -len(kv[1])):
        for (kind, g), wins in groups.items():
            if g != grp:
                continue
            cells = []
            for o in OFFSETS:
                ws = [window_utc(s, e, o) for s, e in wins]
                hit = sum(any(ws_ <= t <= we for ws_, we in ws) for t in ts)
                cells.append(f"{hit}/{len(ts)} {hit / len(ts):4.0%}")
            print(f"  {x + ' <-> ' + grp:<48} {kind:<9}" + "".join(f"{c:>14}" for c in cells))

def cmd_train(a):
    import joblib
    t0 = time.time()
    out = in_cic(a.out)
    events = sorted(read_jsonl(a.monday), key=lambda e: parse_ts(e["timestamp"]))
    bundle, calib_fp, fit_fp = fit_model(events, a.fp_budget, a.monday)
    bundle.update(calib_fp=calib_fp, fit_fp=fit_fp, n_monday=len(events))   # for the report; Scorer ignores them
    joblib.dump(bundle, out)
    print(f"Monday: {len(events)} flows; fit on {bundle['n_fit']}, calibrated on {bundle['n_calib']} held-out, "
          f"{time.time() - t0:.1f}s -> {out}")
    print(f"threshold {bundle['threshold']:.4f}: flags {calib_fp:.1%} of held-out Monday flows "
          f"(budget {a.fp_budget}%), {fit_fp:.1%} of training flows")

class Labeler:
    """Ground truth for one Friday flow, from the official schedule + the decisions above.
    Returns (label, in_official_window): label is an attack name, 'benign' or 'unlabelled'."""

    def __init__(self):
        self.web = []   # (start, end, name) in UTC, web-server attacks only
        self.botnet_window = None
        self.botnet_victims = set()
        for name, kind, wins, _, victims in SCHEDULE:
            for s_, e_ in wins:
                w = window_utc(s_, e_, OFFSET)
                if kind == "botnet":
                    self.botnet_window, self.botnet_victims = w, set(victims)
                else:
                    self.web.append((*w, name))

    def __call__(self, e, t):
        s, d = e.get("src_ip"), e.get("dest_ip")
        pair = {s, d}
        if BOTNET_CC in pair and (pair - {BOTNET_CC}) <= self.botnet_victims and e.get("proto") == "TCP" \
                and BOTNET_PORT == (e.get("dest_port") if d == BOTNET_CC else e.get("src_port")):
            ws, we = self.botnet_window
            return "Botnet ARES", ws <= t <= we
        if NAT_ATTACKER in pair and pair & set(WEB_SERVER):
            for ws, we, name in self.web:
                if ws <= t <= we:
                    return name, True
            dist, name = min((min(abs((t - ws).total_seconds()), abs((t - we).total_seconds())), n)
                             for ws, we, n in self.web)
            if dist <= SLACK:
                return name, True
        if pair & ATTACKER_IPS:
            return "unlabelled", False
        return "benign", False

def flow_key(proto, a_ip, a_port, b_ip, b_port):
    """Direction-free 5-tuple: an alert may be logged in either direction of its flow.
    ICMP alerts carry ports 0 while ICMP flow events have no ports, so missing = 0."""
    return (proto, frozenset({(a_ip, a_port or 0), (b_ip, b_port or 0)}))

def epoch(s):
    return parse_ts(s).timestamp()

def match_alerts(path, flows, index, by_flow_id=None):
    """Attach each alert to the flow with the same 5-tuple that was open at the alert's time.
    flow_id differs on every Suricata run, so run (b)'s alerts cannot use it; on run (a) the
    5-tuple join is checked against the flow_id join. Returns per-flow alert lists + stats."""
    hits = defaultdict(list)       # flow index -> [(t, sid, signature, category)]
    st = Counter()
    for al in read_jsonl(path):
        sid = al["alert"]["signature_id"]
        if sid in IGNORE_SIDS:
            st["ignored"] += 1
            continue
        t = epoch(al["timestamp"])
        # app-layer alerts can fire when the flow is closed, after its last packet: allow up to "seen"
        cands = [i for i in index.get(flow_key(al.get("proto"), al.get("src_ip"), al.get("src_port"),
                                                al.get("dest_ip"), al.get("dest_port")), ())
                 if flows[i]["start"] - 1 <= t <= flows[i]["seen"] + 1]
        i = max(cands, key=lambda i: flows[i]["start"]) if cands else None
        if by_flow_id is not None:
            st["id_agree" if by_flow_id.get(al.get("flow_id")) == i else "id_disagree"] += 1
        if i is None:
            st["unmatched"] += 1
            continue
        st["matched"] += 1
        hits[i].append((t, sid, al["alert"]["signature"], al["alert"].get("category", "")))
    return hits, st

def pct(n, d):
    return f"{n / d:6.1%}" if d else "     -"

def cmd_report(a):
    import joblib
    t0 = time.time()
    out = in_cic(a.out)
    bundle = joblib.load(a.model)
    label = Labeler()

    # 1. Friday in time order, as the live pipeline would see it
    events = sorted(read_jsonl(a.friday), key=lambda e: parse_ts(e["timestamp"]))
    flows, index, by_flow_id = [], defaultdict(list), {}
    for i, e in enumerate(events):
        start = utc(e["flow"]["start"])
        lab, inwin = label(e, start)
        end = epoch(e["flow"]["end"])
        # "seen" = when the flow record exists (pipeline can score it). In pcap replay the event
        # timestamp is the flow manager's clock and is sometimes before the flow's end, so take the max.
        flows.append({"label": lab, "in_window": inwin, "start": start.timestamp(), "end": end,
                      "seen": max(epoch(e["timestamp"]), end), "src": e.get("src_ip"),
                      "usable": False, "anomaly": False})
        index[flow_key(e.get("proto"), e.get("src_ip"), e.get("src_port"), e.get("dest_ip"), e.get("dest_port"))].append(i)
        if "flow_id" in e:
            by_flow_id[e["flow_id"]] = i
        e["_i"] = i
    print(f"read + labelled {len(flows)} Friday flows, {time.time() - t0:.0f}s")

    # 2. anomaly detector: the live code path (Scorer + SourceWindow), Monday model and threshold
    sc = Scorer(a.model)
    for e in events:
        sc.add(e)
    for (e, _), flag in zip(sc.buf, sc.flags()):
        flows[e["_i"]].update(usable=True, anomaly=bool(flag))
    sc.buf = []
    n_excluded = sum(excluded(e) for e in events)
    del events
    print(f"scored {sum(f['usable'] for f in flows)} usable flows, {time.time() - t0:.0f}s")

    # 3. Suricata: both runs, joined to the same flows
    runs = []
    for name, path in a.alerts:
        hits, st = match_alerts(path, flows, index, by_flow_id if name == ALERTS[0][0] else None)
        runs.append((name, hits, st))
        print(f"{name}: {dict(st)}")

    # 4. tables. Denominators are usable flows (what both detectors see in the pipeline);
    #    the broadcast-filtered rest is reported separately.
    names = [n for n, *_ in SCHEDULE]
    rows = [("Botnet ARES", lambda f: f["label"] == "Botnet ARES"),
            ("  in official window", lambda f: f["label"] == "Botnet ARES" and f["in_window"])] + \
           [(n, (lambda n: lambda f: f["label"] == n)(n)) for n in names[1:]] + \
           [("ALL ATTACKS", lambda f: f["label"] in names)]
    run_names = [n for n, *_ in runs]
    res = {"config": {"offset_hours": OFFSET, "nat_attacker": NAT_ATTACKER, "botnet": f"{BOTNET_CC}:{BOTNET_PORT} all day",
                      "slack_s": SLACK, "ignored_sids": sorted(IGNORE_SIDS), "schedule": "https://www.unb.ca/cic/datasets/ids-2017.html",
                      "alerts": dict(a.alerts)},
           "model": {k: bundle.get(k) for k in ("threshold", "fp_budget", "n_fit", "n_calib", "calib_fp", "fit_fp", "n_monday", "sklearn")},
           "labels": Counter(f["label"] for f in flows), "excluded_by_broadcast_filter": n_excluded,
           "join": {n: dict(st) for n, _, st in runs}, "attacks": {}, "false_positives": {}, "analyst_load": {}}
    try:
        res["provenance"] = open(os.path.join(DIR, "provenance.txt")).read()
    except FileNotFoundError:
        pass

    print(f"\nModel (Monday): threshold {bundle['threshold']:.4f}, fit {bundle['n_fit']} / calibration {bundle['n_calib']}, "
          f"held-out Monday FP {bundle.get('calib_fp', float('nan')):.1%} (budget {bundle['fp_budget']}%)")
    print(f"Friday labels: {dict(res['labels'])}; {n_excluded} flows dropped by the broadcast/multicast filter")

    print("\nPer attack, share of usable attack flows detected (flow level):")
    hdr = f"  {'attack':<24} {'flows':>7} {'anomaly':>8}" + "".join(f"{'Suri ' + n:>17}" for n in run_names) + \
          "".join(f"{'either ' + n:>19}" for n in run_names)
    print(hdr)
    for name, sel in rows:
        fs = [i for i, f in enumerate(flows) if sel(f) and f["usable"]]
        n_all = sum(1 for f in flows if sel(f))
        r = {"flows": len(fs), "flows_incl_filtered": n_all}
        if not fs:
            print(f"  {name:<24} {0:>7}   no flows observed, can't be evaluated")
            r["evaluable"] = False
            res["attacks"][name] = r
            continue
        an = [i for i in fs if flows[i]["anomaly"]]
        r["anomaly"] = len(an)
        line = f"  {name:<24} {len(fs):>7} {pct(len(an), len(fs)):>8}"
        for rn, hits, _ in runs:
            su = [i for i in fs if i in hits]
            r[f"suricata {rn}"] = len(su)
            line += f"{pct(len(su), len(fs)):>17}"
        for rn, hits, _ in runs:
            ei = sum(1 for i in fs if i in hits or flows[i]["anomaly"])
            r[f"either {rn}"] = ei
            line += f"{pct(ei, len(fs)):>19}"
        print(line)
        # event level: detected at all, and how long after the attack's (first flow's) start
        t_first = min(flows[i]["start"] for i in fs)
        r["first_flow_utc"] = datetime.fromtimestamp(t_first, timezone.utc).isoformat()
        r["first_detection_s"] = {"anomaly": round(min(flows[i]["seen"] for i in an) - t_first) if an else None}
        for rn, hits, _ in runs:
            ts = [t for i in fs for t, *_ in hits.get(i, ())]
            r["first_detection_s"][f"suricata {rn}"] = round(min(ts) - t_first) if ts else None
            ts = [t for i in fs for t, sid, *_ in hits.get(i, ()) if sid not in ENGINE_SIDS]
            r["first_detection_s"][f"suricata {rn} signatures only"] = round(min(ts) - t_first) if ts else None
            r[f"signatures {rn}"] = Counter(sig for i in fs for _, _, sig, _ in {x[1:]: x for x in hits.get(i, ())}.values()).most_common(5)
        res["attacks"][name] = r

    print("\nEvent level: seconds from the attack's first flow to the first detection (- = never).")
    print("  Suricata: alert time. Anomaly: when the flagged flow's record exists (flow end or timeout), before")
    print("  the pipeline's 30s batch. Flow-level rates undersell Suricata: scan rules fire once per threshold,")
    print("  not on every flow, so event level is the fair comparison for signatures.")
    print("  'sig only' leaves out SURICATA stream/decoder events (SIDs 2200000-2299999): they are protocol")
    print("  oddities that also fire on benign traffic, not attack signatures.")
    print(f"  {'attack':<24} {'anomaly':>9}" + "".join(f"{'Suri ' + n:>17}{'sig only':>10}" for n in run_names))
    for name, r in res["attacks"].items():
        if r.get("evaluable") is False or name == "ALL ATTACKS":
            continue
        fd = r["first_detection_s"]
        cell = lambda v: "-" if v is None else f"{v}s"
        print(f"  {name:<24} {cell(fd['anomaly']):>9}" + "".join(
            f"{cell(fd['suricata ' + n]):>17}{cell(fd['suricata ' + n + ' signatures only']):>10}" for n in run_names))

    print("\nSignatures per attack (flows with that signature, top 3):")
    for name, r in res["attacks"].items():
        for rn in run_names:
            sigs = r.get(f"signatures {rn}")
            if sigs:
                print(f"  {name} [{rn}]: " + "; ".join(f"{s} ({n})" for s, n in sigs[:3]))

    # false positives on benign Friday flows
    ben = [i for i, f in enumerate(flows) if f["label"] == "benign" and f["usable"]]
    hours = (max(f["seen"] for f in flows) - min(f["start"] for f in flows)) / 3600
    fp = {"benign_flows": len(ben), "anomaly": sum(flows[i]["anomaly"] for i in ben),
          "monday_heldout_fp": bundle.get("calib_fp")}
    print(f"\nFalse positives on {len(ben)} usable benign Friday flows ({hours:.1f} h):")
    print(f"  anomaly: {fp['anomaly']} = {pct(fp['anomaly'], len(ben)).strip()}  "
          f"(held-out Monday: {bundle.get('calib_fp', float('nan')):.1%}, by construction ~{bundle['fp_budget']}%)")
    for rn, hits, _ in runs:
        any_ = [i for i in ben if i in hits]
        sig = [i for i in ben if any(sid not in ENGINE_SIDS for _, sid, *_ in hits[i])]
        fp[f"suricata {rn}"] = len(any_)
        fp[f"suricata {rn} excl. engine events"] = len(sig)
        top = Counter(s for i in any_ for s in {x[2] for x in hits[i]}).most_common(3)
        fp[f"suricata {rn} top"] = top
        print(f"  Suri {rn}: {len(any_)} = {pct(len(any_), len(ben)).strip()}; excluding SURICATA stream/decoder "
              f"events: {len(sig)} = {pct(len(sig), len(ben)).strip()}")
        print("     top: " + "; ".join(f"{s} ({n})" for s, n in top))
    res["false_positives"] = fp

    # analyst load: rows per hour, batched like the pipeline (before collapse(), so an upper bound)
    load = {"hours": round(hours, 2)}
    for scope, keep in (("all", lambda f: True), ("benign", lambda f: f["label"] == "benign")):
        load[f"anomaly rows/h ({scope})"] = round(len({(f["src"], int(f["seen"] // BATCH)) for f in flows
                                                       if f["anomaly"] and keep(f)}) / hours, 1)
        for rn, hits, _ in runs:
            load[f"suricata {rn} rows/h ({scope})"] = round(len({(sid, flows[i]["src"], int(t // BATCH))
                for i, hs in hits.items() if keep(flows[i]) for t, sid, *_ in hs}) / hours, 1)
    res["analyst_load"] = load
    print("\nAnalyst load (rows per hour, 30s batches like pipeline.py, before collapse()):")
    for k, v in load.items():
        if k != "hours":
            print(f"  {k}: {v}")

    print("\nCaveats: labels come from the CIC schedule (time + IP), not per-packet ground truth; the Botnet label "
          "extends past the official window (see config); this is a Monday-trained CIC model, so it measures the "
          "method, not the Pi's model; Suricata 7.0.3 + laptop ET Open rules, not the Pi's 8.0.7; CIC CSV labels unused.")
    with open(out, "w") as f:
        json.dump(res, f, indent=1, default=str)
    print(f"\n-> {out} ({time.time() - t0:.0f}s)")

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    v = sub.add_parser("verify", help="compare the official schedule with the Friday traffic (writes nothing)")
    v.add_argument("--friday", default=FRIDAY)
    v.add_argument("--monday", default=MONDAY)
    v.add_argument("--max-bursts", type=int, default=25)
    v.set_defaults(func=cmd_verify)
    t = sub.add_parser("train", help="fit a separate anomaly model on Monday (same code as anomaly.py train)")
    t.add_argument("--monday", default=MONDAY)
    t.add_argument("--fp-budget", type=float, default=FP_BUDGET)
    t.add_argument("--out", default=MODEL)
    t.set_defaults(func=cmd_train)
    r = sub.add_parser("report", help="label Friday, score both detectors, write cic/results.json")
    r.add_argument("--friday", default=FRIDAY)
    r.add_argument("--model", default=MODEL)
    r.add_argument("--alerts", nargs=2, action="append", metavar=("NAME", "FILE"),
                   help=f"Suricata alert file(s); default: {', '.join(n for n, _ in ALERTS)}")
    r.add_argument("--out", default=RESULTS)
    r.set_defaults(func=cmd_report)
    a = ap.parse_args()
    if a.cmd == "report" and not a.alerts:
        a.alerts = ALERTS
    a.func(a)

if __name__ == "__main__":
    main()
