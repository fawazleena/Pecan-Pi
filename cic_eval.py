"""CIC-IDS2017 evaluation of both detectors (anomaly model + Suricata signatures).

Monday (benign) trains a SEPARATE anomaly model with the same code as the Pi's model
(anomaly.fit_model); Friday (attacks) is labelled from the official CIC schedule and
scored. Everything reads and writes under cic/ (gitignored); the live model and the
baseline files are never touched.

Usage:
  cic_eval.py verify                   # schedule vs traffic: timezone + attacker IPs; writes nothing
  nice -n 19 cic_eval.py train         # Monday -> cic/model.joblib
"""
import argparse, os, sys, time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone

from anomaly import FP_BUDGET, fit_model, parse_ts, read_jsonl

DIR = "cic"
MONDAY = os.path.join(DIR, "monday_flows.jsonl.gz")
FRIDAY = os.path.join(DIR, "friday_flows.jsonl.gz")
MODEL = os.path.join(DIR, "model.joblib")

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
    joblib.dump(bundle, out)
    print(f"Monday: {len(events)} flows; fit on {bundle['n_fit']}, calibrated on {bundle['n_calib']} held-out, "
          f"{time.time() - t0:.1f}s -> {out}")
    print(f"threshold {bundle['threshold']:.4f}: flags {calib_fp:.1%} of held-out Monday flows "
          f"(budget {a.fp_budget}%), {fit_fp:.1%} of training flows")

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
    a = ap.parse_args()
    a.func(a)

if __name__ == "__main__":
    main()
