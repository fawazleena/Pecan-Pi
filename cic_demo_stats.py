"""Numbers for the report from one CIC-IDS2017 demo replay (docs/cic-demo.md). Read-only.

  .venv/bin/python cic_demo_stats.py --t0 "2026-10-24 00:30:08" --t1 "2026-10-24 00:35:10" --t2 "2026-10-24 00:40:12"

Times are local (the T0/T1/T2 lines printed around the replay: start, scan -> DDoS, end). Flows on
cic0 that started in [T0, T1) belong to the scan slice, [T1, T2] to the DDoS slice. A flow is an
attack flow if 172.16.0.1 is one end (cic_eval.NAT_ATTACKER: in these windows all scan and DDoS
traffic arrives from it). Per-flow decisions are recomputed offline with the installed model in
eve.json order (the order the live pipeline saw them), so they match the live scorer.
"""
import argparse, sqlite3, subprocess
from collections import Counter
from datetime import datetime, timedelta
from anomaly import Scorer, eve_files, read_flows, parse_ts, excluded, EVE
from netinfo import REPLAY_IFACE, REPLAY_TAG

ATTACKER = "172.16.0.1"
MODEL = "/opt/pecan/anomaly_model.joblib"
TAIL = timedelta(minutes=11)   # flow records arrive up to the 600 s TCP timeout after the replay


def local(s):
    return datetime.fromisoformat(s).astimezone()


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    for k in ("t0", "t1", "t2"):
        ap.add_argument("--" + k, required=True, type=local)
    ap.add_argument("--model", default=MODEL)
    ap.add_argument("--db", default="pecan.db")
    a = ap.parse_args()
    end = a.t2 + TAIL

    # --- flows: offline per-flow decisions with the live code path -------------------------------
    sc = Scorer(a.model)
    flows = [e for e in read_flows(eve_files(EVE)) if e.get("in_iface") == REPLAY_IFACE
             and a.t0 <= parse_ts(e["flow"]["start"]) <= a.t2]
    n_excluded = sum(excluded(e) for e in flows)
    for e in flows:
        sc.add(e)
    flags = sc.flags()
    print(f"cic0 flows started in [T0, T2]: {len(flows)} ({n_excluded} broadcast/multicast excluded, "
          f"{len(sc.buf)} scored)\n")
    print(f"{'slice':<6} {'class':<8} {'flows':>7} {'flagged':>8} {'rate':>7}   first flagged (after slice start)")
    for name, lo, hi in (("scan", a.t0, a.t1), ("ddos", a.t1, a.t2 + timedelta(seconds=1))):
        for cls, want in (("attack", True), ("benign", False)):
            rows = [(e, f) for (e, _), f in zip(sc.buf, flags)
                    if lo <= parse_ts(e["flow"]["start"]) < hi
                    and (ATTACKER in (e.get("src_ip"), e.get("dest_ip"))) == want]
            hit = [e for e, f in rows if f]
            first = min((parse_ts(e["flow"]["start"]) for e in hit), default=None)
            print(f"{name:<6} {cls:<8} {len(rows):>7} {len(hit):>8} {len(hit) / len(rows) if rows else 0:>7.1%}   "
                  + (f"+{(first - lo).total_seconds():.0f}s (flow start)" if first else "-"))
        atk = [parse_ts(e["flow"]["start"]) for e, _ in sc.buf if lo <= parse_ts(e["flow"]["start"]) < hi
               and ATTACKER in (e.get("src_ip"), e.get("dest_ip"))]
        if atk:
            print(f"{'':<6} first attack flow starts +{(min(atk) - lo).total_seconds():.0f}s after slice start")

    # --- the live pipeline: per-flush counters, rows, verdicts, Groq --------------------------------
    since, until = a.t0.strftime("%F %T"), end.strftime("%F %T")
    log = subprocess.run(["journalctl", "-u", "pecan-pipeline", "--since", since, "--until", until, "--no-pager",
                          "-q", "-o", "cat"], capture_output=True, text=True).stdout.splitlines()
    scored = [l.split() for l in log if l.startswith("anomaly: scored")]
    print(f"\nlive pipeline {since} -> {until}: {sum(int(s[2]) for s in scored)} flows scored, "
          f"{sum(int(s[-1]) for s in scored)} flagged, in {len(scored)} batches")
    left = [l for l in log if l.startswith("groq limits")]
    if left:
        print(f"Groq: first call '{left[0].split(': ', 1)[1].split(' (')[0]}', last '{left[-1].split(': ', 1)[1].split(' (')[0]}' "
              f"({len(left)} calls, live Pi rows included)")
    db = sqlite3.connect(f"file:{a.db}?mode=ro", uri=True)
    w = (f"{REPLAY_TAG}%", a.t0.isoformat(), end.isoformat())   # SQLite datetime() normalises both to UTC
    q = ("FROM alerts WHERE reason LIKE ? AND datetime(seen_at) >= datetime(?) AND datetime(seen_at) <= datetime(?)")
    print(f"\n[cic-replay] rows: " + ", ".join(f"{d} {n}" for d, n in db.execute(
        f"SELECT detection, COUNT(*) {q} GROUP BY detection", w)))
    for d, v, p, n in db.execute(f"SELECT detection, verdict, priority, COUNT(*) {q} GROUP BY 1, 2, 3 ORDER BY 1, 4 DESC", w):
        print(f"  {d:<10} {v:<11} {p:<8} {n}")
    print("\nanomaly rows involving the attacker (time = batch time, local):")
    for row in db.execute(f"SELECT id, seen_at, src_ip, dest_ip, count, score, verdict, priority, signature {q} "
                          "AND detection = 'anomaly' AND (src_ip = ? OR dest_ip = ?) ORDER BY id", (*w, ATTACKER, ATTACKER)):
        i, t, s, dst, n, score, v, p, sig = row
        print(f"  {i} {local(t):%H:%M:%S} {s} -> {dst} x{n} score {score} {v}/{p}  {sig.split(': ', 1)[1][:60]}")
    print("\nsignature rows:")
    for sig, n, c in db.execute(f"SELECT signature, COUNT(*), SUM(count) {q} AND detection = 'signature' "
                                "GROUP BY signature ORDER BY 3 DESC", w):
        print(f"  {c:>6} events in {n:>3} rows  {sig}")


if __name__ == "__main__":
    main()
