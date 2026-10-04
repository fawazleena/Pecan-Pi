"""Build offline replay files for testing anomaly.py without touching the network.

Splits a snapshot of real flows by time into train.jsonl (older 80%; `anomaly.py
train` splits it again into fit + calibration) and holdout.jsonl (newest 20%, the
test set), then merges synthetic attack flows (shaped like Suricata flow events)
into copies of the test set only, so attacks never influence the threshold.

Usage:
  make_replay.py SNAPSHOT --pi 192.168.160.145 --peer 192.168.160.65 [--out-dir replay]
Then:
  anomaly.py train --baseline replay/train.jsonl --out replay/model.joblib
  anomaly.py eval replay/holdout.jsonl --model replay/model.joblib     # negative control
  anomaly.py eval replay/scan_pi_to_peer.jsonl --model replay/model.joblib
"""
import argparse, json, os, random
from datetime import datetime, timedelta

from anomaly import parse_ts, read_jsonl

PI_MAC, PEER_MAC = "e4:5f:01:9c:86:2b", "02:00:00:00:00:65"

def fmt(t):
    return t.strftime("%Y-%m-%dT%H:%M:%S.%f+0000")

def flow(t, src, sport, dst, dport, proto, pts, ptc, bts, btc, state, smac, dmac):
    return {"timestamp": fmt(t + timedelta(seconds=60)), "flow_id": random.getrandbits(50),
            "in_iface": "wlan0", "event_type": "flow", "src_ip": src, "src_port": sport,
            "dest_ip": dst, "dest_port": dport, "proto": proto,
            "ether": {"dest_macs": [dmac], "src_macs": [smac]},
            "flow": {"pkts_toserver": pts, "pkts_toclient": ptc, "bytes_toserver": bts,
                     "bytes_toclient": btc, "start": fmt(t), "end": fmt(t + timedelta(milliseconds=2)),
                     "age": 0, "state": state, "reason": "timeout", "alerted": False},
            "synthetic": True}

def connect_scan(t0, src, dst, ports, seconds, smac, dmac, open_ports=(22, 80)):
    """nmap -sT: closed port = SYN / RST; open port = SYN, ACK, RST / SYN-ACK."""
    out = []
    for i, p in enumerate(ports):
        t = t0 + timedelta(seconds=seconds * i / len(ports))
        if p in open_ports:
            out.append(flow(t, src, random.randint(40000, 60000), dst, p, "TCP", 3, 1, 174, 60, "closed", smac, dmac))
        else:
            out.append(flow(t, src, random.randint(40000, 60000), dst, p, "TCP", 1, 1, 60, 54, "closed", smac, dmac))
    return out

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("snapshot")
    ap.add_argument("--pi", required=True)
    ap.add_argument("--peer", required=True)
    ap.add_argument("--out-dir", default="replay")
    ap.add_argument("--train-fraction", type=float, default=0.8)
    a = ap.parse_args()
    random.seed(42)
    os.makedirs(a.out_dir, exist_ok=True)

    events = sorted(read_jsonl(a.snapshot), key=lambda e: parse_ts(e["timestamp"]))
    cut = int(len(events) * a.train_fraction)
    train, holdout = events[:cut], events[cut:]
    t0 = parse_ts(holdout[len(holdout) // 2]["timestamp"])  # inject mid-holdout

    ports = random.sample(range(1, 10000), 1000)
    scenarios = {
        # appliance scans a host on the LAN (nmap --top-ports 1000, ~15s)
        "scan_pi_to_peer": connect_scan(t0, a.pi, a.peer, ports, 15, PI_MAC, PEER_MAC),
        # attacker laptop scans the appliance
        "scan_peer_to_pi": connect_scan(t0, a.peer, a.pi, ports, 15, PEER_MAC, PI_MAC),
        # slower, smaller scan: 100 ports over 60s (harder case)
        "slow_scan_peer_to_pi": connect_scan(t0, a.peer, a.pi, ports[:100], 60, PEER_MAC, PI_MAC),
        # horizontal sweep: port 22 on 50 hosts
        "sweep_pi_ssh": [flow(t0 + timedelta(seconds=i * 0.2), a.pi, 50000 + i,
                              a.pi.rsplit(".", 1)[0] + f".{i + 2}", 22, "TCP", 1, 0, 60, 0, "new", PI_MAC, PEER_MAC)
                         for i in range(50)],
    }

    def write(name, evs):
        evs = sorted(evs, key=lambda e: parse_ts(e["timestamp"]))
        with open(os.path.join(a.out_dir, name + ".jsonl"), "w") as f:
            f.writelines(json.dumps(e) + "\n" for e in evs)
        print(f"{name}.jsonl: {len(evs)} flows")

    write("train", train)
    write("holdout", holdout)
    for name, evs in scenarios.items():
        write(name, holdout + evs)

if __name__ == "__main__":
    main()
