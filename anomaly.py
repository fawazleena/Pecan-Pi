"""Anomaly detection on Suricata flow events (Isolation Forest).

Usage:
  anomaly.py snapshot --since 2026-10-05 [--until 2026-10-07T18:00] [--out baseline_flows.jsonl]
"""
import argparse, glob, gzip, ipaddress, json, os, re, sys
from datetime import datetime

EVE = "/var/log/suricata/eve.json"
BASELINE = "baseline_flows.jsonl"

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

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("snapshot", help="copy flow events from eve.json (+ rotated files) into a baseline file")
    s.add_argument("--since", required=True, help="local time, e.g. 2026-10-05 or 2026-10-05T14:00")
    s.add_argument("--until")
    s.add_argument("--out", default=BASELINE)
    s.set_defaults(func=cmd_snapshot)
    a = ap.parse_args()
    a.func(a)

if __name__ == "__main__":
    main()
