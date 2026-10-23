"""Replay a pcap into the CIC demo's dummy interface at original speed, every frame whole.

  sudo python3 -I cic_replay.py cic/replay/fri_scan.pcap [--iface cic0] [--limit N]

Why not tcpreplay: the CIC-IDS2017 capture host coalesced packets (GRO/TSO), so frames reach
11,649 bytes (79% of the DDoS slice's bytes are in frames over 1514 B). Kali's tcpreplay 4.5.4
sends through a TX_RING with 4096-byte slots: larger frames are truncated and the ring jams
(TP_STATUS_WRONG_FORMAT). Truncating (--mtu-trunc) or splitting would change the byte/packet
counts the anomaly model scores, so the replay would no longer match the CIC evaluation, which
read the pcap whole (suricata -r). This sends each frame with one send() on a raw socket.

Safety: refuses any interface that is not a Linux `dummy` device (no peer, no wire, drops every
frame it sends), so it cannot put attack traffic on wlan0/eth0, even by a typo. Speed is fixed at
1x: a faster replay would compress the 60 s per-source window features. Standard library only.
"""
import argparse, json, signal, socket, struct, subprocess, sys, time

MAGIC = {b"\xd4\xc3\xb2\xa1": ("<", 1e-6), b"\xa1\xb2\xc3\xd4": (">", 1e-6),   # microsecond pcap
         b"\x4d\x3c\xb2\xa1": ("<", 1e-9), b"\xa1\xb2\x3c\x4d": (">", 1e-9)}   # nanosecond pcap
LINKTYPE_ETHERNET = 1
ETH_HEADER = 14


def dummy_mtu(iface):
    """The interface's MTU if it is a dummy device; exits otherwise."""
    out = subprocess.run(["ip", "-d", "-j", "link", "show", "dev", iface], capture_output=True, text=True)
    try:
        link, = json.loads(out.stdout)
    except ValueError:
        sys.exit(f"{iface}: no such interface")
    if link.get("linkinfo", {}).get("info_kind") != "dummy":
        sys.exit(f"{iface} is not a dummy interface: refusing to replay attack traffic onto it")
    if "UP" not in link.get("flags", []):
        sys.exit(f"{iface} is down: ip link set {iface} up")
    return link["mtu"]


def frames(path):
    """(timestamp, frame) from a classic pcap file."""
    with open(path, "rb") as f:
        head = f.read(24)
        if head[:4] not in MAGIC:
            sys.exit(f"{path}: not a classic pcap file (pcapng? convert with editcap -F pcap)")
        endian, unit = MAGIC[head[:4]]
        if struct.unpack(endian + "I", head[20:24])[0] & 0xFFFF != LINKTYPE_ETHERNET:
            sys.exit(f"{path}: link type is not Ethernet")
        while len(h := f.read(16)) == 16:
            sec, frac, incl, _ = struct.unpack(endian + "IIII", h)
            yield sec + frac * unit, f.read(incl)


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--iface", default="cic0")
    ap.add_argument("--limit", type=int, help="stop after this many frames (capture test)")
    a = ap.parse_args()
    mtu = dummy_mtu(a.iface)
    biggest = max(len(fr) for _, fr in frames(a.pcap))   # preflight: refuse rather than send cut frames
    if biggest - ETH_HEADER > mtu:
        sys.exit(f"largest frame is {biggest} B but {a.iface} MTU is {mtu}: "
                 f"ip link set {a.iface} mtu {biggest - ETH_HEADER}, then restart Suricata (it reads the MTU at start)")
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
    s.bind((a.iface, 0))
    stop = []
    signal.signal(signal.SIGINT, lambda *_: stop.append(1))
    sent = failed = 0
    max_lag = 0.0
    start = time.strftime("%F %T")
    t0 = wall0 = None
    next_report = time.monotonic() + 30
    for ts, frame in frames(a.pcap):
        if stop or (a.limit and sent + failed >= a.limit):
            break
        now = time.monotonic()
        if t0 is None:
            t0, wall0 = ts, now
        delay = wall0 + (ts - t0) - now
        if delay > 0:
            time.sleep(delay)
        else:
            max_lag = max(max_lag, -delay)
        try:
            s.send(frame)
            sent += 1
        except OSError as err:
            failed += 1
            if failed <= 5:
                print(f"frame {sent + failed} ({len(frame)} B): {err}", file=sys.stderr)
        if time.monotonic() >= next_report:
            print(f"{time.strftime('%T')}  sent {sent}  failed {failed}  pcap time +{ts - t0:.0f}s  "
                  f"max lag {max_lag * 1000:.0f} ms", flush=True)
            next_report += 30
    span = (ts - t0) if t0 is not None else 0
    print(f"{'interrupted' if stop else 'done'}: {a.pcap} -> {a.iface}, started {start}, ended {time.strftime('%F %T')}\n"
          f"  sent {sent}, failed {failed}, pcap span {span:.1f}s, wall {time.monotonic() - wall0 if wall0 else 0:.1f}s, "
          f"largest frame {biggest} B, max lag behind original timing {max_lag * 1000:.0f} ms")


if __name__ == "__main__":
    main()
