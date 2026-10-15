"""Decoy SSH service with automatic, reversible nftables blocking (the prevention part of the IDPS).

Nothing legitimate runs on the decoy port, so any completed connection to it is unsolicited.
On each connection: block the source at wlan0/eth0 (unless allowlisted), send a real-looking
OpenSSH banner, read at most READ_BYTES of the client's reply, close. There is no authentication,
no shell and no parsing: attacker bytes are only stored, truncated and made printable.
Each hit is appended as one JSON line to honeypot.json, which pipeline.py tails for AI triage.

Blocks expire on their own (nftables set timeout). Stopping the service or rebooting deletes
the table, which lifts every block.

    honeypot.py serve [--port 2222] [--block-seconds 600] [--dry-run]   # run by pecan-honeypot.service
    sudo honeypot.py list | unblock IP | unblock-all
"""
import argparse, asyncio, ipaddress, json, os, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path
from netinfo import host_ips, gateways, iface_ips

PORT = 2222
BLOCK_SECONDS = int(os.environ.get("PECAN_BLOCK_SECONDS", 3600))
BANNER = b"SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3\r\n"
READ_BYTES = 256        # enough for a client banner; nothing more is ever read
READ_SECONDS = 10
BANNER_CHARS = 128      # stored copy of what the client sent
MAX_CONNECTIONS = 50    # beyond this, connections are still logged and blocked, but closed at once
LOG = Path(os.environ.get("LOGS_DIRECTORY", "/var/log/pecan")) / "honeypot.json"
ALLOWLIST = Path(__file__).with_name("allowlist.txt")
NFT = "/usr/sbin/nft"
TABLE = ("inet", "pecan")
TAILSCALE_IFACE = "tailscale0"
WIREGUARD_PORT = 41641  # tailscaled's UDP port (/etc/default/tailscaled)

# Applied as one transaction: create-then-delete makes it idempotent, so a restart starts clean.
RULESET = """
table inet pecan
delete table inet pecan
table inet pecan {
  set blocked4 { type ipv4_addr; flags timeout; size 1024; }
  set blocked6 { type ipv6_addr; flags timeout; size 1024; }
  chain input {
    type filter hook input priority -10; policy accept;
    iifname != { "wlan0", "eth0" } return
    udp dport %(wg)d return
    tcp dport %(port)d ct state established return
    ip saddr @blocked4 counter drop
    ip6 saddr @blocked6 counter drop
  }
}
"""
# iifname: only the Pi's physical interfaces; tailscale0 (SSH over Tailscale) and lo are never touched.
# udp dport: Tailscale's direct WireGuard path to a blocked LAN IP keeps working; WireGuard ignores
#   packets from unauthenticated peers, so this gives an attacker nothing.
# tcp dport ... established: lets the decoy finish the connection that caused the block
#   (so it can read the client banner); new connections from a blocked IP are dropped.


def nft(*args, stdin=None):
    return subprocess.run([NFT, *args], input=stdin, capture_output=True, text=True, timeout=10)


def setup_nft(port):
    r = nft("-f", "-", stdin=RULESET % {"wg": WIREGUARD_PORT, "port": port})
    if r.returncode:
        sys.exit(f"nftables setup failed: {r.stderr.strip()}")


def set_for(ip):
    return "blocked4" if ipaddress.ip_address(ip).version == 4 else "blocked6"


def block(ip, seconds):
    s = set_for(ip)
    if nft("get", "element", *TABLE, s, f"{{ {ip} }}").returncode == 0:
        return "already blocked"
    r = nft("add", "element", *TABLE, s, f"{{ {ip} timeout {seconds}s }}")
    return f"blocked {seconds}s" if r.returncode == 0 else f"block failed: {r.stderr.strip()}"


def load_allowlist():
    nets = []
    try:
        lines = ALLOWLIST.read_text().splitlines()
    except FileNotFoundError:
        return nets
    for line in lines:
        line = line.split("#")[0].strip()
        if line:
            try:
                nets.append(ipaddress.ip_network(line, strict=False))
            except ValueError:
                print(f"allowlist.txt: ignoring {line!r}")
    return nets


def allowlisted(src, local):
    """Why src must never be blocked, or None. Re-read at every hit: hotspot IPs change."""
    ip = ipaddress.ip_address(src)
    if ip.is_loopback:
        return "loopback"
    # By interface, not by address range: 100.64.0.0/10 is also carrier-grade NAT space,
    # so a real attacker on wlan0 can have such an address.
    if local in iface_ips(TAILSCALE_IFACE):
        return "arrived over Tailscale"
    if src in host_ips():
        return "the Pi itself"
    if src in gateways():
        return "default gateway"
    for net in load_allowlist():
        if ip in net:
            return f"allowlist.txt {net}"
    return None


def printable(data):
    return bytes(b if 32 <= b < 127 else 63 for b in data.rstrip(b"\r\n")).decode()[:BANNER_CHARS]


def log(hit):
    line = json.dumps(hit)
    print(line)
    with open(LOG, "a") as f:
        f.write(line + "\n")


async def serve(port, seconds, dry_run):
    if not dry_run:
        setup_nft(port)
    active = 0

    async def on_connect(reader, writer):
        nonlocal active
        peer, local = writer.get_extra_info("peername"), writer.get_extra_info("sockname")
        src, dst = peer[0].split("%")[0], local[0].split("%")[0]  # strip IPv6 scope id
        hit = {"timestamp": datetime.now(timezone.utc).isoformat(), "src_ip": src, "src_port": peer[1],
               "dest_ip": dst, "dest_port": local[1]}
        # Block first, before talking: the handshake is complete, so src is not spoofed.
        why = await asyncio.to_thread(allowlisted, src, dst)
        if why:
            action = f"not blocked: allowlisted ({why})"
        elif dry_run:
            action = f"dry run: would block {seconds}s"
        else:
            action = await asyncio.to_thread(block, src, seconds)
        data = b""
        active += 1
        try:
            if active <= MAX_CONNECTIONS:
                writer.write(BANNER)
                await writer.drain()
                data = await asyncio.wait_for(reader.read(READ_BYTES), READ_SECONDS)
        except (TimeoutError, OSError):
            pass
        finally:
            active -= 1
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass
        hit.update(client_banner=printable(data), bytes=len(data), action=action)
        log(hit)

    server = await asyncio.start_server(on_connect, host=None, port=port)  # all IPv4 + IPv6 addresses
    print(f"honeypot listening on port {port}, block {seconds}s{' (dry run)' if dry_run else ''}, log {LOG}")
    async with server:
        await server.serve_forever()


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve")
    s.add_argument("--port", type=int, default=PORT)
    s.add_argument("--block-seconds", type=int, default=BLOCK_SECONDS)
    s.add_argument("--dry-run", action="store_true", help="log hits but never touch nftables")
    sub.add_parser("list")
    u = sub.add_parser("unblock")
    u.add_argument("ip")
    sub.add_parser("unblock-all")
    a = p.parse_args()

    if a.cmd == "serve":
        asyncio.run(serve(a.port, a.block_seconds, a.dry_run))
        return
    if a.cmd == "list":
        for s in ("blocked4", "blocked6"):
            r = nft("list", "set", *TABLE, s)
            print(r.stdout or r.stderr, end="")
        return
    if a.cmd == "unblock":
        r = nft("delete", "element", *TABLE, set_for(a.ip), f"{{ {a.ip} }}")
    else:
        r = nft("-f", "-", stdin="flush set inet pecan blocked4\nflush set inet pecan blocked6\n")
    print(r.stderr.strip() or "done")
    sys.exit(r.returncode)


if __name__ == "__main__":
    main()
