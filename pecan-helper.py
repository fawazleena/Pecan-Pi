#!/usr/bin/python3 -I
"""Pecan Pi root helper: the only thing the panel may run as root (one sudoers line).

Fixed subcommands, argv only, every argument validated here again (the panel is not trusted).
Standard library only and isolated (-I): it imports nothing from ~/pecan-pi or the venv, which
raven can write. Installed by copy, root:root 0755:

    sudo install -o root -g root -m 0755 pecan-helper.py /usr/local/sbin/pecan-helper

Every call is logged to the journal (journalctl -t pecan-helper) with its arguments and result.

    pecan-helper set-switch signatures|anomaly|auto_block|ai on|off
    pecan-helper list-add allow|deny IP-or-CIDR [NOTE]
    pecan-helper list-remove allow|deny IP-or-CIDR
    pecan-helper list-blocks            # JSON: the honeypot's current timed blocks
    pecan-helper unblock IP             # lift one timed block early
"""
import fcntl, ipaddress, json, os, subprocess, sys, syslog, tempfile

ETC = "/etc/pecan"
SETTINGS = ETC + "/settings.json"
# Same names and defaults as netinfo.SWITCHES / load_settings(); duplicated on purpose (see above).
SWITCHES = ("signatures", "anomaly", "auto_block", "ai")
# Same files and format as netinfo.IP_LISTS / load_ip_list(). protected.txt is installed by hand
# (deploy/pecan-protected.txt) and no command here can change it.
LISTS = {"allow": ETC + "/allowlist.txt", "deny": ETC + "/denylist.txt", "protected": ETC + "/protected.txt"}
# Widest entry each list accepts (prefix length): a typo must not trust or cut off half the internet.
MIN_PREFIX = {"allow": {4: 16, 6: 48}, "deny": {4: 24, 6: 64}}
MAX_ENTRIES = 256          # = size of the denied4/6 nft sets
NOTE_CHARS = 40
NFT = "/usr/sbin/nft"
TABLE = ("inet", "pecan")  # created by honeypot.py; absent while pecan-honeypot is stopped


def log(msg):
    syslog.syslog(syslog.LOG_NOTICE, f"user={os.environ.get('SUDO_USER', '?')} argv={sys.argv[1:]!r} {msg}")


def fail(msg, code=2):
    log(f"result=refused ({msg})")
    print(msg, file=sys.stderr)
    sys.exit(code)


def read_settings():
    """Current switches; a missing or broken file counts as all on, like the readers do."""
    out = dict.fromkeys(SWITCHES, True)
    try:
        with open(SETTINGS) as f:
            data = json.load(f)
        if isinstance(data, dict):
            out.update({k: data[k] for k in SWITCHES if isinstance(data.get(k), bool)})
    except (OSError, ValueError):
        pass
    return out


def write_atomic(path, text):
    """Atomic replace: readers see the old file or the new one, never half of one."""
    fd, tmp = tempfile.mkstemp(dir=ETC, prefix=".tmp.")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)   # the panel (raven) and the honeypot's DynamicUser must read it
        os.replace(tmp, path)
    except BaseException:
        os.unlink(tmp)
        raise


def write_settings(settings):
    write_atomic(SETTINGS, json.dumps(settings, indent=2) + "\n")


def locked():
    """Exclusive lock over /etc/pecan: two clicks at once must not lose one of them."""
    os.makedirs(ETC, mode=0o755, exist_ok=True)
    lock = open(ETC + "/.lock", "w")
    fcntl.flock(lock, fcntl.LOCK_EX)
    return lock


def set_switch(args):
    if len(args) != 2 or args[0] not in SWITCHES or args[1] not in ("on", "off"):
        fail("usage: set-switch " + "|".join(SWITCHES) + " on|off")
    with locked():
        settings = read_settings()
        settings[args[0]] = args[1] == "on"
        write_settings(settings)
    log(f"result=ok {args[0]}={args[1]}")
    print(json.dumps(settings))


# --- IP lists ---------------------------------------------------------------------------------
def run(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as err:
        return subprocess.CompletedProcess(cmd, 1, "", str(err))


def nft(*args):
    return run(NFT, *args)


def fmt(net):
    """How an entry is written to the files and to nft: a single address without /32 or /128."""
    return str(net.network_address) if net.prefixlen == net.max_prefixlen else str(net)


def parse_net(text):
    try:
        return ipaddress.ip_network(text, strict=False)
    except ValueError:
        fail(f"not an IP address or CIDR: {text!r}")


def read_list(name):
    """[(network, note)], same rules as netinfo.load_ip_list()."""
    out = []
    try:
        with open(LISTS[name]) as f:
            lines = f.read().splitlines()
    except FileNotFoundError:
        return out
    for line in lines:
        entry, _, note = line.partition("#")
        try:
            if entry.strip():
                out.append((ipaddress.ip_network(entry.strip(), strict=False), note.strip()))
        except ValueError:
            pass
    return out


def write_list(name, entries):
    head = f"# {LISTS[name]}: written by pecan-helper (change it in the panel)\n"
    write_atomic(LISTS[name], head + "".join(f"{fmt(n)}{'  # ' + note if note else ''}\n" for n, note in entries))


def own_addresses():
    """The Pi's addresses and default gateways: denying them would cut the Pi off its own network."""
    ips = run("/usr/bin/hostname", "-I").stdout.split()
    for fam in ("-4", "-6"):
        for line in run("/usr/sbin/ip", fam, "route", "show", "default").stdout.splitlines():
            f = line.split()
            if len(f) > 2 and f[1] == "via":
                ips.append(f[2])
    return [(ipaddress.ip_network(ip.split("%")[0]), "the Pi itself or its gateway") for ip in ips]


def clash(net, entries):
    """First entry that overlaps net, as text, or None."""
    for other, note in entries:
        if other.version == net.version and other.overlaps(net):
            return fmt(other) + (f" ({note})" if note else "")
    return None


def table_exists():
    return nft("list", "table", *TABLE).returncode == 0


def list_add(args):
    if len(args) not in (2, 3) or args[0] not in MIN_PREFIX:
        fail("usage: list-add allow|deny IP-or-CIDR [NOTE]")
    name, net = args[0], parse_net(args[1])
    note = args[2].strip() if len(args) == 3 else ""
    if len(note) > NOTE_CHARS or "#" in note or any(not 32 <= ord(c) < 127 for c in note):
        fail(f"note: at most {NOTE_CHARS} plain characters, no '#'")
    if net.prefixlen < MIN_PREFIX[name][net.version]:
        fail(f"too wide: the {name} list accepts at most /{MIN_PREFIX[name][net.version]}")
    if net.is_unspecified or net.is_loopback or net.is_multicast:
        fail(f"{fmt(net)} can't be listed")
    with locked():
        entries = read_list(name)
        if len(entries) >= MAX_ENTRIES:
            fail(f"the {name} list is full ({MAX_ENTRIES} entries)")
        if name == "deny":
            # Never deny what must stay reachable; an allow entry has to be removed first.
            for other, why in (("protected", "protected"), ("allow", "on the trusted list")):
                hit = clash(net, read_list(other))
                if hit:
                    fail(f"{fmt(net)} overlaps {hit}, which is {why}")
            hit = clash(net, own_addresses())
            if hit:
                fail(f"{fmt(net)} overlaps {hit}")
        else:
            hit = clash(net, read_list("deny"))
            if hit:
                fail(f"{fmt(net)} overlaps {hit} on the blocked list; remove that first")
        hit = clash(net, entries)
        if hit:
            fail(f"{fmt(net)} overlaps {hit}, already on the list")
        write_list(name, entries + [(net, note)])
        applied = apply_add(name, net)
    log(f"result=ok {name} += {fmt(net)} ({applied})")
    print(json.dumps({"ok": True, "applied": applied}))


def apply_add(name, net):
    """Make the change take effect now, not only at the next honeypot restart."""
    if not table_exists():
        return "saved; takes effect when the trap door service starts"
    if name == "deny":
        r = nft("add", "element", *TABLE, f"denied{net.version}", f"{{ {fmt(net)} }}")
        return "blocked now" if r.returncode == 0 else f"saved, but nft refused: {r.stderr.strip()[:200]}"
    lifted = [ip for ip, _ in timed_blocks() if ipaddress.ip_address(ip) in net]
    for ip in lifted:
        unblock_ip(ip)
    return f"lifted {len(lifted)} current block(s)" if lifted else "no current blocks to lift"


def list_remove(args):
    if len(args) != 2 or args[0] not in MIN_PREFIX:
        fail("usage: list-remove allow|deny IP-or-CIDR")
    name, net = args[0], parse_net(args[1])
    with locked():
        entries = read_list(name)
        kept = [(n, note) for n, note in entries if n != net]
        if len(kept) == len(entries):
            fail(f"{fmt(net)} is not on the {name} list")
        write_list(name, kept)
        applied = "removed"
        if name == "deny" and table_exists():
            r = nft("delete", "element", *TABLE, f"denied{net.version}", f"{{ {fmt(net)} }}")
            applied = "unblocked now" if r.returncode == 0 else f"saved, but nft refused: {r.stderr.strip()[:200]}"
    log(f"result=ok {name} -= {fmt(net)} ({applied})")
    print(json.dumps({"ok": True, "applied": applied}))


def timed_blocks():
    """[(ip, seconds left)] in the honeypot's blocked4/6 sets."""
    out = []
    for s in ("blocked4", "blocked6"):
        r = nft("-j", "list", "set", *TABLE, s)
        if r.returncode:
            continue
        for obj in json.loads(r.stdout).get("nftables", []):
            for e in obj.get("set", {}).get("elem", []):
                e = e.get("elem", e) if isinstance(e, dict) else {"val": e}
                if isinstance(e.get("val"), str):
                    out.append((e["val"], e.get("expires")))
    return out


def list_blocks(args):
    if args:
        fail("usage: list-blocks")
    enforced = table_exists()
    blocks = timed_blocks() if enforced else []
    log(f"result=ok {len(blocks)} blocks")
    print(json.dumps({"enforced": enforced, "blocks": [{"ip": ip, "expires": t} for ip, t in blocks]}))


def unblock_ip(ip):
    v = ipaddress.ip_address(ip).version
    return nft("delete", "element", *TABLE, f"blocked{v}", f"{{ {ip} }}")


def unblock(args):
    if len(args) != 1:
        fail("usage: unblock IP")
    try:
        ip = str(ipaddress.ip_address(args[0]))
    except ValueError:
        fail(f"not an IP address: {args[0]!r}")
    r = unblock_ip(ip)
    if r.returncode:
        fail(f"{ip} is not blocked right now", 1)
    log(f"result=ok unblocked {ip}")
    print(json.dumps({"ok": True}))


COMMANDS = {"set-switch": set_switch, "list-add": list_add, "list-remove": list_remove,
            "list-blocks": list_blocks, "unblock": unblock}


def main():
    syslog.openlog("pecan-helper", 0, syslog.LOG_AUTH)
    os.umask(0o022)
    if os.geteuid() != 0:
        fail("must run as root (sudo)")
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        fail("unknown command; one of: " + ", ".join(COMMANDS))
    try:
        COMMANDS[sys.argv[1]](sys.argv[2:])
    except OSError as err:
        fail(f"error: {err}", 1)


if __name__ == "__main__":
    main()
