#!/usr/bin/python3 -I
"""Pecan Pi root helper: the only thing the panel may run as root (one sudoers line).

Fixed subcommands, argv only, every argument validated here again (the panel is not trusted).
Standard library only and isolated (-I): it imports nothing from ~/pecan-pi or the venv, which
raven can write. Installed by copy, root:root 0755:

    sudo install -o root -g root -m 0755 pecan-helper.py /usr/local/sbin/pecan-helper

Every call is logged to the journal (journalctl -t pecan-helper) with its arguments and result.
Output: one JSON line on stdout (success) or a message on stderr (failure, exit 1/2). The slow rule
commands first print progress lines ("step: rebuilding|testing|reloading") so the panel can show them.
Validation messages start with the field they are about ("port: ...").

    pecan-helper set-switch signatures|anomaly|auto_block|ai on|off
    pecan-helper set-anomaly-iface all|eth0|wlan0|cic0    # interface live anomaly scoring uses (cic0: demo replay)
    pecan-helper list-add allow|deny IP-or-CIDR [NOTE]
    pecan-helper list-remove allow|deny IP-or-CIDR
    pecan-helper list-blocks            # JSON: the honeypot's current timed blocks
    pecan-helper unblock IP             # lift one timed block early
    pecan-helper rules-category CATEGORY on|off      # Suricata rule group; slow (suricata-update)
    pecan-helper custom-add PROTO FROM TO PORT NAME [TEXT]
    pecan-helper custom-edit SID PROTO FROM TO PORT NAME [TEXT]   # same SID, rev+1, keeps on/off
    pecan-helper custom-toggle SID on|off                        # off = kept, commented out
    pecan-helper custom-remove SID
"""
import fcntl, ipaddress, json, os, re, shutil, subprocess, sys, syslog, tempfile

ETC = "/etc/pecan"
SETTINGS = ETC + "/settings.json"
# Same names and defaults as netinfo.SWITCHES / load_settings(); duplicated on purpose (see above).
SWITCHES = ("signatures", "anomaly", "auto_block", "ai")
ANOMALY_IFACES = ("all", "eth0", "wlan0", "cic0")   # netinfo.ANOMALY_IFACES + "all" (no filter)
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
    """Current settings; a missing or broken file counts as all on / all interfaces, like the
    readers do. Every known key is kept, so one command never drops another's setting."""
    out = dict.fromkeys(SWITCHES, True)
    out["anomaly_iface"] = "all"
    try:
        with open(SETTINGS) as f:
            data = json.load(f)
        if isinstance(data, dict):
            out.update({k: data[k] for k in SWITCHES if isinstance(data.get(k), bool)})
            if data.get("anomaly_iface") in ANOMALY_IFACES:
                out["anomaly_iface"] = data["anomaly_iface"]
    except (OSError, ValueError):
        pass
    return out


def write_atomic(path, text):
    """Atomic replace: readers see the old file or the new one, never half of one."""
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path), prefix=".tmp.")
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


def set_anomaly_iface(args):
    if len(args) != 1 or args[0] not in ANOMALY_IFACES:
        fail("usage: set-anomaly-iface " + "|".join(ANOMALY_IFACES))
    with locked():
        settings = read_settings()
        settings["anomaly_iface"] = args[0]
        write_settings(settings)
    log(f"result=ok anomaly_iface={args[0]}")
    print(json.dumps(settings))


# --- IP lists ---------------------------------------------------------------------------------
def run(*cmd, timeout=10):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
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


# --- Suricata rules ---------------------------------------------------------------------------
# Every change is: write the new input, rebuild/test it, and only then let Suricata load it; any
# failure puts the previous files back, and the running Suricata keeps its rules throughout.
RULES_DIR = "/var/lib/suricata/rules"
MERGED = RULES_DIR + "/suricata.rules"          # written by suricata-update
CUSTOM = RULES_DIR + "/pecan-custom.rules"      # ours; listed under rule-files in suricata.yaml
DISABLE_CONF = "/etc/suricata/disable.conf"
# SID 9000001 (ping test). suricata-update only merges its own fixed list of *-events.rules from
# /etc/suricata/rules, so this file must be passed with --local on every rebuild or it is dropped.
LOCAL_RULES = "/etc/suricata/rules/local.rules"
OUR_SIDS = range(9000000, 9200000)              # local.rules + custom range: must never vanish in a rebuild
YAML = "/etc/suricata/suricata.yaml"
SOCKET = "/var/run/suricata/suricata-command.socket"
SURICATA, SURICATA_UPDATE, SURICATASC = "/usr/bin/suricata", "/usr/bin/suricata-update", "/usr/bin/suricatasc"
GENTLE = ("/usr/bin/nice", "-n", "19", "/usr/bin/ionice", "-c3")   # never starve the running Suricata
# Groups the owner may switch off: noisy or policy rules, chosen by the second word of the rule
# name ("ET INFO ..."). Malware, exploits, attacks and scans are deliberately not on this list.
# Same names as panel.RULE_CATEGORIES (labels live there).
CATEGORIES = {"info": ("INFO",), "hunting": ("HUNTING",), "games": ("GAMES",), "chat": ("CHAT",),
              "p2p": ("P2P",), "tor": ("TOR",), "adware": ("ADWARE_PUP",)}
DISABLE_HEAD = "# /etc/suricata/disable.conf: written by pecan-helper (change it in the panel)\n"
SID_MIN, SID_MAX = 9100000, 9199999             # local.rules uses 9000001; ET Open uses 2000000-2999999
MAX_CUSTOM = 100
NAME_RE = re.compile(r"[A-Za-z0-9 .,:_()/-]{3,60}")
TEXT_CHARS = 64


def step(name):
    """Progress line for the panel (stdout, before the final JSON line)."""
    print(f"step: {name}", flush=True)


def rules_locked():
    """One rule change at a time; a second click is refused instead of queued for minutes."""
    os.makedirs(ETC, mode=0o755, exist_ok=True)
    lock = open(ETC + "/.rules-lock", "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        fail("another rule change is still running; try again in a minute", 1)
    return lock


def read_text(path):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return None


def disabled_categories():
    text = read_text(DISABLE_CONF)
    if text is None:
        return set()
    if not text.startswith(DISABLE_HEAD):
        fail(f"{DISABLE_CONF} was not written by pecan-helper; move it away first", 1)
    return {l.split(":", 1)[1].strip() for l in text.splitlines() if l.startswith("# pecan-category:")}


def disable_text(off):
    out = DISABLE_HEAD
    for name in sorted(off):
        out += f"# pecan-category: {name}\n"
        out += "".join(f're:msg:\\s*"(ET|GPL) {word}\\b\n' for word in CATEGORIES[name])
    return out


def enabled_rules(path):
    """{sid: rule line} of the enabled (not commented-out) rules in a rule file."""
    out = {}
    try:
        with open(path, errors="replace") as f:
            for line in f:
                if line.startswith(("alert ", "drop ", "pass ", "reject ")):
                    m = re.search(r"\bsid:\s*(\d+)\s*;", line)
                    if m:
                        out[int(m.group(1))] = line
    except FileNotFoundError:
        pass
    return out


def matches(line, off):
    """Is this rule matched by a switched-off category's disable.conf pattern?"""
    return any(re.search(rf'msg:\s*"(ET|GPL) {word}\b', line, re.I) for name in off for word in CATEGORIES[name])


class Snapshot:
    """Copies of files about to change, put back by restore() if anything fails."""
    def __init__(self, *paths):
        self.saved = []
        for p in paths:
            prev = p + ".pecan-prev"
            if os.path.exists(p):
                shutil.copy2(p, prev)
            self.saved.append((p, prev if os.path.exists(p) else None))

    def restore(self):
        for p, prev in self.saved:
            if prev:
                os.replace(prev, p)
            elif os.path.exists(p):
                os.unlink(p)

    def drop(self):
        for _, prev in self.saved:
            if prev:
                os.unlink(prev)


def first_error(r):
    lines = (r.stderr + r.stdout).splitlines()
    errs = [l for l in lines if l.startswith("E:") or "rror" in l] or lines[-1:] or ["no output"]
    return errs[0].strip()[:300]


def suricata_test(*extra):
    """suricata -T: load the config and rules without touching the running instance."""
    logs = tempfile.mkdtemp(prefix="pecan-test.")
    try:
        return run(*GENTLE, SURICATA, "-T", "-c", YAML, "-l", logs, *extra, timeout=300)
    finally:
        shutil.rmtree(logs, ignore_errors=True)


def reload_suricata():
    """(ok, message). reload-rules over the unix socket waits until the new rules are live; if the
    reload fails, Suricata keeps running on the old ones."""
    if not os.path.exists(SOCKET):
        return True, "saved; Suricata isn't running, it will load this when it starts"
    r = run(SURICATASC, "-c", "reload-rules", SOCKET, timeout=300)
    try:
        if r.returncode or json.loads(r.stdout).get("return") != "OK":
            return False, f"Suricata refused the reload: {(r.stdout or r.stderr).strip()[:200]}"
        stats = json.loads(run(SURICATASC, "-c", "ruleset-stats", SOCKET).stdout)["message"][0]
    except (ValueError, KeyError, IndexError, TypeError):
        return True, "rules reloaded"
    failed = stats.get("rules_failed", 0)
    return True, f"rules reloaded: {stats.get('rules_loaded')} loaded" + (f", {failed} failed" if failed else "")


def rules_category(args):
    if len(args) != 2 or args[0] not in CATEGORIES or args[1] not in ("on", "off"):
        fail("usage: rules-category " + "|".join(CATEGORIES) + " on|off")
    name, on = args[0], args[1] == "on"
    with rules_locked():
        off = disabled_categories()
        new = off - {name} if on else off | {name}
        if new == off:
            print(json.dumps({"ok": True, "applied": "already " + args[1]}))
            return
        before = enabled_rules(MERGED)
        snap = Snapshot(DISABLE_CONF, MERGED)
        write_atomic(DISABLE_CONF, disable_text(new))
        # --offline: rebuild from the rules downloaded last time, so a change never pulls in new rules.
        step("rebuilding")
        r = run(*GENTLE, SURICATA_UPDATE, "--offline", "--no-reload", "--no-test",
                "--disable-conf", DISABLE_CONF, "--local", LOCAL_RULES, timeout=600)
        if r.returncode:
            snap.restore()
            fail(f"suricata-update failed, nothing changed: {first_error(r)}", 1)
        after = enabled_rules(MERGED)
        lost = sorted(sid for sid in before if sid in OUR_SIDS and sid not in after)
        if lost:
            snap.restore()
            fail(f"the rebuild dropped our own rule(s) {lost}, nothing changed", 1)
        # Other rules may only disappear because a switched-off category matched them.
        stray = sorted(sid for sid, line in before.items() if sid not in after and not matches(line, new))
        step("testing")
        r = suricata_test()
        if r.returncode:
            snap.restore()
            fail(f"the new rule set failed Suricata's test, nothing changed: {first_error(r)}", 1)
        step("reloading")
        ok, applied = reload_suricata()
        if not ok:
            snap.restore()
            fail(applied + "; previous rules kept", 1)
        snap.drop()
    changed = abs(len(before) - len(after))
    summary = f"{changed} rule{'s' * (changed != 1)} {'back on' if on else 'off'}"
    if stray:
        applied += f"; note: {len(stray)} other rule(s) not in the rebuild, e.g. SID {', '.join(map(str, stray[:5]))}"
    log(f"result=ok category {name}={args[1]} {summary} ({applied})")
    print(json.dumps({"ok": True, "applied": applied, "summary": summary}))


OFF_PREFIX = "# "   # a switched-off custom rule stays in the file, commented out


def custom_rules():
    """[(sid, line)] of the rules in pecan-custom.rules; a switched-off one starts with OFF_PREFIX."""
    out = []
    for line in (read_text(CUSTOM) or "").splitlines():
        m = re.search(r"\bsid:(\d+);", line)
        if line.startswith(("alert ", OFF_PREFIX + "alert ")) and m:
            out.append((int(m.group(1)), line))
    return out


def custom_sid(text):
    if not text.isdigit() or not SID_MIN <= int(text) <= SID_MAX:
        fail(f"SID must be {SID_MIN}-{SID_MAX}")
    return int(text)


def build_rule(args, sid, rev):
    """PROTO FROM TO PORT NAME [TEXT] -> one alert rule; every field validated here."""
    if len(args) not in (5, 6):
        fail("usage: PROTO FROM TO PORT NAME [TEXT]  (FROM/TO: any|home|outside|IP-or-CIDR)")
    proto, src, dst, port, name = args[0], endpoint(args[1], "from"), endpoint(args[2], "to"), args[3], args[4].strip()
    if proto not in ("tcp", "udp", "icmp", "ip"):
        fail("protocol: tcp, udp, icmp or ip")
    if port != "any":
        if proto not in ("tcp", "udp") or not port.isdigit() or not 1 <= int(port) <= 65535:
            fail("port: 1-65535 (tcp/udp only) or any")
        port = str(int(port))
    if not NAME_RE.fullmatch(name):
        fail("name: 3-60 letters, digits, spaces or . , : _ ( ) / -")
    match = content(args[5]) if len(args) == 6 else ""
    return (f'alert {proto} {src} any -> {dst} {port} (msg:"PECAN CUSTOM {name}"; {match}'
            f"sid:{sid}; rev:{rev};)")


def check_custom_setup():
    if not os.path.isdir(RULES_DIR):
        fail(f"{RULES_DIR} is missing", 1)
    if not loads_custom():
        fail("Suricata isn't set up for custom rules yet: add '- pecan-custom.rules' under rule-files "
             "in /etc/suricata/suricata.yaml", 1)


def find_custom(rules, sid):
    for i, (n, line) in enumerate(rules):
        if n == sid:
            return i, line
    fail(f"no custom rule with SID {sid}")


def endpoint(text, field):
    """'any', 'home' or 'outside', or one IP/CIDR -> the rule's address field."""
    words = {"any": "any", "home": "$HOME_NET", "outside": "$EXTERNAL_NET"}
    if text in words:
        return words[text]
    try:
        return fmt(ipaddress.ip_network(text, strict=False))
    except ValueError:
        fail(f"{field}: not an IP address or CIDR: {text!r}")


def content(text):
    """Text to look for, as a content match: the characters that end or escape a rule field
    (" ; \\ |) are written as hex bytes, so the text can't add rule keywords of its own."""
    if not 1 <= len(text) <= TEXT_CHARS or any(not 32 <= ord(c) < 127 for c in text):
        fail(f"text: 1-{TEXT_CHARS} plain characters")
    body = "".join(f"|{ord(c):02X}|" if c in '";\\|' else c for c in text)
    return f'content:"{body}"; nocase; '


def loads_custom():
    """Is pecan-custom.rules listed under rule-files in suricata.yaml (one-time setup)?"""
    return re.search(r"^\s*-\s*(" + re.escape(RULES_DIR) + r"/)?pecan-custom\.rules\s*$",
                     read_text(YAML) or "", re.M) is not None


def write_custom(rules):
    """Test the new file on its own (fast: only these rules), then put it in place and reload."""
    text = "# " + CUSTOM + ": written by pecan-helper (change it in the panel)\n" + "".join(l + "\n" for _, l in rules)
    fd, tmp = tempfile.mkstemp(dir=RULES_DIR, prefix=".tmp.", suffix=".rules")
    with os.fdopen(fd, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    step("testing")
    r = suricata_test("-S", tmp)
    if r.returncode:
        os.unlink(tmp)
        fail(f"Suricata rejected the rule, nothing changed: {first_error(r)}", 1)
    snap = Snapshot(CUSTOM)
    os.replace(tmp, CUSTOM)
    step("reloading")
    ok, applied = reload_suricata()
    if not ok:
        snap.restore()
        fail(applied + "; previous rules kept", 1)
    snap.drop()
    return applied


def custom_add(args):
    rule = build_rule(args, SID_MIN, 1)   # validate before taking the lock; the real SID comes below
    check_custom_setup()
    with rules_locked():
        rules = custom_rules()
        if len(rules) >= MAX_CUSTOM:
            fail(f"at most {MAX_CUSTOM} custom rules")
        used = {sid for sid, _ in rules}
        sid = next(n for n in range(SID_MIN, SID_MAX + 1) if n not in used)
        rule = build_rule(args, sid, 1)
        applied = write_custom(rules + [(sid, rule)])
    log(f"result=ok custom += {rule} ({applied})")
    print(json.dumps({"ok": True, "sid": sid, "applied": applied}))


def custom_edit(args):
    if len(args) < 1:
        fail("usage: custom-edit SID PROTO FROM TO PORT NAME [TEXT]")
    sid = custom_sid(args[0])
    build_rule(args[1:], sid, 1)
    check_custom_setup()
    with rules_locked():
        rules = custom_rules()
        i, old = find_custom(rules, sid)
        rev = re.search(r"\brev:(\d+);", old)
        rule = build_rule(args[1:], sid, int(rev.group(1)) + 1 if rev else 2)
        if old.startswith(OFF_PREFIX):   # editing doesn't switch a rule back on
            rule = OFF_PREFIX + rule
        rules[i] = (sid, rule)
        applied = write_custom(rules)
    log(f"result=ok custom {sid} := {rule} ({applied})")
    print(json.dumps({"ok": True, "applied": applied}))


def custom_toggle(args):
    if len(args) != 2 or args[1] not in ("on", "off"):
        fail("usage: custom-toggle SID on|off")
    sid, on = custom_sid(args[0]), args[1] == "on"
    check_custom_setup()
    with rules_locked():
        rules = custom_rules()
        i, line = find_custom(rules, sid)
        bare = line[len(OFF_PREFIX):] if line.startswith(OFF_PREFIX) else line
        if (line == bare) == on:
            print(json.dumps({"ok": True, "applied": "already " + args[1]}))
            return
        rules[i] = (sid, bare if on else OFF_PREFIX + bare)
        applied = write_custom(rules)
    log(f"result=ok custom {sid} {args[1]} ({applied})")
    print(json.dumps({"ok": True, "applied": applied}))


def custom_remove(args):
    if len(args) != 1:
        fail("usage: custom-remove SID")
    sid = custom_sid(args[0])
    with rules_locked():
        rules = custom_rules()
        i, _ = find_custom(rules, sid)
        applied = write_custom(rules[:i] + rules[i + 1:])
    log(f"result=ok custom -= {sid} ({applied})")
    print(json.dumps({"ok": True, "applied": applied}))


COMMANDS = {"set-switch": set_switch, "set-anomaly-iface": set_anomaly_iface, "list-add": list_add, "list-remove": list_remove,
            "list-blocks": list_blocks, "unblock": unblock, "rules-category": rules_category,
            "custom-add": custom_add, "custom-edit": custom_edit, "custom-toggle": custom_toggle,
            "custom-remove": custom_remove}


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
