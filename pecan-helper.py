#!/usr/bin/python3 -I
"""Pecan Pi root helper: the only thing the panel may run as root (one sudoers line).

Fixed subcommands, argv only, every argument validated here again (the panel is not trusted).
Standard library only and isolated (-I): it imports nothing from ~/pecan-pi or the venv, which
raven can write. Installed by copy, root:root 0755:

    sudo install -o root -g root -m 0755 pecan-helper.py /usr/local/sbin/pecan-helper

Every call is logged to the journal (journalctl -t pecan-helper) with its arguments and result.

    pecan-helper set-switch signatures|anomaly|auto_block|ai on|off
"""
import fcntl, json, os, sys, syslog, tempfile

ETC = "/etc/pecan"
SETTINGS = ETC + "/settings.json"
# Same names and defaults as netinfo.SWITCHES / load_settings(); duplicated on purpose (see above).
SWITCHES = ("signatures", "anomaly", "auto_block", "ai")


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


def write_settings(settings):
    """Atomic replace: readers see the old file or the new one, never half of one."""
    fd, tmp = tempfile.mkstemp(dir=ETC, prefix=".settings.")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(settings, f, indent=2)
            f.write("\n")
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, 0o644)   # the panel (raven) and the honeypot's DynamicUser must read it
        os.replace(tmp, SETTINGS)
    except BaseException:
        os.unlink(tmp)
        raise


def set_switch(args):
    if len(args) != 2 or args[0] not in SWITCHES or args[1] not in ("on", "off"):
        fail("usage: set-switch " + "|".join(SWITCHES) + " on|off")
    os.makedirs(ETC, mode=0o755, exist_ok=True)
    with open(ETC + "/.lock", "w") as lock:   # two clicks at once must not lose one of them
        fcntl.flock(lock, fcntl.LOCK_EX)
        settings = read_settings()
        settings[args[0]] = args[1] == "on"
        write_settings(settings)
    log(f"result=ok {args[0]}={args[1]}")
    print(json.dumps(settings))


COMMANDS = {"set-switch": set_switch}


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
