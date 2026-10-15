"""The Pi's current addresses, looked up at call time (hotspot IPs change).

Standard library only: used by triage.py and by honeypot.py, which runs sandboxed without the venv.
"""
import subprocess


def run(*cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.SubprocessError):
        return ""


def host_ips():
    return run("hostname", "-I").split()


def gateways():
    """Default gateways, IPv4 and IPv6 ('default via X dev ...')."""
    out = run("ip", "route", "show", "default") + run("ip", "-6", "route", "show", "default")
    return [l.split()[2] for l in out.splitlines() if len(l.split()) > 2 and l.split()[1] == "via"]


def iface_ips(name):
    """Addresses on one interface, without prefix length ('tailscale0 UNKNOWN 100.x/32 fd7a::/128')."""
    fields = run("ip", "-br", "addr", "show", "dev", name).split()
    return [a.split("/")[0] for a in fields[2:]]
