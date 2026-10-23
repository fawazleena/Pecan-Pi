"""The Pi's current addresses, looked up at call time (hotspot IPs change), the
reconnaissance "scan in progress" marker, and the panel's main switches and IP lists.

Standard library only: used by triage.py and by honeypot.py (which runs sandboxed without the
venv), and the marker is read by anomaly.py and pipeline.py to suppress the Pi's own scans.
"""
import ipaddress, json, os, subprocess, time
from datetime import datetime, timezone
from pathlib import Path


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


# Data files (pecan.db, .env, recon_active.json) live next to the code in the repo. The root-run
# services run root-owned copies of the code from /opt/pecan and set PECAN_DATA to the repo.
DATA = Path(os.environ.get("PECAN_DATA") or Path(__file__).parent)


# --- Reconnaissance scan marker ---------------------------------------------------------------
# recon.py writes this while it is scanning so the Pi's own detectors don't flag the scan.
# It is a plain file, not a lock: both detectors only read it, and it is advisory.
RECON_MARKER = DATA / "recon_active.json"
RECON_MAX_AGE = 3600   # seconds; a marker older than this is ignored (safety net against a leak)
RECON_TAIL = 120       # seconds kept active after a scan ends, to cover late flow records


def _now():
    return datetime.now(timezone.utc)


def write_recon_marker(scan_id, targets, ports=None):
    """Start (or extend) the active-scan window. end=None means a scan is running now."""
    RECON_MARKER.write_text(json.dumps({
        "scan_id": scan_id, "targets": list(targets), "ports": list(ports) if ports else None,
        "start": _now().isoformat(), "end": None}))


def finish_recon_marker():
    """Mark the running scan finished; keep it active RECON_TAIL seconds for trailing flows."""
    m = load_recon_marker(ignore_age=True)
    if m:
        m["end"] = (_now().timestamp() + RECON_TAIL)
        RECON_MARKER.write_text(json.dumps({**m, "end": datetime.fromtimestamp(m["end"], timezone.utc).isoformat()}))


def load_recon_marker(ignore_age=False):
    """The current scan marker, or None if there is none, it is stale, expired or unreadable."""
    try:
        m = json.loads(RECON_MARKER.read_text())
        start = datetime.fromisoformat(m["start"]).timestamp()
    except (FileNotFoundError, ValueError, KeyError, OSError):
        return None
    now = time.time()
    if not ignore_age and now - start > RECON_MAX_AGE:
        return None
    if m.get("end"):
        try:
            if now > datetime.fromisoformat(m["end"]).timestamp():
                return None  # scan finished and the tail has passed
        except ValueError:
            return None
    return m


def recon_covers_dest(marker, dest_ip):
    """True if dest_ip is one of the marker's scan targets (exact IP match on parsed targets)."""
    return bool(marker) and dest_ip in (marker.get("targets") or [])


# --- Main switches (panel) --------------------------------------------------------------------
# Written only by the root-owned pecan-helper (the panel's sudo helper), read by the panel, the
# pipeline (every 30 s flush) and the honeypot (every hit), so a change needs no restart.
SETTINGS = Path("/etc/pecan/settings.json")
SWITCHES = ("signatures", "anomaly", "auto_block", "ai")


def load_settings():
    """(switches, error). A missing file or key means on: that is how the Pi behaved before the
    panel existed. An unreadable file also falls back to on (fail towards protection) and returns
    the error, so the panel can say so instead of showing a made-up state."""
    out = dict.fromkeys(SWITCHES, True)
    try:
        data = json.loads(SETTINGS.read_text())
    except FileNotFoundError:
        return out, None
    except (OSError, ValueError) as err:
        return out, f"{SETTINGS}: {err}"
    if not isinstance(data, dict):
        return out, f"{SETTINGS}: not a JSON object"
    out.update({k: data[k] for k in SWITCHES if isinstance(data.get(k), bool)})
    return out, None


# Suricata's capture interfaces (deploy/override.conf). "anomaly_iface" in settings.json limits
# live anomaly scoring to one of them, to match a baseline snapshotted with --iface (e.g. a lab
# SPAN port on eth0). Same values in pecan-helper ("all" = no filter).
# cic0: a dummy interface (no IP, no peer: every frame sent to it is dropped) that only exists
# while CIC-IDS2017 traffic is replayed into it for the demo (docs/cic-demo.md). Rows from it are
# tagged REPLAY_TAG, so they are never mistaken for the Pi's own traffic.
REPLAY_IFACE = "cic0"
REPLAY_TAG = "[cic-replay] "
ANOMALY_IFACES = ("eth0", "wlan0", REPLAY_IFACE)


def load_anomaly_iface():
    """The one interface live anomaly scoring uses, or None for all. Missing, unreadable or
    unknown means all: how the pipeline behaved before the setting existed."""
    try:
        value = json.loads(SETTINGS.read_text()).get("anomaly_iface")
    except (OSError, ValueError, AttributeError):
        return None
    return value if value in ANOMALY_IFACES else None


def model_meta_path(model):
    """The label sidecar next to a model: anomaly_model.joblib -> anomaly_model.meta.json."""
    return Path(str(model).removesuffix(".joblib") + ".meta.json")


_model_hash = {}   # (path, mtime_ns, size) -> sha256: the panel asks every few seconds


def model_label(model):
    """What the installed anomaly model is, in words, or None when there is no model. The label
    comes from the sidecar written by `anomaly.py label` and counts only while its sha256 matches
    the model file, so a model replaced without a new sidecar is never shown under the old name."""
    import hashlib
    try:
        st = os.stat(model)
    except OSError:
        return None
    key = (str(model), st.st_mtime_ns, st.st_size)
    if key not in _model_hash:
        try:
            with open(model, "rb") as f:
                _model_hash.clear()
                _model_hash[key] = hashlib.sha256(f.read()).hexdigest()
        except OSError as err:
            return f"unreadable ({err.strerror})"
    try:
        meta = json.loads(model_meta_path(model).read_text())
    except FileNotFoundError:
        return "unlabelled"
    except (OSError, ValueError):
        return "unknown (label file unreadable)"
    if not isinstance(meta, dict) or meta.get("sha256") != _model_hash[key]:
        return "unknown (label does not match the model file)"
    return str(meta.get("label") or "unlabelled")


# --- IP lists (panel) -------------------------------------------------------------------------
# Written only by pecan-helper (allowlist, denylist) or installed by hand (protected), read by
# the honeypot (every hit, and the denylist at startup) and the panel. One entry per line,
# "IP-or-CIDR  # optional note"; pecan-helper parses the same format (duplicated on purpose).
IP_LISTS = {"allow": Path("/etc/pecan/allowlist.txt"), "deny": Path("/etc/pecan/denylist.txt"),
            "protected": Path("/etc/pecan/protected.txt")}


def load_ip_list(name):
    """[(ip_network, note)] from one list; a missing file is an empty list, bad lines are skipped."""
    try:
        lines = IP_LISTS[name].read_text().splitlines()
    except FileNotFoundError:
        return []
    out = []
    for line in lines:
        entry, _, note = line.partition("#")
        if entry.strip():
            try:
                out.append((ipaddress.ip_network(entry.strip(), strict=False), note.strip()))
            except ValueError:
                print(f"{IP_LISTS[name]}: ignoring {entry.strip()!r}")
    return out
