"""Reconnaissance / VAPT module: non-destructive, analyst-initiated, human-in-the-loop.

Flow:
  1. discover  -- nmap -sV a target the analyst names (never auto-scanned)
  2. CVE match -- map service product/version to known vulns via the local Exploit-DB (offline)
  3. propose   -- for each finding, store a NON-DESTRUCTIVE check + rule-based reasoning (XAI);
                  nothing runs until the analyst approves that specific finding
  4. approve   -- run ONLY the proposed read-only check (banner grab / version re-confirm),
                  store it, and run it through the same Groq triage (detection='recon')

Active exploitation is OUT OF SCOPE and not built. The action registry holds only
non-destructive actions, and ALLOW_DESTRUCTIVE is hardcoded False with no code path that
changes it, so a destructive action cannot run even if one were added by mistake.

  sudo .venv/bin/python recon.py discover 192.168.221.65   # host, hosts, or CIDR
  .venv/bin/python recon.py review [--scan N]
  sudo .venv/bin/python recon.py approve <finding_id>
  sudo .venv/bin/python recon.py decline <finding_id> [--note ...]
  .venv/bin/python recon.py scans

discover/approve/decline write the root-owned pecan.db, so they need sudo, like backfill.py.
review/scans only read it, so they run as a normal user once the recon tables exist (the first
discover creates them).
"""
import argparse, json, socket, subprocess, sys, tempfile
from datetime import datetime, timezone

from libnmap.parser import NmapParser

import netinfo
from triage import open_db, triage_all, UNTRIAGED

DB = "pecan.db"
BANNER_BYTES = 256
BANNER_TIMEOUT = 5
# nmap: service/version scan, polite timing, rate-capped so a scan can never become a flood.
# TCP connect (-sT, the default as non-root) completes handshakes: non-destructive.
NMAP_BASE = ["nmap", "-sT", "-sV", "--version-light", "-T3", "--max-rate", "100"]
NICE = ["nice", "-n", "19", "ionice", "-c3"]   # never take CPU/IO from Suricata

ALLOW_DESTRUCTIVE = False  # hardcoded. No env var, flag, or setter reads or changes this.


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# --- schema -----------------------------------------------------------------------------------
def init(db):
    db.execute("""CREATE TABLE IF NOT EXISTS recon_scan (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        started_at TEXT, target TEXT, args TEXT, host_count INTEGER, note TEXT)""")
    db.execute("""CREATE TABLE IF NOT EXISTS recon_finding (
        id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id INTEGER,
        host TEXT, port INTEGER, proto TEXT, service TEXT, product TEXT, version TEXT, cpe TEXT,
        cves TEXT, exploit_titles TEXT,
        status TEXT DEFAULT 'proposed', proposed_action TEXT, reasoning TEXT,
        verification TEXT, decided_at TEXT, decided_by TEXT)""")
    db.commit()


# --- step 2: CVE matching (offline, Exploit-DB) -----------------------------------------------
def match_cves(product, version):
    """CVE IDs and exploit titles for a product/version from the local Exploit-DB (searchsploit).

    Offline and deterministic. Provenance/caveat (stated to the analyst and in the report):
    Exploit-DB lists vulnerabilities that have a public exploit/PoC, each tagged with its CVE(s).
    It is NOT the full NVD, so no match does not prove there is no CVE -- only that Exploit-DB
    has no entry for this product/version.

    # TODO NVD: a future offline enrichment would match the nmap `cpe` string against a local
    # NVD CPE cache (api.nvd.nist.gov, cached to SQLite) for authoritative CVE coverage. Not built.
    """
    if not product or not version:
        return [], []
    try:
        out = subprocess.run(["searchsploit", "--cve", "-j", product, version],
                             capture_output=True, text=True, timeout=30).stdout
        results = json.loads(out).get("RESULTS_EXPLOIT", [])
    except (OSError, subprocess.SubprocessError, ValueError):
        return [], []
    cves, titles = [], []
    for r in results:
        for code in (r.get("Codes") or "").split(";"):
            code = code.strip()
            if code.startswith("CVE-") and code not in cves:
                cves.append(code)
        if r.get("Title"):
            titles.append(r["Title"])
    return cves, titles


# --- step 3: proposal + explanation -----------------------------------------------------------
def propose(f):
    """Pick a non-destructive check and a plain-English, rule-based reason for a finding dict.
    Deterministic (not an LLM), so the explanation shown at the gate is reproducible."""
    where = f"{f['host']}:{f['port']}"
    svc = f["product"] or f["service"] or "unknown service"
    ver = f" {f['version']}" if f["version"] else ""
    cpe = f" ({f['cpe']})" if f["cpe"] else ""
    if f["cves"]:
        vuln = (f"Exploit-DB lists {', '.join(f['cves'][:5])}"
                + (f" and {len(f['cves']) - 5} more" if len(f["cves"]) > 5 else "") + ", exploit entry available.")
    else:
        vuln = "No Exploit-DB entry for this version (not proof of no CVE; Exploit-DB is not the full NVD)."
    action = "version_reconfirm" if not f["version"] else "banner_grab"
    check = ("re-scan this one port with nmap -sV to establish the exact version"
             if action == "version_reconfirm"
             else "reconnect and read the service banner to re-confirm the version the CVE depends on")
    return action, (f"Host {where} runs {svc}{ver}{cpe}. {vuln} "
                    f"Proposed check: {action} -- {check}. This is read-only: it sends no payload and "
                    f"changes nothing on the target. Requires analyst approval before it runs.")


# --- step 4: non-destructive verification actions ---------------------------------------------
class Action:
    def __init__(self, run, destructive):
        self.run, self.destructive = run, destructive


def do_banner_grab(f):
    """Open a TCP connection, read up to BANNER_BYTES of the banner, close. No payload sent."""
    try:
        with socket.create_connection((f["host"], f["port"]), timeout=BANNER_TIMEOUT) as s:
            s.settimeout(BANNER_TIMEOUT)
            data = s.recv(BANNER_BYTES)
    except OSError as err:
        return f"banner_grab failed: {err}"
    text = bytes(b if 32 <= b < 127 else 63 for b in data.rstrip(b"\r\n")).decode()[:BANNER_BYTES]
    return f"banner_grab: {text!r}" if text else "banner_grab: no banner returned"


def do_version_reconfirm(f):
    """Single focused nmap -sV on just this port. Non-destructive."""
    rc, hosts, err = run_nmap(NMAP_BASE + ["-p", str(f["port"]), f["host"]])
    if rc != 0:
        return f"version_reconfirm failed: {err}"
    for h in hosts:
        for s in h.services:
            if s.port == f["port"]:
                b = s.banner or f"{s.service} {s.cpelist and s.cpelist[0].cpestring or ''}".strip()
                return f"version_reconfirm: {s.service} {b}".strip()
    return "version_reconfirm: port not reported in re-scan"


def do_default_creds(f):
    # SEAM (built later): a tightly-scoped, single-attempt, connect-and-logout default-credential
    # check against an analyst-owned target. Registered as non-destructive but intentionally not
    # implemented in this pass.
    raise NotImplementedError("default_creds verification is not implemented yet (registered seam only)")


ACTIONS = {
    "banner_grab":       Action(do_banner_grab,       destructive=False),
    "version_reconfirm": Action(do_version_reconfirm, destructive=False),
    "default_creds":     Action(do_default_creds,     destructive=False),
    # SEAM: an active-exploitation action would be Action(run=..., destructive=True), registered
    # here. It is intentionally ABSENT. Running any destructive action also requires
    # ALLOW_DESTRUCTIVE (hardcoded False), so adding one later is a deliberate change in two places.
}


def dispatch(name, finding):
    action = ACTIONS[name]
    if action.destructive and not ALLOW_DESTRUCTIVE:
        raise PermissionError("destructive actions are out of scope and disabled")
    return action.run(finding)


# --- nmap helpers -----------------------------------------------------------------------------
def kernel_drops():
    """Latest Suricata capture.kernel_drops, to show a scan cost no packets."""
    try:
        out = subprocess.run(["tail", "-n", "2000", "/var/log/suricata/eve.json"],
                             capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    last = None
    for line in out.splitlines():
        try:
            e = json.loads(line)
            if e.get("event_type") == "stats":
                last = e["stats"]["capture"]["kernel_drops"]
        except (ValueError, KeyError):
            pass
    return last


def run_nmap(cmd):
    """Run nmap under nice/ionice, return (returncode, [NmapHost], stderr)."""
    with tempfile.NamedTemporaryFile(suffix=".xml") as xml:
        full = NICE + cmd + ["-oX", xml.name]
        p = subprocess.run(full, capture_output=True, text=True, timeout=1800)
        if p.returncode != 0:
            return p.returncode, [], p.stderr.strip()
        try:
            report = NmapParser.parse_fromfile(xml.name)
        except Exception as err:  # libnmap raises assorted parse errors
            return 1, [], f"parse error: {err}"
    return 0, report.hosts, ""


# --- commands ---------------------------------------------------------------------------------
def cmd_discover(a):
    db = open_db(DB)
    init(db)
    before = kernel_drops()
    print(f"scanning {a.target} (nmap {' '.join(NMAP_BASE[1:])}); Suricata kernel_drops before: {before}")
    rc, hosts, err = run_nmap(NMAP_BASE + a.target)
    if rc != 0:
        sys.exit(f"nmap failed: {err}")
    up = [h for h in hosts if h.is_up()]
    cur = db.execute("INSERT INTO recon_scan (started_at, target, args, host_count) VALUES (?,?,?,?)",
                     (now_iso(), " ".join(a.target), " ".join(NMAP_BASE), len(up)))
    scan_id = cur.lastrowid
    n = 0
    for h in up:
        for s in h.services:
            if s.state != "open":
                continue
            product = (s.service_dict.get("product") or "").strip()
            version = (s.service_dict.get("version") or "").strip()
            cpe = s.cpelist[0].cpestring if s.cpelist else ""
            cves, titles = match_cves(product, version)
            f = {"host": h.address, "port": s.port, "proto": s.protocol, "service": s.service,
                 "product": product, "version": version, "cpe": cpe, "cves": cves}
            action, reasoning = propose(f)
            db.execute("""INSERT INTO recon_finding
                (scan_id, host, port, proto, service, product, version, cpe, cves, exploit_titles,
                 status, proposed_action, reasoning) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (scan_id, h.address, s.port, s.protocol, s.service, product, version, cpe,
                 json.dumps(cves), json.dumps(titles), "proposed", action, reasoning))
            n += 1
    db.commit()
    after = kernel_drops()
    print(f"scan {scan_id}: {len(up)} host(s) up, {n} open-port finding(s). kernel_drops after: {after}"
          + ("  (unchanged)" if before == after else f"  (CHANGED from {before} -- scan cost Suricata packets)"))
    print(f"review them with:  .venv/bin/python recon.py review --scan {scan_id}")


def cmd_review(a):
    db = open_db(DB)
    init(db)
    where = "WHERE scan_id = ?" if a.scan else ""
    args = (a.scan,) if a.scan else ()
    rows = db.execute(f"""SELECT id, host, port, proto, service, status, proposed_action, cves, reasoning
        FROM recon_finding {where} ORDER BY id""", args).fetchall()
    if not rows:
        print("no findings")
        return
    for fid, host, port, proto, service, status, action, cves, reasoning in rows:
        n = len(json.loads(cves or "[]"))
        print(f"\n[{fid}] {host}:{port}/{proto} {service}  status={status}  cves={n}  proposed={action}")
        print(f"     {reasoning}")
    print("\napprove a check:  sudo .venv/bin/python recon.py approve <id>")


def cmd_approve(a):
    db = open_db(DB)
    init(db)
    row = db.execute("""SELECT id, scan_id, host, port, proto, service, product, version, cpe, cves,
        status, proposed_action FROM recon_finding WHERE id = ?""", (a.finding_id,)).fetchone()
    if not row:
        sys.exit(f"no finding {a.finding_id}")
    keys = ("id", "scan_id", "host", "port", "proto", "service", "product", "version", "cpe", "cves",
            "status", "proposed_action")
    f = dict(zip(keys, row))
    f["cves"] = json.loads(f["cves"] or "[]")
    if f["status"] not in ("proposed", "error"):
        sys.exit(f"finding {a.finding_id} is '{f['status']}', not awaiting approval")
    action = f["proposed_action"]
    print(f"approved: {action} on {f['host']}:{f['port']} ({f['service']})")

    # Cover this finding's host so the verification re-scan doesn't flag the Pi itself.
    netinfo.write_recon_marker(a.finding_id, [f["host"]])
    before = kernel_drops()
    try:
        result = dispatch(action, f)
        status = "verified"
    except NotImplementedError as err:
        print(f"nothing ran: {err}")
        db.execute("UPDATE recon_finding SET status='proposed' WHERE id=?", (a.finding_id,))
        db.commit()
        return
    except PermissionError as err:
        sys.exit(f"refused: {err}")
    except Exception as err:
        result, status = f"{action} error: {err}", "error"
    after = kernel_drops()
    print(f"result: {result}")
    if before != after:
        print(f"note: Suricata kernel_drops changed {before} -> {after}")

    db.execute("UPDATE recon_finding SET status=?, verification=?, decided_at=?, decided_by=? WHERE id=?",
               (status, result, now_iso(), "analyst", a.finding_id))
    db.commit()

    # Run the confirmed finding through the same triage and store it as an alerts row (like backfill.py).
    store_alert(db, f, result)
    print("stored as detection='recon' alert and triaged.")


def store_alert(db, f, result):
    sig = f"Recon: {f['service']} on {f['host']}:{f['port']}" + (f" [{', '.join(f['cves'][:3])}]" if f["cves"] else "")
    item = {"n": 0, "detection": "recon", "signature": sig, "src_ip": netinfo.host_ips()[0] if netinfo.host_ips() else None,
            "dest_ip": f["host"], "dest_port": f["port"], "count": 1, "cves": f["cves"],
            "product": f["product"], "version": f["version"], "cpe": f["cpe"], "action": result}
    now = now_iso()
    results = triage_all([item])
    verdict, priority, reason = results.get(0, UNTRIAGED)
    db.execute("""INSERT INTO alerts (seen_at, signature, src_ip, dest_ip, count, verdict, priority,
        reason, detection, action) VALUES (?,?,?,?,?,?,?,?,?,?)""",
        (now, sig, item["src_ip"], f["host"], 1, verdict, priority, reason, "recon", result))
    db.commit()
    print(f"[{priority}] {verdict} {sig} | {reason}")


def cmd_decline(a):
    db = open_db(DB)
    init(db)
    cur = db.execute("UPDATE recon_finding SET status='declined', decided_at=?, decided_by=?, verification=? "
                     "WHERE id=? AND status IN ('proposed','error')",
                     (now_iso(), "analyst", a.note, a.finding_id))
    db.commit()
    print("declined" if cur.rowcount else f"finding {a.finding_id} not awaiting approval")


def cmd_scans(a):
    db = open_db(DB)
    init(db)
    for sid, started, target, hosts in db.execute(
            "SELECT id, started_at, target, host_count FROM recon_scan ORDER BY id DESC LIMIT 20"):
        n = db.execute("SELECT COUNT(*) FROM recon_finding WHERE scan_id=?", (sid,)).fetchone()[0]
        print(f"[{sid}] {started}  target={target}  hosts_up={hosts}  findings={n}")


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("discover"); d.add_argument("target", nargs="+"); d.set_defaults(func=cmd_discover)
    r = sub.add_parser("review"); r.add_argument("--scan", type=int); r.set_defaults(func=cmd_review)
    ap = sub.add_parser("approve"); ap.add_argument("finding_id", type=int); ap.set_defaults(func=cmd_approve)
    dc = sub.add_parser("decline"); dc.add_argument("finding_id", type=int); dc.add_argument("--note", default="")
    dc.set_defaults(func=cmd_decline)
    sub.add_parser("scans").set_defaults(func=cmd_scans)
    a = p.parse_args()

    # discover/approve emit traffic from the Pi: bracket them with the scan marker so the Pi's own
    # detectors suppress/tag the scan. discover writes it up front (it knows the targets); approve
    # writes it after it loads the finding's host (see cmd_approve).
    if a.cmd == "discover":
        netinfo.write_recon_marker(0, a.target)
        try:
            a.func(a)
        finally:
            netinfo.finish_recon_marker()
    elif a.cmd == "approve":
        try:
            a.func(a)
        finally:
            netinfo.finish_recon_marker()
    else:
        a.func(a)


if __name__ == "__main__":
    main()
