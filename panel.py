"""Pecan Pi control panel: a small Flask app for a non-technical owner, served over HTTPS.

Phase 1: login, layout, status page. Reads pecan.db read-only and runs as the normal user;
nothing here needs root yet (later phases go through the root-owned pecan-helper).

    .venv/bin/python panel.py set-password     # store the admin password hash + secret key in .env
    .venv/bin/python panel.py make-cert        # self-signed TLS cert -> panel/tls/ (gitignored)
    .venv/bin/python panel.py serve [--host IP] [--port 8443]   # default host: the Pi's tailscale0 IP
"""
import argparse, getpass, json, os, secrets, sqlite3, subprocess, sys, threading, time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from dotenv import load_dotenv
from flask import Flask, abort, jsonify, redirect, render_template, request, session, url_for
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import check_password_hash, generate_password_hash
from netinfo import iface_ips

HERE = Path(__file__).parent
ENV = HERE / ".env"
DB = HERE / "pecan.db"
EVE = "/var/log/suricata/eve.json"
TLS = HERE / "panel" / "tls"
SERVICES = ("suricata", "pecan-pipeline", "pecan-honeypot")
PORT = 8443
IDLE_MINUTES = 30          # logged out after this long without a page load or change (polling doesn't count)
MAX_FAILS, FAIL_WINDOW = 5, 15 * 60   # login attempts per client IP per 15 min
FEED_ROWS = 15
STATS_TAIL = 512 * 1024    # bytes of eve.json searched for the latest stats event
DROPS_WINDOW = 10 * 60     # kernel_drops rising within this many seconds -> yellow

PLAIN_VERDICT = {"malicious": "Threat", "suspicious": "Worth a look", "benign": "Normal", "unknown": "Not reviewed yet"}
PLAIN_DETECTION = {"signature": "Known attack pattern", "anomaly": "Unusual behaviour",
                   "honeypot": "Someone tried the trap door", "recon": "Security check result"}
CACHE_PREFIXES = ("[cached] ", "[backfill] ", "[retriage] ")

load_dotenv(ENV)
app = Flask(__name__, template_folder="panel/templates", static_folder="panel/static")
app.config.update(
    SECRET_KEY=os.environ.get("PANEL_SECRET_KEY"),
    SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Strict",
    SESSION_COOKIE_NAME="pecan_session", WTF_CSRF_TIME_LIMIT=None,  # token lives as long as the session
    MAX_CONTENT_LENGTH=64 * 1024)
csrf = CSRFProtect(app)

fails, fails_lock = {}, threading.Lock()   # client IP -> recent failure timestamps (in memory, reset on restart)
drops = {"last": None, "rose_at": 0}        # kernel_drops seen at the previous status check


# --- auth -------------------------------------------------------------------------------------
def locked_out(ip):
    with fails_lock:
        recent = [t for t in fails.get(ip, []) if time.time() - t < FAIL_WINDOW]
        fails[ip] = recent
        return len(recent) >= MAX_FAILS


def record_fail(ip):
    with fails_lock:
        fails.setdefault(ip, []).append(time.time())


@app.before_request
def require_login():
    if request.endpoint in ("login", "static", "favicon"):
        return
    seen = session.get("seen", 0)
    if not session.get("admin") or time.time() - seen > IDLE_MINUTES * 60:
        # Clear only an expired admin session. Clearing a not-yet-logged-in one would drop the
        # CSRF token of the login form already on screen (the browser's own /favicon.ico request
        # did exactly that: "CSRF tokens do not match").
        if session.get("admin"):
            session.clear()
        if request.path.startswith("/api/"):
            abort(401)
        return redirect(url_for("login"))
    if not request.path.startswith("/api/") or request.method != "GET":
        session["seen"] = time.time()


@app.after_request
def headers(resp):
    # No inline scripts/styles and nothing from other sites: an injected string can't run as code.
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
        "object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "same-origin"  # Flask-WTF checks Referer on HTTPS POSTs
    resp.headers["Strict-Transport-Security"] = "max-age=31536000"
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        ip = request.remote_addr
        if locked_out(ip):
            error = "Too many attempts. Wait 15 minutes and try again."
        elif check_password_hash(os.environ["PANEL_PASSWORD_HASH"], request.form.get("password", "")[:256]):
            session.clear()
            session.update(admin=True, seen=time.time())
            print(f"login ok from {ip}")
            return redirect(url_for("home"))
        else:
            record_fail(ip)
            print(f"login failed from {ip}")
            error = "Wrong password."
    return render_template("login.html", error=error), 200 if not error else 401


@app.get("/favicon.ico")
def favicon():
    return redirect(url_for("static", filename="favicon.svg"))


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


# --- status -----------------------------------------------------------------------------------
def service_states():
    out = subprocess.run(["systemctl", "is-active", *SERVICES], capture_output=True, text=True).stdout.split()
    return {s: (out[i] if i < len(out) else "unknown") for i, s in enumerate(SERVICES)}


def kernel_drops():
    """capture.kernel_drops from the newest stats event near the end of eve.json, or None."""
    try:
        with open(EVE, "rb") as f:
            f.seek(max(0, os.fstat(f.fileno()).st_size - STATS_TAIL))
            lines = f.read().decode(errors="replace").splitlines()
    except OSError:
        return None
    for line in reversed(lines):
        if '"event_type":"stats"' in line:
            try:
                return json.loads(line)["stats"]["capture"]["kernel_drops"]
            except (ValueError, KeyError):
                continue
    return None


def query(sql, args=()):
    db = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)  # written by the root pipeline; we only read
    try:
        return db.execute(sql, args).fetchall()
    finally:
        db.close()


def plain_reason(reason):
    reason = reason or ""
    for p in CACHE_PREFIXES:
        if reason.startswith(p):
            reason = reason[len(p):]
    return reason[:1].upper() + reason[1:]


def status():
    now = datetime.now(timezone.utc)
    hour, day = (now - timedelta(hours=1)).isoformat(), (now - timedelta(days=1)).isoformat()
    states = service_states()
    d = kernel_drops()
    if drops["last"] is not None and d is not None and d > drops["last"]:
        drops["rose_at"] = time.time()
    drops["last"] = d
    problems = []  # (level, plain-English sentence)
    try:
        (threats,), = query("SELECT COUNT(*) FROM alerts WHERE seen_at >= ? AND verdict='malicious' AND priority='high'", (hour,))
        (worth,), = query("SELECT COUNT(*) FROM alerts WHERE seen_at >= ? AND (verdict='suspicious' OR priority='medium')", (day,))
        rows = query("SELECT id, seen_at, detection, verdict, priority, signature, sid, severity, src_ip, dest_ip, "
                     "count, score, reason, action FROM alerts ORDER BY id DESC LIMIT ?", (FEED_ROWS,))
    except sqlite3.Error as err:
        threats = worth = 0
        rows = []
        problems.append(("red", f"Can't read the alert database ({err})."))
    if states["suricata"] != "active":
        problems.append(("red", "Network monitoring is stopped."))
    if states["pecan-pipeline"] != "active":
        problems.append(("red", "Alert processing is stopped."))
    if threats:
        problems.append(("red", f"{threats} serious threat{'s' * (threats > 1)} in the last hour."))
    if states["pecan-honeypot"] != "active":
        problems.append(("yellow", "The trap door (automatic blocking) is stopped."))
    if time.time() - drops["rose_at"] < DROPS_WINDOW:
        problems.append(("yellow", "The Pi was too busy to inspect some traffic in the last 10 minutes."))
    if worth:
        problems.append(("yellow", f"{worth} thing{'s' * (worth > 1)} worth a look in the last 24 hours."))
    level = "red" if any(l == "red" for l, _ in problems) else "yellow" if problems else "green"
    headline = {"green": "All good. Your network is protected.",
                "yellow": "Protected, but something needs a look.",
                "red": "Action needed."}[level]
    feed = [{"id": r[0], "time": local_time(r[1]), "detection": r[2], "kind": PLAIN_DETECTION.get(r[2], r[2]),
             "verdict": r[3], "plain_verdict": PLAIN_VERDICT.get(r[3], r[3]), "priority": r[4],
             "signature": r[5], "sid": r[6], "severity": r[7], "src": r[8], "dst": r[9], "count": r[10],
             "score": r[11], "reason": plain_reason(r[12]), "raw_reason": r[12], "action": r[13]} for r in rows]
    return {"level": level, "headline": headline, "problems": [p for _, p in problems],
            "services": states, "kernel_drops": d, "feed": feed}


def local_time(iso):
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%d %b %H:%M:%S")
    except (TypeError, ValueError):
        return str(iso)


@app.get("/")
def home():
    return render_template("home.html", s=status())


@app.get("/api/status")
def api_status():
    return jsonify(status())


# --- setup commands ---------------------------------------------------------------------------
def set_env(updates):
    """Replace or append KEY='value' lines in .env, keeping everything else (GROQ_API_KEY)."""
    lines = ENV.read_text().splitlines() if ENV.exists() else []
    lines = [l for l in lines if l.split("=", 1)[0].strip() not in updates]
    # Single quotes: python-dotenv does no $-interpolation inside them (scrypt hashes contain '$').
    lines += [f"{k}='{v}'" for k, v in updates.items()]
    ENV.write_text("\n".join(lines) + "\n")
    ENV.chmod(0o600)


def cmd_set_password(a):
    pw = getpass.getpass("New admin password (min 12 chars): ")
    if len(pw) < 12:
        sys.exit("too short")
    if pw != getpass.getpass("Again: "):
        sys.exit("passwords differ")
    updates = {"PANEL_PASSWORD_HASH": generate_password_hash(pw, method="scrypt")}
    if not os.environ.get("PANEL_SECRET_KEY"):
        updates["PANEL_SECRET_KEY"] = secrets.token_hex(32)
    set_env(updates)
    print("saved to .env; restart the panel to use it")


def cmd_make_cert(a):
    TLS.mkdir(parents=True, exist_ok=True)
    TLS.chmod(0o700)
    san = ",".join(["DNS:" + os.uname().nodename, "DNS:localhost", "IP:127.0.0.1"]
                   + [f"IP:{ip}" for ip in iface_ips("tailscale0") + a.ip if not ip.startswith("fe80")])
    r = subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
                        "-nodes", "-days", "825", "-subj", "/CN=Pecan Pi panel", "-addext", f"subjectAltName={san}",
                        "-keyout", str(TLS / "key.pem"), "-out", str(TLS / "cert.pem")],
                       capture_output=True, text=True)
    if r.returncode:
        sys.exit(r.stderr)
    (TLS / "key.pem").chmod(0o600)
    fp = subprocess.run(["openssl", "x509", "-in", str(TLS / "cert.pem"), "-noout", "-fingerprint", "-sha256"],
                        capture_output=True, text=True).stdout.strip()
    print(f"cert for {san}\n{fp}\n(compare this fingerprint with the browser's warning page)")


def cmd_serve(a):
    if not (os.environ.get("PANEL_PASSWORD_HASH") and os.environ.get("PANEL_SECRET_KEY")):
        sys.exit("no admin password yet: run  panel.py set-password")
    if not (TLS / "cert.pem").exists():
        sys.exit("no TLS cert yet: run  panel.py make-cert")
    host = a.host or next(iter(iface_ips("tailscale0")), None)
    if not host:
        sys.exit("tailscale0 has no address; pass --host")
    from werkzeug.serving import run_simple
    print(f"panel on https://{host}:{a.port}/")
    run_simple(host, a.port, app, threaded=True,
               ssl_context=(str(TLS / "cert.pem"), str(TLS / "key.pem")))


def main():
    p = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    sub = p.add_subparsers(dest="cmd", required=True)
    sub.add_parser("set-password")
    c = sub.add_parser("make-cert")
    c.add_argument("--ip", action="append", default=[], help="extra IP for the certificate (repeatable)")
    s = sub.add_parser("serve")
    s.add_argument("--host", help="address to listen on (default: tailscale0)")
    s.add_argument("--port", type=int, default=PORT)
    a = p.parse_args()
    {"set-password": cmd_set_password, "make-cert": cmd_make_cert, "serve": cmd_serve}[a.cmd](a)


if __name__ == "__main__":
    main()
