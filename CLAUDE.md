# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Pecan Pi: a Raspberry Pi network-security appliance. Suricata sniffs `wlan0` and `eth0` (both always listed in `deploy/override.conf`, so Wi-Fi or Ethernet works with no config change; an unplugged interface is just idle) and writes events to `/var/log/suricata/eve.json`; a Python pipeline tails that file, batches alerts, sends them to an LLM on Groq (`openai/gpt-oss-120b`) for SOC-style triage, and stores alerts plus AI verdicts in SQLite (`pecan.db`).

## Commands

There is no build, lint, or test suite. Scripts run directly with the venv interpreter (`groq` lives in `.venv`; `python-dotenv` comes from system site-packages):

```sh
.venv/bin/python pipeline.py      # main pipeline (normally run by systemd, see below)
.venv/bin/python test_groq.py     # sanity-check GROQ_API_KEY by listing available Groq models
.venv/bin/python analyze.py       # one-shot: triage the most recent real alert in eve.json
.venv/bin/python alerts.py        # tail eve.json and print alerts, no AI
nice -n 19 .venv/bin/python report.py --since 2026-10-01 [--until ...] [--no-ai]   # PDF report -> reports/ (gitignored)
sudo .venv/bin/python backfill.py  # re-triage 'AI unavailable' rows (--dry-run: no API calls/writes)
.venv/bin/python tui.py         # Textual dashboard: service status + latest 50 alerts (read-only DB, run as normal user)
.venv/bin/python anomaly.py snapshot --since 2026-10-04T22:32   # copy flow events (eve.json + rotated files) into baseline_flows.jsonl
nice -n 19 .venv/bin/python anomaly.py train               # fit Isolation Forest -> anomaly_model.joblib
.venv/bin/python anomaly.py eval FILE.jsonl               # score a flow file with the live code path
.venv/bin/python make_replay.py SNAPSHOT --pi <pi-ip> --peer <laptop-ip> --out-dir replay   # offline attack replays (no network traffic)
sudo python3 honeypot.py list | unblock IP | unblock-all   # current honeypot blocks (nftables table inet pecan)
python3 honeypot.py serve --dry-run --port 2223          # decoy without firewall changes (service must not hold the port)
sudo .venv/bin/python recon.py discover 192.168.221.65   # VAPT: nmap -sV a target the analyst names (never auto-scanned)
.venv/bin/python recon.py review [--scan N]              # list findings + proposed non-destructive check + reasoning
sudo .venv/bin/python recon.py approve <finding_id>      # run ONLY that finding's read-only check, then triage it
sudo .venv/bin/python recon.py decline <finding_id> [--note ...]
.venv/bin/python panel.py set-password | make-cert [--ip IP] | serve [--host IP]   # web panel (normally pecan-panel.service)
sudo sh deploy/install-code.sh   # root-owned copies of root-run code -> /opt/pecan (+ pecan-helper)
```

`GROQ_API_KEY` is read from `.env` (gitignored) via `load_dotenv()`.

Generate a test alert: `ping` any host — `deploy/local.rules` defines SID 9000001 for ICMP echo. This SID is deliberately ignored by `pipeline.py` (`IGNORE_SIDS`) and `analyze.py`, so it confirms Suricata works but never reaches the AI/DB.

Inspect results: `sqlite3 pecan.db "SELECT * FROM alerts ORDER BY id DESC LIMIT 20"`.

## Deployment (systemd)

Files in `deploy/` are copies of what is installed on the Pi; editing them in the repo does not apply them:

| Repo file | Installed at |
|---|---|
| `deploy/pecan-pipeline.service` | `/etc/systemd/system/pecan-pipeline.service` |
| `deploy/override.conf` | `/etc/systemd/system/suricata.service.d/override.conf` |
| `deploy/local.rules` | `/etc/suricata/rules/local.rules` |
| `deploy/logrotate-suricata` | `/etc/logrotate.d/suricata` |
| `deploy/pecan-trafficgen.service` / `.timer` | `/etc/systemd/system/` (enable the `.timer`) |
| `deploy/pecan-logrotate.service` / `.timer` | `/etc/systemd/system/` (enable the `.timer`) |
| `deploy/pecan-honeypot.service` | `/etc/systemd/system/pecan-honeypot.service` (enable it) |
| `deploy/logrotate-pecan` | `/etc/logrotate.d/pecan` |
| `pecan-helper.py` | `/usr/local/sbin/pecan-helper` (`install -o root -g root -m 0755`, a copy, never a symlink) |
| `pipeline.py` `triage.py` `netinfo.py` `anomaly.py` `honeypot.py` `trafficgen.sh` `tailscale_derp.json` (+ `anomaly_model.joblib` if present) | `/opt/pecan/` root-owned copies, via `deploy/install-code.sh` (also installs `pecan-helper`) |
| `deploy/requirements-root.txt` | `/opt/pecan/venv` (root-owned venv, `--system-site-packages`) for `pecan-pipeline` |
| `deploy/pecan-panel.service` | `/etc/systemd/system/pecan-panel.service` (enable it) |
| `deploy/sudoers-pecan` | `/etc/sudoers.d/pecan` (`install -m 0440`, then `visudo -cf`) |
| `deploy/pecan-protected.txt` | `/etc/pecan/protected.txt` (`install -o root -g root -m 0644`) |

Panel main switches live in `/etc/pecan/settings.json` (root-owned, written only by `pecan-helper set-switch`, log: `journalctl -t pecan-helper`). `netinfo.load_settings()`: missing file/key = on; unreadable = on + error. Re-read by `pipeline.py` every flush (signatures, anomaly, AI: off stores `AI explanations off`, which `backfill.py` skips), by `honeypot.py` every hit (auto_block) and by `report.py` (AI off = `--no-ai`). No restart needed. `anomaly_iface` (`all`|`eth0`|`wlan0`, `pecan-helper set-anomaly-iface`; missing/unknown = all, the old behaviour): live anomaly scoring uses flows from that interface only (filtered before the per-source window, like `snapshot --iface`; a change starts a fresh Scorer); signatures are unaffected. Shown read-only in the IT System card (no panel control).

Panel IP lists (`netinfo.load_ip_list()`, one `IP-or-CIDR  # note` per line): `/etc/pecan/allowlist.txt` (trusted: never auto-blocked; max /16, IPv6 /48) and `denylist.txt` (always blocked; max /24, IPv6 /64) are written only by `pecan-helper list-add|list-remove`; `protected.txt` is installed by hand and no command changes it (admin laptop's Tailscale IP). The helper refuses a deny entry overlapping protected, trusted, the Pi's own IPs or gateway, and a trust entry overlapping a deny entry. Adding a trusted range lifts current timed blocks inside it; `list-blocks` / `unblock IP` show and lift timed blocks.

`/etc/suricata/suricata.yaml` is not in the repo; local changes: `ethernet: yes` under eve-log (logs MAC addresses, used by `anomaly.py` to drop broadcast/multicast flows), and `- pecan-custom.rules` under `rule-files` (panel custom rules).

Panel rules (phase 4, `pecan-helper rules-category|custom-add|custom-remove`, one change at a time via `/etc/pecan/.rules-lock`): **categories** = seven noisy/policy rule groups (info, hunting, adware, tor, p2p, chat, games; matched by `re:msg:\s*"(ET|GPL) WORD\b` in `/etc/suricata/disable.conf`, which the helper owns); malware/exploit/attack/scan groups cannot be switched off. A change runs `suricata-update --offline --no-reload --no-test --local /etc/suricata/rules/local.rules` (rebuilds from the cached download, never fetches new rules; `--local` is required: suricata-update merges only its own fixed list of `*-events.rules` from `/etc/suricata/rules`, so without it SID 9000001 silently disappears, found in the live check 2026-10-19), aborts and rolls back if any enabled SID in 9000000-9199999 present before is missing after, notes (doesn't abort) other lost SIDs not explained by a switched-off category, then a full `suricata -T` (~30 s, `nice 19`), then `suricatasc -c reload-rules` (waits until live); any failure restores `disable.conf` + `suricata.rules` (`*.pecan-prev` copies) and the running Suricata keeps its rules. **Custom rules**: structured form only (protocol, from/to = any/home/outside/IP-or-CIDR, port, name, optional text; text chars `" ; \ |` written as hex so they can't add keywords), always `alert`, `msg:"PECAN CUSTOM ..."`, SIDs 9100000-9199999, max 100, in `/var/lib/suricata/rules/pecan-custom.rules`; `custom-edit` keeps the SID and bumps `rev` (and keeps on/off), `custom-toggle` off = the line stays, commented `# alert ...`; every change is tested alone (`suricata -T -S`, ~0.3 s) before reload. Rule changes run as panel background jobs (`/api/jobs/<id>`, polled every 1 s; one at a time; in memory only; the helper prints `step: rebuilding|testing|reloading` lines before its JSON and is started in its own session so a panel restart doesn't interrupt it). Validation messages start with the field (`port:`, `from:`, ...) so the panel shows them under that box. Panel errors: Simple mode shows a plain sentence (`panel.PLAIN_ERRORS`, matched on the helper's text), IT mode the helper's own message. A manual online `suricata-update` also reads `disable.conf`, so categories survive it, but must also be given `--local /etc/suricata/rules/local.rules`. Measured 2026-10-19: full `suricata -T` 30 s, kernel_drops 0 before and after; 5.6 GB RAM available, Suricata RSS 1.4 GB (a reload briefly holds two detection engines).

The stock logrotate config HUPed a pidfile path our override doesn't use, so Suricata never reopened its logs after rotation; the repo version HUPs via `systemctl kill` and uses `delaycompress`. It also sets `daily` + `maxsize 100M` (keep 14): with no frequency it inherited `weekly` from `/etc/logrotate.conf`, so eve.json reached 443 MB in 3.7 days (~120 MB/day). The system logrotate runs only once a day, so `pecan-logrotate.timer` runs this one file hourly to enforce the size cap (`Nice=19`, idle I/O). The Pi has no RTC: after it was off 2026-10-08 15:41 -> 10-15 23:57 the journal shows the boot at the old shutdown time until NTP syncs. `pipeline.py` detects rotation (inode change) and truncation and reopens `eve.json`.

**Install steps outside the repo** (verified 2026-10-19): `sudo systemctl mask systemd-networkd-wait-online.service` (NetworkManager runs the network and systemd-networkd manages no links, so it waited for its timeout: boot ~2m40s -> 39 s). Power: use the official Raspberry Pi 5.1 V 3 A PSU; at 03:21 2026-10-19 the Pi hard-reset (journal just stops, no shutdown) during a Games-on change, i.e. rebuild + `suricata -T` at full 4-core load; after swapping the PSU two back-to-back group changes ran clean with `vcgencmd get_throttled` = `0x0`. Check `get_throttled` after any unexplained reboot.

After changing one, copy it into place, then `sudo systemctl daemon-reload` and restart the relevant unit (`pecan-pipeline` or `suricata`). Logs: `journalctl -u pecan-pipeline -f`.

**Root-run code never runs from `/home/raven`** (phase 6, 2026-10-19): the pipeline (root), trafficgen (root) and honeypot (`CAP_NET_ADMIN`) run root-owned copies in `/opt/pecan`, so editing a `.py` in the repo changes nothing live until `sudo sh deploy/install-code.sh` + restart. Reason: the panel runs as `raven`; if `raven`-writable files ran as root, a panel compromise would be root. The pipeline's data stays in the repo: `WorkingDirectory` + `PECAN_DATA=/home/raven/pecan-pi` (`netinfo.DATA`: `.env`, `recon_active.json`; `pecan.db` relative to the working dir); manual runs from the repo default `DATA` to the script's own dir, as before. The anomaly model is loaded from next to the code (`/opt/pecan/anomaly_model.joblib`): joblib = pickle = code. `install-code.sh` never deletes it; retire it with `sudo rm`.

The pipeline service has no `User=`, so it runs as root and `pecan.db` is root-owned; running `pipeline.py` manually as a regular user will fail to write the DB (and may lack read access to `eve.json`). Stop the service before running it manually to avoid two writers.

## Pipeline architecture (`pipeline.py` + `triage.py`)

- Opens `eve.json` and seeks to the end — only events arriving after startup are processed; restarting the service drops anything in the current batch.
- Alerts are deduplicated in memory by `(signature_id, src_ip, dest_ip)` with a count; the first event of each group is kept as the representative.
- Every `BATCH_SECONDS` (30), the batch is flushed: each group is slimmed to a fixed set of fields, then `triage.collapse()` merges groups of the same SID that share a source or a destination (whichever side gives fewer groups), recording `n_src`/`n_dest` and a `group_key` (`src->*`, `*->dst` or `src->dst`). Reason: Tailscale on the Pi does a STUN netcheck to ~70 relay servers every ~5 min, which used to be ~150 groups (~17k tokens) in one call.
- Groq free tier for `openai/gpt-oss-120b`: **8,000 tokens/minute** (prompt + requested completion) and 1,000 requests/day. An oversized request gets HTTP 413 and retrying cannot help. `triage_all()` therefore sends chunks (<=25 items, ~3,500 estimated prompt tokens, `max_completion_tokens=2000`, `reasoning_effort="low"`), paces them under 7,000 tokens/min, backs off on 429, halves a chunk on 413, and gives up after 90s per flush. Every call logs `groq limits: requests left today X/Y, tokens left this minute A/B` (Groq has no daily-token header).
- **Verdict consistency** (before the cache, SSDP got 4 different verdict/priority combinations in ~30 identical calls): `temperature=0`; a signature item whose rule + host group got a real AI verdict in the last 6h reuses it, reason prefixed `[cached]`. "Host group" = its `group_key`, and for a single pair also the merged `src->*` / `*->dst` groups (`cache_keys()`). Cached rows are never a cache source, so verdicts expire 6h after the AI last judged them; after expiry the last verdict from the previous 7 days is sent as `previous_verdict` and the prompt says to keep it unless something changed. Anomalies are never cached or hinted (a new scan must not inherit an old verdict).
- The prompt requires one line per alert in the form `n | verdict | priority | reason`; `triage.parse()` splits on `|`. Any prompt change must keep this format in sync with the parser. Unparsed alerts or API errors are stored with verdict/priority `unknown` and reason `AI unavailable` rather than dropped.
- **Backfill:** `sudo .venv/bin/python backfill.py [--since ...] [--dry-run]` re-triages `AI unavailable` rows per original batch (same `seen_at`), oldest first. The DB has no payload fields (http/tls/dns), so those reasons are prefixed `[backfill]`. On 2026-10-04 it fixed 1,556 rows (all STUN-burst 413s) with one Groq call plus the cache. `--retriage [--since/--until]` re-judges ALL rows in the range, one verdict per rule + host group for the whole range (no cache/hints), reasons `[retriage]`; it backs up `pecan.db` first, so the original verdicts stay in the backup.
- `CONTEXT` (`triage.py`) describes the host to the model to reduce false positives, including Tailscale: STUN to DERP relays, DERP over TLS, and its port mapper probing the default gateway with SSDP (UDP 1900) and NAT-PMP/PCP (UDP 5351) — this is what fires `ET DOS Possible SSDP Amplification Scan`. `host_context()` appends the current host IPs and default gateway (`hostname -I`, `ip route`) at each call, since hotspot IPs change. Used by `pipeline.py`, `backfill.py`, `report.py` and `analyze.py`.
- Schema: `triage.open_db()` creates the table and adds missing columns with `ALTER TABLE`, backing up `pecan.db` first (`pecan.db.bak-*`).
- Tailscale started 2026-10-04T22:23, before the anomaly baseline (22:32): its STUN/DERP flows are part of the baseline. Keep it running, and say so in the thesis.

`analyze.py` and `alerts.py` are earlier prototypes of the same flow, kept as standalone debugging tools.

## Honeypot + prevention (`honeypot.py`, `pecan-honeypot.service`)

The "P" in IDPS. A decoy SSH service on TCP 2222 (nothing legitimate runs there): on each completed connection it blocks the source with nftables, sends a real OpenSSH banner, reads at most 256 bytes (the client banner) for up to 10 s, closes, and appends one JSON line to `/var/log/pecan/honeypot.json`. No auth, no shell, attacker bytes are only stored (printable ASCII, 128 chars). `pipeline.py` tails that file next to `eve.json` (`Tail` class), groups hits per source IP per 30 s batch, triages them like anything else (`detection='honeypot'`, never cached, `action` column = what the firewall did) and the TUI/report show them.

- **Block first, AI after:** the block is immediate and does not depend on the AI verdict (AI may be down; the banner is attacker-controlled text, so prompt injection cannot unblock anyone). Blocking happens only after a completed TCP handshake, so a spoofed source cannot get someone else blocked.
- **nftables:** own table `inet pecan`, sets `blocked4`/`blocked6` with `timeout` (`PECAN_BLOCK_SECONDS`, default 3600; kernel expires them, even if the service crashed), chain at input priority -10, policy accept. Permanent denylist: sets `denied4`/`denied6` (`flags interval`, no timeout), filled from `/etc/pecan/denylist.txt` at startup and kept in sync live by `pecan-helper`; enforced only while the service runs (overlapping entries are skipped, and if nft rejects the denylist the honeypot starts without it rather than not at all). Only `iifname wlan0/eth0` is filtered, so `tailscale0` (SSH over Tailscale) and `lo` are never touched. Exempt: UDP 41641 (Tailscale's WireGuard; keeps a laptop's direct Tailscale path up when its LAN IP is blocked; WireGuard ignores unauthenticated packets), and established connections to 2222 (so the decoy can finish reading the connection that caused the block). Restart, stop (`ExecStopPost` deletes the table) and reboot all clear every block: deliberately not persisted.
- **Allowlist** (re-read at every hit, hotspot IPs change; `netinfo.py`): loopback, the Pi's IPs, default gateway(s), anything whose local address is on `tailscale0` (by interface, not by 100.64.0.0/10, which is also carrier-grade NAT space), the panel's `/etc/pecan/protected.txt` and `allowlist.txt` (no restart needed). Deliberately NOT allowlisted: IPs with an established SSH session (TCP to :22 is ESTABLISHED before authentication). Allowlisted hits are still logged and triaged (`not blocked: allowlisted (...)`).
- **Service:** `DynamicUser` + only `CAP_NET_ADMIN`, `ProtectSystem=strict`, system `python3` (stdlib only); runs the root-owned copies in `/opt/pecan` (`ProtectHome=yes`). `Nice=10`, `CPUQuota=10%`, `MemoryMax=64M`, max 50 concurrent connections. Editing either file needs `sudo sh deploy/install-code.sh && sudo systemctl restart pecan-honeypot`.
- **Installed block time is 600 s, not the repo's 3600 s:** a drop-in (`sudo systemctl edit pecan-honeypot` -> `/etc/systemd/system/pecan-honeypot.service.d/override.conf`, `[Service]` `Environment=PECAN_BLOCK_SECONDS=600`) is kept for testing and the demo. Back to 1 h: `sudo systemctl revert pecan-honeypot && sudo systemctl restart pecan-honeypot`. Check: `systemctl show pecan-honeypot -p Environment`.
- **Live test passed (2026-10-16):** `nc` from the laptop's hotspot IP (192.168.221.65) to 2222 was logged with its banner and blocked (nc + ping timed out); Tailscale ping and SSH stayed up; DB row 2725: `detection=honeypot`, `action=blocked 600s`, AI `suspicious`/`medium`; `honeypot.py unblock` restored access.
- **Limitations for the thesis:** a scanner that never touches 2222 is not blocked; IP blocks are weak against an attacker who changes IP; Tailscale and the gateway are a deliberate blind spot; blocks do not survive reboot by design. nmap's default/top-1000 port lists may include 2222: the anomaly live test from the laptop (step 7) and the Recon module's own scans can block their own source, so unblock between tests.

## Control panel (`panel.py`, `pecan-panel.service`)

Flask, HTTPS on port 8443 (self-signed cert from `make-cert`, includes the current tailscale0 + wlan0 IPs; re-run after a hotspot change), one admin password (scrypt hash + secret key in `.env`). Runs as `raven`, reads `pecan.db` read-only; every root action goes through `pecan-helper` (one sudoers line). Simple mode (owner) and IT mode (analyst): status, live feed (`/api/feed` polled every 2 s), switches, IP lists, timed blocks, rule groups, own rules (details in the deployment section above). Frontend: `panel/templates`, `panel/static` (no inline JS/CSS: strict CSP). Full write-up: `docs/implementation-notes.md` 5.9.

- **Server:** gunicorn (`python3-gunicorn`, Kali package, seen through the venv's system site-packages), started by `panel.py serve` (falls back to Werkzeug when gunicorn is missing, e.g. on a laptop). Not waitress: it has no TLS. **One worker, 8 threads:** login lockout, the `kernel_drops` trend and rule jobs are in-process memory.
- **Unit:** `User=raven`, `--host 0.0.0.0`, `RestrictNetworkInterfaces=lo wlan0 tailscale0` (by interface, since hotspot IPs change; **never eth0**, future SPAN port). systemd resolves those names to interface numbers at start and tailscaled recreates `tailscale0` on every start, so the unit `BindsTo=` the tailscale0 device and is `WantedBy=` it: stops with it, starts again with it. Trade-off: Tailscale down = panel down (LAN too). `ProtectSystem=strict`, `ProtectHome=read-only`, `PrivateTmp`; `ReadWritePaths=/etc/pecan /etc/suricata /var/lib/suricata -/run/sudo -/run/suricata` because the sandbox also applies to the helper sudo starts inside the unit. **`NoNewPrivileges` must stay off** (sudo is setuid). No `CPUQuota`/`MemoryMax`: the helper's `suricata -T` (~1.4 GB) runs in this cgroup. `KillMode=process`: a panel restart never kills a running rule change.
- **Known in-memory state:** login lockout (5 fails / IP / 15 min) and the job list reset when the panel restarts.
- **Measured (2026-10-19):** rule reloads during the live tests cost 281 `kernel_drops` (0.06%) in total; one rule-group change ~95 s on the Pi 4.
- **Phase 6 verified live (2026-10-19, after reboot):** all four services active under systemd, `/opt/pecan` code in use, Games off/on from the systemd panel works (sandbox paths correct). The power cut mid-change (Deployment section) left rules consistent (no `GAMES` line, 53053 rules): the rollback design held. **Not yet tested:** panel over wlan0 (deferred until the baseline-2 snapshot), recovery after a `tailscaled` restart, the eth0 block.
- Logs: `journalctl -u pecan-panel -f` (gunicorn errors + `login ok/failed from IP`), `journalctl -t pecan-helper` (every change).

### Demo checklist (5-minute video; full table with timings and talking points: implementation-notes 5.10)

Before: all four services active; laptop on the hotspot and on Tailscale, panel open over Tailscale, cert accepted, logged out; Simple mode, Games group on, no leftover own rules; laptop terminal ready with `nc <pi-wlan0-ip> 2222`.

1. Log in (HTTPS, lockout, idle logout).
2. Simple mode: big status, service dots, four switches.
3. Feed: one row, the "normal events hidden" line.
4. Rules: switch **Online games** off and keep going while it runs (~95 s).
5. Laptop: `nc <pi-wlan0-ip> 2222`, Ctrl-C. Panel (still up over Tailscale): "Someone tried the trap door" row + laptop IP under **Blocked for a while**.
6. **Unblock** it.
7. **Always blocked**: add `203.0.113.7` "Demo"; try the gateway IP (refused in plain words); remove 203.0.113.7.
8. Games shows off. **New rule**: "Telnet going out", TCP, home -> outside, port 23.
9. **Explain alerts in plain English** off, then on.
10. IT mode: filter honeypot, search the laptop IP, open the row; System card (`kernel_drops`, Groq limits); raw rule text.
11. Sign out. After: Games back on, remove the Telnet rule, `journalctl -t pecan-helper --since today`.

## Reconnaissance / VAPT (`recon.py`)

The thesis's outward-looking module and its only active capability. Analyst-initiated, non-destructive, human-in-the-loop. Nothing auto-scans: there is no service or timer, `recon.py` only runs when the analyst types it.

1. **Discover:** `recon.py discover <target>` runs `nmap -sT -sV --version-light -T3 --max-rate 100` (TCP connect, rate-capped, under `nice -n 19 ionice -c3`), parsed with `python-libnmap`. Prints Suricata `kernel_drops` before/after so you can show the scan cost no packets. Stores open ports + service/version/CPE in `recon_scan` / `recon_finding`.
2. **CVE match:** per `(product, version)`, `searchsploit --cve -j` against the local Exploit-DB. **Offline and already on Kali.** Provenance caveat (stated in the reasoning and report): Exploit-DB lists vulns that have a public exploit entry, each CVE-tagged; it is NOT the full NVD, so no match is not proof of no CVE. `match_cves()` has a `# TODO NVD:` seam to add a local NVD CPE cache later. `vulners.nse` is deliberately NOT used: it calls vulners.com per scan (not offline, phones home).
3. **Gate + XAI:** each finding is stored `status='proposed'` with a proposed non-destructive action and a **deterministic, rule-based** reasoning string (not an LLM, so the explanation is reproducible). `recon.py review` prints them; nothing runs until `approve <id>`.
4. **On approval:** only the proposed read-only check runs — `banner_grab` (read a banner, send nothing) or `version_reconfirm` (one `nmap -sV` on that port). `default_creds` is **registered as a non-destructive action but its body is `NotImplementedError` (TODO)** — a seam, not built. The confirmed finding is run through the same Groq triage and stored as an `alerts` row `detection='recon'` (like `backfill.py`; never cached). The AI verdict explains; it does not gate (the analyst already did).

**Live test passed (2026-10-16, scan 1):** `discover 192.168.221.65` (the Mint laptop) took ~25 s, 1 host up, 1 open port of the top 1000: 22/tcp OpenSSH 9.6p1 Ubuntu 3ubuntu13.16, no Exploit-DB match, proposed `banner_grab`. Suricata `kernel_drops` 1074 before and after (cumulative counter, unchanged). No Suricata alert fired for the scan, so nothing was tagged `[self-recon]`: Pi and laptop are both in the default HOME_NET, and scan rules match `$EXTERNAL_NET -> $HOME_NET` (same effect as in the CIC eval). `approve 1` read `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.16` (matches nmap), finding -> `verified`; alerts row 3433 `detection=recon`, AI `benign`/`low`.

**Exploitation seam (out of scope, not built):** `ALLOW_DESTRUCTIVE` is hardcoded `False` with no env/flag/setter that changes it. Actions live in an `ACTIONS` registry holding only `destructive=False` entries, and `dispatch()` refuses anything `destructive=True`. Two independent locks: the registry has no destructive action today, and the gate would block it anyway. Adding active exploitation later is a deliberate change in two visible places.

**Self-recon suppression** (so the Pi doesn't flag/block its own scan): `discover`/`approve` write `recon_active.json` (targets + window; `netinfo.py`), cleared on exit with a short tail for trailing flows and ignored if older than 1h. The anomaly detector's `excluded()` drops flows from the Pi's own MAC to a current scan target (same pattern and blind-spot caveat as the Tailscale allowlist); `pipeline.py` **tags** matching Suricata alerts `[self-recon]` rather than dropping them (keeps the audit trail, doesn't blind Suricata). The honeypot is unaffected (outbound scans never hit the inbound decoy; scanning the Pi itself is own-IP, already allowlisted). `collapse()` keys signature groups on `(sid, is_self_recon)` (via `SELF_RECON_TAG`), so a real attacker hitting the same rule+target in the same batch is never merged into the Pi's `[self-recon]` row and never inherits the tag.

**Risk/limits for the thesis:** Exploit-DB ≠ full NVD (no-match ≠ no-CVE); the self-recon exclusion is a deliberate blind spot while a scan runs; CVE matching depends on nmap's version guess. **The Recon module's nmap is the one authorised exception to "no scans during baseline collection" — do not run it on the Pi during the baseline-2 window.**

## Reporting (`report.py`)

PDF for a time range (`--since`/`--until`, local time, compared against `seen_at` in UTC), rendered with WeasyPrint + Jinja2 (Kali system packages, no pip). Reads `pecan.db` read-only, so it runs as a normal user next to the pipeline.

- Sections: executive summary, business impact, counts (verdict/priority/detection, alerts and events), top findings, technical appendix.
- **All numbers come from SQL; Groq writes only the prose**: the summary and the business impact, in one call with aggregates, top findings, the Pi's own IPs (`hostname -I`) and `bia.json`. `--no-ai` or a Groq failure falls back to a fixed template, and the PDF says which was used.
- Top findings group rows by signature + verdict + priority (the latest AI reason is shown, via SQLite's bare-column-with-`MAX(id)` rule); benign findings only fill a short list. `unknown` rows are shown as "not AI-reviewed", never as benign.
- Business impact: thesis definitions of BIA/RTO/RPO are constants in `report.py` (word for word). Asset RTO/RPO values live in `bia.json`, labelled "Example values for a small organization, configurable"; the thesis has no target values.

## Anomaly detection (`anomaly.py`; DISABLED pending baseline 2)

**Status (2026-10-16):** live scoring is **off**. The baseline-1 model was renamed to `anomaly_model.friend.joblib`, so `pipeline.py` logs `anomaly detection off: no /opt/pecan/anomaly_model.joblib`; signatures + AI triage run as normal. Reason: domain shift (below), which also spent a Groq request almost every 30 s batch (anomalies are never cached). **Baseline 2 = the Pi's own traffic on the phone hotspot (wlan0), not the uni network.** The Pi has always been on the user's phone hotspot, even when physically at uni; the hotspot's subnet changes when it restarts (192.168.221.x on 2026-10-18, 192.168.81.x from 2026-10-18 evening). Baseline 1 was a friend's hotspot, so baseline 2 is the network the detector actually runs on. Then the step 5 checklist runs again on it. **Baseline-2 START: PENDING** — set after the user's doctor meeting on 2026-10-19 (user gives the exact time); everything before it (setup, honeypot tests, phase 6 checks, reboots) is excluded. Collect >= 24 h from START.

Isolation Forest on Suricata `flow` events, as a second detector next to signatures. Phases: collect baseline -> `snapshot` -> train -> live scoring inside `pipeline.py`. Broadcast/multicast destinations are excluded in both training and scoring (`is_broadcast_or_multicast`), since that chatter depends on which network the Pi is on.

- 13 features per flow (`FEATURES`): per-flow size/packets/duration/port class/protocol, plus what the same source did in the last 60s (flows, distinct ports, distinct hosts, unanswered fraction). Training, replay and live scoring share `SourceWindow`, so features are computed identically.
- Threshold = false-positive budget (`--fp-budget`, default 2%) on the newest 20% of the baseline, held out from fitting. Attack replays are never used to set it; they are only evaluated with `eval`. Isolation Forest cannot score points beyond the training range as stranger than the most extreme baseline flow, which is why a 0.5% threshold caught nothing.
- Anomalies are grouped per source IP (a sweep across many hosts is one row).
- **Allowlist: the Pi's own Tailscale relay traffic** (`is_own_tailscale_relay()`) is excluded from training and scoring, before the per-source window, like broadcast. All three must hold: source MAC is the Pi's wlan0/eth0, destination is a DERP relay IP in `tailscale_derp.json` (176 IPs, `anomaly.py derp-refresh`, then retrain), and UDP 3478 / TCP 443 / TCP 80 / ICMP. Reason: Tailscale probes relays differently per network (baseline hotspot: UDP STUN; 192.168.221.x hotspot: TCP/443 + ICMP to every region), so 74% of the first live flags (2026-10-16) were these probes, and their burst inflated the window for the Pi's other flows. Signatures still see these flows. **Risk:** traffic from the Pi to Tailscale relay servers on those ports is invisible to the anomaly detector (e.g. a compromised Pi using DERP as an exfiltration channel); a relay IP missing from the list is scored (noisy, not blind). Retrained on the baseline only: 1,940 baseline flows excluded; fit 22,752 / calibration 5,689, threshold -0.6103. Replay: holdout FP 2.0%, 1000-port scans 98.6%, slow scan 86%, SSH sweep 0%.
- Test attacks only with `make_replay.py` + `eval` during baseline collection: no live scans until the baseline snapshot is taken.

The Pi's own traffic is too sparse for a baseline, so `trafficgen.sh` (systemd timer, every ~10 min, `Nice=19`) generates benign DNS lookups, a few HTTPS fetches, and apt update every 6h. **The baseline is therefore partly synthetic**; say so in the thesis. Do not scan or test during the baseline window.

### Thesis finding: domain shift (2026-10-16)

A model trained on one network does not transfer to another. Baseline 1 was recorded on a friend's phone hotspots (192.168.160.x, then 192.168.100.x). On a different hotspot (192.168.221.x) the live model flagged most of the Pi's ordinary traffic:

- Without the Tailscale allowlist: 224 of 295 usable live flows flagged (76%) in the first 6 min after boot; 74% of those were the Pi's own Tailscale relay probes, a behaviour that changes with the network.
- With the allowlist and a retrained model: **107 of 174 usable flows flagged (61%)**, 00:10-00:19 local, steady across the minutes rather than only right after boot. Every HTTPS flow (25/25) and most Tailscale port-mapper probes (UDP 5351, 32/43) were flagged.
- Cause: on that network the Pi's normal minute touches a median of 7 ports / 5 hosts and 23% of its flows go unanswered; in baseline 1 the median was 1 port / 2 hosts with 100% unanswered, and 95% of minutes touched 3 ports or fewer. The gateway answers Tailscale's NAT-PMP/SSDP probes there, Tailscale probes its own public IP (hairpin), and so on.
- Held-out FP on baseline 1 was 2.0% the whole time: the 2% budget only holds on the network the baseline describes.
- Response: not more allowlisting (that would hide symptoms and widen the blind spot), but a new baseline on the network where the detector is used, and retraining whenever the deployment network changes. Caveat: small sample (one 9-minute window right after a boot).

### Baseline 1 (friend's hotspot, superseded)

**Baseline collection started 2026-10-04T22:32 (+03, Pi local time)**: after MAC logging was enabled and the logrotate tests finished. Earlier flows have no MACs; leave them out. Target: ~2,000 usable flows, 2-3 days (i.e. ~Oct 6-7).

**Baseline frozen** (2026-10-04T22:32 -> 2026-10-08T15:40): 70,909 flows; the 40,528 broadcast/multicast flows were then permanently deleted from `baseline_flows.jsonl` (third-party data, promised deletion), leaving 30,381. Training output is identical either way, since `featurize()` drops them before the per-source window. The Pi was 192.168.160.145, then 192.168.100.15 from 2026-10-05T17:41 (all of the newest 20%).

**Results (2026-10-16, steps 1-4):** live model: fit 24,304 / calibration 6,077, threshold -0.5980, flags 2.0% of held-out flows (4.2% of fit flows). Replay (`--pi 192.168.100.15 --peer 192.168.100.65`; `replay/` is gitignored, it holds real flows): FP on real holdout 2.4%; detected 991/1000 for both 1000-port scans, 91/100 for the slow scan, **0/50 for the SSH sweep** (likely looks like Tailscale's STUN fan-out to ~70 relays in the baseline; not tuned away, report as a limitation).

### CIC-IDS2017 evaluation (`cic_eval.py`, 2026-10-16)

Both detectors on public labelled data. Monday pcap (benign) and Friday (attacks) were replayed on the laptop (Suricata 7.0.3, its own ET Open rules, default yaml, `-k none`, no MAC logging, so the broadcast filter uses its IP fallback); slim gzipped flow/alert events live in `cic/` (gitignored; `cic/provenance.txt` has versions and hashes). Friday was replayed twice: (a) default HOME_NET (all RFC1918, as on the Pi) and (b) `HOME_NET=192.168.10.0/24`.

```sh
.venv/bin/python cic_eval.py verify             # schedule vs traffic (writes nothing)
nice -n 19 .venv/bin/python cic_eval.py train   # Monday -> cic/model.joblib (refuses paths outside cic/)
nice -n 19 .venv/bin/python cic_eval.py report  # -> cic/results.json (~6 min); keep cic/report.txt via redirect
nice -n 19 .venv/bin/python cic_eval.py metrics # ablation -> cic/metrics.txt + .json (~7 min; scores Friday, fits nothing)
```

- Separate model, same code (`anomaly.fit_model`), same 2% FP budget on held-out Monday; Friday never tunes anything. Labels come from the official UNB schedule, not the CIC CSVs. `verify` showed: page times are ADT (**+3h = UTC**); all scan/DDoS traffic arrives from the firewall's inside address **172.16.0.1** (NAT), so scan vs DDoS is told apart by time only. **Deliberate deviation:** every victim <-> 205.174.165.73:8080 flow is Botnet all day (bots beacon every ~100s until capture end; only 736/2,199 are in the official 10:02-11:02 window; reported separately). Windows with no flows (sF, sX, sP, sA, sL, sI, b) are "can't be evaluated". 12 stray 172.16.0.1 flows are unlabelled.
- Suricata alerts are joined to flows by direction-free 5-tuple + time (flow_id differs per run); on run (a) this agrees with the flow_id join on 7,790/7,804 alerts.
- **Results:** Monday held-out FP 2.0% (threshold -0.5862); **Friday benign FP 1.8%** (same network four days later: contrast with the domain-shift finding). Anomaly detects 100% of sS/sT/sV/sR scan flows, 82% firewall-on, 99.5% sU, 89% sO; within 0-76s per scan; DDoS only 2.9% of flows (detected at 7s); Botnet ~1% (first flag after 29 min: effectively missed). Suricata with the Pi's HOME_NET misses most scans (172.16.0.1 counts as "home"); with the LAN HOME_NET it catches sS/sT/sV/sR at 0s, firewall-on at 26s and the DDoS by signature (`ET DOS Terse HTTP GET ... AnonMafiaIC`); neither detector catches the botnet by signature. Benign Suricata alerts 1.3% of flows, 0.3% without `SURICATA` stream/decoder events. Analyst load: ~240 benign rows/h from each detector (30s batches, before `collapse()`), more than the Groq free tier could triage if every anomaly batch is a call.
- **Ablation (`cic_eval.py metrics`, 2026-10-18; full tables in `cic/metrics.txt`).** Same flows, labels, model and threshold as `report` (shared `load_friday()`); Friday is test-only, nothing refitted. Universe: usable flows minus the 14 unlabelled (262,083 benign, 260,272 attack). Flow level = each flow one decision; per class = that class vs all benign. Event level: 18 episodes (one per schedule window with traffic, one per bot host), recall = episodes with >= 1 detected flow, precision = attack rows / all alert rows (analyst rows: anomaly source x 30 s, Suricata SID x source x 30 s, before `collapse()`), false alarms/h instead of FPR. Overall:

  | Config | Flow prec | Flow recall | Flow F1 | FPR | Episodes | Event prec | False alarms/h |
  |---|---|---|---|---|---|---|---|
  | (a) anomaly | 97.2% | 63.0% | 0.765 | 1.78% | 16/18 | 8.6% | 236 |
  | (b) Suricata, Pi HOME_NET | 27.3% | 0.5% | 0.010 | 1.29% | 8/18 | 7.6% | 245 |
  | (c) Suricata, LAN HOME_NET | 30.9% | 0.6% | 0.011 | 1.26% | 12/18 | 11.8% | 241 |
  | (d) anomaly OR (b) | 95.5% | 63.5% | 0.762 | 2.99% | 16/18 | 8.1% | 481 |
  | (d) anomaly OR (c) | 95.5% | 63.5% | 0.763 | 2.95% | 16/18 | 10.2% | 477 |
  | (c) signatures only | 22.4% | 0.1% | 0.002 | 0.27% | 8/18 | 23.8% | 40 |

  Anomaly ROC-AUC 0.991 overall; 1.000 sS/sT/sV/sR, 0.997 sU, 0.984 sO, 0.976 firewall-on, 0.978 DDoS, 0.934 Botnet. Findings: the OR adds no episodes over anomaly alone (both miss sN and one bot) but doubles false alarms, since the two detectors' false positives barely overlap (FPR 1.78 + 1.26 ~ 2.95). DDoS and Botnet rank well (AUC > 0.93) but sit inside the 2% threshold (recall 2.9% / 1.0%): a threshold effect, deliberately not tuned on Friday. Suricata's 4/5 bot episodes are only `SURICATA STREAM` engine events. Flow precision is inflated by 50% attack prevalence; FPR and false alarms/h carry over to deployment.
- The evaluation found `SourceWindow` was O(window) per flow (~15-20 ms/flow during a 30k flows/min scan); fixed to running counts with identical feature vectors (commit 3bf52c9).

### Step 5 checklist (after collection; rerun for baseline 2)

For baseline 2: replace `2026-10-04T22:32` with its start time and use `--out baseline_hotspot2.jsonl` (then `--baseline baseline_hotspot2.jsonl`) so baseline 1 stays for the thesis. Snapshot within ~a week of the start (logrotate keeps 14 files, rotating daily or at 100 MB). After freezing, delete its broadcast/multicast flows as was done for baseline 1, run `anomaly.py derp-refresh` before training, and use the Pi/laptop IPs on the current hotspot subnet for `make_replay.py`. No scans or tests on the Pi during collection.

For a lab SPAN baseline on eth0, add `--iface eth0` to `snapshot` (filters on eve's `in_iface`; default keeps all interfaces, the old behaviour). Suricata already captures eth0 (`-i wlan0 -i eth0` in the override, own af-packet entry, cluster-id 99; wlan0 uses the `default` entry; 8 worker threads = 4 per interface). Live scoring must match: `sudo pecan-helper set-anomaly-iface eth0` (see `anomaly_iface` in the Deployment section); set it back to `all` after the lab.


1. **Check size:** `.venv/bin/python anomaly.py snapshot --since 2026-10-04T22:32 --out /tmp/x.jsonl`. Need ~2,000 *usable* flows (the line says how many broadcast/multicast were excluded).
2. **Freeze the baseline:** `.venv/bin/python anomaly.py snapshot --since 2026-10-04T22:32 --until <now>` -> `baseline_flows.jsonl`. Record the until-time and flow counts for the thesis.
3. **Train:** `sudo nice -n 19 .venv/bin/python anomaly.py train` (sudo: the root-run pipeline must read the model). Record: fit/calibration sizes, threshold, held-out FP rate. Keep `--fp-budget 2` unless the held-out FP rate says otherwise; never tune it on attack results. Then `sudo sh deploy/install-code.sh` (copies the model to `/opt/pecan`, the only one the service loads).
4. **Offline evaluation (separate from calibration):** `make_replay.py baseline_flows.jsonl --pi <pi-ip> --peer <laptop-ip> --out-dir replay`, then `anomaly.py train --baseline replay/train.jsonl --out replay/model.joblib` and `anomaly.py eval replay/<file>.jsonl --model replay/model.joblib` for holdout, scan_pi_to_peer, scan_peer_to_pi, slow_scan_peer_to_pi, sweep_pi_ssh. Record FP on real flows and detection on synthetic per file.
5. **Turn it on:** `sudo systemctl restart pecan-pipeline`; journal must say `anomaly detection on`. Note `kernel_drops` (`tail -n 2000 /var/log/suricata/eve.json | grep '"event_type":"stats"' | tail -1 | jq .stats.capture.kernel_drops`).
6. **Live test A (Pi -> laptop):** on the Pi, `nmap -sT -T3 --top-ports 1000 <laptop-ip>` (connect scan, no scripts/version/OS detection). Wait ~2 min (flow timeout + 30s batch), then `sqlite3 pecan.db "SELECT id,detection,src_ip,dest_ip,count,score,signature,verdict,priority,reason FROM alerts WHERE detection='anomaly' ORDER BY id DESC LIMIT 5"`. Expect one anomaly row from the Pi with ~1000 ports and a real AI verdict. Note whether an `ET SCAN` signature also fired.
7. **Live test B (laptop -> Pi):** on the Linux Mint laptop (`sudo apt install nmap`; Pi IP from `ip -br addr`), `nmap -sT -T3 --top-ports 1000 <pi-ip>`. Same check; expect one row laptop -> Pi.
8. **Negative control:** ~30 min of normal use with the generator running; count anomaly rows (expect none or very few).
9. **CPU:** `kernel_drops` after each scan must equal the value from 5.; glance at `top` during scans.
10. **Then:** decide whether the traffic generator keeps running (the model learned its traffic as normal), retrain later on the demo network if it differs, and remember the Recon module's own nmap runs will be flagged.

## Project context
- Final-year capstone, due in ~1 month. I must explain and defend every part of this code to an academic panel, so after each change give me a short plain-English summary of what changed and why.
- Planned modules (from the thesis): Detection (Suricata, done), AI triage (done), Anomaly detection (scikit-learn Isolation Forest on flow features), Honeypot with automated prevention (block attacker IP at the Pi's own interface via nftables), Reconnaissance (nmap, non-destructive, analyst confirms each finding; active exploitation out of scope, done), Reporting (PDF), Interface (Textual TUI).
- Hardware: Raspberry Pi 4, 8GB RAM, Kali Linux, headless over SSH, microSD storage, phone hotspot (IP can change). The Pi belongs to a groupmate.
- Never starve Suricata of CPU. Check kernel_drops in eve.json stats after adding anything heavy.
- Design rule: non-destructive by default. Nothing that crashes, floods, or damages a target.

## Working rules
- One task at a time. Commit and push after each working piece.
- Never commit .env or pecan.db.
- Suricata's process is named "Suricata-Main" (capital S): use `pgrep -af -i suricata`, and manage it only via systemctl, never `suricata -D` by hand.
