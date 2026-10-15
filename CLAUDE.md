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
.venv/bin/python recon.py discover 192.168.221.65        # VAPT: nmap -sV a target the analyst names (never auto-scanned)
.venv/bin/python recon.py review [--scan N]              # list findings + proposed non-destructive check + reasoning
sudo .venv/bin/python recon.py approve <finding_id>      # run ONLY that finding's read-only check, then triage it
sudo .venv/bin/python recon.py decline <finding_id> [--note ...]
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

`/etc/suricata/suricata.yaml` is not in the repo; local change: `ethernet: yes` under eve-log (logs MAC addresses, used by `anomaly.py` to drop broadcast/multicast flows).

The stock logrotate config HUPed a pidfile path our override doesn't use, so Suricata never reopened its logs after rotation; the repo version HUPs via `systemctl kill` and uses `delaycompress`. It also sets `daily` + `maxsize 100M` (keep 14): with no frequency it inherited `weekly` from `/etc/logrotate.conf`, so eve.json reached 443 MB in 3.7 days (~120 MB/day). The system logrotate runs only once a day, so `pecan-logrotate.timer` runs this one file hourly to enforce the size cap (`Nice=19`, idle I/O). The Pi has no RTC: after it was off 2026-10-08 15:41 -> 10-15 23:57 the journal shows the boot at the old shutdown time until NTP syncs. `pipeline.py` detects rotation (inode change) and truncation and reopens `eve.json`.

After changing one, copy it into place, then `sudo systemctl daemon-reload` and restart the relevant unit (`pecan-pipeline` or `suricata`). Logs: `journalctl -u pecan-pipeline -f`.

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
- **nftables:** own table `inet pecan`, sets `blocked4`/`blocked6` with `timeout` (`PECAN_BLOCK_SECONDS`, default 3600; kernel expires them, even if the service crashed), chain at input priority -10, policy accept. Only `iifname wlan0/eth0` is filtered, so `tailscale0` (SSH over Tailscale) and `lo` are never touched. Exempt: UDP 41641 (Tailscale's WireGuard; keeps a laptop's direct Tailscale path up when its LAN IP is blocked; WireGuard ignores unauthenticated packets), and established connections to 2222 (so the decoy can finish reading the connection that caused the block). Restart, stop (`ExecStopPost` deletes the table) and reboot all clear every block: deliberately not persisted.
- **Allowlist** (re-read at every hit, hotspot IPs change; `netinfo.py`): loopback, the Pi's IPs, default gateway(s), anything whose local address is on `tailscale0` (by interface, not by 100.64.0.0/10, which is also carrier-grade NAT space), optional `allowlist.txt` (IP/CIDR per line, `#` comments; restart the service after creating it). Deliberately NOT allowlisted: IPs with an established SSH session (TCP to :22 is ESTABLISHED before authentication). Allowlisted hits are still logged and triaged (`not blocked: allowlisted (...)`).
- **Service:** `DynamicUser` + only `CAP_NET_ADMIN`, `ProtectSystem=strict`, system `python3` (stdlib only); `/home/raven` is 0700, so `honeypot.py`, `netinfo.py` (and `allowlist.txt`) are bind-mounted to `/opt/pecan` read-only. `Nice=10`, `CPUQuota=10%`, `MemoryMax=64M`, max 50 concurrent connections. Editing either file needs `sudo systemctl restart pecan-honeypot`.
- **Installed block time is 600 s, not the repo's 3600 s:** a drop-in (`sudo systemctl edit pecan-honeypot` -> `/etc/systemd/system/pecan-honeypot.service.d/override.conf`, `[Service]` `Environment=PECAN_BLOCK_SECONDS=600`) is kept for testing and the demo. Back to 1 h: `sudo systemctl revert pecan-honeypot && sudo systemctl restart pecan-honeypot`. Check: `systemctl show pecan-honeypot -p Environment`.
- **Live test passed (2026-10-16):** `nc` from the laptop's hotspot IP (192.168.221.65) to 2222 was logged with its banner and blocked (nc + ping timed out); Tailscale ping and SSH stayed up; DB row 2725: `detection=honeypot`, `action=blocked 600s`, AI `suspicious`/`medium`; `honeypot.py unblock` restored access.
- **Limitations for the thesis:** a scanner that never touches 2222 is not blocked; IP blocks are weak against an attacker who changes IP; Tailscale and the gateway are a deliberate blind spot; blocks do not survive reboot by design. nmap's default/top-1000 port lists may include 2222: the anomaly live test from the laptop (step 7) and the Recon module's own scans can block their own source, so unblock between tests.

## Reconnaissance / VAPT (`recon.py`)

The thesis's outward-looking module and its only active capability. Analyst-initiated, non-destructive, human-in-the-loop. Nothing auto-scans: there is no service or timer, `recon.py` only runs when the analyst types it.

1. **Discover:** `recon.py discover <target>` runs `nmap -sT -sV --version-light -T3 --max-rate 100` (TCP connect, rate-capped, under `nice -n 19 ionice -c3`), parsed with `python-libnmap`. Prints Suricata `kernel_drops` before/after so you can show the scan cost no packets. Stores open ports + service/version/CPE in `recon_scan` / `recon_finding`.
2. **CVE match:** per `(product, version)`, `searchsploit --cve -j` against the local Exploit-DB. **Offline and already on Kali.** Provenance caveat (stated in the reasoning and report): Exploit-DB lists vulns that have a public exploit entry, each CVE-tagged; it is NOT the full NVD, so no match is not proof of no CVE. `match_cves()` has a `# TODO NVD:` seam to add a local NVD CPE cache later. `vulners.nse` is deliberately NOT used: it calls vulners.com per scan (not offline, phones home).
3. **Gate + XAI:** each finding is stored `status='proposed'` with a proposed non-destructive action and a **deterministic, rule-based** reasoning string (not an LLM, so the explanation is reproducible). `recon.py review` prints them; nothing runs until `approve <id>`.
4. **On approval:** only the proposed read-only check runs — `banner_grab` (read a banner, send nothing) or `version_reconfirm` (one `nmap -sV` on that port). `default_creds` is **registered as a non-destructive action but its body is `NotImplementedError` (TODO)** — a seam, not built. The confirmed finding is run through the same Groq triage and stored as an `alerts` row `detection='recon'` (like `backfill.py`; never cached). The AI verdict explains; it does not gate (the analyst already did).

**Exploitation seam (out of scope, not built):** `ALLOW_DESTRUCTIVE` is hardcoded `False` with no env/flag/setter that changes it. Actions live in an `ACTIONS` registry holding only `destructive=False` entries, and `dispatch()` refuses anything `destructive=True`. Two independent locks: the registry has no destructive action today, and the gate would block it anyway. Adding active exploitation later is a deliberate change in two visible places.

**Self-recon suppression** (so the Pi doesn't flag/block its own scan): `discover`/`approve` write `recon_active.json` (targets + window; `netinfo.py`), cleared on exit with a short tail for trailing flows and ignored if older than 1h. The anomaly detector's `excluded()` drops flows from the Pi's own MAC to a current scan target (same pattern and blind-spot caveat as the Tailscale allowlist); `pipeline.py` **tags** matching Suricata alerts `[self-recon]` rather than dropping them (keeps the audit trail, doesn't blind Suricata). The honeypot is unaffected (outbound scans never hit the inbound decoy; scanning the Pi itself is own-IP, already allowlisted). Edge case: if a real attacker and the Pi scan the same target+SID in one 30s batch, `collapse()` merges them into one `[self-recon]`-tagged row (`+1 host`).

**Risk/limits for the thesis:** Exploit-DB ≠ full NVD (no-match ≠ no-CVE); the self-recon exclusion is a deliberate blind spot while a scan runs; CVE matching depends on nmap's version guess. **The Recon module's nmap is the one authorised exception to "no scans during baseline collection" — do not run it on the Pi during the baseline-2 window.**

## Reporting (`report.py`)

PDF for a time range (`--since`/`--until`, local time, compared against `seen_at` in UTC), rendered with WeasyPrint + Jinja2 (Kali system packages, no pip). Reads `pecan.db` read-only, so it runs as a normal user next to the pipeline.

- Sections: executive summary, business impact, counts (verdict/priority/detection, alerts and events), top findings, technical appendix.
- **All numbers come from SQL; Groq writes only the prose**: the summary and the business impact, in one call with aggregates, top findings, the Pi's own IPs (`hostname -I`) and `bia.json`. `--no-ai` or a Groq failure falls back to a fixed template, and the PDF says which was used.
- Top findings group rows by signature + verdict + priority (the latest AI reason is shown, via SQLite's bare-column-with-`MAX(id)` rule); benign findings only fill a short list. `unknown` rows are shown as "not AI-reviewed", never as benign.
- Business impact: thesis definitions of BIA/RTO/RPO are constants in `report.py` (word for word). Asset RTO/RPO values live in `bia.json`, labelled "Example values for a small organization, configurable"; the thesis has no target values.

## Anomaly detection (`anomaly.py`; DISABLED pending baseline 2)

**Status (2026-10-16):** live scoring is **off**. The baseline-1 model was renamed to `anomaly_model.friend.joblib`, so `pipeline.py` logs `anomaly detection off: no anomaly_model.joblib`; signatures + AI triage run as normal. Reason: domain shift (below), which also spent a Groq request almost every 30 s batch (anomalies are never cached). **Baseline 2 is collected on the uni network starting Sunday 2026-10-18**, then the step 5 checklist runs again on it.

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

### Step 5 checklist (after collection; rerun for baseline 2)

For baseline 2: replace `2026-10-04T22:32` with its start time and use `--out baseline_uni.jsonl` (then `--baseline baseline_uni.jsonl`) so baseline 1 stays for the thesis. Snapshot within ~a week of the start (logrotate keeps 14 files, rotating daily or at 100 MB). After freezing, delete its broadcast/multicast flows as was done for baseline 1, run `anomaly.py derp-refresh` before training, and use the uni-network Pi/laptop IPs for `make_replay.py`. No scans or tests on the Pi during collection.


1. **Check size:** `.venv/bin/python anomaly.py snapshot --since 2026-10-04T22:32 --out /tmp/x.jsonl`. Need ~2,000 *usable* flows (the line says how many broadcast/multicast were excluded).
2. **Freeze the baseline:** `.venv/bin/python anomaly.py snapshot --since 2026-10-04T22:32 --until <now>` -> `baseline_flows.jsonl`. Record the until-time and flow counts for the thesis.
3. **Train:** `sudo nice -n 19 .venv/bin/python anomaly.py train` (sudo: the root-run pipeline must read the model). Record: fit/calibration sizes, threshold, held-out FP rate. Keep `--fp-budget 2` unless the held-out FP rate says otherwise; never tune it on attack results.
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
