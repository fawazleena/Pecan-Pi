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

`/etc/suricata/suricata.yaml` is not in the repo; local change: `ethernet: yes` under eve-log (logs MAC addresses, used by `anomaly.py` to drop broadcast/multicast flows).

The stock logrotate config HUPed a pidfile path our override doesn't use, so Suricata never reopened its logs after rotation; the repo version HUPs via `systemctl kill` and uses `delaycompress`. `pipeline.py` detects rotation (inode change) and truncation and reopens `eve.json`.

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

## Reporting (`report.py`)

PDF for a time range (`--since`/`--until`, local time, compared against `seen_at` in UTC), rendered with WeasyPrint + Jinja2 (Kali system packages, no pip). Reads `pecan.db` read-only, so it runs as a normal user next to the pipeline.

- Sections: executive summary, business impact, counts (verdict/priority/detection, alerts and events), top findings, technical appendix.
- **All numbers come from SQL; Groq writes only the prose**: the summary and the business impact, in one call with aggregates, top findings, the Pi's own IPs (`hostname -I`) and `bia.json`. `--no-ai` or a Groq failure falls back to a fixed template, and the PDF says which was used.
- Top findings group rows by signature + verdict + priority (the latest AI reason is shown, via SQLite's bare-column-with-`MAX(id)` rule); benign findings only fill a short list. `unknown` rows are shown as "not AI-reviewed", never as benign.
- Business impact: thesis definitions of BIA/RTO/RPO are constants in `report.py` (word for word). Asset RTO/RPO values live in `bia.json`, labelled "Example values for a small organization, configurable"; the thesis has no target values.

## Anomaly detection (`anomaly.py`; steps 1-4 done, step 5 pending)

Isolation Forest on Suricata `flow` events, as a second detector next to signatures. Phases: collect baseline -> `snapshot` -> train -> live scoring inside `pipeline.py`. Broadcast/multicast destinations are excluded in both training and scoring (`is_broadcast_or_multicast`), since that chatter depends on which network the Pi is on.

- 13 features per flow (`FEATURES`): per-flow size/packets/duration/port class/protocol, plus what the same source did in the last 60s (flows, distinct ports, distinct hosts, unanswered fraction). Training, replay and live scoring share `SourceWindow`, so features are computed identically.
- Threshold = false-positive budget (`--fp-budget`, default 2%) on the newest 20% of the baseline, held out from fitting. Attack replays are never used to set it; they are only evaluated with `eval`. Isolation Forest cannot score points beyond the training range as stranger than the most extreme baseline flow, which is why a 0.5% threshold caught nothing.
- Anomalies are grouped per source IP (a sweep across many hosts is one row).
- Test attacks only with `make_replay.py` + `eval` during baseline collection: no live scans until the baseline snapshot is taken.

The Pi's own traffic is too sparse for a baseline, so `trafficgen.sh` (systemd timer, every ~10 min, `Nice=19`) generates benign DNS lookups, a few HTTPS fetches, and apt update every 6h. **The baseline is therefore partly synthetic**; say so in the thesis. Do not scan or test during the baseline window.

**Baseline collection started 2026-10-04T22:32 (+03, Pi local time)**: after MAC logging was enabled and the logrotate tests finished. Earlier flows have no MACs; leave them out. Target: ~2,000 usable flows, 2-3 days (i.e. ~Oct 6-7).

### Step 5 checklist (after collection)

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
- Planned modules (from the thesis): Detection (Suricata, done), AI triage (done), Anomaly detection (scikit-learn Isolation Forest on flow features), Honeypot with automated prevention (block attacker IP at the Pi's own interface via nftables), Reconnaissance (nmap/Scapy, non-destructive, analyst must confirm before any exploit attempt), Reporting (PDF), Interface (Textual TUI).
- Hardware: Raspberry Pi 4, 8GB RAM, Kali Linux, headless over SSH, microSD storage, phone hotspot (IP can change). The Pi belongs to a groupmate.
- Never starve Suricata of CPU. Check kernel_drops in eve.json stats after adding anything heavy.
- Design rule: non-destructive by default. Nothing that crashes, floods, or damages a target.

## Working rules
- One task at a time. Commit and push after each working piece.
- Never commit .env or pecan.db.
- Suricata's process is named "Suricata-Main" (capital S): use `pgrep -af -i suricata`, and manage it only via systemctl, never `suricata -D` by hand.
