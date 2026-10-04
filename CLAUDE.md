# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

Pecan Pi: a Raspberry Pi network-security appliance. Suricata sniffs `wlan0` and writes events to `/var/log/suricata/eve.json`; a Python pipeline tails that file, batches alerts, sends them to an LLM on Groq (`openai/gpt-oss-120b`) for SOC-style triage, and stores alerts plus AI verdicts in SQLite (`pecan.db`).

## Commands

There is no build, lint, or test suite. Scripts run directly with the venv interpreter (`groq` lives in `.venv`; `python-dotenv` comes from system site-packages):

```sh
.venv/bin/python pipeline.py      # main pipeline (normally run by systemd, see below)
.venv/bin/python test_groq.py     # sanity-check GROQ_API_KEY by listing available Groq models
.venv/bin/python analyze.py       # one-shot: triage the most recent real alert in eve.json
.venv/bin/python alerts.py        # tail eve.json and print alerts, no AI
.venv/bin/python tui.py         # Textual dashboard: service status + latest 50 alerts (read-only DB, run as normal user)
.venv/bin/python anomaly.py snapshot --since 2026-10-05   # copy flow events (eve.json + rotated files) into baseline_flows.jsonl
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

## Pipeline architecture (`pipeline.py`)

- Opens `eve.json` and seeks to the end — only events arriving after startup are processed; restarting the service drops anything in the current batch.
- Alerts are deduplicated in memory by `(signature_id, src_ip, dest_ip)` with a count; the first event of each group is kept as the representative.
- Every `BATCH_SECONDS` (30), the batch is flushed: each group is slimmed to a fixed set of fields, numbered with `n`, and sent in **one** LLM call.
- The prompt requires one line per alert in the form `n | verdict | priority | reason`; `triage()` parses lines by splitting on `|`. Any prompt change must keep this format in sync with the parser. Unparsed alerts or API errors are stored with verdict/priority `unknown` and reason `AI unavailable` rather than dropped.
- `CONTEXT` describes the host environment to the model to reduce false positives; it is duplicated in `analyze.py`.
- The `alerts` table is created with `CREATE TABLE IF NOT EXISTS`; there are no migrations, so schema changes need a manual `ALTER TABLE` or recreating `pecan.db`.

`analyze.py` and `alerts.py` are earlier prototypes of the same flow, kept as standalone debugging tools.

## Anomaly detection (`anomaly.py`, in progress)

Isolation Forest on Suricata `flow` events, as a second detector next to signatures. Phases: collect baseline -> `snapshot` -> train -> live scoring inside `pipeline.py`. Broadcast/multicast destinations are excluded in both training and scoring (`is_broadcast_or_multicast`), since that chatter depends on which network the Pi is on.

The Pi's own traffic is too sparse for a baseline, so `trafficgen.sh` (systemd timer, every ~10 min, `Nice=19`) generates benign DNS lookups, a few HTTPS fetches, and apt update every 6h. **The baseline is therefore partly synthetic**; say so in the thesis. Do not scan or test during the baseline window.

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
