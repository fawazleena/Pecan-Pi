# Pecan Pi: Implementation Notes (handoff for the Project B report)

**Snapshot date: 2026-10-16.** This describes the system as built on that date. Anything marked PENDING
had not been done yet. Numbers come from the repository, its commit history, `CLAUDE.md`, the live
database (`pecan.db`) and the CIC-IDS2017 evaluation output (`cic/report.txt`). If something here
disagrees with the code, the code wins; ask before writing it into the report.

Written for groupmates who did not see the build. Technical terms are explained in the
[Glossary](#13-glossary) at the end.

---

## 1. Status: about 85% complete

### DONE

- **Detection (Suricata)** on the Pi, listening on Wi-Fi (`wlan0`) and Ethernet (`eth0`), running as a system service.
- **AI triage (Groq, `openai/gpt-oss-120b`)**: alerts are batched every 30 s, sent to the model, and come back as a verdict, a priority and a reason.
- **Storage (SQLite)**: every alert and its AI verdict is saved in `pecan.db`.
- **TUI (Textual)**: a terminal dashboard showing service status and the latest 50 alerts.
- **Reporting**: a PDF report for any date range, with an executive summary, business impact (BIA/RTO/RPO), counts, top findings and a technical appendix.
- **Anomaly detection (Isolation Forest)**: code, training and evaluation finished. Tested offline (replayed attacks) and on the public CIC-IDS2017 dataset. **Live scoring is switched off** (see Pending and Section 5.6).
- **Honeypot + automated prevention**: fake SSH service on port 2222 that blocks anyone who connects, using the Pi's own firewall (nftables). Live test passed on 2026-10-16.
- **Reconnaissance / VAPT**: analyst-started, non-destructive nmap scan, offline CVE matching, and an approve/decline gate for each finding. Live test against our own laptop passed 2026-10-16 (Section 5.8).
- **CIC-IDS2017 evaluation** of both detectors (signatures and anomaly), plus a performance fix it uncovered.
- **Log rotation fix** so Suricata's log cannot fill the SD card.

### PENDING

1. **Uni lab baseline + live anomaly model.** A new "normal traffic" baseline is collected on the university network starting **Sunday 2026-10-18**. Then: train, evaluate, switch live scoring on, and run the live tests (Section 5.6, "Step 5 checklist" in `CLAUDE.md`).
2. **Cisco SPAN lab.** Not built yet. Nothing about it is in the repository, so it is not described here beyond being pending.
3. **Demo run.** Not done yet.

---

## 2. What Pecan Pi is (one paragraph)

Pecan Pi is a small network-security appliance built on a Raspberry Pi. It watches network traffic,
raises alerts when it sees something known to be bad (signatures) or something unusual (anomaly
detection), asks a large language model (LLM) to judge each alert the way a security-operations-centre
(SOC) analyst would, stores everything in a database, shows it on a dashboard, and produces PDF reports.
It also has a decoy service that automatically blocks attackers (the "prevention" part, which makes it
an **IDPS**: intrusion detection *and prevention* system), and a careful, analyst-controlled scanning
tool for checking other machines for known vulnerabilities.

---

## 3. Hardware and software stack (as built)

| Part | What is actually used |
|---|---|
| Hardware | Raspberry Pi 4, **8 GB RAM**, 4 CPU cores, microSD storage, no real-time clock. Headless (no screen), managed over SSH. The Pi belongs to a groupmate. |
| Network | Phone hotspot (the Pi's IP address changes between hotspots). Both Wi-Fi and Ethernet are monitored. |
| Operating system | **Kali Linux** (Kali GNU/Linux Rolling, `VERSION_ID=2026.3`) |
| Network IDS | **Suricata 8.0.7**, ET Open rule set plus one local test rule |
| AI triage | **Groq** cloud API, model **`openai/gpt-oss-120b`**, free tier |
| Remote access | **Tailscale** 1.102.4 (VPN used to reach the Pi) |
| Database | **SQLite** 3.53.4 (`pecan.db`) |
| Dashboard | **Textual** 8.2.8 (terminal user interface, Python) |
| PDF reports | **WeasyPrint** 69.0 + Jinja2 templates |
| Anomaly detection | **scikit-learn** 1.9.1 `IsolationForest` |
| Firewall (prevention) | **nftables** (Linux kernel firewall) |
| Reconnaissance | **nmap** 7.99, `python-libnmap`, **searchsploit** (local Exploit-DB copy) |
| Language | Python 3 (virtual environment `.venv`; Groq SDK 1.7.0) |
| Service management | systemd (services and timers, files in `deploy/`) |

Software versions above were read off the Pi on the snapshot date.

---

## 4. Architecture overview

```
              network traffic (wlan0 / eth0)
                          |
                          v
   +-------------------------------------------+
   |  Suricata (signatures)                    |---> eve.json  (alerts + flow records)
   +-------------------------------------------+         |
                                                         |
   attacker --> TCP 2222 --> honeypot.py ---block---> nftables (table inet pecan)
                                 |
                                 +--> honeypot.json
                                          |
                                          v
   +--------------------------------------------------------------+
   | pipeline.py  (runs as a service, every 30 s)                 |
   |  - reads new lines from eve.json and honeypot.json           |
   |  - groups duplicate alerts, merges "fan-out" groups          |
   |  - scores flows with the anomaly model (currently OFF)       |
   |  - triage.py: verdict cache, then Groq LLM for the rest      |
   +--------------------------------------------------------------+
                          |
                          v
                   pecan.db (SQLite)  <--- recon.py (analyst-run scans; findings + verified results)
                     |         |
                     v         v
                  tui.py    report.py --> PDF (Groq writes prose only; numbers from SQL)
```

In words:

1. **Suricata** watches traffic and writes events (alerts and per-connection "flow" records) to a log file, `/var/log/suricata/eve.json`.
2. **The honeypot** listens on port 2222. Anyone who connects is blocked immediately by the firewall, and the hit is written to `/var/log/pecan/honeypot.json`.
3. **The pipeline** (`pipeline.py`) follows both log files. Every 30 seconds it groups what arrived, optionally scores flows with the anomaly model, and sends the groups to the AI for a verdict (`triage.py`).
4. Results go into **SQLite** (`pecan.db`).
5. The **TUI** (`tui.py`) and the **PDF report** (`report.py`) read the database (read-only).
6. **Recon** (`recon.py`) is separate: the analyst runs it by hand against a named target. Its findings are stored in the same database and, once approved and verified, triaged by the same AI.

---

## 5. Modules

### 5.1 Detection (Suricata)

**What it does.** Inspects every packet on the Pi's network interfaces and raises an alert when traffic
matches a known attack pattern ("signature"). It also writes a summary record of every connection ("flow"),
which the anomaly detector uses.

**How it works.**
- Suricata runs as a systemd service. A drop-in file (`deploy/override.conf`) makes it listen on both `wlan0` and `eth0`, so Wi-Fi or Ethernet works without changing config; an unplugged interface is just idle.
- Rules: the public ET Open rule set, plus `deploy/local.rules` with one test rule (SID 9000001: any ping raises an alert). This test alert proves Suricata works but is deliberately ignored by the pipeline, so it never reaches the AI or database.
- Output: JSON lines in `eve.json`. One local change to Suricata's main config: `ethernet: yes`, so MAC addresses are logged (used by the anomaly detector).
- **Log rotation fix.** The stock rotation config signalled Suricata through a file path our setup does not use, so Suricata kept writing to the old (rotated) file. It also rotated only weekly. Measured result: `eve.json` grew to **443 MB in 3.7 days (~120 MB/day)**. The fix rotates daily or at 100 MB (keeps 14 files), and a timer checks the size every hour.

**Key design decisions and why.**
- Monitor both interfaces always: no config change when moving between Wi-Fi and Ethernet.
- Suricata is never starved of CPU: other services run at lower priority (`Nice`) and with CPU quotas (pipeline `CPUQuota=50%`, honeypot `CPUQuota=10%`). The check is Suricata's `kernel_drops` counter (packets it had to drop).

**Measured results.** Suricata on the Pi has been producing alerts since 2026-10-01. On the snapshot date the database held **3,387 rows** from 2026-10-01 to 2026-10-15 (3,363 signature, 23 anomaly, 1 honeypot). Detection quality was measured on CIC-IDS2017 (Section 6.2).

**Known limitations.**
- Signatures only catch what a rule describes. Encrypted traffic (HTTPS) hides the content; Suricata can only see metadata such as the server name and certificate.
- Results depend heavily on the `HOME_NET` setting (Section 6.4).
- The Pi has no real-time clock: after it was off (2026-10-08 15:41 to 2026-10-15 23:57) its logs show the old time until the internet clock (NTP) syncs.

### 5.2 AI triage (Groq, gpt-oss-120b)

**What it does.** Acts like a first-line SOC analyst: for each alert it decides `benign`, `suspicious`
or `malicious`, gives a priority (`low`/`medium`/`high`), and writes a one-line reason.

**How it works.**
- Every 30 s the pipeline groups identical alerts (same rule, same source, same destination) and counts them.
- `collapse()` then merges groups of the same rule that share a source or a destination (e.g. "the Pi -> 70 different servers" becomes one row).
- The model receives a description of the host (`CONTEXT`: Kali appliance, apt updates, what Tailscale normally does) plus the Pi's current IPs and gateway, then the alerts. It must answer one line per alert: `n | verdict | priority | reason`. The parser splits on `|`.
- Rate limits of the Groq free tier: **8,000 tokens per minute** and **1,000 requests per day**. The code sends chunks of at most 25 alerts / ~3,500 prompt tokens, paces itself under 7,000 tokens/minute, waits and retries when told to slow down (HTTP 429), halves a chunk that is too large (HTTP 413), and gives up after 90 s per batch.
- If the AI is unavailable or the answer can't be parsed, the alert is **still stored**, with verdict `unknown` and reason `AI unavailable`. `backfill.py` can re-triage those later.
- **Verdict cache:** if the same rule + host group got a real AI verdict in the last 6 hours, that verdict is reused (reason starts `[cached]`). After 6 h the AI judges it again, but is shown its previous verdict and told to keep it unless something changed.
- Settings: `temperature=0`, `reasoning_effort="low"`.

**Key design decisions and why.**
- **Groq, not Claude/OpenAI paid APIs:** free tier, fast. Trade-off: strict rate limits, which drove the batching/chunking design.
- **Collapse fan-out alerts:** Tailscale contacts ~70 relay servers every ~5 minutes, which used to produce ~150 alert groups (~17,000 tokens) in one call, more than double the per-minute limit (Section 6.5).
- **Cache + temperature 0:** fixes inconsistent verdicts (Section 6.3).
- **Never drop an alert because the AI failed:** the audit trail matters more than the verdict.
- **Anomalies and honeypot hits are never cached:** a new scan must not inherit an old verdict.

**Measured results.**
- Backfill on 2026-10-04 fixed **1,556** `AI unavailable` rows (all from the Tailscale burst / HTTP 413 problem) with **one** Groq call plus the cache.
- Before the cache, one SSDP alert got **4 different verdict/priority combinations in ~30 identical calls**.
- Database on the snapshot date: 3,379 `benign`, 8 `suspicious` verdicts (no `malicious`).

**Known limitations.**
- The AI explains; it is not ground truth. It can be wrong, and its quality depends on the context it is given.
- Data leaves the Pi: alert fields (IPs, ports, HTTP/TLS/DNS metadata) are sent to Groq's cloud.
- Free-tier limits: on a busy network the AI cannot judge everything in real time (Section 6.2, analyst load).
- Prompt injection risk: some alert fields come from attackers. Mitigation: the AI never controls blocking (honeypot blocks first, AI after), and recon actions are gated by the analyst, not the AI.

### 5.3 Storage (SQLite)

**What it does.** Keeps every alert and verdict in one file, `pecan.db`.

**How it works.** `triage.open_db()` creates the tables. Columns added later are added automatically,
and the database is backed up first (`pecan.db.bak-<date>`). The pipeline runs as root, so the file is
root-owned; the TUI and report open it read-only.

**Real database columns (snapshot):**

`alerts` table:

| Column | Meaning |
|---|---|
| `id` | row number |
| `seen_at` | batch time (UTC) |
| `sid` | Suricata rule ID |
| `signature` | rule name, or a summary for anomaly/honeypot/recon rows |
| `severity` | Suricata severity |
| `src_ip`, `dest_ip` | source and destination (or `*` / sample after collapsing) |
| `count` | how many events this row stands for |
| `verdict` | `benign` / `suspicious` / `malicious` / `unknown` |
| `priority` | `low` / `medium` / `high` / `unknown` |
| `reason` | AI's one-line reason (may start with `[cached]`, `[backfill]`, `[retriage]`, `[self-recon]`) |
| `detection` | `signature`, `anomaly`, `honeypot` or `recon` (default `signature`) |
| `score` | anomaly score (anomaly rows only) |
| `n_src`, `n_dest` | number of distinct sources / destinations merged into this row |
| `group_key` | how it was grouped: `src->*`, `*->dst` or `src->dst` |
| `action` | what the firewall did (honeypot rows), e.g. `blocked 600s` or `not blocked: allowlisted (...)` |

Index: `alerts_cache (sid, group_key, seen_at)` for the verdict cache.

`recon_scan` table (created by `recon.py` on first use): `id, started_at, target, args, host_count, note`.

`recon_finding` table: `id, scan_id, host, port, proto, service, product, version, cpe, cves, exploit_titles,
status (default 'proposed'), proposed_action, reasoning, verification, decided_at, decided_by`.

**Design decisions.** SQLite: one file, no server, light on a Pi. Read-only access from the dashboard and
report so they can't corrupt data while the pipeline writes.

**Limitations.** No payload fields (HTTP/TLS/DNS details) are stored, so re-triage later (`backfill.py`) sees
less than the live AI did; those reasons are marked `[backfill]`. Single file on a microSD card.

### 5.4 TUI (Textual dashboard)

**What it does.** A terminal dashboard (works over SSH) showing whether the three services (`suricata`,
`pecan-pipeline`, `pecan-honeypot`) are running, and the latest 50 alerts, coloured by priority.

**How it works.** Refreshes every 5 s. Columns: Time, Type (detection), Priority, Verdict, Signature,
Src -> Dst, Count, Reason. A detail panel shows the highlighted alert in full (including anomaly score).
Benign alerts can be hidden. Opens the database read-only and runs as a normal user.

**Design decisions.** Text UI instead of web UI: the Pi is headless and reached over SSH; no web server to secure.

**Limitations.** Read-only; it cannot unblock IPs or approve recon findings (those are command-line actions). Shows the latest 50 only.

### 5.5 Reporting (PDF + BIA)

**What it does.** `report.py --since ... [--until ...]` makes a PDF for a time range: executive summary,
business impact, counts (by verdict, priority, detection type), top findings, technical appendix.

**How it works.**
- **All numbers come from SQL queries. The AI (Groq) only writes the prose** (summary and business impact) in one call, given the aggregates, top findings, the Pi's own IPs and `bia.json`.
- `--no-ai`, or a Groq failure, falls back to a fixed template; the PDF states which was used.
- Top findings group by rule + verdict + priority. `unknown` rows are shown as "not AI-reviewed", never as benign.
- **BIA / RTO / RPO:** the thesis definitions are copied word for word into `report.py`. Asset recovery targets come from `bia.json`, labelled *"Example values for a small organization, configurable"*: router RTO 4 h; workstations RTO 8 h / RPO 24 h; file storage RTO 24 h / RPO 24 h; the Pi itself RTO 24 h / RPO 7 days.
- Rendered with WeasyPrint + Jinja2 at lowest CPU priority (`nice -n 19`).

**Design decisions.** Keeping numbers out of the LLM's hands means the AI cannot invent statistics.

**Limitations.** The RTO/RPO values are examples, not real targets (the thesis gives none). The prose is AI-written and should be read critically.

### 5.6 Anomaly detection (Isolation Forest) — built and evaluated, live scoring OFF

**What it does.** Learns what "normal" traffic looks like on a network and flags connections that don't fit,
so it can catch things no signature describes (e.g. a port scan).

**How it works.**
- Input: Suricata's flow records. 13 features per flow: bytes and packets each direction, duration, port class, protocol (TCP/UDP/ICMP), and what the same source did in the last 60 s (number of flows, distinct ports, distinct hosts, share of unanswered connections).
- Model: scikit-learn `IsolationForest`, 200 trees, `random_state=42`.
- **Threshold = false-positive budget:** 2% by default, set on the newest 20% of the baseline, which is held out from training. Attack data is never used to set it.
- Broadcast/multicast traffic and the Pi's own Tailscale relay traffic are excluded (they depend on the network, not on attacks).
- Anomalies are grouped per source IP (one row per scanning host) and sent to the AI like any alert.
- Phases: collect baseline -> `snapshot` -> `train` -> live scoring inside the pipeline.
- Because the Pi's own traffic is sparse, `trafficgen.sh` (every ~10 min) makes normal DNS lookups, HTTPS fetches and apt updates. **The baseline is therefore partly synthetic.**

**Key design decisions and why.**
- Isolation Forest: unsupervised (needs no labelled attacks), fast, small; suits a Pi. See Appendix Q3.
- Threshold set only on normal data, so the reported detection rates are not tuned to the test attacks.
- Same feature code (`SourceWindow`) for training, replay and live scoring, so features are identical everywhere.

**Measured results.**

*Baseline 1 (friend's phone hotspots, superseded):* collected 2026-10-04T22:32 to 2026-10-08T15:40, 70,909 flows; 40,528 broadcast/multicast flows deleted (third-party data), leaving 30,381.

| Model version | Fit / calibration flows | Threshold | Held-out FP |
|---|---|---|---|
| First model | 24,304 / 6,077 | -0.5980 | 2.0% |
| Retrained with Tailscale relay exclusion (1,940 flows excluded) | 22,752 / 5,689 | -0.6103 | 2.0% |

Offline replay results (synthetic attacks injected into real flows, no network traffic):

| Test | First model | Retrained model |
|---|---|---|
| False positives on real held-out flows | 2.4% | 2.0% |
| 1000-port scans | 991/1000 (both directions) | 98.6% |
| Slow scan | 91/100 | 86% |
| SSH sweep (50 hosts) | **0/50** | **0%** |

Live (domain shift, Section 6.1): on a different hotspot the model flagged 61-76% of the Pi's normal traffic, so live scoring was switched off.

CIC-IDS2017 results: Section 6.2.

**Known limitations.**
- **Does not transfer between networks** (domain shift); must be retrained when the deployment network changes.
- Missed the SSH sweep completely (likely looks like Tailscale's normal fan-out to ~70 relays in the baseline).
- Missed the botnet in CIC-IDS2017 (Appendix Q5) and caught only 2.9% of DDoS flows.
- Partly synthetic baseline.
- Isolation Forest cannot rank points far outside the training range as stranger than the most extreme normal flow; a 0.5% threshold caught nothing.
- Tailscale relay traffic from the Pi is invisible to this detector (could hide exfiltration over that channel).
- **Live scoring is off until the uni baseline (PENDING).**

### 5.7 Honeypot + automated prevention

**What it does.** A fake SSH server on port 2222, where nothing legitimate runs. Anyone who connects is
assumed hostile and is blocked by the Pi's firewall straight away. This is the "P" (prevention) in IDPS.

**How it works.**
- On each completed connection: block the source IP in nftables, send a real-looking OpenSSH banner (`SSH-2.0-OpenSSH_9.2p1 Debian-2+deb12u3`), read at most 256 bytes for up to 10 s, close, write one JSON line to `/var/log/pecan/honeypot.json`. No login, no shell; attacker bytes are only stored (printable ASCII, 128 characters).
- The pipeline picks up the hit, groups hits per source per 30 s, and triages them (`detection='honeypot'`, `action` = what the firewall did, never cached).
- Firewall: own table `inet pecan`, block lists with an automatic timeout (kernel removes entries even if the service crashed). Only `wlan0`/`eth0` are filtered.
- Allowlist (never blocked, still logged): loopback, the Pi's own IPs, default gateway, Tailscale, optional `allowlist.txt`.
- Hardened service: runs as a throw-away user with only the firewall permission (`CAP_NET_ADMIN`), read-only file system, `CPUQuota=10%`, `MemoryMax=64M`, at most 50 connections at once.

**Key design decisions and why.**
- **Block first, AI after:** blocking does not wait for the AI (it may be down), and the banner is attacker text, so prompt injection can't unblock anyone.
- **Only after a full TCP handshake:** a spoofed source address can't complete one, so nobody can get a third party blocked.
- **Exempt Tailscale** (by interface) and its WireGuard port UDP 41641: keeps remote admin access working.
- **Blocks are not saved across restart/reboot** (deliberate): a mistake is undone by restarting.
- Block time: 3600 s in the repo; **600 s installed** on the Pi for testing and the demo.

**Measured results.** Live test passed 2026-10-16: `nc` from the laptop (192.168.221.65) to port 2222 was logged with its banner and blocked (further `nc` and `ping` timed out); Tailscale ping and SSH stayed up; database row 2725 shows `detection=honeypot`, `action=blocked 600s`, AI verdict `suspicious`/`medium`; `honeypot.py unblock` restored access.

**Known limitations.**
- A scanner that never touches port 2222 is not blocked.
- IP blocks are weak against an attacker who changes IP.
- Tailscale and the gateway are a deliberate blind spot.
- nmap's common port lists may include 2222, so our own tests can block our own laptop (unblock between tests).

### 5.8 Reconnaissance / VAPT

**What it does.** Lets the analyst check a machine they name for running services and known
vulnerabilities, without harming it. It is the only module that sends traffic to other machines.

**How it works.**
1. **Discover:** `recon.py discover <target>` runs `nmap -sT -sV --version-light -T3 --max-rate 100` (normal TCP connections, at most 100 packets/s, lowest CPU and disk priority). It prints Suricata's `kernel_drops` before and after, to show the scan did not cost Suricata packets. Open ports and versions go into `recon_scan` / `recon_finding`.
2. **CVE match:** each product + version is looked up **offline** in the local Exploit-DB with `searchsploit`.
3. **Gate + explanation:** each finding is stored as `proposed`, with a proposed read-only check and a **rule-based** (not AI) reasoning text, so the explanation is reproducible. `recon.py review` lists them. Nothing runs until `recon.py approve <id>`.
4. **On approval:** only the proposed read-only check runs: `banner_grab` (read a banner, send nothing) or `version_reconfirm` (one `nmap -sV` on that port). The result is triaged by the same AI and stored as an alert with `detection='recon'`. `default_creds` is registered but **not implemented**.

**Key design decisions and why.**
- **Nothing scans automatically** (no service, no timer). Human in the loop for every action.
- **Active exploitation is out of scope and locked twice:** `ALLOW_DESTRUCTIVE = False` is hardcoded with no way to change it at run time, and the action registry contains no destructive action. Adding exploitation would need deliberate code changes in two visible places.
- **Offline CVE data:** `vulners.nse` was rejected because it contacts vulners.com on every scan.
- **Self-recon suppression:** while a scan runs, the anomaly detector ignores the Pi's flows to the target, and Suricata alerts from it are *tagged* `[self-recon]` (not dropped). A real attacker's alert in the same batch is never merged into the tagged row (bug found and fixed, commit 9919d6c).

**Measured results.** Live test against our own Linux Mint laptop (192.168.221.65), 2026-10-16:

| Step | Result |
|---|---|
| `discover` (scan 1) | ~25 s; 1 host up; 1 open port of the top 1000: **22/tcp, OpenSSH 9.6p1 Ubuntu 3ubuntu13.16** (`cpe:/a:openbsd:openssh:9.6p1`) |
| CVE match | No Exploit-DB entry for this version (stated in the reasoning as *not* proof of no CVE) |
| Proposed check | `banner_grab`, status `proposed` until approval |
| Suricata `kernel_drops` | **1074 before, 1074 after**: the scan cost Suricata no packets (the counter is a running total since Suricata started) |
| Suricata alerts caused by the scan | **None**, so nothing needed the `[self-recon]` tag. Pi and laptop are both private addresses, so both count as HOME_NET, and scan rules only match outside -> inside (the HOME_NET effect, Section 6.4) |
| `approve 1` | Banner read: `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.16`, matching nmap's version; finding -> `verified`, decided by `analyst` |
| AI triage | Stored as alerts row 3433, `detection=recon`; Groq verdict **benign / low**: "authorized SSH banner grab of known OpenSSH version." One Groq request used |

Not yet tested live: a target where Exploit-DB *does* match a CVE, the `version_reconfirm` action, and `decline`.

**Known limitations.**
- Exploit-DB is **not** the full NVD: "no match" does not mean "no CVE". There is a code seam for adding a local NVD cache later.
- CVE matching depends on nmap's version guess.
- Self-recon exclusion is a blind spot while a scan runs.
- Must not be run on the Pi during baseline-2 collection.

---

## 6. Thesis findings

### 6.1 Domain shift (2026-10-16)

A model trained on one network does not work on another. Baseline 1 was recorded on a friend's hotspots
(192.168.160.x, then 192.168.100.x). On a different hotspot (192.168.221.x) the live model flagged most
of the Pi's ordinary traffic:

- Without the Tailscale exclusion: **224 of 295** usable flows flagged (**76%**) in the first 6 minutes after boot; 74% of those were Tailscale relay probes.
- With the exclusion and a retrained model: **107 of 174** flagged (**61%**), 00:10-00:19 local, steady over time. All HTTPS flows (25/25) and most Tailscale port-mapper probes (32/43) were flagged.
- Cause: on the new network a normal minute touched a median of 7 ports / 5 hosts with 23% unanswered; in baseline 1 the median was 1 port / 2 hosts with 100% unanswered, and 95% of minutes touched 3 ports or fewer.
- The held-out false-positive rate on baseline 1 stayed 2.0% throughout: the 2% budget only holds on the network the baseline describes.
- Response: not more allowlisting (that hides symptoms and widens blind spots) but a new baseline on the network where the detector is used (uni, PENDING), and retraining whenever the network changes.
- Caveat: small sample (one 9-minute window right after a boot).

### 6.2 CIC-IDS2017 evaluation

Both detectors were tested on a public, labelled dataset. Monday (normal traffic) trained a separate
anomaly model; Friday (attacks) was used only for testing. The capture files were replayed through
Suricata **7.0.3 on the laptop** (not the Pi's 8.0.7), with ET Open rules. Labels come from the official
UNB schedule, not the dataset's CSV files.

Setup facts found by checking the schedule against the traffic: schedule times are ADT (+3 h = UTC);
all scan and DDoS traffic comes from one address (172.16.0.1, the firewall's NAT), so scan vs DDoS is
told apart by time only. Botnet: every flow between a victim and 205.174.165.73:8080 is counted as botnet
all day (bots beacon every ~100 s), a deliberate deviation from the official 1-hour window (only 736 of
2,199 flows fall in it; reported separately).

**Model:** threshold -0.5862, fit 272,476 / calibration 68,120 flows, held-out Monday FP 2.0%.

**Detection, share of attack flows (anomaly detector):**

| Attack | Flows | Anomaly | Time to first anomaly flag |
|---|---|---|---|
| PortScan -sS | 59,127 | 100.0% | 43 s |
| PortScan -sT | 81,177 | 100.0% | 0 s |
| PortScan -sV | 11,153 | 100.0% | 0 s |
| PortScan -sR | 9,129 | 100.0% | 0 s |
| PortScan -sU | 195 | 99.5% | 38 s |
| PortScan -sO | 94 | 89.4% | 1 s |
| PortScan (firewall on) | 383 | 82.0% | 76 s |
| DDoS LOIT | 96,809 | 2.9% | 7 s |
| Botnet ARES | 2,199 | 1.0% | 1,729 s (~29 min: effectively missed) |
| All attacks | 260,272 | 63.0% | |

Scan types sF, sX, sP, sA, sL, sI, -b had no flows in the data and could not be evaluated.

**Suricata (signatures):** with the Pi's HOME_NET setting, Suricata caught almost none of the scans
(0.5% of attack flows). With HOME_NET set to the victim LAN it caught sS/sT/sV/sR at 0 s, the
firewall-on scan at 26 s, and the DDoS by signature at 10 s (`ET DOS Terse HTTP GET ... AnonMafiaIC`).
Neither detector caught the botnet by a real signature (only generic `SURICATA STREAM` protocol events).
Note: signature rules fire once per threshold, not per flow, so time-to-detection is the fair comparison
for Suricata, not the per-flow percentage.

**False positives on 262,083 benign Friday flows (8 h):** anomaly **1.8%**; Suricata 1.3%, or **0.3%**
excluding `SURICATA` stream/decoder events.

**Analyst load:** ~240 benign rows per hour from each detector (30 s batches, before merging). That is
more than the Groq free tier could triage if every anomaly batch needs a call.

**Key contrast with 6.1:** on the *same* network four days later, the false-positive rate held (1.8% vs 2.0%). On a *different* network it did not (61%).

Caveats (from the evaluation): labels from the schedule (time + IP), not per-packet truth; the Monday-trained CIC model measures the method, not the Pi's model; laptop Suricata 7.0.3 + its own rules, default config, no MAC logging.

### 6.3 LLM verdict inconsistency and the fix

Before the fix, the same SSDP alert sent ~30 times got **4 different verdict/priority combinations**.
Fix: `temperature=0`, plus a verdict cache per rule + host group (6 h), plus showing the AI its previous
verdict (up to 7 days old) and asking it to keep it unless something changed. Cached rows are never a
cache source, so verdicts expire 6 h after the AI last actually judged them. Anomalies and honeypot hits
are never cached. Lesson: an LLM is not deterministic enough on its own to be a consistent analyst.

### 6.4 HOME_NET effect

Suricata's rules are written as "outside -> inside" (`$EXTERNAL_NET -> $HOME_NET`). The Pi uses the default
HOME_NET (all private address ranges). In CIC-IDS2017 the attacker (172.16.0.1) is also a private address,
so it counts as "home" and most scan rules do not fire: 0.5% of attack flows caught, versus scans caught at
0 s with the LAN-only HOME_NET. Configuration matters as much as the rule set.

### 6.5 Tailscale fan-out

Tailscale (used for remote access) probes ~70 relay servers every ~5 minutes. This caused:
- **AI cost:** ~150 alert groups (~17,000 tokens) in one call, over the 8,000 tokens/minute limit (HTTP 413). 1,556 rows ended up `AI unavailable` (later fixed by backfill). Fix: `collapse()` merges fan-out groups; chunking and pacing.
- **False alerts:** Tailscale's port mapper probing the gateway fires `ET DOS Possible SSDP Amplification Scan`. Fix: describe Tailscale's normal behaviour to the AI in `CONTEXT`.
- **Anomaly noise:** 74% of the first live anomaly flags were Tailscale relay probes, and it probes differently per network. Fix: exclude the Pi's own relay traffic (with an explicit risk: it becomes invisible to the anomaly detector).
- Likely cause of the 0/50 SSH-sweep miss (it resembles the relay fan-out in the baseline).
- Tailscale started before baseline 1 (2026-10-04T22:23 vs 22:32), so its traffic is part of the baseline; it stays running.

### 6.6 Performance fix

The CIC evaluation showed the per-source window recounted the whole last 60 s for every flow: ~15-20 ms
per flow during a 30,000 flows/minute scan, too slow for live scoring. It now keeps running counts.
The scan peak went from **105 s to 4.8 s**, with **identical** feature vectors and identical retrained
thresholds (commit 3bf52c9).

---

## 7. Thesis mapping

| Thesis section | What to update |
|---|---|
| 3.1 Modules | Add Honeypot + prevention and Recon/VAPT as built modules; describe the eight modules in Section 5. State "IDPS", not only IDS. Mark anomaly detection as built and evaluated but live scoring pending the uni baseline. |
| 3.2 Tech Stack | Replace with the table in Section 3 (Kali, Groq gpt-oss-120b, 8 GB, Suricata 8.0.7, Tailscale, SQLite, Textual, WeasyPrint, scikit-learn, nftables, nmap/searchsploit). |
| Design diagrams (ERD, DFD, UML) | Redraw (Section 8). |
| **New: Implementation chapter** | Architecture (Section 4), per-module "how it works" and "design decisions" (Section 5), deployment (systemd services, log rotation fix), security hardening of the honeypot service. |
| **New: Results / Evaluation chapter** | Section 6: baseline 1 and replay results, domain shift, CIC-IDS2017 tables, honeypot and recon live tests, verdict-consistency fix, backfill numbers, performance fix. Leave placeholders for uni baseline, live tests, Cisco SPAN lab, demo. |
| **New: Limitations / Discussion** | Every "Known limitations" list in Section 5; HOME_NET effect; partly synthetic baseline; Tailscale blind spots. |
| Ethics section | Section 9. |
| Future work | NVD cache for recon, `default_creds` check, retraining per network, better handling of slow/beaconing threats (botnet), paid AI tier or local model for analyst load. |

---

## 8. Corrections to the original thesis and slides

| Original | Actual |
|---|---|
| Raspberry Pi OS | **Kali Linux** (Rolling 2026.3) |
| Claude API | **Groq** API, model `openai/gpt-oss-120b` |
| 4 GB Raspberry Pi | **8 GB** Raspberry Pi 4 |
| (no VPN) | **Tailscale** added for remote access; it affects detection (Section 6.5) |
| IDS (detection only) | **IDPS**: detection *and* prevention (honeypot + nftables blocking) |
| ERD / DFD / UML diagrams | **Outdated**, see below |

**What the diagrams are missing:**
- The real `alerts` columns (Section 5.3), especially `detection`, `score`, `n_src`, `n_dest`, `group_key`, `action`, which did not exist originally.
- The `recon_scan` and `recon_finding` tables (and the link `recon_finding.scan_id -> recon_scan.id`).
- New modules / processes: anomaly detection (flows -> model -> anomalies), honeypot (decoy -> nftables block -> honeypot log -> pipeline), recon (analyst -> nmap -> searchsploit -> approve/decline -> triage), backfill, PDF reporting with `bia.json`.
- External entities: Groq API (triage and report prose), Tailscale, local Exploit-DB.
- Data stores: `eve.json`, `honeypot.json`, `pecan.db`, `anomaly_model.joblib`, `bia.json`.

---

## 9. Ethics

- **Consent and ownership.** The Pi belongs to a groupmate. Baseline 1 was recorded on a friend's phone hotspots, which captured traffic from other devices. *Confirm with the team what consent was obtained and how, before writing it up; this document only records what the repository says.*
- **Third-party data deletion.** The 40,528 broadcast/multicast flows in baseline 1 (other people's devices) were permanently deleted from the saved baseline, as promised. This does not change training, because those flows are filtered out anyway. Replay files holding real flows are kept out of git (`replay/` is gitignored), as are the database, baselines, models and CIC data.
- **Non-destructive by design.** Nothing crashes, floods or damages a target. Recon is analyst-started, rate-limited (100 packets/s) and limited to read-only checks; exploitation is disabled in code twice over. Attack tests during baseline collection were done offline with synthetic replays, without sending traffic.
- **Isolated testing.** The CIC-IDS2017 attack traffic was replayed from files into Suricata on the laptop; no attacks were sent over a network. Live tests (honeypot, planned nmap tests) are between our own laptop and our own Pi. The Cisco SPAN lab (PENDING) is intended as the isolated lab environment.
- **Data sent to a third party.** Alert metadata is sent to Groq's cloud for triage. State this, and that nothing secret (the API key) is committed.
- **Self-protection.** The honeypot can't be tricked into blocking someone else (handshake required), and blocks expire automatically.

---

## 10. Glossary

| Term | Meaning |
|---|---|
| **IDS / IDPS** | Intrusion Detection System / Intrusion Detection and Prevention System. An IDPS can also act (e.g. block). |
| **Suricata** | Open-source network IDS that matches traffic against rules. |
| **Signature / rule / SID** | A description of a known bad pattern; SID is its numeric ID. |
| **ET Open** | Free public Suricata rule set (Emerging Threats). |
| **eve.json** | Suricata's JSON log of alerts, flows and stats. |
| **Flow** | Summary of one connection (who, ports, bytes, packets, duration). |
| **kernel_drops** | Packets Suricata could not process because it was too busy. Should stay constant. |
| **HOME_NET** | Suricata setting for "our network"; rules use it to decide inside vs outside. |
| **SOC** | Security Operations Centre: team that watches alerts and decides what matters. |
| **Triage** | Sorting alerts by how serious they are. |
| **LLM** | Large Language Model (here `gpt-oss-120b` via Groq). |
| **Token** | A piece of text the LLM counts for limits and cost. |
| **Rate limit / HTTP 429 / 413** | 429 = "too many requests, slow down"; 413 = "request too large". |
| **Temperature** | LLM randomness setting; 0 = as repeatable as possible. |
| **Prompt injection** | Attacker text that tries to give instructions to an LLM. |
| **SQLite** | A database stored in a single file. |
| **TUI** | Text User Interface: a dashboard in the terminal. |
| **BIA / RTO / RPO** | Business Impact Analysis / Recovery Time Objective (max acceptable downtime) / Recovery Point Objective (max acceptable data loss, in time). |
| **Anomaly detection** | Flagging things that differ from learned normal behaviour. |
| **Isolation Forest** | Algorithm that flags points that are easy to separate ("isolate") from the rest using random splits. |
| **Baseline** | Recording of normal traffic used to train the anomaly model. |
| **False positive (FP)** | A harmless thing flagged as suspicious. |
| **FP budget** | The share of normal traffic we accept being flagged (2%); it sets the threshold. |
| **Held-out data** | Data kept aside from training, used only to test. |
| **Domain shift** | When the data in use differs from the training data (here: a different network). |
| **Replay** | Feeding recorded or synthetic traffic records through the detector offline. |
| **CIC-IDS2017** | Public labelled dataset of normal and attack traffic from the Canadian Institute for Cybersecurity (UNB). |
| **Honeypot** | A decoy service that only attackers would touch. |
| **nftables** | The Linux firewall. |
| **Allowlist** | Addresses that are never blocked. |
| **TCP handshake** | The three-step start of a TCP connection; can't be completed with a forged source address. |
| **Tailscale / DERP / STUN** | VPN for remote access / Tailscale's relay servers / a protocol to discover one's public address. |
| **SSDP / NAT-PMP / PCP** | Protocols for asking a router to open ports; Tailscale uses them. |
| **Fan-out** | One host contacting many hosts at once. |
| **VAPT** | Vulnerability Assessment and Penetration Testing. We do the assessment part only. |
| **nmap** | Network scanner that finds open ports and service versions. |
| **CVE** | Public ID for a known vulnerability. |
| **NVD** | US National Vulnerability Database, the full CVE catalogue. |
| **Exploit-DB / searchsploit** | Database of public exploits / offline search tool for it. |
| **CPE** | Standard name for a product + version. |
| **XAI** | Explainable AI; here a rule-based, reproducible reasoning text for each recon finding. |
| **systemd / service / timer** | Linux system that starts programs at boot and runs them on a schedule. |
| **logrotate** | Tool that archives and shrinks log files. |
| **SPAN** | Switch Port Analyzer: a Cisco switch feature that copies traffic to a monitoring port. |

---

## 11. References

Only sources already used or named in the repository / `CLAUDE.md`. Items marked **[verify]** should be
checked (exact title, version, URL, access date) before citing.

1. Canadian Institute for Cybersecurity, University of New Brunswick. *Intrusion Detection Evaluation Dataset (CIC-IDS2017).* https://www.unb.ca/cic/datasets/ids-2017.html (schedule fetched 2026-10-16; URL used in `cic_eval.py`). The dataset page asks users to cite an accompanying paper; it is not referenced in the repo, so look it up on that page **[verify]**.
2. Suricata (OISF). Version 8.0.7 on the Pi, 7.0.3 on the laptop for CIC replays. **[verify: project URL and documentation to cite]**
3. Emerging Threats Open (ET Open) rule set, via `suricata-update`. **[verify]**
4. Groq API, model `openai/gpt-oss-120b`; free-tier limits (8,000 tokens/min, 1,000 requests/day) as observed for this account in October 2026. **[verify: limits change; cite Groq's rate-limit documentation with access date]**
5. scikit-learn, `sklearn.ensemble.IsolationForest`, version 1.9.1. **[verify]** The original Isolation Forest paper is *not* referenced in the repository; if the report cites it, find and verify it separately.
6. Nmap 7.99. https://nmap.org (URL from `nmap --version`).
7. Exploit-DB / `searchsploit` (offline copy on Kali). **[verify]**
8. NVD (National Vulnerability Database), mentioned only as what Exploit-DB is not. **[verify]**
9. `python-libnmap` (nmap output parser). **[verify]**
10. Tailscale 1.102.4, including DERP relays and the relay list (`tailscale_derp.json`, from `anomaly.py derp-refresh`). **[verify]**
11. nftables (Linux firewall). **[verify]**
12. Textual 8.2.8 (TUI framework). **[verify]**
13. WeasyPrint 69.0 and Jinja2 (PDF rendering). **[verify]**
14. SQLite 3.53.4. **[verify]**
15. Kali Linux (Rolling 2026.3). **[verify]**
16. Thesis definitions of BIA, RTO, RPO: copied word for word from our own thesis into `report.py`; cite whatever source the thesis cites.

---

## Appendix A. Likely panel questions (short, honest answers)

**Q1. Most traffic is encrypted (HTTPS). Can the system see attacks inside it?**
No. Suricata sees metadata only: IPs, ports, sizes, timing, and TLS details such as the server name.
The anomaly detector works on exactly this metadata (sizes, packets, duration, ports, fan-out), so it
can still notice behaviour such as scans, but it cannot see malicious content inside an encrypted
session. No TLS interception was built.

**Q2. Could an attacker misuse or bypass the system?**
Yes, in known ways, and we document them: avoid port 2222 and the honeypot never triggers; change IP
to escape a block; hide in Tailscale relay traffic or the gateway, which are deliberate blind spots;
move slowly, like the botnet we missed. Misuse is limited by design: blocking needs a full TCP
handshake, so nobody can get a third party blocked; blocks expire; the AI can't unblock or block
anyone; recon can't run destructive actions (locked twice in code) and never runs without the analyst.
Attacker text sent to the AI is a prompt-injection risk, so the AI only explains and never controls
an action.

**Q3. Why Isolation Forest?**
It is unsupervised, so it needs no labelled attacks, only normal traffic, and labelled attacks from our
own network don't exist. It is fast and small enough for a Pi. Its threshold can be set purely from a
false-positive budget on normal data. Trade-offs we measured: it does not transfer between networks
(domain shift), and it misses attacks that look like normal behaviour (SSH sweep, botnet, most DDoS
flows). On CIC-IDS2017 it caught 100% of the common scan types at 1.8% false positives. We did not
benchmark other algorithms.

**Q4. How reliable is the AI triage?**
It is an assistant, not ground truth. Without controls it was inconsistent (4 different answers for the
same SSDP alert in ~30 calls); `temperature=0` and the verdict cache fixed that. When it fails, alerts
are stored as `unknown`, never dropped or shown as benign. In reports, numbers come from SQL and the AI
writes only the prose. We have no ground-truth measurement of its accuracy on our own alerts. On a busy
network the free tier can't keep up (~240 benign rows/hour per detector on CIC Friday).

**Q5. Why was the botnet missed?**
The ARES bots beacon to their controller about every 100 s: small, regular, normal-looking connections.
For the anomaly detector each one looks like ordinary traffic (first flag after ~29 min, 1% of flows),
and Suricata had no matching signature (only generic stream events). Catching it would need features
about regularity over longer periods, or a specific signature or threat-intel feed. We report it as a
limitation rather than tuning the model to it, because tuning on test attacks would make the results
meaningless.

**Q6. Why did Suricata miss the scans in CIC-IDS2017?**
HOME_NET: the attacker's address is private, and with the Pi's default setting it counts as "home",
so "outside -> inside" rules don't fire. With HOME_NET set to the victim LAN, the same scans were caught
at 0 s.

**Q7. Is the anomaly detector working live?**
Not yet. It was switched off after the domain-shift finding and will be retrained on a new baseline from
the university network (starting 2026-10-18).
