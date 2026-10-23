# CIC-IDS2017 live anomaly demo (replay on the Pi)

Why: the advisers want live anomaly detection shown on the Pi. The Pi's own model is not ready
(baseline 2 pending) and a model from another network gave 61% false alarms (domain shift,
implementation notes 6.1). So the demo uses the **CIC-IDS2017 Monday model** and scores **only
replayed CIC-IDS2017 Friday traffic** on a sealed dummy interface, `cic0`. The hotspot (`wlan0`) is
never scored by this model.

## Safety design

- **`cic0` is a Linux `dummy` interface**: no IP address, no peer, no cable. Its driver drops every
  frame sent to it. `cic_replay.py` writes raw frames to the one device it is given (raw packet
  sockets bypass routing and nftables) and refuses any device that is not a `dummy`, so replayed
  packets can only go to `cic0`, and nothing
  enters the Pi's IP stack (no routing, forwarding or replies). A veth pair was rejected: its peer
  *receives* the frames into the stack, which could route them out of `wlan0` if forwarding were on.
- Checked during the replay: `tcpdump` on `wlan0`/`eth0` for the CIC addresses (192.168.10.0/24,
  172.16.0.1, 205.174.165.0/24; the hotspot is 192.168.81.0/24) must capture 0 packets.
- **Order:** `anomaly_iface=cic0` is set and confirmed in the journal **before** the model is
  installed, and the model is removed **first** at teardown. (An unknown or missing
  `anomaly_iface` means `all`, so this order is what guarantees `wlan0` never meets this model.)
- Replay at 1x speed only: a faster replay would compress the 60 s per-source window features.
  Abort with Ctrl-C if `kernel_drops` rises.
- Rows from `cic0` (signature and anomaly) get the reason prefix `[cic-replay]`, are never merged
  with real rows, never use or feed the verdict cache, and the AI is not told they are a replay
  (it judges the traffic, not its origin). `backfill.py` skips them (reason is not exactly
  `AI unavailable`).

## Model

`cic/model.joblib` from `cic_eval.py train` (Monday): threshold **-0.5862**, fit 272,476 /
calibration 68,120, scikit-learn 1.9.1 (same in `/opt/pecan/venv`),
sha256 `b1e8959d27f28945bcca41d343721f29b9eec7156365c40c2b8da182d79804f0`.
Label sidecar: `anomaly.py label cic/model.joblib --label "CIC-IDS2017 (demo replay only)"` ->
`cic/model.meta.json`. The panel shows "Anomaly model: CIC-IDS2017 (demo replay only)" only while
the sidecar's sha256 matches the installed file. If the model is gone: `nice -n 19 .venv/bin/python
cic_eval.py train` (needs `cic/monday_flows.jsonl.gz`; `random_state=42`, must reproduce the
threshold and sizes above).

## Slices (official schedule, ADT = UTC-3; windows checked against `cic/friday_flows.jsonl.gz`)

| File | UTC (2017-07-07) | ADT | Content | Flows (attack via 172.16.0.1) |
|---|---|---|---|---|
| `fri_scan.pcap` | 17:53:00-17:58:00 | 14:53-14:58 | 1 min warm-up, -sT scan 14:54-14:56 | 89,057 (85,192) |
| `fri_ddos.pcap` | 18:55:00-19:00:00 | 15:55-16:00 | 1 min warm-up, DDoS LOIT from 15:56 | 19,996 (15,767) |

**Groq cost** (simulated with the pipeline's own code on the slim Friday events: 30 s batches,
`collapse()`, `chunks()`): ~10 requests per slice (one per batch, max ~1,900 prompt tokens), i.e.
~20 per full run, ~40 with a rehearsal. Under 4% of the 1,000/day tier; with 2,000 requested
completion tokens, 2 calls/min stays under the 7,000 tokens/min pacing. No cap needed.

## Steps

### 1. Laptop: cut and copy (`editcap` from `wireshark-common`)

```sh
command -v editcap || sudo apt install wireshark-common
cd "/home/fawazo777/Documents/research project"
TZ=UTC capinfos -a -e "Friday-WorkingHours.pcap"     # first packet ~2017-07-07 11:58 UTC
TZ=UTC editcap -F pcap -A "2017-07-07 17:53:00" -B "2017-07-07 17:58:00" "Friday-WorkingHours.pcap" "fri_scan.pcap"
TZ=UTC editcap -F pcap -A "2017-07-07 18:55:00" -B "2017-07-07 19:00:00" "Friday-WorkingHours.pcap" "fri_ddos.pcap"
ls -lh "fri_scan.pcap" "fri_ddos.pcap"; sha256sum "fri_scan.pcap" "fri_ddos.pcap"
scp "fri_scan.pcap" "fri_ddos.pcap" pecan:/home/raven/pecan-pi/cic/replay/
```

### 2. Pi: install the code, restrict scoring to cic0 (no model yet)

```sh
sudo sh deploy/install-code.sh
sudo systemctl restart pecan-pipeline pecan-panel
sudo /usr/local/sbin/pecan-helper set-anomaly-iface cic0
```
Check: `journalctl -u pecan-pipeline --since -2min | grep switches` shows `anomaly_iface=cic0` and
`anomaly=on (no model loaded)`.

### 3. Pi: create cic0 and let Suricata capture it

```sh
sudo ip link add cic0 type dummy
sudo nmcli device set cic0 managed no
sudo sysctl -w net.ipv6.conf.cic0.disable_ipv6=1
sudo ip link set cic0 mtu 12000 arp off up      # largest CIC frame is 11,649 B; Suricata reads the MTU at start
sudo cp -a /etc/suricata/suricata.yaml /etc/suricata/suricata.yaml.pre-cic
sudo install -o root -g root -m 0644 cic/suricata.yaml.cic-demo /etc/suricata/suricata.yaml
sudo nice -n 19 suricata -T -c /etc/suricata/suricata.yaml
vcgencmd get_throttled
sudo install -o root -g root -m 0644 deploy/cic-demo-suricata.conf /etc/systemd/system/suricata.service.d/zz-cic-demo.conf
sudo systemctl daemon-reload && sudo systemctl restart suricata
sudo python3 -I cic_replay.py cic/replay/fri_scan.pcap --limit 200
```
`cic/suricata.yaml.cic-demo` (gitignored) = the installed yaml plus one af-packet entry before
eth0: `interface: cic0`, `cluster-id: 98`, `cluster-type: cluster_flow`, `defrag: yes`, `threads: 1`,
`checksum-checks: no` (added after the first capture test: 6 of 200 replayed packets raised `SURICATA TCPv4
invalid checksum` 2200074; the CIC evaluation ran `suricata -k none`, so flows match it only without the check;
cic0 only, wlan0 keeps the default)
(made by copying the live file and inserting only inside `af-packet:`; check with `diff`).
Check: `eve.json` has events with `"in_iface":"cic0"`; `kernel_drops` 0 after the restart.
Not persistent: `cic0` is gone after a reboot, and Suricata is started with `-i cic0`, so after an
unplanned reboot run the teardown (step 7) straight away.

### 4. Pi: install the model (last)

```sh
sudo install -o root -g root -m 0644 cic/model.joblib /opt/pecan/anomaly_model.joblib
sudo install -o root -g root -m 0644 cic/model.meta.json /opt/pecan/anomaly_model.meta.json
sudo systemctl restart pecan-pipeline
```
Check: journal `anomaly detection on, model: CIC-IDS2017 (demo replay only)` and
`anomaly_iface=cic0`; panel label under "Spot unusual behaviour" and in the System card.

### 5. Replay (rehearsal, then the demo)

**Not tcpreplay** (first rehearsal, 2026-10-24 00:17, aborted after 3 s): the CIC capture host coalesced
packets (GRO/TSO), so frames reach 7,354 B (scan slice; 312 frames over 4 KB) and 11,649 B (DDoS slice;
22,338 over 4 KB, 3,544 over 9,014 B; 79% of its bytes are in frames over 1514 B). Kali's tcpreplay 4.5.4
sends through a TX_RING with 4096-byte slots: it truncated the big frames and then jammed
(`TP_STATUS_WRONG_FORMAT`), with no runtime switch to turn the ring off. Truncating (`--mtu-trunc`) or
splitting would change the byte/packet counts the model scores (the evaluation read the pcap whole with
`suricata -r`), so `cic_replay.py` sends every frame whole with one `send()`, at 1x, dummy interfaces
only. The aborted run left `[cic-replay]` rows 5300-5309 (tail of the -sS scan: 997 ports, malicious/high)
and `kernel_drops` stayed 0.

Terminal 1 (leak check, must end with `0 packets captured`):
```sh
sudo timeout 700 tcpdump -ni wlan0 -c 5 'net 192.168.10.0/24 or host 172.16.0.1 or net 205.174.165.0/24'
```
Terminal 2:
```sh
sudo sh -c 'python3 -I cic_replay.py cic/replay/fri_scan.pcap; python3 -I cic_replay.py cic/replay/fri_ddos.pcap'
```
`kernel_drops` (no sudo): `tail -n 2000 /var/log/suricata/eve.json | grep '"event_type":"stats"' | tail -1 | jq .stats.capture`.

### 6. Numbers for the report

Record T0/T1 (local) of each replay, then:
- flows scored / flagged: `journalctl -u pecan-pipeline --since T0 --until T1 | grep 'anomaly: scored'`
- per-flow detection vs false alarms, offline with the same model: `anomaly.py snapshot --since T0
  --until T1 --iface cic0 --out cic/demo_flows.jsonl`, then split by 172.16.0.1 (attack) vs the rest.
- rows and verdicts: `sqlite3 -readonly pecan.db "SELECT id, detection, src_ip, dest_ip, count, score,
  verdict, priority, signature, reason FROM alerts WHERE reason LIKE '[cic-replay]%' ORDER BY id"`
- signature alerts on cic0, time to first anomaly row, `kernel_drops` after restart / after each
  slice / at the end, load and temperature (panel System card), `get_throttled`, the empty tcpdump.

Caveats for the report: a replay, not a live network; the model was trained on laptop Suricata
7.0.3 flows without MAC addresses, scored here on Pi Suricata 8.0.7 with MACs; HOME_NET is the
Pi's (all RFC1918), so 172.16.0.1 counts as "home" and scan signatures stay quiet (finding 6.4).

### 7. Teardown (back to "switch on, no model, anomaly_iface=all")

```sh
sudo rm /opt/pecan/anomaly_model.joblib /opt/pecan/anomaly_model.meta.json
sudo systemctl restart pecan-pipeline        # journal: "anomaly detection off: no /opt/pecan/anomaly_model.joblib"
sudo /usr/local/sbin/pecan-helper set-anomaly-iface all
sudo rm /etc/systemd/system/suricata.service.d/zz-cic-demo.conf
sudo cp -a /etc/suricata/suricata.yaml.pre-cic /etc/suricata/suricata.yaml
sudo systemctl daemon-reload && sudo systemctl restart suricata
sudo ip link del cic0
```
Panel: the "Spot unusual behaviour" switch shows "Not available yet" again (no model). The code
changes stay: without a model and `anomaly_iface=cic0` they change nothing.

## 2-minute demo script

Before: rehearsal done (DDoS rows already in the feed), panel open in IT mode, two terminals ready.

| Time | Do | Say |
|---|---|---|
| -1:00 | Start `sudo python3 -I cic_replay.py cic/replay/fri_scan.pcap` and the wlan0 `tcpdump` | (warm-up minute, before the advisers' slot) |
| 0:00 | Panel: "Anomaly model: CIC-IDS2017 (demo replay only)", System card `anomaly interface: cic0 only` | Our hotspot model isn't ready, and a model from another network false-alarmed on 61% of normal traffic. So this is a model of a public lab network, scoring only that lab's recorded traffic, replayed into a sealed virtual interface. Our hotspot is not scored. |
| 0:30 | Terminal: the wlan0 `tcpdump`, still nothing | The attack traffic never leaves the Pi: the dummy interface drops every packet |
| 0:50 | Feed: `[cic-replay]` anomaly row from 172.16.0.1 (thousands of ports), AI verdict | The Isolation Forest flags the connect scan; the AI explains it. Scan signatures stay quiet: 172.16.0.1 is a private address, so our HOME_NET counts it as inside (finding 6.4) |
| 1:30 | IT filter: the DDoS rows from the rehearsal | Honest limit: DDoS ranks well (AUC 0.978) but mostly sits inside the 2% threshold; lowering it would be tuning on the test day |
| 1:50 | System card: `kernel_drops` unchanged | Suricata kept up the whole time |
