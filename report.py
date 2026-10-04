"""PDF security report from pecan.db for a time range.

  nice -n 19 .venv/bin/python report.py --since 2026-10-01 [--until 2026-10-04T23:00] [--top 10] [--no-ai]

All numbers come from SQL. Groq writes only the prose (executive summary and business impact),
in one call; with --no-ai or if Groq fails, a fixed template is used instead.
"""
import argparse, json, socket, sqlite3, subprocess, sys
from datetime import datetime, timezone
from pathlib import Path
from jinja2 import Environment

from anomaly import local_time

HERE = Path(__file__).parent
DB = HERE / "pecan.db"
BIA = HERE / "bia.json"
ANOMALY_MODEL = HERE / "anomaly_model.joblib"
PRIORITY_ORDER = "CASE priority WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END"
VERDICT_ORDER = "CASE verdict WHEN 'malicious' THEN 0 WHEN 'suspicious' THEN 1 WHEN 'benign' THEN 2 ELSE 3 END"
TRIAGED = "verdict != 'unknown'"

# Thesis definitions, word for word.
DEFINITIONS = [
    ("BIA (Business Impact Analysis)",
     "a process that identifies critical systems and estimates the operational and financial impact of their "
     "disruption, used to prioritize what a security report should flag as most urgent."),
    ("RTO (Recovery Time Objective)",
     "the maximum acceptable downtime for a system after an incident before the disruption becomes "
     "unacceptable to the business."),
    ("RPO (Recovery Point Objective)",
     "the maximum acceptable amount of data loss, measured in time, dictating how frequently backups must occur."),
]


def load(since, until, top):
    # mode=ro: the DB is root-owned and written by the pipeline; we only read it.
    db = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    rng = "seen_at >= ? AND seen_at < ?"
    args = (since, until)

    def q(sql, extra=()):
        return db.execute(sql, args + extra).fetchall()

    d = {}
    d["groups"], d["events"], d["first"], d["last"] = q(
        f"SELECT COUNT(*), COALESCE(SUM(count), 0), MIN(seen_at), MAX(seen_at) FROM alerts WHERE {rng}")[0]
    for col, order in (("verdict", VERDICT_ORDER), ("priority", PRIORITY_ORDER), ("detection", "detection")):
        d[col] = q(f"SELECT COALESCE({col}, 'signature'), COUNT(*), SUM(count) FROM alerts WHERE {rng} "
                   f"GROUP BY 1 ORDER BY {order}")
    d["untriaged"] = q(f"SELECT COUNT(*) FROM alerts WHERE {rng} AND NOT {TRIAGED}")[0][0]
    d["anomaly_scores"] = q(f"SELECT MIN(score), MAX(score) FROM alerts WHERE {rng} AND detection = 'anomaly'")[0]

    # Findings: rows of the same signature/verdict/priority taken together. With MAX(id), SQLite takes
    # the bare columns (reason, src_ip, ...) from that row, so the reason shown is the latest one.
    findings = f"""SELECT signature, COALESCE(detection, 'signature'), verdict, priority, COUNT(*), SUM(count),
            MIN(seen_at), MAX(seen_at), reason, src_ip, dest_ip, n_src, n_dest, MAX(id)
        FROM alerts WHERE {rng} AND {TRIAGED} AND %s
        GROUP BY signature, verdict, priority ORDER BY {PRIORITY_ORDER}, {VERDICT_ORDER}, SUM(count) DESC LIMIT ?"""
    keys = ("signature", "detection", "verdict", "priority", "rows", "events", "first", "last", "reason",
            "src", "dst", "n_src", "n_dest")
    rows = q(findings % "verdict != 'benign'", (top,))
    if len(rows) < top:  # fill a short list with the most frequent benign findings, labelled benign
        rows += q(findings % "verdict = 'benign'", (top - len(rows),))
    d["top"] = [dict(zip(keys, r)) for r in rows]
    d["impact_findings"] = [f for f in d["top"] if f["priority"] in ("high", "medium")]
    d["impact_total"] = q(f"SELECT COUNT(*) FROM alerts WHERE {rng} AND {TRIAGED} "
                          "AND priority IN ('high', 'medium')")[0][0]

    d["top_signatures"] = q(f"SELECT signature, COUNT(*), SUM(count) FROM alerts WHERE {rng} "
                            "GROUP BY signature ORDER BY 3 DESC LIMIT 10")
    d["top_src"] = q(f"SELECT src_ip, SUM(count) FROM alerts WHERE {rng} GROUP BY 1 ORDER BY 2 DESC LIMIT 5")
    d["top_dst"] = q(f"SELECT dest_ip, SUM(count) FROM alerts WHERE {rng} GROUP BY 1 ORDER BY 2 DESC LIMIT 5")
    db.close()
    return d


def counts(d, key):
    return {k: (n, e) for k, n, e in d[key]}


def load_bia():
    try:
        return json.loads(BIA.read_text())
    except (OSError, ValueError) as err:
        print(f"no business impact config: {err}", file=sys.stderr)
        return None


def model_info():
    """Metadata stored next to the anomaly model by `anomaly.py train`."""
    if not ANOMALY_MODEL.exists():
        return None
    try:
        import joblib
        b = joblib.load(ANOMALY_MODEL)
        return {k: b.get(k) for k in ("threshold", "fp_budget", "n_fit", "n_calib", "window", "sklearn")}
    except Exception as err:
        return {"error": str(err)}


def fallback_text(d, bia, period):
    v, p = counts(d, "verdict"), counts(d, "priority")
    n = lambda c, k: c.get(k, (0, 0))[0]
    summary = (
        f"Between {period}, Pecan Pi recorded {d['events']} security events, grouped into {d['groups']} alerts. "
        f"The AI reviewed {d['groups'] - d['untriaged']} of them: {n(v, 'malicious')} malicious, "
        f"{n(v, 'suspicious')} suspicious and {n(v, 'benign')} benign. "
        f"{n(p, 'high')} were rated high priority and {n(p, 'medium')} medium priority. "
        f"{d['untriaged']} alerts were not reviewed by the AI and need a manual look.")
    if not d["impact_total"]:
        impact = "No high or medium priority findings in this period, so no recovery objectives are at risk."
    else:
        impact = (f"{d['impact_total']} alerts were rated high or medium priority (see Top findings). "
                  "An analyst should match each one to an affected asset below and check whether the "
                  "possible disruption could exceed that asset's RTO or data loss its RPO.")
    return summary, impact


def ai_text(d, bia, period):
    from triage import client, MODEL, CONTEXT, log_limits
    v, p, det = counts(d, "verdict"), counts(d, "priority"), counts(d, "detection")
    facts = {
        "period": period, "this_appliance_ips": own_ips(), "alert_groups": d["groups"], "events": d["events"],
        "by_verdict": {k: x[0] for k, x in v.items()}, "by_priority": {k: x[0] for k, x in p.items()},
        "by_detection": {k: x[0] for k, x in det.items()}, "not_reviewed_by_ai": d["untriaged"],
        "high_or_medium_alerts": d["impact_total"],
        "top_findings": [{k: f[k] for k in ("signature", "detection", "verdict", "priority", "rows", "events",
                                            "src", "dst", "reason")} for f in d["top"]],
    }
    prompt = (
        "You write the plain-language parts of a network security report for non-technical managers.\n"
        + CONTEXT + " Its own IP addresses are in this_appliance_ips: traffic from them comes from "
        "the monitoring appliance itself, not from another device.\nUse ONLY the facts below; do not invent numbers, hosts or events. "
        "Avoid jargon; if a technical term is needed, explain it in a few words. Plain text, no markdown.\n\n"
        "Write two sections, each starting with its marker on its own line:\n"
        "SUMMARY:\n150-250 words: what happened in the period, how serious it is, what (if anything) "
        "should be done. Mention how many alerts were not reviewed by the AI, if any.\n"
        "IMPACT:\nBusiness impact of the high and medium priority findings only, using the BIA, RTO and RPO "
        "definitions and the asset table below. For each finding or group of similar findings, one line "
        "starting with '- ': which asset it could affect, what disruption could follow, and whether that "
        "could exceed the asset's RTO or RPO. Treat benign findings as no impact. If there are no high or "
        "medium findings, say so in one sentence.\n\n"
        "Definitions:\n" + "\n".join(f"{k}: {t}" for k, t in DEFINITIONS) + "\n\n"
        f"Assets ({bia['label'] if bia else 'none configured'}):\n"
        + json.dumps(bia["assets"] if bia else []) + "\n\nFacts:\n" + json.dumps(facts, default=str))
    raw = client.chat.completions.with_raw_response.create(
        model=MODEL, messages=[{"role": "user", "content": prompt}],
        max_completion_tokens=3000, reasoning_effort="low")
    log_limits(raw.headers)
    text = raw.parse().choices[0].message.content or ""
    if "SUMMARY:" not in text or "IMPACT:" not in text:
        raise ValueError("reply is missing SUMMARY:/IMPACT: markers")
    summary, impact = text.split("SUMMARY:", 1)[1].split("IMPACT:", 1)
    return summary.strip(), impact.strip()


def blocks(text):
    """Plain text -> paragraphs and '- ' bullet lists, for the template."""
    out = []
    for line in text.splitlines():
        line = line.strip()
        if line.startswith(("- ", "* ", "• ")):
            if not out or out[-1][0] != "ul":
                out.append(("ul", []))
            out[-1][1].append(line[2:])
        elif line:
            if out and out[-1][0] == "p":
                out[-1] = ("p", out[-1][1] + " " + line)
            else:
                out.append(("p", line))
        elif out and out[-1][0] == "p":
            out.append(("gap", None))
    return [b for b in out if b[0] != "gap"]


def own_ips():
    """This appliance's addresses (local lookup, no traffic), so alerts from the Pi itself are recognised."""
    try:
        return subprocess.run(["hostname", "-I"], capture_output=True, text=True).stdout.split()
    except OSError:
        return []


def show_time(iso):
    return datetime.fromisoformat(iso).astimezone().strftime("%Y-%m-%d %H:%M") if iso else "-"


def endpoint(ip, n):
    return f"{ip} (+{n - 1} hosts)" if n and n > 1 else str(ip)


TEMPLATE = """
<html><head><meta charset="utf-8"><style>
@page { size: A4; margin: 18mm 16mm;
  @bottom-left { content: "Pecan Pi security report · {{ period }}"; font: 8pt "DejaVu Sans", sans-serif; color: #777; }
  @bottom-right { content: "Page " counter(page) " of " counter(pages); font: 8pt "DejaVu Sans", sans-serif; color: #777; } }
body { font-family: "DejaVu Sans", sans-serif; font-size: 9.5pt; color: #222; line-height: 1.4; }
h1 { font-size: 20pt; margin: 0 0 2pt; } h2 { font-size: 13pt; margin: 18pt 0 6pt; border-bottom: 1px solid #ccc; }
.meta { color: #666; margin-bottom: 12pt; }
.tiles { display: flex; gap: 8pt; margin: 8pt 0 10pt; }
.tile { flex: 1; border: 1px solid #ddd; border-radius: 4pt; padding: 6pt 8pt; }
.tile b { display: block; font-size: 16pt; } .tile span { color: #666; font-size: 8pt; }
table { width: 100%; border-collapse: collapse; margin: 4pt 0 8pt; }
th, td { text-align: left; padding: 3pt 4pt; border-bottom: 1px solid #e5e5e5; vertical-align: top; }
th { font-size: 8.5pt; color: #555; } td.n { text-align: right; white-space: nowrap; }
.bar { background: #4a7bd0; height: 7pt; } .barcell { width: 35%; }
.high td { color: #b00020; } .medium td { color: #8a5a00; } .low td { color: #555; }
.small { font-size: 8pt; } .note { color: #666; font-size: 8.5pt; } .caption { font-style: italic; color: #555; }
.cols { display: flex; gap: 12pt; } .cols > div { flex: 1; }
.badge { font-size: 8pt; color: #666; } code { font-size: 8pt; }
</style></head><body>
<h1>Pecan Pi Security Report</h1>
<div class="meta">{{ period }} · host {{ host }} ({{ ips | join(", ") }}) · generated {{ generated }}</div>

<h2>Executive summary</h2>
{% if d.groups == 0 %}<p>No alerts were recorded in this period.</p>{% else %}
<div class="tiles">
  <div class="tile"><b>{{ d.events }}</b><span>security events ({{ d.groups }} alerts)</span></div>
  <div class="tile"><b>{{ pr.get('high', (0,0))[0] }}</b><span>high priority</span></div>
  <div class="tile"><b>{{ vd.get('malicious', (0,0))[0] + vd.get('suspicious', (0,0))[0] }}</b><span>suspicious or malicious</span></div>
  <div class="tile"><b>{{ dt.get('anomaly', (0,0))[0] }}</b><span>anomaly detections</span></div>
</div>{% endif %}
{% for kind, body in summary %}{% if kind == 'p' %}<p>{{ body }}</p>{% else %}<ul>{% for i in body %}<li>{{ i }}</li>{% endfor %}</ul>{% endif %}{% endfor %}
<p class="badge">{{ source }}</p>

<h2>Business impact</h2>
{% for term, text in definitions %}<p><b>{{ term }}:</b> {{ text }}</p>{% endfor %}
{% if bia %}
<table><tr><th>Asset</th><th>RTO</th><th>RPO</th></tr>
{% for a in bia.assets %}<tr><td>{{ a.name }}</td><td>{{ a.rto }}</td><td>{{ a.rpo }}</td></tr>{% endfor %}</table>
<p class="caption">{{ bia.label }}.</p>
{% else %}<p class="note">No asset table: bia.json is missing or invalid.</p>{% endif %}
{% for kind, body in impact %}{% if kind == 'p' %}<p>{{ body }}</p>{% else %}<ul>{% for i in body %}<li>{{ i }}</li>{% endfor %}</ul>{% endif %}{% endfor %}

<h2>Counts</h2>
<p class="note">An alert is one stored row: repeats of the same rule and hosts within 30 seconds count as one alert, and "events" adds up the repeats.</p>
<div class="cols">
{% for title, rows in count_tables %}<div><b>{{ title }}</b>
<table><tr><th></th><th class="n">Alerts</th><th class="n">Events</th><th></th></tr>
{% for label, n, e in rows %}<tr><td>{{ label }}</td><td class="n">{{ n }}</td><td class="n">{{ e }}</td>
<td class="barcell"><div class="bar" style="width: {{ (100 * n / d.groups) | round(1) if d.groups else 0 }}%"></div></td></tr>{% endfor %}
</table></div>{% endfor %}
</div>

<h2>Top findings</h2>
{% if d.top %}
<p class="note">Alerts of the same rule, verdict and priority are shown together; the reason is the AI's most recent one.</p>
<table class="small"><tr><th>Priority</th><th>Verdict</th><th>Finding</th><th>Hosts (latest)</th><th class="n">Alerts / events</th><th>Last seen</th><th>AI reason</th></tr>
{% for f in d.top %}<tr class="{{ f.priority }}"><td>{{ f.priority }}</td><td>{{ f.verdict }}</td>
<td>{{ f.signature }}{% if f.detection == 'anomaly' %} <i>(anomaly)</i>{% endif %}</td>
<td>{{ endpoint(f.src, f.n_src) }} → {{ endpoint(f.dst, f.n_dest) }}</td><td class="n">{{ f.rows }} / {{ f.events }}</td>
<td>{{ show_time(f.last) }}</td><td>{{ f.reason }}</td></tr>{% endfor %}</table>
{% else %}<p>No AI-reviewed alerts in this period.</p>{% endif %}

<h2>Technical appendix</h2>
<ul class="small">
<li><b>Detection.</b> Suricata IDS on wlan0 and eth0 with the Emerging Threats ruleset plus local rules; SID 9000001 (ICMP echo test rule) is ignored.{% if model %} Anomaly detection: Isolation Forest on flow features{% if model.error %} (model metadata unreadable: {{ model.error }}){% else %}, threshold {{ model.threshold | round(4) }}, false-positive budget {{ model.fp_budget }}%, fitted on {{ model.n_fit }} flows, calibrated on {{ model.n_calib }} held-out flows, {{ model.window }} s source window, scikit-learn {{ model.sklearn }}{% endif %}.{% else %} Anomaly detection: no trained model present when this report was generated.{% endif %}</li>
<li><b>AI triage.</b> {{ model_name }} on Groq. Alerts are batched every 30 s, deduplicated by rule, source and destination, and alerts of the same rule sharing a source or destination are merged ("+N hosts"). A verdict for the same rule and host group from the previous 6 hours is reused (reason starts with <code>[cached]</code>). <code>[backfill]</code> marks verdicts given later from stored fields only, without packet details.</li>
<li><b>Not AI-reviewed.</b> {{ d.untriaged }} alerts in this period have verdict "unknown" (AI unavailable at the time). They are counted as unknown, never as benign.</li>
<li><b>Timestamps.</b> Times are when a batch was stored (at most about 30 s after the event), shown in the Pi's local time. Range filter: <code>seen_at &gt;= '{{ since }}' AND seen_at &lt; '{{ until }}'</code> (UTC){% if d.first %}; data spans {{ show_time(d.first) }} to {{ show_time(d.last) }}{% endif %}.</li>
{% if d.anomaly_scores[0] is not none %}<li><b>Anomaly scores</b> in this period: {{ d.anomaly_scores[0] | round(4) }} to {{ d.anomaly_scores[1] | round(4) }} (lower = more unusual).</li>{% endif %}
</ul>
{% if d.top_signatures %}
<b class="small">Most frequent rules</b>
<table class="small"><tr><th>Rule</th><th class="n">Alerts</th><th class="n">Events</th></tr>
{% for s, n, e in d.top_signatures %}<tr><td>{{ s }}</td><td class="n">{{ n }}</td><td class="n">{{ e }}</td></tr>{% endfor %}</table>
<div class="cols">
{% for title, rows in (("Top sources", d.top_src), ("Top destinations", d.top_dst)) %}<div><b class="small">{{ title }}</b>
<table class="small">{% for ip, e in rows %}<tr><td>{{ ip }}</td><td class="n">{{ e }} events</td></tr>{% endfor %}</table></div>{% endfor %}
</div>{% endif %}
</body></html>
"""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--since", required=True, help="local time, e.g. 2026-10-01 or 2026-10-01T14:00")
    ap.add_argument("--until", help="local time (default: now)")
    ap.add_argument("--top", type=int, default=10, help="number of top findings")
    ap.add_argument("--out", help="PDF path (default: reports/pecan-report-<since>-<until>.pdf)")
    ap.add_argument("--no-ai", action="store_true", help="template summary, no Groq call")
    a = ap.parse_args()

    since = local_time(a.since)
    until = local_time(a.until) if a.until else datetime.now().astimezone()
    if until <= since:
        sys.exit("--until must be after --since")
    since_utc = since.astimezone(timezone.utc).isoformat(timespec="microseconds")
    until_utc = until.astimezone(timezone.utc).isoformat(timespec="microseconds")
    period = f"{since:%Y-%m-%d %H:%M} to {until:%Y-%m-%d %H:%M}"

    d = load(since_utc, until_utc, a.top)
    bia = load_bia()
    summary, impact = fallback_text(d, bia, period)
    source = "Automatic summary (AI not used)."
    if not a.no_ai and d["groups"]:
        try:
            summary, impact = ai_text(d, bia, period)
            from triage import MODEL
            source = f"Summary and business impact written by {MODEL}; all figures and tables come directly from the database."
        except Exception as err:
            print("AI summary unavailable:", err, file=sys.stderr)
            source = "AI summary unavailable; automatic summary used."

    from triage import MODEL
    vd, pr, dt = counts(d, "verdict"), counts(d, "priority"), counts(d, "detection")
    relabel = {"unknown": "not AI-reviewed"}
    html = Environment(autoescape=True).from_string(TEMPLATE).render(
        d=d, vd=vd, pr=pr, dt=dt, bia=bia, period=period, since=since_utc, until=until_utc,
        host=socket.gethostname(), ips=own_ips(), generated=datetime.now().astimezone().strftime("%Y-%m-%d %H:%M"),
        summary=blocks(summary), impact=blocks(impact), source=source, definitions=DEFINITIONS,
        count_tables=[("By verdict", [(relabel.get(k, k), n, e) for k, n, e in d["verdict"]]),
                      ("By priority", [(relabel.get(k, k), n, e) for k, n, e in d["priority"]]),
                      ("By detection", d["detection"])],
        model=model_info(), model_name=MODEL, endpoint=endpoint, show_time=show_time)

    out = Path(a.out) if a.out else HERE / "reports" / f"pecan-report-{since:%Y%m%d-%H%M}-{until:%Y%m%d-%H%M}.pdf"
    out.parent.mkdir(parents=True, exist_ok=True)
    from weasyprint import HTML  # imported last: it takes a few seconds to load on the Pi
    HTML(string=html).write_pdf(out)
    print(f"{d['groups']} alerts, {d['untriaged']} not AI-reviewed -> {out}")


if __name__ == "__main__":
    main()
