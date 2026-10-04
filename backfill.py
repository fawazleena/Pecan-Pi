"""Re-triage alerts stored as 'AI unavailable' (Groq error or rate limit at the time).

  sudo .venv/bin/python backfill.py [--since 2026-10-04] [--dry-run]

Rows are processed per original batch (same seen_at), oldest first, grouped with the same
collapse() as the live pipeline. The DB keeps no payload fields (http/tls/dns), so the AI sees
less than it did live: reasons are prefixed '[backfill] '. Verdicts from earlier batches are
reused through the verdict cache, so repeated alerts cost one Groq call.
"""
import argparse
from datetime import timezone
from anomaly import local_time
from triage import open_db, collapse, cached, chunks, triage_all, estimate, build_prompt, MAX_COMPLETION

COLS = ("id", "seen_at", "detection", "sid", "signature", "severity", "src_ip", "dest_ip", "count", "score")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--since", help="local time, e.g. 2026-10-04 or 2026-10-04T22:00")
    ap.add_argument("--dry-run", action="store_true", help="show what would be sent; no API calls, no writes "
                    "(later batches may show as uncached because nothing is written)")
    ap.add_argument("--db", default="pecan.db")
    a = ap.parse_args()

    db = open_db(a.db)
    since = local_time(a.since).astimezone(timezone.utc).isoformat() if a.since else ""
    rows = db.execute(f"SELECT {', '.join(COLS)} FROM alerts WHERE reason = 'AI unavailable' AND seen_at >= ? "
                      "ORDER BY seen_at, id", (since,)).fetchall()
    batches = {}
    for r in rows:
        row = dict(zip(COLS, r))
        row["ids"] = [row.pop("id")]
        batches.setdefault(row.pop("seen_at"), []).append(row)
    print(f"{len(rows)} untriaged rows in {len(batches)} batches")

    fixed = 0
    for seen_at, batch in batches.items():
        items = collapse(batch)
        for n, it in enumerate(items):
            it["n"] = n
        results = cached(db, items, seen_at)
        todo = [it for it in items if it["n"] not in results]
        if a.dry_run:
            parts = chunks(todo)
            tokens = sum(estimate(build_prompt(c)) + MAX_COMPLETION for c in parts)
            print(f"{seen_at}: {len(batch)} rows -> {len(items)} items, {len(results)} cached, "
                  f"{len(todo)} to triage in {len(parts)} call(s), ~{tokens} tokens")
            continue
        results.update(triage_all(todo))
        for it in items:
            if it["n"] not in results:
                continue
            verdict, priority, reason = results[it["n"]]
            if not reason.startswith("[cached]"):
                reason = "[backfill] " + reason
            # Each row keeps its own src/dst; group_key records which group it was judged in.
            cur = db.execute(
                f"UPDATE alerts SET verdict = ?, priority = ?, reason = ?, group_key = ? "
                f"WHERE id IN ({','.join('?' * len(it['ids']))}) AND reason = 'AI unavailable'",
                (verdict, priority, reason, it["group_key"] if it["detection"] == "signature" else None, *it["ids"]))
            fixed += cur.rowcount
        db.commit()  # per batch, so later batches can reuse these verdicts through the cache
        print(f"{seen_at}: {len(batch)} rows -> {len(items)} items, {len(items) - len(todo)} cached")
    if not a.dry_run:
        left = db.execute("SELECT COUNT(*) FROM alerts WHERE reason = 'AI unavailable'").fetchone()[0]
        print(f"triaged {fixed} rows; {left} still untriaged")


if __name__ == "__main__":
    main()
