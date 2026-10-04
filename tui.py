import sqlite3, subprocess
from datetime import datetime
from pathlib import Path
from rich.text import Text
from textual import work
from textual.app import App
from textual.widgets import DataTable, Footer, Static

DB = Path(__file__).with_name("pecan.db")
SERVICES = ("suricata", "pecan-pipeline")
REFRESH_SECONDS = 5
LIMIT = 50
ROW_STYLE = {"high": "bold red", "medium": "yellow", "low": "dim"}
COLUMNS = ("Time", "Priority", "Verdict", "Signature", "Src -> Dst", "Count", "Reason")
REASON_WIDTH = 40  # table shows a truncated reason; the detail panel shows it in full


def service_states():
    # One systemctl call for all units; prints one state per line, in order.
    out = subprocess.run(["systemctl", "is-active", *SERVICES],
                         capture_output=True, text=True).stdout.split()
    return {s: (out[i] if i < len(out) else "unknown") for i, s in enumerate(SERVICES)}


def query(hide_benign):
    # mode=ro: the DB is root-owned and written by the pipeline; we only read it.
    db = sqlite3.connect(f"file:{DB}?mode=ro", uri=True)
    try:
        counts = dict(db.execute("SELECT verdict, COUNT(*) FROM alerts GROUP BY verdict"))
        where = "WHERE verdict != 'benign'" if hide_benign else ""
        rows = db.execute(
            "SELECT id, seen_at, priority, verdict, signature, src_ip, dest_ip, count, reason "
            f"FROM alerts {where} ORDER BY id DESC LIMIT ?", (LIMIT,)).fetchall()
    finally:
        db.close()
    return counts, rows


def shorten(text, width):
    text = str(text)
    return text if len(text) <= width else text[:width - 1] + "…"


def local_time(iso):
    try:
        return datetime.fromisoformat(iso).astimezone().strftime("%m-%d %H:%M:%S")
    except (TypeError, ValueError):
        return str(iso)


class PecanTUI(App):
    TITLE = "Pecan Pi"
    CSS = """
    #status { height: 1; padding: 0 1; background: $panel; }
    DataTable { height: 1fr; }
    #detail { height: auto; max-height: 10; padding: 0 1; border-top: solid $accent; }
    """
    BINDINGS = [("q", "quit", "Quit"), ("r", "refresh", "Refresh"), ("f", "toggle_benign", "Hide benign")]

    hide_benign = False
    details = {}  # row key (DB id) -> (signature, src, dst, reason) for the detail panel

    def compose(self):
        yield Static("Loading...", id="status")
        yield DataTable(cursor_type="row", zebra_stripes=False)
        yield Static("", id="detail")
        yield Footer()

    def on_mount(self):
        self.query_one(DataTable).add_columns(*COLUMNS)
        self.action_refresh()
        self.set_interval(REFRESH_SECONDS, self.action_refresh)

    def action_toggle_benign(self):
        self.hide_benign = not self.hide_benign
        self.action_refresh()

    @work(thread=True, exclusive=True)
    def action_refresh(self):
        # Runs in a background thread so systemctl/SQLite never block the UI.
        states = service_states()
        try:
            counts, rows, error = *query(self.hide_benign), None
        except sqlite3.Error as err:
            counts, rows, error = {}, [], str(err)
        self.call_from_thread(self.render_data, states, counts, rows, error)

    def render_data(self, states, counts, rows, error):
        status = Text()
        for name, state in states.items():
            ok = state == "active"
            status.append(f"{name}: ", style="bold")
            status.append("running" if ok else "stopped", style="green" if ok else "bold red")
            status.append("   ")
        status.append(f"total {sum(counts.values())}", style="bold")
        for verdict in ("malicious", "suspicious", "benign", "unknown"):
            status.append(f"  {verdict} {counts.get(verdict, 0)}")
        if self.hide_benign:
            status.append("   [benign hidden]", style="italic")
        if error:
            status.append(f"   DB error: {error}", style="bold red")
        self.query_one("#status", Static).update(status)

        table = self.query_one(DataTable)
        # clear() resets the cursor to the top, so remember which alert was highlighted.
        selected = self.highlighted_key(table)
        table.clear()
        self.details = {}
        for alert_id, seen_at, priority, verdict, sig, src, dst, count, reason in rows:
            key = str(alert_id)
            self.details[key] = (sig, src, dst, reason)
            style = ROW_STYLE.get(priority, "")
            cells = (local_time(seen_at), priority, verdict, sig, f"{src} -> {dst}", str(count),
                     shorten(reason, REASON_WIDTH))
            table.add_row(*(Text(str(c), style=style) for c in cells), key=key)
        if selected in self.details:
            table.move_cursor(row=table.get_row_index(selected))
        self.show_detail(self.highlighted_key(table))

    def highlighted_key(self, table):
        if not table.row_count:
            return None
        return table.coordinate_to_cell_key(table.cursor_coordinate).row_key.value

    def on_data_table_row_highlighted(self, event):
        self.show_detail(event.row_key.value)

    def show_detail(self, key):
        detail = self.query_one("#detail", Static)
        if key not in self.details:
            detail.update(Text("No alert selected", style="dim"))
            return
        sig, src, dst, reason = self.details[key]
        text = Text()
        for label, value in (("Signature", sig), ("Src -> Dst", f"{src} -> {dst}"), ("Reason", reason)):
            text.append(f"{label}: ", style="bold")
            text.append(f"{value}\n")
        text.rstrip()
        detail.update(text)


if __name__ == "__main__":
    PecanTUI().run()
