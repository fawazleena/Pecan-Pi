// Pecan Pi panel. Every server string goes in via textContent, never innerHTML:
// alert text can contain attacker-controlled bytes (honeypot banners, HTTP fields).
"use strict";
const REFRESH_MS = 5000;
let mode = "simple", last = null;   // last /api/status, re-rendered when the mode changes

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined && text !== null) e.textContent = text;
  return e;
}

function setMode(m) {
  mode = m;
  document.body.classList.toggle("it", mode === "it");
  document.querySelectorAll(".mode button").forEach(b => b.classList.toggle("on", b.dataset.mode === mode));
  try { localStorage.setItem("pecan-mode", mode); } catch (e) { /* storage blocked: fine */ }
  if (last) render(last);
}

function renderSwitches(list) {
  if (busy) return;   // don't redraw under a click that is still being saved
  document.getElementById("switches").replaceChildren(...list.map(w => {
    const row = el("button", "switch-row");
    row.type = "button";
    row.dataset.name = w.name;
    row.setAttribute("role", "switch");
    row.setAttribute("aria-checked", w.on ? "true" : "false");
    row.disabled = !w.available;
    const label = el("span", "", w.label);
    if (w.note) { label.append(el("br"), el("span", "muted small", w.note)); }
    row.append(label, el("span", "switch" + (w.on ? " on" : "")));
    return row;
  }));
}

let busy = false;
async function toggle(row) {
  const on = row.getAttribute("aria-checked") !== "true";
  const label = row.firstChild.textContent;
  if (!on && !confirm(`Turn off "${label}"?`)) return;
  const msg = document.getElementById("switch-msg");
  msg.textContent = "";
  busy = true;
  row.disabled = true;
  try {
    const r = await fetch("/api/switch", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json",
                 "X-CSRFToken": document.querySelector('meta[name="csrf-token"]').content },
      body: JSON.stringify({ name: row.dataset.name, on }) });
    if (r.status === 401) { location.href = "/login"; return; }
    const body = await r.json().catch(() => ({}));
    if (!r.ok) msg.textContent = body.error || "Couldn't change the setting.";
  } catch (e) {
    msg.textContent = "Can't reach the Pi. Nothing was changed.";
  } finally {
    busy = false;
    refresh();   // redraw from the real state on the Pi, whatever happened
  }
}

function render(s) {
  last = s;
  const banner = document.getElementById("banner");
  banner.className = "glass banner " + s.level;
  document.getElementById("headline").textContent = s.headline;
  document.getElementById("problems").replaceChildren(...s.problems.map(p => el("li", "", p)));
  document.getElementById("services").replaceChildren(...Object.entries(s.services).map(([name, state]) => {
    const li = el("li");
    li.append(el("span", "dot " + (state === "active" ? "ok" : "bad")), name);
    return li;
  }));
  document.getElementById("drops").textContent = s.kernel_drops;
  renderSwitches(s.switches);
  document.getElementById("settings-error").textContent = s.settings_error || "";
  // Simple mode leaves out rows the AI judged normal or hasn't explained, and says how many of
  // each; IT mode shows everything.
  const simple = mode === "simple";
  const n = s.hidden_last_hour, u = s.unexplained_last_hour;
  document.getElementById("hidden").textContent = simple ? [
    n ? `${n} normal event${n === 1 ? "" : "s"} hidden (last hour)` : "",
    u ? `${u} alert${u === 1 ? "" : "s"} not yet explained (last hour)` : ""].filter(Boolean).join(" · ") : "";
  document.getElementById("feed").replaceChildren(...(simple ? s.simple_feed : s.feed).map(f => {
    const li = el("li", f.verdict);
    li.append(el("div", "meta", `${f.time} · ${f.kind} · ${f.plain_verdict}`));
    li.append(el("div", "", f.reason || "No explanation yet."));
    if (f.action) li.append(el("div", "meta", "Firewall: " + f.action));
    const raw = el("div", "raw it-only",
      `${f.signature}${f.sid ? " [SID " + f.sid + "]" : ""}${f.severity ? " sev " + f.severity : ""}` +
      `${f.score !== null ? " score " + f.score : ""} · ${f.src} -> ${f.dst} x${f.count} · ${f.priority}`);
    li.append(raw);
    return li;
  }));
  document.getElementById("updated").textContent = "Updated " + new Date().toLocaleTimeString();
}

async function refresh() {
  try {
    const r = await fetch("/api/status", { credentials: "same-origin" });
    if (r.status === 401) { location.href = "/login"; return; }
    if (r.ok) render(await r.json());
  } catch (e) {
    document.getElementById("updated").textContent = "Can't reach the Pi. Retrying...";
  }
}

// --- IP lists: loaded on page load and after each change (current blocks need a root helper
// call, which is journaled, so they are not part of the 5 s poll).
function listMsg(text, ok) {
  const m = document.getElementById("lists-msg");
  m.textContent = text;
  m.className = "small " + (ok ? "ok" : "error");
}

function entryRow(addr, note, button) {
  const li = el("li");
  const label = el("span");
  label.append(el("span", "addr", addr));
  if (note) label.append(" ", el("span", "muted small", note));
  li.append(label);
  if (button) li.append(button);
  return li;
}

function actionButton(text, onClick) {
  const b = el("button", "", text);
  b.type = "button";
  b.addEventListener("click", onClick);
  return b;
}

function minutes(sec) {
  if (sec === null || sec === undefined) return "";
  const m = Math.ceil(sec / 60);
  return `${m} min left`;
}

async function post(url, body) {
  const r = await fetch(url, {
    method: "POST", credentials: "same-origin",
    headers: { "Content-Type": "application/json",
               "X-CSRFToken": document.querySelector('meta[name="csrf-token"]').content },
    body: JSON.stringify(body) });
  if (r.status === 401) { location.href = "/login"; throw new Error("signed out"); }
  const data = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(data.error || "The Pi refused the change.");
  return data;
}

async function change(list, action, net, note) {
  try {
    const d = await post("/api/lists", { list, action, net, note });
    listMsg(`Done${d.applied ? ": " + d.applied : ""}.`, true);
    return true;
  } catch (e) {
    listMsg(e.message === "Failed to fetch" ? "Can't reach the Pi. Nothing was changed." : e.message, false);
    return false;
  } finally {
    loadLists();
  }
}

function renderLists(d) {
  const locked = d.protected.map(p => {
    const li = entryRow(p.net, p.note, el("span", "muted small", "locked"));
    li.classList.add("locked");
    return li;
  });
  document.getElementById("list-protected").replaceChildren(...locked);
  document.getElementById("list-allow").replaceChildren(...d.allow.map(e => entryRow(e.net, e.note,
    actionButton("Remove", () => confirm(`Stop trusting ${e.net}?`) && change("allow", "remove", e.net)))));
  const deny = d.deny.map(e => entryRow(e.net, e.note,
    actionButton("Unblock", () => confirm(`Unblock ${e.net}?`) && change("deny", "remove", e.net))));
  if (!deny.length) deny.push(el("li", "muted small", "Nothing blocked."));
  document.getElementById("list-deny").replaceChildren(...deny);
  let blocks;
  if (d.blocks_error) blocks = [el("li", "muted small", d.blocks_error)];
  else if (d.enforced === false) blocks = [el("li", "muted small",
    "The trap door service is stopped: nothing is being blocked right now, including the list on the left.")];
  else blocks = d.blocks.map(b => entryRow(b.ip, minutes(b.expires), actionButton("Unblock", async () => {
    if (!confirm(`Lift the block on ${b.ip} now?`)) return;
    try { await post("/api/unblock", { ip: b.ip }); listMsg(`${b.ip} unblocked.`, true); }
    catch (e) { listMsg(e.message, false); }
    loadLists();
  })));
  if (!blocks.length) blocks.push(el("li", "muted small", "Nobody right now."));
  document.getElementById("list-blocks").replaceChildren(...blocks);
}

async function loadLists() {
  try {
    const r = await fetch("/api/lists", { credentials: "same-origin" });
    if (r.status === 401) { location.href = "/login"; return; }
    if (r.ok) renderLists(await r.json());
  } catch (e) {
    listMsg("Can't reach the Pi. Retrying when you press Refresh.", false);
  }
}

document.querySelectorAll("form.add").forEach(f => f.addEventListener("submit", async e => {
  e.preventDefault();
  const net = f.net.value.trim(), note = f.note.value.trim();
  if (f.dataset.list === "deny" && !confirm(`Block ${net} from reaching the Pi until you unblock it?`)) return;
  if (await change(f.dataset.list, "add", net, note)) f.reset();
}));
document.getElementById("lists-refresh").addEventListener("click", () => { listMsg("", true); loadLists(); });
loadLists();

document.getElementById("switches").addEventListener("click", e => {
  const row = e.target.closest(".switch-row");
  if (row && !row.disabled && !busy) toggle(row);
});
document.querySelectorAll(".mode button").forEach(b => b.addEventListener("click", () => setMode(b.dataset.mode)));
let saved = "simple";
try { saved = localStorage.getItem("pecan-mode") || "simple"; } catch (e) { /* default */ }
setMode(saved === "it" ? "it" : "simple");
refresh();
setInterval(refresh, REFRESH_MS);
