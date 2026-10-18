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
    if (!r.ok) msg.textContent = (mode === "it" && body.detail) || body.error || "Couldn't change the setting.";
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
  // Simple mode leaves out rows the AI judged normal or hasn't explained (unless the firewall
  // blocked someone: those always show), and says how many of
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
  if (!r.ok) {
    const err = new Error(data.error || "The Pi refused the change.");
    err.detail = data.detail;
    throw err;
  }
  return data;
}

// Simple mode: the plain sentence; IT mode: pecan-helper's own text when there is one.
function errText(e, offline) {
  if (e.message === "Failed to fetch") return offline;
  return mode === "it" && e.detail ? e.detail : e.message;
}

async function change(list, action, net, note) {
  try {
    const d = await post("/api/lists", { list, action, net, note });
    listMsg(`Done${d.applied ? ": " + d.applied : ""}.`, true);
    return true;
  } catch (e) {
    listMsg(errText(e, "Can't reach the Pi. Nothing was changed."), false);
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
  if (d.blocks_error) blocks = [el("li", "muted small", mode === "it" && d.blocks_detail ? d.blocks_detail : d.blocks_error)];
  else if (d.enforced === false) blocks = [el("li", "muted small",
    "The trap door service is stopped: nothing is being blocked right now, including the list on the left.")];
  else blocks = d.blocks.map(b => entryRow(b.ip, minutes(b.expires), actionButton("Unblock", async () => {
    if (!confirm(`Lift the block on ${b.ip} now?`)) return;
    try { await post("/api/unblock", { ip: b.ip }); listMsg(`${b.ip} unblocked.`, true); }
    catch (e) { listMsg(errText(e, "Can't reach the Pi. Nothing was changed."), false); }
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

// --- Rules: categories and custom rules. A change runs suricata-update/suricata -T and reloads
// Suricata, so it takes a minute or two; everything stays disabled until the Pi answers.
let rulesBusy = false;
function rulesMsg(text, ok) {
  const m = document.getElementById("rules-msg");
  m.textContent = text;
  m.className = "small " + (ok ? "ok" : "error");
}

function renderRules(d) {
  document.getElementById("categories").replaceChildren(...d.categories.map(c => {
    const row = el("button", "switch-row");
    row.type = "button";
    row.setAttribute("role", "switch");
    row.setAttribute("aria-checked", c.on ? "true" : "false");
    row.disabled = rulesBusy;
    const label = el("span", "", c.label);
    if (c.note) label.append(el("br"), el("span", "muted small", c.note));
    row.append(label, el("span", "switch" + (c.on ? " on" : "")));
    row.addEventListener("click", () => {
      if (c.on && !confirm(`Stop watching for "${c.label}"? This takes a minute or two.`)) return;
      rulesChange("/api/rules/category", { name: c.name, on: !c.on });
    });
    return row;
  }));
  const custom = d.custom.map(r => {
    const li = el("li", "rule-row" + (r.on ? "" : " off"));
    const sw = el("button", "switch-row");
    sw.type = "button";
    sw.setAttribute("role", "switch");
    sw.setAttribute("aria-checked", r.on ? "true" : "false");
    const label = el("span", "", r.name);
    label.append(el("br"), el("span", "muted small", r.summary + (r.on ? "" : " (off)")));
    sw.append(label, el("span", "switch" + (r.on ? " on" : "")));
    sw.addEventListener("click", () => {
      if (r.on && !confirm(`Switch off the rule "${r.name}"? It is kept and can be switched back on.`)) return;
      rulesChange("/api/rules/custom", { action: "toggle", sid: r.sid, on: !r.on });
    });
    const actions = el("div", "rule-actions");
    actions.append(actionButton("Edit", () => editRule(r)), actionButton("Remove", () =>
      confirm(`Remove the rule "${r.name}"?`) && rulesChange("/api/rules/custom", { action: "remove", sid: r.sid })));
    li.append(sw, actions, el("div", "rule it-only", `SID ${r.sid} rev ${r.rev}: ${r.rule}`));
    return li;
  });
  if (!custom.length) custom.push(el("li", "muted small", "None yet."));
  document.getElementById("custom").replaceChildren(...custom);
  document.querySelectorAll("#rules button").forEach(b => { b.disabled = rulesBusy; });
  document.getElementById("rules-info").textContent = d.rules_loaded === null || d.rules_loaded === undefined ? ""
    : `Suricata: ${d.rules_loaded} rules loaded, ${d.rules_failed} failed, last reload ${d.last_reload}. ` +
      "Files: /etc/suricata/disable.conf, /var/lib/suricata/rules/pecan-custom.rules (SIDs 9100000-9199999).";
}

async function rulesChange(url, body) {
  rulesBusy = true;
  rulesMsg("Applying... this takes a minute or two. Monitoring keeps running.", true);
  document.querySelectorAll("#rules button").forEach(b => { b.disabled = true; });
  try {
    const d = await post(url, body);
    rulesMsg(`Done${d.applied ? ": " + d.applied : ""}.`, true);
    return true;
  } catch (e) {
    rulesMsg(errText(e, "Lost contact with the Pi. Reload the page to see what was saved."), false);
    return false;
  } finally {
    rulesBusy = false;
    loadRules();
  }
}

async function loadRules() {
  try {
    const r = await fetch("/api/rules", { credentials: "same-origin" });
    if (r.status === 401) { location.href = "/login"; return; }
    if (r.ok) renderRules(await r.json());
  } catch (e) {
    rulesMsg("Can't reach the Pi.", false);
  }
}

// The form adds a rule, or edits one (same SID, rev+1) after Edit loaded it. Empty boxes = any.
let editing = null;   // SID being edited, or null
function editRule(r) {
  const f = document.getElementById("custom-add").elements;
  editing = r.sid;
  f.name.value = r.name; f.proto.value = r.proto; f.text.value = r.text;
  for (const k of ["port", "src", "dst"]) f[k].value = r[k] === "any" ? "" : r[k];
  document.getElementById("custom-form-title").textContent = `Edit "${r.name}"`;
  document.getElementById("custom-save").textContent = "Save changes";
  document.getElementById("custom-cancel").hidden = false;
  f.name.focus();
}

function stopEditing() {
  editing = null;
  document.getElementById("custom-add").reset();
  document.getElementById("custom-form-title").textContent = "New rule";
  document.getElementById("custom-save").textContent = "Add rule";
  document.getElementById("custom-cancel").hidden = true;
}

document.getElementById("custom-cancel").addEventListener("click", stopEditing);
document.getElementById("custom-add").addEventListener("submit", async e => {
  e.preventDefault();
  const f = e.target.elements, v = k => f[k].value.trim();
  const body = { action: editing === null ? "add" : "edit", name: v("name"), proto: v("proto"),
                 port: v("port"), src: v("src"), dst: v("dst"), text: f.text.value };
  if (editing !== null) body.sid = editing;
  if (await rulesChange("/api/rules/custom", body)) stopEditing();
});
loadRules();

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
