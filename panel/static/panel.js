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
  const changed = m !== mode || feedCursor === null;
  mode = m;
  document.body.classList.toggle("it", mode === "it");
  document.querySelectorAll(".mode button").forEach(b => b.classList.toggle("on", b.dataset.mode === mode));
  try { localStorage.setItem("pecan-mode", mode); } catch (e) { /* storage blocked: fine */ }
  if (last) render(last);
  if (changed) restartFeed();   // the two views ask the Pi for different rows
  if (mode === "it") loadSystem();
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
    if (switchErr[w.name]) label.append(el("br"), el("span", "item-error", switchErr[w.name]));
    row.append(label, el("span", "switch" + (w.on ? " on" : "")));
    return row;
  }));
}

let busy = false;
const switchErr = {};   // switch name -> why its last change failed (shown on the row)
async function toggle(row) {
  const on = row.getAttribute("aria-checked") !== "true", name = row.dataset.name;
  const label = row.firstChild.firstChild.textContent;
  if (!on && !confirm(`Turn off "${label}"?`)) return;
  delete switchErr[name];
  busy = true;
  row.disabled = true;
  try {
    const r = await fetch("/api/switch", {
      method: "POST", credentials: "same-origin",
      headers: { "Content-Type": "application/json",
                 "X-CSRFToken": document.querySelector('meta[name="csrf-token"]').content },
      body: JSON.stringify({ name, on }) });
    if (r.status === 401) { location.href = "/login"; return; }
    const body = await r.json().catch(() => ({}));
    if (!r.ok) switchErr[name] = nothingChanged((mode === "it" && body.detail) || body.error || "Couldn't change the setting.");
  } catch (e) {
    switchErr[name] = "Can't reach the Pi. Nothing was changed.";
  } finally {
    busy = false;
    refresh();   // redraw from the real state on the Pi, whatever happened
  }
}

let lastBlock = null;   // newest alert row where the firewall blocked someone
function render(s) {
  last = s;
  if (lastBlock !== null && s.last_block > lastBlock) loadLists();   // a new timed block: show it
  lastBlock = s.last_block;
  const banner = document.getElementById("banner");
  banner.className = "glass banner " + s.level;
  document.getElementById("headline").textContent = s.headline;
  document.getElementById("problems").replaceChildren(...s.problems.map(p => el("li", "", p)));
  document.getElementById("services").replaceChildren(...Object.entries(s.services).map(([name, state]) => {
    const li = el("li");
    li.append(el("span", "dot " + (state === "active" ? "ok" : "bad")), name);
    return li;
  }));
  renderSwitches(s.switches);
  document.getElementById("settings-error").textContent = s.settings_error || "";
  // Simple mode leaves out rows the AI judged normal or hasn't explained (unless the firewall
  // blocked someone: those always show), and says how many of each; IT mode shows everything.
  const n = s.hidden_last_hour, u = s.unexplained_last_hour;
  document.getElementById("hidden").textContent = mode === "simple" ? [
    n ? `${n} normal event${n === 1 ? "" : "s"} hidden (last hour)` : "",
    u ? `${u} alert${u === 1 ? "" : "s"} not yet explained (last hour)` : ""].filter(Boolean).join(" · ") : "";
}

async function refresh() {
  try {
    const r = await fetch("/api/status", { credentials: "same-origin" });
    if (r.status === 401) { location.href = "/login"; return; }
    if (r.ok) render(await r.json());
  } catch (e) { /* the feed line already says the Pi can't be reached */ }
}

// --- Live feed: the newest page first, then every 2 s only the rows newer than the last
// answer's cursor (one small query; polling keeps the normal login and idle-logout checks,
// which a held-open stream would bypass). Simple mode: plain cards. IT mode: one dense row per
// alert with every stored field behind a click, and filters. Paused: new rows wait behind an
// "N new" button so nothing moves while someone reads.
const FEED_MS = 2000, FEED_KEEP = 300;
let feedRows = [], feedCursor = null, feedMore = false, feedGen = 0, paused = false, pending = [];
const opened = new Set();   // ids of IT rows whose details are open
const filters = document.getElementById("filters");

async function getFeed(extra) {
  const p = new URLSearchParams({ view: mode });
  if (mode === "it") for (const k of ["detection", "verdict", "q"]) {
    const v = filters.elements[k].value.trim();
    if (v) p.set(k, v);
  }
  for (const [k, v] of Object.entries(extra)) p.set(k, v);
  const r = await fetch("/api/feed?" + p, { credentials: "same-origin" });
  if (r.status === 401) { location.href = "/login"; throw new Error("signed out"); }
  const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || "The alert list can't be read.");
  return d;
}

function feedLine(text) { document.getElementById("updated").textContent = text; }

// Start over (page load, mode or filter change, or too many new rows at once). A generation
// number retires the previous loop: its answer is dropped and it doesn't schedule itself again.
function restartFeed() {
  const gen = ++feedGen;
  feedRows = []; pending = []; feedCursor = null; feedMore = false;
  renderFeed(new Set());
  feedLine("Loading...");
  feedTick(gen);
}

async function feedTick(gen) {
  try {
    const d = await getFeed(feedCursor === null ? {} : { after: feedCursor });
    if (gen !== feedGen) return;
    if (feedCursor === null) {
      feedRows = d.rows; feedMore = d.more; feedCursor = d.cursor;
      renderFeed(new Set());
    } else if (d.more) {   // more new rows than one answer carries: reload the newest page
      feedCursor = null; feedRows = []; pending = [];
    } else {
      feedCursor = d.cursor;
      if (d.rows.length && paused) { pending = d.rows.concat(pending); renderPending(); }
      else if (d.rows.length) addRows(d.rows);
    }
    feedLine((paused ? "Paused" : "Live") + " · " + new Date().toLocaleTimeString());
  } catch (e) {
    if (gen !== feedGen) return;
    feedLine(e.message === "Failed to fetch" ? "Can't reach the Pi. Retrying..." : e.message);
  }
  setTimeout(() => gen === feedGen && feedTick(gen), FEED_MS);
}

function addRows(rows) {
  feedRows = rows.concat(feedRows);
  if (feedRows.length > FEED_KEEP) { feedRows.length = FEED_KEEP; feedMore = true; }
  renderFeed(new Set(rows.map(r => r.id)));
}

function simpleCard(f) {
  const li = el("li", f.verdict);
  li.append(el("div", "meta", `${f.time} · ${f.kind} · ${f.plain_verdict}`));
  li.append(el("div", "", f.reason || "No explanation yet."));
  if (f.action) li.append(el("div", "meta", "Firewall: " + f.action));
  return li;
}

function itRow(f) {
  const li = el("li", "row " + f.verdict);
  const det = el("details");
  det.open = opened.has(f.id);
  det.addEventListener("toggle", () => { if (det.open) opened.add(f.id); else opened.delete(f.id); });
  const sum = el("summary");
  sum.append(el("span", "c-time", f.time), el("span", "c-det", f.detection),
             el("span", "c-verdict", `${f.verdict}/${f.priority}`), el("span", "c-sig", f.signature || ""),
             el("span", "c-flow", `${f.src || "?"} → ${f.dst || "?"}`), el("span", "c-count", "×" + f.count));
  const dl = el("dl");
  const add = (k, v) => { if (v !== null && v !== undefined && v !== "") dl.append(el("dt", "", k), el("dd", "", String(v))); };
  add("row", f.id); add("SID", f.sid); add("severity", f.severity); add("score", f.score);
  add("sources / destinations", f.n_src || f.n_dest ? `${f.n_src || 1} / ${f.n_dest || 1}` : "");
  add("group", f.group_key); add("firewall", f.action); add("AI reason", f.raw_reason || "none");
  det.append(sum, dl);
  li.append(det);
  return li;
}

function renderFeed(fresh) {
  const items = feedRows.map(f => {
    const li = mode === "it" ? itRow(f) : simpleCard(f);
    if (fresh.has(f.id)) li.classList.add("fresh");
    return li;
  });
  if (!items.length && feedCursor !== null) items.push(el("li", "muted small",
    mode === "it" ? "No alerts match." : "Nothing that needs your attention."));
  document.getElementById("feed").replaceChildren(...items);
  document.getElementById("older").hidden = !feedMore;
  renderPending();
}

function renderPending() {
  const n = document.getElementById("new-rows");
  n.hidden = !pending.length;
  n.textContent = `Show ${pending.length} new`;
}

function showPending() {
  const rows = pending;
  pending = [];
  addRows(rows);
}

document.getElementById("pause").addEventListener("click", e => {
  paused = !paused;
  e.target.textContent = paused ? "Resume" : "Pause";
  e.target.setAttribute("aria-pressed", paused ? "true" : "false");
  if (!paused && pending.length) showPending();
  feedLine(paused ? "Paused" : "Live");
});
document.getElementById("new-rows").addEventListener("click", showPending);
document.getElementById("older").addEventListener("click", async e => {
  const gen = feedGen;
  e.target.disabled = true;
  try {
    const d = await getFeed({ before: feedRows.length ? feedRows[feedRows.length - 1].id : feedCursor + 1 });
    if (gen === feedGen) { feedRows = feedRows.concat(d.rows); feedMore = d.more; renderFeed(new Set()); }
  } catch (err) { feedLine(err.message === "Failed to fetch" ? "Can't reach the Pi. Retrying..." : err.message); }
  e.target.disabled = false;
});
let typing = null;
filters.addEventListener("submit", e => e.preventDefault());
filters.addEventListener("change", restartFeed);
filters.elements.q.addEventListener("input", () => { clearTimeout(typing); typing = setTimeout(restartFeed, 400); });

// --- IT mode: System card (Suricata, Pi and pipeline figures), every 15 s while IT mode is on.
async function loadSystem() {
  try {
    const r = await fetch("/api/system", { credentials: "same-origin" });
    if (r.status === 401) { location.href = "/login"; return; }
    if (!r.ok) return;
    const items = [];
    let group = null;
    for (const [g, k, v] of (await r.json()).rows) {
      if (g !== group) { items.push(el("div", "sys-group", g)); group = g; }
      items.push(el("dt", "", k), el("dd", "", v));
    }
    document.getElementById("system").replaceChildren(...items);
  } catch (e) { /* shown again on the next round */ }
}
setInterval(() => { if (mode === "it") loadSystem(); }, 15000);

// --- shared helpers
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
  return `${Math.max(1, Math.ceil(sec / 60))} min left`;
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
    err.field = data.field;
    throw err;
  }
  return data;
}

// Simple mode: the plain sentence; IT mode: pecan-helper's own text when there is one.
function errText(e, offline) {
  if (e.message === "Failed to fetch") return offline;
  return mode === "it" && e.detail ? e.detail : e.message;
}

function nothingChanged(text) {
  return /nothing (was )?changed/i.test(text) ? text : `${text} Nothing was changed.`;
}

// Validation errors go under the box they are about; one call clears the others in that form.
function fieldErrors(form, field, text) {
  form.querySelectorAll(".field-error").forEach(e => { e.textContent = e.dataset.for === field ? text : ""; });
}

// --- IP lists: loaded on page load, after each change, when the status poll shows a new block,
// and when a timed block runs out (current blocks need a root helper call, which is journaled,
// so they are not part of the 5 s poll).
const OFFLINE = "Can't reach the Pi. Nothing was changed.";
let lists = null, listsAt = 0;   // last /api/lists answer and when it arrived
const rowErr = {};               // "list:address" -> why removing it failed
function listMsg(text, ok) {
  const m = document.getElementById("lists-msg");
  m.textContent = text;
  m.className = "small " + (ok ? "ok" : "error");
}

function withError(li, key) {
  if (rowErr[key]) li.append(el("div", "item-error", rowErr[key]));
  return li;
}

async function removeEntry(key, url, body, done) {
  delete rowErr[key];
  listMsg("", true);
  try { await post(url, body); listMsg(done, true); }
  catch (e) { rowErr[key] = nothingChanged(errText(e, OFFLINE)); }
  loadLists();
}

function renderLists(d) {
  const left = Math.floor((Date.now() - listsAt) / 1000);   // seconds since the blocks were read
  const locked = d.protected.map(p => {
    const li = entryRow(p.net, p.note, el("span", "muted small", "locked"));
    li.classList.add("locked");
    return li;
  });
  document.getElementById("list-protected").replaceChildren(...locked);
  document.getElementById("list-allow").replaceChildren(...d.allow.map(e => withError(entryRow(e.net, e.note,
    actionButton("Remove", () => confirm(`Stop trusting ${e.net}?`) &&
      removeEntry(`allow:${e.net}`, "/api/lists", { list: "allow", action: "remove", net: e.net }, `${e.net} is no longer trusted.`))),
    `allow:${e.net}`)));
  const deny = d.deny.map(e => withError(entryRow(e.net, e.note,
    actionButton("Unblock", () => confirm(`Unblock ${e.net}?`) &&
      removeEntry(`deny:${e.net}`, "/api/lists", { list: "deny", action: "remove", net: e.net }, `${e.net} unblocked.`))),
    `deny:${e.net}`));
  if (!deny.length) deny.push(el("li", "muted small", "Nothing blocked."));
  document.getElementById("list-deny").replaceChildren(...deny);
  let blocks;
  if (d.blocks_error) blocks = [el("li", "muted small", mode === "it" && d.blocks_detail ? d.blocks_detail : d.blocks_error)];
  else if (d.enforced === false) blocks = [el("li", "muted small",
    "The trap door service is stopped: nothing is being blocked right now, including the list on the left.")];
  else blocks = d.blocks.filter(b => b.expires === null || b.expires > left).map(b => withError(entryRow(b.ip,
    minutes(b.expires === null ? null : b.expires - left), actionButton("Unblock", () => confirm(`Lift the block on ${b.ip} now?`) &&
      removeEntry(`block:${b.ip}`, "/api/unblock", { ip: b.ip }, `${b.ip} unblocked.`))), `block:${b.ip}`));
  if (!blocks.length) blocks.push(el("li", "muted small", "Nobody right now."));
  document.getElementById("list-blocks").replaceChildren(...blocks);
}

async function loadLists() {
  try {
    const r = await fetch("/api/lists", { credentials: "same-origin" });
    if (r.status === 401) { location.href = "/login"; return; }
    if (r.ok) { lists = await r.json(); listsAt = Date.now(); renderLists(lists); }
  } catch (e) {
    listMsg("Can't reach the Pi. Trying again...", false);
    setTimeout(loadLists, 10000);
  }
}

// Count timed blocks down locally; ask the Pi again once one should have run out.
setInterval(() => {
  if (!lists || !lists.blocks) return;
  const left = (Date.now() - listsAt) / 1000;
  if (lists.blocks.some(b => b.expires !== null && b.expires <= left)) loadLists();
  else renderLists(lists);
}, 15000);

document.querySelectorAll("form.add[data-list]").forEach(f => f.addEventListener("submit", async e => {
  e.preventDefault();
  const net = f.net.value.trim(), note = f.note.value.trim();
  fieldErrors(f, null, "");
  listMsg("", true);
  if (f.dataset.list === "deny" && !confirm(`Block ${net} from reaching the Pi until you unblock it?`)) return;
  try {
    const d = await post("/api/lists", { list: f.dataset.list, action: "add", net, note });
    listMsg(`Done${d.applied ? ": " + d.applied : ""}.`, true);
    f.reset();
  } catch (err) {
    const text = errText(err, OFFLINE);
    if (err.field) fieldErrors(f, err.field, text); else listMsg(nothingChanged(text), false);
  }
  loadLists();
}));
loadLists();

// --- Rules: categories and custom rules. A change is a background job on the Pi (rebuild/test/
// reload, up to a couple of minutes): the page polls it every second, shows the step and the
// seconds on the item that was clicked, keeps every rule control disabled until it ends, then
// reloads this section. One job at a time, on the Pi and here.
let rules = null, job = null;   // last /api/rules answer; the job being followed
const jobStatus = {};            // target ("cat:games", "rule:9100000", "form") -> {text, cls}
const form = document.getElementById("custom-add");

function rulesMsg(text, ok) {
  const m = document.getElementById("rules-msg");
  m.textContent = text;
  m.className = "small " + (ok ? "ok" : "error");
}

function statusLine(target) {
  const p = el("p", "job small " + (jobStatus[target] ? jobStatus[target].cls : ""), jobStatus[target] ? jobStatus[target].text : "");
  p.setAttribute("aria-live", "polite");
  return p;
}

function renderRules() {
  const d = rules;
  if (!d) return;
  document.getElementById("categories").replaceChildren(...d.categories.map(c => {
    const box = el("div");
    const row = el("button", "switch-row");
    row.type = "button";
    row.setAttribute("role", "switch");
    row.setAttribute("aria-checked", c.on ? "true" : "false");
    const label = el("span", "", c.label);
    if (c.note) label.append(el("br"), el("span", "muted small", c.note));
    row.append(label, el("span", "switch" + (c.on ? " on" : "")));
    row.addEventListener("click", () => {
      if (c.on && !confirm(`Stop watching for "${c.label}"? This takes a minute or two.`)) return;
      startJob("/api/rules/category", { name: c.name, on: !c.on }, `cat:${c.name}`);
    });
    box.append(row, statusLine(`cat:${c.name}`));
    return box;
  }));
  // One card per rule, like the IP-list cards: name and plain summary on the left; Edit, Remove
  // and the on/off switch on the right; progress and (IT mode) the rule text underneath.
  const custom = d.custom.map(r => {
    const li = el("li", "rule-card" + (r.on ? "" : " off"));
    const text = el("div", "rule-text");
    const name = el("div", "rule-name", r.name);
    if (!r.on) name.append(" ", el("span", "off-label", "Off"));
    text.append(name, el("div", "muted small", r.summary));
    const sw = el("button", "toggle");
    sw.type = "button";
    sw.setAttribute("role", "switch");
    sw.setAttribute("aria-checked", r.on ? "true" : "false");
    sw.setAttribute("aria-label", `Rule "${r.name}"`);
    sw.append(el("span", "switch" + (r.on ? " on" : "")));
    sw.addEventListener("click", () => {
      if (r.on && !confirm(`Switch off the rule "${r.name}"? It is kept and can be switched back on.`)) return;
      startJob("/api/rules/custom", { action: "toggle", sid: r.sid, on: !r.on }, `rule:${r.sid}`);
    });
    const actions = el("div", "rule-actions");
    actions.append(actionButton("Edit", () => editRule(r)), actionButton("Remove", () =>
      confirm(`Remove the rule "${r.name}"?`) && startJob("/api/rules/custom", { action: "remove", sid: r.sid }, `rule:${r.sid}`)), sw);
    li.append(text, actions, statusLine(`rule:${r.sid}`), el("div", "rule it-only", `SID ${r.sid} rev ${r.rev}: ${r.rule}`));
    return li;
  });
  if (!custom.length) custom.push(el("li", "muted small", "None yet."));
  document.getElementById("custom").replaceChildren(...custom);
  const formLine = form.querySelector(".job");
  formLine.textContent = jobStatus.form ? jobStatus.form.text : "";
  formLine.className = "job small " + (jobStatus.form ? jobStatus.form.cls : "");
  // Every rule control is off while a job runs, whoever started it.
  document.querySelectorAll("#rules button, #rules input, #rules select").forEach(b => { b.disabled = !!job; });
  if (job) rulesMsg("One change at a time. Please wait.", true);
  else if (document.getElementById("rules-msg").textContent.startsWith("One change")) rulesMsg("", true);
  document.getElementById("rules-info").textContent = d.rules_loaded === null || d.rules_loaded === undefined ? ""
    : `Suricata: ${d.rules_loaded} rules loaded, ${d.rules_failed} failed, last reload ${d.last_reload}. ` +
      "Files: /etc/suricata/disable.conf, /var/lib/suricata/rules/pecan-custom.rules (SIDs 9100000-9199999).";
}

function showJob(j) {
  if (j.state === "running") jobStatus[j.target] = { text: `${j.step}... ${j.elapsed}s`, cls: "" };
  else if (j.state === "done") jobStatus[j.target] = { text: `Done${j.summary ? " (" + j.summary + ")" : ""} · ${j.elapsed}s`, cls: "ok" };
  else if (j.field && j.target === "form") {
    jobStatus.form = null;
    fieldErrors(form, j.field, mode === "it" ? j.detail : j.error);
  } else jobStatus[j.target] = { text: nothingChanged(mode === "it" ? j.detail : j.error), cls: "error" };
}

async function startJob(url, body, target) {
  for (const k in jobStatus) delete jobStatus[k];   // only the newest change keeps a status line
  fieldErrors(form, null, "");
  rulesMsg("", true);
  try {
    const d = await post(url, body);
    follow(d.job);
  } catch (e) {
    const text = errText(e, OFFLINE);
    if (e.field && target === "form") fieldErrors(form, e.field, text);
    else jobStatus[target] = { text: nothingChanged(text), cls: "error" };
    loadRules();
  }
}

function follow(j) {
  job = j;
  showJob(j);
  renderRules();
  setTimeout(poll, 1000);
}

async function poll() {
  if (!job) return;
  try {
    const r = await fetch(`/api/jobs/${job.id}`, { credentials: "same-origin" });
    if (r.status === 401) { location.href = "/login"; return; }
    if (r.status === 404) {   // the panel restarted: the job's outcome is unknown, show what is on the Pi
      jobStatus[job.target] = { text: "Lost track of this change (the panel restarted). The list shows what the Pi has now.", cls: "error" };
      job = null;
      loadRules();
      return;
    }
    const j = await r.json();
    showJob(j);
    if (j.state === "running") { job = j; renderRules(); setTimeout(poll, 1000); return; }
    job = null;
    if (j.state === "done" && j.target === "form") stopEditing();
    loadRules();
  } catch (e) {
    jobStatus[job.target] = { text: `Lost contact with the Pi, still waiting... ${job.elapsed}s`, cls: "" };
    renderRules();
    setTimeout(poll, 3000);
  }
}

async function loadRules() {
  try {
    const r = await fetch("/api/rules", { credentials: "same-origin" });
    if (r.status === 401) { location.href = "/login"; return; }
    if (!r.ok) return;
    rules = await r.json();
    if (rules.job && !job) { follow(rules.job); return; }   // a change started elsewhere or before a reload
    renderRules();
  } catch (e) {
    rulesMsg("Can't reach the Pi. Trying again...", false);
    setTimeout(loadRules, 10000);
  }
}

// The form adds a rule, or edits one (same SID, rev+1) after Edit loaded it. Empty boxes = any.
let editing = null;   // SID being edited, or null
function editRule(r) {
  const f = form.elements;
  editing = r.sid;
  f.name.value = r.name; f.proto.value = r.proto; f.text.value = r.text;
  for (const k of ["port", "src", "dst"]) f[k].value = r[k] === "any" ? "" : r[k];
  fieldErrors(form, null, "");
  document.getElementById("custom-form-title").textContent = `Edit "${r.name}"`;
  document.getElementById("custom-save").textContent = "Save changes";
  document.getElementById("custom-cancel").hidden = false;
  f.name.focus();
}

function stopEditing() {
  editing = null;
  form.reset();
  document.getElementById("custom-form-title").textContent = "New rule";
  document.getElementById("custom-save").textContent = "Add rule";
  document.getElementById("custom-cancel").hidden = true;
}

document.getElementById("custom-cancel").addEventListener("click", () => { stopEditing(); fieldErrors(form, null, ""); });
form.addEventListener("submit", e => {
  e.preventDefault();
  const f = form.elements, v = k => f[k].value.trim();
  const body = { action: editing === null ? "add" : "edit", name: v("name"), proto: v("proto"),
                 port: v("port"), src: v("src"), dst: v("dst"), text: f.text.value };
  if (editing !== null) body.sid = editing;
  startJob("/api/rules/custom", body, "form");
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
