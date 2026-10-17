/* TunnelManager dashboard — vanilla JS, live over WebSocket. */
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));

const TNAME = {
  tcpmux: "TCP Mux", wsmux: "WS Mux", tcp: "TCP", ws: "WebSocket", stealth: "Stealth",
  kcp: "KCP", quic: "QUIC", wssmux: "WSS Mux", wss: "WSS", udp: "UDP",
};
const FA = {
  up: "وصل", degraded: "ناپایدار", down: "قطع", testing: "در حال تست", pending: "ساخته نشده",
  online: "آنلاین", offline: "آفلاین", unknown: "نامشخص", ok: "سالم", broken: "قطع",
};
const COL_X = { kharej: 0, iran: 440, domain: 880 };
const COL_TITLE = { kharej: "سرورهای خارج", iran: "سرورهای داخل", domain: "دامنه‌ها" };
const NODE_W = 250;

let S = null;          // last state from the server
let skew = 0;          // server clock - local clock (s)
let events = [];
let evFilter = "all";
let drawer = null;     // {type, id}
let selTransport = null;
let groupDraft = null; // {manual, ids} while editing a domain's group
let ws = null, wsAlive = false;

/* ------------------------------------------------------------------ api */
async function api(method, path, body) {
  const r = await fetch(path, {
    method, credentials: "same-origin",
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await r.json(); } catch (_) { /* empty body */ }
  if (r.status === 401 && path !== "/api/login") { showAuth(); throw new Error("login required"); }
  if (!r.ok) {
    let msg = data && data.detail;
    if (Array.isArray(msg)) msg = msg.map((d) => `${(d.loc || []).slice(-1)[0]}: ${d.msg}`).join(" — ");
    throw new Error(msg || `HTTP ${r.status}`);
  }
  return data;
}

function toast(msg, kind = "info") {
  const el = document.createElement("div");
  el.className = `toast ${kind}`;
  el.textContent = msg;
  $("#toasts").appendChild(el);
  setTimeout(() => el.remove(), kind === "error" ? 7000 : 3500);
}

async function act(fn, okMsg) {
  try { const r = await fn(); if (okMsg) toast(okMsg, "success"); return r; }
  catch (e) { toast(e.message, "error"); throw e; }
}

/* --------------------------------------------------------------- helpers */
const srv = (id) => S.servers.find((s) => s.id === id);
const linkById = (id) => S.links.find((l) => l.id === id);
const byRole = (role) => S.servers.filter((s) => s.role === role).sort((a, b) => a.priority - b.priority || a.name.localeCompare(b.name));
const nm = (id) => (srv(id) || {}).name || "—";
const isBusy = (l) => S.busy.includes(l.id);
const lstatus = (l) => (isBusy(l) ? "testing" : l.status);
const isFlapping = (l) => S.flapping.includes(l.id);
const handedOver = (l) => !!S.handover[l.id];
const ms = (v) => (v == null ? "—" : `${Math.round(v)}ms`);
const provider = (id) => S.providers.find((p) => p.id === id);
const nowS = () => Date.now() / 1000 + skew;
const linkName = (l) => (l ? `${nm(l.kharej_id)} ⇄ ${nm(l.iran_id)}` : "—");
const linkTag = (l) => (l && l.label ? ` (${l.label})` : "");
function linkCell(l, extra = "") {
  const st = lstatus(l);
  const sub = [l.label, l.transport, st === "up" ? ms(l.latency_ms) : FA[st]].filter(Boolean).join(" · ");
  return `<span class="grow"><span>${esc(linkName(l))}</span><span class="sub mono">${esc(sub)}${extra}</span></span>`;
}
function activeLinkIds() {
  const set = new Set();
  for (const d of S.domains) for (const r of d.routes || []) if (r.link_id) set.add(r.link_id);
  return set;
}
function ago(ts) {
  if (!ts) return "—";
  const s = Math.max(0, Math.round(nowS() - ts));
  if (s < 60) return `${s} ثانیه پیش`;
  if (s < 3600) return `${Math.floor(s / 60)} دقیقه پیش`;
  if (s < 86400) return `${Math.floor(s / 3600)} ساعت پیش`;
  return `${Math.floor(s / 86400)} روز پیش`;
}
function dur(s) {
  s = Math.max(0, Math.round(s));
  if (s < 60) return `${s} ثانیه`;
  return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, "0")} دقیقه`;
}
function clock(ts) {
  const d = new Date(ts * 1000);
  const t = d.toLocaleTimeString("en-GB");
  return d.toDateString() === new Date().toDateString() ? t : `${d.toLocaleDateString("en-GB")} ${t}`;
}
function spark(history, w = 110, h = 22) {
  const pts = (history || []).slice(-40);
  if (pts.length < 2) return "";
  const vals = pts.map((p) => p[1]).filter((v) => v >= 0);
  const max = Math.max(10, ...vals) * 1.15;
  const step = w / (pts.length - 1);
  let d = "", fails = "";
  pts.forEach((p, i) => {
    const x = (i * step).toFixed(1);
    if (p[1] < 0) { fails += `<rect x="${x - 1}" y="0" width="2" height="${h}" fill="var(--down)" opacity=".7"/>`; return; }
    const y = (h - (p[1] / max) * (h - 3) - 1.5).toFixed(1);
    d += `${d && pts[i - 1][1] >= 0 ? "L" : "M"}${x},${y}`;
  });
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}" style="display:block">${fails}<path d="${d}" fill="none" stroke="var(--muted)" stroke-width="1.4"/></svg>`;
}

/* ------------------------------------------------------------------ boot */
async function boot() {
  let sess;
  try { sess = await api("GET", "/api/session"); } catch (e) { toast(e.message, "error"); return; }
  $("#ver").textContent = `v${sess.version}`;
  if (!sess.logged_in) return showAuth(sess.configured);
  startApp();
}

function showAuth(configured = true) {
  $("#app").classList.add("hidden");
  $("#auth").classList.remove("hidden");
  const setup = !configured;
  $("#auth-sub").textContent = setup ? "اولین اجرا: یک نام کاربری و رمز عبور برای مدیر بسازید" : "ورود به پنل مدیریت تانل‌ها";
  $("#auth-btn").textContent = setup ? "ساخت حساب و ورود" : "ورود";
  $("#auth-form").onsubmit = async (e) => {
    e.preventDefault();
    const f = new FormData(e.target);
    try {
      await api("POST", setup ? "/api/setup" : "/api/login", { username: f.get("username"), password: f.get("password") });
      startApp();
    } catch (err) { $("#auth-err").textContent = err.message; }
  };
}

let firstState = true;
function startApp() {
  $("#auth").classList.add("hidden");
  $("#app").classList.remove("hidden");
  api("GET", "/api/state").then((st) => {
    events = st.events || [];
    setState(st);
    renderEvents();
  }).catch(() => {});
  connectWS();
}

function connectWS() {
  if (ws) try { ws.close(); } catch (_) { /* ignore */ }
  const proto = location.protocol === "https:" ? "wss" : "ws";
  ws = new WebSocket(`${proto}://${location.host}/ws`);
  ws.onopen = () => { wsAlive = true; $("#live").classList.add("on"); };
  ws.onclose = (e) => {
    wsAlive = false; $("#live").classList.remove("on");
    if (e.code === 4401) return showAuth();
    setTimeout(connectWS, 2500);
  };
  ws.onmessage = (m) => {
    const msg = JSON.parse(m.data);
    if (msg.type === "state") setState(msg.state);
    else if (msg.type === "event") { events.push(msg.event); events = events.slice(-300); renderEvents(msg.event.id); }
    else if (msg.type === "test" && drawer && drawer.type === "link" && drawer.id === msg.link_id) {
      const l = linkById(msg.link_id);
      if (l) { l.tests[msg.result.transport] = msg.result; renderDrawer(); }
    }
  };
}
setInterval(() => { if (wsAlive) try { ws.send("ping"); } catch (_) { /* ignore */ } }, 25000);

function setState(st) {
  S = st;
  skew = st.now - Date.now() / 1000;
  renderAll();
}

function renderAll() {
  if (!S) return;
  renderStats();
  renderCanvas();
  renderTable();
  renderEmpty();
  renderDrawer();
}

/* ----------------------------------------------------------------- stats */
function renderStats() {
  const on = S.servers.filter((s) => s.status === "online").length;
  const live = S.links.filter((l) => l.status !== "pending");
  const up = live.filter((l) => l.status === "up").length;
  const dok = S.domains.filter((d) => d.status === "ok").length;
  const pill = (label, a, b) => {
    const col = !b ? "var(--pending)" : a === b ? "var(--up)" : a >= b / 2 ? "var(--degraded)" : "var(--down)";
    return `<span class="stat"><span class="d" style="background:${col}"></span>${label} <b>${a}/${b}</b></span>`;
  };
  const prop = S.domains.filter((d) => d.pending_ip).length;
  const flap = S.flapping.length;
  const hand = Object.keys(S.handover).length;
  $("#stats").innerHTML =
    pill("سرورها", on, S.servers.length) + pill("تانل‌ها", up, live.length) + pill("دامنه‌ها", dok, S.domains.length) +
    (hand ? `<span class="stat" style="color:var(--handover)">${hand} انتقال پورت</span>` : "") +
    (flap ? `<span class="stat" style="color:var(--degraded)">${flap} تانل ناپایدار</span>` : "") +
    (prop ? `<span class="stat" style="color:var(--degraded)">${prop} در انتظار DNS</span>` : "") +
    (S.busy.length ? `<span class="stat" style="color:var(--testing)">${S.busy.length} عملیات در جریان</span>` : "") +
    (S.demo ? `<span class="stat">حالت دمو</span>` : "") +
    (S.settings.observe_only ? `<span class="stat observe" id="observe-pill" title="پنل فقط نظارت و گزارش می‌کند؛ هیچ تغییری خودکار انجام نمی‌شود">● حالت نظارت</span>` : "");
}
setInterval(() => {
  if (!S) return;
  $("#last-check").textContent = S.last_check ? `بررسی: ${ago(S.last_check)}` : "در انتظار اولین بررسی";
  if (drawer && drawer.type === "domain") {
    const el = $("#failback-timer");
    if (el) el.textContent = failbackText(S.domains.find((x) => x.id === drawer.id)) || "";
  }
}, 1000);

/* ================================================================ canvas */
const canvas = $("#canvas"), world = $("#world"), nodesEl = $("#nodes"), wiresEl = $("#wires");
const view = { x: 60, y: 70, z: 1 };
const pos = {};             // node id -> [x, y] in world units
const els = {};             // node id -> element
let viewRestored = false;
try {
  const saved = localStorage.getItem("tm-view");
  if (saved) { Object.assign(view, JSON.parse(saved)); viewRestored = true; }
} catch (_) { /* ignore */ }

function applyView() {
  world.style.transform = `translate(${view.x}px,${view.y}px) scale(${view.z})`;
  const g = 22 * view.z;
  canvas.style.backgroundSize = `${g}px ${g}px`;
  canvas.style.backgroundPosition = `${view.x}px ${view.y}px`;
  $("#zoom-val").textContent = `${Math.round(view.z * 100)}%`;
  clearTimeout(applyView.t);
  applyView.t = setTimeout(() => { try { localStorage.setItem("tm-view", JSON.stringify({ ...view, cw: canvas.clientWidth })); } catch (_) { /* ignore */ } }, 300);
}
function zoomAt(cx, cy, f) {
  const r = canvas.getBoundingClientRect();
  const px = cx - r.left, py = cy - r.top;
  const nz = Math.min(2.5, Math.max(0.2, view.z * f));
  view.x = px - (px - view.x) * (nz / view.z);
  view.y = py - (py - view.y) * (nz / view.z);
  view.z = nz;
  applyView();
}
function fit() {
  const ids = Object.keys(els);
  if (!ids.length) { Object.assign(view, { x: 60, y: 70, z: 1 }); return applyView(); }
  let x0 = 1e9, y0 = 1e9, x1 = -1e9, y1 = -1e9;
  for (const id of ids) {
    const [x, y] = pos[id]; const el = els[id];
    x0 = Math.min(x0, x); y0 = Math.min(y0, y - 30); x1 = Math.max(x1, x + el.offsetWidth); y1 = Math.max(y1, y + el.offsetHeight);
  }
  const r = canvas.getBoundingClientRect();
  const top = 56, bottom = 60, pad = 30;
  const z = Math.min(1.15, (r.width - pad * 2) / (x1 - x0), (r.height - top - bottom) / (y1 - y0));
  view.z = Math.max(0.2, z);
  view.x = (r.width - (x1 - x0) * view.z) / 2 - x0 * view.z;
  view.y = top + (r.height - top - bottom - (y1 - y0) * view.z) / 2 - y0 * view.z;
  applyView();
}

function serverCard(s) {
  const st = s.status;
  const links = S.links.filter((l) => l.status !== "pending" && (l.iran_id === s.id || l.kharej_id === s.id));
  const up = links.filter((l) => l.status === "up").length;
  const meta = [`<span class="chip">${up}/${links.length} تانل</span>`];
  if (s.ssh_latency_ms != null) meta.push(`<span class="chip mono" title="تأخیر SSH از پنل">ssh ${ms(s.ssh_latency_ms)}</span>`);
  if (s.role === "iran") {
    const doms = S.domains.filter((d) => d.iran_id === s.id).length;
    if (doms) meta.push(`<span class="chip info">${doms} دامنه</span>`);
  }
  return {
    cls: ["node", st === "offline" ? "offline" : "", s.enabled ? "" : "disabled"].join(" "),
    html: `<div class="row1"><span class="dot ${st}"></span><span class="title">${esc(s.name)}</span><span class="role">${s.role === "iran" ? "داخل" : "خارج"}${s.priority !== 100 ? ` · P${s.priority}` : ""}</span></div>
      <div class="ip">${esc(s.ip)}</div><div class="meta">${meta.join("")}</div>`,
  };
}

function domainCard(d) {
  const p = provider(d.provider_id);
  const meta = [];
  if (d.iran_id) meta.push(`<span class="chip">${esc(nm(d.iran_id))}</span>`);
  const routes = d.routes || [];
  for (const r of routes.slice(0, 4)) {
    const l = linkById(r.link_id);
    meta.push(`<span class="chip mono ${r.healthy ? "" : "bad"}" title="${esc(l ? linkName(l) : "بدون تانل")}">${esc(r.spec)}→${esc(l ? nm(l.kharej_id) : "؟")}</span>`);
  }
  if (routes.length > 4) meta.push(`<span class="chip">+${routes.length - 4}</span>`);
  if (!routes.length && d.iran_id) meta.push(`<span class="chip warn">پورت مشخص نشده</span>`);
  if (d.iran_id && d.primary_iran && d.iran_id !== d.primary_iran) meta.push(`<span class="chip warn">جایگزین</span>`);
  if (d.pending_ip) meta.push(`<span class="chip warn">در انتظار DNS</span>`);
  if (!d.auto_failover) meta.push(`<span class="chip">دستی</span>`);
  if (d.error) meta.push(`<span class="chip bad" title="${esc(d.error)}">خطا</span>`);
  return {
    cls: "node domain",
    html: `<div class="row1"><span class="dot ${d.status}"></span><span class="title">${esc(d.fqdn)}</span>${p ? `<span class="prov ${p.kind}">${p.kind === "cloudflare" ? "CF" : "ARVAN"}</span>` : ""}</div>
      <div class="ip">${esc(d.current_ip || "—")}</div><div class="meta">${meta.join("")}</div>`,
  };
}

function renderCanvas() {
  const items = [];
  for (const s of byRole("kharej")) items.push(["kharej", s.id, serverCard(s)]);
  for (const s of byRole("iran")) items.push(["iran", s.id, serverCard(s)]);
  const iranRank = Object.fromEntries(byRole("iran").map((s, i) => [s.id, i]));
  const rank = (d) => iranRank[d.iran_id] ?? 99;
  for (const d of [...S.domains].sort((a, b) => rank(a) - rank(b) || a.fqdn.localeCompare(b.fqdn))) items.push(["domain", d.id, domainCard(d)]);
  const seen = new Set();
  for (const [col, id, card] of items) {
    seen.add(id);
    let el = els[id];
    if (!el) {
      el = document.createElement("div");
      el.dataset.id = id;
      el.dataset.type = col === "domain" ? "domain" : "server";
      el.dataset.col = col;
      nodesEl.appendChild(el);
      els[id] = el;
      bindDrag(el);
    }
    if (el.dataset.html !== card.html) { el.innerHTML = card.html; el.dataset.html = card.html; }
    const keep = ["dragging", "hl"].filter((c) => el.classList.contains(c)).join(" ");
    const cls = `${card.cls} ${keep}`.trim();
    if (el.className !== cls) el.className = cls;
  }
  for (const id of Object.keys(els)) if (!seen.has(id)) { els[id].remove(); delete els[id]; delete pos[id]; }
  // positions: the saved layout, else stacked under the column
  const bottom = { kharej: 30, iran: 30, domain: 30 };
  for (const [col, id] of items) if (pos[id]) bottom[col] = Math.max(bottom[col], pos[id][1] + els[id].offsetHeight + 18);
  for (const [col, id] of items) {
    if (!pos[id]) {
      const saved = S.layout[id];
      pos[id] = saved ? [saved[0], saved[1]] : [COL_X[col], bottom[col]];
      bottom[col] = Math.max(bottom[col], pos[id][1] + els[id].offsetHeight + 18);
    }
    els[id].style.left = `${pos[id][0]}px`;
    els[id].style.top = `${pos[id][1]}px`;
  }
  renderTitles(items);
  if (firstState) {
    firstState = false;
    const sameScreen = view.cw && Math.abs(view.cw - canvas.clientWidth) / canvas.clientWidth < 0.3;
    if (viewRestored && sameScreen) applyView(); else requestAnimationFrame(fit);
  }
  drawWires();
}
function renderTitles(items) {
  let titles = $$(".col-title", world);
  if (!titles.length) {
    for (const col of Object.keys(COL_X)) {
      const t = document.createElement("div");
      t.className = "col-title"; t.dataset.col = col; t.textContent = COL_TITLE[col];
      world.insertBefore(t, nodesEl);
    }
    titles = $$(".col-title", world);
  }
  for (const t of titles) {
    const mine = items.filter((i) => i[0] === t.dataset.col).map((i) => pos[i[1]]);
    t.style.display = mine.length ? "" : "none";
    if (!mine.length) continue;
    t.style.top = `${Math.min(...mine.map((p) => p[1])) - 26}px`;
    t.style.left = `${Math.min(...mine.map((p) => p[0]))}px`;
    t.style.width = `${NODE_W}px`;
    t.style.textAlign = "center";
  }
}

function box(id) {
  const el = els[id];
  if (!el || !pos[id]) return null;
  const [x, y] = pos[id];
  return { x, y, w: el.offsetWidth, h: el.offsetHeight, cx: x + el.offsetWidth / 2, cy: y + el.offsetHeight / 2 };
}
function bezier(x1, y1, x2, y2, dir1, dir2) {
  const dx = Math.max(50, Math.abs(x2 - x1) * 0.45);
  const p = [x1, y1, x1 + dx * dir1, y1, x2 + dx * dir2, y2, x2, y2];
  return { d: `M${p[0]},${p[1]} C${p[2]},${p[3]} ${p[4]},${p[5]} ${p[6]},${p[7]}`, p };
}
function bezAt(p, t) {
  const u = 1 - t;
  return [
    u * u * u * p[0] + 3 * u * u * t * p[2] + 3 * u * t * t * p[4] + t * t * t * p[6],
    u * u * u * p[1] + 3 * u * u * t * p[3] + 3 * u * t * t * p[5] + t * t * t * p[7],
  ];
}

let wiresQueued = false;
function drawWires() {
  if (wiresQueued) return;
  wiresQueued = true;
  requestAnimationFrame(() => { wiresQueued = false; drawWiresNow(); });
}
function drawWiresNow() {
  if (!S) return;
  const showStandby = $("#show-standby").checked;
  const active = activeLinkIds();
  const parts = [], labels = [];
  const edges = [];
  for (const l of S.links) {
    if (l.status === "pending" && !isBusy(l)) continue;
    const a = box(l.kharej_id), b = box(l.iran_id);
    if (!a || !b) continue;
    const st = lstatus(l);
    const standby = st === "up" && !active.has(l.id) && !handedOver(l);
    if (standby && !showStandby) continue;
    edges.push({ kind: "link", l, from: l.kharej_id, to: l.iran_id, a, b, st, act: active.has(l.id), standby });
  }
  for (const d of S.domains) {
    if (!d.iran_id) continue;
    const a = box(d.iran_id), b = box(d.id);
    if (!a || !b) continue;
    edges.push({ kind: "domain", d, from: d.iran_id, to: d.id, a, b });
  }
  // spread the anchor points along each node side, ordered by the far end
  const sides = {};
  for (const e of edges) {
    e.dir1 = e.b.cx >= e.a.cx ? 1 : -1;
    e.dir2 = -e.dir1;
    (sides[`${e.from}|${e.dir1}`] ||= []).push([e, "a"]);
    (sides[`${e.to}|${e.dir2}`] ||= []).push([e, "b"]);
  }
  for (const list of Object.values(sides)) {
    list.sort((p, q) => (p[1] === "a" ? p[0].b.cy : p[0].a.cy) - (q[1] === "a" ? q[0].b.cy : q[0].a.cy));
    list.forEach(([e, end], i) => {
      const bx = e[end];
      e[`y_${end}`] = bx.y + bx.h * (0.22 + (0.56 * (i + 1)) / (list.length + 1));
    });
  }
  const placed = [];
  const placeLabel = (c, w) => {
    for (const t of [0.5, 0.38, 0.62, 0.3, 0.7, 0.44, 0.56]) {
      const [x, y] = bezAt(c.p, t);
      const r = [x - w / 2, y - 10, x + w / 2, y + 10];
      if (!placed.some((q) => r[0] < q[2] && q[0] < r[2] && r[1] < q[3] && q[1] < r[3])) { placed.push(r); return [x, y]; }
    }
    return bezAt(c.p, 0.5);
  };
  for (const e of edges) {
    const x1 = e.dir1 > 0 ? e.a.x + e.a.w : e.a.x;
    const x2 = e.dir2 > 0 ? e.b.x + e.b.w : e.b.x;
    const c = bezier(x1, e.y_a, x2, e.y_b, e.dir1, e.dir2);
    if (e.kind === "link") {
      const l = e.l;
      const moved = handedOver(l) && e.st === "up";
      const cls = `wire ${moved ? "handover" : e.st}${e.act ? " active" : ""}${e.standby ? " standby" : ""}`;
      parts.push(`<path class="${cls}" d="${c.d}" data-link="${l.id}"/>`);
      if (e.act && e.st === "up") parts.push(`<path class="flowline" d="${c.d}" data-link="${l.id}"/>`);
      parts.push(`<path class="hit" d="${c.d}" data-link="${l.id}"/>`);
      if (e.standby) continue;
      let txt;
      if (e.st === "testing") txt = "testing…";
      else if (moved) txt = `${l.transport} · ports moved`;
      else txt = `${l.transport || "—"}${e.st === "up" && l.latency_ms != null ? ` · ${Math.round(l.latency_ms)}ms` : e.st === "down" ? " ✕" : ""}${isFlapping(l) ? " ⚡" : ""}`;
      const w = txt.length * 6.5 + 14;
      const [lx, ly] = placeLabel(c, w);
      labels.push(`<g class="wlabel ${moved ? "handover" : e.st}" data-link="${l.id}" transform="translate(${(lx - w / 2).toFixed(1)},${(ly - 10).toFixed(1)})"><rect width="${w.toFixed(1)}" height="20" rx="10"/><text x="${(w / 2).toFixed(1)}" y="14" text-anchor="middle">${esc(txt)}</text></g>`);
    } else {
      const d = e.d;
      parts.push(`<path class="dwire ${d.pending_ip ? "pending-dns" : d.status}" d="${c.d}" data-domain="${d.id}"/>`);
      if (d.status === "ok" && !d.pending_ip) parts.push(`<path class="flowline" d="${c.d}" data-domain="${d.id}"/>`);
    }
  }
  wiresEl.innerHTML = parts.join("") + labels.join("");
  applyFocus();
}

/* drag nodes; pan & zoom the canvas */
function bindDrag(el) {
  el.addEventListener("pointerdown", (e) => {
    if (e.button !== 0) return;
    e.stopPropagation();
    const id = el.dataset.id;
    const start = { cx: e.clientX, cy: e.clientY, x: pos[id][0], y: pos[id][1] };
    let moved = false;
    el.setPointerCapture(e.pointerId);
    const move = (ev) => {
      const dx = (ev.clientX - start.cx) / view.z, dy = (ev.clientY - start.cy) / view.z;
      if (!moved && Math.hypot(ev.clientX - start.cx, ev.clientY - start.cy) < 4) return;
      moved = true;
      el.classList.add("dragging");
      tip.classList.remove("show");
      pos[id] = [Math.round(start.x + dx), Math.round(start.y + dy)];
      el.style.left = `${pos[id][0]}px`; el.style.top = `${pos[id][1]}px`;
      drawWires();
    };
    const up = () => {
      el.removeEventListener("pointermove", move);
      el.removeEventListener("pointerup", up);
      el.removeEventListener("pointercancel", up);
      el.classList.remove("dragging");
      if (moved) { saveLayout({ [id]: pos[id] }); renderTitles(currentItems()); }
      else openDrawer(el.dataset.type, id);
    };
    el.addEventListener("pointermove", move);
    el.addEventListener("pointerup", up);
    el.addEventListener("pointercancel", up);
  });
}
function currentItems() {
  return Object.values(els).map((el) => [el.dataset.col, el.dataset.id]);
}
let pendingLayout = {};
function saveLayout(p) {
  Object.assign(pendingLayout, p);
  Object.assign(S.layout, p);
  clearTimeout(saveLayout.t);
  saveLayout.t = setTimeout(() => {
    const body = { positions: pendingLayout };
    pendingLayout = {};
    api("PUT", "/api/layout", body).catch(() => {});
  }, 400);
}

const pointers = new Map();
let pan = null, pinch = null;
canvas.addEventListener("pointerdown", (e) => {
  if (e.target.closest(".tools,.legend,.empty-card,.wlabel,.hit")) return;
  pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
  canvas.setPointerCapture(e.pointerId);
  if (pointers.size === 1) { pan = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y }; canvas.classList.add("panning"); }
  else if (pointers.size === 2) {
    const [p, q] = [...pointers.values()];
    pinch = { d: Math.hypot(p.x - q.x, p.y - q.y), z: view.z };
    pan = null;
  }
});
canvas.addEventListener("pointermove", (e) => {
  if (!pointers.has(e.pointerId)) return;
  pointers.set(e.pointerId, { x: e.clientX, y: e.clientY });
  if (pinch && pointers.size === 2) {
    const [p, q] = [...pointers.values()];
    const d = Math.hypot(p.x - q.x, p.y - q.y);
    zoomAt((p.x + q.x) / 2, (p.y + q.y) / 2, (pinch.z * d) / pinch.d / view.z);
  } else if (pan) {
    view.x = pan.vx + e.clientX - pan.x;
    view.y = pan.vy + e.clientY - pan.y;
    applyView();
  }
});
const endPointer = (e) => {
  pointers.delete(e.pointerId);
  if (pointers.size < 2) pinch = null;
  if (!pointers.size) { pan = null; canvas.classList.remove("panning"); }
};
canvas.addEventListener("pointerup", endPointer);
canvas.addEventListener("pointercancel", endPointer);
canvas.addEventListener("wheel", (e) => {
  e.preventDefault();
  zoomAt(e.clientX, e.clientY, Math.exp(-e.deltaY * (e.ctrlKey ? 0.01 : 0.0015)));
}, { passive: false });
$("#tools").addEventListener("click", async (e) => {
  const b = e.target.closest("[data-zoom]");
  if (!b) return;
  const r = canvas.getBoundingClientRect();
  const z = b.dataset.zoom;
  if (z === "in") zoomAt(r.left + r.width / 2, r.top + r.height / 2, 1.2);
  else if (z === "out") zoomAt(r.left + r.width / 2, r.top + r.height / 2, 1 / 1.2);
  else if (z === "fit") fit();
  else if (z === "reset") {
    if (!confirm("چیدمان سرورها به حالت پیش‌فرض برگردد؟")) return;
    await api("DELETE", "/api/layout");
    for (const id of Object.keys(pos)) delete pos[id];
    S.layout = {};
    renderCanvas();
    requestAnimationFrame(fit);
  }
});
$("#show-standby").onchange = drawWires;

/* hover: light up a node's whole path, dim the rest */
let focus = null;
function relatedTo(type, id) {
  const nodes = new Set([id]), links = new Set(), domains = new Set();
  const addLink = (l) => { if (!l) return; links.add(l.id); nodes.add(l.iran_id); nodes.add(l.kharej_id); };
  if (type === "domain") {
    const d = S.domains.find((x) => x.id === id);
    if (d) { domains.add(d.id); if (d.iran_id) nodes.add(d.iran_id); for (const r of d.routes || []) addLink(linkById(r.link_id)); }
  } else if (type === "server") {
    for (const l of S.links) if (l.iran_id === id || l.kharej_id === id) addLink(l);
    for (const d of S.domains) {
      const via = (d.routes || []).map((r) => linkById(r.link_id)).filter(Boolean);
      if (d.iran_id === id || via.some((l) => l.kharej_id === id)) { domains.add(d.id); nodes.add(d.id); }
    }
  } else if (type === "link") {
    addLink(linkById(id));
    for (const d of S.domains) if ((d.routes || []).some((r) => r.link_id === id)) { domains.add(d.id); nodes.add(d.id); }
  }
  return { nodes, links, domains };
}
function applyFocus() {
  world.classList.toggle("focus", !!focus);
  for (const [id, el] of Object.entries(els)) el.classList.toggle("hl", !!focus && focus.nodes.has(id));
  $$("#wires [data-link], #wires [data-domain]").forEach((el) => {
    if (el.classList.contains("hit")) return;
    if (!focus) { el.classList.remove("dim", "hl"); return; }
    const on = el.dataset.link ? focus.links.has(el.dataset.link) : focus.domains.has(el.dataset.domain);
    el.classList.toggle("dim", !on);
    el.classList.toggle("hl", on && el.classList.contains("wire"));
  });
}
function linkTip(l) {
  const best = Object.values(l.tests || {}).filter((t) => t.ok).sort((a, b) => a.latency_ms - b.latency_ms).slice(0, 3)
    .map((t) => `${t.transport} ${ms(t.latency_ms)}`).join("، ");
  return `<b>${esc(linkName(l))}</b>${esc(linkTag(l))}<br>وضعیت: ${FA[lstatus(l)] || l.status}${isFlapping(l) ? " — <span style='color:var(--degraded)'>مدام قطع و وصل</span>" : ""}<br>
    پروتکل: <span class="mono">${esc(l.transport || "—")}</span>${l.pinned ? " (قفل)" : ""} · تأخیر: <span class="mono">${ms(l.latency_ms)}</span><br>
    پورت‌ها: <span class="mono">${esc((l.exposed || []).join(", ") || "—")}</span>
    ${l.error ? `<br><span style="color:var(--down)">${esc(l.error)}</span>` : ""}${best ? `<br><span class="muted">بهترین‌ها: ${esc(best)}</span>` : ""}`;
}

/* --------------------------------------------------------- tunnels table */
function renderTable() {
  const showPending = $("#show-pending").checked;
  const active = activeLinkIds();
  const rows = S.links.filter((l) => showPending || l.status !== "pending")
    .sort((a, b) => nm(a.kharej_id).localeCompare(nm(b.kharej_id)) || nm(a.iran_id).localeCompare(nm(b.iran_id)) || a.priority - b.priority);
  if (!rows.length) {
    $("#links-table").innerHTML = `<tr><td class="muted">هنوز تانلی نیست. سرورها را اضافه کنید؛ تانل‌های فعال روی آن‌ها خودکار پیدا می‌شوند.</td></tr>`;
    return;
  }
  $("#links-table").innerHTML = `<tr><th></th><th>مسیر</th><th>نام</th><th>پروتکل</th><th>تأخیر</th><th>پورت‌ها (سمت داخل)</th><th>نوع</th><th>تاریخچه</th></tr>` +
    rows.map((l) => {
      const st = lstatus(l);
      const tags = [];
      if (active.has(l.id)) tags.push(`<span class="act">● ترافیک</span>`);
      if (handedOver(l)) tags.push(`<span class="chip purple">پورت‌ها روی ${esc(linkName(linkById(S.handover[l.id])))}</span>`);
      if (isFlapping(l)) tags.push(`<span class="chip warn">ناپایدار</span>`);
      return `<tr data-link="${l.id}"><td><span class="dot ${st}"></span></td>
        <td class="pair">${esc(linkName(l))} ${tags.join(" ")}</td>
        <td class="muted">${esc(l.label || "")}</td>
        <td class="mono">${esc(st === "testing" ? "…" : l.transport || "—")}${l.pinned ? " 🔒" : ""}</td>
        <td class="mono">${st === "up" ? ms(l.latency_ms) : `<span class="muted">${FA[st] || st}</span>`}</td>
        <td class="mono small">${esc((l.ports || []).join(", ") || "—")}</td>
        <td>${l.managed ? `<span class="chip">پنل</span>` : `<span class="chip info" title="از قبل روی سرور بود">موجود</span>`}</td>
        <td>${spark(l.history, 90, 18)}</td></tr>`;
    }).join("");
}
$("#show-pending").onchange = renderTable;

/* --------------------------------------------------------------- events */
function renderEvents(newId) {
  const list = events.filter((e) => evFilter === "all" || e.level === evFilter).slice(-200).reverse();
  $("#events").innerHTML = list.map((e) => `<li class="${e.level} ${e.id === newId ? "new" : ""}">
    <span class="lv"></span><span class="msg">${esc(e.message)}</span><time>${clock(e.ts)}</time></li>`).join("")
    || `<li class="muted"><span></span><span>هنوز رویدادی ثبت نشده</span></li>`;
}
$$("#ev-filter button").forEach((b) => (b.onclick = () => {
  evFilter = b.dataset.f;
  $$("#ev-filter button").forEach((x) => x.classList.toggle("on", x === b));
  renderEvents();
}));

/* ------------------------------------------------------------ onboarding */
function renderEmpty() {
  const kh = byRole("kharej"), ir = byRole("iran");
  const steps = [
    ["سرورهای خارج و داخل را اضافه کنید (فقط آی‌پی و SSH)", kh.length > 0 && ir.length > 0],
    ["تانل‌هایی که از قبل فعال‌اند خودکار پیدا می‌شوند؛ بقیه را با «تست و اتصال» بسازید", S.links.some((l) => l.status === "up")],
    ["حساب DNS (آروان/کلادفلر) و دامنه‌ها را اضافه کنید", S.domains.length > 0],
  ];
  const el = $("#empty-hint");
  const show = S.servers.length < 2 || (!S.domains.length && S.servers.length < 3);
  el.classList.toggle("hidden", !show);
  if (!show) return;
  el.innerHTML = `<div class="empty-card"><h3>شروع کار</h3><ol>${steps.map(([t, ok]) => `<li class="${ok ? "done" : ""}">${ok ? "✓ " : ""}${t}</li>`).join("")}</ol>
    <div class="btns"><button class="btn primary sm" data-add="kharej">＋ سرور خارج</button><button class="btn sm" data-add="iran">＋ سرور داخل</button><button class="btn sm" data-add="domain">＋ دامنه</button></div></div>`;
}

/* ---------------------------------------------------------------- drawer */
function openDrawer(type, id) {
  drawer = { type, id };
  selTransport = null;
  groupDraft = null;
  $("#drawer").classList.add("open");
  $("#scrim").classList.add("open");
  renderDrawer(true);
}
function closeDrawer() {
  drawer = null;
  $("#drawer").classList.remove("open");
  $("#scrim").classList.remove("open");
}
function renderDrawer(force) {
  if (!drawer || !S) return;
  const body = $("#drawer-body");
  // never wipe what the user is typing or a group being edited
  if (!force && (groupDraft || (body.contains(document.activeElement) && document.activeElement.matches("input,textarea,select")))) return;
  const keep = $("#drawer").scrollTop;
  const html = drawer.type === "link" ? linkDrawer() : drawer.type === "server" ? serverDrawer() : domainDrawer();
  if (!html) return closeDrawer();
  body.innerHTML = html;
  $("#drawer").scrollTop = keep;
}
const head = (title, sub, status) => `<div class="d-head"><div style="flex:1;min-width:0"><h2>${title}</h2><div class="d-sub">${sub}</div></div>
  ${status ? `<span class="chip"><span class="dot ${status}"></span>${FA[status] || status}</span>` : ""}<button class="btn icon" data-close aria-label="بستن">✕</button></div>`;

function linkDrawer() {
  const l = linkById(drawer.id);
  if (!l) return "";
  const st = lstatus(l);
  const doms = S.domains.filter((d) => (d.routes || []).some((r) => r.link_id === l.id));
  const cand = S.settings.candidate_transports;
  const all = [...cand, ...S.transports.filter((t) => !cand.includes(t))];
  const sel = selTransport || l.transport;
  const grid = all.map((t) => {
    const r = l.tests[t];
    const cls = ["topt", t === l.transport ? "cur" : "", t === sel ? "sel" : "", r ? (r.ok ? "ok" : "bad") : ""].join(" ");
    const res = r ? (r.ok ? `${ms(r.latency_ms)} · ${r.connect_s ?? "?"}s` : "ناموفق") : "تست نشده";
    return `<div class="${cls}" data-pick="${t}" title="${esc(r && r.error ? r.error : "")}"><span class="n">${esc(TNAME[t] || t)}</span><span class="r">${res}</span></div>`;
  }).join("");
  const carriedFrom = Object.entries(S.handover).filter(([, v]) => v === l.id).map(([k]) => linkById(k)).filter(Boolean);
  const minutes = Math.round(S.settings.failback_after / 60);
  const handBox = handedOver(l)
    ? `<div class="box"><h4>انتقال پورت</h4><p class="note">پورت‌های این تانل الان روی <b>${esc(linkName(linkById(S.handover[l.id])))}</b> (همین سرور داخل) باز است، چون این تانل مشکل داشت. وقتی ${minutes} دقیقه بدون قطعی پایدار بماند خودکار برمی‌گردد.</p>
       <div class="btns"><button class="btn sm" data-release="${l.id}">برگرداندن همین حالا</button></div></div>`
    : carriedFrom.length ? `<div class="box"><h4>انتقال پورت</h4><p class="note">این تانل پورت‌های ${carriedFrom.map((x) => `<b>${esc(linkName(x))}</b>`).join("، ")} را هم حمل می‌کند.</p></div>` : "";
  const allowed = l.allowed && l.allowed.length ? l.allowed : cand;
  return `${head(esc(linkName(l)), `${l.managed ? "ساخته‌شده توسط پنل" : "تانل موجود روی سرور"} · <span class="mono">${esc(l.iran_name)}</span>${l.label && l.label !== l.iran_name ? ` · ${esc(l.label)}` : ""}`, st)}
  <div class="box"><h4>وضعیت</h4><dl class="kv">
    <dt>پروتکل</dt><dd><span class="mono">${esc(l.transport || "—")}</span> ${l.pinned ? "🔒 قفل" : "<span class='muted'>(خودکار)</span>"}</dd>
    <dt>تأخیر</dt><dd class="mono">${ms(l.latency_ms)}</dd>
    <dt>پایداری</dt><dd>${isFlapping(l) ? "<span class='chip warn'>مدام قطع و وصل می‌شود</span>" : l.status === "up" && l.up_since ? `وصل از ${ago(l.up_since)}` : "—"}${l.last_fail ? ` <span class="muted small">· آخرین قطعی ${ago(l.last_fail)}</span>` : ""}</dd>
    <dt>پورت تانل</dt><dd class="mono">${l.tunnel_port}</dd>
    <dt>سنجش سلامت</dt><dd>${l.probe_port ? `پروب کامل مسیر <span class="mono muted">127.0.0.1:${l.probe_port}</span>` : "از روی اتصال تانل (پروب کامل با اولین بازنویسی کانفیگ اضافه می‌شود)"}</dd>
    <dt>دامنه‌ها</dt><dd>${doms.map((d) => `<span class="chip">${esc(d.fqdn)}</span>`).join(" ") || "<span class='muted'>— رزرو</span>"}</dd>
    ${l.error ? `<dt>خطا</dt><dd style="color:var(--down)">${esc(l.error)}</dd>` : ""}
  </dl>${spark(l.history, 430, 40)}</div>
  ${handBox}
  <div class="box"><h4>پورت‌های فورواردی — سمت سرور داخل (${esc(nm(l.iran_id))})</h4>
    <textarea id="lp-ports" placeholder="443&#10;8443=2096&#10;2053-2060">${esc((l.ports || []).join("\n"))}</textarea>
    <p class="hint">هر خط یک پورت: «<span class="mono">443</span>» یعنی پورت 443 این سرور داخل به همان پورت روی سرور خارج می‌رود؛ «<span class="mono">8443=2096</span>» یعنی 8443 داخل به 2096 خارج؛ «<span class="mono">2053-2060</span>» یک بازه.</p>
    <label class="check"><input type="checkbox" id="lp-udp" ${l.accept_udp ? "checked" : ""}> UDP هم فوروارد شود</label>
    <label class="check"><input type="checkbox" id="lp-all"> همین پورت‌ها روی همه تانل‌های ${esc(nm(l.kharej_id))} تنظیم شود</label>
    <div class="btns"><button class="btn primary sm" data-save-ports="${l.id}">ذخیره و اعمال</button></div>
  </div>
  <div class="box"><h4>پروتکل اتصال</h4>
    <div class="tgrid">${grid}</div>
    <label class="check"><input type="checkbox" id="pin-on-apply" ${l.pinned ? "checked" : ""}> قفل روی این پروتکل (در قطعی عوض نشود)</label>
    <div class="btns">
      <button class="btn primary sm" data-apply-transport ${sel === l.transport && st === "up" ? "disabled" : ""}>اعمال ${esc(TNAME[sel] || sel || "")}</button>
      <button class="btn sm" data-retest>تست همه پروتکل‌ها</button>
      ${l.pinned ? `<button class="btn sm ghost" data-unpin>آزاد کردن قفل</button>` : ""}
    </div>
    <label>پروتکل‌هایی که بازسازی خودکار این تانل امتحان می‌کند</label>
    <div class="tchecks">${all.map((t) => `<label><input type="checkbox" class="lp-allowed" value="${t}" ${allowed.includes(t) ? "checked" : ""}>${t}</label>`).join("")}</div>
  </div>
  <div class="box"><h4>تنظیمات</h4>
    <div class="grid2"><label>نام نمایشی<input id="lp-label" value="${esc(l.label)}"></label><label>اولویت بین تانل‌های این جفت<input id="lp-prio" type="number" value="${l.priority}"></label></div>
    <div class="btns"><button class="btn sm" data-save-link="${l.id}">ذخیره</button>
      ${l.managed ? `<button class="btn sm danger" data-del-link="${l.id}" data-purge="1">حذف تانل</button>`
        : `<button class="btn sm" data-del-link="${l.id}">فراموش کردن (روی سرور بماند)</button><button class="btn sm danger" data-del-link="${l.id}" data-purge="1">حذف از روی سرورها</button>`}</div>
  </div>`;
}

function serverDrawer() {
  const s = srv(drawer.id);
  if (!s) return "";
  const links = S.links.filter((l) => l.iran_id === s.id || l.kharej_id === s.id);
  const other = (l) => nm(s.role === "iran" ? l.kharej_id : l.iran_id);
  const row = (l) => {
    const st = lstatus(l);
    const sub = [l.label, l.transport, st === "up" ? ms(l.latency_ms) : FA[st]].filter(Boolean).join(" · ");
    return `<div class="opt" data-link="${l.id}" style="cursor:pointer"><span class="dot ${st}"></span>
      <span class="grow"><span>${esc(other(l))}</span><span class="sub mono">${esc(sub)}</span></span></div>`;
  };
  const built = links.filter((l) => l.status !== "pending"), offers = links.filter((l) => l.status === "pending");
  const broken = built.filter((l) => l.status !== "up");
  return `${head(esc(s.name), `<span class="mono">${esc(s.ip)}</span> · سرور ${s.role === "iran" ? "داخل" : "خارج"}`, s.status)}
  <div class="box"><h4>جزئیات</h4><dl class="kv">
    <dt>SSH</dt><dd class="mono">${esc(s.ssh_user)}@${esc(s.ip)}:${s.ssh_port}</dd>
    <dt>تأخیر SSH</dt><dd class="mono">${ms(s.ssh_latency_ms)}</dd>
    <dt>آخرین پاسخ</dt><dd>${ago(s.last_seen)}</dd>
    <dt>BackPack</dt><dd class="mono">${esc(s.backpack_version || "—")}</dd>
    <dt>آخرین جستجوی تانل</dt><dd>${ago(s.last_scan)}</dd>
    <dt>اولویت</dt><dd>${s.priority} ${s.enabled ? "" : "<span class='chip warn'>غیرفعال</span>"}</dd>
    ${s.error ? `<dt>خطا</dt><dd style="color:var(--down)">${esc(s.error)}</dd>` : ""}
  </dl>
  <div class="btns"><button class="btn sm" data-edit-server="${s.id}">ویرایش</button><button class="btn sm" data-test-server="${s.id}">تست SSH</button>
  <button class="btn sm" data-scan>جستجوی تانل‌ها</button><button class="btn sm" data-install="${s.id}">نصب BackPack</button><button class="btn sm danger" data-del-server="${s.id}">حذف</button></div></div>
  <div class="box"><h4>تانل‌ها (${built.length})</h4><div class="opt-list">${built.map(row).join("") || "<span class='muted small'>—</span>"}</div>
    <div class="btns"><button class="btn sm" data-new-link="${s.id}">＋ تانل جدید</button>
    ${broken.length ? `<button class="btn sm" data-discover-links="${broken.map((l) => l.id).join(",")}">ساخت دوباره تانل‌های قطع</button>` : ""}</div></div>
  ${offers.length ? `<div class="box"><h4>جفت‌هایی که تانل ندارند</h4><div class="opt-list">${offers.map(row).join("")}</div>
    <div class="btns"><button class="btn sm" data-discover-links="${offers.map((l) => l.id).join(",")}">ساخت با بهترین پروتکل</button></div></div>` : ""}`;
}

function failbackText(d) {
  if (!d || !d.failback) return "";
  const f = d.failback, name = nm(f.iran_id);
  if (f.wait < 0) return `سرور اصلی ${name} هنوز همه پورت‌های این دامنه را سالم ندارد`;
  const left = f.wait - (nowS() - S.now);
  return left > 0 ? `برگشت به سرور اصلی ${name} بعد از ${dur(left)} پایداری دیگر` : `برگشت به سرور اصلی ${name} در بررسی بعدی`;
}
function domainDrawer() {
  const d = S.domains.find((x) => x.id === drawer.id);
  if (!d) return "";
  const p = provider(d.provider_id);
  const iran = srv(d.iran_id);
  // 1. per-port routes on the Iran server the record points at
  const routeRows = (d.routes || []).map((r) => {
    const l = linkById(r.link_id);
    const st = l ? lstatus(l) : "down";
    const sub = l ? [l.label, l.transport, st === "up" ? ms(l.latency_ms) : FA[st]].filter(Boolean).join(" · ") : "هیچ تانلی این پورت را روی این سرور باز نکرده";
    return `<div class="opt"><span class="dot ${r.healthy ? "up" : st}"></span>
      <span class="grow"><span dir="ltr" style="text-align:right"><span class="mono">${esc(r.spec)}</span> → ${esc(l ? nm(l.kharej_id) : "؟")}</span><span class="sub mono">${esc(sub)}</span></span>
      ${l ? `<button class="btn sm" data-link="${l.id}">تانل</button>` : ""}</div>`;
  }).join("");
  // 2. which ports this domain uses: pick from what the Iran server exposes
  const offered = [];
  for (const l of S.links.filter((x) => x.iran_id === d.iran_id && x.status !== "pending")) {
    for (const spec of l.ports || []) if (!offered.some((o) => o.spec === spec)) offered.push({ spec, l });
  }
  for (const spec of d.specs || []) if (!offered.some((o) => o.spec === spec)) offered.push({ spec, l: null });
  const picker = offered.map((o) => `<label><input type="checkbox" class="dp-port" value="${esc(o.spec)}" ${(d.specs || []).includes(o.spec) ? "checked" : ""}><span dir="ltr">${esc(o.spec)} <span class="muted small">→ ${esc(o.l ? nm(o.l.kharej_id) : "؟")}</span></span></label>`).join("");
  // 3. every Iran server: can it carry all of the domain's ports?
  const cov = (d.coverage || []).map((c) => {
    const s = srv(c.iran_id);
    if (!s) return "";
    const tags = [];
    if (c.iran_id === d.primary_iran) tags.push(`<span class="chip">اصلی</span>`);
    if (c.iran_id === d.iran_id) tags.push(`<span class="chip good">فعلی</span>`);
    const sub = c.ok ? "همه پورت‌ها سالم" : (c.problems[0] || "");
    return `<div class="opt ${c.ok ? "" : "off"}"><span class="dot ${c.ok ? "up" : "down"}"></span>
      <span class="grow"><span>${esc(s.name)} <span class="mono muted small">${esc(s.ip)}</span></span><span class="sub">${esc(sub)}${c.problems.length > 1 ? ` (+${c.problems.length - 1})` : ""}</span></span>
      ${tags.join("")}${c.iran_id !== d.primary_iran ? `<button class="btn sm ghost" data-primary="${c.iran_id}" title="بعد از رفع قطعی، ترافیک به این سرور برمی‌گردد">اصلی شود</button>` : ""}${c.ok && c.iran_id !== d.iran_id ? `<button class="btn sm" data-switch="${c.iran_id}">انتقال</button>` : ""}</div>`;
  }).join("");
  // 4. allowed tunnels (advanced)
  const manual = groupDraft ? groupDraft.manual : d.group.length > 0;
  const notPending = (id) => (linkById(id) || {}).status !== "pending";
  const order = groupDraft ? (groupDraft.manual ? groupDraft.ids : []) : d.effective_group.filter(manual ? () => true : notPending);
  const listed = manual ? [...order, ...S.links.filter((l) => l.status !== "pending").map((l) => l.id).filter((id) => !order.includes(id))] : order;
  const groupRows = listed.map(linkById).filter(Boolean).map((l, i) => {
    const on = order.includes(l.id);
    return `<div class="opt ${on ? "" : "off"}">
      ${manual ? `<input type="checkbox" data-g-toggle="${l.id}" ${on ? "checked" : ""}>` : `<span class="muted small mono">${i + 1}</span>`}
      <span class="dot ${lstatus(l)}"></span>${linkCell(l)}
      ${manual && on ? `<span class="ord"><button type="button" data-g-up="${l.id}" title="بالاتر">▲</button><button type="button" data-g-down="${l.id}" title="پایین‌تر">▼</button></span>` : ""}</div>`;
  }).join("");
  const fb = failbackText(d);
  return `${head(`<span class="mono">${esc(d.fqdn)}</span>`, `${p ? `<span class="prov ${p.kind}">${p.kind === "cloudflare" ? "Cloudflare" : "ArvanCloud"}</span> ${esc(p.name)}` : "بدون حساب DNS"}`, d.status)}
  <div class="box"><h4>مسیر ترافیک</h4>
    <div class="path"><span class="chip">کاربر</span><span class="arrow">→</span><span class="chip mono">${esc(d.fqdn)}</span><span class="arrow">→</span><span class="chip">${esc(iran ? `${iran.name} ${iran.ip}` : "—")}</span></div>
    ${iran ? "" : (d.error || "").startsWith("DNS read") && !d.current_ip
      ? `<p class="note" style="color:var(--degraded)">رکورد این دامنه از DNS خوانده نشد (خطا پایین). تا درست شود، پنل هر ۵ دقیقه دوباره تلاش می‌کند و هیچ تغییری در رکورد نمی‌دهد.</p>`
      : `<p class="note" style="color:var(--degraded)">رکورد این دامنه به هیچ‌کدام از سرورهای داخل ثبت‌شده اشاره نمی‌کند. از لیست «سرورهای داخل» پایین، سرور درست را انتخاب کنید.</p>`}
    ${d.pending_ip ? `<p class="note" style="color:var(--degraded)">رکورد به <span class="mono">${esc(d.pending_ip)}</span> تغییر کرده؛ در انتظار رسیدن تغییر به DNSهای عمومی (${ago(d.pending_since)})…</p>` : ""}
    ${fb ? `<p class="note"><span id="failback-timer">${esc(fb)}</span></p>` : ""}
    <dl class="kv"><dt>آی‌پی رکورد</dt><dd class="mono">${esc(d.current_ip || "—")}</dd><dt>TTL</dt><dd class="mono">${d.ttl}s</dd>
    <dt>آخرین جابه‌جایی</dt><dd>${ago(d.last_switch)}</dd><dt>جابه‌جایی خودکار</dt><dd>${d.auto_failover ? "فعال" : "غیرفعال"}</dd>
    ${d.error ? `<dt>خطا</dt><dd style="color:var(--down)">${esc(d.error)}</dd>` : ""}</dl>
    <div class="btns"><button class="btn sm" data-edit-domain="${d.id}">ویرایش</button><button class="btn sm" data-sync="${d.id}">خواندن رکورد از DNS</button><button class="btn sm danger" data-del-domain="${d.id}">حذف</button></div></div>
  ${iran ? `<div class="box"><h4>پورت‌ها و مسیرها روی ${esc(iran.name)}</h4>
    <div class="opt-list">${routeRows || "<span class='muted small'>هنوز پورتی برای این دامنه انتخاب نشده</span>"}</div>
    <label>این دامنه از کدام پورت‌ها استفاده می‌کند؟</label>
    <div class="tchecks">${picker || "<span class='muted small'>روی این سرور تانلی با پورت فورواردی نیست</span>"}</div>
    <p class="hint">دامنه فقط وقتی سالم حساب می‌شود که همه این پورت‌ها کار کنند، و فقط به سرور داخلی منتقل می‌شود که همه‌شان را سالم داشته باشد.</p>
    <div class="btns"><button class="btn primary sm" data-save-dports="${d.id}">ذخیره پورت‌ها</button></div></div>` : ""}
  <div class="box"><h4>سرورهای داخل</h4>
    <p class="note">در قطعی، رکورد به اولین سروری از این لیست می‌رود که <b>همه پورت‌های دامنه</b> را سالم دارد. «اصلی» بعد از ${Math.round(S.settings.failback_after / 60)} دقیقه پایداری کامل دوباره پشت دامنه می‌آید.</p>
    <div class="opt-list">${cov || "<span class='muted small'>—</span>"}</div></div>
  <div class="box"><h4>پیشرفته: تانل‌های مجاز و ترتیب</h4>
    <div class="seg"><button type="button" data-g-mode="auto" class="${manual ? "" : "on"}">خودکار</button><button type="button" data-g-mode="manual" class="${manual ? "on" : ""}">انتخاب دستی</button></div>
    <p class="hint">${manual ? "فقط تانل‌های تیک‌خورده برای این دامنه استفاده می‌شوند؛ ترتیب آن‌ها ترتیب سرورهای داخل را هم تعیین می‌کند." : "خودکار: همه تانل‌هایی که پورت‌های این دامنه را دارند، به ترتیب اولویت سرورهای داخل؛ و اگر خارجی از کار بیفتد، تانل خارج‌های دیگر روی همان سرور داخل."}</p>
    <div class="opt-list">${groupRows || (groupDraft ? "<span class='muted small'>بعد از ذخیره به‌صورت خودکار محاسبه می‌شود</span>" : "")}</div>
    ${groupDraft ? `<div class="btns"><button class="btn primary sm" data-g-save="${d.id}">ذخیره</button><button class="btn sm ghost" data-g-cancel>انصراف</button></div>` : ""}
  </div>`;
}

/* ----------------------------------------------------------------- modals */
function openModal(html, onSubmit) {
  const f = $("#modal-form");
  f.innerHTML = html;
  $("#modal").classList.add("open");
  f.onsubmit = async (e) => {
    e.preventDefault();
    const btn = f.querySelector("[type=submit]");
    if (btn) btn.disabled = true;
    try { await onSubmit(new FormData(f), f); closeModal(); }
    catch (err) { toast(err.message, "error"); }
    finally { if (btn) btn.disabled = false; }
  };
  const first = f.querySelector("input:not([type=checkbox]),select,textarea");
  if (first) setTimeout(() => first.focus(), 50);
}
function closeModal() { $("#modal").classList.remove("open"); }
const actions = (label) => `<div class="modal-actions"><button type="button" class="btn ghost" data-close-modal>انصراف</button><button class="btn primary" type="submit">${label}</button></div>`;
const lines = (v) => v.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);

function serverForm(role, s) {
  const k = role === "kharej";
  const edit = !!s;
  s = s || { name: "", ip: "", ssh_port: 22, ssh_user: "root", priority: 100, enabled: true, probe_target: "" };
  openModal(`<h2>${edit ? "ویرایش" : "افزودن"} سرور ${k ? "خارج" : "داخل"}</h2>
    <div class="grid2"><label>نام<input name="name" required value="${esc(s.name)}" placeholder="${k ? "Hetzner-DE" : "Tehran-1"}"></label>
    <label>آی‌پی<input name="ip" required class="mono" value="${esc(s.ip)}" placeholder="1.2.3.4"></label></div>
    <div class="grid2"><label>کاربر SSH<input name="ssh_user" value="${esc(s.ssh_user)}"></label><label>پورت SSH<input name="ssh_port" type="number" value="${s.ssh_port}"></label></div>
    <label>رمز SSH<input name="ssh_password" type="password" autocomplete="new-password" value="${edit && s.ssh_password ? "••••" : ""}" placeholder="${edit ? "خالی = بدون تغییر" : ""}"></label>
    <label>کلید خصوصی SSH (اختیاری)<textarea name="ssh_key" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----">${edit && s.ssh_key ? "••••" : ""}</textarea></label>
    ${k ? `<label>هدف پروب سلامت<input name="probe_target" class="mono" value="${esc(s.probe_target)}" placeholder="127.0.0.1:${s.ssh_port}"></label>
    <p class="hint">پنل برای تست واقعی مسیر، از داخل تانل به این آدرس روی سرور خارج وصل می‌شود (پیش‌فرض: SSH همین سرور).</p>` : ""}
    <div class="grid2"><label>اولویت (عدد کمتر = اول)<input name="priority" type="number" value="${s.priority}"></label>
    <label class="check" style="align-self:end"><input type="checkbox" name="enabled" ${s.enabled ? "checked" : ""}> فعال</label></div>
    <p class="hint">${k ? "وقتی یک سرور خارج کامل از کار بیفتد، پورت‌هایش به خارجی با عدد کمتر منتقل می‌شود." : "در قطعی، دامنه به سرور داخلی با عدد کمتر منتقل می‌شود."} اگر همه برابر باشند ترتیب الفبایی نام است. سرور «اصلی» هر دامنه جداست و با اولویت عوض نمی‌شود.</p>
    ${edit ? "" : `<p class="hint">بعد از اتصال، پنل خودش تانل‌های BackPack که از قبل روی سرورها فعال‌اند را پیدا و اضافه می‌کند.</p>`}
    ${actions(edit ? "ذخیره" : "افزودن")}`, async (f) => {
    const body = {
      role, name: f.get("name").trim(), ip: f.get("ip").trim(), ssh_user: f.get("ssh_user").trim() || "root",
      ssh_port: +f.get("ssh_port") || 22, ssh_password: f.get("ssh_password"), ssh_key: f.get("ssh_key"),
      priority: +f.get("priority") || 100, enabled: !!f.get("enabled"), probe_target: k ? f.get("probe_target").trim() : "",
    };
    if (edit) await api("PUT", `/api/servers/${s.id}`, body); else await api("POST", "/api/servers", body);
    toast(edit ? "ذخیره شد" : "سرور اضافه شد؛ در حال اتصال و جستجوی تانل‌ها…", "success");
  });
}

function linkForm(preset = {}) {
  const ir = byRole("iran"), kh = byRole("kharej");
  if (!ir.length || !kh.length) { toast("اول سرورهای داخل و خارج را اضافه کنید"); return; }
  const opt = (list, sel) => list.map((s) => `<option value="${s.id}" ${s.id === sel ? "selected" : ""}>${esc(s.name)} — ${esc(s.ip)}</option>`).join("");
  openModal(`<h2>تانل جدید</h2>
    <div class="grid2"><label>سرور خارج<select name="kharej_id">${opt(kh, preset.kharej_id)}</select></label>
    <label>سرور داخل<select name="iran_id">${opt(ir, preset.iran_id)}</select></label></div>
    <label>پورت‌های فورواردی (سمت داخل)<textarea name="ports" placeholder="443&#10;8443=2096"></textarea></label>
    <div class="grid2"><label>پروتکل<select name="transport"><option value="">خودکار (تست همه و انتخاب بهترین)</option>${S.transports.map((t) => `<option value="${t}">${TNAME[t] || t}</option>`).join("")}</select></label>
    <label>نام نمایشی<input name="label" placeholder="مثلا spare-ws"></label></div>
    <p class="hint">بین یک جفت سرور می‌توانید چند تانل با پروتکل‌های مختلف داشته باشید و آن‌ها را در گروه یک دامنه بگذارید.</p>
    ${actions("ساخت")}`, async (f) => {
    await api("POST", "/api/links", {
      iran_id: f.get("iran_id"), kharej_id: f.get("kharej_id"), label: f.get("label").trim(),
      ports: lines(f.get("ports")), transport: f.get("transport") || null,
    });
    toast("ساخت تانل شروع شد", "success");
  });
}

function providerForm(p) {
  const edit = !!p;
  p = p || { name: "", kind: "arvan", zone: "", proxied: false };
  openModal(`<h2>${edit ? "ویرایش" : "افزودن"} حساب DNS</h2>
    <div class="grid2"><label>نام<input name="name" required value="${esc(p.name)}" placeholder="آروان اصلی"></label>
    <label>سرویس‌دهنده<select name="kind"><option value="arvan" ${p.kind === "arvan" ? "selected" : ""}>ArvanCloud (آروان)</option><option value="cloudflare" ${p.kind === "cloudflare" ? "selected" : ""}>Cloudflare</option></select></label></div>
    <label>Zone (دامنه اصلی)<input name="zone" required class="mono" value="${esc(p.zone)}" placeholder="example.ir"></label>
    <label>API Key / Token<input name="api_token" type="password" class="mono" autocomplete="off" value="${edit ? "••••" : ""}" ${edit ? "" : "required"}></label>
    <p class="hint">آروان: کلید API (با یا بدون پیشوند Apikey). کلادفلر: API Token با دسترسی Zone → DNS → Edit.</p>
    <label class="check"><input type="checkbox" name="proxied" ${p.proxied ? "checked" : ""}> رکوردها پروکسی شوند (ابر آروان / ابر نارنجی) — برای تانل معمولا خاموش</label>
    ${actions(edit ? "ذخیره" : "افزودن")}`, async (f) => {
    const body = { name: f.get("name"), kind: f.get("kind"), zone: f.get("zone"), api_token: f.get("api_token"), proxied: !!f.get("proxied") };
    if (edit) await api("PUT", `/api/providers/${p.id}`, body); else await api("POST", "/api/providers", body);
    toast("ذخیره شد", "success");
  });
}

function domainForm(d) {
  if (!S.providers.length) { toast("اول یک حساب DNS اضافه کنید"); return providerForm(); }
  if (!byRole("kharej").length) { toast("اول سرورها را اضافه کنید"); return serverForm("kharej"); }
  const edit = !!d;
  d = d || { fqdn: "", provider_id: S.providers[0].id, kharej_id: "", ports: [], ttl: 120, auto_failover: true, group: [] };
  openModal(`<h2>${edit ? "ویرایش" : "افزودن"} دامنه</h2>
    <label>دامنه<input name="fqdn" required class="mono" value="${esc(d.fqdn)}" placeholder="sub.example.ir"></label>
    <div class="grid2"><label>حساب DNS<select name="provider_id">${S.providers.map((p) => `<option value="${p.id}" ${p.id === d.provider_id ? "selected" : ""}>${esc(p.name)} (${esc(p.zone)})</option>`).join("")}</select></label>
    <label>سرور خارج (اختیاری)<select name="kharej_id"><option value="">— پورت‌ها را خودم مشخص می‌کنم</option>${byRole("kharej").map((k) => `<option value="${k.id}" ${k.id === d.kharej_id ? "selected" : ""}>${esc(k.name)}</option>`).join("")}</select></label></div>
    <label>پورت‌های این دامنه (اختیاری)<input name="ports" class="mono" value="${esc((d.ports || []).join(", "))}" placeholder="443, 2053"></label>
    <p class="hint">پورت‌هایی که کاربرها با این دامنه به آن‌ها وصل می‌شوند. هر پورت می‌تواند به یک خارج متفاوت برود. خالی بگذارید تا بعد از خواندن رکورد، در پنل دامنه از روی تانل‌های همان سرور داخل تیک بزنید (یا اگر خارج را انتخاب کرده‌اید، پورت‌های تانل‌های همان خارج استفاده شود).</p>
    <div class="grid2"><label>TTL (ثانیه)<input name="ttl" type="number" min="60" value="${d.ttl}"></label>
    <label class="check" style="align-self:end"><input type="checkbox" name="auto_failover" ${d.auto_failover ? "checked" : ""}> جابه‌جایی خودکار در قطعی</label></div>
    ${actions(edit ? "ذخیره" : "افزودن")}`, async (f) => {
    const body = { fqdn: f.get("fqdn"), provider_id: f.get("provider_id"), kharej_id: f.get("kharej_id"), ports: lines(f.get("ports")), ttl: +f.get("ttl") || 120, auto_failover: !!f.get("auto_failover"), group: d.group || [] };
    if (edit) await api("PUT", `/api/domains/${d.id}`, body);
    else { const r = await api("POST", "/api/domains", body); setTimeout(() => openDrawer("domain", r.domain.id), 300); }
    toast("ذخیره شد", "success");
  });
}

function settingsForm() {
  const s = S.settings, tg = s.telegram;
  const order = [...s.candidate_transports, ...S.transports.filter((t) => !s.candidate_transports.includes(t))];
  openModal(`<h2>تنظیمات</h2>
    <fieldset><legend>حالت کار</legend>
      <label class="check"><input type="checkbox" name="observe_only" ${s.observe_only ? "checked" : ""}> <b>حالت نظارت</b>: فقط بررسی و گزارش؛ هیچ رکورد DNS، کانفیگ یا سرویسی خودکار تغییر نمی‌کند</label>
      <p class="hint">در این حالت هر جا پنل می‌خواست کاری کند، فقط در رویدادها و تلگرام می‌گوید «اگر فعال بود چه می‌کرد». کارهایی که خودتان در پنل انجام دهید اجرا می‌شوند.</p>
    </fieldset>
    <fieldset><legend>مانیتورینگ و جابه‌جایی</legend>
      <div class="grid2"><label>فاصله بررسی (ثانیه)<input name="check_interval" type="number" min="10" value="${s.check_interval}"></label>
      <label>چند خطای پشت‌سرهم = «قطع»<input name="fail_threshold" type="number" min="1" value="${s.fail_threshold}"></label></div>
      <div class="grid2"><label>برگشت به اصلی بعد از چند دقیقه پایداری<input name="failback_after" type="number" min="1" value="${Math.round(s.failback_after / 60)}"></label>
      <label>مهلت هر پروتکل در تست (ثانیه)<input name="test_timeout" type="number" min="5" value="${s.test_timeout}"></label></div>
      <div class="grid2"><label>«ناپایدار» = چند قطعی<input name="flap_count" type="number" min="2" value="${s.flap_count}"></label>
      <label>در چند دقیقه<input name="flap_window" type="number" min="1" value="${Math.round(s.flap_window / 60)}"></label></div>
      <label class="check"><input type="checkbox" name="auto_repair" ${s.auto_repair ? "checked" : ""}> بازسازی خودکار تانل‌های قطع با پروتکل‌های دیگر</label>
      <label>پروتکل‌هایی که تست می‌شوند</label>
      <div class="tchecks">${order.map((t) => `<label><input type="checkbox" name="tr" value="${t}" ${s.candidate_transports.includes(t) ? "checked" : ""}>${t}</label>`).join("")}</div>
    </fieldset>
    <fieldset><legend>سرورها و BackPack</legend>
      <label class="check"><input type="checkbox" name="auto_adopt" ${s.auto_adopt ? "checked" : ""}> پیدا کردن و اضافه کردن خودکار تانل‌های موجود روی سرورها</label>
      <label class="check"><input type="checkbox" name="auto_mesh" ${s.auto_mesh ? "checked" : ""}> پیشنهاد تانل برای هر جفت داخل/خارجی که تانل ندارد</label>
      <div class="grid2"><label>جستجوی تانل‌ها هر چند دقیقه<input name="scan_interval" type="number" min="1" value="${Math.round(s.scan_interval / 60)}"></label>
      <label>نسخه BackPack<input name="backpack_release" class="mono" value="${esc(s.backpack_release)}" placeholder="latest"></label></div>
      <div class="grid2"><label>شروع پورت تانل<input name="tunnel_port_base" type="number" value="${s.tunnel_port_base}"></label>
      <label>شروع پورت پروب (لوکال)<input name="probe_port_base" type="number" value="${s.probe_port_base}"></label></div>
      <label class="check"><input type="checkbox" name="install_backpack" ${s.install_backpack ? "checked" : ""}> نصب خودکار BackPack روی سرورهایی که ندارند</label>
    </fieldset>
    <fieldset><legend>ربات تلگرام</legend>
      <label class="check"><input type="checkbox" name="tg_enabled" ${tg.enabled ? "checked" : ""}> ارسال همه رویدادها به تلگرام</label>
      <label>توکن ربات<input name="tg_token" type="password" class="mono" autocomplete="off" value="${esc(tg.bot_token)}" placeholder="123456:ABC..."></label>
      <label>Chat ID ها (با کاما)<input name="tg_chats" class="mono" value="${esc((tg.chat_ids || []).join(", "))}" placeholder="123456789, -100987654321"></label>
      <p class="hint">Chat ID را نمی‌دانید؟ به ربات <span class="mono">/start</span> بدهید.</p>
      <div class="grid2"><label>آدرس API (ریورس‌پروکسی)<input name="tg_base" class="mono" value="${esc(tg.api_base)}"></label>
      <label>پروکسی<input name="tg_proxy" class="mono" value="${esc(tg.proxy)}" placeholder="socks5://127.0.0.1:1080"></label></div>
      <div class="btns"><button type="button" class="btn sm" id="tg-test">ارسال پیام تست</button></div>
    </fieldset>
    <fieldset><legend>حساب‌های DNS</legend>
      <div class="opt-list">${S.providers.map((p) => `<div class="opt"><span class="prov ${p.kind}">${p.kind === "cloudflare" ? "CF" : "ARVAN"}</span><span class="grow">${esc(p.name)} <span class="mono muted small">${esc(p.zone)}</span></span>
        <button type="button" class="btn sm" data-verify-provider="${p.id}">تست</button><button type="button" class="btn sm" data-edit-provider="${p.id}">ویرایش</button><button type="button" class="btn sm danger" data-del-provider="${p.id}">حذف</button></div>`).join("") || "<span class='muted small'>—</span>"}</div>
      <div class="btns"><button type="button" class="btn sm" data-add="provider">＋ حساب DNS</button></div>
    </fieldset>
    ${actions("ذخیره")}`, async (f) => {
    const observe = !!f.get("observe_only");
    if (S.settings.observe_only && !observe && !confirm("حالت نظارت خاموش شود؟ از این به بعد پنل در قطعی‌ها خودش رکورد DNS را عوض می‌کند" + (f.get("auto_repair") ? " و تانل‌های قطع را با پروتکل دیگر بازسازی می‌کند" : "") + ".")) return;
    await api("PUT", "/api/settings", {
      observe_only: observe,
      check_interval: +f.get("check_interval"), fail_threshold: +f.get("fail_threshold"), test_timeout: +f.get("test_timeout"),
      failback_after: Math.round(+f.get("failback_after") * 60), flap_count: +f.get("flap_count"), flap_window: Math.round(+f.get("flap_window") * 60),
      auto_repair: !!f.get("auto_repair"), auto_adopt: !!f.get("auto_adopt"), auto_mesh: !!f.get("auto_mesh"),
      scan_interval: Math.round(+f.get("scan_interval") * 60), candidate_transports: f.getAll("tr"),
      tunnel_port_base: +f.get("tunnel_port_base"), probe_port_base: +f.get("probe_port_base"),
      backpack_release: f.get("backpack_release").trim() || "latest", install_backpack: !!f.get("install_backpack"),
      telegram: { enabled: !!f.get("tg_enabled"), bot_token: f.get("tg_token"), chat_ids: lines(f.get("tg_chats")), api_base: f.get("tg_base").trim() || "https://api.telegram.org", proxy: f.get("tg_proxy").trim() },
    });
    toast("تنظیمات ذخیره شد", "success");
  });
  $("#tg-test").onclick = async () => {
    $("#modal-form").requestSubmit();
    setTimeout(() => act(() => api("POST", "/api/telegram/test"), "پیام تست ارسال شد"), 600);
  };
}

/* --------------------------------------------------------------- clicks */
function addFlow(kind) {
  if (kind === "kharej" || kind === "iran") serverForm(kind);
  else if (kind === "provider") providerForm();
  else if (kind === "domain") domainForm();
  else if (kind === "link") linkForm();
}
function saveDomain(dom, patch) {
  return api("PUT", `/api/domains/${dom.id}`, {
    fqdn: dom.fqdn, provider_id: dom.provider_id, kharej_id: dom.kharej_id, ports: dom.ports || [],
    ttl: dom.ttl, auto_failover: dom.auto_failover, group: dom.group || [], ...patch,
  });
}

const CLICKABLE = "[data-add],[data-close],[data-close-modal],[data-link],[data-pick],[data-apply-transport],[data-retest],[data-unpin],[data-edit-server],[data-test-server],[data-install],[data-del-server],[data-scan],[data-new-link],[data-release],[data-save-ports],[data-save-link],[data-del-link],[data-discover-links],[data-switch],[data-primary],[data-save-dports],[data-sync],[data-edit-domain],[data-del-domain],[data-verify-provider],[data-edit-provider],[data-del-provider],[data-g-mode],[data-g-toggle],[data-g-up],[data-g-down],[data-g-save],[data-g-cancel]";
document.addEventListener("click", async (e) => {
  const t = e.target.closest(CLICKABLE);
  if (!t) {
    if (!e.target.closest(".menu")) $("#add-pop").classList.remove("open");
    return;
  }
  if (t.closest("#wires")) return; // wire clicks are handled below (pointer events)
  const d = t.dataset;
  $("#add-pop").classList.remove("open");
  if (d.add) { closeModal(); return addFlow(d.add); }
  if ("close" in d) return closeDrawer();
  if ("closeModal" in d) return closeModal();
  if (d.pick) { selTransport = d.pick; return renderDrawer(true); }
  if ("applyTransport" in d) {
    const l = linkById(drawer.id);
    const tr = selTransport || l.transport || S.settings.candidate_transports[0];
    await act(() => api("POST", `/api/links/${l.id}/transport`, { transport: tr, pin: $("#pin-on-apply").checked }), `تغییر به ${tr} شروع شد`);
    selTransport = null; return;
  }
  if ("retest" in d) return act(() => api("POST", `/api/links/${drawer.id}/retest`), "تست همه پروتکل‌ها شروع شد");
  if ("unpin" in d) return act(() => api("PUT", `/api/links/${drawer.id}`, { pinned: false }), "قفل آزاد شد");
  if (d.savePorts) {
    return act(() => api("PUT", `/api/links/${d.savePorts}`, { ports: lines($("#lp-ports").value), accept_udp: $("#lp-udp").checked, apply_to_kharej: $("#lp-all").checked }), "پورت‌ها ذخیره شد و روی سرور داخل اعمال می‌شود");
  }
  if (d.saveLink) {
    const allowed = $$(".lp-allowed").filter((x) => x.checked).map((x) => x.value);
    return act(() => api("PUT", `/api/links/${d.saveLink}`, { label: $("#lp-label").value.trim(), priority: +$("#lp-prio").value || 100, allowed }), "ذخیره شد");
  }
  if (d.delLink) {
    const l = linkById(d.delLink);
    const purge = !!d.purge;
    if (!confirm(purge ? `تانل ${linkName(l)} از پنل و از روی سرورها حذف شود؟` : `تانل ${linkName(l)} از پنل حذف شود؟ (روی سرورها دست نمی‌خورد)`)) return;
    await act(() => api("DELETE", `/api/links/${d.delLink}?purge=${purge}`), "حذف شد");
    return closeDrawer();
  }
  if (d.release) return act(() => api("POST", `/api/links/${d.release}/release`), "پورت‌ها برگشت");
  if (d.editServer) { const s = srv(d.editServer); return serverForm(s.role, s); }
  if (d.testServer) {
    const r = await act(() => api("POST", `/api/servers/${d.testServer}/test`));
    return toast(r.status === "online" ? `SSH سالم — ${ms(r.latency_ms)}` : `SSH ناموفق: ${r.error}`, r.status === "online" ? "success" : "error");
  }
  if ("scan" in d) { const r = await act(() => api("POST", "/api/scan")); return toast(r.added ? `${r.added} تانل موجود پیدا و اضافه شد` : "تانل جدیدی پیدا نشد", "success"); }
  if (d.newLink) { const s = srv(d.newLink); return linkForm(s.role === "iran" ? { iran_id: s.id } : { kharej_id: s.id }); }
  if (d.install) { toast("در حال نصب BackPack…"); const r = await act(() => api("POST", `/api/servers/${d.install}/install`)); return toast(`BackPack ${r.version} آماده است`, "success"); }
  if (d.delServer) {
    if (!confirm("سرور از پنل حذف شود؟ تانل‌هایی که پنل ساخته از روی سرورها پاک می‌شوند؛ تانل‌های خودتان دست نمی‌خورند.")) return;
    await act(() => api("DELETE", `/api/servers/${d.delServer}`), "حذف شد"); return closeDrawer();
  }
  if (d.discoverLinks) return act(() => api("POST", "/api/discover", { link_ids: d.discoverLinks.split(",") }), "ساخت تانل‌ها شروع شد");
  if (d.switch) {
    const dom = S.domains.find((x) => x.id === drawer.id);
    const s = srv(d.switch);
    const note = s.id !== dom.primary_iran && dom.auto_failover && !S.settings.observe_only ? `\n\nسرور اصلی این دامنه ${nm(dom.primary_iran)} است؛ اگر این تغییر باید دائمی باشد، ${s.name} را «اصلی» کنید، وگرنه بعد از پایداری اصلی، ترافیک به آن برمی‌گردد.` : "";
    if (!confirm(`رکورد ${dom.fqdn} در DNS به ${s.name} (${s.ip}) تغییر کند؟${note}`)) return;
    return act(() => api("POST", `/api/domains/${dom.id}/switch`, { iran_id: d.switch }), "رکورد تغییر کرد");
  }
  if (d.primary) {
    const dom = S.domains.find((x) => x.id === drawer.id);
    return act(() => api("POST", `/api/domains/${dom.id}/primary`, { iran_id: d.primary }), `${nm(d.primary)} سرور اصلی ${dom.fqdn} شد`);
  }
  if (d.saveDports) {
    const dom = S.domains.find((x) => x.id === d.saveDports);
    const ports = $$(".dp-port").filter((x) => x.checked).map((x) => x.value);
    if (!ports.length) return toast("حداقل یک پورت انتخاب کنید", "error");
    return act(() => saveDomain(dom, { ports }), "پورت‌های دامنه ذخیره شد");
  }
  if (d.gMode) {
    const dom = S.domains.find((x) => x.id === drawer.id);
    const built = dom.effective_group.filter((id) => (linkById(id) || {}).status !== "pending");
    groupDraft = d.gMode === "manual" ? { manual: true, ids: dom.group.length ? [...dom.group] : built } : { manual: false, ids: [] };
    if (d.gMode === "auto" && !dom.group.length) groupDraft = null;
    return renderDrawer(true);
  }
  if (d.gToggle) {
    const ids = groupDraft.ids, i = ids.indexOf(d.gToggle);
    if (i >= 0) ids.splice(i, 1); else ids.push(d.gToggle);
    return renderDrawer(true);
  }
  if (d.gUp || d.gDown) {
    const id = d.gUp || d.gDown, ids = groupDraft.ids, i = ids.indexOf(id), j = d.gUp ? i - 1 : i + 1;
    if (i >= 0 && j >= 0 && j < ids.length) [ids[i], ids[j]] = [ids[j], ids[i]];
    return renderDrawer(true);
  }
  if ("gCancel" in d) { groupDraft = null; return renderDrawer(true); }
  if (d.gSave) {
    const dom = S.domains.find((x) => x.id === d.gSave);
    const group = groupDraft.manual ? groupDraft.ids : [];
    if (groupDraft.manual && !group.length) return toast("حداقل یک تانل انتخاب کنید", "error");
    await act(() => saveDomain(dom, { group }), "ذخیره شد");
    groupDraft = null; return renderDrawer(true);
  }
  if (d.sync) return act(() => api("POST", `/api/domains/${d.sync}/sync`), "رکورد خوانده شد");
  if (d.editDomain) return domainForm(S.domains.find((x) => x.id === d.editDomain));
  if (d.delDomain) { if (!confirm("دامنه از پنل حذف شود؟ (رکورد DNS دست نمی‌خورد)")) return; await act(() => api("DELETE", `/api/domains/${d.delDomain}`), "حذف شد"); return closeDrawer(); }
  if (d.verifyProvider) { const r = await act(() => api("POST", `/api/providers/${d.verifyProvider}/verify`)); return toast(`اتصال سالم: ${r.detail}`, "success"); }
  if (d.editProvider) return providerForm(S.providers.find((p) => p.id === d.editProvider));
  if (d.delProvider) { if (!confirm("حساب DNS حذف شود؟")) return; await act(() => api("DELETE", `/api/providers/${d.delProvider}`), "حذف شد"); return settingsForm(); }
  if (d.link) return openDrawer("link", d.link);
});
// wires & labels live inside the panned canvas: open on a clean click only
wiresEl.addEventListener("pointerdown", (e) => {
  const w = e.target.closest(".hit,.wlabel");
  if (!w) return;
  e.stopPropagation();
  const start = [e.clientX, e.clientY];
  const up = (ev) => {
    window.removeEventListener("pointerup", up);
    if (Math.hypot(ev.clientX - start[0], ev.clientY - start[1]) < 5) openDrawer("link", w.dataset.link);
  };
  window.addEventListener("pointerup", up);
});

/* hover: focus + tooltip */
const tip = $("#tip");
document.addEventListener("mouseover", (e) => {
  if (pan || $(".node.dragging")) return;
  const n = e.target.closest("#nodes .node");
  const w = e.target.closest(".hit,.wlabel");
  if (!n && !w) {
    if (focus) { focus = null; applyFocus(); tip.classList.remove("show"); }
    return;
  }
  if (n) { focus = relatedTo(n.dataset.type, n.dataset.id); applyFocus(); }
  else if (w) {
    focus = relatedTo("link", w.dataset.link); applyFocus();
    const l = linkById(w.dataset.link);
    if (l) { tip.innerHTML = linkTip(l); tip.classList.add("show"); }
  }
});
document.addEventListener("mousemove", (e) => {
  if (!tip.classList.contains("show")) return;
  const x = Math.min(e.clientX + 14, window.innerWidth - tip.offsetWidth - 8);
  tip.style.left = `${x}px`; tip.style.top = `${e.clientY + 14}px`;
});
document.addEventListener("mouseout", (e) => {
  const from = e.target.closest("#nodes .node,.hit,.wlabel");
  const to = e.relatedTarget && e.relatedTarget.closest && e.relatedTarget.closest("#nodes .node,.hit,.wlabel");
  if (from && from !== to) { focus = null; applyFocus(); tip.classList.remove("show"); }
});

$("#btn-discover").onclick = () => {
  const n = S.links.filter((l) => l.status === "pending" || l.status === "down").length;
  if (!n) return toast("تانل ساخته‌نشده یا قطعی وجود ندارد؛ به تانل‌های سالم دست زده نمی‌شود");
  if (!confirm(`${n} تانل ساخته‌نشده یا قطع با تست همه پروتکل‌ها ساخته/بازسازی می‌شود. تانل‌های سالم دست نمی‌خورند. ادامه؟`)) return;
  act(() => api("POST", "/api/discover", {}), "ساخت تانل‌ها شروع شد");
};
document.addEventListener("click", (e) => { if (e.target.closest("#observe-pill")) settingsForm(); });
$("#btn-check").onclick = () => act(() => api("POST", "/api/check"), "بررسی فوری شروع شد");
$("#btn-scan").onclick = async () => { const r = await act(() => api("POST", "/api/scan")); toast(r.added ? `${r.added} تانل موجود پیدا و اضافه شد` : "تانل جدیدی پیدا نشد", "success"); };
$("#btn-add").onclick = (e) => { e.stopPropagation(); $("#add-pop").classList.toggle("open"); };
$("#btn-settings").onclick = settingsForm;
$("#btn-logout").onclick = async () => { await api("POST", "/api/logout"); location.reload(); };
$("#btn-theme").onclick = () => {
  const cur = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = cur;
  try { localStorage.setItem("tm-theme", cur); } catch (_) { /* ignore */ }
};
$("#scrim").onclick = closeDrawer;
$("#modal").addEventListener("mousedown", (e) => { if (e.target.id === "modal") closeModal(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeModal(); closeDrawer(); } });
let lastCanvasW = 0;
window.addEventListener("resize", () => {
  const w = canvas.clientWidth;
  // a different screen (phone <-> desktop): frame everything again
  if (lastCanvasW && Math.abs(w - lastCanvasW) / lastCanvasW > 0.3) fit();
  lastCanvasW = w;
  drawWires();
});
requestAnimationFrame(() => { lastCanvasW = canvas.clientWidth; });

boot();
