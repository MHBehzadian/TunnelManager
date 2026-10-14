/* TunnelManager dashboard — vanilla JS, live over WebSocket. */
"use strict";

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const SVGNS = "http://www.w3.org/2000/svg";

const TNAME = {
  tcpmux: "TCP Mux", wsmux: "WS Mux", tcp: "TCP", ws: "WebSocket", stealth: "Stealth",
  kcp: "KCP", quic: "QUIC", wssmux: "WSS Mux", wss: "WSS", udp: "UDP",
};
const FA = {
  up: "وصل", degraded: "ناپایدار", down: "قطع", testing: "در حال تست", suspended: "معلق", pending: "ساخته نشده",
  online: "آنلاین", offline: "آفلاین", unknown: "نامشخص", ok: "سالم", broken: "قطع",
};
const LEVEL_ICON = { info: "ℹ️", success: "✅", warning: "⚠️", error: "🚨" };

let S = null;          // last state from the server
let skew = 0;          // server clock - local clock (s)
let events = [];
let evFilter = "all";
let drawer = null;     // {type, id}
let selTransport = null;
let ws = null, wsAlive = false;

/* ------------------------------------------------------------------ api */
async function api(method, path, body) {
  const r = await fetch(path, {
    method, credentials: "same-origin",
    headers: body ? { "Content-Type": "application/json" } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  let data = null;
  try { data = await r.json(); } catch (_) { /* empty */ }
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
const byRole = (role) => S.servers.filter((s) => s.role === role).sort((a, b) => a.priority - b.priority || a.name.localeCompare(b.name));
const linkFor = (iran, kharej) => S.links.find((l) => l.iran_id === iran && l.kharej_id === kharej);
const nm = (id) => (srv(id) || {}).name || "—";
const isBusy = (l) => S.busy.includes(l.id);
const lstatus = (l) => (isBusy(l) ? "testing" : l.status);
const ms = (v) => (v == null ? "—" : `${Math.round(v)}ms`);
const provider = (id) => S.providers.find((p) => p.id === id);
function activeLinkIds() {
  const set = new Set();
  for (const d of S.domains) {
    const l = linkFor(d.iran_id, d.effective_kharej_id);
    if (l) set.add(l.id);
  }
  return set;
}
function ago(ts) {
  if (!ts) return "—";
  const s = Math.max(0, Math.round(Date.now() / 1000 + skew - ts));
  if (s < 60) return `${s} ثانیه پیش`;
  if (s < 3600) return `${Math.floor(s / 60)} دقیقه پیش`;
  if (s < 86400) return `${Math.floor(s / 3600)} ساعت پیش`;
  return `${Math.floor(s / 86400)} روز پیش`;
}
function clock(ts) {
  const d = new Date(ts * 1000);
  const t = d.toLocaleTimeString("en-GB");
  return d.toDateString() === new Date().toDateString() ? t : `${d.toLocaleDateString("en-GB")} ${t}`;
}
function spark(history, w = 110, h = 24) {
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
  return `<svg width="${w}" height="${h}" viewBox="0 0 ${w} ${h}">${fails}<path d="${d}" fill="none" stroke="var(--accent)" stroke-width="1.5"/></svg>`;
}

/* ------------------------------------------------------------------ boot */
async function boot() {
  const theme = localStorage.getItem("tm-theme");
  if (theme) document.documentElement.dataset.theme = theme;
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
      const l = S.links.find((x) => x.id === msg.link_id);
      if (l) { l.tests[msg.result.transport] = msg.result; renderDrawer(); }
    }
  };
  setInterval(() => { if (wsAlive) try { ws.send("ping"); } catch (_) { /* ignore */ } }, 25000);
}

function setState(st) {
  S = st;
  skew = st.now - Date.now() / 1000;
  renderAll();
}

function renderAll() {
  if (!S) return;
  renderStats();
  renderTopo();
  renderMatrix();
  renderOnboard();
  renderDrawer();
}

/* ----------------------------------------------------------------- stats */
function renderStats() {
  const on = S.servers.filter((s) => s.status === "online").length;
  const live = S.links.filter((l) => l.status !== "pending" && l.status !== "suspended");
  const up = live.filter((l) => l.status === "up").length;
  const dok = S.domains.filter((d) => d.status === "ok").length;
  const pill = (label, a, b, icon) => {
    const pct = b ? Math.round((a / b) * 100) : 0;
    const col = !b ? "var(--pending)" : pct === 100 ? "var(--up)" : pct >= 50 ? "var(--degraded)" : "var(--down)";
    return `<div class="stat">${icon} ${label} <b>${a}/${b}</b><span class="bar"><i style="width:${pct}%;background:${col}"></i></span></div>`;
  };
  const taken = Object.keys(S.takeover || {}).length;
  $("#stats").innerHTML =
    pill("سرورها", on, S.servers.length, "🖥") + pill("تانل‌ها", up, live.length, "🔗") + pill("دامنه‌ها", dok, S.domains.length, "🌐") +
    (taken ? `<div class="stat" style="color:var(--suspended)">⇆ ${taken} خارج جایگزین شده</div>` : "") +
    (S.busy.length ? `<div class="stat" style="color:var(--testing)">⏳ ${S.busy.length} عملیات در جریان</div>` : "");
}
setInterval(() => { if (S) $("#last-check").textContent = S.last_check ? `بررسی: ${ago(S.last_check)}` : "در انتظار اولین بررسی"; }, 1000);

/* -------------------------------------------------------------- topology */
function serverCard(s) {
  const st = s.status;
  const taken = S.takeover[s.id];
  const holders = Object.entries(S.takeover).filter(([, v]) => v === s.id).map(([k]) => nm(k));
  const meta = [];
  if (s.ssh_latency_ms != null) meta.push(`<span class="chip mono" title="تأخیر SSH از پنل">ssh ${ms(s.ssh_latency_ms)}</span>`);
  if (s.role === "kharej") {
    const ports = s.ports.slice(0, 4).map((p) => `<span class="chip mono accent">${esc(p)}</span>`).join("");
    meta.push(ports || `<span class="chip warn">پورتی تعریف نشده</span>`);
    if (s.ports.length > 4) meta.push(`<span class="chip">+${s.ports.length - 4}</span>`);
  } else {
    const doms = S.domains.filter((d) => d.iran_id === s.id).length;
    meta.push(`<span class="chip ${doms ? "accent" : ""}">🌐 ${doms} دامنه</span>`);
  }
  if (!s.backpack_version && st === "online") meta.push(`<span class="chip">BackPack نصب نشده</span>`);
  if (taken) meta.push(`<span class="chip purple">⇆ ترافیک روی ${esc(nm(taken))}</span>`);
  if (holders.length) meta.push(`<span class="chip purple">میزبان ${esc(holders.join("، "))}</span>`);
  const cls = ["node", st === "offline" ? "offline" : "", s.enabled ? "" : "disabled", taken ? "taken" : ""].join(" ");
  return `<div class="${cls}" data-type="server" data-id="${s.id}">
    <div class="row1"><span class="dot ${st}"></span><span class="title">${esc(s.name)}</span>
      ${s.priority !== 100 ? `<span class="chip" title="اولویت">P${s.priority}</span>` : ""}</div>
    <div class="ip">${esc(s.ip)}</div><div class="meta">${meta.join("")}</div></div>`;
}

function domainCard(d) {
  const p = provider(d.provider_id);
  const k = d.effective_kharej_id;
  const moved = k !== d.kharej_id;
  return `<div class="node" data-type="domain" data-id="${d.id}">
    <div class="row1"><span class="dot ${d.status}"></span><span class="title mono" style="text-align:right">${esc(d.fqdn)}</span>
      ${p ? `<span class="prov ${p.kind}">${p.kind === "cloudflare" ? "CF" : "AR"}</span>` : ""}</div>
    <div class="ip">${esc(d.current_ip || "—")}</div>
    <div class="meta"><span class="chip">🏠 ${esc(d.iran_id ? nm(d.iran_id) : "—")}</span><span class="chip ${moved ? "purple" : ""}">🌍 ${esc(nm(k))}${moved ? " (جایگزین)" : ""}</span>
    ${d.auto_failover ? "" : `<span class="chip warn">دستی</span>`}${d.error ? `<span class="chip bad" title="${esc(d.error)}">خطا</span>` : ""}</div></div>`;
}

function renderTopo() {
  const kh = byRole("kharej"), ir = byRole("iran");
  const irIndex = Object.fromEntries(ir.map((s, i) => [s.id, i]));
  const doms = [...S.domains].sort((a, b) => (irIndex[a.iran_id] ?? 99) - (irIndex[b.iran_id] ?? 99) || a.fqdn.localeCompare(b.fqdn));
  $("#col-kharej .nodes").innerHTML = kh.map(serverCard).join("") || `<div class="empty-col" data-add="kharej">＋ افزودن سرور خارج</div>`;
  $("#col-iran .nodes").innerHTML = ir.map(serverCard).join("") || `<div class="empty-col" data-add="iran">＋ افزودن سرور داخل</div>`;
  $("#col-domain .nodes").innerHTML = doms.map(domainCard).join("") || `<div class="empty-col" data-add="domain">＋ افزودن دامنه</div>`;
  requestAnimationFrame(drawWires);
}

function bez(x1, y1, x2, y2) {
  const dx = Math.max(40, (x2 - x1) * 0.5);
  return { d: `M${x1},${y1} C${x1 + dx},${y1} ${x2 - dx},${y2} ${x2},${y2}`, p: [x1, y1, x1 + dx, y1, x2 - dx, y2, x2, y2] };
}
function bezAt(p, t) {
  const u = 1 - t;
  const x = u * u * u * p[0] + 3 * u * u * t * p[2] + 3 * u * t * t * p[4] + t * t * t * p[6];
  const y = u * u * u * p[1] + 3 * u * u * t * p[3] + 3 * u * t * t * p[5] + t * t * t * p[7];
  return [x, y];
}

function drawWires() {
  const topo = $("#topo"), svg = $("#wires");
  if (!topo || !S) return;
  const base = topo.getBoundingClientRect();
  svg.setAttribute("viewBox", `0 0 ${base.width} ${base.height}`);
  const box = {};
  $$(".node", topo).forEach((el) => {
    const r = el.getBoundingClientRect();
    box[el.dataset.id] = { l: r.left - base.left, r: r.right - base.left, t: r.top - base.top, h: r.height, cy: r.top - base.top + r.height / 2 };
  });
  const showStandby = $("#show-standby").checked;
  const active = activeLinkIds();
  const parts = [], labels = [];

  // kharej -> iran tunnels; spread the anchors so wires do not stack
  const links = S.links.filter((l) => box[l.iran_id] && box[l.kharej_id]);
  const outK = {}, inI = {};
  for (const l of links) {
    if (!showStandby && !active.has(l.id) && l.status === "up") continue;
    (outK[l.kharej_id] ||= []).push(l);
    (inI[l.iran_id] ||= []).push(l);
  }
  const anchor = (list, id, sortKey) => {
    list.sort((a, b) => box[sortKey(a)].cy - box[sortKey(b)].cy);
    const b = box[id], n = list.length;
    return Object.fromEntries(list.map((l, i) => [l.id, b.t + b.h * (0.22 + (0.56 * (i + 1)) / (n + 1))]));
  };
  const ka = {}, ia = {};
  for (const [k, list] of Object.entries(outK)) Object.assign(ka, anchor(list, k, (l) => l.iran_id));
  for (const [i, list] of Object.entries(inI)) Object.assign(ia, anchor(list, i, (l) => l.kharej_id));

  for (const [iid, list] of Object.entries(inI)) {
    list.forEach((l, idx) => {
      const st = lstatus(l);
      const act = active.has(l.id);
      const x1 = box[l.kharej_id].r, y1 = ka[l.id], x2 = box[l.iran_id].l, y2 = ia[l.id];
      const c = bez(x1, y1, x2, y2);
      const cls = `wire ${st} ${act ? "active" : st === "up" ? "standby" : ""}`;
      parts.push(`<path class="${cls}" d="${c.d}" data-link="${l.id}" data-k="${l.kharej_id}" data-i="${l.iran_id}"/>`);
      if (act && st === "up") parts.push(`<path class="wire-flow" style="animation-direction:reverse" d="${c.d}" data-link="${l.id}" data-k="${l.kharej_id}" data-i="${l.iran_id}"/>`);
      parts.push(`<path class="wire-hit" d="${c.d}" data-link="${l.id}"/>`);
      // label only what matters: live routes and broken/changing links;
      // healthy standby links show their details on hover
      if (!act && (st === "up" || st === "pending")) return;
      const t = act ? 0.5 : 0.5 + (((idx % 3) - 1) * 0.14);
      const [lx, ly] = bezAt(c.p, t);
      const txt = st === "testing" ? "testing…" : `${l.transport || "—"}${l.latency_ms != null && st === "up" ? ` · ${Math.round(l.latency_ms)}ms` : st === "down" ? " ✕" : ""}${l.pinned ? " 📌" : ""}`;
      const w = txt.length * 6.6 + 14;
      labels.push(`<g class="wlabel ${st} ${act || st !== "up" ? "" : "standby"}" data-link="${l.id}" transform="translate(${lx - w / 2},${ly - 10})"><rect width="${w}" height="20" rx="10"/><text x="${w / 2}" y="14" text-anchor="middle">${esc(txt)}</text></g>`);
    });
  }

  // iran -> domain (where the A record points)
  const outI = {};
  for (const d of S.domains) if (box[d.iran_id] && box[d.id]) (outI[d.iran_id] ||= []).push(d);
  for (const [iid, list] of Object.entries(outI)) {
    list.sort((a, b) => box[a.id].cy - box[b.id].cy);
    const b = box[iid];
    list.forEach((d, i) => {
      const y1 = b.t + b.h * (0.22 + (0.56 * (i + 1)) / (list.length + 1));
      const c = bez(b.r, y1, box[d.id].l, box[d.id].cy);
      parts.push(`<path class="dwire ${d.status}" d="${c.d}" data-domain="${d.id}" data-i="${iid}"/>`);
      if (d.status === "ok") parts.push(`<path class="wire-flow" style="animation-direction:reverse" d="${c.d}" data-domain="${d.id}" data-i="${iid}"/>`);
    });
  }
  svg.innerHTML = parts.join("") + labels.join("");
  applyFocus();
}

/* hover focus: light up a node's whole path, dim the rest */
let focus = null;
function relatedTo(type, id) {
  const nodes = new Set([id]), links = new Set(), domains = new Set();
  if (type === "domain") {
    const d = S.domains.find((x) => x.id === id);
    if (d) {
      domains.add(d.id);
      nodes.add(d.iran_id); nodes.add(d.effective_kharej_id);
      const l = linkFor(d.iran_id, d.effective_kharej_id);
      if (l) links.add(l.id);
    }
  } else if (type === "server") {
    const s = srv(id);
    for (const l of S.links) if (l.iran_id === id || l.kharej_id === id) { links.add(l.id); nodes.add(l.iran_id); nodes.add(l.kharej_id); }
    for (const d of S.domains) {
      if ((s && s.role === "iran" && d.iran_id === id) || (s && s.role === "kharej" && d.effective_kharej_id === id)) {
        domains.add(d.id); nodes.add(d.id); nodes.add(d.iran_id);
      }
    }
  } else if (type === "link") {
    const l = S.links.find((x) => x.id === id);
    if (l) {
      links.add(l.id); nodes.add(l.iran_id); nodes.add(l.kharej_id);
      for (const d of S.domains) if (d.iran_id === l.iran_id && d.effective_kharej_id === l.kharej_id) { domains.add(d.id); nodes.add(d.id); }
    }
  }
  return { nodes, links, domains };
}
function applyFocus() {
  const topo = $("#topo");
  topo.classList.toggle("focus", !!focus);
  $$(".node", topo).forEach((el) => el.classList.toggle("hl", !!focus && focus.nodes.has(el.dataset.id)));
  $$("#wires .wire, #wires .wire-flow, #wires .dwire").forEach((el) => {
    if (!focus) { el.classList.remove("dim", "hl"); return; }
    const on = el.dataset.link ? focus.links.has(el.dataset.link) : focus.domains.has(el.dataset.domain);
    el.classList.toggle("dim", !on);
    el.classList.toggle("hl", on && !el.classList.contains("wire-flow"));
  });
}

function linkTip(l) {
  const r = l.tests || {};
  const tested = Object.values(r).filter((t) => t.ok).sort((a, b) => a.latency_ms - b.latency_ms).slice(0, 3)
    .map((t) => `${t.transport} ${ms(t.latency_ms)}`).join("، ");
  return `<b>${esc(nm(l.kharej_id))} ⇄ ${esc(nm(l.iran_id))}</b><br>وضعیت: ${FA[lstatus(l)] || l.status}<br>
    پروتکل: <span class="mono">${esc(l.transport || "—")}</span>${l.pinned ? " 📌" : ""} · تأخیر: <span class="mono">${ms(l.latency_ms)}</span><br>
    پورت تانل: <span class="mono">${l.tunnel_port}</span>${l.error ? `<br><span style="color:var(--down)">${esc(l.error)}</span>` : ""}
    ${tested ? `<br><span class="muted">بهترین‌ها: ${esc(tested)}</span>` : ""}`;
}

/* ------------------------------------------------------------------ matrix */
function renderMatrix() {
  const kh = byRole("kharej"), ir = byRole("iran");
  if (!kh.length || !ir.length) { $("#matrix").innerHTML = `<tr><td class="muted">بعد از افزودن سرورهای داخل و خارج، اینجا وضعیت همه تانل‌ها نمایش داده می‌شود.</td></tr>`; return; }
  const active = activeLinkIds();
  let h = `<tr><th></th>${ir.map((i) => `<th><span class="dot ${i.status}" style="display:inline-block;vertical-align:middle"></span> ${esc(i.name)}</th>`).join("")}</tr>`;
  for (const k of kh) {
    h += `<tr><th class="rowh"><span class="dot ${k.status}" style="display:inline-block;vertical-align:middle"></span> ${esc(k.name)}</th>`;
    for (const i of ir) {
      const l = linkFor(i.id, k.id);
      if (!l) { h += `<td><div class="cell pending"><span class="muted">—</span></div></td>`; continue; }
      const st = lstatus(l);
      h += `<td><div class="cell ${st}" data-link="${l.id}">
        <div class="t">${esc(st === "testing" ? "⏳ تست…" : l.transport ? TNAME[l.transport] || l.transport : FA[st])}${l.pinned ? " 📌" : ""}</div>
        <div class="l">${st === "up" ? ms(l.latency_ms) : FA[st] || st}${active.has(l.id) ? ` <span class="active-mark">● فعال</span>` : ""}</div>
        ${spark(l.history, 100, 18)}</div></td>`;
    }
    h += "</tr>";
  }
  $("#matrix").innerHTML = h;
}

/* --------------------------------------------------------------- events */
function renderEvents(newId) {
  const list = events.filter((e) => evFilter === "all" || e.level === evFilter).slice(-200).reverse();
  $("#events").innerHTML = list.map((e) => `<li class="${e.level} ${e.id === newId ? "new" : ""}">
    <span class="ic">${LEVEL_ICON[e.level] || "•"}</span><span class="msg">${esc(e.message)}</span><time>${clock(e.ts)}</time></li>`).join("")
    || `<li class="muted"><span></span><span>هنوز رویدادی ثبت نشده</span></li>`;
}

/* ------------------------------------------------------------ onboarding */
function renderOnboard() {
  const kh = byRole("kharej"), ir = byRole("iran");
  const steps = [
    ["سرورهای خارج را اضافه کنید", kh.length > 0, "kharej"],
    ["سرورهای داخل را اضافه کنید", ir.length > 0, "iran"],
    ["پورت‌های فورواردی هر خارج را مشخص کنید", kh.length > 0 && kh.every((k) => k.ports.length), null],
    ["حساب DNS (کلادفلر/آروان) و دامنه‌ها را اضافه کنید", S.domains.length > 0, S.providers.length ? "domain" : "provider"],
    ["«تست و اتصال همه» را بزنید", S.links.some((l) => l.status === "up"), "discover"],
  ];
  const done = steps.every((s) => s[1]);
  const el = $("#onboard");
  el.classList.toggle("hidden", done);
  if (done) return;
  el.innerHTML = `<div class="steps">${steps.map(([t, ok, a], i) => `<div class="step ${ok ? "done" : ""}">
    <b><span class="n">${ok ? "✓" : i + 1}</span>${t}</b>
    ${!ok && a ? `<button class="btn sm" ${a === "discover" ? 'data-discover="1"' : `data-add="${a}"`}>${a === "discover" ? "⚡ شروع" : "＋ افزودن"}</button>` : ""}</div>`).join("")}</div>`;
}

/* ---------------------------------------------------------------- drawer */
function openDrawer(type, id) {
  drawer = { type, id };
  selTransport = null;
  $("#drawer").classList.add("open");
  $("#scrim").classList.add("open");
  renderDrawer();
}
function closeDrawer() {
  drawer = null;
  $("#drawer").classList.remove("open");
  $("#scrim").classList.remove("open");
}
function renderDrawer() {
  if (!drawer || !S) return;
  const body = $("#drawer-body");
  const keepScroll = $("#drawer").scrollTop;
  if (drawer.type === "link") body.innerHTML = linkDrawer();
  else if (drawer.type === "server") body.innerHTML = serverDrawer();
  else if (drawer.type === "domain") body.innerHTML = domainDrawer();
  if (!body.innerHTML.trim()) return closeDrawer();
  $("#drawer").scrollTop = keepScroll;
}
const head = (title, sub, status) => `<div class="d-head"><div style="flex:1"><h2>${title}</h2><div class="d-sub">${sub}</div></div>
  ${status ? `<span class="chip"><span class="dot ${status}"></span>${FA[status] || status}</span>` : ""}<button class="btn icon" data-close>✕</button></div>`;

function linkDrawer() {
  const l = S.links.find((x) => x.id === drawer.id);
  if (!l) return "";
  const st = lstatus(l);
  const doms = S.domains.filter((d) => d.iran_id === l.iran_id && d.effective_kharej_id === l.kharej_id);
  const cand = S.settings.candidate_transports;
  const all = [...cand, ...S.transports.filter((t) => !cand.includes(t))];
  const sel = selTransport || l.transport;
  const grid = all.map((t) => {
    const r = l.tests[t];
    const cls = ["topt", t === l.transport ? "cur" : "", t === sel ? "sel" : "", r ? (r.ok ? "ok" : "bad") : ""].join(" ");
    const res = r ? (r.ok ? `${ms(r.latency_ms)} · ${r.connect_s ?? "?"}s` : "✕ ناموفق") : cand.includes(t) ? "تست نشده" : "خارج از لیست";
    return `<div class="${cls}" data-pick="${t}" title="${esc(r && r.error ? r.error : "")}"><span class="n">${esc(TNAME[t] || t)}</span><span class="r">${res}</span></div>`;
  }).join("");
  const ports = l.ports && l.ports.length ? l.ports.map((p) => `<span class="chip mono accent">${esc(p)}</span>`).join(" ") : `<span class="muted">—</span>`;
  return `${head(`${esc(nm(l.kharej_id))} ⇄ ${esc(nm(l.iran_id))}`, `تانل ریورس BackPack · <span class="mono">tm-${esc(l.id)}</span>`, st)}
  <div class="box"><h4>وضعیت</h4><dl class="kv">
    <dt>پروتکل فعلی</dt><dd><span class="mono">${esc(l.transport || "—")}</span> ${l.pinned ? "📌 قفل" : "<span class='muted'>(انتخاب خودکار)</span>"}</dd>
    <dt>تأخیر</dt><dd class="mono">${ms(l.latency_ms)}</dd>
    <dt>پورت تانل (داخل)</dt><dd class="mono">${l.tunnel_port}</dd>
    <dt>پورت پروب</dt><dd class="mono">127.0.0.1:${l.probe_port}</dd>
    <dt>آخرین اتصال سالم</dt><dd>${ago(l.last_ok)}</dd>
    <dt>پورت‌های فورواردی</dt><dd>${ports}</dd>
    <dt>دامنه‌های روی این مسیر</dt><dd>${doms.map((d) => `<span class="chip">${esc(d.fqdn)}</span>`).join(" ") || "<span class='muted'>— (رزرو)</span>"}</dd>
    ${l.error ? `<dt>خطا</dt><dd style="color:var(--down)">${esc(l.error)}</dd>` : ""}
  </dl>${spark(l.history, 430, 46)}</div>
  <div class="box"><h4>تغییر پروتکل اتصال</h4>
    <div class="tgrid">${grid}</div>
    <label class="check"><input type="checkbox" id="pin-on-apply" ${l.pinned || !l.transport ? "checked" : ""}> قفل روی این پروتکل (مانیتور در قطعی، پروتکل را عوض نکند)</label>
    <div class="btns">
      <button class="btn primary" data-apply-transport ${sel === l.transport && st === "up" ? "disabled" : ""}>اعمال ${esc(TNAME[sel] || sel || "")}</button>
      <button class="btn" data-retest>🔬 تست دوباره همه پروتکل‌ها</button>
      ${l.pinned ? `<button class="btn ghost" data-unpin>🔓 برگشت به انتخاب خودکار</button>` : ""}
    </div>
    <p class="hint">با «تست دوباره»، همه پروتکل‌های لیست تنظیمات روی این جفت سرور تست می‌شوند و سریع‌ترین مستقر می‌شود.</p>
  </div>`;
}

function serverDrawer() {
  const s = srv(drawer.id);
  if (!s) return "";
  const links = S.links.filter((l) => l.iran_id === s.id || l.kharej_id === s.id);
  const other = (l) => nm(s.role === "iran" ? l.kharej_id : l.iran_id);
  const linksHtml = links.map((l) => `<div class="opt" data-link="${l.id}" style="cursor:pointer"><span class="dot ${lstatus(l)}"></span>
    <span class="grow">${esc(other(l))}</span><span class="chip mono">${esc(l.transport || "—")}</span><span class="mono small">${ms(l.latency_ms)}</span></div>`).join("");
  let failover = "";
  if (s.role === "kharej") {
    const taken = S.takeover[s.id];
    const targets = byRole("kharej").filter((k) => k.id !== s.id && !S.takeover[k.id]);
    failover = taken
      ? `<div class="box"><h4>جایگزینی خارج</h4><p class="muted" style="margin:0">پورت‌ها و ترافیک این سرور الان روی <b>${esc(nm(taken))}</b> است.</p>
          <div class="btns"><button class="btn" data-release="${s.id}">↩ بازگرداندن ترافیک به این سرور</button></div></div>`
      : `<div class="box"><h4>جایگزینی خارج (دستی)</h4><p class="hint" style="margin:0">اگر این سرور خراب شود، مانیتور خودکار ترافیکش را به یک خارج سالم منتقل می‌کند. برای انتقال دستی:</p>
          <div class="btns"><select id="takeover-target">${targets.map((k) => `<option value="${k.id}">${esc(k.name)}</option>`).join("")}</select>
          <button class="btn" data-takeover="${s.id}" ${targets.length ? "" : "disabled"}>⇆ انتقال ترافیک</button></div></div>`;
  }
  return `${head(`${s.role === "iran" ? "🏠" : "🌍"} ${esc(s.name)}`, `<span class="mono">${esc(s.ip)}</span> · سرور ${s.role === "iran" ? "داخل" : "خارج"}`, s.status)}
  <div class="box"><h4>جزئیات</h4><dl class="kv">
    <dt>SSH</dt><dd class="mono">${esc(s.ssh_user)}@${esc(s.ip)}:${s.ssh_port}</dd>
    <dt>تأخیر SSH</dt><dd class="mono">${ms(s.ssh_latency_ms)}</dd>
    <dt>آخرین پاسخ</dt><dd>${ago(s.last_seen)}</dd>
    <dt>BackPack</dt><dd class="mono">${esc(s.backpack_version || "—")}</dd>
    <dt>اولویت</dt><dd>${s.priority} ${s.enabled ? "" : "<span class='chip warn'>غیرفعال</span>"}</dd>
    ${s.role === "kharej" ? `<dt>پورت‌ها</dt><dd>${s.ports.map((p) => `<span class="chip mono accent">${esc(p)}</span>`).join(" ") || "—"}</dd>
    <dt>پروب</dt><dd class="mono">${esc(s.probe_target || `127.0.0.1:${s.ssh_port}`)}</dd>` : ""}
    ${s.error ? `<dt>خطا</dt><dd style="color:var(--down)">${esc(s.error)}</dd>` : ""}
  </dl>
  <div class="btns"><button class="btn" data-edit-server="${s.id}">✎ ویرایش</button><button class="btn" data-test-server="${s.id}">🔌 تست SSH</button>
  <button class="btn" data-install="${s.id}">⬇ نصب BackPack</button><button class="btn danger" data-del-server="${s.id}">حذف</button></div></div>
  ${failover}
  <div class="box"><h4>تانل‌ها (${links.length})</h4><div class="opt-list">${linksHtml || "<span class='muted'>—</span>"}</div>
  ${links.length ? `<div class="btns"><button class="btn" data-discover-links="${links.map((l) => l.id).join(",")}">⚡ تست و اتصال همه تانل‌های این سرور</button></div>` : ""}</div>`;
}

function domainDrawer() {
  const d = S.domains.find((x) => x.id === drawer.id);
  if (!d) return "";
  const p = provider(d.provider_id);
  const k = d.effective_kharej_id;
  const opts = byRole("iran").map((i) => {
    const l = linkFor(i.id, k);
    const st = l ? lstatus(l) : "pending";
    const cur = i.id === d.iran_id;
    return `<div class="opt"><span class="dot ${i.status === "online" ? st : "offline"}"></span><span class="grow">${esc(i.name)} <span class="mono muted small">${esc(i.ip)}</span></span>
      <span class="chip mono">${esc(l && l.transport ? l.transport : "—")} ${l && st === "up" ? ms(l.latency_ms) : ""}</span>
      ${cur ? `<span class="chip good">فعلی</span>` : `<button class="btn sm" data-switch="${i.id}">انتقال</button>`}</div>`;
  }).join("");
  return `${head(`🌐 <span class="mono">${esc(d.fqdn)}</span>`, `${p ? `<span class="prov ${p.kind}">${p.kind === "cloudflare" ? "Cloudflare" : "ArvanCloud"}</span> ${esc(p.name)}` : "بدون حساب DNS"}`, d.status)}
  <div class="box"><h4>مسیر ترافیک</h4>
    <div class="path"><span class="chip">👤 کاربر</span><span class="arrow">→</span><span class="chip mono">${esc(d.fqdn)}</span><span class="arrow">→</span>
    <span class="chip">🏠 ${esc(d.iran_id ? nm(d.iran_id) : "—")}</span><span class="arrow">⇄</span><span class="chip ${k !== d.kharej_id ? "purple" : ""}">🌍 ${esc(nm(k))}</span></div>
    <dl class="kv"><dt>آی‌پی فعلی رکورد</dt><dd class="mono">${esc(d.current_ip || "—")}</dd>
    <dt>سرور خارج اصلی</dt><dd>${esc(nm(d.kharej_id))}${k !== d.kharej_id ? ` <span class="chip purple">جایگزین: ${esc(nm(k))}</span>` : ""}</dd>
    <dt>TTL</dt><dd class="mono">${d.ttl}s</dd><dt>آخرین جابه‌جایی</dt><dd>${ago(d.last_switch)}</dd>
    <dt>جابه‌جایی خودکار</dt><dd>${d.auto_failover ? "فعال" : "غیرفعال"}</dd>
    ${d.error ? `<dt>خطا</dt><dd style="color:var(--down)">${esc(d.error)}</dd>` : ""}</dl>
    <div class="btns"><button class="btn" data-edit-domain="${d.id}">✎ ویرایش</button><button class="btn" data-sync="${d.id}">⟳ خواندن رکورد از DNS</button><button class="btn danger" data-del-domain="${d.id}">حذف</button></div></div>
  <div class="box"><h4>انتقال دستی به سرور داخل دیگر</h4><div class="opt-list">${opts || "<span class='muted'>سرور داخلی ثبت نشده</span>"}</div>
  <p class="hint">با انتقال، رکورد A دامنه در ${p ? (p.kind === "cloudflare" ? "کلادفلر" : "آروان") : "DNS"} به آی‌پی سرور انتخابی تغییر می‌کند.</p></div>`;
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

function serverForm(role, s) {
  const k = role === "kharej";
  const edit = !!s;
  s = s || { name: "", ip: "", ssh_port: 22, ssh_user: "root", priority: 100, enabled: true, ports: [], accept_udp: false, probe_target: "" };
  openModal(`<h2>${edit ? "ویرایش" : "افزودن"} سرور ${k ? "خارج 🌍" : "داخل 🏠"}</h2>
    <div class="grid2"><label>نام<input name="name" required value="${esc(s.name)}" placeholder="${k ? "Hetzner-DE" : "Tehran-1"}"></label>
    <label>آی‌پی<input name="ip" required class="mono" value="${esc(s.ip)}" placeholder="1.2.3.4"></label></div>
    <div class="grid2"><label>کاربر SSH<input name="ssh_user" value="${esc(s.ssh_user)}"></label><label>پورت SSH<input name="ssh_port" type="number" value="${s.ssh_port}"></label></div>
    <label>رمز SSH<input name="ssh_password" type="password" autocomplete="new-password" value="${edit && s.ssh_password ? "••••" : ""}" placeholder="${edit ? "خالی = بدون تغییر" : ""}"></label>
    <label>کلید خصوصی SSH (اختیاری)<textarea name="ssh_key" placeholder="-----BEGIN OPENSSH PRIVATE KEY-----">${edit && s.ssh_key ? "••••" : ""}</textarea></label>
    ${k ? `<label>پورت‌های فورواردی<textarea name="ports" placeholder="443&#10;8443=2096&#10;2053-2060">${esc(s.ports.join("\n"))}</textarea></label>
    <p class="hint">هر خط یک مپینگ با سینتکس BackPack: <span class="mono">443</span> یعنی پورت 443 داخل → 127.0.0.1:443 همین سرور خارج. <span class="mono">8443=2096</span> یعنی 8443 داخل → 2096 خارج. اگر چند خارج دارید پورت‌هایشان نباید تکراری باشد.</p>
    <div class="grid2"><label>هدف پروب سلامت<input name="probe_target" class="mono" value="${esc(s.probe_target)}" placeholder="127.0.0.1:${s.ssh_port}"></label>
    <label class="check" style="align-self:end"><input type="checkbox" name="accept_udp" ${s.accept_udp ? "checked" : ""}> فوروارد UDP هم انجام شود</label></div>` : ""}
    <div class="grid2"><label>اولویت (کمتر = ترجیح)<input name="priority" type="number" value="${s.priority}"></label>
    <label class="check" style="align-self:end"><input type="checkbox" name="enabled" ${s.enabled ? "checked" : ""}> فعال</label></div>
    ${actions(edit ? "ذخیره" : "افزودن")}`, async (f) => {
    const body = {
      role, name: f.get("name").trim(), ip: f.get("ip").trim(), ssh_user: f.get("ssh_user").trim() || "root",
      ssh_port: +f.get("ssh_port") || 22, ssh_password: f.get("ssh_password"), ssh_key: f.get("ssh_key"),
      priority: +f.get("priority") || 100, enabled: !!f.get("enabled"),
      ports: k ? f.get("ports").split(/[\n,]/).map((x) => x.trim()).filter(Boolean) : [],
      accept_udp: !!f.get("accept_udp"), probe_target: k ? f.get("probe_target").trim() : "",
    };
    if (edit) await api("PUT", `/api/servers/${s.id}`, body); else await api("POST", "/api/servers", body);
    toast(edit ? "ذخیره شد" : "سرور اضافه شد", "success");
  });
}

function providerForm(p) {
  const edit = !!p;
  p = p || { name: "", kind: "cloudflare", zone: "", proxied: false };
  openModal(`<h2>${edit ? "ویرایش" : "افزودن"} حساب DNS</h2>
    <div class="grid2"><label>نام<input name="name" required value="${esc(p.name)}" placeholder="Cloudflare اصلی"></label>
    <label>سرویس‌دهنده<select name="kind"><option value="cloudflare" ${p.kind === "cloudflare" ? "selected" : ""}>Cloudflare</option><option value="arvan" ${p.kind === "arvan" ? "selected" : ""}>ArvanCloud (آروان)</option></select></label></div>
    <label>Zone (دامنه اصلی)<input name="zone" required class="mono" value="${esc(p.zone)}" placeholder="example.com"></label>
    <label>API Token / API Key<input name="api_token" type="password" class="mono" autocomplete="off" value="${edit ? "••••" : ""}" ${edit ? "" : "required"}></label>
    <p class="hint">کلادفلر: API Token با دسترسی Zone → DNS → Edit. آروان: کلید API از پنل (Machine User) — با یا بدون پیشوند «Apikey».</p>
    <label class="check"><input type="checkbox" name="proxied" ${p.proxied ? "checked" : ""}> رکوردها پروکسی شوند (ابر نارنجی / ابر آروان) — برای تانل معمولا خاموش</label>
    ${actions(edit ? "ذخیره" : "افزودن")}`, async (f) => {
    const body = { name: f.get("name"), kind: f.get("kind"), zone: f.get("zone"), api_token: f.get("api_token"), proxied: !!f.get("proxied") };
    if (edit) await api("PUT", `/api/providers/${p.id}`, body); else await api("POST", "/api/providers", body);
    toast("ذخیره شد", "success");
  });
}

function domainForm(d) {
  if (!S.providers.length) { toast("اول یک حساب DNS اضافه کنید"); return providerForm(); }
  if (!byRole("kharej").length) { toast("اول یک سرور خارج اضافه کنید"); return serverForm("kharej"); }
  const edit = !!d;
  d = d || { fqdn: "", provider_id: S.providers[0].id, kharej_id: byRole("kharej")[0].id, iran_id: "", ttl: 60, auto_failover: true };
  openModal(`<h2>${edit ? "ویرایش" : "افزودن"} دامنه 🌐</h2>
    <label>دامنه (FQDN)<input name="fqdn" required class="mono" value="${esc(d.fqdn)}" placeholder="sub.example.com"></label>
    <div class="grid2"><label>حساب DNS<select name="provider_id">${S.providers.map((p) => `<option value="${p.id}" ${p.id === d.provider_id ? "selected" : ""}>${esc(p.name)} (${esc(p.zone)})</option>`).join("")}</select></label>
    <label>سرویس روی کدام خارج است؟<select name="kharej_id">${byRole("kharej").map((k) => `<option value="${k.id}" ${k.id === d.kharej_id ? "selected" : ""}>${esc(k.name)}</option>`).join("")}</select></label></div>
    ${edit ? "" : `<label>سرور داخل اولیه<select name="iran_id"><option value="">خودکار (از رکورد فعلی یا بهترین مسیر)</option>${byRole("iran").map((i) => `<option value="${i.id}">${esc(i.name)} — ${esc(i.ip)}</option>`).join("")}</select></label>`}
    <div class="grid2"><label>TTL (ثانیه)<input name="ttl" type="number" value="${d.ttl}"></label>
    <label class="check" style="align-self:end"><input type="checkbox" name="auto_failover" ${d.auto_failover ? "checked" : ""}> جابه‌جایی خودکار در قطعی</label></div>
    <p class="hint">آی‌پی پشت دامنه همیشه یکی از سرورهای داخل است. اگر مسیر آن سرور به خارجِ این دامنه قطع شود، پنل اول پروتکل‌های دیگر را امتحان می‌کند و اگر نشد رکورد را به داخل دیگری منتقل می‌کند.</p>
    ${actions(edit ? "ذخیره" : "افزودن")}`, async (f) => {
    const body = { fqdn: f.get("fqdn"), provider_id: f.get("provider_id"), kharej_id: f.get("kharej_id"), iran_id: f.get("iran_id") || "", ttl: +f.get("ttl") || 60, auto_failover: !!f.get("auto_failover") };
    if (edit) await api("PUT", `/api/domains/${d.id}`, body);
    else {
      const r = await api("POST", "/api/domains", body);
      if (body.iran_id) await api("POST", `/api/domains/${r.domain.id}/switch`, { iran_id: body.iran_id });
    }
    toast("ذخیره شد", "success");
  });
}

function settingsForm() {
  const s = S.settings, tg = s.telegram;
  const order = [...s.candidate_transports, ...S.transports.filter((t) => !s.candidate_transports.includes(t))];
  openModal(`<h2>تنظیمات ⚙</h2>
    <fieldset><legend>مانیتورینگ و جابه‌جایی</legend>
      <div class="grid2"><label>فاصله بررسی (ثانیه)<input name="check_interval" type="number" min="10" value="${s.check_interval}"></label>
      <label>تعداد خطای پشت‌سرهم تا اقدام<input name="fail_threshold" type="number" min="1" value="${s.fail_threshold}"></label></div>
      <div class="grid2"><label>مهلت بالا آمدن هر پروتکل در تست (ثانیه)<input name="test_timeout" type="number" min="5" value="${s.test_timeout}"></label>
      <label class="check" style="align-self:end"><input type="checkbox" name="auto_failback" ${s.auto_failback ? "checked" : ""}> برگشت خودکار به خارج اصلی بعد از رفع مشکل</label></div>
      <label>پروتکل‌هایی که تست می‌شوند</label>
      <div class="tchecks">${order.map((t) => `<label><input type="checkbox" name="tr" value="${t}" ${s.candidate_transports.includes(t) ? "checked" : ""}>${t}</label>`).join("")}</div>
    </fieldset>
    <fieldset><legend>BackPack</legend>
      <div class="grid2"><label>شروع پورت تانل روی سرور داخل<input name="tunnel_port_base" type="number" value="${s.tunnel_port_base}"></label>
      <label>شروع پورت پروب (لوکال)<input name="probe_port_base" type="number" value="${s.probe_port_base}"></label></div>
      <div class="grid2"><label>نسخه ریلیز BackPack<input name="backpack_release" class="mono" value="${esc(s.backpack_release)}" placeholder="latest"></label>
      <label class="check" style="align-self:end"><input type="checkbox" name="install_backpack" ${s.install_backpack ? "checked" : ""}> نصب خودکار روی سرورها</label></div>
    </fieldset>
    <fieldset><legend>ربات تلگرام</legend>
      <label class="check"><input type="checkbox" name="tg_enabled" ${tg.enabled ? "checked" : ""}> ارسال همه رویدادها به تلگرام</label>
      <label>توکن ربات<input name="tg_token" type="password" class="mono" autocomplete="off" value="${esc(tg.bot_token)}" placeholder="123456:ABC..."></label>
      <label>Chat ID ها (با کاما جدا کنید)<input name="tg_chats" class="mono" value="${esc((tg.chat_ids || []).join(", "))}" placeholder="123456789, -100987654321"></label>
      <p class="hint">Chat ID را نمی‌دانید؟ به ربات <span class="mono">/start</span> بدهید تا شناسه را برایتان بفرستد.</p>
      <div class="grid2"><label>آدرس API (برای ریورس‌پروکسی)<input name="tg_base" class="mono" value="${esc(tg.api_base)}"></label>
      <label>پروکسی (اختیاری)<input name="tg_proxy" class="mono" value="${esc(tg.proxy)}" placeholder="socks5://127.0.0.1:1080"></label></div>
      <div class="btns"><button type="button" class="btn" id="tg-test">📨 ارسال پیام تست</button></div>
    </fieldset>
    <fieldset><legend>حساب‌های DNS</legend>
      <div class="opt-list">${S.providers.map((p) => `<div class="opt"><span class="prov ${p.kind}">${p.kind === "cloudflare" ? "CF" : "AR"}</span><span class="grow">${esc(p.name)} <span class="mono muted small">${esc(p.zone)}</span></span>
        <button type="button" class="btn sm" data-verify-provider="${p.id}">تست</button><button type="button" class="btn sm" data-edit-provider="${p.id}">✎</button><button type="button" class="btn sm danger" data-del-provider="${p.id}">✕</button></div>`).join("") || "<span class='muted'>—</span>"}</div>
      <div class="btns"><button type="button" class="btn" data-add="provider">＋ حساب DNS</button></div>
    </fieldset>
    ${actions("ذخیره")}`, async (f) => {
    const body = {
      check_interval: +f.get("check_interval"), fail_threshold: +f.get("fail_threshold"), test_timeout: +f.get("test_timeout"),
      auto_failback: !!f.get("auto_failback"), candidate_transports: f.getAll("tr"),
      tunnel_port_base: +f.get("tunnel_port_base"), probe_port_base: +f.get("probe_port_base"),
      backpack_release: f.get("backpack_release").trim() || "latest", install_backpack: !!f.get("install_backpack"),
      telegram: { enabled: !!f.get("tg_enabled"), bot_token: f.get("tg_token"), chat_ids: f.get("tg_chats").split(",").map((x) => x.trim()).filter(Boolean), api_base: f.get("tg_base").trim() || "https://api.telegram.org", proxy: f.get("tg_proxy").trim() },
    };
    await api("PUT", "/api/settings", body);
    toast("تنظیمات ذخیره شد", "success");
  });
  $("#tg-test").onclick = async () => {
    $("#modal-form").requestSubmit();
    setTimeout(() => act(() => api("POST", "/api/telegram/test"), "پیام تست ارسال شد"), 600);
  };
}

/* ---------------------------------------------------------------- events */
function addFlow(kind) {
  if (kind === "kharej" || kind === "iran") serverForm(kind);
  else if (kind === "provider") providerForm();
  else if (kind === "domain") domainForm();
}

function confirmDo(msg) { return window.confirm(msg); }

document.addEventListener("click", async (e) => {
  const t = e.target.closest("[data-add],[data-close],[data-close-modal],[data-link],[data-pick],[data-apply-transport],[data-retest],[data-unpin],[data-edit-server],[data-test-server],[data-install],[data-del-server],[data-takeover],[data-release],[data-discover-links],[data-switch],[data-sync],[data-edit-domain],[data-del-domain],[data-verify-provider],[data-edit-provider],[data-del-provider],[data-discover],.node,.wlabel,.wire-hit");
  if (!t) {
    if (!e.target.closest(".menu")) $("#add-pop").classList.remove("open");
    return;
  }
  const d = t.dataset;
  $("#add-pop").classList.remove("open");
  if (d.add) { closeModal(); return addFlow(d.add); }
  if ("close" in d) return closeDrawer();
  if ("closeModal" in d) return closeModal();
  if (d.discover) return startDiscover();
  if (d.pick) { selTransport = d.pick; return renderDrawer(); }
  if ("applyTransport" in d) {
    const l = S.links.find((x) => x.id === drawer.id);
    const tr = selTransport || l.transport || S.settings.candidate_transports[0];
    await act(() => api("POST", `/api/links/${l.id}/transport`, { transport: tr, pin: $("#pin-on-apply").checked }), `تغییر به ${tr} شروع شد`);
    selTransport = null; return;
  }
  if ("retest" in d) return act(() => api("POST", `/api/links/${drawer.id}/retest`), "تست همه پروتکل‌ها شروع شد");
  if ("unpin" in d) return act(() => api("POST", `/api/links/${drawer.id}/pin`, { pinned: false }), "انتخاب خودکار فعال شد");
  if (d.editServer) { const s = srv(d.editServer); return serverForm(s.role, s); }
  if (d.testServer) {
    const r = await act(() => api("POST", `/api/servers/${d.testServer}/test`));
    return toast(r.status === "online" ? `SSH سالم — ${ms(r.latency_ms)}` : `SSH ناموفق: ${r.error}`, r.status === "online" ? "success" : "error");
  }
  if (d.install) { toast("در حال نصب BackPack…"); const r = await act(() => api("POST", `/api/servers/${d.install}/install`)); return toast(`BackPack ${r.version} آماده است`, "success"); }
  if (d.delServer) {
    if (!confirmDo("سرور و همه تانل‌هایش حذف شود؟ سرویس‌های BackPack مربوطه هم از روی سرورها پاک می‌شوند.")) return;
    await act(() => api("DELETE", `/api/servers/${d.delServer}`), "حذف شد"); return closeDrawer();
  }
  if (d.takeover) {
    const target = $("#takeover-target").value;
    if (!confirmDo(`ترافیک ${nm(d.takeover)} به ${nm(target)} منتقل شود؟`)) return;
    return act(() => api("POST", `/api/kharej/${d.takeover}/takeover`, { target_id: target }), "انتقال انجام شد");
  }
  if (d.release) return act(() => api("POST", `/api/kharej/${d.release}/release`), "ترافیک برگشت");
  if (d.discoverLinks) return act(() => api("POST", "/api/discover", { link_ids: d.discoverLinks.split(",") }), "تست و اتصال شروع شد");
  if (d.switch) {
    const dom = S.domains.find((x) => x.id === drawer.id);
    if (!confirmDo(`رکورد ${dom.fqdn} به ${nm(d.switch)} تغییر کند؟`)) return;
    return act(() => api("POST", `/api/domains/${dom.id}/switch`, { iran_id: d.switch }), "رکورد DNS تغییر کرد");
  }
  if (d.sync) return act(() => api("POST", `/api/domains/${d.sync}/sync`), "رکورد خوانده شد");
  if (d.editDomain) return domainForm(S.domains.find((x) => x.id === d.editDomain));
  if (d.delDomain) { if (!confirmDo("دامنه از پنل حذف شود؟ (رکورد DNS دست نمی‌خورد)")) return; await act(() => api("DELETE", `/api/domains/${d.delDomain}`), "حذف شد"); return closeDrawer(); }
  if (d.verifyProvider) { const r = await act(() => api("POST", `/api/providers/${d.verifyProvider}/verify`)); return toast(`اتصال سالم: ${r.detail}`, "success"); }
  if (d.editProvider) return providerForm(S.providers.find((p) => p.id === d.editProvider));
  if (d.delProvider) { if (!confirmDo("حساب DNS حذف شود؟")) return; await act(() => api("DELETE", `/api/providers/${d.delProvider}`), "حذف شد"); return settingsForm(); }
  if (d.link) return openDrawer("link", d.link);
  if (t.classList.contains("node")) return openDrawer(d.type, d.id);
});

/* hover: focus + tooltip */
const tip = $("#tip");
document.addEventListener("mouseover", (e) => {
  const n = e.target.closest("#topo .node");
  const w = e.target.closest(".wire-hit,.wlabel");
  if (n) { focus = relatedTo(n.dataset.type, n.dataset.id); applyFocus(); }
  else if (w) {
    focus = relatedTo("link", w.dataset.link); applyFocus();
    const l = S.links.find((x) => x.id === w.dataset.link);
    if (l) { tip.innerHTML = linkTip(l); tip.classList.add("show"); }
  }
});
document.addEventListener("mousemove", (e) => {
  if (!tip.classList.contains("show")) return;
  const x = Math.min(e.clientX + 14, window.innerWidth - tip.offsetWidth - 8);
  tip.style.left = `${x}px`; tip.style.top = `${e.clientY + 14}px`;
});
document.addEventListener("mouseout", (e) => {
  const from = e.target.closest("#topo .node,.wire-hit,.wlabel");
  const to = e.relatedTarget && e.relatedTarget.closest && e.relatedTarget.closest("#topo .node,.wire-hit,.wlabel");
  if (from && from !== to) { focus = null; applyFocus(); tip.classList.remove("show"); }
});

async function startDiscover() {
  const kh = byRole("kharej");
  const missing = kh.filter((k) => !k.ports.length);
  if (missing.length && !confirmDo(`برای ${missing.map((k) => k.name).join("، ")} پورت فورواردی تعریف نشده. تانل فقط با پورت پروب ساخته شود؟`)) return;
  await act(() => api("POST", "/api/discover", {}), "تست همه مسیرها شروع شد — نتیجه‌ها زنده نمایش داده می‌شوند");
}

$("#btn-discover").onclick = startDiscover;
$("#btn-check").onclick = () => act(() => api("POST", "/api/check"), "بررسی فوری شروع شد");
$("#btn-add").onclick = (e) => { e.stopPropagation(); $("#add-pop").classList.toggle("open"); };
$("#btn-settings").onclick = settingsForm;
$("#btn-logout").onclick = async () => { await api("POST", "/api/logout"); location.reload(); };
$("#btn-theme").onclick = () => {
  const cur = document.documentElement.dataset.theme === "light" ? "dark" : "light";
  document.documentElement.dataset.theme = cur;
  localStorage.setItem("tm-theme", cur);
  requestAnimationFrame(drawWires);
};
$("#scrim").onclick = closeDrawer;
$("#modal").addEventListener("mousedown", (e) => { if (e.target.id === "modal") closeModal(); });
document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeModal(); closeDrawer(); } });
$("#show-standby").onchange = drawWires;
$$("#ev-filter button").forEach((b) => (b.onclick = () => {
  evFilter = b.dataset.f;
  $$("#ev-filter button").forEach((x) => x.classList.toggle("on", x === b));
  renderEvents();
}));
window.addEventListener("resize", () => requestAnimationFrame(drawWires));
if (window.ResizeObserver) new ResizeObserver(() => requestAnimationFrame(drawWires)).observe($("#topo"));

boot();
