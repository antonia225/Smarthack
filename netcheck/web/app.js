"use strict";
/* NetCheck web UI. No libraries, no CDN, textContent only (never innerHTML).
   Findings, severities and scores come only from the API; this file only presents them.
   Structure: helpers → components (menu, side panel, NetworkView) → pages (home, history, import) → boot. */

/* ================= configuration ================= */
/* Home shows the newest scan whose source equals this value. Use null to accept any source. */
const HOME_SOURCE = "live";
const ERROR_MS = 2000;
const POLL_MS = 5000;
const MAX_IMPORT_BYTES = 10 * 1024 * 1024;
const SEVERITIES = ["high", "medium", "low", "info"];
const SEV_ICON = { high: "i-sev-high", medium: "i-sev-medium", low: "i-sev-low", info: "i-sev-info", none: "i-check" };
const TYPE_ICON = { router: "i-router", camera: "i-camera", printer: "i-printer", tv: "i-tv", laptop: "i-laptop", phone: "i-phone", nas: "i-nas", iot: "i-iot", unknown: "i-unknown" };
const SVG_NS = "http://www.w3.org/2000/svg";

/* ================= helpers ================= */
let lang = "ro";
const $ = (id) => document.getElementById(id);
const sevRank = (s) => ({ high: 3, medium: 2, low: 1, info: 0 }[s] ?? -1);

function text(key, vars) {
  const dict = TEXTS[lang] || TEXTS.ro;
  let value = dict[key];
  if (value === undefined) value = TEXTS.ro[key];
  if (value === undefined) return key;
  if (typeof value !== "string" || !vars) return value;
  return value.replace(/\{(\w+)\}/g, (_, name) => (vars[name] === undefined ? "" : String(vars[name])));
}
function el(tag, className, content) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (content !== undefined) node.textContent = content;
  return node;
}
function svgEl(tag, className) {
  const node = document.createElementNS(SVG_NS, tag);
  if (className) node.setAttribute("class", className);
  return node;
}
function icon(id, className) {
  const svg = svgEl("svg", className);
  svg.setAttribute("aria-hidden", "true");
  svg.setAttribute("focusable", "false");
  const use = svgEl("use");
  use.setAttribute("href", "#" + id);
  svg.append(use);
  return svg;
}
function button(label, className, iconId) {
  const b = el("button", "btn" + (className ? " " + className : ""));
  b.type = "button";
  if (iconId) b.append(icon(iconId));
  b.append(el("span", "", label));
  return b;
}
function helpHint(key) {
  const hint = el("span", "help-hint", "?");
  hint.tabIndex = 0;
  hint.setAttribute("role", "img");
  hint.dataset.helpKey = key;
  hint.setAttribute("aria-label", text(key));
  hint.dataset.tooltip = text(key);
  return hint;
}
function setButtonLabel(b, label) { const span = b.querySelector("span"); if (span) span.textContent = label; }
const localized = (value) => (value && typeof value === "object" && !Array.isArray(value) ? value[lang] : value);
const findingTitle = (f) => localized(f.title) || f.code;
const whereOf = (f) => f.ip + (f.port ? ":" + f.port : "");
const sevLabel = (s) => text(s);
const typeLabel = (device) => text((device && device.device_type) || "unknown");
function sortedFindings(scan) {
  return ((scan && scan.findings) || []).slice().sort((a, b) =>
    sevRank(b.severity) - sevRank(a.severity) || ipNumber(a.ip) - ipNumber(b.ip) || (a.port || 0) - (b.port || 0) || String(a.code).localeCompare(b.code));
}
function ipNumber(ip) { return String(ip).split(".").reduce((n, p) => n * 256 + (Number(p) || 0), 0); }
function fmtDate(iso) {
  const d = new Date(iso);
  if (!iso || Number.isNaN(d.getTime())) return text("dateUnknown");
  return d.toLocaleString(lang === "ro" ? "ro-RO" : "en-GB", { dateStyle: "medium", timeStyle: "short" });
}
function maskMac(value) { // defensive: the API already masks; never show more than the vendor prefix
  if (!value) return "—";
  if (value.includes("*")) return value;
  return value.split(":").slice(0, 3).join(":") + ":**:**:**";
}
function announce(message) {
  const box = $("announcer");
  if (!box) return;
  box.textContent = "";
  setTimeout(() => { box.textContent = message; }, 50);
}
function highestSeverity(scan, ip) {
  let best = null;
  for (const f of (scan && scan.findings) || []) if (f.ip === ip && (best === null || sevRank(f.severity) > sevRank(best))) best = f.severity;
  return best || "none";
}
function scoreVerdict(score) { return score >= 70 ? "good" : score >= 50 ? "medium" : "bad"; }

/* Network access: never throws on HTTP errors, only when the server is unreachable. */
async function api(path, options) {
  let response;
  try { response = await fetch(path, options); }
  catch (error) { throw Object.assign(new Error("network"), { kind: "network" }); }
  let data = null;
  try { data = await response.json(); } catch (error) { /* not JSON */ }
  return { ok: response.ok, status: response.status, data };
}
const JSON_HEADERS = { "Content-Type": "application/json" };

/* Keyed diff: update only what changed, keep DOM nodes (and focus) otherwise. */
function reconcile(container, items, cache) {
  const seen = new Set();
  let ref = container.firstChild;
  for (const item of items) {
    let node = cache.get(item.key);
    if (!node) { node = item.create(); cache.set(item.key, node); }
    if (node.__sig !== item.sig) { item.update(node); node.__sig = item.sig; }
    seen.add(item.key);
    if (node === ref) ref = ref.nextSibling; else container.insertBefore(node, ref);
  }
  for (const [key, node] of cache) if (!seen.has(key)) { node.remove(); cache.delete(key); }
}

/* ================= dropdown menu (accessible listbox) ================= */
let menuCounter = 0;
function createMenu(labelKey, onChange) {
  const id = "menu" + (++menuCounter);
  const root = el("div", "field");
  const label = el("span", "", text(labelKey)); label.id = id + "-l";
  const trigger = el("button", "menu-btn"); trigger.type = "button";
  trigger.setAttribute("aria-haspopup", "listbox"); trigger.setAttribute("aria-expanded", "false");
  const current = el("span"); current.id = id + "-v";
  trigger.setAttribute("aria-labelledby", label.id + " " + current.id);
  trigger.append(current, icon("i-chevron-down"));
  const list = el("ul", "menu-list"); list.id = id + "-list"; list.setAttribute("role", "listbox"); list.tabIndex = -1; list.hidden = true;
  list.setAttribute("aria-labelledby", label.id);
  root.append(label, trigger, list);
  let items = [], value = null, active = -1;
  const optionEl = (i) => list.children[i];
  function render() {
    list.replaceChildren();
    items.forEach((item, i) => {
      const li = el("li", "menu-opt", item.label); li.id = id + "-o" + i; li.setAttribute("role", "option");
      li.setAttribute("aria-selected", String(item.value === value));
      li.addEventListener("pointerdown", (event) => { event.preventDefault(); choose(i); });
      list.append(li);
    });
    const chosen = items.find((i) => i.value === value);
    current.textContent = chosen ? chosen.label : "—";
  }
  function setActive(i) {
    if (active >= 0 && optionEl(active)) optionEl(active).classList.remove("active");
    active = Math.max(0, Math.min(items.length - 1, i));
    const option = optionEl(active);
    if (option) { option.classList.add("active"); list.setAttribute("aria-activedescendant", option.id); option.scrollIntoView({ block: "nearest" }); }
  }
  function open() {
    if (!items.length) return;
    list.hidden = false; trigger.setAttribute("aria-expanded", "true");
    setActive(Math.max(0, items.findIndex((i) => i.value === value)));
    list.focus();
  }
  function close(refocus) {
    if (list.hidden) return;
    list.hidden = true; trigger.setAttribute("aria-expanded", "false");
    if (refocus) trigger.focus();
  }
  function choose(i) {
    const item = items[i]; close(true);
    if (item && item.value !== value) { value = item.value; render(); onChange(value); }
  }
  trigger.addEventListener("click", () => (list.hidden ? open() : close(true)));
  trigger.addEventListener("keydown", (event) => {
    if (["ArrowDown", "ArrowUp"].includes(event.key)) { event.preventDefault(); open(); }
  });
  list.addEventListener("keydown", (event) => {
    const keys = { ArrowDown: () => setActive(active + 1), ArrowUp: () => setActive(active - 1), Home: () => setActive(0), End: () => setActive(items.length - 1) };
    if (keys[event.key]) { event.preventDefault(); keys[event.key](); }
    else if (event.key === "Enter" || event.key === " ") { event.preventDefault(); choose(active); }
    else if (event.key === "Escape") { event.preventDefault(); event.stopPropagation(); close(true); }
    else if (event.key === "Tab") close(false);
  });
  list.addEventListener("blur", () => close(false));
  return {
    root,
    get value() { return value; },
    setItems(next, selected) { items = next; value = selected !== undefined ? selected : (items.some((i) => i.value === value) ? value : (items[0] ? items[0].value : null)); render(); },
    setLabel() { label.textContent = text(labelKey); },
  };
}

/* ================= side panel: score ring + severity indicators ================= */
function createSidePanel({ showSeverity = true } = {}) {
  const root = el("div", "side");
  const scoreCard = el("section", "card score-card");
  const scoreTitle = el("h2", "card-title"); const scoreHelp = helpHint("scoreHint");
  scoreTitle.append(text("scoreTitle"), scoreHelp); scoreCard.append(scoreTitle);
  const ring = el("div", "ring"); ring.setAttribute("role", "img");
  const svg = svgEl("svg"); svg.setAttribute("viewBox", "0 0 120 120"); svg.setAttribute("aria-hidden", "true");
  const track = svgEl("circle", "track"); const arc = svgEl("circle", "arc");
  for (const c of [track, arc]) { c.setAttribute("cx", "60"); c.setAttribute("cy", "60"); c.setAttribute("r", "52"); }
  arc.setAttribute("pathLength", "100"); arc.setAttribute("stroke-dasharray", "0 100");
  svg.append(track, arc);
  const center = el("div", "center"); const num = el("span", "num"); const of = el("span", "of");
  center.append(num, of); ring.append(svg, center);
  const verdict = el("p", "verdict"); const verdictIcon = icon("i-check"); const verdictText = el("span"); verdict.append(verdictIcon, verdictText);
  const note = el("p", "score-note");
  const info = el("div", "score-info"); info.append(verdict, note);
  scoreCard.append(ring, info);
  const sevCard = el("section", "card sev-card"); sevCard.append(el("h2"));
  const rows = el("ul", "sev-rows"); sevCard.append(rows);
  const rowParts = {};
  for (const sev of SEVERITIES) {
    const li = el("li", "sev-row sev-" + sev);
    const ic = el("span", "ic"); ic.append(icon(SEV_ICON[sev]));
    const lab = el("span", "lab"); const count = el("span", "num"); const bar = el("span", "bar"); const fill = el("i"); bar.append(fill); bar.setAttribute("aria-hidden", "true");
    li.append(ic, lab, count, bar); rows.append(li); rowParts[sev] = { li, lab, count, fill };
  }
  root.append(scoreCard); if (showSeverity) root.append(sevCard);
  let lastSig = "";
  function update(scan) {
    const score = scan && scan.status === "ok" ? Number(scan.network_score) : 0;
    const counts = Object.fromEntries(SEVERITIES.map((s) => [s, 0]));
    for (const f of (scan && scan.findings) || []) if (counts[f.severity] !== undefined) counts[f.severity] += 1;
    const sig = [lang, score, SEVERITIES.map((s) => counts[s]).join(",")].join("|");
    if (sig === lastSig) return;
    lastSig = sig;
    const kind = scoreVerdict(score);
    const label = text(kind === "good" ? "scoreGood" : kind === "medium" ? "scoreMedium" : "scoreBad");
    scoreTitle.firstChild.textContent = text("scoreTitle");
    scoreHelp.dataset.tooltip = text("scoreHint"); scoreHelp.setAttribute("aria-label", text("scoreHint"));
    num.textContent = String(score); of.textContent = text("scoreOf");
    arc.setAttribute("stroke-dasharray", score + " 100");
    ring.setAttribute("aria-label", text("scoreAria", { score, label }));
    scoreCard.className = "card score-card";
    verdict.className = "verdict " + kind;
    ring.style.setProperty("--arc", "var(--" + (kind === "good" ? "good" : kind === "medium" ? "medium" : "high") + ")");
    verdictIcon.firstChild.setAttribute("href", "#" + (kind === "good" ? "i-check" : kind === "medium" ? "i-alert" : "i-sev-high"));
    verdictText.textContent = label; note.textContent = text("scoreNote");
    sevCard.firstChild.textContent = text("severityTitle");
    const total = Math.max(1, SEVERITIES.reduce((n, s) => n + counts[s], 0));
    for (const sev of SEVERITIES) {
      const part = rowParts[sev];
      part.lab.textContent = sevLabel(sev); part.count.textContent = String(counts[sev]);
      part.fill.style.width = Math.round((counts[sev] / total) * 100) + "%";
      part.li.setAttribute("aria-label", text("countAria", { n: counts[sev], label: sevLabel(sev) }));
    }
  }
  return { root, update };
}

/* ================= NetworkView: score, indicators, graph, vulnerabilities, inspector ================= */
function createNetworkView({ allowAsk = true, variant = "classic" } = {}) {
  const isImport = variant === "import";
  const state = { scan: null, scanId: null, selectedIp: null, selectedFinding: null, panel: "closed", size: { w: 0, h: 0 }, chat: { key: "", messages: [], pending: false } };
  const root = el("div", "nv");
  /* graph */
  const graf = el("section", "card nv-graf"); graf.setAttribute("aria-labelledby", "g-title-" + (++menuCounter));
  const grafHead = el("div", "nv-graf-head"); const grafTitle = el("h2"); grafTitle.id = graf.getAttribute("aria-labelledby");
  grafHead.append(grafTitle);
  const graph = el("div", "graph");
  const viewPicker = el("div", "view-picker");
  viewPicker.setAttribute("role", "group");
  const mapButton = button("", "view-opt", "i-network");
  const listButton = button("", "view-opt", "i-file");
  viewPicker.append(mapButton, listButton);
  grafHead.append(viewPicker);
  const deviceList = el("ul", "device-list"); deviceList.hidden = true;
  let listMode = false;
  function chooseView(next) {
    listMode = next;
    graph.hidden = listMode; deviceList.hidden = !listMode;
    mapTools.hidden = listMode;
    mapButton.setAttribute("aria-pressed", String(!listMode));
    listButton.setAttribute("aria-pressed", String(listMode));
  }
  mapButton.addEventListener("click", () => chooseView(false));
  listButton.addEventListener("click", () => chooseView(true));
  const svg = svgEl("svg", "map"); svg.setAttribute("role", "group");
  const edgesG = svgEl("g"); const nodesG = svgEl("g"); svg.append(edgesG, nodesG);
  const camera = { zoom: 1, x: 0, y: 0 };
  function paintCamera() {
    const { w, h } = state.size;
    svg.setAttribute("viewBox", [camera.x, camera.y, w / camera.zoom, h / camera.zoom].join(" "));
    resetZoom.textContent = Math.round(camera.zoom * 100) + "%";
  }
  function zoomMap(factor) {
    const previous = camera.zoom;
    camera.zoom = Math.max(.5, Math.min(3, camera.zoom * factor));
    camera.x += state.size.w / previous / 2 - state.size.w / camera.zoom / 2;
    camera.y += state.size.h / previous / 2 - state.size.h / camera.zoom / 2;
    paintCamera();
  }
  function resetMap() { camera.zoom = 1; camera.x = camera.y = 0; paintCamera(); }
  const mapTools = el("div", "map-tools");
  const zoomOut = button("−", "map-control"); const zoomIn = button("+", "map-control");
  const resetZoom = el("button", "map-control", "100%"); resetZoom.type = "button";
  zoomOut.addEventListener("click", () => zoomMap(1 / 1.2));
  zoomIn.addEventListener("click", () => zoomMap(1.2)); resetZoom.addEventListener("click", resetMap);
  mapTools.append(zoomOut, resetZoom, zoomIn);
  chooseView(false);
  graph.tabIndex = 0;
  graph.addEventListener("keydown", (event) => {
    if (event.target !== graph) return;
    if (event.key === "+" || event.key === "=") zoomMap(1.2);
    else if (event.key === "-") zoomMap(1 / 1.2);
    else if (event.key === "0") resetMap();
    else if (["ArrowLeft", "ArrowRight", "ArrowUp", "ArrowDown"].includes(event.key)) {
      camera.x += ({ArrowLeft:-30, ArrowRight:30}[event.key] || 0) / camera.zoom;
      camera.y += ({ArrowUp:-30, ArrowDown:30}[event.key] || 0) / camera.zoom;
      paintCamera();
    } else return;
    event.preventDefault();
  });
  graph.addEventListener("wheel", (event) => {
    if (!event.ctrlKey && !event.metaKey) return;
    event.preventDefault(); zoomMap(event.deltaY < 0 ? 1.1 : 1 / 1.1);
  }, { passive: false });
  let drag = null;
  svg.addEventListener("pointerdown", (event) => {
    if (event.button !== 0 || event.target.closest(".node")) return;
    drag = { id: event.pointerId, x: event.clientX, y: event.clientY, startX: camera.x, startY: camera.y };
    svg.setPointerCapture(event.pointerId); graph.classList.add("dragging");
  });
  svg.addEventListener("pointermove", (event) => {
    if (!drag || drag.id !== event.pointerId) return;
    camera.x = drag.startX - (event.clientX - drag.x) / camera.zoom;
    camera.y = drag.startY - (event.clientY - drag.y) / camera.zoom; paintCamera();
  });
  function stopDrag() { drag = null; graph.classList.remove("dragging"); }
  svg.addEventListener("pointerup", stopDrag); svg.addEventListener("pointercancel", stopDrag);
  svg.addEventListener("lostpointercapture", stopDrag);
  const none = el("p", "none muted"); none.hidden = true;
  const srList = el("ul", "sr-only");
  graph.append(svg, none, srList);
  const grafToolbar = el("div", "graph-toolbar");
  const graphCount = el("p", "muted"); grafToolbar.append(graphCount, mapTools);
  graf.append(grafHead, grafToolbar, graph, deviceList);
  /* lateral: side panel + inspector overlay in the same grid cell */
  const lateral = el("div", "nv-lateral");
  const side = createSidePanel({ showSeverity: !isImport });
  const inspector = el("aside", "inspector"); inspector.dataset.open = "false"; inspector.setAttribute("aria-label", text("deviceDetails"));
  side.root.querySelector(".sev-card")?.remove();
  if (isImport) { root.classList.add("nv-import"); lateral.append(side.root); } else lateral.append(side.root, inspector);

  /* vulnerabilities band */
  const vuln = el("section", "card nv-vuln"); const vulnTitleId = "v-title-" + (++menuCounter); vuln.setAttribute("aria-labelledby", vulnTitleId);
  const vulnHead = el("div", "nv-vuln-head"); const vulnTitle = el("h2"); vulnTitle.id = vulnTitleId; const vulnCount = el("p", "muted");
  vulnHead.append(vulnTitle, vulnCount);
  const vlist = el("ul", "vlist"); const clean = el("div", "clean"); clean.hidden = true;
  vuln.append(vulnHead, vlist, clean);
  root.append(graf, lateral, vuln); if (isImport) root.append(inspector);

  const nodeCache = new Map(); const rowCache = new Map(); const srCache = new Map(); let genericHub = null;

  /* ---- graph ---- */
  let hubAt = { x: 0, y: 0 };
  function positions(devices) {
    const { w, h } = state.size; const pos = new Map();
    if (!w || !h) return pos;
    const cx = w / 2, cy = Math.max(40, (h - 24) / 2);
    const hub = devices.find((d) => d.device_type === "router");
    const others = devices.filter((d) => d !== hub).sort((a, b) => ipNumber(a.ip) - ipNumber(b.ip));
    hubAt = { x: cx, y: cy };
    if (hub) pos.set(hub.ip, { x: cx, y: cy, r: 40, hub: true });
    const rx = Math.max(48, w / 2 - 84), ry = Math.max(24, h / 2 - 68);
    const n = others.length;
    const outer = n <= 10 ? n : Math.ceil(n * 0.62), inner = n - outer;
    others.forEach((device, i) => {
      const onOuter = i < outer, count = onOuter ? outer : inner, idx = onOuter ? i : i - outer;
      const scale = onOuter ? 1 : 0.55;
      // Small home networks use the corners, leaving the router and its labels clear.
      const angle = n <= 4 ? -3 * Math.PI / 4 + idx * Math.PI / 2 : -3 * Math.PI / 4 + (idx / Math.max(1, count)) * Math.PI * 2 + (onOuter ? 0 : Math.PI / Math.max(1, count));
      const y = n <= 4 ? (Math.sin(angle) < 0 ? 70 : Math.max(70, h - 76)) : Math.max(70, Math.min(h - 76, cy + Math.sin(angle) * ry * scale));
      pos.set(device.ip, { x: cx + Math.cos(angle) * rx * scale, y, r: 28, hub: false, labelAbove: y < cy });
    });
    return pos;
  }
  function applyGraph() {
    const scan = state.scan, devices = (scan && scan.devices) || [];
    zoomIn.setAttribute("aria-label", text("zoomIn")); zoomOut.setAttribute("aria-label", text("zoomOut"));
    resetZoom.setAttribute("aria-label", text("resetMap")); graph.setAttribute("aria-label", text("mapNavigation"));
    graphCount.textContent = text("deviceCount", { n: devices.length });
    viewPicker.setAttribute("aria-label", text("deviceView"));
    setButtonLabel(mapButton, text("mapView")); setButtonLabel(listButton, text("listView"));
    deviceList.setAttribute("aria-label", text("deviceListLabel"));
    deviceList.replaceChildren(...devices.map((device) => {
      const li = el("li"); const b = button("", "device-item", TYPE_ICON[device.device_type] || TYPE_ICON.unknown);
      b.dataset.ip = device.ip;
      const severity = highestSeverity(scan, device.ip);
      const copy = b.querySelector("span");
      copy.append(el("strong", "", typeLabel(device)), el("span", "muted", device.ip));
      const badge = el("span", "device-severity sev-" + severity);
      badge.append(icon(SEV_ICON[severity]), el("span", "", severity === "none" ? text("noFindingsShort") : sevLabel(severity)));
      b.append(badge); b.addEventListener("click", () => selectDevice(device.ip)); li.append(b); return li;
    }));
    grafTitle.textContent = text("networkTitle");
    svg.setAttribute("aria-label", text("networkTitle"));
    none.hidden = devices.length > 0; none.textContent = text("noDevices");
    const pos = positions(devices);
    const hasRouter = devices.some((d) => d.device_type === "router");
    reconcile(nodesG, devices.map((device) => {
      const sev = highestSeverity(scan, device.ip), p = pos.get(device.ip) || { x: 0, y: 0, r: 28, hub: false };
      return { key: device.ip, sig: [lang, device.device_type, sev, p.hub, p.labelAbove].join("|"), create: () => buildNode(device.ip), update: (g) => updateNode(g, device, sev, p.hub, p.labelAbove) };
    }), nodeCache);
    for (const [ip, g] of nodeCache) {
      const p = pos.get(ip); if (!p) continue;
      const t = "translate(" + Math.round(p.x) + "," + Math.round(p.y) + ")";
      if (g.getAttribute("transform") !== t) g.setAttribute("transform", t);
    }
    /* generic hub when there is no router in the scan */
    if (!hasRouter && devices.length) {
      if (!genericHub) { genericHub = svgEl("g", "node hub generic"); genericHub.setAttribute("role", "img"); buildHubGlyph(genericHub); svg.insertBefore(genericHub, nodesG); }
      genericHub.setAttribute("transform", "translate(" + Math.round(state.size.w / 2) + "," + Math.round(Math.max(40, (state.size.h - 24) / 2)) + ")");
      genericHub.setAttribute("aria-label", text("networkNode")); genericHub.querySelector("text").textContent = text("networkNode");
    } else if (genericHub) { genericHub.remove(); genericHub = null; }
    /* Curved links start at the actual hub, including the import layout. */
    edgesG.replaceChildren();
    const { x: cx, y: cy } = hubAt;
    for (const device of devices) {
      const p = pos.get(device.ip); if (!p || p.hub) continue;
      const mx = (cx + p.x) / 2, my = (cy + p.y) / 2, dx = p.x - cx, dy = p.y - cy;
      const path = svgEl("path", "edge");
      path.setAttribute("d", "M" + cx + " " + cy + " Q" + (mx - dy * 0.18) + " " + (my + dx * 0.18) + " " + p.x + " " + p.y);
      edgesG.append(path);
    }
    reconcile(srList, devices.map((device) => ({
      key: device.ip, sig: [lang, device.device_type, highestSeverity(scan, device.ip)].join("|"),
      create: () => { const li = el("li"); const b = el("button"); b.type = "button"; b.tabIndex = -1; b.addEventListener("click", () => selectDevice(device.ip)); li.append(b); return li; },
      update: (li) => { li.firstChild.textContent = nodeAria(device); },
    })), srCache);
  }
  const nodeAria = (device) => text("nodeAria", { ip: device.ip, type: typeLabel(device), severity: highestSeverity(state.scan, device.ip) === "none" ? text("noFindingsShort") : sevLabel(highestSeverity(state.scan, device.ip)) });
  function buildHubGlyph(g) {
    const disc = svgEl("circle", "disc"); disc.setAttribute("r", "40");
    const glyph = svgEl("use", "glyph"); glyph.setAttribute("href", "#i-network");
    for (const [k, v] of [["x", -20], ["y", -20], ["width", 40], ["height", 40]]) glyph.setAttribute(k, String(v));
    const label = svgEl("text"); label.setAttribute("y", "64");
    g.append(disc, glyph, label);
  }
  function buildNode(ip) {
    const g = svgEl("g", "node"); g.dataset.ip = ip;
    g.setAttribute("role", "button"); g.setAttribute("tabindex", "0"); g.setAttribute("aria-pressed", "false");
    const focus = svgEl("circle", "focus"), disc = svgEl("circle", "disc"), glyph = svgEl("use", "glyph");
    const badge = svgEl("g", "badge-wrap"), badgeBg = svgEl("circle", "badge"), badgeIcon = svgEl("use", "badge-icon");
    badgeBg.setAttribute("r", "12"); badge.append(badgeBg, badgeIcon);
    const t1 = svgEl("text"), t2 = svgEl("text", "sub");
    g.append(focus, disc, glyph, badge, t1, t2);
    g.__parts = { focus, disc, glyph, badge, badgeIcon, t1, t2 };
    g.addEventListener("click", () => selectDevice(ip));
    g.addEventListener("keydown", (event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); selectDevice(ip); } });
    return g;
  }
  function updateNode(g, device, sev, hub, labelAbove) {
    const { focus, disc, glyph, badge, badgeIcon, t1, t2 } = g.__parts;
    const r = hub ? 40 : 28, g2 = hub ? 22 : 15;
    g.setAttribute("class", "node sev-" + sev + (hub ? " hub" : ""));
    focus.setAttribute("r", String(r + 6)); disc.setAttribute("r", String(r));
    glyph.setAttribute("href", "#" + (TYPE_ICON[device.device_type] || TYPE_ICON.unknown));
    for (const [k, v] of [["x", -g2], ["y", -g2], ["width", g2 * 2], ["height", g2 * 2]]) glyph.setAttribute(k, String(v));
    badge.setAttribute("transform", "translate(" + Math.round(r * 0.72) + "," + -Math.round(r * 0.72) + ")");
    badgeIcon.setAttribute("href", "#" + SEV_ICON[sev]);
    for (const [k, v] of [["x", -9], ["y", -9], ["width", 18], ["height", 18]]) badgeIcon.setAttribute(k, String(v));
    t1.setAttribute("y", String(labelAbove ? -r - 22 : r + 24)); t2.setAttribute("y", String(labelAbove ? -r - 2 : r + 44));
    t1.textContent = typeLabel(device) + " · " + String(device.ip).split(".").pop();
    t2.textContent = sev === "none" ? text("noFindingsShort") : sevLabel(sev);
    g.setAttribute("aria-label", nodeAria(device));
  }

  /* ---- vulnerabilities ---- */
  function applyList() {
    const scan = state.scan, all = sortedFindings(scan);
    vulnTitle.textContent = text("vulnTitle"); vulnCount.textContent = text("vulnCount", { n: all.length });
    clean.hidden = all.length > 0; vlist.hidden = all.length === 0;
    if (!all.length) {
      clean.replaceChildren(icon("i-check"), el("strong", "", text("cleanTitle")), el("p", "", text("cleanText")));
      reconcile(vlist, [], rowCache); return;
    }
    const items = []; let lastSev = null;
    all.forEach((finding, index) => {
      if (finding.severity !== lastSev) {
        lastSev = finding.severity;
        items.push({ key: "g:" + finding.severity, sig: lang + finding.severity, create: () => el("li", "vgroup sev-" + finding.severity), update: (li) => { li.replaceChildren(icon(SEV_ICON[finding.severity]), el("span", "", sevLabel(finding.severity))); } });
      }
      const key = finding.ip + "|" + (finding.port ?? "") + "|" + finding.code, step = (localized(finding.fix) || [])[0] || "";
      items.push({
        key, sig: [lang, index === 0, findingTitle(finding), step, finding.severity].join("|"),
        create: () => { const li = el("li"); const b = el("button"); b.type = "button"; b.dataset.ip = finding.ip; b.dataset.findingKey = key; b.addEventListener("click", () => selectFinding(finding)); li.append(b); return li; },
        update: (li) => fillRow(li.firstChild, finding, index === 0, step),
      });
    });
    reconcile(vlist, items, rowCache);
  }
  function fillRow(b, finding, priority, step) {
    const key = finding.ip + "|" + (finding.port ?? "") + "|" + finding.code;
    b.dataset.findingKey = key;
    b.className = "vrow sev-" + finding.severity + (priority ? " priority" : "");
    const sq = el("span", "sq"); sq.append(icon(SEV_ICON[finding.severity]));
    b.setAttribute("aria-label", text("rowAria", { title: findingTitle(finding), where: whereOf(finding), severity: sevLabel(finding.severity) }));
    if (priority) {
      const body = el("span", "body");
      const kick = el("span", "kick"); kick.append(icon(SEV_ICON[finding.severity]), el("span", "", text("priority") + " · " + sevLabel(finding.severity)));
      const stepLine = el("span", "step"); stepLine.append(el("b", "", text("firstStep") + ": "), document.createTextNode(step || text("noFix")));
      body.append(kick, el("span", "t", findingTitle(finding)), stepLine, el("span", "w", whereOf(finding)));
      b.replaceChildren(sq, body, icon("i-chevron", "go"));
    } else {
      b.replaceChildren(sq, el("span", "t", findingTitle(finding)), el("span", "w", whereOf(finding)), icon("i-chevron", "go"));
    }
    b.setAttribute("aria-pressed", String(b.dataset.findingKey === state.selectedFinding));
  }
  function refreshSelection() {
    for (const [ip, g] of nodeCache) g.setAttribute("aria-pressed", String(ip === state.selectedIp));
    for (const li of vlist.querySelectorAll("li > button")) li.setAttribute("aria-pressed", String(li.dataset.findingKey === state.selectedFinding));
  }

  /* ---- inspector ---- */
  function applyInert() {
    inspector.setAttribute("role", "complementary");
    inspector.removeAttribute("aria-modal");
  }
  function renderUnselected() {
    const body = el("div", "unselected-device");
    body.append(icon("i-network"), el("h2", "", text("noDeviceSelected")), el("p", "muted", text("selectDeviceHint")));
    inspector.replaceChildren(body);
  }
  renderUnselected();
  const deviceOf = (ip) => ((state.scan && state.scan.devices) || []).find((d) => d.ip === ip) || null;

  function inspectorHead(titleText, onBack, backLabel) {
    const head = el("div", "insp-head");
    const back = button(backLabel || text("back"), "plain", "i-back"); back.addEventListener("click", onBack);
    const h = el("h2", "", titleText); h.tabIndex = -1; h.dataset.focus = "1";
    head.append(back, h);
    return head;
  }
  function renderDetail() {
    const device = deviceOf(state.selectedIp);
    if (!device) { closePanel(false); return; }
    inspector.setAttribute("aria-label", text("deviceDetails"));
    const body = el("div", "insp-body");
    body.append(el("p", "dev-ip", device.ip));
    const facts = el("dl", "facts");
    for (const [k, v] of [[text("deviceType"), typeLabel(device)], [text("vendor"), device.vendor || "—"], [text("macLabel"), maskMac(device.mac_masked)]]) { facts.append(el("dt", "", k), el("dd", "", v)); }
    body.append(facts);
    body.append(el("h3", "", text("portsTitle")));
    const ports = el("div", "ports");
    for (const p of device.ports || []) ports.append(el("span", "port", p.port + "/" + p.protocol + (p.service ? " · " + p.service : "") + (p.product ? " · " + p.product + (p.version ? " " + p.version : "") : "")));
    if (!(device.ports || []).length) ports.append(el("span", "muted", text("noPorts")));
    body.append(ports);
    const mine = sortedFindings(state.scan).filter((f) => (
      f.ip === device.ip
      && (!state.selectedFinding || f.ip + "|" + (f.port ?? "") + "|" + f.code === state.selectedFinding)
    ));
    if (!mine.length) body.append(el("p", "muted", text("noDeviceFindings")));
    for (const finding of mine) {
      const card = el("article", "dfind sev-" + finding.severity);
      card.append(el("p", "finding-severity", text("severityLabel", { level: sevLabel(finding.severity) })));
      const h4 = el("h4"); h4.append(icon(SEV_ICON[finding.severity]), el("span", "", findingTitle(finding) + (finding.port ? " · " + finding.port : "")));
      card.append(h4, el("p", "", localized(finding.explain) || text("missingExplain")));
      const steps = localized(finding.fix) || [];
      if (steps.length) {
        const row = el("div", "insp-actions");
        const manual = button(text("manualFix"), "plain");
        const automatic = button(text("agentFix"), "primary");
        const ol = el("ol", "steps"); ol.hidden = true;
        for (const s of steps) ol.append(el("li", "", s));
        manual.setAttribute("aria-expanded", "false");
        manual.addEventListener("click", () => {
          ol.hidden = !ol.hidden;
          manual.setAttribute("aria-expanded", String(!ol.hidden));
        });
        const status = el("p", "muted"); status.setAttribute("role", "status");
        automatic.addEventListener("click", async () => {
          automatic.disabled = true; status.textContent = text("agentWorking");
          try {
            const result = await api("/api/agent/plan", {
              method: "POST", headers: JSON_HEADERS,
              body: JSON.stringify({ scan_id: state.scanId, device_ip: finding.ip, finding_code: finding.code, port: finding.port ?? null, lang })
            });
            if (!result.ok) throw new Error("plan");
            ol.replaceChildren(...(result.data.finding.fix || []).map((step) => el("li", "", step)));
            ol.hidden = false;
            status.textContent = text("agentConfirm");
            const confirm = button(text("agentConfirmButton"), "primary");
            confirm.addEventListener("click", async () => {
              confirm.disabled = true; status.textContent = text("agentWorking");
              try {
                const execution = await api("/api/agent/remediate", {
                  method: "POST", headers: JSON_HEADERS,
                  body: JSON.stringify({ scan_id: state.scanId, device_ip: finding.ip, finding_code: finding.code, port: finding.port ?? null, lang, confirm: true })
                });
                if (execution.ok) {
                  status.textContent = text(execution.data.status === "ok" ? "agentDone" : "agentAccepted");
                } else {
                  status.textContent = execution.data && execution.data.detail === "agent_failed"
                    ? text("agentFailed")
                    : text("agentUnavailable");
                }
                if (!execution.ok) confirm.disabled = false;
              } catch (error) {
                status.textContent = text("agentUnavailable"); confirm.disabled = false;
              }
            });
            row.append(confirm);
          } catch (error) {
            status.textContent = text("agentUnavailable"); automatic.disabled = false;
          }
        });
        row.append(manual, automatic); card.append(row, ol, status);
      }
      body.append(card);
    }
    if (allowAsk) { const ask = button(text("askAI"), "primary", "i-chat"); ask.addEventListener("click", openChat); const row = el("div", "insp-actions"); row.append(ask); body.append(row); }
    inspector.replaceChildren(inspectorHead(text("deviceDetails"), () => closePanel(true)), body);
  }
  function renderEmpty() {
    inspector.setAttribute("aria-label", text("deviceDetails"));
    const box = el("div", "insp-empty"); box.append(icon("i-network", "big"), el("p", "muted", text("noDeviceSelected")));
    inspector.replaceChildren(box);
  }
  function chatKeyNow() { return [state.scanId, state.selectedIp, lang].join("|"); }
  function renderChat() {
    if (state.chat.key !== chatKeyNow()) state.chat = { key: chatKeyNow(), messages: [], pending: false, historyLoaded: false };
    const device = deviceOf(state.selectedIp);
    inspector.setAttribute("aria-label", text("chatTitle"));
    const head = inspectorHead(text("chatTitle"), () => { if (state.selectedIp) openDetail(); else closePanel(true); });
    const body = el("div", "insp-body");
    body.append(el("p", "privacy", text("chatNotice")));
    body.append(el("p", "context", text("chatAbout", { name: device ? device.ip + " · " + typeLabel(device) : text("chatNetwork") })));
    const log = el("div", "chat-log"); log.setAttribute("role", "log"); log.setAttribute("aria-live", "polite"); log.setAttribute("aria-label", text("chatLogLabel"));
    const chips = el("div", "chips");
    const questions = [text("chatQ1"), text("chatQ2")];
    const form = el("form", "chat-form"); const input = el("input"); input.type = "text"; input.maxLength = 500; input.required = true;
    input.placeholder = text("chatPlaceholder"); input.setAttribute("aria-label", text("chatPlaceholder"));
    const send = button(text("send"), "primary", "i-send"); send.type = "submit";
    form.append(input, send);
    function paintLog() {
      log.replaceChildren();
      for (const m of state.chat.messages) {
        const box = el("article", "msg" + (m.role === "user" ? " user" : ""));
        box.append(el("span", "who", m.role === "user" ? text("you") : text("assistant")));

        box.append(el("p", "", m.pending ? text("chatThinking") : String(m.text || "").replace(/\[(?:catalog|kb|ev):[^\]]+\]/g, "").trim()));
        if (m.action && m.action.action === "propose_scan") {
          const proposal = el("div", "scan-proposal");
          const target = m.action.target === "local-network" ? text("localNetwork") : m.action.target;
          proposal.append(el("p", "", text("scanProposal") + ": " + target));
          const confirm = button(text("confirmProposal"), "primary", "i-radar");
          confirm.addEventListener("click", () => confirmProposal(m.action, confirm));
          proposal.append(confirm);
          box.append(proposal);
        }

        log.append(box);
      }
      for (const b of chips.querySelectorAll("button")) b.disabled = state.chat.pending;
      input.disabled = send.disabled = state.chat.pending;
      log.scrollTop = log.scrollHeight;
    }
    async function loadHistory(chat) {
      if (chat.historyLoaded) return;
      chat.historyLoaded = true;
      const params = new URLSearchParams({ lang });
      if (state.selectedIp) params.set("device_ip", state.selectedIp);
      try {
        const result = await api("/api/scans/" + encodeURIComponent(state.scanId) + "/answers?" + params.toString());
        if (!result.ok || state.chat !== chat) return;
        chat.messages = [];
        for (const item of result.data || []) {
          chat.messages.push(
            { role: "user", text: item.question },
            { role: "assistant", text: item.answer, mode: item.mode === "ai" ? "ai" : "docs" },
          );
        }
        if (state.panel === "chat") paintLog();
      } catch (error) {
        /* A temporary history failure must not block a new question. */
      }
    }
    async function ask(question) {
      const value = question.trim();
      if (!value || state.chat.pending) return;
      const chat = state.chat; chat.pending = true;
      chat.messages.push({ role: "user", text: value }, { role: "assistant", pending: true });
      paintLog();
      let reply;
      try {
        const r = await api("/api/ask", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ scan_id: state.scanId, device_ip: state.selectedIp, question: value, lang }) });
        if (r.ok && r.data && typeof r.data.answer === "string") reply = {
          role: "assistant",
          text: r.data.answer,
          sources: r.data.sources,
          mode: r.data.mode === "ai" ? "ai" : r.data.mode === "refused" ? "" : "docs",
          action: r.data.action
        };
      } catch (error) { /* offline: fall through to the local explanation */ }
      if (!reply) reply = { role: "assistant", text: unavailableText() };
      chat.messages[chat.messages.length - 1] = reply; chat.pending = false;
      if (state.chat === chat && state.panel === "chat") { paintLog(); input.value = ""; input.focus(); }
    }
    async function confirmProposal(action, confirm) {
      confirm.disabled = true;
      let target = action.target;
      try {
        if (target === "local-network") {
          const network = await api("/api/network");
          if (!network.ok || !network.data || typeof network.data.subnet !== "string") throw new Error("network");
          target = network.data.subnet;
        }
        const result = await api("/api/scan", {
          method: "POST",
          headers: JSON_HEADERS,
          body: JSON.stringify({ target, confirm: true })
        });
        if (!result.ok) {
          const error = result.data && result.data.error;
          const localized = error && error.message && (error.message[lang] || error.message.en || error.message.ro);
          throw new Error(localized || text("scanRejected"));
        }
        chat.messages.push({ role: "assistant", text: text("scanAccepted"), mode: "docs" });
      } catch (error) {
        chat.messages.push({ role: "assistant", text: error.message || text("scanRejected"), mode: "docs" });
      }
      paintLog();
    }
    for (const q of questions) { const c = el("button", "chip", q); c.type = "button"; c.addEventListener("click", () => ask(q)); chips.append(c); }
    form.addEventListener("submit", (event) => { event.preventDefault(); const v = input.value; input.value = ""; ask(v); });
    body.append(log, chips);
    paintLog();
    loadHistory(state.chat);
    inspector.replaceChildren(head, body, form);
  }
  /* If the assistant is down we show the scan's own explanation: only text that came from the catalog. */
  function unavailableText() {
    return text("chatUnavailable");
  }
  function focusPanel() { const h = inspector.querySelector("[data-focus]"); if (h) h.focus({ preventScroll: true }); }
  function showPanel(kind) {
    state.panel = kind;
    inspector.classList.toggle("chat-open", kind === "chat");
    if (kind === "detail") renderDetail(); else if (kind === "chat") renderChat(); else renderUnselected();
    inspector.dataset.open = String(kind !== "closed");
    applyInert();
  }
  function openDetail() { showPanel("detail"); focusPanel(); }
  function openChat() { showPanel("chat"); focusPanel(); }
  function closePanel(returnFocus) {
    const ip = state.selectedIp;
    state.selectedIp = null;
    state.selectedFinding = null;
    showPanel("closed");
    refreshSelection();
    if (!returnFocus) return;
    const target = listMode ? [...deviceList.querySelectorAll("button")].find((b) => b.dataset.ip === ip) : nodeCache.get(ip) || [...vlist.querySelectorAll("li > button")].find((b) => b.dataset.ip === ip);
    if (target) target.focus({ preventScroll: true });
  }
  function selectDevice(ip) { state.selectedIp = ip; state.selectedFinding = null; refreshSelection(); openDetail(); }
  function selectFinding(finding) {
    state.selectedIp = finding.ip;
    state.selectedFinding = finding.ip + "|" + (finding.port ?? "") + "|" + finding.code;
    refreshSelection();
    openDetail();
  }
  function onEscape() {
    if (state.panel === "chat" && state.selectedIp) { openDetail(); return true; }
    if (state.panel !== "closed") { closePanel(true); return true; }
    return false;
  }

  if (window.ResizeObserver) {
    new ResizeObserver((entries) => {
      const box = entries[0].contentRect;
      const w = Math.round(box.width), h = Math.round(box.height);
      if (w === state.size.w && h === state.size.h) return;
      state.size = { w, h }; paintCamera(); applyGraph();
    }).observe(graph);
  }

  function update(scan, scanId) {
    if (scanId !== state.scanId) resetMap();
    state.scan = scan; state.scanId = scanId;
    if (state.selectedIp && !deviceOf(state.selectedIp)) { state.selectedIp = null; if (state.panel !== "closed") showPanel("closed"); }
    if (state.selectedFinding && !sortedFindings(scan).some((finding) => (
      finding.ip + "|" + (finding.port ?? "") + "|" + finding.code === state.selectedFinding
    ))) state.selectedFinding = null;
    if (isImport && state.panel === "closed") renderEmpty();
    side.update(scan); applyGraph(); applyList(); refreshSelection();
    if (state.panel === "detail") { const sig = detailSig(); if (sig !== state.detailSig) { state.detailSig = sig; renderDetail(); } }
  }
  function detailSig() {
    return JSON.stringify([
      lang,
      state.selectedFinding,
      deviceOf(state.selectedIp),
      sortedFindings(state.scan).filter((f) => f.ip === state.selectedIp),
    ]);
  }
  /* A language change re-renders everything that has text. */
  function rerender() {
    side.update(state.scan); applyGraph(); applyList(); refreshSelection();
    if (state.panel === "detail") renderDetail(); else if (state.panel === "chat") renderChat(); else renderUnselected();
  }
  if (isImport) showPanel("closed");
  return { root, update, rerender, onEscape, get selectedIp() { return state.selectedIp; }, get panel() { return state.panel; }, close: () => closePanel(false) };
}

/* ================= pages ================= */
function pageHeader(page, titleKey, titleId) {
  const head = el("header", "page-head");
  const left = el("div"); const titleRow = el("div", "title-row"); const h1 = el("h1"); h1.id = titleId; h1.tabIndex = -1; h1.dataset.titleKey = titleKey; h1.textContent = text(titleKey);
  const hintKey = titleKey.replace("Title", "Hint");
  const hint = helpHint(hintKey);
  titleRow.append(h1, hint);
  const sub = el("p", "page-sub");
  const kicker = el("p", "eyebrow"); kicker.dataset.i18n = "section" + titleKey; kicker.textContent = text(kicker.dataset.i18n);
  left.append(kicker, titleRow, sub);
  const actions = el("div", "actions");
  head.append(left, actions); page.append(head);
  return { head, h1, sub, actions, hint };
}
function errorNotice(titleKey, stepsKey, detail) {
  const box = el("div", "notice bad"); box.setAttribute("role", "alert");
  box.append(icon("i-alert"));
  const body = el("div"); body.append(el("strong", "", text(titleKey)));
  const steps = text(stepsKey);
  if (Array.isArray(steps)) { const ol = el("ol", "steps"); for (const s of steps) ol.append(el("li", "", s)); body.append(ol); }
  if (detail) body.append(el("p", "muted", text("errDetail", { detail })));
  box.append(body);
  return box;
}

/* ---- Home: live, independent of Import ---- */
function createHomePage() {
  const root = $("page-home");
  const head = pageHeader(root, "homeTitle", "home-title");
  const scanBtn = button(text("scanBtn"), "primary", "i-radar");
  head.actions.append(scanBtn);
  const status = el("div", "notice"); status.hidden = true; status.setAttribute("role", "status");
  const errorBox = el("div"); errorBox.hidden = true;
  const emptyBox = el("div", "card empty"); emptyBox.hidden = true;
  const loadingBox = el("p", "muted", text("loading"));
  const view = createNetworkView();
  view.root.hidden = true;
  root.append(errorBox, status, loadingBox, emptyBox, view.root);
  const s = { scanId: null, scan: null, loaded: false, scanning: false, timer: null, polling: false, offline: false, started: 0 };

  function paintStatic() {
    head.h1.textContent = text("homeTitle");
    head.hint.dataset.tooltip = text("homeHint"); head.hint.setAttribute("aria-label", text("homeHint"));
    setButtonLabel(scanBtn, s.scanning ? text("scanning") : s.scan ? text("scanAgain") : text("scanBtn"));
    head.sub.textContent = s.scan && s.when ? text("lastScan", { when: fmtDate(s.when) }) : "";
    loadingBox.textContent = text("loading");
    if (emptyBox.__lang !== lang) {
      emptyBox.__lang = lang;
      emptyBox.replaceChildren(icon("i-network", "big"), el("h2", "", text("emptyTitle")), el("p", "muted", text("emptyText")));
      const go = button(text("scanBtn"), "primary", "i-radar"); go.addEventListener("click", openScanSheet);
      const imp = el("button", "link", text("orImport")); imp.type = "button"; imp.addEventListener("click", () => showPage("import", true));
      emptyBox.append(go, imp);
    }
    if (s.scanning) paintStatus();
  }
  function paintState() {
    loadingBox.hidden = s.loaded; emptyBox.hidden = !s.loaded || Boolean(s.scan); view.root.hidden = !s.scan;
    scanBtn.disabled = s.scanning; paintStatic();
  }
  function paintStatus() {
    status.hidden = !s.scanning && !s.offline;
    status.replaceChildren();
    if (s.scanning) {
      status.append(el("span", "spinner"), el("div", "", ""));
      status.lastChild.append(el("strong", "", text("scanning")), el("p", "muted", text("scanningNote") + " " + text("elapsed", { s: Math.floor((Date.now() - s.started) / 1000) })));
    } else if (s.offline) { status.append(icon("i-alert"), el("span", "", text("offline"))); }
  }

  async function loadScan(id, announceNew) {
    const r = await api("/api/scans/" + encodeURIComponent(id));
    if (!r.ok || !r.data || r.data.status !== "ok") return false;
    s.scanId = id; s.scan = r.data; s.when = s.whenById && s.whenById[id] || s.when;
    view.update(r.data, id); paintState();
    if (announceNew) announce(text("newScan", { score: r.data.network_score }));
    return true;
  }
  async function poll() {
    if (s.polling || s.scanning || document.hidden) return;
    s.polling = true;
    try {
      const r = await api("/api/scans");
      if (!r.ok || !Array.isArray(r.data)) throw new Error("list");
      if (s.offline) { s.offline = false; paintStatus(); }
      s.whenById = Object.fromEntries(r.data.map((x) => [x.id, x.scanned_at]));
      const mine = r.data.filter((x) => x.status === "ok" && (HOME_SOURCE === null || x.source === HOME_SOURCE));
      const newest = mine.length ? mine[mine.length - 1] : null;
      if (!newest) { if (s.scan) { s.scan = null; s.scanId = null; view.update(null, null); } }
      else if (newest.id !== s.scanId) { s.when = newest.scanned_at; await loadScan(newest.id, s.loaded && s.scanId !== null); }
      s.loaded = true; paintState();
    } catch (error) {
      if (!s.offline) { s.offline = true; paintStatus(); }
      s.loaded = true; paintState();
    } finally { s.polling = false; }
  }

  /* ---- scan flow ---- */
  const dialog = $("dlg-scan");
  function sheet(titleText, bodyNodes, actions) {
    dialog.replaceChildren();
    const h = el("h2", "", titleText); h.id = "dlg-scan-title";
    const body = el("div", "body"); body.append(...bodyNodes);
    const row = el("div", "row-actions"); row.append(...actions);
    dialog.append(h, body, row);
  }
  async function openScanSheet() {
    if (s.scanning) return;
    const cancel = button(text("cancel"), "", null); cancel.addEventListener("click", () => dialog.close());
    sheet(text("sheetScanTitle"), [el("p", "muted", text("checking"))], [cancel]);
    if (!dialog.open) dialog.showModal();
    let network, preview;
    try { [network, preview] = await Promise.all([api("/api/network"), api("/api/scan/preview")]); }
    catch (error) { showScanError({ kind: "network" }, cancel, true); return; }
    if (!network.ok) { showScanError({ status: network.status, code: "network_detection_failed", detail: (network.data && network.data.detail) || null }, cancel, true); return; }
    const info = network.data, pv = preview.ok ? preview.data : null;
    const problems = [];
    if (pv && !pv.nmap) problems.push(text("noNmap"));
    if (pv && pv.problems) for (const p of pv.problems) if (!/nmap/i.test(p)) problems.push(p);
    if (!pv || !pv.target || problems.length) {
      const close = button(text("close"), "primary", null); close.addEventListener("click", () => dialog.close());
      const notice = errorNotice("blockedTitle", "blockedSteps"); for (const p of problems) notice.lastChild.append(el("p", "muted", p));
      sheet(text("sheetScanTitle"), [notice], [close]); return;
    }
    const facts = el("dl", "netfacts");
    for (const [k, v] of [[text("netName"), info.interface], [text("netSubnet"), pv.target], [text("netGateway"), info.gateway]]) facts.append(el("dt", "", k), el("dd", "", v));
    const ok = button(text("confirmScan"), "primary", "i-radar");
    ok.addEventListener("click", () => { dialog.close(); runScan(pv.target); });
    sheet(text("sheetScanTitle"), [el("p", "", text("sheetScanText")), facts, el("p", "muted", text("netPorts", { tcp: pv.tcp_ports, udp: pv.udp_ports.length }))], [cancel, ok]);
    ok.focus();
  }
  function showScanError(problem, cancel, inSheet) {
    const notice = scanErrorNotice(problem);
    if (inSheet) { const close = button(text("close"), "primary", null); close.addEventListener("click", () => dialog.close()); sheet(text("sheetScanTitle"), [notice], [close]); }
  }
  function scanErrorNotice(p) {
    const detail = p.detail && typeof p.detail === "object" ? localized(p.detail) : p.detail;
    if (p.kind === "network") return errorNotice("errServer", "errServerSteps");
    if (p.status === 403) return errorNotice("errPermission", "errPermissionSteps", detail);
    if (p.status === 409 && p.code === "network_detection_failed") return errorNotice("errNetwork", "errNetworkSteps", detail);
    if (p.status === 409) return errorNotice("errBusy", "errBusySteps");
    if (p.status === 502) return errorNotice("errScanFailed", "errScanFailedSteps", detail);
    if (p.status === 500) return errorNotice("errOperation", "errOperationSteps");
    return errorNotice("errOperation", "errOperationSteps", detail);
  }
  async function runScan(target) {
    s.scanning = true; s.started = Date.now(); errorBox.hidden = true; errorBox.replaceChildren();
    paintState(); paintStatus(); announce(text("scanning"));
    s.timer = setInterval(paintStatus, 1000);
    try {
      const r = await api("/api/scan", { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ target, confirm: true }) });
      if (!r.ok) {
        const body = r.data || {}, err = body.error || {};
        showError({ status: r.status, code: err.code, detail: err.message ? err.message : (typeof body.detail === "string" ? body.detail : null) });
      } else {
        s.when = new Date().toISOString();
        const loaded = await loadScan(r.data.scan_id, false);
        if (loaded) announce(text("scanDone", { score: s.scan.network_score }));
      }
    } catch (error) { showError({ kind: "network" }); }
    finally { clearInterval(s.timer); s.scanning = false; paintState(); paintStatus(); }
  }
  function showError(problem) { errorBox.replaceChildren(scanErrorNotice(problem)); errorBox.hidden = false; }

  scanBtn.addEventListener("click", openScanSheet);
  return {
    root, titleEl: head.h1,
    activate() { poll(); },
    deactivate() {},
    poll, rerender() { paintState(); view.rerender(); },
    reset() { s.scan = null; s.scanId = null; s.loaded = true; view.update(null, null); paintState(); },
    onEscape: () => view.onEscape(), init() { paintState(); poll(); },
  };
}

/* ---- History: live scans only ---- */
function createHistoryPage() {
  const root = $("page-history");
  const head = pageHeader(root, "histTitle", "history-title");
  const exportBtn = button(text("exportBtn"), "", "i-share"); const clearBtn = button(text("clearHistory"), "danger", "i-trash");
  head.actions.append(exportBtn, clearBtn);
  const historyStatus = el("div", "notice"); historyStatus.hidden = true; historyStatus.setAttribute("role", "status"); root.append(historyStatus);
  const body = el("div"); body.style.display = "contents";
  root.append(body);
  const s = { scans: [], selectedId: null, detail: null, detailCache: new Map(), loaded: false, cmpBefore: null, cmpAfter: null };
  const side = createSidePanel();
  const menuBefore = createMenu("compareBefore", (v) => { s.cmpBefore = Number(v); compare(); });
  const menuAfter = createMenu("compareAfter", (v) => { s.cmpAfter = Number(v); compare(); });
  const cmpBox = el("div", "cmp"); cmpBox.setAttribute("aria-live", "polite");
  let chartCard, listCard, compareCard, histGrid, histMain, histSide, emptyCard;

  function validScans() { return s.scans.filter((x) => x.status === "ok"); }
  function buildLayout() {
    histGrid = el("div", "hist"); histMain = el("div", "hist-main"); histSide = el("div", "hist-side"); histSide.append(side.root);
    chartCard = el("section", "card"); listCard = el("section", "card"); compareCard = el("section", "card");
    compareCard.append(el("h2", "card-title"), (() => { const p = el("div", "pickers"); p.append(menuBefore.root, menuAfter.root); return p; })(), cmpBox);
    histMain.append(chartCard, listCard, compareCard); histGrid.append(histMain, histSide);
    emptyCard = el("div", "card empty");
    body.replaceChildren(emptyCard, histGrid);
  }
  buildLayout();

  function smoothPath(points) {
    if (points.length < 2) return "";
    let d = "M" + points[0].x + " " + points[0].y;
    for (let i = 0; i < points.length - 1; i++) {
      const p0 = points[i - 1] || points[i], p1 = points[i], p2 = points[i + 1], p3 = points[i + 2] || p2;
      const c1x = p1.x + (p2.x - p0.x) / 6, c1y = p1.y + (p2.y - p0.y) / 6, c2x = p2.x - (p3.x - p1.x) / 6, c2y = p2.y - (p3.y - p1.y) / 6;
      d += " C" + c1x.toFixed(1) + " " + c1y.toFixed(1) + " " + c2x.toFixed(1) + " " + c2y.toFixed(1) + " " + p2.x + " " + p2.y;
    }
    return d;
  }
  function paintChart() {
    chartCard.replaceChildren(el("h2", "card-title", text("chartTitle")));
    const valid = validScans().slice(-20);
    if (valid.length < 2) { chartCard.append(el("p", "muted", text("chartNeedMore"))); chartCard.lastChild.style.marginTop = "12px"; return; }
    const W = Math.max(160, chartCard.clientWidth - 80), H = 220, left = 44, right = 20, top = 28, bottom = 24;
    const x = (i) => Math.round(left + ((W - left - right) * i) / (valid.length - 1));
    const y = (score) => Math.round(top + ((100 - score) * (H - top - bottom)) / 100);
    const svg = svgEl("svg"); svg.setAttribute("viewBox", "0 0 " + W + " " + H); svg.setAttribute("role", "img");
    svg.setAttribute("aria-label", text("chartAria", { n: valid.length, first: valid[0].network_score, last: valid[valid.length - 1].network_score }));
    for (const g of [0, 50, 100]) {
      const line = svgEl("line", "chart-grid"); line.setAttribute("x1", String(left)); line.setAttribute("x2", String(W - right)); line.setAttribute("y1", String(y(g))); line.setAttribute("y2", String(y(g)));
      const lab = svgEl("text", "chart-lab"); lab.setAttribute("x", String(left - 10)); lab.setAttribute("y", String(y(g) + 5)); lab.textContent = String(g);
      svg.append(line, lab);
    }
    const pts = valid.map((scan, i) => ({ x: x(i), y: y(scan.network_score) }));
    const path = svgEl("path", "chart-line"); path.setAttribute("d", smoothPath(pts)); svg.append(path);
    valid.forEach((scan, i) => {
      const c = svgEl("circle", "chart-pt"); c.setAttribute("cx", String(pts[i].x)); c.setAttribute("cy", String(pts[i].y)); c.setAttribute("r", "7");
      const title = svgEl("title"); title.textContent = text("pointAria", { when: fmtDate(scan.scanned_at), score: scan.network_score }); c.append(title);
      const v = svgEl("text", "chart-val"); v.setAttribute("x", String(pts[i].x)); v.setAttribute("y", String(pts[i].y - 14)); v.textContent = String(scan.network_score);
      svg.append(c, v);
    });
    const wrap = el("div", "chart-wrap"); wrap.append(svg); chartCard.append(wrap);
  }
  function paintList() {
    listCard.replaceChildren(el("h2", "card-title", text("scansTitle")));
    const ul = el("ul", "scan-list");
    for (const scan of s.scans.slice().reverse()) {
      const li = el("li"); const b = el("button", "scan-row"); b.type = "button"; b.setAttribute("aria-pressed", String(scan.id === s.selectedId));
      b.append(el("span", "when", fmtDate(scan.scanned_at)), el("span", "sc", scan.status === "ok" ? text("scanRowScore", { score: scan.network_score }) : text("scanError")));
      b.disabled = scan.status !== "ok";
      b.addEventListener("click", () => select(scan.id));
      li.append(b); ul.append(li);
    }
    listCard.append(ul);
  }
  function paintCompare() {
    compareCard.firstChild.textContent = text("compareTitle");
    menuBefore.setLabel(); menuAfter.setLabel();
    const valid = validScans();
    const items = valid.map((x) => ({ value: x.id, label: fmtDate(x.scanned_at) + " · " + text("scanRowScore", { score: x.network_score }) }));
    if (valid.length >= 2) {
      if (!valid.some((x) => x.id === s.cmpBefore)) s.cmpBefore = valid[valid.length - 2].id;
      if (!valid.some((x) => x.id === s.cmpAfter)) s.cmpAfter = valid[valid.length - 1].id;
    }
    menuBefore.setItems(items, s.cmpBefore); menuAfter.setItems(items, s.cmpAfter);
    compare();
  }
  let compareToken = 0;
  async function compare() {
    const token = ++compareToken;
    cmpBox.replaceChildren();
    if (validScans().length < 2) { cmpBox.append(el("p", "muted", text("compareNeed"))); return; }
    if (s.cmpBefore === s.cmpAfter) { cmpBox.append(el("p", "muted", text("compareSame"))); return; }
    let r;
    try { r = await api("/api/compare?a=" + s.cmpBefore + "&b=" + s.cmpAfter); } catch (error) { r = { ok: false }; }
    if (token !== compareToken) return;
    if (!r.ok) { cmpBox.append(el("p", "muted", text("compareFailed"))); return; }
    const d = r.data;
    cmpBox.append(el("p", "big", text("scoreChange", { a: d.score_before, b: d.score_after })));
    const sections = [
      ["resolvedTitle", d.resolved_findings.map((f) => findingLine(f))], ["newFindingsTitle", d.new_findings.map((f) => findingLine(f))],
      ["newDevices", d.new_devices], ["removedDevices", d.removed_devices],
      ["openedPorts", d.opened_ports.map((p) => p.ip + ":" + p.port + "/" + p.protocol)], ["closedPorts", d.closed_ports.map((p) => p.ip + ":" + p.port + "/" + p.protocol)],
    ];
    for (const [key, values] of sections) {
      cmpBox.append(el("h3", "", text(key)));
      const ul = el("ul"); for (const v of values) ul.append(el("li", "", v)); if (!values.length) ul.append(el("li", "muted", text("none")));
      cmpBox.append(ul);
    }
  }
  const findingLine = (f) => f.code + " · " + whereOf(f);

  async function select(id) {
    s.selectedId = id;
    const hadFocus = listCard.contains(document.activeElement);
    paintList();
    if (hadFocus) { const pressed = listCard.querySelector('[aria-pressed="true"]'); if (pressed) pressed.focus(); }
    if (!s.detailCache.has(id)) {
      const r = await api("/api/scans/" + id);
      if (r.ok) s.detailCache.set(id, r.data);
    }
    if (s.selectedId === id) side.update(s.detailCache.get(id) || null);
  }
  async function refresh() {
    let r;
    try { r = await api("/api/scans"); } catch (error) { r = { ok: false }; }
    if (!r.ok || !Array.isArray(r.data)) {
      historyStatus.hidden = false; historyStatus.replaceChildren(icon("i-alert"), el("span", "", text("historyUnavailable")));
      return;
    }
    historyStatus.hidden = true;
    s.scans = r.data.filter((x) => HOME_SOURCE === null || x.source === HOME_SOURCE);
    s.loaded = true; paintAll();
    const valid = validScans();
    if (valid.length && !valid.some((x) => x.id === s.selectedId)) await select(valid[valid.length - 1].id);
  }
  function paintAll() {
    head.h1.textContent = text("histTitle");
    setButtonLabel(exportBtn, text("exportBtn")); setButtonLabel(clearBtn, text("clearHistory"));
    const has = s.scans.length > 0;
    emptyCard.hidden = has; histGrid.hidden = !has; exportBtn.hidden = clearBtn.hidden = !has;
    emptyCard.replaceChildren(icon("i-clock", "big"), el("h2", "", text("histEmptyTitle")), el("p", "muted", text("histEmptyText")));
    if (!has) return;
    paintChart(); paintList(); paintCompare();
    side.update(s.detailCache.get(s.selectedId) || null);
  }

  exportBtn.addEventListener("click", () => {
    const valid = validScans();
    if (!valid.length) return;
    let url = "/api/report?lang=" + lang;
    if (s.cmpBefore && s.cmpAfter && s.cmpBefore !== s.cmpAfter && valid.length >= 2) url += "&a=" + s.cmpBefore + "&b=" + s.cmpAfter;
    else url += "&a=" + (s.selectedId || valid[valid.length - 1].id);
    window.open(url, "_blank", "noopener");
  });
  /* clear history sheet */
  const dialog = $("dlg-clear");
  clearBtn.addEventListener("click", () => {
    dialog.replaceChildren();
    const h = el("h2", "", text("clearTitle")); h.id = "dlg-clear-title";
    const err = el("p", "notice bad"); err.setAttribute("role", "alert"); err.hidden = true;
    const body = el("div", "body"); body.append(el("p", "", text("clearText")), err);
    const cancel = button(text("cancel"), "", null); cancel.addEventListener("click", () => dialog.close());
    const confirm = button(text("clearConfirm"), "danger", "i-trash");
    confirm.addEventListener("click", async () => {
      confirm.disabled = true;
      let r; try { r = await api("/api/history", { method: "DELETE" }); } catch (error) { r = { ok: false }; }
      if (!r.ok) { err.hidden = false; err.textContent = text("clearFailed"); confirm.disabled = false; return; }
      dialog.close(); document.dispatchEvent(new CustomEvent("netcheck:cleared")); announce(text("cleared"));
    });
    const row = el("div", "row-actions"); row.append(cancel, confirm);
    dialog.append(h, body, row);
    dialog.showModal(); cancel.focus();
  });
  return {
    root, titleEl: head.h1,
    activate() { refresh(); }, rerender() { if (s.loaded) paintAll(); else head.h1.textContent = text("histTitle"); },
    reset() { s.scans = []; s.detailCache.clear(); s.selectedId = null; paintAll(); },
    onEscape: () => false, init() { paintAll(); },
  };
}

/* ---- Import: a batch of files, static; saved locally with source "import", hidden from Home and History ---- */
function createImportPage() {
  const root = $("page-import");
  const head = pageHeader(root, "importTitle", "import-title");
  const againBtn = button(text("importAgain"), "", "i-upload");
  const backBtn = button(text("backToFiles"), "", "i-back");
  head.actions.append(backBtn, againBtn);
  const input = el("input"); input.type = "file"; input.accept = ".xml,application/xml,text/xml"; input.multiple = true; input.hidden = true;
  const drop = el("div", "drop"); const results = el("div", "results"); results.setAttribute("aria-live", "polite");
  const list = el("ul", "file-list"); list.setAttribute("aria-label", text("importTitle"));
  const view = createNetworkView({ variant: "import" }); view.root.hidden = true;
  root.append(input, results, drop, list, view.root);
  const s = { items: [], current: -1, mode: "list", errors: [], busy: "", timer: 0 };

  function clearErrors() { clearTimeout(s.timer); s.errors = []; paint(); }
  function paint() {
    setButtonLabel(againBtn, text("importAgain")); setButtonLabel(backBtn, text("backToFiles"));
    const detail = s.mode === "detail" && s.items[s.current];
    const item = s.items[s.current];
    head.h1.textContent = detail ? item.name : text("importTitle");
    head.sub.textContent = "";
    head.head.classList.toggle("swap", Boolean(detail));
    root.classList.toggle("import-detail", Boolean(detail));
    const empty = !s.items.length;
    drop.hidden = !empty; list.hidden = empty || Boolean(detail); view.root.hidden = !detail;
    againBtn.hidden = empty || Boolean(detail); backBtn.hidden = !detail;
    drop.replaceChildren(icon("i-upload", "big"), el("h2", "", text("dropTitle")), el("p", "muted", text("dropNote")));
    const choose = button(text("chooseFiles"), "primary", "i-file"); choose.addEventListener("click", () => input.click()); drop.append(choose);
    drop.append(el("p", "muted", text("importPrivacy")));
    list.replaceChildren(...s.items.map((it, i) => {
      const li = el("li"); const card = el("button", "file-card"); card.type = "button"; card.dataset.index = String(i);
      const score = it.scan && it.scan.network_score;
      card.append(icon("i-file"), el("span", "file-name", it.name), el("span", "file-score", text("fileScore", { n: score })), icon("i-chevron"));
      card.addEventListener("click", () => showItem(i));
      li.append(card); return li;
    }));
    results.replaceChildren();
    if (s.busy) { const n = el("div", "notice"); n.append(el("span", "spinner"), el("span", "", s.busy)); results.append(n); }
    for (const e of s.errors) {
      const n = el("div", "notice bad"); n.setAttribute("role", "alert");
      const x = button("", "icon-only", "i-close"); x.setAttribute("aria-label", text("dismiss")); x.addEventListener("click", clearErrors);
      n.append(icon("i-alert"), el("span", "grow", text(e.key, { name: e.name })), x); results.append(n);
    }
  }
  function showItem(index) {
    s.current = index; s.mode = "detail"; const item = s.items[index];
    view.update(item.scan, item.id); paint(); head.h1.focus({ preventScroll: true });
  }
  function backToList() {
    s.mode = "list"; paint();
    const card = list.querySelector('[data-index="' + s.current + '"]'); if (card) card.focus({ preventScroll: true });
  }
  async function processFiles(fileList) {
    const files = Array.from(fileList || []);
    if (!files.length || s.busy) return;
    clearTimeout(s.timer); s.errors = []; const added = [];
    for (let i = 0; i < files.length; i++) {
      const file = files[i];
      s.busy = text("importProgress", { n: i + 1, total: files.length }); paint(); announce(s.busy);
      if (!/\.xml$/i.test(file.name)) { s.errors.push({ key: "badType", name: file.name }); continue; }
      if (file.size > MAX_IMPORT_BYTES) { s.errors.push({ key: "tooBig", name: file.name }); continue; }
      try {
        const r = await api("/api/import?filename=" + encodeURIComponent(file.name), { method: "POST", headers: { "Content-Type": "application/xml" }, body: await file.text() });
        if (r.status === 413) { s.errors.push({ key: "tooBig", name: file.name }); continue; }
        if (!r.ok || !r.data) { s.errors.push({ key: "importFailed", name: file.name }); continue; }
        if (r.data.status !== "ok") { s.errors.push({ key: "brokenFile", name: file.name }); continue; }
        added.push({ id: r.data.scan_id, name: file.name, date: new Date().toISOString(), scan: r.data });
      } catch (error) { s.errors.push({ key: "importFailed", name: file.name }); }
    }
    s.busy = ""; s.items.push(...added); s.mode = "list"; paint();
    if (s.errors.length) s.timer = setTimeout(clearErrors, ERROR_MS);
    input.value = "";
    announce(text("importResult", { ok: added.length, bad: s.errors.length }));
  }
  againBtn.addEventListener("click", () => input.click());
  backBtn.addEventListener("click", backToList);
  input.addEventListener("change", () => processFiles(input.files));
  ["dragenter", "dragover"].forEach((name) => drop.addEventListener(name, (event) => { event.preventDefault(); drop.classList.add("dragging"); }));
  ["dragleave", "drop"].forEach((name) => drop.addEventListener(name, (event) => { event.preventDefault(); drop.classList.remove("dragging"); }));
  drop.addEventListener("drop", (event) => processFiles(event.dataTransfer && event.dataTransfer.files));
  return {
    root, titleEl: head.h1,
    activate() {}, rerender() { paint(); if (s.mode === "detail") view.rerender(); },
    deactivate() {},
    reset() { clearTimeout(s.timer); s.items = []; s.current = -1; s.mode = "list"; s.errors = []; view.update(null, null); paint(); },
    onEscape() { if (view.onEscape()) return true; if (s.mode === "detail") { backToList(); return true; } return false; },
    init() { paint(); },
  };
}

/* ================= boot ================= */
const pages = {};
let currentPage = null;
function applyStaticText() {
  document.documentElement.lang = lang;
  document.querySelectorAll("[data-i18n]").forEach((node) => { node.textContent = text(node.dataset.i18n); });
  document.querySelectorAll("[data-i18n-aria]").forEach((node) => node.setAttribute("aria-label", text(node.dataset.i18nAria)));
  document.querySelectorAll(".help-hint[data-help-key]").forEach((node) => {
    const value = text(node.dataset.helpKey);
    node.dataset.tooltip = value;
    node.setAttribute("aria-label", value);
  });
  for (const b of document.querySelectorAll(".lang-opt")) b.setAttribute("aria-checked", String(b.dataset.lang === lang));
}
function showPage(id, focusTitle) {
  if (!pages[id]) id = "home";
  if (currentPage && currentPage !== id && pages[currentPage].deactivate) pages[currentPage].deactivate();
  currentPage = id;
  if (focusTitle) $("main").scrollTop = 0;
  for (const key of Object.keys(pages)) pages[key].root.hidden = key !== id;
  for (const b of document.querySelectorAll(".nav-item")) { if (b.dataset.page === id) b.setAttribute("aria-current", "page"); else b.removeAttribute("aria-current"); }
  try { history.replaceState(null, "", "#" + id); } catch (error) { /* file:// or sandbox */ }
  pages[id].activate();
  if (focusTitle) pages[id].titleEl.focus({ preventScroll: true });
}
function setLanguage(next) {
  lang = next === "en" ? "en" : "ro";
  try { localStorage.setItem("netcheck-language", lang); } catch (error) { /* storage is optional */ }
  applyStaticText();
  for (const key of Object.keys(pages)) pages[key].rerender();
}
function loadLanguage() {
  const fromUrl = new URLSearchParams(location.search).get("lang");
  if (fromUrl === "ro" || fromUrl === "en") { lang = fromUrl; return; }
  try { const saved = localStorage.getItem("netcheck-language"); if (saved === "ro" || saved === "en") lang = saved; } catch (error) { /* ignore */ }
}
function showAuthScreen(mode = "login") {
  const screen = $("auth-screen");
  screen.hidden = false;
  document.querySelector(".app").hidden = true;
  screen.replaceChildren();
  const card = el("section", "auth-card");
  const title = el("h1", "", text(mode === "login" ? "authLogin" : "authRegister"));
  const intro = el("p", "", text("authWelcome"));
  const form = el("form", "auth-form");
  const userLabel = el("label", "", text("authUsername"));
  const user = el("input"); user.type = "email"; user.required = true; user.autocomplete = mode === "login" ? "username" : "email";
  userLabel.append(user);
  const passLabel = el("label", "", text("authPassword"));
  const pass = el("input"); pass.type = "password"; pass.required = true; pass.minLength = 8; pass.autocomplete = mode === "login" ? "current-password" : "new-password";
  passLabel.append(pass);
  const error = el("p", "auth-error");
  const submit = button(text(mode === "login" ? "authSubmitLogin" : "authSubmitRegister"), "primary");
  submit.type = "submit";
  const switcher = el("button", "auth-switch", text(mode === "login" ? "authSwitchRegister" : "authSwitchLogin")); switcher.type = "button";
  switcher.addEventListener("click", () => showAuthScreen(mode === "login" ? "register" : "login"));
  form.append(userLabel, passLabel, error, submit);
  form.addEventListener("submit", async (event) => {
    event.preventDefault(); submit.disabled = true; error.textContent = "";
    const result = await api("/api/auth/" + mode, { method: "POST", headers: JSON_HEADERS, body: JSON.stringify({ username: user.value, password: pass.value }) });
    if (result.ok) { screen.hidden = true; document.querySelector(".app").hidden = false; startApp(); return; }
    error.textContent = result.data && result.data.detail === "password_too_short" ? text("authPasswordHint") : text("authInvalid");
    submit.disabled = false;
  });
  card.append(title, intro, form, switcher); screen.append(card); user.focus();
}
function startApp() {
  document.querySelector(".app").hidden = false;
  const logout = $("auth-logout");
  logout.hidden = false; logout.textContent = text("authLogout");
  logout.onclick = async () => { await api("/api/auth/logout", { method: "POST" }); location.reload(); };
  loadLanguage();
  pages.home = createHomePage(); pages.history = createHistoryPage(); pages.import = createImportPage();
  applyStaticText();
  for (const key of Object.keys(pages)) pages[key].init();
  for (const b of document.querySelectorAll(".nav-item")) b.addEventListener("click", () => showPage(b.dataset.page, true));
  for (const b of document.querySelectorAll(".lang-opt")) b.addEventListener("click", () => setLanguage(b.dataset.lang));
  $("lang-ro").parentElement.addEventListener("keydown", (event) => {
    if (event.key === "ArrowRight" || event.key === "ArrowDown") { event.preventDefault(); setLanguage("en"); $("lang-en").focus(); }
    if (event.key === "ArrowLeft" || event.key === "ArrowUp") { event.preventDefault(); setLanguage("ro"); $("lang-ro").focus(); }
  });
  document.addEventListener("keydown", (event) => {
    if (event.key !== "Escape" || document.querySelector("dialog[open]") || !currentPage) return;
    if (pages[currentPage].onEscape()) event.preventDefault();
  });
  document.addEventListener("netcheck:cleared", () => { for (const key of Object.keys(pages)) pages[key].reset(); });
  /* Live updates only while the browser tab is visible; resume immediately on return. */
  setInterval(() => pages.home.poll(), POLL_MS);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) pages.home.poll(); });
  const initial = (location.hash || "#home").slice(1);
  showPage(initial, false);
}
async function boot() {
  loadLanguage();
  const result = await api("/api/auth/me");
  if (result.ok && result.data && result.data.authenticated) startApp();
  else showAuthScreen("login");
}
boot();
