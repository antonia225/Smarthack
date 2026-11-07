// Faza 1: doar interfață. Fără logică reală; textele vin din texts.js (obiectul TEXTS).
// REGULĂ DE SECURITATE: tot ce se afișează (nume de dispozitive, fișiere, texte din scanare)
// se pune DOAR cu textContent, niciodată cu innerHTML.
"use strict";

const params = new URLSearchParams(location.search);
const state = {
  lang: params.get("lang") === "en" ? "en" : "ro",
  // normal | empty | error | clean   (ex.: index.html?state=clean)
  ui: ["empty", "error", "clean"].includes(params.get("state")) ? params.get("state") : "normal",
  view: "home",          // home | history | problem
  problem: null,         // indexul problemei afișate în detaliu
  dialogSev: null,       // gravitatea afișată în fereastra mică
  search: "",
  sevFilter: "all",
  openSteps: new Set(),  // carduri de probleme cu pașii deschiși
  openPorts: new Set(),  // dispozitive cu porturile deschise
  compareA: 2,
  compareB: 3,
  cleared: false,
  scans: [],
  currentScanId: null,
  compareResult: null
};

const SEVERITIES = [
  { key: "high", text: "sevHigh", rank: 3 },
  { key: "medium", text: "sevMedium", rank: 2 },
  { key: "low", text: "sevLow", rank: 1 },
  { key: "info", text: "sevInfo", rank: 0 }
];

// Test cu date ostile: index.html?hostile=1 pune cod HTML în nume. Trebuie să apară ca text simplu.
if (params.get("hostile")) {
  const bad = "<img src=x onerror=alert(1)>";
  ["ro", "en"].forEach((l) => {
    TEXTS[l].devices[1].name = bad;
    TEXTS[l].scans[3].devices[1] = bad;
    TEXTS[l].scans[3].file = bad;
  });
}

// ---------- Ajutoare ----------
function t(key) {
  const v = TEXTS[state.lang] && TEXTS[state.lang][key];
  return v !== undefined ? v : TEXTS.ro[key] !== undefined ? TEXTS.ro[key] : key;
}

function fmt(template, vars) {
  return Object.keys(vars).reduce((s, k) => s.replace("{" + k + "}", vars[k]), template);
}

function $(id) { return document.getElementById(id); }

function reduceMotion() {
  return window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
}

// Creează un element; textul se pune DOAR cu textContent.
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

const SVG_NS = "http://www.w3.org/2000/svg";
function svgEl(tag, attrs) {
  const node = document.createElementNS(SVG_NS, tag);
  Object.keys(attrs || {}).forEach((k) => node.setAttribute(k, attrs[k]));
  return node;
}

// Iconiță SVG din sprite-ul din index.html
function svgIcon(id) {
  const svg = svgEl("svg", { "aria-hidden": "true" });
  svg.appendChild(svgEl("use", { href: "#" + id }));
  return svg;
}

function sevName(levelKey) {
  return t(SEVERITIES.find((s) => s.key === levelKey).text);
}

function pill(levelKey) {
  return el("span", "pill sev-" + levelKey, sevName(levelKey));
}

function scoreLevel(score) {
  return score >= 70 ? "good" : score >= 50 ? "medium" : "bad";
}

// Număr care urcă de la 0 la valoare
function countUp(node, to, dur) {
  if (reduceMotion()) { node.textContent = to; return; }
  const start = performance.now();
  node.textContent = "0";
  const step = (now) => {
    const p = Math.max(0, Math.min(1, (now - start) / (dur || 1100)));
    node.textContent = Math.round(to * (1 - Math.pow(1 - p, 3)));
    if (p < 1) requestAnimationFrame(step);
  };
  requestAnimationFrame(step);
}

// MAC mascat parțial (confidențialitate): se văd doar primii 3 octeți
function maskMac(mac) {
  if (!mac) return "";
  if (mac.includes("*")) return mac;
  return mac.split(":").slice(0, 3).join(":") + ":••:••:••";
}

function portLabel(ipPort) {
  const [ip, port] = ipPort.split(":");
  return fmt(t("locationPort"), { ip, port });
}

function location_(p) {
  return p.port ? fmt(t("locationPort"), { ip: p.ip, port: p.port }) : fmt(t("location"), { ip: p.ip });
}

// Problemele afișate (în starea „clean” nu există niciuna) și scorul
function getCurrentScan() {
  return state.scans.find((scan) => scan.id === state.currentScanId) || state.scans[state.scans.length - 1];
}

function getProblems() {
  const scan = getCurrentScan();
  return state.ui === "clean" || !scan ? [] : scan.problems;
}

function getDevices() {
  const scan = getCurrentScan();
  return scan ? scan.devices : [];
}

function getScans() { return state.scans; }
function getScore() {
  const scan = getCurrentScan();
  return state.ui === "clean" || !scan ? t("scoreMax") : scan.score;
}

// Probleme sortate: cele mai grave primele (păstrăm indexul original pentru link-uri)
function sortedProblems() {
  const rank = (lvl) => SEVERITIES.find((s) => s.key === lvl).rank;
  return getProblems()
    .map((p, i) => ({ p, i }))
    .sort((a, b) => rank(b.p.level) - rank(a.p.level) || b.p.points - a.p.points);
}

function deviceByIp(ip) {
  return getDevices().find((d) => d.ip === ip);
}

function kindIcon(kind) {
  return { router: "i-router", laptop: "i-laptop", camera: "i-camera", printer: "i-printer",
    tv: "i-tv", phone: "i-phone" }[kind] || "i-unknown";
}

// Rând simplu de problemă (link spre pagina ei) — folosit în fereastra mică
function problemRow(p, i) {
  const li = el("li");
  const row = el("a", "problem-row sev-" + p.level);
  row.href = "#problem-" + i;

  const main = el("div", "problem-main");
  main.appendChild(el("span", "problem-name", fmt(t("problemRow"), { n: i + 1, ip: p.ip })));
  main.appendChild(el("span", "problem-desc", p.desc));

  const side = el("div", "problem-side");
  side.appendChild(pill(p.level));
  side.appendChild(el("span", "problem-arrow", t("arrow")));

  row.appendChild(main);
  row.appendChild(side);
  li.appendChild(row);
  return li;
}

// ---------- Texte statice ----------
function applyTexts() {
  document.documentElement.lang = state.lang;
  document.querySelectorAll("[data-i18n]").forEach((node) => {
    node.textContent = t(node.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-aria]").forEach((node) => {
    node.setAttribute("aria-label", t(node.dataset.i18nAria));
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((node) => {
    node.setAttribute("placeholder", t(node.dataset.i18nPlaceholder));
  });
  document.querySelectorAll(".nav-btn").forEach((btn) => {
    btn.title = btn.querySelector("span").textContent;
  });
  $("lang-ro").classList.toggle("active", state.lang === "ro");
  $("lang-en").classList.toggle("active", state.lang === "en");
  updateToggle();
  renderHome();
  renderHistory();
  renderDialog();
  renderProblem();
  applyUiState();
}

// ---------- Stări speciale: normal / goală / eroare / curat / istoric șters ----------
function applyUiState() {
  const empty = state.ui === "empty";
  const error = state.ui === "error";
  $("home-content").hidden = empty || error;
  $("empty-state").hidden = !empty;
  $("error-card").hidden = !error;

  const noHistory = empty || state.cleared;
  $("history-empty").hidden = !noHistory;
  $("history-content").hidden = noHistory;
  $("btn-clear").hidden = noHistory;
}

// ---------- Pagina Acasă ----------
function renderHome() {
  const problems = getProblems();
  const sorted = sortedProblems();
  const score = getScore();
  const scanSelect = $("scan-select");
  scanSelect.replaceChildren();
  getScans().forEach((scan) => {
    const option = el("option", "", scan.file + " · " + scan.date);
    option.value = String(scan.id);
    scanSelect.appendChild(option);
  });
  scanSelect.value = state.currentScanId === null ? "" : String(state.currentScanId);
  scanSelect.dispatchEvent(new Event("dd-refresh"));
  const lastScan = document.querySelector(".last-scan span");
  if (lastScan) {
    const current = getCurrentScan();
    lastScan.textContent = current ? current.date : "";
  }

  // --- Cardul de sus: dispozitiv periculos / stare pozitivă ---
  const hasProblems = sorted.length > 0;
  $("hero-problem").hidden = !hasProblems;
  $("hero-clean").hidden = hasProblems;
  if (hasProblems) {
    const top = sorted[0].p;
    const dev = deviceByIp(top.ip);
    const icon = $("hero-device-icon");
    icon.replaceChildren(svgIcon(kindIcon(dev ? dev.kind : "unknown")));
    $("hero-device-name").textContent = dev ? dev.name : top.device;
    $("hero-device-type").textContent = dev ? dev.type : "";
    $("hero-device-ip").textContent = top.ip;
    $("overview-pill").className = "pill sev-" + top.level;
    $("overview-pill").textContent = sevName(top.level);
    $("hero-title").textContent = top.desc;
    $("hero-explain").textContent = top.detail;
    $("hero-first").textContent = top.first;
  }

  // --- Scor (valoarea finală; animația rulează în animateScore) ---
  const level = scoreLevel(score);
  const panel = $("score-panel");
  panel.classList.remove("good", "medium", "bad");
  panel.classList.add(level);
  $("score-number").textContent = score;
  $("score-label").textContent =
    t(level === "good" ? "scoreGood" : level === "medium" ? "scoreMedium" : "scoreBad");
  $("score-attention").textContent =
    t(level === "good" ? "attentionGood" : level === "medium" ? "attentionMedium" : "attentionBad");
  $("score-badge-icon").replaceChildren(
    svgIcon(level === "good" ? "i-shield" : level === "medium" ? "i-shield-alert" : "i-shield-x"));
  const circ = 2 * Math.PI * 52;
  $("ring-value").style.strokeDasharray = (score / t("scoreMax")) * circ + " " + circ;

  // --- Numărul de probleme pe gravitate ---
  const sevList = $("sev-list");
  sevList.replaceChildren();
  SEVERITIES.forEach((s) => {
    const count = problems.filter((p) => p.level === s.key).length;
    const li = el("li");
    const btn = el("button", "sev-row sev-" + s.key);
    btn.type = "button";
    btn.disabled = count === 0;
    btn.appendChild(el("span", "sev-dot"));
    btn.appendChild(el("span", "sev-name", sevName(s.key)));
    btn.appendChild(el("span", "sev-count", String(count)));
    btn.addEventListener("click", () => openDialog(s.key));
    li.appendChild(btn);
    sevList.appendChild(li);
  });

  renderFilter();
  renderProblemList();
  renderDevices();

  // --- Rezumat ---
  const summary = $("summary");
  summary.replaceChildren();
  [
    ["i-devices", "statDevices", getDevices().length],
    ["i-list", "statProblems", problems.length],
    ["i-check", "statResolved", t("resolvedCount")]
  ].forEach(([icon, label, value]) => {
    const box = el("button", "stat stat-link");
    box.type = "button";
    box.addEventListener("click", () => goStat(label));
    const ic = el("span", "stat-icon");
    ic.setAttribute("aria-hidden", "true");
    ic.appendChild(svgIcon(icon));
    const txt = el("div");
    txt.appendChild(el("span", "stat-number", String(value)));
    txt.appendChild(el("span", "stat-label", t(label)));
    box.appendChild(ic);
    box.appendChild(txt);
    summary.appendChild(box);
  });
}

function goStat(label) {
  const smooth = reduceMotion() ? "auto" : "smooth";
  if (label === "statResolved") {
    showView("history");
    const c = $("compare");
    if (c) { c.scrollIntoView({ behavior: smooth, block: "start" }); c.focus({ preventScroll: true }); }
    return;
  }
  const target = $(label === "statDevices" ? "devices" : "problems");
  target.scrollIntoView({ behavior: smooth, block: "start" });
}
$("see-more").addEventListener("click", () => {
  state.showAllProblems = !state.showAllProblems;
  renderProblemList();
});

// Cercul se umple de la 0 până la scor, iar numărul urcă odată cu el
function animateScore() {
  if ($("home-content").hidden) return;
  const score = getScore();
  const circ = 2 * Math.PI * 52;
  const ring = $("ring-value");
  const final = (score / t("scoreMax")) * circ + " " + circ;
  if (reduceMotion()) {
    ring.style.strokeDasharray = final;
    $("score-number").textContent = score;
    return;
  }
  ring.style.transition = "none";
  ring.style.strokeDasharray = "0 " + circ;
  void ring.getBoundingClientRect(); // forțează recalcularea
  ring.style.transition = "";
  requestAnimationFrame(() => { ring.style.strokeDasharray = final; });
  countUp($("score-number"), score, 1200);
}

// ---------- Filtru de gravitate ----------
function renderFilter() {
  const sel = $("sev-filter");
  sel.replaceChildren();
  const all = el("option", "", t("filterAll"));
  all.value = "all";
  sel.appendChild(all);
  SEVERITIES.forEach((s) => {
    const o = el("option", "", sevName(s.key));
    o.value = s.key;
    sel.appendChild(o);
  });
  sel.value = state.sevFilter;
  sel.dispatchEvent(new Event("dd-refresh"));
}

// ---------- Carduri de probleme ----------
function renderProblemList() {
  const list = $("problem-list");
  list.replaceChildren();
  const q = state.search.trim().toLowerCase();
  const all = sortedProblems();

  const LIMIT = 3;
  const matches = all.filter(({ p }) =>
    (state.sevFilter === "all" || p.level === state.sevFilter) &&
    (!q || (p.code + " " + p.ip + " " + p.desc + " " + p.device).toLowerCase().includes(q)));
  const shown = matches.length;
  const visible = state.showAllProblems ? matches : matches.slice(0, LIMIT);
  const more = $("see-more");
  more.hidden = shown <= LIMIT;
  const en = state.lang === "en";
  more.textContent = state.showAllProblems ? (en ? "See less" : "Vezi mai puține")
    : (en ? "See more (" : "Vezi mai multe (") + (shown - LIMIT) + ")";

  visible.forEach(({ p, i }) => {

    const li = el("li", "problem-card sev-" + p.level);

    const head = el("div", "pc-head");
    head.appendChild(pill(p.level));
    head.appendChild(el("span", "pc-points", p.points ? fmt(t("points"), { n: p.points }) : t("pointsNone")));
    head.appendChild(el("span", "pc-code", t("codeLabel") + " " + p.code));
    li.appendChild(head);

    const title = el("h3", "pc-title");
    const link = el("a", "", p.desc);
    link.href = "#problem-" + i;
    title.appendChild(link);
    li.appendChild(title);

    li.appendChild(el("p", "pc-loc", location_(p)));
    li.appendChild(el("p", "pc-explain", p.detail));

    // Buton „Cum repar” + pași numerotați (ascunși la început)
    const open = state.openSteps.has(i);
    const stepsId = "steps-" + i;
    const btn = el("button", "btn-fix");
    btn.type = "button";
    btn.setAttribute("aria-expanded", String(open));
    btn.setAttribute("aria-controls", stepsId);
    btn.appendChild(svgIcon("i-wrench"));
    const label = el("span", "", open ? t("hideSteps") : t("howToFix"));
    btn.appendChild(label);
    btn.appendChild(svgIcon("i-chevron-down"));

    const steps = el("ol", "steps");
    steps.id = stepsId;
    steps.hidden = !open;
    p.steps.forEach((s) => steps.appendChild(el("li", "", s)));

    btn.addEventListener("click", () => {
      const now = steps.hidden;
      steps.hidden = !now;
      btn.setAttribute("aria-expanded", String(now));
      label.textContent = now ? t("hideSteps") : t("howToFix");
      if (now) state.openSteps.add(i); else state.openSteps.delete(i);
    });

    li.appendChild(btn);
    li.appendChild(steps);
    list.appendChild(li);
  });

  const nr = $("no-results");
  nr.hidden = shown !== 0;
  nr.textContent = all.length === 0 ? t("noProblemsList") : t("noResults");
}

// ---------- Tabelul de dispozitive ----------
function worstProblemFor(ip) {
  return sortedProblems().map((x) => x.p).find((p) => p.ip === ip);
}

function renderDevices() {
  const body = $("device-body");
  body.replaceChildren();
  getDevices().forEach((d, i) => {
    const tr = el("tr");
    const cell = (labelKey, content, cls) => {
      const td = el("td", cls || "");
      td.setAttribute("data-label", t(labelKey));
      if (content instanceof Node) td.appendChild(content);
      else td.textContent = content;
      tr.appendChild(td);
      return td;
    };

    cell("colIp", d.ip, "mono");

    const type = el("div", "type-cell");
    const ic = el("span", "type-icon");
    ic.appendChild(svgIcon(kindIcon(d.kind)));
    type.appendChild(ic);
    type.appendChild(el("span", "", d.type));
    cell("colType", type);

    cell("colName", d.name, "strong");
    cell("colVendor", d.vendor);
    cell("colMac", maskMac(d.mac), "mono");

    const worst = worstProblemFor(d.ip);
    const wc = el("div", "worst");
    if (worst) {
      wc.appendChild(pill(worst.level));
      wc.appendChild(el("span", "", worst.desc));
    } else {
      wc.appendChild(el("span", "muted", t("noProblem")));
    }
    cell("colWorst", wc);

    const chips = el("div", "chips");
    if (d.ports.length === 0) chips.appendChild(el("span", "muted", t("noPortsShort")));
    d.ports.forEach((p) => chips.appendChild(el("span", "chip", String(p.port))));
    cell("colPorts", chips);

    const open = state.openPorts.has(i);
    const btn = el("button", "btn-fix btn-fix-sm");
    btn.type = "button";
    btn.setAttribute("aria-expanded", String(open));
    btn.setAttribute("aria-controls", "ports-" + i);
    const label = el("span", "", open ? t("hidePorts") : t("showPorts"));
    btn.appendChild(label);
    btn.appendChild(svgIcon("i-chevron-down"));
    cell("colAction", btn);
    body.appendChild(tr);

    // Rând cu porturile (ascuns inițial)
    const detail = el("tr", "ports-row");
    detail.id = "ports-" + i;
    detail.hidden = !open;
    const td = el("td");
    td.colSpan = 8;
    if (d.ports.length === 0) {
      td.appendChild(el("p", "muted", t("noPorts")));
    } else {
      const ul = el("ul", "chips");
      d.ports.forEach((p) => ul.appendChild(el("li", "chip chip-wide", fmt(t("portLine"), { port: p.port, service: p.service }))));
      td.appendChild(ul);
    }
    detail.appendChild(td);
    body.appendChild(detail);

    btn.addEventListener("click", () => {
      const now = detail.hidden;
      detail.hidden = !now;
      btn.setAttribute("aria-expanded", String(now));
      label.textContent = now ? t("hidePorts") : t("showPorts");
      if (now) state.openPorts.add(i); else state.openPorts.delete(i);
    });
  });
}

// ---------- Istoric: tabel, grafic, comparare ----------
function scanTotal(s) { return s.high + s.medium + s.low + s.info; }

function renderHistory() {
  const scans = getScans();

  const body = $("history-body");
  body.replaceChildren();
  scans.slice().reverse().forEach((s) => {
    const tr = el("tr");
    const cell = (key, content, cls) => {
      const td = el("td", cls || "");
      td.setAttribute("data-label", t(key));
      if (content instanceof Node) td.appendChild(content);
      else td.textContent = content;
      tr.appendChild(td);
    };
    cell("histFile", s.file, "strong");
    cell("histDate", s.date);
    cell("histScore", el("span", "pill score-" + scoreLevel(s.score), String(s.score)));
    cell("histProblems", String(scanTotal(s)));
    body.appendChild(tr);
  });

  renderChart(scans);
  renderCompareControls(scans);
  renderCompare(false);
}

// Curbă netedă prin puncte
function smoothPath(pts) {
  let d = "M" + pts[0].x + "," + pts[0].y;
  for (let i = 0; i < pts.length - 1; i++) {
    const p0 = pts[i - 1] || pts[i], p1 = pts[i], p2 = pts[i + 1], p3 = pts[i + 2] || p2;
    d += " C" + (p1.x + (p2.x - p0.x) / 6) + "," + (p1.y + (p2.y - p0.y) / 6) + " " +
      (p2.x - (p3.x - p1.x) / 6) + "," + (p2.y - (p3.y - p1.y) / 6) + " " + p2.x + "," + p2.y;
  }
  return d;
}

function renderChart(scans) {
  if (scans.length === 0) {
    $("chart-wrap").replaceChildren();
    $("chart-stats").replaceChildren();
    return;
  }
  const W = 560, H = 220, L = 44, R = 60, T = 34, B = 46;
  const pw = W - L - R, ph = H - T - B;
  const x = (i) => L + (scans.length === 1 ? pw / 2 : (pw * i) / (scans.length - 1));
  const y = (v) => T + ph - (v / 100) * ph;
  const pts = scans.map((s, i) => ({ x: x(i), y: y(s.score) }));

  const svg = svgEl("svg", { viewBox: "0 0 " + W + " " + H, class: "chart", role: "img" });
  svg.setAttribute("aria-label", t("chartAria") + ": " + scans.map((s) => s.date + " " + s.score).join(", "));

  const defs = svgEl("defs");
  const grad = svgEl("linearGradient", { id: "areaGrad", x1: "0", y1: "0", x2: "0", y2: "1" });
  grad.appendChild(svgEl("stop", { offset: "0", class: "grad-top" }));
  grad.appendChild(svgEl("stop", { offset: "1", class: "grad-bottom" }));
  defs.appendChild(grad);
  svg.appendChild(defs);

  [0, 50, 100].forEach((v) => {
    svg.appendChild(svgEl("line", { x1: L, x2: W - R, y1: y(v), y2: y(v), class: "grid" }));
    const lab = svgEl("text", { x: L - 10, y: y(v) + 5, "text-anchor": "end", class: "axis" });
    lab.textContent = v;
    svg.appendChild(lab);
  });

  const line = smoothPath(pts);
  svg.appendChild(svgEl("path", { d: line + " L" + pts[pts.length - 1].x + "," + y(0) + " L" + pts[0].x + "," + y(0) + " Z", class: "area" }));
  svg.appendChild(svgEl("path", { d: line, class: "line", pathLength: "1" }));

  scans.forEach((s, i) => {
    const g = svgEl("g", { class: "pt-group", style: "animation-delay:" + (0.5 + i * 0.18) + "s" });
    g.appendChild(svgEl("circle", { cx: pts[i].x, cy: pts[i].y, r: 7, class: "pt pt-" + scoreLevel(s.score) }));
    const v = svgEl("text", { x: pts[i].x, y: pts[i].y - 15, "text-anchor": "middle", class: "val" });
    v.textContent = s.score;
    g.appendChild(v);
    svg.appendChild(g);
    const d = svgEl("text", { x: pts[i].x, y: H - 14, "text-anchor": "middle", class: "axis" });
    d.textContent = s.date;
    svg.appendChild(d);
  });

  $("chart-wrap").replaceChildren(svg);

  // Mini-statistici lângă grafic
  const last = scans[scans.length - 1], prev = scans[scans.length - 2];
  const best = Math.max.apply(null, scans.map((s) => s.score));
  const delta = prev ? last.score - prev.score : 0;
  const stats = $("chart-stats");
  stats.replaceChildren();
  const add = (labelKey, valueNode) => {
    const li = el("li");
    li.appendChild(el("span", "cs-label", t(labelKey)));
    li.appendChild(valueNode);
    stats.appendChild(li);
  };
  add("chartLatest", el("span", "pill score-" + scoreLevel(last.score), String(last.score)));
  add("chartBest", el("span", "cs-value", String(best)));
  const dEl = el("span", "cs-value " + (delta > 0 ? "better" : delta < 0 ? "worse" : "same"),
    (delta > 0 ? "+" : delta < 0 ? "−" : "") + Math.abs(delta));
  add("chartChange", dEl);
}

// ---------- Comparare: Înainte | ↔ | După ----------
function renderCompareControls(scans) {
  [["cmp-before", "compareA"], ["cmp-after", "compareB"]].forEach(([id, key]) => {
    const sel = $(id);
    sel.replaceChildren();
    scans.forEach((s, i) => {
      const o = el("option", "", s.file + " · " + s.date);
      o.value = String(i);
      sel.appendChild(o);
    });
    sel.value = String(state[key]);
    if (!sel.value || !Array.from(sel.options).some((option) => option.value === sel.value)) {
      state[key] = scans[0] ? scans[0].id : "";
      sel.value = String(state[key]);
    }
    sel.dispatchEvent(new Event("dd-refresh"));
  });
}

function fillPanel(bodyId, scan) {
  const body = $(bodyId);
  body.replaceChildren();
  const top = el("div", "panel-score");
  top.appendChild(el("span", "panel-score-label", t("compareScore")));
  const num = el("span", "panel-score-num score-" + scoreLevel(scan.score), "0");
  top.appendChild(num);
  top.appendChild(el("span", "panel-score-max", "/100"));
  body.appendChild(top);
  const bar = el("div", "panel-bar");
  const fill = el("span", "panel-bar-fill score-" + scoreLevel(scan.score));
  fill.style.width = Math.max(0, Math.min(100, scan.score)) + "%";
  bar.appendChild(fill);
  body.appendChild(bar);
  body.appendChild(el("p", "muted panel-date", scan.date));
  const ul = el("ul", "panel-sev");
  SEVERITIES.forEach((s) => {
    const li = el("li");
    li.appendChild(el("span", "sev-dot sev-" + s.key));
    li.appendChild(el("span", "panel-sev-name", sevName(s.key)));
    li.appendChild(el("strong", "", String(scan[s.key])));
    ul.appendChild(li);
  });
  body.appendChild(ul);
  countUp(num, scan.score, 900);
  return body;
}

function diffSets(a, b) {
  return { added: b.filter((x) => !a.includes(x)), removed: a.filter((x) => !b.includes(x)) };
}

function renderCompare(animate) {
  const scans = getScans();
  const a = scans.find((scan) => scan.id === state.compareA);
  const b = scans.find((scan) => scan.id === state.compareB);
  if (!a || !b) {
    $("panel-before-body").replaceChildren();
    $("panel-after-body").replaceChildren();
    $("diff-grid").replaceChildren();
    return;
  }

  const pb = fillPanel("panel-before-body", a);
  const pa = fillPanel("panel-after-body", b);
  [["panel-before", pb], ["panel-after", pa]].forEach(([id, bodyEl]) => {
    const panel = $(id);
    panel.classList.remove("swing");
    if (animate !== false && !reduceMotion()) {
      void panel.offsetWidth;
      panel.classList.add("swing");
    }
  });

  // Rezumat în cuvinte
  const delta = b.score - a.score;
  const sum = $("compare-summary");
  sum.className = "compare-summary " + (delta > 0 ? "better" : delta < 0 ? "worse" : "same");
  sum.textContent = delta > 0 ? fmt(t("cmpUp"), { n: delta })
    : delta < 0 ? fmt(t("cmpDown"), { n: -delta }) : t("cmpSame");

  if (!state.compareResult || state.compareResult.a !== a.id || state.compareResult.b !== b.id) {
    fetch("/api/compare?a=" + encodeURIComponent(a.id) + "&b=" + encodeURIComponent(b.id))
      .then((response) => {
        if (!response.ok) throw new Error("compare");
        return response.json();
      })
      .then((result) => {
        state.compareResult = { a: a.id, b: b.id, value: result };
        renderCompare(false);
      })
      .catch(() => showMessage("msgReadFail", "error"));
    return;
  }

  const result = state.compareResult.value;
  const pr = {
    added: result.new_findings.map((item) => item.code + " · " + item.ip),
    removed: result.resolved_findings.map((item) => item.code + " · " + item.ip)
  };
  const dv = {
    added: result.new_devices,
    removed: result.removed_devices
  };
  const pt = {
    added: result.opened_ports.map((item) => item.ip + ":" + item.port),
    removed: result.closed_ports.map((item) => item.ip + ":" + item.port)
  };
  const groups = [
    { title: "dResolved", tone: "good", items: pr.removed },
    { title: "dNewProblems", tone: "bad", items: pr.added },
    { title: "dNewDevices", tone: "info", items: dv.added },
    { title: "dGoneDevices", tone: "warn", items: dv.removed },
    { title: "dOpenedPorts", tone: "bad", items: pt.added.map(portLabel) },
    { title: "dClosedPorts", tone: "good", items: pt.removed.map(portLabel) }
  ];

  state.diffGroups = groups;
  if (state.diffTab == null || state.diffTab >= groups.length) state.diffTab = 0;
  renderDiffViewer();
}

function renderDiffViewer() {
  const groups = state.diffGroups || [];
  const host = $("diff-grid");
  host.replaceChildren();
  if (groups.length === 0) return;
  const nav = el("div", "diff-nav");
  nav.setAttribute("role", "tablist");
  groups.forEach((g, n) => {
    const b = el("button", "diff-tab tone-" + g.tone + (n === state.diffTab ? " active" : ""));
    b.type = "button";
    b.setAttribute("role", "tab");
    b.setAttribute("aria-selected", n === state.diffTab ? "true" : "false");
    b.appendChild(el("span", "diff-tab-name", t(g.title)));
    b.appendChild(el("span", "diff-tab-count", String(g.items.length)));
    b.addEventListener("click", () => { state.diffTab = n; renderDiffViewer(); });
    nav.appendChild(b);
  });
  host.appendChild(nav);

  const g = groups[state.diffTab];
  const pane = el("div", "diff-pane tone-" + g.tone);
  pane.setAttribute("role", "tabpanel");
  const head = el("div", "diff-pane-head");
  const prev = el("button", "diff-step", "‹");
  prev.type = "button";
  prev.setAttribute("aria-label", state.lang === "en" ? "Previous" : "Înapoi");
  prev.disabled = state.diffTab === 0;
  prev.addEventListener("click", () => { state.diffTab--; renderDiffViewer(); });
  const next = el("button", "diff-step", "›");
  next.type = "button";
  next.setAttribute("aria-label", state.lang === "en" ? "Next" : "Înainte");
  next.disabled = state.diffTab === groups.length - 1;
  next.addEventListener("click", () => { state.diffTab++; renderDiffViewer(); });
  head.appendChild(el("h3", "", t(g.title)));
  head.appendChild(el("span", "diff-pos", (state.diffTab + 1) + " / " + groups.length));
  head.appendChild(prev);
  head.appendChild(next);
  pane.appendChild(head);
  if (g.items.length === 0) {
    pane.appendChild(el("p", "muted", t("dNothing")));
  } else {
    const ul = el("ul", "diff-list");
    g.items.forEach((it) => ul.appendChild(el("li", "", it)));
    pane.appendChild(ul);
  }
  host.appendChild(pane);
}

// ---------- Fereastra mică (probleme după gravitate) ----------
const dialog = $("sev-dialog");

function openDialog(sevKey) {
  state.dialogSev = sevKey;
  renderDialog();
  if (!dialog.open) dialog.showModal();
}

function renderDialog() {
  if (!state.dialogSev) return;
  const items = getProblems()
    .map((p, i) => ({ p, i }))
    .filter((x) => x.p.level === state.dialogSev);
  $("dialog-title").textContent = sevName(state.dialogSev) + " · " + items.length;
  const list = $("dialog-list");
  list.replaceChildren();
  items.forEach((x) => {
    const li = problemRow(x.p, x.i);
    li.querySelector("a").addEventListener("click", () => dialog.close());
    list.appendChild(li);
  });
}

function closeDialog() { if (dialog.open) dialog.close(); }
dialog.addEventListener("close", () => { state.dialogSev = null; });
dialog.addEventListener("click", (e) => { if (e.target === dialog) closeDialog(); });
$("dialog-close").addEventListener("click", closeDialog);

// ---------- Confirmare: șterge tot istoricul ----------
const confirmDialog = $("confirm-dialog");
$("btn-clear").addEventListener("click", () => confirmDialog.showModal());
$("confirm-cancel").addEventListener("click", () => confirmDialog.close());
confirmDialog.addEventListener("click", (e) => { if (e.target === confirmDialog) confirmDialog.close(); });
$("confirm-ok").addEventListener("click", () => {
  confirmDialog.close();
  showMessage("msgLoading", "loading");
  fetch("/api/history", { method: "DELETE" })
    .then((response) => {
      if (!response.ok) throw new Error("history");
      state.scans = [];
      state.currentScanId = null;
      state.compareResult = null;
      state.cleared = true;
      state.ui = "empty";
      applyTexts();
      showMessage("msgCleared");
    })
    .catch(() => showMessage("msgReadFail", "error"));
});

// ---------- Detaliu problemă ----------
function renderProblem() {
  const box = $("problem-detail");
  box.replaceChildren();
  if (state.problem === null) return;
  const p = getProblems()[state.problem];
  if (!p) {
    box.className = "card detail";
    box.appendChild(el("p", "muted", t("notFound")));
    return;
  }
  box.className = "card detail sev-" + p.level;
  box.appendChild(pill(p.level));
  box.appendChild(el("h1", "", p.desc));
  box.appendChild(el("p", "muted", location_(p)));

  const grid = el("dl", "detail-grid");
  [
    ["detailDevice", p.device],
    ["detailIp", p.ip],
    ["detailLevel", sevName(p.level)]
  ].forEach(([label, value]) => {
    const d = el("div");
    d.appendChild(el("dt", "", t(label)));
    d.appendChild(el("dd", "", value));
    grid.appendChild(d);
  });
  box.appendChild(grid);

  box.appendChild(el("p", "", p.detail));
  const fix = el("div", "fix");
  fix.appendChild(el("h2", "", t("detailFix")));
  const ol = el("ol", "steps");
  p.steps.forEach((s) => ol.appendChild(el("li", "", s)));
  fix.appendChild(ol);
  box.appendChild(fix);
}

// ---------- Mesaje ----------
const msgBox = $("messages");
const msgText = $("messages-text");
let msgTimer = null;

function showMessage(key, kind) {
  msgText.textContent = t(key);
  msgBox.hidden = false;
  msgBox.classList.toggle("error", kind === "error");
  msgBox.setAttribute("role", kind === "error" ? "alert" : "status");
  clearTimeout(msgTimer);
  if (kind !== "loading" && kind !== "error") msgTimer = setTimeout(hideMessage, 4000);
}

function hideMessage() {
  msgBox.hidden = true;
  msgText.textContent = "";
}

// ---------- Pagini ----------
const mainEl = $("main");

function showView(view) {
  state.view = view;
  ["home", "history", "problem"].forEach((v) => {
    $("view-" + v).hidden = v !== view;
  });
  const navView = view === "problem" ? "home" : view;
  document.querySelectorAll(".nav-btn").forEach((btn) => {
    const active = btn.dataset.view === navView;
    btn.classList.toggle("active", active);
    if (active) btn.setAttribute("aria-current", "page");
    else btn.removeAttribute("aria-current");
  });
  window.scrollTo(0, 0);
  mainEl.focus({ preventScroll: true }); // cititoarele de ecran și tastatura încep de sus

  if (view === "home") animateScore();
  if (view === "history" && !$("history-content").hidden) {
    renderChart(getScans());   // regenerat, ca să se vadă animația la fiecare intrare
    renderCompare(true);
  }
}

function goTo(view) {
  state.problem = null;
  if (location.hash) history.pushState(null, "", location.pathname + location.search);
  showView(view);
}

// Adresa #problem-N deschide pagina problemei
function route() {
  const m = location.hash.match(/^#problem-(\d+)$/);
  if (m) {
    state.problem = Number(m[1]);
    renderProblem();
    showView("problem");
  } else {
    state.problem = null;
    showView(state.view === "problem" ? "home" : state.view);
  }
}
window.addEventListener("hashchange", route);

// ---------- Bara laterală: închidere / deschidere din siglă ----------
const appBox = document.querySelector(".app");
const toggleBtn = $("btn-toggle");

function updateToggle() {
  const collapsed = appBox.classList.contains("collapsed");
  toggleBtn.setAttribute("aria-expanded", String(!collapsed));
  toggleBtn.setAttribute("aria-label", t(collapsed ? "menuExpand" : "menuCollapse"));
  toggleBtn.title = toggleBtn.getAttribute("aria-label");
}

try {
  if (localStorage.getItem("sidebarCollapsed") === "1") appBox.classList.add("collapsed");
} catch (e) { /* fără stocare: rămâne deschisă */ }

toggleBtn.addEventListener("click", () => {
  appBox.classList.toggle("collapsed");
  updateToggle();
  try {
    localStorage.setItem("sidebarCollapsed", appBox.classList.contains("collapsed") ? "1" : "0");
  } catch (e) { /* ignorat */ }
});

// ---------- Evenimente ----------
document.querySelectorAll(".nav-btn").forEach((btn) => {
  btn.addEventListener("click", () => goTo(btn.dataset.view));
});
$("back-btn").addEventListener("click", () => goTo("home"));

$("skip-link").addEventListener("click", (e) => {
  e.preventDefault();
  mainEl.focus();
});

// „Vezi toate problemele” derulează la secțiunea cu probleme (fără să schimbe pagina)
$("see-all").addEventListener("click", (e) => {
  e.preventDefault();
  const target = $("problems");
  target.scrollIntoView({ behavior: reduceMotion() ? "auto" : "smooth", block: "start" });
  target.focus({ preventScroll: true });
});

const fileInput = $("file-input");
function pickFile() { fileInput.click(); }
$("btn-import").addEventListener("click", pickFile);
document.querySelectorAll('[data-action="import"]').forEach((b) => b.addEventListener("click", pickFile));
fileInput.addEventListener("change", () => {
  const f = fileInput.files && fileInput.files[0];
  fileInput.value = "";
  if (!f) return;
  if (!/\.xml$/i.test(f.name)) { showMessage("msgBadFile", "error"); return; }
  showMessage("msgLoading", "loading");
  const reader = new FileReader();
  reader.onerror = () => showMessage("msgReadFail", "error");
  reader.onload = () => {
    try {
      const doc = new DOMParser().parseFromString(String(reader.result), "application/xml");
      if (doc.querySelector("parsererror")) throw new Error("xml");
      fetch("/api/import?filename=" + encodeURIComponent(f.name), {
        method: "POST",
        headers: { "Content-Type": "application/xml" },
        body: String(reader.result)
      })
        .then((response) => {
          if (!response.ok) throw new Error("import");
          return loadData(false);
        })
        .then(() => showMessage("msgImported"))
        .catch(() => showMessage("msgReadFail", "error"));
    } catch (e) {
      showMessage("msgBadFile", "error");
    }
  };
  reader.readAsText(f);
});

$("btn-lang").addEventListener("click", () => {
  state.lang = state.lang === "ro" ? "en" : "ro";
  applyTexts();
  showMessage("msgLang");
});

$("messages-close").addEventListener("click", hideMessage);

// Căutare și filtru: se actualizează doar lista (câmpul își păstrează focusul)
$("search").addEventListener("input", (e) => {
  state.search = e.target.value;
  renderProblemList();
});
$("sev-filter").addEventListener("change", (e) => {
  state.sevFilter = e.target.value;
  renderProblemList();
});

// Compararea a două scanări
$("cmp-before").addEventListener("change", (e) => { state.compareA = Number(e.target.value); state.compareResult = null; renderCompare(true); });
$("cmp-after").addEventListener("change", (e) => { state.compareB = Number(e.target.value); state.compareResult = null; renderCompare(true); });
$("scan-select").addEventListener("change", (e) => {
  state.currentScanId = Number(e.target.value);
  renderHome();
});

// ---------- Liste derulante personalizate ----------
function enhanceSelect(sel) {
  const wrap = el("div", "dd");
  sel.parentNode.insertBefore(wrap, sel);
  wrap.appendChild(sel);
  sel.classList.add("dd-native");
  sel.tabIndex = -1;
  sel.setAttribute("aria-hidden", "true");
  const btn = el("button", "dd-btn");
  btn.type = "button";
  btn.setAttribute("aria-haspopup", "listbox");
  btn.setAttribute("aria-expanded", "false");
  const label = el("span", "dd-label");
  btn.appendChild(label);
  const chev = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  chev.setAttribute("aria-hidden", "true");
  chev.innerHTML = '<use href="#i-chevron-down"/>';
  btn.appendChild(chev);
  const menu = el("ul", "dd-menu");
  menu.setAttribute("role", "listbox");
  menu.hidden = true;
  wrap.appendChild(btn);
  wrap.appendChild(menu);
  const lbl = document.querySelector('label[for="' + sel.id + '"]');
  if (lbl) lbl.addEventListener("click", (e) => { e.preventDefault(); btn.focus(); });

  function refresh() {
    const o = sel.options[sel.selectedIndex];
    label.textContent = o ? o.textContent : "";
    menu.replaceChildren();
    Array.from(sel.options).forEach((opt) => {
      const on = opt.value === sel.value;
      const li = el("li", "dd-opt" + (on ? " selected" : ""));
      li.setAttribute("role", "option");
      li.setAttribute("aria-selected", on ? "true" : "false");
      li.dataset.value = opt.value;
      if (SEVERITIES.some((s) => s.key === opt.value)) li.appendChild(el("span", "sev-dot sev-" + opt.value));
      li.appendChild(el("span", "dd-opt-text", opt.textContent));
      li.appendChild(el("span", "dd-check", on ? "✓" : ""));
      menu.appendChild(li);
    });
  }
  function close() { menu.hidden = true; btn.setAttribute("aria-expanded", "false"); wrap.classList.remove("open"); }
  function open() {
    refresh();
    menu.hidden = false; btn.setAttribute("aria-expanded", "true"); wrap.classList.add("open");
    const cur = menu.querySelector(".selected");
    if (cur) cur.scrollIntoView({ block: "nearest" });
  }
  function choose(v) {
    sel.value = v;
    sel.dispatchEvent(new Event("change", { bubbles: true }));
    refresh(); close(); btn.focus();
  }
  btn.addEventListener("click", () => (menu.hidden ? open() : close()));
  menu.addEventListener("click", (e) => {
    const li = e.target.closest(".dd-opt");
    if (li) choose(li.dataset.value);
  });
  wrap.addEventListener("keydown", (e) => {
    if (e.key === "Escape") { close(); btn.focus(); }
    else if (e.key === "ArrowDown" || e.key === "ArrowUp") {
      e.preventDefault();
      if (menu.hidden) { open(); return; }
      const idx = Array.from(sel.options).findIndex((o) => o.value === sel.value);
      const n = Math.max(0, Math.min(sel.options.length - 1, idx + (e.key === "ArrowDown" ? 1 : -1)));
      sel.value = sel.options[n].value;
      sel.dispatchEvent(new Event("change", { bubbles: true }));
      refresh();
    }
  });
  document.addEventListener("click", (e) => { if (!wrap.contains(e.target)) close(); });
  sel.addEventListener("dd-refresh", refresh);
  refresh();
}
["scan-select", "sev-filter", "cmp-before", "cmp-after"].forEach((id) => enhanceSelect($(id)));

applyTexts();
route();

function findingModel(finding, devices) {
  const device = devices.find((item) => item.ip === finding.ip);
  const name = device && (device.hostname || device.vendor);
  return {
    code: finding.code,
    desc: finding.evidence || finding.code,
    ip: finding.ip,
    port: finding.port,
    points: finding.points,
    level: finding.severity,
    device: name || finding.ip,
    detail: finding.evidence || finding.code,
    first: finding.evidence || finding.code,
    steps: []
  };
}

function deviceModel(device) {
  const kind = String(device.device_type || "unknown").toLowerCase();
  return {
    kind: ["router", "camera", "printer", "laptop", "tv", "phone"].includes(kind) ? kind : "unknown",
    ip: device.ip,
    type: device.device_type || "unknown",
    name: device.hostname || device.vendor || device.ip,
    vendor: device.vendor || "",
    mac: device.mac_masked || "",
    ports: (device.ports || []).map((port) => ({
      port: port.port,
      service: port.service || "",
      protocol: port.protocol || "",
      product: port.product || "",
      version: port.version || ""
    }))
  };
}

function scanModel(summary, detail) {
  const findings = detail.findings || [];
  const devices = (detail.devices || []).map(deviceModel);
  const counts = { high: 0, medium: 0, low: 0, info: 0 };
  findings.forEach((finding) => {
    if (counts[finding.severity] !== undefined) counts[finding.severity]++;
  });
  return {
    id: summary.id,
    file: summary.file,
    date: new Date(summary.scanned_at).toLocaleString(state.lang),
    score: detail.network_score,
    high: counts.high,
    medium: counts.medium,
    low: counts.low,
    info: counts.info,
    problems: findings.map((finding) => findingModel(finding, devices)),
    devices,
    ports: devices.flatMap((device) => device.ports.map((port) => device.ip + ":" + port.port))
  };
}

async function loadData(showLoading) {
  if (showLoading) showMessage("msgLoading", "loading");
  const response = await fetch("/api/scans");
  if (!response.ok) throw new Error("scans");
  const summaries = await response.json();
  const details = await Promise.all(summaries.map((summary) =>
    fetch("/api/scans/" + encodeURIComponent(summary.id)).then((item) => {
      if (!item.ok) throw new Error("scan");
      return item.json();
    })
  ));
  state.scans = summaries.map((summary, index) => scanModel(summary, details[index]));
  state.currentScanId = state.scans.length ? state.scans[state.scans.length - 1].id : null;
  state.cleared = state.scans.length === 0;
  state.ui = state.scans.length ? "normal" : "empty";
  if (state.scans.length) {
    state.compareA = state.scans[Math.max(0, state.scans.length - 2)].id;
    state.compareB = state.scans[state.scans.length - 1].id;
  }
  state.compareResult = null;
  applyTexts();
}

loadData(true).catch(() => {
  state.ui = "error";
  applyTexts();
  showMessage("msgReadFail", "error");
});
