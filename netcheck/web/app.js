"use strict";

const params = new URLSearchParams(location.search);
const state = {
  lang: params.get("lang") === "en" ? "en" : "ro",
  view: "home",
  scans: [],
  currentScanId: null,
  panel: "list",
  selectedIp: null,
  messageTimer: null,
  chatMessages: []
};

const SEVERITIES = ["high", "medium", "low", "info"];
const $ = (id) => document.getElementById(id);
const text = (key, fallback) => (TEXTS[state.lang] && TEXTS[state.lang][key]) || fallback || key;
const icon = (id) => {
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("aria-hidden", "true");
  const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
  use.setAttribute("href", "#" + id);
  svg.appendChild(use);
  return svg;
};
const node = (tag, className, value) => {
  const element = document.createElement(tag);
  if (className) element.className = className;
  if (value !== undefined) element.textContent = value;
  return element;
};

function currentScan() {
  return state.scans.find((scan) => scan.id === state.currentScanId) || state.scans[state.scans.length - 1] || null;
}

function severityRank(severity) {
  return { high: 3, medium: 2, low: 1, info: 0 }[severity] || 0;
}

function findings(scan) {
  return (scan && scan.findings ? scan.findings : []).slice().sort((a, b) =>
    severityRank(b.severity) - severityRank(a.severity) || String(a.ip).localeCompare(String(b.ip)));
}

function deviceForIp(ip, scan = currentScan()) {
  return (scan && scan.devices ? scan.devices : []).find((device) => device.ip === ip) || null;
}

function deviceType(device) {
  const key = device && device.device_type ? device.device_type : "unknown";
  return text(key, key);
}

function severityLabel(severity) {
  return text(severity, severity);
}

function localized(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value[state.lang] : value;
}

function findingTitle(finding) {
  return localized(finding.title) || finding.code || text("vulnerabilities", "Vulnerability");
}

function maskMac(value) {
  if (!value) return "";
  if (value.includes("*")) return value;
  return value.split(":").slice(0, 3).join(":") + ":**:**:**";
}

function announce(message, kind = "info") {
  const box = $("messages");
  box.className = "message " + kind;
  box.textContent = message;
  box.hidden = false;
  clearTimeout(state.messageTimer);
  state.messageTimer = setTimeout(() => { box.hidden = true; }, 5000);
}

function setLanguage(lang) {
  state.lang = lang;
  state.chatMessages = [];
  state.chatRequest = (state.chatRequest || 0) + 1;
  try { localStorage.setItem("netcheck-language", lang); } catch (error) { /* storage is optional */ }
  render();
}

function loadLanguage() {
  try {
    const saved = localStorage.getItem("netcheck-language");
    if (saved === "ro" || saved === "en") state.lang = saved;
  } catch (error) { /* storage is optional */ }
}

function applyStaticText() {
  document.documentElement.lang = state.lang;
  document.querySelectorAll("[data-i18n]").forEach((element) => {
    element.textContent = text(element.dataset.i18n);
  });
  document.querySelectorAll("[data-i18n-aria]").forEach((element) => {
    element.setAttribute("aria-label", text(element.dataset.i18nAria));
  });
  $("lang-ro").classList.toggle("active", state.lang === "ro");
  $("lang-en").classList.toggle("active", state.lang === "en");
}

function renderScore(scan) {
  const score = scan && scan.status === "ok" ? Number(scan.network_score) : 100;
  $("score-number").textContent = String(score);
  $("score-label").textContent = text(score >= 70 ? "scoreGood" : score >= 50 ? "scoreMedium" : "scoreBad");
  $("score-ring").className = "ring score-" + (score >= 70 ? "good" : score >= 50 ? "medium" : "bad");
  $("score-ring").setAttribute("aria-label", (text("scoreTitle", "Network score") + ": " + score + " / 100"));
  const counts = Object.fromEntries(SEVERITIES.map((severity) => [severity, 0]));
  findings(scan).forEach((finding) => { if (counts[finding.severity] !== undefined) counts[finding.severity] += 1; });
  const list = $("sev-list");
  list.replaceChildren();
  SEVERITIES.forEach((severity) => {
    const item = node("li", "severity-item sev-" + severity);
    item.append(icon(severity === "high" ? "i-shield-x" : severity === "medium" ? "i-shield-alert" : "i-shield"));
    item.append(node("span", "", severityLabel(severity)));
    item.append(node("strong", "", String(counts[severity])));
    list.append(item);
  });
}

function graphPosition(index, total, width, height) {
  if (index === 0) return { x: width / 2, y: height / 2 };
  const angle = ((index - 1) / Math.max(1, total - 1)) * Math.PI * 2 - Math.PI / 2;
  return { x: width / 2 + Math.cos(angle) * Math.min(width, height) * 0.34, y: height / 2 + Math.sin(angle) * Math.min(width, height) * 0.34 };
}

function renderGraph(scan) {
  const container = $("network-graph");
  container.replaceChildren();
  const devices = scan && scan.devices ? scan.devices : [];
  const width = 720;
  const height = 420;
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 " + width + " " + height);
  svg.setAttribute("role", "group");
  svg.setAttribute("aria-label", text("networkTitle", "Device map"));
  const center = devices.findIndex((device) => device.device_type === "router");
  const ordered = center >= 0 ? [devices[center], ...devices.filter((_, index) => index !== center)] : devices;
  const positions = ordered.map((_, index) => graphPosition(index, ordered.length, width, height));
  positions.slice(1).forEach((position) => {
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", String(positions[0].x)); line.setAttribute("y1", String(positions[0].y));
    line.setAttribute("x2", String(position.x)); line.setAttribute("y2", String(position.y));
    line.setAttribute("class", "graph-link"); svg.append(line);
  });
  const riskByIp = {};
  findings(scan).forEach((finding) => {
    if (!riskByIp[finding.ip] || severityRank(finding.severity) > severityRank(riskByIp[finding.ip])) riskByIp[finding.ip] = finding.severity;
  });
  ordered.forEach((device, index) => {
    const position = positions[index];
    const group = document.createElementNS("http://www.w3.org/2000/svg", "g");
    const severity = riskByIp[device.ip] || "info";
    group.setAttribute("class", "graph-node sev-" + severity);
    group.setAttribute("role", "button");
    group.setAttribute("tabindex", "0");
    group.setAttribute("aria-label", device.ip + ", " + deviceType(device) + ", " + severityLabel(severity));
    group.addEventListener("click", () => openDevice(device.ip));
    group.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); openDevice(device.ip); }
    });
    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", String(position.x)); circle.setAttribute("cy", String(position.y)); circle.setAttribute("r", index === 0 ? "48" : "38");
    group.append(circle);
    const label = document.createElementNS("http://www.w3.org/2000/svg", "text");
    label.setAttribute("x", String(position.x)); label.setAttribute("y", String(position.y + 66));
    label.setAttribute("text-anchor", "middle"); label.textContent = device.ip;
    group.append(label);
    svg.append(group);
  });
  if (!devices.length) container.append(node("p", "muted", text("emptyText", "Import a scan to see devices.")));
  else container.append(svg);
  const list = $("device-list"); list.replaceChildren();
  devices.forEach((device) => {
    const button = node("button", "button", device.ip + " · " + deviceType(device));
    button.type = "button";
    button.addEventListener("click", () => openDevice(device.ip));
    list.append(button);
  });
}

function renderInspector(scan) {
  const panel = $("panel-content");
  panel.replaceChildren();
  const allFindings = findings(scan);
  if (state.panel === "chat") return renderChat(panel, scan);
  if (state.panel === "detail" && state.selectedIp) return renderDeviceDetail(panel, scan, state.selectedIp);
  const heading = node("h2", "", text("vulnerabilities", "Vulnerabilities"));
  heading.id = "panel-title"; panel.append(heading);
  if (!allFindings.length) {
    panel.append(node("p", "empty-panel", text("cleanText", "No known vulnerabilities were found.")));
    return;
  }
  const first = allFindings[0];
  const priority = node("article", "priority-card sev-" + first.severity);
  priority.append(node("span", "kicker", text("priority", "Most dangerous")));
  priority.append(node("h3", "", findingTitle(first)));
  priority.append(node("p", "", (text("firstStep", "First step") + ": " + ((first.fix && localized(first.fix)[0]) || text("noAdvice", "No remediation step.")))));
  priority.append(node("p", "muted", first.ip));
  panel.append(priority);
  const list = node("ul", "finding-list");
  allFindings.forEach((finding) => {
    const item = node("li", "finding-item sev-" + finding.severity);
    const button = node("button", "finding-button");
    button.type = "button"; button.append(icon("i-warning")); button.append(node("span", "", findingTitle(finding)));
    button.append(node("small", "", finding.ip + (finding.port ? ":" + finding.port : "")));
    button.addEventListener("click", () => openDevice(finding.ip));
    item.append(button); list.append(item);
  });
  panel.append(list);
}

function renderDeviceDetail(panel, scan, ip) {
  const device = deviceForIp(ip, scan);
  const back = node("button", "back-button", "‹ " + text("back", "Back"));
  back.type = "button"; back.addEventListener("click", () => { state.panel = "list"; render(); focusPanel(); });
  panel.append(back);
  const heading = node("h2", "", text("deviceDetails", "Device details"));
  heading.id = "panel-title"; panel.append(heading);
  if (!device) return;
  panel.append(node("p", "device-ip", device.ip));
  const details = node("dl", "device-facts");
  [["type", deviceType(device)], ["mac", maskMac(device.mac_masked)].filter(Boolean)].forEach(([key, value]) => {
    details.append(node("dt", "", text(key, key))); details.append(node("dd", "", value));
  });
  panel.append(details);
  panel.append(node("h3", "subheading", text("vulnerabilities", "Vulnerabilities")));
  const deviceFindings = findings(scan).filter((finding) => finding.ip === ip);
  deviceFindings.forEach((finding) => {
    const article = node("article", "detail-finding sev-" + finding.severity);
    article.append(node("h4", "", findingTitle(finding)));
    article.append(node("p", "", localized(finding.explain) || text("catalogMissing", "Explanation unavailable.")));
    if (finding.fix && localized(finding.fix).length) {
      const steps = node("ol", "steps");
      localized(finding.fix).forEach((step) => steps.append(node("li", "", step)));
      article.append(steps);
    }
    panel.append(article);
  });
  if (!deviceFindings.length) panel.append(node("p", "muted", text("noDeviceFindings", "No findings for this device.")));
  const ask = node("button", "button primary");
  ask.type = "button"; ask.append(icon("i-shield")); ask.append(node("span", "", text("askAI", "Ask AI")));
  ask.addEventListener("click", () => { state.panel = "chat"; render(); focusPanel(); });
  panel.append(ask);
}

function renderChat(panel, scan) {
  const back = node("button", "back-button", "‹ " + text("back", "Back"));
  back.type = "button"; back.addEventListener("click", () => { state.panel = "list"; render(); focusPanel(); });
  panel.append(back);
  const heading = node("h2", "", text("chatTitle", "Explanations for you"));
  heading.id = "panel-title"; panel.append(heading);
  panel.append(node("p", "privacy-note", text("chatNotice", "AI is not connected yet. Local explanations remain available.")));
  const context = node("p", "context-chip");
  context.textContent = state.selectedIp ? text("device", "Device") + ": " + state.selectedIp : text("networkTitle", "Device map");
  panel.append(context);
  const log = node("div", "chat-log");
  log.setAttribute("role", "log");
  log.setAttribute("aria-live", "polite");
  const pending = state.chatMessages.some((message) => message.pending);
  state.chatMessages.forEach((message) => {
    const item = node("article", "chat-message " + message.role);
    item.append(node("strong", "", message.role === "user" ? text("you") : text("assistant", "Asistent")));
    if (message.mode) {
      item.append(node("span", "chat-mode", message.mode === "ai"
        ? text("aiAnswer", "Asistent AI")
        : text("docAnswer", "Răspuns din documentație")));
    }
    item.append(node("p", "", message.text));
    if (message.sources && message.sources.length) {
      const sources = node("p", "chat-sources", text("sources", "Sources") + ": " +
        message.sources.map((source) => source.title || source.id).join(", "));
      item.append(sources);
    }
    log.append(item);
  });
  panel.append(log);
  const questions = node("div", "chat-questions");
  [text("chatQuestion", "What do the results mean?"), text("chatSteps", "Where do I start?")].forEach((question) => {
    const button = node("button", "button", question); button.type = "button";
    button.disabled = pending;
    button.addEventListener("click", () => askLearning(scan, question));
    questions.append(button);
  });
  panel.append(questions);
  const form = node("form", "chat-form");
  const input = node("input");
  input.type = "text"; input.disabled = pending; input.required = true; input.maxLength = 500;
  input.placeholder = text("chatPlaceholder", "Ask about this scan");
  input.setAttribute("aria-label", text("chatPlaceholder", "Ask about this scan"));
  const submit = node("button", "button primary", text("send", "Send"));
  submit.type = "submit"; submit.disabled = pending;
  form.append(input, submit);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    askLearning(scan, input.value);
  });
  panel.append(form);
}

async function askLearning(scan, question) {
  const value = question.trim();
  if (!value || !scan || state.chatMessages.some((message) => message.pending)) return;
  const requestId = state.chatRequest = (state.chatRequest || 0) + 1;
  const scanId = scan.id, deviceIp = state.selectedIp, lang = state.lang;
  state.chatMessages.push({ role: "user", text: value });
  state.chatMessages.push({ role: "assistant", pending: true, text: text("loading", "Loading…") });
  render(); focusPanel();
  try {
    const response = await fetch("/api/ask", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        scan_id: scanId,
        device_ip: deviceIp,
        question: value,
        lang
      })
    });
    if (!response.ok) throw new Error("ask");
    const result = await response.json();
    if (requestId !== state.chatRequest) return;
    state.chatMessages[state.chatMessages.length - 1] = {
      role: "assistant",
      text: result.answer,
      sources: result.sources,
      mode: result.mode
    };
  } catch (error) {
    if (requestId !== state.chatRequest) return;
    state.chatMessages[state.chatMessages.length - 1] = {
      role: "assistant",
      text: text("chatError", "The assistant could not answer right now.")
    };
  }
  render();
  if (state.view === "home" && state.panel === "chat") focusPanel();
}

function renderHome() {
  const scan = currentScan();
  const selector = $("scan-select");
  selector.replaceChildren();
  state.scans.forEach((item) => {
    const option = node("option", "", item.file || text("noScans", "No scans"));
    option.value = String(item.id);
    selector.append(option);
  });
  selector.value = state.currentScanId == null ? "" : String(state.currentScanId);
  $("home-content").hidden = !scan || scan.status !== "ok";
  $("empty-state").hidden = Boolean(scan);
  $("scan-error").hidden = !scan || scan.status === "ok";
  renderScore(scan); renderGraph(scan); renderInspector(scan);
}

function renderHistory() {
  const list = $("history-list"); list.replaceChildren();
  $("history-empty").hidden = state.scans.length > 0;
  $("history-content").hidden = state.scans.length === 0;
  $("btn-clear").hidden = state.scans.length === 0;
  state.scans.slice().reverse().forEach((scan) => {
    const item = node("li", "history-row");
    item.append(node("strong", "", scan.file || text("invalidScan", "Invalid file")));
    item.append(node("span", "", scan.scanned_at ? new Date(scan.scanned_at).toLocaleString(state.lang) : ""));
    item.append(node("b", "", scan.network_score == null ? "—" : String(scan.network_score)));
    list.append(item);
  });
  renderChart();
  renderComparisonPickers();
}

function renderComparisonPickers() {
  const valid = state.scans.filter((scan) => scan.status === "ok");
  ["cmp-before", "cmp-after"].forEach((id, index) => {
    const select = $(id), previous = select.value;
    select.replaceChildren();
    valid.forEach((scan) => {
      const option = node("option", "", scan.file + " (#" + scan.id + ")");
      option.value = String(scan.id); select.append(option);
    });
    select.value = valid.some((scan) => String(scan.id) === previous)
      ? previous : valid.length ? String(valid[index ? valid.length - 1 : 0].id) : "";
  });
  updateComparison();
}

async function updateComparison() {
  const before = $("cmp-before").value, after = $("cmp-after").value;
  const request = state.comparisonRequest = (state.comparisonRequest || 0) + 1;
  const lang = state.lang, box = $("comparison");
  box.replaceChildren();
  if (!before || !after || before === after) {
    box.append(node("p", "muted", text("compareNeed"))); return;
  }
  try {
    const response = await fetch("/api/compare?a=" + before + "&b=" + after);
    if (!response.ok) throw new Error("compare");
    const result = await response.json();
    if (request !== state.comparisonRequest || state.lang !== lang || state.view !== "history") return;
    box.append(node("p", "", text("scoreChange").replace("{before}", result.score_before).replace("{after}", result.score_after)));
    [["resolved", result.resolved_findings], ["added", result.new_findings]].forEach(([key, values]) => {
      box.append(node("h3", "subheading", text(key)));
      const list = node("ul");
      values.forEach((finding) => list.append(node("li", "", finding.code + " · " + finding.ip + (finding.port ? ":" + finding.port : ""))));
      if (!values.length) list.append(node("li", "", text("noChanges")));
      box.append(list);
    });
  } catch (error) {
    if (request === state.comparisonRequest && state.lang === lang) box.append(node("p", "", text("compareFailed")));
  }
}

function renderChart() {
  const valid = state.scans.filter((scan) => scan.status === "ok" && Number.isFinite(scan.network_score));
  const wrap = $("chart-wrap"); wrap.replaceChildren();
  if (!valid.length) { wrap.append(node("p", "muted", text("chartEmpty", "No valid scans yet."))); return; }
  const width = 720, height = 220, left = 44, right = 20, top = 24, bottom = 40;
  const x = (index) => left + (valid.length === 1 ? (width - left - right) / 2 : (width - left - right) * index / (valid.length - 1));
  const y = (score) => top + (100 - score) * (height - top - bottom) / 100;
  const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  svg.setAttribute("viewBox", "0 0 " + width + " " + height); svg.setAttribute("role", "img");
  svg.setAttribute("aria-label", text("chartTitle", "Score over time"));
  [0, 50, 100].forEach((score) => {
    const line = document.createElementNS("http://www.w3.org/2000/svg", "line");
    line.setAttribute("x1", String(left)); line.setAttribute("x2", String(width - right));
    line.setAttribute("y1", String(y(score))); line.setAttribute("y2", String(y(score))); line.setAttribute("class", "chart-grid"); svg.append(line);
  });
  const path = valid.map((scan, index) => (index ? "L" : "M") + x(index) + " " + y(scan.network_score)).join(" ");
  const curve = document.createElementNS("http://www.w3.org/2000/svg", "path");
  curve.setAttribute("d", path); curve.setAttribute("class", "chart-line"); svg.append(curve);
  valid.forEach((scan, index) => {
    const circle = document.createElementNS("http://www.w3.org/2000/svg", "circle");
    circle.setAttribute("cx", String(x(index))); circle.setAttribute("cy", String(y(scan.network_score)));
    circle.setAttribute("r", "7"); circle.setAttribute("class", "chart-point");
    circle.setAttribute("aria-label", String(scan.network_score)); svg.append(circle);
  });
  wrap.append(svg);
}

function render() {
  applyStaticText();
  document.querySelectorAll("main > section").forEach((section) => { section.hidden = section.id !== "view-" + state.view; });
  document.querySelectorAll(".nav-btn").forEach((button) => {
    const active = button.dataset.view === state.view; button.classList.toggle("active", active);
    if (active) button.setAttribute("aria-current", "page"); else button.removeAttribute("aria-current");
  });
  if (state.view === "home") renderHome(); else if (state.view === "history") renderHistory();
}

async function loadScans() {
  try {
    const response = await fetch("/api/scans");
    if (!response.ok) throw new Error("scans");
    state.scans = await response.json();
    if (state.scans.length) state.currentScanId = state.scans[state.scans.length - 1].id;
    if (state.scans.length) {
      const detail = await fetch("/api/scans/" + encodeURIComponent(state.currentScanId));
      if (detail.ok) state.scans[state.scans.length - 1] = { ...state.scans[state.scans.length - 1], ...(await detail.json()) };
    }
    render();
  } catch (error) {
    announce(text("loadFailed", "Could not load scans."), "error");
    render();
  }
}

function focusPanel() {
  const panel = $("inspector"); panel.focus({ preventScroll: true });
}

async function importFile(file) {
  if (!file || !/\.xml$/i.test(file.name) || file.size > 10 * 1024 * 1024) {
    announce(text("badFile", "Choose one XML file no larger than 10 MB."), "error"); return;
  }
  try {
    const response = await fetch("/api/import?filename=" + encodeURIComponent(file.name), {
      method: "POST", headers: { "Content-Type": "application/xml" }, body: await file.text()
    });
    if (!response.ok) throw new Error("import");
    const result = await response.json();
    state.scans.push({ id: result.scan_id, ...result, scanned_at: new Date().toISOString() });
    state.chatRequest = (state.chatRequest || 0) + 1;
    state.chatMessages = []; state.selectedIp = null;
    state.currentScanId = result.scan_id; state.view = "home"; state.panel = "list";
    announce(text("imported", "The file was imported.")); render();
  } catch (error) {
    announce(text("importFailed", "Import failed."), "error");
  }
}

function bindEvents() {
  document.querySelectorAll('[data-action="import"]').forEach((button) => button.addEventListener("click", () => {
    state.view = "import"; render(); $("btn-import").focus();
  }));
  ["cmp-before", "cmp-after"].forEach((id) => $(id).addEventListener("change", updateComparison));
  $("lang-ro").addEventListener("click", () => setLanguage("ro"));
  $("lang-en").addEventListener("click", () => setLanguage("en"));
  document.querySelectorAll(".nav-btn").forEach((button) => button.addEventListener("click", () => { state.view = button.dataset.view; render(); }));
  $("scan-select").addEventListener("change", async (event) => {
    state.chatRequest = (state.chatRequest || 0) + 1;
    state.chatMessages = []; state.panel = "list"; state.selectedIp = null;
    state.currentScanId = Number(event.target.value);
    const scanId = state.currentScanId;
    try {
      const response = await fetch("/api/scans/" + scanId);
      if (!response.ok) throw new Error("scan");
      const detail = await response.json();
      state.scans = state.scans.map((scan) => scan.id === scanId ? { ...scan, ...detail } : scan);
      if (state.currentScanId !== scanId) return;
      render(); $("scan-select").focus();
    } catch (error) {
      announce(text("loadFailed"), "error");
    }
  });
  $("btn-import").addEventListener("click", () => $("file-input").click());
  $("file-input").addEventListener("change", (event) => importFile(event.target.files[0]));
  const drop = $("drop-zone");
  ["dragenter", "dragover"].forEach((eventName) => drop.addEventListener(eventName, (event) => { event.preventDefault(); drop.classList.add("dragging"); }));
  ["dragleave", "drop"].forEach((eventName) => drop.addEventListener(eventName, (event) => { event.preventDefault(); drop.classList.remove("dragging"); }));
  drop.addEventListener("drop", (event) => importFile(event.dataTransfer.files[0]));
  $("btn-clear").addEventListener("click", () => $("confirm-dialog").showModal());
  $("confirm-cancel").addEventListener("click", () => $("confirm-dialog").close());
  $("confirm-delete").addEventListener("click", async () => {
    const response = await fetch("/api/history", { method: "DELETE" });
    if (!response.ok) { announce(text("deleteFailed", "Could not clear history."), "error"); return; }
    $("confirm-dialog").close(); state.scans = []; state.currentScanId = null; announce(text("deleted", "History was cleared.")); render();
  });
  $("btn-export").addEventListener("click", () => {
    const scan = currentScan();
    if (scan) window.open("/api/report?a=" + encodeURIComponent(scan.id) + "&lang=" + state.lang, "_blank", "noopener");
    else announce(text("historyEmptyText", "History is empty."));
  });
  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape" && !$("confirm-dialog").open && state.view === "home" && state.panel !== "list") {
      event.preventDefault();
      state.panel = state.panel === "chat" && state.selectedIp ? "detail" : "list"; render(); focusPanel();
    }
  });
}

function openDevice(ip) {
  state.chatRequest = (state.chatRequest || 0) + 1;
  state.selectedIp = ip; state.panel = "detail"; state.chatMessages = []; render(); focusPanel();
}

loadLanguage();
bindEvents();
loadScans();
