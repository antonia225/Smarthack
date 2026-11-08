"""Deterministic local answer used whenever an AI answer is unavailable (NFR-06).

The answer is composed from the saved analysis (score, top risk, devices,
findings) and the bilingual catalog in the requested language. It never calls
the LLM and never recomputes or changes findings, severities or scores; it only
presents what the engine already stored. The knowledge corpus is a secondary
source: only passages in the requested language, trimmed to whole sentences,
and never table-of-contents or reference boilerplate.
"""

from __future__ import annotations

from collections import Counter
import re
from typing import Any

from netcheck.catalog import load_catalog
from . import intent
from .retriever import Passage, passages, search, source_dict


PREFIX = {
    "scan": {
        "ro": "Răspuns din scanare și catalogul local:",
        "en": "Answer from the scan and the local catalog:",
    },
    "docs": {
        "ro": "Răspuns din catalogul și documentația locală:",
        "en": "Answer from the local catalog and documentation:",
    },
}

_SEVERITIES = ("high", "medium", "low", "info")
# Same labels as the web UI (netcheck/web/texts.js).
_SEVERITY_LABEL = {
    "ro": {"high": "ridicată", "medium": "medie", "low": "scăzută", "info": "informativă"},
    "en": {"high": "high", "medium": "medium", "low": "low", "info": "information"},
}
_COUNT_LABEL = {
    "ro": {"high": "Ridicată", "medium": "Medie", "low": "Scăzută", "info": "Informativ"},
    "en": {"high": "High", "medium": "Medium", "low": "Low", "info": "Information"},
}
_TYPE_LABEL = {
    "ro": {"router": "router", "camera": "cameră", "printer": "imprimantă", "nas": "stocare",
           "iot": "obiect smart", "unknown": "tip necunoscut"},
    "en": {"router": "router", "camera": "camera", "printer": "printer", "nas": "storage",
           "iot": "smart object", "unknown": "unknown type"},
}
_IP = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_TOC = re.compile(r"\.{4,}|(?:\.\s){3,}|table of contents|cuprins", re.I)
_BOILERPLATE = re.compile(r"\bISBN\b|\bdoi:|\bRetrieved\b|\bArchived from\b|\^", re.I)
_SENTENCE_SPLIT = re.compile(r"(?<=[.!?])\s+(?=[\"“(]?[A-ZĂÂÎȘŞȚŢ0-9])")

T = {
    "ro": {
        "scan_source": "Scanarea salvată",
        "score": "Scorul rețelei este {score} din 100 ({verdict}).",
        "counts": "Constatări după severitate: {counts}.",
        "score_meaning": "Scorul pornește de la 100 și scade pentru fiecare problemă găsită, mai mult pentru "
                         "cele grave; constatările informative nu îl scad.",
        "disclaimer": "Scorul descrie doar această scanare. Nu garantează că rețeaua e sigură.",
        "good": "scor bun", "medium": "merită atenție", "bad": "are nevoie de atenție",
        "where_port": "{ip}, portul {port}", "port_suffix": ", portul {port}", "severity": "severitate {sev}",
        "device_count": "Dispozitivul {device} are {n}.",
        "device_none": "Scanarea nu a găsit constatări pentru {device}.",
        "network_none": "Scanarea nu a găsit nicio constatare în rețea.",
        "worst": "Cel mai expus dispozitiv este {device}: {title}{port}, {sev}.",
        "worst_more": "Pe acest dispozitiv scanarea a găsit în total {n}.",
        "worst_info": "Toate constatările sunt informative și nu scad scorul.",
        "selected_other": "Dispozitivul selectat, {device}, are {n}; cea mai serioasă: {title} ({sev}).",
        "first_step": "Primul pas: {step}",
        "start": "Începe cu: {title} ({where}), {sev}.",
        "steps": "Pași:",
        "then": "Apoi: {title} ({where}).",
        "fix_more": "Încă {n} au pași în lista de constatări.",
        "nothing_to_fix": "Scanarea nu a găsit nimic de reparat pentru {scope}.",
        "network_scope": "rețea",
        "network_top": "Cea mai importantă constatare din rețea: {title} pe {device}.",
        "ports": "Porturi raportate de scanare:",
        "no_ports": "niciun port raportat",
        "more_devices": "…și încă {n} dispozitive.",
        "sev_high": "Da, merită rezolvat cât mai curând.",
        "sev_medium": "Moderat: merită rezolvat, dar nu e cel mai urgent tip de problemă.",
        "sev_low": "Puțin: cea mai serioasă constatare are severitate scăzută.",
        "sev_info": "Nu pare: constatările sunt doar informative și nu scad scorul.",
        "top_device": "Cea mai serioasă constatare a dispozitivului {device}: {title}{port}, {sev}.",
        "top_network": "Cea mai serioasă constatare din rețea: {title} pe {device}{port}, {sev}.",
        "explain_device": "Pentru {device}, scanarea a găsit {n}:",
        "explain_more": "…și încă {n}.",
        "ask_fix": "Pentru pași de reparare, întreabă „Cum repar?”.",
        "docs_excerpt": "Din documentație ({title}): {text}",
        "no_answer": "Scanarea și catalogul local nu pot răspunde la această întrebare. "
                     "Încearcă: „Care e scorul meu?”, „Cu ce încep?” sau „Cum repar?”.",
        "local_catalog": "Catalog local",
    },
    "en": {
        "scan_source": "Saved scan",
        "score": "The network score is {score} out of 100 ({verdict}).",
        "counts": "Findings by severity: {counts}.",
        "score_meaning": "The score starts at 100 and goes down for each problem found, more for serious "
                         "ones; informational findings do not lower it.",
        "disclaimer": "The score describes this scan only. It does not guarantee the network is safe.",
        "good": "good score", "medium": "worth a look", "bad": "needs attention",
        "where_port": "{ip}, port {port}", "port_suffix": ", port {port}", "severity": "{sev} severity",
        "device_count": "The device {device} has {n}.",
        "device_none": "The scan found no findings for {device}.",
        "network_none": "The scan found no findings on the network.",
        "worst": "The most exposed device is {device}: {title}{port}, {sev}.",
        "worst_more": "On this device the scan found {n} in total.",
        "worst_info": "All findings are informational and do not lower the score.",
        "selected_other": "The selected device, {device}, has {n}; the most serious: {title} ({sev}).",
        "first_step": "First step: {step}",
        "start": "Start with: {title} ({where}), {sev}.",
        "steps": "Steps:",
        "then": "Then: {title} ({where}).",
        "fix_more": "Another {n} have steps in the findings list.",
        "nothing_to_fix": "The scan found nothing to fix for {scope}.",
        "network_scope": "the network",
        "network_top": "The most important finding on the network: {title} on {device}.",
        "ports": "Ports reported by the scan:",
        "no_ports": "no ports reported",
        "more_devices": "…and {n} more devices.",
        "sev_high": "Yes, it is worth fixing soon.",
        "sev_medium": "Moderately: worth fixing, but not the most urgent kind of problem.",
        "sev_low": "A little: the most serious finding has low severity.",
        "sev_info": "It does not look so: the findings are informational and do not lower the score.",
        "top_device": "The most serious finding on {device}: {title}{port}, {sev}.",
        "top_network": "The most serious finding on the network: {title} on {device}{port}, {sev}.",
        "explain_device": "For {device}, the scan found {n}:",
        "explain_more": "…and another {n}.",
        "ask_fix": "For fix steps, ask \"How do I fix it?\".",
        "docs_excerpt": "From the documentation ({title}): {text}",
        "no_answer": "The scan and the local catalog cannot answer that question. "
                     "Try: \"What is my score?\", \"Where do I start?\" or \"How do I fix it?\".",
        "local_catalog": "Local catalog",
    },
}


def _findings_count(n: int, lang: str) -> str:
    if lang == "en":
        return f"{n} finding" if n == 1 else f"{n} findings"
    if n == 1:
        return "1 constatare"
    return f"{n} de constatări" if n >= 20 else f"{n} constatări"


def _verdict(score: Any, lang: str) -> str:
    # Presentation band only, identical to scoreVerdict() in netcheck/web/app.js.
    value = int(score) if isinstance(score, (int, float)) else 0
    return T[lang]["good" if value >= 70 else "medium" if value >= 50 else "bad"]


class _Context:
    """Read-only view of the stored analysis in the requested language."""

    def __init__(self, analysis: dict[str, Any], lang: str, device_ip: str | None, question: str):
        self.lang = lang
        self.t = T[lang]
        self.catalog = load_catalog()
        self.analysis = analysis
        self.devices = {device.get("ip"): device for device in analysis.get("devices", [])}
        if device_ip is None:
            # "Ce înseamnă 192.168.1.40?" scopes the answer like a selected device.
            mentioned = [ip for ip in _IP.findall(question) if ip in self.devices]
            device_ip = mentioned[0] if mentioned else None
        self.device_ip = device_ip
        findings = list(analysis.get("findings", []))
        top = analysis.get("top_risk") or None
        self.top = None
        if top:
            for finding in findings:
                if (finding.get("ip"), finding.get("code")) == (top.get("ip"), top.get("code")):
                    self.top = finding
                    break
            else:
                self.top = dict(top)
        # Stored order, with the engine's top risk first; nothing is re-ranked.
        if any(f is self.top for f in findings):
            findings = [self.top] + [f for f in findings if f is not self.top]
        self.findings = findings
        self.scoped = [f for f in self.findings if device_ip is None or f.get("ip") == device_ip]
        self.codes: list[str] = []
        self.passages: list[Passage] = []

    # -- catalog text, in the requested language --------------------------------
    def field(self, finding: dict[str, Any], name: str) -> Any:
        value = finding.get(name)
        if isinstance(value, dict):
            value = value.get(self.lang)
        if value is None or (name == "fix" and not isinstance(value, list)):
            value = self.catalog[str(finding["code"])][name][self.lang]
        return value

    def use(self, finding: dict[str, Any]) -> None:
        code = str(finding["code"])
        if code not in self.codes:
            self.codes.append(code)

    def title(self, finding: dict[str, Any]) -> str:
        self.use(finding)
        return str(self.field(finding, "title"))

    def explain(self, finding: dict[str, Any]) -> str:
        self.use(finding)
        return str(self.field(finding, "explain"))

    def steps(self, finding: dict[str, Any]) -> list[str]:
        self.use(finding)
        return [f"{index}. {step}" for index, step in enumerate(self.field(finding, "fix"), 1)]

    # -- scan facts --------------------------------------------------------------
    def device(self, ip: str | None) -> str:
        device = self.devices.get(ip, {})
        kind = _TYPE_LABEL[self.lang].get(str(device.get("device_type") or "unknown"), _TYPE_LABEL[self.lang]["unknown"])
        return f"{ip} ({kind})"

    def where(self, finding: dict[str, Any]) -> str:
        port = finding.get("port")
        return self.t["where_port"].format(ip=finding.get("ip"), port=port) if port else str(finding.get("ip"))

    def sev(self, finding: dict[str, Any]) -> str:
        label = _SEVERITY_LABEL[self.lang].get(str(finding.get("severity")), str(finding.get("severity")))
        return self.t["severity"].format(sev=label)

    def port(self, finding: dict[str, Any]) -> str:
        port = finding.get("port")
        return self.t["port_suffix"].format(port=port) if port else ""

    def device_findings(self, ip: str | None) -> list[dict[str, Any]]:
        return [f for f in self.findings if f.get("ip") == ip]

    def score_line(self) -> str:
        score = self.analysis.get("network_score")
        return self.t["score"].format(score=score, verdict=_verdict(score, self.lang))

    def counts_line(self) -> str:
        counts = Counter(str(f.get("severity")) for f in self.findings)
        parts = [f"{_COUNT_LABEL[self.lang][sev]} {counts.get(sev, 0)}" for sev in _SEVERITIES]
        return self.t["counts"].format(counts=" · ".join(parts))

    def scope_name(self) -> str:
        return self.device(self.device_ip) if self.device_ip else self.t["network_scope"]


# -- intents ----------------------------------------------------------------------
def _score(c: _Context) -> list[str]:
    lines = [c.score_line(), c.counts_line(), c.t["score_meaning"]]
    if c.device_ip:
        own = c.device_findings(c.device_ip)
        if own:
            lines.append(c.t["device_count"].format(device=c.device(c.device_ip), n=_findings_count(len(own), c.lang)))
        else:
            lines.append(c.t["device_none"].format(device=c.device(c.device_ip)))
    lines.append(c.t["disclaimer"])
    return lines


def _worst(c: _Context) -> list[str]:
    top = c.top
    if top is None:
        return [c.t["network_none"], c.t["disclaimer"]]
    lines = [c.t["worst"].format(device=c.device(top.get("ip")), title=c.title(top), port=c.port(top), sev=c.sev(top)),
             c.explain(top)]
    own = c.device_findings(top.get("ip"))
    if len(own) > 1:
        lines.append(c.t["worst_more"].format(n=_findings_count(len(own), c.lang)))
    if top.get("severity") == "info":
        lines.append(c.t["worst_info"])
    fix = c.field(top, "fix")
    if fix:
        lines.append(c.t["first_step"].format(step=fix[0]))
    if c.device_ip and c.device_ip != top.get("ip"):
        selected = c.device_findings(c.device_ip)
        if selected:
            lines.append(c.t["selected_other"].format(
                device=c.device(c.device_ip), n=_findings_count(len(selected), c.lang),
                title=c.title(selected[0]), sev=c.sev(selected[0])))
        else:
            lines.append(c.t["device_none"].format(device=c.device(c.device_ip)))
    return lines


def _nothing_to_fix(c: _Context) -> list[str]:
    lines = [c.t["nothing_to_fix"].format(scope=c.scope_name())]
    if c.device_ip and c.top is not None:
        lines.append(c.t["network_top"].format(title=c.title(c.top), device=c.device(c.top.get("ip"))))
    return lines + [c.t["disclaimer"]]


def _start(c: _Context) -> list[str]:
    if not c.scoped:
        return _nothing_to_fix(c)
    first = c.scoped[0]
    lines = [c.t["start"].format(title=c.title(first), where=c.where(first), sev=c.sev(first)),
             c.explain(first), c.t["steps"], *c.steps(first)]
    if len(c.scoped) > 1:
        lines.append(c.t["then"].format(title=c.title(c.scoped[1]), where=c.where(c.scoped[1])))
    return lines


def _fix(c: _Context) -> list[str]:
    if not c.scoped:
        return _nothing_to_fix(c)
    lines: list[str] = []
    for finding in c.scoped[:3]:
        lines.append(f"{c.title(finding)} ({c.where(finding)}):")
        lines.extend(c.steps(finding))
    if len(c.scoped) > 3:
        lines.append(c.t["fix_more"].format(n=_findings_count(len(c.scoped) - 3, c.lang)))
    return lines


def _ports(c: _Context) -> list[str]:
    ips = [c.device_ip] if c.device_ip else list(c.devices)
    lines = [c.t["ports"]]
    for ip in ips[:10]:
        ports = [
            f"{port.get('protocol', '')}/{port.get('port', '')} {port.get('service', '')}".strip()
            for port in c.devices.get(ip, {}).get("ports", [])
        ]
        lines.append(f"• {c.device(ip)}: {', '.join(ports) or c.t['no_ports']}")
    if len(ips) > 10:
        lines.append(c.t["more_devices"].format(n=len(ips) - 10))
    return lines


def _severity(c: _Context) -> list[str]:
    if c.device_ip:
        if not c.scoped:
            return [c.t["device_none"].format(device=c.device(c.device_ip)), c.t["disclaimer"]]
        top = c.scoped[0]
    else:
        top = c.top
        if top is None:
            return [c.t["network_none"], c.score_line(), c.t["disclaimer"]]
    lines = [c.t.get(f"sev_{top.get('severity')}", "")]
    template = "top_device" if c.device_ip else "top_network"
    lines.append(c.t[template].format(device=c.device(top.get("ip")), title=c.title(top), port=c.port(top), sev=c.sev(top)))
    lines.append(c.explain(top))
    if c.device_ip:
        lines.append(c.t["device_count"].format(device=c.device(c.device_ip), n=_findings_count(len(c.scoped), c.lang)))
    else:
        lines.extend([c.score_line(), c.counts_line()])
    lines.append(c.t["disclaimer"])
    return [line for line in lines if line]


def _explain(c: _Context) -> list[str]:
    if c.device_ip:
        if not c.scoped:
            return [c.t["device_none"].format(device=c.device(c.device_ip)), c.t["disclaimer"]]
        lines = [c.t["explain_device"].format(device=c.device(c.device_ip), n=_findings_count(len(c.scoped), c.lang))]
        for finding in c.scoped[:3]:
            lines.append(f"• {c.title(finding)}{c.port(finding)}, {c.sev(finding)}: {c.explain(finding)}")
        if len(c.scoped) > 3:
            lines.append(c.t["explain_more"].format(n=_findings_count(len(c.scoped) - 3, c.lang)))
        return lines + [c.t["ask_fix"]]
    lines = [c.score_line(), c.counts_line()]
    if c.top is None:
        return lines + [c.t["network_none"], c.t["disclaimer"]]
    top = c.top
    lines.append(c.t["top_network"].format(device=c.device(top.get("ip")), title=c.title(top), port=c.port(top), sev=c.sev(top)))
    lines.append(c.explain(top))
    return lines + [c.t["ask_fix"], c.t["disclaimer"]]


_HANDLERS = {
    intent.SCORE: _score, intent.WORST: _worst, intent.START: _start, intent.FIX: _fix,
    intent.PORTS: _ports, intent.SEVERITY: _severity, intent.EXPLAIN: _explain,
}


# -- secondary corpus -----------------------------------------------------------------
def clean_excerpt(text: str, *, max_sentences: int = 2) -> str | None:
    """Return up to ``max_sentences`` whole sentences, or None for unusable text.

    Drops a leading fragment that starts mid-sentence and a trailing fragment
    without final punctuation; rejects table-of-contents and reference lists.
    """

    if _TOC.search(text):
        return None
    tokens = text.split()
    if not tokens or sum(any(ch.isdigit() for ch in token) for token in tokens) / len(tokens) > 0.15:
        return None
    sentences = _SENTENCE_SPLIT.split(" ".join(tokens))
    if sentences and not sentences[0][:1].isupper():
        sentences = sentences[1:]
    if sentences and not re.search(r"[.!?][\"”)]?$", sentences[-1]):
        sentences = sentences[:-1]
    kept = [s for s in sentences if 4 <= len(s.split()) <= 60 and not _BOILERPLATE.search(s)]
    return " ".join(kept[:max_sentences]) or None


def _usable_kb(passage: Passage, lang: str) -> str | None:
    if passage.source_type != "kb" or passage.language != lang:
        return None
    return clean_excerpt(passage.text)


def _related_excerpt(code: str, lang: str) -> tuple[Passage, str] | None:
    """One clean corpus excerpt documented for ``code`` in the requested language."""

    # The lead passage of a source documented for the code is usually its
    # definition; ordering by (document, passage number) keeps this deterministic.
    candidates = [p for p in passages(lang) if p.source_type == "kb" and code in p.codes]
    def order(passage: Passage) -> tuple[str, int]:
        number = passage.id.rsplit("#", 1)[-1]
        return passage.document_id, int(number) if number.isdigit() else 0

    for passage in sorted(candidates, key=order):
        text = _usable_kb(passage, lang)
        if text:
            return passage, text
    return None


def _render(lines: list[str], c: _Context, kind: str, sources: list[dict[str, Any]]) -> tuple[str, list[dict[str, Any]]]:
    citations = [f"[catalog:{code}]" for code in c.codes] + [f"[kb:{p.id}]" for p in c.passages]
    body = "\n".join(lines)
    text = PREFIX[kind][c.lang] + "\n" + body + ("\n" + " ".join(citations) if citations else "")
    return text, sources


def _catalog_source(code: str, lang: str, catalog: dict[str, Any]) -> dict[str, Any]:
    return {"type": "catalog", "id": code, "title": str(catalog[code]["title"][lang])}


def answer(
    question: str,
    analysis: dict[str, Any],
    *,
    lang: str,
    device_ip: str | None = None,
) -> tuple[str, list[dict[str, str | None]]]:
    c = _Context(analysis, lang, device_ip, question)
    name = intent.detect(question)
    if name is not None:
        lines = _HANDLERS[name](c)
        if c.codes and name in {intent.WORST, intent.START, intent.EXPLAIN, intent.SEVERITY, intent.FIX}:
            related = _related_excerpt(c.codes[0], lang)
            if related:
                passage, text = related
                c.passages.append(passage)
                lines.append(c.t["docs_excerpt"].format(title=passage.title, text=text))
        sources = [{"type": "scan", "id": "scan", "title": c.t["scan_source"]}]
        sources += [_catalog_source(code, lang, c.catalog) for code in c.codes]
        sources += [source_dict(p) for p in c.passages]
        return _render(lines, c, "scan", sources)

    # Not a recognized scan question: local retrieval, same language only.
    lines = []
    if c.device_ip and c.scoped:
        first = c.scoped[0]
        lines.append(f"{c.title(first)} ({c.where(first)}): {c.explain(first)}")
        lines.extend(c.steps(first))
    # At most one catalog entry and one corpus excerpt: lower-ranked hits were
    # mostly unrelated in the reproduced questions.
    catalog_done = bool(c.codes)
    for passage in search(question, lang=lang):
        if catalog_done and c.passages:
            break
        text = _usable_kb(passage, lang) if passage.source_type == "kb" else None
        if text:
            if not c.passages:
                c.passages.append(passage)
                lines.append(c.t["docs_excerpt"].format(title=passage.title, text=text))
            continue
        # A catalog hit, or a corpus passage in another language: show the
        # catalog entry for the code it documents, in the requested language.
        code = passage.id if passage.source_type == "catalog" else next(iter(passage.codes), None)
        if catalog_done or code is None or code in c.codes or code not in c.catalog:
            continue
        catalog_done = True
        entry = {"code": code}
        lines.append(f"{c.title(entry)}: {c.explain(entry)}")
        lines.extend(c.steps(entry))
    sources = [_catalog_source(code, lang, c.catalog) for code in c.codes] + [source_dict(p) for p in c.passages]
    if not lines:
        lines = [c.t["no_answer"]]
        sources = [{"type": "catalog", "id": "local", "title": c.t["local_catalog"]}]
    return _render(lines, c, "docs", sources)
