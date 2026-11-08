"""Self-contained HTML report for an IT provider."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from typing import Any

from netcheck.catalog import load_catalog


def _text(value: object) -> str:
    return escape(str(value), quote=True)


def _masked_mac(value: object) -> str:
    raw = str(value or "")
    if not raw:
        return "—"
    groups = raw.split(":")
    if len(groups) == 6:
        return ":".join(groups[:3] + ["**", "**", "**"])
    return "masked"


def _finding_html(finding: dict[str, Any], lang: str) -> str:
    catalog = load_catalog().get(str(finding["code"]))
    if catalog is None:
        title = str(finding["code"])
        explanation = "No catalog explanation is available."
        fixes: list[str] = []
    else:
        title = str(catalog["title"][lang])
        explanation = str(catalog["explain"][lang])
        fixes = [str(step) for step in catalog["fix"][lang]]
    steps = "".join(f"<li>{_text(step)}</li>" for step in fixes)
    location = f"{finding['ip']}:{finding['port']}" if finding.get("port") else finding["ip"]
    return (
        '<article class="finding">'
        f"<h3>{_text(title)}</h3>"
        f'<p><strong>{_text(finding["severity"])}</strong> · {_text(location)}</p>'
        f"<p>{_text(explanation)}</p>"
        f"<h4>{'Ce poți face' if lang == 'ro' else 'What you can do'}</h4>"
        f"<ol>{steps}</ol>"
        "</article>"
    )


def _devices_html(analysis: dict[str, Any], lang: str) -> str:
    if not analysis.get("devices"):
        return "<p>—</p>"
    type_label = "Tip" if lang == "ro" else "Type"
    mac_label = "MAC mascat" if lang == "ro" else "Masked MAC"
    cards = []
    for device in analysis["devices"]:
        cards.append(
            '<article class="device">'
            f"<h3>{_text(device['ip'])}</h3>"
            f"<p><strong>{type_label}:</strong> {_text(device.get('device_type', 'unknown'))}</p>"
            f"<p><strong>{mac_label}:</strong> {_text(_masked_mac(device.get('mac_masked')))}</p>"
            "</article>"
        )
    return "".join(cards)


def _resolved_html(before: dict[str, Any], after: dict[str, Any], lang: str) -> str:
    before_keys = {
        (item["ip"], item.get("port"), item["code"]): item
        for item in before.get("findings", [])
    }
    after_keys = {
        (item["ip"], item.get("port"), item["code"])
        for item in after.get("findings", [])
    }
    resolved_keys = sorted(
        before_keys.keys(),
        key=lambda item: (item[0], item[1] is None, item[1] or -1, item[2]),
    )
    resolved = [before_keys[key] for key in resolved_keys if key not in after_keys]
    if not resolved:
        return f"<p>{'Niciuna' if lang == 'ro' else 'None'}.</p>"
    return "".join(_finding_html(item, lang) for item in resolved)


def render_report(
    current: dict[str, Any],
    *,
    before: dict[str, Any] | None = None,
    lang: str = "ro",
) -> str:
    is_comparison = before is not None
    title = "Raport pentru furnizorul IT" if lang == "ro" else "IT provider report"
    score_label = "Scor" if lang == "ro" else "Score"
    findings_label = "Constatări" if lang == "ro" else "Findings"
    devices_label = "Dispozitive" if lang == "ro" else "Devices"
    resolved_label = "Rezolvate între scanări" if lang == "ro" else "Resolved between scans"
    generated = datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M")
    scores = (
        f"{_text(before.get('network_score'))} → {_text(current.get('network_score'))}"
        if is_comparison
        else _text(current.get("network_score"))
    )
    findings = "".join(_finding_html(item, lang) for item in current.get("findings", []))
    if not findings:
        findings = "<p>—</p>"
    resolved = _resolved_html(before, current, lang) if before else ""
    resolved_section = (
        f"<section><h2>{resolved_label}</h2>{resolved}</section>" if before else ""
    )
    return f"""<!doctype html>
<html lang="{_text(lang)}">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>{_text(title)}</title>
<style>
@page {{ size: A4; margin: 16mm; }}
* {{ box-sizing: border-box; }}
body {{ color: #17202e; font: 11pt/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; }}
header {{ border-bottom: 3px solid #1B3A78; margin-bottom: 18px; padding-bottom: 12px; }}
h1 {{ font-size: 24pt; margin: 0 0 6px; }} h2 {{ border-bottom: 1px solid #d8dee8; font-size: 15pt; margin: 20px 0 10px; padding-bottom: 4px; }}
h3 {{ font-size: 11.5pt; margin: 0 0 5px; }} h4 {{ margin: 10px 0 3px; }}
.meta {{ color: #526174; }} .summary {{ display: flex; gap: 28px; margin: 14px 0; }}
.summary strong {{ display: block; font-size: 18pt; color: #1B3A78; }}
.device, .finding {{ border: 1px solid #d8dee8; border-left: 4px solid #1B3A78; border-radius: 6px; margin: 8px 0; padding: 10px 12px; page-break-inside: avoid; }}
.finding strong {{ color: #a51d2d; text-transform: uppercase; }} ol {{ margin: 5px 0 0 20px; padding: 0; }}
.toolbar {{ margin: 0 0 18px; }} button {{ background: #1B3A78; border: 0; border-radius: 5px; color: #fff; padding: 8px 14px; }}
@media print {{ .toolbar {{ display: none; }} }}
</style>
</head>
<body>
<div class="toolbar"><button onclick="window.print()">Print / Save PDF</button></div>
<header><h1>{_text(title)}</h1><p class="meta">NetCheck · {_text(generated)}</p></header>
<section class="summary"><div><span>{score_label}</span><strong>{scores} / 100</strong></div></section>
<section><h2>{devices_label}</h2>{_devices_html(current, lang)}</section>
<section><h2>{findings_label}</h2>{findings}</section>
{resolved_section}
</body></html>"""
