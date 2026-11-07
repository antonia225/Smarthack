"""Build the minimal, pseudonymized scan context allowed into an AI prompt."""

from __future__ import annotations

from typing import Any


def build_evidence(analysis: dict[str, Any], device_ip: str | None = None, *, lang: str = "ro") -> list[dict[str, Any]]:
    en = lang == "en"
    label = "Device" if en else "Dispozitiv"
    no_ports = "no ports" if en else "niciun port"
    none = "none" if en else "niciunul"
    port_label = "ports" if en else "porturi"
    findings_label = "findings" if en else "finding-uri"
    severity_label = "severity" if en else "severitate"
    device_label = "device" if en else "dispozitiv"
    score_label = "Network score" if en else "Scorul rețelei"
    devices = analysis.get("devices", [])
    findings = analysis.get("findings", [])
    labels = {device["ip"]: f"{label} {index + 1}" for index, device in enumerate(devices)}
    selected = [device for device in devices if device_ip is None or device["ip"] == device_ip]
    evidence: list[dict[str, Any]] = [
        {"id": "ev:score", "text": f"{score_label}: {analysis.get('network_score', 'unknown' if en else 'necunoscut')} / 100."}
    ]
    for device in selected:
        ports = [
            f"{port.get('protocol', '')}/{port.get('port', '')} {port.get('service', '')}".strip()
            for port in device.get("ports", [])
        ]
        device_findings = [
            finding for finding in findings if finding.get("ip") == device.get("ip")
        ]
        evidence.append(
            {
                "id": f"ev:{device['ip']}:device",
                "text": (
                    f"{labels[device['ip']]} ({device.get('device_type', 'unknown')}), "
                    f"IP {device['ip']}; {port_label}: {', '.join(ports) or no_ports}; "
                    f"{findings_label}: {', '.join(f['code'] for f in device_findings) or none}."
                ),
            }
        )
    for finding in findings:
        if device_ip is not None and finding.get("ip") != device_ip:
            continue
        evidence.append(
            {
                "id": f"ev:{finding['ip']}:{finding.get('port') or 'device'}",
                "text": (
                    f"IP {finding['ip']}, port {finding.get('port') or device_label}, "
                    f"finding {finding['code']}, {severity_label} {finding['severity']}."
                ),
            }
        )
    return evidence
