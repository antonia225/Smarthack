"""Build the minimal, pseudonymized scan context allowed into an AI prompt."""

from __future__ import annotations

from typing import Any


def build_evidence(analysis: dict[str, Any], device_ip: str | None = None) -> list[dict[str, Any]]:
    devices = analysis.get("devices", [])
    findings = analysis.get("findings", [])
    labels = {device["ip"]: f"Dispozitiv {chr(65 + index)}" for index, device in enumerate(devices)}
    selected = [device for device in devices if device_ip is None or device["ip"] == device_ip]
    evidence: list[dict[str, Any]] = [
        {"id": "score", "text": f"Scorul rețelei: {analysis.get('network_score', 'necunoscut')} / 100."}
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
                    f"IP {device['ip']}; porturi: {', '.join(ports) or 'niciun port'}; "
                    f"finding-uri: {', '.join(f['code'] for f in device_findings) or 'niciunul'}."
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
                    f"IP {finding['ip']}, port {finding.get('port') or 'dispozitiv'}, "
                    f"finding {finding['code']}, severitate {finding['severity']}."
                ),
            }
        )
    return evidence
