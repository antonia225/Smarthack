"""Build the analysis model and calculate deterministic network scores."""

from __future__ import annotations

from dataclasses import asdict
from ipaddress import ip_address
from pathlib import Path
from typing import Iterable

from .parser import Device, ParsedScan, Port, parse_file
from .rules import Finding, evaluate_findings


def calculate_score(findings: Iterable[Finding]) -> int:
    """Return a score from 0 to 100 based on finding points."""

    return max(0, 100 - sum(finding.points for finding in findings))


def score_findings(findings: Iterable[Finding]) -> int:
    """Compatibility name for callers that score a finding collection."""

    return calculate_score(findings)


def _mask_mac(mac: str) -> str:
    groups = mac.upper().split(":")
    if len(groups) != 6 or any(not group for group in groups):
        return ""
    return ":".join(groups[:3] + ["**", "**", "**"])


def _device_type(device: Device) -> str:
    vendor = device.vendor.lower()
    hostname = device.hostname.lower()
    services = {port.service.lower() for port in device.ports}

    if "rtsp" in services or any(name in vendor for name in ("hikvision", "dahua")):
        return "camera"
    if "jetdirect" in services:
        return "printer"
    if (
        any(name in vendor for name in ("tp-link", "netgear", "ubiquiti"))
        or any(name in hostname for name in ("router", "gateway"))
    ):
        return "router"
    if "microsoft-ds" in services or "synology" in vendor:
        return "nas"
    if "mqtt" in services or "espressif" in vendor:
        return "iot"
    return "unknown"


def _port_model(port: Port) -> dict[str, object]:
    return {
        "port": port.port,
        "protocol": port.protocol,
        "service": port.service,
        "product": port.product,
        "version": port.version,
    }


def _device_model(device: Device) -> dict[str, object]:
    return {
        "ip": device.ip,
        "mac_masked": _mask_mac(device.mac),
        "vendor": device.vendor,
        "hostname": device.hostname,
        "device_type": _device_type(device),
        "ports": [_port_model(port) for port in device.ports],
    }


def _finding_model(finding: Finding) -> dict[str, object]:
    return asdict(finding)


def _top_risk(findings: list[Finding]) -> dict[str, object] | None:
    if not findings:
        return None
    finding = findings[0]
    return {
        "ip": finding.ip,
        "code": finding.code,
        "severity": finding.severity,
    }


def analyze_file(path: str | Path) -> dict[str, object]:
    """Parse, evaluate, and score one Nmap XML file."""

    parsed = parse_file(path)
    file_name = Path(path).name
    if parsed.status != "ok":
        return {
            "file": file_name,
            "status": "error",
            "error": parsed.error,
        }

    findings = evaluate_findings(parsed)
    return {
        "file": file_name,
        "status": "ok",
        "network_score": calculate_score(findings),
        "top_risk": _top_risk(findings),
        "devices": [_device_model(device) for device in parsed.devices],
        "findings": [_finding_model(finding) for finding in findings],
    }


def sort_findings_for_csv(
    results: Iterable[dict[str, object]],
) -> list[dict[str, object]]:
    """Flatten analysis results in the required CSV order."""

    rows: list[dict[str, object]] = []
    for result in results:
        if result.get("status") != "ok":
            continue
        file_name = str(result["file"])
        for finding in result["findings"]:  # type: ignore[union-attr]
            row = dict(finding)  # type: ignore[arg-type]
            row["file"] = file_name
            rows.append(row)

    return sorted(
        rows,
        key=lambda row: (
            str(row["file"]),
            ip_address(str(row["ip"])),
            row["port"] is None,
            row["port"] if row["port"] is not None else -1,
            str(row["code"]),
        ),
    )
