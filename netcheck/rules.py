"""Evaluate parsed Nmap data against the fixed findings catalog."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import ip_address
import re

from .parser import Device, ParsedScan, Port


SEVERITY_POINTS = {
    "high": 20,
    "medium": 10,
    "low": 5,
    "info": 0,
}

_SERVICE_RULES = {
    "telnet": ("TELNET_OPEN", "high"),
    "ms-wbt-server": ("RDP_EXPOSED", "high"),
    "vnc": ("VNC_EXPOSED", "high"),
    "mysql": ("DB_EXPOSED", "high"),
    "postgresql": ("DB_EXPOSED", "high"),
    "redis": ("DB_EXPOSED", "high"),
    "mongodb": ("DB_EXPOSED", "high"),
    "rtsp": ("CAMERA_STREAM_EXPOSED", "high"),
    "ftp": ("FTP_CLEARTEXT", "medium"),
    "mqtt": ("MQTT_EXPOSED", "medium"),
    "jetdirect": ("PRINTER_RAW_EXPOSED", "low"),
    "ssh": ("SSH_OPEN", "info"),
}

_HTTP_KEYWORDS = ("login", "admin", "config", "setup", "router", "settings")


@dataclass(frozen=True)
class Finding:
    ip: str
    port: int | None
    code: str
    severity: str
    points: int
    evidence: str


def _evidence(port: Port) -> str:
    return f"{port.protocol}/{port.port} {port.service}".strip()


def _finding(
    device: Device,
    port: Port | None,
    code: str,
    severity: str,
    evidence: str | None = None,
) -> Finding:
    return Finding(
        ip=device.ip,
        port=port.port if port is not None else None,
        code=code,
        severity=severity,
        points=SEVERITY_POINTS[severity],
        evidence=evidence if evidence is not None else (_evidence(port) if port else ""),
    )


def _version_numbers(version: str) -> tuple[int, ...] | None:
    match = re.search(r"\d+(?:\.\d+)+", version)
    if match is None:
        return None
    return tuple(int(part) for part in match.group(0).split("."))


def _is_outdated(port: Port) -> bool:
    product = port.product.lower()
    version = _version_numbers(port.version)
    if version is None:
        return False

    if "vsftpd" in product:
        return version == (2, 3, 4)
    if "openssh" in product:
        return version < (7, 4)
    if "apache" in product:
        return version[:2] <= (2, 2)
    if "iis" in product:
        return version <= (7, 5)
    if "samba" in product:
        return version[0] <= 3
    return False


def _http_finding(device: Device, port: Port) -> Finding | None:
    if port.service.lower() != "http" or port.tunnel.lower() == "ssl":
        return None
    title = port.http_title.lower()
    if not title or not any(keyword in title for keyword in _HTTP_KEYWORDS):
        return None
    return _finding(device, port, "HTTP_ADMIN_CLEARTEXT", "medium")


def _smb_finding(device: Device, ports: list[Port]) -> Finding | None:
    smb_ports = [
        port
        for port in ports
        if port.service.lower() in {"microsoft-ds", "netbios-ssn"}
    ]
    if not smb_ports:
        return None
    selected = next(
        (port for port in smb_ports if port.port == 445),
        next((port for port in smb_ports if port.port == 139), smb_ports[0]),
    )
    return _finding(device, selected, "SMB_EXPOSED", "medium")


def _unknown_device_finding(device: Device, open_ports: list[Port]) -> Finding | None:
    if device.vendor or device.hostname or not open_ports:
        return None
    return _finding(
        device,
        None,
        "UNKNOWN_DEVICE",
        "low",
        evidence="unknown device",
    )


def evaluate_findings(scan: ParsedScan) -> list[Finding]:
    """Return deterministic findings for open ports in a parsed scan."""

    if scan.status != "ok":
        return []

    findings: list[Finding] = []
    for device in scan.devices:
        open_ports = [port for port in device.ports if port.state.lower() == "open"]
        for port in open_ports:
            service = port.service.lower()
            rule = _SERVICE_RULES.get(service)
            if rule is not None:
                findings.append(_finding(device, port, *rule))

            http_finding = _http_finding(device, port)
            if http_finding is not None:
                findings.append(http_finding)

            if service == "upnp" and port.protocol.lower() == "udp":
                findings.append(_finding(device, port, "UPNP_EXPOSED", "medium"))
            if service == "snmp" and port.protocol.lower() == "udp":
                findings.append(_finding(device, port, "SNMP_EXPOSED", "medium"))
            if _is_outdated(port):
                findings.append(_finding(device, port, "OUTDATED_SERVICE", "high"))

        smb_finding = _smb_finding(device, open_ports)
        if smb_finding is not None:
            findings.append(smb_finding)
        unknown_finding = _unknown_device_finding(device, open_ports)
        if unknown_finding is not None:
            findings.append(unknown_finding)

    severity_order = {"high": 0, "medium": 1, "low": 2, "info": 3}
    return sorted(
        findings,
        key=lambda finding: (
            severity_order[finding.severity],
            ip_address(finding.ip),
            finding.port is None,
            finding.port if finding.port is not None else -1,
            finding.code,
        ),
    )


def apply_rules(scan: ParsedScan) -> list[Finding]:
    """Compatibility name for callers that describe rule evaluation as apply."""

    return evaluate_findings(scan)
