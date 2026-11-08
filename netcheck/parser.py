"""Parse Nmap XML scan results into deterministic Python data."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re

from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException


from netcheck.scan_xml import MAX_XML_BYTES as MAX_SCAN_SIZE


@dataclass
class Port:
    port: int
    protocol: str
    state: str
    service: str = ""
    product: str = ""
    version: str = ""
    tunnel: str = ""
    http_title: str = ""


@dataclass
class Device:
    ip: str
    mac: str = ""
    vendor: str = ""
    hostname: str = ""
    ports: list[Port] = field(default_factory=list)


@dataclass
class ParsedScan:
    file: str
    status: str
    devices: list[Device] = field(default_factory=list)
    error: dict[str, object] | None = None


def _error(file: str, code: str = "invalid_xml") -> ParsedScan:
    return ParsedScan(
        file=file,
        status="error",
        error={
            "code": code,
            "message": {
                "ro": "Fișierul nu poate fi citit.",
                "en": "The file cannot be read.",
            },
        },
    )


def _text(element: ElementTree.Element | None) -> str:
    return (element.text or "").strip() if element is not None else ""


def _http_title(port_element: ElementTree.Element) -> str:
    for script in port_element.findall("script"):
        if script.get("id") != "http-title":
            continue
        output = script.get("output", "").strip()
        if output:
            return output
        for element in script.findall("elem"):
            value = _text(element)
            if element.get("key") == "title" and value:
                return value
        return _text(script)
    return ""


def _parse_port(port_element: ElementTree.Element) -> Port | None:
    try:
        port = int(port_element.get("portid", ""))
    except ValueError:
        return None

    state_element = port_element.find("state")
    service_element = port_element.find("service")
    return Port(
        port=port,
        protocol=port_element.get("protocol", ""),
        state=state_element.get("state", "") if state_element is not None else "",
        service=service_element.get("name", "") if service_element is not None else "",
        product=service_element.get("product", "") if service_element is not None else "",
        version=service_element.get("version", "") if service_element is not None else "",
        tunnel=service_element.get("tunnel", "") if service_element is not None else "",
        http_title=_http_title(port_element),
    )


def _parse_host(host_element: ElementTree.Element) -> Device | None:
    ip = ""
    mac = ""
    vendor = ""
    for address in host_element.findall("address"):
        address_type = address.get("addrtype", "")
        if address_type == "ipv4" and not ip:
            ip = address.get("addr", "")
        elif address_type == "mac":
            mac = address.get("addr", "")
            vendor = address.get("vendor", "")

    if not ip:
        return None

    hostname_element = host_element.find("./hostnames/hostname")
    ports = [
        parsed
        for port_element in host_element.findall("./ports/port")
        if (parsed := _parse_port(port_element)) is not None
    ]
    return Device(
        ip=ip,
        mac=mac,
        vendor=vendor,
        hostname=hostname_element.get("name", "") if hostname_element is not None else "",
        ports=ports,
    )


def parse_file(path: str | Path) -> ParsedScan:
    """Parse one Nmap XML file, returning a controlled error on bad input."""

    file_path = Path(path)
    file_name = str(path)
    try:
        content = file_path.read_bytes()
    except OSError:
        return _error(file_name, "file_read_error")

    if len(content) > MAX_SCAN_SIZE:
        return _error(file_name, "file_too_large")

    try:
        root = ElementTree.fromstring(content)
    except (ElementTree.ParseError, DefusedXmlException, ValueError):
        return _error(file_name)

    if root.tag != "nmaprun":
        return _error(file_name, "invalid_root")

    devices = [
        parsed
        for host_element in root.findall("host")
        if (parsed := _parse_host(host_element)) is not None
    ]
    devices.sort(key=lambda device: device.ip)
    return ParsedScan(file=file_name, status="ok", devices=devices)


def parse_scan(path: str | Path) -> ParsedScan:
    """Compatibility name for callers that use scan-oriented terminology."""

    return parse_file(path)
