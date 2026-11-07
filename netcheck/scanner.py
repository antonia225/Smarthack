"""Detect the local network and run allowlisted nmap scans."""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
import re
import subprocess
from pathlib import Path


_VALIDATION_TOKEN = object()


@dataclass
class NetworkInfo:
    interface: str
    ip: str
    cidr: str
    gateway: str


@dataclass
class ValidatedTarget:
    target: str
    allowed_networks: list[str]
    _validation_token: object | None = field(
        default=None,
        repr=False,
        compare=False,
    )


@dataclass
class ScanResult:
    xml_path: str
    success: bool
    error: str | None = None


def _run_system_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, capture_output=True, text=True, check=True)


def _extract_field(output: str, field_name: str) -> str:
    match = re.search(
        rf"^\s*{re.escape(field_name)}:\s*(\S+)",
        output,
        re.MULTILINE,
    )
    if match is None:
        raise RuntimeError(f"Nu am putut determina câmpul {field_name}.")
    return match.group(1)


def _get_default_route() -> tuple[str, str]:
    result = _run_system_command(["route", "-n", "get", "default"])
    interface = _extract_field(result.stdout, "interface")
    gateway = _extract_field(result.stdout, "gateway")
    return interface, gateway


def _get_interface_ip(interface: str) -> str:
    result = _run_system_command(["ipconfig", "getifaddr", interface])
    ip = result.stdout.strip()
    if not ip:
        raise RuntimeError(f"Nu am putut determina adresa IP pentru {interface}.")
    ip_address(ip)
    return ip


def _get_interface_prefix(interface: str) -> int:
    result = _run_system_command(["ifconfig", interface])
    match = re.search(r"\bnetmask\s+(0x[0-9a-fA-F]+)\b", result.stdout)
    if match is None:
        raise RuntimeError(f"Nu am putut determina masca pentru {interface}.")

    netmask = IPv4Address(int(match.group(1), 16))
    return IPv4Network(f"0.0.0.0/{netmask}").prefixlen


def detect_network() -> NetworkInfo:
    """Detect the active macOS interface, address, network, and gateway."""

    interface, gateway = _get_default_route()
    ip = _get_interface_ip(interface)
    prefix = _get_interface_prefix(interface)
    cidr = str(ip_network(f"{ip}/{prefix}", strict=False))
    return NetworkInfo(interface=interface, ip=ip, cidr=cidr, gateway=gateway)


def _permission_error(message_ro: str, message_en: str) -> PermissionError:
    return PermissionError(f"{message_ro} / {message_en}")


def _parse_target(target: str) -> IPv4Network:
    try:
        parsed = ip_network(target, strict=False)
    except ValueError:
        try:
            parsed = ip_network(f"{target}/32", strict=False)
        except ValueError as exc:
            raise _permission_error(
                "Ținta nu este o adresă sau rețea validă",
                "The target is not a valid address or network",
            ) from exc

    if parsed.version != 4:
        raise _permission_error(
            "Sunt permise doar ținte IPv4",
            "Only IPv4 targets are allowed",
        )
    return parsed


def validate_scan_request(
    target: str,
    allowed_networks: list[str] | None = None,
    confirm: bool = False,
) -> ValidatedTarget:
    """Validate an IPv4 target against private, explicitly allowed networks."""

    if confirm is not True:
        raise _permission_error(
            "Confirmarea scanării este obligatorie",
            "Scan confirmation is required",
        )

    if allowed_networks is None:
        allowed_networks = [detect_network().cidr]

    try:
        target_network = _parse_target(target)
        permitted = [
            ip_network(network, strict=False) for network in allowed_networks
        ]
    except ValueError as exc:
        raise _permission_error(
            "Rețeaua permisă nu este validă",
            "The allowed network is invalid",
        ) from exc

    if not target_network.is_private:
        raise _permission_error(
            "Nu putem scana o adresă publică",
            "We can't scan a public address",
        )

    if target_network.prefixlen < 24:
        raise _permission_error(
            "Subnetul este prea mare; sunt permise cel mult rețele /24",
            "The subnet is too large; networks broader than /24 are forbidden",
        )

    if not any(target_network.subnet_of(network) for network in permitted):
        raise _permission_error(
            "Nu putem scana o țintă din afara rețelei permise",
            "We can't scan a target outside the allowed network",
        )

    return ValidatedTarget(
        target=target,
        allowed_networks=list(allowed_networks),
        _validation_token=_VALIDATION_TOKEN,
    )


def run_scan(validated_target: ValidatedTarget, output_path: str) -> ScanResult:
    """Run the fixed allowlisted Nmap scan and save its XML output."""

    if (
        not isinstance(validated_target, ValidatedTarget)
        or validated_target._validation_token is not _VALIDATION_TOKEN
    ):
        raise PermissionError(
            "Ținta nu a fost validată prin validate_scan_request "
            "/ The target was not validated by validate_scan_request"
        )

    command = [
        "nmap",
        "-sS",
        "-sU",
        "-sV",
        "--script",
        "http-title",
        "--max-rate",
        "100",
        "-oX",
        output_path,
        validated_target.target,
    ]

    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        error = result.stderr.strip() or result.stdout.strip() or "Nmap failed."
        return ScanResult(output_path, success=False, error=error)

    if not Path(output_path).is_file():
        return ScanResult(
            output_path,
            success=False,
            error="Nmap did not write the XML output.",
        )

    return ScanResult(output_path, success=True)
