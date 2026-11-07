"""Detect the local network and run allowlisted nmap scans."""

from __future__ import annotations

from dataclasses import dataclass, field
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network
import re
import json
import platform
import subprocess
from pathlib import Path


_VALIDATION_TOKEN = object()


@dataclass
class NetworkInfo:
    interface: str
    ip: str
    prefix_length: int
    subnet: str
    gateway: str

    @property
    def cidr(self) -> str:
        """Compatibility alias for existing validation callers."""
        return self.subnet


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


class NetworkDetectionError(RuntimeError):
    """The local IPv4 network cannot be selected safely."""


def _run_system_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", check=True, timeout=10,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise NetworkDetectionError(
            f"Nu pot citi configurația rețelei ({command[0]}): {exc}"
        ) from exc


def _usable_address(address: IPv4Address) -> bool:
    return not (
        address.is_loopback or address.is_link_local or address.is_unspecified
        or address.is_multicast or address.is_reserved
    )


def _detect_macos() -> NetworkInfo:
    """Detect one unambiguous macOS LAN; never execute a scan.

    Requires a single active Ethernet/Wi-Fi IPv4 address and default gateway.
    IPv4 tunnels and routes on non-LAN interfaces fail closed, including
    split-tunnel VPNs. IPv6-only utun interfaces are harmless for this contract.
    """
    interfaces = _run_system_command(["/sbin/ifconfig", "-a"]).stdout
    routes = _run_system_command(["/usr/sbin/netstat", "-rn", "-f", "inet"]).stdout
    candidates = []
    for block in re.split(r"(?=^\S+: flags=)", interfaces, flags=re.MULTILINE):
        header = re.match(r"(\S+): flags=\w+<([^>]*)>", block)
        if not header:
            continue
        name, flags_text = header.groups()
        flags = set(flags_text.split(","))
        if "LOOPBACK" in flags or "UP" not in flags:
            continue
        addresses = re.findall(r"^\s+inet (\S+) netmask (\S+)", block, re.MULTILINE)
        if not addresses:
            continue
        if "POINTOPOINT" in flags or not re.fullmatch(r"en\d+", name):
            raise NetworkDetectionError(f"Interfață IPv4 VPN/virtuală activă: {name}.")
        if not re.search(r"^\s*status: active\s*$", block, re.MULTILINE):
            continue
        for ip_text, mask_text in addresses:
            try:
                address = IPv4Address(ip_text)
                mask = IPv4Address(int(mask_text, 16)) if mask_text.startswith("0x") else IPv4Address(mask_text)
                network = IPv4Network(f"{address}/{mask}", strict=False)
            except ValueError as exc:
                raise NetworkDetectionError(f"IPv4 sau mască invalidă pe {name}.") from exc
            if _usable_address(address):
                if address in (network.network_address, network.broadcast_address):
                    raise NetworkDetectionError(f"Adresă IPv4 neutilizabilă pe {name}.")
                candidates.append((name, address, network))
    if not candidates:
        raise NetworkDetectionError("Nu există o conexiune LAN IPv4 activă utilizabilă.")
    if len(candidates) != 1:
        names = ", ".join(f"{name} ({ip})" for name, ip, _ in candidates)
        raise NetworkDetectionError(f"Rețea ambiguă: mai multe adrese/interfețe active: {names}.")
    name, address, network = candidates[0]
    defaults = set()
    found_header = False
    for line in routes.splitlines():
        columns = line.split()
        if columns[:1] == ["Destination"]:
            found_header = True
            continue
        if not found_header or len(columns) < 4:
            continue
        destination, gateway, flags, interface = columns[:4]
        if interface.startswith("lo"):
            continue
        if interface != name:
            raise NetworkDetectionError(
                f"Rută IPv4 pe altă interfață ({interface}); posibil VPN sau rețea ambiguă."
            )
        if destination == "default" and "U" in flags and "G" in flags:
            defaults.add(gateway)
    if len(defaults) != 1:
        raise NetworkDetectionError("Gateway IPv4 absent sau ambiguu; verificați conexiunea LAN.")
    try:
        gateway = IPv4Address(defaults.pop())
    except ValueError as exc:
        raise NetworkDetectionError("Gateway-ul nu este o adresă IPv4 validă.") from exc
    if (not _usable_address(gateway) or gateway not in network
            or gateway in (address, network.network_address, network.broadcast_address)):
        raise NetworkDetectionError("Gateway-ul nu este o adresă utilizabilă în subnetul local.")
    return NetworkInfo(name, str(address), network.prefixlen, str(network), str(gateway))


# Emit only structured data; no localized table parsing or user-supplied script.
_WINDOWS_NETWORK_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)
@{
  adapters = @(Get-NetAdapter -IncludeHidden | Select-Object ifIndex,Name,Status,HardwareInterface)
  addresses = @(Get-NetIPAddress -AddressFamily IPv4 -PolicyStore ActiveStore | Select-Object InterfaceIndex,IPAddress,PrefixLength,AddressState)
  routes = @(Get-NetRoute -AddressFamily IPv4 -PolicyStore ActiveStore | Select-Object InterfaceIndex,DestinationPrefix,NextHop)
} | ConvertTo-Json -Depth 5 -Compress
"""


def _read_json(command: list[str]):
    try:
        return json.loads(_run_system_command(command).stdout.lstrip("\ufeff"))
    except (ValueError, UnicodeError) as exc:
        raise NetworkDetectionError("Configurația rețelei nu conține JSON valid.") from exc


def _select_network(candidates, routes) -> NetworkInfo:
    if not candidates:
        raise NetworkDetectionError("Nu există o conexiune LAN IPv4 activă utilizabilă.")
    if len(candidates) != 1:
        raise NetworkDetectionError("Rețea ambiguă: mai multe adrese/interfețe IPv4 active.")
    key, name, address, network = candidates[0]
    gateways = set()
    for interface, destination, gateway in routes:
        if interface != key:
            raise NetworkDetectionError("Rută IPv4 pe altă interfață; posibil VPN sau rețea ambiguă.")
        if destination in ("default", "0.0.0.0/0"):
            gateways.add(gateway)
    if len(gateways) != 1:
        raise NetworkDetectionError("Gateway IPv4 absent sau ambiguu.")
    gateway = IPv4Address(gateways.pop())
    if (not _usable_address(gateway) or gateway not in network
            or gateway in (address, network.network_address, network.broadcast_address)):
        raise NetworkDetectionError("Gateway-ul nu este o adresă utilizabilă în subnetul local.")
    return NetworkInfo(name, str(address), network.prefixlen, str(network), str(gateway))


def _candidate(key, name, ip, prefix):
    address = IPv4Address(ip)
    network = IPv4Network(f"{address}/{prefix}", strict=False)
    if not _usable_address(address):
        return None
    if address in (network.network_address, network.broadcast_address):
        raise NetworkDetectionError(f"Adresă IPv4 neutilizabilă pe {name}.")
    return key, name, address, network


def _detect_windows() -> NetworkInfo:
    data = _read_json([
        "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
        "-Command", _WINDOWS_NETWORK_SCRIPT,
    ])
    adapters = {a["ifIndex"]: a for a in data["adapters"]}
    candidates = []
    loopbacks = set()
    for item in data["addresses"]:
        key = item["InterfaceIndex"]
        address = IPv4Address(item["IPAddress"])
        if address.is_loopback:
            loopbacks.add(key)
            continue
        adapter = adapters.get(key)
        if adapter is None:
            raise NetworkDetectionError("Adaptor IPv4 necunoscut; posibil VPN.")
        if adapter["Status"] != "Up":
            continue
        if adapter["HardwareInterface"] is not True:
            raise NetworkDetectionError(f"Adaptor IPv4 VPN/virtual activ: {adapter['Name']}.")
        # MSFT_NetIPAddress AddressState: Preferred = 4.
        if item["AddressState"] not in (4, "Preferred"):
            raise NetworkDetectionError("Adresa IPv4 nu este în starea Preferred.")
        candidate = _candidate(key, adapter["Name"], str(address), item["PrefixLength"])
        if candidate:
            candidates.append(candidate)
    routes = [(r["InterfaceIndex"], r["DestinationPrefix"], r["NextHop"])
              for r in data["routes"] if r["InterfaceIndex"] not in loopbacks]
    return _select_network(candidates, routes)


def _linux_physical_interface(name: str) -> bool:
    # Kernel device association, rather than guessing physical status from names.
    if not re.fullmatch(r"[A-Za-z0-9_.:-]+", name):
        return False
    return (Path("/sys/class/net") / name / "device").exists()


def _detect_linux() -> NetworkInfo:
    interfaces = _read_json(["ip", "-j", "-4", "address", "show"])
    routes_data = _read_json(["ip", "-j", "-4", "route", "show", "table", "all"])
    rules = _read_json(["ip", "-j", "-4", "rule", "show"])
    # Fail closed on policy routing (including VPNs using separate tables).
    expected = {(0, "local"), (32766, "main"), (32767, "default")}
    actual = set()
    for rule in rules:
        table = {255: "local", 254: "main", 253: "default"}.get(rule.get("table"), rule.get("table"))
        if rule.get("src", "all") != "all" or set(rule) - {"priority", "src", "table", "protocol"}:
            raise NetworkDetectionError("Reguli IPv4 speciale; posibil VPN/policy routing.")
        actual.add((rule["priority"], table))
    if actual != expected or len(rules) != 3:
        raise NetworkDetectionError("Reguli IPv4 speciale; posibil VPN/policy routing.")
    candidates = []
    loopbacks = set()
    for item in interfaces:
        name = item["ifname"]
        flags = item["flags"]
        if "LOOPBACK" in flags:
            loopbacks.add(name)
            continue
        if "UP" not in flags:
            continue
        addresses = [a for a in item["addr_info"] if a["family"] == "inet"]
        if not addresses:
            continue
        if "POINTOPOINT" in flags or not _linux_physical_interface(name):
            raise NetworkDetectionError(f"Interfață IPv4 VPN/virtuală activă: {name}.")
        if item["operstate"] != "UP":
            continue
        for addr in addresses:
            if any(addr.get(flag) for flag in ("tentative", "dadfailed", "deprecated")):
                raise NetworkDetectionError(f"Adresă IPv4 instabilă pe {name}.")
            candidate = _candidate(name, name, addr["local"], addr["prefixlen"])
            if candidate:
                candidates.append(candidate)
    routes = []
    for route in routes_data:
        if route.get("dev") in loopbacks:
            continue
        if route.get("type", "unicast") not in ("unicast", "local", "broadcast") or "nexthops" in route:
            raise NetworkDetectionError("Rutare IPv4 specială sau multipath; rețea ambiguă.")
        routes.append((route["dev"], route["dst"], route.get("gateway")))
    return _select_network(candidates, routes)


def detect_network() -> NetworkInfo:
    """Detect one unambiguous LAN on macOS, Windows or Linux; never scan."""
    system = platform.system()
    backend = {"Darwin": _detect_macos, "Windows": _detect_windows, "Linux": _detect_linux}.get(system)
    if backend is None:
        raise NetworkDetectionError(f"Sistem nesuportat: {system}. Suport: macOS, Windows, Linux.")
    try:
        return backend()
    except (ValueError, TypeError, KeyError, AttributeError) as exc:
        raise NetworkDetectionError("Configurație IPv4 invalidă sau incompletă; detectarea a fost oprită.") from exc


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
