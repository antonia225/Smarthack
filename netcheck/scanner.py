"""Detect the local network and run allowlisted nmap scans."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from ipaddress import IPv4Address, IPv4Network, ip_network
import re
import hashlib
import hmac
import secrets
import json
import platform
import subprocess
import time
from pathlib import Path

from defusedxml.common import DefusedXmlException
from xml.etree.ElementTree import ParseError

from netcheck.nmap_ports import port_specification
from netcheck.scan_xml import read_completed_scan


_VALIDATION_KEY = secrets.token_bytes(32)
_DEFAULT_LAB_CONFIG = Path(__file__).resolve().parent.parent / "lab" / "network.json"
_PRIVATE_LANS = tuple(IPv4Network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"))
_MACOS_NMAP_WRAPPER = Path("/usr/local/libexec/netcheck-nmap-wrapper")
_MACOS_SCAN_DIR = Path("/var/tmp/netcheck-scans")


@dataclass(frozen=True)
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


@dataclass(frozen=True)
class ValidatedTarget:
    target: str
    allowed_networks: tuple[str, ...]
    network: NetworkInfo | None = None
    _validation_token: str | None = field(
        default=None,
        repr=False,
        compare=False,
    )


@dataclass
class ScanResult:
    xml_path: str
    success: bool
    error: str | None = None
    duration_seconds: float = 0.0


class NetworkDetectionError(RuntimeError):
    """The local IPv4 network cannot be selected safely."""


def default_scan_output_dir() -> Path:
    return _MACOS_SCAN_DIR if platform.system() == "Darwin" else Path("scans")


def _run_system_command(command: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command, capture_output=True, text=True, encoding="utf-8", check=True, timeout=10,
        )
    except FileNotFoundError as exc:
        requirement = {
            "ip": "Instalați iproute2 (comanda ip cu suport JSON).",
            "powershell.exe": "Este necesar Windows PowerShell cu modulele NetTCPIP și NetAdapter.",
        }.get(command[0], "Verificați disponibilitatea utilitarelor native de rețea.")
        raise NetworkDetectionError(f"Lipsește utilitarul {command[0]}. {requirement}") from exc
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
        if columns[:4] == ["Destination", "Gateway", "Flags", "Netif"]:
            found_header = True
            continue
        if not found_header or not columns:
            continue
        if len(columns) < 4:
            raise NetworkDetectionError("Tabelul rutelor IPv4 este incomplet; detectarea a fost oprită.")
        destination, gateway, flags, interface = columns[:4]
        if re.fullmatch(r"lo\d+", interface):
            continue
        if "U" not in flags or "R" in flags or "B" in flags:
            raise NetworkDetectionError("Rută IPv4 inactivă, reject sau blackhole; verificați rutarea.")
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
    # Interfaces that carry a default route; a virtual one is a VPN-like path.
    default_ifaces = {r["InterfaceIndex"] for r in data["routes"]
                      if r["DestinationPrefix"] == "0.0.0.0/0"}
    candidates = []
    loopbacks = set()
    ignored = set()
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
            ignored.add(key)
            continue
        if adapter["HardwareInterface"] is not True:
            if key in default_ifaces:
                raise NetworkDetectionError(f"Adaptor IPv4 VPN/virtual activ: {adapter['Name']}.")
            # Docker/Hyper-V/WSL switches have no default route: not the LAN.
            ignored.add(key)
            continue
        # MSFT_NetIPAddress AddressState: Preferred = 4.
        if item["AddressState"] not in (4, "Preferred"):
            raise NetworkDetectionError("Adresa IPv4 nu este în starea Preferred.")
        candidate = _candidate(key, adapter["Name"], str(address), item["PrefixLength"])
        if candidate:
            candidates.append(candidate)
        else:
            ignored.add(key)  # e.g. 169.254.x.x with no DHCP lease
    routes = []
    for r in data["routes"]:
        key = r["InterfaceIndex"]
        if key in loopbacks:
            continue
        # Drop on-link routes of ignored interfaces, but never a default route:
        # a default route through an ignored interface stays ambiguous.
        if key in ignored and r["DestinationPrefix"] != "0.0.0.0/0":
            continue
        routes.append((key, r["DestinationPrefix"], r["NextHop"]))
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
    """Detect one unambiguous IPv4 LAN; never scan.

    Backends: macOS native tools, Windows PowerShell, Linux iproute2 JSON.
    Native demonstration platform: macOS; other platforms require lab validation.
    The caller must connect to the intended lab: IP configuration cannot prove
    that a network belongs to the laboratory or identify its hotspot owner.
    Raises NetworkDetectionError instead of choosing among ambiguous networks.
    """
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
    if not isinstance(target, str) or not target or target != target.strip():
        raise _permission_error("Țintă invalidă", "Invalid target")
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


def _check_policy(target: str, allowed_networks) -> tuple[str, ...]:
    target_network = _parse_target(target)
    try:
        if isinstance(allowed_networks, (str, bytes)):
            raise ValueError("Expected a collection of CIDRs")
        permitted = tuple(IPv4Network(value, strict=False) for value in allowed_networks)
    except (ValueError, TypeError) as exc:
        raise _permission_error("Allowlist invalid", "Invalid allowlist") from exc
    if not permitted or any(
        not any(network.subnet_of(private) for private in _PRIVATE_LANS)
        for network in (target_network, *permitted)
    ):
        raise _permission_error(
            "Sunt permise doar rețele private RFC1918; adresele speciale/publice sunt interzise",
            "Only RFC1918 private networks are allowed; special/public addresses are forbidden",
        )
    if target_network.prefixlen < 24:
        raise _permission_error("Subnetul este prea mare; limita este /24", "Subnet too large; limit is /24")
    if not any(target_network.subnet_of(network) for network in permitted):
        raise _permission_error("Ținta este în afara rețelei permise", "Target is outside the allowlist")
    return tuple(str(network) for network in permitted)


def _check_network(expected: NetworkInfo, target: str) -> None:
    current = detect_network()
    if current != expected:
        raise _permission_error(
            "Rețeaua s-a schimbat; reautorizați explicit laboratorul",
            "Network changed; explicitly reauthorize the laboratory",
        )
    if not _parse_target(target).subnet_of(IPv4Network(current.subnet)):
        raise _permission_error("Ținta nu este în LAN-ul autorizat", "Target is outside the authorized LAN")


def configure_lab_network(allowed_networks: list[str], *, confirm: bool = False,
                          config_path: str | Path = _DEFAULT_LAB_CONFIG) -> None:
    """Explicitly authorize and persist the current lab; never called automatically.

    Existing configuration is not overwritten. Remove it deliberately to authorize
    a different lab. IP/interface/gateway matching is not hotspot authentication.
    """
    if confirm is not True:
        raise _permission_error("Confirmarea laboratorului este obligatorie", "Lab confirmation is required")
    if not allowed_networks:
        raise _permission_error("Allowlist gol", "Empty allowlist")
    permitted = _check_policy(allowed_networks[0], allowed_networks)
    network = detect_network()
    if any(not IPv4Network(value).subnet_of(IPv4Network(network.subnet)) for value in permitted):
        raise _permission_error("Allowlist în afara LAN-ului", "Allowlist outside the LAN")
    Path(config_path).parent.mkdir(parents=True, exist_ok=True)
    with Path(config_path).open("x", encoding="utf-8") as handle:
        json.dump({"network": asdict(network), "allowed_networks": permitted}, handle, indent=2)


def _signature(target: str, allowed_networks: tuple[str, ...], network: NetworkInfo) -> str:
    payload = json.dumps([target, allowed_networks, asdict(network)], sort_keys=True).encode()
    return hmac.new(_VALIDATION_KEY, payload, hashlib.sha256).hexdigest()


def validate_scan_request(
    target: str,
    allowed_networks: list[str] | None = None,
    confirm: bool = False,
    *,
    config_path: str | Path = _DEFAULT_LAB_CONFIG,
) -> ValidatedTarget:
    """Validate against explicit authorization, never auto-authorize a detected LAN."""
    if confirm is not True:
        raise _permission_error("Confirmarea scanării este obligatorie", "Scan confirmation is required")
    if allowed_networks is None:
        try:
            data = json.loads(Path(config_path).read_text(encoding="utf-8"))
            expected = NetworkInfo(**data["network"])
            allowed_networks = data["allowed_networks"]
        except FileNotFoundError as exc:
            # Never auto-authorize the connected LAN: run `configure-lab` first.
            _default_allowed(detect_network())  # keeps the clear venue-Wi-Fi message
            raise _lab_not_configured() from exc
        except (OSError, ValueError, TypeError, KeyError) as exc:
            raise _permission_error(
                "Configurația laboratorului lipsește sau este invalidă; configurați explicit laboratorul",
                "Lab configuration missing or invalid; explicitly configure the lab",
            ) from exc
    else:
        # An explicit allowlist authorizes this request, bound to its current LAN.
        expected = None
    permitted = _check_policy(target, allowed_networks)
    canonical = str(_parse_target(target)) if "/" in target else str(IPv4Address(target))
    if expected is None:
        expected = detect_network()
    _check_network(expected, canonical)
    return ValidatedTarget(canonical, permitted, expected, _signature(canonical, permitted, expected))


def _lab_not_configured() -> PermissionError:
    return _permission_error(
        "Laboratorul nu este configurat; rulați `python -m netcheck configure-lab --confirm` pe hotspot-ul echipei",
        "Lab is not configured; run `python -m netcheck configure-lab --confirm` on your team hotspot",
    )


def _default_allowed(network: NetworkInfo) -> str:
    """The connected subnet as default allowlist; only hotspot-sized LANs.

    A phone hotspot is a /24 or smaller. A larger network (e.g. a /16 venue
    Wi-Fi) is never authorized automatically: scanning it is forbidden by the
    rules of engagement unless the team explicitly configures it.
    """
    subnet = IPv4Network(network.subnet)
    if subnet.prefixlen < 24:
        raise _permission_error(
            f"Rețeaua conectată ({subnet}) este prea mare pentru un hotspot și pare Wi-Fi-ul "
            "locației; conectează-te la hotspot-ul echipei. Scanarea ei este interzisă",
            f"The connected network ({subnet}) is too large for a hotspot and looks like the "
            "venue Wi-Fi; connect to your team hotspot. Scanning it is not allowed",
        )
    return str(subnet)


def default_scan_target(config_path: str | Path = _DEFAULT_LAB_CONFIG) -> str:
    """Saved lab subnet; refused when no lab was configured."""
    try:
        data = json.loads(Path(config_path).read_text(encoding="utf-8"))
        network = NetworkInfo(**data["network"])
        return network.subnet
    except FileNotFoundError as exc:
        # Never auto-authorize the connected LAN: run `configure-lab` first.
        _default_allowed(detect_network())  # keeps the clear venue-Wi-Fi message
        raise _lab_not_configured() from exc
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise _permission_error(
            "Configurația laboratorului lipsește sau este invalidă; configurați explicit laboratorul",
            "Lab configuration missing or invalid; explicitly configure the lab",
        ) from exc


def run_scan(validated_target: ValidatedTarget, output_path: str) -> ScanResult:
    """Run the fixed allowlisted Nmap scan and save its XML output."""

    if (not isinstance(validated_target, ValidatedTarget)
            or not isinstance(validated_target.network, NetworkInfo)
            or not isinstance(validated_target._validation_token, str)
            or not hmac.compare_digest(validated_target._validation_token, _signature(
                validated_target.target, validated_target.allowed_networks, validated_target.network))):
        raise _permission_error("Ținta nu este validată sau a fost modificată", "Target is unvalidated or modified")
    _check_policy(validated_target.target, validated_target.allowed_networks)
    _check_network(validated_target.network, validated_target.target)

    started = time.monotonic()
    def outcome(success: bool, error: str | None = None) -> ScanResult:
        return ScanResult(output_path, success, error, round(time.monotonic() - started, 3))

    if Path(output_path).exists():
        return outcome(False, "Fișierul există deja / Output file already exists")
    if platform.system() == "Darwin":
        command = [
            "sudo", "-n", str(_MACOS_NMAP_WRAPPER),
            validated_target.target, str(Path(output_path).resolve()),
        ]
    else:
        try:
            ports = port_specification()
        except FileNotFoundError as exc:
            if "nmap lipsește" in str(exc).lower() and "not installed" in str(exc).lower():
                return ScanResult(output_path, False, "nmap nu este instalat / nmap is not installed")
            return outcome(False, str(exc))
        except (OSError, ValueError) as exc:
            return outcome(False, str(exc))
        command = [
            "nmap", "-n", "-sS", "-sU", "-sV", "--script", "http-title",
            "--script-timeout", "30s", "-p", ports, "--max-rate", "100",
            "-oX", output_path, validated_target.target,
        ]

    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        return outcome(False, "Scanarea a depășit 300 s; XML incomplet / Scan exceeded 300 s; incomplete XML")
    except OSError as exc:
        if isinstance(exc, FileNotFoundError):
            return ScanResult(output_path, False, "nmap nu este instalat / nmap is not installed")
        return outcome(False, _scan_error_message(str(exc), ""))
    if result.returncode != 0:
        error = _scan_error_message(result.stderr, result.stdout)
        return outcome(False, error)
    try:
        read_completed_scan(output_path)
    except (OSError, ValueError, ParseError, DefusedXmlException) as exc:
        return outcome(False, f"Rezultat XML invalid / Invalid XML result: {exc}")
    return outcome(True)


def _scan_error_message(stderr: str, stdout: str) -> str:
    """Translate common Nmap privilege/driver failures without hiding details."""
    combined = f"{stderr}\n{stdout}".strip()
    lowered = combined.lower()
    if any(marker in lowered for marker in (
        "npcap", "failed to open device", "dnet: failed", "requires root",
        "must be run as root", "you need to be root", "permission denied",
        "operation not permitted", "could not open a raw socket",
        "password is required", "not allowed",
    )):
        return (
            "Privilegii sau driver Npcap lipsă pentru -sS/-sU; pe macOS instalați "
            "wrapperul și regula sudoers, iar pe Windows instalați/activați Npcap. "
            "/ Missing privileges or Npcap driver for -sS/-sU; on macOS install "
            "the wrapper and sudoers rule, and on Windows install/enable Npcap. "
            f"Detaliu / Detail: {combined or 'Nmap privilege error'}"
        )
    if any(marker in lowered for marker in ("no such file", "not found", "cannot find")):
        return "Nmap lipsește / Nmap is not installed"
    if not combined:
        return "Nmap a eșuat / Nmap failed"
    return combined
