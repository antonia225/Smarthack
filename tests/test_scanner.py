"""Tests for network detection, target validation, and Nmap execution."""

from pathlib import Path
import sys
from unittest.mock import patch

import pytest

from netcheck.scanner import (
    NetworkInfo,
    ValidatedTarget,
    detect_network,
    run_scan,
    validate_scan_request,
)


def interface(name="en0", ip="172.20.10.3", mask="0xfffffff0", flags="UP,BROADCAST,RUNNING", status="active"):
    return f"{name}: flags=8863<{flags}> mtu 1500\n\tinet {ip} netmask {mask}\n\tstatus: {status}\n"


def detect_with(interfaces, routes="default 172.20.10.1 UGScg en0\n"):
    outputs = {
        ("/sbin/ifconfig", "-a"): interfaces,
        ("/usr/sbin/netstat", "-rn", "-f", "inet"): "Destination Gateway Flags Netif Expire\n" + routes,
    }
    def fake_run(command, **kwargs):
        return type("Completed", (), {"stdout": outputs[tuple(command)]})()
    with patch("netcheck.scanner.platform.system", return_value="Darwin"), patch(
        "netcheck.scanner.subprocess.run", side_effect=fake_run
    ):
        return detect_network()


@pytest.mark.parametrize("mask,prefix,subnet", [
    ("0xfffffff0", 28, "172.20.10.0/28"),
    ("0xffffff00", 24, "172.20.10.0/24"),
    ("255.255.254.0", 23, "172.20.10.0/23"),
])
def test_detect_network_uses_real_mask(mask, prefix, subnet):
    result = detect_with(interface(mask=mask) + interface("lo0", "127.0.0.1", flags="UP,LOOPBACK"))
    assert result == NetworkInfo("en0", "172.20.10.3", prefix, subnet, "172.20.10.1")
    assert result.cidr == subnet


@pytest.mark.parametrize("interfaces,routes", [
    ("", ""),
    (interface(status="inactive"), ""),
    (interface(ip="169.254.1.2"), ""),
    (interface() + interface("en1"), "default 172.20.10.1 UG en0"),
    (interface() + interface("utun0", flags="UP,POINTOPOINT"), ""),
    (interface() + interface("bridge0"), ""),
    (interface(), "default 172.20.10.1 UG en0\n10/8 10.0.0.1 UG utun0"),
    (interface(), ""),
    (interface(), "default 192.168.1.1 UG en0"),
    (interface(), "default 172.20.10.1 UG en0\ndefault 172.20.10.4 UG en0"),
    (interface(mask="0xff00ff00"), ""),
    (interface(), "default link#14 UG en0"),
    (interface(), "default 172.20.10.3 UG en0"),
    (interface(), "default 172.20.10.1 UG en0\n10/8 10.0.0.1"),
    (interface(), "default 172.20.10.1 UGR en0"),
    (interface(), "default 172.20.10.1 UGB en0"),
    (interface(), "default 172.20.10.1 UG en0\n10/8 172.20.10.1 G en0"),
    (interface() + "\tinet 172.20.10.4 netmask 0xfffffff0\n", ""),
])
def test_detect_network_fails_closed(interfaces, routes):
    from netcheck.scanner import NetworkDetectionError
    with pytest.raises(NetworkDetectionError):
        detect_with(interfaces, routes)


def test_ipv6_only_tunnel_does_not_block_ipv4():
    assert detect_with(interface() + "utun0: flags=8051<UP,POINTOPOINT> mtu 1500\n\tinet6 fe80::1 prefixlen 64\n").interface == "en0"


def test_macos_local_host_route_and_inactive_interface_are_excluded():
    result = detect_with(
        interface() + interface("en1", status="inactive"),
        "default 172.20.10.1 UGScg en0\n172.20.10.3 00:11:22:33:44:55 UHLWI lo0\n",
    )
    assert result.interface == "en0"


def test_unsupported_platform():
    from netcheck.scanner import NetworkDetectionError
    with patch("netcheck.scanner.platform.system", return_value="FreeBSD"), patch("netcheck.scanner.subprocess.run") as run:
        with pytest.raises(NetworkDetectionError, match="macOS"):
            detect_network()
        run.assert_not_called()


def test_command_failure_is_clear():
    from netcheck.scanner import NetworkDetectionError
    with patch("netcheck.scanner.platform.system", return_value="Darwin"), patch("netcheck.scanner.subprocess.run", side_effect=OSError("unavailable")):
        with pytest.raises(NetworkDetectionError, match="configurația"):
            detect_network()


@patch("netcheck.scanner.detect_network", return_value=NetworkInfo("en0", "172.20.10.2", 28, "172.20.10.0/28", "172.20.10.1"))
def test_validate_scan_request_accepts_allowed_private_network(_detect):
    result = validate_scan_request(
        "172.20.10.0/28",
        ["172.20.10.0/28"],
        confirm=True,
    )

    assert result.target == "172.20.10.0/28"
    assert result.allowed_networks == ("172.20.10.0/28",)


@pytest.mark.parametrize("target", ["8.8.8.8", "172.20.11.3"])
def test_validate_scan_request_rejects_public_or_disallowed_target(target):
    with pytest.raises(PermissionError):
        validate_scan_request(
            target,
            ["172.20.10.0/28"],
            confirm=True,
        )


def test_validate_scan_request_requires_confirmation():
    with pytest.raises(PermissionError):
        validate_scan_request(
            "172.20.10.3",
            ["172.20.10.0/28"],
            confirm=False,
        )


def test_validate_scan_request_rejects_subnet_larger_than_slash_24():
    with pytest.raises(PermissionError):
        validate_scan_request(
            "10.240.0.0/16",
            ["10.240.0.0/16"],
            confirm=True,
        )


def test_run_scan_rejects_unvalidated_target(tmp_path):
    target = ValidatedTarget("172.20.10.3", ["172.20.10.0/28"])

    with pytest.raises(PermissionError):
        run_scan(target, str(tmp_path / "scan.xml"))


@patch("netcheck.scanner.detect_network", return_value=NetworkInfo("en0", "172.20.10.2", 28, "172.20.10.0/28", "172.20.10.1"))
def test_run_scan_builds_fixed_command_and_writes_xml(_detect, tmp_path):
    output_path = str(tmp_path / "scan.xml")
    validated = validate_scan_request(
        "172.20.10.3",
        ["172.20.10.0/28"],
        confirm=True,
    )

    def fake_run(command, **kwargs):
        if sys.platform == "darwin":
            expected = [
                "sudo", "-n", "/usr/local/libexec/netcheck-nmap-wrapper",
                "172.20.10.3", output_path,
            ]
        else:
            expected = [
                "nmap", "-n", "-sS", "-sU", "-sV", "--script", "http-title",
                "--script-timeout", "30s", "-p",
                "T:1-1000,U:53,123,161,1900,5353", "--max-rate", "100",
                "-oX", output_path, "172.20.10.3",
            ]
        assert command == expected
        assert kwargs == {"capture_output": True, "text": True, "timeout": 300}
        Path(output_path).write_text('<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>', encoding="utf-8")
        return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch("netcheck.scanner.subprocess.run", side_effect=fake_run), patch(
        "netcheck.scanner.port_specification", return_value="T:1-1000,U:53,123,161,1900,5353"
    ):
        result = run_scan(validated, output_path)

    assert result.xml_path == output_path
    assert result.success is True
    assert result.error is None
