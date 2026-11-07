"""Tests for network detection, target validation, and Nmap execution."""

from pathlib import Path
from unittest.mock import patch

import pytest

from netcheck.scanner import (
    NetworkInfo,
    ValidatedTarget,
    detect_network,
    run_scan,
    validate_scan_request,
)


def test_detect_network_parses_macos_commands():
    outputs = {
        ("route", "-n", "get", "default"): (
            "   gateway: 172.20.10.1\n"
            " interface: en0\n"
        ),
        ("ipconfig", "getifaddr", "en0"): "172.20.10.3\n",
        ("ifconfig", "en0"): "inet 172.20.10.3 netmask 0xfffffff0 broadcast 172.20.10.15\n",
    }

    def fake_run(command, **kwargs):
        key = tuple(command)
        return type("Completed", (), {"stdout": outputs[key], "stderr": ""})()

    with patch("netcheck.scanner.subprocess.run", side_effect=fake_run):
        result = detect_network()

    assert result == NetworkInfo(
        interface="en0",
        ip="172.20.10.3",
        cidr="172.20.10.0/28",
        gateway="172.20.10.1",
    )


def test_validate_scan_request_accepts_allowed_private_network():
    result = validate_scan_request(
        "172.20.10.0/28",
        ["172.20.10.0/28"],
        confirm=True,
    )

    assert result.target == "172.20.10.0/28"
    assert result.allowed_networks == ["172.20.10.0/28"]


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


def test_run_scan_builds_fixed_command_and_writes_xml(tmp_path):
    output_path = str(tmp_path / "scan.xml")
    validated = validate_scan_request(
        "172.20.10.3",
        ["172.20.10.0/28"],
        confirm=True,
    )

    def fake_run(command, **kwargs):
        expected = [
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
            "172.20.10.3",
        ]
        assert command == expected
        assert kwargs == {"capture_output": True, "text": True}
        Path(output_path).write_text("<nmaprun />", encoding="utf-8")
        return type("Completed", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    with patch("netcheck.scanner.subprocess.run", side_effect=fake_run):
        result = run_scan(validated, output_path)

    assert result.xml_path == output_path
    assert result.success is True
    assert result.error is None
