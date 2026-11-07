"""Focused tests for Nmap parsing and fixed findings rules."""

from pathlib import Path

from netcheck.parser import parse_file
from netcheck.rules import evaluate_findings


VALIDATION_DIR = Path(__file__).parent / "validation"


def test_parser_extracts_devices_ports_and_http_title():
    scan = parse_file(VALIDATION_DIR / "V2_smart_home.xml")

    assert scan.status == "ok"
    camera = next(device for device in scan.devices if device.ip == "192.168.1.40")
    http = next(port for port in camera.ports if port.port == 80)
    assert camera.vendor == "Hikvision"
    assert camera.hostname == "ipcam"
    assert http.http_title == "Camera Web Login"


def test_parser_returns_controlled_error_for_truncated_xml():
    scan = parse_file(VALIDATION_DIR / "V7_broken.xml")

    assert scan.status == "error"
    assert scan.error is not None
    assert scan.error["code"] == "invalid_xml"


def test_rules_apply_service_and_http_findings():
    scan = parse_file(VALIDATION_DIR / "V2_smart_home.xml")

    findings = evaluate_findings(scan)

    assert [(finding.ip, finding.port, finding.code) for finding in findings] == [
        ("192.168.1.40", 554, "CAMERA_STREAM_EXPOSED"),
        ("192.168.1.1", 80, "HTTP_ADMIN_CLEARTEXT"),
        ("192.168.1.1", 1900, "UPNP_EXPOSED"),
        ("192.168.1.40", 80, "HTTP_ADMIN_CLEARTEXT"),
        ("192.168.1.41", 1883, "MQTT_EXPOSED"),
    ]


def test_rules_use_one_smb_finding_and_ignore_filtered_ports():
    scan = parse_file(VALIDATION_DIR / "V3_small_office.xml")

    findings = evaluate_findings(scan)
    smb = [finding for finding in findings if finding.code == "SMB_EXPOSED"]

    assert [(finding.ip, finding.port) for finding in smb] == [
        ("192.168.1.20", 445)
    ]
    assert not any(
        finding.code == "DB_EXPOSED" and finding.ip == "192.168.1.20"
        for finding in findings
    )
