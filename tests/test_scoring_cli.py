"""Tests for scoring, analysis models, and CSV export."""

import csv
from pathlib import Path

from netcheck.cli import main
from netcheck.scoring import analyze_file


VALIDATION_DIR = Path(__file__).parent / "validation"


def test_analyze_file_builds_model_and_score():
    result = analyze_file(VALIDATION_DIR / "V2_smart_home.xml")

    assert result["status"] == "ok"
    assert result["network_score"] == 40
    assert result["top_risk"] == {
        "ip": "192.168.1.40",
        "code": "CAMERA_STREAM_EXPOSED",
        "severity": "high",
    }
    camera = next(
        device for device in result["devices"] if device["ip"] == "192.168.1.40"
    )
    assert camera["mac_masked"] == "C0:56:E3:**:**:**"
    assert camera["device_type"] == "camera"


def test_analyze_file_returns_controlled_error():
    result = analyze_file(VALIDATION_DIR / "V7_broken.xml")

    assert result["status"] == "error"
    assert result["file"] == "V7_broken.xml"
    assert result["error"]["code"] == "invalid_xml"


def test_cli_writes_expected_csv_files(tmp_path):
    output = tmp_path / "out"

    assert main(["analyze", str(VALIDATION_DIR), "--out", str(output)]) == 0

    with (output / "scores.csv").open(newline="", encoding="utf-8") as handle:
        scores = list(csv.DictReader(handle))
    assert {row["file"]: row["network_score"] for row in scores} == {
        "V1_home_basic.xml": "90",
        "V2_smart_home.xml": "40",
        "V3_small_office.xml": "45",
        "V4_legacy.xml": "25",
        "V5_nonstandard_ports.xml": "50",
        "V6a_before.xml": "60",
        "V6b_after.xml": "100",
        "V7_broken.xml": "ERROR",
    }

    with (output / "findings.csv").open(newline="", encoding="utf-8") as handle:
        findings = list(csv.DictReader(handle))
    assert len(findings) == 24
    assert findings[-1]["finding_code"] == "TELNET_OPEN"
