"""Tests for SQLite scan history."""

from pathlib import Path

from netcheck import history
from netcheck.scoring import analyze_file


VALIDATION_DIR = Path(__file__).parent / "validation"


def test_save_and_read_scan(monkeypatch, tmp_path):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "netcheck.db")
    analysis = analyze_file(VALIDATION_DIR / "V2_smart_home.xml")

    scan_id = history.save_scan(analysis)
    assert history.get_scan(scan_id) == analysis


def test_compare_v6_reports_resolved_findings(monkeypatch, tmp_path):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "netcheck.db")
    before_id = history.save_scan(analyze_file(VALIDATION_DIR / "V6a_before.xml"))
    after_id = history.save_scan(analyze_file(VALIDATION_DIR / "V6b_after.xml"))

    result = history.compare(before_id, after_id)

    assert result["score_before"] == 60
    assert result["score_after"] == 100
    assert len(result["resolved_findings"]) == 3
    assert result["new_findings"] == []


def test_delete_history(monkeypatch, tmp_path):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "netcheck.db")
    history.save_scan(analyze_file(VALIDATION_DIR / "V1_home_basic.xml"))

    history.delete_history()

    assert history.list_scans() == []
