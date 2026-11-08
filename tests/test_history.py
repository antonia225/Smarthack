"""Tests for SQLite scan history."""

from pathlib import Path
import sqlite3

import pytest

from netcheck import history
from netcheck.scoring import analyze_file


VALIDATION_DIR = Path(__file__).parent / "validation"


def test_save_and_read_scan(monkeypatch, tmp_path):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "netcheck.db")
    analysis = analyze_file(VALIDATION_DIR / "V2_smart_home.xml")

    scan_id = history.save_scan(analysis)
    # Without an explicit source the file name is stored (legacy behaviour).
    assert history.get_scan(scan_id) == {**analysis, "source": analysis["file"]}


def test_source_is_stored_and_listed(monkeypatch, tmp_path):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "netcheck.db")
    live = history.save_scan({**analyze_file(VALIDATION_DIR / "V1_home_basic.xml"), "source": "live"})
    imported = history.save_scan({**analyze_file(VALIDATION_DIR / "V7_broken.xml"), "source": "import"})
    assert history.get_scan(live)["source"] == "live"
    assert history.get_scan(imported)["source"] == "import"
    assert [(row["id"], row["source"]) for row in history.list_scans()] == [(live, "live"), (imported, "import")]


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
    scan_id = history.save_scan(analyze_file(VALIDATION_DIR / "V1_home_basic.xml"))

    history.delete_history()

    assert history.list_scans() == []
    assert history.list_answers(scan_id) == []


def test_save_and_list_answers(monkeypatch, tmp_path):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "netcheck.db")
    scan_id = history.save_scan(analyze_file(VALIDATION_DIR / "V1_home_basic.xml"))

    first_id = history.save_answer(scan_id, "Prima întrebare", "Primul răspuns", "fallback")
    second_id = history.save_answer(scan_id, "A doua întrebare", "Al doilea răspuns", "ai")

    answers = history.list_answers(scan_id)
    assert [answer["id"] for answer in answers] == [first_id, second_id]
    assert answers[0]["question"] == "Prima întrebare"
    assert answers[0]["answer"] == "Primul răspuns"
    assert answers[0]["mode"] == "fallback"
    assert answers[1]["mode"] == "ai"
    assert answers[0]["created_at"]


def test_answers_are_filtered_by_device_and_language(monkeypatch, tmp_path):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "netcheck.db")
    scan_id = history.save_scan(analyze_file(VALIDATION_DIR / "V1_home_basic.xml"))

    history.save_answer(scan_id, "Router?", "Răspuns", "fallback", "192.168.1.1", "ro")
    history.save_answer(scan_id, "Ports?", "Answer", "ai", "192.168.1.2", "en")

    answers = history.list_answers(scan_id, device_ip="192.168.1.1", lang="ro")
    assert [answer["question"] for answer in answers] == ["Router?"]


def test_history_closes_connections_on_success_and_failure(monkeypatch, tmp_path):
    connections = []
    original = sqlite3.connect

    def connect(*args, **kwargs):
        connection = original(*args, **kwargs)
        connections.append(connection)
        return connection

    monkeypatch.setattr(history.sqlite3, "connect", connect)
    assert history.list_scans() == []
    with pytest.raises(KeyError):
        history.get_scan(999)
    for connection in connections:
        with pytest.raises(sqlite3.ProgrammingError, match="closed"):
            connection.execute("SELECT 1")
