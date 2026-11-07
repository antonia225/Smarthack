"""Tests for the local FastAPI endpoints."""

from pathlib import Path

from fastapi.testclient import TestClient

from netcheck import api, history


VALIDATION_DIR = Path(__file__).parent / "validation"


def test_import_list_get_compare_and_delete(monkeypatch, tmp_path):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "netcheck.db")
    client = TestClient(api.app)
    xml = (VALIDATION_DIR / "V6a_before.xml").read_bytes()

    response = client.post(
        "/api/import?filename=V6a_before.xml",
        content=xml,
        headers={"content-type": "application/xml"},
    )
    assert response.status_code == 200
    before_id = response.json()["scan_id"]
    assert response.json()["network_score"] == 60

    response = client.post(
        "/api/import?filename=V6b_after.xml",
        content=(VALIDATION_DIR / "V6b_after.xml").read_bytes(),
    )
    after_id = response.json()["scan_id"]
    assert client.get("/api/scans").status_code == 200
    assert client.get(f"/api/scans/{before_id}").json()["file"] == "V6a_before.xml"

    comparison = client.get(
        f"/api/compare?a={before_id}&b={after_id}"
    ).json()
    assert comparison["score_before"] == 60
    assert comparison["score_after"] == 100
    assert len(comparison["resolved_findings"]) == 3

    assert client.delete("/api/history").json() == {"status": "ok"}
    assert client.get("/api/scans").json() == []


def test_report_is_escaped_private_and_contains_resolved_findings(monkeypatch, tmp_path):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "report.db")
    client = TestClient(api.app)
    before = client.post(
        "/api/import?filename=%3Cunsafe%3E.xml",
        content=(VALIDATION_DIR / "V6a_before.xml").read_bytes(),
    ).json()["scan_id"]
    after = client.post(
        "/api/import?filename=after.xml",
        content=(VALIDATION_DIR / "V6b_after.xml").read_bytes(),
    ).json()["scan_id"]

    report = client.get(f"/api/report?a={before}&b={after}&lang=en")

    assert report.status_code == 200
    html = report.text
    assert "<!doctype html>" in html
    assert "50:C7:BF:88:24:57" not in html
    assert "router.lan" not in html
    assert "&lt;unsafe&gt;.xml" not in html
    assert "Resolved between scans" in html
    assert "Telnet" in html


def test_report_rejects_missing_or_invalid_scan(monkeypatch, tmp_path):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "report-errors.db")
    client = TestClient(api.app)
    assert client.get("/api/report?a=404").status_code == 404


import pytest
from dataclasses import dataclass
from netcheck.catalog import load_catalog
from netcheck.scoring import analyze_file


@pytest.mark.parametrize("lang", [None, "ro", "en"])
def test_catalog_on_import_retrieval_and_simulated_scan(monkeypatch, lang):
    client = TestClient(api.app)
    source = VALIDATION_DIR / "V6a_before.xml"
    raw = analyze_file(source)
    query = "" if lang is None else "?lang=" + lang

    @dataclass
    class SimulatedResult:
        success: bool = True
        xml_path: str = str(source)

    monkeypatch.setattr(api.service, "scan", lambda *args, **kwargs: SimulatedResult())
    imported = client.post("/api/import" + query, content=source.read_bytes())
    assert imported.status_code == 200
    scan_id = imported.json()["scan_id"]
    retrieved = client.get(f"/api/scans/{scan_id}" + query)
    scanned = client.post("/api/scan" + query, json={"target": "192.168.1.1", "confirm": True})
    for response in (imported, retrieved, scanned):
        assert response.status_code == 200
        result = response.json()
        assert result["network_score"] == raw["network_score"]
        assert result["devices"] == raw["devices"]
        assert result["top_risk"] == raw["top_risk"]
        original = {f["code"]: f for f in raw["findings"]}
        for finding in result["findings"]:
            entry = load_catalog()[finding["code"]]
            for field in ("title", "explain", "fix"):
                assert finding[field] == (entry[field] if lang is None else entry[field][lang])
            assert {k: v for k, v in finding.items() if k not in {"title", "explain", "fix"}} == original[finding["code"]]
    assert all("title" not in f for f in history.get_scan(scan_id)["findings"])


def test_invalid_language_rejected_before_scan(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("must not scan for an invalid language")
    monkeypatch.setattr(api.service, "scan", forbidden)
    client = TestClient(api.app)
    assert client.post("/api/scan?lang=fr", json={"target": "192.168.1.1", "confirm": True}).status_code == 422
    assert client.post("/api/import?lang=fr", content=b"").status_code == 422
    assert client.get("/api/scans/1?lang=fr").status_code == 422


def test_missing_catalog_returns_bilingual_error(monkeypatch, tmp_path):
    from netcheck import catalog
    catalog._read_catalog.cache_clear()
    monkeypatch.setattr(catalog, "CATALOG_PATH", tmp_path / "missing.json")
    try:
        response = TestClient(api.app).post("/api/import", content=(VALIDATION_DIR / "V6a_before.xml").read_bytes())
        assert response.status_code == 503
        assert response.json()["error"]["code"] == "catalog_unavailable"
        assert set(response.json()["error"]["message"]) == {"ro", "en"}
        assert history.list_scans() == []
    finally:
        catalog._read_catalog.cache_clear()


@pytest.mark.parametrize("filename", ["V6b_after.xml", "V7_broken.xml"])
def test_catalog_preserves_empty_and_invalid_analysis(filename):
    source = VALIDATION_DIR / filename
    expected = analyze_file(source)
    client = TestClient(api.app)
    response = client.post("/api/import", params={"filename": filename}, content=source.read_bytes())
    assert response.status_code == 200
    result = response.json()
    scan_id = result.pop("scan_id")
    assert result == expected
    assert client.get(f"/api/scans/{scan_id}").json() == expected


@pytest.mark.parametrize(('filename', 'display_name'), [
    ('<unsafe>.xml', '<unsafe>.xml'),
    ('CON.xml', 'CON.xml'),
    ('report:before?.xml', 'report:before?.xml'),
    ('x' * 260 + '.xml', 'x' * 260 + '.xml'),
    (r'C:\uploads\report<unsafe>.xml', 'report<unsafe>.xml'),
    ('../../uploads/before.xml', 'before.xml'),
    ('', 'scan.xml'),
])
def test_import_client_filename_is_only_display_metadata(monkeypatch, filename, display_name):
    original_write = Path.write_bytes
    writes = []

    def windows_compatible_write(path, content):
        # Reproduce Windows filename restrictions even when CI runs on Unix.
        invalid = '<>:"/\\|?*'
        stem = path.name.split('.')[0].upper()
        if (any(char in path.name for char in invalid) or len(path.name) > 255
                or stem in {'CON', 'PRN', 'AUX', 'NUL'}):
            raise OSError(22, 'Invalid argument', str(path))
        writes.append(path)
        return original_write(path, content)

    monkeypatch.setattr(Path, 'write_bytes', windows_compatible_write)
    client = TestClient(api.app)
    response = client.post('/api/import', params={'filename': filename},
                           content=(VALIDATION_DIR / 'V6a_before.xml').read_bytes())

    assert response.status_code == 200
    result = response.json()
    assert result['file'] == display_name
    assert result['network_score'] == 60
    assert writes and all(not path.exists() for path in writes)
    saved = client.get(f"/api/scans/{result['scan_id']}").json()
    assert saved['file'] == display_name
