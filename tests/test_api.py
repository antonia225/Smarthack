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


def test_live_scan_rejects_unauthorized_target(monkeypatch, tmp_path):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "netcheck.db")
    run_called = False

    def fail_if_called(*args, **kwargs):
        nonlocal run_called
        run_called = True
        raise AssertionError("nmap must not run for a rejected target")

    monkeypatch.setattr(api, "run_scan", fail_if_called)
    client = TestClient(api.app)

    response = client.post(
        "/api/scan",
        json={
            "target": "8.8.8.8",
            "allowed_networks": ["172.20.10.0/28"],
            "confirm": True,
        },
    )

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "permission_denied"
    assert run_called is False
