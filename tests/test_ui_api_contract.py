"""API contract used by the web UI: every route, every error code, source marking, report privacy."""
from pathlib import Path
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from netcheck import api, history, scanner, service
from netcheck.scanner import NetworkInfo, ScanResult

VALIDATION = Path(__file__).parent / "validation"
LAB = NetworkInfo("en0", "172.20.10.2", 28, "172.20.10.0/28", "172.20.10.1")


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setattr(history, "DB_PATH", tmp_path / "ui.db")
    return TestClient(api.create_app(config_path=tmp_path / "none.json", output_dir=tmp_path), base_url="http://127.0.0.1")


def import_file(client, name, display=None):
    return client.post(f"/api/import?filename={display or name}", content=(VALIDATION / name).read_bytes(),
                       headers={"content-type": "application/xml"})


# ---- source marking: Home reads live scans, Import never appears there ----
def test_import_is_marked_import_and_listed_with_source(client):
    scan_id = import_file(client, "V1_home_basic.xml").json()["scan_id"]
    rows = client.get("/api/scans").json()
    assert [(r["id"], r["source"]) for r in rows] == [(scan_id, "import")]
    assert client.get(f"/api/scans/{scan_id}").json()["source"] == "import"


def test_live_scan_is_marked_live(client, tmp_path):
    result = ScanResult(str(VALIDATION / "V2_smart_home.xml"), True, None, 1.5)
    with patch.object(service, "scan", return_value=result):
        response = client.post("/api/scan", json={"target": "172.20.10.3", "confirm": True})
    assert response.status_code == 200
    body = response.json()
    assert body["network_score"] == 40 and body["source"] == "live"
    assert client.get(f"/api/scans/{body['scan_id']}").json()["source"] == "live"
    # an import afterwards does not change which scan Home would pick (the newest *live* one)
    import_file(client, "V1_home_basic.xml")
    live = [r for r in client.get("/api/scans").json() if r["source"] == "live"]
    assert [r["id"] for r in live] == [body["scan_id"]]


def test_scan_response_has_bilingual_catalog_text_for_the_ui(client):
    with patch.object(service, "scan", return_value=ScanResult(str(VALIDATION / "V2_smart_home.xml"), True)):
        body = client.post("/api/scan", json={"target": "172.20.10.3", "confirm": True}).json()
    finding = body["findings"][0]
    for field in ("title", "explain", "fix"):
        assert set(finding[field]) == {"ro", "en"}


# ---- POST /api/scan: every error code the UI handles ----
@pytest.mark.parametrize("raised,status,code", [
    (PermissionError("Ținta este în afara rețelei permise / Target is outside the allowlist"), 403, "permission_denied"),
    (scanner.NetworkDetectionError("Nu există o conexiune LAN IPv4 activă utilizabilă."), 409, "network_detection_failed"),
    (OSError("disk"), 500, "operation_failed"),
])
def test_scan_error_codes(client, raised, status, code):
    with patch.object(service, "scan", side_effect=raised):
        response = client.post("/api/scan", json={"target": "172.20.10.3", "confirm": True})
    assert response.status_code == status
    error = response.json()["error"]
    assert error["code"] == code and set(error["message"]) == {"ro", "en"}


def test_scan_busy_is_409_with_detail(client):
    with patch.object(service, "scan", side_effect=service.ScanBusyError("O scanare este deja în curs / A scan is already in progress")):
        response = client.post("/api/scan", json={"target": "172.20.10.3", "confirm": True})
    assert response.status_code == 409 and "error" not in response.json()
    assert "scan" in response.json()["detail"].lower()


def test_scan_failed_is_502_scan_failed(client):
    with patch.object(service, "scan", return_value=ScanResult("x.xml", False, "nmap nu este instalat / nmap is not installed")):
        response = client.post("/api/scan", json={"target": "172.20.10.3", "confirm": True})
    assert response.status_code == 502
    assert response.json()["error"]["code"] == "scan_failed"
    assert client.get("/api/scans").json() == []  # nothing saved for a failed scan


@pytest.mark.parametrize("body", [{"confirm": "true"}, {"target": "172.20.10.3", "confirm": 1}, {"target": 5}])
def test_scan_rejects_invalid_requests_with_422(client, body):
    assert client.post("/api/scan", json=body).status_code == 422


def test_scan_without_confirm_is_refused_before_nmap(client):
    with patch("netcheck.scanner.detect_network", return_value=LAB), patch("netcheck.scanner.subprocess.run") as process:
        response = client.post("/api/scan", json={"target": "172.20.10.3"})
    assert response.status_code == 403 and process.call_count == 0


# ---- GET /api/network and preview ----
def test_network_ok_and_409(client):
    with patch.object(scanner, "detect_network", return_value=LAB):
        assert client.get("/api/network").json()["subnet"] == "172.20.10.0/28"
    with patch.object(scanner, "detect_network", side_effect=scanner.NetworkDetectionError("none")):
        assert client.get("/api/network").status_code == 409


def test_preview_reports_blocked_venue_network(client):
    venue = NetworkInfo("wlan", "10.240.236.194", 16, "10.240.0.0/16", "10.240.0.3")
    with patch.object(scanner, "detect_network", return_value=venue), \
            patch("netcheck.api.port_specification", return_value="T:80,443,U:53,123,161,1900,5353"):
        body = client.get("/api/scan/preview").json()
    assert body["target"] is None and body["problems"]


def test_preview_ready_on_a_hotspot(client):
    with patch.object(scanner, "detect_network", return_value=LAB), \
            patch("netcheck.api.port_specification", return_value="T:80,443,U:53,123,161,1900,5353"):
        body = client.get("/api/scan/preview").json()
    assert body["target"] == "172.20.10.0/28" and body["nmap"] is True and body["tcp_ports"] == 2


# ---- import / list / get / compare / delete ----
def test_import_batch_and_broken_file_do_not_crash(client):
    ids = [import_file(client, n).json() for n in ("V1_home_basic.xml", "V7_broken.xml", "V3_small_office.xml")]
    assert [i["status"] for i in ids] == ["ok", "error", "ok"]
    assert len(client.get("/api/scans").json()) == 3


def test_get_unknown_scan_is_404_and_compare_needs_valid_scans(client):
    assert client.get("/api/scans/999").status_code == 404
    ok = import_file(client, "V1_home_basic.xml").json()["scan_id"]
    broken = import_file(client, "V7_broken.xml").json()["scan_id"]
    assert client.get(f"/api/compare?a={ok}&b={broken}").status_code == 400
    assert client.get(f"/api/compare?a={ok}&b=999").status_code == 404


def test_delete_history_clears_everything(client):
    import_file(client, "V1_home_basic.xml")
    assert client.delete("/api/history").json() == {"status": "ok"}
    assert client.get("/api/scans").json() == []


# ---- POST /api/ask: the UI must work with and without it ----
def test_ask_falls_back_to_documentation_without_a_provider(client, monkeypatch):
    monkeypatch.delenv("NETCHECK_LLM_API_KEY", raising=False)
    monkeypatch.delenv("NETCHECK_LLM_MODEL", raising=False)
    scan_id = import_file(client, "V2_smart_home.xml").json()["scan_id"]
    response = client.post("/api/ask", json={"scan_id": scan_id, "device_ip": "192.168.1.40", "question": "Ce înseamnă?", "lang": "ro"})
    assert response.status_code == 200
    body = response.json()
    assert body["mode"] == "fallback" and isinstance(body["answer"], str) and "sources" in body


def test_ask_errors(client):
    assert client.post("/api/ask", json={"scan_id": 99, "question": "x", "lang": "ro"}).status_code == 404
    scan_id = import_file(client, "V2_smart_home.xml").json()["scan_id"]
    assert client.post("/api/ask", json={"scan_id": scan_id, "device_ip": "1.2.3.4", "question": "x", "lang": "ro"}).status_code == 404
    broken = import_file(client, "V7_broken.xml").json()["scan_id"]
    assert client.post("/api/ask", json={"scan_id": broken, "question": "x", "lang": "ro"}).status_code == 400
    assert client.post("/api/ask", json={"scan_id": scan_id, "question": "", "lang": "ro"}).status_code == 422


# ---- GET /api/report ----
def test_report_has_no_hostname_no_full_mac_and_escapes(client):
    before = import_file(client, "V6a_before.xml", display="%3Cscript%3Ealert(1)%3C%2Fscript%3E.xml").json()["scan_id"]
    after = import_file(client, "V6b_after.xml").json()["scan_id"]
    for url in (f"/api/report?a={before}&b={after}&lang=ro", f"/api/report?a={before}&lang=en"):
        response = client.get(url)
        assert response.status_code == 200
        html = response.text
        assert "@page" in html and "A4" in html
        assert "<script>alert" not in html and "router.lan" not in html
        assert "50:C7:BF:88:24:57" not in html
        assert "**:**:**" in html
    ro = client.get(f"/api/report?a={before}&b={after}&lang=ro").text
    assert "60 → 100" in ro and "Rezolvate între scanări" in ro


def test_report_rejects_bad_requests(client):
    assert client.get("/api/report?a=999").status_code == 404
    broken = import_file(client, "V7_broken.xml").json()["scan_id"]
    assert client.get(f"/api/report?a={broken}").status_code == 400
    assert client.get("/api/report?a=1&lang=fr").status_code == 422
