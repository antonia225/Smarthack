"""Regressions for real Nmap table guesses and Apple/lab fingerprints."""
from netcheck.scoring import analyze_file


def analyze(tmp_path, ports):
    path = tmp_path / 'evidence.xml'
    path.write_text('<nmaprun><host><address addr="172.20.10.2" addrtype="ipv4"/><ports>' + ports + '</ports></host></nmaprun>')
    return analyze_file(path)


def port(number, name, extra='', state='open'):
    return f'<port protocol="tcp" portid="{number}"><state state="{state}"/><service name="{name}" {extra}/></port>'


def test_table_names_are_not_service_evidence(tmp_path):
    result = analyze(tmp_path, port(21, 'ftp', 'method="table" conf="3"') + port(5432, 'postgresql', 'method="table" conf="3"'))
    assert result['network_score'] == 100
    assert {p['service'] for p in result['devices'][0]['ports']} == {'unknown'}
    assert all(f['severity'] == 'info' and f['points'] == 0 for f in result['findings'])


def test_airtunes_fingerprint_overrides_rtsp_and_camera_guess(tmp_path):
    result = analyze(tmp_path, port(5000, 'rtsp', 'method="table" conf="3" servicefp="RTSP/1.0 403 Forbidden Server: AirTunes/1005.13.1"'))
    device = result['devices'][0]
    assert device['ports'][0]['service'] == 'airplay'
    assert device['device_type'] != 'camera'
    assert result['network_score'] == 100
    assert not any(f['code'] == 'CAMERA_STREAM_EXPOSED' for f in result['findings'])


def test_lab_banner_overrides_incorrect_printer_product(tmp_path):
    result = analyze(tmp_path, port(23, 'telnet', 'method="table" product="HP LaserJet telnetd" servicefp="SmartHack Telnet simulator No shell"'))
    assert result['devices'][0]['ports'][0]['product'] == 'SmartHack Telnet simulator'
    assert any(f['code'] == 'TELNET_OPEN' for f in result['findings'])
    assert result['network_score'] == 80


def test_probed_database_keeps_exposure_finding(tmp_path):
    result = analyze(tmp_path, port(5432, 'postgresql', 'method="probed" conf="10" product="PostgreSQL"'))
    assert any(f['code'] == 'DB_EXPOSED' for f in result['findings'])
    assert result['network_score'] == 80


def test_low_confidence_probe_is_not_a_confirmed_service(tmp_path):
    result = analyze(tmp_path, port(5432, 'postgresql', 'method="probed" conf="3"'))
    assert result['devices'][0]['ports'][0]['service'] == 'unknown'
    assert result['network_score'] == 100


def test_rtsp_without_camera_evidence_does_not_classify_camera(tmp_path):
    result = analyze(tmp_path, port(554, 'rtsp', 'method="probed" conf="10"'))
    assert result['devices'][0]['device_type'] == 'unknown'
    assert any(f['code'] == 'CAMERA_STREAM_EXPOSED' for f in result['findings'])


def test_closed_rtsp_does_not_classify_camera(tmp_path):
    result = analyze(tmp_path, port(554, 'rtsp', 'product="IP camera" method="probed"', state='closed'))
    assert result['devices'][0]['device_type'] == 'unknown'
    assert result['findings'] == []
