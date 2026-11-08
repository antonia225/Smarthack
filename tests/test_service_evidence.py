"""Rules decide on the service name Nmap reports, whatever method found it.

The brief grades findings on the reported service name. Nmap marks names it
could only infer from the port number as ``method="table"`` (typical for UDP
services that did not answer a probe), so these names must still trigger the
official rules, and response banners must not rename a reported service.
"""
from pathlib import Path

from netcheck import catalog
from netcheck.scoring import analyze_file

VALIDATION = Path(__file__).parent / "validation"


def analyze(tmp_path, ports):
    path = tmp_path / 'evidence.xml'
    path.write_text('<nmaprun><host><address addr="172.20.10.2" addrtype="ipv4"/><ports>' + ports + '</ports></host></nmaprun>')
    return analyze_file(path)


def port(number, name, extra='', state='open', protocol='tcp'):
    return f'<port protocol="{protocol}" portid="{number}"><state state="{state}"/><service name="{name}" {extra}/></port>'


def codes(result):
    return {f['code'] for f in result['findings']}


def test_table_names_still_trigger_official_rules(tmp_path):
    result = analyze(tmp_path, port(21, 'ftp', 'method="table" conf="3"') + port(5432, 'postgresql', 'method="table" conf="3"'))
    assert {p['service'] for p in result['devices'][0]['ports']} == {'ftp', 'postgresql'}
    assert codes(result) == {'FTP_CLEARTEXT', 'DB_EXPOSED', 'UNKNOWN_DEVICE'}
    assert result['network_score'] == 65


def test_udp_table_snmp_still_yields_snmp_exposed(tmp_path):
    result = analyze(tmp_path, port(161, 'snmp', 'method="table" conf="3"', protocol='udp'))
    assert 'SNMP_EXPOSED' in codes(result)


def test_v4_with_table_snmp_keeps_official_findings_and_score(tmp_path):
    original = '<service name="snmp" product="SNMPv1 server" extrainfo="public" method="probed" conf="10"/>'
    text = (VALIDATION / 'V4_legacy.xml').read_text()
    assert text.count(original) == 1
    path = tmp_path / 'V4_table_snmp.xml'
    path.write_text(text.replace(original, '<service name="snmp" method="table" conf="3"/>'))
    result = analyze_file(path)
    assert len(result['findings']) == 6
    assert 'SNMP_EXPOSED' in codes(result)
    assert result['network_score'] == 25


def test_airtunes_banner_does_not_hide_rtsp_finding(tmp_path):
    result = analyze(tmp_path, port(5000, 'rtsp', 'method="table" conf="3" servicefp="RTSP/1.0 403 Forbidden Server: AirTunes/1005.13.1"'))
    device = result['devices'][0]
    assert device['ports'][0]['service'] == 'rtsp'
    assert 'CAMERA_STREAM_EXPOSED' in codes(result)
    assert result['network_score'] == 75


def test_lab_banner_does_not_rewrite_reported_product(tmp_path):
    result = analyze(tmp_path, port(23, 'telnet', 'method="table" product="HP LaserJet telnetd" servicefp="SmartHack Telnet simulator No shell"'))
    assert result['devices'][0]['ports'][0]['product'] == 'HP LaserJet telnetd'
    assert 'TELNET_OPEN' in codes(result)
    assert result['network_score'] == 75


def test_probed_database_keeps_exposure_finding(tmp_path):
    result = analyze(tmp_path, port(5432, 'postgresql', 'method="probed" conf="10" product="PostgreSQL"'))
    assert 'DB_EXPOSED' in codes(result)
    assert result['network_score'] == 75


def test_low_confidence_probe_keeps_reported_service(tmp_path):
    result = analyze(tmp_path, port(5432, 'postgresql', 'method="probed" conf="3"'))
    assert result['devices'][0]['ports'][0]['service'] == 'postgresql'
    assert 'DB_EXPOSED' in codes(result)


def test_unknown_device_is_low_and_costs_five_points(tmp_path):
    result = analyze(tmp_path, port(8888, 'sun-answerbook', 'method="probed" conf="10"'))
    unknown = [f for f in result['findings'] if f['code'] == 'UNKNOWN_DEVICE']
    assert len(unknown) == 1
    assert unknown[0]['severity'] == 'low'
    assert unknown[0]['points'] == 5
    assert result['network_score'] == 95
    entry = catalog.load_catalog()['UNKNOWN_DEVICE']
    assert (entry['severity'], entry['points']) == ('low', 5)


def test_rtsp_without_camera_evidence_does_not_classify_camera(tmp_path):
    result = analyze(tmp_path, port(554, 'rtsp', 'method="probed" conf="10"'))
    assert result['devices'][0]['device_type'] == 'unknown'
    assert 'CAMERA_STREAM_EXPOSED' in codes(result)


def test_closed_rtsp_does_not_classify_camera(tmp_path):
    result = analyze(tmp_path, port(554, 'rtsp', 'product="IP camera" method="probed"', state='closed'))
    assert result['devices'][0]['device_type'] == 'unknown'
    assert result['findings'] == []
