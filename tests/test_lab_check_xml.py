from pathlib import Path

from lab.compare import main as compare_main
from lab.services.check_xml import EXPECTED, codes_for_paths


def xml_for(ip, ports):
    entries = []
    for port, state, service, extra in ports:
        script_xml = extra if extra.startswith("<") else ""
        service_attributes = "" if extra.startswith("<") else extra
        entries.append(
            f'<port protocol="tcp" portid="{port}"><state state="{state}"/>'
            f'<service name="{service}"{service_attributes}/>{script_xml}</port>'
        )
    return (
        '<!-- fixture sintetic de test, nu captură de laborator -->'
        f'<nmaprun><host><address addr="{ip}" addrtype="ipv4"/>'
        f'<ports>{"".join(entries)}</ports></host>'
        '<runstats><finished exit="success"/></runstats></nmaprun>'
    )


def test_check_xml_covers_findings_and_exclusions(tmp_path):
    fixture = tmp_path / "synthetic.xml"
    fixture.write_text(xml_for("172.20.10.3", [
        ("80", "open", "http", '<script id="http-title" output="Admin Login"/>'),
        ("443", "open", "http", ' tunnel="ssl"'),
        ("5432", "open", "postgresql", ""),
        ("1883", "open", "mqtt", ""),
        ("23", "open", "telnet", ""),
        ("21", "open", "ftp", ""),
        ("9999", "filtered", "http", ""),
        ("8081", "open", "http", '<script id="http-title" output="Status"/>'),
    ]), encoding="utf-8")
    assert codes_for_paths([fixture]) == EXPECTED

    loopback = tmp_path / "loopback.xml"
    loopback.write_text(xml_for("127.0.0.1", [("23", "open", "telnet", "")]), encoding="utf-8")
    assert codes_for_paths([loopback]) == set()


def test_compare_reports_resolved_and_introduced(tmp_path, capsys):
    before = tmp_path / "before"
    after = tmp_path / "after"
    before.mkdir()
    after.mkdir()
    before.joinpath("one.xml").write_text(
        xml_for("172.20.10.3", [("23", "open", "telnet", "")]), encoding="utf-8"
    )
    after.joinpath("one.xml").write_text(
        xml_for("172.20.10.3", [("1883", "open", "mqtt", "")]), encoding="utf-8"
    )
    assert compare_main([str(before), str(after)]) == 0
    output = capsys.readouterr().out
    assert "TELNET_OPEN" in output and "MQTT_EXPOSED" in output
