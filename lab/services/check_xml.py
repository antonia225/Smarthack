"""Check the five Task 2 catalog rules in existing XML; never edit captures."""
import sys
from pathlib import Path
from ipaddress import IPv4Address
import xml.etree.ElementTree as ET
from defusedxml.common import DefusedXmlException

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from netcheck.scan_xml import read_completed_scan

EXPECTED = {
    'HTTP_ADMIN_CLEARTEXT', 'DB_EXPOSED', 'MQTT_EXPOSED',
    'TELNET_OPEN', 'FTP_CLEARTEXT',
}

def check(paths):
    found = set()
    for filename in paths:
        root = read_completed_scan(filename)
        for host in root.findall('host'):
            address = host.find("address[@addrtype='ipv4']")
            ip = address.get('addr') if address is not None else '?'
            if ip == '?' or IPv4Address(ip).is_loopback:
                print(f'LOCAL ONLY: {filename} ({ip}); nu confirma accesul prin hotspot')
                continue
            for port in host.findall('ports/port'):
                state, service = port.find('state'), port.find('service')
                if state is None or state.get('state') != 'open' or service is None:
                    continue
                name = service.get('name', '')
                code = {'telnet': 'TELNET_OPEN', 'ftp': 'FTP_CLEARTEXT',
                        'mqtt': 'MQTT_EXPOSED'}.get(name)
                if name in {'mysql', 'postgresql', 'redis', 'mongodb'}:
                    code = 'DB_EXPOSED'
                title = ' '.join(s.get('output', '') for s in port.findall('script')
                                 if s.get('id') == 'http-title').lower()
                if (name == 'http' and service.get('tunnel') != 'ssl'
                        and any(word in title for word in
                                ('login', 'admin', 'config', 'setup', 'router', 'settings'))):
                    code = 'HTTP_ADMIN_CLEARTEXT'
                print(f'{ip}:{port.get("portid")} service={name} -> {code or "fara finding din cele cinci"}')
                if code:
                    found.add(code)
    for code in sorted(EXPECTED - found):
        print(f'NECONFIRMAT: {code}')
    if found == EXPECTED:
        print('OK: cele cinci tipuri sunt prezente. Verifica separat ca IP-urile apartin hotspot-ului autorizat.')
    return 0 if found == EXPECTED else 1

if __name__ == '__main__':
    if len(sys.argv) < 2:
        raise SystemExit('Utilizare: python3 lab/services/check_xml.py fisier.xml [fisier.xml ...]')
    try:
        raise SystemExit(check(sys.argv[1:]))
    except (ET.ParseError, OSError, ValueError, DefusedXmlException) as exc:
        raise SystemExit(str(exc))
