"""Port coverage uses Nmap frequency data rather than well-known numbers."""
from unittest.mock import patch

import pytest

from netcheck.nmap_ports import port_specification, services_file


def test_tcp_top_thousand_including_ties_and_exact_udp(tmp_path):
    db = tmp_path / 'nmap-services'
    # Synthetic frequencies: 999 higher ports, three tied at the cutoff,
    # one lower port. UDP frequency must not influence TCP selection.
    db.write_text(''.join(f's{i} {i}/tcp 0.5\n' for i in range(1, 1000))
                  + 'a 5000/tcp 0.1\nb 5001/tcp 0.1\nc 5002/tcp 0.1\n'
                  + 'd 6000/tcp 0.01\ndns 9999/udp 0.9\n')
    tcp, udp = port_specification(db).split(',U:')
    ports = {int(p) for p in tcp.removeprefix('T:').split(',')}
    assert ports == set(range(1, 1000)) | {5000, 5001, 5002}
    assert udp == '53,123,161,1900,5353'


def test_incomplete_service_database_fails(tmp_path):
    db = tmp_path / 'nmap-services'
    db.write_text('http 80/tcp 0.5\n')
    with pytest.raises(ValueError, match='1000'):
        port_specification(db)


def test_missing_nmap_is_explicit():
    with patch('netcheck.nmap_ports.shutil.which', return_value=None), pytest.raises(FileNotFoundError):
        services_file()
