"""Real execution error paths with Nmap mocked; no packets are sent."""
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

from netcheck import scanner
from netcheck.scan_xml import read_completed_scan

LAB = scanner.NetworkInfo('en0', '172.20.10.2', 28, '172.20.10.0/28', '172.20.10.1')
GOOD_XML = '<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>'


@pytest.fixture
def execution(tmp_path):
    with patch('netcheck.scanner.detect_network', return_value=LAB), patch(
        'netcheck.scanner.port_specification', return_value='T:1-1000,U:53,123,161,1900,5353'
    ), patch('netcheck.scanner.subprocess.run') as process:
        target = scanner.validate_scan_request('172.20.10.3', [LAB.subnet], confirm=True)
        yield target, tmp_path / 'scan.xml', process


@pytest.mark.parametrize('error', [FileNotFoundError('missing nmap'),
                                  subprocess.TimeoutExpired('nmap', 300)])
def test_execution_errors_are_results(execution, error):
    target, path, process = execution
    process.side_effect = error
    result = scanner.run_scan(target, str(path))
    assert not result.success and result.error
    assert result.duration_seconds >= 0


@pytest.mark.parametrize('content', [
    '', '<nmaprun>', '<nmaprun />',
    '<other><runstats><finished exit="success"/></runstats></other>',
    '<nmaprun><runstats><finished exit="error"/></runstats></nmaprun>',
    '<nmaprun><host timedout="true"/><runstats><finished exit="success"/></runstats></nmaprun>',
    '<!DOCTYPE nmaprun [<!ENTITY x SYSTEM "file:///nonexistent">]><nmaprun>&x;</nmaprun>',
])
def test_incomplete_or_hostile_xml_is_not_success(execution, content):
    target, path, process = execution
    def run(*args, **kwargs):
        path.write_text(content)
        return subprocess.CompletedProcess(args, 0, '', '')
    process.side_effect = run
    assert not scanner.run_scan(target, str(path)).success


def test_output_is_not_overwritten(execution):
    target, path, process = execution
    path.write_text(GOOD_XML)
    assert not scanner.run_scan(target, str(path)).success
    process.assert_not_called()
    assert path.read_text() == GOOD_XML


def test_oversize_xml_is_rejected_before_parse(tmp_path):
    path = tmp_path / 'scan.xml'
    path.write_bytes(b' ' * 65)
    with patch('netcheck.scan_xml.MAX_XML_BYTES', 64), pytest.raises(ValueError, match='10 MB'):
        read_completed_scan(path)
