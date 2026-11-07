"""Thread/process concurrency checks without scan traffic."""
from concurrent.futures import ThreadPoolExecutor
import subprocess
import sys
from threading import Event
from unittest.mock import patch

import pytest

from netcheck import service
from netcheck.scanner import ScanResult


def test_concurrent_request_is_refused_before_validation(tmp_path):
    entered, release = Event(), Event()

    def active_scan(validated, destination):
        entered.set()
        assert release.wait(timeout=5)
        return ScanResult(destination, success=True)

    with patch('netcheck.service.scanner.validate_scan_request') as validate, patch(
        'netcheck.service.scanner.run_scan', side_effect=active_scan
    ) as run, ThreadPoolExecutor(max_workers=1) as pool:
        first = pool.submit(service.scan, '172.20.10.3', confirm=True, output_dir=tmp_path)
        try:
            assert entered.wait(timeout=5)
            with pytest.raises(service.ScanBusyError, match='already in progress'):
                service.scan('172.20.10.4', confirm=True, output_dir=tmp_path / 'other')
            assert validate.call_count == 1
            assert run.call_count == 1
            assert not (tmp_path / 'other').exists()
        finally:
            release.set()
        assert first.result(timeout=5).success
        assert service.scan('172.20.10.4', confirm=True, output_dir=tmp_path).success


@pytest.mark.parametrize('stage', ['validation', 'scan'])
def test_failed_request_releases_scan_slot(tmp_path, stage):
    with patch('netcheck.service.scanner.validate_scan_request') as validate, patch(
        'netcheck.service.scanner.run_scan'
    ) as run:
        failing = validate if stage == 'validation' else run
        failing.side_effect = RuntimeError('simulated failure')
        with pytest.raises(RuntimeError, match='simulated failure'):
            service.scan('172.20.10.3', confirm=True, output_dir=tmp_path)
        failing.side_effect = None
        run.return_value = ScanResult(str(tmp_path / 'result.xml'), success=True)
        assert service.scan('172.20.10.3', confirm=True, output_dir=tmp_path).success


def test_other_process_is_blocked_and_can_retry_after_release():
    code = """
import sys
from pathlib import Path
from netcheck import service
service._SCAN_LOCK_PATH = Path(sys.argv[1])
try:
    with service._cross_process_lock():
        pass
except service.ScanBusyError:
    raise SystemExit(23)
"""
    command = [sys.executable, '-c', code, str(service._SCAN_LOCK_PATH)]
    with service._cross_process_lock():
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        assert result.returncode == 23, result.stderr
    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
