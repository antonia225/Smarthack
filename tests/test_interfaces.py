"""CLI/HTTP integration through real guardrails, with no scan traffic."""
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from netcheck.api import create_app
from netcheck.cli import main
from netcheck.scanner import NetworkInfo, NetworkDetectionError, configure_lab_network

LAB = NetworkInfo('en0', '172.20.10.2', 28, '172.20.10.0/28', '172.20.10.1')
VENUE = NetworkInfo('en0', '192.168.1.2', 24, '192.168.1.0/24', '192.168.1.1')


@pytest.fixture
def environment(tmp_path):
    config = tmp_path / 'lab.json'
    output = tmp_path / 'scans'
    with patch('netcheck.scanner.detect_network', return_value=LAB) as detect, patch(
        'netcheck.scanner.subprocess.run'
    ) as process, patch('netcheck.scanner.port_specification', return_value='T:1-1000,U:53,123,161,1900,5353'):
        configure_lab_network([LAB.subnet], confirm=True, config_path=config)
        def fake_scan(command, **kwargs):
            if sys.platform == 'darwin':
                assert command[0:2] == ['sudo', '-n']
                output_path = command[4]
                assert command[3] == '172.20.10.3'
            else:
                assert command[0] == 'nmap'
                output_index = command.index('-oX') + 1
                output_path = command[output_index]
                assert command[-1] == '172.20.10.3'
            Path(output_path).write_text(
                '<nmaprun><runstats><finished exit="success"/></runstats></nmaprun>'
            )
            return subprocess.CompletedProcess(command, 0, '', '')
        process.side_effect = fake_scan
        with TestClient(create_app(config_path=config, output_dir=output), base_url="http://127.0.0.1") as client:
            yield config, output, detect, process, client


def invoke(env, target='172.20.10.3', confirm=True):
    config, output, *_ = env
    return main(['--config', str(config), 'scan', target, '--output-dir', str(output)]
                + (['--confirm'] if confirm else []))


@pytest.mark.parametrize('channel', ['cli', 'api'])
@pytest.mark.parametrize('problem', ['confirmation', 'public', 'loopback', 'link_local',
                                    'ipv6', 'outside', 'large', 'missing_config',
                                    'network_change', 'late_network_change', 'offline', 'hostname'])
def test_refusal_never_starts_process(environment, channel, problem):
    config, output, detect, process, client = environment
    target, confirm = '172.20.10.3', True
    targets = {'public': '8.8.8.8', 'loopback': '127.0.0.1', 'link_local': '169.254.1.2',
               'ipv6': '::1', 'outside': '172.20.10.16/28', 'large': '172.20.0.0/16',
               'hostname': 'example.com'}
    target = targets.get(problem, target)
    if problem == 'confirmation': confirm = False
    if problem == 'missing_config': config.unlink()
    if problem == 'network_change': detect.return_value = VENUE
    if problem == 'late_network_change': detect.side_effect = [LAB, VENUE]
    if problem == 'offline': detect.side_effect = NetworkDetectionError('No LAN')
    if channel == 'cli':
        assert invoke(environment, target, confirm) == 2
    else:
        response = client.post('/api/scan', json={'target': target, 'confirm': confirm})
        assert response.status_code == (409 if problem == 'offline' else 403)
    process.assert_not_called()
    assert not list(output.glob('*.xml'))


@pytest.mark.parametrize('channel', ['cli', 'api'])
def test_success_uses_guardrails_and_unique_artifacts(environment, channel):
    _, output, detect, process, client = environment
    for _ in range(2):
        if channel == 'cli':
            assert invoke(environment) == 0
        else:
            response = client.post('/api/scan', json={'target': '172.20.10.3', 'confirm': True})
            assert response.status_code == 200
            assert response.json()['success'] is True
    assert process.call_count == 2
    assert len(list(output.glob('*.xml'))) == 2
    assert detect.call_count == 5  # configuration + validation and prelaunch per request


@pytest.mark.parametrize('body', [
    {'target': '172.20.10.3'}, {'target': '172.20.10.3', 'confirm': False},
    {'target': '172.20.10.3', 'confirm': 'true'}, {'target': '172.20.10.3', 'confirm': 1},
    {'target': '172.20.10.3', 'confirm': True, 'allowed_networks': ['0.0.0.0/0']},
    {'target': '172.20.10.3', 'confirm': True, 'output_path': '/tmp/override.xml'},
    {'target': 123, 'confirm': True},
])
def test_api_requires_literal_confirmation_and_forbids_overrides(environment, body):
    response = environment[-1].post('/api/scan', json=body)
    assert response.status_code in (403, 422)
    environment[3].assert_not_called()


@pytest.mark.parametrize('channel', ['cli', 'api'])
@pytest.mark.parametrize('failure', ['missing_nmap', 'nonzero', 'missing_xml'])
def test_execution_failure_is_reported(environment, channel, failure):
    process, client = environment[3:]
    process.side_effect = None
    if failure == 'missing_nmap': process.side_effect = FileNotFoundError('nmap missing')
    else: process.return_value = subprocess.CompletedProcess([], 1 if failure == 'nonzero' else 0, '', 'failed')
    if channel == 'cli': assert invoke(environment) == 1
    else:
        response = client.post('/api/scan', json={'target': '172.20.10.3', 'confirm': True})
        assert response.status_code == 502


def test_cli_configure_requires_confirmation_and_persists(tmp_path):
    config = tmp_path / 'lab.json'
    args = ['--config', str(config), 'configure-lab', '--allow', LAB.subnet]
    with patch('netcheck.scanner.detect_network', return_value=LAB):
        assert main(args) == 2
        assert not config.exists()
        assert main(args + ['--confirm']) == 0
        assert config.exists()
        assert main(args + ['--confirm']) == 1


def test_cli_configure_without_allow_proposes_detected_subnet(tmp_path, capsys):
    config = tmp_path / 'lab.json'
    with patch('netcheck.scanner.detect_network', return_value=LAB) as detect:
        assert main(['--config', str(config), 'configure-lab']) == 2
        assert not config.exists()
        assert '172.20.10.0/28' in capsys.readouterr().out
        assert main(['--config', str(config), 'configure-lab', '--confirm']) == 0
    assert config.exists()
    assert detect.call_count == 3


def test_demo_refusals_never_calls_subprocess(capsys):
    with patch('netcheck.scanner.subprocess.run') as process:
        assert main(['demo-refusals']) == 0
    output = capsys.readouterr().out
    assert '8.8.8.8' in output
    assert '10.240.0.5' in output
    assert '10.240.0.0/16' in output
    assert 'Confirmarea scanării este obligatorie' in output
    assert 'subprocess nu a fost apelat' in output
    process.assert_not_called()


def test_read_only_network_routes(environment):
    assert environment[-1].get('/api/network').json()['subnet'] == LAB.subnet
    assert main(['network']) == 0
    environment[3].assert_not_called()


@pytest.mark.parametrize('channel', ['cli', 'api'])
def test_corrupt_configuration_is_not_replaced(environment, channel):
    environment[0].write_text('{invalid')
    if channel == 'cli':
        assert invoke(environment) == 2
    else:
        assert environment[-1].post('/api/scan', json={
            'target': '172.20.10.3', 'confirm': True}).status_code == 403
    assert environment[0].read_text() == '{invalid'
    environment[3].assert_not_called()


def test_serve_binds_only_loopback(tmp_path):
    with patch('uvicorn.run') as run:
        assert main(['--config', str(tmp_path / 'lab.json'), 'serve', '--port', '8765']) == 0
    assert run.call_args.kwargs == {'host': '127.0.0.1', 'port': 8765}


def test_api_rejects_untrusted_host(environment):
    response = environment[-1].post('/api/scan', headers={'host': 'attacker.example'},
                                   json={'target': '172.20.10.3', 'confirm': True})
    assert response.status_code == 400
    environment[3].assert_not_called()


@pytest.mark.parametrize('channel', ['cli', 'api'])
def test_busy_scan_reports_conflict(environment, channel):
    from netcheck import service
    with service._SCAN_LOCK:
        if channel == 'cli':
            assert invoke(environment) == 2
        else:
            response = environment[-1].post('/api/scan', json={'target': '172.20.10.3', 'confirm': True})
            assert response.status_code == 409
    environment[3].assert_not_called()
