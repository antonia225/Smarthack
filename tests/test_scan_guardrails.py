"""Authorization regressions: no real network commands or scan traffic."""
from dataclasses import FrozenInstanceError, replace
from unittest.mock import patch

import pytest

from netcheck.scanner import (
    NetworkDetectionError, NetworkInfo, configure_lab_network, validate_scan_request, run_scan,
)

LAB = NetworkInfo("en0", "172.20.10.2", 28, "172.20.10.0/28", "172.20.10.1")
VENUE = NetworkInfo("en0", "192.168.1.2", 24, "192.168.1.0/24", "192.168.1.1")


@pytest.fixture(autouse=True)
def no_network():
    with patch("netcheck.scanner.detect_network", return_value=LAB) as detect, patch(
        "netcheck.scanner.subprocess.run"
    ) as process:
        yield detect, process


def test_missing_config_defaults_allowlist_to_connected_subnet(tmp_path, no_network):
    missing = tmp_path / "missing.json"
    validated = validate_scan_request("172.20.10.3", confirm=True, config_path=missing)
    assert validated.allowed_networks == ("172.20.10.0/28",)
    for outside in ("8.8.8.8", "192.168.1.5", "172.20.10.200"):
        with pytest.raises(PermissionError):
            validate_scan_request(outside, confirm=True, config_path=missing)
    with pytest.raises(PermissionError, match="confirmation is required"):
        validate_scan_request("172.20.10.3", confirm=False, config_path=missing)
    no_network[1].assert_not_called()


def test_corrupt_config_is_still_refused(tmp_path):
    bad = tmp_path / "bad.json"
    bad.write_text("{nope", encoding="utf-8")
    with pytest.raises(PermissionError, match="configuration missing"):
        validate_scan_request("172.20.10.3", confirm=True, config_path=bad)


def test_default_target_without_config_is_connected_subnet(tmp_path):
    from netcheck.scanner import default_scan_target
    assert default_scan_target(tmp_path / "missing.json") == "172.20.10.0/28"


def test_large_connected_network_is_never_authorized_by_default(tmp_path, no_network):
    from netcheck.scanner import default_scan_target
    venue = NetworkInfo("wlan", "10.240.236.194", 16, "10.240.0.0/16", "10.240.0.3")
    with patch("netcheck.scanner.detect_network", return_value=venue):
        with pytest.raises(PermissionError, match="venue Wi-Fi"):
            default_scan_target(tmp_path / "missing.json")
        with pytest.raises(PermissionError, match="venue Wi-Fi"):
            validate_scan_request("10.240.236.5", confirm=True, config_path=tmp_path / "missing.json")
    no_network[1].assert_not_called()


def test_persisted_authorization_survives_reload_and_rejects_network_change(tmp_path, no_network):
    path = tmp_path / "lab.json"
    configure_lab_network([LAB.subnet], confirm=True, config_path=path)
    original = path.read_bytes()
    assert validate_scan_request("172.20.10.3", confirm=True, config_path=path).network == LAB
    no_network[0].return_value = VENUE
    with pytest.raises(PermissionError):
        validate_scan_request("192.168.1.3", confirm=True, config_path=path)
    with pytest.raises(PermissionError, match="Network changed"):
        validate_scan_request("172.20.10.3", confirm=True, config_path=path)
    assert path.read_bytes() == original
    no_network[1].assert_not_called()


def test_configuration_requires_confirmation_and_no_implicit_overwrite(tmp_path):
    path = tmp_path / "lab.json"
    with pytest.raises(PermissionError):
        configure_lab_network([LAB.subnet], config_path=path)
    assert not path.exists()
    configure_lab_network([LAB.subnet], confirm=True, config_path=path)
    with pytest.raises(FileExistsError):
        configure_lab_network([LAB.subnet], confirm=True, config_path=path)


@pytest.mark.parametrize("target", [
    "127.0.0.1", "169.254.1.2", "0.0.0.0", "224.0.0.1", "255.255.255.255",
    "100.64.0.1", "192.0.2.1", "198.18.0.1", "240.0.0.1", "8.8.8.8",
    "127.0.0.0/24", "169.254.1.0/24", "::1",
])
def test_special_addresses_rejected_even_when_allowlisted(target, no_network):
    with pytest.raises(PermissionError):
        validate_scan_request(target, [target], confirm=True)
    no_network[1].assert_not_called()


def test_validated_data_is_deeply_immutable():
    allowlist = [LAB.subnet]
    validated = validate_scan_request("172.20.10.3", allowlist, confirm=True)
    allowlist[0] = VENUE.subnet
    assert validated.allowed_networks == (LAB.subnet,)
    with pytest.raises(FrozenInstanceError):
        validated.target = "8.8.8.8"
    with pytest.raises(FrozenInstanceError):
        validated.network.gateway = "172.20.10.4"


@pytest.mark.parametrize("changes", [
    {"target": "8.8.8.8"}, {"target": "172.20.10.4"},
    {"allowed_networks": ("0.0.0.0/0",)}, {"network": VENUE},
])
def test_copied_validation_cannot_authorize_other_values(changes, no_network, tmp_path):
    validated = validate_scan_request("172.20.10.3", [LAB.subnet], confirm=True)
    with pytest.raises(PermissionError, match="modified"):
        run_scan(replace(validated, **changes), str(tmp_path / "scan.xml"))
    no_network[1].assert_not_called()


@pytest.mark.parametrize("changed", [VENUE, replace(LAB, gateway="172.20.10.4"),
                                      replace(LAB, interface="en1")])
def test_network_rechecked_before_process_launch(changed, no_network, tmp_path):
    validated = validate_scan_request("172.20.10.3", [LAB.subnet], confirm=True)
    no_network[0].return_value = changed
    with pytest.raises(PermissionError, match="Network changed"):
        run_scan(validated, str(tmp_path / "scan.xml"))
    no_network[1].assert_not_called()


def test_disconnect_before_launch_prevents_process(no_network, tmp_path):
    validated = validate_scan_request("172.20.10.3", [LAB.subnet], confirm=True)
    no_network[0].side_effect = NetworkDetectionError("No LAN")
    with pytest.raises(NetworkDetectionError):
        run_scan(validated, str(tmp_path / "scan.xml"))
    no_network[1].assert_not_called()


def test_policy_is_rechecked_before_launch(no_network, tmp_path):
    validated = validate_scan_request("172.20.10.3", [LAB.subnet], confirm=True)
    with patch("netcheck.scanner._check_policy", side_effect=PermissionError("Policy changed")):
        with pytest.raises(PermissionError, match="Policy changed"):
            run_scan(validated, str(tmp_path / "scan.xml"))
    no_network[1].assert_not_called()
