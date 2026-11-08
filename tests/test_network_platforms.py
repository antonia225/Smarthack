"""Platform command fixtures; these do not replace native laptop verification."""
import json
import subprocess
from copy import deepcopy
from unittest.mock import patch

import pytest

from netcheck.scanner import detect_network, NetworkDetectionError


def windows():
    return {
        "adapters": [{"ifIndex": 7, "Name": "Wi-Fi laborator", "Status": "Up", "HardwareInterface": True}],
        "addresses": [{"InterfaceIndex": 7, "IPAddress": "192.168.42.70", "PrefixLength": 26, "AddressState": 4},
                      {"InterfaceIndex": 1, "IPAddress": "127.0.0.1", "PrefixLength": 8, "AddressState": 4}],
        "routes": [{"InterfaceIndex": 7, "DestinationPrefix": "0.0.0.0/0", "NextHop": "192.168.42.65"},
                   {"InterfaceIndex": 1, "DestinationPrefix": "127.0.0.0/8", "NextHop": "0.0.0.0"}],
    }


def linux():
    return [
        [{"ifname": "wlp2s0", "flags": ["UP", "BROADCAST"], "operstate": "UP", "addr_info": [
            {"family": "inet", "local": "192.168.42.70", "prefixlen": 26}]},
         {"ifname": "lo", "flags": ["UP", "LOOPBACK"], "addr_info": []}],
        [{"dst": "default", "gateway": "192.168.42.65", "dev": "wlp2s0"},
         {"dst": "192.168.42.64/26", "dev": "wlp2s0"},
         {"dst": "127.0.0.0/8", "dev": "lo", "type": "local"}],
        [{"priority": 0, "src": "all", "table": "local"},
         {"priority": 32766, "src": "all", "table": "main"},
         {"priority": 32767, "src": "all", "table": "default"}],
    ]


def run_fixture(system, data):
    outputs = [data] if system == "Windows" else data
    def run(command, **kwargs):
        assert kwargs["timeout"] == 10
        assert kwargs["check"] is True
        if system == "Windows":
            assert command[:4] == ["powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive"]
        else:
            assert command[:3] == ["ip", "-j", "-4"]
        return subprocess.CompletedProcess(command, 0, json.dumps(outputs.pop(0)))
    with patch("netcheck.scanner.platform.system", return_value=system), patch(
        "netcheck.scanner.subprocess.run", side_effect=run
    ), patch("netcheck.scanner._linux_physical_interface", side_effect=lambda name: name in ("wlp2s0", "eth0")):
        return detect_network()


@pytest.mark.parametrize("system,factory", [("Windows", windows), ("Linux", linux)])
def test_non_iphone_subnet(system, factory):
    result = run_fixture(system, factory())
    assert result.ip == "192.168.42.70"
    assert result.prefix_length == 26
    assert result.subnet == "192.168.42.64/26"
    assert result.gateway == "192.168.42.65"
    assert result.interface == ("Wi-Fi laborator" if system == "Windows" else "wlp2s0")


@pytest.mark.parametrize("problem", ["offline", "multiple", "alias", "vpn", "route_vpn", "no_gateway", "two_gateways", "bad_gateway", "bad_prefix", "address_state"])
def test_windows_rejects_uncertainty(problem):
    data = windows()
    if problem == "offline": data["adapters"][0]["Status"] = "Disconnected"
    if problem == "multiple":
        data["adapters"].append(dict(data["adapters"][0], ifIndex=8, Name="Ethernet"))
        data["addresses"].append(dict(data["addresses"][0], InterfaceIndex=8))
    if problem == "alias": data["addresses"].append(dict(data["addresses"][0], IPAddress="192.168.42.71"))
    if problem == "vpn": data["adapters"][0]["HardwareInterface"] = False
    if problem == "route_vpn": data["routes"].append({"InterfaceIndex": 99, "DestinationPrefix": "10.0.0.0/8", "NextHop": "10.0.0.1"})
    if problem == "no_gateway": data["routes"] = []
    if problem == "two_gateways": data["routes"].append(dict(data["routes"][0], NextHop="192.168.42.66"))
    if problem == "bad_gateway": data["routes"][0]["NextHop"] = "10.0.0.1"
    if problem == "bad_prefix": data["addresses"][0]["PrefixLength"] = 33
    if problem == "address_state": data["addresses"][0]["AddressState"] = 2
    with pytest.raises(NetworkDetectionError): run_fixture("Windows", data)


@pytest.mark.parametrize("problem", ["offline", "multiple", "alias", "vpn", "route_vpn", "policy", "multipath", "no_gateway", "two_gateways", "bad_gateway", "bad_prefix"])
def test_linux_rejects_uncertainty(problem):
    data = linux()
    if problem == "offline": data[0][0]["operstate"] = "DOWN"
    if problem == "multiple": data[0].append(dict(deepcopy(data[0][0]), ifname="eth0"))
    if problem == "alias": data[0][0]["addr_info"].append(dict(data[0][0]["addr_info"][0], local="192.168.42.71"))
    if problem == "vpn": data[0][0]["ifname"] = "tun0"
    if problem == "route_vpn": data[1].append({"dev": "tun0", "dst": "10.0.0.0/8"})
    if problem == "policy": data[2].append({"priority": 100, "src": "all", "table": 51820})
    if problem == "multipath": data[1][0]["nexthops"] = [{"dev": "wlp2s0"}]
    if problem == "no_gateway": data[1] = []
    if problem == "two_gateways": data[1].append(dict(data[1][0], gateway="192.168.42.66"))
    if problem == "bad_gateway": data[1][0]["gateway"] = "10.0.0.1"
    if problem == "bad_prefix": data[0][0]["addr_info"][0]["prefixlen"] = 33
    with pytest.raises(NetworkDetectionError): run_fixture("Linux", data)


@pytest.mark.parametrize("system", ["Windows", "Linux"])
@pytest.mark.parametrize("output", ["not json", "null", "{}", "[]"])
def test_malformed_output(system, output):
    with patch("netcheck.scanner.platform.system", return_value=system), patch(
        "netcheck.scanner.subprocess.run", return_value=subprocess.CompletedProcess([], 0, output)
    ), pytest.raises(NetworkDetectionError):
        detect_network()


@pytest.mark.parametrize("system", ["Windows", "Linux"])
@pytest.mark.parametrize("error", [FileNotFoundError("missing"), subprocess.TimeoutExpired("command", 10), subprocess.CalledProcessError(1, "command")])
def test_command_errors(system, error):
    with patch("netcheck.scanner.platform.system", return_value=system), patch(
        "netcheck.scanner.subprocess.run", side_effect=error
    ), pytest.raises(NetworkDetectionError):
        detect_network()


def test_windows_ignores_docker_switch_and_link_local_adapters():
    data = windows()
    data["adapters"] += [
        {"ifIndex": 20, "Name": "vEthernet (Default Switch)", "Status": "Up", "HardwareInterface": False},
        {"ifIndex": 21, "Name": "Ethernet", "Status": "Up", "HardwareInterface": True},
    ]
    data["addresses"] += [
        {"InterfaceIndex": 20, "IPAddress": "172.30.192.1", "PrefixLength": 20, "AddressState": 4},
        {"InterfaceIndex": 21, "IPAddress": "169.254.248.61", "PrefixLength": 16, "AddressState": 4},
    ]
    data["routes"] += [
        {"InterfaceIndex": 20, "DestinationPrefix": "172.30.192.0/20", "NextHop": "0.0.0.0"},
        {"InterfaceIndex": 21, "DestinationPrefix": "169.254.0.0/16", "NextHop": "0.0.0.0"},
    ]
    assert run_fixture("Windows", data).subnet == "192.168.42.64/26"


def test_windows_virtual_adapter_with_default_route_is_still_rejected():
    data = windows()
    data["adapters"][0]["HardwareInterface"] = False
    with pytest.raises(NetworkDetectionError):
        run_fixture("Windows", data)
