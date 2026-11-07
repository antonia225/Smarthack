"""Opt-in native command/parser smoke test; never sends scan traffic.

CI hosts may have virtual adapters or multiple networks. A deliberate safety
rejection is valid here; command failures and malformed native output are not.
This does not replace successful detection on a lab-connected physical laptop.
"""

import os
from ipaddress import IPv4Address, IPv4Network

import pytest

from netcheck.scanner import NetworkDetectionError, detect_network


@pytest.mark.native
@pytest.mark.skipif(
    os.environ.get("NETCHECK_NATIVE_TEST") != "1",
    reason="Native network inspection is opt-in",
)
def test_native_network_commands_and_parser():
    try:
        info = detect_network()
    except NetworkDetectionError as exc:
        # Wrapped command/JSON/schema failures must fail CI, not masquerade as
        # successful handling of an ambiguous runner network.
        assert exc.__cause__ is None, str(exc)
        print(f"Native network rejected safely: {exc}")
        return
    network = IPv4Network(info.subnet)
    assert info.interface
    assert network.prefixlen == info.prefix_length
    assert IPv4Address(info.ip) in network
    assert IPv4Address(info.gateway) in network
    assert info.ip != info.gateway
