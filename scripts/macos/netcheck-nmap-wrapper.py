#!/usr/bin/env python3
"""Root-owned, argument-free Nmap entry point for the limited sudo rule."""
from ipaddress import ip_network
import os
from pathlib import Path
import re
import sys


ALLOWED_DIR = Path("/var/tmp/netcheck-scans")
NMAP = "/usr/local/bin/nmap"
OUTPUT_NAME = re.compile(r"^[0-9a-f]{32}\.xml$")
PORT_SPECIFICATION = "__PORT_SPECIFICATION__"
RFC1918 = (
    ip_network("10.0.0.0/8"),
    ip_network("172.16.0.0/12"),
    ip_network("192.168.0.0/16"),
)


def _ports() -> str:
    if PORT_SPECIFICATION != "__PORT_SPECIFICATION__":
        return PORT_SPECIFICATION
    # Development wrapper: use the same local database as the unprivileged app.
    from netcheck.nmap_ports import port_specification
    return port_specification()


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        return 2
    try:
        target = ip_network(argv[1], strict=False)
        output = Path(argv[2]).resolve(strict=False)
    except ValueError:
        return 2
    if target.version != 4 or target.prefixlen < 24 or not any(
        target.subnet_of(private) for private in RFC1918
    ):
        return 2
    if output.parent != ALLOWED_DIR.resolve() or not OUTPUT_NAME.fullmatch(output.name):
        return 2
    os.execv(NMAP, [
        NMAP, "-n", "-sS", "-sU", "-sV", "--script", "http-title",
        "--script-timeout", "30s", "-p", _ports(),
        "--max-rate", "100", "-oX", str(output), argv[1],
    ])
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
