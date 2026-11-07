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


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        return 2
    try:
        target = ip_network(argv[1], strict=False)
        output = Path(argv[2]).resolve(strict=False)
    except ValueError:
        return 2
    if target.version != 4 or target.prefixlen < 24:
        return 2
    if output.parent != ALLOWED_DIR or not OUTPUT_NAME.fullmatch(output.name):
        return 2
    os.execv(NMAP, [
        NMAP, "-n", "-sS", "-sU", "-sV", "--script", "http-title",
        "--script-timeout", "30s", "-p", "T:1-1000,U:53,123,161,1900,5353",
        "--max-rate", "100", "-oX", str(output), argv[1],
    ])
    return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
