#!/bin/sh
set -eu

PREFIX=/usr/local
WRAPPER="$PREFIX/libexec/netcheck-nmap-wrapper"
SUDOERS=/etc/sudoers.d/netcheck-nmap
SCAN_DIR=/var/tmp/netcheck-scans
NMAP="$(command -v nmap)"
REPO_ROOT="$(CDPATH= cd -- "$(dirname "$0")/../.." && pwd)"

if [ "$(id -u)" -ne 0 ]; then
    echo "Rulați instalarea ca administrator / Run installation as administrator." >&2
    exit 1
fi
mkdir -p "$PREFIX/libexec" "$SCAN_DIR"
mkdir -p /etc/sudoers.d
chmod 755 "$SCAN_DIR"
PORT_SPECIFICATION="$(PYTHONPATH="$REPO_ROOT" python3 -c \
    'from netcheck.nmap_ports import port_specification; print(port_specification())')"
PORT_SPECIFICATION="$PORT_SPECIFICATION" NMAP="$NMAP" python3 - \
    "$(dirname "$0")/netcheck-nmap-wrapper.py" "$WRAPPER" <<'PY'
from pathlib import Path
import os
import sys

source = Path(sys.argv[1]).read_text(encoding="utf-8")
source = source.replace('NMAP = "/usr/local/bin/nmap"', f"NMAP = {os.environ['NMAP']!r}")
source = source.replace('PORT_SPECIFICATION = "__PORT_SPECIFICATION__"',
                        f"PORT_SPECIFICATION = {os.environ['PORT_SPECIFICATION']!r}")
Path(sys.argv[2]).write_text(source, encoding="utf-8")
PY
chown root:wheel "$WRAPPER" "$SCAN_DIR"
chmod 755 "$WRAPPER"
cat > "$SUDOERS" <<EOF
%admin ALL=(root) NOPASSWD: $WRAPPER
EOF
chown root:wheel "$SUDOERS"
chmod 440 "$SUDOERS"
visudo -c
echo "Instalat / Installed: $WRAPPER; sudoers valid / valid."
