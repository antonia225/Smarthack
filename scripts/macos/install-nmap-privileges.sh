#!/bin/sh
set -eu

PREFIX=/usr/local
WRAPPER="$PREFIX/libexec/netcheck-nmap-wrapper"
SUDOERS=/etc/sudoers.d/netcheck-nmap
SCAN_DIR=/var/tmp/netcheck-scans
NMAP="$(command -v nmap)"

if [ "$(id -u)" -ne 0 ]; then
    echo "Rulați instalarea ca administrator / Run installation as administrator." >&2
    exit 1
fi
mkdir -p "$PREFIX/libexec" "$SCAN_DIR"
mkdir -p /etc/sudoers.d
chmod 755 "$SCAN_DIR"
sed "s#^NMAP = .*#NMAP = '$NMAP'#" \
    "$(dirname "$0")/netcheck-nmap-wrapper.py" > "$WRAPPER"
chown root:wheel "$WRAPPER" "$SCAN_DIR"
chmod 755 "$WRAPPER"
cat > "$SUDOERS" <<EOF
%admin ALL=(root) NOPASSWD: $WRAPPER
EOF
chown root:wheel "$SUDOERS"
chmod 440 "$SUDOERS"
visudo -c
echo "Instalat / Installed: $WRAPPER; sudoers valid / valid."
