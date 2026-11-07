#!/bin/sh
set -eu

WRAPPER=/usr/local/libexec/netcheck-nmap-wrapper
SUDOERS=/etc/sudoers.d/netcheck-nmap
if [ "$(id -u)" -ne 0 ]; then
    echo "Rulați dezinstalarea ca administrator / Run uninstallation as administrator." >&2
    exit 1
fi
rm -f "$SUDOERS" "$WRAPPER"
visudo -c
echo "Dezinstalat / Uninstalled."
