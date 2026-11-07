#!/bin/sh
set -eu

command -v gitleaks >/dev/null 2>&1 || {
    echo "gitleaks lipsește / gitleaks is not installed." >&2
    exit 127
}

gitleaks detect --source . --config .gitleaks.toml --no-banner --redact
gitleaks git --config .gitleaks.toml --log-opts="--all" --no-banner --redact
