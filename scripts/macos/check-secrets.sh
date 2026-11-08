#!/bin/sh
set -eu

command -v gitleaks >/dev/null 2>&1 || {
    echo "gitleaks lipsește / gitleaks is not installed." >&2
    exit 127
}

# Working tree, including untracked files (`gitleaks dir`; on recent versions `detect` scans Git history).
gitleaks dir --config .gitleaks.toml --no-banner --redact .
# Git history, all refs.
gitleaks git --config .gitleaks.toml --log-opts="--all" --no-banner --redact
