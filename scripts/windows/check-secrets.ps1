$ErrorActionPreference = "Stop"

if (-not (Get-Command gitleaks -ErrorAction SilentlyContinue)) {
    Write-Error "gitleaks lipsește / gitleaks is not installed."
}

# Working tree, including untracked files (`gitleaks dir`; on recent versions `detect` scans Git history).
gitleaks dir --config .gitleaks.toml --no-banner --redact .
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
# Git history, all refs.
gitleaks git --config .gitleaks.toml --log-opts="--all" --no-banner --redact
exit $LASTEXITCODE
