$ErrorActionPreference = "Stop"

if (-not (Get-Command gitleaks -ErrorAction SilentlyContinue)) {
    Write-Error "gitleaks lipsește / gitleaks is not installed."
}

gitleaks detect --source . --config .gitleaks.toml --no-banner --redact
gitleaks git --config .gitleaks.toml --log-opts="--all" --no-banner --redact
