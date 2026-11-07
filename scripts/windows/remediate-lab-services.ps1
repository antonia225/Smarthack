param(
    [string]$ComposeDirectory = (Join-Path $PSScriptRoot "..\..\lab\services")
)

$ErrorActionPreference = "Stop"
$statePath = Join-Path $ComposeDirectory "remediation-state.json"
$state = @()

Get-CimInstance Win32_Process |
    Where-Object { $_.CommandLine -and $_.CommandLine -match "simulators\.py" } |
    ForEach-Object {
        $state += [pscustomobject]@{
            Kind = "simulator"
            ProcessId = $_.ProcessId
            CommandLine = $_.CommandLine
        }
        Stop-Process -Id $_.ProcessId -Force
    }

Push-Location $ComposeDirectory
try {
    docker compose stop mqtt simulators
} finally {
    Pop-Location
}

$state | ConvertTo-Json | Set-Content -Path $statePath -Encoding UTF8
Write-Output "Remediere aplicata / Remediation applied. Starea este în / State is in $statePath"
Write-Output "Verificați / Verify: Get-NetTCPConnection -LocalPort 23,1883 -ErrorAction SilentlyContinue"
