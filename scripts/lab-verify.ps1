param(
    [string]$Before = "lab/before",
    [string]$After = "lab/after"
)
$ErrorActionPreference = "Stop"
python lab/services/check_xml.py (Get-ChildItem (Join-Path $Before "*.xml")).FullName
python lab/services/check_xml.py (Get-ChildItem (Join-Path $After "*.xml")).FullName
python lab/compare.py $Before $After
Write-Host "Next / Următorii pași: păstrați XML-urile și folosiți analizorul oficial când este implementat."
