param([switch]$Approved)
$ErrorActionPreference = 'Stop'
if (-not $Approved) { throw 'Running package verification requires -Approved.' }
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) { $python = (Get-Command python).Source }
Push-Location $root
try { & $python -m unittest discover -s tests -v; if ($LASTEXITCODE -ne 0) { throw 'Verification failed.' } }
finally { Pop-Location }
