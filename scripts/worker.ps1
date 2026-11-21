param([switch]$Approved)
$ErrorActionPreference = 'Stop'
if (-not $Approved) { throw 'Starting the model worker requires -Approved.' }
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) { throw 'Run install.ps1 -Approved first.' }
if (-not $env:HUB_WORKER_TOKEN) { throw 'Set HUB_WORKER_TOKEN in this process environment first.' }
$config = Join-Path $root 'config.json'
if (-not (Test-Path -LiteralPath $config)) { throw 'Create and review package-local config.json from config.example.json first.' }
Push-Location $root
try { & $python -m hub.worker --config $config }
finally { Pop-Location }
