param([switch]$Approved)
$ErrorActionPreference = 'Stop'
if (-not $Approved) { throw 'Package-local dependency installation requires -Approved.' }
$root = Split-Path -Parent $PSScriptRoot
python -m venv (Join-Path $root '.venv')
& (Join-Path $root '.venv\Scripts\python.exe') -m pip install -r (Join-Path $root 'requirements.txt')
if ($LASTEXITCODE -ne 0) { throw 'Package-local dependency installation failed.' }
