param([switch]$Approved)
$ErrorActionPreference = 'Stop'
if (-not $Approved) { throw 'Stopping the local broker requires -Approved.' }
$root = Split-Path -Parent $PSScriptRoot
$record = Join-Path $root 'state\broker-process.json'
if (-not (Test-Path -LiteralPath $record)) { return }
$owned = Get-Content -Raw -LiteralPath $record | ConvertFrom-Json
$process = Get-Process -Id $owned.pid -ErrorAction SilentlyContinue
if ($process -and $process.StartTime.ToUniversalTime().Ticks -eq [long]$owned.start_ticks) {
    Stop-Process -Id $process.Id -Force
}
Remove-Item -LiteralPath $record -Force
