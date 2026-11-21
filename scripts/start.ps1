param([switch]$Approved, [switch]$EnableRelay, [switch]$EnableWorkers)
$ErrorActionPreference = 'Stop'
if (-not $Approved) { throw 'Starting the local broker requires -Approved.' }
$root = Split-Path -Parent $PSScriptRoot
$python = Join-Path $root '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) { throw 'Run install.ps1 -Approved first.' }
if (-not $env:HUB_COORDINATOR_TOKEN) { throw 'Set HUB_COORDINATOR_TOKEN in this process environment first.' }
if ($EnableRelay) {
    if (-not $env:HUB_RELAY_TOKEN) { throw 'Set a distinct HUB_RELAY_TOKEN in this process environment first.' }
    $env:HUB_ENABLE_RELAY = '1'
} else {
    $env:HUB_ENABLE_RELAY = '0'
}
if ($EnableWorkers) {
    if (-not $env:HUB_WORKER_TOKENS) { throw 'Set distinct HUB_WORKER_TOKENS in this process environment first.' }
    $configPath = Join-Path $root 'config.json'
    if (-not (Test-Path -LiteralPath $configPath)) { throw 'Create and review config.json before enabling workers.' }
    $workerConfig = (Get-Content -Raw -LiteralPath $configPath | ConvertFrom-Json).worker
    if (-not $workerConfig.enabled) { throw 'Worker execution remains disabled in config.json.' }
    $env:HUB_ENABLE_WORKERS = '1'
} else {
    $env:HUB_ENABLE_WORKERS = '0'
}
$state = Join-Path $root 'state'
New-Item -ItemType Directory -Force $state | Out-Null
$record = Join-Path $state 'broker-process.json'
if (Test-Path -LiteralPath $record) {
    $old = Get-Content -Raw -LiteralPath $record | ConvertFrom-Json
    $p = Get-Process -Id $old.pid -ErrorAction SilentlyContinue
    if ($p -and $p.StartTime.ToUniversalTime().Ticks -eq [long]$old.start_ticks) { throw 'The tracked broker process is already running.' }
    Remove-Item -LiteralPath $record -Force
}
$env:HUB_DB_PATH = Join-Path $state 'hub.sqlite3'
$proc = Start-Process -FilePath $python -ArgumentList @('-m','uvicorn','--factory','hub.api:create_app','--host','127.0.0.1','--port','8765') -WorkingDirectory $root -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $state 'broker.out.log') -RedirectStandardError (Join-Path $state 'broker.err.log')
$proc.Refresh()
@{ pid = $proc.Id; start_ticks = $proc.StartTime.ToUniversalTime().Ticks } | ConvertTo-Json | Set-Content -LiteralPath $record -Encoding utf8
