param([switch]$Approved)
$ErrorActionPreference = 'Stop'
if (-not $Approved) { throw 'Setting the broker emergency stop requires -Approved.' }
if (-not $env:HUB_COORDINATOR_TOKEN) { throw 'Set HUB_COORDINATOR_TOKEN in this process environment first.' }
$headers = @{ Authorization = "Bearer $env:HUB_COORDINATOR_TOKEN" }
Invoke-RestMethod -Method Post -Uri 'http://127.0.0.1:8765/v1/emergency-stop?stopped=true' -Headers $headers
