$Token = "PUT-A-LONG-RANDOM-STRING-HERE"
$Base  = "http://127.0.0.1:8000"

Invoke-WebRequest -Method POST "$Base/cron/payouts/auto-create?token=$Token" | Out-Null
Start-Sleep -Seconds 3
Invoke-WebRequest -Method POST "$Base/cron/payouts/run-batch?token=$Token" | Out-Null

Write-Host "[DONE] Auto-create + Run-batch executed."
