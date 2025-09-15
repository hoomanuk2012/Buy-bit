@echo off
setlocal
set TOKEN=4b9a2c2d7c7a49a8a0d0df6eb1f6f434
set BASE=http://127.0.0.1:8000

curl -s -I "%BASE%/healthz" | find "200" >nul || (
  echo [ERROR] Server not reachable at %BASE%.
  pause & exit /b 1
)

echo [REFRESH] Checking processing batches...
curl -s -X POST "%BASE%/cron/payouts/refresh-processing?token=%TOKEN%"
echo.
echo [DONE]
pause
