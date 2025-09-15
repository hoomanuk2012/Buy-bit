@echo off
setlocal
set TOKEN=4b9a2c2d7c7a49a8a0d0df6eb1f6f434
set BASE=http://127.0.0.1:8000

curl -s -I "%BASE%/healthz" | find "200" >nul || ( echo [ERR] Server down & pause & exit /b 1 )

echo [1/3] Auto-create...
curl -s -X POST "%BASE%/cron/payouts/auto-create?token=%TOKEN%"
echo.

echo [2/3] Run batch...
curl -s -X POST "%BASE%/cron/payouts/run-batch?token=%TOKEN%"
echo.

timeout /t 5 >nul

echo [3/3] Refresh processing...
curl -s -X POST "%BASE%/cron/payouts/refresh-processing?token=%TOKEN%"
echo.

echo [DONE]
pause
