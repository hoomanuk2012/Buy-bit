@echo off
setlocal
REM ====== CONFIG ======
set TOKEN=4b9a2c2d7c7a49a8a0d0df6eb1f6f434
set BASE=http://127.0.0.1:8000
REM ====================

echo [CHECK] Is server up at %BASE% ?
curl -s -I "%BASE%/" | find "200" >nul
if errorlevel 1 (
  echo [ERROR] Server not reachable on %BASE%.
  echo Start it with: waitress-serve --listen=127.0.0.1:8000 app:app
  pause
  exit /b 1
)

echo [STEP 1] Auto-create payouts (pending)...
curl -s -X POST "%BASE%/cron/payouts/auto-create?token=%TOKEN%"
echo.

echo [STEP 2] Run payout batch (pending -> processing)...
curl -s -X POST "%BASE%/cron/payouts/run-batch?token=%TOKEN%"
echo.

echo [DONE] Auto-create + Run-batch executed.
pause
