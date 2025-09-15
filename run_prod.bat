@echo off
cd /d D:\buybit
set PYTHONUTF8=1
REM اگر .env داری، python-dotenv قبلاً load_dotenv() را در app.py انجام می‌دهد
waitress-serve --listen=127.0.0.1:8000 app:app
