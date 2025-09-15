@echo off
cd /d D:\buybit
call .\.venv\Scripts\activate
set PAYPAL_ENV=sandbox
set FORCE_HTTPS=0
waitress-serve --listen=127.0.0.1:8000 app:app
