@echo off
cd /d D:\buybit
call .venv\Scripts\activate
set FLASK_APP=app
set FLASK_DEBUG=1
set FORCE_HTTPS=0
flask run -h 127.0.0.1 -p 8000
