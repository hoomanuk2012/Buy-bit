@echo off
cd /d D:\buybit
.\.venv\Scripts\activate
python -m dotenv -f .env.live run -- waitress-serve --listen=0.0.0.0:8000 app:app
