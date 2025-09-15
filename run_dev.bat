@echo off
cd /d D:\buybit
.\.venv\Scripts\activate
python -m dotenv -f .env.dev run -- ".\.venv\Scripts\python.exe" app.py
