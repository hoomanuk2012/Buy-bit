@echo off
setlocal
cd /d D:\buybit
if not exist D:\buybit\logs mkdir D:\buybit\logs

"C:\Users\hooma\AppData\Local\Programs\Python\Python313\Scripts\waitress-serve.exe" ^
  --listen=127.0.0.1:8000 app:app >> D:\buybit\logs\server.log 2>&1
