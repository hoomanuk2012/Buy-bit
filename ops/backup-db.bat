@echo off
setlocal
set SRC=D:\buybit\buybit.db
set DST=D:\buybit\backups

if not exist "%DST%" mkdir "%DST%"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ts=(Get-Date).ToString('yyyyMMdd-HHmmss');" ^
  "Copy-Item '%SRC%' (Join-Path '%DST%' ('buybit-'+$ts+'.db'));" ^
  "(Get-ChildItem '%DST%' -Filter 'buybit-*.db' | Sort-Object LastWriteTime -Descending | Select-Object -Skip 30) | Remove-Item -Force"

echo [DONE] DB backup created (max 30 files kept).
