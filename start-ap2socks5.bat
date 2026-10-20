@echo off
REM Start/stop ap2socks5.exe (Administrator). Hotspot must already be up (only-ap.bat).
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0start-ap2socks5.ps1" %*
