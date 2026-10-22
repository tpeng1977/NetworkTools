@echo off
setlocal
REM Enable IPv6 (ms_tcpip6) on all network adapters. Requires Administrator.

net session >NUL 2>&1
if errorlevel 1 (
  echo [!] Need Administrator. Right-click -^> Run as administrator.
  exit /b 1
)

echo [*] Enabling IPv6 binding on all adapters...
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-NetAdapter -ErrorAction SilentlyContinue | ForEach-Object { Enable-NetAdapterBinding -Name $_.Name -ComponentID ms_tcpip6 -ErrorAction SilentlyContinue; Write-Host ('[+] ' + $_.Name) }"

REM Clear "prefer IPv4 / disable IPv6" tweaks if present (0 = fully enabled).
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters" /v DisabledComponents /t REG_DWORD /d 0 /f >NUL

echo.
echo [*] Current IPv6 bindings:
powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "Get-NetAdapterBinding -ComponentID ms_tcpip6 | Format-Table Name,Enabled -AutoSize"

echo [*] Done. If IPv6 still missing, reboot once.
endlocal
