@echo off
setlocal
REM Convenience launcher for internet-service.ps1 (auto-elevates).
REM Packages into dist\VortexInternet\ (gitignored) and controls the service.
REM Usage: internet-service.bat stage|install|start|stop|restart|status|uninstall

set "ROOT=%~dp0"
set "ACTION=%~1"
if "%ACTION%"=="" set "ACTION=status"

powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%ROOT%internet-service.ps1" %*
set "ERR=%ERRORLEVEL%"
endlocal & exit /b %ERR%
