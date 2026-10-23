# Smoke-test Internet in-process SmartLink SOCKS (--router-only, no Admin/WinDivert).
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$cxx = if ($env:CXX) { $env:CXX } else { "g++" }
& $cxx -std=c++17 -O2 -Wall -Iinclude src/internet.cpp -o internet.exe -lws2_32 -liphlpapi
if ($LASTEXITCODE -ne 0) { throw "internet build failed" }
& $cxx -std=c++17 -O2 -Wall -Iinclude src/server.cpp -o server.exe -lws2_32
if ($LASTEXITCODE -ne 0) { throw "server build failed" }
& $cxx -std=c++17 -O2 -Wall -Iinclude tests/echo_server.cpp -o tests/echo_server.exe -lws2_32
if ($LASTEXITCODE -ne 0) { throw "echo build failed" }
& $cxx -std=c++17 -O2 -Wall -Iinclude tests/socks5_http_get.cpp -o tests/socks5_http_get.exe -lws2_32
if ($LASTEXITCODE -ne 0) { throw "socks5_http_get build failed" }

function Stop-Stack {
    Get-Process -Name internet,server,echo_server -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 400
}
Stop-Stack

$echo = Start-Process .\tests\echo_server.exe -ArgumentList "19082" -PassThru -WindowStyle Hidden -WorkingDirectory $Root `
    -RedirectStandardOutput tests\inet_echo.log -RedirectStandardError tests\inet_echo.err
$srv = Start-Process .\server.exe -ArgumentList "tests\peer_relay_server.json" -PassThru -WindowStyle Hidden -WorkingDirectory $Root `
    -RedirectStandardOutput tests\inet_srv.log -RedirectStandardError tests\inet_srv.err
Start-Sleep -Seconds 1
$inet = Start-Process .\internet.exe -ArgumentList "tests\internet_router_test.json","--router-only" -PassThru -WindowStyle Hidden -WorkingDirectory $Root `
    -RedirectStandardOutput tests\inet_router.log -RedirectStandardError tests\inet_router.err
Start-Sleep -Seconds 1

try {
    if ($echo.HasExited -or $srv.HasExited -or $inet.HasExited) {
        Get-Content tests\inet_router.log,tests\inet_router.err -ErrorAction SilentlyContinue
        throw "process exited early"
    }
    Write-Host "=== SOCKS via internet --router-only ==="
    & .\tests\socks5_http_get.exe 21081 19082 127.0.0.1
    if ($LASTEXITCODE -ne 0) { throw "http via internet router failed" }
    & .\tests\socks5_http_get.exe 21081 19082 localhost
    if ($LASTEXITCODE -ne 0) { throw "localhost via internet router failed" }
    for ($i = 0; $i -lt 8; $i++) {
        & .\tests\socks5_http_get.exe 21081 19082 127.0.0.1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "burst failed at $i" }
    }
    Write-Host "INTERNET ROUTER SMOKE OK"
}
finally {
    Stop-Stack
}
