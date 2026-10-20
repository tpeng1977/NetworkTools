# Integration test suite for Windows (MinGW).
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

Write-Host "=== Build all ==="
& .\build.bat all
if ($LASTEXITCODE -ne 0) { throw "build failed" }

function Stop-Procs {
    Get-Process -Name server,client,echo_server -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 400
}

Stop-Procs

Write-Host "=== Unit tests ==="
& .\tests\test_core.exe
if ($LASTEXITCODE -ne 0) { throw "unit tests failed" }

Write-Host "=== Start echo / server / client ==="
$echo = Start-Process -FilePath ".\tests\echo_server.exe" -ArgumentList "19080" -PassThru -WindowStyle Hidden -WorkingDirectory $Root
$srv  = Start-Process -FilePath ".\server.exe" -ArgumentList "config\server.json" -PassThru -WindowStyle Hidden -WorkingDirectory $Root
Start-Sleep -Seconds 1
$cli  = Start-Process -FilePath ".\client.exe" -ArgumentList "config\client.json" -PassThru -WindowStyle Hidden -WorkingDirectory $Root
Start-Sleep -Seconds 1

try {
    Write-Host "=== SOCKS5 HTTP GET ==="
    & .\tests\socks5_http_get.exe 11080 19080 127.0.0.1
    if ($LASTEXITCODE -ne 0) { throw "socks5 http get failed" }

    Write-Host "=== Anti-probe ==="
    & .\tests\probe_test.exe 18888
    if ($LASTEXITCODE -ne 0) { throw "probe test failed" }

    Write-Host "=== Wrong secret ==="
    & .\tests\wrong_secret_test.exe 18888
    if ($LASTEXITCODE -ne 0) { throw "wrong secret test failed" }

    Write-Host "=== Binary echo (IPv4) ==="
    & .\tests\binary_echo_test.exe 11080 19080
    if ($LASTEXITCODE -ne 0) { throw "binary echo test failed" }

    Write-Host "=== Stress 20x10 ==="
    & .\tests\stress_test.exe 20 10 11080 19080
    if ($LASTEXITCODE -ne 0) { throw "stress test failed" }

    Write-Host "=== Sustained 15s burst ==="
    $deadline = (Get-Date).AddSeconds(15)
    $loops = 0
    while ((Get-Date) -lt $deadline) {
        & .\tests\socks5_http_get.exe 11080 19080 127.0.0.1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "sustained loop failed at $loops" }
        $loops++
    }
    Write-Host "Sustained OK loops=$loops"

    Write-Host ""
    Write-Host "ALL INTEGRATION TESTS PASSED"
}
finally {
    Stop-Procs
    if ($echo -and !$echo.HasExited) { Stop-Process -Id $echo.Id -Force -ErrorAction SilentlyContinue }
    if ($srv -and !$srv.HasExited) { Stop-Process -Id $srv.Id -Force -ErrorAction SilentlyContinue }
    if ($cli -and !$cli.HasExited) { Stop-Process -Id $cli.Id -Force -ErrorAction SilentlyContinue }
}
