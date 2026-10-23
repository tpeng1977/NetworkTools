# Local peer ↔ server ↔ multilink end-to-end (no remote hosts).
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$cxx = $env:CXX
if (-not $cxx) { $cxx = "g++" }
$incs = "-Iinclude"
$flags = "-std=c++17 -O2 -Wall"
$libs = "-lws2_32"

function Stop-PeerStack {
    Get-Process -Name server,peer,multilink,echo_server,dns_tcp_stub -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 500
}

Write-Host "=== Build peer stack + helpers ==="
& $cxx ($flags -split ' ') ($incs -split ' ') src/server.cpp -o server.exe ($libs -split ' ')
if ($LASTEXITCODE -ne 0) { throw "server build failed" }
& $cxx ($flags -split ' ') ($incs -split ' ') src/peer.cpp -o peer.exe ($libs -split ' ')
if ($LASTEXITCODE -ne 0) { throw "peer build failed" }
& $cxx ($flags -split ' ') ($incs -split ' ') src/multilink.cpp -o multilink.exe ($libs -split ' ') -liphlpapi
if ($LASTEXITCODE -ne 0) { throw "multilink build failed" }
& $cxx ($flags -split ' ') ($incs -split ' ') tests/echo_server.cpp -o tests/echo_server.exe ($libs -split ' ')
if ($LASTEXITCODE -ne 0) { throw "echo build failed" }
& $cxx ($flags -split ' ') ($incs -split ' ') tests/dns_tcp_stub.cpp -o tests/dns_tcp_stub.exe ($libs -split ' ')
if ($LASTEXITCODE -ne 0) { throw "dns stub build failed" }
& $cxx ($flags -split ' ') ($incs -split ' ') tests/socks5_http_get.cpp -o tests/socks5_http_get.exe ($libs -split ' ')
if ($LASTEXITCODE -ne 0) { throw "socks5_http_get build failed" }
& $cxx ($flags -split ' ') ($incs -split ' ') tests/socks5_http_get_ip.cpp -o tests/socks5_http_get_ip.exe ($libs -split ' ')
if ($LASTEXITCODE -ne 0) { throw "socks5_http_get_ip build failed" }
& $cxx ($flags -split ' ') ($incs -split ' ') tests/socks5_dns_get.cpp -o tests/socks5_dns_get.exe ($libs -split ' ')
if ($LASTEXITCODE -ne 0) { throw "socks5_dns_get build failed" }
& $cxx ($flags -split ' ') ($incs -split ' ') tests/test_peer_protocol.cpp -o tests/test_peer_protocol.exe ($libs -split ' ')
if ($LASTEXITCODE -ne 0) { throw "test_peer_protocol build failed" }

Write-Host "=== Unit: peer protocol ==="
& .\tests\test_peer_protocol.exe
if ($LASTEXITCODE -ne 0) { throw "peer protocol unit failed" }

Stop-PeerStack

$logDir = Join-Path $Root "tests"
Remove-Item "$logDir\peer_e2e_*.log" -ErrorAction SilentlyContinue

Write-Host "=== Start echo / dns-stub / server / peer / multilink ==="
$echo = Start-Process -FilePath ".\tests\echo_server.exe" -ArgumentList "19081" `
    -RedirectStandardOutput (Join-Path $logDir "peer_e2e_echo.log") `
    -RedirectStandardError (Join-Path $logDir "peer_e2e_echo.err") `
    -PassThru -WindowStyle Hidden -WorkingDirectory $Root
$dns = Start-Process -FilePath ".\tests\dns_tcp_stub.exe" -ArgumentList "15353" `
    -RedirectStandardOutput (Join-Path $logDir "peer_e2e_dns.log") `
    -RedirectStandardError (Join-Path $logDir "peer_e2e_dns.err") `
    -PassThru -WindowStyle Hidden -WorkingDirectory $Root
$srv = Start-Process -FilePath ".\server.exe" -ArgumentList "tests\peer_relay_server.json" `
    -RedirectStandardOutput (Join-Path $logDir "peer_e2e_srv.log") `
    -RedirectStandardError (Join-Path $logDir "peer_e2e_srv.err") `
    -PassThru -WindowStyle Hidden -WorkingDirectory $Root
Start-Sleep -Seconds 1
$peer = Start-Process -FilePath ".\peer.exe" -ArgumentList "tests\peer_relay_peer.json" `
    -RedirectStandardOutput (Join-Path $logDir "peer_e2e_peer.log") `
    -RedirectStandardError (Join-Path $logDir "peer_e2e_peer.err") `
    -PassThru -WindowStyle Hidden -WorkingDirectory $Root
Start-Sleep -Seconds 1
$ml = Start-Process -FilePath ".\multilink.exe" -ArgumentList "tests\peer_relay_multilink.json" `
    -RedirectStandardOutput (Join-Path $logDir "peer_e2e_ml.log") `
    -RedirectStandardError (Join-Path $logDir "peer_e2e_ml.err") `
    -PassThru -WindowStyle Hidden -WorkingDirectory $Root
Start-Sleep -Seconds 1

try {
    if ($echo.HasExited -or $dns.HasExited -or $srv.HasExited -or $peer.HasExited -or $ml.HasExited) {
        throw "a process exited early — check tests/peer_e2e_*.log"
    }

    Write-Host "=== 1) HTTP via peer, DOMAIN atyp (127.0.0.1) ==="
    & .\tests\socks5_http_get.exe 21080 19081 127.0.0.1
    if ($LASTEXITCODE -ne 0) { throw "domain-atyp http failed" }

    Write-Host "=== 2) HTTP via peer, DOMAIN atyp (localhost) ==="
    & .\tests\socks5_http_get.exe 21080 19081 localhost
    if ($LASTEXITCODE -ne 0) { throw "localhost domain http failed" }

    Write-Host "=== 3) HTTP via peer, IPv4 atyp ==="
    & .\tests\socks5_http_get_ip.exe 21080 19081 127.0.0.1
    if ($LASTEXITCODE -ne 0) { throw "ipv4-atyp http failed" }

    Write-Host "=== 4) DNS-over-TCP via peer (local stub) ==="
    & .\tests\socks5_dns_get.exe 21080 15353 127.0.0.1 peer-dns.test
    if ($LASTEXITCODE -ne 0) { throw "dns-over-tcp via peer failed" }

    Write-Host "=== 5) Burst 12 sequential HTTP (peer pool recycle) ==="
    for ($i = 0; $i -lt 12; $i++) {
        & .\tests\socks5_http_get.exe 21080 19081 127.0.0.1 | Out-Null
        if ($LASTEXITCODE -ne 0) { throw "burst failed at $i" }
    }
    Write-Host "burst OK"

    Write-Host "=== 6) Parallel 4 HTTP (workers=4) ==="
    $jobs = @()
    for ($i = 0; $i -lt 4; $i++) {
        $jobs += Start-Job -ScriptBlock {
            param($root)
            Set-Location $root
            & .\tests\socks5_http_get.exe 21080 19081 127.0.0.1
            exit $LASTEXITCODE
        } -ArgumentList $Root
    }
    $jobs | Wait-Job | Out-Null
    foreach ($j in $jobs) {
        $code = Receive-Job $j 6>$null; if (-not $?) { }
        if ($j.State -ne "Completed") { throw "parallel job not completed" }
        Remove-Job $j -Force
    }
    # Re-run sequential check that pool recovered
    Start-Sleep -Milliseconds 800
    & .\tests\socks5_http_get.exe 21080 19081 127.0.0.1
    if ($LASTEXITCODE -ne 0) { throw "post-parallel http failed" }

    Write-Host ""
    Write-Host "ALL PEER RELAY LOCAL TESTS PASSED"
    Write-Host "--- server log (tail) ---"
    Get-Content (Join-Path $logDir "peer_e2e_srv.log") -Tail 20
    Write-Host "--- peer log (tail) ---"
    Get-Content (Join-Path $logDir "peer_e2e_peer.log") -Tail 20
    Write-Host "--- multilink log (tail) ---"
    Get-Content (Join-Path $logDir "peer_e2e_ml.log") -Tail 20
}
finally {
    Stop-PeerStack
}
