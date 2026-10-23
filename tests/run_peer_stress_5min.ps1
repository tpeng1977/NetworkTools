# 5-minute high-intensity local peer relay stress.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
Set-Location $Root

$cxx = if ($env:CXX) { $env:CXX } else { "g++" }
$flags = @("-std=c++17", "-O2", "-Wall", "-Iinclude")
$libs = @("-lws2_32")

function Stop-PeerStack {
    Get-Process -Name server,peer,multilink,echo_server,dns_tcp_stub,peer_sustained_stress -ErrorAction SilentlyContinue |
        Stop-Process -Force -ErrorAction SilentlyContinue
    Start-Sleep -Milliseconds 600
}

Write-Host "=== Build ==="
& $cxx @flags src/server.cpp -o server.exe @libs
if ($LASTEXITCODE -ne 0) { throw "server build failed" }
& $cxx @flags src/peer.cpp -o peer.exe @libs
if ($LASTEXITCODE -ne 0) { throw "peer build failed" }
& $cxx @flags src/multilink.cpp -o multilink.exe @libs -liphlpapi
if ($LASTEXITCODE -ne 0) { throw "multilink build failed" }
& $cxx @flags tests/echo_server.cpp -o tests/echo_server.exe @libs
if ($LASTEXITCODE -ne 0) { throw "echo build failed" }
& $cxx @flags tests/dns_tcp_stub.cpp -o tests/dns_tcp_stub.exe @libs
if ($LASTEXITCODE -ne 0) { throw "dns stub build failed" }
& $cxx @flags tests/peer_sustained_stress.cpp -o tests/peer_sustained_stress.exe @libs
if ($LASTEXITCODE -ne 0) { throw "stress build failed" }

Stop-PeerStack
$logDir = Join-Path $Root "tests"
foreach ($n in @("stress5_echo","stress5_dns","stress5_srv","stress5_peer","stress5_ml","stress5_out")) {
    Remove-Item (Join-Path $logDir "$n.log") -ErrorAction SilentlyContinue
    Remove-Item (Join-Path $logDir "$n.err") -ErrorAction SilentlyContinue
}

Write-Host "=== Start stack (peer workers=32) ==="
$echo = Start-Process .\tests\echo_server.exe -ArgumentList "19081" -PassThru -WindowStyle Hidden -WorkingDirectory $Root `
    -RedirectStandardOutput (Join-Path $logDir "stress5_echo.log") -RedirectStandardError (Join-Path $logDir "stress5_echo.err")
$dns = Start-Process .\tests\dns_tcp_stub.exe -ArgumentList "15353" -PassThru -WindowStyle Hidden -WorkingDirectory $Root `
    -RedirectStandardOutput (Join-Path $logDir "stress5_dns.log") -RedirectStandardError (Join-Path $logDir "stress5_dns.err")
$srv = Start-Process .\server.exe -ArgumentList "tests\peer_relay_server.json" -PassThru -WindowStyle Hidden -WorkingDirectory $Root `
    -RedirectStandardOutput (Join-Path $logDir "stress5_srv.log") -RedirectStandardError (Join-Path $logDir "stress5_srv.err")
Start-Sleep -Seconds 1
$peer = Start-Process .\peer.exe -ArgumentList "tests\peer_relay_peer_stress.json" -PassThru -WindowStyle Hidden -WorkingDirectory $Root `
    -RedirectStandardOutput (Join-Path $logDir "stress5_peer.log") -RedirectStandardError (Join-Path $logDir "stress5_peer.err")
Start-Sleep -Seconds 2
$ml = Start-Process .\multilink.exe -ArgumentList "tests\peer_relay_multilink.json" -PassThru -WindowStyle Hidden -WorkingDirectory $Root `
    -RedirectStandardOutput (Join-Path $logDir "stress5_ml.log") -RedirectStandardError (Join-Path $logDir "stress5_ml.err")
Start-Sleep -Seconds 2

# Wait until peer pool is warm (at least some Via-peer readiness)
$deadline = (Get-Date).AddSeconds(15)
while ((Get-Date) -lt $deadline) {
    if ($peer.HasExited -or $srv.HasExited -or $ml.HasExited) { break }
    $reg = @(Select-String -Path (Join-Path $logDir "stress5_peer.log") -Pattern "Peer registered" -ErrorAction SilentlyContinue)
    if ($reg.Count -ge 8) { break }
    Start-Sleep -Milliseconds 300
}

try {
    foreach ($p in @($echo,$dns,$srv,$peer,$ml)) {
        if ($null -eq $p -or $p.HasExited) { throw "stack process exited early — see tests/stress5_*.log" }
    }

    Write-Host "=== Sustained stress 300s x 12 threads ==="
    $stress = Start-Process .\tests\peer_sustained_stress.exe -ArgumentList "300","12","21080","19081","15353" `
        -PassThru -WorkingDirectory $Root -NoNewWindow `
        -RedirectStandardOutput (Join-Path $logDir "stress5_out.log") `
        -RedirectStandardError (Join-Path $logDir "stress5_out.err")

    while (-not $stress.HasExited) {
        Start-Sleep -Seconds 5
        foreach ($p in @($echo,$dns,$srv,$peer,$ml)) {
            if ($p.HasExited) {
                Stop-Process -Id $stress.Id -Force -ErrorAction SilentlyContinue
                throw "stack process died mid-stress pid=$($p.Id) name check logs"
            }
        }
        Get-Content (Join-Path $logDir "stress5_out.log") -Tail 1 -ErrorAction SilentlyContinue
    }
    $null = $stress.WaitForExit(5000)
    $code = $stress.ExitCode
    if ($null -eq $code) { $code = -1 }

    if ($code -ne 0) {
        Write-Host "--- stress stdout ---"
        Get-Content (Join-Path $logDir "stress5_out.log") -Tail 30
        Write-Host "--- stress stderr ---"
        Get-Content (Join-Path $logDir "stress5_out.err") -Tail 30 -ErrorAction SilentlyContinue
        Write-Host "--- server rejects ---"
        Select-String -Path (Join-Path $logDir "stress5_srv.log") -Pattern "No peer|CONNECT_FAIL|rejected" -ErrorAction SilentlyContinue |
            Select-Object -Last 20
        Write-Host "--- multilink rejects ---"
        Select-String -Path (Join-Path $logDir "stress5_ml.log") -Pattern "rejected|failed" -ErrorAction SilentlyContinue |
            Select-Object -Last 20
        throw "stress exited $code"
    }

    Write-Host ""
    Write-Host "=== 5-MINUTE PEER STRESS PASSED ==="
    Get-Content (Join-Path $logDir "stress5_out.log") -Tail 8
    $rejects = @(Select-String -Path (Join-Path $logDir "stress5_srv.log") -Pattern "No peer" -ErrorAction SilentlyContinue)
    $mlfail = @(Select-String -Path (Join-Path $logDir "stress5_ml.log") -Pattern "rejected|failed" -ErrorAction SilentlyContinue)
    Write-Host "server 'No peer' count=$($rejects.Count)  multilink fail lines=$($mlfail.Count)"
}
finally {
    Stop-PeerStack
}
