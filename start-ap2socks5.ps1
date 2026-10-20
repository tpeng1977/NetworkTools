# Start/stop ap2socks5.exe alone — WinDivert AP -> SOCKS5 forwarding.
# Does NOT start/stop the mobile hotspot (use only-ap.bat for that).
# Does NOT start SOCKS5 (start local/smartlink/multilink/client first).
# Config: config/ap2socks5.json
param(
    [switch]$Stop,
    [string]$Config = "config\ap2socks5.json"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $Root

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`""
    if ($Stop) { $arg += " -Stop" }
    if ($Config -and $Config -ne "config\ap2socks5.json") {
        $arg += " -Config `"$Config`""
    }
    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $arg -WorkingDirectory $Root | Out-Null
    exit 0
}

function Stop-LocalExe([string]$Name) {
    Get-Process -Name ([IO.Path]::GetFileNameWithoutExtension($Name)) -ErrorAction SilentlyContinue |
        Where-Object { $_.Path -and $_.Path.StartsWith($Root, [StringComparison]::OrdinalIgnoreCase) } |
        ForEach-Object {
            Write-Host "[*] stop $($_.ProcessName) pid=$($_.Id)"
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
}

function Get-JsonObject([string]$Path) {
    if (-not (Test-Path $Path)) { return $null }
    return (Get-Content $Path -Raw -Encoding UTF8 | ConvertFrom-Json)
}

function Find-ApAdapter([string]$Gateway) {
    # Always return an Objectarray{} — a single PSCustomObject from return/unwrap
    # makes .Count mean "property count" or $null, so the wait loop never matches.
    $addrs = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.IPAddress -and
            $_.IPAddress -notlike "127.*" -and
            $_.IPAddress -notlike "169.254.*"
        })
    $hit = $null
    if ($Gateway) {
        $hit = $addrs | Where-Object { $_.IPAddress -eq $Gateway } | Select-Object -First 1
    }
    if (-not $hit) {
        $hit = $addrs | Where-Object { $_.IPAddress -eq "192.168.137.1" } | Select-Object -First 1
    }
    if (-not $hit) { return @() }
    return @(
        [pscustomobject]@{
            InterfaceAlias = $hit.InterfaceAlias
            InterfaceIndex = $hit.InterfaceIndex
            IPAddress      = $hit.IPAddress
            PrefixLength   = $hit.PrefixLength
        }
    )
}

if ($Stop) {
    Write-Host "[*] stop ap2socks5"
    Stop-LocalExe "ap2socks5.exe"
    Stop-LocalExe "ap2socks5.next.exe"
    Write-Host "[*] ap2socks5 stopped (hotspot left running)"
    exit 0
}

$cfgPath = Join-Path $Root $Config
if (-not (Test-Path $cfgPath)) {
    throw "Config not found: $cfgPath (copy from config_example/ap2socks5_example.json)"
}
$cfg = Get-JsonObject $cfgPath
$apGateway = if ($cfg.ap_gateway) { [string]$cfg.ap_gateway } else { "192.168.137.1" }
$socksHost = if ($cfg.socks5_host) { [string]$cfg.socks5_host } else { "127.0.0.1" }
$socksPort = if ($cfg.socks5_port) { [int]$cfg.socks5_port } else { 11080 }

foreach ($file in @("ap2socks5.exe", "WinDivert.dll", "WinDivert64.sys")) {
    if (-not (Test-Path (Join-Path $Root $file))) {
        throw "Missing $file next to this script"
    }
}

Write-Host "[*] stop previous ap2socks5"
Stop-LocalExe "ap2socks5.exe"
Stop-LocalExe "ap2socks5.next.exe"
Start-Sleep -Milliseconds 400

$next = Join-Path $Root "ap2socks5.next.exe"
if (Test-Path $next) {
    Move-Item -Force $next (Join-Path $Root "ap2socks5.exe")
    Write-Host "[*] installed new ap2socks5.exe"
}

Write-Host "[*] wait for AP gateway $apGateway (start only-ap.bat first if needed)"
$hit = $null
for ($i = 0; $i -lt 45; $i++) {
    $found = @(Find-ApAdapter $apGateway)
    if ($found.Count -ge 1) {
        $hit = $found[0]
        break
    }
    Start-Sleep -Milliseconds 500
}
if (-not $hit) {
    Write-Host "[!] IPv4 adapters seen:"
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        ForEach-Object { Write-Host ("    {0}  {1}/{2}" -f $_.InterfaceAlias, $_.IPAddress, $_.PrefixLength) }
    throw "AP gateway $apGateway not found. Run only-ap.bat first, then retry."
}
Write-Host "[*] AP adapter $($hit.InterfaceAlias) ifIndex=$($hit.InterfaceIndex) $($hit.IPAddress)/$($hit.PrefixLength)"

$tcp = Get-NetTCPConnection -LocalAddress $socksHost -LocalPort $socksPort -State Listen -ErrorAction SilentlyContinue
if (-not $tcp) {
    Write-Host "[!] SOCKS5 not listening on ${socksHost}:$socksPort"
    Write-Host "    Start one of: local.exe / smartlink.exe / multilink.exe / client.exe"
}

$outLog = Join-Path $Root "ap2socks5.out.log"
$errLog = Join-Path $Root "ap2socks5.err.log"
Remove-Item $outLog, $errLog -ErrorAction SilentlyContinue

$relCfg = $Config
if ([System.IO.Path]::IsPathRooted($Config)) { $relCfg = $cfgPath }

Write-Host "[*] start ap2socks5.exe $relCfg"
$proc = Start-Process -FilePath (Join-Path $Root "ap2socks5.exe") `
    -ArgumentList $relCfg `
    -WorkingDirectory $Root `
    -RedirectStandardOutput $outLog `
    -RedirectStandardError $errLog `
    -PassThru -WindowStyle Hidden

Start-Sleep -Seconds 2
if ($proc.HasExited) {
    Write-Host "----- ap2socks5 output -----"
    Get-Content $outLog, $errLog -Encoding UTF8 -ErrorAction SilentlyContinue | ForEach-Object { Write-Host $_ }
    throw "ap2socks5.exe exited with code $($proc.ExitCode)"
}

Write-Host ""
Write-Host "----- ap2socks5 (first lines) -----"
Get-Content $outLog -Encoding UTF8 -ErrorAction SilentlyContinue | Select-Object -First 16 | ForEach-Object { Write-Host $_ }

Write-Host ""
Write-Host "Ready: AP exclusive + fake-IP remote DNS (browser-style)."
Write-Host "  AP gateway   : $apGateway ($($hit.InterfaceAlias))"
Write-Host "  SOCKS5       : ${socksHost}:$socksPort"
Write-Host "  DNS          : fake-IP 198.18.0.0/15; SOCKS5 resolves names"
Write-Host "  Phone tip    : disable Private DNS/DoH; toggle Wi-Fi to flush DNS cache"
Write-Host "  Logs         : ap2socks5.out.log / ap2socks5.err.log"
Write-Host "Stop with:  start-ap2socks5.bat -Stop"
