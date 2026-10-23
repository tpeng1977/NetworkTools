# Package internet.exe into dist\ and register it as a Windows service (Win10/11).
# Uses WinSW (https://github.com/winsw/winsw) so Ctrl+C reaches internet.exe and
# WinDivert can shut down cleanly.
#
# Layout (gitignored):
#   dist\VortexInternet\
#     internet.exe, WinDivert*.dll/sys
#     config\internet.json, multirules.yaml, geo\...
#     VortexInternet.exe + .xml   (WinSW)
#     internet-service.ps1/.bat   (local copies for start/stop)
#     logs\
#
# Repo scripts stay tracked; runtime payload lives only under dist\.
#
# Usage (from repo root):
#   .\internet-service.ps1 stage              # only copy payload → dist\VortexInternet
#   .\internet-service.ps1 install            # stage + register Windows service (Admin)
#   .\internet-service.ps1 start | stop | restart | status
#   .\internet-service.ps1 uninstall
#   .\internet-service.ps1 uninstall -Purge   # also delete dist\VortexInternet
#
param(
    [Parameter(Position = 0)]
    [ValidateSet("stage", "install", "uninstall", "start", "stop", "restart", "status")]
    [string]$Action = "status",

    # Source config in the repo (copied into dist on install).
    [string]$Config = "config\internet.json",

    # Install / run root (default: <repo>\dist\VortexInternet).
    [string]$DistDir = "",

    [string]$ServiceId = "VortexInternet",

    [string]$DisplayName = "Vortex Internet",

    # Demand-start only (default: Automatic Delayed Start).
    [switch]$Manual,

    # Path to WinSW-x64.exe; default: <repo>\tools\WinSW-x64.exe (download if missing).
    [string]$WinSWPath = "",

    # Skip WinSW download.
    [switch]$Offline,

    # On uninstall, also remove the dist folder.
    [switch]$Purge
)

$ErrorActionPreference = "Stop"

# When invoked from a copy under dist\, treat that folder as DistDir and walk
# up to find the repo (parent of dist\) for rebuild sources.
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$RepoRoot = $ScriptDir
if ((Split-Path -Leaf $ScriptDir) -eq "VortexInternet" -and
    (Split-Path -Leaf (Split-Path -Parent $ScriptDir)) -eq "dist") {
    $RepoRoot = Split-Path -Parent (Split-Path -Parent $ScriptDir)
}
if (-not $DistDir) {
    $DistDir = Join-Path $RepoRoot "dist\VortexInternet"
}

function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# stage only needs write access to dist\; service ops need Administrator.
$needsAdmin = $Action -ne "stage" -and $Action -ne "status"
if ($needsAdmin -and -not (Test-Admin)) {
    $arg = "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`" $Action"
    if ($Config -and $Config -ne "config\internet.json") { $arg += " -Config `"$Config`"" }
    if ($DistDir) { $arg += " -DistDir `"$DistDir`"" }
    if ($ServiceId -and $ServiceId -ne "VortexInternet") { $arg += " -ServiceId `"$ServiceId`"" }
    if ($DisplayName -and $DisplayName -ne "Vortex Internet") { $arg += " -DisplayName `"$DisplayName`"" }
    if ($Manual) { $arg += " -Manual" }
    if ($WinSWPath) { $arg += " -WinSWPath `"$WinSWPath`"" }
    if ($Offline) { $arg += " -Offline" }
    if ($Purge) { $arg += " -Purge" }
    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $arg -WorkingDirectory $RepoRoot | Out-Null
    exit 0
}

$WrapperName = $ServiceId
$WrapperExe = Join-Path $DistDir "$WrapperName.exe"
$WrapperXml = Join-Path $DistDir "$WrapperName.xml"
$LogDir = Join-Path $DistDir "logs"
$DistConfigRel = "config\internet.json"

function Get-ServiceObj {
    Get-Service -Name $ServiceId -ErrorAction SilentlyContinue
}

function Resolve-SourceConfig {
    if ([IO.Path]::IsPathRooted($Config)) { return $Config }
    return (Join-Path $RepoRoot $Config)
}

function Get-JsonPaths([string]$CfgPath) {
    $raw = Get-Content -LiteralPath $CfgPath -Raw -Encoding UTF8
    $obj = $raw | ConvertFrom-Json
    [pscustomobject]@{
        RulesPath  = if ($obj.rules_path) { [string]$obj.rules_path } else { "config/multirules.yaml" }
        GeoIpCn    = if ($obj.geoip_cn) { [string]$obj.geoip_cn } else { "config/geo/geoip-cn.txt" }
        GeoSiteCn  = if ($obj.geosite_cn) { [string]$obj.geosite_cn } else { "config/geo/geosite-cn.txt" }
    }
}

function Resolve-RepoRelative([string]$Rel) {
    $norm = $Rel -replace "/", "\"
    if ([IO.Path]::IsPathRooted($norm)) { return $norm }
    return (Join-Path $RepoRoot $norm)
}

function Assert-BuildArtifacts {
    $need = @(
        (Join-Path $RepoRoot "internet.exe"),
        (Join-Path $RepoRoot "WinDivert.dll"),
        (Join-Path $RepoRoot "WinDivert64.sys")
    )
    foreach ($p in $need) {
        if (-not (Test-Path -LiteralPath $p)) {
            throw "Missing build artifact: $p (run build.bat and place WinDivert 2.2 next to internet.exe)"
        }
    }
    $cfg = Resolve-SourceConfig
    if (-not (Test-Path -LiteralPath $cfg)) {
        throw "Missing config: $cfg (copy from config_example\internet_example.json)"
    }
}

function Assert-DistInstalled {
    if (-not (Test-Path -LiteralPath (Join-Path $DistDir "internet.exe"))) {
        throw "Dist not staged at $DistDir. Run: .\internet-service.ps1 install"
    }
    if (-not (Test-Path -LiteralPath $WrapperExe)) {
        throw "Service wrapper missing: $WrapperExe. Run: .\internet-service.ps1 install"
    }
}

function Resolve-WinSW {
    if ($WinSWPath) {
        if (-not (Test-Path -LiteralPath $WinSWPath)) {
            throw "WinSW not found: $WinSWPath"
        }
        return (Resolve-Path -LiteralPath $WinSWPath).Path
    }
    $local = Join-Path $RepoRoot "tools\WinSW-x64.exe"
    if (Test-Path -LiteralPath $local) { return $local }

    if ($Offline) {
        throw "WinSW missing at tools\WinSW-x64.exe (re-run without -Offline, or pass -WinSWPath)"
    }

    $tools = Join-Path $RepoRoot "tools"
    if (-not (Test-Path $tools)) { New-Item -ItemType Directory -Path $tools | Out-Null }

    $url = "https://github.com/winsw/winsw/releases/download/v2.12.0/WinSW-x64.exe"
    Write-Host "[*] downloading WinSW → $local"
    Write-Host "    $url"
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Invoke-WebRequest -Uri $url -OutFile $local -UseBasicParsing
    } catch {
        throw "Failed to download WinSW: $($_.Exception.Message). Place WinSW-x64.exe at tools\WinSW-x64.exe or pass -WinSWPath."
    }
    return $local
}

function Copy-ForceFile([string]$Src, [string]$Dst) {
    $dir = Split-Path -Parent $Dst
    if (-not (Test-Path -LiteralPath $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    Copy-Item -LiteralPath $Src -Destination $Dst -Force
    Write-Host "[*] copy $(Split-Path -Leaf $Src) → $Dst"
}

function Publish-DistPayload {
    Assert-BuildArtifacts
    $srcCfg = Resolve-SourceConfig
    $paths = Get-JsonPaths $srcCfg

    if (-not (Test-Path -LiteralPath $DistDir)) {
        New-Item -ItemType Directory -Path $DistDir -Force | Out-Null
    }
    if (-not (Test-Path -LiteralPath $LogDir)) {
        New-Item -ItemType Directory -Path $LogDir -Force | Out-Null
    }

    Write-Host "[*] staging → $DistDir"

    Copy-ForceFile (Join-Path $RepoRoot "internet.exe") (Join-Path $DistDir "internet.exe")
    Copy-ForceFile (Join-Path $RepoRoot "WinDivert.dll") (Join-Path $DistDir "WinDivert.dll")
    Copy-ForceFile (Join-Path $RepoRoot "WinDivert64.sys") (Join-Path $DistDir "WinDivert64.sys")

    # Keep relative paths inside JSON (config\..., config\geo\...) valid under DistDir.
    Copy-ForceFile $srcCfg (Join-Path $DistDir $DistConfigRel)

    $rulesSrc = Resolve-RepoRelative $paths.RulesPath
    if (-not (Test-Path -LiteralPath $rulesSrc)) {
        throw "rules_path not found: $rulesSrc (from $srcCfg)"
    }
    # Preserve the relative path string from JSON when it is under config\.
    $rulesRel = ($paths.RulesPath -replace "/", "\")
    if (-not [IO.Path]::IsPathRooted($rulesRel)) {
        Copy-ForceFile $rulesSrc (Join-Path $DistDir $rulesRel)
    } else {
        Copy-ForceFile $rulesSrc (Join-Path $DistDir "config\multirules.yaml")
    }

    foreach ($rel in @($paths.GeoIpCn, $paths.GeoSiteCn)) {
        $src = Resolve-RepoRelative $rel
        if (-not (Test-Path -LiteralPath $src)) {
            throw "geo file missing: $src"
        }
        $dstRel = ($rel -replace "/", "\")
        if ([IO.Path]::IsPathRooted($dstRel)) {
            $dstRel = Join-Path "config\geo" (Split-Path -Leaf $src)
        }
        Copy-ForceFile $src (Join-Path $DistDir $dstRel)
    }

    # Control scripts inside dist so the package is self-contained.
    $ps1Src = Join-Path $RepoRoot "internet-service.ps1"
    $batSrc = Join-Path $RepoRoot "internet-service.bat"
    if (Test-Path -LiteralPath $ps1Src) {
        # Prefer repo script; if we are already the dist copy, still refresh from RepoRoot when possible.
        Copy-ForceFile $ps1Src (Join-Path $DistDir "internet-service.ps1")
    }
    if (Test-Path -LiteralPath $batSrc) {
        Copy-ForceFile $batSrc (Join-Path $DistDir "internet-service.bat")
    }

    Write-Host "[+] staged $DistDir"
}

function Remove-LegacyRootInstall {
    # Older script versions dropped WinSW + logs in the repo root.
    foreach ($name in @("VortexInternet.exe", "VortexInternet.xml")) {
        $p = Join-Path $RepoRoot $name
        if (Test-Path -LiteralPath $p) {
            Write-Host "[*] remove legacy $p"
            Remove-Item -LiteralPath $p -Force -ErrorAction SilentlyContinue
        }
    }
    $legacyLogs = Join-Path $RepoRoot "logs"
    if (Test-Path -LiteralPath $legacyLogs) {
        Write-Host "[*] remove legacy $legacyLogs"
        Remove-Item -LiteralPath $legacyLogs -Recurse -Force -ErrorAction SilentlyContinue
    }
}

function Write-WrapperXml {
    $xml = @"
<!-- Generated by internet-service.ps1 — runtime only (under dist\, gitignored). -->
<service>
  <id>$ServiceId</id>
  <name>$DisplayName</name>
  <description>Vortex Internet: MultiLink + EnableNet (WinDivert). Transparent proxy; no per-app SOCKS settings.</description>
  <executable>$DistDir\internet.exe</executable>
  <arguments>$DistConfigRel</arguments>
  <workingdirectory>$DistDir</workingdirectory>
  <logpath>$LogDir</logpath>
  <log mode="roll">
    <sizeThreshold>10240</sizeThreshold>
    <keepFiles>8</keepFiles>
  </log>
  <stoptimeout>20sec</stoptimeout>
  <stopparentprocessfirst>true</stopparentprocessfirst>
  <onfailure action="restart" delay="5 sec"/>
  <onfailure action="restart" delay="15 sec"/>
  <onfailure action="none"/>
  <resetfailure>1 hour</resetfailure>
  <priority>Normal</priority>
</service>
"@
    [IO.File]::WriteAllText($WrapperXml, $xml, [Text.UTF8Encoding]::new($false))
    Write-Host "[*] wrote $WrapperXml"
}

function Install-InternetService {
    Remove-LegacyRootInstall
    Publish-DistPayload
    $winsw = Resolve-WinSW

    $existing = Get-ServiceObj
    if ($existing -and $existing.Status -eq "Running") {
        Write-Host "[*] stopping running $ServiceId before refresh..."
        if (Test-Path -LiteralPath $WrapperExe) { & $WrapperExe stop 2>$null }
        else { Stop-Service -Name $ServiceId -Force -ErrorAction SilentlyContinue }
        Start-Sleep -Seconds 2
    }

    Write-WrapperXml
    Copy-Item -LiteralPath $winsw -Destination $WrapperExe -Force
    Write-Host "[*] wrapper $WrapperExe"

    Push-Location $DistDir
    try {
        if (-not (Get-ServiceObj)) {
            & $WrapperExe install
            if ($LASTEXITCODE -ne 0) { throw "WinSW install failed (exit $LASTEXITCODE)" }
            Write-Host "[+] installed service $ServiceId"
        } else {
            Write-Host "[*] service entry exists; refreshed files under $DistDir"
        }
    } finally {
        Pop-Location
    }

    if ($Manual) {
        Set-Service -Name $ServiceId -StartupType Manual
        Write-Host "[*] start type: Manual"
    } else {
        Set-Service -Name $ServiceId -StartupType Automatic -ErrorAction SilentlyContinue
        sc.exe config $ServiceId start= delayed-auto | Out-Null
        Write-Host "[*] start type: Automatic (Delayed)"
    }

    Write-Host "[*] dist:  $DistDir"
    Write-Host "[*] logs:  $LogDir"
    Write-Host "[*] next:  .\internet-service.ps1 start"
}

function Uninstall-InternetService {
    $svc = Get-ServiceObj
    if (-not $svc -and -not (Test-Path -LiteralPath $WrapperExe)) {
        Write-Host "[*] service $ServiceId not installed"
    } else {
        if ($svc -and $svc.Status -ne "Stopped") {
            Write-Host "[*] stopping $ServiceId..."
            if (Test-Path -LiteralPath $WrapperExe) { & $WrapperExe stop }
            else { Stop-Service -Name $ServiceId -Force -ErrorAction SilentlyContinue }
            Start-Sleep -Seconds 2
        }
        if (Test-Path -LiteralPath $WrapperExe) {
            Push-Location $DistDir
            try { & $WrapperExe uninstall } finally { Pop-Location }
            if ($LASTEXITCODE -ne 0 -and (Get-ServiceObj)) {
                sc.exe delete $ServiceId | Out-Null
            }
        } elseif (Get-ServiceObj) {
            sc.exe delete $ServiceId | Out-Null
        }
        Write-Host "[+] uninstalled $ServiceId"
    }

    if ($Purge) {
        if (Test-Path -LiteralPath $DistDir) {
            Remove-Item -LiteralPath $DistDir -Recurse -Force
            Write-Host "[+] removed $DistDir"
        }
        $distParent = Split-Path -Parent $DistDir
        if ((Split-Path -Leaf $distParent) -eq "dist" -and
            (Test-Path -LiteralPath $distParent) -and
            -not (Get-ChildItem -LiteralPath $distParent -Force -ErrorAction SilentlyContinue)) {
            Remove-Item -LiteralPath $distParent -Force -ErrorAction SilentlyContinue
        }
    }
}

function Start-InternetService {
    Assert-DistInstalled
    $svc = Get-ServiceObj
    if (-not $svc) { throw "Service $ServiceId is not installed. Run: .\internet-service.ps1 install" }

    foreach ($name in @("internet", "enable_net", "multilink", "smartlink", "activate_net")) {
        Get-Process -Name $name -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "[!] stopping conflicting process $($_.ProcessName) pid=$($_.Id)"
            Stop-Process -Id $_.Id -Force -ErrorAction SilentlyContinue
        }
    }

    if ($svc.Status -eq "Running") {
        Write-Host "[*] $ServiceId already running"
        return
    }
    & $WrapperExe start
    Start-Sleep -Seconds 1
    $svc = Get-ServiceObj
    Write-Host "[+] $ServiceId → $($svc.Status)"
}

function Stop-InternetService {
    $svc = Get-ServiceObj
    if (-not $svc) {
        Write-Host "[*] service $ServiceId not installed"
        return
    }
    if ($svc.Status -eq "Stopped") {
        Write-Host "[*] $ServiceId already stopped"
        return
    }
    if (Test-Path -LiteralPath $WrapperExe) { & $WrapperExe stop }
    else { Stop-Service -Name $ServiceId -Force }
    Start-Sleep -Seconds 1
    $svc = Get-ServiceObj
    Write-Host "[+] $ServiceId → $($svc.Status)"
}

function Restart-InternetService {
    Stop-InternetService
    Start-Sleep -Milliseconds 500
    Start-InternetService
}

function Show-Status {
    Write-Host "[*] repo:    $RepoRoot"
    Write-Host "[*] dist:    $DistDir"
    $svc = Get-ServiceObj
    if (-not $svc) {
        Write-Host "[*] ${ServiceId}: not installed"
        Write-Host "    install: .\internet-service.ps1 install"
        return
    }
    Write-Host "[*] $ServiceId"
    Write-Host "    status:     $($svc.Status)"
    Write-Host "    start type: $($svc.StartType)"
    Write-Host "    wrapper:    $WrapperExe"
    Write-Host "    config:     $(Join-Path $DistDir $DistConfigRel)"
    Write-Host "    logs:       $LogDir"
    if (Test-Path $LogDir) {
        Get-ChildItem $LogDir -File -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 5 |
            ForEach-Object { Write-Host ("    log file:   {0} ({1:u})" -f $_.Name, $_.LastWriteTimeUtc) }
    }
}

switch ($Action) {
    "stage"     { Remove-LegacyRootInstall; Publish-DistPayload }
    "install"   { Install-InternetService }
    "uninstall" { Uninstall-InternetService }
    "start"     { Start-InternetService }
    "stop"      { Stop-InternetService }
    "restart"   { Restart-InternetService }
    "status"    { Show-Status }
}
