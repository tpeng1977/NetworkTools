# Start or stop the Windows mobile hotspot only (system ICS / NAT).
# Hardens the SoftAP radio for router-like stability (especially USB Wi-Fi dongles).
# Config: config/hotspot.json
# Requires Administrator.
param(
    [switch]$Stop,
    [switch]$Watch,
    [switch]$NoWatch
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
    if ($Watch) { $arg += " -Watch" }
    if ($NoWatch) { $arg += " -NoWatch" }
    Start-Process -FilePath "powershell.exe" -Verb RunAs -ArgumentList $arg -WorkingDirectory $Root | Out-Null
    exit 0
}

Add-Type -AssemblyName System.Runtime.WindowsRuntime | Out-Null
$null = [Windows.Networking.Connectivity.NetworkInformation, Windows.Networking.Connectivity, ContentType = WindowsRuntime]
$null = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager, Windows.Networking.NetworkOperators, ContentType = WindowsRuntime]
$null = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringSessionAccessPointConfiguration, Windows.Networking.NetworkOperators, ContentType = WindowsRuntime]
$null = [Windows.Networking.NetworkOperators.TetheringWiFiPerformancePriority, Windows.Networking.NetworkOperators, ContentType = WindowsRuntime]

$script:AsOp = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
    $_.Name -eq "AsTask" -and $_.IsGenericMethod -and $_.GetParameters().Count -eq 1 -and
    $_.GetParameters()[0].ParameterType.Name -eq "IAsyncOperation``1"
} | Select-Object -First 1)

$script:AsAction = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {
    $_.Name -eq "AsTask" -and -not $_.IsGenericMethod -and $_.GetParameters().Count -eq 1 -and
    $_.GetParameters()[0].ParameterType.Name -eq "IAsyncAction"
} | Select-Object -First 1)

function Get-TaskErrorText($ErrorRecord) {
    $ex = $ErrorRecord.Exception
    if ($ex -is [System.AggregateException] -and $ex.InnerExceptions.Count -gt 0) {
        return ($ex.InnerExceptions | ForEach-Object { $_.Message }) -join "; "
    }
    if ($ex.InnerException) { return $ex.InnerException.Message }
    return $ex.Message
}

function Wait-WinRtOp($AsyncOp, [Type]$ResultType) {
    $task = $script:AsOp.MakeGenericMethod($ResultType).Invoke($null, @($AsyncOp))
    try {
        $task.Wait() | Out-Null
        return $task.Result
    } catch {
        Write-Host "[!] tethering op: $(Get-TaskErrorText $_)"
        return $null
    }
}

function Wait-WinRtAction($AsyncAction) {
    $task = $script:AsAction.Invoke($null, @($AsyncAction))
    try {
        $task.Wait() | Out-Null
        return $true
    } catch {
        Write-Host "[!] tethering config: $(Get-TaskErrorText $_)"
        return $false
    }
}

function Get-EnumCode($value) {
    if ($null -eq $value) { return $null }
    try { return [int]$value } catch {}
    try { return [int]$value.value__ } catch {}
    return $null
}

function Get-TetherState([object]$Manager) {
    $code = Get-EnumCode $Manager.TetheringOperationalState
    switch ($code) {
        0 { return "Unknown" }
        1 { return "On" }
        2 { return "Off" }
        3 { return "InTransition" }
        default { return "Unknown($code)" }
    }
}

function Format-TetherResult($value) {
    $code = Get-EnumCode $value
    $names = @{
        0 = "Success"; 1 = "Unknown"; 2 = "MobileBroadbandDeviceOff"
        3 = "WiFiDeviceOff"; 4 = "EntitlementCheckTimeout"; 5 = "EntitlementCheckFailure"
        6 = "OperationInProgress"; 7 = "BluetoothDeviceOff"; 8 = "NetworkLimitedConnectivity"
        9 = "AlreadyOn"; 10 = "RadioRestriction"; 11 = "BandInterference"
    }
    if ($null -eq $code) { return "unparsed" }
    if ($names.ContainsKey($code)) { return "$($names[$code]) ($code)" }
    return "code=$code"
}

function Wait-TetherSettled([object]$Manager, [int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        $state = Get-TetherState $Manager
        if ($state -eq "On" -or $state -eq "Off") { return $state }
        Start-Sleep -Milliseconds 300
    }
    return Get-TetherState $Manager
}

function Get-UpstreamWifiProfile {
    $profiles = @([Windows.Networking.Connectivity.NetworkInformation]::GetConnectionProfiles())
    $wifi = @($profiles | Where-Object {
        $_.NetworkAdapter -and
        [int]$_.NetworkAdapter.IanaInterfaceType -eq 71 -and
        [string]$_.GetNetworkConnectivityLevel() -eq "InternetAccess"
    })
    if ($wifi.Count -gt 0) { return $wifi[0] }
    $inet = [Windows.Networking.Connectivity.NetworkInformation]::GetInternetConnectionProfile()
    if ($inet -and $inet.NetworkAdapter -and [int]$inet.NetworkAdapter.IanaInterfaceType -eq 71) {
        return $inet
    }
    return $inet
}

function Get-TetherManager {
    $profile = Get-UpstreamWifiProfile
    if (-not $profile) {
        throw "No Wi-Fi internet profile. Connect WLAN first (not only a VPN/TUN)."
    }
    $iana = [int]$profile.NetworkAdapter.IanaInterfaceType
    Write-Host "[*] upstream profile=$($profile.ProfileName) iana=$iana"
    if ($iana -eq 53) {
        Write-Host "[!] upstream looks like a VPN/TUN adapter; Mobile Hotspot ICS often fails"
    }
    return [Windows.Networking.NetworkOperators.NetworkOperatorTetheringManager]::CreateFromConnectionProfile($profile)
}

function Disable-PeerlessTimeout {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\icssvc\Settings"
    if (-not (Test-Path $key)) { New-Item -Path $key -Force | Out-Null }
    New-ItemProperty -Path $key -Name PeerlessTimeoutEnabled -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -Path $key -Name PeerlessTimeout -PropertyType DWord -Value 120 -Force | Out-Null
    Write-Host "[*] PeerlessTimeoutEnabled=0 (idle auto-off disabled)"
}

function Ensure-IcsServices {
    foreach ($name in @("SharedAccess", "icssvc", "WlanSvc")) {
        $svc = Get-Service -Name $name -ErrorAction SilentlyContinue
        if (-not $svc) { continue }
        if ($svc.StartType -eq "Disabled") {
            Set-Service -Name $name -StartupType Manual -ErrorAction SilentlyContinue
        }
        if ($svc.Status -ne "Running") {
            Start-Service $name -ErrorAction SilentlyContinue
            Write-Host "[*] started service $name"
        }
    }
}

function Disable-AllClassicIcs {
    try {
        regsvr32.exe /s hnetcfg.dll | Out-Null
        $ns = New-Object -ComObject HNetCfg.HNetShare
        foreach ($c in @($ns.EnumEveryConnection)) {
            if ($null -eq $c) { continue }
            try {
                $cfg = $ns.INetSharingConfigurationForINetConnection($c)
                if (-not $cfg -or -not $cfg.SharingEnabled) { continue }
                $name = try { $ns.NetConnectionProps($c).Name } catch { "?" }
                $cfg.DisableSharing()
                Write-Host "[*] disabled classic ICS on $name"
            } catch {}
        }
    } catch {
        Write-Host "[!] classic ICS cleanup: $($_.Exception.Message)"
    }
}

function Deprioritize-VpnRoutes {
    $suspect = @(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object {
        $_.ConnectionState -eq "Connected" -and (
            $_.InterfaceAlias -match '^(Meta|Clash|TUN|Wintun|tap|VPN)' -or
            (Get-NetAdapter -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue).InterfaceDescription -match 'Wintun|Meta|Clash|TAP-Windows|WireGuard'
        )
    })
    foreach ($ifc in $suspect) {
        try {
            if ([int]$ifc.InterfaceMetric -lt 4000) {
                Set-NetIPInterface -InterfaceIndex $ifc.ifIndex -InterfaceMetric 5000 -ErrorAction Stop
                Write-Host "[*] raised metric on $($ifc.InterfaceAlias)"
            }
        } catch {
            Write-Host "[!] could not deprioritize $($ifc.InterfaceAlias): $($_.Exception.Message)"
        }
    }
}

function Invoke-PowerCfg([string[]]$Args) {
    # powercfg writes localized errors to stderr; never let that abort the script.
    $prev = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $out = & powercfg.exe @Args 2>&1
        $code = $LASTEXITCODE
        return @{ Ok = ($code -eq 0); Text = ($out | Out-String); Code = $code }
    } catch {
        return @{ Ok = $false; Text = $_.Exception.Message; Code = -1 }
    } finally {
        $ErrorActionPreference = $prev
    }
}

function Set-PowerPlanForSoftAp {
    $usbSub = "2a737441-1930-4402-8d77-b2bebba308a3"
    # GUID differs across Windows builds; discover from the current scheme.
    $usbSs = $null
    $q = Invoke-PowerCfg @("/q", "SCHEME_CURRENT", $usbSub)
    if ($q.Ok) {
        # e.g. "电源设置 GUID: 48e6b7a6-...  (USB 选择性暂停设置)"
        if ($q.Text -match "(?im)(?:电源设置 GUID|Power Setting GUID):\s*([0-9a-f\-]+)\s+\([^)]*(?:USB 选择性暂停|USB selective suspend)") {
            $usbSs = $Matches[1]
        }
    }
    if (-not $usbSs) {
        # Common GUIDs (Win10 / Win11 variants)
        foreach ($cand in @(
            "48e6b7a6-50f5-4782-a5d4-53bb8f07e226",
            "48e0ffb8-8c27-4b64-8dfb-75e3a6ead524"
        )) {
            $t = Invoke-PowerCfg @("/q", "SCHEME_CURRENT", $usbSub, $cand)
            if ($t.Ok) { $usbSs = $cand; break }
        }
    }

    $did = @()
    if ($usbSs) {
        foreach ($setter in @("/SETACVALUEINDEX", "/SETDCVALUEINDEX")) {
            $r = Invoke-PowerCfg @($setter, "SCHEME_CURRENT", $usbSub, $usbSs, "0")
            if (-not $r.Ok) { Write-Host "[!] powercfg USB suspend: $($r.Text.Trim())" }
        }
        $did += "USB selective suspend=off"
    } else {
        Write-Host "[!] USB selective suspend setting not found in power plan (skipped)"
    }

    # Wireless adapter subgroup is missing on many desktops — skip quietly if absent.
    $wlanSub = "19cbb8fa-5279-450d-91b8-2d07072b8777"
    $wlanPs = "12bbebe6-58d6-4636-95bb-3217ef867c1a"
    $wq = Invoke-PowerCfg @("/q", "SCHEME_CURRENT", $wlanSub, $wlanPs)
    if ($wq.Ok) {
        foreach ($setter in @("/SETACVALUEINDEX", "/SETDCVALUEINDEX")) {
            Invoke-PowerCfg @($setter, "SCHEME_CURRENT", $wlanSub, $wlanPs, "0") | Out-Null
        }
        $did += "Wi-Fi=max performance"
    }

    Invoke-PowerCfg @("/SETACTIVE", "SCHEME_CURRENT") | Out-Null
    if ($did.Count -gt 0) {
        Write-Host "[*] power plan: $($did -join ', ')"
    }
}

function Disable-DevicePowerSaving([string]$InstanceId, [string]$Label) {
    if (-not $InstanceId) { return }
    # PnPCapabilities 24 (0x18): do not allow Windows to power off the device.
    $enumKey = "HKLM:\SYSTEM\CurrentControlSet\Enum\$InstanceId"
    try {
        if (Test-Path $enumKey) {
            New-ItemProperty -Path $enumKey -Name PnPCapabilities -PropertyType DWord -Value 24 -Force | Out-Null
        }
    } catch {}
    $paramKey = Join-Path $enumKey "Device Parameters"
    try {
        if (Test-Path $paramKey) {
            New-ItemProperty -Path $paramKey -Name EnhancedPowerManagementEnabled -PropertyType DWord -Value 0 -Force | Out-Null
            New-ItemProperty -Path $paramKey -Name AllowIdleIrpInD3 -PropertyType DWord -Value 0 -Force | Out-Null
            New-ItemProperty -Path $paramKey -Name DeviceSelectiveSuspended -PropertyType DWord -Value 0 -Force | Out-Null
        }
    } catch {}

    $patterns = @([regex]::Escape($InstanceId))
    if ($InstanceId -match 'VID_([0-9A-F]+)&PID_([0-9A-F]+)') {
        $patterns += ("VID_{0}&PID_{1}" -f $Matches[1], $Matches[2])
    }
    try {
        $disabled = $false
        Get-CimInstance -Namespace root\wmi -ClassName MSPower_DeviceEnable -ErrorAction SilentlyContinue | ForEach-Object {
            $name = [string]$_.InstanceName
            foreach ($pat in $patterns) {
                if ($name -match $pat -and $_.Enable) {
                    $_.Enable = $false
                    Set-CimInstance -CimInstance $_ -ErrorAction SilentlyContinue
                    $disabled = $true
                }
            }
        }
        if ($disabled) { Write-Host "[*] disabled OS power-off on $Label" }
    } catch {}
}

function Get-SoftApPhysicalAdapter([string]$PreferName) {
    $adapters = @(Get-NetAdapter -ErrorAction SilentlyContinue)
    if ($PreferName -and $PreferName -ne "auto") {
        $hit = $adapters | Where-Object { $_.Name -eq $PreferName } | Select-Object -First 1
        if ($hit) { return $hit }
    }
    # SoftAP virtual MAC shares the OUI prefix with the physical radio.
    $virtuals = @($adapters | Where-Object {
        $_.Status -eq "Up" -and $_.InterfaceDescription -match "Wi-Fi Direct Virtual|Microsoft Hosted Network"
    })
    foreach ($v in $virtuals) {
        $vm = ($v.MacAddress -replace "[-:]", "")
        if ($vm.Length -lt 10) { continue }
        $prefix = $vm.Substring(0, 10)
        foreach ($p in $adapters) {
            if ($p.InterfaceDescription -match "Virtual|Bluetooth|WAN Miniport|Wi-Fi Direct") { continue }
            $pm = ($p.MacAddress -replace "[-:]", "")
            if ($pm.Length -ge 10 -and $pm.Substring(0, 10) -eq $prefix) { return $p }
        }
    }
    # Prefer a disconnected USB Wi-Fi that supports SoftAP (common second dongle).
    $usb = @($adapters | Where-Object {
        $_.InterfaceDescription -match "802\.11|Wireless|Wi-?Fi" -and
        $_.InterfaceDescription -notmatch "Virtual|Bluetooth" -and
        $_.Status -ne "Up"
    })
    if ($usb.Count -eq 1) { return $usb[0] }
    return $null
}

function Set-AdapterProp([string]$Name, [string]$Keyword, [string]$Value, [string]$Label) {
    $prop = Get-NetAdapterAdvancedProperty -Name $Name -RegistryKeyword $Keyword -ErrorAction SilentlyContinue
    if (-not $prop) { return $false }
    $cur = [string]@($prop.RegistryValue)[0]
    if ($cur -eq $Value) { return $false }
    Set-NetAdapterAdvancedProperty -Name $Name -RegistryKeyword $Keyword -RegistryValue $Value -NoRestart -ErrorAction Stop
    Write-Host "[*] $Name $Label ($cur -> $Value)"
    return $true
}

function Harden-SoftApRadio([string]$PreferName) {
    $nic = Get-SoftApPhysicalAdapter $PreferName
    if (-not $nic) {
        Write-Host "[!] SoftAP physical radio not found; applying global power harden only"
        Set-PowerPlanForSoftAp
        return $null
    }
    Write-Host "[*] SoftAP radio: $($nic.Name) ($($nic.InterfaceDescription))"

    Set-PowerPlanForSoftAp

    # Kill the #1 cause of "SSID sometimes invisible" on USB SoftAP: selective suspend.
    $changed = $false
    try { if (Set-AdapterProp $nic.Name "*SelectiveSuspend" "0" "USB selective suspend disabled") { $changed = $true } } catch {
        Write-Host "[!] selective suspend: $($_.Exception.Message)"
    }
    try { Set-AdapterProp $nic.Name "*SSIdleTimeout" "60" "suspend idle timeout raised" | Out-Null } catch {}

    # Lock SoftAP radio to 2.4 GHz only — dual-band hopping makes beacons vanish.
    try { if (Set-AdapterProp $nic.Name "ChannelMode" "0" "channel mode = 2.4 GHz only") { $changed = $true } } catch {
        Write-Host "[!] channel mode: $($_.Exception.Message)"
    }
    try { if (Set-AdapterProp $nic.Name "PreferABand" "0" "prefer 5G disabled") { $changed = $true } } catch {}
    try { Set-AdapterProp $nic.Name "SmartScan" "0" "smart scan disabled" | Out-Null } catch {}
    try { Set-AdapterProp $nic.Name "FixAPBW20" "1" "AP BW20 forced" | Out-Null } catch {}

    try {
        Disable-NetAdapterPowerManagement -Name $nic.Name -SelectiveSuspend -DeviceSleepOnDisconnect `
            -NoRestart -ErrorAction SilentlyContinue | Out-Null
    } catch {}

    $pnp = Get-PnpDevice -InstanceId $nic.PnPDeviceID -ErrorAction SilentlyContinue
    if (-not $pnp) {
        $pnp = Get-PnpDevice | Where-Object { $_.FriendlyName -eq $nic.InterfaceDescription } | Select-Object -First 1
    }
    if ($pnp) { Disable-DevicePowerSaving $pnp.InstanceId $nic.Name }

    # Also harden every Wi-Fi Direct virtual adapter (the one that actually beacons).
    Get-PnpDevice -Class Net -ErrorAction SilentlyContinue |
        Where-Object { $_.FriendlyName -match "Wi-Fi Direct Virtual|Hosted Network" -and $_.Status -eq "OK" } |
        ForEach-Object { Disable-DevicePowerSaving $_.InstanceId $_.FriendlyName }

    # USB MediaTek needs a one-shot reset for SelectiveSuspend/ChannelMode to stick.
    # Only bounce when SoftAP is currently Off so we don't kick connected phones.
    $tetherOff = $true
    try {
        if ($script:mgr) { $tetherOff = ((Get-TetherState $script:mgr) -eq "Off") }
    } catch {}
    if ($changed -and ($script:bounceRadio -or $tetherOff)) {
        Write-Host "[*] restarting $($nic.Name) once so SoftAP settings take effect"
        Disable-NetAdapter -Name $nic.Name -Confirm:$false -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
        Enable-NetAdapter -Name $nic.Name -Confirm:$false -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 4
    } elseif ($changed) {
        Write-Host "[*] SoftAP settings queued (hotspot already on). Stop/start once if SSID still blinks."
    }
    return $nic
}

function Stop-Hotspot {
    $mgr = Get-TetherManager
    $state = Get-TetherState $mgr
    if ($state -eq "Off") {
        Write-Host "[*] hotspot already off"
        return
    }
    $resultType = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult]
    $result = Wait-WinRtOp ($mgr.StopTetheringAsync()) $resultType
    Write-Host "[*] hotspot stop: $(Format-TetherResult $result) state=$(Get-TetherState $mgr)"
}

if ($Stop) {
    Stop-Hotspot
    Write-Host "[*] stopped"
    exit 0
}

$hotPath = Join-Path $Root "config\hotspot.json"
if (-not (Test-Path $hotPath)) { throw "Missing $hotPath" }
$hot = Get-Content -Raw -Path $hotPath | ConvertFrom-Json

$ssid = [string]$hot.ssid
$password = [string]$hot.password
$apGateway = if ($hot.ap_gateway) { [string]$hot.ap_gateway } else { "192.168.137.1" }
$bandPref = if ($hot.band) { [string]$hot.band } else { "2.4" }
$prefer5 = if ($null -ne $hot.prefer_5ghz) { [bool]$hot.prefer_5ghz } else { $false }
$script:bounceRadio = if ($null -ne $hot.bounce_radio) { [bool]$hot.bounce_radio } else { $false }
$deprioritizeVpn = if ($null -ne $hot.deprioritize_vpn) { [bool]$hot.deprioritize_vpn } else { $true }
$apRadio = if ($hot.ap_radio) { [string]$hot.ap_radio } else { "auto" }
$doWatch = -not $NoWatch -and ($Watch -or ($null -eq $hot.watch) -or [bool]$hot.watch)

if ($ssid.Length -lt 1 -or $ssid.Length -gt 32) { throw "SSID length must be 1..32" }
if ($password.Length -lt 8 -or $password.Length -gt 63) { throw "Hotspot password length must be 8..63" }

function Wait-HotspotAddress([string]$Gateway, [int]$Seconds) {
    $deadline = (Get-Date).AddSeconds($Seconds)
    while ((Get-Date) -lt $deadline) {
        $addrs = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
            Where-Object { $_.IPAddress -notlike "127.*" -and $_.IPAddress -notlike "169.254.*" })
        $hit = $null
        if ($Gateway) {
            $hit = $addrs | Where-Object { $_.IPAddress -eq $Gateway } | Select-Object -First 1
        }
        if (-not $hit) {
            $hit = $addrs | Where-Object { $_.IPAddress -eq "192.168.137.1" } | Select-Object -First 1
        }
        if ($hit) { return $hit }
        Start-Sleep -Milliseconds 400
    }
    return $null
}

Disable-PeerlessTimeout
Ensure-IcsServices
Disable-AllClassicIcs
if ($deprioritizeVpn) { Deprioritize-VpnRoutes }

$mgr = Get-TetherManager
$resultType = [Windows.Networking.NetworkOperators.NetworkOperatorTetheringOperationResult]
$bandEnum = [Windows.Networking.NetworkOperators.TetheringWiFiBand]
$prioEnum = [Windows.Networking.NetworkOperators.TetheringWiFiPerformancePriority]

function Resolve-BandList {
    # Never run "netsh wlan show networks" — scans interrupt SoftAP beacons.
    $list = New-Object System.Collections.Generic.List[string]
    $pref = $bandPref.ToLowerInvariant()
    switch -Regex ($pref) {
        '^(2\.?4|2,4|24|two)' {
            $list.Add("TwoPointFourGigahertz")
            $list.Add("Auto")
        }
        '^(5|5g|5ghz|five)' {
            $list.Add("FiveGigahertz")
            $list.Add("TwoPointFourGigahertz")
            $list.Add("Auto")
        }
        '^(auto|any)$' {
            if ($prefer5) {
                $list.Add("FiveGigahertz")
                $list.Add("TwoPointFourGigahertz")
                $list.Add("Auto")
            } else {
                $list.Add("TwoPointFourGigahertz")
                $list.Add("Auto")
            }
        }
        default {
            $list.Add("TwoPointFourGigahertz")
            $list.Add("Auto")
        }
    }
    return @($list | Select-Object -Unique)
}

function Band-Label([string]$BandName) {
    switch ($BandName) {
        "SixGigahertz" { return "6 GHz" }
        "FiveGigahertz" { return "5 GHz" }
        "TwoPointFourGigahertz" { return "2.4 GHz" }
        "Auto" { return "Auto" }
        default { return $BandName }
    }
}

function Set-HotspotConfig([string]$BandName) {
    $cfg = $mgr.GetCurrentAccessPointConfiguration()
    $cfg.Ssid = $ssid
    $cfg.Passphrase = $password
    $cfg.Band = [Enum]::Parse($bandEnum, $BandName)
    return Wait-WinRtAction ($mgr.ConfigureAccessPointAsync($cfg))
}

function Start-HotspotRadio([string]$BandName) {
    $session = New-Object Windows.Networking.NetworkOperators.NetworkOperatorTetheringSessionAccessPointConfiguration
    $session.Ssid = $ssid
    $session.Passphrase = $password
    $session.Band = [Enum]::Parse($bandEnum, $BandName)
    $session.PerformancePriority = [Enum]::Parse($prioEnum, "Default")
    $startResult = Wait-WinRtOp ($mgr.StartTetheringAsync($session)) $resultType
    if ($null -ne $startResult) {
        Write-Host "[*] hotspot start: $(Format-TetherResult $startResult)"
    }
    $now = Wait-TetherSettled $mgr 25
    Write-Host "[*] hotspot state: $now"
    return ($now -eq "On")
}

function Stop-HotspotRadio {
    if ((Get-TetherState $mgr) -eq "Off") { return }
    $stopResult = Wait-WinRtOp ($mgr.StopTetheringAsync()) $resultType
    if ($null -ne $stopResult) { Write-Host "[*] hotspot stop: $(Format-TetherResult $stopResult)" }
    Wait-TetherSettled $mgr 20 | Out-Null
}

function Get-ConfiguredBandLabel {
    try {
        $cfg = $mgr.GetCurrentAccessPointConfiguration()
        return (Band-Label ([string]$cfg.Band))
    } catch {
        return "unknown"
    }
}

function Start-OnlyHotspot {
    $script:mgr = Get-TetherManager
    $preferBands = Resolve-BandList

    $state = Get-TetherState $mgr
    if ($state -eq "InTransition") { $state = Wait-TetherSettled $mgr 15 }

    if ($state -eq "On") {
        $hit = Wait-HotspotAddress $apGateway 3
        if ($hit) {
            $script:bandLabel = Get-ConfiguredBandLabel
            Write-Host "[*] hotspot already on ($bandLabel); leaving it running"
            return $true
        }
        Write-Host "[!] hotspot On but no $apGateway — restarting"
        Stop-HotspotRadio
    }

    $started = $false
    foreach ($want in $preferBands) {
        $label = Band-Label $want
        if (-not (Set-HotspotConfig $want)) {
            Write-Host "[!] could not set hotspot band to $label"
        }
        Write-Host "[*] hotspot SSID=$ssid requested band=$label"
        if (Start-HotspotRadio $want) {
            $addr = Wait-HotspotAddress $apGateway 12
            if ($addr) {
                $script:bandLabel = $label
                $started = $true
                break
            }
            Write-Host "[!] $label came On but gateway $apGateway never appeared"
        } else {
            Write-Host "[!] $label did not stay on"
        }
        Stop-HotspotRadio
    }

    if (-not $started) { throw "Mobile hotspot failed to start" }
    Write-Host "[*] hotspot on air: $bandLabel"
    return $true
}

try {
    $script:mgr = Get-TetherManager

    # If USB SoftAP still has selective suspend / dual-band hopping, cycle once so
    # driver settings actually stick. Leaving an already-On hotspot alone while the
    # dongle sleeps is why the SSID keeps blinking.
    $radio = Get-SoftApPhysicalAdapter $apRadio
    $needCycle = $false
    if ($radio) {
        $ss = Get-NetAdapterAdvancedProperty -Name $radio.Name -RegistryKeyword "*SelectiveSuspend" -ErrorAction SilentlyContinue
        $cm = Get-NetAdapterAdvancedProperty -Name $radio.Name -RegistryKeyword "ChannelMode" -ErrorAction SilentlyContinue
        if ($ss -and [string]@($ss.RegistryValue)[0] -ne "0") { $needCycle = $true }
        if ($cm -and [string]@($cm.RegistryValue)[0] -ne "0") { $needCycle = $true }
    }
    if ($needCycle -and ((Get-TetherState $mgr) -ne "Off")) {
        Write-Host "[*] cycling hotspot once to apply SoftAP stability settings"
        Stop-HotspotRadio
    }

    $null = Harden-SoftApRadio $apRadio
    Start-OnlyHotspot | Out-Null
    # Re-assert power flags after the SoftAP virtual adapter appears (no bounce).
    $null = Harden-SoftApRadio $apRadio

    $hit = Wait-HotspotAddress $apGateway 20
    if (-not $hit) {
        throw "Mobile hotspot adapter has no IPv4 (expected $apGateway)."
    }
    $adapter = $hit.InterfaceAlias
    $ip = $hit.IPAddress
    Write-Host "[*] $adapter address $ip"

    $fwd = @(Get-NetIPInterface -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.Forwarding -eq "Enabled" -and $_.ConnectionState -eq "Connected" })
    Write-Host "[*] IPv4 forwarding on: $(($fwd | ForEach-Object { $_.InterfaceAlias }) -join ', ')"

    Write-Host ""
    Write-Host "Ready. (system NAT / ICS, SoftAP hardened)"
    Write-Host "  Hotspot SSID : $ssid ($bandLabel)"
    Write-Host "  AP adapter   : $adapter $ip"
    Write-Host "  Config       : config\hotspot.json"
    Write-Host "Stop with:  only-ap.bat -Stop"
    if ($doWatch) {
        Write-Host "Watch mode  : ON (keep this window open)"
    } else {
        Write-Host "Keep-alive: only-ap.bat -Watch"
    }

    if ($doWatch) {
        Write-Host ""
        Write-Host "[*] watch: restart if Windows drops the hotspot (Ctrl+C to exit)"
        $tick = 0
        while ($true) {
            Start-Sleep -Seconds 10
            $tick++
            try {
                if ($deprioritizeVpn) { Deprioritize-VpnRoutes }
                # Re-assert power settings every ~2 min (Windows may reset them).
                if (($tick % 12) -eq 0) {
                    Set-PowerPlanForSoftAp
                    $nic = Get-SoftApPhysicalAdapter $apRadio
                    if ($nic) {
                        try { Set-AdapterProp $nic.Name "*SelectiveSuspend" "0" "USB selective suspend disabled" | Out-Null } catch {}
                    }
                }
                $mgr = Get-TetherManager
                $state = Get-TetherState $mgr
                if ($state -eq "InTransition") { $state = Wait-TetherSettled $mgr 10 }
                if ($state -ne "On") {
                    Write-Host "[!] hotspot state=$state — restarting $(Get-Date -Format HH:mm:ss)"
                    Ensure-IcsServices
                    Start-OnlyHotspot | Out-Null
                    $null = Harden-SoftApRadio $apRadio
                } elseif (-not (Wait-HotspotAddress $apGateway 2)) {
                    Write-Host "[!] gateway missing — restarting $(Get-Date -Format HH:mm:ss)"
                    Ensure-IcsServices
                    Stop-HotspotRadio
                    Start-OnlyHotspot | Out-Null
                    $null = Harden-SoftApRadio $apRadio
                }
            } catch {
                Write-Host "[!] watch: $($_.Exception.Message)"
            }
        }
    }
} catch {
    Write-Host "[-] $($_.Exception.Message)"
    if ([Environment]::UserInteractive) {
        Read-Host "Press Enter to close"
    }
    exit 1
}
