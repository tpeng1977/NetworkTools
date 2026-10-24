# Resume-friendly download of Android google_apis x86_64 system image (API 34).
# Safe to re-run: uses curl -C - until size matches Content-Length and zip opens.

param(
  [string]$Url = "https://dl.google.com/android/repository/sys-img/google_apis/x86_64-34_r14.zip",
  [string]$OutZip = "$env:TEMP\x86_64-34_r14.zip",
  [string]$SdkRoot = "$env:LOCALAPPDATA\Android\Sdk"
)

$ErrorActionPreference = "Stop"

function Get-RemoteLength([string]$u) {
  $hdr = curl.exe -sI -L $u
  $line = $hdr | Select-String -Pattern "(?i)^content-length:\s*(\d+)" | Select-Object -Last 1
  if (-not $line) { return 0 }
  return [int64]$line.Matches[0].Groups[1].Value
}

function Test-ZipOk([string]$path) {
  Add-Type -AssemblyName System.IO.Compression.FileSystem
  try {
    $z = [System.IO.Compression.ZipFile]::OpenRead($path)
    $n = $z.Entries.Count
    $z.Dispose()
    return $n -gt 0
  } catch {
    return $false
  }
}

$expect = Get-RemoteLength $Url
if ($expect -le 0) {
  Write-Host "[!] cannot read Content-Length; will still resume blindly"
  $expect = 1563721130
}

Write-Host "[*] url=$Url"
Write-Host "[*] out=$OutZip"
Write-Host "[*] expect=$expect bytes ($([math]::Round($expect/1MB,1)) MB)"

function Stop-StaleCurlWriters([string]$path) {
  # curl exit 23 = write error (often another curl still locking the same -o file)
  $leaf = Split-Path $path -Leaf
  Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object {
      $_.Name -match '^curl(\.exe)?$' -and
      $_.CommandLine -and
      $_.CommandLine -like "*$leaf*"
    } |
    ForEach-Object {
      Write-Host "[!] killing stale curl pid=$($_.ProcessId)"
      Stop-Process -Id $_.ProcessId -Force -ErrorAction SilentlyContinue
    }
  Start-Sleep -Milliseconds 500
}

$attempt = 0
while ($true) {
  $attempt++
  Stop-StaleCurlWriters $OutZip
  $have = if (Test-Path $OutZip) { (Get-Item $OutZip).Length } else { 0 }
  Write-Host "[*] attempt=$attempt have=$have ($([math]::Round(100.0*$have/[math]::Max($expect,1),1))%)"

  if ($have -eq $expect -and (Test-ZipOk $OutZip)) {
    Write-Host "[+] download complete + ZIP_OK"
    break
  }
  if ($have -gt $expect) {
    Write-Host "[!] local file larger than remote; deleting and restarting"
    Remove-Item -Force $OutZip
    $have = 0
  }

  # -C - resumes from local size; --retry* for flaky links. Avoid -f (CDN quirks).
  # --max-time 0 = no overall timeout (unstable net may stall then recover).
  curl.exe -L --retry 30 --retry-delay 3 --retry-all-errors `
    -C - --connect-timeout 30 --max-time 0 `
    --speed-time 60 --speed-limit 1024 `
    -o $OutZip $Url
  $code = $LASTEXITCODE
  Write-Host "[*] curl_exit=$code"

  if ($code -eq 23) {
    Write-Host "[!] write error (file lock?); clear stale curl and resume"
    Stop-StaleCurlWriters $OutZip
  }

  $have = if (Test-Path $OutZip) { (Get-Item $OutZip).Length } else { 0 }
  if ($have -eq $expect) {
    if (Test-ZipOk $OutZip) {
      Write-Host "[+] ZIP_OK"
      break
    }
    Write-Host "[!] size ok but zip corrupt; deleting and restarting"
    Remove-Item -Force $OutZip
  }

  $backoff = [Math]::Min(5 + $attempt, 30)
  Write-Host "[*] incomplete; sleeping ${backoff}s then resume (-C -)..."
  Start-Sleep -Seconds $backoff
}

# Install into SDK tree
$dest = Join-Path $SdkRoot "system-images\android-34\google_apis\x86_64"
Write-Host "[*] extracting -> $dest"
New-Item -ItemType Directory -Force -Path $dest | Out-Null
# Clear incomplete installer leftovers
Get-ChildItem $dest -Force | Where-Object { $_.Name -ne "." } | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

# Prefer tar: .NET ZipFile.ExtractToDirectory is picky with resumed downloads.
$tmp = Join-Path (Split-Path $dest -Parent) "_extract"
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $tmp | Out-Null
tar -xf $OutZip -C $tmp
if ($LASTEXITCODE -ne 0) { throw "tar extract failed" }
if (Test-Path (Join-Path $tmp "x86_64")) {
  Move-Item -Force (Join-Path $tmp "x86_64\*") $dest
} else {
  Move-Item -Force (Join-Path $tmp "*") $dest
}
Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue

if (-not (Test-Path (Join-Path $dest "system.img")) -and -not (Test-Path (Join-Path $dest "system" ))) {
  Write-Host "[!] extract layout unexpected:"
  Get-ChildItem $dest | Select-Object Name
  exit 1
}

# Accept licenses quietly for avdmanager
$sm = Join-Path $SdkRoot "cmdline-tools\latest\bin\sdkmanager.bat"
if (Test-Path $sm) {
  Write-Host "[*] accepting licenses"
  1..20 | ForEach-Object { "y" } | & $sm --licenses 2>$null | Out-Null
}

$avd = Join-Path $SdkRoot "cmdline-tools\latest\bin\avdmanager.bat"
$emuName = "Vortex_API34"
Write-Host "[*] creating AVD $emuName"
echo no | & $avd create avd -n $emuName -k "system-images;android-34;google_apis;x86_64" -d "pixel_6" --force
if ($LASTEXITCODE -ne 0) {
  # device id optional
  echo no | & $avd create avd -n $emuName -k "system-images;android-34;google_apis;x86_64" --force
}

Write-Host "[+] done. Start with:"
Write-Host "  `"$SdkRoot\emulator\emulator.exe`" -avd $emuName -netdelay none -netspeed full"
exit 0
