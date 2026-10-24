# Resumable download of Android emulator system image (unstable networks).
# Prefers aria2c (-c multi-connection resume); falls back to curl -C -.
param(
  [string]$Api = "34",
  [string]$Tag = "google_apis",
  [string]$Abi = "x86_64",
  [string]$Rev = "14",
  [string]$OutDir = ""
)

$ErrorActionPreference = "Stop"
$sdk = if ($env:ANDROID_HOME) { $env:ANDROID_HOME } else { Join-Path $env:LOCALAPPDATA "Android\Sdk" }
if (-not $OutDir) { $OutDir = Join-Path $sdk "system-images\android-$Api\$Tag\$Abi" }

$zipName = "${Abi}-${Api}_r${Rev}.zip"
$url = "https://dl.google.com/android/repository/sys-img/$Tag/$zipName"
$work = Join-Path $env:TEMP "vortex-avd-dl"
New-Item -ItemType Directory -Force -Path $work | Out-Null
$zip = Join-Path $work $zipName

Write-Host "[*] URL  $url"
Write-Host "[*] ZIP  $zip"
Write-Host "[*] DEST $OutDir"

function Get-Aria2 {
  $c = Get-Command aria2c -ErrorAction SilentlyContinue
  if ($c) { return $c.Source }
  $wingetAria = @(
    "$env:LOCALAPPDATA\Microsoft\WinGet\Links\aria2c.exe",
    "$env:ProgramFiles\aria2\aria2c.exe",
    "$env:LOCALAPPDATA\Programs\aria2\aria2c.exe"
  ) | Where-Object { Test-Path $_ } | Select-Object -First 1
  return $wingetAria
}

$aria = Get-Aria2
if (-not $aria) {
  Write-Host "[*] aria2c not found — installing via winget (aria2.aria2)..."
  winget install -e --id aria2.aria2 --accept-package-agreements --accept-source-agreements
  $env:Path = [System.Environment]::GetEnvironmentVariable("Path", "Machine") + ";" +
              [System.Environment]::GetEnvironmentVariable("Path", "User")
  $aria = Get-Aria2
}

if ($aria) {
  Write-Host "[*] Using aria2c (断点续传 + 多连接): $aria"
  # -c continue, -x connections, -s splits, -k min split, --max-tries=0 infinite, --retry-wait
  & $aria -c -x 8 -s 8 -k 1M --file-allocation=none `
    --max-tries=0 --retry-wait=3 --timeout=60 --connect-timeout=30 `
    --auto-file-renaming=false --allow-overwrite=true `
    -d $work -o $zipName $url
  if ($LASTEXITCODE -ne 0) { throw "aria2c failed exit=$LASTEXITCODE" }
} else {
  Write-Host "[*] aria2 unavailable — curl -C - resume loop"
  $ok = $false
  for ($i = 1; $i -le 50; $i++) {
    Write-Host "[*] curl attempt $i ..."
    & curl.exe -L --retry 20 --retry-delay 3 --retry-all-errors -C - --connect-timeout 30 -o $zip $url
    if ($LASTEXITCODE -eq 0 -and (Test-Path $zip)) { $ok = $true; break }
    Start-Sleep -Seconds 5
  }
  if (-not $ok) { throw "curl resume failed after retries" }
}

Write-Host "[*] Size $((Get-Item $zip).Length) bytes — verifying zip..."
Add-Type -AssemblyName System.IO.Compression.FileSystem
$z = [System.IO.Compression.ZipFile]::OpenRead($zip)
$n = $z.Entries.Count
$z.Dispose()
if ($n -lt 5) { throw "zip looks incomplete (entries=$n)" }
Write-Host "[+] ZIP OK entries=$n"

# Install into SDK layout
if (Test-Path $OutDir) {
  Remove-Item -Recurse -Force $OutDir
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Write-Host "[*] Extracting to $OutDir ..."
[System.IO.Compression.ZipFile]::ExtractToDirectory($zip, $OutDir)

# Some zips nest one extra folder — flatten if needed
$children = Get-ChildItem $OutDir
if ($children.Count -eq 1 -and $children[0].PSIsContainer) {
  $inner = $children[0].FullName
  Get-ChildItem $inner | Move-Item -Destination $OutDir -Force
  Remove-Item $inner -Recurse -Force
}

# Minimal source.properties so avdmanager accepts the image
$sp = Join-Path $OutDir "source.properties"
@"
AndroidVersion.ApiLevel=$Api
Pkg.Revision=$Rev
SystemImage.TagId=$Tag
SystemImage.Abi=$Abi
"@ | Set-Content -Path $sp -Encoding ASCII

Write-Host "[+] Installed system image:"
Get-ChildItem $OutDir | Select-Object Name, Length | Format-Table -AutoSize
Write-Host ""
Write-Host "Next:"
Write-Host "  avdmanager create avd -n VortexApi34 -k `"system-images;android-$Api;$Tag;$Abi`" -d pixel_6 --force"
Write-Host "  emulator -avd VortexApi34 -netdelay none -netspeed full"
