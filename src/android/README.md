# Vortex Internet (Android)

Android VPN client aligned with desktop `internet.exe` / `config/internet.json`:

- **VpnService TUN** — apps need no proxy settings (desktop WinDivert equivalent)
- **MultiLink Vortex** — same JSON links (`link1`/`link2`/`link3` + optional `peer_secret` / `VIA_PEER`)
- **Clash-style rules** — `DOMAIN` / `DOMAIN-SUFFIX` / `DOMAIN-KEYWORD` / `IP-CIDR` / `GEOIP` / `GEOSITE` / `MATCH`
- **Geo DB** — packs `config/geo/geoip-cn.txt` + `geosite-cn.txt` into `assets/geo/`
- **Redir-host DNS** — same as `internet.cpp` (`resolve_ipv4_fast` + `dns_bind_name`); stand-in only on collision/miss; Vortex DNS-over-TCP fallback
- **Learned TCP** — always `CONNECT(domain)` / DIRECT via rules (never CONNECT by IP); GEOIP no-resolve safe
- **Traffic split** — `protect` + disallow self; DNS/learned TCP on TUN; unknown TCP = protect passthrough (reinject substitute)
- **Close path** — upstream EOF → FIN (not RST); client FIN → half-close; idle / max_connections from JSON

## One-command APK

From the **repo root** (needs JDK 17+ and Android SDK / Android Studio):

```bat
build-android.bat
```

Output (gitignored):

```
dist\VortexInternetAndroid\vortex-internet.apk
```

Install:

```bat
adb install -r dist\VortexInternetAndroid\vortex-internet.apk
```

If present, the build copies into app assets:

- `config\internet.json` → `assets/internet.json`
- `config\multirules.yaml` → `assets/rules.yaml`
- `config\geo\geoip-cn.txt` / `geosite-cn.txt` → `assets/geo/`

## Source layout

```
src/android/          Gradle project (this directory)
  app/src/main/java/com/vortex/internet/
  app/src/main/assets/internet.json
  app/src/main/assets/rules.yaml
  app/src/main/assets/geo/geoip-cn.txt
  app/src/main/assets/geo/geosite-cn.txt
```

Edit repo `config\` then re-run `build-android.bat`.
