# Network Tools

Encrypted SOCKS5 tunnel (Vortex) with custom ARX stream cipher, random padding, and active-probe camouflage — plus rule-based front ends and a Windows SoftAP bridge.

Supports **Linux**, **Windows**, and **macOS**.

## Features

- No fixed magic numbers; per-session random salt
- Bidirectional independent key streams
- Random payload padding (anti length fingerprinting)
- Active-probe defense (non-auth traffic gets an HTTP 404 nginx-style reply)
- Local SOCKS5 client (IPv4 / domain / IPv6 CONNECT)
- SmartLink: rule-based SOCKS5 (`DIRECT` / single `PROXY`) using Clash-style rules
- MultiLink: rule-based SOCKS5 with multiple named upstreams (`link1` / `link2` / `DIRECT`)
- Peer relay: `peer.exe` registers on `server`; multilink links with `peer_secret` use `VIA_PEER` (multilink → server → peer → target)
- Local: plain SOCKS5 that always connects DIRECT (no tunnel; useful for tests)
- ActivateNet: system-wide transparent proxy for **this PC’s apps** (WinDivert, fake-IP DNS → local SOCKS5 on multilink/smartlink — no SOCKS setting in apps)
- EnableNet: same goal as ActivateNet with **redir-host** DNS (real A when unique; `198.18` stand-in on collision) → SOCKS5 CONNECT(domain)
- **Internet** (`internet.exe`): MultiLink + EnableNet **in one process** — same `multilink.json` / rules; system apps need no proxy settings; in-process loopback SOCKS + self-port / all-uplink-IP exclusion
- **LinuxNetwork** (`linux_network`): Linux equivalent of `internet.exe` — MultiLink + redir-host via **iptables** (no TUN); systemd package under `dist/VortexInternetLinux/`
- AP2Socks5 + only-ap: Windows Mobile Hotspot clients → local SOCKS5 (WinDivert, fake-IP DNS)
- Separate JSON configs for server, client, smartlink, multilink, local, peer, activate_net, enable_net, internet / linux_network, ap2socks5, hotspot
- Designed for long-running use (timeouts, keepalive, connection limits)

## Requirements

| Platform | Compiler | Notes |
|----------|----------|-------|
| Linux | g++ or clang++ (C++17) | `pthread`; transparent mode needs root + `iptables` |
| macOS | clang++ (Xcode / Command Line Tools) | `SO_NOSIGPIPE` handled in code; **no** `linux_network` (iptables-only) |
| Windows | MinGW-w64 / MSYS2 `g++` | links `ws2_32` |

Optional: CMake >= 3.14

## Quick build

### Linux / macOS

```bash
chmod +x build.sh
./build.sh          # server + client
./build.sh test     # also build & run unit tests
./build.sh all      # binaries + all test helpers
```

Or with Make:

```bash
make
make test
```

Or with CMake:

```bash
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

### Windows (MinGW / MSYS2)

```bat
build.bat
build.bat test
build.bat all
```

Or:

```bat
mingw32-make
```

Or CMake (same commands as above in a developer shell).

## Run

**On the remote host (server):**

```bash
./server config/server.json
```

**On the local machine (client):**

```bash
./client config/client.json
```

Point applications to the local SOCKS5 endpoint (defaults in config):

- SOCKS5: `127.0.0.1:11080`
- Upstream server: `127.0.0.1:18888` (change `server_ip` for a real remote host)

Both sides must use the **same** `master_secret`.

## Configuration

Copy templates from `config_example/` into `config/` (local `config/*.json` and `config/*.yaml` are gitignored). Geo lists live under `config/geo/`.

### `config/server.json`

| Key | Meaning |
|-----|---------|
| `bind_ip` | Listen address (`0.0.0.0` = all interfaces) |
| `bind_port` | Listen port |
| `master_secret` | Shared secret (must match client) |
| `padding_min` / `padding_max` | Random pad bytes per frame |
| `camouflage` | Reply HTTP 404 to invalid probes |
| `listen_backlog` | `listen()` backlog |
| `idle_timeout_sec` | Socket idle timeout |
| `max_payload` | Max plaintext payload per frame |
| `max_connections` | Concurrent session cap |

### `config/client.json`

| Key | Meaning |
|-----|---------|
| `socks5_bind_ip` / `socks5_bind_port` | Local SOCKS5 listen address |
| `server_ip` / `server_port` | Remote Vortex server |
| `master_secret` | Shared secret (must match server) |
| `padding_min` / `padding_max` | Random pad bytes per frame |
| `listen_backlog` | Local listen backlog |
| `idle_timeout_sec` | Socket idle timeout |
| `max_payload` | Max plaintext payload per frame |

### Peer relay (`peer.exe` + `peer_secret` on a multilink link)

Exit node that dials into `server`, registers with `peer_secret`, and handles `CMD_VIA_PEER` jobs.
Each registered worker accepts **many sequential jobs** on one TCP session (no reconnect per request):

```
multilink (link with peer_secret) → server → peer → target
```

```bat
REM 1) server (same master_secret)
server.exe config\server.json

REM 2) peer workers (same master_secret + peer_secret)
peer.exe config\peer.json

REM 3) multilink — link3 sets peer_secret (see config/multilink.json)
multilink.exe config\multilink.json
```

| Key (`config/peer.json`) | Meaning |
|--------------------------|---------|
| `server_ip` / `server_port` | Vortex server to dial |
| `master_secret` | Must match server |
| `peer_secret` | Must match the multilink link’s `peer_secret` |
| `workers` | Parallel registered sessions (each handles many jobs; raise if sites open many concurrent HTTPS) |
| `reconnect_ms` | Delay after a control-session drop before re-HELLO |

On a multilink link, set `"peer_secret": "..."` to send `VIA_PEER` instead of a normal `CONNECT` (server then forwards to a matching peer).

Idle / NAT notes: peer↔server control links use TCP keepalive (~60s) and peers re-HELLO after ~90s idle. If a pooled socket is half-dead, the server drops it on the next `VIA_PEER` and tries another worker — restarting only `peer` is enough; you should not need to restart `server`.

## SOCKS5 front ends (pick one)

Only one process should bind `127.0.0.1:11080` at a time. Point browsers and `ap2socks5` at that port.

### `local` — plain DIRECT SOCKS5

`local.exe` speaks SOCKS5 and always opens a direct TCP connection to the target (no Vortex tunnel). Useful for baseline tests.

```bat
local.exe config\local.json
```

| Key | Meaning |
|-----|---------|
| `socks5_bind_ip` / `socks5_bind_port` | Listen address (default `127.0.0.1:11080`) |

### `smartlink` — rules + one PROXY uplink

Rule-aware SOCKS5. Matched `PROXY` / default tunnel traffic uses one Vortex server (same keys as `client.json`); `DIRECT` uses the local network stack.

```bat
smartlink.exe config\smartlink.json
```

| Key | Meaning |
|-----|---------|
| (same tunnel keys as `client.json`) | Bind, remote server, secret, padding, timeouts |
| `rules_path` | Clash-style rules (default `config/rules.yaml`) |
| `geoip_cn` / `geosite_cn` | Lists for `GEOIP,CN` / `GEOSITE,cn` |
| `log_decisions` | Log each CONNECT / DNS decision |

### `multilink` — rules + named uplinks (`link1` / `link2` / …)

Like SmartLink, but each rule can select a named outbound from `config/multilink.json`. DNS over TCP/53 is routed by the **queried name**, not by the resolver IP (so remote DNS from browsers / AP works with DOMAIN rules).

```bat
multilink.exe config\multilink.json
```

| Key | Meaning |
|-----|---------|
| `multilink.<name>.*` | Per-link Vortex server (`server_ip`, `server_port`, `master_secret`, …) |
| `multilink.<name>.peer_secret` | Optional. If set, this link sends `VIA_PEER` so `server` relays via a matching `peer.exe` |
| `socks5_bind_ip` / `socks5_bind_port` | Local SOCKS5 listen address |
| `rules_path` | Clash-style rules (default `config/multirules.yaml`) |
| `geoip_cn` / `geosite_cn` | Geo lists |
| `log_decisions` | Log each CONNECT / DNS decision |

Outbound names in rules: `DIRECT`, `link1`, `link2`, `link3`, … (must match keys under `multilink`). Example templates: `config_example/multilink_example.json`, `config_example/peer_example.json`.

### Shared rule syntax

Supported types: `IP-CIDR`, `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `GEOIP` (`private` / `CN`), `GEOSITE` (`cn`), `MATCH`. First match wins. `no-resolve` skips DNS when matching IP rules against a domain. SmartLink actions are `DIRECT` / `PROXY`; MultiLink actions are `DIRECT` / named link.

## ActivateNet — this PC, no app proxy settings

`activate_net.exe` captures **outbound** IPv4 TCP and DNS from local applications (WinDivert), answers DNS with fake-IP (`198.18.0.0/15`), terminates TCP locally, and relays each flow with **SOCKS5 CONNECT(domain)** to `multilink.exe` or `smartlink.exe` on `127.0.0.1:11080`. Routing (`DIRECT`, `link1`, `link2`, …) is handled entirely by the SOCKS5 upstream — not inside ActivateNet. Browsers and other apps need **no** SOCKS/HTTP proxy configuration.

Does **not** bridge Mobile Hotspot / SoftAP (that remains `ap2socks5`).

**Run two processes** (Administrator for ActivateNet):

```bat
REM 1) SOCKS5 with rules (normal user OK unless your setup needs admin)
multilink.exe config\multilink.json
REM or: smartlink.exe config\smartlink.json

REM 2) Transparent capture (Administrator; WinDivert.dll + WinDivert64.sys next to exe)
activate_net.exe config\activate_net.json
```

Config: `config/activate_net.json` (see `config_example/activate_net_example.json`), or pass `config/multilink.json` — ActivateNet reads `socks5_bind_ip` / `socks5_bind_port` from that file as the SOCKS5 endpoint.

Behavior notes:

- DNS: all **A** queries get **fake-IP** (`198.18.0.0/15`); TCP to fake-IP uses SOCKS5 CONNECT(domain)
- **Only TCP to `198.18.0.0/15` is diverted** — real IPs (multilink/smartlink DIRECT and Vortex uplinks) are **not** captured
- Outbound **UDP/443 (QUIC)**, **UDP/853 (DoT)**, and **IPv6** are dropped so apps fall back to IPv4 TCP through ActivateNet
- Upstream SOCKS `DIRECT` resolves via **DNS-over-TCP** so fake-IP UDP hijack cannot loop

Requires Administrator for `activate_net.exe`.

## EnableNet — this PC, redir-host DNS (no fake-IP by default)

`enable_net.exe` is the **redir-host** counterpart to ActivateNet: same WinDivert + local SOCKS5 stack, but DNS answers use a sticky **IP↔hostname** map instead of always allocating fake-IP.

- Prefer a **real A** from local UDP DNS (fast CN CDN) when that IP is not already bound to another name
- On CDN / GFW-poisoned **IP collision**, or when resolve fails, allocate a unique **`198.18.0.0/15` stand-in** (same pool as ActivateNet) so each hostname stays distinct
- TCP to learned / stand-in IPs is terminated and relayed with **SOCKS5 CONNECT(domain) only** — never CONNECT by IP (poisoned A records like `www.google.com` → `185.45.5.x` would otherwise skip DOMAIN rules and fail upstream with `cmd=4`)
- Other TCP (private, unknown public, multilink/smartlink uplink) is reinjected; UDP/443, UDP/853, and IPv6 are dropped like ActivateNet

Does **not** bridge Mobile Hotspot / SoftAP (use `ap2socks5`).

**Run two processes** (Administrator for EnableNet):

```bat
REM 1) SOCKS5 with rules first
multilink.exe config\multilink.json

REM 2) Transparent capture (Administrator; WinDivert.dll + WinDivert64.sys next to exe)
enable_net.exe config\enable_net.json
```

Config: `config/enable_net.json` (see `config_example/enable_net_example.json`). Same keys as ActivateNet (`socks5_host` / `socks5_port`, `mss`, `idle_timeout_sec`, `max_connections`, `max_dns_inflight`, `log_connections`). Passing `config/multilink.json` also works — EnableNet reads `socks5_bind_ip` / `socks5_bind_port` as the upstream.

| | ActivateNet | EnableNet |
|---|-------------|-----------|
| DNS to apps | Always fake-IP `198.18/15` | Real A when unique; `198.18` on collision / miss |
| Diverted TCP | Only to `198.18/15` | To learned / stand-in IPs (mapping table) |
| SOCKS CONNECT | Domain | Domain (never IP) |
| Best when | Maximum isolation from poisoned DNS | Prefer real IPs / redir-host style |

Requires Administrator for `enable_net.exe`. Start multilink/smartlink **before** EnableNet.

Optional: `enable-ipv6.bat` (Administrator) re-enables the IPv6 stack binding on adapters if it was turned off; EnableNet itself still drops outbound IPv6 so apps stay on IPv4 TCP through the proxy.

## Internet — MultiLink + EnableNet (one process)

`internet.exe` embeds MultiLink (same rules / link1·link2·link3 / VIA_PEER as `multilink.exe`) and EnableNet (redir-host WinDivert) so **local apps need no SOCKS/HTTP proxy settings**.

```
Apps --(no proxy)--> WinDivert (DNS + learned-IP TCP)
                          |
                     loopback SOCKS 127.0.0.1:11080  (in-process MultiLink)
                          |
                     DIRECT / link1 / link2 / link3 (peer)
```

Self-exclusion (avoids divert capturing the router):

- Divert filter is `outbound and not loopback` — SOCKS hops to `127.0.0.1` are never captured
- Every Vortex / DIRECT / DNS-UDP socket registers its **local source port** before connect; those packets are reinjected
- All configured multilink `server_ip` values are reinjected (uplinks)

```bat
REM Administrator; WinDivert.dll + WinDivert64.sys next to internet.exe
REM Stop multilink.exe / enable_net.exe first (same SOCKS port + divert)
REM Remote: server.exe (+ peer.exe for link3) must match secrets
internet.exe config\internet.json
```

Config: `config/internet.json` — **same shape as `multilink.json`** (see `config_example/internet_example.json` / `multilink_example.json`). Optional divert overlays: `mss`, `max_connections`, `divert_idle_timeout_sec`, `max_dns_inflight`, `log_connections`.

Prefer `internet.exe` over running `multilink` + `enable_net` as two processes.

### Windows service (Win10/11)

From the **repo root**, one command stages a self-contained payload into **`dist\VortexInternet\`** (gitignored — the folder appears only after this runs):

```bat
internet-service.bat stage
```

That copies `internet.exe`, WinDivert, MinGW runtime DLLs (`libgcc_s_seh-1.dll`, `libstdc++-6.dll`, `libwinpthread-1.dll` from PATH/`msys64\ucrt64\bin` if needed), `config\internet.json` + rules/geo, and control scripts into `dist\VortexInternet\` (and removes any legacy `VortexInternet.*` / `logs\` left in the repo root by older installs).

Register / control the delayed auto-start service `VortexInternet` (WinSW wrapper; Administrator; auto-elevates):

```bat
internet-service.bat install
internet-service.bat start
internet-service.bat stop
internet-service.bat restart
internet-service.bat status
internet-service.bat uninstall
internet-service.bat uninstall -Purge
```

`install` runs `stage` first, then registers the service with working directory `dist\VortexInternet\`. Same actions via `.\internet-service.ps1 <action>`. After rebuilding `internet.exe`, re-run `stage` or `install` to refresh `dist\`. Offline: place [WinSW-x64.exe](https://github.com/winsw/winsw/releases) at `tools\WinSW-x64.exe` and use `-Offline`.

## LinuxNetwork — MultiLink + redir-host (iptables, one process)

`linux_network` is the **Linux** counterpart of `internet.exe`: in-process MultiLink SOCKS plus sticky **redir-host** DNS, so desktop apps need **no** SOCKS/HTTP proxy settings.

```
Apps --(no proxy)--> iptables OUTPUT (UDP/53 + learned-IP TCP)
                          |
                     loopback SOCKS 127.0.0.1:11080  (in-process MultiLink)
                          |
                     DIRECT / link1 / link2 / link3 (peer)
```

Decision tree matches `internet.cpp`:

- Own egress uses **`SO_MARK`** (never hijacked) + uplink / LAN excludes
- Sticky DNS: real A when unique; `198.18.0.0/15` stand-in on collision / miss
- **Learned** TCP → REDIRECT → SOCKS5 **CONNECT(domain)** only
- **Unlearned** TCP → not redirected (WinDivert reinject equivalent)
- UDP/443 + UDP/853 rejected so stacks fall back to TCP

```bash
# Linux only (root for transparent mode)
make linux_network
sudo ./linux_network config/internet.json

# SOCKS-only (no iptables): same MultiLink router
./linux_network --router-only config/internet.json
```

Config: same `config/internet.json` shape as multilink / Windows Internet (`rules_path`, `geoip_cn`, `geosite_cn`, links, secrets).

If stop leaves DNS/routing broken:

```bash
sudo ./scripts/restore-network.sh
```

### Relocatable systemd package

```bash
make dist-linux    # → dist/VortexInternetLinux/ (gitignored)
```

Copy that folder anywhere, then:

```bash
cd /path/to/VortexInternetLinux
sudo ./install-service.sh      # enable + start vortex-linux-network
sudo ./uninstall-service.sh    # stop, remove unit, restore network
```

`install-service.sh` rewrites unit paths from its own directory (safe to relocate). Logs: `journalctl -u vortex-linux-network -f`.

Docker smoke test (privileged, isolated netns):

```bash
./scripts/test-linux-network.sh --docker
```

## Android VPN (VpnService)

Source: `src/android/` — MultiLink + redir-host DNS over Android **VpnService** (desktop `internet.exe` equivalent; no per-app proxy). Config assets mirror `internet.json` / rules.

One-command APK (needs **JDK 17+** and **Android SDK** / Android Studio; set `JAVA_HOME` / `ANDROID_HOME` if needed):

```bat
build-android.bat
```

Output: `dist\VortexInternetAndroid\vortex-internet.apk` (gitignored). Install with `adb install -r dist\VortexInternetAndroid\vortex-internet.apk`. Details: `src/android/README.md`.

## Windows Mobile Hotspot

Typical stack (Administrator where noted):

```
Phone --Wi-Fi--> only-ap (hotspot/ICS)
                      |
                 ap2socks5 (WinDivert, exclusive AP data-plane)
                      |
                 multilink / smartlink / local / client   (SOCKS5 :11080)
                      |
                 Internet (DIRECT and/or Vortex uplink)
```

### `only-ap` — hotspot only (no proxy)

Starts or stops the Windows Mobile Hotspot from `config/hotspot.json`. Uses system ICS/NAT so phones get internet through the PC **without** `ap2socks5`. Does not start SOCKS5 or WinDivert.

```bat
only-ap.bat
only-ap.bat -Stop
only-ap.bat -Watch
```

| Key (`config/hotspot.json`) | Meaning |
|-----------------------------|---------|
| `ssid` / `password` | SoftAP credentials |
| `band` / `prefer_5ghz` | Radio preference (`2.4` / `5`) |
| `ap_gateway` | Expected gateway (usually `192.168.137.1`) |
| `ap_radio` | SoftAP NIC hint (`auto` or adapter name) |
| `deprioritize_vpn` / `watch` | Stability helpers for USB Wi-Fi dongles |

### `ap2socks5` — AP clients through SOCKS5

`ap2socks5.exe` claims the SoftAP data-plane with WinDivert: OS must not forward AP traffic (DHCP is reinjected so leases still work; ARP stays at L2). Phone TCP is terminated and reopened as SOCKS5 `CONNECT`.

**Remote DNS (browser-style):** UDP/53 `A` answers are **fake-IP** (`198.18.0.0/15`). Real resolution is done by the SOCKS5 upstream when CONNECT uses `ATYP=DOMAIN`. Bindings are cached in `ap2socks5.fakeip.cache`. Phones should use DHCP DNS (AP gateway) and disable Private DNS / DoH.

```
Phone --AP--> ap2socks5 --SOCKS5--> multilink/smartlink/… --> Internet
```

`config/ap2socks5.json`:

| Key | Default | Meaning |
|-----|---------|---------|
| `ap_adapter` | `auto` | SoftAP NIC (`192.168.137.1`, often `本地连接*`) |
| `ap_gateway` / `ap_prefix` | `192.168.137.1/24` | AP subnet |
| `socks5_host` / `socks5_port` | `127.0.0.1:11080` | Upstream SOCKS5 (multilink/smartlink/…) |
| `mss` | `1200` | TCP payload slice back to clients |
| `idle_timeout_sec` | `180` | Drop a silent flow |
| `max_connections` | `1024` | Concurrent TCP flows |

Requires `WinDivert.dll` + `WinDivert64.sys` ([WinDivert 2.2.2](https://github.com/basil00/WinDivert/releases)) next to `ap2socks5.exe`.

Recommended order:

```bat
REM 1) SOCKS5 front end (example: multilink)
multilink.exe config\multilink.json

REM 2) Hotspot only
only-ap.bat

REM 3) Bridge AP -> SOCKS5 (Administrator)
start-ap2socks5.bat
start-ap2socks5.bat -Stop
```

`start-ap2socks5.bat` does **not** start the hotspot or SOCKS5; run `only-ap.bat` and a SOCKS5 front end first. Logs: `ap2socks5.out.log` / `ap2socks5.err.log`.

## Project layout

```
include/               Shared headers (cipher, protocol, config, net)
src/server.cpp         Remote tunnel server
src/client.cpp         Local SOCKS5 client (always PROXY / one uplink)
src/local.cpp          Plain SOCKS5 (always DIRECT)
src/smartlink.cpp      Rule-based SOCKS5 (DIRECT / PROXY)
src/multilink.cpp      Rule-based SOCKS5 (DIRECT / link1 / link2 / …)
src/peer.cpp           Peer exit node (VIA_PEER relay through server)
src/ap2socks5.cpp      Windows AP → SOCKS5 (WinDivert, fake-IP DNS)
src/activate_net.cpp   This PC → SOCKS5 (WinDivert, fake-IP DNS)
src/enable_net.cpp     This PC → SOCKS5 (WinDivert, redir-host DNS)
src/internet.cpp       MultiLink + EnableNet combined (self-excluding divert)
src/linux_network.cpp  Linux MultiLink + redir-host (iptables; internet.exe equivalent)
src/android/           Android VpnService client (Gradle; see src/android/README.md)
config/                Local JSON/YAML (gitignored) + geo/
config_example/        Checked-in config templates
dist/                  Runtime install tree (gitignored; Win/Android/Linux packages)
scripts/               Linux pack/install/restore + e2e test helpers
internet-service.bat|.ps1  Stage dist\VortexInternet + Windows service control
build-android.bat      Build Android APK → dist\VortexInternetAndroid\
make dist-linux        Stage dist/VortexInternetLinux (relocatable systemd package)
only-ap.bat|.ps1       Mobile Hotspot only
start-ap2socks5.bat|.ps1  Start/stop ap2socks5 (hotspot must already be up)
enable-ipv6.bat        Re-enable ms_tcpip6 on adapters (Administrator)
tests/                 Unit + integration tests
build.sh / build.bat   Build scripts
CMakeLists.txt / Makefile
```

## Tests

Unit tests:

```bash
./build.sh test          # Linux/macOS
build.bat test           # Windows
```

Full integration (starts echo + server + client, then exercises proxy paths):

```bash
# Linux / macOS
chmod +x tests/run_integration.sh
./tests/run_integration.sh

# Windows PowerShell
powershell -ExecutionPolicy Bypass -File tests/run_integration.ps1
```

Covered scenarios:

- Cipher round-trip and frame encode/decode
- SOCKS5 HTTP proxying
- Anti-probe camouflage
- Wrong shared secret rejection
- Binary bidirectional echo
- Concurrent stress traffic
- Peer protocol helpers (`CMD_PEER_HELLO` / `CMD_VIA_PEER` packing)
- Local peer relay stack (no remote hosts): `powershell -File tests/run_peer_relay.ps1`
  (HTTP DOMAIN/IPv4 via peer, `localhost` resolution on peer, DNS-over-TCP via peer, burst + parallel)
- 5-minute high-intensity peer stress: `powershell -File tests/run_peer_stress_5min.ps1`
  (12 threads × 300s; mixed HTTP/DNS via peer; requires `fail=0`)

## Protocol overview

1. Client (or peer) sends 8-byte random salt (plaintext).
2. Both sides derive directional ciphers from `master_secret` + salt.
3. Framed traffic: encrypted length (2 bytes) + encrypted body  
   `[cmd][data_len][data][padding]`.
4. First authenticated frame may be:
   - `CONNECT` (0x01) — normal client tunnel to a target
   - `PEER_HELLO` (0x06) — peer registers with `peer_secret` and waits for jobs
   - `VIA_PEER` (0x07) — client asks server to forward the CONNECT target through a matching peer
5. Anything else gets active-probe camouflage (HTTP 404-style reply when enabled).

## License / disclaimer

For research, learning, and authorized network use only. You are responsible for complying with local laws and network policies.
