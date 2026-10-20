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
- Local: plain SOCKS5 that always connects DIRECT (no tunnel; useful for tests)
- AP2Socks5 + only-ap: Windows Mobile Hotspot clients → local SOCKS5 (WinDivert, fake-IP DNS)
- Separate JSON configs for server, client, smartlink, multilink, local, ap2socks5, hotspot
- Designed for long-running use (timeouts, keepalive, connection limits)

## Requirements

| Platform | Compiler | Notes |
|----------|----------|-------|
| Linux | g++ or clang++ (C++17) | `pthread` |
| macOS | clang++ (Xcode / Command Line Tools) | `SO_NOSIGPIPE` handled in code |
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
| `socks5_bind_ip` / `socks5_bind_port` | Local SOCKS5 listen address |
| `rules_path` | Clash-style rules (default `config/multirules.yaml`) |
| `geoip_cn` / `geosite_cn` | Geo lists |
| `log_decisions` | Log each CONNECT / DNS decision |

Outbound names in rules: `DIRECT`, `link1`, `link2`, … (must match keys under `multilink`).

### Shared rule syntax

Supported types: `IP-CIDR`, `DOMAIN`, `DOMAIN-SUFFIX`, `DOMAIN-KEYWORD`, `GEOIP` (`private` / `CN`), `GEOSITE` (`cn`), `MATCH`. First match wins. `no-resolve` skips DNS when matching IP rules against a domain. SmartLink actions are `DIRECT` / `PROXY`; MultiLink actions are `DIRECT` / named link.

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
src/ap2socks5.cpp      Windows AP → SOCKS5 (WinDivert, fake-IP DNS)
config/                Local JSON/YAML (gitignored) + geo/
config_example/        Checked-in config templates
only-ap.bat|.ps1       Mobile Hotspot only
start-ap2socks5.bat|.ps1  Start/stop ap2socks5 (hotspot must already be up)
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

## Protocol overview

1. Client sends 8-byte random salt (plaintext).
2. Both sides derive directional ciphers from `master_secret` + salt.
3. Framed traffic: encrypted length (2 bytes) + encrypted body  
   `[cmd][data_len][data][padding]`.
4. First frame must be a valid `CONNECT`; otherwise the server camouflages as a web server.

## License / disclaimer

For research, learning, and authorized network use only. You are responsible for complying with local laws and network policies.
