#!/usr/bin/env bash
# ICMP + ICMPv6 Vortex path: server CMD_ICMP ↔ loopback; optional linux_network NFQUEUE.
# Usage:
#   ./tests/run_icmp.sh              # unit + server raw ICMP (may need sudo for SOCK_RAW)
#   sudo ./tests/run_icmp.sh --full  # also smoke linux_network NFQUEUE + ping/ping6 DIRECT
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

FULL=0
[[ "${1:-}" == "--full" ]] && FULL=1

echo "[BUILD] icmp-related..."
# build.sh test aborts on unrelated missing-config unit fails; build targets we need.
{
  bash ./build.sh >/tmp/vortex-icmp-build.log 2>&1
  g++ -std=c++17 -O2 -Wall -Wextra -Iinclude tests/test_icmp_relay.cpp -o tests/test_icmp_relay -pthread
  g++ -std=c++17 -O2 -Wall -Wextra -Iinclude tests/test_peer_protocol.cpp -o tests/test_peer_protocol -pthread
} || {
  echo "FAIL build"; tail -80 /tmp/vortex-icmp-build.log; exit 1
}
./tests/test_icmp_relay || exit 1
./tests/test_peer_protocol || exit 1

# Minimal server config on high port
python3 - <<'PY'
import json
cfg = {
  "bind_ip": "127.0.0.1",
  "bind_port": 31991,
  "master_secret": "icmp_test_secret_2026",
  "camouflage": False,
  "padding_min": 0,
  "padding_max": 0,
  "max_payload": 32768,
  "idle_timeout_sec": 30,
  "max_connections": 64,
  "listen_backlog": 16,
}
json.dump(cfg, open("/tmp/vortex-icmp-server.json", "w"))
print("[*] server config /tmp/vortex-icmp-server.json")
PY

./server /tmp/vortex-icmp-server.json >/tmp/vortex-icmp-server.log 2>&1 &
SPID=$!
cleanup() {
  kill -INT "$SPID" 2>/dev/null || true
  kill -INT "${LPID:-}" 2>/dev/null || true
  sleep 0.3
  kill -9 "$SPID" 2>/dev/null || true
  kill -9 "${LPID:-}" 2>/dev/null || true
}
trap cleanup EXIT
sleep 0.4

# Client-side ICMP + ICMPv6 via Vortex (server exits with raw sockets).
cat > /tmp/vortex-icmp-client.cpp <<'CPP'
#include "icmp_util.hpp"
#include "net.hpp"
#include "protocol.hpp"
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
static bool one(const char* host, const uint8_t* echo, size_t elen, bool v6) {
  socket_t fd = tcp_connect("127.0.0.1", 31991, 5);
  if (fd == INVALID_SOCK) { std::fprintf(stderr, "connect fail\n"); return false; }
  uint64_t salt = get_random_salt();
  uint8_t sb[8]; std::memcpy(sb, &salt, 8);
  if (!send_all(fd, sb, 8)) { net_close(fd); return false; }
  vortex::SessionCrypto up, down;
  up.init("icmp_test_secret_2026", salt);
  down.init("icmp_test_secret_2026", salt ^ 0xA5A5A5A5A5A5A5A5ULL);
  auto wire = vortex::build_icmp_wire(host, echo, elen);
  if (!vortex::send_frame(fd, up, vortex::CMD_ICMP, wire, 0, 0)) { net_close(fd); return false; }
  auto fr = vortex::recv_frame(fd, down, 32768);
  net_close(fd);
  if (!fr.ok || fr.cmd != vortex::CMD_DATA || fr.data.size() < 8) {
    std::fprintf(stderr, "no ICMP reply host=%s cmd=%d\n", host, fr.ok ? fr.cmd : -1);
    return false;
  }
  if (v6) {
    if (!vortex::icmp_util::is_echo_reply_v6(fr.data.data(), fr.data.size())) return false;
  } else {
    if (!vortex::icmp_util::is_echo_reply_v4(fr.data.data(), fr.data.size())) return false;
  }
  if (vortex::icmp_util::echo_id(fr.data.data()) !=
      vortex::icmp_util::echo_id(echo)) return false;
  std::printf("PASS: Vortex CMD_ICMP echo via server → %s\n", host);
  return true;
}
int main() {
  if (!net_init()) return 2;
  uint8_t e4[8] = {8,0,0,0,0x11,0x22,0x00,0x07};
  uint8_t e6[8] = {128,0,0,0,0x33,0x44,0x00,0x09};
  bool ok = one("127.0.0.1", e4, 8, false);
  ok = one("::1", e6, 8, true) && ok;
  // PROXY-style ATYP_DOMAIN: exit getaddrinfo("localhost") → loopback echo.
  if (ok) {
    const bool dom = one("localhost", e4, 8, false);
    std::printf("%s: Vortex CMD_ICMP ATYP_DOMAIN localhost\n", dom ? "PASS" : "FAIL");
    ok = dom && ok;
  }
  net_cleanup();
  return ok ? 0 : 1;
}
CPP
g++ -std=c++17 -O2 -Iinclude /tmp/vortex-icmp-client.cpp -o /tmp/vortex-icmp-client -pthread
if /tmp/vortex-icmp-client; then
  echo "[+] server ICMP/ICMPv6 path ok"
else
  rc=$?
  echo "[-] server ICMP path failed (rc=$rc). Often needs CAP_NET_RAW on server."
  echo "---- server log ----"; cat /tmp/vortex-icmp-server.log
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "WARN: re-run under sudo for live SOCK_RAW ICMP/ICMPv6"
    exit 0
  fi
  exit 1
fi

if [[ "$FULL" -eq 1 ]]; then
  if [[ "$(id -u)" -ne 0 ]]; then
    echo "FAIL: --full needs root for linux_network NFQUEUE"
    exit 1
  fi
  if [[ ! -f config/internet.json ]]; then
    echo "SKIP: no config/internet.json for linux_network smoke"
    exit 0
  fi
  python3 - <<'PY'
import json
cfg=json.load(open("config/internet.json"))
cfg["socks5_bind_port"]=31996
cfg["log_decisions"]=True
cfg["log_connections"]=True
json.dump(cfg, open("/tmp/vortex-icmp-ln.json","w"))
print("[*] linux_network test config /tmp/vortex-icmp-ln.json")
PY
  ./linux_network /tmp/vortex-icmp-ln.json >/tmp/vortex-icmp-ln.log 2>&1 &
  LPID=$!
  for i in $(seq 1 50); do
    grep -q "ICMP NFQUEUE" /tmp/vortex-icmp-ln.log 2>/dev/null && break
    sleep 0.1
  done
  if ! grep -q "ICMP NFQUEUE" /tmp/vortex-icmp-ln.log; then
    echo "FAIL: linux_network ICMP NFQUEUE not up"; cat /tmp/vortex-icmp-ln.log; exit 1
  fi
  if ! grep -q "IPv4/ICMPv6" /tmp/vortex-icmp-ln.log; then
    echo "WARN: log missing ICMPv6 marker (older binary?)"
  fi
  if ! grep -q "icmp-ip-exit\|PROXY=SOCKS DoT\|PROXY CMD_ICMP with IP" /tmp/vortex-icmp-ln.log; then
    echo "WARN: log missing build/ICMP IP-exit banner (older binary?)"
  fi
  # Client-only path: IP literal wire works on old exit; DOMAIN gets CONNECT_FAIL.
  cat > /tmp/vortex-icmp-atyp-check.cpp <<'CPP'
#include "protocol.hpp"
#include <cstdio>
int main() {
  uint8_t e[8]={8,0,0,0,1,2,0,3};
  auto ip = vortex::build_icmp_wire("142.251.152.119", e, 8);
  auto dom = vortex::build_icmp_wire("www.google.com", e, 8);
  if (ip.empty() || ip[1] != vortex::ATYP_IPV4) return 1;
  if (dom.empty() || dom[1] != vortex::ATYP_DOMAIN) return 2;
  std::printf("PASS: PROXY ICMP prefers ATYP_IPV4 for real dst; DOMAIN reserved for stand-in\n");
  return 0;
}
CPP
  g++ -std=c++17 -O2 -Iinclude /tmp/vortex-icmp-atyp-check.cpp -o /tmp/vortex-icmp-atyp-check
  /tmp/vortex-icmp-atyp-check || { echo "FAIL: ICMP atyp preference"; exit 1; }
  # DIRECT private/loopback should ACCEPT
  if ping -c 1 -W 2 127.0.0.1 >/dev/null; then
    echo "[+] ping 127.0.0.1 (DIRECT/private accept) ok"
  else
    echo "FAIL: ping 127.0.0.1"; exit 1
  fi
  if ping -6 -c 1 -W 2 ::1 >/dev/null 2>&1 || ping6 -c 1 -W 2 ::1 >/dev/null 2>&1; then
    echo "[+] ping6 ::1 (DIRECT/private accept) ok"
  else
    echo "FAIL: ping6 ::1"; exit 1
  fi
  # Unit-level inject address contract + PROXY domain wire (anti-poison).
  cat > /tmp/vortex-icmp-inject-check.cpp <<'CPP'
#include "icmp_util.hpp"
#include "protocol.hpp"
#include <arpa/inet.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
int main() {
  uint8_t r[8] = {0,0,0,0,1,2,0,3};
  in_addr t{}, c{};
  inet_pton(AF_INET, "104.244.42.197", &t);
  inet_pton(AF_INET, "192.168.0.106", &c);
  auto p = vortex::icmp_util::build_echo_reply_ip4(t.s_addr, c.s_addr, r, 8);
  if (p.size() != 28) return 1;
  uint32_t s=0,d=0; std::memcpy(&s,p.data()+12,4); std::memcpy(&d,p.data()+16,4);
  if (s != t.s_addr || d != c.s_addr) return 2;
  uint8_t e4[8] = {8,0,0,0,1,2,0,3};
  auto w = vortex::build_icmp_wire("www.google.com", e4, 8);
  if (w.empty() || w[1] != vortex::ATYP_DOMAIN) return 3;
  std::string host; std::vector<uint8_t> body;
  if (!vortex::parse_icmp_wire(w, host, body) || host != "www.google.com") return 4;
  // GFW poison literals stay ATYP_IP* (linux_network prefers learned domain instead).
  auto poison4 = vortex::build_icmp_wire("185.45.5.35", e4, 8);
  auto poison6 = vortex::build_icmp_wire("2001::1", e4, 8);
  if (poison4.empty() || poison4[1] != vortex::ATYP_IPV4) return 5;
  if (poison6.empty() || poison6[1] != vortex::ATYP_IPV6) return 6;
  std::printf("PASS: inject src=target + PROXY domain wire\n");
  return 0;
}
CPP
  g++ -std=c++17 -O2 -Iinclude /tmp/vortex-icmp-inject-check.cpp -o /tmp/vortex-icmp-inject-check
  /tmp/vortex-icmp-inject-check || { echo "FAIL: inject address contract"; exit 1; }
  kill -INT "$LPID" 2>/dev/null || true
  sleep 1
  echo "[+] linux_network ICMP/ICMPv6 smoke ok"
fi

echo "[OK] run_icmp.sh finished"
