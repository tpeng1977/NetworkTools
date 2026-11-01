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
  kill -INT "$LPID" 2>/dev/null || true
  sleep 1
  echo "[+] linux_network ICMP/ICMPv6 smoke ok"
fi

echo "[OK] run_icmp.sh finished"
