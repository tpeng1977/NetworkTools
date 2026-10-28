#!/usr/bin/env bash
# Linux e2e: to_remote / to_local TCP + UDP port forwards.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CXX="${CXX:-g++}"
CXXFLAGS="-std=c++17 -O2 -Wall -Wextra -Iinclude"
LDFLAGS="-pthread"

stop_stack() {
  pkill -TERM -f './server tests/port_forward_server.json' 2>/dev/null || true
  pkill -TERM -f './peer tests/port_forward_peer.json' 2>/dev/null || true
  pkill -TERM -f 'tests/echo_server' 2>/dev/null || true
  pkill -TERM -f 'tests/udp_echo' 2>/dev/null || true
  sleep 0.3
  pkill -KILL -f './server tests/port_forward_server.json' 2>/dev/null || true
  pkill -KILL -f './peer tests/port_forward_peer.json' 2>/dev/null || true
  pkill -KILL -f 'tests/echo_server' 2>/dev/null || true
  pkill -KILL -f 'tests/udp_echo' 2>/dev/null || true
  sleep 0.4
}

echo "=== Build ==="
$CXX $CXXFLAGS src/server.cpp -o server $LDFLAGS
$CXX $CXXFLAGS src/peer.cpp -o peer $LDFLAGS
$CXX $CXXFLAGS tests/echo_server.cpp -o tests/echo_server $LDFLAGS
$CXX $CXXFLAGS tests/udp_echo.cpp -o tests/udp_echo $LDFLAGS
$CXX $CXXFLAGS tests/tcp_echo_client.cpp -o tests/tcp_echo_client $LDFLAGS
$CXX $CXXFLAGS tests/udp_echo_client.cpp -o tests/udp_echo_client $LDFLAGS
$CXX $CXXFLAGS tests/test_port_forward.cpp -o tests/test_port_forward $LDFLAGS
$CXX $CXXFLAGS tests/test_peer_protocol.cpp -o tests/test_peer_protocol $LDFLAGS

echo "=== Unit: port forward ==="
./tests/test_port_forward
echo "=== Unit: peer protocol ==="
./tests/test_peer_protocol

stop_stack
mkdir -p tests
rm -f tests/pf_e2e_*.log

echo "=== Start echo targets + server + peer ==="
# Peer-local targets for to_remote (server:19888 → peer:19800)
./tests/echo_server 19800 >tests/pf_e2e_echo_r0.log 2>&1 &
./tests/echo_server 19801 >tests/pf_e2e_echo_r1.log 2>&1 &
./tests/echo_server 19802 >tests/pf_e2e_echo_r2.log 2>&1 &
# Server-side targets for to_local (peer:19900 → server-side:19810)
./tests/echo_server 19810 >tests/pf_e2e_echo_l0.log 2>&1 &
./tests/echo_server 19811 >tests/pf_e2e_echo_l1.log 2>&1 &
./tests/echo_server 19812 >tests/pf_e2e_echo_l2.log 2>&1 &
# UDP targets
./tests/udp_echo 19800 >tests/pf_e2e_udp_r0.log 2>&1 &
./tests/udp_echo 19810 >tests/pf_e2e_udp_l0.log 2>&1 &

./server tests/port_forward_server.json >tests/pf_e2e_srv.log 2>&1 &
sleep 0.6
./peer tests/port_forward_peer.json >tests/pf_e2e_peer.log 2>&1 &
sleep 1.5

cleanup() { stop_stack; }
trap cleanup EXIT

if ! pgrep -f './server tests/port_forward_server.json' >/dev/null; then
  echo "server died early"; tail -50 tests/pf_e2e_srv.log; exit 1
fi
if ! pgrep -f './peer tests/port_forward_peer.json' >/dev/null; then
  echo "peer died early"; tail -80 tests/pf_e2e_peer.log; exit 1
fi

echo "=== 1) to_remote TCP (ssh -R style) 127.0.0.1:19888 → peer:19800 ==="
./tests/tcp_echo_client 127.0.0.1 19888 VORTEX_R_TCP

echo "=== 2) to_remote TCP range map 19891 → 19801 ==="
./tests/tcp_echo_client 127.0.0.1 19891 VORTEX_R_TCP_RANGE

echo "=== 3) to_local TCP (ssh -L style) 127.0.0.1:19900 → 19810 ==="
./tests/tcp_echo_client 127.0.0.1 19900 VORTEX_L_TCP

echo "=== 4) to_local TCP range 19901 → 19811 ==="
./tests/tcp_echo_client 127.0.0.1 19901 VORTEX_L_TCP_RANGE

echo "=== 5) to_remote UDP 19888 → peer udp:19800 ==="
./tests/udp_echo_client 127.0.0.1 19888 VORTEX_R_UDP

echo "=== 6) to_local UDP 19900 → remote udp:19810 ==="
./tests/udp_echo_client 127.0.0.1 19900 VORTEX_L_UDP

echo "=== 7) Stability: 8 sequential to_remote TCP ==="
for i in $(seq 1 8); do
  ./tests/tcp_echo_client 127.0.0.1 19888 "SEQ_$i" >/dev/null
done
echo "burst OK"

echo "=== 8) Peer reconnect: kill peer, restart, retest ==="
pkill -TERM -f './peer tests/port_forward_peer.json' 2>/dev/null || true
sleep 1.2
# Drop half-dead peer sockets from the server pool by forcing a fresh peer process.
./peer tests/port_forward_peer.json >tests/pf_e2e_peer2.log 2>&1 &
# Wait until to_remote listener answers again (install + workers + udp mux).
ok=0
for _ in $(seq 1 40); do
  if ./tests/tcp_echo_client 127.0.0.1 19888 VORTEX_R_RECONNECT >/dev/null 2>&1; then
    ok=1
    break
  fi
  sleep 0.25
done
if [[ "$ok" != "1" ]]; then
  echo "to_remote TCP after reconnect failed"
  tail -40 tests/pf_e2e_peer2.log || true
  tail -40 tests/pf_e2e_srv.log || true
  exit 1
fi
echo "to_remote TCP reconnect OK"
./tests/tcp_echo_client 127.0.0.1 19900 VORTEX_L_RECONNECT
./tests/udp_echo_client 127.0.0.1 19888 VORTEX_R_UDP_RECONN
./tests/udp_echo_client 127.0.0.1 19900 VORTEX_L_UDP_RECONN

echo ""
echo "ALL PORT FORWARD TESTS PASSED"
echo "--- peer log (tail) ---"
tail -30 tests/pf_e2e_peer.log || true
echo "--- server log (tail) ---"
tail -30 tests/pf_e2e_srv.log || true
