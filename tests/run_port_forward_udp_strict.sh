#!/usr/bin/env bash
# Strict UDP coverage for to_remote / to_local (seq, burst, concurrent, large, idle, kill).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CXX="${CXX:-g++}"
CXXFLAGS="-std=c++17 -O2 -Wall -Wextra -Iinclude"
LDFLAGS="-pthread"
LOGDIR=tests/repeat_logs
mkdir -p "$LOGDIR"

SRV_CFG=tests/port_forward_udp_strict_server.json
PEER_CFG=tests/port_forward_udp_strict_peer.json

# listen → map
# to_remote: 19222/19223 → peer udp 19202/19203
# to_local:  19302/19303 → server-side udp 19212/19213

stop_all() {
  pkill -KILL -f "./server $SRV_CFG" 2>/dev/null || true
  pkill -KILL -f "./peer $PEER_CFG" 2>/dev/null || true
  pkill -KILL -f 'udp_echo 1920' 2>/dev/null || true
  pkill -KILL -f 'udp_echo 1921' 2>/dev/null || true
  sleep 0.3
}
trap stop_all EXIT

wait_udp_ready() {
  local deadline=$((SECONDS + 30))
  while (( SECONDS < deadline )); do
    if ./tests/udp_echo_client 127.0.0.1 19222 readyR >/dev/null 2>&1 && \
       ./tests/udp_echo_client 127.0.0.1 19302 readyL >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  echo READY_TIMEOUT
  tail -50 "$LOGDIR"/udp_strict_*.log 2>/dev/null || true
  return 1
}

echo "=== Build ==="
$CXX $CXXFLAGS src/server.cpp -o server $LDFLAGS
$CXX $CXXFLAGS src/peer.cpp -o peer $LDFLAGS
$CXX $CXXFLAGS tests/udp_echo.cpp -o tests/udp_echo $LDFLAGS
$CXX $CXXFLAGS tests/udp_echo_client.cpp -o tests/udp_echo_client $LDFLAGS
$CXX $CXXFLAGS tests/udp_strict_harness.cpp -o tests/udp_strict_harness $LDFLAGS
$CXX $CXXFLAGS tests/test_port_forward.cpp -o tests/test_port_forward $LDFLAGS
./tests/test_port_forward

stop_all
for p in 19202 19203 19212 19213; do
  ./tests/udp_echo "$p" >"$LOGDIR/udp_strict_echo_$p.log" 2>&1 &
done
sleep 0.2
./server "$SRV_CFG" >"$LOGDIR/udp_strict_server.log" 2>&1 &
echo $! >"$LOGDIR/udp_strict_server.pid"
sleep 0.4
./peer "$PEER_CFG" >"$LOGDIR/udp_strict_peer.log" 2>&1 &
echo $! >"$LOGDIR/udp_strict_peer.pid"
wait_udp_ready
echo "READY_OK"

echo "=== 1) Sequential new-socket rounds (to_remote / to_local) x120 ==="
./tests/udp_strict_harness seq 127.0.0.1 19222 120
./tests/udp_strict_harness seq 127.0.0.1 19223 60
./tests/udp_strict_harness seq 127.0.0.1 19302 120
./tests/udp_strict_harness seq 127.0.0.1 19303 60

echo "=== 2) Same-socket burst (session affinity) ==="
./tests/udp_strict_harness burst 127.0.0.1 19222 80
./tests/udp_strict_harness burst 127.0.0.1 19302 80

echo "=== 3) Concurrent multi-source clients ==="
./tests/udp_strict_harness conc 127.0.0.1 19222 12 30
./tests/udp_strict_harness conc 127.0.0.1 19302 12 30

echo "=== 4) Large payloads (2KB / 8KB) ==="
./tests/udp_strict_harness large 127.0.0.1 19222 2048
./tests/udp_strict_harness large 127.0.0.1 19302 2048
./tests/udp_strict_harness large 127.0.0.1 19222 8192
./tests/udp_strict_harness large 127.0.0.1 19302 8192

echo "=== 5) Idle expiry (udp_idle_sec=5, sleep 7) then reuse socket ==="
./tests/udp_strict_harness idle 127.0.0.1 19222 7
./tests/udp_strict_harness idle 127.0.0.1 19302 7

echo "=== 6) Interleaved remote/local UDP ==="
for i in $(seq 1 40); do
  ./tests/udp_echo_client 127.0.0.1 19222 "IR$i" >/dev/null
  ./tests/udp_echo_client 127.0.0.1 19302 "IL$i" >/dev/null
done
echo "interleaved OK"

echo "=== 7) Kill peer; restart; UDP recovers ==="
kill -KILL "$(cat "$LOGDIR/udp_strict_peer.pid")" 2>/dev/null || true
sleep 0.5
./peer "$PEER_CFG" >"$LOGDIR/udp_strict_peer2.log" 2>&1 &
echo $! >"$LOGDIR/udp_strict_peer.pid"
wait_udp_ready
./tests/udp_strict_harness seq 127.0.0.1 19222 20
./tests/udp_strict_harness seq 127.0.0.1 19302 20
./tests/udp_strict_harness burst 127.0.0.1 19222 20
echo "peer kill UDP recovery OK"

echo "=== 8) Kill server; restart; peer rebinds UDP ==="
kill -KILL "$(cat "$LOGDIR/udp_strict_server.pid")" 2>/dev/null || true
sleep 0.5
./server "$SRV_CFG" >"$LOGDIR/udp_strict_server2.log" 2>&1 &
echo $! >"$LOGDIR/udp_strict_server.pid"
wait_udp_ready
./tests/udp_strict_harness seq 127.0.0.1 19222 20
./tests/udp_strict_harness seq 127.0.0.1 19302 20
./tests/udp_strict_harness conc 127.0.0.1 19222 8 10
echo "server kill UDP recovery OK"

echo "ALL STRICT UDP PORT-FORWARD TESTS PASSED"
