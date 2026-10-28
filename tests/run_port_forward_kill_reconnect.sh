#!/usr/bin/env bash
# Kill peer or server mid-flight; forwarding must recover without dead-waiting.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CXX="${CXX:-g++}"
CXXFLAGS="-std=c++17 -O2 -Wall -Wextra -Iinclude"
LDFLAGS="-pthread"
LOGDIR=tests/repeat_logs
mkdir -p "$LOGDIR"

SRV_CFG=tests/port_forward_repeat_server.json
PEER_CFG=tests/port_forward_repeat_peer.json

stop_all() {
  pkill -KILL -f "./server $SRV_CFG" 2>/dev/null || true
  pkill -KILL -f "./peer $PEER_CFG" 2>/dev/null || true
  pkill -KILL -f 'tests/echo_server 19002' 2>/dev/null || true
  pkill -KILL -f 'tests/echo_server 19012' 2>/dev/null || true
  sleep 0.3
}
trap stop_all EXIT

wait_ready() {
  local deadline=$((SECONDS + 25))
  while (( SECONDS < deadline )); do
    if ./tests/tcp_echo_client 127.0.0.1 19022 ready >/dev/null 2>&1 && \
       ./tests/tcp_echo_client 127.0.0.1 19102 ready >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  echo "READY_TIMEOUT"
  tail -40 "$LOGDIR"/kr_*.log 2>/dev/null || true
  return 1
}

echo "=== Build ==="
$CXX $CXXFLAGS src/server.cpp -o server $LDFLAGS
$CXX $CXXFLAGS src/peer.cpp -o peer $LDFLAGS
$CXX $CXXFLAGS tests/echo_server.cpp -o tests/echo_server $LDFLAGS
$CXX $CXXFLAGS tests/tcp_echo_client.cpp -o tests/tcp_echo_client $LDFLAGS

stop_all
./tests/echo_server 19002 64 >"$LOGDIR/kr_echo_r.log" 2>&1 &
./tests/echo_server 19012 64 >"$LOGDIR/kr_echo_l.log" 2>&1 &
sleep 0.2
./server "$SRV_CFG" >"$LOGDIR/kr_server.log" 2>&1 &
echo $! >"$LOGDIR/kr_server.pid"
sleep 0.4
./peer "$PEER_CFG" >"$LOGDIR/kr_peer.log" 2>&1 &
echo $! >"$LOGDIR/kr_peer.pid"
wait_ready
echo "baseline OK"

echo "=== Kill peer mid-session; auto-reconnect ==="
./tests/tcp_echo_client 127.0.0.1 19022 before-peer-kill >/dev/null
kill -KILL "$(cat "$LOGDIR/kr_peer.pid")" 2>/dev/null || true
# peer worker_loop is gone with the process — restart peer like a supervisor would
sleep 0.5
./peer "$PEER_CFG" >"$LOGDIR/kr_peer2.log" 2>&1 &
echo $! >"$LOGDIR/kr_peer.pid"
wait_ready
for i in $(seq 1 20); do
  ./tests/tcp_echo_client 127.0.0.1 19022 "after-peer-$i" >/dev/null
done
echo "peer kill recovery OK"

echo "=== Kill server mid-session; peer reconnects to new server ==="
./tests/tcp_echo_client 127.0.0.1 19022 before-server-kill >/dev/null
kill -KILL "$(cat "$LOGDIR/kr_server.pid")" 2>/dev/null || true
sleep 0.5
./server "$SRV_CFG" >"$LOGDIR/kr_server2.log" 2>&1 &
echo $! >"$LOGDIR/kr_server.pid"
# Peer workers should reconnect within reconnect_ms + HELLO; bound the wait.
wait_ready
for i in $(seq 1 20); do
  ./tests/tcp_echo_client 127.0.0.1 19022 "after-server-$i" >/dev/null
  ./tests/tcp_echo_client 127.0.0.1 19102 "after-server-L$i" >/dev/null
done
echo "server kill recovery OK"

echo "=== Rapid kill/restart peer 5x ==="
for k in $(seq 1 5); do
  kill -KILL "$(cat "$LOGDIR/kr_peer.pid")" 2>/dev/null || true
  sleep 0.2
  ./peer "$PEER_CFG" >"$LOGDIR/kr_peer_r$k.log" 2>&1 &
  echo $! >"$LOGDIR/kr_peer.pid"
  wait_ready
  ./tests/tcp_echo_client 127.0.0.1 19022 "rapid-$k" >/dev/null
done
echo "rapid peer restart OK"

echo "ALL KILL/RECONNECT TESTS PASSED"
