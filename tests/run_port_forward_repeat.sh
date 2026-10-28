#!/usr/bin/env bash
# Regression: to_remote / to_local must survive many sequential connect/close cycles
# (SSH -R style: first session OK, later sessions must not reset / desync).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CXX="${CXX:-g++}"
CXXFLAGS="-std=c++17 -O2 -Wall -Wextra -Iinclude"
LDFLAGS="-pthread"
ROUNDS="${ROUNDS:-80}"
LOGDIR=tests/repeat_logs
mkdir -p "$LOGDIR"

stop_all() {
  pkill -TERM -f './server tests/port_forward_repeat_server.json' 2>/dev/null || true
  pkill -TERM -f './peer tests/port_forward_repeat_peer.json' 2>/dev/null || true
  pkill -TERM -f 'tests/echo_server 19002' 2>/dev/null || true
  pkill -TERM -f 'tests/echo_server 19012' 2>/dev/null || true
  sleep 0.3
  pkill -KILL -f './server tests/port_forward_repeat_server.json' 2>/dev/null || true
  pkill -KILL -f './peer tests/port_forward_repeat_peer.json' 2>/dev/null || true
  pkill -KILL -f 'tests/echo_server 19002' 2>/dev/null || true
  pkill -KILL -f 'tests/echo_server 19012' 2>/dev/null || true
  sleep 0.2
}
trap stop_all EXIT

echo "=== Build ==="
$CXX $CXXFLAGS src/server.cpp -o server $LDFLAGS
$CXX $CXXFLAGS src/peer.cpp -o peer $LDFLAGS
$CXX $CXXFLAGS tests/echo_server.cpp -o tests/echo_server $LDFLAGS
$CXX $CXXFLAGS tests/tcp_echo_client.cpp -o tests/tcp_echo_client $LDFLAGS
$CXX $CXXFLAGS tests/test_port_forward.cpp -o tests/test_port_forward $LDFLAGS
./tests/test_port_forward

stop_all
./tests/echo_server 19002 64 >"$LOGDIR/echo_remote_target.log" 2>&1 &
./tests/echo_server 19012 64 >"$LOGDIR/echo_local_target.log" 2>&1 &
sleep 0.2
./server tests/port_forward_repeat_server.json >"$LOGDIR/server.log" 2>&1 &
sleep 0.4
./peer tests/port_forward_repeat_peer.json >"$LOGDIR/peer.log" 2>&1 &

ready=0
for _ in $(seq 1 50); do
  if ./tests/tcp_echo_client 127.0.0.1 19022 ping >/dev/null 2>&1 && \
     ./tests/tcp_echo_client 127.0.0.1 19102 ping >/dev/null 2>&1; then
    ready=1
    break
  fi
  sleep 0.2
done
[[ "$ready" == 1 ]] || { echo READY_FAIL; tail -40 "$LOGDIR"/*.log; exit 1; }
echo READY_OK

echo "=== Sequential to_remote (ssh -R) x$ROUNDS ==="
for i in $(seq 1 "$ROUNDS"); do
  payload="R${i}-$(printf '%04d' "$i")-ABCDEFG"
  out=$(./tests/tcp_echo_client 127.0.0.1 19022 "$payload" 2>&1) || {
    echo "FAIL to_remote round $i: $out"
    tail -60 "$LOGDIR/server.log" "$LOGDIR/peer.log"
    exit 1
  }
  echo "$out" | grep -q "TCP_OK" || {
    echo "FAIL to_remote round $i unexpected: $out"
    exit 1
  }
done
echo "to_remote OK ($ROUNDS)"

echo "=== Sequential to_local (ssh -L) x$ROUNDS ==="
for i in $(seq 1 "$ROUNDS"); do
  payload="L${i}-$(printf '%04d' "$i")-XYZ"
  out=$(./tests/tcp_echo_client 127.0.0.1 19102 "$payload" 2>&1) || {
    echo "FAIL to_local round $i: $out"
    tail -60 "$LOGDIR/server.log" "$LOGDIR/peer.log"
    exit 1
  }
  echo "$out" | grep -q "TCP_OK" || {
    echo "FAIL to_local round $i unexpected: $out"
    exit 1
  }
done
echo "to_local OK ($ROUNDS)"

echo "=== Interleaved remote/local x40 ==="
for i in $(seq 1 40); do
  ./tests/tcp_echo_client 127.0.0.1 19022 "IR$i" >/dev/null
  ./tests/tcp_echo_client 127.0.0.1 19102 "IL$i" >/dev/null
done
echo "interleaved OK"

echo "ALL REPEAT PORT-FORWARD TESTS PASSED"
