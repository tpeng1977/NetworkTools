#!/usr/bin/env bash
# ≥30min aggressive soak for to_remote / to_local TCP+UDP port forwards.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DURATION_SEC="${DURATION_SEC:-1800}"
THREADS="${THREADS:-20}"
PEER_RESTART_EVERY_SEC="${PEER_RESTART_EVERY_SEC:-480}"
CXX="${CXX:-g++}"
CXXFLAGS="-std=c++17 -O2 -Wall -Wextra -Iinclude"
LDFLAGS="-pthread"

SRV_CFG=tests/port_forward_soak7_server.json
PEER_CFG=tests/port_forward_soak7_peer.json
LOGDIR=tests/soak_logs
mkdir -p "$LOGDIR"

stop_stack() {
  pkill -TERM -f 'tests/port_forward_soak7_server.json' 2>/dev/null || true
  pkill -TERM -f 'tests/port_forward_soak7_peer.json' 2>/dev/null || true
  pkill -TERM -f 'tests/port_forward_soak ' 2>/dev/null || true
  pkill -TERM -f 'tests/echo_server 108' 2>/dev/null || true
  pkill -TERM -f 'tests/udp_echo 108' 2>/dev/null || true
  sleep 0.5
  pkill -KILL -f 'tests/port_forward_soak7_server.json' 2>/dev/null || true
  pkill -KILL -f 'tests/port_forward_soak7_peer.json' 2>/dev/null || true
  pkill -KILL -f 'tests/port_forward_soak ' 2>/dev/null || true
  pkill -KILL -f 'tests/echo_server 108' 2>/dev/null || true
  pkill -KILL -f 'tests/udp_echo 108' 2>/dev/null || true
  sleep 0.3
}

fd_snapshot() {
  local label="$1"
  local spid ppid
  spid=$(pgrep -f './server tests/port_forward_soak7_server.json' | head -1 || true)
  ppid=$(pgrep -f './peer tests/port_forward_soak7_peer.json' | head -1 || true)
  local sfd=0 pfd=0
  if [[ -n "${spid:-}" && -d "/proc/$spid/fd" ]]; then sfd=$(ls "/proc/$spid/fd" 2>/dev/null | wc -l | tr -d ' '); fi
  if [[ -n "${ppid:-}" && -d "/proc/$ppid/fd" ]]; then pfd=$(ls "/proc/$ppid/fd" 2>/dev/null | wc -l | tr -d ' '); fi
  echo "[mon] $label server_pid=${spid:--} fds=$sfd peer_pid=${ppid:--} fds=$pfd" | tee -a "$LOGDIR/monitor.log"
}

alive_or_die() {
  if ! pgrep -f './server tests/port_forward_soak7_server.json' >/dev/null; then
    echo "FATAL: server died"; tail -80 "$LOGDIR/srv.log" || true; return 1
  fi
  if ! pgrep -f './peer tests/port_forward_soak7_peer.json' >/dev/null; then
    echo "FATAL: peer died"; tail -80 "$LOGDIR/peer.log" || true; return 1
  fi
  return 0
}

wait_ready() {
  for _ in $(seq 1 60); do
    if ./tests/tcp_echo_client 127.0.0.1 10888 SOAK_READY >/dev/null 2>&1 &&
       ./tests/tcp_echo_client 127.0.0.1 10900 SOAK_READY_L >/dev/null 2>&1 &&
       ./tests/udp_echo_client 127.0.0.1 10888 SOAK_READY_UR >/dev/null 2>&1 &&
       ./tests/udp_echo_client 127.0.0.1 10900 SOAK_READY_UL >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.25
  done
  echo "stack not ready"; tail -40 "$LOGDIR/srv.log" || true; tail -40 "$LOGDIR/peer.log" || true; return 1
}

start_echoes() {
  for p in 10800 10801 10802 10803 10804 10810 10811 10812 10813 10814; do
    ./tests/echo_server "$p" 512 >"$LOGDIR/echo_tcp_$p.log" 2>&1 &
    ./tests/udp_echo "$p" >"$LOGDIR/echo_udp_$p.log" 2>&1 &
  done
}

start_stack() {
  ./server "$SRV_CFG" >"$LOGDIR/srv.log" 2>&1 &
  sleep 0.5
  ./peer "$PEER_CFG" >"$LOGDIR/peer.log" 2>&1 &
  sleep 1.5
}

restart_peer() {
  echo "[*] peer restart at $(date -Is)" | tee -a "$LOGDIR/monitor.log"
  pkill -TERM -f './peer tests/port_forward_soak7_peer.json' 2>/dev/null || true
  sleep 1.0
  pkill -KILL -f './peer tests/port_forward_soak7_peer.json' 2>/dev/null || true
  sleep 0.3
  ./peer "$PEER_CFG" >"$LOGDIR/peer.log" 2>&1 &
  wait_ready || true
  fd_snapshot "after_peer_restart"
}

echo "=== Build soak binaries ==="
$CXX $CXXFLAGS src/server.cpp -o server $LDFLAGS
$CXX $CXXFLAGS src/peer.cpp -o peer $LDFLAGS
$CXX $CXXFLAGS tests/echo_server.cpp -o tests/echo_server $LDFLAGS
$CXX $CXXFLAGS tests/udp_echo.cpp -o tests/udp_echo $LDFLAGS
$CXX $CXXFLAGS tests/tcp_echo_client.cpp -o tests/tcp_echo_client $LDFLAGS
$CXX $CXXFLAGS tests/udp_echo_client.cpp -o tests/udp_echo_client $LDFLAGS
$CXX $CXXFLAGS tests/port_forward_soak.cpp -o tests/port_forward_soak $LDFLAGS
$CXX $CXXFLAGS tests/test_port_forward.cpp -o tests/test_port_forward $LDFLAGS
./tests/test_port_forward

stop_stack
rm -f "$LOGDIR"/*.log
start_echoes
start_stack
trap 'stop_stack' EXIT

alive_or_die
wait_ready
fd_snapshot "start"
START_LINE=$(grep '\[mon\] start' "$LOGDIR/monitor.log" | tail -1)
START_SRV_FD=$(echo "$START_LINE" | sed -n 's/.*server_pid=[^ ]* fds=\([0-9]*\).*/\1/p')
START_PEER_FD=$(echo "$START_LINE" | sed -n 's/.*peer_pid=[^ ]* fds=\([0-9]*\).*/\1/p')

echo "=== Soak DURATION_SEC=$DURATION_SEC THREADS=$THREADS PEER_RESTART_EVERY_SEC=$PEER_RESTART_EVERY_SEC ==="
./tests/port_forward_soak "$DURATION_SEC" "$THREADS" | tee "$LOGDIR/soak.log" &
SOAK_PID=$!
SOAK_START=$(date +%s)
NEXT_RESTART=$((SOAK_START + PEER_RESTART_EVERY_SEC))
RC=0
while kill -0 "$SOAK_PID" 2>/dev/null; do
  now=$(date +%s)
  if ! alive_or_die; then kill -TERM "$SOAK_PID" 2>/dev/null || true; RC=1; break; fi
  if (( now >= NEXT_RESTART )); then restart_peer; NEXT_RESTART=$((now + PEER_RESTART_EVERY_SEC)); fi
  if (( (now - SOAK_START) % 60 < 3 )); then fd_snapshot "t=$((now - SOAK_START))s"; fi
  sleep 2
done
wait "$SOAK_PID" || RC=$?
SOAK_END=$(date +%s)
ELAPSED=$((SOAK_END - SOAK_START))
fd_snapshot "end"
END_LINE=$(grep '\[mon\] end' "$LOGDIR/monitor.log" | tail -1)
END_SRV_FD=$(echo "$END_LINE" | sed -n 's/.*server_pid=[^ ]* fds=\([0-9]*\).*/\1/p')
END_PEER_FD=$(echo "$END_LINE" | sed -n 's/.*peer_pid=[^ ]* fds=\([0-9]*\).*/\1/p')
echo ""
echo "=== Soak wall-clock ${ELAPSED}s (target ${DURATION_SEC}s) exit=$RC ==="
echo "FD start server=${START_SRV_FD:-?} peer=${START_PEER_FD:-?} end server=${END_SRV_FD:-?} peer=${END_PEER_FD:-?}"
tail -20 "$LOGDIR/soak.log" || true
sleep 2
fd_snapshot "post_drain"
if (( ELAPSED + 5 < DURATION_SEC )); then echo "FAIL: soak ended early"; exit 1; fi
if (( RC != 0 )); then echo "FAIL: soak binary returned $RC"; exit "$RC"; fi
echo "PORT FORWARD SOAK SCRIPT PASSED"
exit 0
