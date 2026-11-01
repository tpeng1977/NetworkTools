#!/usr/bin/env bash
# Dual-stack soak: concurrent short connections for DURATION_SEC (default 1800).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

DURATION_SEC="${DURATION_SEC:-1800}"
WORKERS="${WORKERS:-16}"
CXX="${CXX:-g++}"
CXXFLAGS="-std=c++17 -O2 -Wall -Wextra -Iinclude"
LDFLAGS="-pthread"
LOGDIR=tests/dualstack/logs
mkdir -p "$LOGDIR"
PIDFILE="$LOGDIR/soak_pids.txt"

stop_stack() {
  if [[ -f "$PIDFILE" ]]; then
    while read -r p; do
      [[ -n "${p:-}" ]] && kill -TERM "$p" 2>/dev/null || true
    done <"$PIDFILE" || true
    sleep 0.5
    while read -r p; do
      [[ -n "${p:-}" ]] && kill -KILL "$p" 2>/dev/null || true
    done <"$PIDFILE" || true
    rm -f "$PIDFILE"
  fi
  pkill -KILL -f 'tests/dualstack/server.json' 2>/dev/null || true
  pkill -KILL -f 'tests/dualstack/client_dual.json' 2>/dev/null || true
  pkill -KILL -f 'tests/dualstack/multilink.json' 2>/dev/null || true
  pkill -KILL -f 'tests/dualstack/smartlink.json' 2>/dev/null || true
  pkill -KILL -f 'tests/dualstack/peer.json' 2>/dev/null || true
  pkill -KILL -f 'echo_server 29080' 2>/dev/null || true
  pkill -KILL -f 'dualstack_soak_worker' 2>/dev/null || true
  sleep 0.3
}
record_pid() { echo "$1" >>"$PIDFILE"; }

alive_or_die() {
  pgrep -f 'echo_server 29080' >/dev/null || { echo "FATAL echo_server"; return 1; }
  pgrep -f 'server tests/dualstack/server.json' >/dev/null || { echo "FATAL server"; return 1; }
  pgrep -f 'client tests/dualstack/client_dual.json' >/dev/null || { echo "FATAL client"; return 1; }
  pgrep -f 'multilink tests/dualstack/multilink.json' >/dev/null || { echo "FATAL multilink"; return 1; }
  return 0
}

echo "=== Build ==="
$CXX $CXXFLAGS src/server.cpp -o server $LDFLAGS
$CXX $CXXFLAGS src/client.cpp -o client $LDFLAGS
$CXX $CXXFLAGS src/multilink.cpp -o multilink $LDFLAGS
$CXX $CXXFLAGS src/smartlink.cpp -o smartlink $LDFLAGS
$CXX $CXXFLAGS src/peer.cpp -o peer $LDFLAGS
$CXX $CXXFLAGS tests/echo_server.cpp -o tests/echo_server $LDFLAGS
$CXX $CXXFLAGS tests/socks5_dualstack_get.cpp -o tests/socks5_dualstack_get $LDFLAGS
$CXX $CXXFLAGS tests/dualstack_soak_worker.cpp -o tests/dualstack_soak_worker $LDFLAGS

stop_stack
: >"$LOGDIR/soak_monitor.log"
: >"$LOGDIR/soak_errors.log"
: >"$PIDFILE"

# Bounded worker pool (arg2=workers).
./tests/echo_server 29080 128 :: >"$LOGDIR/soak_echo.log" 2>&1 &
record_pid $!
./server tests/dualstack/server.json >"$LOGDIR/soak_srv.log" 2>&1 &
record_pid $!
sleep 0.6
./client tests/dualstack/client_dual.json >"$LOGDIR/soak_cli.log" 2>&1 &
record_pid $!
./multilink tests/dualstack/multilink.json >"$LOGDIR/soak_ml.log" 2>&1 &
record_pid $!
./smartlink tests/dualstack/smartlink.json >"$LOGDIR/soak_sl.log" 2>&1 &
record_pid $!
./peer tests/dualstack/peer.json >"$LOGDIR/soak_peer.log" 2>&1 &
record_pid $!
sleep 1.0

if ! alive_or_die; then
  echo "stack failed to start"
  stop_stack
  exit 1
fi

echo "=== Soak ${DURATION_SEC}s with ${WORKERS} workers ==="
START=$(date +%s)
LAST_MON_AT=-30
./tests/dualstack_soak_worker "$DURATION_SEC" "$WORKERS" \
  >"$LOGDIR/soak_worker.out" 2>"$LOGDIR/soak_errors.log" &
WPID=$!
record_pid "$WPID"

while kill -0 "$WPID" 2>/dev/null; do
  now=$(date +%s)
  elapsed=$((now - START))
  if ! alive_or_die; then
    kill "$WPID" 2>/dev/null || true
    wait "$WPID" 2>/dev/null || true
    errs=$(wc -l <"$LOGDIR/soak_errors.log" | tr -d ' ')
    echo "Component died at ${elapsed}s errors=${errs}"
    tail -n 40 "$LOGDIR/soak_echo.log" "$LOGDIR/soak_srv.log" "$LOGDIR/soak_cli.log" 2>/dev/null || true
    stop_stack
    exit 1
  fi
  if (( elapsed >= LAST_MON_AT + 30 )); then
    errs=$(wc -l <"$LOGDIR/soak_errors.log" | tr -d ' ')
    echo "[mon] t=${elapsed}s errors=$errs" | tee -a "$LOGDIR/soak_monitor.log"
    LAST_MON_AT=$elapsed
  fi
  sleep 2
done

wait "$WPID"
WEC=$?
errs=$(wc -l <"$LOGDIR/soak_errors.log" | tr -d ' ')
ok_line=$(tail -5 "$LOGDIR/soak_worker.out" || true)
echo "worker_exit=$WEC errors=$errs"
echo "$ok_line"

if ! alive_or_die; then
  stop_stack
  exit 1
fi
stop_stack

if [[ "$WEC" -ne 0 || "$errs" -ne 0 ]]; then
  echo "=== Dual-stack soak FAILED (errors=$errs) ==="
  exit 1
fi
echo "=== Dual-stack soak PASSED duration=${DURATION_SEC}s errors=0 ==="
