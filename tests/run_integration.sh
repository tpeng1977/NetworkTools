#!/usr/bin/env bash
# Integration test suite for Linux / macOS.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

./build.sh all

EXE=""
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*) EXE=".exe" ;;
esac

stop_procs() {
  pkill -f "./server${EXE}" 2>/dev/null || true
  pkill -f "./client${EXE}" 2>/dev/null || true
  pkill -f "echo_server${EXE}" 2>/dev/null || true
  sleep 0.4
}

stop_procs

echo "=== Unit tests ==="
"./tests/test_core${EXE}"

echo "=== Start echo / server / client ==="
"./tests/echo_server${EXE}" 19080 >/tmp/vortex_echo.log 2>&1 &
ECHO_PID=$!
"./server${EXE}" config/server.json >/tmp/vortex_srv.log 2>&1 &
SRV_PID=$!
sleep 1
"./client${EXE}" config/client.json >/tmp/vortex_cli.log 2>&1 &
CLI_PID=$!
sleep 1

cleanup() {
  kill "$ECHO_PID" "$SRV_PID" "$CLI_PID" 2>/dev/null || true
  stop_procs
}
trap cleanup EXIT

echo "=== SOCKS5 HTTP GET ==="
"./tests/socks5_http_get${EXE}" 11080 19080 127.0.0.1

echo "=== Anti-probe ==="
"./tests/probe_test${EXE}" 18888

echo "=== Wrong secret ==="
"./tests/wrong_secret_test${EXE}" 18888

echo "=== Binary echo (IPv4) ==="
"./tests/binary_echo_test${EXE}" 11080 19080

echo "=== Stress 20x10 ==="
"./tests/stress_test${EXE}" 20 10 11080 19080

echo "=== Sustained 15s burst ==="
deadline=$((SECONDS + 15))
loops=0
while (( SECONDS < deadline )); do
  "./tests/socks5_http_get${EXE}" 11080 19080 127.0.0.1 >/dev/null
  loops=$((loops + 1))
done
echo "Sustained OK loops=$loops"

echo ""
echo "ALL INTEGRATION TESTS PASSED"
