#!/usr/bin/env bash
# Build Vortex Shield on Linux / macOS / WSL / MSYS2.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

detect_cxx() {
  if [[ -n "${CXX:-}" ]]; then
    echo "$CXX"
    return
  fi
  if command -v clang++ >/dev/null 2>&1; then
    # Prefer clang++ on macOS; also fine on Linux.
    if [[ "$(uname -s)" == "Darwin" ]]; then
      echo "clang++"
      return
    fi
  fi
  if command -v g++ >/dev/null 2>&1; then
    echo "g++"
    return
  fi
  if command -v clang++ >/dev/null 2>&1; then
    echo "clang++"
    return
  fi
  echo "ERROR: no C++17 compiler found (need g++ or clang++)" >&2
  exit 1
}

CXX="$(detect_cxx)"
CXXFLAGS="-std=c++17 -O2 -Wall -Wextra -Iinclude"
LDFLAGS=""

uname_s="$(uname -s 2>/dev/null || echo Unknown)"
case "$uname_s" in
  MINGW*|MSYS*|CYGWIN*)
    LDFLAGS="-lws2_32"
    EXE=".exe"
    ;;
  *)
    LDFLAGS="-pthread"
    EXE=""
    ;;
esac

echo "[BUILD] platform=$uname_s compiler=$CXX"
echo "[BUILD] server..."
$CXX $CXXFLAGS src/server.cpp -o "server${EXE}" $LDFLAGS
echo "[BUILD] client..."
$CXX $CXXFLAGS src/client.cpp -o "client${EXE}" $LDFLAGS
echo "[BUILD] smartlink..."
SMART_LIBS=""
case "$uname_s" in
  MINGW*|MSYS*|CYGWIN*) SMART_LIBS="-liphlpapi" ;;
esac
$CXX $CXXFLAGS src/smartlink.cpp -o "smartlink${EXE}" $LDFLAGS $SMART_LIBS
echo "[BUILD] multilink..."
$CXX $CXXFLAGS src/multilink.cpp -o "multilink${EXE}" $LDFLAGS $SMART_LIBS
echo "[BUILD] local..."
$CXX $CXXFLAGS src/local.cpp -o "local${EXE}" $LDFLAGS
echo "[BUILD] peer..."
$CXX $CXXFLAGS src/peer.cpp -o "peer${EXE}" $LDFLAGS

case "$uname_s" in
  MINGW*|MSYS*|CYGWIN*)
    echo "[BUILD] ap2socks5..."
    $CXX $CXXFLAGS src/ap2socks5.cpp -o "ap2socks5${EXE}" $LDFLAGS -liphlpapi
    ;;
esac

if [[ "${1:-}" == "test" || "${1:-}" == "all" ]]; then
  echo "[BUILD] unit test..."
  $CXX $CXXFLAGS tests/test_core.cpp -o "tests/test_core${EXE}" $LDFLAGS
  $CXX $CXXFLAGS tests/test_packet_build.cpp -o "tests/test_packet_build${EXE}"
  $CXX $CXXFLAGS tests/test_rules.cpp -o "tests/test_rules${EXE}" $LDFLAGS
  $CXX $CXXFLAGS tests/test_multilink.cpp -o "tests/test_multilink${EXE}" $LDFLAGS
  $CXX $CXXFLAGS tests/test_peer_protocol.cpp -o "tests/test_peer_protocol${EXE}" $LDFLAGS
  echo "[TEST] running unit tests..."
  "./tests/test_core${EXE}"
  "./tests/test_packet_build${EXE}"
  "./tests/test_rules${EXE}"
  "./tests/test_multilink${EXE}"
  "./tests/test_peer_protocol${EXE}"
fi

if [[ "${1:-}" == "all" ]]; then
  for t in echo_server socks5_http_get probe_test wrong_secret_test binary_echo_test stress_test; do
    echo "[BUILD] tests/${t}..."
    $CXX $CXXFLAGS "tests/${t}.cpp" -o "tests/${t}${EXE}" $LDFLAGS
  done
fi

echo "[BUILD] OK"
echo "  ./server${EXE} config/server.json"
echo "  ./client${EXE} config/client.json"
echo "  ./smartlink${EXE} config/smartlink.json"
echo "  ./multilink${EXE} config/multilink.json"
echo "  ./local${EXE} config/local.json"
case "$uname_s" in
  MINGW*|MSYS*|CYGWIN*) echo "  ./ap2socks5${EXE} config/ap2socks5.json" ;;
esac
