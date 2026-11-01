#!/usr/bin/env bash
# Dual-stack e2e: IPv4-only / IPv6-only / dual IPv6-prefer for client/multilink/smartlink/peer.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

CXX="${CXX:-g++}"
CXXFLAGS="-std=c++17 -O2 -Wall -Wextra -Iinclude"
LDFLAGS="-pthread"
LOGDIR=tests/dualstack/logs
mkdir -p "$LOGDIR"

PIDDIR=tests/dualstack/logs
stop_stack() {
  if [[ -f "$PIDDIR/pids.txt" ]]; then
    while read -r p; do
      [[ -n "$p" ]] && kill -TERM "$p" 2>/dev/null || true
    done <"$PIDDIR/pids.txt"
    sleep 0.4
    while read -r p; do
      [[ -n "$p" ]] && kill -KILL "$p" 2>/dev/null || true
    done <"$PIDDIR/pids.txt"
    rm -f "$PIDDIR/pids.txt"
  fi
  pkill -KILL -f 'tests/dualstack/server.json' 2>/dev/null || true
  pkill -KILL -f 'tests/dualstack/client_' 2>/dev/null || true
  pkill -KILL -f 'tests/dualstack/peer.json' 2>/dev/null || true
  pkill -KILL -f 'tests/dualstack/multilink.json' 2>/dev/null || true
  pkill -KILL -f 'tests/dualstack/smartlink.json' 2>/dev/null || true
  pkill -KILL -f 'echo_server 29080' 2>/dev/null || true
  pkill -KILL -f 'echo_server 29081' 2>/dev/null || true
  pkill -KILL -f 'echo_server 29082' 2>/dev/null || true
  pkill -KILL -f 'dualstack_soak_worker' 2>/dev/null || true
  pkill -KILL -f 'dns_tcp_stub' 2>/dev/null || true
  pkill -KILL -f 'linux_network --router-only' 2>/dev/null || true
  pkill -KILL -f 'tests/dualstack/multilink_fallback.json' 2>/dev/null || true
  sleep 0.3
}
record_pid() { echo "$1" >>"$PIDDIR/pids.txt"; }

fail() { echo "FAIL: $*"; stop_stack; exit 1; }
pass() { echo "PASS: $*"; }

echo "=== Build dual-stack binaries ==="
$CXX $CXXFLAGS src/server.cpp -o server $LDFLAGS
$CXX $CXXFLAGS src/client.cpp -o client $LDFLAGS
$CXX $CXXFLAGS src/peer.cpp -o peer $LDFLAGS
$CXX $CXXFLAGS src/multilink.cpp -o multilink $LDFLAGS
$CXX $CXXFLAGS src/smartlink.cpp -o smartlink $LDFLAGS
$CXX $CXXFLAGS tests/echo_server.cpp -o tests/echo_server $LDFLAGS
$CXX $CXXFLAGS tests/socks5_dualstack_get.cpp -o tests/socks5_dualstack_get $LDFLAGS
$CXX $CXXFLAGS tests/socks5_dns_dual_get.cpp -o tests/socks5_dns_dual_get $LDFLAGS
$CXX $CXXFLAGS tests/dns_tcp_stub.cpp -o tests/dns_tcp_stub $LDFLAGS
$CXX $CXXFLAGS tests/test_dualstack_unit.cpp -o tests/test_dualstack_unit $LDFLAGS
# linux_network is Linux-only (iptables); skip build on other platforms.
if [[ "$(uname -s)" == "Linux" ]]; then
  $CXX $CXXFLAGS src/linux_network.cpp -o linux_network $LDFLAGS
fi

echo "=== Unit: dual-stack ==="
./tests/test_dualstack_unit || fail "unit tests"

stop_stack
rm -f "$LOGDIR"/*.log

echo "=== Start echo (dual-stack ::) + server (::) ==="
: >"$LOGDIR/pids.txt"
./tests/echo_server 29080 64 :: >"$LOGDIR/echo.log" 2>&1 &
record_pid $!
./server tests/dualstack/server.json >"$LOGDIR/srv.log" 2>&1 &
record_pid $!
sleep 0.8
pgrep -f 'server tests/dualstack/server.json' >/dev/null || fail "server not up"
# Confirm server accepts both families.
python3 - <<'PY' || fail "server not dual-stack reachable"
import socket,sys
ok=0
for fam,host in [(socket.AF_INET,'127.0.0.1'),(socket.AF_INET6,'::1')]:
    s=socket.socket(fam,socket.SOCK_STREAM)
    s.settimeout(2)
    try:
        s.connect((host,28888))
        ok+=1
    except Exception as e:
        print('connect fail',host,e); sys.exit(1)
    finally:
        s.close()
print('server dual ok',ok)
PY
pass "server dual-stack listen"

echo "=== Start clients (dual / v4 / v6) + multilink + smartlink + peer ==="
./client tests/dualstack/client_dual.json >"$LOGDIR/cli_dual.log" 2>&1 &
record_pid $!
./client tests/dualstack/client_v4.json >"$LOGDIR/cli_v4.log" 2>&1 &
record_pid $!
./client tests/dualstack/client_v6.json >"$LOGDIR/cli_v6.log" 2>&1 &
record_pid $!
./multilink tests/dualstack/multilink.json >"$LOGDIR/ml.log" 2>&1 &
record_pid $!
./smartlink tests/dualstack/smartlink.json >"$LOGDIR/sl.log" 2>&1 &
record_pid $!
./peer tests/dualstack/peer.json >"$LOGDIR/peer.log" 2>&1 &
record_pid $!
sleep 1.2

# Verify client dual prefers IPv6 uplink (log line).
grep -q '\[::1\]:28888' "$LOGDIR/cli_dual.log" || grep -q '::1:28888\|\[::1\]' "$LOGDIR/cli_dual.log" \
  || fail "client_dual did not log IPv6-prefer uplink"
pass "client dual IPv6-prefer log"

echo "=== SOCKS via dual client: domain / IPv4 / IPv6 targets ==="
# SOCKS listener is dual (::); dial SOCKS over IPv4 and IPv6.
./tests/socks5_dualstack_get 127.0.0.1 21080 127.0.0.1 29080 || fail "dual SOCKS IPv4 target via v4 socks"
./tests/socks5_dualstack_get 127.0.0.1 21080 ::1 29080 || fail "dual SOCKS IPv6 target via v4 socks"
./tests/socks5_dualstack_get ::1 21080 127.0.0.1 29080 || fail "dual SOCKS IPv4 target via v6 socks"
./tests/socks5_dualstack_get ::1 21080 ::1 29080 || fail "dual SOCKS IPv6 target via v6 socks"
pass "dual client SOCKS CONNECT (v4/v6 socks × v4/v6 targets)"

echo "=== SOCKS via IPv4-only / IPv6-only clients ==="
./tests/socks5_dualstack_get 127.0.0.1 21081 127.0.0.1 29080 || fail "v4 client"
./tests/socks5_dualstack_get ::1 21082 ::1 29080 || fail "v6 client"
pass "v4-only and v6-only clients"

echo "=== MultiLink rules: DIRECT loopback v4/v6 ==="
./tests/socks5_dualstack_get 127.0.0.1 21090 127.0.0.1 29080 || fail "ml DIRECT v4"
./tests/socks5_dualstack_get ::1 21090 ::1 29080 || fail "ml DIRECT v6"
grep -qi 'Peer online' "$LOGDIR/srv.log" || fail "peer did not register"
pass "multilink DIRECT v4/v6 + peer registered"

echo "=== MultiLink PROXY tunnel (MATCH→Vortex) IPv4/IPv6 targets ==="
./multilink tests/dualstack/multilink_proxy.json >"$LOGDIR/ml_proxy.log" 2>&1 &
record_pid $!
sleep 0.6
./tests/socks5_dualstack_get 127.0.0.1 21092 127.0.0.1 29080 || fail "ml PROXY v4"
./tests/socks5_dualstack_get 127.0.0.1 21092 ::1 29080 || fail "ml PROXY v6"
pass "multilink PROXY tunnel v4/v6"

echo "=== MultiLink uplink dead-IPv6 → live-IPv4 fallback ==="
./multilink tests/dualstack/multilink_fallback.json >"$LOGDIR/ml_fallback.log" 2>&1 &
record_pid $!
# Allow IPv6 connect timeout then IPv4 success (per-host cap ≤5s).
sleep 6
./tests/socks5_dualstack_get 127.0.0.1 21093 127.0.0.1 29080 || fail "ml fallback CONNECT"
grep -q 'uplink fallback' "$LOGDIR/ml_fallback.log" || fail "missing uplink fallback log"
grep -Eq 'failed=\[fd00::dead:beef\(v6\)\].*ok=127\.0\.0\.1:28888\(v4\)' "$LOGDIR/ml_fallback.log" \
  || fail "fallback log did not distinguish v6 fail / v4 ok"
pass "multilink uplink IPv6→IPv4 fallback + log"

echo "=== DNS A+AAAA via MultiLink DIRECT and PROXY ==="
./tests/dns_tcp_stub 15353 127.0.0.1 >"$LOGDIR/dns_stub.log" 2>&1 &
record_pid $!
sleep 0.3
# DIRECT by queried name (direct-dns.test); SOCKS target is the stub.
./tests/socks5_dns_dual_get 21090 15353 127.0.0.1 direct-dns.test || fail "DNS DIRECT A+AAAA"
# PROXY by queried name (proxy-dns.test); tunnel to stub via Vortex.
./tests/socks5_dns_dual_get 21090 15353 127.0.0.1 proxy-dns.test || fail "DNS PROXY A+AAAA"
# Also via MATCH→PROXY multilink on 21092.
./tests/socks5_dns_dual_get 21092 15353 127.0.0.1 anything.test || fail "DNS PROXY-all A+AAAA"
pass "DNS A+AAAA DIRECT + PROXY"

echo "=== SmartLink DIRECT loopback ==="
./tests/socks5_dualstack_get ::1 21091 ::1 29080 || fail "smartlink DIRECT v6"
./tests/socks5_dualstack_get ::1 21091 127.0.0.1 29080 || fail "smartlink DIRECT v4"
pass "smartlink DIRECT"

if [[ "$(uname -s)" == "Linux" && -x ./linux_network ]]; then
  echo "=== linux_network --router-only DIRECT IPv6 prefer + IPv4 fallback ==="
  # Prefer: AAAA=::1 with listener; A=127.0.0.1 with NO listener on this port.
  ./tests/echo_server 29081 16 ::1 >"$LOGDIR/ln_echo_v6.log" 2>&1 &
  record_pid $!
  # Fallback: dead ULA AAAA; live A on 127.0.0.1.
  ./tests/echo_server 29082 16 127.0.0.1 >"$LOGDIR/ln_echo_v4.log" 2>&1 &
  record_pid $!
  ./tests/dns_tcp_stub 15410 127.0.0.1 127.0.0.1 ::1 >"$LOGDIR/ln_dns_prefer.log" 2>&1 &
  record_pid $!
  ./tests/dns_tcp_stub 15411 127.0.0.1 127.0.0.1 fd00::dead:beef >"$LOGDIR/ln_dns_fallback.log" 2>&1 &
  record_pid $!
  sleep 0.4
  VORTEX_DIRECT_DNS=127.0.0.1 VORTEX_DIRECT_DNS_PORT=15410 \
    ./linux_network --router-only tests/dualstack/linux_network.json >"$LOGDIR/ln.log" 2>&1 &
  record_pid $!
  sleep 0.8
  pgrep -f 'linux_network --router-only' >/dev/null || fail "linux_network router-only not up"
  ./tests/socks5_dualstack_get 127.0.0.1 21094 ::1 29080 || fail "ln DIRECT IPv6 literal"
  ./tests/socks5_dualstack_get 127.0.0.1 21094 127.0.0.1 29080 || fail "ln DIRECT IPv4 literal"
  # Domain → marked dual-stack resolve; only ::1 listens on 29081 → must use IPv6.
  ./tests/socks5_dualstack_get 127.0.0.1 21094 prefer-v6.test 29081 || fail "ln DIRECT domain IPv6 prefer"
  # Restart router with fallback stub (dead AAAA → live A).
  pkill -TERM -f 'linux_network --router-only' 2>/dev/null || true
  sleep 0.5
  VORTEX_DIRECT_DNS=127.0.0.1 VORTEX_DIRECT_DNS_PORT=15411 \
    ./linux_network --router-only tests/dualstack/linux_network.json >"$LOGDIR/ln_fb.log" 2>&1 &
  record_pid $!
  sleep 0.8
  ./tests/socks5_dualstack_get 127.0.0.1 21094 fallback-v4.test 29082 || fail "ln DIRECT domain IPv4 fallback"
  pass "linux_network --router-only DIRECT IPv6 prefer + IPv4 fallback"
fi

echo "=== Concurrent burst (50 short connects) ==="
fail_n=0
for i in $(seq 1 50); do
  ./tests/socks5_dualstack_get 127.0.0.1 21080 127.0.0.1 29080 >/dev/null || fail_n=$((fail_n+1))
  ./tests/socks5_dualstack_get ::1 21080 ::1 29080 >/dev/null || fail_n=$((fail_n+1))
done
[[ "$fail_n" -eq 0 ]] || fail "burst failures=$fail_n"
pass "50×2 short connects"

echo "=== Parallel hammer (20 concurrent) ==="
pids=()
for i in $(seq 1 20); do
  (
    ./tests/socks5_dualstack_get 127.0.0.1 21080 ::1 29080 >/dev/null
    ./tests/socks5_dualstack_get ::1 21090 127.0.0.1 29080 >/dev/null
  ) &
  pids+=($!)
done
ham_fail=0
for p in "${pids[@]}"; do
  wait "$p" || ham_fail=$((ham_fail+1))
done
[[ "$ham_fail" -eq 0 ]] || fail "parallel hammer failures=$ham_fail"
pass "parallel hammer"

# Processes still alive?
pgrep -f './server tests/dualstack/server.json' >/dev/null || fail "server died"
pgrep -f './client tests/dualstack/client_dual.json' >/dev/null || fail "client_dual died"
pgrep -f './multilink tests/dualstack/multilink.json' >/dev/null || fail "multilink died"

stop_stack
echo ""
echo "=== Dual-stack e2e ALL PASSED ==="
