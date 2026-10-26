#!/usr/bin/env bash
# Kill linux_network (if any) then restore host networking.
# Usage: sudo ./scripts/cleanup-linux-network.sh
#        sudo ./scripts/restore-network.sh
set -uo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Usage: sudo $0"
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"

echo "[*] killing linux_network (if any)..."
# Prefer graceful stop so in-process restore runs; then force.
pkill -INT -x linux_network 2>/dev/null || true
pkill -INT -f '/linux_network ' 2>/dev/null || true
sleep 1
pkill -9 -x linux_network 2>/dev/null || true
pkill -9 -f '/linux_network ' 2>/dev/null || true
sleep 0.2

bash "$ROOT/scripts/restore-network-settings.sh"

echo "[*] check:"
IFACE=$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
IFACE="${IFACE:-wlo1}"
echo -n "    default route: "; ip route show default | head -1 || echo "(none)"
echo -n "    DNS: "; resolvectl dns "$IFACE" 2>/dev/null || true
echo -n "    ping 8.8.8.8: "
if ping -c1 -W2 8.8.8.8 >/dev/null 2>&1; then echo OK; else echo FAIL; fi
echo -n "    resolve baidu.com: "
if getent hosts baidu.com >/dev/null 2>&1; then echo OK; else echo FAIL; fi
echo "[*] restore done"
