#!/usr/bin/env bash
# Install vortex-linux-network.service into /etc/systemd/system/
# Usage:
#   sudo ./scripts/install-linux-network-service.sh           # install + enable + start
#   sudo ./scripts/install-linux-network-service.sh --no-start
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Usage: sudo $0 [--no-start]"
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UNIT_SRC="$ROOT/scripts/vortex-linux-network.service"
UNIT_DST="/etc/systemd/system/vortex-linux-network.service"
NO_START=0
[[ "${1:-}" == "--no-start" ]] && NO_START=1

if [[ ! -x "$ROOT/linux_network" ]]; then
  echo "[*] building linux_network..."
  (cd "$ROOT" && make linux_network)
fi
if [[ ! -x "$ROOT/linux_network" ]]; then
  echo "[-] missing $ROOT/linux_network"
  exit 1
fi
if [[ ! -f "$ROOT/config/internet.json" ]]; then
  echo "[-] missing $ROOT/config/internet.json"
  exit 1
fi
if [[ ! -f "$UNIT_SRC" ]]; then
  echo "[-] missing $UNIT_SRC"
  exit 1
fi

# Rewrite paths in the unit to this checkout (portable if repo moves).
tmp="$(mktemp)"
sed \
  -e "s|/home/joyshop/Develop/ProxyImplement|${ROOT}|g" \
  "$UNIT_SRC" >"$tmp"

echo "[*] installing $UNIT_DST"
install -m 644 "$tmp" "$UNIT_DST"
rm -f "$tmp"

# Ensure restore script is executable
chmod +x "$ROOT/scripts/restore-network-settings.sh" \
         "$ROOT/scripts/restore-network.sh" \
         "$ROOT/scripts/cleanup-linux-network.sh" 2>/dev/null || true

systemctl daemon-reload
systemctl enable vortex-linux-network.service

if [[ "$NO_START" -eq 0 ]]; then
  # Stop any manual instance first
  pkill -INT -x linux_network 2>/dev/null || true
  sleep 0.5
  pkill -9 -x linux_network 2>/dev/null || true
  systemctl restart vortex-linux-network.service
  sleep 0.8
  systemctl --no-pager --full status vortex-linux-network.service || true
  echo
  echo "[+] installed and started"
else
  echo "[+] installed and enabled (not started)"
fi

echo "    status:  systemctl status vortex-linux-network"
echo "    logs:    journalctl -u vortex-linux-network -f"
echo "    stop:    sudo systemctl stop vortex-linux-network"
echo "    start:   sudo systemctl start vortex-linux-network"
echo "    remove:  sudo ./scripts/uninstall-linux-network-service.sh"
