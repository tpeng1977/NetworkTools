#!/usr/bin/env bash
# Remove vortex-linux-network.service and restore networking.
# Usage: sudo ./scripts/uninstall-linux-network-service.sh
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Usage: sudo $0"
  exit 1
fi

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
UNIT_DST="/etc/systemd/system/vortex-linux-network.service"

systemctl stop vortex-linux-network.service 2>/dev/null || true
systemctl disable vortex-linux-network.service 2>/dev/null || true
rm -f "$UNIT_DST"
systemctl daemon-reload
systemctl reset-failed vortex-linux-network.service 2>/dev/null || true

# Ensure host network is clean
bash "$ROOT/scripts/restore-network-settings.sh" || true

echo "[+] vortex-linux-network.service removed"
