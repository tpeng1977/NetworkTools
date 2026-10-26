#!/usr/bin/env bash
# Build a relocatable dist/VortexInternetLinux package.
# Usage: ./scripts/pack-vortex-internet-linux.sh
#    or: make dist-linux
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist/VortexInternetLinux"

echo "[*] packaging → $OUT"
rm -rf "$OUT"
mkdir -p "$OUT/config/geo"

# Binary
if [[ ! -x "$ROOT/linux_network" ]]; then
  echo "[*] building linux_network..."
  make -C "$ROOT" linux_network
fi
install -m 755 "$ROOT/linux_network" "$OUT/linux_network"

# Config + rules/geo (relative paths in internet.json)
install -m 644 "$ROOT/config/internet.json" "$OUT/config/internet.json"
install -m 644 "$ROOT/config/multirules.yaml" "$OUT/config/multirules.yaml"
install -m 644 "$ROOT/config/geo/geoip-cn.txt" "$OUT/config/geo/geoip-cn.txt"
install -m 644 "$ROOT/config/geo/geosite-cn.txt" "$OUT/config/geo/geosite-cn.txt"

# Network restore helpers (same content as repo scripts/; live at package root)
install -m 755 "$ROOT/scripts/restore-network-settings.sh" "$OUT/restore-network-settings.sh"
# Wrapper that kills leftover process then restores (for manual recovery)
cat >"$OUT/restore-network.sh" <<'EOF'
#!/usr/bin/env bash
# Kill leftover linux_network then restore host networking.
# Works from any copy of this directory: sudo ./restore-network.sh
set -uo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Usage: sudo $0"
  exit 1
fi
echo "[*] killing linux_network (if any)..."
pkill -INT -x linux_network 2>/dev/null || true
sleep 0.8
pkill -9 -x linux_network 2>/dev/null || true
bash "$ROOT/restore-network-settings.sh"
IFACE=$(ip -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
IFACE="${IFACE:-wlo1}"
echo "[*] check:"
echo -n "    ping 8.8.8.8: "; ping -c1 -W2 8.8.8.8 >/dev/null 2>&1 && echo OK || echo FAIL
echo -n "    resolve baidu.com: "; getent hosts baidu.com >/dev/null 2>&1 && echo OK || echo FAIL
echo "[*] restore done"
EOF
chmod 755 "$OUT/restore-network.sh"

# systemd unit template — paths filled by install-service.sh from this dir
cat >"$OUT/vortex-linux-network.service" <<'EOF'
[Unit]
Description=Vortex LinuxNetwork (redir-host + MultiLink transparent proxy)
After=network-online.target NetworkManager.service systemd-resolved.service
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=__ROOT__
ExecStart=__ROOT__/linux_network __ROOT__/config/internet.json
KillSignal=SIGINT
TimeoutStopSec=45
ExecStopPost=/bin/bash __ROOT__/restore-network-settings.sh
Restart=on-failure
RestartSec=5
StartLimitIntervalSec=60
StartLimitBurst=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=vortex-linux-network
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

# Install / uninstall — self-locating via dirname
cat >"$OUT/install-service.sh" <<'EOF'
#!/usr/bin/env bash
# Install systemd unit from this package directory (relocatable).
# Usage:
#   sudo ./install-service.sh           # enable + start
#   sudo ./install-service.sh --no-start
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Usage: sudo $0 [--no-start]"
  exit 1
fi

ROOT="$(cd "$(dirname "$0")" && pwd)"
UNIT_DST="/etc/systemd/system/vortex-linux-network.service"
NO_START=0
[[ "${1:-}" == "--no-start" ]] && NO_START=1

need=(
  "$ROOT/linux_network"
  "$ROOT/config/internet.json"
  "$ROOT/config/multirules.yaml"
  "$ROOT/config/geo/geoip-cn.txt"
  "$ROOT/config/geo/geosite-cn.txt"
  "$ROOT/vortex-linux-network.service"
  "$ROOT/restore-network-settings.sh"
)
for f in "${need[@]}"; do
  if [[ ! -e "$f" ]]; then
    echo "[-] missing $f"
    exit 1
  fi
done
chmod +x "$ROOT/linux_network" \
         "$ROOT/install-service.sh" \
         "$ROOT/uninstall-service.sh" \
         "$ROOT/restore-network.sh" \
         "$ROOT/restore-network-settings.sh" 2>/dev/null || true

tmp="$(mktemp)"
sed "s|__ROOT__|${ROOT}|g" "$ROOT/vortex-linux-network.service" >"$tmp"
echo "[*] installing $UNIT_DST"
echo "    ROOT=$ROOT"
install -m 644 "$tmp" "$UNIT_DST"
rm -f "$tmp"

systemctl daemon-reload
systemctl enable vortex-linux-network.service

if [[ "$NO_START" -eq 0 ]]; then
  pkill -INT -x linux_network 2>/dev/null || true
  sleep 0.5
  pkill -9 -x linux_network 2>/dev/null || true
  systemctl restart vortex-linux-network.service
  sleep 0.8
  systemctl --no-pager --full status vortex-linux-network.service || true
  echo
  echo "[+] installed and started from $ROOT"
else
  echo "[+] installed and enabled (not started)"
fi

echo "    status:   systemctl status vortex-linux-network"
echo "    logs:     journalctl -u vortex-linux-network -f"
echo "    stop:     sudo systemctl stop vortex-linux-network"
echo "    uninstall: sudo $ROOT/uninstall-service.sh"
EOF
chmod 755 "$OUT/install-service.sh"

cat >"$OUT/uninstall-service.sh" <<'EOF'
#!/usr/bin/env bash
# Remove systemd unit and restore networking. Relocatable.
# Usage: sudo ./uninstall-service.sh
set -euo pipefail

if [[ "$(id -u)" -ne 0 ]]; then
  echo "Usage: sudo $0"
  exit 1
fi

ROOT="$(cd "$(dirname "$0")" && pwd)"
UNIT_DST="/etc/systemd/system/vortex-linux-network.service"

systemctl stop vortex-linux-network.service 2>/dev/null || true
systemctl disable vortex-linux-network.service 2>/dev/null || true
rm -f "$UNIT_DST"
systemctl daemon-reload
systemctl reset-failed vortex-linux-network.service 2>/dev/null || true

bash "$ROOT/restore-network-settings.sh" || true
echo "[+] vortex-linux-network.service removed (ROOT was $ROOT)"
EOF
chmod 755 "$OUT/uninstall-service.sh"

cat >"$OUT/README.txt" <<'EOF'
VortexInternetLinux — relocatable package
=========================================

Contents:
  linux_network              binary
  config/                    internet.json + rules + geo
  install-service.sh         sudo ./install-service.sh
  uninstall-service.sh       sudo ./uninstall-service.sh
  restore-network.sh         emergency network restore
  restore-network-settings.sh
  vortex-linux-network.service

You may copy this whole directory anywhere, then:

  cd /path/to/VortexInternetLinux
  sudo ./install-service.sh

Paths inside the systemd unit are rewritten to the directory you run
install-service.sh from, so moving the folder later requires re-install:

  sudo ./uninstall-service.sh
  # move/copy folder
  sudo ./install-service.sh
EOF

# Strip CRLF if any host tools introduced them
find "$OUT" -type f \( -name '*.sh' -o -name '*.service' -o -name 'README.txt' \) \
  -exec sed -i 's/\r$//' {} +

echo "[+] package ready:"
find "$OUT" -type f | sort | sed "s|^$ROOT/||"
du -sh "$OUT"
