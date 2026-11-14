#!/usr/bin/env bash
# Build relocatable dist/linux_gate package.
# Usage: ./scripts/pack-linux-gate.sh
#    or: make dist-linux-gate / make linux_gate
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/dist/linux_gate"

echo "[*] packaging → $OUT"
rm -rf "$OUT"
mkdir -p "$OUT/config"

if [[ ! -x "$ROOT/linux_gate" ]]; then
  echo "[*] building linux_gate..."
  make -C "$ROOT" linux_gate-bin
fi
install -m 755 "$ROOT/linux_gate" "$OUT/linux_gate"

if [[ -f "$ROOT/config/linux_gate.json" ]]; then
  install -m 644 "$ROOT/config/linux_gate.json" "$OUT/config/linux_gate.json"
else
  install -m 644 "$ROOT/config_example/linux_gate_example.json" "$OUT/config/linux_gate.json"
fi
install -m 644 "$ROOT/config_example/linux_gate_example.json" "$OUT/config/linux_gate_example.json"

cat >"$OUT/restore-gate.sh" <<'EOF'
#!/usr/bin/env bash
# Tear down linux_gate LAN rules/addrs without touching wan (wifi).
set -uo pipefail
ROOT="$(cd "$(dirname "$0")" && pwd)"
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Usage: sudo $0"
  exit 1
fi
CFG="$ROOT/config/linux_gate.json"
[[ -f "$CFG" ]] || CFG="$ROOT/config/linux_gate_example.json"
echo "[*] stopping linux_gate..."
pkill -INT -x linux_gate 2>/dev/null || true
sleep 0.5
pkill -9 -x linux_gate 2>/dev/null || true
"$ROOT/linux_gate" --stop "$CFG" 2>/dev/null || true
echo "[+] gate cleaned (wan untouched)"
EOF
chmod 755 "$OUT/restore-gate.sh"

cat >"$OUT/vortex-linux-gate.service" <<'EOF'
[Unit]
Description=Vortex LinuxGate (wired LAN → local redirect_port)
After=network-online.target
Wants=network-online.target
# Start multilink / linux_network first so redirect_port is listening.
After=vortex-linux-network.service

[Service]
Type=simple
User=root
Group=root
WorkingDirectory=__ROOT__
ExecStart=__ROOT__/linux_gate __ROOT__/config/linux_gate.json
KillSignal=SIGINT
TimeoutStopSec=30
ExecStopPost=__ROOT__/linux_gate --stop __ROOT__/config/linux_gate.json
Restart=on-failure
RestartSec=5
StandardOutput=journal
StandardError=journal
SyslogIdentifier=vortex-linux-gate
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF

cat >"$OUT/install-service.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Usage: sudo $0 [--no-start]"
  exit 1
fi
ROOT="$(cd "$(dirname "$0")" && pwd)"
UNIT_DST="/etc/systemd/system/vortex-linux-gate.service"
NO_START=0
[[ "${1:-}" == "--no-start" ]] && NO_START=1

need=("$ROOT/linux_gate" "$ROOT/config/linux_gate.json" "$ROOT/vortex-linux-gate.service")
for f in "${need[@]}"; do
  [[ -e "$f" ]] || { echo "[-] missing $f"; exit 1; }
done
chmod +x "$ROOT/linux_gate" "$ROOT/install-service.sh" "$ROOT/uninstall-service.sh" \
         "$ROOT/restore-gate.sh" 2>/dev/null || true

tmp="$(mktemp)"
sed "s|__ROOT__|${ROOT}|g" "$ROOT/vortex-linux-gate.service" >"$tmp"
install -m 644 "$tmp" "$UNIT_DST"
rm -f "$tmp"
systemctl daemon-reload
systemctl enable vortex-linux-gate.service
if [[ "$NO_START" -eq 0 ]]; then
  pkill -INT -x linux_gate 2>/dev/null || true
  sleep 0.3
  systemctl restart vortex-linux-gate.service
  sleep 0.5
  systemctl --no-pager --full status vortex-linux-gate.service || true
  echo "[+] installed and started from $ROOT"
else
  echo "[+] installed and enabled (not started)"
fi
echo "    Prerequisites: multilink/linux_network listening on redirect_port + SOCKS"
echo "    Optional: apt install dnsmasq"
EOF
chmod 755 "$OUT/install-service.sh"

cat >"$OUT/uninstall-service.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ "$(id -u)" -ne 0 ]]; then
  echo "Usage: sudo $0"
  exit 1
fi
ROOT="$(cd "$(dirname "$0")" && pwd)"
UNIT_DST="/etc/systemd/system/vortex-linux-gate.service"
systemctl stop vortex-linux-gate.service 2>/dev/null || true
systemctl disable vortex-linux-gate.service 2>/dev/null || true
rm -f "$UNIT_DST"
systemctl daemon-reload
bash "$ROOT/restore-gate.sh" || true
echo "[+] vortex-linux-gate.service removed"
EOF
chmod 755 "$OUT/uninstall-service.sh"

cat >"$OUT/README.txt" <<'EOF'
Vortex LinuxGate — wired NIC as dual-stack LAN gateway
======================================================

Turns lan_iface (default enp3s0) into a gateway for other PCs.
Does NOT change wan_iface (default wlo1) addressing, routes, or DNS.

Traffic from LAN clients:
  TCP          → DNAT to 127.0.0.1 / ::1 :redirect_port  (run multilink first)
  UDP/53 DNS   → local stub → SOCKS5 (socks5_host:socks5_port)
  ICMP echo    → NFQUEUE → SOCKS policy probe → synthetic reply

IPv4: private LAN (default 192.168.137.1/24 + DHCP)
IPv6: prefer GUA /64 learned from wan_iface; else ULA fd00:56::1/64

Quick start:
  1) Start multilink (or linux_network) with redirect_port + SOCKS bound
  2) sudo apt install dnsmasq    # DHCP + IPv6 RA
  3) sudo ./linux_gate config/linux_gate.json
  4) Plug client into enp3s0 (or switch); DHCP should assign gateway

Stop / clean (wan untouched):
  sudo ./restore-gate.sh
  # or: sudo ./linux_gate --stop config/linux_gate.json

systemd:
  sudo ./install-service.sh
  sudo ./uninstall-service.sh
EOF

find "$OUT" -type f \( -name '*.sh' -o -name '*.service' -o -name 'README.txt' \) \
  -exec sed -i 's/\r$//' {} +

echo "[+] package ready:"
find "$OUT" -type f | sort | sed "s|^$ROOT/||"
du -sh "$OUT"
