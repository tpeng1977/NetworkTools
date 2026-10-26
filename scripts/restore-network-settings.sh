#!/usr/bin/env bash
# Restore iptables / routes / DNS only — does NOT kill linux_network.
# Called by: linux_network on Ctrl+C, and by restore-network.sh after kill.
# Usage: sudo ./scripts/restore-network-settings.sh
set -uo pipefail

IP="${IP:-$(command -v ip || true)}"
IP="${IP:-/usr/sbin/ip}"
IPT="${IPT:-$(command -v iptables || true)}"
IPT="${IPT:-/usr/sbin/iptables}"
MARK=0x564e4554

IFACE=$("$IP" -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}')
GW=$("$IP" -4 route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}')
IFACE="${IFACE:-wlo1}"
GW="${GW:-192.168.0.1}"

echo "[*] removing iptables divert chains..."
# Delete jump repeatedly (in case inserted more than once).
for _ in 1 2 3 4 5; do
  "$IPT" -t nat -D OUTPUT -j VORTEX_OUT 2>/dev/null || break
done
for _ in 1 2 3 4 5; do
  "$IPT" -t filter -D OUTPUT -j VORTEX_FILTER 2>/dev/null || break
done
"$IPT" -t nat -F VORTEX_OUT 2>/dev/null || true
"$IPT" -t nat -X VORTEX_OUT 2>/dev/null || true
"$IPT" -t nat -F VORTEX_TCP 2>/dev/null || true
"$IPT" -t nat -X VORTEX_TCP 2>/dev/null || true
"$IPT" -t filter -F VORTEX_FILTER 2>/dev/null || true
"$IPT" -t filter -X VORTEX_FILTER 2>/dev/null || true

for chain_spec in \
  "nat OUTPUT VORTEX_DNS" \
  "nat OUTPUT VORTEX_LN" \
  "filter OUTPUT VORTEX_LN_F"
do
  set -- $chain_spec
  for _ in 1 2 3; do
    "$IPT" -t "$1" -D "$2" -j "$3" 2>/dev/null || break
  done
  "$IPT" -t "$1" -F "$3" 2>/dev/null || true
  "$IPT" -t "$1" -X "$3" 2>/dev/null || true
done

echo "[*] removing leftover TUN / policy routing..."
"$IP" rule del fwmark "$MARK" lookup main pref 100 2>/dev/null || true
"$IP" rule del lookup 19818 pref 200 2>/dev/null || true
for c in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
  "$IP" rule del to "$c" lookup main pref 150 2>/dev/null || true
done
"$IP" route flush table 19818 2>/dev/null || true
"$IP" -6 route del unreachable default 2>/dev/null || true
"$IP" -6 route del unreachable default metric 1 2>/dev/null || true
"$IP" link set vortex0 down 2>/dev/null || true
"$IP" link delete vortex0 2>/dev/null || true
"$IP" addr del 198.18.0.1/15 dev lo 2>/dev/null || true
"$IP" route del 198.18.0.0/15 dev lo 2>/dev/null || true

echo "[*] restoring DNS on $IFACE..."
if command -v resolvectl >/dev/null 2>&1; then
  resolvectl revert "$IFACE" 2>/dev/null || true
  resolvectl domain "$IFACE" "" 2>/dev/null || true
  resolvectl dnsovertls "$IFACE" no 2>/dev/null || true

  if command -v nmcli >/dev/null 2>&1; then
    nmcli device reapply "$IFACE" 2>/dev/null || true
    sleep 0.4
    CONN=$(nmcli -t -f NAME,DEVICE connection show --active 2>/dev/null \
      | awk -F: -v d="$IFACE" '$2==d{print $1; exit}')
    if [[ -n "${CONN:-}" ]]; then
      nmcli connection up "$CONN" ifname "$IFACE" 2>/dev/null || true
      sleep 0.6
    fi
  fi

  CUR=$(resolvectl dns "$IFACE" 2>/dev/null | sed 's/^[^:]*:[[:space:]]*//')
  if [[ -z "${CUR// /}" ]]; then
    echo "    DNS empty — setting $GW 114.114.114.114 8.8.8.8"
    resolvectl dns "$IFACE" "$GW" 114.114.114.114 8.8.8.8
  else
    echo "    DNS servers: $CUR"
  fi
  resolvectl flush-caches 2>/dev/null || true
  resolvectl reset-server-features 2>/dev/null || true
fi

rm -f /run/vortex-linux-network.lock /tmp/vortex-linux-network.lock
echo "[*] network settings restored"
