#!/usr/bin/env bash
# Kill leftover port-forward soak stacks without matching this script's path.
set -euo pipefail

kill_pat() {
  local pat="$1"
  local pids
  pids=$(pgrep -f "$pat" 2>/dev/null || true)
  if [[ -n "${pids}" ]]; then
    # shellcheck disable=SC2086
    kill -TERM ${pids} 2>/dev/null || true
    sleep 0.3
    pids=$(pgrep -f "$pat" 2>/dev/null || true)
    [[ -n "${pids}" ]] && kill -KILL ${pids} 2>/dev/null || true
  fi
}

kill_pat './server tests/port_forward_soak'
kill_pat './peer tests/port_forward_soak'
kill_pat './tests/port_forward_soak '
kill_pat './tests/echo_server'
kill_pat './tests/udp_echo'
kill_pat './server /tmp/pf_v'
kill_pat './peer /tmp/pf_v'

echo cleaned
ss -tlnp 2>/dev/null | grep -E '10888|20888|23888|24888|25888|26888|27888|22888|21888' \
  || echo 'no soak ports listening'
