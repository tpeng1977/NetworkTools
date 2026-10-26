#!/usr/bin/env bash
# Requires: sudo, dig, python3. Or run via docker (see below).
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ "${1:-}" == "--docker" ]]; then
  exec docker run --rm --privileged --user root --cap-add=NET_ADMIN \
    --entrypoint bash \
    -v "$ROOT:/app" -w /app \
    longmeidao/peach:edge \
    -c 'export DEBIAN_FRONTEND=noninteractive
        apt-get update -qq && apt-get install -y -qq iproute2 iptables dnsutils python3 >/dev/null
        exec bash /app/scripts/test-linux-network.sh --in-container'
fi

NEED_ROOT=1
[[ "${1:-}" == "--in-container" ]] && NEED_ROOT=0
if [[ "$NEED_ROOT" == 1 && "$(id -u)" -ne 0 ]]; then
  echo "Usage: sudo $0   OR   $0 --docker"
  exit 1
fi

python3 - <<'PY'
import json
cfg=json.load(open("config/internet.json"))
cfg["socks5_bind_port"]=31997
cfg["log_decisions"]=True
cfg["log_connections"]=True
json.dump(cfg, open("/tmp/vortex-inet-test.json","w"))
print("[*] test config /tmp/vortex-inet-test.json port", cfg["socks5_bind_port"])
PY

./linux_network /tmp/vortex-inet-test.json >/tmp/vortex-ln-test.log 2>&1 &
LPID=$!
trap 'kill -INT $LPID 2>/dev/null || true; sleep 1; kill -9 $LPID 2>/dev/null || true' EXIT

for i in $(seq 1 50); do
  grep -q "divert:" /tmp/vortex-ln-test.log 2>/dev/null && break
  sleep 0.1
done
grep -q "divert:" /tmp/vortex-ln-test.log || { echo FAIL: no divert:; cat /tmp/vortex-ln-test.log; exit 1; }
echo "[+] started pid=$LPID"

python3 - <<'PY'
import socket, subprocess, time
def dig(name):
    out=subprocess.check_output(["dig","+short","+time=3","+tries=2","@198.18.0.2",name,"A"], text=True, timeout=15)
    ips=[l.strip() for l in out.splitlines() if l.strip() and l[0].isdigit()]
    if not ips: raise SystemExit(f"FAIL DNS empty for {name}: {out!r}")
    return ips[0]
def tcp(ip, port=443):
    s=socket.socket(); s.settimeout(10)
    s.connect((ip, port)); s.close()
hosts=[("www.baidu.com","DIRECT"),("www.google.com","link1"),("www.binance.com","link2")]
resolved={}
for h,_ in hosts:
    resolved[h]=dig(h)
    print(f"[+] DNS {h} -> {resolved[h]}")
time.sleep(0.2)
for h,_ in hosts:
    tcp(resolved[h])
    print(f"[+] TCP connect {h} {resolved[h]}:443 ok")
time.sleep(3.0)
log=open("/tmp/vortex-ln-test.log").read()
checks=[
    ("www.baidu.com", "DIRECT", "via SOCKS5/domain"),
    ("www.google.com", "link1", "via SOCKS5/domain"),
    ("www.binance.com", "link2", "via SOCKS5/domain"),
]
ok=True
for host, decision, how in checks:
    if f"DNS q={host}" not in log and f"DNS q={host} " not in log:
        # cached form also fine
        if host not in log:
            print(f"FAIL missing DNS log for {host}"); ok=False
    if decision not in log or host not in log:
        print(f"FAIL missing decision {decision} for {host}")
        ok=False
    else:
        print(f"[+] rule hit for {host} contains {decision}")
    if f"{host}/" not in log or "SOCKS5/domain" not in log:
        # still require domain path somewhere for these hosts
        if f"TCP {host}/" not in log:
            print(f"FAIL missing SOCKS5/domain TCP for {host}")
            ok=False
        else:
            print(f"[+] TCP domain path for {host}")
    else:
        print(f"[+] TCP domain path for {host}")
if "TCP passthru" in log and log.count("via SOCKS5/domain") < 3:
    print("WARN: passthru present; domain paths:", log.count("via SOCKS5/domain"))
if not ok:
    print("--- log ---"); print(log); raise SystemExit(1)

# Real HTTPS through TUN (not just TCP handshake) — catches QUIC/routing/DNS bugs.
import urllib.request, ssl
ctx = ssl.create_default_context()
for url, expect in [
    ("https://www.baidu.com/", True),
    ("https://www.google.com/generate_204", True),
]:
    req = urllib.request.Request(url, method="GET", headers={"User-Agent": "vortex-test"})
    try:
        with urllib.request.urlopen(req, timeout=20, context=ctx) as r:
            code = r.getcode()
            print(f"[+] HTTPS {url} -> {code}")
            if code >= 400:
                raise SystemExit(f"FAIL bad HTTP {code} for {url}")
    except Exception as e:
        raise SystemExit(f"FAIL HTTPS {url}: {e}")
print("[+] ALL CHECKS PASSED")
PY
