# Dual-stack (IPv4 + IPv6) tests

## Quick e2e

```bash
bash tests/run_dualstack.sh
```

Covers:

- Unit: prefer-IPv6 order, `::`/`*` dual listen, `0.0.0.0` IPv4-only, `bind_ip` string/array multi-listen, `server_ip` arrays, IP-CIDR6 / GEOIP rules, IPv6→IPv4 fallback (+ `ConnectHostsDetail` tags)
- Server bind: single `"::"` dual-stack, or `"bind_ip": ["::","0.0.0.0"]` / `["::1","127.0.0.1"]` multi-socket
- Client / MultiLink / SmartLink / Peer with `server_ip: ["::1","127.0.0.1"]` (IPv6 first)
- MultiLink uplink: dead IPv6 → live IPv4 fallback with distinguishable logs (`v6` fail / `v4` ok)
- SOCKS CONNECT: IPv4 literal, IPv6 literal, socks over v4/v6; domain resolve prefers AAAA then A
- `tcp_connect_direct_host`: domain AAAA→A resolve, IPv6-prefer connect + dead-IPv6→IPv4 fallback
- DNS-over-TCP via MultiLink: separate A and AAAA queries succeed on DIRECT and PROXY paths (not A-only)
- `linux_network --router-only`: SOCKS DIRECT IPv4/IPv6 literals (+ domain prefer/fallback via local DNS stub)
- Rules DIRECT for `127.0.0.0/8` and `::1/128`
- Burst + parallel hammer

## Soak (≥30 min recommended)

```bash
DURATION_SEC=1800 WORKERS=16 bash tests/run_dualstack_soak.sh
```

## linux_network note

Transparent divert uses **iptables** REDIRECT (IPv4). Full IPv6 transparent hijack
(ip6tables REDIRECT / TPROXY for all flows) is **not** implemented. Sticky DNS
answers **AAAA→NODATA** so apps stay on learned A → SOCKS CONNECT(domain); the
in-process router DIRECT path then does dual-stack **IPv6-prefer** egress (same
as multilink). Returning real AAAA from divert DNS would bypass PROXY on native
IPv6. Router SOCKS / `--router-only` and uplink `tcp_connect_hosts` are
dual-stack; ip6tables only adds RETURN excludes for IPv6 uplinks / ULA /
loopback so dual-stack uplinks are not stolen.
Root + CAP_NET_ADMIN required for divert; without root, use `--router-only` or
MultiLink/SmartLink SOCKS tests above.
