// LinuxGate: same divert model as linux_network.cpp, but for ONE LAN iface
// (PREROUTING -i lan_iface) instead of host OUTPUT.
//
// Mirror of linux_network divert (no Fake-IP, dual-stack):
//   UDP/53  → linux_network sticky DNS (:53053) — real A/AAAA + learn IP→name
//   TCP/*   → REDIRECT → redirect_port — SO_ORIGINAL_DST + SOCKS CONNECT(domain)
//   UDP/443 → reject (force TCP; kill QUIC)
//   other UDP/ICMP → drop (no SOCKS-probe — that starved the uplink)
//
// Prerequisites: linux_network (or multilink) already listening on
//   redirect_bind 0.0.0.0/:: :redirect_port, SOCKS socks5_host_*:socks5_port,
//   sticky DNS 127.0.0.1:dns_redirect_port (default 53053).
// Optional: dnsmasq for DHCPv4 + IPv6 RA.
//
// Usage:
//   sudo ./linux_gate config/linux_gate.json
//   sudo ./linux_gate --stop

#ifndef __linux__
#error linux_gate.cpp is Linux-only
#endif

#include "config.hpp"
#include "net.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <linux/netfilter.h>
#include <linux/netfilter/nfnetlink.h>
#include <linux/netfilter/nfnetlink_queue.h>
#include <linux/netlink.h>
#include <netinet/icmp6.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <poll.h>
#include <signal.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <cctype>
#include <chrono>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {

std::atomic<bool> g_run{true};
LinuxGateConfig g_cfg;
std::string g_run_dir = "/run/vortex-linux-gate";
std::string g_lan_ipv6; // assigned GUA or ULA on lan_iface
pid_t g_dnsmasq_pid = -1;
int g_lock_fd = -1;
int g_dns4_fd = -1;
int g_dns6_fd = -1;
std::atomic<int> g_dns_inflight{0};
constexpr int kDnsMaxInflight = 64;
constexpr int kDnsCacheTtlSec = 30;
std::mutex g_log_mu;
std::mutex g_dns_cache_mu;
struct DnsCacheEnt {
    std::vector<uint8_t> answer;
    std::chrono::steady_clock::time_point expire{};
};
std::unordered_map<std::string, DnsCacheEnt> g_dns_cache; // qname+type → answer

void log_line(const std::string& s) {
    if (!g_cfg.log) return;
    std::lock_guard<std::mutex> lock(g_log_mu);
    std::cout << s << std::endl;
}

void on_signal(int) { g_run = false; }

int run_cmd(const std::string& cmd) {
    const int rc = ::system(cmd.c_str());
    if (WIFEXITED(rc)) return WEXITSTATUS(rc);
    return -1;
}

std::string shell_out(const std::string& cmd) {
    FILE* p = ::popen(cmd.c_str(), "r");
    if (!p) return {};
    std::string out;
    char buf[512];
    while (fgets(buf, sizeof(buf), p)) out += buf;
    ::pclose(p);
    return out;
}

bool iface_exists(const std::string& ifname) {
    return ::access(("/sys/class/net/" + ifname).c_str(), F_OK) == 0;
}

bool acquire_lock() {
    ::mkdir(g_run_dir.c_str(), 0755);
    g_lock_fd = ::open((g_run_dir + "/lock").c_str(), O_RDWR | O_CREAT, 0644);
    if (g_lock_fd < 0) return false;
    if (flock(g_lock_fd, LOCK_EX | LOCK_NB) != 0) {
        std::cerr << "[-] another linux_gate is running\n";
        return false;
    }
    return true;
}

// ---- WAN IPv6 prefix detection (read-only; never modifies wan) ----
struct WanV6Prefix {
    in6_addr prefix{};
    int plen = 64;
    std::string text; // e.g. 2409:8a70:a9c:d8e0::/64
    bool ok = false;
};

WanV6Prefix detect_wan_v6_prefix(const std::string& wan) {
    WanV6Prefix out;
    const std::string raw = shell_out("ip -6 -o addr show dev " + wan + " scope global 2>/dev/null");
    std::istringstream ss(raw);
    std::string line;
    while (std::getline(ss, line)) {
        // ... inet6 2409:.../64 ...
        const auto pos = line.find("inet6 ");
        if (pos == std::string::npos) continue;
        size_t a = pos + 6;
        while (a < line.size() && std::isspace(static_cast<unsigned char>(line[a]))) ++a;
        size_t b = a;
        while (b < line.size() && !std::isspace(static_cast<unsigned char>(line[b]))) ++b;
        std::string cidr = line.substr(a, b - a);
        const auto slash = cidr.find('/');
        if (slash == std::string::npos) continue;
        std::string ip = cidr.substr(0, slash);
        int plen = 64;
        try { plen = std::stoi(cidr.substr(slash + 1)); } catch (...) { continue; }
        if (plen < 48 || plen > 64) continue;
        in6_addr addr{};
        if (inet_pton(AF_INET6, ip.c_str(), &addr) != 1) continue;
        // Zero host bits beyond plen for prefix.
        const int host_bits = 128 - plen;
        for (int i = 0; i < host_bits; ++i) {
            const int bit = 127 - i;
            const int byte = bit / 8;
            const int mask = 1 << (7 - (bit % 8));
            reinterpret_cast<uint8_t*>(&addr)[byte] &= static_cast<uint8_t>(~mask);
        }
        out.prefix = addr;
        out.plen = plen;
        char buf[INET6_ADDRSTRLEN] = {};
        inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
        out.text = std::string(buf) + "/" + std::to_string(plen);
        out.ok = true;
        break;
    }
    return out;
}

std::string make_lan_ipv6_from_prefix(const WanV6Prefix& p) {
    in6_addr a = p.prefix;
    // host ::a (gateway)
    reinterpret_cast<uint8_t*>(&a)[15] = 0x0a;
    char buf[INET6_ADDRSTRLEN] = {};
    inet_ntop(AF_INET6, &a, buf, sizeof(buf));
    return buf;
}

// ---- Host networking (LAN only) ----
void setup_sysctl_forward() {
    // Forwarding is host-wide but does not change wan addressing / DNS / routes.
    run_cmd("sysctl -w net.ipv4.ip_forward=1 >/dev/null");
    run_cmd("sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null");
    run_cmd("sysctl -w net.ipv4.conf.all.route_localnet=1 >/dev/null");
    run_cmd("sysctl -w net.ipv4.conf." + g_cfg.lan_iface + ".route_localnet=1 >/dev/null");
    // Divert path: loose rp_filter + larger conntrack / socket buffers for LAN clients.
    run_cmd("sysctl -w net.ipv4.conf." + g_cfg.lan_iface + ".rp_filter=2 >/dev/null");
    run_cmd("sysctl -w net.ipv4.conf.all.rp_filter=2 >/dev/null");
    run_cmd("sysctl -w net.netfilter.nf_conntrack_max=262144 >/dev/null 2>/dev/null");
    run_cmd("sysctl -w net.netfilter.nf_conntrack_tcp_timeout_established=600 >/dev/null 2>/dev/null");
    run_cmd("sysctl -w net.core.rmem_max=16777216 >/dev/null");
    run_cmd("sysctl -w net.core.wmem_max=16777216 >/dev/null");
    run_cmd("sysctl -w net.ipv4.tcp_rmem='4096 87380 16777216' >/dev/null");
    run_cmd("sysctl -w net.ipv4.tcp_wmem='4096 65536 16777216' >/dev/null");
    run_cmd("sysctl -w net.ipv4.tcp_fastopen=3 >/dev/null");
    run_cmd("sysctl -w net.ipv4.tcp_slow_start_after_idle=0 >/dev/null");
}

void setup_lan_ipv4() {
    run_cmd("ip link set " + g_cfg.lan_iface + " up");
    run_cmd("ip -4 addr flush dev " + g_cfg.lan_iface + " 2>/dev/null");
    run_cmd("ip -4 addr add " + g_cfg.lan_ipv4 + "/" + std::to_string(g_cfg.lan_ipv4_prefix) +
            " dev " + g_cfg.lan_iface);
    log_line("[*] LAN IPv4 " + g_cfg.lan_ipv4 + "/" + std::to_string(g_cfg.lan_ipv4_prefix) +
             " on " + g_cfg.lan_iface);
}

void setup_lan_ipv6() {
    if (!g_cfg.ipv6_enable) {
        g_lan_ipv6.clear();
        return;
    }
    run_cmd("ip -6 addr flush dev " + g_cfg.lan_iface + " scope global 2>/dev/null");
    run_cmd("ip -6 addr flush dev " + g_cfg.lan_iface + " scope unique-local 2>/dev/null");

    const WanV6Prefix wan = detect_wan_v6_prefix(g_cfg.wan_iface);
    if (wan.ok) {
        g_lan_ipv6 = make_lan_ipv6_from_prefix(wan);
        run_cmd("ip -6 addr add " + g_lan_ipv6 + "/" + std::to_string(wan.plen) +
                " dev " + g_cfg.lan_iface);
        // Best-effort NDP proxy so GUAs on LAN are reachable via wan (read-only on wan addrs).
        run_cmd("sysctl -w net.ipv6.conf." + g_cfg.wan_iface + ".proxy_ndp=1 >/dev/null");
        run_cmd("sysctl -w net.ipv6.conf." + g_cfg.lan_iface + ".proxy_ndp=1 >/dev/null");
        log_line("[*] LAN IPv6 GUA " + g_lan_ipv6 + "/" + std::to_string(wan.plen) +
                 " (prefix from " + g_cfg.wan_iface + " " + wan.text + ", wan untouched)");
    } else {
        g_lan_ipv6 = g_cfg.lan_ipv6_ula;
        run_cmd("ip -6 addr add " + g_lan_ipv6 + "/" + std::to_string(g_cfg.lan_ipv6_prefix) +
                " dev " + g_cfg.lan_iface);
        log_line("[*] LAN IPv6 ULA " + g_lan_ipv6 + "/" + std::to_string(g_cfg.lan_ipv6_prefix) +
                 " (no GUA prefix on " + g_cfg.wan_iface + ")");
    }
}

void teardown_lan_addrs() {
    if (!iface_exists(g_cfg.lan_iface)) return;
    run_cmd("ip -4 addr flush dev " + g_cfg.lan_iface + " 2>/dev/null");
    run_cmd("ip -6 addr flush dev " + g_cfg.lan_iface + " scope global 2>/dev/null");
    run_cmd("ip -6 addr flush dev " + g_cfg.lan_iface + " scope unique-local 2>/dev/null");
}

// ---- iptables: only -i lan_iface (never host OUTPUT / wan) ----
void iptables_uninstall() {
    const std::string& lan = g_cfg.lan_iface;
    const std::string q = std::to_string(g_cfg.icmp_queue_num);
    for (int i = 0; i < 8; ++i) {
        run_cmd("iptables -t nat -D PREROUTING -i " + lan + " -j VORTEX_GATE_PRE 2>/dev/null");
        run_cmd("iptables -t nat -D POSTROUTING -j VORTEX_GATE_POST 2>/dev/null");
        run_cmd("iptables -t mangle -D PREROUTING -i " + lan + " -j VORTEX_GATE_ICMP 2>/dev/null");
        run_cmd("iptables -t filter -D FORWARD -i " + lan + " -j VORTEX_GATE_FWD 2>/dev/null");
        run_cmd("ip6tables -t nat -D PREROUTING -i " + lan + " -j VORTEX_GATE_PRE6 2>/dev/null");
        run_cmd("ip6tables -t mangle -D PREROUTING -i " + lan + " -j VORTEX_GATE_ICMP6 2>/dev/null");
        run_cmd("ip6tables -t filter -D FORWARD -i " + lan + " -j VORTEX_GATE_FWD6 2>/dev/null");
    }
    run_cmd("iptables -t nat -F VORTEX_GATE_PRE 2>/dev/null");
    run_cmd("iptables -t nat -X VORTEX_GATE_PRE 2>/dev/null");
    run_cmd("iptables -t nat -F VORTEX_GATE_POST 2>/dev/null");
    run_cmd("iptables -t nat -X VORTEX_GATE_POST 2>/dev/null");
    run_cmd("iptables -t mangle -F VORTEX_GATE_ICMP 2>/dev/null");
    run_cmd("iptables -t mangle -X VORTEX_GATE_ICMP 2>/dev/null");
    run_cmd("iptables -t filter -F VORTEX_GATE_FWD 2>/dev/null");
    run_cmd("iptables -t filter -X VORTEX_GATE_FWD 2>/dev/null");
    run_cmd("ip6tables -t nat -F VORTEX_GATE_PRE6 2>/dev/null");
    run_cmd("ip6tables -t nat -X VORTEX_GATE_PRE6 2>/dev/null");
    run_cmd("ip6tables -t mangle -F VORTEX_GATE_ICMP6 2>/dev/null");
    run_cmd("ip6tables -t mangle -X VORTEX_GATE_ICMP6 2>/dev/null");
    run_cmd("ip6tables -t filter -F VORTEX_GATE_FWD6 2>/dev/null");
    run_cmd("ip6tables -t filter -X VORTEX_GATE_FWD6 2>/dev/null");
    (void)q;
}

bool iptables_install() {
    iptables_uninstall();
    const std::string& lan = g_cfg.lan_iface;
    const std::string rp = std::to_string(g_cfg.redirect_port);
    const std::string dns_local = std::to_string(g_cfg.dns_udp_port);
    const std::string dns_up_host = g_cfg.dns_redirect_host_v4;
    const std::string dns_up_port = std::to_string(g_cfg.dns_redirect_port);
    const std::string q = std::to_string(g_cfg.icmp_queue_num);
    const bool sticky_dns = (g_cfg.dns_redirect_port > 0);

    run_cmd("iptables -t nat -N VORTEX_GATE_PRE 2>/dev/null || iptables -t nat -F VORTEX_GATE_PRE");
    run_cmd("iptables -t nat -N VORTEX_GATE_POST 2>/dev/null || iptables -t nat -F VORTEX_GATE_POST");
    run_cmd("iptables -t filter -N VORTEX_GATE_FWD 2>/dev/null || iptables -t filter -F VORTEX_GATE_FWD");
    run_cmd("iptables -t nat -I PREROUTING 1 -i " + lan + " -j VORTEX_GATE_PRE");
    run_cmd("iptables -t nat -I POSTROUTING 1 -j VORTEX_GATE_POST");
    run_cmd("iptables -t filter -I FORWARD 1 -i " + lan + " -j VORTEX_GATE_FWD");
    (void)q; // ICMP no longer NFQUEUE'd (SOCKS probe starved the uplink)

    // Same shape as linux_network OUTPUT divert, applied to lan_iface PREROUTING:
    //   UDP/53 → sticky DNS (learn real A/AAAA) or local SOCKS stub
    //   TCP/*  → REDIRECT redirect_port (SO_ORIGINAL_DST intact; never DNAT→127.0.0.1)
    //   UDP/443 → reject (QUIC off)
    if (sticky_dns) {
        run_cmd("iptables -t nat -A VORTEX_GATE_PRE -p udp --dport 53 -j DNAT --to-destination " +
                dns_up_host + ":" + dns_up_port);
        in_addr dns_ip{};
        const bool dns_loopback =
            inet_pton(AF_INET, dns_up_host.c_str(), &dns_ip) == 1 &&
            ((ntohl(dns_ip.s_addr) & 0xff000000u) == 0x7f000000u);
        if (dns_loopback) {
            run_cmd("iptables -t nat -A VORTEX_GATE_POST -p udp -d " + dns_up_host +
                    " --dport " + dns_up_port + " -j SNAT --to-source 127.0.0.1");
        }
    } else {
        run_cmd("iptables -t nat -A VORTEX_GATE_PRE -p udp --dport 53 -j REDIRECT --to-ports " +
                dns_local);
    }
    run_cmd("iptables -t nat -A VORTEX_GATE_PRE -d " + g_cfg.lan_ipv4 + " -j RETURN");
    run_cmd("iptables -t nat -A VORTEX_GATE_PRE -p tcp -j REDIRECT --to-ports " + rp);

    // No raw FORWARD to wan — everything must hit divert/local.
    // ICMP: drop (do NOT SOCKS-probe — that starved multilink and made browsing slow).
    run_cmd("iptables -t filter -A VORTEX_GATE_FWD -p udp --dport 443 -j REJECT "
            "--reject-with icmp-port-unreachable");
    run_cmd("iptables -t filter -A VORTEX_GATE_FWD -p tcp -j REJECT --reject-with tcp-reset");
    run_cmd("iptables -t filter -A VORTEX_GATE_FWD -p udp -j REJECT --reject-with icmp-port-unreachable");
    run_cmd("iptables -t filter -A VORTEX_GATE_FWD -p icmp -j DROP");

    if (g_cfg.ipv6_enable) {
        run_cmd("ip6tables -t nat -N VORTEX_GATE_PRE6 2>/dev/null || ip6tables -t nat -F VORTEX_GATE_PRE6");
        run_cmd("ip6tables -t filter -N VORTEX_GATE_FWD6 2>/dev/null || ip6tables -t filter -F VORTEX_GATE_FWD6");
        run_cmd("ip6tables -t nat -I PREROUTING 1 -i " + lan + " -j VORTEX_GATE_PRE6");
        run_cmd("ip6tables -t filter -I FORWARD 1 -i " + lan + " -j VORTEX_GATE_FWD6");

        // IPv6 sticky is IPv4-only on linux_network (:53053) — REDIRECT to local
        // forwarder that UDP-relays to sticky so AAAA still learns.
        run_cmd("ip6tables -t nat -A VORTEX_GATE_PRE6 -p udp --dport 53 -j REDIRECT --to-ports " +
                dns_local);
        if (!g_lan_ipv6.empty()) {
            run_cmd("ip6tables -t nat -A VORTEX_GATE_PRE6 -d " + g_lan_ipv6 + " -j RETURN");
        }
        run_cmd("ip6tables -t nat -A VORTEX_GATE_PRE6 -d fe80::/10 -j RETURN");
        run_cmd("ip6tables -t nat -A VORTEX_GATE_PRE6 -p tcp -j REDIRECT --to-ports " + rp);
        run_cmd("ip6tables -t filter -A VORTEX_GATE_FWD6 -p icmpv6 --icmpv6-type neighbour-solicitation -j RETURN");
        run_cmd("ip6tables -t filter -A VORTEX_GATE_FWD6 -p icmpv6 --icmpv6-type neighbour-advertisement -j RETURN");
        run_cmd("ip6tables -t filter -A VORTEX_GATE_FWD6 -p icmpv6 --icmpv6-type router-solicitation -j RETURN");
        run_cmd("ip6tables -t filter -A VORTEX_GATE_FWD6 -p icmpv6 --icmpv6-type router-advertisement -j RETURN");
        run_cmd("ip6tables -t filter -A VORTEX_GATE_FWD6 -p udp --dport 443 -j REJECT "
                "--reject-with icmp6-port-unreachable");
        run_cmd("ip6tables -t filter -A VORTEX_GATE_FWD6 -p tcp -j REJECT --reject-with tcp-reset");
        run_cmd("ip6tables -t filter -A VORTEX_GATE_FWD6 -p udp -j REJECT --reject-with icmp6-port-unreachable");
        run_cmd("ip6tables -t filter -A VORTEX_GATE_FWD6 -p icmpv6 -j DROP");
    }

    log_line(std::string("[*] LAN divert on ") + lan +
             ": TCP REDIRECT→:" + rp +
             (sticky_dns
                  ? ("  UDP/53→sticky " + format_host_port(dns_up_host, g_cfg.dns_redirect_port))
                  : ("  UDP/53→SOCKS5 " +
                     format_host_port(g_cfg.socks5_host_v4, g_cfg.socks5_port))) +
             "  QUIC/ICMP dropped  (no Fake-IP)");
    return true;
}

// ---- dnsmasq (DHCP + RA); DNS answers come from our stub via --server ----
bool write_dnsmasq_conf(const std::string& path) {
    std::ofstream out(path);
    if (!out) return false;
    out << "# generated by linux_gate — do not edit\n"
        << "interface=" << g_cfg.lan_iface << "\n"
        << "bind-interfaces\n"
        << "except-interface=" << g_cfg.wan_iface << "\n"
        << "except-interface=lo\n"
        << "dhcp-range=" << g_cfg.dhcpv4_start << "," << g_cfg.dhcpv4_end << ","
        << g_cfg.dhcp_lease << "\n"
        << "dhcp-option=option:router," << g_cfg.lan_ipv4 << "\n"
        // IPv4 DNS only → DNAT straight into sticky :53053 (no userspace relay).
        // Sticky still returns AAAA; IPv6 TCP uses redirect_port.
        << "dhcp-option=option:dns-server," << g_cfg.lan_ipv4 << "\n"
        << "no-resolv\n"
        << "port=0\n"; // DHCP/RA only
    if (g_cfg.ipv6_enable && !g_lan_ipv6.empty()) {
        out << "enable-ra\n"
            << "ra-param=" << g_cfg.lan_iface << ",60,600\n"
            << "dhcp-range=::,constructor:" << g_cfg.lan_iface
            << ",ra-stateless,ra-names," << g_cfg.dhcp_lease << "\n";
        // No option6 DNS — force clients onto IPv4 sticky path (faster, still dual-stack TCP).
    }
    return true;
}

void stop_dnsmasq() {
    if (g_dnsmasq_pid > 0) {
        ::kill(g_dnsmasq_pid, SIGTERM);
        int st = 0;
        ::waitpid(g_dnsmasq_pid, &st, 0);
        g_dnsmasq_pid = -1;
    }
    run_cmd("pkill -f 'dnsmasq.*vortex-linux-gate' 2>/dev/null");
}

bool start_dnsmasq() {
    if (!g_cfg.enable_dhcp) return true;
    if (::access("/usr/sbin/dnsmasq", X_OK) != 0 && ::access("/usr/bin/dnsmasq", X_OK) != 0) {
        std::cerr << "[-] dnsmasq not found — install it for DHCP/RA; LAN IP is still up\n";
        return true;
    }
    const std::string conf = g_run_dir + "/dnsmasq.conf";
    const std::string pidf = g_run_dir + "/dnsmasq.pid";
    if (!write_dnsmasq_conf(conf)) return false;
    stop_dnsmasq();
    const std::string bin = (::access("/usr/sbin/dnsmasq", X_OK) == 0) ? "/usr/sbin/dnsmasq"
                                                                        : "/usr/bin/dnsmasq";
    const std::string cmd = bin + " -C " + conf + " -x " + pidf + " --log-facility=-";
    const int rc = run_cmd(cmd);
    if (rc != 0) {
        std::cerr << "[-] dnsmasq start failed (rc=" << rc << ")\n";
        return false;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));
    std::ifstream in(pidf);
    if (in) in >> g_dnsmasq_pid;
    log_line("[*] dnsmasq DHCP/RA on " + g_cfg.lan_iface + " (dns via our :" +
             std::to_string(g_cfg.dns_udp_port) + ")");
    return true;
}

// ---- SOCKS5 DNS (UDP on LAN → TCP via SOCKS) ----
socket_t socks5_dial() {
    for (const auto& host : g_cfg.socks5_hosts()) {
        socket_t s = tcp_connect(host, g_cfg.socks5_port, 5);
        if (s != INVALID_SOCK) return s;
    }
    return INVALID_SOCK;
}

std::string dns_qname(const uint8_t* data, size_t n) {
    if (n < 13) return "?";
    size_t i = 12;
    std::string out;
    while (i < n) {
        const uint8_t lab = data[i++];
        if (lab == 0) break;
        if ((lab & 0xc0) == 0xc0) break; // compression — stop
        if (lab > 63 || i + lab > n) break;
        if (!out.empty()) out.push_back('.');
        out.append(reinterpret_cast<const char*>(data + i), lab);
        i += lab;
    }
    return out.empty() ? "?" : out;
}

bool socks5_dns_tcp_one(const uint8_t* dns4, const uint8_t* query, size_t qlen,
                        std::vector<uint8_t>& answer) {
    socket_t s = socks5_dial();
    if (s == INVALID_SOCK) return false;
    const uint8_t greet[3] = {0x05, 0x01, 0x00};
    if (!send_all(s, greet, 3)) { net_close(s); return false; }
    uint8_t grepr[2];
    if (!recv_exact(s, grepr, 2) || grepr[0] != 0x05 || grepr[1] != 0x00) {
        net_close(s);
        return false;
    }

    // CONNECT dns4:53 — DNS-over-TCP through SOCKS (multilink/linux_network rules)
    uint8_t req[10] = {0x05, 0x01, 0x00, 0x01,
                       dns4[0], dns4[1], dns4[2], dns4[3], 0, 53};
    if (!send_all(s, req, sizeof(req))) { net_close(s); return false; }
    uint8_t rrep[4];
    if (!recv_exact(s, rrep, 4) || rrep[1] != 0x00) { net_close(s); return false; }
    if (rrep[3] == 0x01) {
        uint8_t skip[6];
        if (!recv_exact(s, skip, 6)) { net_close(s); return false; }
    } else if (rrep[3] == 0x04) {
        uint8_t skip[18];
        if (!recv_exact(s, skip, 18)) { net_close(s); return false; }
    } else if (rrep[3] == 0x03) {
        uint8_t nl = 0;
        if (!recv_exact(s, &nl, 1)) { net_close(s); return false; }
        std::vector<uint8_t> skip(static_cast<size_t>(nl) + 2);
        if (!recv_exact(s, skip.data(), skip.size())) { net_close(s); return false; }
    } else {
        net_close(s);
        return false;
    }

    uint8_t lenb[2] = {static_cast<uint8_t>(qlen >> 8), static_cast<uint8_t>(qlen & 0xff)};
    if (!send_all(s, lenb, 2) || !send_all(s, query, qlen)) { net_close(s); return false; }
    if (!recv_exact(s, lenb, 2)) { net_close(s); return false; }
    const size_t alen = (static_cast<size_t>(lenb[0]) << 8) | lenb[1];
    if (alen == 0 || alen > 4096) { net_close(s); return false; }
    answer.resize(alen);
    if (!recv_exact(s, answer.data(), alen)) { net_close(s); return false; }
    net_close(s);
    return true;
}

bool socks5_dns_tcp(const uint8_t* query, size_t qlen, std::vector<uint8_t>& answer) {
    // Prefer public recursive resolvers reached only via SOCKS — never local :53053.
    static const uint8_t ups[][4] = {
        {1, 1, 1, 1},
        {8, 8, 8, 8},
        {9, 9, 9, 9},
    };
    for (const auto& ip : ups) {
        answer.clear();
        if (socks5_dns_tcp_one(ip, query, qlen, answer)) return true;
    }
    return false;
}

std::string dns_cache_key(const uint8_t* data, size_t n) {
    // qname + qtype (2 bytes after qname)
    const std::string qn = dns_qname(data, n);
    uint16_t qtype = 0;
    size_t i = 12;
    while (i < n) {
        const uint8_t lab = data[i++];
        if (lab == 0) break;
        if ((lab & 0xc0) == 0xc0) { i += 1; break; }
        i += lab;
    }
    if (i + 2 <= n) qtype = static_cast<uint16_t>((data[i] << 8) | data[i + 1]);
    return qn + "|" + std::to_string(qtype);
}

bool dns_cache_get(const std::string& key, uint16_t want_id, std::vector<uint8_t>& answer) {
    std::lock_guard<std::mutex> lock(g_dns_cache_mu);
    auto it = g_dns_cache.find(key);
    if (it == g_dns_cache.end()) return false;
    if (std::chrono::steady_clock::now() >= it->second.expire) {
        g_dns_cache.erase(it);
        return false;
    }
    answer = it->second.answer;
    if (answer.size() >= 2) {
        answer[0] = static_cast<uint8_t>(want_id >> 8);
        answer[1] = static_cast<uint8_t>(want_id & 0xff);
    }
    return true;
}

void dns_cache_put(const std::string& key, const std::vector<uint8_t>& answer) {
    if (answer.size() < 12) return;
    std::lock_guard<std::mutex> lock(g_dns_cache_mu);
    if (g_dns_cache.size() > 4096) g_dns_cache.clear();
    DnsCacheEnt e;
    e.answer = answer;
    e.expire = std::chrono::steady_clock::now() + std::chrono::seconds(kDnsCacheTtlSec);
    g_dns_cache[key] = std::move(e);
}

// UDP relay to linux_network sticky DNS — real A/AAAA + IP→name learn (no Fake-IP).
// Reuses a connected datagram socket per thread (avoid open/close per query).
bool sticky_dns_udp(const uint8_t* query, size_t qlen, std::vector<uint8_t>& answer) {
    thread_local socket_t tls_fd = INVALID_SOCK;
    thread_local int tls_port = -1;
    if (tls_fd == INVALID_SOCK || tls_port != g_cfg.dns_redirect_port) {
        if (tls_fd != INVALID_SOCK) net_close(tls_fd);
        tls_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        tls_port = g_cfg.dns_redirect_port;
        if (tls_fd < 0) { tls_fd = INVALID_SOCK; return false; }
        timeval tv{};
        tv.tv_sec = 3;
        tv.tv_usec = 0;
        setsockopt(tls_fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_port = htons(static_cast<uint16_t>(g_cfg.dns_redirect_port));
        if (inet_pton(AF_INET, g_cfg.dns_redirect_host_v4.c_str(), &dst.sin_addr) != 1 ||
            ::connect(tls_fd, reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) != 0) {
            net_close(tls_fd);
            tls_fd = INVALID_SOCK;
            return false;
        }
    }
    if (::send(tls_fd, query, qlen, 0) < 0) {
        net_close(tls_fd);
        tls_fd = INVALID_SOCK;
        return false;
    }
    uint8_t buf[4096];
    const ssize_t n = ::recv(tls_fd, buf, sizeof(buf), 0);
    if (n < 12) return false;
    answer.assign(buf, buf + n);
    return true;
}

void handle_dns_datagram(const uint8_t* data, size_t n, const sockaddr* peer, socklen_t plen,
                         int reply_fd) {
    if (n < 12 || n > 2048) return;
    const uint16_t qid = static_cast<uint16_t>((data[0] << 8) | data[1]);
    const std::string key = dns_cache_key(data, n);
    std::vector<uint8_t> answer;
    if (dns_cache_get(key, qid, answer)) {
        ::sendto(reply_fd, answer.data(), answer.size(), 0, peer, plen);
        return;
    }
    const bool sticky = (g_cfg.dns_redirect_port > 0);
    const bool ok = sticky ? sticky_dns_udp(data, n, answer) : socks5_dns_tcp(data, n, answer);
    if (!ok || answer.size() < 12) {
        log_line(std::string("[-] DNS ") + (sticky ? "sticky" : "SOCKS") + " fail q=" +
                 dns_qname(data, n));
        std::vector<uint8_t> fail(data, data + n);
        fail[2] = static_cast<uint8_t>((fail[2] & 0x80) | 0x80);
        fail[3] = static_cast<uint8_t>((fail[3] & 0xf0) | 0x02);
        ::sendto(reply_fd, fail.data(), fail.size(), 0, peer, plen);
        return;
    }
    dns_cache_put(key, answer);
    ::sendto(reply_fd, answer.data(), answer.size(), 0, peer, plen);
}

bool port_is_listening4(const std::string& host, int port) {
    // /proc/net/{tcp,udp} local_address is hex(IP):hex(port). On little-endian
    // hosts the IP dword matches in_addr.s_addr as stored (network order bytes
    // interpreted as host uint32) — do NOT ntohl() before compare.
    in_addr want{};
    if (inet_pton(AF_INET, host.c_str(), &want) != 1) return false;
    const uint32_t want_ip = static_cast<uint32_t>(want.s_addr);
    const uint16_t want_port = static_cast<uint16_t>(port);
    auto scan = [&](const char* path) {
        std::ifstream in(path);
        if (!in) return false;
        std::string line;
        std::getline(in, line); // header
        while (std::getline(in, line)) {
            std::istringstream ss(line);
            std::string sl, local;
            ss >> sl >> local;
            const auto colon = local.find(':');
            if (colon == std::string::npos) continue;
            uint32_t ip = 0;
            uint32_t p = 0;
            try {
                ip = static_cast<uint32_t>(std::stoul(local.substr(0, colon), nullptr, 16));
                // port hex is network-order digits, e.g. 53 → "0035" → 0x35 == 53
                p = static_cast<uint32_t>(std::stoul(local.substr(colon + 1), nullptr, 16));
            } catch (...) { continue; }
            if (static_cast<uint16_t>(p) != want_port) continue;
            if (ip == want_ip || ip == 0) return true;
        }
        return false;
    };
    return scan("/proc/net/udp") || scan("/proc/net/tcp") ||
           scan("/proc/net/udp6") || scan("/proc/net/tcp6");
}

bool open_dns_listeners() {
    int one = 1;
    const bool sticky = (g_cfg.dns_redirect_port > 0);

    if (sticky) {
        if (!port_is_listening4(g_cfg.dns_redirect_host_v4, g_cfg.dns_redirect_port)) {
            log_line("[-] warn: sticky DNS " +
                     format_host_port(g_cfg.dns_redirect_host_v4, g_cfg.dns_redirect_port) +
                     " not listening — start linux_network first");
        } else {
            log_line("[*] DNS IPv4 UDP/53 DNAT → sticky " +
                     format_host_port(g_cfg.dns_redirect_host_v4, g_cfg.dns_redirect_port) +
                     " (real A/AAAA + learn)");
        }
    } else {
        // Fallback: gate SOCKS DoT stub (no IP→name learn in linux_network).
        g_dns4_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
        if (g_dns4_fd < 0) return false;
        setsockopt(g_dns4_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
        sockaddr_in a4{};
        a4.sin_family = AF_INET;
        a4.sin_port = htons(static_cast<uint16_t>(g_cfg.dns_udp_port));
        a4.sin_addr.s_addr = htonl(INADDR_ANY);
        if (bind(g_dns4_fd, reinterpret_cast<sockaddr*>(&a4), sizeof(a4)) != 0) {
            std::cerr << "[-] bind DNS UDP 0.0.0.0:" << g_cfg.dns_udp_port << " failed\n";
            return false;
        }
        log_line("[*] DNS UDP/53 → SOCKS5 stub (set dns_redirect_port=53053 for sticky learn)");
    }

    // IPv6: always local :dns_udp_port — sticky relay or SOCKS stub.
    if (g_cfg.ipv6_enable) {
        g_dns6_fd = ::socket(AF_INET6, SOCK_DGRAM, 0);
        if (g_dns6_fd >= 0) {
            setsockopt(g_dns6_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
            int v6only = 1;
            setsockopt(g_dns6_fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only));
            sockaddr_in6 a6{};
            a6.sin6_family = AF_INET6;
            a6.sin6_port = htons(static_cast<uint16_t>(g_cfg.dns_udp_port));
            a6.sin6_addr = in6addr_any;
            if (bind(g_dns6_fd, reinterpret_cast<sockaddr*>(&a6), sizeof(a6)) != 0) {
                ::close(g_dns6_fd);
                g_dns6_fd = -1;
                log_line("[-] bind DNS UDPv6 :" + std::to_string(g_cfg.dns_udp_port) + " failed");
            } else {
                log_line(std::string("[*] DNS UDPv6 → ") +
                         (sticky ? "sticky relay" : "SOCKS5 stub") + " :" +
                         std::to_string(g_cfg.dns_udp_port));
            }
        }
    }
    return true;
}

void dns_loop() {
    uint8_t buf[2048];
    while (g_run.load()) {
        pollfd pf[2]{};
        int nfd = 0;
        if (g_dns4_fd >= 0) { pf[nfd].fd = g_dns4_fd; pf[nfd].events = POLLIN; ++nfd; }
        if (g_dns6_fd >= 0) { pf[nfd].fd = g_dns6_fd; pf[nfd].events = POLLIN; ++nfd; }
        if (nfd == 0) break;
        const int pr = ::poll(pf, nfd, 200);
        if (pr < 0) {
            if (errno == EINTR) continue;
            break;
        }
        for (int i = 0; i < nfd; ++i) {
            if (!(pf[i].revents & POLLIN)) continue;
            sockaddr_storage peer{};
            socklen_t plen = sizeof(peer);
            const int n = static_cast<int>(::recvfrom(pf[i].fd, buf, sizeof(buf), 0,
                                                      reinterpret_cast<sockaddr*>(&peer), &plen));
            if (n <= 0) continue;
            // Parallel resolve — do not block the recv loop on sticky RTT.
            if (g_dns_inflight.load() >= kDnsMaxInflight) continue;
            ++g_dns_inflight;
            std::vector<uint8_t> q(buf, buf + n);
            const int rfd = pf[i].fd;
            std::thread([q = std::move(q), peer, plen, rfd]() mutable {
                struct Guard {
                    ~Guard() { --g_dns_inflight; }
                } guard;
                handle_dns_datagram(q.data(), q.size(),
                                    reinterpret_cast<sockaddr*>(&peer), plen, rfd);
            }).detach();
        }
    }
}

void cleanup_all() {
    g_run = false;
    stop_dnsmasq();
    iptables_uninstall();
    teardown_lan_addrs();
    if (g_dns4_fd >= 0) { ::close(g_dns4_fd); g_dns4_fd = -1; }
    if (g_dns6_fd >= 0) { ::close(g_dns6_fd); g_dns6_fd = -1; }
    if (g_lock_fd >= 0) { ::close(g_lock_fd); g_lock_fd = -1; }
}

} // namespace

int main(int argc, char** argv) {
    std::string config_path = "config/linux_gate.json";
    bool stop_only = false;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--stop") stop_only = true;
        else if (a == "-h" || a == "--help") {
            std::cout << "Usage: sudo " << argv[0] << " [config.json]\n"
                      << "       sudo " << argv[0] << " --stop [config.json]\n";
            return 0;
        } else if (!a.empty() && a[0] != '-') config_path = a;
    }

    if (geteuid() != 0) {
        std::cerr << "[-] root required (LAN + iptables). Use sudo.\n";
        return 1;
    }

    try {
        g_cfg = LinuxGateConfig::load(config_path);
    } catch (const std::exception& e) {
        // --stop with missing config: still try uninstall with defaults
        if (!stop_only) {
            std::cerr << "[-] " << e.what() << "\n";
            return 1;
        }
    }

    if (stop_only) {
        stop_dnsmasq();
        iptables_uninstall();
        teardown_lan_addrs();
        std::cout << "[*] linux_gate stopped / cleaned\n";
        return 0;
    }

    if (!iface_exists(g_cfg.lan_iface)) {
        std::cerr << "[-] lan_iface " << g_cfg.lan_iface << " not found\n";
        return 1;
    }
    if (!iface_exists(g_cfg.wan_iface)) {
        std::cerr << "[-] wan_iface " << g_cfg.wan_iface << " not found\n";
        return 1;
    }
    if (!net_init()) {
        std::cerr << "[-] net_init failed\n";
        return 1;
    }
    if (!acquire_lock()) {
        net_cleanup();
        return 1;
    }

    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    std::signal(SIGPIPE, SIG_IGN);

    log_line("[*] LinuxGate — LAN gateway on " + g_cfg.lan_iface +
             " (wan " + g_cfg.wan_iface + " read-only)");
    log_line("[*] config " + config_path);
    log_line("[*] redirect " + format_host_port(g_cfg.redirect_host_v4, g_cfg.redirect_port) +
             " / " + format_host_port(g_cfg.redirect_host_v6, g_cfg.redirect_port));
    log_line("[*] SOCKS via " + format_host_port(g_cfg.socks5_host_v4, g_cfg.socks5_port) +
             " / " + format_host_port(g_cfg.socks5_host_v6, g_cfg.socks5_port));

    setup_sysctl_forward();
    setup_lan_ipv4();
    setup_lan_ipv6();
    if (!open_dns_listeners()) {
        cleanup_all();
        net_cleanup();
        return 1;
    }
    if (!iptables_install()) {
        cleanup_all();
        net_cleanup();
        return 1;
    }
    start_dnsmasq();

    std::thread dns_thr(dns_loop);

    log_line("[*] clients: DHCP from " + g_cfg.dhcpv4_start + "-" + g_cfg.dhcpv4_end +
             " gw=" + g_cfg.lan_ipv4 +
             (g_lan_ipv6.empty() ? "" : " ipv6=" + g_lan_ipv6));
    log_line("[*] model=linux_network divert on " + g_cfg.lan_iface +
             " (sticky DNS + TCP REDIRECT, no Fake-IP, no ICMP-SOCKS); Ctrl+C cleans LAN only");

    while (g_run.load()) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    cleanup_all();
    if (dns_thr.joinable()) dns_thr.join();
    net_cleanup();
    std::cout << "[*] linux_gate stopped\n";
    return 0;
}
