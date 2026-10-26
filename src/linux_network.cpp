// LinuxNetwork: MultiLink + redir-host transparent proxy in ONE process.
// Linux equivalent of src/internet.cpp (WinDivert) — NO TUN.
//
// Config: same JSON as multilink.json / internet.json (InternetConfig).
// Apps need no proxy settings. Requires root (iptables).
//
// Architecture (mirrors internet.exe):
//   1) In-process MultiLink SOCKS5 on 127.0.0.1
//   2) iptables OUTPUT: own SO_MARK traffic NEVER hijacked (no self-bite)
//   3) Sticky redir-host DNS via REDIRECT UDP/53 → local DNS
//   4) TCP REDIRECT → local transparent port:
//        learned IP → SOCKS CONNECT(domain) → MultiLink
//        unlearned  → marked direct (WinDivert reinject equivalent)
//   5) REJECT UDP/443+853 so stacks fall back to TCP
//
// Usage:
//   sudo ./linux_network config/internet.json
//   ./linux_network --router-only config/internet.json

#ifndef __linux__
#error linux_network.cpp is Linux-only (iptables transparent proxy).
#endif

#include "config.hpp"
#include "net.hpp"
#include "packet_build.hpp"
#include "protocol.hpp"
#include "rules.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/netfilter_ipv4.h>
#include <poll.h>
#include <csignal>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace linux_self {
// Mirrors internet_self in internet.cpp: mark + sport registry so our egress is never hijacked.

constexpr uint32_t kMark = 0x564e4554u; // 'VNET'

inline bool set_mark(socket_t s) {
    const int m = static_cast<int>(kMark);
    return setsockopt(s, SOL_SOCKET, SO_MARK, &m, sizeof(m)) == 0;
}

inline std::mutex g_mu;
inline std::unordered_set<uint16_t> g_sports;
inline std::unordered_set<uint32_t> g_uplink_nets; // network-order IPv4

inline void register_port(uint16_t sport) {
    if (!sport) return;
    std::lock_guard<std::mutex> lock(g_mu);
    g_sports.insert(sport);
}
inline void unregister_port(uint16_t sport) {
    if (!sport) return;
    std::lock_guard<std::mutex> lock(g_mu);
    g_sports.erase(sport);
}
inline void register_socket(socket_t s) {
    sockaddr_in a{};
    socklen_type alen = sizeof(a);
    if (getsockname(s, reinterpret_cast<sockaddr*>(&a), &alen) != 0) return;
    register_port(ntohs(a.sin_port));
}
inline void unregister_socket(socket_t s) {
    sockaddr_in a{};
    socklen_type alen = sizeof(a);
    if (getsockname(s, reinterpret_cast<sockaddr*>(&a), &alen) != 0) return;
    unregister_port(ntohs(a.sin_port));
}
inline bool is_own_sport(uint16_t sport) {
    std::lock_guard<std::mutex> lock(g_mu);
    return g_sports.count(sport) != 0;
}
inline void clear_uplink_ipv4() {
    std::lock_guard<std::mutex> lock(g_mu);
    g_uplink_nets.clear();
}
inline void add_uplink_ipv4(uint32_t net_order) {
    if (!net_order) return;
    std::lock_guard<std::mutex> lock(g_mu);
    g_uplink_nets.insert(net_order);
}
inline bool is_uplink_ipv4(uint32_t net_order) {
    std::lock_guard<std::mutex> lock(g_mu);
    return g_uplink_nets.count(net_order) != 0;
}

// internet.cpp tcp_connect_registered: bind → register → connect. Plus SO_MARK.
inline socket_t tcp_connect_registered(const std::string& host, int port, int idle_timeout_sec) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res) {
        return INVALID_SOCK;
    }
    socket_t fd = INVALID_SOCK;
    for (addrinfo* p = res; p; p = p->ai_next) {
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd == INVALID_SOCK) continue;
        set_mark(fd);
        set_socket_options(fd, idle_timeout_sec);
        sockaddr_in local{};
        local.sin_family = AF_INET;
        local.sin_addr.s_addr = htonl(INADDR_ANY);
        local.sin_port = 0;
        if (::bind(fd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
            net_close(fd);
            fd = INVALID_SOCK;
            continue;
        }
        register_socket(fd);
        if (::connect(fd, p->ai_addr, static_cast<socklen_type>(p->ai_addrlen)) == 0) break;
        unregister_socket(fd);
        net_close(fd);
        fd = INVALID_SOCK;
    }
    freeaddrinfo(res);
    return fd;
}

inline socket_t tcp_connect_marked(const std::string& host, int port, int idle_timeout_sec) {
    return tcp_connect_registered(host, port, idle_timeout_sec);
}
inline socket_t tcp_connect_direct_marked(const std::string& host, int port, int idle_timeout_sec) {
    return tcp_connect_registered(host, port, idle_timeout_sec);
}

inline socket_t udp_socket_marked() {
    socket_t fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == INVALID_SOCK) return INVALID_SOCK;
    set_mark(fd);
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = 0;
    if (::bind(fd, reinterpret_cast<sockaddr*>(&local), sizeof(local)) == 0) register_socket(fd);
    return fd;
}

} // namespace linux_self

using ResolveHostFn = std::string (*)(const std::string&);
ResolveHostFn g_resolve_host_for_direct = nullptr;

// ---------------------------------------------------------------------------
// MultiLink SOCKS5 router (same behavior as multilink.cpp / internet router)
// ---------------------------------------------------------------------------
namespace router_detail {

std::atomic<bool> g_running{true};
rules::Engine g_rules;
std::mutex g_log_mu;

void log_line(const std::string& s) {
    std::lock_guard<std::mutex> lock(g_log_mu);
    std::cout << s << std::endl;
}

std::mutex g_name_mu;
std::unordered_map<uint32_t, std::pair<std::string, std::chrono::steady_clock::time_point>> g_ip_name;

void remember_ip_name(uint32_t ip_host, const std::string& name) {
    if (name.empty()) return;
    std::lock_guard<std::mutex> lock(g_name_mu);
    g_ip_name[ip_host] = {name, std::chrono::steady_clock::now()};
}

std::string cached_name(uint32_t ip_host) {
    std::lock_guard<std::mutex> lock(g_name_mu);
    auto it = g_ip_name.find(ip_host);
    if (it == g_ip_name.end()) return {};
    if (std::chrono::steady_clock::now() - it->second.second > std::chrono::minutes(10)) {
        g_ip_name.erase(it);
        return {};
    }
    return it->second.first;
}

size_t dns_skip_name(const uint8_t* msg, size_t len, size_t off) {
    int hops = 0;
    while (off < len && hops < 64) {
        const uint8_t lab = msg[off];
        if (lab == 0) return off + 1;
        if ((lab & 0xC0) == 0xC0) return off + 2 < len ? off + 2 : len;
        if (off + 1 + lab > len) return len;
        off += 1 + lab;
        ++hops;
    }
    return len;
}

std::string dns_qname(const uint8_t* msg, size_t len) {
    if (len < 12) return {};
    size_t off = 12;
    std::string name;
    int hops = 0;
    while (off < len && hops < 64) {
        const uint8_t lab = msg[off++];
        if (lab == 0) break;
        if ((lab & 0xC0) == 0xC0 || off + lab > len) return {};
        if (!name.empty()) name.push_back('.');
        name.append(reinterpret_cast<const char*>(msg + off), lab);
        off += lab;
        ++hops;
    }
    return rules::to_lower(name);
}

void remember_dns_answers(const uint8_t* msg, size_t len, const std::string& qname) {
    if (len < 12 || qname.empty()) return;
    const int qd = (msg[4] << 8) | msg[5];
    const int an = (msg[6] << 8) | msg[7];
    size_t off = 12;
    for (int i = 0; i < qd; ++i) {
        off = dns_skip_name(msg, len, off);
        if (off + 4 > len) return;
        off += 4;
    }
    for (int i = 0; i < an; ++i) {
        off = dns_skip_name(msg, len, off);
        if (off + 10 > len) return;
        const int typ = (msg[off] << 8) | msg[off + 1];
        const int rdlen = (msg[off + 8] << 8) | msg[off + 9];
        off += 10;
        if (off + static_cast<size_t>(rdlen) > len) return;
        if (typ == 1 && rdlen == 4) {
            uint32_t net = 0;
            std::memcpy(&net, msg + off, 4);
            remember_ip_name(ntohl(net), qname);
        }
        off += static_cast<size_t>(rdlen);
    }
}

bool is_loopback_v4_literal(const std::string& ip) {
    in_addr a{};
    if (inet_pton(AF_INET, ip.c_str(), &a) != 1) return false;
    return (ntohl(a.s_addr) >> 24) == 127u; // 127.0.0.0/8 (incl. systemd-resolved 127.0.0.53)
}

bool is_fakeip_v4_literal(const std::string& ip) {
    in_addr a{};
    if (inet_pton(AF_INET, ip.c_str(), &a) != 1) return false;
    // 198.18.0.0/15 — our TUN / sink / stand-in pool (never a real uplink resolver)
    return (ntohl(a.s_addr) & 0xFFFE0000u) == 0xC6120000u;
}

// Prefer real uplink resolvers. Never return 127/8 or 198.18/15 (self-loop after hijack).
std::string system_dns_server() {
    const char* paths[] = {
        "/run/systemd/resolve/resolv.conf", // real uplink DNS (not the stub)
        "/etc/resolv.conf",
    };
    for (const char* path : paths) {
        std::ifstream in(path);
        if (!in) continue;
        std::string line;
        while (std::getline(in, line)) {
            if (line.rfind("nameserver ", 0) != 0) continue;
            std::string ip = line.substr(11);
            const auto sp = ip.find_first_of(" \t#");
            if (sp != std::string::npos) ip.resize(sp);
            if (ip.empty() || ip == "::1" || is_loopback_v4_literal(ip) || is_fakeip_v4_literal(ip))
                continue;
            return ip;
        }
    }
    return "223.5.5.5";
}

struct Session {
    socket_t local_fd = INVALID_SOCK;
    socket_t remote_fd = INVALID_SOCK;
    std::atomic<bool> alive{true};
    LinkEndpoint link;
    int idle_timeout_sec = 300;
    vortex::SessionCrypto up;
    vortex::SessionCrypto down;
    bool via_proxy = false;

    ~Session() {
        alive = false;
        if (remote_fd != INVALID_SOCK) {
            shutdown_both(remote_fd);
            net_close(remote_fd);
            remote_fd = INVALID_SOCK;
        }
        if (local_fd != INVALID_SOCK) {
            shutdown_both(local_fd);
            net_close(local_fd);
            local_fd = INVALID_SOCK;
        }
    }
};

struct SocksTarget {
    uint8_t atyp = 0;
    std::string host;
    uint16_t port = 0;
    bool has_ipv4 = false;
    uint32_t ipv4_host = 0;
    std::vector<uint8_t> wire;
};

bool socks5_read_target(socket_t local_fd, SocksTarget& t) {
    uint8_t hdr[2];
    if (!recv_exact(local_fd, hdr, 2)) return false;
    if (hdr[0] != 0x05) return false;
    const uint8_t nmethods = hdr[1];
    if (nmethods == 0) return false;
    std::vector<uint8_t> methods(nmethods);
    if (!recv_exact(local_fd, methods.data(), nmethods)) return false;

    const uint8_t method_ok[2] = {0x05, 0x00};
    if (!send_all(local_fd, method_ok, 2)) return false;

    uint8_t req[4];
    if (!recv_exact(local_fd, req, 4)) return false;
    if (req[0] != 0x05 || req[1] != 0x01) {
        const uint8_t fail[] = {0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        send_all(local_fd, fail, sizeof(fail));
        return false;
    }

    t.atyp = req[3];
    t.wire.clear();
    t.wire.push_back(t.atyp);

    if (t.atyp == vortex::ATYP_IPV4) {
        uint8_t ip[4];
        if (!recv_exact(local_fd, ip, 4)) return false;
        t.wire.insert(t.wire.end(), ip, ip + 4);
        char buf[INET_ADDRSTRLEN] = {};
        in_addr a{};
        std::memcpy(&a.s_addr, ip, 4);
        inet_ntop(AF_INET, &a, buf, sizeof(buf));
        t.host = buf;
        t.has_ipv4 = true;
        t.ipv4_host = ntohl(a.s_addr);
    } else if (t.atyp == vortex::ATYP_DOMAIN) {
        uint8_t len = 0;
        if (!recv_exact(local_fd, &len, 1)) return false;
        if (len == 0) return false;
        t.wire.push_back(len);
        std::vector<uint8_t> domain(len);
        if (!recv_exact(local_fd, domain.data(), len)) return false;
        t.wire.insert(t.wire.end(), domain.begin(), domain.end());
        t.host.assign(reinterpret_cast<char*>(domain.data()), domain.size());
    } else if (t.atyp == vortex::ATYP_IPV6) {
        uint8_t ip[16];
        if (!recv_exact(local_fd, ip, 16)) return false;
        t.wire.insert(t.wire.end(), ip, ip + 16);
        char buf[INET6_ADDRSTRLEN] = {};
        inet_ntop(AF_INET6, ip, buf, sizeof(buf));
        t.host = buf;
    } else {
        const uint8_t fail[] = {0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        send_all(local_fd, fail, sizeof(fail));
        return false;
    }

    uint8_t port_bytes[2];
    if (!recv_exact(local_fd, port_bytes, 2)) return false;
    t.wire.insert(t.wire.end(), port_bytes, port_bytes + 2);
    t.port = static_cast<uint16_t>((port_bytes[0] << 8) | port_bytes[1]);
    return true;
}

void reply_socks_fail(socket_t fd, uint8_t code) {
    const uint8_t fail[] = {0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    send_all(fd, fail, sizeof(fail));
}

bool reply_socks_ok(socket_t fd) {
    const uint8_t success[] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    return send_all(fd, success, sizeof(success));
}

void relay_raw(socket_t from, socket_t to, std::shared_ptr<Session> s) {
    std::vector<uint8_t> buf(static_cast<size_t>(s->link.max_payload > 0 ? s->link.max_payload : 32768));
    while (s->alive && g_running) {
        const int n = recv_some(from, buf.data(), buf.size());
        if (n <= 0) break;
        if (!send_all(to, buf.data(), static_cast<size_t>(n))) break;
    }
    s->alive = false;
    shutdown_both(s->local_fd);
    shutdown_both(s->remote_fd);
}

void relay_proxy_down(std::shared_ptr<Session> s) {
    while (s->alive && g_running) {
        auto frame = vortex::recv_frame(s->remote_fd, s->down, s->link.max_payload);
        if (!frame.ok) break;
        if (frame.cmd == vortex::CMD_DATA) {
            if (!frame.data.empty()) {
                if (!send_all(s->local_fd, frame.data.data(), frame.data.size())) break;
            }
        } else if (frame.cmd == vortex::CMD_CLOSE) {
            break;
        } else {
            break;
        }
    }
    s->alive = false;
    shutdown_both(s->local_fd);
    shutdown_both(s->remote_fd);
}

bool host_is_ipv4_literal(const std::string& host) {
    in_addr a{};
    return inet_pton(AF_INET, host.c_str(), &a) == 1;
}

void prefer_remote_dns_wire(SocksTarget& t, const std::string& domain) {
    if (domain.empty() || domain.size() > 255) return;
    if (host_is_ipv4_literal(domain)) return;
    t.atyp = vortex::ATYP_DOMAIN;
    t.host = domain;
    t.has_ipv4 = false;
    t.ipv4_host = 0;
    t.wire.clear();
    t.wire.push_back(vortex::ATYP_DOMAIN);
    t.wire.push_back(static_cast<uint8_t>(domain.size()));
    t.wire.insert(t.wire.end(), domain.begin(), domain.end());
    t.wire.push_back(static_cast<uint8_t>(t.port >> 8));
    t.wire.push_back(static_cast<uint8_t>(t.port & 0xFF));
}

bool open_proxy(std::shared_ptr<Session> s, const SocksTarget& t) {
    socket_t remote_fd =
        linux_self::tcp_connect_marked(s->link.server_ip, s->link.server_port, s->idle_timeout_sec);
    if (remote_fd == INVALID_SOCK) {
        log_line("[-] uplink TCP failed " + s->link.name + " " + s->link.server_ip + ":" +
                 std::to_string(s->link.server_port));
        return false;
    }
    s->remote_fd = remote_fd;
    s->via_proxy = true;

    uint64_t salt = get_random_salt();
    uint8_t salt_buf[8];
    std::memcpy(salt_buf, &salt, 8);
    if (!send_all(remote_fd, salt_buf, 8)) return false;

    s->up.init(s->link.master_secret, salt);
    s->down.init(s->link.master_secret, salt ^ 0xA5A5A5A5A5A5A5A5ULL);

    const bool via_peer = !s->link.peer_secret.empty();
    if (via_peer) {
        const auto payload = vortex::build_via_peer_payload(s->link.peer_secret, t.wire);
        if (payload.empty() ||
            !vortex::send_frame(remote_fd, s->up, vortex::CMD_VIA_PEER, payload,
                                s->link.padding_min, s->link.padding_max)) {
            log_line("[-] VIA_PEER send failed via " + s->link.name + " " + t.host + ":" +
                     std::to_string(t.port));
            return false;
        }
    } else if (!vortex::send_frame(remote_fd, s->up, vortex::CMD_CONNECT, t.wire,
                                   s->link.padding_min, s->link.padding_max)) {
        log_line("[-] CONNECT send failed via " + s->link.name + " " + t.host + ":" +
                 std::to_string(t.port));
        return false;
    }
    auto reply = vortex::recv_frame(remote_fd, s->down, s->link.max_payload);
    if (!reply.ok || reply.cmd != vortex::CMD_CONNECT_OK) {
        log_line(std::string("[-] ") + (via_peer ? "VIA_PEER" : "CONNECT") +
                 " rejected via " + s->link.name + " " + t.host + ":" +
                 std::to_string(t.port) +
                 (reply.ok ? " cmd=" + std::to_string(reply.cmd) : " (frame)"));
        return false;
    }
    return true;
}

bool dns_query_direct(const uint8_t* query, size_t qlen, std::vector<uint8_t>& answer) {
    const std::string dns = system_dns_server();
    socket_t fd = linux_self::udp_socket_marked();
    if (fd == INVALID_SOCK) return false;
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    if (inet_pton(AF_INET, dns.c_str(), &dst.sin_addr) != 1) {
        net_close(fd);
        return false;
    }
    timeval tv{};
    tv.tv_sec = 3;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    if (sendto(fd, query, qlen, 0, reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) < 0) {
        net_close(fd);
        return false;
    }
    answer.resize(2048);
    const int n = static_cast<int>(
        recvfrom(fd, answer.data(), answer.size(), 0, nullptr, nullptr));
    net_close(fd);
    if (n <= 0) return false;
    answer.resize(static_cast<size_t>(n));
    return true;
}

bool dns_query_proxy(std::shared_ptr<Session> s, const SocksTarget& t,
                     const uint8_t* framed, size_t framed_len, std::vector<uint8_t>& framed_out) {
    if (!open_proxy(s, t)) return false;
    if (!vortex::send_frame(s->remote_fd, s->up, vortex::CMD_DATA,
                            framed, framed_len, s->link.padding_min, s->link.padding_max)) {
        return false;
    }
    framed_out.clear();
    while (framed_out.size() < 2) {
        auto frame = vortex::recv_frame(s->remote_fd, s->down, s->link.max_payload);
        if (!frame.ok || frame.cmd != vortex::CMD_DATA) return false;
        framed_out.insert(framed_out.end(), frame.data.begin(), frame.data.end());
    }
    const size_t need = 2 + (static_cast<size_t>(framed_out[0]) << 8 | framed_out[1]);
    while (framed_out.size() < need) {
        auto frame = vortex::recv_frame(s->remote_fd, s->down, s->link.max_payload);
        if (!frame.ok || frame.cmd != vortex::CMD_DATA) return false;
        framed_out.insert(framed_out.end(), frame.data.begin(), frame.data.end());
    }
    if (framed_out.size() > need) framed_out.resize(need);
    vortex::send_frame(s->remote_fd, s->up, vortex::CMD_CLOSE,
                       nullptr, 0, s->link.padding_min, s->link.padding_max);
    return need > 2;
}

bool select_link(const MultilinkConfig& cfg, const rules::Decision& decision,
                 LinkEndpoint& out, std::string& err) {
    if (decision.action == rules::Action::Direct) {
        out = {};
        return true;
    }
    const LinkEndpoint* ep = cfg.find_link(decision.outbound);
    if (!ep) {
        err = "unknown outbound '" + decision.outbound + "'";
        return false;
    }
    out = *ep;
    return true;
}

void handle_dns(std::shared_ptr<Session> s, const SocksTarget& target,
                const MultilinkConfig& cfg) {
    if (!reply_socks_ok(s->local_fd)) return;
    uint8_t lenb[2];
    if (!recv_exact(s->local_fd, lenb, 2)) return;
    const size_t qlen = (static_cast<size_t>(lenb[0]) << 8) | lenb[1];
    if (qlen == 0 || qlen > 4096) return;
    std::vector<uint8_t> query(qlen);
    if (!recv_exact(s->local_fd, query.data(), qlen)) return;

    const std::string name = dns_qname(query.data(), query.size());
    const auto decision = g_rules.decide(name.empty() ? target.host : name, false, 0, false);

    LinkEndpoint link;
    std::string link_err;
    if (!select_link(cfg, decision, link, link_err)) {
        if (cfg.log_decisions) {
            log_line(std::string("[-] DNS ") + link_err + " for " +
                     (name.empty() ? target.host : name));
        }
        return;
    }
    s->link = link;

    if (cfg.log_decisions) {
        log_line(std::string("[*] DNS ") + rules::decision_name(decision) + " " +
                 (name.empty() ? target.host : name) + "  (" + decision.matched + ")");
    }

    std::vector<uint8_t> framed;
    framed.push_back(lenb[0]);
    framed.push_back(lenb[1]);
    framed.insert(framed.end(), query.begin(), query.end());

    std::vector<uint8_t> out;
    bool ok = false;
    if (decision.action == rules::Action::Direct) {
        std::vector<uint8_t> answer;
        ok = dns_query_direct(query.data(), query.size(), answer);
        if (ok) {
            out.push_back(static_cast<uint8_t>(answer.size() >> 8));
            out.push_back(static_cast<uint8_t>(answer.size()));
            out.insert(out.end(), answer.begin(), answer.end());
            remember_dns_answers(answer.data(), answer.size(), name);
        }
    } else {
        ok = dns_query_proxy(s, target, framed.data(), framed.size(), out);
        if (ok && out.size() > 2) remember_dns_answers(out.data() + 2, out.size() - 2, name);
    }
    if (!ok || out.size() < 2) return;
    send_all(s->local_fd, out.data(), out.size());
}

bool open_direct(std::shared_ptr<Session> s, const SocksTarget& t) {
    // Sticky/marked resolve — never unmarked DNS-over-TCP (loops into TUN).
    std::string connect_host = t.host;
    if (g_resolve_host_for_direct) {
        const std::string resolved = g_resolve_host_for_direct(t.host);
        if (!resolved.empty()) connect_host = resolved;
    }
    socket_t remote_fd = linux_self::tcp_connect_direct_marked(
        connect_host, static_cast<int>(t.port), s->idle_timeout_sec);
    if (remote_fd == INVALID_SOCK) return false;
    s->remote_fd = remote_fd;
    s->via_proxy = false;
    return true;
}

void handle_socks5(socket_t local_fd, MultilinkConfig cfg) {
    auto s = std::make_shared<Session>();
    s->local_fd = local_fd;
    s->idle_timeout_sec = 300;
    if (!cfg.links.empty()) {
        s->idle_timeout_sec = cfg.links.begin()->second.idle_timeout_sec;
    }
    set_socket_options(local_fd, s->idle_timeout_sec);

    SocksTarget target;
    if (!socks5_read_target(local_fd, target)) return;

    if (target.port == 53) {
        handle_dns(s, target, cfg);
        return;
    }

    std::string rule_host = target.host;
    bool has_ip = false;
    uint32_t ip_host = 0;
    if (target.has_ipv4) {
        const std::string learned = cached_name(target.ipv4_host);
        if (!learned.empty()) {
            rule_host = learned;
        } else {
            has_ip = true;
            ip_host = target.ipv4_host;
        }
    }
    const auto decision = g_rules.decide(rule_host, has_ip, ip_host, /*allow_dns_resolve=*/false);

    LinkEndpoint link;
    std::string link_err;
    if (!select_link(cfg, decision, link, link_err)) {
        if (cfg.log_decisions) {
            log_line(std::string("[-] ") + link_err + " for " + target.host + ":" +
                     std::to_string(target.port));
        }
        reply_socks_fail(local_fd, 0x01);
        return;
    }
    s->link = link;
    if (!link.name.empty()) s->idle_timeout_sec = link.idle_timeout_sec;

    if (cfg.log_decisions) {
        log_line(std::string("[*] ") + rules::decision_name(decision) + " " +
                 rule_host + ":" + std::to_string(target.port) +
                 "  (" + decision.matched + ")" +
                 (link.name.empty()
                      ? ""
                      : " via " + link.name + " " + link.server_ip +
                            (link.peer_secret.empty() ? "" : " (peer)")));
    }

    bool ok = false;
    if (decision.action == rules::Action::Direct) {
        ok = open_direct(s, target);
        if (!ok) {
            reply_socks_fail(local_fd, 0x05);
            return;
        }
    } else {
        SocksTarget connect_tgt = target;
        if (!host_is_ipv4_literal(rule_host)) {
            prefer_remote_dns_wire(connect_tgt, rule_host);
        }
        ok = open_proxy(s, connect_tgt);
        if (!ok) {
            reply_socks_fail(local_fd, 0x01);
            return;
        }
    }

    if (!reply_socks_ok(local_fd)) return;

    if (s->via_proxy) {
        std::thread(relay_proxy_down, s).detach();
        std::vector<uint8_t> buf(static_cast<size_t>(s->link.max_payload));
        while (s->alive && g_running) {
            const int n = recv_some(local_fd, buf.data(), buf.size());
            if (n <= 0) break;
            if (!vortex::send_frame(s->remote_fd, s->up, vortex::CMD_DATA,
                                    buf.data(), static_cast<size_t>(n),
                                    s->link.padding_min, s->link.padding_max)) {
                break;
            }
        }
        s->alive = false;
        vortex::send_frame(s->remote_fd, s->up, vortex::CMD_CLOSE,
                           nullptr, 0, s->link.padding_min, s->link.padding_max);
    } else {
        std::thread(relay_raw, s->remote_fd, local_fd, s).detach();
        relay_raw(local_fd, s->remote_fd, s);
    }

    shutdown_both(local_fd);
    shutdown_both(s->remote_fd);
}

} // namespace router_detail

namespace linux_router {
MultilinkConfig g_cfg;
socket_t g_listen = INVALID_SOCK;

bool start(const MultilinkConfig& cfg) {
    g_cfg = cfg;
    try {
        router_detail::g_rules.load(cfg.rules_path, cfg.geoip_cn, cfg.geosite_cn);
    } catch (const std::exception& e) {
        std::cerr << "[-] rules: " << e.what() << "\n";
        return false;
    }
    g_listen = create_listen_socket("127.0.0.1", cfg.socks5_bind_port, cfg.listen_backlog);
    if (g_listen == INVALID_SOCK) {
        std::cerr << "[-] LinuxNetwork router bind 127.0.0.1:" << cfg.socks5_bind_port
                  << " failed\n";
        return false;
    }
    linux_self::clear_uplink_ipv4();
    for (const auto& kv : cfg.links) {
        in_addr up{};
        if (inet_pton(AF_INET, kv.second.server_ip.c_str(), &up) == 1) {
            linux_self::add_uplink_ipv4(up.s_addr);
        }
    }
    std::thread([] {
        while (router_detail::g_running) {
            sockaddr_in peer{};
            socklen_type peer_len = sizeof(peer);
            socket_t local_fd = accept(g_listen, reinterpret_cast<sockaddr*>(&peer), &peer_len);
            if (local_fd == INVALID_SOCK) {
                if (!router_detail::g_running) break;
                continue;
            }
            std::thread(router_detail::handle_socks5, local_fd, g_cfg).detach();
        }
    }).detach();
    std::cout << "[*] LinuxNetwork router (MultiLink) SOCKS5 127.0.0.1:" << cfg.socks5_bind_port
              << std::endl;
    std::cout << "[*] rules " << cfg.rules_path
              << " (" << router_detail::g_rules.rule_count() << " entries)"
              << "  GEOIP-CN=" << router_detail::g_rules.cn_cidr_count()
              << "  GEOSITE-CN=" << router_detail::g_rules.cn_domain_count()
              << std::endl;
    for (const auto& kv : cfg.links) {
        const auto& L = kv.second;
        std::cout << "[*] Link " << L.name << " -> " << L.server_ip << ":" << L.server_port
                  << (L.peer_secret.empty() ? "" : "  peer-relay") << std::endl;
    }
    std::cout << "[*] Default link " << cfg.default_link << std::endl;
    if (router_detail::g_rules.cn_cidr_count() == 0 ||
        router_detail::g_rules.cn_domain_count() == 0) {
        std::cerr << "[-] geo lists empty — check geoip_cn / geosite_cn paths "
                     "(relative to process cwd)\n";
    }
    return true;
}

void stop() {
    router_detail::g_running = false;
    if (g_listen != INVALID_SOCK) {
        net_close(g_listen);
        g_listen = INVALID_SOCK;
    }
}
} // namespace linux_router

// ---------------------------------------------------------------------------
// Divert engine — Linux stand-in for WinDivert path in internet.cpp
// Decision tree MUST match internet.cpp::on_packet (learned→SOCKS, else reinject).
// Capture: iptables OUTPUT REDIRECT (own SO_MARK never enters). No TUN.
// ---------------------------------------------------------------------------
namespace {

using router_detail::log_line;

constexpr const char* kLockPath = "/run/vortex-linux-network.lock";
constexpr uint16_t kDnsListenPort = 53053;
constexpr uint16_t kTcpListenPort = 53080;
constexpr const char* kStandInCidr = "198.18.0.0/15";

ActivateNetConfig g_cfg;
std::atomic<bool> g_run{true};
std::atomic<uint64_t> g_dns_ok{0}, g_dns_fail{0};
std::atomic<uint64_t> g_connect_ok{0}, g_socks_fail{0}, g_passthru{0};
std::atomic<uint64_t> g_tcp_passthru{0}, g_tcp_ok{0}, g_tcp_fail{0}, g_drop_quic{0};
std::atomic<int> g_dns_inflight{0};
std::atomic<int> g_dns_log_left{40};

int g_lock_fd = -1;
int g_dns_fd = -1;
int g_tcp_fd = -1;
bool g_hijack_installed = false;
std::string g_dns_restore_iface;
std::string g_uplink_dns = "223.5.5.5";

std::mutex g_dns_mu;
struct DnsNameEntry { std::string name; };
std::unordered_map<uint32_t, DnsNameEntry> g_ip_to_name;
std::unordered_map<std::string, uint32_t> g_name_to_ip;
constexpr uint32_t kDnsTtl = 300;
constexpr uint32_t kStandInHostMin = 0xC6120101u; // 198.18.1.1
constexpr uint32_t kStandInHostMax = 0xC613FFFEu;
uint32_t g_standin_next = kStandInHostMin;
std::mutex g_learned_ipt_mu;
std::unordered_set<uint32_t> g_learned_ipt_added; // net-order IPs with REDIRECT rules

std::string ip_to_string(uint32_t net) {
    char buf[INET_ADDRSTRLEN] = {};
    in_addr a{};
    a.s_addr = net;
    if (!inet_ntop(AF_INET, &a, buf, sizeof(buf))) return "?";
    return buf;
}
int run_cmd(const std::string& cmd) {
    const int rc = ::system(cmd.c_str());
    if (rc == -1) return -1;
    return WIFEXITED(rc) ? WEXITSTATUS(rc) : -1;
}
std::string ip_bin() {
    if (::access("/usr/sbin/ip", X_OK) == 0) return "/usr/sbin/ip";
    if (::access("/sbin/ip", X_OK) == 0) return "/sbin/ip";
    return "ip";
}
std::string iptables_bin() {
    if (::access("/usr/sbin/iptables", X_OK) == 0) return "/usr/sbin/iptables";
    if (::access("/sbin/iptables", X_OK) == 0) return "/sbin/iptables";
    return "iptables";
}
std::string mark_hex() {
    char buf[16];
    std::snprintf(buf, sizeof(buf), "0x%x", linux_self::kMark);
    return buf;
}

std::string to_lower_host(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}
bool is_private_ip(uint32_t net_order) {
    const uint32_t h = ntohl(net_order);
    if ((h & 0xFF000000u) == 0x0A000000u) return true;
    if ((h & 0xFFF00000u) == 0xAC100000u) return true;
    if ((h & 0xFFFF0000u) == 0xC0A80000u) return true;
    if ((h & 0xFF000000u) == 0x7F000000u) return true;
    if ((h & 0xFFFF0000u) == 0xA9FE0000u) return true;
    return false;
}
bool is_standin_ip(uint32_t net_order) {
    return (ntohl(net_order) & 0xFFFE0000u) == 0xC6120000u;
}

size_t dns_skip_name(const uint8_t* msg, size_t len, size_t off) {
    int hops = 0;
    while (off < len && hops < 64) {
        const uint8_t lab = msg[off];
        if (lab == 0) return off + 1;
        if ((lab & 0xC0) == 0xC0) return off + 2 < len ? off + 2 : len;
        if (off + 1 + lab > len) return len;
        off += 1 + lab;
        ++hops;
    }
    return len;
}
std::string dns_qname(const uint8_t* msg, size_t len) {
    if (len < 12) return {};
    size_t off = 12;
    std::string name;
    int hops = 0;
    while (off < len && hops < 64) {
        const uint8_t lab = msg[off++];
        if (lab == 0) break;
        if ((lab & 0xC0) == 0xC0 || off + lab > len) return name.empty() ? std::string("?") : name;
        if (!name.empty()) name.push_back('.');
        name.append(reinterpret_cast<const char*>(msg + off), lab);
        off += lab;
        ++hops;
    }
    return to_lower_host(name);
}
uint16_t dns_qtype(const uint8_t* msg, size_t len) {
    if (len < 12) return 0;
    size_t off = dns_skip_name(msg, len, 12);
    if (off + 4 > len) return 0;
    return static_cast<uint16_t>((msg[off] << 8) | msg[off + 1]);
}
std::string dns_lookup_name(uint32_t net_order) {
    std::lock_guard<std::mutex> lock(g_dns_mu);
    auto it = g_ip_to_name.find(net_order);
    return it == g_ip_to_name.end() ? std::string{} : it->second.name;
}

void ipt_learn_add(uint32_t ip_net) {
    if (!ip_net || is_private_ip(ip_net)) return;
    {
        std::lock_guard<std::mutex> lock(g_learned_ipt_mu);
        if (g_learned_ipt_added.count(ip_net)) return;
        g_learned_ipt_added.insert(ip_net);
    }
    // internet.cpp: only LEARNED destinations are stolen; unlearned stay on wire (reinject).
    const std::string ipt = iptables_bin();
    const std::string ip = ip_to_string(ip_net);
    run_cmd(ipt + " -t nat -C VORTEX_TCP -d " + ip + " -p tcp -j REDIRECT --to-ports " +
            std::to_string(kTcpListenPort) + " 2>/dev/null || " +
            ipt + " -t nat -A VORTEX_TCP -d " + ip + " -p tcp -j REDIRECT --to-ports " +
            std::to_string(kTcpListenPort));
}

uint32_t dns_standin_alloc_locked(const std::string& qname) {
    for (int n = 0; n < 65536; ++n) {
        uint32_t host = g_standin_next++;
        if (g_standin_next > kStandInHostMax) g_standin_next = kStandInHostMin;
        const uint8_t b3 = static_cast<uint8_t>(host & 0xFF);
        if (b3 == 0 || b3 == 255) continue;
        if ((host & 0xFFFFFF00u) == 0xC6120000u) continue; // skip 198.18.0.x
        const uint32_t net = htonl(host);
        if (g_ip_to_name.count(net)) continue;
        g_ip_to_name[net] = DnsNameEntry{qname};
        g_name_to_ip[qname] = net;
        return net;
    }
    return 0;
}

uint32_t dns_bind_name(const std::string& qname_raw, uint32_t real_ip) {
    const std::string qname = to_lower_host(qname_raw);
    if (qname.empty() || qname == "?") return 0;
    uint32_t answer = 0;
    {
        std::lock_guard<std::mutex> lock(g_dns_mu);
        auto nit = g_name_to_ip.find(qname);
        if (nit != g_name_to_ip.end() && nit->second) answer = nit->second;
        else if (real_ip && !is_private_ip(real_ip) && !is_standin_ip(real_ip)) {
            auto iit = g_ip_to_name.find(real_ip);
            if (iit == g_ip_to_name.end()) {
                g_ip_to_name[real_ip] = DnsNameEntry{qname};
                g_name_to_ip[qname] = real_ip;
                answer = real_ip;
            } else if (iit->second.name == qname) {
                g_name_to_ip[qname] = real_ip;
                answer = real_ip;
            } else {
                answer = dns_standin_alloc_locked(qname);
            }
        } else {
            answer = dns_standin_alloc_locked(qname);
        }
    }
    if (answer) ipt_learn_add(answer);
    return answer;
}

std::vector<uint8_t> dns_reply_nodata(const std::vector<uint8_t>& query) {
    if (query.size() < 12) return {};
    size_t off = dns_skip_name(query.data(), query.size(), 12);
    if (off + 4 > query.size()) return {};
    off += 4;
    std::vector<uint8_t> resp(query.begin(), query.begin() + static_cast<std::ptrdiff_t>(off));
    resp[2] = static_cast<uint8_t>((resp[2] & 0x01) | 0x80);
    resp[3] = 0x80;
    resp[6] = resp[7] = resp[8] = resp[9] = resp[10] = resp[11] = 0;
    return resp;
}
std::vector<uint8_t> dns_reply_servfail(const std::vector<uint8_t>& query) {
    if (query.size() < 12) return {};
    size_t off = dns_skip_name(query.data(), query.size(), 12);
    if (off + 4 > query.size()) return {};
    off += 4;
    std::vector<uint8_t> resp(query.begin(), query.begin() + static_cast<std::ptrdiff_t>(off));
    resp[2] = static_cast<uint8_t>((resp[2] & 0x01) | 0x80);
    resp[3] = static_cast<uint8_t>((resp[3] & 0xF0) | 0x02);
    resp[6] = resp[7] = resp[8] = resp[9] = resp[10] = resp[11] = 0;
    return resp;
}
std::vector<uint8_t> dns_reply_a(const std::vector<uint8_t>& query, uint32_t ip_net) {
    if (query.size() < 12) return {};
    size_t off = dns_skip_name(query.data(), query.size(), 12);
    if (off + 4 > query.size()) return {};
    off += 4;
    std::vector<uint8_t> resp(query.begin(), query.begin() + static_cast<std::ptrdiff_t>(off));
    resp[2] = static_cast<uint8_t>((resp[2] & 0x01) | 0x80);
    resp[3] = 0x80;
    resp[6] = 0; resp[7] = 1;
    resp[8] = resp[9] = resp[10] = resp[11] = 0;
    resp.push_back(0xC0); resp.push_back(0x0C);
    resp.push_back(0x00); resp.push_back(0x01);
    resp.push_back(0x00); resp.push_back(0x01);
    resp.push_back(static_cast<uint8_t>(kDnsTtl >> 24));
    resp.push_back(static_cast<uint8_t>(kDnsTtl >> 16));
    resp.push_back(static_cast<uint8_t>(kDnsTtl >> 8));
    resp.push_back(static_cast<uint8_t>(kDnsTtl));
    resp.push_back(0x00); resp.push_back(0x04);
    const uint8_t* p = reinterpret_cast<const uint8_t*>(&ip_net);
    resp.insert(resp.end(), p, p + 4);
    return resp;
}

std::vector<uint8_t> build_dns_query_a(const std::string& name, uint16_t id) {
    std::vector<uint8_t> q;
    q.push_back(static_cast<uint8_t>(id >> 8));
    q.push_back(static_cast<uint8_t>(id));
    q.push_back(0x01); q.push_back(0x00);
    q.push_back(0x00); q.push_back(0x01);
    q.push_back(0x00); q.push_back(0x00);
    q.push_back(0x00); q.push_back(0x00);
    q.push_back(0x00); q.push_back(0x00);
    size_t i = 0;
    while (i < name.size()) {
        size_t j = name.find('.', i);
        if (j == std::string::npos) j = name.size();
        const size_t lab = j - i;
        if (lab == 0 || lab > 63) return {};
        q.push_back(static_cast<uint8_t>(lab));
        q.insert(q.end(), name.begin() + static_cast<std::ptrdiff_t>(i),
                 name.begin() + static_cast<std::ptrdiff_t>(j));
        i = j + (j < name.size() ? 1 : 0);
    }
    q.push_back(0);
    q.push_back(0x00); q.push_back(0x01);
    q.push_back(0x00); q.push_back(0x01);
    return q;
}

enum class DnsAResult { Ok, NoData, Fail };
DnsAResult parse_dns_a_answer(const uint8_t* resp, size_t rlen, uint32_t& out_net) {
    if (!resp || rlen < 12) return DnsAResult::Fail;
    const uint8_t rcode = static_cast<uint8_t>(resp[3] & 0x0F);
    if (rcode == 3) return DnsAResult::NoData;
    if (rcode != 0) return DnsAResult::Fail;
    const uint16_t ancount = static_cast<uint16_t>((resp[6] << 8) | resp[7]);
    auto skip_name = [&](size_t off) -> size_t {
        int hops = 0;
        while (off < rlen && hops < 64) {
            const uint8_t lab = resp[off];
            if (lab == 0) return off + 1;
            if ((lab & 0xC0) == 0xC0) return off + 2 < rlen ? off + 2 : rlen;
            if (off + 1 + lab > rlen) return rlen;
            off += 1 + lab; ++hops;
        }
        return rlen;
    };
    size_t off = skip_name(12);
    if (off + 4 > rlen) return DnsAResult::Fail;
    off += 4;
    bool saw = false;
    for (uint16_t ai = 0; ai < ancount && off + 10 <= rlen; ++ai) {
        off = skip_name(off);
        if (off + 10 > rlen) return DnsAResult::Fail;
        const uint16_t typ = static_cast<uint16_t>((resp[off] << 8) | resp[off + 1]);
        const uint16_t rdlen = static_cast<uint16_t>((resp[off + 8] << 8) | resp[off + 9]);
        off += 10;
        if (off + rdlen > rlen) return DnsAResult::Fail;
        saw = true;
        if (typ == 1 && rdlen == 4) {
            uint32_t ip = 0;
            std::memcpy(&ip, resp + off, 4);
            if (ip && !is_private_ip(ip)) { out_net = ip; return DnsAResult::Ok; }
        }
        off += rdlen;
    }
    return saw || ancount == 0 ? DnsAResult::NoData : DnsAResult::Fail;
}

DnsAResult resolve_ipv4_dns_udp(const std::string& name, uint32_t resolver_net, uint32_t& out_net,
                                int timeout_ms = 1500) {
    if (name.empty() || name.size() > 253 || !resolver_net) return DnsAResult::Fail;
    const auto q = build_dns_query_a(
        name, static_cast<uint16_t>(std::chrono::steady_clock::now().time_since_epoch().count() & 0xFFFF));
    if (q.empty()) return DnsAResult::Fail;
    socket_t s = linux_self::udp_socket_marked();
    if (s == INVALID_SOCK) return DnsAResult::Fail;
    timeval tv{};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    dst.sin_addr.s_addr = resolver_net;
    if (sendto(s, q.data(), q.size(), 0, reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) < 0) {
        linux_self::unregister_socket(s);
        net_close(s);
        return DnsAResult::Fail;
    }
    uint8_t buf[2048];
    const int n = static_cast<int>(recvfrom(s, buf, sizeof(buf), 0, nullptr, nullptr));
    linux_self::unregister_socket(s);
    net_close(s);
    if (n < 12) return DnsAResult::Fail;
    return parse_dns_a_answer(buf, static_cast<size_t>(n), out_net);
}

bool resolve_ipv4_fast(const std::string& name, uint32_t client_resolver_net, uint32_t& out_net) {
    in_addr lit{};
    if (inet_pton(AF_INET, name.c_str(), &lit) == 1) {
        out_net = lit.s_addr;
        return !is_private_ip(out_net);
    }
    auto try_udp = [&](uint32_t resolver) -> DnsAResult {
        if (!resolver) return DnsAResult::Fail;
        return resolve_ipv4_dns_udp(name, resolver, out_net, 600);
    };
    DnsAResult r = try_udp(client_resolver_net);
    if (r == DnsAResult::Ok) return true;
    if (r == DnsAResult::NoData) return false;
    const uint32_t r88 = htonl(0x08080808u);
    const uint32_t r1111 = htonl(0x01010101u);
    if (client_resolver_net != r88) {
        r = try_udp(r88);
        if (r == DnsAResult::Ok) return true;
        if (r == DnsAResult::NoData) return false;
    }
    if (client_resolver_net != r1111) {
        r = try_udp(r1111);
        if (r == DnsAResult::Ok) return true;
        if (r == DnsAResult::NoData) return false;
    }
    return false;
}

std::string resolve_host_for_direct(const std::string& host) {
    in_addr lit{};
    if (inet_pton(AF_INET, host.c_str(), &lit) == 1) return host;
    const std::string q = to_lower_host(host);
    uint32_t ip_net = 0;
    {
        std::lock_guard<std::mutex> lock(g_dns_mu);
        auto it = g_name_to_ip.find(q);
        if (it != g_name_to_ip.end()) ip_net = it->second;
    }
    if (!ip_net || is_standin_ip(ip_net)) {
        uint32_t resolver_net = 0;
        in_addr ra{};
        if (inet_pton(AF_INET, g_uplink_dns.c_str(), &ra) == 1) resolver_net = ra.s_addr;
        uint32_t real = 0;
        if (resolve_ipv4_fast(host, resolver_net, real) && real) ip_net = real;
    }
    if (!ip_net || is_standin_ip(ip_net)) return {};
    return ip_to_string(ip_net);
}

struct DirectResolveInit {
    DirectResolveInit() { g_resolve_host_for_direct = &resolve_host_for_direct; }
};
DirectResolveInit g_direct_resolve_init;

bool recvn(socket_t s, char* buf, int n) {
    int got = 0;
    while (got < n) {
        const int r = static_cast<int>(::recv(s, buf + got, static_cast<size_t>(n - got), 0));
        if (r <= 0) return false;
        got += r;
    }
    return true;
}
void set_timeouts(socket_t s, int sec) {
    timeval tv{};
    tv.tv_sec = sec > 0 ? sec : 1;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}
bool send_all_buf(socket_t s, const void* data, size_t len) {
    const char* p = static_cast<const char*>(data);
    size_t off = 0;
    while (off < len) {
        const int n = static_cast<int>(::send(s, p + off, len - off, MSG_NOSIGNAL));
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

socket_t tcp_connect_timeout(const std::string& host, int port, int timeout_sec) {
    // To local SOCKS only — still mark+register (internet.cpp style).
    return linux_self::tcp_connect_registered(host, port, timeout_sec);
}

bool socks5_read_connect_reply(socket_t s) {
    char hdr[4];
    if (!recvn(s, hdr, 4) || hdr[0] != 0x05 || hdr[1] != 0x00) return false;
    int rest = 0;
    if (static_cast<uint8_t>(hdr[3]) == 0x01) rest = 6;
    else if (static_cast<uint8_t>(hdr[3]) == 0x04) rest = 18;
    else if (static_cast<uint8_t>(hdr[3]) == 0x03) {
        char ln = 0;
        if (!recvn(s, &ln, 1)) return false;
        rest = static_cast<unsigned char>(ln) + 2;
    } else return false;
    if (rest <= 0) return true;
    std::vector<char> skip(static_cast<size_t>(rest));
    return recvn(s, skip.data(), rest);
}
socket_t socks5_handshake(int timeout_sec) {
    socket_t s = tcp_connect_timeout(g_cfg.socks5_host, g_cfg.socks5_port, timeout_sec);
    if (s == INVALID_SOCK) return INVALID_SOCK;
    const uint8_t greet[] = {0x05, 0x01, 0x00};
    if (!send_all_buf(s, greet, 3)) {
        linux_self::unregister_socket(s);
        net_close(s);
        return INVALID_SOCK;
    }
    char greply[2];
    if (!recvn(s, greply, 2) || greply[0] != 0x05 || greply[1] != 0x00) {
        linux_self::unregister_socket(s);
        net_close(s);
        return INVALID_SOCK;
    }
    return s;
}
socket_t socks5_connect_host(const std::string& host, uint16_t port, int timeout_sec) {
    if (host.empty() || host.size() > 255) return INVALID_SOCK;
    socket_t s = socks5_handshake(timeout_sec);
    if (s == INVALID_SOCK) return INVALID_SOCK;
    std::vector<uint8_t> req(5 + host.size() + 2);
    req[0] = 0x05; req[1] = 0x01; req[2] = 0x00; req[3] = 0x03;
    req[4] = static_cast<uint8_t>(host.size());
    std::memcpy(req.data() + 5, host.data(), host.size());
    req[5 + host.size()] = static_cast<uint8_t>(port >> 8);
    req[6 + host.size()] = static_cast<uint8_t>(port & 0xFF);
    if (!send_all_buf(s, req.data(), req.size()) || !socks5_read_connect_reply(s)) {
        linux_self::unregister_socket(s);
        net_close(s);
        return INVALID_SOCK;
    }
    return s;
}

bool is_doh_host(const std::string& host) {
    const std::string h = to_lower_host(host);
    if (h == "dns.google" || h == "dns.google.com") return true;
    if (h.size() >= 18 && h.compare(h.size() - 18, 18, ".cloudflare-dns.com") == 0) return true;
    if (h == "dns.quad9.net" || (h.size() > 14 && h.compare(h.size() - 14, 14, ".dns.quad9.net") == 0))
        return true;
    if (h.find("dns.nextdns.io") != std::string::npos) return true;
    if (h.size() > 11 && h.compare(h.size() - 11, 11, ".opendns.com") == 0) return true;
    if (h.rfind("doh.", 0) == 0 || h.find("dns.adguard") != std::string::npos) return true;
    return false;
}

void relay_both(socket_t a, socket_t b) {
    std::atomic<bool> alive{true};
    auto one = [&](socket_t from, socket_t to) {
        std::vector<char> buf(16384);
        while (alive.load() && g_run.load()) {
            const int n = static_cast<int>(::recv(from, buf.data(), buf.size(), 0));
            if (n <= 0) break;
            if (!send_all_buf(to, buf.data(), static_cast<size_t>(n))) break;
        }
        alive = false;
        ::shutdown(from, SHUT_RD);
        ::shutdown(to, SHUT_WR);
    };
    std::thread t(one, b, a);
    one(a, b);
    if (t.joinable()) t.join();
}

// internet.cpp socks_worker: LEARNED only → SOCKS CONNECT(domain). Never CONNECT(IP).
void handle_transparent_tcp(socket_t client) {
    sockaddr_in orig{};
    socklen_t olen = sizeof(orig);
    if (getsockopt(client, SOL_IP, SO_ORIGINAL_DST, &orig, &olen) != 0) {
        net_close(client);
        return;
    }
    const uint32_t dst = orig.sin_addr.s_addr;
    const uint16_t dport = ntohs(orig.sin_port);
    const std::string learned = dns_lookup_name(dst);

    // internet.cpp: unlearned → reinject. Here packet was only redirected because IP
    // was learned (or stand-in range); if map miss, marked direct (= reinject).
    if (learned.empty()) {
        ++g_tcp_passthru; ++g_passthru;
        char ipbuf[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &dst, ipbuf, sizeof(ipbuf));
        socket_t up = linux_self::tcp_connect_registered(ipbuf, dport, g_cfg.idle_timeout_sec);
        if (up == INVALID_SOCK) {
            ++g_tcp_fail;
            net_close(client);
            return;
        }
        if (g_cfg.log_connections) {
            log_line("[*] TCP passthru(reinject) " + std::string(ipbuf) + ":" + std::to_string(dport));
        }
        ++g_tcp_ok;
        relay_both(client, up);
        linux_self::unregister_socket(up);
        net_close(up);
        net_close(client);
        return;
    }

    if (is_doh_host(learned)) {
        if (g_cfg.log_connections) log_line("[-] block DoH " + learned);
        net_close(client);
        return;
    }

    socket_t s = socks5_connect_host(learned, dport, 15);
    if (s == INVALID_SOCK) {
        ++g_socks_fail; ++g_tcp_fail;
        if (g_cfg.log_connections) {
            log_line("[-] SOCKS CONNECT fail " + learned + ":" + std::to_string(dport));
        }
        net_close(client);
        return;
    }
    ++g_connect_ok; ++g_tcp_ok;
    if (g_cfg.log_connections) {
        log_line("[+] TCP " + learned + "/" + ip_to_string(dst) + ":" + std::to_string(dport) +
                 " via SOCKS5/domain");
    }
    relay_both(client, s);
    linux_self::unregister_socket(s);
    net_close(s);
    net_close(client);
}

void handle_dns_query(const uint8_t* data, size_t len, const sockaddr_in& peer) {
    if (len < 12 || len > 1500) return;
    std::vector<uint8_t> query(data, data + len);
    const std::string qname = dns_qname(query.data(), query.size());
    const uint16_t qtype = dns_qtype(query.data(), query.size());

    auto reply = [&](const std::vector<uint8_t>& resp, const std::string& note, bool ok) {
        if (resp.empty()) { ++g_dns_fail; return; }
        sendto(g_dns_fd, resp.data(), resp.size(), 0, reinterpret_cast<const sockaddr*>(&peer),
               sizeof(peer));
        if (ok) ++g_dns_ok; else ++g_dns_fail;
        if (g_dns_log_left.fetch_sub(1) > 0) {
            log_line(std::string(ok ? "[+] DNS q=" : "[-] DNS q=") +
                     (qname.empty() ? "?" : qname) + " " + note);
        }
    };

    if (qtype != 1) {
        reply(dns_reply_nodata(query), "type" + std::to_string(qtype) + "->NODATA", true);
        return;
    }
    if (qname.empty() || qname == "?") {
        reply(dns_reply_servfail(query), "bad qname->SERVFAIL", false);
        return;
    }
    {
        std::lock_guard<std::mutex> lock(g_dns_mu);
        auto it = g_name_to_ip.find(qname);
        if (it != g_name_to_ip.end() && it->second) {
            reply(dns_reply_a(query, it->second), "cached A " + ip_to_string(it->second), true);
            ipt_learn_add(it->second);
            return;
        }
    }
    if (g_dns_inflight.load() >= g_cfg.max_dns_inflight) {
        reply(dns_reply_servfail(query), "overloaded->SERVFAIL", false);
        return;
    }
    ++g_dns_inflight;
    std::thread([query, peer, qname]() {
        struct Guard { ~Guard() { --g_dns_inflight; } } guard;
        auto reply = [&](const std::vector<uint8_t>& resp, const std::string& note, bool ok) {
            if (resp.empty()) { ++g_dns_fail; return; }
            sendto(g_dns_fd, resp.data(), resp.size(), 0, reinterpret_cast<const sockaddr*>(&peer),
                   sizeof(peer));
            if (ok) ++g_dns_ok; else ++g_dns_fail;
            if (g_dns_log_left.fetch_sub(1) > 0) {
                log_line(std::string(ok ? "[+] DNS q=" : "[-] DNS q=") + qname + " " + note);
            }
        };
        uint32_t resolver_net = 0;
        {
            in_addr a{};
            if (inet_pton(AF_INET, g_uplink_dns.c_str(), &a) == 1) resolver_net = a.s_addr;
        }
        uint32_t real_ip = 0;
        const bool resolved = resolve_ipv4_fast(qname, resolver_net, real_ip);
        const uint32_t answer = dns_bind_name(qname, resolved ? real_ip : 0);
        if (!answer) {
            reply(dns_reply_servfail(query), "bind failed->SERVFAIL", false);
            return;
        }
        router_detail::remember_ip_name(ntohl(answer), qname);
        std::string note = "A " + ip_to_string(answer);
        if (is_standin_ip(answer)) note += resolved ? " (stand-in/collision)" : " (stand-in/no-resolve)";
        else if (resolved) note += " (redir-host)";
        reply(dns_reply_a(query, answer), note, true);
    }).detach();
}

void dns_loop() {
    uint8_t buf[2048];
    while (g_run.load()) {
        sockaddr_in peer{};
        socklen_t plen = sizeof(peer);
        const int n = static_cast<int>(
            recvfrom(g_dns_fd, buf, sizeof(buf), 0, reinterpret_cast<sockaddr*>(&peer), &plen));
        if (n < 0) {
            if (!g_run.load()) break;
            if (errno == EINTR || errno == EAGAIN) continue;
            break;
        }
        handle_dns_query(buf, static_cast<size_t>(n), peer);
    }
}

void tcp_accept_loop() {
    while (g_run.load()) {
        sockaddr_in peer{};
        socklen_t plen = sizeof(peer);
        socket_t c = accept(g_tcp_fd, reinterpret_cast<sockaddr*>(&peer), &plen);
        if (c == INVALID_SOCK) {
            if (!g_run.load()) break;
            if (errno == EINTR || errno == EAGAIN) continue;
            break;
        }
        set_timeouts(c, std::max(30, g_cfg.idle_timeout_sec));
        std::thread(handle_transparent_tcp, c).detach();
    }
}

std::string default_outbound_iface() {
    FILE* fp = popen((ip_bin() + " -4 route show default 2>/dev/null").c_str(), "r");
    if (!fp) return {};
    char line[512];
    std::string out;
    if (fgets(line, sizeof(line), fp)) out = line;
    pclose(fp);
    const auto pos = out.find(" dev ");
    if (pos == std::string::npos) return {};
    std::string dev = out.substr(pos + 5);
    const auto sp = dev.find_first_of(" \t\n\r");
    if (sp != std::string::npos) dev.resize(sp);
    return dev;
}

std::string find_restore_settings_script() {
    // cwd (repo or dist package), then next to the binary.
    const char* cands[] = {
        "restore-network-settings.sh",
        "./restore-network-settings.sh",
        "scripts/restore-network-settings.sh",
        "./scripts/restore-network-settings.sh",
        nullptr,
    };
    for (int i = 0; cands[i]; ++i) {
        if (::access(cands[i], R_OK) == 0) return cands[i];
    }
    char exe[4096];
    const ssize_t n = ::readlink("/proc/self/exe", exe, sizeof(exe) - 1);
    if (n > 0) {
        exe[n] = 0;
        std::string path(exe);
        const auto slash = path.find_last_of('/');
        const std::string dir = slash == std::string::npos ? "." : path.substr(0, slash);
        const std::string near[] = {
            dir + "/restore-network-settings.sh",
            dir + "/scripts/restore-network-settings.sh",
            dir + "/../scripts/restore-network-settings.sh",
        };
        for (const auto& p : near) {
            if (::access(p.c_str(), R_OK) == 0) return p;
        }
    }
    return {};
}

void hijack_uninstall() {
    // Same settings restore as sudo ./scripts/restore-network.sh (no pkill).
    const std::string script = find_restore_settings_script();
    if (!script.empty()) {
        log_line("[*] running " + script);
        run_cmd("bash " + script);
    } else {
        log_line("[-] restore-network-settings.sh not found — inline fallback");
        const std::string ipt = iptables_bin();
        const std::string ip = ip_bin();
        for (int i = 0; i < 5; ++i) {
            if (run_cmd(ipt + " -t nat -D OUTPUT -j VORTEX_OUT 2>/dev/null") != 0) break;
        }
        for (int i = 0; i < 5; ++i) {
            if (run_cmd(ipt + " -t filter -D OUTPUT -j VORTEX_FILTER 2>/dev/null") != 0) break;
        }
        run_cmd(ipt + " -t nat -F VORTEX_OUT 2>/dev/null");
        run_cmd(ipt + " -t nat -X VORTEX_OUT 2>/dev/null");
        run_cmd(ipt + " -t nat -F VORTEX_TCP 2>/dev/null");
        run_cmd(ipt + " -t nat -X VORTEX_TCP 2>/dev/null");
        run_cmd(ipt + " -t filter -F VORTEX_FILTER 2>/dev/null");
        run_cmd(ipt + " -t filter -X VORTEX_FILTER 2>/dev/null");
        run_cmd(ip + " addr del 198.18.0.1/15 dev lo 2>/dev/null");
        const std::string iface = default_outbound_iface();
        if (!iface.empty() && ::access("/usr/bin/resolvectl", X_OK) == 0) {
            run_cmd("resolvectl revert " + iface + " 2>/dev/null");
            run_cmd("resolvectl domain " + iface + " \"\" 2>/dev/null");
            run_cmd("resolvectl flush-caches 2>/dev/null");
        }
        if (!iface.empty() && ::access("/usr/bin/nmcli", X_OK) == 0) {
            run_cmd("nmcli device reapply " + iface + " 2>/dev/null");
        }
    }
    g_dns_restore_iface.clear();
    g_hijack_installed = false;
    {
        std::lock_guard<std::mutex> lock(g_learned_ipt_mu);
        g_learned_ipt_added.clear();
    }
}

bool hijack_install() {
    const std::string ipt = iptables_bin();
    const std::string ip = ip_bin();
    const std::string mark = mark_hex();
    hijack_uninstall();

    g_uplink_dns = router_detail::system_dns_server();
    if (g_uplink_dns.empty() || router_detail::is_fakeip_v4_literal(g_uplink_dns) ||
        router_detail::is_loopback_v4_literal(g_uplink_dns)) {
        g_uplink_dns = "223.5.5.5";
    }
    log_line("[*] uplink DNS for redir-host resolve: " + g_uplink_dns);

    // Stand-in pool needs a local route (internet.cpp uses 198.18 without TUN too via Divert).
    run_cmd(ip + " addr replace 198.18.0.1/15 dev lo");

    run_cmd(ipt + " -t nat -N VORTEX_OUT 2>/dev/null || " + ipt + " -t nat -F VORTEX_OUT");
    run_cmd(ipt + " -t nat -N VORTEX_TCP 2>/dev/null || " + ipt + " -t nat -F VORTEX_TCP");
    run_cmd(ipt + " -t filter -N VORTEX_FILTER 2>/dev/null || " + ipt + " -t filter -F VORTEX_FILTER");
    run_cmd(ipt + " -t nat -D OUTPUT -j VORTEX_OUT 2>/dev/null");
    run_cmd(ipt + " -t filter -D OUTPUT -j VORTEX_FILTER 2>/dev/null");
    if (run_cmd(ipt + " -t nat -I OUTPUT 1 -j VORTEX_OUT") != 0) return false;
    run_cmd(ipt + " -t filter -I OUTPUT 1 -j VORTEX_FILTER");

    run_cmd(ipt + " -t nat -F VORTEX_OUT");
    run_cmd(ipt + " -t nat -F VORTEX_TCP");
    run_cmd(ipt + " -t filter -F VORTEX_FILTER");

    // internet.cpp: own / uplink → reinject. Marked sockets never enter this chain.
    run_cmd(ipt + " -t nat -A VORTEX_OUT -m mark --mark " + mark + " -j RETURN");
    // DNS sticky first (before 127/8 RETURN) — matches divert capture of all UDP/53.
    if (run_cmd(ipt + " -t nat -A VORTEX_OUT -p udp --dport 53 -j REDIRECT --to-ports " +
                std::to_string(kDnsListenPort)) != 0) {
        return false;
    }
    run_cmd(ipt + " -t nat -A VORTEX_OUT -d 127.0.0.0/8 -j RETURN");
    run_cmd(ipt + " -t nat -A VORTEX_OUT -d 10.0.0.0/8 -j RETURN");
    run_cmd(ipt + " -t nat -A VORTEX_OUT -d 172.16.0.0/12 -j RETURN");
    run_cmd(ipt + " -t nat -A VORTEX_OUT -d 192.168.0.0/16 -j RETURN");
    run_cmd(ipt + " -t nat -A VORTEX_OUT -d 169.254.0.0/16 -j RETURN");
    // Uplink excludes (internet_self::is_uplink_ipv4 → reinject).
    for (const auto& kv : linux_router::g_cfg.links) {
        run_cmd(ipt + " -t nat -A VORTEX_OUT -d " + kv.second.server_ip + " -j RETURN");
        run_cmd(ipt + " -t filter -A VORTEX_FILTER -d " + kv.second.server_ip + " -j RETURN");
    }
    // Stand-in range always redirected (collision fake-IP).
    run_cmd(ipt + " -t nat -A VORTEX_OUT -d " + std::string(kStandInCidr) +
            " -p tcp -j REDIRECT --to-ports " + std::to_string(kTcpListenPort));
    // Learned real IPs: rules appended to VORTEX_TCP in ipt_learn_add (unlearned never stolen).
    run_cmd(ipt + " -t nat -A VORTEX_OUT -j VORTEX_TCP");

    // QUIC/DoT drop with ICMP so stacks fall back (internet.cpp drops; we REJECT).
    run_cmd(ipt + " -t filter -A VORTEX_FILTER -m mark --mark " + mark + " -j RETURN");
    run_cmd(ipt + " -t filter -A VORTEX_FILTER -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable");
    run_cmd(ipt + " -t filter -A VORTEX_FILTER -p udp --dport 853 -j REJECT --reject-with icmp-port-unreachable");
    run_cmd(ipt + " -t filter -A VORTEX_FILTER -p tcp --dport 853 -j REJECT --reject-with tcp-reset");

    // Do NOT rewrite resolvectl — that survives Ctrl+C poorly (empty DNS after
    // revert; needs manual Wi-Fi reconnect). UDP/53 REDIRECT already catches
    // systemd-resolved's upstream queries (192.168.x.x / 114.x / …).
    g_dns_restore_iface = default_outbound_iface();
    if (::access("/usr/bin/resolvectl", X_OK) == 0) {
        run_cmd("resolvectl flush-caches 2>/dev/null");
    }

    g_hijack_installed = true;
    log_line("[*] divert: UDP/53→:" + std::to_string(kDnsListenPort) +
             "  learned TCP→:" + std::to_string(kTcpListenPort) +
             "  unlearned=passthru(reinject)  own mark=" + mark);
    return true;
}

bool open_listeners() {
    g_dns_fd = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (g_dns_fd < 0) return false;
    int one = 1;
    setsockopt(g_dns_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in a{};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    a.sin_port = htons(kDnsListenPort);
    if (bind(g_dns_fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        std::cerr << "[-] bind DNS 127.0.0.1:" << kDnsListenPort << " failed\n";
        return false;
    }

    g_tcp_fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (g_tcp_fd < 0) return false;
    setsockopt(g_tcp_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    // Transparent: allow receiving redirected connections.
    setsockopt(g_tcp_fd, SOL_IP, IP_TRANSPARENT, &one, sizeof(one));
    a.sin_port = htons(kTcpListenPort);
    if (bind(g_tcp_fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
        // IP_TRANSPARENT may need CAP_NET_ADMIN; try without for REDIRECT (local).
        int zero = 0;
        setsockopt(g_tcp_fd, SOL_IP, IP_TRANSPARENT, &zero, sizeof(zero));
        if (bind(g_tcp_fd, reinterpret_cast<sockaddr*>(&a), sizeof(a)) != 0) {
            std::cerr << "[-] bind TCP 127.0.0.1:" << kTcpListenPort << " failed\n";
            return false;
        }
    }
    if (listen(g_tcp_fd, 128) != 0) return false;
    return true;
}

bool acquire_singleton() {
    g_lock_fd = ::open(kLockPath, O_RDWR | O_CREAT, 0644);
    if (g_lock_fd < 0) g_lock_fd = ::open("/tmp/vortex-linux-network.lock", O_RDWR | O_CREAT, 0644);
    if (g_lock_fd < 0) return false;
    if (flock(g_lock_fd, LOCK_EX | LOCK_NB) != 0) {
        std::cerr << "[-] another linux_network is already running\n";
        return false;
    }
    return true;
}

void wake_shutdown() {
    g_run = false;
    router_detail::g_running = false;
    if (g_dns_fd >= 0) { ::shutdown(g_dns_fd, SHUT_RDWR); ::close(g_dns_fd); g_dns_fd = -1; }
    if (g_tcp_fd >= 0) { ::shutdown(g_tcp_fd, SHUT_RDWR); ::close(g_tcp_fd); g_tcp_fd = -1; }
}

void on_signal(int) { wake_shutdown(); }

std::string parent_dir(const std::string& path) {
    const auto pos = path.find_last_of('/');
    if (pos == std::string::npos) return ".";
    if (pos == 0) return "/";
    return path.substr(0, pos);
}
std::string file_basename(const std::string& path) {
    const auto pos = path.find_last_of('/');
    return pos == std::string::npos ? path : path.substr(pos + 1);
}
std::string resolve_data_path(const std::string& p, const std::string& config_path) {
    if (p.empty() || p[0] == '/') return p;
    if (::access(p.c_str(), R_OK) == 0) return p;
    const std::string dir = parent_dir(config_path);
    const std::string beside = dir + "/" + p;
    if (::access(beside.c_str(), R_OK) == 0) return beside;
    const std::string base_beside = dir + "/" + file_basename(p);
    if (::access(base_beside.c_str(), R_OK) == 0) return base_beside;
    return p;
}
void resolve_multilink_paths(MultilinkConfig& cfg, const std::string& config_path) {
    cfg.rules_path = resolve_data_path(cfg.rules_path, config_path);
    cfg.geoip_cn = resolve_data_path(cfg.geoip_cn, config_path);
    cfg.geosite_cn = resolve_data_path(cfg.geosite_cn, config_path);
}

} // namespace

int main(int argc, char** argv) {
    std::string config_path = "config/internet.json";
    bool router_only = false;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--router-only") router_only = true;
        else if (!a.empty() && a[0] != '-') config_path = a;
    }

    if (!net_init()) {
        std::cerr << "[-] net_init failed\n";
        return 1;
    }
    std::signal(SIGPIPE, SIG_IGN);
    {
        struct sigaction sa{};
        sa.sa_handler = on_signal;
        sigemptyset(&sa.sa_mask);
        sa.sa_flags = 0;
        sigaction(SIGINT, &sa, nullptr);
        sigaction(SIGTERM, &sa, nullptr);
    }

    InternetConfig icfg;
    try {
        icfg = InternetConfig::load(config_path);
        resolve_multilink_paths(icfg.multilink, config_path);
    } catch (const std::exception& e) {
        std::cerr << "[-] " << e.what() << "\n";
        net_cleanup();
        return 1;
    }

    MultilinkConfig& ml = icfg.multilink;
    g_cfg.socks5_host = "127.0.0.1";
    g_cfg.socks5_port = ml.socks5_bind_port;
    g_cfg.mss = icfg.mss;
    g_cfg.idle_timeout_sec = icfg.divert_idle_timeout_sec;
    g_cfg.max_connections = icfg.max_connections;
    g_cfg.max_dns_inflight = icfg.max_dns_inflight;
    g_cfg.log_connections = icfg.log_connections;

    if (!router_only) {
        if (geteuid() != 0) {
            std::cerr << "[-] transparent mode needs root. Use sudo, or --router-only.\n";
            net_cleanup();
            return 1;
        }
        if (!acquire_singleton()) {
            net_cleanup();
            return 1;
        }
    }

    if (!linux_router::start(ml)) {
        net_cleanup();
        return 1;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    if (router_only) {
        log_line("[*] LinuxNetwork --router-only (MultiLink SOCKS only)");
        while (g_run) std::this_thread::sleep_for(std::chrono::milliseconds(200));
        linux_router::stop();
        net_cleanup();
        return 0;
    }

    if (!open_listeners() || !hijack_install()) {
        wake_shutdown();
        hijack_uninstall();
        linux_router::stop();
        net_cleanup();
        return 1;
    }

    // Match internet.cpp startup logs.
    log_line("[*] LinuxNetwork — transparent redir-host + MultiLink (internet.cpp aligned, no TUN)");
    log_line("[*] config " + config_path);
    log_line("[*] router SOCKS 127.0.0.1:" + std::to_string(g_cfg.socks5_port) +
             "  links=" + std::to_string(ml.links.size()) +
             "  default=" + ml.default_link);
    log_line("[*] filter: outbound UDP/53 + learned TCP + QUIC drop; not mark/LAN/uplink/loopback");
    log_line("[*] self-exclude: SO_MARK " + mark_hex() + " + registered sports + Vortex server IPs");
    log_line("[*] apps: no proxy settings; DNS sticky map; TCP CONNECT(domain) via rules");
    log_line("[*] unlearned TCP: never redirected (WinDivert reinject)");
    log_line("[*] Ctrl+C restores iptables/DNS immediately; if stuck: sudo ./scripts/restore-network.sh");

    std::thread dns_thr(dns_loop);
    std::thread tcp_thr(tcp_accept_loop);

    auto last_stat = std::chrono::steady_clock::now();
    while (g_run.load()) {
        // Short sleep so Ctrl+C restores network within ~200ms (not up to 30s).
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        if (!g_run.load()) break;
        const auto now = std::chrono::steady_clock::now();
        if (now - last_stat < std::chrono::seconds(30)) continue;
        last_stat = now;
        log_line("[*] dns_ok=" + std::to_string(g_dns_ok.load()) +
                 " dns_fail=" + std::to_string(g_dns_fail.load()) +
                 " connect_ok=" + std::to_string(g_connect_ok.load()) +
                 " socks_fail=" + std::to_string(g_socks_fail.load()) +
                 " tcp_passthru=" + std::to_string(g_tcp_passthru.load()) +
                 " tcp_ok=" + std::to_string(g_tcp_ok.load()) +
                 " tcp_fail=" + std::to_string(g_tcp_fail.load()) +
                 " drop_quic=" + std::to_string(g_drop_quic.load()) +
                 " passthru=" + std::to_string(g_passthru.load()));
    }

    // Restore network FIRST — before joining worker threads (can block).
    log_line("[*] shutting down — restoring iptables/DNS...");
    hijack_uninstall();
    wake_shutdown();
    linux_router::stop();
    if (dns_thr.joinable()) dns_thr.join();
    if (tcp_thr.joinable()) tcp_thr.join();
    net_cleanup();
    log_line("[*] LinuxNetwork stopped (network restored)");
    return 0;
}
