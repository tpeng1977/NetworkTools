// Internet: MultiLink (same as multilink.cpp) + EnableNet (redir-host WinDivert) in ONE process.
// Config: same JSON shape as multilink.json. Apps need no proxy settings.
// Requires Administrator + WinDivert 2.2 next to this exe. Windows-only.

#ifndef _WIN32
#error Internet is Windows-only (WinDivert).
#endif

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include "config.hpp"
#include "net.hpp"
#include "packet_build.hpp"
#include "protocol.hpp"
#include "rules.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
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


namespace internet_self {
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
inline void add_uplink_ipv4(uint32_t net_order) {
    if (!net_order) return;
    std::lock_guard<std::mutex> lock(g_mu);
    g_uplink_nets.insert(net_order);
}
inline void clear_uplink_ipv4() {
    std::lock_guard<std::mutex> lock(g_mu);
    g_uplink_nets.clear();
}
inline bool is_uplink_ipv4(uint32_t net_order) {
    std::lock_guard<std::mutex> lock(g_mu);
    return g_uplink_nets.count(net_order) != 0;
}
} // namespace internet_self

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace router_detail {

std::atomic<bool> g_running{true};
rules::Engine g_rules;
std::mutex g_log_mu;

void on_signal(int) {
    g_running = false;
}

void log_line(const std::string& s) {
    std::lock_guard<std::mutex> lock(g_log_mu);
    std::cout << s << std::endl;
}

// IP -> domain learned from DNS answers, so a later TCP connect by IP still
// matches DOMAIN / GEOSITE rules.
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

std::string system_dns_server() {
#ifdef _WIN32
    ULONG sz = sizeof(FIXED_INFO);
    std::vector<uint8_t> buf(sz);
    if (GetNetworkParams(reinterpret_cast<FIXED_INFO*>(buf.data()), &sz) == ERROR_BUFFER_OVERFLOW) {
        buf.resize(sz);
    }
    auto* info = reinterpret_cast<FIXED_INFO*>(buf.data());
    if (GetNetworkParams(info, &sz) != ERROR_SUCCESS) return "223.5.5.5";
    for (auto* s = &info->DnsServerList; s; s = s->Next) {
        const std::string ip = s->IpAddress.String;
        if (ip.empty() || ip == "0.0.0.0" || ip == "127.0.0.1") continue;
        if (ip.rfind("192.168.137.", 0) == 0) continue;
        return ip;
    }
#else
    std::ifstream in("/etc/resolv.conf");
    std::string line;
    while (std::getline(in, line)) {
        if (line.rfind("nameserver ", 0) != 0) continue;
        std::string ip = line.substr(11);
        const auto sp = ip.find_first_of(" \t");
        if (sp != std::string::npos) ip.resize(sp);
        if (!ip.empty() && ip != "127.0.0.1") return ip;
    }
#endif
    return "223.5.5.5";
}

// Bind ephemeral port, register with divert self-exclude, then connect.
socket_t tcp_connect_registered(const std::string& host, int port, int idle_timeout_sec) {
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
        internet_self::register_socket(fd);
        if (::connect(fd, p->ai_addr, static_cast<socklen_type>(p->ai_addrlen)) == 0) break;
        internet_self::unregister_socket(fd);
        net_close(fd);
        fd = INVALID_SOCK;
    }
    freeaddrinfo(res);
    return fd;
}

socket_t tcp_connect_direct_registered(const std::string& host, int port, int idle_timeout_sec) {
    in_addr lit{};
    if (inet_pton(AF_INET, host.c_str(), &lit) == 1) {
        return tcp_connect_registered(host, port, idle_timeout_sec);
    }
    uint32_t ip_net = 0;
    if (resolve_ipv4_dns_tcp(host, ip_net)) {
        char buf[INET_ADDRSTRLEN] = {};
        if (inet_ntop(AF_INET, &ip_net, buf, sizeof(buf))) {
            return tcp_connect_registered(buf, port, idle_timeout_sec);
        }
    }
    return tcp_connect_registered(host, port, idle_timeout_sec);
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
            internet_self::unregister_socket(remote_fd);
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
    std::vector<uint8_t> wire; // ATYP + addr + port for Vortex CONNECT
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
        tcp_connect_registered(s->link.server_ip, s->link.server_port, s->idle_timeout_sec);
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
    socket_t fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == INVALID_SOCK) return false;
    sockaddr_in bind_a{};
    bind_a.sin_family = AF_INET;
    bind_a.sin_addr.s_addr = htonl(INADDR_ANY);
    bind_a.sin_port = 0;
    if (::bind(fd, reinterpret_cast<sockaddr*>(&bind_a), sizeof(bind_a)) != 0) {
        net_close(fd);
        return false;
    }
    internet_self::register_socket(fd);
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    if (inet_pton(AF_INET, dns.c_str(), &dst.sin_addr) != 1) {
        internet_self::unregister_socket(fd);
        net_close(fd);
        return false;
    }
#ifdef _WIN32
    DWORD ms = 3000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&ms), sizeof(ms));
#else
    timeval tv{};
    tv.tv_sec = 3;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    if (sendto(fd, reinterpret_cast<const char*>(query), static_cast<int>(qlen), 0,
               reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) < 0) {
        internet_self::unregister_socket(fd);
        net_close(fd);
        return false;
    }
    answer.resize(2048);
    const int n = recvfrom(fd, reinterpret_cast<char*>(answer.data()),
                           static_cast<int>(answer.size()), 0, nullptr, nullptr);
    internet_self::unregister_socket(fd);
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
    // Never locally resolve for matching — poisoned cache → wrong GEOIP,CN.
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
    socket_t remote_fd =
        tcp_connect_direct_registered(t.host, static_cast<int>(t.port), s->idle_timeout_sec);
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


namespace internet_router {
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
    // Always loopback — divert filter is "not loopback"; in-process SOCKS must not be captured.
    g_listen = create_listen_socket("127.0.0.1", cfg.socks5_bind_port, cfg.listen_backlog);
    if (g_listen == INVALID_SOCK) {
        std::cerr << "[-] Internet router bind 127.0.0.1:" << cfg.socks5_bind_port << " failed\n";
        return false;
    }
    internet_self::clear_uplink_ipv4();
    for (const auto& kv : cfg.links) {
        in_addr up{};
        if (inet_pton(AF_INET, kv.second.server_ip.c_str(), &up) == 1) {
            internet_self::add_uplink_ipv4(up.s_addr);
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
    std::cout << "[*] Internet router (MultiLink) SOCKS5 127.0.0.1:" << cfg.socks5_bind_port
              << " rules=" << cfg.rules_path << " (" << router_detail::g_rules.rule_count() << ")"
              << std::endl;
    for (const auto& kv : cfg.links) {
        const auto& L = kv.second;
        std::cout << "[*] Link " << L.name << " -> " << L.server_ip << ":" << L.server_port
                  << (L.peer_secret.empty() ? "" : "  peer-relay") << std::endl;
    }
    std::cout << "[*] Default link " << cfg.default_link << std::endl;
    return true;
}

void stop() {
    router_detail::g_running = false;
    if (g_listen != INVALID_SOCK) {
        net_close(g_listen);
        g_listen = INVALID_SOCK;
    }
}
} // namespace internet_router

namespace {

constexpr int WINDIVERT_LAYER_NETWORK = 0;
constexpr int16_t WINDIVERT_PRIORITY_HIGHEST = 30000;

#pragma pack(push, 1)
struct DivertAddr {
    int64_t Timestamp;
    uint32_t bits0;
    uint32_t Reserved2;
    uint8_t reserved3[64];
};
static_assert(sizeof(DivertAddr) == 80, "WinDivert 2.2 address size");
#pragma pack(pop)

inline void addr_set_outbound(DivertAddr& a, bool outbound) {
    if (outbound) a.bits0 |= (1u << 17);
    else a.bits0 &= ~(1u << 17);
}
inline void addr_set_impostor(DivertAddr& a, bool on) {
    if (on) a.bits0 |= (1u << 19);
    else a.bits0 &= ~(1u << 19);
}
inline void addr_clear_checksum_bits(DivertAddr& a) {
    a.bits0 &= ~((1u << 21) | (1u << 22) | (1u << 23));
}

using FnOpen = HANDLE(WINAPI*)(const char*, int, int16_t, uint64_t);
using FnRecv = BOOL(WINAPI*)(HANDLE, void*, UINT, UINT*, DivertAddr*);
using FnSend = BOOL(WINAPI*)(HANDLE, const void*, UINT, UINT*, const DivertAddr*);
using FnClose = BOOL(WINAPI*)(HANDLE);
using FnShutdown = BOOL(WINAPI*)(HANDLE, int);
using FnSetParam = BOOL(WINAPI*)(HANDLE, int, uint64_t);
using FnCalc = BOOL(WINAPI*)(void*, UINT, DivertAddr*, uint64_t);

FnOpen g_open = nullptr;
FnRecv g_recv = nullptr;
FnSend g_send = nullptr;
FnClose g_close = nullptr;
FnShutdown g_shutdown = nullptr;
FnSetParam g_set_param = nullptr;
FnCalc g_calc = nullptr;

ActivateNetConfig g_cfg;
std::atomic<bool> g_run{true};
std::mutex g_log_mu;

void log_line(const std::string& s) {
    std::lock_guard<std::mutex> lock(g_log_mu);
    std::cout << s << std::endl;
}

std::string ip_to_string(uint32_t net) {
    char buf[INET_ADDRSTRLEN] = {};
    in_addr a{};
    a.s_addr = net;
    if (!inet_ntop(AF_INET, &a, buf, sizeof(buf))) return "?";
    return buf;
}

std::atomic<uint16_t> g_ip_id{1};
std::atomic<uint64_t> g_captured{0}, g_dns_ok{0}, g_dns_fail{0};
std::atomic<uint64_t> g_connect_ok{0}, g_socks_fail{0}, g_passthru{0};
std::atomic<uint64_t> g_drop_quic{0}, g_drop_ipv6{0};
std::atomic<uint64_t> g_tcp_passthru{0};
std::atomic<uint64_t> g_rx{0}, g_tx{0};
std::atomic<int> g_dns_inflight{0};

void register_own_port(uint16_t sport) { internet_self::register_port(sport); }
void unregister_own_port(uint16_t sport) { internet_self::unregister_port(sport); }
void register_own_socket(SOCKET s) { internet_self::register_socket(s); }
void unregister_own_socket(SOCKET s) { internet_self::unregister_socket(s); }
bool is_own_sport(uint16_t sport) { return internet_self::is_own_sport(sport); }

bool is_private_ip(uint32_t net_order) {
    const uint32_t h = ntohl(net_order);
    if ((h & 0xFF000000u) == 0x0A000000u) return true;
    if ((h & 0xFFF00000u) == 0xAC100000u) return true;
    if ((h & 0xFFFF0000u) == 0xC0A80000u) return true;
    if ((h & 0xFF000000u) == 0x7F000000u) return true;
    if ((h & 0xFFFF0000u) == 0xA9FE0000u) return true; // link-local
    return false;
}

constexpr uint32_t kDnsTtl = 300;
// Collision / resolve-miss stand-ins (same pool as activate_net fake-IP).
constexpr uint32_t kStandInHostMin = 0xC6120001u;
constexpr uint32_t kStandInHostMax = 0xC613FFFEu;

struct DnsNameEntry {
    std::string name;
};
std::mutex g_dns_mu;
std::unordered_map<uint32_t, DnsNameEntry> g_ip_to_name;
std::unordered_map<std::string, uint32_t> g_name_to_ip;
uint32_t g_standin_next = kStandInHostMin;

std::string to_lower_host(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
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
    if (it == g_ip_to_name.end()) return {};
    return it->second.name;
}

// Allocate a unique 198.18 stand-in (caller holds g_dns_mu).
uint32_t dns_standin_alloc_locked(const std::string& qname) {
    for (int n = 0; n < 65536; ++n) {
        uint32_t host = g_standin_next++;
        if (g_standin_next > kStandInHostMax) g_standin_next = kStandInHostMin;
        const uint8_t b3 = static_cast<uint8_t>(host & 0xFF);
        if (b3 == 0 || b3 == 255) continue;
        const uint32_t net = htonl(host);
        if (g_ip_to_name.count(net)) continue;
        g_ip_to_name[net] = DnsNameEntry{qname};
        g_name_to_ip[qname] = net;
        return net;
    }
    return 0;
}

// Sticky IP↔name bind. Prefer real_ip when free; on CDN/poison collision or
// missing real_ip, allocate a unique stand-in so CONNECT(domain) stays correct
// (activate_net behavior). Never overwrite another hostname's IP.
uint32_t dns_bind_name(const std::string& qname_raw, uint32_t real_ip) {
    const std::string qname = to_lower_host(qname_raw);
    if (qname.empty() || qname == "?") return 0;
    std::lock_guard<std::mutex> lock(g_dns_mu);
    auto nit = g_name_to_ip.find(qname);
    if (nit != g_name_to_ip.end() && nit->second) return nit->second;

    if (real_ip && !is_private_ip(real_ip) && !is_standin_ip(real_ip)) {
        auto iit = g_ip_to_name.find(real_ip);
        if (iit == g_ip_to_name.end()) {
            g_ip_to_name[real_ip] = DnsNameEntry{qname};
            g_name_to_ip[qname] = real_ip;
            return real_ip;
        }
        if (iit->second.name == qname) {
            g_name_to_ip[qname] = real_ip;
            return real_ip;
        }
        // Shared/poisoned IP already owned by another name → unique stand-in.
    }
    return dns_standin_alloc_locked(qname);
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
    resp[3] = static_cast<uint8_t>((resp[3] & 0xF0) | 0x02); // SERVFAIL
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
    resp[6] = 0;
    resp[7] = 1;
    resp[8] = resp[9] = resp[10] = resp[11] = 0;
    resp.push_back(0xC0);
    resp.push_back(0x0C);
    resp.push_back(0x00);
    resp.push_back(0x01);
    resp.push_back(0x00);
    resp.push_back(0x01);
    resp.push_back(static_cast<uint8_t>(kDnsTtl >> 24));
    resp.push_back(static_cast<uint8_t>(kDnsTtl >> 16));
    resp.push_back(static_cast<uint8_t>(kDnsTtl >> 8));
    resp.push_back(static_cast<uint8_t>(kDnsTtl));
    resp.push_back(0x00);
    resp.push_back(0x04);
    const uint8_t* p = reinterpret_cast<const uint8_t*>(&ip_net);
    resp.insert(resp.end(), p, p + 4);
    return resp;
}

bool load_windivert() {
    HMODULE m = LoadLibraryA("WinDivert.dll");
    if (!m) return false;
    g_open = reinterpret_cast<FnOpen>(GetProcAddress(m, "WinDivertOpen"));
    g_recv = reinterpret_cast<FnRecv>(GetProcAddress(m, "WinDivertRecv"));
    g_send = reinterpret_cast<FnSend>(GetProcAddress(m, "WinDivertSend"));
    g_close = reinterpret_cast<FnClose>(GetProcAddress(m, "WinDivertClose"));
    g_shutdown = reinterpret_cast<FnShutdown>(GetProcAddress(m, "WinDivertShutdown"));
    g_set_param = reinterpret_cast<FnSetParam>(GetProcAddress(m, "WinDivertSetParam"));
    g_calc = reinterpret_cast<FnCalc>(GetProcAddress(m, "WinDivertHelperCalcChecksums"));
    return g_open && g_recv && g_send && g_close;
}

void inject_inbound(HANDLE divert, DivertAddr addr, const std::vector<uint8_t>& packet) {
    addr_set_outbound(addr, false);
    addr_set_impostor(addr, true);
    addr_clear_checksum_bits(addr);
    if (g_calc) {
        DivertAddr tmp = addr;
        g_calc(const_cast<uint8_t*>(packet.data()), static_cast<UINT>(packet.size()), &tmp, 0);
    }
    UINT sent = 0;
    g_send(divert, packet.data(), static_cast<UINT>(packet.size()), &sent, &addr);
}

void reinject(HANDLE divert, const DivertAddr& addr, const uint8_t* packet, UINT len) {
    UINT sent = 0;
    g_send(divert, packet, len, &sent, &addr);
}

bool recvn(SOCKET s, char* buf, int n) {
    int got = 0;
    while (got < n) {
        const int r = recv(s, buf + got, n - got, 0);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

bool send_all(SOCKET s, const uint8_t* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        const int n = send(s, reinterpret_cast<const char*>(data + off),
                           static_cast<int>(len - off), 0);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

void set_timeouts(SOCKET s, int sec) {
    DWORD ms = static_cast<DWORD>(sec) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&ms), sizeof(ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&ms), sizeof(ms));
}

SOCKET tcp_connect_timeout(const std::string& host, int port, int timeout_sec) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res) {
        return INVALID_SOCKET;
    }
    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(res);
        return INVALID_SOCKET;
    }
    register_own_socket(s);
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    int rc = connect(s, res->ai_addr, static_cast<int>(res->ai_addrlen));
    freeaddrinfo(res);
    if (rc != 0 && WSAGetLastError() != WSAEWOULDBLOCK) {
        unregister_own_socket(s);
        closesocket(s);
        return INVALID_SOCKET;
    }
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(s, &wfds);
    timeval tv{};
    tv.tv_sec = timeout_sec;
    rc = select(0, nullptr, &wfds, nullptr, &tv);
    if (rc <= 0) {
        unregister_own_socket(s);
        closesocket(s);
        return INVALID_SOCKET;
    }
    int soerr = 0;
    int slen = sizeof(soerr);
    getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &slen);
    if (soerr != 0) {
        unregister_own_socket(s);
        closesocket(s);
        return INVALID_SOCKET;
    }
    nb = 0;
    ioctlsocket(s, FIONBIO, &nb);
    set_timeouts(s, timeout_sec);
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char*>(&one), sizeof(one));
    return s;
}

bool socks5_read_connect_reply(SOCKET s) {
    char hdr[4];
    if (!recvn(s, hdr, 4) || hdr[0] != 0x05 || hdr[1] != 0x00) return false;
    int rest = 0;
    if (static_cast<uint8_t>(hdr[3]) == 0x01) rest = 6;
    else if (static_cast<uint8_t>(hdr[3]) == 0x04) rest = 18;
    else if (static_cast<uint8_t>(hdr[3]) == 0x03) {
        char ln = 0;
        if (!recvn(s, &ln, 1)) return false;
        rest = static_cast<unsigned char>(ln) + 2;
    } else {
        return false;
    }
    if (rest <= 0) return true;
    std::vector<char> skip(static_cast<size_t>(rest));
    return recvn(s, skip.data(), rest);
}

SOCKET socks5_handshake(int timeout_sec) {
    SOCKET s = tcp_connect_timeout(g_cfg.socks5_host, g_cfg.socks5_port, timeout_sec);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    const char greet[] = {0x05, 0x01, 0x00};
    if (!send_all(s, reinterpret_cast<const uint8_t*>(greet), 3)) {
        unregister_own_socket(s);
        closesocket(s);
        return INVALID_SOCKET;
    }
    char greply[2];
    if (!recvn(s, greply, 2) || greply[0] != 0x05 || greply[1] != 0x00) {
        unregister_own_socket(s);
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

SOCKET socks5_connect_host(const std::string& host, uint16_t dst_port_host, int timeout_sec) {
    if (host.empty() || host.size() > 255) return INVALID_SOCKET;
    SOCKET s = socks5_handshake(timeout_sec);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    std::vector<uint8_t> req(5 + host.size() + 2);
    req[0] = 0x05;
    req[1] = 0x01;
    req[2] = 0x00;
    req[3] = 0x03;
    req[4] = static_cast<uint8_t>(host.size());
    std::memcpy(req.data() + 5, host.data(), host.size());
    req[5 + host.size()] = static_cast<uint8_t>(dst_port_host >> 8);
    req[5 + host.size() + 1] = static_cast<uint8_t>(dst_port_host);
    if (!send_all(s, req.data(), req.size()) || !socks5_read_connect_reply(s)) {
        unregister_own_socket(s);
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

SOCKET socks5_connect_ip(uint32_t dst_net, uint16_t dst_port_host, int timeout_sec) {
    if (!dst_net) return INVALID_SOCKET;
    SOCKET s = socks5_handshake(timeout_sec);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    uint8_t req[10] = {0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0,
                       static_cast<uint8_t>(dst_port_host >> 8),
                       static_cast<uint8_t>(dst_port_host)};
    std::memcpy(req + 4, &dst_net, 4);
    if (!send_all(s, req, sizeof(req)) || !socks5_read_connect_reply(s)) {
        unregister_own_socket(s);
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

std::vector<uint8_t> build_dns_query_a(const std::string& name, uint16_t id) {
    std::vector<uint8_t> q;
    q.push_back(static_cast<uint8_t>(id >> 8));
    q.push_back(static_cast<uint8_t>(id));
    q.push_back(0x01);
    q.push_back(0x00);
    q.push_back(0x00);
    q.push_back(0x01);
    q.push_back(0x00);
    q.push_back(0x00);
    q.push_back(0x00);
    q.push_back(0x00);
    q.push_back(0x00);
    q.push_back(0x00);
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
    q.push_back(0x00);
    q.push_back(0x01);
    q.push_back(0x00);
    q.push_back(0x01);
    return q;
}

enum class DnsAResult { Ok, NoData, Fail };

DnsAResult parse_dns_a_answer(const uint8_t* resp, size_t rlen, uint32_t& out_net) {
    if (!resp || rlen < 12) return DnsAResult::Fail;
    const uint8_t rcode = static_cast<uint8_t>(resp[3] & 0x0F);
    if (rcode == 3) return DnsAResult::NoData; // NXDOMAIN
    if (rcode != 0) return DnsAResult::Fail;
    const uint16_t ancount = static_cast<uint16_t>((resp[6] << 8) | resp[7]);
    auto skip_name = [&](size_t off) -> size_t {
        int hops = 0;
        while (off < rlen && hops < 64) {
            const uint8_t lab = resp[off];
            if (lab == 0) return off + 1;
            if ((lab & 0xC0) == 0xC0) return off + 2 < rlen ? off + 2 : rlen;
            if (off + 1 + lab > rlen) return rlen;
            off += 1 + lab;
            ++hops;
        }
        return rlen;
    };
    size_t off = skip_name(12);
    if (off + 4 > rlen) return DnsAResult::Fail;
    off += 4;
    bool saw_answer = false;
    for (uint16_t ai = 0; ai < ancount && off + 10 <= rlen; ++ai) {
        off = skip_name(off);
        if (off + 10 > rlen) return DnsAResult::Fail;
        const uint16_t typ = static_cast<uint16_t>((resp[off] << 8) | resp[off + 1]);
        const uint16_t rdlen = static_cast<uint16_t>((resp[off + 8] << 8) | resp[off + 9]);
        off += 10;
        if (off + rdlen > rlen) return DnsAResult::Fail;
        saw_answer = true;
        if (typ == 1 && rdlen == 4) {
            uint32_t ip = 0;
            std::memcpy(&ip, resp + off, 4);
            if (ip && !is_private_ip(ip)) {
                out_net = ip;
                return DnsAResult::Ok;
            }
        }
        off += rdlen;
    }
    return saw_answer || ancount == 0 ? DnsAResult::NoData : DnsAResult::Fail;
}

// Fast UDP A lookup. Must register own_sport so WinDivert reinjects our query
// (filter captures all outbound UDP/53).
DnsAResult resolve_ipv4_dns_udp(const std::string& name, uint32_t resolver_net, uint32_t& out_net,
                                int timeout_ms = 1500) {
    if (name.empty() || name.size() > 253 || !resolver_net) return DnsAResult::Fail;
    const auto q = build_dns_query_a(name, static_cast<uint16_t>(GetTickCount() & 0xFFFF));
    if (q.empty()) return DnsAResult::Fail;

    SOCKET s = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) return DnsAResult::Fail;
    sockaddr_in local{};
    local.sin_family = AF_INET;
    local.sin_addr.s_addr = htonl(INADDR_ANY);
    local.sin_port = 0;
    if (bind(s, reinterpret_cast<sockaddr*>(&local), sizeof(local)) != 0) {
        closesocket(s);
        return DnsAResult::Fail;
    }
    register_own_socket(s);
    DWORD ms = static_cast<DWORD>(timeout_ms);
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&ms), sizeof(ms));

    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    dst.sin_addr.s_addr = resolver_net;
    const int sent = sendto(s, reinterpret_cast<const char*>(q.data()), static_cast<int>(q.size()), 0,
                            reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
    if (sent != static_cast<int>(q.size())) {
        unregister_own_socket(s);
        closesocket(s);
        return DnsAResult::Fail;
    }

    uint8_t buf[2048];
    const int n = recvfrom(s, reinterpret_cast<char*>(buf), sizeof(buf), 0, nullptr, nullptr);
    unregister_own_socket(s);
    closesocket(s);
    if (n < 12) return DnsAResult::Fail;
    return parse_dns_a_answer(buf, static_cast<size_t>(n), out_net);
}

bool dns_tcp_transact(SOCKET s, const std::string& name, uint32_t& out_net) {
    const auto q = build_dns_query_a(name, static_cast<uint16_t>(GetTickCount() & 0xFFFF));
    if (q.empty()) return false;
    uint8_t lenb[2] = {static_cast<uint8_t>(q.size() >> 8), static_cast<uint8_t>(q.size())};
    if (!send_all(s, lenb, 2) || !send_all(s, q.data(), q.size())) return false;
    uint8_t rlenb[2];
    if (!recvn(s, reinterpret_cast<char*>(rlenb), 2)) return false;
    const size_t rlen = (static_cast<size_t>(rlenb[0]) << 8) | rlenb[1];
    if (rlen < 12 || rlen > 4096) return false;
    std::vector<uint8_t> resp(rlen);
    if (!recvn(s, reinterpret_cast<char*>(resp.data()), static_cast<int>(rlen))) return false;
    return parse_dns_a_answer(resp.data(), rlen, out_net) == DnsAResult::Ok;
}

// Resolve A via SOCKS5 → 8.8.8.8:53 DNS-over-TCP (bypasses GFW UDP pollution).
bool resolve_ipv4_via_socks(const std::string& name, uint32_t& out_net) {
    SOCKET s = socks5_connect_ip(htonl(0x08080808u), 53, 6);
    if (s == INVALID_SOCKET) s = socks5_connect_ip(htonl(0x01010101u), 53, 6);
    if (s == INVALID_SOCKET) return false;
    set_timeouts(s, 6);
    const bool ok = dns_tcp_transact(s, name, out_net);
    unregister_own_socket(s);
    closesocket(s);
    return ok;
}

bool resolve_ipv4_fast(const std::string& name, uint32_t client_resolver_net, uint32_t& out_net) {
    in_addr lit{};
    if (inet_pton(AF_INET, name.c_str(), &lit) == 1) {
        out_net = lit.s_addr;
        return !is_private_ip(out_net);
    }

    // Local UDP first (fast CN CDN). Poisoned A for google is OK: we always
    // CONNECT(domain) so multilink/remote DNS + DOMAIN rules still work.
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

    // Clean path when local DNS fails entirely: SOCKS → 8.8.8.8 DNS-over-TCP.
    if (resolve_ipv4_via_socks(name, out_net)) return true;
    if (resolve_ipv4_dns_tcp(name, out_net) && !is_private_ip(out_net)) return true;
    return false;
}

struct Seg {
    uint32_t seq = 0;
    uint8_t flags = 0;
    std::vector<uint8_t> data;
    int sends = 0;
    std::chrono::steady_clock::time_point last_send{};
};
struct OooSeg {
    uint32_t seq = 0;
    std::vector<uint8_t> data;
    bool fin = false;
};
uint32_t seg_end(const Seg& s) {
    uint32_t n = s.seq + static_cast<uint32_t>(s.data.size());
    if (s.flags & pkt::TCP_SYN) ++n;
    if (s.flags & pkt::TCP_FIN) ++n;
    return n;
}

struct FlowKey {
    uint32_t src = 0, dst = 0;
    uint16_t sport = 0, dport = 0;
    bool operator==(const FlowKey& o) const {
        return src == o.src && dst == o.dst && sport == o.sport && dport == o.dport;
    }
};
struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const {
        return (static_cast<size_t>(k.src) * 1315423911u) ^ k.dst ^
               (static_cast<size_t>(k.sport) << 16) ^ k.dport;
    }
};

enum class FlowState { SynSent, Open, Closing, Dead };
struct Flow {
    FlowKey key;
    HANDLE divert = nullptr;
    DivertAddr addr{};
    std::mutex mu;
    std::condition_variable cv;
    std::atomic<bool> alive{true};
    FlowState state = FlowState::SynSent;
    uint32_t isn = 0, client_isn = 0, rcv_nxt = 0, snd_una = 0, snd_nxt = 0;
    uint16_t peer_wnd = 65535, peer_mss = 1460;
    std::vector<Seg> segs;
    std::vector<OooSeg> ooo;
    size_t ooo_bytes = 0;
    std::vector<uint8_t> to_socks;
    bool fin_from_client = false, fin_queued = false, local_closed = false;
    SOCKET sock = INVALID_SOCKET;
    std::chrono::steady_clock::time_point last_rx = std::chrono::steady_clock::now();
};

std::mutex g_map_mu;
std::unordered_map<FlowKey, std::shared_ptr<Flow>, FlowKeyHash> g_flows;

bool flow_exists(const FlowKey& key) {
    std::lock_guard<std::mutex> lock(g_map_mu);
    auto it = g_flows.find(key);
    return it != g_flows.end() && it->second->alive;
}

size_t unacked_bytes(const Flow& f) {
    size_t n = 0;
    for (const auto& s : f.segs) n += s.data.size();
    return n;
}
uint16_t recv_window(const Flow& f) {
    const size_t cap = 256 * 1024;
    if (f.to_socks.size() >= cap) return 0;
    const size_t left = cap - f.to_socks.size();
    return static_cast<uint16_t>(left > 65535 ? 65535 : left);
}
uint32_t tx_seq(const Flow& f) {
    for (const auto& s : f.segs) {
        if (s.sends == 0 && pkt::seq_diff(seg_end(s), f.snd_una) > 0) return s.seq;
    }
    return f.snd_nxt;
}
bool seg_fits(const Flow& f, const Seg& s) {
    if (s.flags & pkt::TCP_SYN) return true;
    const int32_t need = pkt::seq_diff(seg_end(s), f.snd_una);
    if (need <= 0) return true;
    return f.peer_wnd > 0 && static_cast<uint32_t>(need) <= f.peer_wnd;
}

void transmit_locked(Flow& f, Seg& s) {
    uint8_t mss_opt[4] = {2, 4, 0x05, 0xB4};
    const bool syn = (s.flags & pkt::TCP_SYN) != 0;
    auto packet = pkt::build_tcp(
        f.key.dst, f.key.src, f.key.dport, f.key.sport,
        s.seq, f.rcv_nxt, s.flags, recv_window(f),
        s.data.empty() ? nullptr : s.data.data(), s.data.size(),
        g_ip_id++,
        syn ? mss_opt : nullptr, syn ? sizeof(mss_opt) : 0);
    inject_inbound(f.divert, f.addr, packet);
    s.sends += 1;
    s.last_send = std::chrono::steady_clock::now();
}
void flush_send_locked(Flow& f) {
    for (auto& s : f.segs) {
        if (pkt::seq_diff(seg_end(s), f.snd_una) <= 0) continue;
        if (s.sends > 0) continue;
        if (!seg_fits(f, s)) break;
        transmit_locked(f, s);
    }
}
void enqueue_locked(Flow& f, uint8_t flags, const uint8_t* data, size_t len) {
    if (len == 0) {
        Seg s;
        s.seq = f.snd_nxt;
        s.flags = flags;
        uint32_t step = 0;
        if (flags & pkt::TCP_SYN) ++step;
        if (flags & pkt::TCP_FIN) ++step;
        f.snd_nxt += step;
        f.segs.push_back(std::move(s));
        flush_send_locked(f);
        return;
    }
    size_t mss = static_cast<size_t>(std::min(g_cfg.mss, static_cast<int>(f.peer_mss)));
    if (mss < 200) mss = 200;
    size_t off = 0;
    while (off < len) {
        const size_t n = std::min(len - off, mss);
        const bool last = (off + n == len);
        uint8_t fl = pkt::TCP_ACK | pkt::TCP_PSH;
        if (last && (flags & pkt::TCP_FIN)) fl |= pkt::TCP_FIN;
        Seg s;
        s.seq = f.snd_nxt;
        s.flags = fl;
        s.data.assign(data + off, data + off + n);
        f.snd_nxt += static_cast<uint32_t>(n);
        if (fl & pkt::TCP_FIN) f.snd_nxt += 1;
        f.segs.push_back(std::move(s));
        off += n;
    }
    flush_send_locked(f);
}
void send_ack_locked(Flow& f) {
    auto packet = pkt::build_tcp(
        f.key.dst, f.key.src, f.key.dport, f.key.sport,
        tx_seq(f), f.rcv_nxt, pkt::TCP_ACK, recv_window(f),
        nullptr, 0, g_ip_id++);
    inject_inbound(f.divert, f.addr, packet);
}
void send_rst_locked(Flow& f) {
    auto packet = pkt::build_tcp(
        f.key.dst, f.key.src, f.key.dport, f.key.sport,
        tx_seq(f), f.rcv_nxt, pkt::TCP_RST | pkt::TCP_ACK, 0,
        nullptr, 0, g_ip_id++);
    inject_inbound(f.divert, f.addr, packet);
    f.state = FlowState::Dead;
    f.alive = false;
}
void ack_update_locked(Flow& f, uint32_t ack) {
    if (pkt::seq_diff(ack, f.snd_nxt) > 0) return;
    if (pkt::seq_diff(ack, f.snd_una) <= 0) return;
    f.snd_una = ack;
    auto it = f.segs.begin();
    while (it != f.segs.end()) {
        if (pkt::seq_diff(ack, seg_end(*it)) >= 0) it = f.segs.erase(it);
        else ++it;
    }
    f.cv.notify_all();
}
bool accept_payload_locked(Flow& f, const uint8_t* data, size_t len, bool fin) {
    if (f.to_socks.size() + len > 256 * 1024) return false;
    if (len > 0) {
        f.to_socks.insert(f.to_socks.end(), data, data + len);
        f.rcv_nxt += static_cast<uint32_t>(len);
        g_rx += len;
    }
    if (fin && !f.fin_from_client) {
        f.rcv_nxt += 1;
        f.fin_from_client = true;
    }
    return true;
}
void take_ooo_locked(Flow& f) {
    bool progressed = true;
    while (progressed) {
        progressed = false;
        for (size_t i = 0; i < f.ooo.size();) {
            OooSeg& o = f.ooo[i];
            const int32_t d = pkt::seq_diff(o.seq, f.rcv_nxt);
            if (d > 0) {
                ++i;
                continue;
            }
            const size_t skip = static_cast<size_t>(-d);
            if (skip > o.data.size()) {
                f.ooo_bytes -= o.data.size();
                f.ooo.erase(f.ooo.begin() + static_cast<std::ptrdiff_t>(i));
                progressed = true;
                continue;
            }
            const size_t n = o.data.size() - skip;
            const bool fin = o.fin && (skip + n == o.data.size());
            if (!accept_payload_locked(f, n ? o.data.data() + skip : nullptr, n, fin)) return;
            f.ooo_bytes -= o.data.size();
            f.ooo.erase(f.ooo.begin() + static_cast<std::ptrdiff_t>(i));
            progressed = true;
        }
    }
}

void close_flow_socket(const std::shared_ptr<Flow>& f) {
    f->alive = false;
    f->cv.notify_all();
    if (f->sock != INVALID_SOCKET) {
        unregister_own_socket(f->sock);
        shutdown(f->sock, SD_BOTH);
        closesocket(f->sock);
        f->sock = INVALID_SOCKET;
    }
}
void erase_flow(const std::shared_ptr<Flow>& f) {
    std::lock_guard<std::mutex> lock(g_map_mu);
    auto it = g_flows.find(f->key);
    if (it != g_flows.end() && it->second == f) g_flows.erase(it);
}

void socks_worker(std::shared_ptr<Flow> f) {
    // Match activate_net: always SOCKS5 CONNECT(domain). Never CONNECT(IP) —
    // local DNS is often poisoned (e.g. google → 185.45.5.35) and IP CONNECT
    // skips DOMAIN rules then fails remotely with cmd=4.
    const std::string learned = dns_lookup_name(f->key.dst);

    auto fail_rst = [&](const std::string& why) {
        ++g_socks_fail;
        log_line("[-] " + why + " " + ip_to_string(f->key.src) + ":" +
                 std::to_string(f->key.sport) + " -> " + ip_to_string(f->key.dst) + ":" +
                 std::to_string(f->key.dport));
        {
            std::lock_guard<std::mutex> lock(f->mu);
            if (f->alive) send_rst_locked(*f);
        }
        erase_flow(f);
    };

    if (learned.empty()) {
        fail_rst("no learned domain for dst IP");
        return;
    }

    const std::string dst_label = learned + "/" + ip_to_string(f->key.dst);
    SOCKET s = socks5_connect_host(learned, f->key.dport, 15);

    {
        std::lock_guard<std::mutex> lock(f->mu);
        if (!f->alive) {
            if (s != INVALID_SOCKET) {
                unregister_own_socket(s);
                closesocket(s);
            }
            erase_flow(f);
            return;
        }
        if (s == INVALID_SOCKET) {
            ++g_socks_fail;
            log_line("[-] SOCKS5 CONNECT failed " + ip_to_string(f->key.src) + ":" +
                     std::to_string(f->key.sport) + " -> " + dst_label + ":" +
                     std::to_string(f->key.dport) +
                     " (is Internet router SOCKS up on " + g_cfg.socks5_host + ":" +
                     std::to_string(g_cfg.socks5_port) + "?)");
            send_rst_locked(*f);
            erase_flow(f);
            return;
        }
        f->sock = s;
        f->state = FlowState::Open;
        set_timeouts(s, std::max(30, g_cfg.idle_timeout_sec));
    }
    ++g_connect_ok;
    if (g_cfg.log_connections) {
        log_line("[+] TCP " + ip_to_string(f->key.src) + ":" + std::to_string(f->key.sport) +
                 " -> " + dst_label + ":" + std::to_string(f->key.dport) + " via SOCKS5/domain");
    }

    std::thread downstream([f, s] {
        std::vector<uint8_t> buf(16384);
        while (f->alive) {
            const int n = recv(s, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0);
            if (n == 0) break;
            if (n < 0) {
                const int err = WSAGetLastError();
                if (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) {
                    if (!f->alive) break;
                    continue;
                }
                break;
            }
            std::unique_lock<std::mutex> lock(f->mu);
            while (f->alive && unacked_bytes(*f) > 64 * 1024) {
                lock.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                lock.lock();
            }
            if (!f->alive) break;
            enqueue_locked(*f, pkt::TCP_ACK, buf.data(), static_cast<size_t>(n));
            g_tx += static_cast<uint64_t>(n);
        }
        std::lock_guard<std::mutex> lock(f->mu);
        if (f->alive && !f->fin_queued) {
            f->fin_queued = true;
            f->state = FlowState::Closing;
            enqueue_locked(*f, pkt::TCP_FIN | pkt::TCP_ACK, nullptr, 0);
        }
        f->local_closed = true;
        f->cv.notify_all();
    });

    while (f->alive) {
        std::vector<uint8_t> chunk;
        bool fin = false;
        {
            std::unique_lock<std::mutex> lock(f->mu);
            f->cv.wait_for(lock, std::chrono::milliseconds(200), [&] {
                return !f->alive || !f->to_socks.empty() || f->fin_from_client || f->local_closed;
            });
            if (!f->alive && f->to_socks.empty()) break;
            if (f->local_closed && f->to_socks.empty() && !f->fin_from_client) break;
            chunk.swap(f->to_socks);
            fin = f->fin_from_client;
        }
        if (!chunk.empty() && !send_all(s, chunk.data(), chunk.size())) {
            shutdown(s, SD_BOTH);
            break;
        }
        if (fin) {
            shutdown(s, SD_SEND);
            break;
        }
    }
    downstream.join();
    if (s != INVALID_SOCKET) {
        unregister_own_socket(s);
        shutdown(s, SD_BOTH);
        closesocket(s);
    }
    f->sock = INVALID_SOCKET;
    {
        std::unique_lock<std::mutex> lock(f->mu);
        f->cv.wait_for(lock, std::chrono::seconds(20), [&] {
            flush_send_locked(*f);
            return !f->alive || (f->fin_queued && pkt::seq_diff(f->snd_nxt, f->snd_una) <= 0);
        });
        f->alive = false;
        f->cv.notify_all();
    }
    erase_flow(f);
}

void handle_dns(HANDLE divert, DivertAddr addr, uint32_t src, uint16_t sport,
                uint32_t dst, std::vector<uint8_t> query) {
    struct Guard {
        ~Guard() { --g_dns_inflight; }
    } guard;

    const std::string qname = dns_qname(query.data(), query.size());
    const uint16_t qtype = dns_qtype(query.data(), query.size());

    auto inject_dns = [&](const std::vector<uint8_t>& resp, const std::string& note, bool ok) {
        if (resp.empty()) {
            ++g_dns_fail;
            return;
        }
        auto packet = pkt::build_udp(dst, src, 53, sport, resp.data(), resp.size(), g_ip_id++);
        inject_inbound(divert, addr, packet);
        if (ok) ++g_dns_ok;
        else ++g_dns_fail;
        log_line(std::string(ok ? "[+] DNS q=" : "[-] DNS q=") + qname + " " + note);
    };

    if (qtype != 1) {
        // AAAA etc. → NODATA so stacks use IPv4 / learned A only (like activate_net).
        inject_dns(dns_reply_nodata(query), "type" + std::to_string(qtype) + "->NODATA", true);
        return;
    }
    if (qname.empty() || qname == "?") {
        inject_dns(dns_reply_servfail(query), "bad qname->SERVFAIL", false);
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_dns_mu);
        auto it = g_name_to_ip.find(qname);
        if (it != g_name_to_ip.end() && it->second) {
            inject_dns(dns_reply_a(query, it->second), "cached A " + ip_to_string(it->second), true);
            return;
        }
    }

    uint32_t real_ip = 0;
    const bool resolved = resolve_ipv4_fast(qname, dst, real_ip);
    // Sticky bind: real IP if unique, else 198.18 stand-in. On resolve miss still
    // allocate stand-in so CONNECT(domain) can use remote DNS (activate_net path).
    const uint32_t answer = dns_bind_name(qname, resolved ? real_ip : 0);
    if (!answer) {
        inject_dns(dns_reply_servfail(query), "bind failed->SERVFAIL", false);
        return;
    }
    std::string note = "A " + ip_to_string(answer);
    if (is_standin_ip(answer)) {
        note += resolved ? " (stand-in/collision)" : " (stand-in/no-resolve)";
    } else if (resolved) {
        note += " (redir-host)";
    }
    inject_dns(dns_reply_a(query, answer), note, true);
}

void handle_tcp(HANDLE divert, const DivertAddr& addr, const pkt::Ipv4L4& v) {
    FlowKey key{v.src_net, v.dst_net, v.sport, v.dport};
    const bool syn = (v.tcp_flags & pkt::TCP_SYN) != 0;
    const bool ackf = (v.tcp_flags & pkt::TCP_ACK) != 0;
    const bool rst = (v.tcp_flags & pkt::TCP_RST) != 0;
    const bool fin = (v.tcp_flags & pkt::TCP_FIN) != 0;

    if (rst) {
        std::shared_ptr<Flow> flow;
        {
            std::lock_guard<std::mutex> lock(g_map_mu);
            auto it = g_flows.find(key);
            if (it != g_flows.end()) flow = it->second;
        }
        if (flow) {
            close_flow_socket(flow);
            erase_flow(flow);
        }
        return;
    }

    if (syn && !ackf) {
        std::shared_ptr<Flow> created;
        {
            std::lock_guard<std::mutex> lock(g_map_mu);
            auto it = g_flows.find(key);
            if (it != g_flows.end() && it->second->alive) return;
            if (it != g_flows.end()) g_flows.erase(it);
            if (static_cast<int>(g_flows.size()) >= g_cfg.max_connections) return;
            created = std::make_shared<Flow>();
            created->key = key;
            created->divert = divert;
            created->addr = addr;
            created->isn = static_cast<uint32_t>(GetTickCount() ^ (v.src_net + v.sport * 17u));
            created->client_isn = v.seq;
            created->rcv_nxt = v.seq + 1;
            created->snd_una = created->isn;
            created->snd_nxt = created->isn;
            created->peer_wnd = v.window ? v.window : 65535;
            if (v.mss >= 200 && v.mss < 2000) created->peer_mss = v.mss;
            g_flows.emplace(key, created);
        }
        {
            std::lock_guard<std::mutex> lock(created->mu);
            enqueue_locked(*created, pkt::TCP_SYN | pkt::TCP_ACK, nullptr, 0);
        }
        std::thread(socks_worker, created).detach();
        return;
    }

    std::shared_ptr<Flow> flow;
    {
        std::lock_guard<std::mutex> lock(g_map_mu);
        auto it = g_flows.find(key);
        if (it != g_flows.end()) flow = it->second;
    }
    if (!flow) return;

    std::lock_guard<std::mutex> lock(flow->mu);
    if (!flow->alive) return;
    flow->addr = addr;
    flow->last_rx = std::chrono::steady_clock::now();
    if (ackf) {
        ack_update_locked(*flow, v.ack);
        flow->peer_wnd = v.window;
        flush_send_locked(*flow);
    }
    if (v.payload_len == 0 && !fin) {
        if (ackf) flow->cv.notify_all();
        return;
    }

    const uint8_t* payload = v.payload;
    size_t plen = v.payload_len;
    const int32_t diff = pkt::seq_diff(v.seq, flow->rcv_nxt);
    if (diff > 0) {
        if (plen > 0 && diff < 256 * 1024 && flow->ooo_bytes + plen <= 64 * 1024) {
            OooSeg o;
            o.seq = v.seq;
            o.data.assign(payload, payload + plen);
            o.fin = fin;
            flow->ooo.push_back(std::move(o));
            flow->ooo_bytes += plen;
        }
        send_ack_locked(*flow);
        return;
    }
    if (diff < 0) {
        const uint32_t already = static_cast<uint32_t>(-diff);
        if (already >= plen) {
            if (fin && !flow->fin_from_client) accept_payload_locked(*flow, nullptr, 0, true);
            send_ack_locked(*flow);
            flow->cv.notify_all();
            return;
        }
        payload += already;
        plen -= already;
    }
    if (accept_payload_locked(*flow, plen ? payload : nullptr, plen, fin && !flow->fin_from_client)) {
        take_ooo_locked(*flow);
    }
    send_ack_locked(*flow);
    flow->cv.notify_all();
}

void on_packet(HANDLE divert, DivertAddr addr, const uint8_t* packet, UINT len) {
    ++g_captured;
    if (len < 1) return;
    const uint8_t ver = static_cast<uint8_t>(packet[0] >> 4);
    if (ver == 6) {
        ++g_drop_ipv6;
        return;
    }

    auto v = pkt::parse_ipv4(packet, len);
    if (!v.ok || v.fragmented) {
        reinject(divert, addr, packet, len);
        ++g_passthru;
        return;
    }
    if (is_own_sport(v.sport) || internet_self::is_uplink_ipv4(v.dst_net) ||
        internet_self::is_uplink_ipv4(v.src_net)) {
        reinject(divert, addr, packet, len);
        ++g_passthru;
        return;
    }

    if (v.proto == 17 && v.dport == 53) {
        if (v.payload_len == 0 || v.payload_len > 1500) return;
        if (g_dns_inflight.load() >= g_cfg.max_dns_inflight) {
            // Overloaded: reinject so system resolver can answer (better than blackhole).
            reinject(divert, addr, packet, len);
            ++g_passthru;
            return;
        }
        ++g_dns_inflight;
        std::vector<uint8_t> q(v.payload, v.payload + v.payload_len);
        std::thread(handle_dns, divert, addr, v.src_net, v.sport, v.dst_net, std::move(q)).detach();
        return;
    }
    // Drop browser QUIC/DoT so they fall back to TCP→learned-IP→SOCKS.
    // smartlink/multilink uplink is TCP-only, so this does not affect them.
    if (v.proto == 17 && (v.dport == 443 || v.dport == 853)) {
        ++g_drop_quic;
        return;
    }
    if (v.proto == 6) {
        FlowKey key{v.src_net, v.dst_net, v.sport, v.dport};
        const bool syn = (v.tcp_flags & pkt::TCP_SYN) != 0;
        const bool ackf = (v.tcp_flags & pkt::TCP_ACK) != 0;
        const std::string learned = dns_lookup_name(v.dst_net);
        const bool in_flow = flow_exists(key);

        if (syn && !ackf) {
            if (learned.empty()) {
                reinject(divert, addr, packet, len);
                ++g_tcp_passthru;
                ++g_passthru;
                return;
            }
            handle_tcp(divert, addr, v);
            return;
        }
        if (learned.empty() && !in_flow) {
            reinject(divert, addr, packet, len);
            ++g_tcp_passthru;
            ++g_passthru;
            return;
        }
        if (in_flow) {
            handle_tcp(divert, addr, v);
            return;
        }
        reinject(divert, addr, packet, len);
        ++g_tcp_passthru;
        ++g_passthru;
        return;
    }
    reinject(divert, addr, packet, len);
    ++g_passthru;
}

void recv_loop(HANDLE h) {
    std::vector<uint8_t> buf(0xFFFF);
    DivertAddr addr{};
    while (g_run) {
        UINT recv_len = 0;
        if (!g_recv(h, buf.data(), static_cast<UINT>(buf.size()), &recv_len, &addr)) {
            if (!g_run) break;
            continue;
        }
        on_packet(h, addr, buf.data(), recv_len);
    }
}

void retransmit_loop() {
    while (g_run) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        const auto now = std::chrono::steady_clock::now();
        std::vector<std::shared_ptr<Flow>> snap;
        {
            std::lock_guard<std::mutex> lock(g_map_mu);
            for (auto& kv : g_flows) snap.push_back(kv.second);
        }
        for (auto& f : snap) {
            std::lock_guard<std::mutex> lock(f->mu);
            if (!f->alive) continue;
            if (now - f->last_rx > std::chrono::seconds(g_cfg.idle_timeout_sec)) {
                send_rst_locked(*f);
                continue;
            }
            for (auto& s : f->segs) {
                if (pkt::seq_diff(seg_end(s), f->snd_una) <= 0) continue;
                if (s.sends == 0) continue;
                if (now - s.last_send < std::chrono::milliseconds(400)) continue;
                if (s.sends >= 8) {
                    send_rst_locked(*f);
                    break;
                }
                transmit_locked(*f, s);
            }
            flush_send_locked(*f);
        }
    }
}

BOOL WINAPI on_console(DWORD) {
    g_run = false;
    return TRUE;
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
        std::cerr << "[-] WSAStartup failed\n";
        return 1;
    }
    SetConsoleCtrlHandler(on_console, TRUE);

    InternetConfig icfg;
    try {
        icfg = InternetConfig::load(config_path);
    } catch (const std::exception& e) {
        std::cerr << "[-] " << e.what() << "\n";
        net_cleanup();
        return 1;
    }

    const MultilinkConfig& ml = icfg.multilink;
    g_cfg.socks5_host = "127.0.0.1";
    g_cfg.socks5_port = ml.socks5_bind_port;
    g_cfg.mss = icfg.mss;
    g_cfg.idle_timeout_sec = icfg.divert_idle_timeout_sec;
    g_cfg.max_connections = icfg.max_connections;
    g_cfg.max_dns_inflight = icfg.max_dns_inflight;
    g_cfg.log_connections = icfg.log_connections;

    if (!internet_router::start(ml)) {
        net_cleanup();
        return 1;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    if (router_only) {
        log_line("[*] Internet --router-only (MultiLink SOCKS only; no WinDivert)");
        log_line("[*] SOCKS 127.0.0.1:" + std::to_string(ml.socks5_bind_port));
        while (g_run) std::this_thread::sleep_for(std::chrono::milliseconds(200));
        internet_router::stop();
        net_cleanup();
        return 0;
    }

    if (!load_windivert()) {
        std::cerr << "[-] WinDivert.dll not found next to internet.exe\n";
        internet_router::stop();
        net_cleanup();
        return 1;
    }

    const std::string filter =
        "outbound and not loopback and not impostor and ("
        "ipv6 or "
        "(ip and udp.DstPort == 53) or "
        "(ip and udp.DstPort == 443) or "
        "(ip and udp.DstPort == 853) or "
        "(ip and tcp)"
        ")";
    HANDLE h = g_open(filter.c_str(), WINDIVERT_LAYER_NETWORK, WINDIVERT_PRIORITY_HIGHEST, 0);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        std::cerr << "[-] WinDivertOpen failed err=" << err
                  << (err == 5 ? " (need Administrator)" : "") << "\n";
        internet_router::stop();
        net_cleanup();
        return 1;
    }
    if (g_set_param) {
        g_set_param(h, 0, 8192);
        g_set_param(h, 1, 8000);
        g_set_param(h, 2, 16ull << 20);
    }

    log_line("[*] Internet — transparent redir-host + MultiLink (single process)");
    log_line("[*] config " + config_path);
    log_line("[*] router SOCKS 127.0.0.1:" + std::to_string(g_cfg.socks5_port) +
             "  links=" + std::to_string(ml.links.size()) +
             "  default=" + ml.default_link);
    log_line("[*] filter: " + filter);
    log_line("[*] self-exclude: router/uplink source ports + all Vortex server IPs");
    log_line("[*] apps: no proxy settings; DNS sticky map; TCP CONNECT(domain) via rules");

    std::thread retx(retransmit_loop);
    std::thread reader(recv_loop, h);

    while (g_run) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        if (!g_run) break;
        size_t flows = 0;
        {
            std::lock_guard<std::mutex> lock(g_map_mu);
            flows = g_flows.size();
        }
        log_line("[*] captured=" + std::to_string(g_captured.load()) +
                 " flows=" + std::to_string(flows) +
                 " dns_ok=" + std::to_string(g_dns_ok.load()) +
                 " dns_fail=" + std::to_string(g_dns_fail.load()) +
                 " connect_ok=" + std::to_string(g_connect_ok.load()) +
                 " socks_fail=" + std::to_string(g_socks_fail.load()) +
                 " tcp_passthru=" + std::to_string(g_tcp_passthru.load()) +
                 " drop_quic=" + std::to_string(g_drop_quic.load()) +
                 " drop_v6=" + std::to_string(g_drop_ipv6.load()) +
                 " passthru=" + std::to_string(g_passthru.load()) +
                 " rx=" + std::to_string(g_rx.load()) +
                 " tx=" + std::to_string(g_tx.load()));
    }

    if (g_shutdown) g_shutdown(h, 0x3);
    reader.join();
    retx.join();
    {
        std::lock_guard<std::mutex> lock(g_map_mu);
        for (auto& kv : g_flows) close_flow_socket(kv.second);
        g_flows.clear();
    }
    g_close(h);
    internet_router::stop();
    net_cleanup();
    log_line("[*] Internet stopped");
    return 0;
}
