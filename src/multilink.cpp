#include "config.hpp"
#include "net.hpp"
#include "protocol.hpp"
#include "rules.hpp"

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

#ifdef _WIN32
#  include <iphlpapi.h>
#endif

#ifdef __linux__
#  include <linux/netfilter_ipv4.h>
#  include <netinet/in.h>
#  ifndef IP6T_SO_ORIGINAL_DST
#    define IP6T_SO_ORIGINAL_DST 80
#  endif
#  ifndef IPV6_TRANSPARENT
#    define IPV6_TRANSPARENT 75
#  endif
#endif

namespace {

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
// matches DOMAIN / GEOSITE rules (SOCKS DNS-over-TCP + sticky UDP DNS).
std::mutex g_name_mu;
std::unordered_map<uint32_t, std::pair<std::string, std::chrono::steady_clock::time_point>> g_ip_name;
std::unordered_map<std::string, std::pair<std::string, std::chrono::steady_clock::time_point>> g_ip6_name;

void remember_ip_name(uint32_t ip_host, const std::string& name) {
    if (name.empty()) return;
    std::lock_guard<std::mutex> lock(g_name_mu);
    g_ip_name[ip_host] = {name, std::chrono::steady_clock::now()};
}

void remember_ip6_name(const std::string& ip6, const std::string& name) {
    if (name.empty() || ip6.empty()) return;
    std::lock_guard<std::mutex> lock(g_name_mu);
    g_ip6_name[ip6] = {name, std::chrono::steady_clock::now()};
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

std::string cached_name6(const std::string& ip6) {
    if (ip6.empty()) return {};
    std::lock_guard<std::mutex> lock(g_name_mu);
    auto it = g_ip6_name.find(ip6);
    if (it == g_ip6_name.end()) return {};
    if (std::chrono::steady_clock::now() - it->second.second > std::chrono::minutes(10)) {
        g_ip6_name.erase(it);
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

uint16_t dns_qtype(const uint8_t* msg, size_t len) {
    if (len < 12) return 0;
    size_t off = dns_skip_name(msg, len, 12);
    if (off + 4 > len) return 0;
    return static_cast<uint16_t>((msg[off] << 8) | msg[off + 1]);
}

const char* dns_qtype_name(uint16_t qtype) {
    if (qtype == 1) return "A";
    if (qtype == 28) return "AAAA";
    return "OTHER";
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
        // Learn A/AAAA so redirect TCP by real IP can still DOMAIN CONNECT.
        if (typ == 1 && rdlen == 4) {
            uint32_t net = 0;
            std::memcpy(&net, msg + off, 4);
            remember_ip_name(ntohl(net), qname);
        } else if (typ == 28 && rdlen == 16) {
            char buf[INET6_ADDRSTRLEN] = {};
            if (inet_ntop(AF_INET6, msg + off, buf, sizeof(buf))) {
                remember_ip6_name(buf, qname);
            }
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
        if (ip.empty() || ip == "127.0.0.1") continue;
        // Accept IPv4 or IPv6 resolvers; skip IPv4-mapped oddities.
        return ip;
    }
#endif
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
    std::vector<uint8_t> buf(static_cast<size_t>(s->link.max_payload));
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

// Rebuild Vortex CONNECT as ATYP_DOMAIN so the remote server resolves
// (local / cached A records are often GFW-poisoned).
void prefer_remote_dns_wire(SocksTarget& t, const std::string& domain) {
    if (domain.empty() || domain.size() > 255) return;
    if (host_is_ipv4_literal(domain) || host_is_ipv6_literal(domain)) return;
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

void log_uplink_connect(const LinkEndpoint& link, const ConnectHostsDetail& detail, bool ok) {
    if (!ok) {
        log_line("[-] uplink TCP failed " + link.name + " " +
                 format_hosts_port(link.uplink_hosts(), link.server_port));
        return;
    }
    // Distinguish IPv6-prefer hit vs IPv6-dead→IPv4 fallback.
    if (!detail.failed_hosts.empty()) {
        std::string failed;
        for (size_t i = 0; i < detail.failed_hosts.size(); ++i) {
            if (i) failed += ",";
            failed += detail.failed_hosts[i];
            failed += "(";
            failed += host_family_tag(detail.failed_hosts[i]);
            failed += ")";
        }
        log_line("[*] uplink fallback " + link.name + " failed=[" + failed + "] ok=" +
                 format_host_port(detail.used_host, link.server_port) + "(" +
                 host_family_tag(detail.used_host) + ")");
    } else if (link.uplink_hosts().size() > 1) {
        log_line("[+] uplink " + link.name + " " +
                 format_host_port(detail.used_host, link.server_port) + "(" +
                 host_family_tag(detail.used_host) + ")");
    }
}

bool open_proxy(std::shared_ptr<Session> s, const SocksTarget& t) {
    ConnectHostsDetail detail;
    socket_t remote_fd = tcp_connect_hosts(s->link.uplink_hosts(), s->link.server_port,
                                           s->idle_timeout_sec, &detail);
    if (remote_fd == INVALID_SOCK) {
        log_uplink_connect(s->link, detail, false);
        return false;
    }
    log_uplink_connect(s->link, detail, true);
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

// Forward DNS query as-is (A or AAAA) via UDP to system / configured resolver.
bool dns_query_udp(const std::string& dns, const uint8_t* query, size_t qlen,
                   std::vector<uint8_t>& answer) {
    const std::string bare = strip_ip_brackets(dns);
    const bool v6 = host_is_ipv6_literal(bare);
    socket_t fd = ::socket(v6 ? AF_INET6 : AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == INVALID_SOCK) return false;
#ifdef _WIN32
    DWORD ms = 3000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&ms), sizeof(ms));
#else
    timeval tv{};
    tv.tv_sec = 3;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
#endif
    if (v6) {
        sockaddr_in6 dst{};
        dst.sin6_family = AF_INET6;
        dst.sin6_port = htons(53);
        if (inet_pton(AF_INET6, bare.c_str(), &dst.sin6_addr) != 1) {
            net_close(fd);
            return false;
        }
        if (sendto(fd, reinterpret_cast<const char*>(query), static_cast<int>(qlen), 0,
                   reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) < 0) {
            net_close(fd);
            return false;
        }
    } else {
        sockaddr_in dst{};
        dst.sin_family = AF_INET;
        dst.sin_port = htons(53);
        if (inet_pton(AF_INET, bare.c_str(), &dst.sin_addr) != 1) {
            net_close(fd);
            return false;
        }
        if (sendto(fd, reinterpret_cast<const char*>(query), static_cast<int>(qlen), 0,
                   reinterpret_cast<sockaddr*>(&dst), sizeof(dst)) < 0) {
            net_close(fd);
            return false;
        }
    }
    answer.resize(2048);
    const int n = recvfrom(fd, reinterpret_cast<char*>(answer.data()),
                           static_cast<int>(answer.size()), 0, nullptr, nullptr);
    net_close(fd);
    if (n <= 0) return false;
    answer.resize(static_cast<size_t>(n));
    return true;
}

bool dns_query_direct(const uint8_t* query, size_t qlen, std::vector<uint8_t>& answer) {
    return dns_query_udp(system_dns_server(), query, qlen, answer);
}

// DNS-over-TCP to a specific resolver (honors client SOCKS target; keeps A/AAAA).
bool dns_query_tcp_resolver(const std::string& host, uint16_t port, const uint8_t* query,
                            size_t qlen, std::vector<uint8_t>& answer) {
    return dns_tcp_transact_raw(strip_ip_brackets(host), static_cast<int>(port ? port : 53),
                                query, qlen, answer, 3);
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
    const uint16_t qtype = dns_qtype(query.data(), query.size());
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
                 (name.empty() ? target.host : name) + " " + dns_qtype_name(qtype) +
                 "  (" + decision.matched + ")");
    }

    std::vector<uint8_t> framed;
    framed.push_back(lenb[0]);
    framed.push_back(lenb[1]);
    framed.insert(framed.end(), query.begin(), query.end());

    std::vector<uint8_t> out;
    bool ok = false;
    if (decision.action == rules::Action::Direct) {
        std::vector<uint8_t> answer;
        // Prefer the SOCKS-target resolver when it is a literal so A/AAAA both
        // reach the client's chosen DNS (browser DoT-TCP style). Else system DNS.
        if (host_is_ipv4_literal(target.host) || host_is_ipv6_literal(target.host)) {
            ok = dns_query_tcp_resolver(target.host, target.port, query.data(), query.size(),
                                        answer);
        }
        if (!ok) ok = dns_query_direct(query.data(), query.size(), answer);
        if (ok) {
            out.push_back(static_cast<uint8_t>(answer.size() >> 8));
            out.push_back(static_cast<uint8_t>(answer.size()));
            out.insert(out.end(), answer.begin(), answer.end());
            remember_dns_answers(answer.data(), answer.size(), name);
        }
    } else {
        // PROXY: tunnel DNS-over-TCP to the SOCKS target; query type (A/AAAA) preserved.
        ok = dns_query_proxy(s, target, framed.data(), framed.size(), out);
        if (ok && out.size() > 2) remember_dns_answers(out.data() + 2, out.size() - 2, name);
    }
    if (!ok || out.size() < 2) return;
    send_all(s->local_fd, out.data(), out.size());
}

bool open_direct(std::shared_ptr<Session> s, const SocksTarget& t) {
    // DNS-over-TCP: bypass activate_net's UDP/53 fake-IP hijack.
    socket_t remote_fd =
        tcp_connect_direct_host(t.host, static_cast<int>(t.port), s->idle_timeout_sec);
    if (remote_fd == INVALID_SOCK) return false;
    s->remote_fd = remote_fd;
    s->via_proxy = false;
    return true;
}

SocksTarget make_target_ipv4(uint32_t ip_net, uint16_t port) {
    SocksTarget t;
    t.atyp = vortex::ATYP_IPV4;
    t.port = port;
    t.has_ipv4 = true;
    t.ipv4_host = ntohl(ip_net);
    char buf[INET_ADDRSTRLEN] = {};
    in_addr a{};
    a.s_addr = ip_net;
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    t.host = buf;
    t.wire.clear();
    t.wire.push_back(vortex::ATYP_IPV4);
    const uint8_t* raw = reinterpret_cast<const uint8_t*>(&ip_net);
    t.wire.insert(t.wire.end(), raw, raw + 4);
    t.wire.push_back(static_cast<uint8_t>(port >> 8));
    t.wire.push_back(static_cast<uint8_t>(port & 0xFF));
    return t;
}

SocksTarget make_target_ipv6(const in6_addr& addr, uint16_t port) {
    SocksTarget t;
    t.atyp = vortex::ATYP_IPV6;
    t.port = port;
    char buf[INET6_ADDRSTRLEN] = {};
    inet_ntop(AF_INET6, &addr, buf, sizeof(buf));
    t.host = buf;
    t.wire.clear();
    t.wire.push_back(vortex::ATYP_IPV6);
    const uint8_t* raw = reinterpret_cast<const uint8_t*>(&addr);
    t.wire.insert(t.wire.end(), raw, raw + 16);
    t.wire.push_back(static_cast<uint8_t>(port >> 8));
    t.wire.push_back(static_cast<uint8_t>(port & 0xFF));
    return t;
}

bool read_redirect_target(socket_t local_fd, bool is_v6, SocksTarget& out) {
#ifdef __linux__
    if (is_v6) {
        sockaddr_in6 orig6{};
        socklen_t olen = sizeof(orig6);
        if (getsockopt(local_fd, SOL_IPV6, IP6T_SO_ORIGINAL_DST, &orig6, &olen) != 0) {
            return false;
        }
        out = make_target_ipv6(orig6.sin6_addr, ntohs(orig6.sin6_port));
        return true;
    }
    sockaddr_in orig{};
    socklen_t olen = sizeof(orig);
    if (getsockopt(local_fd, SOL_IP, SO_ORIGINAL_DST, &orig, &olen) != 0) {
        return false;
    }
    out = make_target_ipv4(orig.sin_addr.s_addr, ntohs(orig.sin_port));
    return true;
#else
    (void)local_fd;
    (void)is_v6;
    (void)out;
    return false;
#endif
}

void serve_stream_target(socket_t local_fd, MultilinkConfig cfg, SocksTarget target,
                         bool socks_reply) {
    auto s = std::make_shared<Session>();
    s->local_fd = local_fd;
    s->idle_timeout_sec = 300;
    if (!cfg.links.empty()) {
        s->idle_timeout_sec = cfg.links.begin()->second.idle_timeout_sec;
    }
    set_socket_options(local_fd, s->idle_timeout_sec);

    // Prefer a learned domain over a (possibly poisoned) literal IP for rules.
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
    } else if (target.atyp == vortex::ATYP_IPV6) {
        const std::string learned = cached_name6(target.host);
        if (!learned.empty()) rule_host = learned;
    }
    const auto decision = g_rules.decide(rule_host, has_ip, ip_host, /*allow_dns_resolve=*/false);

    LinkEndpoint link;
    std::string link_err;
    if (!select_link(cfg, decision, link, link_err)) {
        if (cfg.log_decisions) {
            log_line(std::string("[-] ") + link_err + " for " +
                     format_host_port(target.host, target.port));
        }
        if (socks_reply) reply_socks_fail(local_fd, 0x01);
        return;
    }
    s->link = link;
    if (!link.name.empty()) s->idle_timeout_sec = link.idle_timeout_sec;

    if (cfg.log_decisions) {
        log_line(std::string(socks_reply ? "[*] " : "[*] REDIR ") +
                 rules::decision_name(decision) + " " +
                 format_host_port(rule_host, target.port) +
                 "  (" + decision.matched + ")" +
                 (link.name.empty()
                      ? ""
                      : " via " + link.name + " " +
                            format_hosts_port(link.uplink_hosts(), link.server_port) +
                            (link.peer_secret.empty() ? "" : " (peer)")));
    }

    bool ok = false;
    if (decision.action == rules::Action::Direct) {
        ok = open_direct(s, target);
        if (!ok) {
            if (socks_reply) reply_socks_fail(local_fd, 0x05);
            return;
        }
    } else {
        // Non-DIRECT: always ask remote to resolve when we have a domain name.
        SocksTarget connect_tgt = target;
        if (!host_is_ipv4_literal(rule_host) && !host_is_ipv6_literal(rule_host)) {
            prefer_remote_dns_wire(connect_tgt, rule_host);
        }
        ok = open_proxy(s, connect_tgt);
        if (!ok) {
            if (socks_reply) reply_socks_fail(local_fd, 0x01);
            return;
        }
    }

    if (socks_reply && !reply_socks_ok(local_fd)) return;

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

void handle_socks5(socket_t local_fd, MultilinkConfig cfg) {
    int idle = 300;
    if (!cfg.links.empty()) idle = cfg.links.begin()->second.idle_timeout_sec;
    set_socket_options(local_fd, idle);

    SocksTarget target;
    if (!socks5_read_target(local_fd, target)) return;

    // Hotspot DNS arrives as TCP/53 to 1.1.1.1. Route by the queried name,
    // not by the resolver address.
    if (target.port == 53) {
        auto s = std::make_shared<Session>();
        s->local_fd = local_fd;
        s->idle_timeout_sec = idle;
        handle_dns(s, target, cfg);
        return;
    }

    serve_stream_target(local_fd, std::move(cfg), std::move(target), /*socks_reply=*/true);
}

void handle_redirect(socket_t local_fd, MultilinkConfig cfg, bool is_v6) {
    SocksTarget target;
    if (!read_redirect_target(local_fd, is_v6, target)) {
        net_close(local_fd);
        return;
    }
    serve_stream_target(local_fd, std::move(cfg), std::move(target), /*socks_reply=*/false);
}

// Sticky UDP DNS (linux_gate dns_redirect_*): real A/AAAA + learn IP→name for redirect.
bool resolve_sticky_dns(const MultilinkConfig& cfg, const uint8_t* query, size_t qlen,
                        std::vector<uint8_t>& answer) {
    answer.clear();
    if (qlen < 12 || qlen > 4096) return false;
    const std::string name = dns_qname(query, qlen);
    const uint16_t qtype = dns_qtype(query, qlen);
    const auto decision =
        g_rules.decide(name.empty() ? "?" : name, false, 0, /*allow_dns_resolve=*/false);

    LinkEndpoint link;
    std::string link_err;
    if (!select_link(cfg, decision, link, link_err)) {
        if (cfg.log_decisions) {
            log_line(std::string("[-] sticky DNS ") + link_err + " for " +
                     (name.empty() ? "?" : name));
        }
        return false;
    }

    if (cfg.log_decisions) {
        log_line(std::string("[*] sticky DNS ") + rules::decision_name(decision) + " " +
                 (name.empty() ? "?" : name) + " " + dns_qtype_name(qtype) +
                 "  (" + decision.matched + ")" +
                 (link.name.empty() ? "" : " via " + link.name));
    }

    if (decision.action == rules::Action::Direct) {
        if (!dns_query_direct(query, qlen, answer)) return false;
        remember_dns_answers(answer.data(), answer.size(), name);
        return true;
    }

    auto s = std::make_shared<Session>();
    s->link = link;
    s->idle_timeout_sec = link.idle_timeout_sec > 0 ? link.idle_timeout_sec : 300;
    // PROXY: DNS-over-TCP to 8.8.8.8 via Vortex (same path as SOCKS :53).
    SocksTarget t = make_target_ipv4(htonl(0x08080808u), 53);
    std::vector<uint8_t> framed;
    framed.push_back(static_cast<uint8_t>((qlen >> 8) & 0xFF));
    framed.push_back(static_cast<uint8_t>(qlen & 0xFF));
    framed.insert(framed.end(), query, query + qlen);
    std::vector<uint8_t> out;
    if (!dns_query_proxy(s, t, framed.data(), framed.size(), out) || out.size() < 2) {
        return false;
    }
    answer.assign(out.begin() + 2, out.end());
    remember_dns_answers(answer.data(), answer.size(), name);
    return true;
}

void sticky_dns_loop(socket_t dns_fd, MultilinkConfig cfg) {
    uint8_t buf[2048];
    while (g_running) {
        sockaddr_storage peer{};
        socklen_t plen = sizeof(peer);
        const int n = static_cast<int>(
            recvfrom(dns_fd, reinterpret_cast<char*>(buf), sizeof(buf), 0,
                     reinterpret_cast<sockaddr*>(&peer), &plen));
        if (n < 0) {
            if (!g_running) break;
            continue;
        }
        if (n < 12) continue;
        std::vector<uint8_t> query(buf, buf + n);
        std::thread([dns_fd, cfg, query, peer, plen]() {
            std::vector<uint8_t> answer;
            if (!resolve_sticky_dns(cfg, query.data(), query.size(), answer) || answer.empty()) {
                return;
            }
            sendto(dns_fd, reinterpret_cast<const char*>(answer.data()),
                   static_cast<int>(answer.size()), 0,
                   reinterpret_cast<const sockaddr*>(&peer), plen);
        }).detach();
    }
}

bool listen_is_ipv6(socket_t fd) {
    sockaddr_storage ss{};
    socklen_t len = sizeof(ss);
    if (getsockname(fd, reinterpret_cast<sockaddr*>(&ss), &len) != 0) return false;
    return ss.ss_family == AF_INET6;
}

} // namespace

int main(int argc, char* argv[]) {
    std::string config_path = "config/multilink.json";
    if (argc >= 2) config_path = argv[1];

    if (!net_init()) {
        std::cerr << "[-] Network subsystem init failed\n";
        return 1;
    }

    MultilinkConfig cfg;
    try {
        cfg = MultilinkConfig::load(config_path);
        g_rules.load(cfg.rules_path, cfg.geoip_cn, cfg.geosite_cn, cfg.geoipv6_cn);
    } catch (const std::exception& e) {
        std::cerr << "[-] " << e.what() << "\n";
        net_cleanup();
        return 1;
    }

#ifndef _WIN32
    std::signal(SIGPIPE, SIG_IGN);
#endif
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    // 多地址绑定：支持 IPv4 / IPv6 字面量与 "::"/"*" 通配；与 server / linux_network
    // 一致，多绑定时若同时有 IPv4 companion，通配 "::" 使用 V6ONLY=1。
    const auto& bind_ips = cfg.socks5_bind_ips.empty()
        ? std::vector<std::string>{cfg.socks5_bind_ip}
        : cfg.socks5_bind_ips;
    bool has_v4_companion = false;
    for (const auto& h : bind_ips) {
        if (h == "0.0.0.0" || host_is_ipv4_literal(h)) {
            has_v4_companion = true;
            break;
        }
    }
    const bool multi = bind_ips.size() > 1;

    std::vector<socket_t> listen_fds;
    for (const auto& bind_ip : bind_ips) {
        const bool is_wild = bind_ip.empty() || bind_ip == "*" || bind_ip == "::";
        const bool prefer_dual = is_wild && !(multi && has_v4_companion);
        socket_t listen_fd = create_listen_socket(
            bind_ip, cfg.socks5_bind_port, cfg.listen_backlog, prefer_dual);
        if (listen_fd == INVALID_SOCK) {
            std::cerr << "[-] Failed to bind SOCKS5 "
                      << format_host_port(bind_ip, cfg.socks5_bind_port) << "\n";
            continue;
        }
        listen_fds.push_back(listen_fd);
        std::cout << "[*] MultiLink SOCKS5 on "
                  << format_host_port(bind_ip, cfg.socks5_bind_port);
        if (prefer_dual) std::cout << " (dual-stack IPv4+IPv6)";
        else if (is_wild && !prefer_dual) std::cout << " (IPv6-only; companion IPv4 bind)";
        std::cout << std::endl;
    }

    if (listen_fds.empty()) {
        std::cerr << "[-] Failed to bind any SOCKS5 address\n";
        net_cleanup();
        return 1;
    }

    // redirect_port：绑定 redirect_bind_ip（缺省回退 socks5_bind_ip）。
    std::vector<socket_t> redirect_fds;
    std::vector<bool> redirect_is_v6;
    if (cfg.redirect_port > 0 && cfg.redirect_port != cfg.socks5_bind_port) {
        const auto redir_ips = cfg.redirect_listen_ips();
        bool redir_has_v4 = false;
        for (const auto& h : redir_ips) {
            if (h == "0.0.0.0" || host_is_ipv4_literal(h)) {
                redir_has_v4 = true;
                break;
            }
        }
        const bool redir_multi = redir_ips.size() > 1;
        for (const auto& bind_ip : redir_ips) {
            const bool is_wild = bind_ip.empty() || bind_ip == "*" || bind_ip == "::";
            const bool prefer_dual = is_wild && !(redir_multi && redir_has_v4);
            socket_t fd = create_listen_socket(
                bind_ip, cfg.redirect_port, cfg.listen_backlog, prefer_dual);
            if (fd == INVALID_SOCK) {
                std::cerr << "[-] Failed to bind redirect "
                          << format_host_port(bind_ip, cfg.redirect_port) << "\n";
                continue;
            }
            redirect_fds.push_back(fd);
            redirect_is_v6.push_back(listen_is_ipv6(fd));
            std::cout << "[*] MultiLink redirect on "
                      << format_host_port(bind_ip, cfg.redirect_port);
            if (prefer_dual) std::cout << " (dual-stack IPv4+IPv6)";
            else if (is_wild && !prefer_dual) std::cout << " (IPv6-only; companion IPv4 bind)";
            std::cout << std::endl;
        }
        if (redirect_fds.empty()) {
            std::cerr << "[-] Failed to bind any redirect_port address\n";
        }
    } else if (cfg.redirect_port == cfg.socks5_bind_port) {
        std::cerr << "[-] redirect_port equals socks5_bind_port (" << cfg.redirect_port
                  << "); skip redirect listeners\n";
    }

    // Sticky DNS UDP：供 linux_gate DNAT UDP/53 → dns_redirect_host_v4:port。
    socket_t sticky_dns_fd = INVALID_SOCK;
    if (cfg.dns_redirect_port > 0) {
        sticky_dns_fd =
            create_udp_listen_socket(cfg.dns_redirect_host_v4, cfg.dns_redirect_port);
        if (sticky_dns_fd == INVALID_SOCK) {
            std::cerr << "[-] Failed to bind sticky DNS "
                      << format_host_port(cfg.dns_redirect_host_v4, cfg.dns_redirect_port)
                      << "\n";
        } else {
            std::cout << "[*] MultiLink sticky DNS on "
                      << format_host_port(cfg.dns_redirect_host_v4, cfg.dns_redirect_port)
                      << " (UDP; learn A/AAAA for redirect DOMAIN CONNECT)" << std::endl;
        }
    }

    for (const auto& kv : cfg.links) {
        const auto& L = kv.second;
        std::cout << "[*] Link " << L.name << " -> "
                  << format_hosts_port(L.uplink_hosts(), L.server_port)
                  << "  padding=[" << L.padding_min << "," << L.padding_max << "]"
                  << (L.peer_secret.empty() ? "" : "  peer-relay")
                  << std::endl;
    }
    std::cout << "[*] Default link " << cfg.default_link << std::endl;
    std::cout << "[*] Rules " << cfg.rules_path
              << " (" << g_rules.rule_count() << " entries)"
              << "  GEOIP-CN=" << g_rules.cn_cidr_count()
              << "  GEOIP-CN6=" << g_rules.cn_cidr6_count()
              << "  GEOSITE-CN=" << g_rules.cn_domain_count()
              << std::endl;
    std::cout.flush();

    std::vector<std::thread> accept_threads;
    for (socket_t listen_fd : listen_fds) {
        accept_threads.emplace_back([listen_fd, cfg]() {
            while (g_running) {
                socket_t local_fd = accept_any(listen_fd);
                if (local_fd == INVALID_SOCK) {
                    if (!g_running) break;
                    continue;
                }
                std::thread(handle_socks5, local_fd, cfg).detach();
            }
        });
    }
    for (size_t i = 0; i < redirect_fds.size(); ++i) {
        const socket_t listen_fd = redirect_fds[i];
        const bool is_v6 = redirect_is_v6[i];
        accept_threads.emplace_back([listen_fd, cfg, is_v6]() {
            while (g_running) {
                socket_t local_fd = accept_any(listen_fd);
                if (local_fd == INVALID_SOCK) {
                    if (!g_running) break;
                    continue;
                }
                std::thread(handle_redirect, local_fd, cfg, is_v6).detach();
            }
        });
    }
    if (sticky_dns_fd != INVALID_SOCK) {
        accept_threads.emplace_back(sticky_dns_loop, sticky_dns_fd, cfg);
    }

    // 主线程等待退出信号
    while (g_running) {
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    // 清理监听套接字
    for (socket_t listen_fd : listen_fds) {
        net_close(listen_fd);
    }
    for (socket_t listen_fd : redirect_fds) {
        net_close(listen_fd);
    }
    if (sticky_dns_fd != INVALID_SOCK) {
        net_close(sticky_dns_fd);
    }

    // 等待所有 accept 线程退出
    for (auto& t : accept_threads) {
        if (t.joinable()) t.join();
    }

    net_cleanup();
    std::cout << "[*] MultiLink stopped\n";
    return 0;
}