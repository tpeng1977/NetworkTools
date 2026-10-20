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

bool host_is_ipv4_literal(const std::string& host) {
    in_addr a{};
    return inet_pton(AF_INET, host.c_str(), &a) == 1;
}

// Rebuild Vortex CONNECT as ATYP_DOMAIN so the remote server resolves
// (local / cached A records are often GFW-poisoned).
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
    socket_t remote_fd = tcp_connect(s->link.server_ip, s->link.server_port, s->idle_timeout_sec);
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

    if (!vortex::send_frame(remote_fd, s->up, vortex::CMD_CONNECT,
                            t.wire, s->link.padding_min, s->link.padding_max)) {
        log_line("[-] CONNECT send failed via " + s->link.name + " " + t.host + ":" +
                 std::to_string(t.port));
        return false;
    }
    auto reply = vortex::recv_frame(remote_fd, s->down, s->link.max_payload);
    if (!reply.ok || reply.cmd != vortex::CMD_CONNECT_OK) {
        log_line("[-] CONNECT rejected via " + s->link.name + " " + t.host + ":" +
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
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(53);
    if (inet_pton(AF_INET, dns.c_str(), &dst.sin_addr) != 1) {
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
        net_close(fd);
        return false;
    }
    answer.resize(2048);
    const int n = recvfrom(fd, reinterpret_cast<char*>(answer.data()), static_cast<int>(answer.size()), 0, nullptr, nullptr);
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
    // DNS-over-TCP: bypass activate_net's UDP/53 fake-IP hijack.
    socket_t remote_fd =
        tcp_connect_direct_host(t.host, static_cast<int>(t.port), s->idle_timeout_sec);
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

    // Hotspot DNS arrives as TCP/53 to 1.1.1.1. Route by the queried name,
    // not by the resolver address.
    if (target.port == 53) {
        handle_dns(s, target, cfg);
        return;
    }

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
                 (link.name.empty() ? "" : " via " + link.name + " " + link.server_ip));
    }

    bool ok = false;
    if (decision.action == rules::Action::Direct) {
        ok = open_direct(s, target);
        if (!ok) {
            reply_socks_fail(local_fd, 0x05);
            return;
        }
    } else {
        // Non-DIRECT: always ask remote to resolve when we have a domain name.
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
        g_rules.load(cfg.rules_path, cfg.geoip_cn, cfg.geosite_cn);
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

    socket_t listen_fd = create_listen_socket(
        cfg.socks5_bind_ip, cfg.socks5_bind_port, cfg.listen_backlog);
    if (listen_fd == INVALID_SOCK) {
        std::cerr << "[-] Failed to bind SOCKS5 "
                  << cfg.socks5_bind_ip << ":" << cfg.socks5_bind_port << "\n";
        net_cleanup();
        return 1;
    }

    std::cout << "[*] MultiLink SOCKS5 on "
              << cfg.socks5_bind_ip << ":" << cfg.socks5_bind_port << std::endl;
    for (const auto& kv : cfg.links) {
        const auto& L = kv.second;
        std::cout << "[*] Link " << L.name << " -> " << L.server_ip << ":" << L.server_port
                  << "  padding=[" << L.padding_min << "," << L.padding_max << "]"
                  << std::endl;
    }
    std::cout << "[*] Default link " << cfg.default_link << std::endl;
    std::cout << "[*] Rules " << cfg.rules_path
              << " (" << g_rules.rule_count() << " entries)"
              << "  GEOIP-CN=" << g_rules.cn_cidr_count()
              << "  GEOSITE-CN=" << g_rules.cn_domain_count()
              << std::endl;
    std::cout.flush();

    while (g_running) {
        sockaddr_in peer{};
        socklen_type peer_len = sizeof(peer);
        socket_t local_fd = accept(listen_fd, reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (local_fd == INVALID_SOCK) {
            if (!g_running) break;
            continue;
        }
        std::thread(handle_socks5, local_fd, cfg).detach();
    }

    net_close(listen_fd);
    net_cleanup();
    std::cout << "[*] MultiLink stopped\n";
    return 0;
}
