#!/usr/bin/env python3
"""Generate src/internet.cpp from enable_net.cpp + smartlink.cpp."""
import re
import pathlib

root = pathlib.Path(__file__).resolve().parents[1]
en = (root / "src/enable_net.cpp").read_text(encoding="utf-8")
sm = (root / "src/smartlink.cpp").read_text(encoding="utf-8")

sm = re.sub(
    r'^#include "config.hpp"\n#include "net.hpp"\n#include "protocol.hpp"\n#include "rules.hpp"\n\n',
    "",
    sm,
    count=1,
)
sm = re.sub(r"#ifdef _WIN32\n#  include <iphlpapi.h>\n#endif\n\n", "", sm, count=1)
sm = re.sub(
    r"\n} // namespace\n\nint main\(int argc, char\* argv\[\]\) \{.*\n\}\n?\Z",
    "\n} // namespace router_detail\n",
    sm,
    count=1,
    flags=re.S,
)
sm = sm.replace(
    "namespace {\n\nstd::atomic<bool> g_running{true};",
    "namespace router_detail {\n\nstd::atomic<bool> g_running{true};",
    1,
)

sm = sm.replace(
    """bool open_proxy(std::shared_ptr<Session> s, const SocksTarget& t) {
    socket_t remote_fd = tcp_connect(s->cfg.server_ip, s->cfg.server_port, s->cfg.idle_timeout_sec);
    if (remote_fd == INVALID_SOCK) return false;
    s->remote_fd = remote_fd;
    s->via_proxy = true;""",
    """bool open_proxy(std::shared_ptr<Session> s, const SocksTarget& t) {
    socket_t remote_fd = tcp_connect(s->cfg.server_ip, s->cfg.server_port, s->cfg.idle_timeout_sec);
    if (remote_fd == INVALID_SOCK) return false;
    internet_self::register_socket(remote_fd);
    s->remote_fd = remote_fd;
    s->via_proxy = true;""",
)

sm = sm.replace(
    """bool open_direct(std::shared_ptr<Session> s, const SocksTarget& t) {
    // DNS-over-TCP: bypass activate_net's UDP/53 fake-IP hijack.
    socket_t remote_fd =
        tcp_connect_direct_host(t.host, static_cast<int>(t.port), s->cfg.idle_timeout_sec);
    if (remote_fd == INVALID_SOCK) return false;
    s->remote_fd = remote_fd;
    s->via_proxy = false;
    return true;
}""",
    """bool open_direct(std::shared_ptr<Session> s, const SocksTarget& t) {
    socket_t remote_fd =
        tcp_connect_direct_host(t.host, static_cast<int>(t.port), s->cfg.idle_timeout_sec);
    if (remote_fd == INVALID_SOCK) return false;
    internet_self::register_socket(remote_fd);
    s->remote_fd = remote_fd;
    s->via_proxy = false;
    return true;
}""",
)

sm = sm.replace(
    """bool dns_query_direct(const uint8_t* query, size_t qlen, std::vector<uint8_t>& answer) {
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
}""",
    """bool dns_query_direct(const uint8_t* query, size_t qlen, std::vector<uint8_t>& answer) {
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
}""",
)

sm = sm.replace(
    """    ~Session() {
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
    }""",
    """    ~Session() {
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
    }""",
)

export_fn = r"""
namespace internet_router {
SmartlinkConfig g_cfg;
socket_t g_listen = INVALID_SOCK;

bool start(const SmartlinkConfig& cfg) {
    g_cfg = cfg;
    try {
        router_detail::g_rules.load(cfg.rules_path, cfg.geoip_cn, cfg.geosite_cn);
    } catch (const std::exception& e) {
        std::cerr << "[-] rules: " << e.what() << "\n";
        return false;
    }
    g_listen = create_listen_socket("127.0.0.1", cfg.socks5_bind_port, cfg.listen_backlog);
    if (g_listen == INVALID_SOCK) {
        std::cerr << "[-] Internet router bind 127.0.0.1:" << cfg.socks5_bind_port << " failed\n";
        return false;
    }
    in_addr up{};
    if (inet_pton(AF_INET, cfg.server_ip.c_str(), &up) == 1) {
        internet_self::set_uplink_ipv4(up.s_addr);
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
    std::cout << "[*] Internet router (SmartLink) SOCKS5 127.0.0.1:" << cfg.socks5_bind_port
              << " upstream " << cfg.server_ip << ":" << cfg.server_port
              << " rules=" << cfg.rules_path << " (" << router_detail::g_rules.rule_count() << ")"
              << std::endl;
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
"""

en = en.replace(
    """std::mutex g_own_mu;
std::unordered_set<uint16_t> g_own_sports;

void register_own_port(uint16_t sport) {
    if (!sport) return;
    std::lock_guard<std::mutex> lock(g_own_mu);
    g_own_sports.insert(sport);
}
void unregister_own_port(uint16_t sport) {
    if (!sport) return;
    std::lock_guard<std::mutex> lock(g_own_mu);
    g_own_sports.erase(sport);
}
void register_own_socket(SOCKET s) {
    sockaddr_in a{};
    int alen = sizeof(a);
    if (getsockname(s, reinterpret_cast<sockaddr*>(&a), &alen) != 0) return;
    register_own_port(ntohs(a.sin_port));
}
void unregister_own_socket(SOCKET s) {
    sockaddr_in a{};
    int alen = sizeof(a);
    if (getsockname(s, reinterpret_cast<sockaddr*>(&a), &alen) != 0) return;
    unregister_own_port(ntohs(a.sin_port));
}
bool is_own_sport(uint16_t sport) {
    std::lock_guard<std::mutex> lock(g_own_mu);
    return g_own_sports.count(sport) != 0;
}
""",
    """void register_own_port(uint16_t sport) { internet_self::register_port(sport); }
void unregister_own_port(uint16_t sport) { internet_self::unregister_port(sport); }
void register_own_socket(SOCKET s) { internet_self::register_socket(s); }
void unregister_own_socket(SOCKET s) { internet_self::unregister_socket(s); }
bool is_own_sport(uint16_t sport) { return internet_self::is_own_sport(sport); }
""",
)

en = en.replace(
    """    if (is_own_sport(v.sport)) {
        reinject(divert, addr, packet, len);
        ++g_passthru;
        return;
    }
""",
    """    if (is_own_sport(v.sport) || internet_self::is_uplink_ipv4(v.dst_net) ||
        internet_self::is_uplink_ipv4(v.src_net)) {
        reinject(divert, addr, packet, len);
        ++g_passthru;
        return;
    }
""",
)

new_main = r'''
int main(int argc, char** argv) {
    std::string config_path = "config/internet.json";
    if (argc >= 2) config_path = argv[1];

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

    g_cfg.socks5_host = "127.0.0.1";
    g_cfg.socks5_port = icfg.socks5_bind_port;
    g_cfg.mss = icfg.mss;
    g_cfg.idle_timeout_sec = icfg.divert_idle_timeout_sec;
    g_cfg.max_connections = icfg.max_connections;
    g_cfg.max_dns_inflight = icfg.max_dns_inflight;
    g_cfg.log_connections = icfg.log_connections;

    SmartlinkConfig scfg;
    scfg.socks5_bind_ip = "127.0.0.1";
    scfg.socks5_bind_port = icfg.socks5_bind_port;
    scfg.server_ip = icfg.server_ip;
    scfg.server_port = icfg.server_port;
    scfg.master_secret = icfg.master_secret;
    scfg.padding_min = icfg.padding_min;
    scfg.padding_max = icfg.padding_max;
    scfg.listen_backlog = icfg.listen_backlog;
    scfg.idle_timeout_sec = icfg.idle_timeout_sec;
    scfg.max_payload = icfg.max_payload;
    scfg.rules_path = icfg.rules_path;
    scfg.geoip_cn = icfg.geoip_cn;
    scfg.geosite_cn = icfg.geosite_cn;
    scfg.log_decisions = icfg.log_decisions;

    if (!internet_router::start(scfg)) {
        net_cleanup();
        return 1;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

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

    log_line("[*] Internet — transparent redir-host + SmartLink (single process)");
    log_line("[*] config " + config_path);
    log_line("[*] router SOCKS 127.0.0.1:" + std::to_string(g_cfg.socks5_port) +
             "  Vortex " + icfg.server_ip + ":" + std::to_string(icfg.server_port));
    log_line("[*] filter: " + filter);
    log_line("[*] self-exclude: router/uplink source ports + Vortex server IP");
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
'''

en = en[: en.find("int main(int argc, char** argv)")] + new_main

self_hdr = r"""
namespace internet_self {
inline std::mutex g_mu;
inline std::unordered_set<uint16_t> g_sports;
inline std::atomic<uint32_t> g_uplink_net{0};

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
inline void set_uplink_ipv4(uint32_t net_order) { g_uplink_net.store(net_order); }
inline bool is_uplink_ipv4(uint32_t net_order) {
    const uint32_t u = g_uplink_net.load();
    return u != 0 && u == net_order;
}
} // namespace internet_self
"""

header = r"""// Internet: SmartLink (rules + Vortex) + EnableNet (redir-host WinDivert) in ONE process.
// Apps need no proxy settings. Requires Administrator + WinDivert 2.2 next to this exe.
// Windows-only.

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

""" + self_hdr + "\n"

idx = en.find("namespace {\n\nconstexpr int WINDIVERT_LAYER_NETWORK")
if idx < 0:
    idx = en.find("namespace {")
en_body = en[idx:]

# Fix log message leftovers
en_body = en_body.replace("EnableNet stopped", "Internet divert stopped")
en_body = en_body.replace(
    "is multilink/smartlink running on",
    "is Internet router SOCKS up on",
)

out = header + sm + "\n" + export_fn + "\n" + en_body
path = root / "src/internet.cpp"
path.write_text(out, encoding="utf-8")
print("wrote", path, "bytes", path.stat().st_size)
