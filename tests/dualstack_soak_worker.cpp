// Dual-stack soak worker: mixes short SOCKS CONNECTs over IPv4/IPv6 socks + targets.
#include "net.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

static std::atomic<uint64_t> g_ok{0}, g_fail{0}, g_stop{0};

static bool socks5_http(const std::string& socks_host, int socks_port,
                        const std::string& target_host, int target_port) {
    socket_t fd = tcp_connect(socks_host, socks_port, 5);
    if (fd == INVALID_SOCK) return false;
    set_socket_options(fd, 5);

    const uint8_t greet[] = {0x05, 0x01, 0x00};
    if (!send_all(fd, greet, sizeof(greet))) {
        net_close(fd);
        return false;
    }
    uint8_t method[2];
    if (!recv_exact(fd, method, 2) || method[0] != 0x05 || method[1] != 0x00) {
        net_close(fd);
        return false;
    }

    std::vector<uint8_t> req{0x05, 0x01, 0x00};
    const std::string h = strip_ip_brackets(target_host);
    in_addr v4{};
    in6_addr v6{};
    if (inet_pton(AF_INET, h.c_str(), &v4) == 1) {
        req.push_back(0x01);
        uint8_t ip[4];
        std::memcpy(ip, &v4.s_addr, 4);
        req.insert(req.end(), ip, ip + 4);
    } else if (inet_pton(AF_INET6, h.c_str(), &v6) == 1) {
        req.push_back(0x04);
        uint8_t ip[16];
        std::memcpy(ip, &v6, 16);
        req.insert(req.end(), ip, ip + 16);
    } else {
        net_close(fd);
        return false;
    }
    req.push_back(static_cast<uint8_t>((target_port >> 8) & 0xFF));
    req.push_back(static_cast<uint8_t>(target_port & 0xFF));
    if (!send_all(fd, req.data(), req.size())) {
        net_close(fd);
        return false;
    }
    uint8_t rh[4];
    if (!recv_exact(fd, rh, 4) || rh[0] != 0x05 || rh[1] != 0x00) {
        net_close(fd);
        return false;
    }
    size_t rest = (rh[3] == 0x04) ? 18 : (rh[3] == 0x01 ? 6 : 0);
    if (rest == 0) {
        net_close(fd);
        return false;
    }
    std::vector<uint8_t> skip(rest);
    if (!recv_exact(fd, skip.data(), skip.size())) {
        net_close(fd);
        return false;
    }

    const char* http = "GET / HTTP/1.0\r\nHost: x\r\n\r\n";
    if (!send_all(fd, reinterpret_cast<const uint8_t*>(http), std::strlen(http))) {
        net_close(fd);
        return false;
    }
    // Long-ish transfer: keep reading briefly.
    char buf[2048];
    std::string body;
    for (int i = 0; i < 8; ++i) {
        int n = recv_some(fd, reinterpret_cast<uint8_t*>(buf), sizeof(buf));
        if (n <= 0) break;
        body.append(buf, static_cast<size_t>(n));
        if (body.find("VORTEX_ECHO_OK") != std::string::npos) break;
    }
    net_close(fd);
    return body.find("VORTEX_ECHO_OK") != std::string::npos;
}

static void worker_loop(int id) {
    const struct {
        const char* socks;
        int sport;
        const char* tgt;
        int tport;
    } cases[] = {
        {"127.0.0.1", 21080, "127.0.0.1", 29080},
        {"127.0.0.1", 21080, "::1", 29080},
        {"::1", 21080, "127.0.0.1", 29080},
        {"::1", 21080, "::1", 29080},
        {"127.0.0.1", 21090, "127.0.0.1", 29080},
        {"::1", 21090, "::1", 29080},
        {"::1", 21091, "::1", 29080},
        {"::1", 21091, "127.0.0.1", 29080},
    };
    size_t i = static_cast<size_t>(id);
    while (!g_stop.load()) {
        const auto& c = cases[i % (sizeof(cases) / sizeof(cases[0]))];
        ++i;
        if (socks5_http(c.socks, c.sport, c.tgt, c.tport)) {
            ++g_ok;
        } else {
            ++g_fail;
            // Rate-limit failure spam so a dead echo cannot fill disks in seconds.
            static thread_local uint64_t local_fail = 0;
            if ((++local_fail % 64) == 1) {
                std::cerr << "fail socks=" << c.socks << ":" << c.sport << " tgt=" << c.tgt
                          << ":" << c.tport << "\n";
            }
            if (g_stop.load()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
    }
}

int main(int argc, char* argv[]) {
    const int duration = (argc >= 2) ? std::atoi(argv[1]) : 60;
    const int workers = (argc >= 3) ? std::atoi(argv[2]) : 8;
    if (!net_init()) return 1;
    std::vector<std::thread> th;
    th.reserve(static_cast<size_t>(workers));
    for (int i = 0; i < workers; ++i) th.emplace_back(worker_loop, i);

    std::this_thread::sleep_for(std::chrono::seconds(duration));
    g_stop = 1;
    for (auto& t : th) t.join();
    net_cleanup();
    std::cout << "ok=" << g_ok.load() << " fail=" << g_fail.load() << "\n";
    return g_fail.load() == 0 ? 0 : 1;
}
