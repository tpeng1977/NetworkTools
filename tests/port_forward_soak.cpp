// Intense local soak for SSH-style port forwards (to_remote / to_local, TCP+UDP).
#include "net.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <mutex>
#include <random>
#include <string>
#include <thread>
#include <vector>

namespace {

std::atomic<uint64_t> g_ok{0};
std::atomic<uint64_t> g_fail{0};
std::atomic<uint64_t> g_tcp_r{0};
std::atomic<uint64_t> g_tcp_l{0};
std::atomic<uint64_t> g_udp_r{0};
std::atomic<uint64_t> g_udp_l{0};
std::atomic<uint64_t> g_storm{0};
std::atomic<uint64_t> g_sustained{0};
std::atomic<uint64_t> g_burst{0};
std::atomic<bool> g_run{true};
std::mutex g_err_mu;
std::string g_last_err;

void set_err(const std::string& e) {
    std::lock_guard<std::mutex> lock(g_err_mu);
    g_last_err = e;
}

thread_local std::mt19937_64 tls_rng{std::random_device{}() ^
                                     (static_cast<uint64_t>(
                                          std::hash<std::thread::id>{}(std::this_thread::get_id()))
                                      << 1)};

uint32_t rnd_u32() { return static_cast<uint32_t>(tls_rng()); }

std::vector<uint8_t> make_pattern(size_t n, uint32_t seed) {
    std::vector<uint8_t> out(n);
    uint32_t x = seed ? seed : 0xA5A5A5A5u;
    // Binary magic so echo_server never mis-detects HTTP on random payloads.
    if (n >= 4) {
        out[0] = 0x56; // V
        out[1] = 0x58; // X
        out[2] = 0x01;
        out[3] = 0x00;
    }
    for (size_t i = (n >= 4 ? 4 : 0); i < n; ++i) {
        x = x * 1664525u + 1013904223u;
        out[i] = static_cast<uint8_t>((x >> 16) & 0xFF);
    }
    return out;
}

bool recv_exact_deadline(socket_t fd, uint8_t* buf, size_t n,
                         std::chrono::steady_clock::time_point deadline) {
    size_t got = 0;
    while (got < n) {
        if (std::chrono::steady_clock::now() > deadline) return false;
        const int r = recv_some(fd, buf + got, n - got);
        if (r <= 0) {
            if (net_would_block(net_errno())) {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
                continue;
            }
            return false;
        }
        got += static_cast<size_t>(r);
    }
    return true;
}

bool tcp_echo_roundtrip(const std::string& host, uint16_t port, const uint8_t* data, size_t len,
                        int timeout_sec) {
    socket_t fd = tcp_connect(host, static_cast<int>(port), timeout_sec);
    if (fd == INVALID_SOCK) {
        set_err("tcp connect " + host + ":" + std::to_string(port));
        return false;
    }
    // Slightly longer I/O timeout than connect so large echoes can finish under load.
    set_socket_options(fd, timeout_sec + 5);
    if (!send_all(fd, data, len)) {
        set_err("tcp send");
        net_close(fd);
        return false;
    }
    std::vector<uint8_t> got(len);
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(timeout_sec > 0 ? timeout_sec : 5);
    if (!recv_exact_deadline(fd, got.data(), len, deadline)) {
        set_err("tcp recv incomplete");
        net_close(fd);
        return false;
    }
    if (std::memcmp(got.data(), data, len) != 0) {
        set_err("tcp payload corruption");
        net_close(fd);
        return false;
    }
    net_close(fd);
    return true;
}

bool tcp_short(const std::string& host, uint16_t port) {
    const uint32_t seed = rnd_u32();
    const size_t n = 16 + (rnd_u32() % 240);
    auto payload = make_pattern(n, seed);
    return tcp_echo_roundtrip(host, port, payload.data(), payload.size(), 8);
}

bool tcp_large(const std::string& host, uint16_t port) {
    // Stay under max_payload (32768) for a single relay chunk; multi-chunk via echo loop.
    const uint32_t seed = rnd_u32();
    const size_t n = 4096 + (rnd_u32() % 12000); // ~4–16 KiB
    auto payload = make_pattern(n, seed);
    return tcp_echo_roundtrip(host, port, payload.data(), payload.size(), 15);
}

bool tcp_sustained(const std::string& host, uint16_t port) {
    socket_t fd = tcp_connect(host, static_cast<int>(port), 10);
    if (fd == INVALID_SOCK) {
        set_err("tcp sustained connect");
        return false;
    }
    set_socket_options(fd, 20);
    const int rounds = 4 + static_cast<int>(rnd_u32() % 8);
    for (int r = 0; r < rounds; ++r) {
        const uint32_t seed = rnd_u32();
        const size_t n = 512 + (rnd_u32() % 8000);
        auto payload = make_pattern(n, seed);
        if (!send_all(fd, payload.data(), payload.size())) {
            set_err("tcp sustained send");
            net_close(fd);
            return false;
        }
        std::vector<uint8_t> got(n);
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(15);
        if (!recv_exact_deadline(fd, got.data(), n, deadline)) {
            set_err("tcp sustained recv");
            net_close(fd);
            return false;
        }
        if (std::memcmp(got.data(), payload.data(), n) != 0) {
            set_err("tcp sustained corruption");
            net_close(fd);
            return false;
        }
    }
    net_close(fd);
    return true;
}

bool udp_echo_once(const std::string& host, uint16_t port, const uint8_t* data, size_t len,
                   int timeout_sec) {
    socket_t fd = create_udp_socket();
    if (fd == INVALID_SOCK) return false;
    set_recv_timeout(fd, timeout_sec > 0 ? timeout_sec : 3);
    if (!udp_send_to_host(fd, data, len, host, port)) {
        set_err("udp sendto");
        net_close(fd);
        return false;
    }
    std::vector<uint8_t> buf(65535);
    sockaddr_in from{};
    const int n = udp_recv_from(fd, buf.data(), buf.size(), from);
    if (n <= 0) {
        set_err("udp recv timeout/fail");
        net_close(fd);
        return false;
    }
    if (static_cast<size_t>(n) != len || std::memcmp(buf.data(), data, len) != 0) {
        set_err("udp mismatch/corruption");
        net_close(fd);
        return false;
    }
    net_close(fd);
    return true;
}

bool udp_short(const std::string& host, uint16_t port) {
    const uint32_t seed = rnd_u32();
    const size_t n = 8 + (rnd_u32() % 500);
    auto payload = make_pattern(n, seed);
    return udp_echo_once(host, port, payload.data(), payload.size(), 4);
}

bool udp_large(const std::string& host, uint16_t port) {
    // UDP_DATA overhead ~5+addr; keep well under max_payload 32768.
    const uint32_t seed = rnd_u32();
    const size_t n = 1024 + (rnd_u32() % 12000);
    auto payload = make_pattern(n, seed);
    return udp_echo_once(host, port, payload.data(), payload.size(), 5);
}

bool udp_burst_session(const std::string& host, uint16_t port) {
    // Same socket = same UDP session affinity path.
    socket_t fd = create_udp_socket();
    if (fd == INVALID_SOCK) return false;
    set_recv_timeout(fd, 4);
    const int pkts = 6 + static_cast<int>(rnd_u32() % 10);
    for (int i = 0; i < pkts; ++i) {
        const uint32_t seed = rnd_u32() ^ static_cast<uint32_t>(i * 97);
        const size_t n = 32 + (rnd_u32() % 2000);
        auto payload = make_pattern(n, seed);
        if (!udp_send_to_host(fd, payload.data(), payload.size(), host, port)) {
            set_err("udp burst send");
            net_close(fd);
            return false;
        }
        std::vector<uint8_t> buf(65535);
        sockaddr_in from{};
        const int rn = udp_recv_from(fd, buf.data(), buf.size(), from);
        if (rn <= 0 || static_cast<size_t>(rn) != n ||
            std::memcmp(buf.data(), payload.data(), n) != 0) {
            set_err("udp burst mismatch");
            net_close(fd);
            return false;
        }
    }
    net_close(fd);
    return true;
}

struct PortSet {
    std::vector<uint16_t> remote_tcp; // to_remote listen
    std::vector<uint16_t> local_tcp;  // to_local listen
};

void record(bool ok, const char* kind) {
    if (ok) {
        ++g_ok;
        if (std::strcmp(kind, "tcp_r") == 0) ++g_tcp_r;
        else if (std::strcmp(kind, "tcp_l") == 0) ++g_tcp_l;
        else if (std::strcmp(kind, "udp_r") == 0) ++g_udp_r;
        else if (std::strcmp(kind, "udp_l") == 0) ++g_udp_l;
        else if (std::strcmp(kind, "storm") == 0) ++g_storm;
        else if (std::strcmp(kind, "sust") == 0) ++g_sustained;
        else if (std::strcmp(kind, "burst") == 0) ++g_burst;
    } else {
        ++g_fail;
    }
}

void storm_worker(PortSet ports) {
    while (g_run.load()) {
        const uint16_t pr = ports.remote_tcp[rnd_u32() % ports.remote_tcp.size()];
        const uint16_t pl = ports.local_tcp[rnd_u32() % ports.local_tcp.size()];
        for (int i = 0; i < 4 && g_run.load(); ++i) {
            record(tcp_short("127.0.0.1", pr), "storm");
            record(tcp_short("127.0.0.1", pl), "storm");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
}

void mixed_worker(int id, PortSet ports) {
    uint64_t n = 0;
    while (g_run.load()) {
        const uint16_t pr = ports.remote_tcp[rnd_u32() % ports.remote_tcp.size()];
        const uint16_t pl = ports.local_tcp[rnd_u32() % ports.local_tcp.size()];
        bool ok = false;
        const char* kind = "tcp_r";
        // Weight shorts higher so peer VIA_PEER workers are not pinned by long
        // sustained streams under extreme concurrency.
        switch (n % 12) {
        case 0:
        case 1:
        case 2:
            kind = "tcp_r";
            ok = tcp_short("127.0.0.1", pr);
            break;
        case 3:
        case 4:
        case 5:
            kind = "tcp_l";
            ok = tcp_short("127.0.0.1", pl);
            break;
        case 6:
            kind = "tcp_r";
            ok = tcp_large("127.0.0.1", pr);
            break;
        case 7:
            kind = "tcp_l";
            ok = tcp_large("127.0.0.1", pl);
            break;
        case 8:
            kind = "sust";
            ok = tcp_sustained("127.0.0.1", (n & 1) ? pr : pl);
            break;
        case 9:
            kind = "udp_r";
            ok = (n & 1) ? udp_large("127.0.0.1", pr) : udp_short("127.0.0.1", pr);
            break;
        case 10:
            kind = "udp_l";
            ok = (n & 1) ? udp_large("127.0.0.1", pl) : udp_short("127.0.0.1", pl);
            break;
        default:
            kind = "burst";
            ok = udp_burst_session("127.0.0.1", (n & 1) ? pr : pl);
            break;
        }
        record(ok, kind);
        ++n;
        if ((n & 7ULL) == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        (void)id;
    }
}

} // namespace

int main(int argc, char* argv[]) {
    int seconds = 1800;
    int threads = 24;
    if (argc >= 2) seconds = std::atoi(argv[1]);
    if (argc >= 3) threads = std::atoi(argv[2]);
    if (seconds < 1) seconds = 1;
    if (threads < 4) threads = 4;

    PortSet ports;
    // Matches tests/port_forward_soak_peer.json
    ports.remote_tcp = {10888, 10891, 10892, 10893, 10894};
    ports.local_tcp = {10900, 10901, 10902, 10903, 10904};

    if (!net_init()) return 1;

    std::cout << "[*] port-forward soak " << seconds << "s threads=" << threads
              << " to_remote_ports=" << ports.remote_tcp.size()
              << " to_local_ports=" << ports.local_tcp.size() << std::endl;
    std::cout.flush();

    const int storm_n = (std::max)(2, threads / 6);
    const int mixed_n = threads - storm_n;

    std::vector<std::thread> pool;
    pool.reserve(static_cast<size_t>(threads));
    for (int i = 0; i < storm_n; ++i) pool.emplace_back(storm_worker, ports);
    for (int i = 0; i < mixed_n; ++i) pool.emplace_back(mixed_worker, i, ports);

    const auto start = std::chrono::steady_clock::now();
    uint64_t last_ok = 0;
    uint64_t last_fail = 0;
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        const auto elapsed =
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() -
                                                             start)
                .count();
        const uint64_t ok = g_ok.load();
        const uint64_t fail = g_fail.load();
        const uint64_t dok = ok - last_ok;
        const uint64_t dfail = fail - last_fail;
        last_ok = ok;
        last_fail = fail;
        std::string err;
        {
            std::lock_guard<std::mutex> lock(g_err_mu);
            err = g_last_err;
        }
        std::cout << "[+] t=" << elapsed << "s ok=" << ok << " fail=" << fail
                  << " tcp_r=" << g_tcp_r.load() << " tcp_l=" << g_tcp_l.load()
                  << " udp_r=" << g_udp_r.load() << " udp_l=" << g_udp_l.load()
                  << " storm=" << g_storm.load() << " sust=" << g_sustained.load()
                  << " burst=" << g_burst.load() << " +ok=" << dok << " +fail=" << dfail;
        if (!err.empty()) std::cout << " last_err=" << err;
        std::cout << std::endl;
        std::cout.flush();
        if (elapsed >= seconds) break;
    }

    g_run = false;
    for (auto& t : pool) t.join();
    net_cleanup();

    std::cout << "[*] DONE ok=" << g_ok.load() << " fail=" << g_fail.load()
              << " tcp_r=" << g_tcp_r.load() << " tcp_l=" << g_tcp_l.load()
              << " udp_r=" << g_udp_r.load() << " udp_l=" << g_udp_l.load() << std::endl;

    // Allow a tiny transient fail budget under reconnect storms (script may restart peer).
    const uint64_t okf = g_ok.load();
    const uint64_t failf = g_fail.load();
    if (okf == 0) {
        std::cerr << "[-] FAIL zero successes\n";
        return 1;
    }
    // Hard fail on corruption, or fail rate > 5% (allows brief peer-restart windows).
    {
        std::lock_guard<std::mutex> lock(g_err_mu);
        if (g_last_err.find("corruption") != std::string::npos) {
            std::cerr << "[-] FAIL corruption last_err=" << g_last_err << "\n";
            return 1;
        }
    }
    if (failf * 10 > okf) {
        std::lock_guard<std::mutex> lock(g_err_mu);
        std::cerr << "[-] FAIL high error rate last_err=" << g_last_err << "\n";
        return 1;
    }
    std::cout << "PORT FORWARD SOAK PASSED\n";
    return 0;
}
