// Sustained peer-relay stress via local multilink SOCKS5.
// Mixes DOMAIN HTTP, IPv4 ATYP HTTP, localhost DOMAIN, and DNS-over-TCP.
#include "net.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace {

std::atomic<uint64_t> g_ok{0};
std::atomic<uint64_t> g_fail{0};
std::atomic<uint64_t> g_http{0};
std::atomic<uint64_t> g_dns{0};
std::atomic<bool> g_run{true};
std::mutex g_err_mu;
std::string g_last_err;

void set_err(const std::string& e) {
    std::lock_guard<std::mutex> lock(g_err_mu);
    g_last_err = e;
}

bool socks_greet(socket_t fd) {
    uint8_t greet[] = {0x05, 0x01, 0x00};
    uint8_t greply[2];
    return send_all(fd, greet, sizeof(greet)) && recv_exact(fd, greply, 2) && greply[0] == 0x05 &&
           greply[1] == 0x00;
}

bool socks_connect_domain(socket_t fd, const std::string& host, uint16_t port) {
    std::vector<uint8_t> req = {0x05, 0x01, 0x00, 0x03, static_cast<uint8_t>(host.size())};
    req.insert(req.end(), host.begin(), host.end());
    uint16_t pbe = htons(port);
    uint8_t pb[2];
    std::memcpy(pb, &pbe, 2);
    req.insert(req.end(), pb, pb + 2);
    uint8_t rreply[10];
    if (!send_all(fd, req.data(), req.size()) || !recv_exact(fd, rreply, 10)) {
        set_err("socks domain connect I/O");
        return false;
    }
    if (rreply[1] != 0x00) {
        set_err("socks domain connect code=" + std::to_string(rreply[1]));
        return false;
    }
    return true;
}

bool socks_connect_ipv4(socket_t fd, const std::string& ip, uint16_t port) {
    in_addr a{};
    if (inet_pton(AF_INET, ip.c_str(), &a) != 1) return false;
    uint8_t req[10] = {0x05, 0x01, 0x00, 0x01};
    std::memcpy(req + 4, &a.s_addr, 4);
    uint16_t pbe = htons(port);
    std::memcpy(req + 8, &pbe, 2);
    uint8_t rreply[10];
    if (!send_all(fd, req, sizeof(req)) || !recv_exact(fd, rreply, 10)) {
        set_err("socks ipv4 connect I/O");
        return false;
    }
    if (rreply[1] != 0x00) {
        set_err("socks ipv4 connect code=" + std::to_string(rreply[1]));
        return false;
    }
    return true;
}

bool http_get_ok(socket_t fd, const std::string& host) {
    std::string http = "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
    if (!send_all(fd, reinterpret_cast<const uint8_t*>(http.data()), http.size())) {
        set_err("http send");
        return false;
    }
    std::string resp;
    uint8_t buf[1024];
    while (true) {
        int n = recv_some(fd, buf, sizeof(buf));
        if (n <= 0) break;
        resp.append(reinterpret_cast<char*>(buf), n);
        if (resp.size() > 65536) break;
    }
    if (resp.find("VORTEX_ECHO_OK") == std::string::npos) {
        set_err("http missing VORTEX_ECHO_OK");
        return false;
    }
    return true;
}

bool do_http_domain(int proxy_port, int echo_port, const std::string& host) {
    socket_t fd = tcp_connect("127.0.0.1", proxy_port, 15);
    if (fd == INVALID_SOCK) {
        set_err("proxy tcp");
        return false;
    }
    bool ok = socks_greet(fd) && socks_connect_domain(fd, host, static_cast<uint16_t>(echo_port)) &&
              http_get_ok(fd, host);
    net_close(fd);
    return ok;
}

bool do_http_ipv4(int proxy_port, int echo_port) {
    socket_t fd = tcp_connect("127.0.0.1", proxy_port, 15);
    if (fd == INVALID_SOCK) {
        set_err("proxy tcp");
        return false;
    }
    bool ok = socks_greet(fd) && socks_connect_ipv4(fd, "127.0.0.1", static_cast<uint16_t>(echo_port)) &&
              http_get_ok(fd, "127.0.0.1");
    net_close(fd);
    return ok;
}

std::vector<uint8_t> build_query_a(const std::string& name) {
    std::vector<uint8_t> q = {0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
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

bool do_dns(int proxy_port, int dns_port) {
    socket_t fd = tcp_connect("127.0.0.1", proxy_port, 15);
    if (fd == INVALID_SOCK) {
        set_err("proxy tcp dns");
        return false;
    }
    if (!socks_greet(fd) || !socks_connect_domain(fd, "127.0.0.1", static_cast<uint16_t>(dns_port))) {
        net_close(fd);
        return false;
    }
    auto q = build_query_a("peer-stress.test");
    if (q.empty()) {
        net_close(fd);
        return false;
    }
    uint8_t lenb[2] = {static_cast<uint8_t>(q.size() >> 8), static_cast<uint8_t>(q.size())};
    if (!send_all(fd, lenb, 2) || !send_all(fd, q.data(), q.size())) {
        set_err("dns send");
        net_close(fd);
        return false;
    }
    uint8_t rlenb[2];
    if (!recv_exact(fd, rlenb, 2)) {
        set_err("dns rlen");
        net_close(fd);
        return false;
    }
    const size_t rlen = (static_cast<size_t>(rlenb[0]) << 8) | rlenb[1];
    if (rlen < 12 || rlen > 4096) {
        set_err("dns bad rlen");
        net_close(fd);
        return false;
    }
    std::vector<uint8_t> resp(rlen);
    if (!recv_exact(fd, resp.data(), rlen)) {
        set_err("dns body");
        net_close(fd);
        return false;
    }
    net_close(fd);
    bool found = false;
    for (size_t i = 0; i + 14 <= resp.size(); ++i) {
        if (resp[i] == 0x00 && resp[i + 1] == 0x01 && resp[i + 2] == 0x00 && resp[i + 3] == 0x01 &&
            resp[i + 8] == 0x00 && resp[i + 9] == 0x04) {
            found = (resp[i + 10] == 127 && resp[i + 11] == 0 && resp[i + 12] == 0 && resp[i + 13] == 1);
            break;
        }
    }
    if (!found) set_err("dns no A 127.0.0.1");
    return found;
}

void record(bool ok, bool is_dns) {
    if (ok) {
        ++g_ok;
        if (is_dns) ++g_dns;
        else ++g_http;
    } else {
        ++g_fail;
    }
}

void worker_loop(int id, int proxy_port, int echo_port, int dns_port) {
    uint64_t n = 0;
    while (g_run.load()) {
        bool ok = false;
        bool is_dns = false;
        switch (n % 5) {
        case 0:
            ok = do_http_domain(proxy_port, echo_port, "127.0.0.1");
            break;
        case 1:
            ok = do_http_domain(proxy_port, echo_port, "localhost");
            break;
        case 2:
            ok = do_http_ipv4(proxy_port, echo_port);
            break;
        case 3:
            ok = do_http_domain(proxy_port, echo_port, "127.0.0.1");
            break;
        default:
            is_dns = true;
            ok = do_dns(proxy_port, dns_port);
            break;
        }
        record(ok, is_dns);
        ++n;
        // Tiny yield so we don't pin the machine; still high intensity.
        if ((n & 3ULL) == 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(1));
        }
        (void)id;
    }
}

} // namespace

int main(int argc, char* argv[]) {
    int seconds = 300;
    int threads = 12;
    int proxy_port = 21080;
    int echo_port = 19081;
    int dns_port = 15353;
    if (argc >= 2) seconds = std::atoi(argv[1]);
    if (argc >= 3) threads = std::atoi(argv[2]);
    if (argc >= 4) proxy_port = std::atoi(argv[3]);
    if (argc >= 5) echo_port = std::atoi(argv[4]);
    if (argc >= 6) dns_port = std::atoi(argv[5]);

    if (!net_init()) return 1;

    std::cout << "[*] peer sustained stress " << seconds << "s threads=" << threads
              << " proxy=" << proxy_port << " echo=" << echo_port << " dns=" << dns_port
              << std::endl;
    std::cout.flush();

    std::vector<std::thread> pool;
    pool.reserve(static_cast<size_t>(threads));
    for (int i = 0; i < threads; ++i) {
        pool.emplace_back(worker_loop, i, proxy_port, echo_port, dns_port);
    }

    const auto start = std::chrono::steady_clock::now();
    uint64_t last_ok = 0;
    uint64_t last_fail = 0;
    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        const auto elapsed =
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start)
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
        std::cout << "[+] t=" << elapsed << "s ok=" << ok << " fail=" << fail << " http=" << g_http.load()
                  << " dns=" << g_dns.load() << " +ok=" << dok << " +fail=" << dfail;
        if (!err.empty()) std::cout << " last_err=" << err;
        std::cout << std::endl;
        std::cout.flush();
        if (elapsed >= seconds) break;
    }

    g_run = false;
    for (auto& t : pool) t.join();
    net_cleanup();

    std::cout << "[*] DONE ok=" << g_ok.load() << " fail=" << g_fail.load()
              << " http=" << g_http.load() << " dns=" << g_dns.load() << std::endl;
    if (g_fail.load() != 0) {
        std::lock_guard<std::mutex> lock(g_err_mu);
        std::cerr << "[-] FAIL last_err=" << g_last_err << "\n";
        return 1;
    }
    if (g_ok.load() == 0) {
        std::cerr << "[-] FAIL zero successes\n";
        return 1;
    }
    std::cout << "PEER SUSTAINED STRESS PASSED\n";
    return 0;
}
