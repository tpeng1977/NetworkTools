// Minimal DNS-over-TCP stub: answers A / AAAA for every query by qtype.
// Usage: dns_tcp_stub [port] [bind_ip] [a_ip] [aaaa_ip]
#include "net.hpp"
#include <atomic>
#include <csignal>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

std::atomic<bool> g_run{true};
void on_sig(int) { g_run = false; }

static std::string g_a_ip = "127.0.0.1";
static std::string g_aaaa_ip = "::1";

static size_t skip_name(const uint8_t* msg, size_t len, size_t off) {
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

static uint16_t qtype_of(const uint8_t* q, size_t qlen) {
    if (qlen < 12) return 0;
    size_t off = skip_name(q, qlen, 12);
    if (off + 2 > qlen) return 0;
    return static_cast<uint16_t>((q[off] << 8) | q[off + 1]);
}

static std::vector<uint8_t> build_reply(const uint8_t* q, size_t qlen) {
    std::vector<uint8_t> out;
    if (qlen < 12) return out;
    const uint16_t qtype = qtype_of(q, qlen);
    out.assign(q, q + qlen);
    out[2] = 0x81; // QR + RD
    out[3] = 0x80; // RA
    out[6] = 0;
    out[7] = 1; // ANCOUNT=1
    out[8] = 0;
    out[9] = 0;
    out[10] = 0;
    out[11] = 0;
    // Answer: pointer to QNAME at offset 12
    out.push_back(0xC0);
    out.push_back(0x0C);
    out.push_back(static_cast<uint8_t>(qtype >> 8));
    out.push_back(static_cast<uint8_t>(qtype & 0xFF));
    out.push_back(0x00);
    out.push_back(0x01); // CLASS IN
    out.push_back(0x00);
    out.push_back(0x00);
    out.push_back(0x00);
    out.push_back(0x3C); // TTL 60
    if (qtype == 28) {
        in6_addr a6{};
        if (inet_pton(AF_INET6, strip_ip_brackets(g_aaaa_ip).c_str(), &a6) != 1) return {};
        out.push_back(0x00);
        out.push_back(0x10);
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&a6);
        out.insert(out.end(), p, p + 16);
    } else {
        in_addr a4{};
        if (inet_pton(AF_INET, g_a_ip.c_str(), &a4) != 1) return {};
        out.push_back(0x00);
        out.push_back(0x04);
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&a4.s_addr);
        out.insert(out.end(), p, p + 4);
    }
    return out;
}

void handle(socket_t fd) {
    set_socket_options(fd, 10);
    uint8_t lenb[2];
    if (!recv_exact(fd, lenb, 2)) {
        net_close(fd);
        return;
    }
    const size_t qlen = (static_cast<size_t>(lenb[0]) << 8) | lenb[1];
    if (qlen < 12 || qlen > 4096) {
        net_close(fd);
        return;
    }
    std::vector<uint8_t> q(qlen);
    if (!recv_exact(fd, q.data(), qlen)) {
        net_close(fd);
        return;
    }
    auto ans = build_reply(q.data(), q.size());
    if (ans.empty()) {
        net_close(fd);
        return;
    }
    uint8_t rlen[2] = {static_cast<uint8_t>(ans.size() >> 8), static_cast<uint8_t>(ans.size())};
    send_all(fd, rlen, 2);
    send_all(fd, ans.data(), ans.size());
    shutdown_both(fd);
    net_close(fd);
}

int main(int argc, char* argv[]) {
    int port = 15353;
    std::string bind_ip = "127.0.0.1";
    if (argc >= 2) port = std::atoi(argv[1]);
    if (argc >= 3) bind_ip = argv[2];
    if (argc >= 4) g_a_ip = argv[3];
    if (argc >= 5) g_aaaa_ip = argv[4];
    net_init();
    std::signal(SIGINT, on_sig);
    std::signal(SIGTERM, on_sig);
    socket_t fd = create_listen_socket(bind_ip, port, 64);
    if (fd == INVALID_SOCK) {
        std::cerr << "dns stub bind failed\n";
        return 1;
    }
    std::cout << "dns-tcp-stub on " << bind_ip << ":" << port << " A=" << g_a_ip
              << " AAAA=" << g_aaaa_ip << std::endl;
    std::cout.flush();
    while (g_run) {
        socket_t c = accept_any(fd);
        if (c == INVALID_SOCK) continue;
        std::thread(handle, c).detach();
    }
    net_close(fd);
    net_cleanup();
    return 0;
}
