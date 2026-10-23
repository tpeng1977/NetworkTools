// Minimal DNS-over-TCP stub: answers A 127.0.0.1 for every query.
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

static std::vector<uint8_t> build_a_reply(const uint8_t* q, size_t qlen, uint32_t ip_be) {
    std::vector<uint8_t> out;
    if (qlen < 12) return out;
    out.assign(q, q + qlen);
    out[2] = 0x81; // QR + RD
    out[3] = 0x80; // RA
    out[6] = 0;
    out[7] = 1; // ANCOUNT=1
    out[8] = 0;
    out[9] = 0;
    out[10] = 0;
    out[11] = 0;
    // Answer: pointer to QNAME at offset 12, TYPE A, CLASS IN, TTL, RDLENGTH, RDATA
    out.push_back(0xC0);
    out.push_back(0x0C);
    out.push_back(0x00);
    out.push_back(0x01);
    out.push_back(0x00);
    out.push_back(0x01);
    out.push_back(0x00);
    out.push_back(0x00);
    out.push_back(0x00);
    out.push_back(0x3C);
    out.push_back(0x00);
    out.push_back(0x04);
    out.push_back(static_cast<uint8_t>((ip_be >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((ip_be >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((ip_be >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(ip_be & 0xFF));
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
    // 127.0.0.1 in host order for builder that packs BE octets
    auto ans = build_a_reply(q.data(), q.size(), 0x7F000001u);
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
    if (argc >= 2) port = std::atoi(argv[1]);
    net_init();
    std::signal(SIGINT, on_sig);
    std::signal(SIGTERM, on_sig);
    socket_t fd = create_listen_socket("127.0.0.1", port, 64);
    if (fd == INVALID_SOCK) {
        std::cerr << "dns stub bind failed\n";
        return 1;
    }
    std::cout << "dns-tcp-stub on " << port << std::endl;
    std::cout.flush();
    while (g_run) {
        sockaddr_in peer{};
        socklen_type len = sizeof(peer);
        socket_t c = accept(fd, reinterpret_cast<sockaddr*>(&peer), &len);
        if (c == INVALID_SOCK) continue;
        std::thread(handle, c).detach();
    }
    net_close(fd);
    net_cleanup();
    return 0;
}
