// SOCKS5 CONNECT helper for dual-stack tests.
// Usage:
//   socks5_dualstack_get <socks_host> <socks_port> <target_host> <target_port> [expect_substr]
// target_host may be IPv4, IPv6, or domain. SOCKS ATYP chosen automatically.
#include "net.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

static bool socks5_connect(socket_t fd, const std::string& host, uint16_t port) {
    const uint8_t greet[] = {0x05, 0x01, 0x00};
    if (!send_all(fd, greet, sizeof(greet))) return false;
    uint8_t method[2];
    if (!recv_exact(fd, method, 2) || method[0] != 0x05 || method[1] != 0x00) return false;

    std::vector<uint8_t> req;
    req.push_back(0x05);
    req.push_back(0x01);
    req.push_back(0x00);

    const std::string h = strip_ip_brackets(host);
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
        if (h.empty() || h.size() > 255) return false;
        req.push_back(0x03);
        req.push_back(static_cast<uint8_t>(h.size()));
        req.insert(req.end(), h.begin(), h.end());
    }
    req.push_back(static_cast<uint8_t>(port >> 8));
    req.push_back(static_cast<uint8_t>(port & 0xFF));
    if (!send_all(fd, req.data(), req.size())) return false;

    uint8_t reply_hdr[4];
    if (!recv_exact(fd, reply_hdr, 4) || reply_hdr[0] != 0x05 || reply_hdr[1] != 0x00) {
        return false;
    }
    size_t rest = 0;
    if (reply_hdr[3] == 0x01) rest = 4 + 2;
    else if (reply_hdr[3] == 0x04) rest = 16 + 2;
    else if (reply_hdr[3] == 0x03) {
        uint8_t len = 0;
        if (!recv_exact(fd, &len, 1)) return false;
        rest = static_cast<size_t>(len) + 2;
    } else {
        return false;
    }
    std::vector<uint8_t> skip(rest);
    return recv_exact(fd, skip.data(), skip.size());
}

int main(int argc, char* argv[]) {
    if (argc < 5) {
        std::cerr << "usage: " << argv[0]
                  << " <socks_host> <socks_port> <target_host> <target_port> [expect]\n";
        return 2;
    }
    const std::string socks_host = argv[1];
    const int socks_port = std::atoi(argv[2]);
    const std::string target_host = argv[3];
    const int target_port = std::atoi(argv[4]);
    const std::string expect = (argc >= 6) ? argv[5] : "VORTEX_ECHO_OK";

    if (!net_init()) return 1;
    socket_t fd = tcp_connect(socks_host, socks_port, 8);
    if (fd == INVALID_SOCK) {
        std::cerr << "socks connect failed\n";
        return 3;
    }
    set_socket_options(fd, 8);
    if (!socks5_connect(fd, target_host, static_cast<uint16_t>(target_port))) {
        std::cerr << "socks handshake/CONNECT failed\n";
        net_close(fd);
        return 4;
    }

    const std::string http =
        "GET / HTTP/1.1\r\nHost: dualstack-test\r\nConnection: close\r\n\r\n";
    if (!send_all(fd, reinterpret_cast<const uint8_t*>(http.data()), http.size())) {
        std::cerr << "send failed\n";
        net_close(fd);
        return 5;
    }

    std::string body;
    std::vector<uint8_t> buf(4096);
    for (int i = 0; i < 64; ++i) {
        int n = recv_some(fd, buf.data(), buf.size());
        if (n <= 0) break;
        body.append(reinterpret_cast<char*>(buf.data()), static_cast<size_t>(n));
        if (body.find(expect) != std::string::npos) break;
    }
    net_close(fd);
    net_cleanup();

    if (body.find(expect) == std::string::npos) {
        std::cerr << "missing expect substr; got " << body.size() << " bytes\n";
        return 6;
    }
    std::cout << "OK " << socks_host << " -> " << target_host << ":" << target_port << "\n";
    return 0;
}
