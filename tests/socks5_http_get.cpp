#include "net.hpp"
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

// Minimal SOCKS5 CONNECT then HTTP GET through the proxy.
int main(int argc, char* argv[]) {
    std::string proxy_ip = "127.0.0.1";
    int proxy_port = 11080;
    std::string host = "127.0.0.1";
    int host_port = 19080;
    if (argc >= 2) proxy_port = std::atoi(argv[1]);
    if (argc >= 3) host_port = std::atoi(argv[2]);
    if (argc >= 4) host = argv[3];

    if (!net_init()) return 1;

    socket_t fd = tcp_connect(proxy_ip, proxy_port, 10);
    if (fd == INVALID_SOCK) {
        std::cerr << "proxy connect failed\n";
        return 2;
    }

    // greeting
    uint8_t greet[] = {0x05, 0x01, 0x00};
    if (!send_all(fd, greet, sizeof(greet))) return 3;
    uint8_t greply[2];
    if (!recv_exact(fd, greply, 2) || greply[0] != 0x05 || greply[1] != 0x00) {
        std::cerr << "socks greeting failed\n";
        return 4;
    }

    // request with domain
    std::vector<uint8_t> req;
    req.push_back(0x05);
    req.push_back(0x01);
    req.push_back(0x00);
    req.push_back(0x03);
    req.push_back(static_cast<uint8_t>(host.size()));
    req.insert(req.end(), host.begin(), host.end());
    uint16_t pbe = htons(static_cast<uint16_t>(host_port));
    uint8_t pb[2];
    std::memcpy(pb, &pbe, 2);
    req.insert(req.end(), pb, pb + 2);
    if (!send_all(fd, req.data(), req.size())) return 5;

    uint8_t rreply[10];
    if (!recv_exact(fd, rreply, 10) || rreply[1] != 0x00) {
        std::cerr << "socks connect failed code=" << (int)rreply[1] << "\n";
        return 6;
    }

    std::string http = "GET / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
    if (!send_all(fd, reinterpret_cast<const uint8_t*>(http.data()), http.size())) return 7;

    std::string resp;
    uint8_t buf[2048];
    while (true) {
        int n = recv_some(fd, buf, sizeof(buf));
        if (n <= 0) break;
        resp.append(reinterpret_cast<char*>(buf), n);
    }
    net_close(fd);
    net_cleanup();

    if (resp.find("VORTEX_ECHO_OK") == std::string::npos) {
        std::cerr << "unexpected response:\n" << resp << "\n";
        return 8;
    }
    std::cout << "SOCKS5 HTTP GET OK (" << resp.size() << " bytes)\n";
    return 0;
}
