// SOCKS5 CONNECT using ATYP IPv4 (not domain), then HTTP GET.
#include "net.hpp"
#include <cstring>
#include <iostream>
#include <string>

int main(int argc, char* argv[]) {
    int proxy_port = 21080;
    int host_port = 19081;
    std::string ip = "127.0.0.1";
    if (argc >= 2) proxy_port = std::atoi(argv[1]);
    if (argc >= 3) host_port = std::atoi(argv[2]);
    if (argc >= 4) ip = argv[3];

    if (!net_init()) return 1;
    socket_t fd = tcp_connect("127.0.0.1", proxy_port, 10);
    if (fd == INVALID_SOCK) return 2;

    uint8_t greet[] = {0x05, 0x01, 0x00};
    if (!send_all(fd, greet, sizeof(greet))) return 3;
    uint8_t greply[2];
    if (!recv_exact(fd, greply, 2) || greply[0] != 0x05) return 4;

    in_addr a{};
    if (inet_pton(AF_INET, ip.c_str(), &a) != 1) return 5;
    uint8_t req[10] = {0x05, 0x01, 0x00, 0x01};
    std::memcpy(req + 4, &a.s_addr, 4);
    uint16_t pbe = htons(static_cast<uint16_t>(host_port));
    std::memcpy(req + 8, &pbe, 2);
    if (!send_all(fd, req, sizeof(req))) return 6;
    uint8_t rreply[10];
    if (!recv_exact(fd, rreply, 10) || rreply[1] != 0x00) {
        std::cerr << "socks connect failed code=" << (int)rreply[1] << "\n";
        return 7;
    }

    std::string http = "GET / HTTP/1.1\r\nHost: " + ip + "\r\nConnection: close\r\n\r\n";
    if (!send_all(fd, reinterpret_cast<const uint8_t*>(http.data()), http.size())) return 8;
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
        std::cerr << "unexpected:\n" << resp << "\n";
        return 9;
    }
    std::cout << "SOCKS5 HTTP GET (IPv4 ATYP) OK\n";
    return 0;
}
