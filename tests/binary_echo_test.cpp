#include "net.hpp"

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

// SOCKS5 CONNECT then send binary blob; expect exact echo from echo_server.
int main(int argc, char* argv[]) {
    int proxy_port = 11080;
    int host_port = 19080;
    if (argc >= 2) proxy_port = std::atoi(argv[1]);
    if (argc >= 3) host_port = std::atoi(argv[2]);
    if (!net_init()) return 1;

    socket_t fd = tcp_connect("127.0.0.1", proxy_port, 10);
    if (fd == INVALID_SOCK) return 2;

    uint8_t greet[] = {0x05, 0x01, 0x00};
    uint8_t greply[2];
    if (!send_all(fd, greet, sizeof(greet)) || !recv_exact(fd, greply, 2)) return 3;

    std::vector<uint8_t> req = {0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1};
    uint16_t pbe = htons(static_cast<uint16_t>(host_port));
    uint8_t pb[2];
    std::memcpy(pb, &pbe, 2);
    req.insert(req.end(), pb, pb + 2);
    uint8_t rreply[10];
    if (!send_all(fd, req.data(), req.size()) || !recv_exact(fd, rreply, 10) ||
        rreply[1] != 0x00) {
        std::cerr << "socks connect failed\n";
        return 4;
    }

    // Binary payload (not HTTP); echo_server echoes raw bytes.
    std::vector<uint8_t> payload(4096);
    for (size_t i = 0; i < payload.size(); ++i) {
        payload[i] = static_cast<uint8_t>((i * 13 + 7) & 0xFF);
    }
    if (!send_all(fd, payload.data(), payload.size())) return 5;

    std::vector<uint8_t> got;
    got.reserve(payload.size());
    uint8_t buf[1024];
    while (got.size() < payload.size()) {
        int n = recv_some(fd, buf, sizeof(buf));
        if (n <= 0) break;
        got.insert(got.end(), buf, buf + n);
    }
    net_close(fd);
    net_cleanup();

    if (got != payload) {
        std::cerr << "binary mismatch got=" << got.size()
                  << " want=" << payload.size() << "\n";
        return 6;
    }
    std::cout << "Binary echo OK (" << got.size() << " bytes)\n";
    return 0;
}
