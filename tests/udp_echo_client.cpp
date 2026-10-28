#include "net.hpp"

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "usage: udp_echo_client <host> <port> [payload]\n";
        return 2;
    }
    const std::string host = argv[1];
    const int port = std::atoi(argv[2]);
    const std::string payload = (argc >= 4) ? argv[3] : "VORTEX_FWD_UDP_OK";

    net_init();
    socket_t fd = create_udp_socket();
    if (fd == INVALID_SOCK) return 1;
    set_recv_timeout(fd, 3);

    if (!udp_send_to_host(fd, reinterpret_cast<const uint8_t*>(payload.data()), payload.size(),
                          host, static_cast<uint16_t>(port))) {
        std::cerr << "sendto failed\n";
        return 1;
    }
    std::vector<uint8_t> buf(4096);
    sockaddr_in from{};
    const int n = udp_recv_from(fd, buf.data(), buf.size(), from);
    if (n <= 0) {
        std::cerr << "recvfrom failed/timeout\n";
        return 1;
    }
    const std::string got(reinterpret_cast<char*>(buf.data()), static_cast<size_t>(n));
    if (got != payload) {
        std::cerr << "mismatch got=[" << got << "]\n";
        return 1;
    }
    std::cout << "UDP_OK " << got << std::endl;
    net_close(fd);
    net_cleanup();
    return 0;
}
