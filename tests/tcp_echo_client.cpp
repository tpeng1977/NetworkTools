#include "net.hpp"

#include <cstring>
#include <iostream>
#include <string>
#include <vector>

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cerr << "usage: tcp_echo_client <host> <port> [payload]\n";
        return 2;
    }
    const std::string host = argv[1];
    const int port = std::atoi(argv[2]);
    const std::string payload = (argc >= 4) ? argv[3] : "VORTEX_FWD_TCP_OK";

    net_init();
    socket_t fd = tcp_connect(host, port, 5);
    if (fd == INVALID_SOCK) {
        std::cerr << "connect failed\n";
        return 1;
    }
    set_socket_options(fd, 5);
    if (!send_all(fd, reinterpret_cast<const uint8_t*>(payload.data()), payload.size())) {
        std::cerr << "send failed\n";
        return 1;
    }
    std::vector<uint8_t> buf(4096);
    const int n = recv_some(fd, buf.data(), buf.size());
    if (n <= 0) {
        std::cerr << "recv failed\n";
        return 1;
    }
    const std::string got(reinterpret_cast<char*>(buf.data()), static_cast<size_t>(n));
    if (got.find(payload) == std::string::npos && got != payload) {
        // echo_server may wrap HTTP; for raw payload expect exact echo
        if (got != payload) {
            std::cerr << "mismatch got=[" << got << "]\n";
            net_close(fd);
            return 1;
        }
    }
    std::cout << "TCP_OK " << got.substr(0, payload.size()) << std::endl;
    net_close(fd);
    net_cleanup();
    return 0;
}
