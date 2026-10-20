#include "net.hpp"
#include <chrono>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

// Active probe: connect and send garbage; expect HTTP 404 camouflage.
int main(int argc, char* argv[]) {
    int port = 18888;
    if (argc >= 2) port = std::atoi(argv[1]);
    if (!net_init()) return 1;

    socket_t fd = tcp_connect("127.0.0.1", port, 8);
    if (fd == INVALID_SOCK) {
        std::cerr << "connect failed\n";
        return 2;
    }

    uint8_t junk[64];
    for (int i = 0; i < 64; ++i) junk[i] = static_cast<uint8_t>(i * 37 + 11);
    send_all(fd, junk, sizeof(junk));

    // Server may need a moment to reject the bogus handshake.
    uint8_t buf[1024];
    int n = 0;
    for (int attempt = 0; attempt < 30 && n <= 0; ++attempt) {
        n = recv_some(fd, buf, sizeof(buf));
        if (n <= 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
    net_close(fd);
    net_cleanup();

    if (n <= 0) {
        std::cerr << "no camouflage response\n";
        return 3;
    }
    std::string resp(reinterpret_cast<char*>(buf), n);
    if (resp.find("404") == std::string::npos || resp.find("HTTP/1.1") == std::string::npos) {
        std::cerr << "not camouflage:\n" << resp << "\n";
        return 4;
    }
    std::cout << "Anti-probe camouflage OK\n";
    return 0;
}
