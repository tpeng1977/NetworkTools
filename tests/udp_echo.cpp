#include "net.hpp"

#include <atomic>
#include <csignal>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#ifndef _WIN32
#  include <poll.h>
#endif

std::atomic<bool> g_run{true};
void on_sig(int) { g_run = false; }

int main(int argc, char* argv[]) {
    int port = 19082;
    if (argc >= 2) port = std::atoi(argv[1]);
    net_init();
    std::signal(SIGINT, on_sig);
    std::signal(SIGTERM, on_sig);

    socket_t fd = create_udp_listen_socket("127.0.0.1", port);
    if (fd == INVALID_SOCK) {
        std::cerr << "udp bind failed\n";
        return 1;
    }
    std::cout << "udp echo on " << port << std::endl;
    std::cout.flush();

    std::vector<uint8_t> buf(65535);
    while (g_run) {
#ifdef _WIN32
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        timeval tv{};
        tv.tv_sec = 0;
        tv.tv_usec = 200000;
        const int sel = ::select(static_cast<int>(fd) + 1, &rfds, nullptr, nullptr, &tv);
#else
        pollfd pfd{fd, POLLIN, 0};
        const int sel = ::poll(&pfd, 1, 200);
#endif
        if (sel < 0) break;
        if (sel == 0) continue;
        sockaddr_in from{};
        const int n = udp_recv_from(fd, buf.data(), buf.size(), from);
        if (n <= 0) continue;
        udp_send_to(fd, buf.data(), static_cast<size_t>(n), from);
    }
    net_close(fd);
    net_cleanup();
    return 0;
}
