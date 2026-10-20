#include "net.hpp"
#include <atomic>
#include <csignal>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

std::atomic<bool> g_run{true};
void on_sig(int) { g_run = false; }

void handle(socket_t fd) {
    set_socket_options(fd, 30);
    std::vector<uint8_t> buf(4096);
    // Very simple HTTP response if request looks like HTTP, else echo
    int n = recv_some(fd, buf.data(), buf.size());
    if (n <= 0) { net_close(fd); return; }

    std::string req(reinterpret_cast<char*>(buf.data()), n);
    if (req.find("HTTP/") != std::string::npos || req.rfind("GET ", 0) == 0) {
        std::string body = "VORTEX_ECHO_OK";
        std::string resp =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: " + std::to_string(body.size()) + "\r\n"
            "Connection: close\r\n\r\n" + body;
        send_all(fd, reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
    } else {
        send_all(fd, buf.data(), static_cast<size_t>(n));
        while (true) {
            n = recv_some(fd, buf.data(), buf.size());
            if (n <= 0) break;
            if (!send_all(fd, buf.data(), static_cast<size_t>(n))) break;
        }
    }
    shutdown_both(fd);
    net_close(fd);
}

int main(int argc, char* argv[]) {
    int port = 19080;
    if (argc >= 2) port = std::atoi(argv[1]);
    net_init();
    std::signal(SIGINT, on_sig);
    socket_t fd = create_listen_socket("127.0.0.1", port, 64);
    if (fd == INVALID_SOCK) {
        std::cerr << "bind failed\n";
        return 1;
    }
    std::cout << "echo on " << port << std::endl;
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
