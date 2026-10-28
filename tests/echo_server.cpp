#include "net.hpp"
#include <atomic>
#include <csignal>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

std::atomic<bool> g_run{true};
std::atomic<int> g_inflight{0};
void on_sig(int) { g_run = false; }

void handle(socket_t fd) {
    struct Guard {
        ~Guard() { --g_inflight; }
    } guard;
    set_socket_options(fd, 30);
    std::vector<uint8_t> buf(65536);
    int n = recv_some(fd, buf.data(), buf.size());
    if (n <= 0) {
        net_close(fd);
        return;
    }

    // Only treat as HTTP when the request *starts* with a method. Scanning the
    // whole buffer for "HTTP/" falsely triggers on random binary stress payloads.
    std::string req(reinterpret_cast<char*>(buf.data()), static_cast<size_t>(n));
    const bool looks_http = req.rfind("GET ", 0) == 0 || req.rfind("POST ", 0) == 0 ||
                            req.rfind("HEAD ", 0) == 0 || req.rfind("PUT ", 0) == 0 ||
                            req.rfind("DELETE ", 0) == 0 || req.rfind("OPTIONS ", 0) == 0;
    if (looks_http) {
        std::string body = "VORTEX_ECHO_OK";
        std::string resp =
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: text/plain\r\n"
            "Content-Length: " +
            std::to_string(body.size()) +
            "\r\n"
            "Connection: close\r\n\r\n" +
            body;
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
    int max_inflight = 256;
    if (argc >= 2) port = std::atoi(argv[1]);
    if (argc >= 3) max_inflight = std::atoi(argv[2]);
    net_init();
    std::signal(SIGINT, on_sig);
    socket_t fd = create_listen_socket("127.0.0.1", port, 512);
    if (fd == INVALID_SOCK) {
        std::cerr << "bind failed\n";
        return 1;
    }
    std::cout << "echo on " << port << " max_inflight=" << max_inflight << std::endl;
    while (g_run) {
        sockaddr_in peer{};
        socklen_type len = sizeof(peer);
        socket_t c = accept(fd, reinterpret_cast<sockaddr*>(&peer), &len);
        if (c == INVALID_SOCK) continue;
        if (g_inflight.load() >= max_inflight) {
            net_close(c);
            continue;
        }
        ++g_inflight;
        std::thread(handle, c).detach();
    }
    net_close(fd);
    net_cleanup();
    return 0;
}
