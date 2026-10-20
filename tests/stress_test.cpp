#include "net.hpp"
#include <atomic>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

std::atomic<int> g_ok{0};
std::atomic<int> g_fail{0};

void worker(int proxy_port, int host_port, int rounds) {
    for (int r = 0; r < rounds; ++r) {
        socket_t fd = tcp_connect("127.0.0.1", proxy_port, 10);
        if (fd == INVALID_SOCK) { ++g_fail; continue; }

        uint8_t greet[] = {0x05, 0x01, 0x00};
        uint8_t greply[2];
        if (!send_all(fd, greet, sizeof(greet)) || !recv_exact(fd, greply, 2) ||
            greply[1] != 0x00) {
            net_close(fd); ++g_fail; continue;
        }

        std::string host = "127.0.0.1";
        std::vector<uint8_t> req = {0x05, 0x01, 0x00, 0x03,
                                    static_cast<uint8_t>(host.size())};
        req.insert(req.end(), host.begin(), host.end());
        uint16_t pbe = htons(static_cast<uint16_t>(host_port));
        uint8_t pb[2];
        std::memcpy(pb, &pbe, 2);
        req.insert(req.end(), pb, pb + 2);

        uint8_t rreply[10];
        if (!send_all(fd, req.data(), req.size()) || !recv_exact(fd, rreply, 10) ||
            rreply[1] != 0x00) {
            net_close(fd); ++g_fail; continue;
        }

        std::string http =
            "GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n";
        send_all(fd, reinterpret_cast<const uint8_t*>(http.data()), http.size());

        std::string resp;
        uint8_t buf[1024];
        while (true) {
            int n = recv_some(fd, buf, sizeof(buf));
            if (n <= 0) break;
            resp.append(reinterpret_cast<char*>(buf), n);
        }
        net_close(fd);
        if (resp.find("VORTEX_ECHO_OK") != std::string::npos) ++g_ok;
        else ++g_fail;
    }
}

int main(int argc, char* argv[]) {
    int threads = 20;
    int rounds = 10;
    int proxy_port = 11080;
    int host_port = 19080;
    if (argc >= 2) threads = std::atoi(argv[1]);
    if (argc >= 3) rounds = std::atoi(argv[2]);
    if (argc >= 4) proxy_port = std::atoi(argv[3]);
    if (argc >= 5) host_port = std::atoi(argv[4]);

    if (!net_init()) return 1;

    std::vector<std::thread> pool;
    for (int i = 0; i < threads; ++i) {
        pool.emplace_back(worker, proxy_port, host_port, rounds);
    }
    for (auto& t : pool) t.join();
    net_cleanup();

    std::cout << "stress ok=" << g_ok << " fail=" << g_fail
              << " total=" << (threads * rounds) << "\n";
    return g_fail == 0 ? 0 : 1;
}
