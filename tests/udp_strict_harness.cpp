// Strict UDP port-forward harness: sequential, burst, concurrent, large, idle-expiry.
#include "net.hpp"

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

namespace {

std::atomic<int> g_fail{0};
std::string g_last_err;

void set_err(const std::string& e) {
    g_last_err = e;
}

bool echo_once(const std::string& host, uint16_t port, const std::vector<uint8_t>& payload,
               int timeout_sec = 3, int retries = 1) {
    for (int attempt = 0; attempt <= retries; ++attempt) {
        socket_t fd = create_udp_socket();
        if (fd == INVALID_SOCK) {
            set_err("socket");
            return false;
        }
        set_recv_timeout(fd, timeout_sec);
        if (!udp_send_to_host(fd, payload.data(), payload.size(), host, port)) {
            set_err("sendto");
            net_close(fd);
            return false;
        }
        std::vector<uint8_t> buf(payload.size() + 64);
        sockaddr_in from{};
        const int n = udp_recv_from(fd, buf.data(), buf.size(), from);
        net_close(fd);
        if (n < 0) {
            set_err("timeout");
            if (attempt < retries) continue;
            return false;
        }
        if (static_cast<size_t>(n) != payload.size() ||
            std::memcmp(buf.data(), payload.data(), payload.size()) != 0) {
            set_err("mismatch");
            return false; // real corruption — do not retry
        }
        return true;
    }
    return false;
}

bool burst_same_socket(const std::string& host, uint16_t port, int count) {
    socket_t fd = create_udp_socket();
    if (fd == INVALID_SOCK) return false;
    set_recv_timeout(fd, 3);
    for (int i = 0; i < count; ++i) {
        char msg[64];
        const int len =
            std::snprintf(msg, sizeof(msg), "BURST-%04d-ABCDEF", i);
        if (!udp_send_to_host(fd, reinterpret_cast<const uint8_t*>(msg),
                              static_cast<size_t>(len), host, port)) {
            set_err("burst send");
            net_close(fd);
            return false;
        }
        std::vector<uint8_t> buf(128);
        sockaddr_in from{};
        const int n = udp_recv_from(fd, buf.data(), buf.size(), from);
        if (n != len || std::memcmp(buf.data(), msg, static_cast<size_t>(len)) != 0) {
            set_err("burst recv");
            net_close(fd);
            return false;
        }
    }
    net_close(fd);
    return true;
}

void concurrent_worker(const std::string& host, uint16_t port, int id, int rounds) {
    for (int i = 0; i < rounds; ++i) {
        char msg[80];
        const int len =
            std::snprintf(msg, sizeof(msg), "C%02d-R%04d-PAYLOAD", id, i);
        std::vector<uint8_t> payload(reinterpret_cast<uint8_t*>(msg),
                                     reinterpret_cast<uint8_t*>(msg) + len);
        // One timeout retry; mismatch aborts immediately.
        if (!echo_once(host, port, payload, 5, 1)) {
            ++g_fail;
            return;
        }
    }
}

} // namespace

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cerr << "usage: udp_strict_harness <mode> ...\n"
                     "  seq <host> <port> <rounds>\n"
                     "  burst <host> <port> <count>\n"
                     "  conc <host> <port> <threads> <rounds>\n"
                     "  large <host> <port> <bytes>\n"
                     "  idle <host> <port> <sleep_sec>\n";
        return 2;
    }
    net_init();
    const std::string mode = argv[1];
    bool ok = false;

    if (mode == "seq" && argc >= 5) {
        const std::string host = argv[2];
        const uint16_t port = static_cast<uint16_t>(std::atoi(argv[3]));
        const int rounds = std::atoi(argv[4]);
        ok = true;
        for (int i = 0; i < rounds; ++i) {
            char msg[64];
            const int len = std::snprintf(msg, sizeof(msg), "SEQ-%05d-UDP", i);
            std::vector<uint8_t> payload(reinterpret_cast<uint8_t*>(msg),
                                         reinterpret_cast<uint8_t*>(msg) + len);
            // New socket each round = new client tuple / session path.
            if (!echo_once(host, port, payload)) {
                ok = false;
                std::cerr << "seq fail at " << i << " " << g_last_err << "\n";
                break;
            }
        }
    } else if (mode == "burst" && argc >= 5) {
        ok = burst_same_socket(argv[2], static_cast<uint16_t>(std::atoi(argv[3])),
                               std::atoi(argv[4]));
        if (!ok) std::cerr << "burst fail " << g_last_err << "\n";
    } else if (mode == "conc" && argc >= 6) {
        const std::string host = argv[2];
        const uint16_t port = static_cast<uint16_t>(std::atoi(argv[3]));
        const int threads = std::atoi(argv[4]);
        const int rounds = std::atoi(argv[5]);
        g_fail = 0;
        std::vector<std::thread> pool;
        for (int t = 0; t < threads; ++t) {
            pool.emplace_back(concurrent_worker, host, port, t, rounds);
        }
        for (auto& th : pool) th.join();
        ok = g_fail.load() == 0;
        if (!ok) std::cerr << "conc fails=" << g_fail.load() << " last=" << g_last_err << "\n";
    } else if (mode == "large" && argc >= 5) {
        const int bytes = std::atoi(argv[4]);
        std::vector<uint8_t> payload(static_cast<size_t>(bytes));
        for (int i = 0; i < bytes; ++i) payload[static_cast<size_t>(i)] = static_cast<uint8_t>(i & 0xff);
        // Magic prefix so we can spot truncation
        const char magic[] = "LGUDP";
        std::memcpy(payload.data(), magic, 5);
        ok = echo_once(argv[2], static_cast<uint16_t>(std::atoi(argv[3])), payload, 5);
        if (!ok) std::cerr << "large fail " << g_last_err << "\n";
    } else if (mode == "idle" && argc >= 5) {
        const std::string host = argv[2];
        const uint16_t port = static_cast<uint16_t>(std::atoi(argv[3]));
        const int sleep_sec = std::atoi(argv[4]);
        // Same socket across idle — session may expire; must still work after.
        socket_t fd = create_udp_socket();
        if (fd == INVALID_SOCK) return 1;
        set_recv_timeout(fd, 4);
        const char* a = "IDLE-BEFORE";
        if (!udp_send_to_host(fd, reinterpret_cast<const uint8_t*>(a), std::strlen(a), host,
                              port)) {
            std::cerr << "idle pre send fail\n";
            return 1;
        }
        std::vector<uint8_t> buf(64);
        sockaddr_in from{};
        if (udp_recv_from(fd, buf.data(), buf.size(), from) <= 0) {
            std::cerr << "idle pre recv fail\n";
            return 1;
        }
        std::this_thread::sleep_for(std::chrono::seconds(sleep_sec));
        const char* b = "IDLE-AFTER";
        if (!udp_send_to_host(fd, reinterpret_cast<const uint8_t*>(b), std::strlen(b), host,
                              port)) {
            std::cerr << "idle post send fail\n";
            return 1;
        }
        const int n = udp_recv_from(fd, buf.data(), buf.size(), from);
        net_close(fd);
        ok = n == static_cast<int>(std::strlen(b)) &&
             std::memcmp(buf.data(), b, static_cast<size_t>(n)) == 0;
        if (!ok) std::cerr << "idle post recv fail\n";
    } else {
        std::cerr << "bad args\n";
        return 2;
    }

    net_cleanup();
    if (ok) {
        std::cout << "UDP_STRICT_OK " << mode << std::endl;
        return 0;
    }
    return 1;
}
