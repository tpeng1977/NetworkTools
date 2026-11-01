#include "net.hpp"

#include <atomic>
#include <condition_variable>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#ifndef _WIN32
#include <poll.h>
#endif

std::atomic<bool> g_run{true};
std::atomic<uint64_t> g_handled{0};

void on_sig(int) { g_run = false; }

void handle_one(socket_t fd) {
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
        while (g_run) {
            n = recv_some(fd, buf.data(), buf.size());
            if (n <= 0) break;
            if (!send_all(fd, buf.data(), static_cast<size_t>(n))) break;
        }
    }
    shutdown_both(fd);
    net_close(fd);
    ++g_handled;
}

// Fixed-size worker pool. Per-connection std::thread().detach() churned tens of
// millions of threads during dual-stack soak and eventually segfaulted (~t=1300s).
struct Pool {
    std::mutex mu;
    std::condition_variable cv;
    std::queue<socket_t> q;
    std::vector<std::thread> workers;
    size_t max_queue = 4096;

    void start(int n) {
        workers.reserve(static_cast<size_t>(n));
        for (int i = 0; i < n; ++i) {
            workers.emplace_back([this] {
                while (true) {
                    socket_t fd = INVALID_SOCK;
                    {
                        std::unique_lock<std::mutex> lock(mu);
                        cv.wait(lock, [&] { return !g_run || !q.empty(); });
                        if (!g_run && q.empty()) return;
                        fd = q.front();
                        q.pop();
                    }
                    if (fd != INVALID_SOCK) handle_one(fd);
                }
            });
        }
    }

    bool submit(socket_t fd) {
        std::lock_guard<std::mutex> lock(mu);
        if (q.size() >= max_queue) return false;
        q.push(fd);
        cv.notify_one();
        return true;
    }

    void stop() {
        g_run = false;
        cv.notify_all();
        for (auto& t : workers) {
            if (t.joinable()) t.join();
        }
        std::lock_guard<std::mutex> lock(mu);
        while (!q.empty()) {
            net_close(q.front());
            q.pop();
        }
    }
};

int main(int argc, char* argv[]) {
    int port = 19080;
    int workers = 64;
    if (argc >= 2) port = std::atoi(argv[1]);
    if (argc >= 3) workers = std::atoi(argv[2]);
    if (workers < 1) workers = 1;
    if (workers > 512) workers = 512;
    // Dual-stack (:: + IPV6_V6ONLY=0) so IPv4 and IPv6 clients can both hit the echo.
    const char* bind_ip = "127.0.0.1";
    if (argc >= 4) bind_ip = argv[3];

    net_init();
#ifndef _WIN32
    std::signal(SIGPIPE, SIG_IGN);
#endif
    std::signal(SIGINT, on_sig);
    std::signal(SIGTERM, on_sig);

    socket_t fd = create_listen_socket(bind_ip, port, 512);
    if (fd == INVALID_SOCK) {
        std::cerr << "bind failed on " << bind_ip << "\n";
        return 1;
    }

    Pool pool;
    pool.max_queue = static_cast<size_t>(workers) * 64;
    pool.start(workers);

    std::cout << "echo on " << format_host_port(bind_ip, port)
              << " workers=" << workers << " max_queue=" << pool.max_queue << std::endl;

    while (g_run) {
#ifdef _WIN32
        socket_t c = accept_any(fd);
        if (c == INVALID_SOCK) {
            if (!g_run) break;
            continue;
        }
#else
        // Poll so SIGTERM can stop a quiet accept loop without waiting for a client.
        pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        const int pr = ::poll(&pfd, 1, 500);
        if (pr < 0) {
            if (net_interrupted(net_errno())) continue;
            break;
        }
        if (pr == 0) continue;
        socket_t c = accept_any(fd);
        if (c == INVALID_SOCK) continue;
#endif
        if (!pool.submit(c)) {
            // Back-pressure: drop instead of spawning unbounded threads.
            net_close(c);
        }
    }

    pool.stop();
    net_close(fd);
    net_cleanup();
    std::cout << "echo stopped handled=" << g_handled.load() << std::endl;
    return 0;
}
