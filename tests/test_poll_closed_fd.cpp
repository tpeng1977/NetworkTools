// Regression: after a listen fd is closed under a poll loop, the loop must
// exit instead of busy-spinning on sticky POLLNVAL (server to_remote accept/UDP
// threads after stop_fwd_install).
#include "net.hpp"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <poll.h>
#include <thread>

namespace {

bool poll_revents_invalid(short revents) { return (revents & POLLNVAL) != 0; }
bool poll_revents_err_or_hup(short revents) {
    return (revents & (POLLERR | POLLHUP)) != 0;
}

// Mirrors fixed to_remote_tcp_accept_loop exit conditions.
int fixed_loop_iters_after_close(socket_t listen_fd, int max_iters) {
    int iters = 0;
    while (iters < max_iters) {
        ++iters;
        pollfd pfd{};
        pfd.fd = listen_fd;
        pfd.events = POLLIN;
        const int sel = ::poll(&pfd, 1, 200);
        if (sel < 0) {
            if (net_would_block(net_errno())) continue;
            break;
        }
        if (sel == 0) continue;
        if (poll_revents_invalid(pfd.revents) || poll_revents_err_or_hup(pfd.revents)) break;
        if (!(pfd.revents & POLLIN)) continue;
        sockaddr_in peer{};
        socklen_type plen = sizeof(peer);
        socket_t c = accept(listen_fd, reinterpret_cast<sockaddr*>(&peer), &plen);
        if (c == INVALID_SOCK) {
            if (!net_would_block(net_errno())) break;
            continue;
        }
        net_close(c);
    }
    return iters;
}

// Pre-fix bug: ignore POLLNVAL → poll returns immediately forever.
int buggy_loop_iters_after_close(socket_t listen_fd, int max_iters) {
    int iters = 0;
    while (iters < max_iters) {
        ++iters;
        pollfd pfd{};
        pfd.fd = listen_fd;
        pfd.events = POLLIN;
        const int sel = ::poll(&pfd, 1, 200);
        if (sel < 0) {
            if (net_would_block(net_errno())) continue;
            break;
        }
        if (sel == 0) continue;
        // Intentionally ignore POLLNVAL / ERR / HUP (the production bug).
        sockaddr_in peer{};
        socklen_type plen = sizeof(peer);
        socket_t c = accept(listen_fd, reinterpret_cast<sockaddr*>(&peer), &plen);
        if (c == INVALID_SOCK) continue;
        net_close(c);
    }
    return iters;
}

} // namespace

int main() {
    if (!net_init()) {
        std::fprintf(stderr, "net_init failed\n");
        return 1;
    }

    // Fixed pattern: close then one poll wake → exit (iters == 1).
    {
        socket_t lfd = create_listen_socket("127.0.0.1", 0, 8);
        if (lfd == INVALID_SOCK) {
            std::fprintf(stderr, "create_listen_socket failed\n");
            return 1;
        }
        net_close(lfd);
        const auto t0 = std::chrono::steady_clock::now();
        const int iters = fixed_loop_iters_after_close(lfd, 100000);
        const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now() - t0)
                            .count();
        if (iters > 3) {
            std::fprintf(stderr, "FAIL: fixed loop did not exit promptly (iters=%d)\n",
                         iters);
            return 1;
        }
        if (us > 200000) {
            std::fprintf(stderr, "FAIL: fixed loop too slow (%lld us)\n",
                         static_cast<long long>(us));
            return 1;
        }
        std::printf("ok fixed-loop exits after close (iters=%d, %lld us)\n", iters,
                    static_cast<long long>(us));
    }

    // Buggy pattern: hits max_iters quickly → proves POLLNVAL busy-spin.
    {
        socket_t lfd = create_listen_socket("127.0.0.1", 0, 8);
        if (lfd == INVALID_SOCK) {
            std::fprintf(stderr, "create_listen_socket failed\n");
            return 1;
        }
        net_close(lfd);
        constexpr int kCap = 20000;
        const auto t0 = std::chrono::steady_clock::now();
        const int iters = buggy_loop_iters_after_close(lfd, kCap);
        const auto us = std::chrono::duration_cast<std::chrono::microseconds>(
                            std::chrono::steady_clock::now() - t0)
                            .count();
        if (iters < kCap) {
            std::fprintf(stderr,
                         "FAIL: expected buggy loop to hit cap %d, got %d\n", kCap, iters);
            return 1;
        }
        // Should finish far faster than kCap * 200ms if it is truly spinning.
        if (us > 2000000) {
            std::fprintf(stderr, "FAIL: buggy loop too slow to be a spin (%lld us)\n",
                         static_cast<long long>(us));
            return 1;
        }
        std::printf("ok buggy-loop busy-spins on POLLNVAL (iters=%d in %lld us)\n", iters,
                    static_cast<long long>(us));
    }

    // Detached-thread smoke: close under a fixed-style worker; it must join soon.
    {
        socket_t lfd = create_listen_socket("127.0.0.1", 0, 8);
        if (lfd == INVALID_SOCK) {
            std::fprintf(stderr, "create_listen_socket failed\n");
            return 1;
        }
        std::atomic<bool> done{false};
        std::thread th([&]() {
            fixed_loop_iters_after_close(lfd, 1000000);
            done = true;
        });
        std::this_thread::sleep_for(std::chrono::milliseconds(30));
        net_close(lfd);
        const auto t0 = std::chrono::steady_clock::now();
        th.join();
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - t0)
                            .count();
        if (!done.load() || ms > 500) {
            std::fprintf(stderr, "FAIL: worker did not stop after close (%lld ms)\n",
                         static_cast<long long>(ms));
            return 1;
        }
        std::printf("ok worker joins after under-thread close (%lld ms)\n",
                    static_cast<long long>(ms));
    }

    net_cleanup();
    std::printf("PASS test_poll_closed_fd\n");
    return 0;
}
