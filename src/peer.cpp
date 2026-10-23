// Peer: dials into Vortex server, registers with peer_secret, and exits traffic
// for CMD_VIA_PEER sessions (multilink → server → peer → target).
//
// Cross-platform. Config: config/peer.json

#include "config.hpp"
#include "net.hpp"
#include "protocol.hpp"

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace {

std::atomic<bool> g_running{true};

void on_signal(int) { g_running = false; }

struct PeerJob {
    socket_t server_fd = INVALID_SOCK;
    socket_t target_fd = INVALID_SOCK;
    std::atomic<bool> alive{true};
    PeerConfig cfg;
    // Same layout as client.cpp toward the server:
    vortex::SessionCrypto to_server;   // encrypt outbound to server (salt)
    vortex::SessionCrypto from_server; // decrypt inbound from server (salt^XOR)

    ~PeerJob() {
        alive = false;
        if (target_fd != INVALID_SOCK) {
            shutdown_both(target_fd);
            net_close(target_fd);
            target_fd = INVALID_SOCK;
        }
        if (server_fd != INVALID_SOCK) {
            shutdown_both(server_fd);
            net_close(server_fd);
            server_fd = INVALID_SOCK;
        }
    }
};

void relay_target_to_server(std::shared_ptr<PeerJob> s) {
    std::vector<uint8_t> buf(static_cast<size_t>(s->cfg.max_payload));
    while (s->alive && g_running) {
        if (s->target_fd == INVALID_SOCK) break;
        const int n = recv_some(s->target_fd, buf.data(), buf.size());
        if (n <= 0) break;
        if (!vortex::send_frame(s->server_fd, s->to_server, vortex::CMD_DATA,
                                buf.data(), static_cast<size_t>(n),
                                s->cfg.padding_min, s->cfg.padding_max)) {
            break;
        }
    }
    s->alive = false;
    shutdown_both(s->server_fd);
}

bool handle_one_job(std::shared_ptr<PeerJob> s, const std::vector<uint8_t>& connect_data) {
    std::string host;
    uint16_t port = 0;
    if (!vortex::parse_connect_target(connect_data, host, port)) {
        vortex::send_frame(s->server_fd, s->to_server, vortex::CMD_CONNECT_FAIL,
                           nullptr, 0, s->cfg.padding_min, s->cfg.padding_max);
        return false;
    }

    socket_t tfd = tcp_connect(host, static_cast<int>(port), s->cfg.idle_timeout_sec);
    if (tfd == INVALID_SOCK) {
        vortex::send_frame(s->server_fd, s->to_server, vortex::CMD_CONNECT_FAIL,
                           nullptr, 0, s->cfg.padding_min, s->cfg.padding_max);
        std::cout << "[-] Peer connect failed " << host << ":" << port << std::endl;
        return false;
    }
    s->target_fd = tfd;

    if (!vortex::send_frame(s->server_fd, s->to_server, vortex::CMD_CONNECT_OK,
                            nullptr, 0, s->cfg.padding_min, s->cfg.padding_max)) {
        return false;
    }
    std::cout << "[+] Peer exit " << host << ":" << port << std::endl;
    std::cout.flush();

    std::thread(relay_target_to_server, s).detach();

    std::vector<uint8_t> buf(static_cast<size_t>(s->cfg.max_payload));
    while (s->alive && g_running) {
        auto frame = vortex::recv_frame(s->server_fd, s->from_server, s->cfg.max_payload);
        if (!frame.ok) break;
        if (frame.cmd == vortex::CMD_DATA) {
            if (!frame.data.empty()) {
                if (!send_all(s->target_fd, frame.data.data(), frame.data.size())) break;
            }
        } else if (frame.cmd == vortex::CMD_CLOSE) {
            break;
        } else {
            break;
        }
    }
    s->alive = false;
    shutdown_both(s->target_fd);
    shutdown_both(s->server_fd);
    return true;
}

// One long-lived worker: register, then accept sequential CONNECT jobs.
// After each job the TCP session to the server ends; caller reconnects.
bool run_peer_session(const PeerConfig& cfg) {
    socket_t fd = tcp_connect(cfg.server_ip, cfg.server_port, cfg.idle_timeout_sec);
    if (fd == INVALID_SOCK) {
        std::cerr << "[-] Peer cannot reach server " << cfg.server_ip << ":" << cfg.server_port
                  << "\n";
        return false;
    }
    set_socket_options(fd, cfg.idle_timeout_sec);

    uint64_t salt = get_random_salt();
    uint8_t salt_buf[8];
    std::memcpy(salt_buf, &salt, 8);
    if (!send_all(fd, salt_buf, 8)) {
        net_close(fd);
        return false;
    }

    auto s = std::make_shared<PeerJob>();
    s->server_fd = fd;
    s->cfg = cfg;
    s->to_server.init(cfg.master_secret, salt);
    s->from_server.init(cfg.master_secret, salt ^ 0xA5A5A5A5A5A5A5A5ULL);

    std::vector<uint8_t> hello(cfg.peer_secret.begin(), cfg.peer_secret.end());
    if (!vortex::send_frame(fd, s->to_server, vortex::CMD_PEER_HELLO, hello,
                            cfg.padding_min, cfg.padding_max)) {
        return false;
    }
    auto ack = vortex::recv_frame(fd, s->from_server, cfg.max_payload);
    if (!ack.ok || ack.cmd != vortex::CMD_CONNECT_OK) {
        std::cerr << "[-] Peer HELLO rejected\n";
        return false;
    }
    std::cout << "[*] Peer registered secret_len=" << cfg.peer_secret.size() << std::endl;
    std::cout.flush();

    // Idle wait for a job (CONNECT). Long idle timeout already set.
    auto job = vortex::recv_frame(fd, s->from_server, cfg.max_payload);
    if (!job.ok) return false;
    if (job.cmd != vortex::CMD_CONNECT) {
        std::cerr << "[-] Peer expected CONNECT job, got cmd=" << static_cast<int>(job.cmd)
                  << "\n";
        return false;
    }
    handle_one_job(s, job.data);
    return true;
}

void worker_loop(PeerConfig cfg, int id) {
    while (g_running) {
        const bool ok = run_peer_session(cfg);
        if (!g_running) break;
        if (!ok) {
            std::this_thread::sleep_for(std::chrono::milliseconds(cfg.reconnect_ms));
        } else {
            // Job finished; immediately reconnect for the next job.
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
        }
        if (ok) {
            // quiet
        } else {
            std::cout << "[*] Peer worker#" << id << " reconnecting...\n";
            std::cout.flush();
        }
    }
}

} // namespace

int main(int argc, char* argv[]) {
    std::string config_path = "config/peer.json";
    if (argc >= 2) config_path = argv[1];

    if (!net_init()) {
        std::cerr << "[-] Network subsystem init failed\n";
        return 1;
    }

    PeerConfig cfg;
    try {
        cfg = PeerConfig::load(config_path);
    } catch (const std::exception& e) {
        std::cerr << "[-] " << e.what() << "\n";
        net_cleanup();
        return 1;
    }

#ifndef _WIN32
    std::signal(SIGPIPE, SIG_IGN);
#endif
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);

    std::cout << "[*] Vortex Peer → " << cfg.server_ip << ":" << cfg.server_port
              << "  workers=" << cfg.workers
              << "  padding=[" << cfg.padding_min << "," << cfg.padding_max << "]"
              << std::endl;
    std::cout.flush();

    std::vector<std::thread> threads;
    threads.reserve(static_cast<size_t>(cfg.workers));
    for (int i = 0; i < cfg.workers; ++i) {
        threads.emplace_back(worker_loop, cfg, i);
    }
    for (auto& t : threads) t.join();

    net_cleanup();
    std::cout << "[*] Peer stopped\n";
    return 0;
}
