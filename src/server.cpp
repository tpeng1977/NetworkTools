#include "config.hpp"
#include "net.hpp"
#include "protocol.hpp"

#include <atomic>
#include <csignal>
#include <iostream>
#include <memory>
#include <string>
#include <thread>

namespace {

std::atomic<bool> g_running{true};
std::atomic<int> g_active_sessions{0};

void on_signal(int) {
    g_running = false;
}

struct SessionGuard {
    std::atomic<int>& counter;
    explicit SessionGuard(std::atomic<int>& c) : counter(c) { ++counter; }
    ~SessionGuard() { --counter; }
};

struct ServerSession {
    socket_t client_fd = INVALID_SOCK;
    socket_t target_fd = INVALID_SOCK;
    std::atomic<bool> alive{true};
    ServerConfig cfg;
    vortex::SessionCrypto up;   // client -> server
    vortex::SessionCrypto down; // server -> client
    std::mutex target_mu;

    ~ServerSession() {
        alive = false;
        if (target_fd != INVALID_SOCK) {
            shutdown_both(target_fd);
            net_close(target_fd);
            target_fd = INVALID_SOCK;
        }
        if (client_fd != INVALID_SOCK) {
            shutdown_both(client_fd);
            net_close(client_fd);
            client_fd = INVALID_SOCK;
        }
    }
};

void relay_target_to_client(std::shared_ptr<ServerSession> s) {
    std::vector<uint8_t> buf(static_cast<size_t>(s->cfg.max_payload));
    while (s->alive && g_running) {
        socket_t tfd;
        {
            std::lock_guard<std::mutex> lock(s->target_mu);
            tfd = s->target_fd;
        }
        if (tfd == INVALID_SOCK) break;

        int n = recv_some(tfd, buf.data(), buf.size());
        if (n <= 0) break;

        if (!vortex::send_frame(s->client_fd, s->down, vortex::CMD_DATA,
                                buf.data(), static_cast<size_t>(n),
                                s->cfg.padding_min, s->cfg.padding_max)) {
            break;
        }
    }
    s->alive = false;
    shutdown_both(s->client_fd);
}

bool handle_connect(std::shared_ptr<ServerSession>& s,
                    const std::vector<uint8_t>& data) {
    std::string host;
    uint16_t port = 0;
    if (!vortex::parse_connect_target(data, host, port)) {
        return false;
    }

    socket_t tfd = tcp_connect(host, port, s->cfg.idle_timeout_sec);
    if (tfd == INVALID_SOCK) {
        vortex::send_frame(s->client_fd, s->down, vortex::CMD_CONNECT_FAIL,
                           nullptr, 0, s->cfg.padding_min, s->cfg.padding_max);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(s->target_mu);
        s->target_fd = tfd;
    }

    if (!vortex::send_frame(s->client_fd, s->down, vortex::CMD_CONNECT_OK,
                            nullptr, 0, s->cfg.padding_min, s->cfg.padding_max)) {
        return false;
    }

    std::cout << "[+] Connected " << host << ":" << port << std::endl;
    std::cout.flush();
    std::thread(relay_target_to_client, s).detach();
    return true;
}

void handle_client(socket_t client_fd, ServerConfig cfg) {
    SessionGuard guard(g_active_sessions);
    auto s = std::make_shared<ServerSession>();
    s->client_fd = client_fd;
    s->cfg = std::move(cfg);

    // Short handshake timeout so probes cannot stall the server.
    set_socket_options(client_fd, 3);

    auto fail_probe = [&]() {
        if (s->cfg.camouflage) vortex::send_http_camouflage(client_fd);
    };

    // 1) Read 8-byte salt
    uint8_t salt_buf[8];
    if (!recv_exact(client_fd, salt_buf, 8)) {
        fail_probe();
        return;
    }
    uint64_t salt = 0;
    std::memcpy(&salt, salt_buf, 8);

    s->up.init(s->cfg.master_secret, salt);
    s->down.init(s->cfg.master_secret, salt ^ 0xA5A5A5A5A5A5A5A5ULL);

    // 2) First frame must be a valid CONNECT (anti-probe gate).
    //    Cap body size so random length fields cannot force huge reads.
    auto first = vortex::recv_frame(client_fd, s->up, s->cfg.max_payload, 512);
    if (!first.ok || first.cmd != vortex::CMD_CONNECT) {
        fail_probe();
        return;
    }

    std::string host;
    uint16_t port = 0;
    if (!vortex::parse_connect_target(first.data, host, port)) {
        fail_probe();
        return;
    }

    // Authenticated: restore normal idle timeout
    set_recv_timeout(client_fd, s->cfg.idle_timeout_sec);

    if (!handle_connect(s, first.data)) {
        return;
    }

    // 3) Relay client -> target
    while (s->alive && g_running) {
        auto frame = vortex::recv_frame(client_fd, s->up, s->cfg.max_payload);
        if (!frame.ok) break;

        if (frame.cmd == vortex::CMD_DATA) {
            socket_t tfd;
            {
                std::lock_guard<std::mutex> lock(s->target_mu);
                tfd = s->target_fd;
            }
            if (tfd == INVALID_SOCK) break;
            if (!frame.data.empty()) {
                if (!send_all(tfd, frame.data.data(), frame.data.size())) break;
            }
        } else if (frame.cmd == vortex::CMD_CLOSE) {
            break;
        } else if (frame.cmd == vortex::CMD_CONNECT) {
            // Only one CONNECT per session
            break;
        } else {
            break;
        }
    }

    s->alive = false;
    {
        std::lock_guard<std::mutex> lock(s->target_mu);
        if (s->target_fd != INVALID_SOCK) {
            shutdown_both(s->target_fd);
        }
    }
    shutdown_both(client_fd);
}

} // namespace

int main(int argc, char* argv[]) {
    std::string config_path = "config/server.json";
    if (argc >= 2) config_path = argv[1];

    if (!net_init()) {
        std::cerr << "[-] Network subsystem init failed\n";
        return 1;
    }

    ServerConfig cfg;
    try {
        cfg = ServerConfig::load(config_path);
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

    socket_t listen_fd = create_listen_socket(cfg.bind_ip, cfg.bind_port, cfg.listen_backlog);
    if (listen_fd == INVALID_SOCK) {
        std::cerr << "[-] Failed to bind " << cfg.bind_ip << ":" << cfg.bind_port << "\n";
        net_cleanup();
        return 1;
    }

    std::cout << "[*] Vortex Shield Server listening on "
              << cfg.bind_ip << ":" << cfg.bind_port << std::endl;
    std::cout << "[*] Camouflage: " << (cfg.camouflage ? "on" : "off")
              << "  padding=[" << cfg.padding_min << "," << cfg.padding_max << "]"
              << std::endl;
    std::cout.flush();

    while (g_running) {
        sockaddr_in peer{};
        socklen_type peer_len = sizeof(peer);
        socket_t client_fd = accept(listen_fd, reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (client_fd == INVALID_SOCK) {
            if (!g_running) break;
            continue;
        }
        if (g_active_sessions.load() >= cfg.max_connections) {
            if (cfg.camouflage) vortex::send_http_camouflage(client_fd);
            net_close(client_fd);
            continue;
        }
        std::thread(handle_client, client_fd, cfg).detach();
    }

    net_close(listen_fd);
    net_cleanup();
    std::cout << "[*] Server stopped\n";
    return 0;
}
