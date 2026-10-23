#include "config.hpp"
#include "net.hpp"
#include "protocol.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {

std::atomic<bool> g_running{true};
std::atomic<int> g_active_sessions{0};

void on_signal(int) { g_running = false; }

struct SessionGuard {
    std::atomic<int>& counter;
    explicit SessionGuard(std::atomic<int>& c) : counter(c) { ++counter; }
    ~SessionGuard() { --counter; }
};

// Long-lived peer worker waiting for VIA_PEER jobs.
struct PeerConn {
    socket_t fd = INVALID_SOCK;
    vortex::SessionCrypto up;   // decrypt peer → server
    vortex::SessionCrypto down; // encrypt server → peer
    ServerConfig cfg;
    std::string secret;
    std::atomic<bool> alive{true};
    std::mutex mu;
    bool busy = false;

    ~PeerConn() {
        alive = false;
        if (fd != INVALID_SOCK) {
            shutdown_both(fd);
            net_close(fd);
            fd = INVALID_SOCK;
        }
    }
};

std::mutex g_peer_mu;
std::unordered_map<std::string, std::vector<std::shared_ptr<PeerConn>>> g_peers;
std::condition_variable g_peer_cv;

void unregister_peer(const std::shared_ptr<PeerConn>& p) {
    if (!p) return;
    std::lock_guard<std::mutex> lock(g_peer_mu);
    auto it = g_peers.find(p->secret);
    if (it == g_peers.end()) return;
    auto& vec = it->second;
    vec.erase(std::remove_if(vec.begin(), vec.end(),
                             [&](const std::shared_ptr<PeerConn>& x) { return x == p; }),
              vec.end());
    if (vec.empty()) g_peers.erase(it);
    g_peer_cv.notify_all();
}

std::shared_ptr<PeerConn> acquire_peer(const std::string& secret, int wait_ms) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(wait_ms);
    std::unique_lock<std::mutex> lock(g_peer_mu);
    while (g_running) {
        auto it = g_peers.find(secret);
        if (it != g_peers.end()) {
            for (auto& p : it->second) {
                if (p && p->alive && !p->busy && p->fd != INVALID_SOCK) {
                    p->busy = true;
                    return p;
                }
            }
        }
        if (wait_ms <= 0) return nullptr;
        if (g_peer_cv.wait_until(lock, deadline) == std::cv_status::timeout) {
            return nullptr;
        }
    }
    return nullptr;
}

void release_peer(const std::shared_ptr<PeerConn>& p, bool /*drop*/) {
    if (!p) return;
    {
        std::lock_guard<std::mutex> lock(p->mu);
        p->busy = false;
    }
    // Workers are one-shot: after a job (or failure) remove from the idle pool.
    unregister_peer(p);
    g_peer_cv.notify_all();
}

struct ServerSession {
    socket_t client_fd = INVALID_SOCK;
    socket_t target_fd = INVALID_SOCK;
    std::atomic<bool> alive{true};
    ServerConfig cfg;
    vortex::SessionCrypto up;   // client -> server
    vortex::SessionCrypto down; // server -> client
    std::mutex target_mu;
    std::shared_ptr<PeerConn> peer; // when relaying via peer

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
        if (peer) {
            release_peer(peer, true);
            peer.reset();
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

void relay_peer_to_client(std::shared_ptr<ServerSession> s, std::shared_ptr<PeerConn> peer) {
    while (s->alive && peer->alive && g_running) {
        auto frame = vortex::recv_frame(peer->fd, peer->up, s->cfg.max_payload);
        if (!frame.ok) break;
        if (frame.cmd == vortex::CMD_DATA) {
            if (!frame.data.empty()) {
                if (!vortex::send_frame(s->client_fd, s->down, vortex::CMD_DATA,
                                        frame.data, s->cfg.padding_min, s->cfg.padding_max)) {
                    break;
                }
            }
        } else if (frame.cmd == vortex::CMD_CLOSE) {
            break;
        } else if (frame.cmd == vortex::CMD_CONNECT_FAIL) {
            break;
        } else {
            break;
        }
    }
    s->alive = false;
    peer->alive = false;
    shutdown_both(s->client_fd);
}

bool handle_connect_direct(std::shared_ptr<ServerSession>& s,
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

bool handle_via_peer(std::shared_ptr<ServerSession>& s, const std::vector<uint8_t>& data) {
    std::string secret;
    std::vector<uint8_t> target_wire;
    if (!vortex::parse_via_peer_payload(data, secret, target_wire)) {
        vortex::send_frame(s->client_fd, s->down, vortex::CMD_CONNECT_FAIL,
                           nullptr, 0, s->cfg.padding_min, s->cfg.padding_max);
        return false;
    }

    std::string host;
    uint16_t port = 0;
    if (!vortex::parse_connect_target(target_wire, host, port)) {
        vortex::send_frame(s->client_fd, s->down, vortex::CMD_CONNECT_FAIL,
                           nullptr, 0, s->cfg.padding_min, s->cfg.padding_max);
        return false;
    }

    auto peer = acquire_peer(secret, 8000);
    if (!peer) {
        std::cout << "[-] No peer for secret (target " << host << ":" << port << ")\n";
        std::cout.flush();
        vortex::send_frame(s->client_fd, s->down, vortex::CMD_CONNECT_FAIL,
                           nullptr, 0, s->cfg.padding_min, s->cfg.padding_max);
        return false;
    }
    s->peer = peer;

    if (!vortex::send_frame(peer->fd, peer->down, vortex::CMD_CONNECT, target_wire,
                            s->cfg.padding_min, s->cfg.padding_max)) {
        release_peer(peer, true);
        s->peer.reset();
        vortex::send_frame(s->client_fd, s->down, vortex::CMD_CONNECT_FAIL,
                           nullptr, 0, s->cfg.padding_min, s->cfg.padding_max);
        return false;
    }

    auto reply = vortex::recv_frame(peer->fd, peer->up, s->cfg.max_payload);
    if (!reply.ok || reply.cmd != vortex::CMD_CONNECT_OK) {
        release_peer(peer, true);
        s->peer.reset();
        vortex::send_frame(s->client_fd, s->down, vortex::CMD_CONNECT_FAIL,
                           nullptr, 0, s->cfg.padding_min, s->cfg.padding_max);
        return false;
    }

    if (!vortex::send_frame(s->client_fd, s->down, vortex::CMD_CONNECT_OK,
                            nullptr, 0, s->cfg.padding_min, s->cfg.padding_max)) {
        release_peer(peer, true);
        s->peer.reset();
        return false;
    }

    std::cout << "[+] Via-peer " << host << ":" << port << std::endl;
    std::cout.flush();
    std::thread(relay_peer_to_client, s, peer).detach();
    return true;
}

void handle_peer_hello(socket_t fd, ServerConfig cfg, uint64_t salt,
                       const std::vector<uint8_t>& hello_data,
                       vortex::SessionCrypto& up_already,
                       vortex::SessionCrypto& down_already) {
    if (hello_data.empty() || hello_data.size() > 255) {
        if (cfg.camouflage) vortex::send_http_camouflage(fd);
        net_close(fd);
        return;
    }
    const std::string secret(reinterpret_cast<const char*>(hello_data.data()), hello_data.size());

    auto peer = std::make_shared<PeerConn>();
    peer->fd = fd;
    peer->cfg = cfg;
    peer->secret = secret;
    // Reuse cipher+seq from the HELLO decrypt — a fresh init() would desync seq.
    peer->up.init(cfg.master_secret, salt);
    peer->down.init(cfg.master_secret, salt ^ 0xA5A5A5A5A5A5A5A5ULL);
    {
        std::lock_guard<std::mutex> lock(up_already.mu);
        peer->up.seq = up_already.seq;
    }
    {
        std::lock_guard<std::mutex> lock(down_already.mu);
        peer->down.seq = down_already.seq;
    }

    set_recv_timeout(fd, cfg.idle_timeout_sec);

    if (!vortex::send_frame(fd, peer->down, vortex::CMD_CONNECT_OK, nullptr, 0,
                            cfg.padding_min, cfg.padding_max)) {
        return;
    }

    {
        std::lock_guard<std::mutex> lock(g_peer_mu);
        g_peers[secret].push_back(peer);
    }
    g_peer_cv.notify_all();
    size_t pool_n = 0;
    {
        std::lock_guard<std::mutex> lock(g_peer_mu);
        pool_n = g_peers[secret].size();
    }
    std::cout << "[*] Peer online secret_len=" << secret.size() << " pool=" << pool_n
              << std::endl;
    std::cout.flush();

    // Idle until VIA_PEER acquires this worker (sets busy) or the peer drops.
    // Do not read frames here — that would race the job handler.
    while (g_running && peer->alive) {
        bool busy = false;
        {
            std::lock_guard<std::mutex> lock(peer->mu);
            busy = peer->busy;
        }
        if (busy) {
            // Job handler owns I/O until it marks !alive / release_peer.
            while (g_running && peer->alive) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }
    unregister_peer(peer);
    std::cout << "[*] Peer offline secret_len=" << secret.size() << std::endl;
    std::cout.flush();
}

void handle_client(socket_t client_fd, ServerConfig cfg) {
    SessionGuard guard(g_active_sessions);
    auto s = std::make_shared<ServerSession>();
    s->client_fd = client_fd;
    s->cfg = std::move(cfg);

    set_socket_options(client_fd, 3);

    auto fail_probe = [&]() {
        if (s->cfg.camouflage) vortex::send_http_camouflage(client_fd);
    };

    uint8_t salt_buf[8];
    if (!recv_exact(client_fd, salt_buf, 8)) {
        fail_probe();
        return;
    }
    uint64_t salt = 0;
    std::memcpy(&salt, salt_buf, 8);

    s->up.init(s->cfg.master_secret, salt);
    s->down.init(s->cfg.master_secret, salt ^ 0xA5A5A5A5A5A5A5A5ULL);

    auto first = vortex::recv_frame(client_fd, s->up, s->cfg.max_payload, 768);
    if (!first.ok) {
        fail_probe();
        return;
    }

    // Peer registration path (does not count as a normal client relay).
    if (first.cmd == vortex::CMD_PEER_HELLO) {
        // Transfer ownership of fd to peer handler; clear so destructor won't double-close.
        s->client_fd = INVALID_SOCK;
        handle_peer_hello(client_fd, s->cfg, salt, first.data, s->up, s->down);
        return;
    }

    if (first.cmd == vortex::CMD_CONNECT) {
        std::string host;
        uint16_t port = 0;
        if (!vortex::parse_connect_target(first.data, host, port)) {
            fail_probe();
            return;
        }
        set_recv_timeout(client_fd, s->cfg.idle_timeout_sec);
        if (!handle_connect_direct(s, first.data)) return;

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
            } else {
                break;
            }
        }
        s->alive = false;
        {
            std::lock_guard<std::mutex> lock(s->target_mu);
            if (s->target_fd != INVALID_SOCK) shutdown_both(s->target_fd);
        }
        shutdown_both(client_fd);
        return;
    }

    if (first.cmd == vortex::CMD_VIA_PEER) {
        set_recv_timeout(client_fd, s->cfg.idle_timeout_sec);
        if (!handle_via_peer(s, first.data)) return;

        auto peer = s->peer;
        while (s->alive && g_running && peer && peer->alive) {
            auto frame = vortex::recv_frame(client_fd, s->up, s->cfg.max_payload);
            if (!frame.ok) break;
            if (frame.cmd == vortex::CMD_DATA) {
                if (!frame.data.empty()) {
                    if (!vortex::send_frame(peer->fd, peer->down, vortex::CMD_DATA,
                                            frame.data, s->cfg.padding_min,
                                            s->cfg.padding_max)) {
                        break;
                    }
                }
            } else if (frame.cmd == vortex::CMD_CLOSE) {
                vortex::send_frame(peer->fd, peer->down, vortex::CMD_CLOSE, nullptr, 0,
                                   s->cfg.padding_min, s->cfg.padding_max);
                break;
            } else {
                break;
            }
        }
        s->alive = false;
        if (peer) {
            peer->alive = false;
            shutdown_both(peer->fd);
            release_peer(peer, true);
            s->peer.reset();
        }
        shutdown_both(client_fd);
        return;
    }

    fail_probe();
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

    std::cout << "[*] Vortex Shield Server listening on " << cfg.bind_ip << ":" << cfg.bind_port
              << std::endl;
    std::cout << "[*] Camouflage: " << (cfg.camouflage ? "on" : "off")
              << "  padding=[" << cfg.padding_min << "," << cfg.padding_max << "]"
              << "  peer-relay=on" << std::endl;
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
