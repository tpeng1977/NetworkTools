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

void on_signal(int) {
    g_running = false;
}

struct ClientSession {
    socket_t local_fd = INVALID_SOCK;
    socket_t remote_fd = INVALID_SOCK;
    std::atomic<bool> alive{true};
    ClientConfig cfg;
    vortex::SessionCrypto up;   // client -> server
    vortex::SessionCrypto down; // server -> client

    ~ClientSession() {
        alive = false;
        if (remote_fd != INVALID_SOCK) {
            shutdown_both(remote_fd);
            net_close(remote_fd);
            remote_fd = INVALID_SOCK;
        }
        if (local_fd != INVALID_SOCK) {
            shutdown_both(local_fd);
            net_close(local_fd);
            local_fd = INVALID_SOCK;
        }
    }
};

bool socks5_handshake_and_build_target(socket_t local_fd,
                                       std::vector<uint8_t>& target_info) {
    uint8_t hdr[2];
    if (!recv_exact(local_fd, hdr, 2)) return false;
    if (hdr[0] != 0x05) return false;
    uint8_t nmethods = hdr[1];
    if (nmethods == 0) return false;
    std::vector<uint8_t> methods(nmethods);
    if (!recv_exact(local_fd, methods.data(), nmethods)) return false;

    // No authentication
    const uint8_t method_ok[2] = {0x05, 0x00};
    if (!send_all(local_fd, method_ok, 2)) return false;

    // Request: VER CMD RSV ATYP ...
    uint8_t req[4];
    if (!recv_exact(local_fd, req, 4)) return false;
    if (req[0] != 0x05 || req[1] != 0x01) { // only CONNECT
        const uint8_t fail[] = {0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        send_all(local_fd, fail, sizeof(fail));
        return false;
    }

    uint8_t atyp = req[3];
    target_info.clear();
    target_info.push_back(atyp);

    if (atyp == vortex::ATYP_IPV4) {
        uint8_t ip[4];
        if (!recv_exact(local_fd, ip, 4)) return false;
        target_info.insert(target_info.end(), ip, ip + 4);
    } else if (atyp == vortex::ATYP_DOMAIN) {
        uint8_t len = 0;
        if (!recv_exact(local_fd, &len, 1)) return false;
        if (len == 0) return false;
        target_info.push_back(len);
        std::vector<uint8_t> domain(len);
        if (!recv_exact(local_fd, domain.data(), len)) return false;
        target_info.insert(target_info.end(), domain.begin(), domain.end());
    } else if (atyp == vortex::ATYP_IPV6) {
        uint8_t ip[16];
        if (!recv_exact(local_fd, ip, 16)) return false;
        target_info.insert(target_info.end(), ip, ip + 16);
    } else {
        const uint8_t fail[] = {0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        send_all(local_fd, fail, sizeof(fail));
        return false;
    }

    uint8_t port_bytes[2];
    if (!recv_exact(local_fd, port_bytes, 2)) return false;
    target_info.insert(target_info.end(), port_bytes, port_bytes + 2);
    return true;
}

void relay_remote_to_local(std::shared_ptr<ClientSession> s) {
    while (s->alive && g_running) {
        auto frame = vortex::recv_frame(s->remote_fd, s->down, s->cfg.max_payload);
        if (!frame.ok) break;

        if (frame.cmd == vortex::CMD_DATA) {
            if (!frame.data.empty()) {
                if (!send_all(s->local_fd, frame.data.data(), frame.data.size())) break;
            }
        } else if (frame.cmd == vortex::CMD_CLOSE) {
            break;
        } else {
            break;
        }
    }
    s->alive = false;
    shutdown_both(s->local_fd);
    shutdown_both(s->remote_fd);
}

void handle_socks5(socket_t local_fd, ClientConfig cfg) {
    auto s = std::make_shared<ClientSession>();
    s->local_fd = local_fd;
    s->cfg = std::move(cfg);
    set_socket_options(local_fd, s->cfg.idle_timeout_sec);

    std::vector<uint8_t> target_info;
    if (!socks5_handshake_and_build_target(local_fd, target_info)) {
        return;
    }

    socket_t remote_fd = tcp_connect(s->cfg.server_ip, s->cfg.server_port,
                                     s->cfg.idle_timeout_sec);
    if (remote_fd == INVALID_SOCK) {
        const uint8_t fail[] = {0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        send_all(local_fd, fail, sizeof(fail));
        return;
    }
    s->remote_fd = remote_fd;

    // Salt + directional key separation (down uses salt XOR constant)
    uint64_t salt = get_random_salt();
    uint8_t salt_buf[8];
    std::memcpy(salt_buf, &salt, 8);
    if (!send_all(remote_fd, salt_buf, 8)) {
        const uint8_t fail[] = {0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        send_all(local_fd, fail, sizeof(fail));
        return;
    }

    s->up.init(s->cfg.master_secret, salt);
    s->down.init(s->cfg.master_secret, salt ^ 0xA5A5A5A5A5A5A5A5ULL);

    if (!vortex::send_frame(remote_fd, s->up, vortex::CMD_CONNECT,
                            target_info, s->cfg.padding_min, s->cfg.padding_max)) {
        const uint8_t fail[] = {0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        send_all(local_fd, fail, sizeof(fail));
        return;
    }

    auto reply = vortex::recv_frame(remote_fd, s->down, s->cfg.max_payload);
    if (!reply.ok || reply.cmd != vortex::CMD_CONNECT_OK) {
        const uint8_t fail[] = {0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        send_all(local_fd, fail, sizeof(fail));
        return;
    }

    const uint8_t success[] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    if (!send_all(local_fd, success, sizeof(success))) return;

    std::thread(relay_remote_to_local, s).detach();

    std::vector<uint8_t> buf(static_cast<size_t>(s->cfg.max_payload));
    while (s->alive && g_running) {
        int n = recv_some(local_fd, buf.data(), buf.size());
        if (n <= 0) break;
        if (!vortex::send_frame(remote_fd, s->up, vortex::CMD_DATA,
                                buf.data(), static_cast<size_t>(n),
                                s->cfg.padding_min, s->cfg.padding_max)) {
            break;
        }
    }

    s->alive = false;
    vortex::send_frame(remote_fd, s->up, vortex::CMD_CLOSE,
                       nullptr, 0, s->cfg.padding_min, s->cfg.padding_max);
    shutdown_both(local_fd);
    shutdown_both(remote_fd);
}

} // namespace

int main(int argc, char* argv[]) {
    std::string config_path = "config/client.json";
    if (argc >= 2) config_path = argv[1];

    if (!net_init()) {
        std::cerr << "[-] Network subsystem init failed\n";
        return 1;
    }

    ClientConfig cfg;
    try {
        cfg = ClientConfig::load(config_path);
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

    socket_t listen_fd = create_listen_socket(
        cfg.socks5_bind_ip, cfg.socks5_bind_port, cfg.listen_backlog);
    if (listen_fd == INVALID_SOCK) {
        std::cerr << "[-] Failed to bind SOCKS5 "
                  << cfg.socks5_bind_ip << ":" << cfg.socks5_bind_port << "\n";
        net_cleanup();
        return 1;
    }

    std::cout << "[*] Vortex SOCKS5 Client on "
              << cfg.socks5_bind_ip << ":" << cfg.socks5_bind_port << std::endl;
    std::cout << "[*] Upstream " << cfg.server_ip << ":" << cfg.server_port
              << "  padding=[" << cfg.padding_min << "," << cfg.padding_max << "]"
              << std::endl;
    std::cout.flush();

    while (g_running) {
        sockaddr_in peer{};
        socklen_type peer_len = sizeof(peer);
        socket_t local_fd = accept(listen_fd, reinterpret_cast<sockaddr*>(&peer), &peer_len);
        if (local_fd == INVALID_SOCK) {
            if (!g_running) break;
            continue;
        }
        std::thread(handle_socks5, local_fd, cfg).detach();
    }

    net_close(listen_fd);
    net_cleanup();
    std::cout << "[*] Client stopped\n";
    return 0;
}
