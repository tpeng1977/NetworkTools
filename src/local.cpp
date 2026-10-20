#include "config.hpp"
#include "net.hpp"
#include "protocol.hpp"

#include <atomic>
#include <csignal>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace {

std::atomic<bool> g_running{true};

void on_signal(int) {
    g_running = false;
}

struct Session {
    socket_t local_fd = INVALID_SOCK;
    socket_t remote_fd = INVALID_SOCK;
    std::atomic<bool> alive{true};
    LocalConfig cfg;

    ~Session() {
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

struct SocksTarget {
    std::string host;
    uint16_t port = 0;
};

bool socks5_read_target(socket_t local_fd, SocksTarget& t) {
    uint8_t hdr[2];
    if (!recv_exact(local_fd, hdr, 2)) return false;
    if (hdr[0] != 0x05) return false;
    const uint8_t nmethods = hdr[1];
    if (nmethods == 0) return false;
    std::vector<uint8_t> methods(nmethods);
    if (!recv_exact(local_fd, methods.data(), nmethods)) return false;

    const uint8_t method_ok[2] = {0x05, 0x00};
    if (!send_all(local_fd, method_ok, 2)) return false;

    uint8_t req[4];
    if (!recv_exact(local_fd, req, 4)) return false;
    if (req[0] != 0x05 || req[1] != 0x01) {
        const uint8_t fail[] = {0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        send_all(local_fd, fail, sizeof(fail));
        return false;
    }

    const uint8_t atyp = req[3];
    if (atyp == vortex::ATYP_IPV4) {
        uint8_t ip[4];
        if (!recv_exact(local_fd, ip, 4)) return false;
        char buf[INET_ADDRSTRLEN] = {};
        in_addr a{};
        std::memcpy(&a.s_addr, ip, 4);
        inet_ntop(AF_INET, &a, buf, sizeof(buf));
        t.host = buf;
    } else if (atyp == vortex::ATYP_DOMAIN) {
        uint8_t len = 0;
        if (!recv_exact(local_fd, &len, 1)) return false;
        if (len == 0) return false;
        std::vector<uint8_t> domain(len);
        if (!recv_exact(local_fd, domain.data(), len)) return false;
        t.host.assign(reinterpret_cast<char*>(domain.data()), domain.size());
    } else if (atyp == vortex::ATYP_IPV6) {
        uint8_t ip[16];
        if (!recv_exact(local_fd, ip, 16)) return false;
        char buf[INET6_ADDRSTRLEN] = {};
        inet_ntop(AF_INET6, ip, buf, sizeof(buf));
        t.host = buf;
    } else {
        const uint8_t fail[] = {0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        send_all(local_fd, fail, sizeof(fail));
        return false;
    }

    uint8_t port_bytes[2];
    if (!recv_exact(local_fd, port_bytes, 2)) return false;
    t.port = static_cast<uint16_t>((port_bytes[0] << 8) | port_bytes[1]);
    return true;
}

void reply_socks_fail(socket_t fd, uint8_t code) {
    const uint8_t fail[] = {0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    send_all(fd, fail, sizeof(fail));
}

bool reply_socks_ok(socket_t fd) {
    const uint8_t success[] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
    return send_all(fd, success, sizeof(success));
}

void relay_raw(socket_t from, socket_t to, std::shared_ptr<Session> s) {
    std::vector<uint8_t> buf(static_cast<size_t>(s->cfg.max_payload));
    while (s->alive && g_running) {
        const int n = recv_some(from, buf.data(), buf.size());
        if (n <= 0) break;
        if (!send_all(to, buf.data(), static_cast<size_t>(n))) break;
    }
    s->alive = false;
    shutdown_both(s->local_fd);
    shutdown_both(s->remote_fd);
}

void handle_socks5(socket_t local_fd, LocalConfig cfg) {
    auto s = std::make_shared<Session>();
    s->local_fd = local_fd;
    s->cfg = std::move(cfg);
    set_socket_options(local_fd, s->cfg.idle_timeout_sec);

    SocksTarget target;
    if (!socks5_read_target(local_fd, target)) return;

    socket_t remote_fd = tcp_connect(target.host, static_cast<int>(target.port),
                                     s->cfg.idle_timeout_sec);
    if (remote_fd == INVALID_SOCK) {
        reply_socks_fail(local_fd, 0x05);
        return;
    }
    s->remote_fd = remote_fd;

    if (!reply_socks_ok(local_fd)) return;

    std::thread(relay_raw, s->remote_fd, local_fd, s).detach();
    relay_raw(local_fd, s->remote_fd, s);

    shutdown_both(local_fd);
    shutdown_both(s->remote_fd);
}

} // namespace

int main(int argc, char* argv[]) {
    std::string config_path = "config/local.json";
    if (argc >= 2) config_path = argv[1];

    if (!net_init()) {
        std::cerr << "[-] Network subsystem init failed\n";
        return 1;
    }

    LocalConfig cfg;
    try {
        cfg = LocalConfig::load(config_path);
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

    std::cout << "[*] Local SOCKS5 on "
              << cfg.socks5_bind_ip << ":" << cfg.socks5_bind_port
              << "  (direct, no tunnel)" << std::endl;
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
    std::cout << "[*] Local SOCKS5 stopped\n";
    return 0;
}
