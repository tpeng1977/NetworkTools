// Peer: dials into Vortex server, registers with peer_secret, and exits traffic
// for CMD_VIA_PEER sessions (multilink → server → peer → target).
//
// Optional SSH-style port forwards from peer.json:
//   to_remote ≈ ssh -R : server listens on remote_*; peer dials local_* (CONNECT jobs)
//   to_local  ≈ ssh -L : peer listens on local_*; opens CONNECT to server for remote_*
// TCP and UDP both supported. One TCP registration handles many sequential jobs.

#include "config.hpp"
#include "net.hpp"
#include "port_forward.hpp"
#include "protocol.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#ifndef _WIN32
#  include <poll.h>
#endif

namespace {

#ifdef _WIN32
using pollfd_t = WSAPOLLFD;
using nfds_count_t = ULONG;
inline int vortex_poll(pollfd_t* fds, nfds_count_t nfds, int timeout_ms) {
    return WSAPoll(fds, nfds, timeout_ms);
}
#else
using pollfd_t = pollfd;
using nfds_count_t = nfds_t;
inline int vortex_poll(pollfd_t* fds, nfds_count_t nfds, int timeout_ms) {
    return ::poll(fds, nfds, timeout_ms);
}
#endif

std::atomic<bool> g_running{true};
std::atomic<int> g_fwd_conns{0};

void on_signal(int) { g_running = false; }

struct LoadedForwards {
    vortex::PortForwardSpec to_remote;
    vortex::PortForwardSpec to_local;
};

LoadedForwards load_forwards(const PeerConfig& cfg) {
    LoadedForwards f;
    if (!cfg.to_remote_json.empty()) {
        f.to_remote = vortex::parse_to_remote_object(cfg.to_remote_json);
    }
    if (!cfg.to_local_json.empty()) {
        f.to_local = vortex::parse_to_local_object(cfg.to_local_json);
    }
    return f;
}

struct PeerSession {
    socket_t server_fd = INVALID_SOCK;
    PeerConfig cfg;
    vortex::SessionCrypto to_server;
    vortex::SessionCrypto from_server;

    ~PeerSession() {
        if (server_fd != INVALID_SOCK) {
            shutdown_both(server_fd);
            net_close(server_fd);
            server_fd = INVALID_SOCK;
        }
    }
};

struct JobState {
    socket_t target_fd = INVALID_SOCK;
    std::atomic<bool> alive{true};
    std::atomic<bool> close_sent{false};
};

void relay_target_to_server(std::shared_ptr<PeerSession> s, std::shared_ptr<JobState> job) {
    std::vector<uint8_t> buf(static_cast<size_t>(s->cfg.max_payload));
    while (job->alive && g_running) {
        if (job->target_fd == INVALID_SOCK) break;
        const int n = recv_some(job->target_fd, buf.data(), buf.size());
        if (n <= 0) break;
        if (!vortex::send_frame(s->server_fd, s->to_server, vortex::CMD_DATA,
                                buf.data(), static_cast<size_t>(n),
                                s->cfg.padding_min, s->cfg.padding_max)) {
            break;
        }
    }
    job->alive = false;
    if (!job->close_sent.exchange(true)) {
        vortex::send_frame(s->server_fd, s->to_server, vortex::CMD_CLOSE, nullptr, 0,
                           s->cfg.padding_min, s->cfg.padding_max);
    }
    if (job->target_fd != INVALID_SOCK) {
        shutdown_both(job->target_fd);
    }
}

bool handle_one_job(std::shared_ptr<PeerSession> s, const std::vector<uint8_t>& connect_data) {
    std::string host;
    uint16_t port = 0;
    if (!vortex::parse_connect_target(connect_data, host, port)) {
        vortex::send_frame(s->server_fd, s->to_server, vortex::CMD_CONNECT_FAIL,
                           nullptr, 0, s->cfg.padding_min, s->cfg.padding_max);
        return true;
    }

    socket_t tfd = tcp_connect(host, static_cast<int>(port), s->cfg.idle_timeout_sec);
    if (tfd == INVALID_SOCK) {
        vortex::send_frame(s->server_fd, s->to_server, vortex::CMD_CONNECT_FAIL,
                           nullptr, 0, s->cfg.padding_min, s->cfg.padding_max);
        std::cout << "[-] Peer connect failed " << host << ":" << port << std::endl;
        std::cout.flush();
        return true;
    }

    auto job = std::make_shared<JobState>();
    job->target_fd = tfd;

    if (!vortex::send_frame(s->server_fd, s->to_server, vortex::CMD_CONNECT_OK,
                            nullptr, 0, s->cfg.padding_min, s->cfg.padding_max)) {
        net_close(tfd);
        job->target_fd = INVALID_SOCK;
        return false;
    }
    std::cout << "[+] Peer exit " << host << ":" << port << std::endl;
    std::cout.flush();

    std::thread up_relay(relay_target_to_server, s, job);

    bool control_ok = true;
    bool got_server_close = false;
    while (job->alive && g_running) {
        pollfd_t pfd{};
        pfd.fd = s->server_fd;
        pfd.events = POLLIN;
        const int sel = vortex_poll(&pfd, 1, 50);
        if (!job->alive) break;
        if (sel < 0) {
            if (net_would_block(net_errno())) continue;
            control_ok = false;
            break;
        }
        if (sel == 0) continue;

        auto frame = vortex::recv_frame(s->server_fd, s->from_server, s->cfg.max_payload);
        if (!frame.ok) {
            control_ok = false;
            break;
        }
        if (frame.cmd == vortex::CMD_DATA) {
            if (!frame.data.empty()) {
                if (!send_all(job->target_fd, frame.data.data(), frame.data.size())) break;
            }
        } else if (frame.cmd == vortex::CMD_CLOSE) {
            got_server_close = true;
            break;
        } else {
            control_ok = false;
            break;
        }
    }

    job->alive = false;
    if (job->target_fd != INVALID_SOCK) shutdown_both(job->target_fd);
    if (up_relay.joinable()) up_relay.join();
    if (job->target_fd != INVALID_SOCK) {
        net_close(job->target_fd);
        job->target_fd = INVALID_SOCK;
    }

    if (control_ok && !got_server_close && g_running) {
        set_recv_timeout(s->server_fd, 10);
        for (;;) {
            auto fin = vortex::recv_frame(s->server_fd, s->from_server, s->cfg.max_payload);
            if (!fin.ok) {
                set_recv_timeout(s->server_fd, s->cfg.idle_timeout_sec);
                return false;
            }
            if (fin.cmd == vortex::CMD_CLOSE) break;
            if (fin.cmd == vortex::CMD_DATA) continue;
            std::cerr << "[-] Peer expected job-end CLOSE, got cmd="
                      << static_cast<int>(fin.cmd) << "\n";
            set_recv_timeout(s->server_fd, s->cfg.idle_timeout_sec);
            return false;
        }
        set_recv_timeout(s->server_fd, s->cfg.idle_timeout_sec);
    }
    return control_ok;
}

bool send_fwd_config(socket_t fd, vortex::SessionCrypto& crypto, const PeerConfig& cfg,
                     const LoadedForwards& fwd, uint8_t flags) {
    uint8_t f = flags;
    if (cfg.enable_udp) f = static_cast<uint8_t>(f | vortex::FWD_FLAG_UDP);
    auto payload = vortex::build_fwd_config_payload(fwd.to_remote, fwd.to_local, f);
    return vortex::send_frame(fd, crypto, vortex::CMD_FWD_CONFIG, payload, cfg.padding_min,
                              cfg.padding_max);
}

bool run_peer_session(const PeerConfig& cfg, const LoadedForwards& fwd) {
    socket_t fd = tcp_connect(cfg.server_ip, cfg.server_port, cfg.idle_timeout_sec);
    if (fd == INVALID_SOCK) {
        std::cerr << "[-] Peer cannot reach server " << cfg.server_ip << ":" << cfg.server_port
                  << "\n";
        return false;
    }
    set_socket_options(fd, cfg.idle_timeout_sec);
    set_tcp_keepalive(fd, 60, 10, 3);

    uint64_t salt = get_random_salt();
    uint8_t salt_buf[8];
    std::memcpy(salt_buf, &salt, 8);
    if (!send_all(fd, salt_buf, 8)) {
        net_close(fd);
        return false;
    }

    auto s = std::make_shared<PeerSession>();
    s->server_fd = fd;
    s->cfg = cfg;
    s->to_server.init(cfg.master_secret, salt);
    s->from_server.init(cfg.master_secret, salt ^ 0xA5A5A5A5A5A5A5A5ULL);

    std::vector<uint8_t> hello(cfg.peer_secret.begin(), cfg.peer_secret.end());
    if (!vortex::send_frame(fd, s->to_server, vortex::CMD_PEER_HELLO, hello, cfg.padding_min,
                            cfg.padding_max)) {
        return false;
    }
    auto ack = vortex::recv_frame(fd, s->from_server, cfg.max_payload);
    if (!ack.ok || ack.cmd != vortex::CMD_CONNECT_OK) {
        std::cerr << "[-] Peer HELLO rejected\n";
        return false;
    }
    if (!send_fwd_config(fd, s->to_server, cfg, fwd, 0)) {
        std::cerr << "[-] Peer FWD_CONFIG send failed\n";
        return false;
    }
    std::cout << "[*] Peer registered secret_len=" << cfg.peer_secret.size() << std::endl;
    std::cout.flush();

    const int job_wait_sec =
        cfg.idle_timeout_sec > 0 ? (std::min)(90, cfg.idle_timeout_sec) : 90;

    while (g_running) {
        set_recv_timeout(fd, job_wait_sec);
        auto job = vortex::recv_frame(fd, s->from_server, cfg.max_payload);
        set_recv_timeout(fd, cfg.idle_timeout_sec);
        if (!job.ok) return false;
        if (job.cmd != vortex::CMD_CONNECT) {
            std::cerr << "[-] Peer expected CONNECT job, got cmd=" << static_cast<int>(job.cmd)
                      << "\n";
            return false;
        }
        if (!handle_one_job(s, job.data)) return false;
    }
    return true;
}

void worker_loop(PeerConfig cfg, LoadedForwards fwd, int id) {
    while (g_running) {
        const bool ok = run_peer_session(cfg, fwd);
        if (!g_running) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(cfg.reconnect_ms));
        std::cout << "[*] Peer worker#" << id << (ok ? " refresh" : " reconnect") << "...\n";
        std::cout.flush();
    }
}

// ---- to_local TCP (ssh -L) ----

struct TunnelSession {
    socket_t local_fd = INVALID_SOCK;
    socket_t remote_fd = INVALID_SOCK;
    PeerConfig cfg;
    vortex::SessionCrypto up;
    vortex::SessionCrypto down;
    std::atomic<bool> alive{true};

    ~TunnelSession() {
        alive = false;
        if (local_fd != INVALID_SOCK) {
            shutdown_both(local_fd);
            net_close(local_fd);
            local_fd = INVALID_SOCK;
        }
        if (remote_fd != INVALID_SOCK) {
            shutdown_both(remote_fd);
            net_close(remote_fd);
            remote_fd = INVALID_SOCK;
        }
    }
};

void relay_remote_to_local(std::shared_ptr<TunnelSession> s) {
    while (s->alive && g_running) {
        auto frame = vortex::recv_frame(s->remote_fd, s->down, s->cfg.max_payload);
        if (!frame.ok) break;
        if (frame.cmd == vortex::CMD_DATA) {
            if (!frame.data.empty() &&
                !send_all(s->local_fd, frame.data.data(), frame.data.size())) {
                break;
            }
        } else if (frame.cmd == vortex::CMD_CLOSE) {
            break;
        } else {
            break;
        }
    }
    s->alive = false;
    shutdown_both(s->local_fd);
}

void handle_to_local_tcp_client(socket_t local_fd, PeerConfig cfg, std::string target_host,
                                uint16_t target_port) {
    struct ConnGuard {
        ~ConnGuard() { --g_fwd_conns; }
    } guard;

    auto s = std::make_shared<TunnelSession>();
    s->local_fd = local_fd;
    s->cfg = std::move(cfg);
    set_socket_options(local_fd, s->cfg.idle_timeout_sec);

    socket_t remote_fd =
        tcp_connect(s->cfg.server_ip, s->cfg.server_port, s->cfg.idle_timeout_sec);
    if (remote_fd == INVALID_SOCK) return;
    s->remote_fd = remote_fd;
    set_socket_options(remote_fd, s->cfg.idle_timeout_sec);

    uint64_t salt = get_random_salt();
    uint8_t salt_buf[8];
    std::memcpy(salt_buf, &salt, 8);
    if (!send_all(remote_fd, salt_buf, 8)) return;

    s->up.init(s->cfg.master_secret, salt);
    s->down.init(s->cfg.master_secret, salt ^ 0xA5A5A5A5A5A5A5A5ULL);

    auto wire = vortex::build_connect_target_host(target_host, target_port);
    if (wire.empty()) return;
    if (!vortex::send_frame(remote_fd, s->up, vortex::CMD_CONNECT, wire, s->cfg.padding_min,
                            s->cfg.padding_max)) {
        return;
    }
    auto reply = vortex::recv_frame(remote_fd, s->down, s->cfg.max_payload);
    if (!reply.ok || reply.cmd != vortex::CMD_CONNECT_OK) {
        std::cout << "[-] to_local CONNECT fail " << target_host << ":" << target_port << "\n";
        std::cout.flush();
        return;
    }
    std::cout << "[+] to_local TCP → " << target_host << ":" << target_port << std::endl;
    std::cout.flush();

    std::thread(relay_remote_to_local, s).detach();
    std::vector<uint8_t> buf(static_cast<size_t>(s->cfg.max_payload));
    while (s->alive && g_running) {
        const int n = recv_some(local_fd, buf.data(), buf.size());
        if (n <= 0) break;
        if (!vortex::send_frame(remote_fd, s->up, vortex::CMD_DATA, buf.data(),
                                static_cast<size_t>(n), s->cfg.padding_min,
                                s->cfg.padding_max)) {
            break;
        }
    }
    s->alive = false;
    vortex::send_frame(remote_fd, s->up, vortex::CMD_CLOSE, nullptr, 0, s->cfg.padding_min,
                       s->cfg.padding_max);
    shutdown_both(local_fd);
    shutdown_both(remote_fd);
}

void to_local_tcp_accept_loop(socket_t listen_fd, PeerConfig cfg, std::string target_host,
                              uint16_t target_port) {
    while (g_running) {
        pollfd_t pfd{};
        pfd.fd = listen_fd;
        pfd.events = POLLIN;
        const int sel = vortex_poll(&pfd, 1, 200);
        if (sel < 0) {
            if (net_would_block(net_errno())) continue;
            break;
        }
        if (sel == 0) continue;
        sockaddr_in peer{};
        socklen_type plen = sizeof(peer);
        // Back-pressure: do not accept when at cap (avoids accept-then-RST which
        // looks like a successful connect followed by a mysterious short read).
        if (g_fwd_conns.load() >= cfg.forward_max_conns) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }
        socket_t c = accept(listen_fd, reinterpret_cast<sockaddr*>(&peer), &plen);
        if (c == INVALID_SOCK) continue;
        if (g_fwd_conns.load() >= cfg.forward_max_conns) {
            net_close(c);
            continue;
        }
        ++g_fwd_conns;
        std::thread(handle_to_local_tcp_client, c, cfg, target_host, target_port).detach();
    }
    net_close(listen_fd);
}

// ---- UDP mux ----

struct UdpLocalSession {
    uint32_t sid = 0;
    sockaddr_in client{};
    std::chrono::steady_clock::time_point last{};
};

struct UdpMuxState {
    PeerConfig cfg;
    socket_t mux_fd = INVALID_SOCK;
    vortex::SessionCrypto to_server;
    vortex::SessionCrypto from_server;
    std::mutex mu;
    std::unordered_map<uint16_t, socket_t> listen_fds; // to_local UDP binds
    std::unordered_map<uint32_t, UdpLocalSession> by_sid;
    std::unordered_map<std::string, uint32_t> by_client;
    std::unordered_map<uint32_t, uint16_t> sid_to_listen;
    std::atomic<uint32_t> next_sid{1};
    std::atomic<bool> alive{true};
};

std::string client_key(uint16_t listen_port, const sockaddr_in& from) {
    return std::to_string(listen_port) + "|" + sockaddr_ip_str(from) + ":" +
           std::to_string(ntohs(from.sin_port));
}

void expire_udp_local(std::shared_ptr<UdpMuxState> st) {
    const auto now = std::chrono::steady_clock::now();
    std::vector<uint32_t> dead;
    {
        std::lock_guard<std::mutex> lock(st->mu);
        for (auto& kv : st->by_sid) {
            const auto age =
                std::chrono::duration_cast<std::chrono::seconds>(now - kv.second.last).count();
            if (age >= st->cfg.udp_idle_sec) dead.push_back(kv.first);
        }
        for (uint32_t sid : dead) {
            st->by_sid.erase(sid);
            st->sid_to_listen.erase(sid);
        }
        for (auto it = st->by_client.begin(); it != st->by_client.end();) {
            if (st->by_sid.find(it->second) == st->by_sid.end()) it = st->by_client.erase(it);
            else ++it;
        }
    }
    if (st->mux_fd == INVALID_SOCK) return;
    for (uint32_t sid : dead) {
        auto pl = vortex::build_udp_close_payload(sid, vortex::UDP_FLAG_TO_LOCAL);
        vortex::send_frame(st->mux_fd, st->to_server, vortex::CMD_UDP_CLOSE, pl,
                           st->cfg.padding_min, st->cfg.padding_max);
    }
}

bool run_udp_mux_session(PeerConfig cfg, LoadedForwards fwd, std::shared_ptr<UdpMuxState> st) {
    socket_t fd = tcp_connect(cfg.server_ip, cfg.server_port, cfg.idle_timeout_sec);
    if (fd == INVALID_SOCK) return false;
    set_socket_options(fd, cfg.idle_timeout_sec);
    set_tcp_keepalive(fd, 60, 10, 3);

    uint64_t salt = get_random_salt();
    uint8_t salt_buf[8];
    std::memcpy(salt_buf, &salt, 8);
    if (!send_all(fd, salt_buf, 8)) {
        net_close(fd);
        return false;
    }

    st->cfg = cfg;
    st->to_server.init(cfg.master_secret, salt);
    st->from_server.init(cfg.master_secret, salt ^ 0xA5A5A5A5A5A5A5A5ULL);
    st->mux_fd = fd;
    st->alive = true;

    std::vector<uint8_t> hello(cfg.peer_secret.begin(), cfg.peer_secret.end());
    if (!vortex::send_frame(fd, st->to_server, vortex::CMD_PEER_HELLO, hello, cfg.padding_min,
                            cfg.padding_max)) {
        net_close(fd);
        st->mux_fd = INVALID_SOCK;
        return false;
    }
    auto ack = vortex::recv_frame(fd, st->from_server, cfg.max_payload);
    if (!ack.ok || ack.cmd != vortex::CMD_CONNECT_OK) {
        net_close(fd);
        st->mux_fd = INVALID_SOCK;
        return false;
    }
    if (!send_fwd_config(fd, st->to_server, cfg, fwd,
                         static_cast<uint8_t>(vortex::FWD_FLAG_UDP_MUX))) {
        net_close(fd);
        st->mux_fd = INVALID_SOCK;
        return false;
    }
    std::cout << "[*] Peer UDP mux online\n";
    std::cout.flush();

    std::unordered_map<uint16_t, std::pair<std::string, uint16_t>> local_to_remote;
    for (const auto& m : fwd.to_local.maps) {
        local_to_remote[m.listen_port] = {fwd.to_local.target_ip, m.target_port};
    }

    // Per-session UDP sockets for to_remote outbound (demux replies when many
    // clients share the same target host:port). Hard-capped to avoid FD exhaustion.
    constexpr size_t kMaxRemoteUdpSessions = 512;
    std::unordered_map<uint32_t, socket_t> remote_sid_socks;
    std::unordered_map<uint32_t, sockaddr_in> remote_sid_target;
    std::unordered_map<uint32_t, std::chrono::steady_clock::time_point> remote_sid_last;
    auto close_remote_sid = [&](uint32_t sid) {
        auto it = remote_sid_socks.find(sid);
        if (it != remote_sid_socks.end()) {
            if (it->second != INVALID_SOCK) net_close(it->second);
            remote_sid_socks.erase(it);
        }
        remote_sid_target.erase(sid);
        remote_sid_last.erase(sid);
    };
    auto evict_remote_if_needed = [&]() {
        while (remote_sid_socks.size() >= kMaxRemoteUdpSessions) {
            uint32_t victim = 0;
            auto oldest = std::chrono::steady_clock::time_point::max();
            bool found = false;
            for (const auto& kv : remote_sid_last) {
                if (!found || kv.second < oldest) {
                    oldest = kv.second;
                    victim = kv.first;
                    found = true;
                }
            }
            if (!found) break;
            close_remote_sid(victim);
            auto pl = vortex::build_udp_close_payload(victim, 0);
            vortex::send_frame(fd, st->to_server, vortex::CMD_UDP_CLOSE, pl, cfg.padding_min,
                               cfg.padding_max);
        }
    };
    auto expire_remote_socks = [&](std::chrono::steady_clock::time_point now) {
        std::vector<uint32_t> dead;
        for (const auto& kv : remote_sid_last) {
            const auto age =
                std::chrono::duration_cast<std::chrono::seconds>(now - kv.second).count();
            if (age >= cfg.udp_idle_sec) dead.push_back(kv.first);
        }
        for (uint32_t sid : dead) {
            close_remote_sid(sid);
            auto pl = vortex::build_udp_close_payload(sid, 0);
            vortex::send_frame(fd, st->to_server, vortex::CMD_UDP_CLOSE, pl, cfg.padding_min,
                               cfg.padding_max);
        }
    };

    auto last_expire = std::chrono::steady_clock::now();
    const size_t cap = static_cast<size_t>((std::min)(cfg.max_payload - 64, 65535));
    std::vector<uint8_t> buf(cap > 0 ? cap : 1024);

    while (g_running && st->alive) {
        // poll() — select/FD_SET aborts when fd >= FD_SETSIZE under high concurrency.
        std::vector<std::pair<uint16_t, socket_t>> listens;
        {
            std::lock_guard<std::mutex> lock(st->mu);
            for (auto& kv : st->listen_fds) listens.push_back(kv);
        }
        std::vector<std::pair<uint32_t, socket_t>> remote_socks;
        remote_socks.reserve(remote_sid_socks.size());
        for (auto& kv : remote_sid_socks) {
            if (kv.second != INVALID_SOCK) remote_socks.push_back(kv);
        }

        std::vector<pollfd_t> pfds;
        pfds.reserve(1 + listens.size() + remote_socks.size());
        pfds.push_back(pollfd_t{});
        pfds.back().fd = fd;
        pfds.back().events = POLLIN;
        for (auto& kv : listens) {
            pfds.push_back(pollfd_t{});
            pfds.back().fd = kv.second;
            pfds.back().events = POLLIN;
        }
        for (auto& kv : remote_socks) {
            pfds.push_back(pollfd_t{});
            pfds.back().fd = kv.second;
            pfds.back().events = POLLIN;
        }

        const int sel =
            vortex_poll(pfds.data(), static_cast<nfds_count_t>(pfds.size()), 200);
        if (sel < 0) {
            if (net_would_block(net_errno())) continue;
            break;
        }

        const auto now = std::chrono::steady_clock::now();
        if (now - last_expire > std::chrono::seconds(5)) {
            expire_udp_local(st);
            expire_remote_socks(now);
            last_expire = now;
        }
        if (sel == 0) continue;

        const size_t listen_base = 1;
        const size_t remote_base = listen_base + listens.size();
        for (size_t i = 0; i < listens.size(); ++i) {
            if (!(pfds[listen_base + i].revents & (POLLIN | POLLERR | POLLHUP))) continue;
            auto& kv = listens[i];
            sockaddr_in from{};
            const int n = udp_recv_from(kv.second, buf.data(), buf.size(), from);
            if (n <= 0) continue;
            auto tit = local_to_remote.find(kv.first);
            if (tit == local_to_remote.end()) continue;

            uint32_t sid = 0;
            bool first = false;
            {
                std::lock_guard<std::mutex> lock(st->mu);
                const std::string key = client_key(kv.first, from);
                auto it = st->by_client.find(key);
                if (it == st->by_client.end()) {
                    sid = st->next_sid++;
                    if (sid == 0) sid = st->next_sid++;
                    UdpLocalSession sess;
                    sess.sid = sid;
                    sess.client = from;
                    sess.last = now;
                    st->by_sid[sid] = sess;
                    st->by_client[key] = sid;
                    st->sid_to_listen[sid] = kv.first;
                    first = true;
                } else {
                    sid = it->second;
                    st->by_sid[sid].last = now;
                }
            }
            auto pl = vortex::build_udp_data_payload(
                sid, first ? &tit->second.first : nullptr, first ? tit->second.second : 0,
                buf.data(), static_cast<size_t>(n), vortex::UDP_FLAG_TO_LOCAL);
            if (pl.size() > static_cast<size_t>(cfg.max_payload)) continue;
            if (!vortex::send_frame(fd, st->to_server, vortex::CMD_UDP_DATA, pl,
                                    cfg.padding_min, cfg.padding_max)) {
                st->alive = false;
                break;
            }
        }
        if (!st->alive) break;

        for (size_t i = 0; i < remote_socks.size(); ++i) {
            if (!(pfds[remote_base + i].revents & (POLLIN | POLLERR | POLLHUP))) continue;
            auto& kv = remote_socks[i];
            sockaddr_in from{};
            const int n = udp_recv_from(kv.second, buf.data(), buf.size(), from);
            if (n <= 0) continue;
            remote_sid_last[kv.first] = now;
            auto pl = vortex::build_udp_data_payload(kv.first, nullptr, 0, buf.data(),
                                                     static_cast<size_t>(n), 0);
            if (pl.size() <= static_cast<size_t>(cfg.max_payload) &&
                !vortex::send_frame(fd, st->to_server, vortex::CMD_UDP_DATA, pl,
                                    cfg.padding_min, cfg.padding_max)) {
                st->alive = false;
                break;
            }
        }
        if (!st->alive) break;
        if (!(pfds[0].revents & (POLLIN | POLLERR | POLLHUP))) continue;

        auto frame = vortex::recv_frame(fd, st->from_server, cfg.max_payload);
        if (!frame.ok) {
            st->alive = false;
            break;
        }
        if (frame.cmd == vortex::CMD_UDP_DATA) {
            uint32_t sid = 0;
            bool has_addr = false;
            std::string addr_host;
            uint16_t addr_port = 0;
            std::vector<uint8_t> payload;
            uint8_t uflags = 0;
            if (!vortex::parse_udp_data_payload(frame.data, sid, has_addr, addr_host, addr_port,
                                                payload, &uflags) ||
                payload.empty()) {
                continue;
            }
            if ((uflags & vortex::UDP_FLAG_TO_LOCAL) != 0) {
                std::lock_guard<std::mutex> lock(st->mu);
                auto lit = st->sid_to_listen.find(sid);
                if (lit != st->sid_to_listen.end()) {
                    auto fdit = st->listen_fds.find(lit->second);
                    auto sit = st->by_sid.find(sid);
                    if (fdit != st->listen_fds.end() && sit != st->by_sid.end()) {
                        sit->second.last = now;
                        udp_send_to(fdit->second, payload.data(), payload.size(),
                                    sit->second.client);
                    }
                }
                continue;
            }
            // to_remote: never touch to_local session tables (sid namespaces collide).
            if (has_addr) {
                sockaddr_in tgt{};
                tgt.sin_family = AF_INET;
                tgt.sin_port = htons(addr_port);
                if (inet_pton(AF_INET, addr_host.c_str(), &tgt.sin_addr) != 1) continue;
                close_remote_sid(sid);
                evict_remote_if_needed();
                socket_t sfd = create_udp_socket();
                if (sfd == INVALID_SOCK) continue;
                if (!udp_send_to(sfd, payload.data(), payload.size(), tgt)) {
                    net_close(sfd);
                    continue;
                }
                remote_sid_socks[sid] = sfd;
                remote_sid_target[sid] = tgt;
                remote_sid_last[sid] = now;
            } else {
                auto it = remote_sid_socks.find(sid);
                auto tit = remote_sid_target.find(sid);
                if (it == remote_sid_socks.end() || tit == remote_sid_target.end()) continue;
                remote_sid_last[sid] = now;
                udp_send_to(it->second, payload.data(), payload.size(), tit->second);
            }
        } else if (frame.cmd == vortex::CMD_UDP_CLOSE) {
            uint32_t sid = 0;
            uint8_t cflags = 0;
            if (!vortex::parse_udp_close_payload(frame.data, sid, &cflags)) continue;
            if ((cflags & vortex::UDP_FLAG_TO_LOCAL) != 0) {
                std::lock_guard<std::mutex> lock(st->mu);
                st->by_sid.erase(sid);
                st->sid_to_listen.erase(sid);
                for (auto it = st->by_client.begin(); it != st->by_client.end();) {
                    if (it->second == sid) it = st->by_client.erase(it);
                    else ++it;
                }
            } else {
                close_remote_sid(sid);
            }
        } else {
            st->alive = false;
            break;
        }
    }

    for (auto& kv : remote_sid_socks) {
        if (kv.second != INVALID_SOCK) net_close(kv.second);
    }
    remote_sid_socks.clear();
    remote_sid_target.clear();
    if (st->mux_fd != INVALID_SOCK) {
        net_close(st->mux_fd);
        st->mux_fd = INVALID_SOCK;
    }
    st->alive = false;
    return false;
}

void udp_mux_worker_loop(PeerConfig cfg, LoadedForwards fwd, std::shared_ptr<UdpMuxState> st) {
    while (g_running) {
        run_udp_mux_session(cfg, fwd, st);
        if (!g_running) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(cfg.reconnect_ms));
        std::cout << "[*] Peer UDP mux reconnect...\n";
        std::cout.flush();
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
    LoadedForwards fwd;
    try {
        cfg = PeerConfig::load(config_path);
        fwd = load_forwards(cfg);
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
              << "  multi-job=on" << std::endl;
    if (!fwd.to_remote.empty()) {
        std::cout << "[*] to_remote (ssh -R): " << fwd.to_remote.maps.size()
                  << " maps  server listens " << fwd.to_remote.listen_ip
                  << " → peer " << fwd.to_remote.target_ip << std::endl;
    }
    if (!fwd.to_local.empty()) {
        std::cout << "[*] to_local (ssh -L): " << fwd.to_local.maps.size()
                  << " maps  peer listens " << fwd.to_local.listen_ip
                  << " → " << fwd.to_local.target_ip << std::endl;
    }
    std::cout.flush();

    std::vector<std::thread> threads;

    for (const auto& m : fwd.to_local.maps) {
        socket_t lfd =
            create_listen_socket(fwd.to_local.listen_ip, m.listen_port, cfg.listen_backlog);
        if (lfd == INVALID_SOCK) {
            std::cerr << "[-] to_local TCP bind failed " << fwd.to_local.listen_ip << ":"
                      << m.listen_port << "\n";
            continue;
        }
        std::cout << "[*] to_local TCP listen " << fwd.to_local.listen_ip << ":"
                  << m.listen_port << " → " << fwd.to_local.target_ip << ":" << m.target_port
                  << std::endl;
        threads.emplace_back(to_local_tcp_accept_loop, lfd, cfg, fwd.to_local.target_ip,
                             m.target_port);
    }

    auto udp_shared = std::make_shared<UdpMuxState>();
    if (cfg.enable_udp) {
        for (const auto& m : fwd.to_local.maps) {
            socket_t ufd = create_udp_listen_socket(fwd.to_local.listen_ip, m.listen_port);
            if (ufd == INVALID_SOCK) {
                std::cerr << "[-] to_local UDP bind failed " << fwd.to_local.listen_ip << ":"
                          << m.listen_port << "\n";
                continue;
            }
            std::cout << "[*] to_local UDP listen " << fwd.to_local.listen_ip << ":"
                      << m.listen_port << " → " << fwd.to_local.target_ip << ":"
                      << m.target_port << std::endl;
            std::lock_guard<std::mutex> lock(udp_shared->mu);
            udp_shared->listen_fds[m.listen_port] = ufd;
        }
    }
    std::cout.flush();

    const bool need_udp =
        cfg.enable_udp && (!fwd.to_remote.empty() || !udp_shared->listen_fds.empty());
    if (need_udp) {
        // Single mux owns listen sockets + to_remote UDP path.
        threads.emplace_back(udp_mux_worker_loop, cfg, fwd, udp_shared);
    }

    for (int i = 0; i < cfg.workers; ++i) {
        threads.emplace_back(worker_loop, cfg, fwd, i);
    }
    for (auto& t : threads) t.join();

    {
        std::lock_guard<std::mutex> lock(udp_shared->mu);
        for (auto& kv : udp_shared->listen_fds) {
            if (kv.second != INVALID_SOCK) net_close(kv.second);
        }
    }

    net_cleanup();
    std::cout << "[*] Peer stopped\n";
    return 0;
}
