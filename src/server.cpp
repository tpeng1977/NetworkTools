#include "config.hpp"
#include "net.hpp"
#include "port_forward.hpp"
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
std::atomic<int> g_active_sessions{0};
std::atomic<int> g_fwd_conns{0};

void on_signal(int) { g_running = false; }

struct SessionGuard {
    std::atomic<int>& counter;
    explicit SessionGuard(std::atomic<int>& c) : counter(c) { ++counter; }
    ~SessionGuard() { --counter; }
};

// Long-lived peer worker waiting for VIA_PEER / to_remote TCP jobs.
struct PeerConn {
    socket_t fd = INVALID_SOCK;
    vortex::SessionCrypto up;   // decrypt peer → server
    vortex::SessionCrypto down; // encrypt server → peer
    ServerConfig cfg;
    std::string secret;
    std::atomic<bool> alive{true};
    std::mutex mu;
    bool busy = false;
    bool udp_mux = false;

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

// UDP mux peers per secret (not in VIA_PEER pool).
std::mutex g_udp_mu;
std::unordered_map<std::string, std::vector<std::shared_ptr<PeerConn>>> g_udp_mux;

void unregister_peer(const std::shared_ptr<PeerConn>& p) {
    if (!p) return;
    if (p->udp_mux) {
        std::lock_guard<std::mutex> lock(g_udp_mu);
        auto it = g_udp_mux.find(p->secret);
        if (it == g_udp_mux.end()) return;
        auto& vec = it->second;
        vec.erase(std::remove_if(vec.begin(), vec.end(),
                                 [&](const std::shared_ptr<PeerConn>& x) { return x == p; }),
                  vec.end());
        if (vec.empty()) g_udp_mux.erase(it);
        return;
    }
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

std::shared_ptr<PeerConn> acquire_udp_mux(const std::string& secret) {
    std::lock_guard<std::mutex> lock(g_udp_mu);
    auto it = g_udp_mux.find(secret);
    if (it == g_udp_mux.end()) return nullptr;
    for (auto& p : it->second) {
        if (p && p->alive && p->fd != INVALID_SOCK) return p;
    }
    return nullptr;
}

void release_peer(const std::shared_ptr<PeerConn>& p, bool drop) {
    if (!p) return;
    if (drop) {
        p->alive = false;
        {
            std::lock_guard<std::mutex> lock(p->mu);
            p->busy = false;
        }
        unregister_peer(p);
        if (p->fd != INVALID_SOCK) {
            shutdown_both(p->fd);
        }
    } else {
        {
            std::lock_guard<std::mutex> lock(p->mu);
            p->busy = false;
        }
        g_peer_cv.notify_all();
    }
}

// Bound waits so a killed peer/server cannot stall accept/worker threads for idle_timeout.
constexpr int kPeerJobIoSec = 20;      // during an active TCP forward job
constexpr int kPeerTeardownSec = 2;    // join / drain after CLOSE
constexpr int kPeerDrainMaxFrames = 64;

// Finish a peer job before returning the connection to the pool.
// Without this, a trailing CMD_CLOSE/DATA from the previous job is read as the
// CONNECT_OK of the next job → second SSH (-R) fails with reset / MAC errors.
bool drain_peer_job_boundary(const std::shared_ptr<PeerConn>& peer, const ServerConfig& cfg,
                             bool already_got_close) {
    if (!peer || !peer->alive || peer->fd == INVALID_SOCK) return false;
    if (already_got_close) return true;
    set_recv_timeout(peer->fd, kPeerTeardownSec);
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(kPeerTeardownSec + 1);
    int frames = 0;
    while (std::chrono::steady_clock::now() < deadline && frames < kPeerDrainMaxFrames) {
        ++frames;
        auto frame = vortex::recv_frame(peer->fd, peer->up, cfg.max_payload);
        if (!frame.ok) {
            peer->alive = false;
            return false;
        }
        if (frame.cmd == vortex::CMD_CLOSE || frame.cmd == vortex::CMD_CONNECT_FAIL) {
            set_recv_timeout(peer->fd, cfg.idle_timeout_sec > 0 ? cfg.idle_timeout_sec : 300);
            return true;
        }
        if (frame.cmd == vortex::CMD_DATA) continue; // discard trailing payload
        peer->alive = false;
        return false;
    }
    peer->alive = false;
    return false;
}

void finish_peer_job(std::shared_ptr<PeerConn>& peer, const ServerConfig& cfg, bool peer_link_ok,
                     bool got_peer_close) {
    if (!peer) return;
    // Cap any in-flight recv so join/drain cannot wait for a dead peer's idle_timeout.
    if (peer->fd != INVALID_SOCK) set_recv_timeout(peer->fd, kPeerTeardownSec);
    bool reusable = peer_link_ok && peer->alive;
    if (reusable) {
        reusable = drain_peer_job_boundary(peer, cfg, got_peer_close);
    }
    if (!reusable || !peer->alive) release_peer(peer, true);
    else {
        set_recv_timeout(peer->fd, cfg.idle_timeout_sec > 0 ? cfg.idle_timeout_sec : 300);
        release_peer(peer, false);
    }
}

// ---- to_remote forward registry (installed from peer FWD_CONFIG) ----

struct FwdBinding {
    std::string secret;
    std::string listen_ip;
    uint16_t listen_port = 0;
    std::string target_ip;
    uint16_t target_port = 0;
};

struct FwdInstall {
    std::string secret;
    vortex::PortForwardSpec to_remote;
    int refcount = 0;
    std::vector<socket_t> tcp_fds;
    std::vector<socket_t> udp_fds;
    std::vector<std::thread> threads;
    ServerConfig cfg;
    int max_fwd_conns = 512;
    int udp_idle_sec = 60;
};

std::mutex g_fwd_mu;
std::unordered_map<std::string, std::shared_ptr<FwdInstall>> g_fwd_by_secret;
// listen_port → binding (TCP and UDP share port numbers per map)
std::unordered_map<uint16_t, FwdBinding> g_tcp_binds;
std::unordered_map<uint16_t, FwdBinding> g_udp_binds;

struct ServerSession {
    socket_t client_fd = INVALID_SOCK;
    socket_t target_fd = INVALID_SOCK;
    std::atomic<bool> alive{true};
    ServerConfig cfg;
    vortex::SessionCrypto up;
    vortex::SessionCrypto down;
    std::mutex target_mu;
    std::shared_ptr<PeerConn> peer;

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
        if (!vortex::send_frame(s->client_fd, s->down, vortex::CMD_DATA, buf.data(),
                                static_cast<size_t>(n), s->cfg.padding_min,
                                s->cfg.padding_max)) {
            break;
        }
    }
    s->alive = false;
    shutdown_both(s->client_fd);
}

void relay_peer_to_client(std::shared_ptr<ServerSession> s, std::shared_ptr<PeerConn> peer,
                          std::atomic<bool>* got_peer_close = nullptr) {
    while (s->alive && peer->alive && g_running) {
        auto frame = vortex::recv_frame(peer->fd, peer->up, s->cfg.max_payload);
        if (!frame.ok) {
            peer->alive = false;
            break;
        }
        if (frame.cmd == vortex::CMD_DATA) {
            if (!frame.data.empty()) {
                if (!vortex::send_frame(s->client_fd, s->down, vortex::CMD_DATA, frame.data,
                                        s->cfg.padding_min, s->cfg.padding_max)) {
                    break;
                }
            }
        } else if (frame.cmd == vortex::CMD_CLOSE || frame.cmd == vortex::CMD_CONNECT_FAIL) {
            if (got_peer_close) got_peer_close->store(true);
            break;
        } else {
            peer->alive = false;
            break;
        }
    }
    s->alive = false;
    shutdown_both(s->client_fd);
}

// Relay between an accepted local TCP client and a peer CONNECT job (to_remote).
void relay_peer_to_local(socket_t local_fd, std::shared_ptr<PeerConn> peer, ServerConfig cfg,
                         std::atomic<bool>& alive, std::atomic<bool>& got_peer_close) {
    while (alive && peer->alive && g_running) {
        auto frame = vortex::recv_frame(peer->fd, peer->up, cfg.max_payload);
        if (!frame.ok) {
            peer->alive = false;
            break;
        }
        if (frame.cmd == vortex::CMD_DATA) {
            if (!frame.data.empty() &&
                !send_all(local_fd, frame.data.data(), frame.data.size())) {
                break;
            }
        } else if (frame.cmd == vortex::CMD_CLOSE || frame.cmd == vortex::CMD_CONNECT_FAIL) {
            got_peer_close.store(true);
            break;
        } else {
            peer->alive = false;
            break;
        }
    }
    alive = false;
    shutdown_both(local_fd);
}

bool open_peer_connect_job(std::shared_ptr<PeerConn>& peer, const std::string& secret,
                           const std::vector<uint8_t>& target_wire, const ServerConfig& cfg) {
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(15000);
    while (std::chrono::steady_clock::now() < deadline) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                              deadline - std::chrono::steady_clock::now())
                              .count();
        peer = acquire_peer(secret, left > 0 ? static_cast<int>(left) : 0);
        if (!peer) return false;

        set_recv_timeout(peer->fd, 5);
        if (!vortex::send_frame(peer->fd, peer->down, vortex::CMD_CONNECT, target_wire,
                                cfg.padding_min, cfg.padding_max)) {
            release_peer(peer, true);
            peer.reset();
            continue;
        }
        auto reply = vortex::recv_frame(peer->fd, peer->up, cfg.max_payload);
        if (!reply.ok) {
            release_peer(peer, true);
            peer.reset();
            continue;
        }
        // Active job uses a bounded I/O timeout so a killed peer unblocks quickly.
        set_recv_timeout(peer->fd, kPeerJobIoSec);
        if (reply.cmd == vortex::CMD_CONNECT_OK) return true;
        // CONNECT_FAIL: peer finished this attempt cleanly and is idle again.
        // Any other cmd (e.g. leftover CLOSE) means the stream is desynced — drop it.
        if (reply.cmd == vortex::CMD_CONNECT_FAIL) {
            release_peer(peer, false);
        } else {
            release_peer(peer, true);
        }
        peer.reset();
        return false;
    }
    return false;
}

void handle_to_remote_tcp_client(socket_t client_fd, FwdBinding bind, ServerConfig cfg,
                                 int max_fwd) {
    struct Guard {
        ~Guard() { --g_fwd_conns; }
    } guard;
    (void)max_fwd;
    set_socket_options(client_fd, cfg.idle_timeout_sec);

    auto wire = vortex::build_connect_target_host(bind.target_ip, bind.target_port);
    if (wire.empty()) {
        net_close(client_fd);
        return;
    }

    std::shared_ptr<PeerConn> peer;
    if (!open_peer_connect_job(peer, bind.secret, wire, cfg) || !peer) {
        std::cout << "[-] to_remote TCP no peer for " << bind.listen_port << " → "
                  << bind.target_ip << ":" << bind.target_port << "\n";
        std::cout.flush();
        net_close(client_fd);
        return;
    }

    std::cout << "[+] to_remote TCP :" << bind.listen_port << " → peer "
              << bind.target_ip << ":" << bind.target_port << std::endl;
    std::cout.flush();

    std::atomic<bool> alive{true};
    std::atomic<bool> relay_done{false};
    std::atomic<bool> got_peer_close{false};
    std::thread down([client_fd, peer, cfg, &alive, &relay_done, &got_peer_close]() {
        relay_peer_to_local(client_fd, peer, cfg, alive, got_peer_close);
        relay_done.store(true);
    });

    bool peer_ok = true;
    bool close_sent = false;
    std::vector<uint8_t> buf(static_cast<size_t>(cfg.max_payload));
    while (alive && g_running && peer && peer->alive) {
        if (relay_done.load()) break;
        pollfd_t pfd{};
        pfd.fd = client_fd;
        pfd.events = POLLIN;
        const int sel = vortex_poll(&pfd, 1, 50);
        if (!alive || relay_done.load()) break;
        if (sel < 0) {
            if (net_would_block(net_errno())) continue;
            break;
        }
        if (sel == 0) continue;
        const int n = recv_some(client_fd, buf.data(), buf.size());
        if (n <= 0) break;
        if (!vortex::send_frame(peer->fd, peer->down, vortex::CMD_DATA, buf.data(),
                                static_cast<size_t>(n), cfg.padding_min, cfg.padding_max)) {
            if (relay_done.load()) break;
            peer_ok = false;
            break;
        }
    }

    alive = false;
    if (peer && peer->fd != INVALID_SOCK) set_recv_timeout(peer->fd, kPeerTeardownSec);
    if (peer && peer->alive && peer_ok && !close_sent) {
        vortex::send_frame(peer->fd, peer->down, vortex::CMD_CLOSE, nullptr, 0, cfg.padding_min,
                           cfg.padding_max);
        close_sent = true;
    }
    if (down.joinable()) down.join();
    finish_peer_job(peer, cfg, peer_ok, got_peer_close.load());
    shutdown_both(client_fd);
    net_close(client_fd);
}

void to_remote_tcp_accept_loop(socket_t listen_fd, FwdBinding bind, ServerConfig cfg,
                               int max_fwd) {
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
        sockaddr_in peeraddr{};
        socklen_type plen = sizeof(peeraddr);
        // Back-pressure: skip accept when at cap so clients block/fail on connect
        // instead of seeing accept-then-RST mid-handshake.
        if (g_fwd_conns.load() >= max_fwd) {
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
            continue;
        }
        socket_t c = accept(listen_fd, reinterpret_cast<sockaddr*>(&peeraddr), &plen);
        if (c == INVALID_SOCK) continue;
        if (g_fwd_conns.load() >= max_fwd) {
            net_close(c);
            continue;
        }
        ++g_fwd_conns;
        std::thread(handle_to_remote_tcp_client, c, bind, cfg, max_fwd).detach();
    }
}

// UDP to_remote session table (server side)
struct UdpRemoteSession {
    uint32_t sid = 0;
    sockaddr_in client{};
    uint16_t listen_port = 0;
    std::string target_ip;
    uint16_t target_port = 0;
    std::chrono::steady_clock::time_point last{};
};

struct UdpRemoteState {
    std::mutex mu;
    std::unordered_map<uint32_t, UdpRemoteSession> by_sid;
    std::unordered_map<std::string, uint32_t> by_client;
    std::atomic<uint32_t> next_sid{1};
};

std::shared_ptr<UdpRemoteState> g_udp_remote = std::make_shared<UdpRemoteState>();

std::string udp_client_key(uint16_t listen_port, const sockaddr_in& from) {
    return std::to_string(listen_port) + "|" + sockaddr_ip_str(from) + ":" +
           std::to_string(ntohs(from.sin_port));
}

void to_remote_udp_loop(socket_t listen_fd, FwdBinding bind, ServerConfig cfg,
                        int udp_idle_sec) {
    const size_t cap = static_cast<size_t>((std::min)(cfg.max_payload - 64, 65535));
    std::vector<uint8_t> buf(cap > 0 ? cap : 1024);
    auto last_expire = std::chrono::steady_clock::now();

    while (g_running) {
        pollfd_t pfd{};
        pfd.fd = listen_fd;
        pfd.events = POLLIN;
        const int sel = vortex_poll(&pfd, 1, 200);
        if (sel < 0) {
            if (net_would_block(net_errno())) continue;
            break;
        }

        const auto now = std::chrono::steady_clock::now();
        if (now - last_expire > std::chrono::seconds(5)) {
            std::vector<uint32_t> dead;
            {
                std::lock_guard<std::mutex> lock(g_udp_remote->mu);
                for (auto& kv : g_udp_remote->by_sid) {
                    if (kv.second.listen_port != bind.listen_port) continue;
                    const auto age =
                        std::chrono::duration_cast<std::chrono::seconds>(now - kv.second.last)
                            .count();
                    if (age >= udp_idle_sec) dead.push_back(kv.first);
                }
                for (uint32_t sid : dead) {
                    g_udp_remote->by_sid.erase(sid);
                }
                for (auto it = g_udp_remote->by_client.begin();
                     it != g_udp_remote->by_client.end();) {
                    if (g_udp_remote->by_sid.find(it->second) == g_udp_remote->by_sid.end()) {
                        it = g_udp_remote->by_client.erase(it);
                    } else {
                        ++it;
                    }
                }
            }
            auto mux = acquire_udp_mux(bind.secret);
            if (mux) {
                for (uint32_t sid : dead) {
                    auto pl = vortex::build_udp_close_payload(sid);
                    std::lock_guard<std::mutex> lock(mux->mu);
                    vortex::send_frame(mux->fd, mux->down, vortex::CMD_UDP_CLOSE, pl,
                                       cfg.padding_min, cfg.padding_max);
                }
            }
            last_expire = now;
        }
        if (sel == 0) continue;
        if (!(pfd.revents & (POLLIN | POLLERR | POLLHUP))) continue;

        sockaddr_in from{};
        const int n = udp_recv_from(listen_fd, buf.data(), buf.size(), from);
        if (n <= 0) continue;

        auto mux = acquire_udp_mux(bind.secret);
        if (!mux) continue;

        uint32_t sid = 0;
        bool first = false;
        {
            std::lock_guard<std::mutex> lock(g_udp_remote->mu);
            const std::string key = udp_client_key(bind.listen_port, from);
            auto it = g_udp_remote->by_client.find(key);
            if (it == g_udp_remote->by_client.end()) {
                sid = g_udp_remote->next_sid++;
                if (sid == 0) sid = g_udp_remote->next_sid++;
                UdpRemoteSession sess;
                sess.sid = sid;
                sess.client = from;
                sess.listen_port = bind.listen_port;
                sess.target_ip = bind.target_ip;
                sess.target_port = bind.target_port;
                sess.last = now;
                g_udp_remote->by_sid[sid] = sess;
                g_udp_remote->by_client[key] = sid;
                first = true;
            } else {
                sid = it->second;
                g_udp_remote->by_sid[sid].last = now;
            }
        }

        auto pl = vortex::build_udp_data_payload(
            sid, first ? &bind.target_ip : nullptr, first ? bind.target_port : 0, buf.data(),
            static_cast<size_t>(n));
        if (pl.size() > static_cast<size_t>(cfg.max_payload)) continue;
        std::lock_guard<std::mutex> lock(mux->mu);
        if (!vortex::send_frame(mux->fd, mux->down, vortex::CMD_UDP_DATA, pl, cfg.padding_min,
                                cfg.padding_max)) {
            mux->alive = false;
        }
    }
}

void run_udp_mux_server_loop_v2(std::shared_ptr<PeerConn> peer) {
    // Per-session sockets for to_local outbound so concurrent clients sharing a
    // target host:port do not steal each other's replies. Hard-capped for FDs.
    constexpr size_t kMaxLocalUdpSessions = 512;
    std::unordered_map<uint32_t, socket_t> local_sid_socks;
    std::unordered_map<uint32_t, sockaddr_in> local_sid_target;
    std::unordered_map<uint32_t, std::chrono::steady_clock::time_point> local_sid_last;
    auto close_local_sid = [&](uint32_t sid) {
        auto it = local_sid_socks.find(sid);
        if (it != local_sid_socks.end()) {
            if (it->second != INVALID_SOCK) net_close(it->second);
            local_sid_socks.erase(it);
        }
        local_sid_target.erase(sid);
        local_sid_last.erase(sid);
    };
    auto evict_local_if_needed = [&]() {
        while (local_sid_socks.size() >= kMaxLocalUdpSessions) {
            uint32_t victim = 0;
            auto oldest = std::chrono::steady_clock::time_point::max();
            bool found = false;
            for (const auto& kv : local_sid_last) {
                if (!found || kv.second < oldest) {
                    oldest = kv.second;
                    victim = kv.first;
                    found = true;
                }
            }
            if (!found) break;
            close_local_sid(victim);
            auto pl = vortex::build_udp_close_payload(victim, vortex::UDP_FLAG_TO_LOCAL);
            std::lock_guard<std::mutex> lock(peer->mu);
            vortex::send_frame(peer->fd, peer->down, vortex::CMD_UDP_CLOSE, pl,
                               peer->cfg.padding_min, peer->cfg.padding_max);
        }
    };
    auto expire_local_socks = [&](std::chrono::steady_clock::time_point now) {
        const int idle = peer->cfg.idle_timeout_sec > 0 ? peer->cfg.idle_timeout_sec : 60;
        // Prefer a shorter UDP idle; reuse peer idle as upper bound.
        const int udp_idle = (std::min)(idle, 60);
        std::vector<uint32_t> dead;
        for (const auto& kv : local_sid_last) {
            const auto age =
                std::chrono::duration_cast<std::chrono::seconds>(now - kv.second).count();
            if (age >= udp_idle) dead.push_back(kv.first);
        }
        for (uint32_t sid : dead) {
            close_local_sid(sid);
            auto pl = vortex::build_udp_close_payload(sid, vortex::UDP_FLAG_TO_LOCAL);
            std::lock_guard<std::mutex> lock(peer->mu);
            vortex::send_frame(peer->fd, peer->down, vortex::CMD_UDP_CLOSE, pl,
                               peer->cfg.padding_min, peer->cfg.padding_max);
        }
    };

    const size_t cap = static_cast<size_t>((std::min)(peer->cfg.max_payload - 64, 65535));
    std::vector<uint8_t> buf(cap > 0 ? cap : 1024);
    auto last_expire = std::chrono::steady_clock::now();

    while (g_running && peer->alive) {
        std::vector<std::pair<uint32_t, socket_t>> local_socks;
        local_socks.reserve(local_sid_socks.size());
        for (auto& kv : local_sid_socks) {
            if (kv.second != INVALID_SOCK) local_socks.push_back(kv);
        }
        std::vector<pollfd_t> pfds;
        pfds.reserve(1 + local_socks.size());
        pfds.push_back(pollfd_t{});
        pfds.back().fd = peer->fd;
        pfds.back().events = POLLIN;
        for (auto& kv : local_socks) {
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
            expire_local_socks(now);
            last_expire = now;
        }

        if (sel > 0) {
            for (size_t i = 0; i < local_socks.size(); ++i) {
                if (!(pfds[1 + i].revents & (POLLIN | POLLERR | POLLHUP))) continue;
                auto& kv = local_socks[i];
                sockaddr_in from{};
                const int n = udp_recv_from(kv.second, buf.data(), buf.size(), from);
                if (n <= 0) continue;
                local_sid_last[kv.first] = now;
                auto pl = vortex::build_udp_data_payload(
                    kv.first, nullptr, 0, buf.data(), static_cast<size_t>(n),
                    vortex::UDP_FLAG_TO_LOCAL);
                if (pl.size() <= static_cast<size_t>(peer->cfg.max_payload)) {
                    std::lock_guard<std::mutex> lock(peer->mu);
                    if (!vortex::send_frame(peer->fd, peer->down, vortex::CMD_UDP_DATA, pl,
                                            peer->cfg.padding_min, peer->cfg.padding_max)) {
                        peer->alive = false;
                    }
                }
            }
        }
        if (!peer->alive) break;
        if (sel == 0 || !(pfds[0].revents & (POLLIN | POLLERR | POLLHUP))) continue;

        auto frame = vortex::recv_frame(peer->fd, peer->up, peer->cfg.max_payload);
        if (!frame.ok) {
            peer->alive = false;
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

            // to_local uplink from peer (flag set) — never consult to_remote sid table.
            if ((uflags & vortex::UDP_FLAG_TO_LOCAL) != 0) {
                if (has_addr) {
                    sockaddr_in tgt{};
                    tgt.sin_family = AF_INET;
                    tgt.sin_port = htons(addr_port);
                    if (inet_pton(AF_INET, addr_host.c_str(), &tgt.sin_addr) != 1) continue;
                    close_local_sid(sid);
                    evict_local_if_needed();
                    socket_t sfd = create_udp_socket();
                    if (sfd == INVALID_SOCK) continue;
                    if (!udp_send_to(sfd, payload.data(), payload.size(), tgt)) {
                        net_close(sfd);
                        continue;
                    }
                    local_sid_socks[sid] = sfd;
                    local_sid_target[sid] = tgt;
                    local_sid_last[sid] = std::chrono::steady_clock::now();
                } else {
                    auto it = local_sid_socks.find(sid);
                    auto tit = local_sid_target.find(sid);
                    if (it == local_sid_socks.end() || tit == local_sid_target.end()) continue;
                    local_sid_last[sid] = std::chrono::steady_clock::now();
                    udp_send_to(it->second, payload.data(), payload.size(), tit->second);
                }
                continue;
            }

            // to_remote reply from peer
            sockaddr_in client{};
            uint16_t listen_port = 0;
            bool is_remote = false;
            {
                std::lock_guard<std::mutex> lock(g_udp_remote->mu);
                auto it = g_udp_remote->by_sid.find(sid);
                if (it != g_udp_remote->by_sid.end()) {
                    client = it->second.client;
                    listen_port = it->second.listen_port;
                    is_remote = true;
                    it->second.last = std::chrono::steady_clock::now();
                }
            }
            if (is_remote) {
                socket_t ufd = INVALID_SOCK;
                {
                    std::lock_guard<std::mutex> lock(g_fwd_mu);
                    auto inst = g_fwd_by_secret.find(peer->secret);
                    if (inst != g_fwd_by_secret.end()) {
                        for (size_t i = 0; i < inst->second->to_remote.maps.size() &&
                                           i < inst->second->udp_fds.size();
                             ++i) {
                            if (inst->second->to_remote.maps[i].listen_port == listen_port) {
                                ufd = inst->second->udp_fds[i];
                                break;
                            }
                        }
                    }
                }
                if (ufd != INVALID_SOCK) {
                    udp_send_to(ufd, payload.data(), payload.size(), client);
                }
                continue;
            }
        } else if (frame.cmd == vortex::CMD_UDP_CLOSE) {
            uint32_t sid = 0;
            uint8_t cflags = 0;
            if (!vortex::parse_udp_close_payload(frame.data, sid, &cflags)) continue;
            if ((cflags & vortex::UDP_FLAG_TO_LOCAL) != 0) {
                close_local_sid(sid);
            } else {
                std::lock_guard<std::mutex> lock(g_udp_remote->mu);
                g_udp_remote->by_sid.erase(sid);
                for (auto it = g_udp_remote->by_client.begin();
                     it != g_udp_remote->by_client.end();) {
                    if (it->second == sid) it = g_udp_remote->by_client.erase(it);
                    else ++it;
                }
            }
        } else {
            peer->alive = false;
            break;
        }
    }
    for (auto& kv : local_sid_socks) {
        if (kv.second != INVALID_SOCK) net_close(kv.second);
    }
}

void stop_fwd_install(std::shared_ptr<FwdInstall> inst) {
    if (!inst) return;
    for (socket_t fd : inst->tcp_fds) {
        if (fd != INVALID_SOCK) {
            shutdown_both(fd);
            net_close(fd);
        }
    }
    for (socket_t fd : inst->udp_fds) {
        if (fd != INVALID_SOCK) net_close(fd);
    }
    inst->tcp_fds.clear();
    inst->udp_fds.clear();
    {
        std::lock_guard<std::mutex> lock(g_fwd_mu);
        for (const auto& m : inst->to_remote.maps) {
            g_tcp_binds.erase(m.listen_port);
            g_udp_binds.erase(m.listen_port);
        }
    }
}

void install_to_remote(const std::string& secret, const vortex::PortForwardSpec& spec,
                       const ServerConfig& cfg, bool enable_udp) {
    if (spec.empty()) return;
    std::lock_guard<std::mutex> lock(g_fwd_mu);
    auto it = g_fwd_by_secret.find(secret);
    if (it != g_fwd_by_secret.end()) {
        // Listeners already up for this secret; keep a single install.
        return;
    }

    auto inst = std::make_shared<FwdInstall>();
    inst->secret = secret;
    inst->to_remote = spec;
    inst->refcount = 1;
    inst->cfg = cfg;
    inst->max_fwd_conns = 1024;
    inst->udp_idle_sec = 60;

    for (const auto& m : spec.maps) {
        if (g_tcp_binds.count(m.listen_port)) {
            std::cerr << "[-] to_remote TCP port conflict :" << m.listen_port << "\n";
            continue;
        }
        socket_t lfd = create_listen_socket(spec.listen_ip, m.listen_port, cfg.listen_backlog);
        if (lfd == INVALID_SOCK) {
            std::cerr << "[-] to_remote TCP bind failed " << spec.listen_ip << ":"
                      << m.listen_port << "\n";
            continue;
        }
        FwdBinding b;
        b.secret = secret;
        b.listen_ip = spec.listen_ip;
        b.listen_port = m.listen_port;
        b.target_ip = spec.target_ip;
        b.target_port = m.target_port;
        g_tcp_binds[m.listen_port] = b;
        inst->tcp_fds.push_back(lfd);
        std::cout << "[*] to_remote TCP listen " << spec.listen_ip << ":" << m.listen_port
                  << " → peer " << spec.target_ip << ":" << m.target_port << std::endl;
        std::thread(to_remote_tcp_accept_loop, lfd, b, cfg, inst->max_fwd_conns).detach();

        if (enable_udp) {
            socket_t ufd = create_udp_listen_socket(spec.listen_ip, m.listen_port);
            if (ufd == INVALID_SOCK) {
                std::cerr << "[-] to_remote UDP bind failed " << spec.listen_ip << ":"
                          << m.listen_port << "\n";
                inst->udp_fds.push_back(INVALID_SOCK);
            } else {
                g_udp_binds[m.listen_port] = b;
                inst->udp_fds.push_back(ufd);
                std::cout << "[*] to_remote UDP listen " << spec.listen_ip << ":"
                          << m.listen_port << " → peer " << spec.target_ip << ":"
                          << m.target_port << std::endl;
                std::thread(to_remote_udp_loop, ufd, b, cfg, inst->udp_idle_sec).detach();
            }
        } else {
            inst->udp_fds.push_back(INVALID_SOCK);
        }
    }
    std::cout.flush();
    g_fwd_by_secret[secret] = inst;
}

void release_to_remote(const std::string& secret) {
    // Keep listeners while any VIA_PEER worker for this secret is still registered.
    {
        std::lock_guard<std::mutex> lock(g_peer_mu);
        auto it = g_peers.find(secret);
        if (it != g_peers.end() && !it->second.empty()) return;
    }
    std::shared_ptr<FwdInstall> doomed;
    {
        std::lock_guard<std::mutex> lock(g_fwd_mu);
        auto it = g_fwd_by_secret.find(secret);
        if (it == g_fwd_by_secret.end()) return;
        doomed = it->second;
        g_fwd_by_secret.erase(it);
    }
    stop_fwd_install(doomed);
    std::cout << "[*] to_remote listeners released for peer secret_len=" << secret.size()
              << std::endl;
    std::cout.flush();
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
        vortex::send_frame(s->client_fd, s->down, vortex::CMD_CONNECT_FAIL, nullptr, 0,
                           s->cfg.padding_min, s->cfg.padding_max);
        return false;
    }

    {
        std::lock_guard<std::mutex> lock(s->target_mu);
        s->target_fd = tfd;
    }

    if (!vortex::send_frame(s->client_fd, s->down, vortex::CMD_CONNECT_OK, nullptr, 0,
                            s->cfg.padding_min, s->cfg.padding_max)) {
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
        vortex::send_frame(s->client_fd, s->down, vortex::CMD_CONNECT_FAIL, nullptr, 0,
                           s->cfg.padding_min, s->cfg.padding_max);
        return false;
    }

    std::string host;
    uint16_t port = 0;
    if (!vortex::parse_connect_target(target_wire, host, port)) {
        vortex::send_frame(s->client_fd, s->down, vortex::CMD_CONNECT_FAIL, nullptr, 0,
                           s->cfg.padding_min, s->cfg.padding_max);
        return false;
    }

    std::shared_ptr<PeerConn> peer;
    if (!open_peer_connect_job(peer, secret, target_wire, s->cfg) || !peer) {
        std::cout << "[-] No peer for secret (target " << host << ":" << port << ")\n";
        std::cout.flush();
        vortex::send_frame(s->client_fd, s->down, vortex::CMD_CONNECT_FAIL, nullptr, 0,
                           s->cfg.padding_min, s->cfg.padding_max);
        return false;
    }

    s->peer = peer;
    if (!vortex::send_frame(s->client_fd, s->down, vortex::CMD_CONNECT_OK, nullptr, 0,
                            s->cfg.padding_min, s->cfg.padding_max)) {
        vortex::send_frame(peer->fd, peer->down, vortex::CMD_CLOSE, nullptr, 0,
                           s->cfg.padding_min, s->cfg.padding_max);
        release_peer(peer, true);
        s->peer.reset();
        return false;
    }

    std::cout << "[+] Via-peer " << host << ":" << port << std::endl;
    std::cout.flush();
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
    const std::string secret(reinterpret_cast<const char*>(hello_data.data()),
                             hello_data.size());

    auto peer = std::make_shared<PeerConn>();
    peer->fd = fd;
    peer->cfg = cfg;
    peer->secret = secret;
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

    set_tcp_keepalive(fd, 60, 10, 3);
    set_recv_timeout(fd, cfg.idle_timeout_sec);

    if (!vortex::send_frame(fd, peer->down, vortex::CMD_CONNECT_OK, nullptr, 0, cfg.padding_min,
                            cfg.padding_max)) {
        return;
    }

    // FWD_CONFIG from peer (required for protocol sync; may be empty maps).
    auto fwd_frame = vortex::recv_frame(fd, peer->up, cfg.max_payload);
    if (!fwd_frame.ok || fwd_frame.cmd != vortex::CMD_FWD_CONFIG) {
        std::cerr << "[-] Peer missing FWD_CONFIG after HELLO\n";
        return;
    }
    vortex::PortForwardSpec to_remote;
    vortex::PortForwardSpec to_local;
    uint8_t flags = 0;
    if (!vortex::parse_fwd_config_payload(fwd_frame.data, to_remote, to_local, flags)) {
        std::cerr << "[-] Peer FWD_CONFIG parse failed\n";
        return;
    }
    const bool enable_udp = (flags & vortex::FWD_FLAG_UDP) != 0;
    const bool is_udp_mux = (flags & vortex::FWD_FLAG_UDP_MUX) != 0;
    peer->udp_mux = is_udp_mux;

    if (!to_remote.empty() && !is_udp_mux) {
        install_to_remote(secret, to_remote, cfg, enable_udp);
    }

    if (is_udp_mux) {
        {
            std::lock_guard<std::mutex> lock(g_udp_mu);
            g_udp_mux[secret].push_back(peer);
        }
        std::cout << "[*] Peer UDP mux online secret_len=" << secret.size() << std::endl;
        std::cout.flush();
        run_udp_mux_server_loop_v2(peer);
        unregister_peer(peer);
        // Do not release to_remote here — TCP workers still hold refs.
        std::cout << "[*] Peer UDP mux offline secret_len=" << secret.size() << std::endl;
        std::cout.flush();
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

    while (g_running && peer->alive) {
        bool busy = false;
        {
            std::lock_guard<std::mutex> lock(peer->mu);
            busy = peer->busy;
        }
        if (busy) {
            while (g_running && peer->alive) {
                {
                    std::lock_guard<std::mutex> lock(peer->mu);
                    if (!peer->busy) break;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            continue;
        }

        pollfd_t pfd{};
        pfd.fd = peer->fd;
        pfd.events = POLLIN;
        const int sel = vortex_poll(&pfd, 1, 200);
        if (sel < 0) {
            if (net_would_block(net_errno())) continue;
            peer->alive = false;
            break;
        }
        if (sel == 0) continue;
        {
            std::lock_guard<std::mutex> lock(peer->mu);
            if (peer->busy) continue;
        }
        char peek = 0;
#ifdef _WIN32
        const int n = ::recv(peer->fd, &peek, 1, MSG_PEEK);
#else
        const int n = static_cast<int>(::recv(peer->fd, &peek, 1, MSG_PEEK));
#endif
        if (n <= 0) {
            peer->alive = false;
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    unregister_peer(peer);
    release_to_remote(secret);
    std::cout << "[*] Peer offline secret_len=" << secret.size() << std::endl;
    std::cout.flush();
}

void handle_client(socket_t client_fd, ServerConfig cfg) {
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

    if (first.cmd == vortex::CMD_PEER_HELLO) {
        s->client_fd = INVALID_SOCK;
        handle_peer_hello(client_fd, s->cfg, salt, first.data, s->up, s->down);
        return;
    }

    SessionGuard guard(g_active_sessions);

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
        std::atomic<bool> relay_done{false};
        std::atomic<bool> got_peer_close{false};
        std::thread down_relay([s, peer, &relay_done, &got_peer_close]() {
            relay_peer_to_client(s, peer, &got_peer_close);
            relay_done.store(true);
        });

        bool peer_link_ok = true;
        bool close_to_peer_sent = false;
        while (s->alive && g_running && peer && peer->alive) {
            if (relay_done.load()) break;
            auto frame = vortex::recv_frame(client_fd, s->up, s->cfg.max_payload);
            if (!frame.ok) break;
            if (frame.cmd == vortex::CMD_DATA) {
                if (relay_done.load()) break;
                if (!frame.data.empty()) {
                    if (!vortex::send_frame(peer->fd, peer->down, vortex::CMD_DATA, frame.data,
                                            s->cfg.padding_min, s->cfg.padding_max)) {
                        if (relay_done.load()) break;
                        peer_link_ok = false;
                        break;
                    }
                }
            } else if (frame.cmd == vortex::CMD_CLOSE) {
                vortex::send_frame(peer->fd, peer->down, vortex::CMD_CLOSE, nullptr, 0,
                                   s->cfg.padding_min, s->cfg.padding_max);
                close_to_peer_sent = true;
                break;
            } else {
                peer_link_ok = false;
                break;
            }
        }

        s->alive = false;
        if (peer && peer->fd != INVALID_SOCK) set_recv_timeout(peer->fd, kPeerTeardownSec);
        if (peer && peer->alive && peer_link_ok && !close_to_peer_sent) {
            vortex::send_frame(peer->fd, peer->down, vortex::CMD_CLOSE, nullptr, 0,
                               s->cfg.padding_min, s->cfg.padding_max);
            close_to_peer_sent = true;
        }
        if (down_relay.joinable()) down_relay.join();
        (void)relay_done;
        (void)close_to_peer_sent;

        if (peer) {
            finish_peer_job(peer, s->cfg, peer_link_ok, got_peer_close.load());
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
              << "  peer-relay=on  port-forward=on" << std::endl;
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
