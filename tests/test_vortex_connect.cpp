// E2E: open Vortex CONNECT via multilink.json uplinks with ATYP_DOMAIN
// (remote DNS). Verifies google / youtube / mit reachability without activate_net.
#include "config.hpp"
#include "net.hpp"
#include "protocol.hpp"
#include "rules.hpp"
#include "vortex_cipher.hpp"

#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#ifdef _WIN32
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <sys/socket.h>
#  include <unistd.h>
#endif

static int g_fail = 0;

static void expect(bool ok, const std::string& msg) {
    if (!ok) {
        std::cerr << "[FAIL] " << msg << "\n";
        ++g_fail;
    } else {
        std::cout << "[OK] " << msg << "\n";
    }
}

static socket_t tcp_connect_ip(const std::string& ip, int port, int timeout_sec) {
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, ip.c_str(), &dst.sin_addr) != 1) return INVALID_SOCK;
    socket_t s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCK) return INVALID_SOCK;
#ifdef _WIN32
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
#else
    int flags = fcntl(s, F_GETFL, 0);
    fcntl(s, F_SETFL, flags | O_NONBLOCK);
#endif
    int rc = connect(s, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
#ifdef _WIN32
    if (rc != 0 && WSAGetLastError() != WSAEWOULDBLOCK) {
        net_close(s);
        return INVALID_SOCK;
    }
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(s, &wfds);
    timeval tv{};
    tv.tv_sec = timeout_sec;
    rc = select(0, nullptr, &wfds, nullptr, &tv);
    if (rc <= 0) {
        net_close(s);
        return INVALID_SOCK;
    }
    int soerr = 0;
    int slen = sizeof(soerr);
    getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &slen);
    if (soerr != 0) {
        net_close(s);
        return INVALID_SOCK;
    }
    nb = 0;
    ioctlsocket(s, FIONBIO, &nb);
    DWORD ms = static_cast<DWORD>(timeout_sec) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&ms), sizeof(ms));
#else
    (void)timeout_sec;
#endif
    return s;
}

static bool vortex_connect_domain(const LinkEndpoint& link, const std::string& host, uint16_t port,
                                  std::string& err) {
    socket_t s = tcp_connect_ip(link.server_ip, link.server_port, link.idle_timeout_sec);
    if (s == INVALID_SOCK) {
        err = "uplink TCP failed";
        return false;
    }
    const uint64_t salt = get_random_salt();
    uint8_t salt_buf[8];
    std::memcpy(salt_buf, &salt, 8);
    if (!send_all(s, salt_buf, 8)) {
        err = "salt send failed";
        net_close(s);
        return false;
    }
    vortex::SessionCrypto up, down;
    up.init(link.master_secret, salt);
    down.init(link.master_secret, salt ^ 0xA5A5A5A5A5A5A5A5ULL);

    std::vector<uint8_t> wire;
    wire.push_back(vortex::ATYP_DOMAIN);
    wire.push_back(static_cast<uint8_t>(host.size()));
    wire.insert(wire.end(), host.begin(), host.end());
    wire.push_back(static_cast<uint8_t>(port >> 8));
    wire.push_back(static_cast<uint8_t>(port));

    if (!vortex::send_frame(s, up, vortex::CMD_CONNECT, wire, link.padding_min, link.padding_max)) {
        err = "CONNECT send failed";
        net_close(s);
        return false;
    }
    auto reply = vortex::recv_frame(s, down, link.max_payload);
    if (!reply.ok || reply.cmd != vortex::CMD_CONNECT_OK) {
        err = reply.ok ? ("cmd=" + std::to_string(reply.cmd)) : "frame error";
        net_close(s);
        return false;
    }

    // TLS ClientHello-ish probe is overkill; send HTTP GET for :80 only.
    if (port == 80) {
        const std::string req = "HEAD / HTTP/1.1\r\nHost: " + host + "\r\nConnection: close\r\n\r\n";
        if (!vortex::send_frame(s, up, vortex::CMD_DATA,
                                reinterpret_cast<const uint8_t*>(req.data()), req.size(),
                                link.padding_min, link.padding_max)) {
            err = "DATA send failed";
            net_close(s);
            return false;
        }
        auto data = vortex::recv_frame(s, down, link.max_payload);
        if (!data.ok || data.cmd != vortex::CMD_DATA || data.data.size() < 12) {
            err = "no HTTP response";
            net_close(s);
            return false;
        }
    }
    net_close(s);
    return true;
}

int main() {
    if (!net_init()) {
        std::cerr << "[-] net_init failed\n";
        return 1;
    }

    MultilinkConfig cfg;
    try {
        cfg = MultilinkConfig::load("config/multilink.json");
    } catch (const std::exception& e) {
        std::cerr << "[-] " << e.what() << "\n";
        return 1;
    }
    rules::Engine eng;
    eng.load(cfg.rules_path, cfg.geoip_cn, cfg.geosite_cn);

    struct Target {
        const char* host;
        uint16_t port;
        const char* expect_link;
    };
    const Target targets[] = {
        {"www.google.com", 443, "link1"},
        {"www.youtube.com", 443, "link1"},
        {"web.mit.edu", 443, "link1"},
        {"www.baidu.com", 443, "DIRECT"},
    };

    for (const auto& t : targets) {
        const auto d = eng.decide(t.host, false, 0, false);
        const std::string out = rules::decision_name(d);
        expect(out == t.expect_link,
               std::string("rule ") + t.host + " -> " + out + " (" + d.matched + ")");
        if (d.action == rules::Action::Direct) continue;

        const LinkEndpoint* ep = cfg.find_link(d.outbound);
        expect(ep != nullptr, std::string("link ") + d.outbound + " exists");
        if (!ep) continue;

        std::string err;
        const auto t0 = std::chrono::steady_clock::now();
        const bool ok = vortex_connect_domain(*ep, t.host, t.port, err);
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - t0)
                            .count();
        expect(ok, std::string("CONNECT ") + t.host + ":" + std::to_string(t.port) + " via " +
                       ep->name + " remote-DNS (" + std::to_string(ms) + "ms)" +
                       (ok ? "" : " err=" + err));
    }

    net_cleanup();
    if (g_fail) {
        std::cerr << g_fail << " failures\n";
        return 1;
    }
    std::cout << "All vortex connect tests passed\n";
    return 0;
}
