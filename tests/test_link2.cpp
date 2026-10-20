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

static socket_t connect_ip(const std::string& ip, int port, int sec) {
    sockaddr_in dst{};
    dst.sin_family = AF_INET;
    dst.sin_port = htons(static_cast<uint16_t>(port));
    if (inet_pton(AF_INET, ip.c_str(), &dst.sin_addr) != 1) return INVALID_SOCK;
    socket_t s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (s == INVALID_SOCK) return INVALID_SOCK;
#ifdef _WIN32
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    int rc = connect(s, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
    if (rc != 0 && WSAGetLastError() != WSAEWOULDBLOCK) {
        net_close(s);
        return INVALID_SOCK;
    }
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(s, &wfds);
    timeval tv{};
    tv.tv_sec = sec;
    if (select(0, nullptr, &wfds, nullptr, &tv) <= 0) {
        net_close(s);
        return INVALID_SOCK;
    }
    int soerr = 0, slen = sizeof(soerr);
    getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &slen);
    if (soerr) {
        net_close(s);
        return INVALID_SOCK;
    }
    nb = 0;
    ioctlsocket(s, FIONBIO, &nb);
    DWORD ms = static_cast<DWORD>(sec) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&ms), sizeof(ms));
#endif
    return s;
}

static bool vortex_domain(const LinkEndpoint& link, const std::string& host, uint16_t port,
                          std::string& err) {
    socket_t s = connect_ip(link.server_ip, link.server_port, 8);
    if (s == INVALID_SOCK) {
        err = "TCP to " + link.server_ip + ":" + std::to_string(link.server_port) + " failed";
        return false;
    }
    uint64_t salt = get_random_salt();
    uint8_t sb[8];
    std::memcpy(sb, &salt, 8);
    if (!send_all(s, sb, 8)) {
        err = "salt";
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
        err = "send CONNECT";
        net_close(s);
        return false;
    }
    auto r = vortex::recv_frame(s, down, link.max_payload);
    net_close(s);
    if (!r.ok || r.cmd != vortex::CMD_CONNECT_OK) {
        err = r.ok ? ("cmd=" + std::to_string(r.cmd)) : "bad frame";
        return false;
    }
    return true;
}

int main() {
    if (!net_init()) return 1;
    MultilinkConfig cfg = MultilinkConfig::load("config/multilink.json");
    rules::Engine eng;
    eng.load(cfg.rules_path, cfg.geoip_cn, cfg.geosite_cn);

    expect(cfg.find_link("link1") != nullptr, "link1 loaded");
    expect(cfg.find_link("link2") != nullptr, "link2 loaded");
    if (cfg.find_link("link1")) {
        std::cout << "    link1 -> " << cfg.find_link("link1")->server_ip << ":"
                  << cfg.find_link("link1")->server_port << "\n";
    }
    if (cfg.find_link("link2")) {
        std::cout << "    link2 -> " << cfg.find_link("link2")->server_ip << ":"
                  << cfg.find_link("link2")->server_port << "\n";
    }

    auto d = eng.decide("test-ipv6.com", false, 0, false);
    expect(rules::decision_name(d) == "link2" && d.matched.find("test-ipv6") != std::string::npos,
           "test-ipv6.com => link2 (" + d.matched + ")");
    d = eng.decide("ipv4.lookup.test-ipv6.com", false, 0, false);
    expect(rules::decision_name(d) == "link2", "ipv4.lookup.test-ipv6.com => link2");
    d = eng.decide("www.google.com", false, 0, false);
    expect(rules::decision_name(d) == "link1", "www.google.com => link1 (" + d.matched + ")");

    for (const char* name : {"link1", "link2"}) {
        const LinkEndpoint* ep = cfg.find_link(name);
        if (!ep) continue;
        std::string err;
        auto t0 = std::chrono::steady_clock::now();
        bool ok = vortex_domain(*ep, "www.google.com", 443, err);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - t0)
                      .count();
        expect(ok, std::string(name) + " CONNECT www.google.com:443 (" + std::to_string(ms) +
                       "ms)" + (ok ? "" : " " + err));
    }

    {
        const LinkEndpoint* ep = cfg.find_link("link2");
        std::string err;
        auto t0 = std::chrono::steady_clock::now();
        bool ok = vortex_domain(*ep, "test-ipv6.com", 443, err);
        auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                      std::chrono::steady_clock::now() - t0)
                      .count();
        expect(ok, "link2 CONNECT test-ipv6.com:443 (" + std::to_string(ms) + "ms)" +
                       (ok ? "" : " " + err));
    }

    net_cleanup();
    if (g_fail) {
        std::cerr << g_fail << " failures\n";
        return 1;
    }
    std::cout << "All link2 tests passed\n";
    return 0;
}
