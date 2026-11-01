#include "config.hpp"
#include "net.hpp"
#include "protocol.hpp"
#include "rules.hpp"

#include <atomic>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

static int g_failed = 0;
#define CHECK(cond, msg)                                                                         \
    do {                                                                                         \
        if (!(cond)) {                                                                           \
            std::cerr << "FAIL: " << msg << "\n";                                                \
            ++g_failed;                                                                          \
        } else {                                                                                 \
            std::cout << "PASS: " << msg << "\n";                                                \
        }                                                                                        \
    } while (0)

static void test_prefer_ipv6_order() {
    std::vector<std::string> h = {"1.2.3.4", "2001:db8::1", "9.9.9.9", "::1"};
    prefer_ipv6_order(h);
    CHECK(h.size() == 4, "prefer size");
    CHECK(h[0].find(':') != std::string::npos, "first is v6");
    CHECK(h[1].find(':') != std::string::npos, "second is v6");
    CHECK(h[2].find(':') == std::string::npos, "third is v4");
}

static void test_parse_connect_ipv6() {
    std::vector<uint8_t> data;
    data.push_back(vortex::ATYP_IPV6);
    in6_addr a{};
    inet_pton(AF_INET6, "::1", &a);
    uint8_t raw[16];
    std::memcpy(raw, &a, 16);
    data.insert(data.end(), raw, raw + 16);
    uint16_t port = htons(8080);
    uint8_t pb[2];
    std::memcpy(pb, &port, 2);
    data.insert(data.end(), pb, pb + 2);
    std::string host;
    uint16_t out = 0;
    CHECK(vortex::parse_connect_target(data, host, out), "parse ipv6");
    CHECK(host == "::1", "ipv6 host ::1");
    CHECK(out == 8080, "ipv6 port");
}

static void test_listen_dual_and_v6() {
    if (!net_init()) {
        CHECK(false, "net_init");
        return;
    }
    // Prefer ports away from dualstack soak (29080) / e2e (28888).
    socket_t dual = create_listen_socket("::", 27991, 8);
    CHECK(dual != INVALID_SOCK, "listen :: dual-stack");
    socket_t c4 = tcp_connect("127.0.0.1", 27991, 3);
    CHECK(c4 != INVALID_SOCK, "connect dual via IPv4");
    socket_t a4 = accept_any(dual);
    CHECK(a4 != INVALID_SOCK, "accept IPv4-mapped on dual");
    if (c4 != INVALID_SOCK) net_close(c4);
    if (a4 != INVALID_SOCK) net_close(a4);

    socket_t c6 = tcp_connect("::1", 27991, 3);
    CHECK(c6 != INVALID_SOCK, "connect dual via IPv6");
    socket_t a6 = accept_any(dual);
    CHECK(a6 != INVALID_SOCK, "accept IPv6 on dual");
    if (c6 != INVALID_SOCK) net_close(c6);
    if (a6 != INVALID_SOCK) net_close(a6);
    if (dual != INVALID_SOCK) net_close(dual);

    // "*" same dual-stack semantics as "::"
    socket_t star = create_listen_socket("*", 27995, 8);
    CHECK(star != INVALID_SOCK, "listen * dual-stack");
    socket_t sc4 = tcp_connect("127.0.0.1", 27995, 3);
    socket_t sa4 = accept_any(star);
    CHECK(sc4 != INVALID_SOCK && sa4 != INVALID_SOCK, "* accepts IPv4");
    if (sc4 != INVALID_SOCK) net_close(sc4);
    if (sa4 != INVALID_SOCK) net_close(sa4);
    socket_t sc6 = tcp_connect("::1", 27995, 3);
    socket_t sa6 = accept_any(star);
    CHECK(sc6 != INVALID_SOCK && sa6 != INVALID_SOCK, "* accepts IPv6");
    if (sc6 != INVALID_SOCK) net_close(sc6);
    if (sa6 != INVALID_SOCK) net_close(sa6);
    if (star != INVALID_SOCK) net_close(star);

    // Legacy IPv4-only: 0.0.0.0 must still work; ::1 must not land on it.
    socket_t v4any = create_listen_socket("0.0.0.0", 27996, 8);
    CHECK(v4any != INVALID_SOCK, "listen 0.0.0.0 IPv4-only");
    socket_t v4c = tcp_connect("127.0.0.1", 27996, 3);
    socket_t v4a = accept_any(v4any);
    CHECK(v4c != INVALID_SOCK && v4a != INVALID_SOCK, "0.0.0.0 accepts IPv4");
    if (v4c != INVALID_SOCK) net_close(v4c);
    if (v4a != INVALID_SOCK) net_close(v4a);
    socket_t v4c6 = tcp_connect("::1", 27996, 3);
    CHECK(v4c6 == INVALID_SOCK, "0.0.0.0 rejects IPv6 connect");
    if (v4c6 != INVALID_SOCK) net_close(v4c6);
    if (v4any != INVALID_SOCK) net_close(v4any);

    socket_t v6only = create_listen_socket("::1", 27992, 8);
    CHECK(v6only != INVALID_SOCK, "listen ::1");
    socket_t c61 = tcp_connect("::1", 27992, 3);
    CHECK(c61 != INVALID_SOCK, "connect ::1");
    socket_t a61 = accept_any(v6only);
    CHECK(a61 != INVALID_SOCK, "accept ::1");
    if (c61 != INVALID_SOCK) net_close(c61);
    if (a61 != INVALID_SOCK) net_close(a61);
    if (v6only != INVALID_SOCK) net_close(v6only);
    net_cleanup();
}

static void test_client_server_ip_array() {
    const char* path = "tests/dualstack/client_dual.json";
    try {
        auto c = ClientConfig::load(path);
        CHECK(c.server_ips.size() == 2, "client dual server_ips size");
        CHECK(c.server_ip == "::1", "client prefers IPv6 primary");
        CHECK(c.uplink_hosts().front() == "::1", "uplink_hosts front ::1");
    } catch (const std::exception& e) {
        CHECK(false, std::string("load client_dual: ") + e.what());
    }
    try {
        auto p = PeerConfig::load("tests/dualstack/peer.json");
        CHECK(p.server_ips.size() == 2, "peer server_ips size");
        CHECK(p.server_ip == "::1", "peer prefers IPv6");
    } catch (const std::exception& e) {
        CHECK(false, std::string("load peer: ") + e.what());
    }
    try {
        auto m = MultilinkConfig::load("tests/dualstack/multilink.json");
        auto* l = m.find_link("link1");
        CHECK(l != nullptr, "multilink link1");
        if (l) {
            CHECK(l->server_ips.size() == 2, "multilink dual ips");
            CHECK(l->server_ip == "::1", "multilink prefers IPv6");
        }
    } catch (const std::exception& e) {
        CHECK(false, std::string("load multilink: ") + e.what());
    }
}

static void test_rules_ipv6() {
    rules::Engine eng;
    try {
        eng.load("tests/dualstack/rules.yaml", "config/geo/geoip-cn.txt",
                 "config/geo/geosite-cn.txt", "config/geo/geoipv6-cn.txt");
    } catch (const std::exception& e) {
        CHECK(false, std::string("rules load: ") + e.what());
        return;
    }
    auto d1 = eng.decide("::1", false, 0, false);
    CHECK(d1.action == rules::Action::Direct, "::1 DIRECT");
    auto d2 = eng.decide("127.0.0.1", true, 0x7f000001u, false);
    CHECK(d2.action == rules::Action::Direct, "127.0.0.1 DIRECT");
}

static void test_tcp_connect_hosts_prefer() {
    if (!net_init()) {
        CHECK(false, "net_init prefer");
        return;
    }
    socket_t l = create_listen_socket("::1", 27993, 8);
    CHECK(l != INVALID_SOCK, "prefer listen ::1");
    // Dead IPv4 first would fail; with IPv6-first order ::1 should win.
    std::vector<std::string> hosts = {"::1", "127.0.0.1"};
    prefer_ipv6_order(hosts);
    socket_t c = tcp_connect_hosts(hosts, 27993, 3);
    CHECK(c != INVALID_SOCK, "tcp_connect_hosts to ::1");
    socket_t a = accept_any(l);
    CHECK(a != INVALID_SOCK, "accept prefer");
    // Verify connected family is IPv6.
    if (c != INVALID_SOCK) {
        sockaddr_storage ss{};
        socklen_type sl = sizeof(ss);
        CHECK(getsockname(c, reinterpret_cast<sockaddr*>(&ss), &sl) == 0, "getsockname");
        CHECK(ss.ss_family == AF_INET6, "connected via AF_INET6");
        net_close(c);
    }
    if (a != INVALID_SOCK) net_close(a);
    if (l != INVALID_SOCK) net_close(l);
    net_cleanup();
}

static void test_tcp_connect_hosts_fallback() {
    if (!net_init()) {
        CHECK(false, "net_init fallback");
        return;
    }
    socket_t l = create_listen_socket("127.0.0.1", 27994, 8);
    CHECK(l != INVALID_SOCK, "fallback listen v4");
    // Unreachable ULA first — must fail over to 127.0.0.1 within connect timeout.
    std::vector<std::string> hosts = {"fd00::dead:beef", "127.0.0.1"};
    prefer_ipv6_order(hosts);
    CHECK(hosts.front().find(':') != std::string::npos, "fallback still prefers v6 first");
    ConnectHostsDetail detail;
    socket_t c = tcp_connect_hosts(hosts, 27994, 2, &detail);
    CHECK(c != INVALID_SOCK, "fallback to IPv4 after dead IPv6");
    CHECK(detail.used_host == "127.0.0.1", "detail used IPv4");
    CHECK(detail.failed_hosts.size() == 1, "detail recorded dead IPv6");
    CHECK(std::string(host_family_tag(detail.failed_hosts.front())) == "v6", "failed tag v6");
    CHECK(std::string(host_family_tag(detail.used_host)) == "v4", "used tag v4");
    socket_t a = accept_any(l);
    CHECK(a != INVALID_SOCK, "accept fallback");
    if (c != INVALID_SOCK) net_close(c);
    if (a != INVALID_SOCK) net_close(a);
    if (l != INVALID_SOCK) net_close(l);
    net_cleanup();
}

static void test_tcp_connect_direct_host_prefer() {
    if (!net_init()) {
        CHECK(false, "net_init direct prefer");
        return;
    }
    // DNS stub: AAAA=::1 A=127.0.0.1; only ::1 listens → must pick IPv6.
    const int dns_port = 15401;
    const int echo_port = 27997;
    socket_t l = create_listen_socket("::1", echo_port, 8);
    CHECK(l != INVALID_SOCK, "direct prefer listen ::1");

    // Fork-less: resolve via stub in a background accept? Use resolve then connect helpers.
    // Spin stub in a detached thread by execing is heavy; call resolve_hosts against stub
    // process started by the shell harness. Here we simulate the same path with an
    // in-process DNS-over-TCP peer using a tiny listener that answers A/AAAA.
    std::atomic<bool> stub_run{true};
    socket_t stub = create_listen_socket("127.0.0.1", dns_port, 8);
    CHECK(stub != INVALID_SOCK, "direct prefer dns stub listen");
    auto stub_reply = [](const uint8_t* q, size_t qlen, uint16_t want_type,
                         const uint8_t* rdata, size_t rdlen) {
        std::vector<uint8_t> out(q, q + qlen);
        out[2] = 0x81;
        out[3] = 0x80;
        out[6] = 0;
        out[7] = 1;
        out[8] = out[9] = out[10] = out[11] = 0;
        out.push_back(0xC0);
        out.push_back(0x0C);
        out.push_back(static_cast<uint8_t>(want_type >> 8));
        out.push_back(static_cast<uint8_t>(want_type & 0xFF));
        out.push_back(0x00);
        out.push_back(0x01);
        out.push_back(0x00);
        out.push_back(0x00);
        out.push_back(0x00);
        out.push_back(0x3C);
        out.push_back(static_cast<uint8_t>(rdlen >> 8));
        out.push_back(static_cast<uint8_t>(rdlen & 0xFF));
        out.insert(out.end(), rdata, rdata + rdlen);
        return out;
    };
    std::thread stub_thr([&] {
        while (stub_run.load()) {
            socket_t c = accept_any(stub);
            if (c == INVALID_SOCK) continue;
            set_socket_options(c, 3);
            uint8_t lenb[2];
            if (!recv_exact(c, lenb, 2)) {
                net_close(c);
                continue;
            }
            const size_t qlen = (static_cast<size_t>(lenb[0]) << 8) | lenb[1];
            if (qlen < 12 || qlen > 4096) {
                net_close(c);
                continue;
            }
            std::vector<uint8_t> q(qlen);
            if (!recv_exact(c, q.data(), qlen)) {
                net_close(c);
                continue;
            }
            size_t off = 12;
            while (off < q.size() && q[off] != 0) {
                off += 1 + q[off];
                if (off >= q.size()) break;
            }
            uint16_t qtype = 0;
            if (off + 3 < q.size()) {
                qtype = static_cast<uint16_t>((q[off + 1] << 8) | q[off + 2]);
            }
            const uint8_t v4[] = {127, 0, 0, 1};
            uint8_t v6b[16] = {};
            v6b[15] = 1; // ::1
            auto ans = (qtype == 28) ? stub_reply(q.data(), q.size(), 28, v6b, 16)
                                     : stub_reply(q.data(), q.size(), 1, v4, 4);
            uint8_t rlen[2] = {static_cast<uint8_t>(ans.size() >> 8),
                               static_cast<uint8_t>(ans.size())};
            send_all(c, rlen, 2);
            send_all(c, ans.data(), ans.size());
            net_close(c);
        }
    });

    socket_t c = tcp_connect_direct_host("prefer-v6.test", echo_port, 3, "127.0.0.1", dns_port);
    CHECK(c != INVALID_SOCK, "tcp_connect_direct_host prefers IPv6");
    if (c != INVALID_SOCK) {
        sockaddr_storage ss{};
        socklen_type sl = sizeof(ss);
        CHECK(getsockname(c, reinterpret_cast<sockaddr*>(&ss), &sl) == 0, "direct prefer getsockname");
        CHECK(ss.ss_family == AF_INET6, "direct prefer connected AF_INET6");
        net_close(c);
    }
    socket_t a = accept_any(l);
    CHECK(a != INVALID_SOCK, "direct prefer accept");
    if (a != INVALID_SOCK) net_close(a);

    stub_run = false;
    // Unblock accept
    socket_t wake = tcp_connect("127.0.0.1", dns_port, 1);
    if (wake != INVALID_SOCK) net_close(wake);
    net_close(stub);
    if (stub_thr.joinable()) stub_thr.join();
    if (l != INVALID_SOCK) net_close(l);
    net_cleanup();
}

static void test_tcp_connect_direct_host_fallback() {
    if (!net_init()) {
        CHECK(false, "net_init direct fallback");
        return;
    }
    const int dns_port = 15402;
    const int echo_port = 27998;
    // Only IPv4 listener; AAAA is dead ULA → must fall back to A.
    socket_t l = create_listen_socket("127.0.0.1", echo_port, 8);
    CHECK(l != INVALID_SOCK, "direct fallback listen v4");

    std::atomic<bool> stub_run{true};
    socket_t stub = create_listen_socket("127.0.0.1", dns_port, 8);
    CHECK(stub != INVALID_SOCK, "direct fallback dns stub listen");
    std::thread stub_thr([&] {
        while (stub_run.load()) {
            socket_t c = accept_any(stub);
            if (c == INVALID_SOCK) continue;
            set_socket_options(c, 3);
            uint8_t lenb[2];
            if (!recv_exact(c, lenb, 2)) {
                net_close(c);
                continue;
            }
            const size_t qlen = (static_cast<size_t>(lenb[0]) << 8) | lenb[1];
            if (qlen < 12 || qlen > 4096) {
                net_close(c);
                continue;
            }
            std::vector<uint8_t> q(qlen);
            if (!recv_exact(c, q.data(), qlen)) {
                net_close(c);
                continue;
            }
            size_t off = 12;
            while (off < q.size() && q[off] != 0) {
                off += 1 + q[off];
                if (off >= q.size()) break;
            }
            uint16_t qtype = 0;
            if (off + 3 < q.size()) {
                qtype = static_cast<uint16_t>((q[off + 1] << 8) | q[off + 2]);
            }
            std::vector<uint8_t> ans(q.data(), q.data() + qlen);
            ans[2] = 0x81;
            ans[3] = 0x80;
            ans[6] = 0;
            ans[7] = 1;
            ans[8] = ans[9] = ans[10] = ans[11] = 0;
            ans.push_back(0xC0);
            ans.push_back(0x0C);
            ans.push_back(static_cast<uint8_t>(qtype >> 8));
            ans.push_back(static_cast<uint8_t>(qtype & 0xFF));
            ans.push_back(0x00);
            ans.push_back(0x01);
            ans.push_back(0x00);
            ans.push_back(0x00);
            ans.push_back(0x00);
            ans.push_back(0x3C);
            if (qtype == 28) {
                // fd00::dead:beef
                in6_addr a6{};
                inet_pton(AF_INET6, "fd00::dead:beef", &a6);
                ans.push_back(0x00);
                ans.push_back(0x10);
                const uint8_t* p = reinterpret_cast<const uint8_t*>(&a6);
                ans.insert(ans.end(), p, p + 16);
            } else {
                ans.push_back(0x00);
                ans.push_back(0x04);
                ans.push_back(0x7F);
                ans.push_back(0x00);
                ans.push_back(0x00);
                ans.push_back(0x01);
            }
            uint8_t rlen[2] = {static_cast<uint8_t>(ans.size() >> 8),
                               static_cast<uint8_t>(ans.size())};
            send_all(c, rlen, 2);
            send_all(c, ans.data(), ans.size());
            net_close(c);
        }
    });

    socket_t c = tcp_connect_direct_host("fallback-v4.test", echo_port, 2, "127.0.0.1", dns_port);
    CHECK(c != INVALID_SOCK, "tcp_connect_direct_host falls back to IPv4");
    if (c != INVALID_SOCK) {
        sockaddr_storage ss{};
        socklen_type sl = sizeof(ss);
        CHECK(getsockname(c, reinterpret_cast<sockaddr*>(&ss), &sl) == 0, "direct fallback getsockname");
        CHECK(ss.ss_family == AF_INET, "direct fallback connected AF_INET");
        net_close(c);
    }
    socket_t a = accept_any(l);
    CHECK(a != INVALID_SOCK, "direct fallback accept");
    if (a != INVALID_SOCK) net_close(a);

    stub_run = false;
    socket_t wake = tcp_connect("127.0.0.1", dns_port, 1);
    if (wake != INVALID_SOCK) net_close(wake);
    net_close(stub);
    if (stub_thr.joinable()) stub_thr.join();
    if (l != INVALID_SOCK) net_close(l);
    net_cleanup();
}

static void test_dns_collect_a_aaaa() {
    // Minimal synthetic answers: parse A + AAAA RDATA via dns_collect_answer_hosts.
    auto mk_ans = [](uint16_t typ, const uint8_t* rdata, size_t rdlen) {
        std::vector<uint8_t> m;
        // header
        m.insert(m.end(), {0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00});
        // QNAME: a.test
        m.push_back(1);
        m.push_back('a');
        m.push_back(4);
        m.push_back('t');
        m.push_back('e');
        m.push_back('s');
        m.push_back('t');
        m.push_back(0);
        m.push_back(static_cast<uint8_t>(typ >> 8));
        m.push_back(static_cast<uint8_t>(typ & 0xFF));
        m.push_back(0x00);
        m.push_back(0x01);
        // Answer pointer + RR
        m.push_back(0xC0);
        m.push_back(0x0C);
        m.push_back(static_cast<uint8_t>(typ >> 8));
        m.push_back(static_cast<uint8_t>(typ & 0xFF));
        m.push_back(0x00);
        m.push_back(0x01);
        m.push_back(0x00);
        m.push_back(0x00);
        m.push_back(0x00);
        m.push_back(0x3C);
        m.push_back(static_cast<uint8_t>(rdlen >> 8));
        m.push_back(static_cast<uint8_t>(rdlen & 0xFF));
        m.insert(m.end(), rdata, rdata + rdlen);
        return m;
    };
    const uint8_t v4[] = {127, 0, 0, 1};
    const uint8_t v6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    auto a = mk_ans(1, v4, 4);
    auto aaaa = mk_ans(28, v6, 16);
    std::vector<std::string> ov6, ov4;
    dns_collect_answer_hosts(a.data(), a.size(), ov6, ov4);
    CHECK(ov4.size() == 1 && ov4[0] == "127.0.0.1", "collect A");
    ov6.clear();
    ov4.clear();
    dns_collect_answer_hosts(aaaa.data(), aaaa.size(), ov6, ov4);
    CHECK(ov6.size() == 1 && ov6[0] == "::1", "collect AAAA");
}

static void test_multilink_fallback_config() {
    try {
        auto m = MultilinkConfig::load("tests/dualstack/multilink_fallback.json");
        auto* l = m.find_link("link1");
        CHECK(l != nullptr, "fallback cfg link1");
        if (l) {
            CHECK(l->server_ips.size() == 2, "fallback cfg dual ips");
            CHECK(l->server_ips.front().find(':') != std::string::npos, "fallback cfg v6 first");
            CHECK(l->server_ips.back() == "127.0.0.1", "fallback cfg v4 second");
        }
    } catch (const std::exception& e) {
        CHECK(false, std::string("load multilink_fallback: ") + e.what());
    }
}

static void test_bind_ip_array_config_and_listen() {
    const char* path = "/tmp/vortex_bind_ip_array_ut.json";
    {
        std::ofstream out(path);
        out << "{\n"
               "  \"bind_ip\": [\"::1\", \"127.0.0.1\"],\n"
               "  \"bind_port\": 27980,\n"
               "  \"master_secret\": \"ut\"\n"
               "}\n";
    }
    try {
        auto c = ServerConfig::load(path);
        CHECK(c.bind_ips.size() == 2, "bind_ips size 2");
        CHECK(c.bind_ips[0] == "::1", "bind_ips[0] ::1");
        CHECK(c.bind_ips[1] == "127.0.0.1", "bind_ips[1] v4");
        CHECK(c.bind_ip == "::1", "bind_ip primary");
    } catch (const std::exception& e) {
        CHECK(false, std::string("load bind array: ") + e.what());
        return;
    }

    {
        std::ofstream out(path);
        out << "{\n"
               "  \"bind_ip\": [\"::\", \"0.0.0.0\"],\n"
               "  \"bind_port\": 27981,\n"
               "  \"master_secret\": \"ut\"\n"
               "}\n";
    }
    try {
        auto c = ServerConfig::load(path);
        CHECK(c.bind_ips.size() == 2, "any bind_ips size");
        CHECK(c.bind_ips[0] == "::" && c.bind_ips[1] == "0.0.0.0", "any bind pair");
    } catch (const std::exception& e) {
        CHECK(false, std::string("load any bind array: ") + e.what());
    }

    if (!net_init()) {
        CHECK(false, "net_init bind array");
        return;
    }
    // Explicit dual sockets: :: with V6ONLY=1 + 0.0.0.0
    socket_t v6 = create_listen_socket("::", 27982, 8, false);
    socket_t v4 = create_listen_socket("0.0.0.0", 27982, 8, true);
    CHECK(v6 != INVALID_SOCK && v4 != INVALID_SOCK, "multi-bind :: + 0.0.0.0");
    socket_t c4 = tcp_connect("127.0.0.1", 27982, 3);
    socket_t a4 = accept_any(v4);
    CHECK(c4 != INVALID_SOCK && a4 != INVALID_SOCK, "multi-bind accepts IPv4");
    if (c4 != INVALID_SOCK) net_close(c4);
    if (a4 != INVALID_SOCK) net_close(a4);
    socket_t c6 = tcp_connect("::1", 27982, 3);
    socket_t a6 = accept_any(v6);
    CHECK(c6 != INVALID_SOCK && a6 != INVALID_SOCK, "multi-bind accepts IPv6");
    if (c6 != INVALID_SOCK) net_close(c6);
    if (a6 != INVALID_SOCK) net_close(a6);
    if (v4 != INVALID_SOCK) net_close(v4);
    if (v6 != INVALID_SOCK) net_close(v6);

    socket_t l6 = create_listen_socket("::1", 27983, 8);
    socket_t l4 = create_listen_socket("127.0.0.1", 27983, 8);
    CHECK(l6 != INVALID_SOCK && l4 != INVALID_SOCK, "loopback dual bind");
    socket_t lc4 = tcp_connect("127.0.0.1", 27983, 3);
    socket_t la4 = accept_any(l4);
    CHECK(lc4 != INVALID_SOCK && la4 != INVALID_SOCK, "loopback v4");
    if (lc4 != INVALID_SOCK) net_close(lc4);
    if (la4 != INVALID_SOCK) net_close(la4);
    socket_t lc6 = tcp_connect("::1", 27983, 3);
    socket_t la6 = accept_any(l6);
    CHECK(lc6 != INVALID_SOCK && la6 != INVALID_SOCK, "loopback v6");
    if (lc6 != INVALID_SOCK) net_close(lc6);
    if (la6 != INVALID_SOCK) net_close(la6);
    if (l4 != INVALID_SOCK) net_close(l4);
    if (l6 != INVALID_SOCK) net_close(l6);
    net_cleanup();
}

int main() {
    test_prefer_ipv6_order();
    test_parse_connect_ipv6();
    test_listen_dual_and_v6();
    test_client_server_ip_array();
    test_bind_ip_array_config_and_listen();
    test_rules_ipv6();
    test_tcp_connect_hosts_prefer();
    test_tcp_connect_hosts_fallback();
    test_tcp_connect_direct_host_prefer();
    test_tcp_connect_direct_host_fallback();
    test_dns_collect_a_aaaa();
    test_multilink_fallback_config();
    if (g_failed) {
        std::cerr << g_failed << " dualstack unit failures\n";
        return 1;
    }
    std::cout << "All dualstack unit tests passed\n";
    return 0;
}
