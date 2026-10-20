#include "config.hpp"
#include "protocol.hpp"
#include "vortex_cipher.hpp"

#include <cassert>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

static int g_failed = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { \
        std::cerr << "FAIL: " << msg << "\n"; \
        ++g_failed; \
    } else { \
        std::cout << "PASS: " << msg << "\n"; \
    } \
} while (0)

void test_cipher_roundtrip() {
    const std::string key = "VortexSecureNetwork2026_KeyMix";
    uint64_t salt = 0x1122334455667788ULL;
    VortexCipher a(key, salt);
    VortexCipher b(key, salt);
    uint64_t seq_a = 0, seq_b = 0;

    std::vector<uint8_t> data(1000);
    for (size_t i = 0; i < data.size(); ++i) data[i] = static_cast<uint8_t>(i & 0xFF);
    auto original = data;

    a.crypt(data, seq_a);
    CHECK(data != original, "cipher changes plaintext");
    b.crypt(data, seq_b);
    CHECK(data == original, "cipher decrypt restores plaintext");
    CHECK(seq_a == seq_b, "sequences match after roundtrip");
}

void test_cipher_direction_isolation() {
    const std::string key = "test-key";
    uint64_t salt = 99;
    VortexCipher up(key, salt);
    VortexCipher down(key, salt ^ 0xA5A5A5A5A5A5A5A5ULL);
    uint64_t su = 0, sd = 0;

    std::vector<uint8_t> msg = {1, 2, 3, 4, 5};
    auto copy = msg;
    up.crypt(msg, su);
    down.crypt(copy, sd);
    CHECK(msg != copy, "up/down directions produce different streams");
}

void test_parse_connect_ipv4() {
    std::vector<uint8_t> data;
    data.push_back(vortex::ATYP_IPV4);
    data.push_back(127);
    data.push_back(0);
    data.push_back(0);
    data.push_back(1);
    uint16_t port = htons(80);
    uint8_t pb[2];
    std::memcpy(pb, &port, 2);
    data.insert(data.end(), pb, pb + 2);

    std::string host;
    uint16_t out_port = 0;
    bool ok = vortex::parse_connect_target(data, host, out_port);
    CHECK(ok, "parse ipv4 connect");
    CHECK(host == "127.0.0.1", "ipv4 host");
    CHECK(out_port == 80, "ipv4 port");
}

void test_parse_connect_domain() {
    std::string domain = "example.com";
    std::vector<uint8_t> data;
    data.push_back(vortex::ATYP_DOMAIN);
    data.push_back(static_cast<uint8_t>(domain.size()));
    data.insert(data.end(), domain.begin(), domain.end());
    uint16_t port = htons(443);
    uint8_t pb[2];
    std::memcpy(pb, &port, 2);
    data.insert(data.end(), pb, pb + 2);

    std::string host;
    uint16_t out_port = 0;
    bool ok = vortex::parse_connect_target(data, host, out_port);
    CHECK(ok, "parse domain connect");
    CHECK(host == "example.com", "domain host");
    CHECK(out_port == 443, "domain port");
}

void test_config_server() {
    try {
        auto c = ServerConfig::load("config/server.json");
        CHECK(c.bind_port == 18888, "server bind_port");
        CHECK(c.bind_ip == "0.0.0.0", "server bind_ip");
        CHECK(!c.master_secret.empty(), "server master_secret");
        CHECK(c.camouflage == true, "server camouflage");
        CHECK(c.padding_max >= c.padding_min, "server padding range");
    } catch (const std::exception& e) {
        CHECK(false, std::string("server config load: ") + e.what());
    }
}

void test_config_client() {
    try {
        auto c = ClientConfig::load("config/client.json");
        CHECK(c.socks5_bind_port == 11080, "client socks5 port");
        CHECK(c.server_port == 18888, "client server port");
        CHECK(c.server_ip == "127.0.0.1", "client server ip");
        CHECK(!c.master_secret.empty(), "client master_secret");
    } catch (const std::exception& e) {
        CHECK(false, std::string("client config load: ") + e.what());
    }
}

void test_frame_pipe() {
    // In-memory frame encode/decode via socket pair simulation using loopback TCP
    if (!net_init()) {
        CHECK(false, "net_init");
        return;
    }

    socket_t listen_fd = create_listen_socket("127.0.0.1", 18999, 8);
    CHECK(listen_fd != INVALID_SOCK, "create test listen socket");
    if (listen_fd == INVALID_SOCK) {
        net_cleanup();
        return;
    }

    socket_t client = tcp_connect("127.0.0.1", 18999, 5);
    CHECK(client != INVALID_SOCK, "test client connect");
    sockaddr_in peer{};
    socklen_type plen = sizeof(peer);
    socket_t server = accept(listen_fd, reinterpret_cast<sockaddr*>(&peer), &plen);
    CHECK(server != INVALID_SOCK, "test server accept");

    if (client != INVALID_SOCK && server != INVALID_SOCK) {
        const std::string secret = "frame-test-secret";
        uint64_t salt = 0xDEADBEEFCAFEBABEULL;
        vortex::SessionCrypto send_c, recv_c;
        send_c.init(secret, salt);
        recv_c.init(secret, salt);

        std::vector<uint8_t> payload = {'H', 'e', 'l', 'l', 'o', '!', 1, 2, 3};
        bool sent = vortex::send_frame(client, send_c, vortex::CMD_DATA,
                                       payload, 8, 32);
        CHECK(sent, "send_frame");

        auto frame = vortex::recv_frame(server, recv_c, 32768);
        CHECK(frame.ok, "recv_frame ok");
        CHECK(frame.cmd == vortex::CMD_DATA, "recv_frame cmd");
        CHECK(frame.data == payload, "recv_frame payload");

        // Multi-frame sequence continuity
        for (int i = 0; i < 20; ++i) {
            std::vector<uint8_t> p = {static_cast<uint8_t>(i), 0xAA, 0xBB};
            CHECK(vortex::send_frame(client, send_c, vortex::CMD_DATA, p, 0, 16),
                  "multi send");
            auto f = vortex::recv_frame(server, recv_c, 32768);
            CHECK(f.ok && f.data == p, "multi recv");
        }

        net_close(client);
        net_close(server);
    }
    net_close(listen_fd);
    net_cleanup();
}

int main() {
    std::cout << "=== Vortex core unit tests ===\n";
    test_cipher_roundtrip();
    test_cipher_direction_isolation();
    test_parse_connect_ipv4();
    test_parse_connect_domain();
    test_config_server();
    test_config_client();
    test_frame_pipe();

    if (g_failed == 0) {
        std::cout << "\nAll tests passed.\n";
        return 0;
    }
    std::cout << "\n" << g_failed << " assertion(s) failed.\n";
    return 1;
}
