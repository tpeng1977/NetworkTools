#include "protocol.hpp"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

static int g_fail = 0;

static void expect(bool cond, const char* msg) {
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", msg);
        ++g_fail;
    } else {
        std::printf("PASS: %s\n", msg);
    }
}

int main() {
    // Build CONNECT target wire: domain example.com:80
    const std::string host = "example.com";
    std::vector<uint8_t> wire;
    wire.push_back(vortex::ATYP_DOMAIN);
    wire.push_back(static_cast<uint8_t>(host.size()));
    wire.insert(wire.end(), host.begin(), host.end());
    wire.push_back(0);
    wire.push_back(80);

    const std::string secret = "test_peer_secret";
    const auto payload = vortex::build_via_peer_payload(secret, wire);
    expect(!payload.empty(), "build_via_peer_payload non-empty");
    expect(payload[0] == secret.size(), "secret length prefix");

    std::string out_secret;
    std::vector<uint8_t> out_wire;
    expect(vortex::parse_via_peer_payload(payload, out_secret, out_wire), "parse ok");
    expect(out_secret == secret, "secret round-trip");
    expect(out_wire == wire, "target wire round-trip");

    std::string thost;
    uint16_t tport = 0;
    expect(vortex::parse_connect_target(out_wire, thost, tport), "parse connect target");
    expect(thost == host && tport == 80, "host/port match");

    expect(vortex::build_via_peer_payload("", wire).empty(), "empty secret rejected");
    expect(vortex::CMD_PEER_HELLO == 0x06 && vortex::CMD_VIA_PEER == 0x07, "cmd ids");

    if (g_fail) {
        std::fprintf(stderr, "%d failure(s)\n", g_fail);
        return 1;
    }
    std::printf("All peer protocol tests passed\n");
    return 0;
}
