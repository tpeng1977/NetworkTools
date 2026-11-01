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
    expect(vortex::CMD_FWD_CONFIG == 0x08 && vortex::CMD_UDP_DATA == 0x09 &&
               vortex::CMD_UDP_CLOSE == 0x0A,
           "fwd cmd ids");
    expect(vortex::CMD_ICMP == 0x0B && vortex::CMD_VIA_PEER_ICMP == 0x0C, "icmp cmd ids");

    // ICMP wire + VIA_PEER_ICMP round-trip (v4 + v6)
    {
        uint8_t echo[8] = {8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01};
        const auto wire = vortex::build_icmp_wire("127.0.0.1", echo, sizeof(echo));
        expect(!wire.empty() && wire[0] == 1 && wire[1] == vortex::ATYP_IPV4, "icmp wire build");
        std::string h;
        std::vector<uint8_t> ic;
        expect(vortex::parse_icmp_wire(wire, h, ic), "icmp wire parse");
        expect(h == "127.0.0.1" && ic.size() == 8 && ic[0] == 8, "icmp wire fields");
        const auto via = vortex::build_via_peer_icmp_payload(secret, wire);
        std::string sec2;
        std::vector<uint8_t> wire2;
        expect(vortex::parse_via_peer_icmp_payload(via, sec2, wire2), "via icmp parse");
        expect(sec2 == secret && wire2 == wire, "via icmp round-trip");

        uint8_t echo6[8] = {128, 0, 0, 0, 0x56, 0x78, 0x00, 0x02};
        const auto wire6 = vortex::build_icmp_wire("::1", echo6, sizeof(echo6));
        expect(!wire6.empty() && wire6[1] == vortex::ATYP_IPV6, "icmp6 wire build");
        expect(vortex::parse_icmp_wire(wire6, h, ic) && h == "::1" && ic[0] == 128,
               "icmp6 wire parse");
        const auto via6 = vortex::build_via_peer_icmp_payload(secret, wire6);
        expect(vortex::parse_via_peer_icmp_payload(via6, sec2, wire2) && wire2 == wire6,
               "via icmp6 round-trip");

        const auto wire_dom = vortex::build_icmp_wire("www.google.com", echo, sizeof(echo));
        expect(!wire_dom.empty() && wire_dom[1] == vortex::ATYP_DOMAIN, "icmp domain wire");
        expect(vortex::parse_icmp_wire(wire_dom, h, ic) && h == "www.google.com",
               "icmp domain parse");
        const auto via_dom = vortex::build_via_peer_icmp_payload(secret, wire_dom);
        expect(vortex::parse_via_peer_icmp_payload(via_dom, sec2, wire2) && wire2 == wire_dom,
               "via icmp domain round-trip");
    }

    if (g_fail) {
        std::fprintf(stderr, "%d failure(s)\n", g_fail);
        return 1;
    }
    std::printf("All peer protocol tests passed\n");
    return 0;
}
