// ICMP / ICMPv6 echo helpers + optional live loopback probe (needs CAP_NET_RAW).
#include "icmp_util.hpp"
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
    uint8_t echo4[8] = {8, 0, 0, 0, 0xAB, 0xCD, 0x00, 0x2A};
    expect(vortex::icmp_util::is_echo_request_v4(echo4, 8), "echo4 request detect");
    expect(!vortex::icmp_util::is_echo_reply_v4(echo4, 8), "echo4 not reply");
    expect(vortex::icmp_util::echo_id(echo4) == 0xABCD, "icmp id");
    expect(vortex::icmp_util::echo_seq(echo4) == 0x002A, "icmp seq");

    std::vector<uint8_t> pkt4(echo4, echo4 + 8);
    vortex::icmp_util::fix_icmp_checksum(pkt4);
    expect(vortex::icmp_util::checksum(pkt4.data(), pkt4.size()) == 0, "v4 checksum folds to 0");

    const auto wire4 = vortex::build_icmp_wire("8.8.8.8", pkt4.data(), pkt4.size());
    std::string host;
    std::vector<uint8_t> body;
    expect(vortex::parse_icmp_wire(wire4, host, body) && host == "8.8.8.8", "wire v4 host");

    // ICMPv6 echo-request type 128
    uint8_t echo6[8] = {128, 0, 0, 0, 0x10, 0x20, 0x00, 0x03};
    expect(vortex::icmp_util::is_echo_request_v6(echo6, 8), "echo6 request detect");
    expect(!vortex::icmp_util::is_echo_reply_v6(echo6, 8), "echo6 not reply");
    expect(vortex::icmp_util::echo_id(echo6) == 0x1020, "icmp6 id");
    expect(vortex::icmp_util::echo_seq(echo6) == 0x0003, "icmp6 seq");

    const auto wire6 = vortex::build_icmp_wire("2001:db8::1", echo6, sizeof(echo6));
    expect(!wire6.empty() && wire6[0] == 1 && wire6[1] == vortex::ATYP_IPV6, "wire v6 build");
    expect(vortex::parse_icmp_wire(wire6, host, body) && host == "2001:db8::1", "wire v6 host");
    expect(body.size() == 8 && body[0] == 128, "wire v6 icmp body");

    const auto via6 = vortex::build_via_peer_icmp_payload("peer_sec", wire6);
    std::string sec;
    std::vector<uint8_t> inner;
    expect(vortex::parse_via_peer_icmp_payload(via6, sec, inner) && sec == "peer_sec" &&
               inner == wire6,
           "via peer icmp6 round-trip");

    // Live loopback IPv4
    std::vector<uint8_t> reply;
    if (vortex::icmp_util::echo_exchange_v4("127.0.0.1", pkt4, reply, 1500)) {
        expect(vortex::icmp_util::is_echo_reply_v4(reply.data(), reply.size()), "loopback v4 reply");
        expect(vortex::icmp_util::echo_id(reply.data()) == 0xABCD, "loopback v4 id match");
        std::printf("PASS: live ICMP echo 127.0.0.1\n");
    } else {
        std::printf("SKIP: live ICMP echo (need CAP_NET_RAW / root, or ICMP blocked)\n");
    }

#if defined(__linux__)
    std::vector<uint8_t> pkt6(echo6, echo6 + 8);
    reply.clear();
    if (vortex::icmp_util::echo_exchange_v6("::1", pkt6, reply, 1500)) {
        expect(vortex::icmp_util::is_echo_reply_v6(reply.data(), reply.size()), "loopback v6 reply");
        expect(vortex::icmp_util::echo_id(reply.data()) == 0x1020, "loopback v6 id match");
        std::printf("PASS: live ICMPv6 echo ::1\n");
    } else {
        std::printf("SKIP: live ICMPv6 echo (need CAP_NET_RAW / root, or ICMPv6 blocked)\n");
    }
#endif

    if (g_fail) {
        std::fprintf(stderr, "%d failure(s)\n", g_fail);
        return 1;
    }
    std::printf("All icmp relay tests passed\n");
    return 0;
}
