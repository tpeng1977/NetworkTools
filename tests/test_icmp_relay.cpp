// ICMP / ICMPv6 echo helpers + optional live loopback probe (needs CAP_NET_RAW).
#include "icmp_util.hpp"
#include "protocol.hpp"

#include <arpa/inet.h>
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

    // PROXY path: ATYP_DOMAIN so exit resolves (avoids client GFW poison / stand-in).
    const auto wire_dom = vortex::build_icmp_wire("www.google.com", pkt4.data(), pkt4.size());
    expect(!wire_dom.empty() && wire_dom[0] == 1 && wire_dom[1] == vortex::ATYP_DOMAIN,
           "wire domain atyp");
    expect(vortex::parse_icmp_wire(wire_dom, host, body) && host == "www.google.com" &&
               body.size() == pkt4.size(),
           "wire domain host");
    // Poison literals must still round-trip as IP (legacy); domain is preferred by linux_network.
    const auto wire_poison = vortex::build_icmp_wire("185.45.5.35", pkt4.data(), pkt4.size());
    expect(vortex::parse_icmp_wire(wire_poison, host, body) && host == "185.45.5.35",
           "wire poison v4 still ipv4 atyp");

    // Echo-reply IP packet: src=target (104.x), dst=client (192.168.x) — not LAN egress.
    uint8_t reply4[8] = {0, 0, 0, 0, 0xAB, 0xCD, 0x00, 0x2A};
    in_addr tgt{}, client{};
    inet_pton(AF_INET, "104.244.42.197", &tgt);
    inet_pton(AF_INET, "192.168.0.106", &client);
    const auto ip4pkt =
        vortex::icmp_util::build_echo_reply_ip4(tgt.s_addr, client.s_addr, reply4, 8);
    expect(ip4pkt.size() == 28, "v4 inject pkt len");
    if (ip4pkt.size() >= 28) {
        uint32_t got_src = 0, got_dst = 0;
        std::memcpy(&got_src, ip4pkt.data() + 12, 4);
        std::memcpy(&got_dst, ip4pkt.data() + 16, 4);
        expect(got_src == tgt.s_addr, "v4 inject src=echo-request dst (target)");
        expect(got_dst == client.s_addr, "v4 inject dst=echo-request src (client)");
        expect(ip4pkt[20] == 0, "v4 inject icmp type echo-reply");
        expect(got_src != client.s_addr, "v4 inject must not use LAN client as src");
    }

    // TTL preserved on inject; default stays 64 for old exits (no trailer).
    {
        const auto p117 =
            vortex::icmp_util::build_echo_reply_ip4(tgt.s_addr, client.s_addr, reply4, 8, 117);
        expect(p117.size() == 28 && p117[8] == 117, "v4 inject keeps remote ttl");
        const auto pdef =
            vortex::icmp_util::build_echo_reply_ip4(tgt.s_addr, client.s_addr, reply4, 8);
        expect(pdef.size() == 28 && pdef[8] == 64, "v4 inject default ttl 64");
        std::vector<uint8_t> r(reply4, reply4 + 8);
        vortex::icmp_util::append_ttl_trailer(r, 117);
        expect(r.size() == 9 && vortex::icmp_util::strip_ttl_trailer(r, 8) == 117 && r.size() == 8,
               "ttl trailer round-trip");
        std::vector<uint8_t> old(reply4, reply4 + 8);
        expect(vortex::icmp_util::strip_ttl_trailer(old, 8) == 0 && old.size() == 8,
               "old exit: no trailer");
    }

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
    const auto wire_poison6 = vortex::build_icmp_wire("2001::1", echo6, sizeof(echo6));
    expect(!wire_poison6.empty() && wire_poison6[1] == vortex::ATYP_IPV6, "wire poison v6 atyp");
    expect(vortex::parse_icmp_wire(wire_poison6, host, body) && host == "2001::1",
           "wire poison v6 host");
    const auto wire_dom6 = vortex::build_icmp_wire("www.google.com", echo6, sizeof(echo6));
    expect(!wire_dom6.empty() && wire_dom6[1] == vortex::ATYP_DOMAIN, "wire domain v6 atyp");
    expect(vortex::parse_icmp_wire(wire_dom6, host, body) && host == "www.google.com",
           "wire domain v6 host");

#if defined(__linux__)
    uint8_t reply6[8] = {129, 0, 0, 0, 0x10, 0x20, 0x00, 0x03};
    in6_addr tgt6{}, client6{};
    inet_pton(AF_INET6, "2001:db8::1", &tgt6);
    inet_pton(AF_INET6, "fd00::106", &client6);
    const auto ip6pkt = vortex::icmp_util::build_echo_reply_ip6(tgt6, client6, reply6, 8);
    {
        const auto p6 = vortex::icmp_util::build_echo_reply_ip6(tgt6, client6, reply6, 8, 115);
        expect(p6.size() == 48 && p6[7] == 115, "v6 inject keeps remote hop limit");
    }
    expect(ip6pkt.size() == 48, "v6 inject pkt len");
    if (ip6pkt.size() >= 48) {
        expect(std::memcmp(ip6pkt.data() + 8, &tgt6, 16) == 0, "v6 inject src=target");
        expect(std::memcmp(ip6pkt.data() + 24, &client6, 16) == 0, "v6 inject dst=client");
        expect(ip6pkt[40] == 129, "v6 inject icmp type echo-reply");
    }
#endif

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
