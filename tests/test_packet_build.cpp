#include "packet_build.hpp"

#include <cstring>
#include <iostream>

static int g_failed = 0;

#define CHECK(cond, msg) do { \
    if (!(cond)) { std::cerr << "FAIL: " << msg << "\n"; ++g_failed; } \
    else { std::cout << "PASS: " << msg << "\n"; } \
} while (0)

int main() {
    const uint32_t src = (20u) | (137u << 8) | (168u << 16) | (192u << 24);
    const uint32_t dst = (4u) | (3u << 8) | (2u << 16) | (1u << 24);

    const uint8_t payload[] = {'p', 'i', 'n', 'g'};
    auto tcp = pkt::build_tcp(src, dst, 40000, 443, 1000, 2000,
                              pkt::TCP_ACK | pkt::TCP_PSH, 65535,
                              payload, sizeof(payload), 7);
    CHECK(tcp.size() == 20 + 20 + 4, "tcp size");
    CHECK(pkt::header_checksum_ok(tcp.data()), "ipv4 checksum");
    auto parsed = pkt::parse_ipv4(tcp.data(), tcp.size());
    CHECK(parsed.ok && !parsed.fragmented, "parse tcp");
    CHECK(parsed.sport == 40000 && parsed.dport == 443, "tcp ports");
    CHECK(parsed.seq == 1000 && parsed.ack == 2000, "tcp seq/ack");
    CHECK((parsed.tcp_flags & pkt::TCP_ACK) && (parsed.tcp_flags & pkt::TCP_PSH), "tcp flags");
    CHECK(parsed.payload_len == 4 && parsed.payload[0] == 'p', "tcp payload");
    CHECK(parsed.src_net == src && parsed.dst_net == dst, "tcp addrs");

    uint8_t tcp_seg[24];
    std::memcpy(tcp_seg, tcp.data() + 20, 24);
    pkt::checksum_tcp_udp(tcp.data(), tcp_seg, 24, 16);
    CHECK(pkt::load_be16(tcp_seg + 16) == pkt::load_be16(tcp.data() + 20 + 16), "tcp checksum stable");

    auto udp = pkt::build_udp(dst, src, 53, 53000, payload, sizeof(payload), 9);
    CHECK(pkt::header_checksum_ok(udp.data()), "udp ipv4 checksum");
    auto up = pkt::parse_ipv4(udp.data(), udp.size());
    CHECK(up.ok && up.proto == 17 && up.sport == 53 && up.dport == 53000, "parse udp");
    CHECK(up.payload_len == 4, "udp payload");

    CHECK(pkt::seq_diff(5, 1) == 4, "seq diff forward");
    CHECK(pkt::seq_diff(1, 5) == -4, "seq diff back");
    CHECK(pkt::seq_diff(0, 0xFFFFFFFFu) == 1, "seq wrap");

    const uint8_t junk[] = {0x45, 0x00, 0x00, 0x14};
    auto bad = pkt::parse_ipv4(junk, sizeof(junk));
    CHECK(!bad.ok, "truncated packet rejected");

    if (g_failed) {
        std::cout << g_failed << " failed\n";
        return 1;
    }
    std::cout << "All packet tests passed.\n";
    return 0;
}
