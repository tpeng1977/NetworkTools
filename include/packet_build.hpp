#ifndef PACKET_BUILD_HPP
#define PACKET_BUILD_HPP

#include <cstdint>
#include <cstring>
#include <vector>

// Raw IPv4/TCP/UDP builders. Addresses are network byte order.
// Ports, sequence numbers, and acknowledgement numbers are host byte order.

namespace pkt {

constexpr uint8_t TCP_FIN = 0x01;
constexpr uint8_t TCP_SYN = 0x02;
constexpr uint8_t TCP_RST = 0x04;
constexpr uint8_t TCP_PSH = 0x08;
constexpr uint8_t TCP_ACK = 0x10;

inline uint16_t fold_checksum(uint32_t acc) {
    while (acc >> 16) {
        acc = (acc & 0xFFFFu) + (acc >> 16);
    }
    return static_cast<uint16_t>(~acc);
}

inline uint32_t sum_bytes(const uint8_t* p, size_t n, uint32_t acc = 0) {
    size_t i = 0;
    for (; i + 1 < n; i += 2) {
        acc += (static_cast<uint32_t>(p[i]) << 8) | p[i + 1];
    }
    if (i < n) {
        acc += static_cast<uint32_t>(p[i]) << 8;
    }
    return acc;
}

inline void store_be16(uint8_t* p, uint16_t v) {
    p[0] = static_cast<uint8_t>(v >> 8);
    p[1] = static_cast<uint8_t>(v);
}

inline void store_be32(uint8_t* p, uint32_t v) {
    p[0] = static_cast<uint8_t>(v >> 24);
    p[1] = static_cast<uint8_t>(v >> 16);
    p[2] = static_cast<uint8_t>(v >> 8);
    p[3] = static_cast<uint8_t>(v);
}

inline uint16_t load_be16(const uint8_t* p) {
    return static_cast<uint16_t>((p[0] << 8) | p[1]);
}

inline uint32_t load_be32(const uint8_t* p) {
    return (static_cast<uint32_t>(p[0]) << 24) |
           (static_cast<uint32_t>(p[1]) << 16) |
           (static_cast<uint32_t>(p[2]) << 8) |
           p[3];
}

// Signed distance on the TCP sequence space.
inline int32_t seq_diff(uint32_t a, uint32_t b) {
    return static_cast<int32_t>(a - b);
}

inline void write_ipv4_header(uint8_t* ip, uint16_t total_len, uint16_t id,
                              uint8_t proto, uint32_t src_net, uint32_t dst_net) {
    std::memset(ip, 0, 20);
    ip[0] = 0x45;
    store_be16(ip + 2, total_len);
    store_be16(ip + 4, id);
    ip[8] = 64;
    ip[9] = proto;
    std::memcpy(ip + 12, &src_net, 4);
    std::memcpy(ip + 16, &dst_net, 4);
    store_be16(ip + 10, fold_checksum(sum_bytes(ip, 20)));
}

inline void checksum_tcp_udp(uint8_t* ip, uint8_t* l4, size_t l4_len, size_t csum_off) {
    store_be16(l4 + csum_off, 0);
    uint32_t acc = 0;
    acc = sum_bytes(ip + 12, 8, acc);
    acc += ip[9];
    acc += static_cast<uint32_t>(l4_len);
    acc = sum_bytes(l4, l4_len, acc);
    store_be16(l4 + csum_off, fold_checksum(acc));
}

inline std::vector<uint8_t> build_tcp(uint32_t src_net, uint32_t dst_net,
                                      uint16_t sport, uint16_t dport,
                                      uint32_t seq, uint32_t ack,
                                      uint8_t flags, uint16_t window,
                                      const uint8_t* payload, size_t payload_len,
                                      uint16_t ip_id,
                                      const uint8_t* tcp_opt = nullptr, size_t tcp_opt_len = 0) {
    const size_t opt_len = (tcp_opt && tcp_opt_len) ? ((tcp_opt_len + 3) & ~size_t{3}) : 0;
    const size_t total = 20 + 20 + opt_len + payload_len;
    std::vector<uint8_t> pkt(total);
    write_ipv4_header(pkt.data(), static_cast<uint16_t>(total), ip_id, 6, src_net, dst_net);
    uint8_t* tcp = pkt.data() + 20;
    store_be16(tcp + 0, sport);
    store_be16(tcp + 2, dport);
    store_be32(tcp + 4, seq);
    store_be32(tcp + 8, ack);
    tcp[12] = static_cast<uint8_t>(((20 + opt_len) / 4) << 4);
    tcp[13] = flags;
    store_be16(tcp + 14, window);
    if (opt_len && tcp_opt) std::memcpy(tcp + 20, tcp_opt, tcp_opt_len);
    if (payload_len && payload) std::memcpy(tcp + 20 + opt_len, payload, payload_len);
    checksum_tcp_udp(pkt.data(), tcp, 20 + opt_len + payload_len, 16);
    return pkt;
}

inline std::vector<uint8_t> build_udp(uint32_t src_net, uint32_t dst_net,
                                      uint16_t sport, uint16_t dport,
                                      const uint8_t* payload, size_t payload_len,
                                      uint16_t ip_id) {
    const size_t total = 20 + 8 + payload_len;
    std::vector<uint8_t> pkt(total);
    write_ipv4_header(pkt.data(), static_cast<uint16_t>(total), ip_id, 17, src_net, dst_net);
    uint8_t* udp = pkt.data() + 20;
    store_be16(udp + 0, sport);
    store_be16(udp + 2, dport);
    store_be16(udp + 4, static_cast<uint16_t>(8 + payload_len));
    if (payload_len && payload) {
        std::memcpy(udp + 8, payload, payload_len);
    }
    checksum_tcp_udp(pkt.data(), udp, 8 + payload_len, 6);
    return pkt;
}

// ICMP Dest Unreachable (type 3). code 3 = Port Unreachable — makes QUIC/HTTP3
// stacks fail fast and fall back to TCP instead of hanging on a silent drop.
inline std::vector<uint8_t> build_icmp_dest_unreach(uint32_t src_net, uint32_t dst_net,
                                                    uint8_t code,
                                                    const uint8_t* orig_packet, size_t orig_len,
                                                    uint16_t ip_id) {
    if (!orig_packet || orig_len < 20) return {};
    const int ihl = (orig_packet[0] & 0x0F) * 4;
    if (ihl < 20 || static_cast<size_t>(ihl) > orig_len) return {};
    const size_t take = std::min(orig_len, static_cast<size_t>(ihl) + 8);
    const size_t total = 20 + 8 + take;
    std::vector<uint8_t> pkt(total, 0);
    write_ipv4_header(pkt.data(), static_cast<uint16_t>(total), ip_id, 1, src_net, dst_net);
    uint8_t* icmp = pkt.data() + 20;
    icmp[0] = 3; // Destination Unreachable
    icmp[1] = code;
    std::memcpy(icmp + 8, orig_packet, take);
    store_be16(icmp + 2, fold_checksum(sum_bytes(icmp, 8 + take)));
    return pkt;
}

struct Ipv4L4 {
    bool ok = false;
    bool fragmented = false;
    uint8_t proto = 0;
    uint32_t src_net = 0;
    uint32_t dst_net = 0;
    uint16_t sport = 0;
    uint16_t dport = 0;
    uint32_t seq = 0;
    uint32_t ack = 0;
    uint8_t tcp_flags = 0;
    uint16_t window = 0;
    uint16_t mss = 0;
    const uint8_t* payload = nullptr;
    size_t payload_len = 0;
};

inline Ipv4L4 parse_ipv4(const uint8_t* p, size_t len) {
    Ipv4L4 v;
    if (len < 20 || (p[0] >> 4) != 4) return v;
    const int ihl = (p[0] & 0x0F) * 4;
    if (ihl < 20 || static_cast<size_t>(ihl) > len) return v;
    const uint16_t total = load_be16(p + 2);
    if (total < ihl || total > len) return v;
    const uint16_t frag = load_be16(p + 6);
    const uint16_t off = frag & 0x1FFF;
    const bool mf = (frag & 0x2000) != 0;
    v.proto = p[9];
    std::memcpy(&v.src_net, p + 12, 4);
    std::memcpy(&v.dst_net, p + 16, 4);
    if (off != 0 || mf) {
        v.fragmented = true;
        v.ok = true;
        return v;
    }
    const uint8_t* l4 = p + ihl;
    const size_t l4_len = static_cast<size_t>(total - ihl);
    if (v.proto == 6) {
        if (l4_len < 20) return v;
        const int thl = ((l4[12] >> 4) & 0x0F) * 4;
        if (thl < 20 || static_cast<size_t>(thl) > l4_len) return v;
        v.sport = load_be16(l4 + 0);
        v.dport = load_be16(l4 + 2);
        v.seq = load_be32(l4 + 4);
        v.ack = load_be32(l4 + 8);
        v.tcp_flags = l4[13];
        v.window = load_be16(l4 + 14);
        if (thl > 20) {
            const uint8_t* op = l4 + 20;
            const int ol = thl - 20;
            for (int i = 0; i < ol;) {
                const uint8_t kind = op[i];
                if (kind == 0) break;
                if (kind == 1) { ++i; continue; }
                if (i + 1 >= ol) break;
                const int ln = op[i + 1];
                if (ln < 2 || i + ln > ol) break;
                if (kind == 2 && ln == 4) v.mss = load_be16(op + i + 2);
                i += ln;
            }
        }
        v.payload = l4 + thl;
        v.payload_len = l4_len - static_cast<size_t>(thl);
        v.ok = true;
    } else if (v.proto == 17) {
        if (l4_len < 8) return v;
        v.sport = load_be16(l4 + 0);
        v.dport = load_be16(l4 + 2);
        size_t ulen = load_be16(l4 + 4);
        if (ulen < 8 || ulen > l4_len) ulen = l4_len;
        v.payload = l4 + 8;
        v.payload_len = ulen - 8;
        v.ok = true;
    } else {
        v.ok = true;
    }
    return v;
}

// RST for an IPv6 TCP packet. src/dst are the addresses to put on the RST
// (already swapped relative to the packet that was received).
inline std::vector<uint8_t> build_ipv6_tcp_rst(const uint8_t src[16], const uint8_t dst[16],
                                               uint16_t sport, uint16_t dport,
                                               uint32_t seq, uint32_t ack, bool with_ack) {
    std::vector<uint8_t> pkt(60, 0);
    pkt[0] = 0x60;
    store_be16(pkt.data() + 4, 20);
    pkt[6] = 6;
    pkt[7] = 64;
    std::memcpy(pkt.data() + 8, src, 16);
    std::memcpy(pkt.data() + 24, dst, 16);
    uint8_t* tcp = pkt.data() + 40;
    store_be16(tcp + 0, sport);
    store_be16(tcp + 2, dport);
    store_be32(tcp + 4, seq);
    store_be32(tcp + 8, ack);
    tcp[12] = (5 << 4);
    tcp[13] = with_ack ? (TCP_RST | TCP_ACK) : TCP_RST;
    uint32_t acc = sum_bytes(pkt.data() + 8, 32);
    acc += 6;
    acc += 20;
    acc = sum_bytes(tcp, 20, acc);
    store_be16(tcp + 16, fold_checksum(acc));
    return pkt;
}

inline bool header_checksum_ok(const uint8_t* ip) {
    const int ihl = (ip[0] & 0x0F) * 4;
    return fold_checksum(sum_bytes(ip, static_cast<size_t>(ihl))) == 0;
}

} // namespace pkt

#endif
