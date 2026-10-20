// Offline unit test for ap2socks5-style DNS A-record learning (IP -> qname).
#include <cstdint>
#include <cstring>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

static size_t dns_skip_name(const uint8_t* msg, size_t len, size_t off) {
    int hops = 0;
    while (off < len && hops < 64) {
        const uint8_t lab = msg[off];
        if (lab == 0) return off + 1;
        if ((lab & 0xC0) == 0xC0) return off + 2 < len ? off + 2 : len;
        if (off + 1 + lab > len) return len;
        off += 1 + lab;
        ++hops;
    }
    return len;
}

static void learn(const uint8_t* msg, size_t len, const std::string& qname,
                  std::unordered_map<uint32_t, std::string>& out) {
    if (len < 12 || qname.empty()) return;
    const int qd = (msg[4] << 8) | msg[5];
    const int an = (msg[6] << 8) | msg[7];
    size_t off = 12;
    for (int i = 0; i < qd; ++i) {
        off = dns_skip_name(msg, len, off);
        if (off + 4 > len) return;
        off += 4;
    }
    for (int i = 0; i < an; ++i) {
        off = dns_skip_name(msg, len, off);
        if (off + 10 > len) return;
        const int typ = (msg[off] << 8) | msg[off + 1];
        const int rdlen = (msg[off + 8] << 8) | msg[off + 9];
        off += 10;
        if (off + static_cast<size_t>(rdlen) > len) return;
        if (typ == 1 && rdlen == 4) {
            uint32_t net = 0;
            std::memcpy(&net, msg + off, 4);
            out[net] = qname;
        }
        off += static_cast<size_t>(rdlen);
    }
}

// Build: HDR + qname www.qq.com + QTYPE A + QCLASS IN + A answer 183.194.238.117
static std::vector<uint8_t> make_a_answer() {
    std::vector<uint8_t> m = {
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        3, 'w', 'w', 'w', 2, 'q', 'q', 3, 'c', 'o', 'm', 0,
        0x00, 0x01, 0x00, 0x01,
        0xC0, 0x0C, // pointer to qname
        0x00, 0x01, 0x00, 0x01,
        0x00, 0x00, 0x01, 0x2C, // TTL 300
        0x00, 0x04,
        183, 194, 238, 117
    };
    return m;
}

int main() {
    auto msg = make_a_answer();
    std::unordered_map<uint32_t, std::string> map;
    learn(msg.data(), msg.size(), "www.qq.com", map);
    const uint32_t want = (117u << 24) | (238u << 16) | (194u << 8) | 183u; // LE host...
    // network order bytes 183.194.238.117 on little-endian: 0x75EEC2B7
    uint32_t net = 0;
    const uint8_t ip[4] = {183, 194, 238, 117};
    std::memcpy(&net, ip, 4);
    if (map.size() != 1 || map[net] != "www.qq.com") {
        std::cerr << "learn failed size=" << map.size() << "\n";
        return 1;
    }
    std::cout << "DNS name learn OK: " << map[net] << " <- 183.194.238.117\n";
    (void)want;
    return 0;
}
