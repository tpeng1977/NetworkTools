#ifndef VORTEX_PROTOCOL_HPP
#define VORTEX_PROTOCOL_HPP

#include "vortex_cipher.hpp"
#include "net.hpp"

#include <mutex>
#include <random>
#include <string>
#include <vector>

// Frame layout after decryption:
//   [cmd:1][data_len:2 BE][data:data_len][padding:...]
// Wire: [enc_len:2][enc_body:N]  where N = htons(enc_len) after decrypt of length field.
//
// Each direction uses its own VortexCipher + sequence counter (both start at 0).

namespace vortex {

constexpr uint8_t CMD_CONNECT      = 0x01;
constexpr uint8_t CMD_DATA         = 0x02;
constexpr uint8_t CMD_CONNECT_OK   = 0x03;
constexpr uint8_t CMD_CONNECT_FAIL = 0x04;
constexpr uint8_t CMD_CLOSE        = 0x05;
// Peer relay: peer registers with server; client asks server to forward via peer.
constexpr uint8_t CMD_PEER_HELLO   = 0x06; // peer→server: data = peer_secret
constexpr uint8_t CMD_VIA_PEER     = 0x07; // client→server: [u8 len][secret][CONNECT target…]
// Port forwarding (peer advertises maps; UDP mux uses dedicated peer sessions).
constexpr uint8_t CMD_FWD_CONFIG   = 0x08; // peer→server after HELLO: PortForward maps
constexpr uint8_t CMD_UDP_DATA     = 0x09; // UDP datagram on mux: [sid][addr?][payload]
constexpr uint8_t CMD_UDP_CLOSE    = 0x0A; // UDP session expiry: [sid][flags]
// ICMP echo relay (ping diagnostics over Vortex). Payload carries address + ICMP body.
constexpr uint8_t CMD_ICMP           = 0x0B; // client↔server / server↔peer
constexpr uint8_t CMD_VIA_PEER_ICMP  = 0x0C; // client→server: [u8 len][secret][ICMP wire]

constexpr uint8_t ATYP_IPV4   = 0x01;
constexpr uint8_t ATYP_DOMAIN = 0x03;
constexpr uint8_t ATYP_IPV6   = 0x04;

// ICMP wire (CMD_ICMP data / inner of VIA_PEER_ICMP):
//   [u8 ver=1][atyp][addr…][icmp_payload…]
// No port field (unlike CONNECT). icmp_payload is type/code/checksum/rest:
//   IPv4 ICMP echo = type 8/0; ICMPv6 echo = type 128/129 (ATYP_IPV6).
// Exit side recomputes checksum (ICMPv6 via kernel pseudo-header when csum=0).
inline std::vector<uint8_t> build_icmp_wire(const std::string& host,
                                            const uint8_t* icmp, size_t icmp_len) {
    std::vector<uint8_t> out;
    if (!icmp || icmp_len < 8 || icmp_len > 65535 - 32) return out;
    in_addr v4{};
    in6_addr v6{};
    out.push_back(1); // version
    if (inet_pton(AF_INET, host.c_str(), &v4) == 1) {
        out.push_back(ATYP_IPV4);
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&v4);
        out.insert(out.end(), p, p + 4);
    } else if (inet_pton(AF_INET6, host.c_str(), &v6) == 1) {
        out.push_back(ATYP_IPV6);
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&v6);
        out.insert(out.end(), p, p + 16);
    } else {
        return {};
    }
    out.insert(out.end(), icmp, icmp + icmp_len);
    return out;
}

inline bool parse_icmp_wire(const std::vector<uint8_t>& data, std::string& host,
                            std::vector<uint8_t>& icmp) {
    host.clear();
    icmp.clear();
    if (data.size() < 1 + 1 + 4 + 8 || data[0] != 1) return false;
    size_t off = 1;
    const uint8_t atyp = data[off++];
    if (atyp == ATYP_IPV4) {
        if (data.size() < off + 4 + 8) return false;
        char ip[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, data.data() + off, ip, sizeof(ip))) return false;
        host = ip;
        off += 4;
    } else if (atyp == ATYP_IPV6) {
        if (data.size() < off + 16 + 8) return false;
        char ip[INET6_ADDRSTRLEN];
        if (!inet_ntop(AF_INET6, data.data() + off, ip, sizeof(ip))) return false;
        host = ip;
        off += 16;
    } else {
        return false;
    }
    icmp.assign(data.begin() + static_cast<std::ptrdiff_t>(off), data.end());
    return !host.empty() && icmp.size() >= 8;
}

inline std::vector<uint8_t> build_via_peer_icmp_payload(const std::string& peer_secret,
                                                        const std::vector<uint8_t>& icmp_wire) {
    std::vector<uint8_t> out;
    if (peer_secret.empty() || peer_secret.size() > 255 || icmp_wire.empty()) return out;
    out.push_back(static_cast<uint8_t>(peer_secret.size()));
    out.insert(out.end(), peer_secret.begin(), peer_secret.end());
    out.insert(out.end(), icmp_wire.begin(), icmp_wire.end());
    return out;
}

inline bool parse_via_peer_icmp_payload(const std::vector<uint8_t>& data,
                                        std::string& peer_secret,
                                        std::vector<uint8_t>& icmp_wire) {
    if (data.empty()) return false;
    const size_t n = data[0];
    if (n == 0 || data.size() < 1 + n + 1 + 1 + 4 + 8) return false;
    peer_secret.assign(reinterpret_cast<const char*>(data.data() + 1), n);
    icmp_wire.assign(data.begin() + 1 + static_cast<std::ptrdiff_t>(n), data.end());
    return !peer_secret.empty() && !icmp_wire.empty();
}

inline std::vector<uint8_t> build_via_peer_payload(const std::string& peer_secret,
                                                   const std::vector<uint8_t>& target_wire) {
    std::vector<uint8_t> out;
    if (peer_secret.empty() || peer_secret.size() > 255 || target_wire.empty()) return out;
    out.push_back(static_cast<uint8_t>(peer_secret.size()));
    out.insert(out.end(), peer_secret.begin(), peer_secret.end());
    out.insert(out.end(), target_wire.begin(), target_wire.end());
    return out;
}

inline bool parse_via_peer_payload(const std::vector<uint8_t>& data,
                                   std::string& peer_secret,
                                   std::vector<uint8_t>& target_wire) {
    if (data.empty()) return false;
    const size_t n = data[0];
    if (n == 0 || data.size() < 1 + n + 4) return false;
    peer_secret.assign(reinterpret_cast<const char*>(data.data() + 1), n);
    target_wire.assign(data.begin() + 1 + static_cast<std::ptrdiff_t>(n), data.end());
    return !peer_secret.empty() && !target_wire.empty();
}

struct SessionCrypto {
    VortexCipher cipher;
    uint64_t seq = 0;
    std::mutex mu;

    SessionCrypto() = default;

    void init(const std::string& secret, uint64_t salt) {
        cipher = VortexCipher(secret, salt);
        seq = 0;
    }
};

inline int random_padding(int pad_min, int pad_max) {
    if (pad_max <= pad_min) return pad_min;
    static thread_local std::mt19937 rng{std::random_device{}()};
    std::uniform_int_distribution<int> dist(pad_min, pad_max);
    return dist(rng);
}

inline bool send_frame(socket_t fd,
                       SessionCrypto& crypto,
                       uint8_t cmd,
                       const uint8_t* data,
                       size_t data_len,
                       int pad_min,
                       int pad_max) {
    const int pad = random_padding(pad_min, pad_max);
    const size_t body_len = 1 + 2 + data_len + static_cast<size_t>(pad);
    if (body_len > 65535) return false;

    std::vector<uint8_t> body(body_len);
    body[0] = cmd;
    uint16_t dlen_be = htons(static_cast<uint16_t>(data_len));
    std::memcpy(body.data() + 1, &dlen_be, 2);
    if (data_len > 0 && data) {
        std::memcpy(body.data() + 3, data, data_len);
    }
    if (pad > 0) {
        fill_random_bytes(body.data() + 3 + data_len, static_cast<size_t>(pad));
    }

    uint16_t len_be = htons(static_cast<uint16_t>(body_len));
    uint8_t len_hdr[2];
    std::memcpy(len_hdr, &len_be, 2);

    std::lock_guard<std::mutex> lock(crypto.mu);
    crypto.cipher.crypt(len_hdr, 2, crypto.seq);
    crypto.cipher.crypt(body.data(), body.size(), crypto.seq);

    if (!send_all(fd, len_hdr, 2)) return false;
    return send_all(fd, body.data(), body.size());
}

inline bool send_frame(socket_t fd,
                       SessionCrypto& crypto,
                       uint8_t cmd,
                       const std::vector<uint8_t>& data,
                       int pad_min,
                       int pad_max) {
    return send_frame(fd, crypto, cmd,
                      data.empty() ? nullptr : data.data(), data.size(),
                      pad_min, pad_max);
}

struct RecvFrame {
    uint8_t cmd = 0;
    std::vector<uint8_t> data;
    bool ok = false;
};

inline RecvFrame recv_frame(socket_t fd,
                            SessionCrypto& crypto,
                            size_t max_payload,
                            size_t max_body = 65535) {
    RecvFrame out;
    uint8_t len_hdr[2];
    if (!recv_exact(fd, len_hdr, 2)) return out;

    {
        std::lock_guard<std::mutex> lock(crypto.mu);
        crypto.cipher.crypt(len_hdr, 2, crypto.seq);
    }

    uint16_t body_len = 0;
    std::memcpy(&body_len, len_hdr, 2);
    body_len = ntohs(body_len);

    // Minimum valid body: cmd + data_len fields
    if (body_len < 3 || static_cast<size_t>(body_len) > max_body) return out;

    std::vector<uint8_t> body(body_len);
    if (!recv_exact(fd, body.data(), body_len)) return out;

    {
        std::lock_guard<std::mutex> lock(crypto.mu);
        crypto.cipher.crypt(body.data(), body.size(), crypto.seq);
    }

    out.cmd = body[0];
    uint16_t data_len = 0;
    std::memcpy(&data_len, body.data() + 1, 2);
    data_len = ntohs(data_len);

    if (static_cast<size_t>(data_len) + 3 > body_len) return out;
    if (data_len > max_payload) return out;

    out.data.assign(body.begin() + 3, body.begin() + 3 + data_len);
    out.ok = true;
    return out;
}

inline bool parse_connect_target(const std::vector<uint8_t>& data,
                                 std::string& host,
                                 uint16_t& port) {
    if (data.size() < 4) return false;
    size_t off = 0;
    uint8_t atyp = data[off++];
    if (atyp == ATYP_IPV4) {
        if (data.size() < off + 4 + 2) return false;
        char ip[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, data.data() + off, ip, sizeof(ip))) return false;
        host = ip;
        off += 4;
    } else if (atyp == ATYP_DOMAIN) {
        if (data.size() < off + 1) return false;
        uint8_t len = data[off++];
        if (len == 0 || data.size() < off + len + 2) return false;
        host.assign(reinterpret_cast<const char*>(data.data() + off), len);
        off += len;
    } else if (atyp == ATYP_IPV6) {
        if (data.size() < off + 16 + 2) return false;
        char ip[INET6_ADDRSTRLEN];
        if (!inet_ntop(AF_INET6, data.data() + off, ip, sizeof(ip))) return false;
        host = ip;
        off += 16;
    } else {
        return false;
    }
    if (data.size() < off + 2) return false;
    std::memcpy(&port, data.data() + off, 2);
    port = ntohs(port);
    return !host.empty() && port != 0;
}

inline void send_http_camouflage(socket_t fd) {
    static const char body[] =
        "<html>\r\n"
        "<head><title>404 Not Found</title></head>\r\n"
        "<body>\r\n"
        "<center><h1>404 Not Found</h1></center>\r\n"
        "<hr><center>nginx/1.24.0</center>\r\n"
        "</body>\r\n"
        "</html>\r\n";
    const size_t body_len = sizeof(body) - 1;
    std::string resp =
        "HTTP/1.1 404 Not Found\r\n"
        "Server: nginx/1.24.0\r\n"
        "Content-Type: text/html\r\n"
        "Content-Length: " + std::to_string(body_len) + "\r\n"
        "Connection: close\r\n"
        "\r\n";
    resp.append(body, body_len);
    send_all(fd, reinterpret_cast<const uint8_t*>(resp.data()), resp.size());
}

} // namespace vortex

#endif // VORTEX_PROTOCOL_HPP
