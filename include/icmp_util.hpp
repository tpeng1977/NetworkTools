#ifndef VORTEX_ICMP_UTIL_HPP
#define VORTEX_ICMP_UTIL_HPP

// Lightweight ICMP echo helpers for ping diagnostics over Vortex / linux_network.
// SOCK_RAW needs CAP_NET_RAW (or root) on POSIX. Windows stubs return false.

#include "net.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#ifndef _WIN32
#  include <arpa/inet.h>
#  include <chrono>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <netinet/ip.h>
#  include <netinet/ip_icmp.h>
#  include <poll.h>
#  include <sys/socket.h>
#  include <unistd.h>
#  if defined(__linux__)
#    include <netinet/icmp6.h>
#  endif
#endif

namespace vortex {
namespace icmp_util {

#ifndef _WIN32
#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif
#ifndef ICMP_ECHOREPLY
#define ICMP_ECHOREPLY 0
#endif
#endif

inline uint16_t checksum(const uint8_t* data, size_t len) {
    uint32_t sum = 0;
    for (size_t i = 0; i + 1 < len; i += 2) {
        sum += (static_cast<uint32_t>(data[i]) << 8) | data[i + 1];
    }
    if (len & 1) sum += static_cast<uint32_t>(data[len - 1]) << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

inline void fix_icmp_checksum(std::vector<uint8_t>& icmp) {
    if (icmp.size() < 8) return;
    icmp[2] = 0;
    icmp[3] = 0;
    const uint16_t c = checksum(icmp.data(), icmp.size());
    icmp[2] = static_cast<uint8_t>((c >> 8) & 0xFF);
    icmp[3] = static_cast<uint8_t>(c & 0xFF);
}

inline bool is_echo_request_v4(const uint8_t* icmp, size_t len) {
    return icmp && len >= 8 && icmp[0] == 8; // ICMP_ECHO
}
inline bool is_echo_reply_v4(const uint8_t* icmp, size_t len) {
    return icmp && len >= 8 && icmp[0] == 0; // ICMP_ECHOREPLY
}
inline bool is_echo_request_v6(const uint8_t* icmp, size_t len) {
    return icmp && len >= 8 && icmp[0] == 128; // ICMP6_ECHO_REQUEST
}
inline bool is_echo_reply_v6(const uint8_t* icmp, size_t len) {
    return icmp && len >= 8 && icmp[0] == 129; // ICMP6_ECHO_REPLY
}

inline uint16_t echo_id(const uint8_t* icmp) {
    return static_cast<uint16_t>((icmp[4] << 8) | icmp[5]);
}
inline uint16_t echo_seq(const uint8_t* icmp) {
    return static_cast<uint16_t>((icmp[6] << 8) | icmp[7]);
}

// Optional TTL / hop-limit trailer (backward compatible with servers that omit it).
// An echo reply always carries the same payload length as the request, so the exit may
// append ONE byte (remote reply TTL/hop limit) after the ICMP body. Old exits return
// reply.size()==req.size() → no trailer → client falls back to 64.
inline void append_ttl_trailer(std::vector<uint8_t>& reply, int ttl) {
    if (ttl > 0 && ttl <= 255) reply.push_back(static_cast<uint8_t>(ttl));
}
// Returns TTL (1..255) if trailer was present and stripped, else 0.
inline int strip_ttl_trailer(std::vector<uint8_t>& reply, size_t req_icmp_len) {
    if (reply.size() == req_icmp_len + 1 && req_icmp_len >= 8) {
        const int ttl = reply.back();
        reply.pop_back();
        return ttl;
    }
    return 0;
}

#ifdef _WIN32

inline bool echo_exchange(const std::string&, const std::vector<uint8_t>&,
                          std::vector<uint8_t>& reply, int, int = 0, int* ttl_out = nullptr) {
    if (ttl_out) *ttl_out = 0;
    reply.clear();
    return false;
}
inline bool inject_echo_reply_v4(uint32_t, uint32_t, const uint8_t*, size_t, int = 0,
                                 uint8_t = 64) {
    return false;
}
inline bool inject_echo_reply_v6(const in6_addr&, const in6_addr&, const uint8_t*, size_t,
                                 int = 0, uint8_t = 64) {
    return false;
}

#else

inline bool echo_exchange_v4(const std::string& host, const std::vector<uint8_t>& req,
                             std::vector<uint8_t>& reply, int timeout_ms,
                             int so_mark = 0, int* ttl_out = nullptr) {
    reply.clear();
    if (ttl_out) *ttl_out = 0;
    if (!is_echo_request_v4(req.data(), req.size())) return false;
    in_addr dst{};
    if (inet_pton(AF_INET, host.c_str(), &dst) != 1) return false;

    const int fd = ::socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) return false;
#if defined(__linux__)
    if (so_mark != 0) {
        setsockopt(fd, SOL_SOCKET, SO_MARK, &so_mark, sizeof(so_mark));
    }
#else
    (void)so_mark;
#endif

    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr = dst;
    std::vector<uint8_t> pkt = req;
    fix_icmp_checksum(pkt);
    if (::sendto(fd, pkt.data(), pkt.size(), 0, reinterpret_cast<sockaddr*>(&sa),
                 sizeof(sa)) < 0) {
        ::close(fd);
        return false;
    }

    const uint16_t want_id = echo_id(pkt.data());
    const uint16_t want_seq = echo_seq(pkt.data());
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    uint8_t buf[2048];
    while (std::chrono::steady_clock::now() < deadline) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                              deadline - std::chrono::steady_clock::now())
                              .count();
        pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        const int pr = ::poll(&pfd, 1, left > 0 ? static_cast<int>(left) : 0);
        if (pr <= 0) break;
        const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n < 20) continue;
        const int ihl = (buf[0] & 0x0F) * 4;
        if (ihl < 20 || n < ihl + 8) continue;
        if (buf[9] != IPPROTO_ICMP) continue;
        const uint8_t* icmp = buf + ihl;
        const size_t icmplen = static_cast<size_t>(n - ihl);
        if (!is_echo_reply_v4(icmp, icmplen)) continue;
        if (echo_id(icmp) != want_id || echo_seq(icmp) != want_seq) continue;
        reply.assign(icmp, icmp + icmplen);
        if (ttl_out) *ttl_out = buf[8]; // remote reply TTL as seen at this exit
        ::close(fd);
        return true;
    }
    ::close(fd);
    return false;
}

#if defined(__linux__)
// ICMPv6 checksum covers a pseudo-header; leave csum=0 and let the kernel fill it
// on SOCK_RAW IPPROTO_ICMPV6 send (same for inject_echo_reply_v6).
inline bool echo_exchange_v6(const std::string& host, const std::vector<uint8_t>& req,
                             std::vector<uint8_t>& reply, int timeout_ms,
                             int so_mark = 0, int* ttl_out = nullptr) {
    reply.clear();
    if (ttl_out) *ttl_out = 0;
    if (!is_echo_request_v6(req.data(), req.size())) return false;
    in6_addr dst{};
    const std::string host_norm = strip_ip_brackets(host);
    if (inet_pton(AF_INET6, host_norm.c_str(), &dst) != 1) return false;

    const int fd = ::socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (fd < 0) return false;
    if (so_mark != 0) {
        setsockopt(fd, SOL_SOCKET, SO_MARK, &so_mark, sizeof(so_mark));
    }
    // Filter to echo replies to reduce noise from NDP / other ICMPv6.
    icmp6_filter filt;
    ICMP6_FILTER_SETBLOCKALL(&filt);
    ICMP6_FILTER_SETPASS(ICMP6_ECHO_REPLY, &filt);
    setsockopt(fd, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt));
    {
        const int on = 1; // hop limit of the echo-reply via cmsg (raw v6 recv has no IP hdr)
        setsockopt(fd, IPPROTO_IPV6, IPV6_RECVHOPLIMIT, &on, sizeof(on));
    }

    std::vector<uint8_t> pkt = req;
    pkt[2] = 0;
    pkt[3] = 0;

    sockaddr_in6 sa{};
    sa.sin6_family = AF_INET6;
    sa.sin6_addr = dst;
    if (::sendto(fd, pkt.data(), pkt.size(), 0, reinterpret_cast<sockaddr*>(&sa),
                 sizeof(sa)) < 0) {
        ::close(fd);
        return false;
    }

    const uint16_t want_id = echo_id(pkt.data());
    const uint16_t want_seq = echo_seq(pkt.data());
    const auto deadline =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
    uint8_t buf[2048];
    while (std::chrono::steady_clock::now() < deadline) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(
                              deadline - std::chrono::steady_clock::now())
                              .count();
        pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLIN;
        const int pr = ::poll(&pfd, 1, left > 0 ? static_cast<int>(left) : 0);
        if (pr <= 0) break;
        uint8_t cbuf[128];
        iovec iov{buf, sizeof(buf)};
        msghdr mh{};
        mh.msg_iov = &iov;
        mh.msg_iovlen = 1;
        mh.msg_control = cbuf;
        mh.msg_controllen = sizeof(cbuf);
        const ssize_t n = ::recvmsg(fd, &mh, 0);
        if (n < 8) continue;
        if (!is_echo_reply_v6(buf, static_cast<size_t>(n))) continue;
        if (echo_id(buf) != want_id || echo_seq(buf) != want_seq) continue;
        if (ttl_out) {
            for (cmsghdr* cm = CMSG_FIRSTHDR(&mh); cm; cm = CMSG_NXTHDR(&mh, cm)) {
                if (cm->cmsg_level == IPPROTO_IPV6 && cm->cmsg_type == IPV6_HOPLIMIT &&
                    cm->cmsg_len >= CMSG_LEN(sizeof(int))) {
                    int hl = 0;
                    std::memcpy(&hl, CMSG_DATA(cm), sizeof(hl));
                    *ttl_out = hl;
                }
            }
        }
        reply.assign(buf, buf + n);
        ::close(fd);
        return true;
    }
    ::close(fd);
    return false;
}
#endif

// Resolve a hostname and echo. Family follows the ICMP request type (v4 vs v6)
// so PROXY ATYP_DOMAIN jobs do not mix A into ping6 or AAAA into ping.
inline bool echo_exchange(const std::string& host, const std::vector<uint8_t>& req,
                          std::vector<uint8_t>& reply, int timeout_ms, int so_mark = 0,
                          int* ttl_out = nullptr) {
    if (ttl_out) *ttl_out = 0;
    const std::string bare = strip_ip_brackets(host);
    in_addr v4{};
    if (inet_pton(AF_INET, bare.c_str(), &v4) == 1) {
        return echo_exchange_v4(bare, req, reply, timeout_ms, so_mark, ttl_out);
    }
#if defined(__linux__)
    in6_addr v6{};
    if (inet_pton(AF_INET6, bare.c_str(), &v6) == 1) {
        return echo_exchange_v6(bare, req, reply, timeout_ms, so_mark, ttl_out);
    }
#endif
    if (bare.empty() || req.size() < 8) {
        reply.clear();
        return false;
    }
    const bool want6 = is_echo_request_v6(req.data(), req.size());
    if (!want6 && !is_echo_request_v4(req.data(), req.size())) {
        reply.clear();
        return false;
    }
    addrinfo hints{};
    hints.ai_family = want6 ? AF_INET6 : AF_INET;
    hints.ai_socktype = SOCK_DGRAM; // any; we only need addresses for raw echo
    addrinfo* res = nullptr;
    if (getaddrinfo(bare.c_str(), nullptr, &hints, &res) != 0 || !res) {
        reply.clear();
        return false;
    }
    bool ok = false;
    for (addrinfo* ai = res; ai; ai = ai->ai_next) {
        char ip[INET6_ADDRSTRLEN] = {};
        if (ai->ai_family == AF_INET && !want6) {
            auto* sa = reinterpret_cast<sockaddr_in*>(ai->ai_addr);
            if (!inet_ntop(AF_INET, &sa->sin_addr, ip, sizeof(ip))) continue;
            ok = echo_exchange_v4(ip, req, reply, timeout_ms, so_mark, ttl_out);
        }
#if defined(__linux__)
        else if (ai->ai_family == AF_INET6 && want6) {
            auto* sa = reinterpret_cast<sockaddr_in6*>(ai->ai_addr);
            if (!inet_ntop(AF_INET6, &sa->sin6_addr, ip, sizeof(ip))) continue;
            ok = echo_exchange_v6(ip, req, reply, timeout_ms, so_mark, ttl_out);
        }
#endif
        if (ok) break;
    }
    freeaddrinfo(res);
    if (!ok) reply.clear();
    return ok;
}

// Build a full IPv4 packet for an ICMP echo-reply injection.
// reply_src = original echo-request destination (target host address)
// reply_dst = original echo-request source (local ping client)
// Without IP_HDRINCL the kernel would stamp the local egress IP as source,
// which makes ping report "DIFFERENT ADDRESS!".
inline std::vector<uint8_t> build_echo_reply_ip4(uint32_t reply_src_net, uint32_t reply_dst_net,
                                                 const uint8_t* icmp, size_t icmp_len,
                                                 uint8_t ttl = 64) {
    std::vector<uint8_t> out;
    if (!is_echo_reply_v4(icmp, icmp_len) || icmp_len > 65507) return out;
    out.resize(20 + icmp_len);
    uint8_t* ip = out.data();
    std::memset(ip, 0, 20);
    ip[0] = 0x45;
    const uint16_t total = static_cast<uint16_t>(20 + icmp_len);
    ip[2] = static_cast<uint8_t>((total >> 8) & 0xFF);
    ip[3] = static_cast<uint8_t>(total & 0xFF);
    ip[8] = ttl ? ttl : 64;
    ip[9] = IPPROTO_ICMP;
    std::memcpy(ip + 12, &reply_src_net, 4);
    std::memcpy(ip + 16, &reply_dst_net, 4);
    const uint16_t ip_csum = checksum(ip, 20);
    ip[10] = static_cast<uint8_t>((ip_csum >> 8) & 0xFF);
    ip[11] = static_cast<uint8_t>(ip_csum & 0xFF);
    uint8_t* icmp_p = ip + 20;
    std::memcpy(icmp_p, icmp, icmp_len);
    icmp_p[2] = 0;
    icmp_p[3] = 0;
    const uint16_t ic = checksum(icmp_p, icmp_len);
    icmp_p[2] = static_cast<uint8_t>((ic >> 8) & 0xFF);
    icmp_p[3] = static_cast<uint8_t>(ic & 0xFF);
    return out;
}

// Inject ICMP echo-reply with forged source = original request destination.
inline bool inject_echo_reply_v4(uint32_t reply_src_net, uint32_t reply_dst_net,
                                 const uint8_t* icmp, size_t icmp_len, int so_mark = 0,
                                 uint8_t ttl = 64) {
    auto pkt = build_echo_reply_ip4(reply_src_net, reply_dst_net, icmp, icmp_len, ttl);
    if (pkt.empty()) return false;
    // IPPROTO_RAW + full header, or IPPROTO_ICMP + IP_HDRINCL — both work on Linux.
    const int fd = ::socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) return false;
#if defined(__linux__)
    if (so_mark != 0) {
        setsockopt(fd, SOL_SOCKET, SO_MARK, &so_mark, sizeof(so_mark));
    }
#else
    (void)so_mark;
#endif
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = reply_dst_net;
    const bool ok =
        ::sendto(fd, pkt.data(), pkt.size(), 0, reinterpret_cast<sockaddr*>(&sa),
                 sizeof(sa)) >= 0;
    ::close(fd);
    return ok;
}

#if defined(__linux__)
// ICMPv6 checksum over IPv6 pseudo-header + ICMP body (needed for IPPROTO_RAW inject).
inline uint16_t icmp6_checksum(const in6_addr& src, const in6_addr& dst, const uint8_t* icmp,
                               size_t icmp_len) {
    uint32_t sum = 0;
    const uint8_t* s = reinterpret_cast<const uint8_t*>(&src);
    const uint8_t* d = reinterpret_cast<const uint8_t*>(&dst);
    for (int i = 0; i < 16; i += 2) {
        sum += (static_cast<uint32_t>(s[i]) << 8) | s[i + 1];
        sum += (static_cast<uint32_t>(d[i]) << 8) | d[i + 1];
    }
    sum += static_cast<uint32_t>((icmp_len >> 16) & 0xFFFF);
    sum += static_cast<uint32_t>(icmp_len & 0xFFFF);
    sum += IPPROTO_ICMPV6;
    for (size_t i = 0; i + 1 < icmp_len; i += 2) {
        sum += (static_cast<uint32_t>(icmp[i]) << 8) | icmp[i + 1];
    }
    if (icmp_len & 1) sum += static_cast<uint32_t>(icmp[icmp_len - 1]) << 8;
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return static_cast<uint16_t>(~sum);
}

inline std::vector<uint8_t> build_echo_reply_ip6(const in6_addr& reply_src,
                                                 const in6_addr& reply_dst,
                                                 const uint8_t* icmp, size_t icmp_len,
                                                 uint8_t hop_limit = 64) {
    std::vector<uint8_t> out;
    if (!is_echo_reply_v6(icmp, icmp_len) || icmp_len > 65495) return out;
    out.resize(40 + icmp_len, 0);
    uint8_t* ip = out.data();
    ip[0] = 0x60;
    ip[4] = static_cast<uint8_t>((icmp_len >> 8) & 0xFF);
    ip[5] = static_cast<uint8_t>(icmp_len & 0xFF);
    ip[6] = IPPROTO_ICMPV6;
    ip[7] = hop_limit ? hop_limit : 64;
    std::memcpy(ip + 8, &reply_src, 16);
    std::memcpy(ip + 24, &reply_dst, 16);
    uint8_t* icmp_p = ip + 40;
    std::memcpy(icmp_p, icmp, icmp_len);
    icmp_p[2] = 0;
    icmp_p[3] = 0;
    const uint16_t c = icmp6_checksum(reply_src, reply_dst, icmp_p, icmp_len);
    icmp_p[2] = static_cast<uint8_t>((c >> 8) & 0xFF);
    icmp_p[3] = static_cast<uint8_t>(c & 0xFF);
    return out;
}

// Inject ICMPv6 echo-reply with forged source = original request destination.
inline bool inject_echo_reply_v6(const in6_addr& reply_src, const in6_addr& reply_dst,
                                 const uint8_t* icmp, size_t icmp_len, int so_mark = 0,
                                 uint8_t hop_limit = 64) {
    auto pkt = build_echo_reply_ip6(reply_src, reply_dst, icmp, icmp_len, hop_limit);
    if (pkt.empty()) return false;
    const int fd = ::socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);
    if (fd < 0) return false;
    if (so_mark != 0) {
        setsockopt(fd, SOL_SOCKET, SO_MARK, &so_mark, sizeof(so_mark));
    }
    sockaddr_in6 sa{};
    sa.sin6_family = AF_INET6;
    sa.sin6_addr = reply_dst;
    const bool ok =
        ::sendto(fd, pkt.data(), pkt.size(), 0, reinterpret_cast<sockaddr*>(&sa),
                 sizeof(sa)) >= 0;
    ::close(fd);
    return ok;
}
#endif

#endif // !_WIN32

} // namespace icmp_util
} // namespace vortex

#endif // VORTEX_ICMP_UTIL_HPP
