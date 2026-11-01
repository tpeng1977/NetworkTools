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

#ifdef _WIN32

inline bool echo_exchange(const std::string&, const std::vector<uint8_t>&,
                          std::vector<uint8_t>& reply, int, int = 0) {
    reply.clear();
    return false;
}
inline bool inject_echo_reply_v4(uint32_t, const uint8_t*, size_t, int = 0) { return false; }

#else

inline bool echo_exchange_v4(const std::string& host, const std::vector<uint8_t>& req,
                             std::vector<uint8_t>& reply, int timeout_ms,
                             int so_mark = 0) {
    reply.clear();
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
                             int so_mark = 0) {
    reply.clear();
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
        const ssize_t n = ::recv(fd, buf, sizeof(buf), 0);
        if (n < 8) continue;
        if (!is_echo_reply_v6(buf, static_cast<size_t>(n))) continue;
        if (echo_id(buf) != want_id || echo_seq(buf) != want_seq) continue;
        reply.assign(buf, buf + n);
        ::close(fd);
        return true;
    }
    ::close(fd);
    return false;
}
#endif

inline bool echo_exchange(const std::string& host, const std::vector<uint8_t>& req,
                          std::vector<uint8_t>& reply, int timeout_ms, int so_mark = 0) {
    in_addr v4{};
    if (inet_pton(AF_INET, host.c_str(), &v4) == 1) {
        return echo_exchange_v4(host, req, reply, timeout_ms, so_mark);
    }
#if defined(__linux__)
    in6_addr v6{};
    if (inet_pton(AF_INET6, host.c_str(), &v6) == 1) {
        return echo_exchange_v6(host, req, reply, timeout_ms, so_mark);
    }
#endif
    (void)reply;
    (void)timeout_ms;
    (void)so_mark;
    return false;
}

inline bool inject_echo_reply_v4(uint32_t src_net, const uint8_t* icmp, size_t icmp_len,
                                 int so_mark = 0) {
    if (!is_echo_reply_v4(icmp, icmp_len)) return false;
    const int fd = ::socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (fd < 0) return false;
#if defined(__linux__)
    if (so_mark != 0) {
        setsockopt(fd, SOL_SOCKET, SO_MARK, &so_mark, sizeof(so_mark));
    }
#else
    (void)so_mark;
#endif
    std::vector<uint8_t> pkt(icmp, icmp + icmp_len);
    fix_icmp_checksum(pkt);
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = src_net;
    const bool ok =
        ::sendto(fd, pkt.data(), pkt.size(), 0, reinterpret_cast<sockaddr*>(&sa),
                 sizeof(sa)) >= 0;
    ::close(fd);
    return ok;
}

#if defined(__linux__)
inline bool inject_echo_reply_v6(const in6_addr& src, const uint8_t* icmp, size_t icmp_len,
                                 int so_mark = 0) {
    if (!is_echo_reply_v6(icmp, icmp_len)) return false;
    const int fd = ::socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6);
    if (fd < 0) return false;
    if (so_mark != 0) {
        setsockopt(fd, SOL_SOCKET, SO_MARK, &so_mark, sizeof(so_mark));
    }
    std::vector<uint8_t> pkt(icmp, icmp + icmp_len);
    pkt[2] = 0;
    pkt[3] = 0;
    sockaddr_in6 sa{};
    sa.sin6_family = AF_INET6;
    sa.sin6_addr = src;
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
