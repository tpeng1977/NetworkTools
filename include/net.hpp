#ifndef VORTEX_NET_HPP
#define VORTEX_NET_HPP

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#  include <mstcpip.h>
   using socket_t = SOCKET;
   constexpr socket_t INVALID_SOCK = INVALID_SOCKET;
   using socklen_type = int;
   inline int net_close(socket_t s) { return closesocket(s); }
   inline int net_errno() { return WSAGetLastError(); }
   inline bool net_would_block(int e) {
       return e == WSAEWOULDBLOCK || e == WSAEINTR;
   }
   inline bool net_interrupted(int e) { return e == WSAEINTR; }
#else
#  include <arpa/inet.h>
#  include <fcntl.h>
#  include <netdb.h>
#  include <netinet/in.h>
#  include <netinet/tcp.h>
#  include <sys/select.h>
#  include <sys/socket.h>
#  include <sys/types.h>
#  include <unistd.h>
   using socket_t = int;
   constexpr socket_t INVALID_SOCK = -1;
   using socklen_type = socklen_t;
   inline int net_close(socket_t s) { return ::close(s); }
   inline int net_errno() { return errno; }
   inline bool net_would_block(int e) {
       return e == EAGAIN || e == EWOULDBLOCK || e == EINTR;
   }
   inline bool net_interrupted(int e) { return e == EINTR; }
   // macOS does not provide MSG_NOSIGNAL; use SO_NOSIGPIPE instead.
#  ifndef MSG_NOSIGNAL
#    define MSG_NOSIGNAL 0
#  endif
#endif

inline bool net_init() {
#ifdef _WIN32
    WSADATA wsa;
    return WSAStartup(MAKEWORD(2, 2), &wsa) == 0;
#else
    return true;
#endif
}

inline void net_cleanup() {
#ifdef _WIN32
    WSACleanup();
#endif
}

inline void set_recv_timeout(socket_t fd, int timeout_sec) {
#ifdef _WIN32
    DWORD timeout_ms = static_cast<DWORD>(timeout_sec) * 1000;
    if (timeout_ms == 0) timeout_ms = 1000;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO,
               reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO,
               reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));
#else
    timeval tv{};
    tv.tv_sec = timeout_sec > 0 ? timeout_sec : 1;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
#endif
}

// Detect dead/NAT-dropped peer control links well before OS defaults (~2h on Windows).
inline void set_tcp_keepalive(socket_t fd, int idle_sec = 60, int interval_sec = 10,
                              int probe_count = 3) {
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, reinterpret_cast<const char*>(&one), sizeof(one));
#ifdef _WIN32
    struct {
        u_long onoff;
        u_long keepalivetime;
        u_long keepaliveinterval;
    } ka{};
    ka.onoff = 1;
    ka.keepalivetime = static_cast<u_long>((idle_sec > 0 ? idle_sec : 60) * 1000UL);
    ka.keepaliveinterval = static_cast<u_long>((interval_sec > 0 ? interval_sec : 10) * 1000UL);
    DWORD bytes = 0;
    WSAIoctl(fd, SIO_KEEPALIVE_VALS, &ka, sizeof(ka), nullptr, 0, &bytes, nullptr, nullptr);
    (void)probe_count;
#elif defined(__APPLE__)
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPALIVE, reinterpret_cast<const char*>(&idle_sec),
               sizeof(idle_sec));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, reinterpret_cast<const char*>(&interval_sec),
               sizeof(interval_sec));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, reinterpret_cast<const char*>(&probe_count),
               sizeof(probe_count));
#else
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPIDLE, reinterpret_cast<const char*>(&idle_sec),
               sizeof(idle_sec));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPINTVL, reinterpret_cast<const char*>(&interval_sec),
               sizeof(interval_sec));
    setsockopt(fd, IPPROTO_TCP, TCP_KEEPCNT, reinterpret_cast<const char*>(&probe_count),
               sizeof(probe_count));
#endif
}

inline void set_socket_options(socket_t fd, int idle_timeout_sec) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
               reinterpret_cast<const char*>(&one), sizeof(one));
    set_tcp_keepalive(fd);
#ifdef __APPLE__
    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE,
               reinterpret_cast<const char*>(&one), sizeof(one));
#endif
    set_recv_timeout(fd, idle_timeout_sec > 0 ? idle_timeout_sec : 300);
}

inline bool send_all(socket_t fd, const uint8_t* data, size_t len) {
    size_t sent = 0;
    while (sent < len) {
#ifdef _WIN32
        int n = ::send(fd, reinterpret_cast<const char*>(data + sent),
                       static_cast<int>(len - sent), 0);
#else
        ssize_t n = ::send(fd, data + sent, len - sent, MSG_NOSIGNAL);
#endif
        if (n <= 0) {
            // With SO_SNDTIMEO, EAGAIN/EWOULDBLOCK means the send timed out — do not spin.
            if (n < 0 && net_interrupted(net_errno())) continue;
            return false;
        }
        sent += static_cast<size_t>(n);
    }
    return true;
}

inline bool recv_exact(socket_t fd, uint8_t* data, size_t len) {
    size_t got = 0;
    while (got < len) {
#ifdef _WIN32
        int n = ::recv(fd, reinterpret_cast<char*>(data + got),
                       static_cast<int>(len - got), 0);
#else
        ssize_t n = ::recv(fd, data + got, len - got, 0);
#endif
        if (n <= 0) {
            // With SO_RCVTIMEO, EAGAIN means the recv timed out — do not spin forever.
            if (n < 0 && net_interrupted(net_errno())) continue;
            return false;
        }
        got += static_cast<size_t>(n);
    }
    return true;
}

inline int recv_some(socket_t fd, uint8_t* data, size_t len) {
#ifdef _WIN32
    return ::recv(fd, reinterpret_cast<char*>(data), static_cast<int>(len), 0);
#else
    return static_cast<int>(::recv(fd, data, len, 0));
#endif
}

// Accept both "2001:db8::1" and "[2001:db8::1]" in config / CLI host fields.
inline std::string strip_ip_brackets(std::string host) {
    if (host.size() >= 2 && host.front() == '[' && host.back() == ']') {
        host = host.substr(1, host.size() - 2);
    }
    return host;
}

inline bool host_is_ipv6_literal(const std::string& host) {
    in6_addr v6{};
    return inet_pton(AF_INET6, strip_ip_brackets(host).c_str(), &v6) == 1;
}

inline bool host_is_ipv4_literal(const std::string& host) {
    in_addr v4{};
    return inet_pton(AF_INET, strip_ip_brackets(host).c_str(), &v4) == 1;
}

// Dual-stack listen:
//   "::" / "" / "*"  → AF_INET6 + IPV6_V6ONLY=0 when prefer_dual (accept IPv4-mapped + IPv6)
//   same wildcards with prefer_dual=false → AF_INET6 + IPV6_V6ONLY=1 (for multi-bind lists)
//   "0.0.0.0"        → AF_INET only (legacy)
//   IPv4 / IPv6 lit  → that family only
inline socket_t create_listen_socket(const std::string& bind_ip, int port, int backlog,
                                     bool prefer_dual = true) {
    const std::string ip = strip_ip_brackets(bind_ip);
    const bool is_wildcard = ip.empty() || ip == "*" || ip == "::";
    const bool want_dual = is_wildcard && prefer_dual;
    const bool want_v4any = (ip == "0.0.0.0");
    in6_addr v6addr{};
    in_addr v4addr{};
    bool use_v6 = false;
    if (is_wildcard) {
        use_v6 = true;
        v6addr = in6addr_any;
    } else if (want_v4any) {
        use_v6 = false;
        v4addr.s_addr = htonl(INADDR_ANY);
    } else if (inet_pton(AF_INET6, ip.c_str(), &v6addr) == 1) {
        use_v6 = true;
    } else if (inet_pton(AF_INET, ip.c_str(), &v4addr) == 1) {
        use_v6 = false;
    } else {
        return INVALID_SOCK;
    }

    socket_t fd = INVALID_SOCK;
    if (use_v6) {
        fd = ::socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        if (fd == INVALID_SOCK) return INVALID_SOCK;
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char*>(&one), sizeof(one));
#ifdef __APPLE__
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE,
                   reinterpret_cast<const char*>(&one), sizeof(one));
#endif
        // Dual-stack only for lone "::"/"*"/"", or prefer_dual; else v6-only.
        int v6only = want_dual ? 0 : 1;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
                   reinterpret_cast<const char*>(&v6only), sizeof(v6only));

        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(static_cast<uint16_t>(port));
        addr.sin6_addr = v6addr;
        if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            net_close(fd);
            return INVALID_SOCK;
        }
    } else {
        fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (fd == INVALID_SOCK) return INVALID_SOCK;
        int one = 1;
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
                   reinterpret_cast<const char*>(&one), sizeof(one));
#ifdef __APPLE__
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE,
                   reinterpret_cast<const char*>(&one), sizeof(one));
#endif
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(port));
        addr.sin_addr = v4addr;
        if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            net_close(fd);
            return INVALID_SOCK;
        }
    }
    if (listen(fd, backlog) != 0) {
        net_close(fd);
        return INVALID_SOCK;
    }
    return fd;
}

// Accept on IPv4 or dual-stack IPv6 listeners without truncating peer address.
inline socket_t accept_any(socket_t listen_fd) {
    sockaddr_storage peer{};
    socklen_type peer_len = sizeof(peer);
    return accept(listen_fd, reinterpret_cast<sockaddr*>(&peer), &peer_len);
}

inline std::string format_host_port(const std::string& host, int port) {
    const std::string h = strip_ip_brackets(host);
    if (host_is_ipv6_literal(h)) {
        return "[" + h + "]:" + std::to_string(port);
    }
    return h + ":" + std::to_string(port);
}

inline std::string format_hosts_port(const std::vector<std::string>& hosts, int port) {
    if (hosts.empty()) return format_host_port("", port);
    std::string out;
    for (size_t i = 0; i < hosts.size(); ++i) {
        if (i) out += " | ";
        out += format_host_port(hosts[i], port);
    }
    return out;
}

inline bool set_nonblock(socket_t fd, bool on) {
#ifdef _WIN32
    u_long mode = on ? 1 : 0;
    return ioctlsocket(fd, FIONBIO, &mode) == 0;
#else
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) return false;
    if (on) flags |= O_NONBLOCK;
    else flags &= ~O_NONBLOCK;
    return fcntl(fd, F_SETFL, flags) == 0;
#endif
}

// Non-blocking connect with explicit timeout so IPv6-first fallback cannot stall
// on unreachable AAAA / blackhole routes for a full TCP SYN RTO.
inline bool connect_with_timeout(socket_t fd, const sockaddr* addr, socklen_type len,
                                 int timeout_sec) {
    if (!set_nonblock(fd, true)) return false;
    const int rc = ::connect(fd, addr, len);
    if (rc == 0) {
        set_nonblock(fd, false);
        return true;
    }
#ifdef _WIN32
    const int err = net_errno();
    if (err != WSAEWOULDBLOCK && err != WSAEINPROGRESS) {
        set_nonblock(fd, false);
        return false;
    }
#else
    if (errno != EINPROGRESS) {
        set_nonblock(fd, false);
        return false;
    }
#endif
    fd_set wset, eset;
    FD_ZERO(&wset);
    FD_ZERO(&eset);
    FD_SET(fd, &wset);
    FD_SET(fd, &eset);
    timeval tv{};
    tv.tv_sec = timeout_sec > 0 ? timeout_sec : 1;
    tv.tv_usec = 0;
    const int sel = ::select(static_cast<int>(fd) + 1, nullptr, &wset, &eset, &tv);
    if (sel <= 0) {
        set_nonblock(fd, false);
        return false;
    }
    int soerr = 0;
    socklen_type slen = sizeof(soerr);
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &slen) != 0 ||
        soerr != 0) {
        set_nonblock(fd, false);
        return false;
    }
    set_nonblock(fd, false);
    return true;
}

inline socket_t tcp_connect(const std::string& host, int port, int idle_timeout_sec) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* res = nullptr;
    std::string port_str = std::to_string(port);
    const std::string host_norm = strip_ip_brackets(host);
    if (getaddrinfo(host_norm.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
        return INVALID_SOCK;
    }

    // Cap per-address connect wait so dual-stack host lists fail over quickly.
    int connect_timeout = idle_timeout_sec > 0 ? idle_timeout_sec : 5;
    if (connect_timeout > 5) connect_timeout = 5;
    if (connect_timeout < 1) connect_timeout = 1;

    // Prefer IPv6 results first (stable within each family), then IPv4.
    std::vector<addrinfo*> ordered;
    for (addrinfo* p = res; p; p = p->ai_next) {
        if (p->ai_family == AF_INET6) ordered.push_back(p);
    }
    for (addrinfo* p = res; p; p = p->ai_next) {
        if (p->ai_family != AF_INET6) ordered.push_back(p);
    }

    socket_t fd = INVALID_SOCK;
    for (addrinfo* p : ordered) {
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd == INVALID_SOCK) continue;
        set_socket_options(fd, idle_timeout_sec);
        if (connect_with_timeout(fd, p->ai_addr, static_cast<socklen_type>(p->ai_addrlen),
                                 connect_timeout)) {
            break;
        }
        net_close(fd);
        fd = INVALID_SOCK;
    }
    freeaddrinfo(res);
    return fd;
}

// Optional detail for uplink / Happy-Eyeballs-style fallback logging.
struct ConnectHostsDetail {
    std::string used_host;                 // first success
    std::vector<std::string> failed_hosts; // earlier attempts that timed out / refused
};

inline const char* host_family_tag(const std::string& host) {
    if (host_is_ipv6_literal(host)) return "v6";
    if (host_is_ipv4_literal(host)) return "v4";
    return "name";
}

// Try hosts in order (callers should put IPv6 first). First successful connect wins.
inline socket_t tcp_connect_hosts(const std::vector<std::string>& hosts, int port,
                                  int idle_timeout_sec,
                                  ConnectHostsDetail* detail = nullptr) {
    if (detail) {
        detail->used_host.clear();
        detail->failed_hosts.clear();
    }
    for (const auto& h : hosts) {
        if (h.empty()) continue;
        socket_t fd = tcp_connect(h, port, idle_timeout_sec);
        if (fd != INVALID_SOCK) {
            if (detail) detail->used_host = h;
            return fd;
        }
        if (detail) detail->failed_hosts.push_back(h);
    }
    return INVALID_SOCK;
}

// Build a DNS query (QDCOUNT=1) for A (1) or AAAA (28).
inline std::vector<uint8_t> build_dns_query(const std::string& name, uint16_t qtype,
                                            uint16_t id = 0x1234) {
    std::vector<uint8_t> q;
    if (name.empty() || name.size() > 253) return q;
    q.push_back(static_cast<uint8_t>(id >> 8));
    q.push_back(static_cast<uint8_t>(id & 0xFF));
    q.push_back(0x01);
    q.push_back(0x00);
    q.push_back(0x00);
    q.push_back(0x01);
    q.push_back(0x00);
    q.push_back(0x00);
    q.push_back(0x00);
    q.push_back(0x00);
    q.push_back(0x00);
    q.push_back(0x00);
    size_t i = 0;
    while (i < name.size()) {
        size_t j = name.find('.', i);
        if (j == std::string::npos) j = name.size();
        const size_t lab = j - i;
        if (lab == 0 || lab > 63) return {};
        q.push_back(static_cast<uint8_t>(lab));
        q.insert(q.end(), name.begin() + static_cast<std::ptrdiff_t>(i),
                 name.begin() + static_cast<std::ptrdiff_t>(j));
        i = j + (j < name.size() ? 1 : 0);
    }
    q.push_back(0);
    q.push_back(static_cast<uint8_t>(qtype >> 8));
    q.push_back(static_cast<uint8_t>(qtype & 0xFF));
    q.push_back(0x00);
    q.push_back(0x01);
    return q;
}

inline size_t dns_wire_skip_name(const uint8_t* msg, size_t len, size_t off) {
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

// Exchange one DNS-over-TCP query; returns raw response wire (no 2-byte length).
inline bool dns_tcp_transact_raw(const std::string& resolver, int resolver_port,
                                 const uint8_t* query, size_t qlen,
                                 std::vector<uint8_t>& resp, int timeout_sec = 3) {
    if (!query || qlen < 12 || qlen > 4096) return false;
    socket_t fd = tcp_connect(resolver, resolver_port, timeout_sec);
    if (fd == INVALID_SOCK) return false;
    uint8_t lenb[2] = {static_cast<uint8_t>(qlen >> 8), static_cast<uint8_t>(qlen)};
    if (!send_all(fd, lenb, 2) || !send_all(fd, query, qlen)) {
        net_close(fd);
        return false;
    }
    uint8_t rlenb[2];
    if (!recv_exact(fd, rlenb, 2)) {
        net_close(fd);
        return false;
    }
    const size_t rlen = (static_cast<size_t>(rlenb[0]) << 8) | rlenb[1];
    if (rlen < 12 || rlen > 4096) {
        net_close(fd);
        return false;
    }
    resp.resize(rlen);
    if (!recv_exact(fd, resp.data(), rlen)) {
        net_close(fd);
        return false;
    }
    net_close(fd);
    return true;
}

// Collect A (type=1) and/or AAAA (type=28) RDATA hosts from a DNS answer.
inline void dns_collect_answer_hosts(const uint8_t* resp, size_t rlen,
                                     std::vector<std::string>& out_v6,
                                     std::vector<std::string>& out_v4) {
    if (!resp || rlen < 12) return;
    const uint16_t ancount = static_cast<uint16_t>((resp[6] << 8) | resp[7]);
    size_t off = dns_wire_skip_name(resp, rlen, 12);
    if (off + 4 > rlen) return;
    off += 4; // QTYPE + QCLASS
    for (uint16_t ai = 0; ai < ancount && off + 10 <= rlen; ++ai) {
        off = dns_wire_skip_name(resp, rlen, off);
        if (off + 10 > rlen) return;
        const uint16_t typ = static_cast<uint16_t>((resp[off] << 8) | resp[off + 1]);
        const uint16_t rdlen = static_cast<uint16_t>((resp[off + 8] << 8) | resp[off + 9]);
        off += 10;
        if (off + rdlen > rlen) return;
        if (typ == 28 && rdlen == 16) {
            char buf[INET6_ADDRSTRLEN] = {};
            if (inet_ntop(AF_INET6, resp + off, buf, sizeof(buf))) out_v6.emplace_back(buf);
        } else if (typ == 1 && rdlen == 4) {
            char buf[INET_ADDRSTRLEN] = {};
            if (inet_ntop(AF_INET, resp + off, buf, sizeof(buf))) out_v4.emplace_back(buf);
        }
        off += rdlen;
    }
}

// DNS-over-TCP A+AAAA lookup. Used when UDP/53 is hijacked by activate_net fake-IP
// (getaddrinfo would return 198.18.x and DIRECT would loop back into SOCKS).
// Returns hosts with IPv6 first, then IPv4 (Happy Eyeballs spirit).
// resolver_port defaults to 53; tests may point at a local DNS-over-TCP stub.
inline bool resolve_hosts_dns_tcp(const std::string& name, std::vector<std::string>& out_hosts,
                                  const char* resolver = "8.8.8.8", int timeout_sec = 3,
                                  int resolver_port = 53) {
    out_hosts.clear();
    in_addr lit{};
    if (inet_pton(AF_INET, name.c_str(), &lit) == 1) {
        out_hosts.push_back(name);
        return true;
    }
    in6_addr lit6{};
    const std::string bare = strip_ip_brackets(name);
    if (inet_pton(AF_INET6, bare.c_str(), &lit6) == 1) {
        out_hosts.push_back(bare);
        return true;
    }
    if (name.empty() || name.size() > 253) return false;
    if (resolver_port <= 0 || resolver_port > 65535) resolver_port = 53;

    auto try_resolver = [&](const char* r) -> bool {
        if (!r || !*r) return false;
        std::vector<std::string> v6, v4;
        // AAAA first so a working IPv6 path is preferred before A.
        for (uint16_t qtype : {static_cast<uint16_t>(28), static_cast<uint16_t>(1)}) {
            const auto q = build_dns_query(name, qtype);
            if (q.empty()) continue;
            std::vector<uint8_t> resp;
            if (!dns_tcp_transact_raw(r, resolver_port, q.data(), q.size(), resp, timeout_sec))
                continue;
            dns_collect_answer_hosts(resp.data(), resp.size(), v6, v4);
        }
        for (const auto& h : v6) {
            if (std::find(out_hosts.begin(), out_hosts.end(), h) == out_hosts.end())
                out_hosts.push_back(h);
        }
        for (const auto& h : v4) {
            if (std::find(out_hosts.begin(), out_hosts.end(), h) == out_hosts.end())
                out_hosts.push_back(h);
        }
        return !out_hosts.empty();
    };

    if (try_resolver(resolver)) return true;
    // Only fall through to public resolvers on the standard DNS port.
    if (resolver_port == 53) {
        if (std::string(resolver) != "8.8.8.8" && try_resolver("8.8.8.8")) return true;
        if (std::string(resolver) != "1.1.1.1" && try_resolver("1.1.1.1")) return true;
    }
    return false;
}

// DNS-over-TCP A lookup (first A only). Kept for callers that need a single IPv4.
inline bool resolve_ipv4_dns_tcp(const std::string& name, uint32_t& out_net,
                                 const char* resolver = "8.8.8.8", int timeout_sec = 3,
                                 int resolver_port = 53) {
    std::vector<std::string> hosts;
    if (!resolve_hosts_dns_tcp(name, hosts, resolver, timeout_sec, resolver_port)) return false;
    for (const auto& h : hosts) {
        in_addr a{};
        if (inet_pton(AF_INET, h.c_str(), &a) == 1) {
            out_net = a.s_addr;
            return out_net != 0;
        }
    }
    return false;
}

// Prefer DNS-over-TCP when resolving hostnames so activate_net fake-IP UDP
// hijack cannot poison DIRECT connects into 198.18.x loops.
// Dual-stack: AAAA then A, IPv6 connect first with timed fallback to IPv4.
// Optional resolver/resolver_port let tests drive a local DNS-over-TCP stub.
inline socket_t tcp_connect_direct_host(const std::string& host, int port, int idle_timeout_sec,
                                       const char* resolver = nullptr, int resolver_port = 53) {
    in_addr lit{};
    if (inet_pton(AF_INET, host.c_str(), &lit) == 1) {
        return tcp_connect(host, port, idle_timeout_sec);
    }
    in6_addr lit6{};
    if (inet_pton(AF_INET6, strip_ip_brackets(host).c_str(), &lit6) == 1) {
        return tcp_connect(strip_ip_brackets(host), port, idle_timeout_sec);
    }
    std::vector<std::string> hosts;
    const char* r = (resolver && *resolver) ? resolver : "8.8.8.8";
    if (resolve_hosts_dns_tcp(host, hosts, r, 3, resolver_port)) {
        socket_t fd = tcp_connect_hosts(hosts, port, idle_timeout_sec);
        if (fd != INVALID_SOCK) return fd;
    }
    // Last resort: system getaddrinfo (already IPv6-prefer inside tcp_connect).
    // Skip when a non-standard stub port was requested (tests must not hit real DNS).
    if (resolver_port != 53) return INVALID_SOCK;
    return tcp_connect(host, port, idle_timeout_sec);
}

inline void shutdown_both(socket_t fd) {
    if (fd == INVALID_SOCK) return;
#ifdef _WIN32
    ::shutdown(fd, SD_BOTH);
#else
    ::shutdown(fd, SHUT_RDWR);
#endif
}

inline socket_t create_udp_socket(int family = AF_INET) {
    socket_t fd = ::socket(family, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == INVALID_SOCK) return INVALID_SOCK;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&one), sizeof(one));
    return fd;
}

inline socket_t create_udp_listen_socket(const std::string& bind_ip, int port) {
    const std::string ip = strip_ip_brackets(bind_ip);
    const bool want_dual = ip.empty() || ip == "*" || ip == "::";
    const bool want_v4any = (ip == "0.0.0.0");
    in6_addr v6addr{};
    in_addr v4addr{};
    bool use_v6 = false;
    if (want_dual) {
        use_v6 = true;
        v6addr = in6addr_any;
    } else if (want_v4any) {
        use_v6 = false;
        v4addr.s_addr = htonl(INADDR_ANY);
    } else if (inet_pton(AF_INET6, ip.c_str(), &v6addr) == 1) {
        use_v6 = true;
    } else if (inet_pton(AF_INET, ip.c_str(), &v4addr) == 1) {
        use_v6 = false;
    } else {
        return INVALID_SOCK;
    }

    socket_t fd = create_udp_socket(use_v6 ? AF_INET6 : AF_INET);
    if (fd == INVALID_SOCK) return INVALID_SOCK;
    if (use_v6) {
        int v6only = want_dual ? 0 : 1;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY,
                   reinterpret_cast<const char*>(&v6only), sizeof(v6only));
        sockaddr_in6 addr{};
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(static_cast<uint16_t>(port));
        addr.sin6_addr = v6addr;
        if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            net_close(fd);
            return INVALID_SOCK;
        }
    } else {
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_port = htons(static_cast<uint16_t>(port));
        addr.sin_addr = v4addr;
        if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
            net_close(fd);
            return INVALID_SOCK;
        }
    }
    return fd;
}

inline bool udp_send_to(socket_t fd, const uint8_t* data, size_t len,
                        const sockaddr_in& to) {
#ifdef _WIN32
    const int n = ::sendto(fd, reinterpret_cast<const char*>(data),
                           static_cast<int>(len), 0,
                           reinterpret_cast<const sockaddr*>(&to), sizeof(to));
#else
    const ssize_t n = ::sendto(fd, data, len, 0,
                               reinterpret_cast<const sockaddr*>(&to), sizeof(to));
#endif
    return n >= 0 && static_cast<size_t>(n) == len;
}

inline bool udp_send_to_host(socket_t fd, const uint8_t* data, size_t len,
                             const std::string& host, uint16_t port) {
    sockaddr_in to{};
    to.sin_family = AF_INET;
    to.sin_port = htons(port);
    if (inet_pton(AF_INET, host.c_str(), &to.sin_addr) != 1) return false;
    return udp_send_to(fd, data, len, to);
}

inline int udp_recv_from(socket_t fd, uint8_t* data, size_t len, sockaddr_in& from) {
    socklen_type flen = sizeof(from);
#ifdef _WIN32
    return ::recvfrom(fd, reinterpret_cast<char*>(data), static_cast<int>(len), 0,
                      reinterpret_cast<sockaddr*>(&from), &flen);
#else
    return static_cast<int>(
        ::recvfrom(fd, data, len, 0, reinterpret_cast<sockaddr*>(&from), &flen));
#endif
}

inline std::string sockaddr_ip_str(const sockaddr_in& a) {
    char buf[INET_ADDRSTRLEN] = {};
    if (!inet_ntop(AF_INET, &a.sin_addr, buf, sizeof(buf))) return {};
    return std::string(buf);
}

#endif // VORTEX_NET_HPP
