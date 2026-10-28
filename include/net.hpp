#ifndef VORTEX_NET_HPP
#define VORTEX_NET_HPP

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

inline socket_t create_listen_socket(const std::string& bind_ip, int port, int backlog) {
    socket_t fd = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
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
    if (bind_ip.empty() || bind_ip == "0.0.0.0") {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        if (inet_pton(AF_INET, bind_ip.c_str(), &addr.sin_addr) != 1) {
            net_close(fd);
            return INVALID_SOCK;
        }
    }

    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        net_close(fd);
        return INVALID_SOCK;
    }
    if (listen(fd, backlog) != 0) {
        net_close(fd);
        return INVALID_SOCK;
    }
    return fd;
}

inline socket_t tcp_connect(const std::string& host, int port, int idle_timeout_sec) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* res = nullptr;
    std::string port_str = std::to_string(port);
    if (getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res) != 0 || !res) {
        return INVALID_SOCK;
    }

    socket_t fd = INVALID_SOCK;
    for (addrinfo* p = res; p; p = p->ai_next) {
        fd = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (fd == INVALID_SOCK) continue;
        set_socket_options(fd, idle_timeout_sec);
        if (::connect(fd, p->ai_addr, static_cast<socklen_type>(p->ai_addrlen)) == 0) {
            break;
        }
        net_close(fd);
        fd = INVALID_SOCK;
    }
    freeaddrinfo(res);
    return fd;
}

// DNS-over-TCP A lookup. Used when UDP/53 is hijacked by activate_net fake-IP
// (getaddrinfo would return 198.18.x and DIRECT would loop back into SOCKS).
inline bool resolve_ipv4_dns_tcp(const std::string& name, uint32_t& out_net,
                                 const char* resolver = "8.8.8.8", int timeout_sec = 3) {
    in_addr lit{};
    if (inet_pton(AF_INET, name.c_str(), &lit) == 1) {
        out_net = lit.s_addr;
        return true;
    }
    if (name.empty() || name.size() > 253) return false;

    std::vector<uint8_t> q;
    q.push_back(0x12);
    q.push_back(0x34);
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
        if (lab == 0 || lab > 63) return false;
        q.push_back(static_cast<uint8_t>(lab));
        q.insert(q.end(), name.begin() + static_cast<std::ptrdiff_t>(i),
                 name.begin() + static_cast<std::ptrdiff_t>(j));
        i = j + (j < name.size() ? 1 : 0);
    }
    q.push_back(0);
    q.push_back(0x00);
    q.push_back(0x01);
    q.push_back(0x00);
    q.push_back(0x01);

    socket_t fd = tcp_connect(resolver, 53, timeout_sec);
    if (fd == INVALID_SOCK) {
        fd = tcp_connect("1.1.1.1", 53, timeout_sec);
        if (fd == INVALID_SOCK) return false;
    }
    uint8_t lenb[2] = {static_cast<uint8_t>(q.size() >> 8), static_cast<uint8_t>(q.size())};
    if (!send_all(fd, lenb, 2) || !send_all(fd, q.data(), q.size())) {
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
    std::vector<uint8_t> resp(rlen);
    if (!recv_exact(fd, resp.data(), rlen)) {
        net_close(fd);
        return false;
    }
    net_close(fd);

    auto skip_name = [&](size_t off) -> size_t {
        int hops = 0;
        while (off < resp.size() && hops < 64) {
            const uint8_t lab = resp[off];
            if (lab == 0) return off + 1;
            if ((lab & 0xC0) == 0xC0) return off + 2 < resp.size() ? off + 2 : resp.size();
            if (off + 1 + lab > resp.size()) return resp.size();
            off += 1 + lab;
            ++hops;
        }
        return resp.size();
    };

    const uint16_t ancount = static_cast<uint16_t>((resp[6] << 8) | resp[7]);
    size_t off = skip_name(12);
    if (off + 4 > resp.size()) return false;
    off += 4;
    for (uint16_t ai = 0; ai < ancount && off + 10 <= resp.size(); ++ai) {
        off = skip_name(off);
        if (off + 10 > resp.size()) return false;
        const uint16_t typ = static_cast<uint16_t>((resp[off] << 8) | resp[off + 1]);
        const uint16_t rdlen = static_cast<uint16_t>((resp[off + 8] << 8) | resp[off + 9]);
        off += 10;
        if (off + rdlen > resp.size()) return false;
        if (typ == 1 && rdlen == 4) {
            std::memcpy(&out_net, resp.data() + off, 4);
            return out_net != 0;
        }
        off += rdlen;
    }
    return false;
}

// Prefer DNS-over-TCP when resolving hostnames so activate_net fake-IP UDP
// hijack cannot poison DIRECT connects into 198.18.x loops.
inline socket_t tcp_connect_direct_host(const std::string& host, int port, int idle_timeout_sec) {
    in_addr lit{};
    if (inet_pton(AF_INET, host.c_str(), &lit) == 1) {
        return tcp_connect(host, port, idle_timeout_sec);
    }
    uint32_t ip_net = 0;
    if (resolve_ipv4_dns_tcp(host, ip_net)) {
        char buf[INET_ADDRSTRLEN] = {};
        if (inet_ntop(AF_INET, &ip_net, buf, sizeof(buf))) {
            return tcp_connect(buf, port, idle_timeout_sec);
        }
    }
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

inline socket_t create_udp_socket() {
    socket_t fd = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (fd == INVALID_SOCK) return INVALID_SOCK;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR,
               reinterpret_cast<const char*>(&one), sizeof(one));
    return fd;
}

inline socket_t create_udp_listen_socket(const std::string& bind_ip, int port) {
    socket_t fd = create_udp_socket();
    if (fd == INVALID_SOCK) return INVALID_SOCK;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(static_cast<uint16_t>(port));
    if (bind_ip.empty() || bind_ip == "0.0.0.0") {
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    } else {
        if (inet_pton(AF_INET, bind_ip.c_str(), &addr.sin_addr) != 1) {
            net_close(fd);
            return INVALID_SOCK;
        }
    }
    if (bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        net_close(fd);
        return INVALID_SOCK;
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
