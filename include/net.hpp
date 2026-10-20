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
   using socket_t = SOCKET;
   constexpr socket_t INVALID_SOCK = INVALID_SOCKET;
   using socklen_type = int;
   inline int net_close(socket_t s) { return closesocket(s); }
   inline int net_errno() { return WSAGetLastError(); }
   inline bool net_would_block(int e) {
       return e == WSAEWOULDBLOCK || e == WSAEINTR;
   }
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

inline void set_socket_options(socket_t fd, int idle_timeout_sec) {
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY,
               reinterpret_cast<const char*>(&one), sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE,
               reinterpret_cast<const char*>(&one), sizeof(one));
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
            if (n < 0 && net_would_block(net_errno())) continue;
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
            if (n < 0 && net_would_block(net_errno())) continue;
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

inline void shutdown_both(socket_t fd) {
    if (fd == INVALID_SOCK) return;
#ifdef _WIN32
    ::shutdown(fd, SD_BOTH);
#else
    ::shutdown(fd, SHUT_RDWR);
#endif
}

#endif // VORTEX_NET_HPP
