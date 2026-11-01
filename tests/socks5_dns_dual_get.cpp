// SOCKS5 CONNECT to a DNS-over-TCP resolver; send A and AAAA; require both answers.
#include "net.hpp"
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

static std::vector<uint8_t> build_query(const std::string& name, uint16_t qtype) {
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

static bool has_rr_type(const std::vector<uint8_t>& resp, uint16_t want) {
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
    if (resp.size() < 12) return false;
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
        if (typ == want) return true;
        off += rdlen;
    }
    return false;
}

static bool socks_dns_query(const std::string& socks_host, int socks_port,
                            const std::string& resolver, int resolver_port,
                            const std::string& qname, uint16_t qtype,
                            std::vector<uint8_t>& resp) {
    socket_t fd = tcp_connect(socks_host, socks_port, 10);
    if (fd == INVALID_SOCK) return false;
    uint8_t greet[] = {0x05, 0x01, 0x00};
    if (!send_all(fd, greet, sizeof(greet))) {
        net_close(fd);
        return false;
    }
    uint8_t greply[2];
    if (!recv_exact(fd, greply, 2) || greply[0] != 0x05 || greply[1] != 0x00) {
        net_close(fd);
        return false;
    }

    std::vector<uint8_t> req;
    req.push_back(0x05);
    req.push_back(0x01);
    req.push_back(0x00);
    if (host_is_ipv6_literal(resolver)) {
        req.push_back(0x04);
        in6_addr a{};
        inet_pton(AF_INET6, strip_ip_brackets(resolver).c_str(), &a);
        uint8_t raw[16];
        std::memcpy(raw, &a, 16);
        req.insert(req.end(), raw, raw + 16);
    } else if (host_is_ipv4_literal(resolver)) {
        req.push_back(0x01);
        in_addr a{};
        inet_pton(AF_INET, resolver.c_str(), &a);
        uint8_t raw[4];
        std::memcpy(raw, &a.s_addr, 4);
        req.insert(req.end(), raw, raw + 4);
    } else {
        req.push_back(0x03);
        req.push_back(static_cast<uint8_t>(resolver.size()));
        req.insert(req.end(), resolver.begin(), resolver.end());
    }
    req.push_back(static_cast<uint8_t>((resolver_port >> 8) & 0xFF));
    req.push_back(static_cast<uint8_t>(resolver_port & 0xFF));
    if (!send_all(fd, req.data(), req.size())) {
        net_close(fd);
        return false;
    }
    uint8_t rreply[4];
    if (!recv_exact(fd, rreply, 4) || rreply[1] != 0x00) {
        net_close(fd);
        return false;
    }
    // Skip BND.ADDR
    if (rreply[3] == 0x01) {
        uint8_t skip[6];
        if (!recv_exact(fd, skip, 6)) {
            net_close(fd);
            return false;
        }
    } else if (rreply[3] == 0x04) {
        uint8_t skip[18];
        if (!recv_exact(fd, skip, 18)) {
            net_close(fd);
            return false;
        }
    } else if (rreply[3] == 0x03) {
        uint8_t n = 0;
        if (!recv_exact(fd, &n, 1)) {
            net_close(fd);
            return false;
        }
        std::vector<uint8_t> skip(static_cast<size_t>(n) + 2);
        if (!recv_exact(fd, skip.data(), skip.size())) {
            net_close(fd);
            return false;
        }
    } else {
        net_close(fd);
        return false;
    }

    auto q = build_query(qname, qtype);
    if (q.empty()) {
        net_close(fd);
        return false;
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
    resp.resize(rlen);
    if (!recv_exact(fd, resp.data(), rlen)) {
        net_close(fd);
        return false;
    }
    net_close(fd);
    return true;
}

int main(int argc, char* argv[]) {
    std::string socks_host = "127.0.0.1";
    int socks_port = 21090;
    std::string resolver = "127.0.0.1";
    int resolver_port = 15353;
    std::string qname = "dual.example.test";
    if (argc >= 2) socks_port = std::atoi(argv[1]);
    if (argc >= 3) resolver_port = std::atoi(argv[2]);
    if (argc >= 4) resolver = argv[3];
    if (argc >= 5) qname = argv[4];
    if (argc >= 6) socks_host = argv[5];

    if (!net_init()) return 1;

    std::vector<uint8_t> a_resp, aaaa_resp;
    if (!socks_dns_query(socks_host, socks_port, resolver, resolver_port, qname, 1, a_resp)) {
        std::cerr << "A query failed\n";
        return 2;
    }
    if (!has_rr_type(a_resp, 1)) {
        std::cerr << "A answer missing type A RDATA\n";
        return 3;
    }
    if (!socks_dns_query(socks_host, socks_port, resolver, resolver_port, qname, 28, aaaa_resp)) {
        std::cerr << "AAAA query failed\n";
        return 4;
    }
    if (!has_rr_type(aaaa_resp, 28)) {
        std::cerr << "AAAA answer missing type AAAA RDATA\n";
        return 5;
    }
    std::cout << "PASS dual DNS A+AAAA via SOCKS " << socks_host << ":" << socks_port
              << " -> " << resolver << ":" << resolver_port << " q=" << qname << "\n";
    net_cleanup();
    return 0;
}
