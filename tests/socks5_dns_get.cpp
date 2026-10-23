// SOCKS5 CONNECT to a DNS-over-TCP resolver, send one A query, print first A.
#include "net.hpp"
#include <cstdio>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

static std::vector<uint8_t> build_query_a(const std::string& name) {
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
    q.push_back(0x00);
    q.push_back(0x01);
    q.push_back(0x00);
    q.push_back(0x01);
    return q;
}

int main(int argc, char* argv[]) {
    int proxy_port = 21080;
    std::string resolver = "127.0.0.1";
    int resolver_port = 15353;
    std::string qname = "peer-dns.test";
    if (argc >= 2) proxy_port = std::atoi(argv[1]);
    if (argc >= 3) resolver_port = std::atoi(argv[2]);
    if (argc >= 4) resolver = argv[3];
    if (argc >= 5) qname = argv[4];

    if (!net_init()) return 1;
    socket_t fd = tcp_connect("127.0.0.1", proxy_port, 10);
    if (fd == INVALID_SOCK) {
        std::cerr << "proxy connect failed\n";
        return 2;
    }
    uint8_t greet[] = {0x05, 0x01, 0x00};
    if (!send_all(fd, greet, sizeof(greet))) return 3;
    uint8_t greply[2];
    if (!recv_exact(fd, greply, 2) || greply[0] != 0x05 || greply[1] != 0x00) return 4;

    std::vector<uint8_t> req;
    req.push_back(0x05);
    req.push_back(0x01);
    req.push_back(0x00);
    req.push_back(0x03);
    req.push_back(static_cast<uint8_t>(resolver.size()));
    req.insert(req.end(), resolver.begin(), resolver.end());
    uint16_t pbe = htons(static_cast<uint16_t>(resolver_port));
    uint8_t pb[2];
    std::memcpy(pb, &pbe, 2);
    req.insert(req.end(), pb, pb + 2);
    if (!send_all(fd, req.data(), req.size())) return 5;
    uint8_t rreply[10];
    if (!recv_exact(fd, rreply, 10) || rreply[1] != 0x00) {
        std::cerr << "socks connect failed code=" << (int)rreply[1] << "\n";
        return 6;
    }

    auto q = build_query_a(qname);
    if (q.empty()) return 7;
    uint8_t lenb[2] = {static_cast<uint8_t>(q.size() >> 8), static_cast<uint8_t>(q.size())};
    if (!send_all(fd, lenb, 2) || !send_all(fd, q.data(), q.size())) return 8;

    uint8_t rlenb[2];
    if (!recv_exact(fd, rlenb, 2)) return 9;
    const size_t rlen = (static_cast<size_t>(rlenb[0]) << 8) | rlenb[1];
    if (rlen < 12 || rlen > 4096) return 10;
    std::vector<uint8_t> resp(rlen);
    if (!recv_exact(fd, resp.data(), rlen)) return 11;
    net_close(fd);
    net_cleanup();

    // Find first A RDATA (type=1, rdlen=4) after question — scan loosely.
    bool found = false;
    for (size_t i = 0; i + 12 <= resp.size(); ++i) {
        if (resp[i] == 0x00 && resp[i + 1] == 0x01 && resp[i + 2] == 0x00 && resp[i + 3] == 0x01 &&
            i + 10 < resp.size() && resp[i + 8] == 0x00 && resp[i + 9] == 0x04 && i + 14 <= resp.size()) {
            char ip[32];
            std::snprintf(ip, sizeof(ip), "%u.%u.%u.%u", resp[i + 10], resp[i + 11], resp[i + 12],
                          resp[i + 13]);
            std::cout << "DNS A " << qname << " -> " << ip << "\n";
            found = (std::string(ip) == "127.0.0.1");
            break;
        }
    }
    if (!found) {
        std::cerr << "no A 127.0.0.1 in answer (len=" << rlen << ")\n";
        return 12;
    }
    std::cout << "SOCKS5 DNS-over-TCP OK\n";
    return 0;
}
