// ActivateNet: system-wide transparent proxy for THIS PC's applications.
//
// WinDivert captures outbound IPv4 TCP + DNS from local apps, answers DNS
// with fake-IP (198.18.0.0/15), terminates TCP, and relays via SOCKS5
// CONNECT(domain) to multilink.exe / smartlink.exe on 127.0.0.1:11080.
// Routing rules live in the SOCKS5 upstream — not embedded here.
//
// Does NOT touch Mobile Hotspot / SoftAP (use ap2socks5 for that).
// Requires Administrator + WinDivert 2.2 next to this executable.
// Windows-only.

#ifndef _WIN32
#error ActivateNet is Windows-only (WinDivert).
#endif

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include "config.hpp"
#include "net.hpp"
#include "packet_build.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace {

constexpr int WINDIVERT_LAYER_NETWORK = 0;
constexpr int16_t WINDIVERT_PRIORITY_HIGHEST = 30000;

#pragma pack(push, 1)
struct DivertAddr {
    int64_t Timestamp;
    uint32_t bits0;
    uint32_t Reserved2;
    uint8_t reserved3[64];
};
static_assert(sizeof(DivertAddr) == 80, "WinDivert 2.2 address size");
#pragma pack(pop)

inline void addr_set_outbound(DivertAddr& a, bool outbound) {
    if (outbound) a.bits0 |= (1u << 17);
    else a.bits0 &= ~(1u << 17);
}
inline void addr_set_impostor(DivertAddr& a, bool on) {
    if (on) a.bits0 |= (1u << 19);
    else a.bits0 &= ~(1u << 19);
}
inline void addr_clear_checksum_bits(DivertAddr& a) {
    a.bits0 &= ~((1u << 21) | (1u << 22) | (1u << 23));
}

using FnOpen = HANDLE(WINAPI*)(const char*, int, int16_t, uint64_t);
using FnRecv = BOOL(WINAPI*)(HANDLE, void*, UINT, UINT*, DivertAddr*);
using FnSend = BOOL(WINAPI*)(HANDLE, const void*, UINT, UINT*, const DivertAddr*);
using FnClose = BOOL(WINAPI*)(HANDLE);
using FnShutdown = BOOL(WINAPI*)(HANDLE, int);
using FnSetParam = BOOL(WINAPI*)(HANDLE, int, uint64_t);
using FnCalc = BOOL(WINAPI*)(void*, UINT, DivertAddr*, uint64_t);

FnOpen g_open = nullptr;
FnRecv g_recv = nullptr;
FnSend g_send = nullptr;
FnClose g_close = nullptr;
FnShutdown g_shutdown = nullptr;
FnSetParam g_set_param = nullptr;
FnCalc g_calc = nullptr;

ActivateNetConfig g_cfg;
std::atomic<bool> g_run{true};
std::mutex g_log_mu;

void log_line(const std::string& s) {
    std::lock_guard<std::mutex> lock(g_log_mu);
    std::cout << s << std::endl;
}

std::string ip_to_string(uint32_t net) {
    char buf[INET_ADDRSTRLEN] = {};
    in_addr a{};
    a.s_addr = net;
    if (!inet_ntop(AF_INET, &a, buf, sizeof(buf))) return "?";
    return buf;
}

std::atomic<uint16_t> g_ip_id{1};
std::atomic<uint64_t> g_captured{0}, g_dns_ok{0}, g_dns_fail{0};
std::atomic<uint64_t> g_connect_ok{0}, g_socks_fail{0}, g_passthru{0};
std::atomic<uint64_t> g_drop_quic{0}, g_drop_ipv6{0};
std::atomic<uint64_t> g_fakeip_miss{0}, g_realip_reject{0};
std::atomic<uint64_t> g_rx{0}, g_tx{0};
std::atomic<int> g_dns_inflight{0};

std::mutex g_own_mu;
std::unordered_set<uint16_t> g_own_sports;

void register_own_port(uint16_t sport) {
    if (!sport) return;
    std::lock_guard<std::mutex> lock(g_own_mu);
    g_own_sports.insert(sport);
}
void unregister_own_port(uint16_t sport) {
    if (!sport) return;
    std::lock_guard<std::mutex> lock(g_own_mu);
    g_own_sports.erase(sport);
}
void register_own_socket(SOCKET s) {
    sockaddr_in a{};
    int alen = sizeof(a);
    if (getsockname(s, reinterpret_cast<sockaddr*>(&a), &alen) != 0) return;
    register_own_port(ntohs(a.sin_port));
}
void unregister_own_socket(SOCKET s) {
    sockaddr_in a{};
    int alen = sizeof(a);
    if (getsockname(s, reinterpret_cast<sockaddr*>(&a), &alen) != 0) return;
    unregister_own_port(ntohs(a.sin_port));
}
bool is_own_sport(uint16_t sport) {
    std::lock_guard<std::mutex> lock(g_own_mu);
    return g_own_sports.count(sport) != 0;
}

bool is_private_ip(uint32_t net_order) {
    const uint32_t h = ntohl(net_order);
    if ((h & 0xFF000000u) == 0x0A000000u) return true;
    if ((h & 0xFFF00000u) == 0xAC100000u) return true;
    if ((h & 0xFFFF0000u) == 0xC0A80000u) return true;
    if ((h & 0xFF000000u) == 0x7F000000u) return true;
    return false;
}
bool is_fake_ip(uint32_t net_order) {
    return (ntohl(net_order) & 0xFFFE0000u) == 0xC6120000u;
}

constexpr uint32_t kFakeIpHostMin = 0xC6120001u;
constexpr uint32_t kFakeIpHostMax = 0xC613FFFEu;
constexpr uint32_t kFakeDnsTtl = 300;

struct DnsNameEntry {
    std::string name;
};
std::mutex g_dns_mu;
std::unordered_map<uint32_t, DnsNameEntry> g_ip_to_name;
std::unordered_map<std::string, uint32_t> g_name_to_fake;
uint32_t g_fake_next_host = kFakeIpHostMin;

std::string to_lower_host(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

size_t dns_skip_name(const uint8_t* msg, size_t len, size_t off) {
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
std::string dns_qname(const uint8_t* msg, size_t len) {
    if (len < 12) return {};
    size_t off = 12;
    std::string name;
    int hops = 0;
    while (off < len && hops < 64) {
        const uint8_t lab = msg[off++];
        if (lab == 0) break;
        if ((lab & 0xC0) == 0xC0 || off + lab > len) return name.empty() ? std::string("?") : name;
        if (!name.empty()) name.push_back('.');
        name.append(reinterpret_cast<const char*>(msg + off), lab);
        off += lab;
        ++hops;
    }
    return to_lower_host(name);
}
uint16_t dns_qtype(const uint8_t* msg, size_t len) {
    if (len < 12) return 0;
    size_t off = dns_skip_name(msg, len, 12);
    if (off + 4 > len) return 0;
    return static_cast<uint16_t>((msg[off] << 8) | msg[off + 1]);
}

std::string dns_lookup_name(uint32_t net_order) {
    std::lock_guard<std::mutex> lock(g_dns_mu);
    auto it = g_ip_to_name.find(net_order);
    if (it == g_ip_to_name.end()) return {};
    return it->second.name;
}

uint32_t fake_ip_alloc(const std::string& qname_raw) {
    const std::string qname = to_lower_host(qname_raw);
    if (qname.empty() || qname == "?") return 0;
    std::lock_guard<std::mutex> lock(g_dns_mu);
    auto it = g_name_to_fake.find(qname);
    if (it != g_name_to_fake.end()) return it->second;
    for (int n = 0; n < 65536; ++n) {
        uint32_t host = g_fake_next_host++;
        if (g_fake_next_host > kFakeIpHostMax) g_fake_next_host = kFakeIpHostMin;
        const uint8_t b3 = static_cast<uint8_t>(host & 0xFF);
        if (b3 == 0 || b3 == 255) continue;
        const uint32_t net = htonl(host);
        if (g_ip_to_name.count(net)) continue;
        g_ip_to_name[net] = DnsNameEntry{qname};
        g_name_to_fake[qname] = net;
        return net;
    }
    return 0;
}

std::vector<uint8_t> dns_reply_nodata(const std::vector<uint8_t>& query) {
    if (query.size() < 12) return {};
    size_t off = dns_skip_name(query.data(), query.size(), 12);
    if (off + 4 > query.size()) return {};
    off += 4;
    std::vector<uint8_t> resp(query.begin(), query.begin() + static_cast<std::ptrdiff_t>(off));
    resp[2] = static_cast<uint8_t>((resp[2] & 0x01) | 0x80);
    resp[3] = 0x80;
    resp[6] = resp[7] = resp[8] = resp[9] = resp[10] = resp[11] = 0;
    return resp;
}
std::vector<uint8_t> dns_reply_a(const std::vector<uint8_t>& query, uint32_t ip_net) {
    if (query.size() < 12) return {};
    size_t off = dns_skip_name(query.data(), query.size(), 12);
    if (off + 4 > query.size()) return {};
    off += 4;
    std::vector<uint8_t> resp(query.begin(), query.begin() + static_cast<std::ptrdiff_t>(off));
    resp[2] = static_cast<uint8_t>((resp[2] & 0x01) | 0x80);
    resp[3] = 0x80;
    resp[6] = 0;
    resp[7] = 1;
    resp[8] = resp[9] = resp[10] = resp[11] = 0;
    resp.push_back(0xC0);
    resp.push_back(0x0C);
    resp.push_back(0x00);
    resp.push_back(0x01);
    resp.push_back(0x00);
    resp.push_back(0x01);
    resp.push_back(static_cast<uint8_t>(kFakeDnsTtl >> 24));
    resp.push_back(static_cast<uint8_t>(kFakeDnsTtl >> 16));
    resp.push_back(static_cast<uint8_t>(kFakeDnsTtl >> 8));
    resp.push_back(static_cast<uint8_t>(kFakeDnsTtl));
    resp.push_back(0x00);
    resp.push_back(0x04);
    const uint8_t* p = reinterpret_cast<const uint8_t*>(&ip_net);
    resp.insert(resp.end(), p, p + 4);
    return resp;
}

bool load_windivert() {
    HMODULE m = LoadLibraryA("WinDivert.dll");
    if (!m) return false;
    g_open = reinterpret_cast<FnOpen>(GetProcAddress(m, "WinDivertOpen"));
    g_recv = reinterpret_cast<FnRecv>(GetProcAddress(m, "WinDivertRecv"));
    g_send = reinterpret_cast<FnSend>(GetProcAddress(m, "WinDivertSend"));
    g_close = reinterpret_cast<FnClose>(GetProcAddress(m, "WinDivertClose"));
    g_shutdown = reinterpret_cast<FnShutdown>(GetProcAddress(m, "WinDivertShutdown"));
    g_set_param = reinterpret_cast<FnSetParam>(GetProcAddress(m, "WinDivertSetParam"));
    g_calc = reinterpret_cast<FnCalc>(GetProcAddress(m, "WinDivertHelperCalcChecksums"));
    return g_open && g_recv && g_send && g_close;
}

void inject_inbound(HANDLE divert, DivertAddr addr, const std::vector<uint8_t>& packet) {
    addr_set_outbound(addr, false);
    addr_set_impostor(addr, true);
    addr_clear_checksum_bits(addr);
    if (g_calc) {
        DivertAddr tmp = addr;
        g_calc(const_cast<uint8_t*>(packet.data()), static_cast<UINT>(packet.size()), &tmp, 0);
    }
    UINT sent = 0;
    g_send(divert, packet.data(), static_cast<UINT>(packet.size()), &sent, &addr);
}

void reinject(HANDLE divert, const DivertAddr& addr, const uint8_t* packet, UINT len) {
    UINT sent = 0;
    g_send(divert, packet, len, &sent, &addr);
}

bool recvn(SOCKET s, char* buf, int n) {
    int got = 0;
    while (got < n) {
        const int r = recv(s, buf + got, n - got, 0);
        if (r <= 0) return false;
        got += r;
    }
    return true;
}

bool send_all(SOCKET s, const uint8_t* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        const int n = send(s, reinterpret_cast<const char*>(data + off),
                           static_cast<int>(len - off), 0);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

void set_timeouts(SOCKET s, int sec) {
    DWORD ms = static_cast<DWORD>(sec) * 1000;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char*>(&ms), sizeof(ms));
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, reinterpret_cast<char*>(&ms), sizeof(ms));
}

SOCKET tcp_connect_timeout(const std::string& host, int port, int timeout_sec) {
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0 || !res) {
        return INVALID_SOCKET;
    }
    SOCKET s = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (s == INVALID_SOCKET) {
        freeaddrinfo(res);
        return INVALID_SOCKET;
    }
    register_own_socket(s);
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    int rc = connect(s, res->ai_addr, static_cast<int>(res->ai_addrlen));
    freeaddrinfo(res);
    if (rc != 0 && WSAGetLastError() != WSAEWOULDBLOCK) {
        unregister_own_socket(s);
        closesocket(s);
        return INVALID_SOCKET;
    }
    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(s, &wfds);
    timeval tv{};
    tv.tv_sec = timeout_sec;
    rc = select(0, nullptr, &wfds, nullptr, &tv);
    if (rc <= 0) {
        unregister_own_socket(s);
        closesocket(s);
        return INVALID_SOCKET;
    }
    int soerr = 0;
    int slen = sizeof(soerr);
    getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &slen);
    if (soerr != 0) {
        unregister_own_socket(s);
        closesocket(s);
        return INVALID_SOCKET;
    }
    nb = 0;
    ioctlsocket(s, FIONBIO, &nb);
    set_timeouts(s, timeout_sec);
    int one = 1;
    setsockopt(s, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char*>(&one), sizeof(one));
    return s;
}

bool socks5_read_connect_reply(SOCKET s) {
    char hdr[4];
    if (!recvn(s, hdr, 4) || hdr[0] != 0x05 || hdr[1] != 0x00) return false;
    int rest = 0;
    if (static_cast<uint8_t>(hdr[3]) == 0x01) rest = 6;
    else if (static_cast<uint8_t>(hdr[3]) == 0x04) rest = 18;
    else if (static_cast<uint8_t>(hdr[3]) == 0x03) {
        char ln = 0;
        if (!recvn(s, &ln, 1)) return false;
        rest = static_cast<unsigned char>(ln) + 2;
    } else {
        return false;
    }
    if (rest <= 0) return true;
    std::vector<char> skip(static_cast<size_t>(rest));
    return recvn(s, skip.data(), rest);
}

SOCKET socks5_handshake(int timeout_sec) {
    SOCKET s = tcp_connect_timeout(g_cfg.socks5_host, g_cfg.socks5_port, timeout_sec);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    const char greet[] = {0x05, 0x01, 0x00};
    if (!send_all(s, reinterpret_cast<const uint8_t*>(greet), 3)) {
        unregister_own_socket(s);
        closesocket(s);
        return INVALID_SOCKET;
    }
    char greply[2];
    if (!recvn(s, greply, 2) || greply[0] != 0x05 || greply[1] != 0x00) {
        unregister_own_socket(s);
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

SOCKET socks5_connect_host(const std::string& host, uint16_t dst_port_host, int timeout_sec) {
    if (host.empty() || host.size() > 255) return INVALID_SOCKET;
    SOCKET s = socks5_handshake(timeout_sec);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    std::vector<uint8_t> req(5 + host.size() + 2);
    req[0] = 0x05;
    req[1] = 0x01;
    req[2] = 0x00;
    req[3] = 0x03;
    req[4] = static_cast<uint8_t>(host.size());
    std::memcpy(req.data() + 5, host.data(), host.size());
    req[5 + host.size()] = static_cast<uint8_t>(dst_port_host >> 8);
    req[5 + host.size() + 1] = static_cast<uint8_t>(dst_port_host);
    if (!send_all(s, req.data(), req.size()) || !socks5_read_connect_reply(s)) {
        unregister_own_socket(s);
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

struct Seg {
    uint32_t seq = 0;
    uint8_t flags = 0;
    std::vector<uint8_t> data;
    int sends = 0;
    std::chrono::steady_clock::time_point last_send{};
};
struct OooSeg {
    uint32_t seq = 0;
    std::vector<uint8_t> data;
    bool fin = false;
};
uint32_t seg_end(const Seg& s) {
    uint32_t n = s.seq + static_cast<uint32_t>(s.data.size());
    if (s.flags & pkt::TCP_SYN) ++n;
    if (s.flags & pkt::TCP_FIN) ++n;
    return n;
}

struct FlowKey {
    uint32_t src = 0, dst = 0;
    uint16_t sport = 0, dport = 0;
    bool operator==(const FlowKey& o) const {
        return src == o.src && dst == o.dst && sport == o.sport && dport == o.dport;
    }
};
struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const {
        return (static_cast<size_t>(k.src) * 1315423911u) ^ k.dst ^
               (static_cast<size_t>(k.sport) << 16) ^ k.dport;
    }
};

enum class FlowState { SynSent, Open, Closing, Dead };
struct Flow {
    FlowKey key;
    HANDLE divert = nullptr;
    DivertAddr addr{};
    std::mutex mu;
    std::condition_variable cv;
    std::atomic<bool> alive{true};
    FlowState state = FlowState::SynSent;
    uint32_t isn = 0, client_isn = 0, rcv_nxt = 0, snd_una = 0, snd_nxt = 0;
    uint16_t peer_wnd = 65535, peer_mss = 1460;
    std::vector<Seg> segs;
    std::vector<OooSeg> ooo;
    size_t ooo_bytes = 0;
    std::vector<uint8_t> to_socks;
    bool fin_from_client = false, fin_queued = false, local_closed = false;
    SOCKET sock = INVALID_SOCKET;
    std::chrono::steady_clock::time_point last_rx = std::chrono::steady_clock::now();
};

std::mutex g_map_mu;
std::unordered_map<FlowKey, std::shared_ptr<Flow>, FlowKeyHash> g_flows;

size_t unacked_bytes(const Flow& f) {
    size_t n = 0;
    for (const auto& s : f.segs) n += s.data.size();
    return n;
}
uint16_t recv_window(const Flow& f) {
    const size_t cap = 256 * 1024;
    if (f.to_socks.size() >= cap) return 0;
    const size_t left = cap - f.to_socks.size();
    return static_cast<uint16_t>(left > 65535 ? 65535 : left);
}
uint32_t tx_seq(const Flow& f) {
    for (const auto& s : f.segs) {
        if (s.sends == 0 && pkt::seq_diff(seg_end(s), f.snd_una) > 0) return s.seq;
    }
    return f.snd_nxt;
}
bool seg_fits(const Flow& f, const Seg& s) {
    if (s.flags & pkt::TCP_SYN) return true;
    const int32_t need = pkt::seq_diff(seg_end(s), f.snd_una);
    if (need <= 0) return true;
    return f.peer_wnd > 0 && static_cast<uint32_t>(need) <= f.peer_wnd;
}

void transmit_locked(Flow& f, Seg& s) {
    uint8_t mss_opt[4] = {2, 4, 0x05, 0xB4};
    const bool syn = (s.flags & pkt::TCP_SYN) != 0;
    auto packet = pkt::build_tcp(
        f.key.dst, f.key.src, f.key.dport, f.key.sport,
        s.seq, f.rcv_nxt, s.flags, recv_window(f),
        s.data.empty() ? nullptr : s.data.data(), s.data.size(),
        g_ip_id++,
        syn ? mss_opt : nullptr, syn ? sizeof(mss_opt) : 0);
    inject_inbound(f.divert, f.addr, packet);
    s.sends += 1;
    s.last_send = std::chrono::steady_clock::now();
}
void flush_send_locked(Flow& f) {
    for (auto& s : f.segs) {
        if (pkt::seq_diff(seg_end(s), f.snd_una) <= 0) continue;
        if (s.sends > 0) continue;
        if (!seg_fits(f, s)) break;
        transmit_locked(f, s);
    }
}
void enqueue_locked(Flow& f, uint8_t flags, const uint8_t* data, size_t len) {
    if (len == 0) {
        Seg s;
        s.seq = f.snd_nxt;
        s.flags = flags;
        uint32_t step = 0;
        if (flags & pkt::TCP_SYN) ++step;
        if (flags & pkt::TCP_FIN) ++step;
        f.snd_nxt += step;
        f.segs.push_back(std::move(s));
        flush_send_locked(f);
        return;
    }
    size_t mss = static_cast<size_t>(std::min(g_cfg.mss, static_cast<int>(f.peer_mss)));
    if (mss < 200) mss = 200;
    size_t off = 0;
    while (off < len) {
        const size_t n = std::min(len - off, mss);
        const bool last = (off + n == len);
        uint8_t fl = pkt::TCP_ACK | pkt::TCP_PSH;
        if (last && (flags & pkt::TCP_FIN)) fl |= pkt::TCP_FIN;
        Seg s;
        s.seq = f.snd_nxt;
        s.flags = fl;
        s.data.assign(data + off, data + off + n);
        f.snd_nxt += static_cast<uint32_t>(n);
        if (fl & pkt::TCP_FIN) f.snd_nxt += 1;
        f.segs.push_back(std::move(s));
        off += n;
    }
    flush_send_locked(f);
}
void send_ack_locked(Flow& f) {
    auto packet = pkt::build_tcp(
        f.key.dst, f.key.src, f.key.dport, f.key.sport,
        tx_seq(f), f.rcv_nxt, pkt::TCP_ACK, recv_window(f),
        nullptr, 0, g_ip_id++);
    inject_inbound(f.divert, f.addr, packet);
}
void send_rst_locked(Flow& f) {
    auto packet = pkt::build_tcp(
        f.key.dst, f.key.src, f.key.dport, f.key.sport,
        tx_seq(f), f.rcv_nxt, pkt::TCP_RST | pkt::TCP_ACK, 0,
        nullptr, 0, g_ip_id++);
    inject_inbound(f.divert, f.addr, packet);
    f.state = FlowState::Dead;
    f.alive = false;
}
void ack_update_locked(Flow& f, uint32_t ack) {
    if (pkt::seq_diff(ack, f.snd_nxt) > 0) return;
    if (pkt::seq_diff(ack, f.snd_una) <= 0) return;
    f.snd_una = ack;
    auto it = f.segs.begin();
    while (it != f.segs.end()) {
        if (pkt::seq_diff(ack, seg_end(*it)) >= 0) it = f.segs.erase(it);
        else ++it;
    }
    f.cv.notify_all();
}
bool accept_payload_locked(Flow& f, const uint8_t* data, size_t len, bool fin) {
    if (f.to_socks.size() + len > 256 * 1024) return false;
    if (len > 0) {
        f.to_socks.insert(f.to_socks.end(), data, data + len);
        f.rcv_nxt += static_cast<uint32_t>(len);
        g_rx += len;
    }
    if (fin && !f.fin_from_client) {
        f.rcv_nxt += 1;
        f.fin_from_client = true;
    }
    return true;
}
void take_ooo_locked(Flow& f) {
    bool progressed = true;
    while (progressed) {
        progressed = false;
        for (size_t i = 0; i < f.ooo.size();) {
            OooSeg& o = f.ooo[i];
            const int32_t d = pkt::seq_diff(o.seq, f.rcv_nxt);
            if (d > 0) {
                ++i;
                continue;
            }
            const size_t skip = static_cast<size_t>(-d);
            if (skip > o.data.size()) {
                f.ooo_bytes -= o.data.size();
                f.ooo.erase(f.ooo.begin() + static_cast<std::ptrdiff_t>(i));
                progressed = true;
                continue;
            }
            const size_t n = o.data.size() - skip;
            const bool fin = o.fin && (skip + n == o.data.size());
            if (!accept_payload_locked(f, n ? o.data.data() + skip : nullptr, n, fin)) return;
            f.ooo_bytes -= o.data.size();
            f.ooo.erase(f.ooo.begin() + static_cast<std::ptrdiff_t>(i));
            progressed = true;
        }
    }
}

void close_flow_socket(const std::shared_ptr<Flow>& f) {
    f->alive = false;
    f->cv.notify_all();
    if (f->sock != INVALID_SOCKET) {
        unregister_own_socket(f->sock);
        shutdown(f->sock, SD_BOTH);
        closesocket(f->sock);
        f->sock = INVALID_SOCKET;
    }
}
void erase_flow(const std::shared_ptr<Flow>& f) {
    std::lock_guard<std::mutex> lock(g_map_mu);
    auto it = g_flows.find(f->key);
    if (it != g_flows.end() && it->second == f) g_flows.erase(it);
}

void socks_worker(std::shared_ptr<Flow> f) {
    const bool fake = is_fake_ip(f->key.dst);
    const std::string learned = dns_lookup_name(f->key.dst);

    auto fail_rst = [&](const std::string& why) {
        ++g_socks_fail;
        log_line("[-] " + why + " " + ip_to_string(f->key.src) + ":" +
                 std::to_string(f->key.sport) + " -> " + ip_to_string(f->key.dst) + ":" +
                 std::to_string(f->key.dport));
        {
            std::lock_guard<std::mutex> lock(f->mu);
            if (f->alive) send_rst_locked(*f);
        }
        erase_flow(f);
    };

    if (fake && learned.empty()) {
        ++g_fakeip_miss;
        fail_rst("unknown fake-IP (flush DNS cache)");
        return;
    }
    if (!fake && !is_private_ip(f->key.dst)) {
        ++g_realip_reject;
        fail_rst("reject real-IP (use system DNS; disable DoH/Private DNS)");
        return;
    }

    const std::string dst_label =
        !learned.empty() ? (learned + "/" + ip_to_string(f->key.dst)) : ip_to_string(f->key.dst);

    SOCKET s = INVALID_SOCKET;
    if (!learned.empty()) {
        s = socks5_connect_host(learned, f->key.dport, 15);
    } else {
        fail_rst("no domain for flow");
        return;
    }

    {
        std::lock_guard<std::mutex> lock(f->mu);
        if (!f->alive) {
            if (s != INVALID_SOCKET) {
                unregister_own_socket(s);
                closesocket(s);
            }
            erase_flow(f);
            return;
        }
        if (s == INVALID_SOCKET) {
            ++g_socks_fail;
            log_line("[-] SOCKS5 CONNECT failed " + ip_to_string(f->key.src) + ":" +
                     std::to_string(f->key.sport) + " -> " + dst_label + ":" +
                     std::to_string(f->key.dport) +
                     " (is multilink/smartlink running on " + g_cfg.socks5_host + ":" +
                     std::to_string(g_cfg.socks5_port) + "?)");
            send_rst_locked(*f);
            erase_flow(f);
            return;
        }
        f->sock = s;
        f->state = FlowState::Open;
        set_timeouts(s, std::max(30, g_cfg.idle_timeout_sec));
    }
    ++g_connect_ok;
    if (g_cfg.log_connections) {
        log_line("[+] TCP " + ip_to_string(f->key.src) + ":" + std::to_string(f->key.sport) +
                 " -> " + dst_label + ":" + std::to_string(f->key.dport) + " via SOCKS5");
    }

    std::thread downstream([f, s] {
        std::vector<uint8_t> buf(16384);
        while (f->alive) {
            const int n = recv(s, reinterpret_cast<char*>(buf.data()), static_cast<int>(buf.size()), 0);
            if (n == 0) break;
            if (n < 0) {
                const int err = WSAGetLastError();
                if (err == WSAETIMEDOUT || err == WSAEWOULDBLOCK) {
                    if (!f->alive) break;
                    continue;
                }
                break;
            }
            std::unique_lock<std::mutex> lock(f->mu);
            while (f->alive && unacked_bytes(*f) > 64 * 1024) {
                lock.unlock();
                std::this_thread::sleep_for(std::chrono::milliseconds(10));
                lock.lock();
            }
            if (!f->alive) break;
            enqueue_locked(*f, pkt::TCP_ACK, buf.data(), static_cast<size_t>(n));
            g_tx += static_cast<uint64_t>(n);
        }
        std::lock_guard<std::mutex> lock(f->mu);
        if (f->alive && !f->fin_queued) {
            f->fin_queued = true;
            f->state = FlowState::Closing;
            enqueue_locked(*f, pkt::TCP_FIN | pkt::TCP_ACK, nullptr, 0);
        }
        f->local_closed = true;
        f->cv.notify_all();
    });

    while (f->alive) {
        std::vector<uint8_t> chunk;
        bool fin = false;
        {
            std::unique_lock<std::mutex> lock(f->mu);
            f->cv.wait_for(lock, std::chrono::milliseconds(200), [&] {
                return !f->alive || !f->to_socks.empty() || f->fin_from_client || f->local_closed;
            });
            if (!f->alive && f->to_socks.empty()) break;
            if (f->local_closed && f->to_socks.empty() && !f->fin_from_client) break;
            chunk.swap(f->to_socks);
            fin = f->fin_from_client;
        }
        if (!chunk.empty() && !send_all(s, chunk.data(), chunk.size())) {
            shutdown(s, SD_BOTH);
            break;
        }
        if (fin) {
            shutdown(s, SD_SEND);
            break;
        }
    }
    downstream.join();
    if (s != INVALID_SOCKET) {
        unregister_own_socket(s);
        shutdown(s, SD_BOTH);
        closesocket(s);
    }
    f->sock = INVALID_SOCKET;
    {
        std::unique_lock<std::mutex> lock(f->mu);
        f->cv.wait_for(lock, std::chrono::seconds(20), [&] {
            flush_send_locked(*f);
            return !f->alive || (f->fin_queued && pkt::seq_diff(f->snd_nxt, f->snd_una) <= 0);
        });
        f->alive = false;
        f->cv.notify_all();
    }
    erase_flow(f);
}

void handle_dns(HANDLE divert, DivertAddr addr, uint32_t src, uint16_t sport,
                uint32_t dst, std::vector<uint8_t> query) {
    struct Guard {
        ~Guard() { --g_dns_inflight; }
    } guard;

    const std::string qname = dns_qname(query.data(), query.size());
    const uint16_t qtype = dns_qtype(query.data(), query.size());

    auto inject_dns = [&](const std::vector<uint8_t>& resp, const std::string& note) {
        if (resp.empty()) {
            ++g_dns_fail;
            return;
        }
        auto packet = pkt::build_udp(dst, src, 53, sport, resp.data(), resp.size(), g_ip_id++);
        inject_inbound(divert, addr, packet);
        ++g_dns_ok;
        log_line("[+] DNS q=" + qname + " " + note);
    };

    if (qtype != 1) {
        inject_dns(dns_reply_nodata(query), "type" + std::to_string(qtype) + "->NODATA");
        return;
    }
    if (qname.empty() || qname == "?") {
        ++g_dns_fail;
        return;
    }

    const uint32_t fake = fake_ip_alloc(qname);
    if (!fake) {
        ++g_dns_fail;
        log_line("[-] DNS fake-IP pool exhausted q=" + qname);
        return;
    }
    inject_dns(dns_reply_a(query, fake), "fake-IP " + ip_to_string(fake));
}

void handle_tcp(HANDLE divert, const DivertAddr& addr, const pkt::Ipv4L4& v) {
    FlowKey key{v.src_net, v.dst_net, v.sport, v.dport};
    const bool syn = (v.tcp_flags & pkt::TCP_SYN) != 0;
    const bool ackf = (v.tcp_flags & pkt::TCP_ACK) != 0;
    const bool rst = (v.tcp_flags & pkt::TCP_RST) != 0;
    const bool fin = (v.tcp_flags & pkt::TCP_FIN) != 0;

    if (rst) {
        std::shared_ptr<Flow> flow;
        {
            std::lock_guard<std::mutex> lock(g_map_mu);
            auto it = g_flows.find(key);
            if (it != g_flows.end()) flow = it->second;
        }
        if (flow) {
            close_flow_socket(flow);
            erase_flow(flow);
        }
        return;
    }

    if (syn && !ackf) {
        std::shared_ptr<Flow> created;
        {
            std::lock_guard<std::mutex> lock(g_map_mu);
            auto it = g_flows.find(key);
            if (it != g_flows.end() && it->second->alive) return;
            if (it != g_flows.end()) g_flows.erase(it);
            if (static_cast<int>(g_flows.size()) >= g_cfg.max_connections) return;
            created = std::make_shared<Flow>();
            created->key = key;
            created->divert = divert;
            created->addr = addr;
            created->isn = static_cast<uint32_t>(GetTickCount() ^ (v.src_net + v.sport * 17u));
            created->client_isn = v.seq;
            created->rcv_nxt = v.seq + 1;
            created->snd_una = created->isn;
            created->snd_nxt = created->isn;
            created->peer_wnd = v.window ? v.window : 65535;
            if (v.mss >= 200 && v.mss < 2000) created->peer_mss = v.mss;
            g_flows.emplace(key, created);
        }
        {
            std::lock_guard<std::mutex> lock(created->mu);
            enqueue_locked(*created, pkt::TCP_SYN | pkt::TCP_ACK, nullptr, 0);
        }
        std::thread(socks_worker, created).detach();
        return;
    }

    std::shared_ptr<Flow> flow;
    {
        std::lock_guard<std::mutex> lock(g_map_mu);
        auto it = g_flows.find(key);
        if (it != g_flows.end()) flow = it->second;
    }
    if (!flow) return;

    std::lock_guard<std::mutex> lock(flow->mu);
    if (!flow->alive) return;
    flow->addr = addr;
    flow->last_rx = std::chrono::steady_clock::now();
    if (ackf) {
        ack_update_locked(*flow, v.ack);
        flow->peer_wnd = v.window;
        flush_send_locked(*flow);
    }
    if (v.payload_len == 0 && !fin) {
        if (ackf) flow->cv.notify_all();
        return;
    }

    const uint8_t* payload = v.payload;
    size_t plen = v.payload_len;
    const int32_t diff = pkt::seq_diff(v.seq, flow->rcv_nxt);
    if (diff > 0) {
        if (plen > 0 && diff < 256 * 1024 && flow->ooo_bytes + plen <= 64 * 1024) {
            OooSeg o;
            o.seq = v.seq;
            o.data.assign(payload, payload + plen);
            o.fin = fin;
            flow->ooo.push_back(std::move(o));
            flow->ooo_bytes += plen;
        }
        send_ack_locked(*flow);
        return;
    }
    if (diff < 0) {
        const uint32_t already = static_cast<uint32_t>(-diff);
        if (already >= plen) {
            if (fin && !flow->fin_from_client) accept_payload_locked(*flow, nullptr, 0, true);
            send_ack_locked(*flow);
            flow->cv.notify_all();
            return;
        }
        payload += already;
        plen -= already;
    }
    if (accept_payload_locked(*flow, plen ? payload : nullptr, plen, fin && !flow->fin_from_client)) {
        take_ooo_locked(*flow);
    }
    send_ack_locked(*flow);
    flow->cv.notify_all();
}

void on_packet(HANDLE divert, DivertAddr addr, const uint8_t* packet, UINT len) {
    ++g_captured;
    if (len < 1) return;
    const uint8_t ver = static_cast<uint8_t>(packet[0] >> 4);
    if (ver == 6) {
        ++g_drop_ipv6;
        return;
    }

    auto v = pkt::parse_ipv4(packet, len);
    if (!v.ok || v.fragmented) {
        reinject(divert, addr, packet, len);
        ++g_passthru;
        return;
    }
    if (is_own_sport(v.sport)) {
        reinject(divert, addr, packet, len);
        ++g_passthru;
        return;
    }

    if (v.proto == 17 && v.dport == 53) {
        if (v.payload_len == 0 || v.payload_len > 1500) return;
        if (g_dns_inflight.load() >= g_cfg.max_dns_inflight) return;
        ++g_dns_inflight;
        std::vector<uint8_t> q(v.payload, v.payload + v.payload_len);
        std::thread(handle_dns, divert, addr, v.src_net, v.sport, v.dst_net, std::move(q)).detach();
        return;
    }
    // Drop browser QUIC/DoT so they fall back to TCP→fake-IP→SOCKS.
    // smartlink/multilink uplink is TCP-only, so this does not affect them.
    if (v.proto == 17 && (v.dport == 443 || v.dport == 853)) {
        ++g_drop_quic;
        return;
    }
    if (v.proto == 6) {
        // Only terminate TCP to fake-IP. Real destinations (multilink/smartlink
        // DIRECT and Vortex uplinks) must pass through untouched.
        if (!is_fake_ip(v.dst_net)) {
            reinject(divert, addr, packet, len);
            ++g_passthru;
            return;
        }
        handle_tcp(divert, addr, v);
        return;
    }
    reinject(divert, addr, packet, len);
    ++g_passthru;
}

void recv_loop(HANDLE h) {
    std::vector<uint8_t> buf(0xFFFF);
    DivertAddr addr{};
    while (g_run) {
        UINT recv_len = 0;
        if (!g_recv(h, buf.data(), static_cast<UINT>(buf.size()), &recv_len, &addr)) {
            if (!g_run) break;
            continue;
        }
        on_packet(h, addr, buf.data(), recv_len);
    }
}

void retransmit_loop() {
    while (g_run) {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        const auto now = std::chrono::steady_clock::now();
        std::vector<std::shared_ptr<Flow>> snap;
        {
            std::lock_guard<std::mutex> lock(g_map_mu);
            for (auto& kv : g_flows) snap.push_back(kv.second);
        }
        for (auto& f : snap) {
            std::lock_guard<std::mutex> lock(f->mu);
            if (!f->alive) continue;
            if (now - f->last_rx > std::chrono::seconds(g_cfg.idle_timeout_sec)) {
                send_rst_locked(*f);
                continue;
            }
            for (auto& s : f->segs) {
                if (pkt::seq_diff(seg_end(s), f->snd_una) <= 0) continue;
                if (s.sends == 0) continue;
                if (now - s.last_send < std::chrono::milliseconds(400)) continue;
                if (s.sends >= 8) {
                    send_rst_locked(*f);
                    break;
                }
                transmit_locked(*f, s);
            }
            flush_send_locked(*f);
        }
    }
}

BOOL WINAPI on_console(DWORD) {
    g_run = false;
    return TRUE;
}

} // namespace

int main(int argc, char** argv) {
    std::string config_path = "config/activate_net.json";
    if (argc >= 2) config_path = argv[1];

    if (!net_init()) {
        std::cerr << "[-] WSAStartup failed\n";
        return 1;
    }
    SetConsoleCtrlHandler(on_console, TRUE);

    try {
        g_cfg = ActivateNetConfig::load(config_path);
    } catch (const std::exception& e) {
        std::cerr << "[-] " << e.what() << "\n";
        net_cleanup();
        return 1;
    }

    if (!load_windivert()) {
        std::cerr << "[-] WinDivert.dll not found next to activate_net.exe\n";
        net_cleanup();
        return 1;
    }

    // Critical: do NOT capture all TCP — that steals multilink/smartlink outbound
    // (Vortex uplinks + DIRECT). Only hijack DNS, QUIC/DoT, IPv6, and TCP to fake-IP.
    const std::string filter =
        "outbound and not loopback and not impostor and ("
        "ipv6 or "
        "(ip and udp.DstPort == 53) or "
        "(ip and udp.DstPort == 443) or "
        "(ip and udp.DstPort == 853) or "
        "(ip and tcp and ip.DstAddr >= 198.18.0.0 and ip.DstAddr <= 198.19.255.255)"
        ")";
    HANDLE h = g_open(filter.c_str(), WINDIVERT_LAYER_NETWORK, WINDIVERT_PRIORITY_HIGHEST, 0);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        std::cerr << "[-] WinDivertOpen failed err=" << err
                  << (err == 5 ? " (need Administrator)" : "") << "\n";
        net_cleanup();
        return 1;
    }
    if (g_set_param) {
        g_set_param(h, 0, 8192);
        g_set_param(h, 1, 8000);
        g_set_param(h, 2, 16ull << 20);
    }

    log_line("[*] ActivateNet — local apps → SOCKS5 (multilink/smartlink)");
    log_line("[*] config " + config_path);
    log_line("[*] upstream SOCKS5 " + g_cfg.socks5_host + ":" + std::to_string(g_cfg.socks5_port));
    log_line("[*] filter: " + filter);
    log_line("[*] DNS: fake-IP 198.18.0.0/15; TCP to fake-IP → SOCKS5 CONNECT(domain)");
    log_line("[*] TCP to real IPs NOT captured (smartlink/multilink uplink+DIRECT pass)");
    log_line("[*] drop UDP/443(QUIC) UDP/853(DoT) and all IPv6");
    log_line("[*] start multilink.exe or smartlink.exe BEFORE this process");

    std::thread retx(retransmit_loop);
    std::thread reader(recv_loop, h);

    while (g_run) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        if (!g_run) break;
        size_t flows = 0;
        {
            std::lock_guard<std::mutex> lock(g_map_mu);
            flows = g_flows.size();
        }
        log_line("[*] captured=" + std::to_string(g_captured.load()) +
                 " flows=" + std::to_string(flows) +
                 " dns_ok=" + std::to_string(g_dns_ok.load()) +
                 " connect_ok=" + std::to_string(g_connect_ok.load()) +
                 " socks_fail=" + std::to_string(g_socks_fail.load()) +
                 " fake_miss=" + std::to_string(g_fakeip_miss.load()) +
                 " realip_rej=" + std::to_string(g_realip_reject.load()) +
                 " drop_quic=" + std::to_string(g_drop_quic.load()) +
                 " drop_v6=" + std::to_string(g_drop_ipv6.load()) +
                 " passthru=" + std::to_string(g_passthru.load()) +
                 " rx=" + std::to_string(g_rx.load()) +
                 " tx=" + std::to_string(g_tx.load()));
    }

    if (g_shutdown) g_shutdown(h, 0x3);
    reader.join();
    retx.join();
    {
        std::lock_guard<std::mutex> lock(g_map_mu);
        for (auto& kv : g_flows) close_flow_socket(kv.second);
        g_flows.clear();
    }
    g_close(h);
    net_cleanup();
    log_line("[*] ActivateNet stopped");
    return 0;
}
