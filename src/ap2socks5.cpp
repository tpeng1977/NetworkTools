// AP2Socks5: transparent proxy for a Windows Wi-Fi access point.
//
// Goal: the OS must not process AP data-plane traffic. WinDivert claims the AP
// NIC: every inbound IPv4/IPv6 packet is diverted to us; outbound packets from
// the Windows stack (non-impostor) are DROPped. We only reinject DHCP so the
// built-in hotspot can still lease 192.168.137.x. TCP goes through SOCKS5;
// DNS(UDP/53) becomes DNS-over-TCP via SOCKS5; replies are injected as
// impostor packets. ARP stays with Windows (L2 only).
//
// Remote DNS (browser-style, Clash fake-IP):
//   UDP/53 A queries are answered with a synthetic 198.18.0.0/15 address.
//   Real resolution is never done for the phone — TCP SOCKS5 CONNECT uses
//   ATYP=DOMAIN so the upstream (multilink) resolves exactly like a browser
//   with socks_remote_dns. AAAA/HTTPS/other -> NODATA. Non-fake IPs (stale
//   cache / DoH) still fall back to IP CONNECT.
//
// Requires Administrator and WinDivert 2.2 (WinDivert.dll + WinDivert64.sys
// next to this executable).

#ifndef _WIN32
#error AP2Socks5 is Windows-only (WinDivert).
#endif

#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>
#include <netioapi.h>

#include "config.hpp"
#include "packet_build.hpp"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace {

constexpr int WINDIVERT_LAYER_NETWORK = 0;
constexpr int WINDIVERT_LAYER_NETWORK_FORWARD = 1;
constexpr int16_t WINDIVERT_PRIORITY_HIGHEST = 30000;
constexpr uint64_t WINDIVERT_FLAG_DROP = 0x2;
constexpr uint64_t WINDIVERT_FLAG_SEND_ONLY = 0x8;

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

inline void addr_set_loopback(DivertAddr& a, bool on) {
    if (on) a.bits0 |= (1u << 18);
    else a.bits0 &= ~(1u << 18);
}

inline void addr_clear_checksum_bits(DivertAddr& a) {
    a.bits0 &= ~((1u << 21) | (1u << 22) | (1u << 23));
}

inline void addr_set_ifindex(DivertAddr& a, uint32_t ifindex) {
    std::memcpy(a.reserved3, &ifindex, sizeof(ifindex));
    uint32_t sub = 0;
    std::memcpy(a.reserved3 + 4, &sub, sizeof(sub));
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

uint32_t string_to_ip_net(const std::string& s) {
    in_addr a{};
    if (inet_pton(AF_INET, s.c_str(), &a) != 1) return 0;
    return a.s_addr;
}

std::string wide_to_utf8(const wchar_t* w) {
    if (!w || !*w) return {};
    const int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 1) return {};
    std::string out(static_cast<size_t>(n - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), n, nullptr, nullptr);
    return out;
}

struct Settings {
    std::string ap_adapter = "auto";
    uint32_t ap_ifindex = 0;
    std::string ap_gateway = "192.168.137.1";
    int ap_prefix = 24;
    std::string socks5_host = "127.0.0.1";
    int socks5_port = 11080;
    std::string dns_server = "1.1.1.1";
    int dns_port = 53;
    std::string capture_layer = "forward";
    int mss = 1200;
    int idle_timeout_sec = 180;
    int max_connections = 1024;
    int max_dns_inflight = 64;
    uint32_t gw_net = 0;
    uint32_t mask_host = 0;
    uint32_t first_host = 0;
    uint32_t last_host = 0;
    uint32_t dns_net = 0;
};

Settings g_cfg;
std::atomic<int> g_dns_inflight{0};
std::atomic<uint16_t> g_ip_id{1};
std::atomic<uint64_t> g_tx_bytes{0};
std::atomic<uint64_t> g_rx_bytes{0};
std::atomic<uint64_t> g_captured{0};
std::atomic<uint64_t> g_send_fail{0};
std::atomic<uint64_t> g_dns_ok{0};
std::atomic<uint64_t> g_dns_fail{0};
std::atomic<uint64_t> g_socks_fail{0};
std::atomic<uint64_t> g_fakeip_dns{0};
std::atomic<uint64_t> g_fakeip_miss{0};
std::atomic<uint64_t> g_aaaa_stripped{0};
std::atomic<uint64_t> g_dhcp_pass{0};
std::atomic<uint64_t> g_swallowed{0};
std::atomic<uint64_t> g_domain_connect{0};
std::atomic<uint64_t> g_ip_connect{0};
std::atomic<uint64_t> g_realip_reject{0};
HANDLE g_inject = nullptr;

// Fake-IP pool 198.18.0.0/15 — phone routes here; we map back to qname.
constexpr uint32_t kFakeIpHostMin = 0xC6120001u; // 198.18.0.1
constexpr uint32_t kFakeIpHostMax = 0xC613FFFEu; // 198.19.255.254
constexpr uint32_t kFakeDnsTtl = 300;

struct DnsNameEntry {
    std::string name;
    std::chrono::steady_clock::time_point expire{};
};
std::mutex g_dns_name_mu;
std::unordered_map<uint32_t, DnsNameEntry> g_ip_to_name;   // fake IP (net) -> qname
std::unordered_map<std::string, uint32_t> g_name_to_fake;  // qname -> fake IP (net)
uint32_t g_fake_next_host = kFakeIpHostMin;

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
    uint32_t src = 0;
    uint32_t dst = 0;
    uint16_t sport = 0;
    uint16_t dport = 0;
    bool operator==(const FlowKey& o) const {
        return src == o.src && dst == o.dst && sport == o.sport && dport == o.dport;
    }
};

struct FlowKeyHash {
    size_t operator()(const FlowKey& k) const {
        uint64_t x = (static_cast<uint64_t>(k.src) << 32) ^ k.dst;
        x ^= (static_cast<uint64_t>(k.sport) << 16) ^ k.dport;
        x *= 0x9E3779B97F4A7C15ULL;
        return static_cast<size_t>(x ^ (x >> 32));
    }
};

enum class FlowState { Handshake, Open, Closing, Dead };

struct Flow {
    FlowKey key;
    FlowState state = FlowState::Handshake;
    HANDLE divert = nullptr;
    DivertAddr addr{};
    SOCKET sock = INVALID_SOCKET;
    uint32_t isn = 0;
    uint32_t client_isn = 0;
    uint32_t snd_una = 0;
    uint32_t snd_nxt = 0;
    uint32_t rcv_nxt = 0;
    uint32_t peer_wnd = 65535;
    uint16_t peer_mss = 1200;
    std::vector<Seg> segs;
    std::vector<OooSeg> ooo;
    size_t ooo_bytes = 0;
    std::vector<uint8_t> to_socks;
    bool fin_from_client = false;
    bool fin_queued = false;
    bool local_closed = false;
    std::atomic<bool> alive{true};
    std::mutex mu;
    std::condition_variable cv;
    std::chrono::steady_clock::time_point last_rx{std::chrono::steady_clock::now()};
};

std::mutex g_map_mu;
std::unordered_map<FlowKey, std::shared_ptr<Flow>, FlowKeyHash> g_flows;

bool load_windivert() {
    wchar_t path[MAX_PATH];
    GetModuleFileNameW(nullptr, path, MAX_PATH);
    std::wstring dir = path;
    const auto slash = dir.find_last_of(L"\\/");
    if (slash != std::wstring::npos) dir.resize(slash);
    SetDllDirectoryW(dir.c_str());
    const std::wstring dll = dir + L"\\WinDivert.dll";
    HMODULE mod = LoadLibraryW(dll.c_str());
    if (!mod) mod = LoadLibraryA("WinDivert.dll");
    if (!mod) return false;
    auto bind_fn = [](auto& dst, const char* name, HMODULE mod) {
        FARPROC raw = GetProcAddress(mod, name);
        std::memcpy(&dst, &raw, sizeof(dst));
    };
    bind_fn(g_open, "WinDivertOpen", mod);
    bind_fn(g_recv, "WinDivertRecv", mod);
    bind_fn(g_send, "WinDivertSend", mod);
    bind_fn(g_close, "WinDivertClose", mod);
    bind_fn(g_shutdown, "WinDivertShutdown", mod);
    bind_fn(g_set_param, "WinDivertSetParam", mod);
    bind_fn(g_calc, "WinDivertHelperCalcChecksums", mod);
    return g_open && g_recv && g_send && g_close;
}

bool dst_in_ap_subnet(const uint8_t* packet, size_t len) {
    if (len < 20 || g_cfg.gw_net == 0) return false;
    uint32_t dst_net = 0;
    std::memcpy(&dst_net, packet + 16, 4);
    const uint32_t dst_h = ntohl(dst_net);
    const uint32_t gw_h = ntohl(g_cfg.gw_net);
    return (dst_h & g_cfg.mask_host) == (gw_h & g_cfg.mask_host);
}

void inject(HANDLE h, DivertAddr addr, std::vector<uint8_t>& packet, bool tcp) {
    // Replies are injected on the NETWORK layer as outbound impostor packets.
    // Pin IfIdx to the AP NIC so UDP DNS answers reach hotspot clients
    // (otherwise the stack may send them out WLAN/VPN and the phone never sees them).
    DivertAddr out{};
    addr_set_outbound(out, true);
    addr_set_impostor(out, true);
    if (g_cfg.ap_ifindex != 0 && dst_in_ap_subnet(packet.data(), packet.size())) {
        addr_set_ifindex(out, g_cfg.ap_ifindex);
    }
    addr_clear_checksum_bits(out);
    if (g_calc) {
        g_calc(packet.data(), static_cast<UINT>(packet.size()), &out, 0);
    }
    HANDLE dest = g_inject ? g_inject : h;
    UINT sent = 0;
    if (!g_send(dest, packet.data(), static_cast<UINT>(packet.size()), &sent, &out)) {
        const uint64_t n = ++g_send_fail;
        if (n <= 8) {
            log_line("[-] WinDivertSend failed (" + std::to_string(GetLastError()) + ")");
        }
        return;
    }
    (void)tcp;
    (void)addr;
    g_tx_bytes += packet.size();
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
    return name;
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

uint16_t dns_qtype(const uint8_t* msg, size_t len) {
    if (len < 12) return 0;
    size_t off = dns_skip_name(msg, len, 12);
    if (off + 4 > len) return 0;
    return static_cast<uint16_t>((msg[off] << 8) | msg[off + 1]);
}

std::string to_lower_host(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

bool is_fake_ip(uint32_t net_order) {
    const uint32_t h = ntohl(net_order);
    return (h & 0xFFFE0000u) == 0xC6120000u; // 198.18.0.0/15
}

bool is_private_ip(uint32_t net_order) {
    const uint32_t h = ntohl(net_order);
    if ((h & 0xFF000000u) == 0x0A000000u) return true;      // 10.0.0.0/8
    if ((h & 0xFFF00000u) == 0xAC100000u) return true;      // 172.16.0.0/12
    if ((h & 0xFFFF0000u) == 0xC0A80000u) return true;      // 192.168.0.0/16
    if ((h & 0xFF000000u) == 0x7F000000u) return true;      // 127.0.0.0/8
    return false;
}

std::string dns_lookup_name(uint32_t net_order) {
    std::lock_guard<std::mutex> lock(g_dns_name_mu);
    auto it = g_ip_to_name.find(net_order);
    if (it == g_ip_to_name.end()) return {};
    // Fake-IP bindings stay for the process lifetime (phone may cache longer
    // than DNS TTL). Refresh expire on lookup.
    it->second.expire = std::chrono::steady_clock::now() + std::chrono::seconds(kFakeDnsTtl);
    return it->second.name;
}

constexpr const char* kFakeIpCachePath = "ap2socks5.fakeip.cache";

void fakeip_save_unlocked() {
    std::ofstream out(kFakeIpCachePath, std::ios::trunc);
    if (!out) return;
    for (const auto& kv : g_name_to_fake) {
        out << ip_to_string(kv.second) << ' ' << kv.first << '\n';
    }
}

void fakeip_load() {
    std::ifstream in(kFakeIpCachePath);
    if (!in) return;
    std::lock_guard<std::mutex> lock(g_dns_name_mu);
    std::string ip_s, name;
    int n = 0;
    while (in >> ip_s >> name) {
        const uint32_t net = string_to_ip_net(ip_s);
        if (!net || !is_fake_ip(net) || name.empty()) continue;
        name = to_lower_host(name);
        DnsNameEntry e;
        e.name = name;
        e.expire = std::chrono::steady_clock::now() + std::chrono::seconds(kFakeDnsTtl);
        g_ip_to_name[net] = std::move(e);
        g_name_to_fake[name] = net;
        const uint32_t host = ntohl(net);
        if (host >= g_fake_next_host) g_fake_next_host = host + 1;
        if (g_fake_next_host > kFakeIpHostMax) g_fake_next_host = kFakeIpHostMin;
        ++n;
    }
    if (n > 0) log_line("[*] loaded " + std::to_string(n) + " fake-IP bindings from cache");
}

uint32_t fake_ip_alloc(const std::string& qname_raw) {
    const std::string qname = to_lower_host(qname_raw);
    if (qname.empty() || qname == "?") return 0;
    std::lock_guard<std::mutex> lock(g_dns_name_mu);
    auto it = g_name_to_fake.find(qname);
    if (it != g_name_to_fake.end()) {
        auto& e = g_ip_to_name[it->second];
        e.name = qname;
        e.expire = std::chrono::steady_clock::now() + std::chrono::seconds(kFakeDnsTtl);
        return it->second;
    }
    // Allocate next host in 198.18/15; skip .0 / .255 as a mild hygiene.
    for (int n = 0; n < 65536; ++n) {
        uint32_t host = g_fake_next_host++;
        if (g_fake_next_host > kFakeIpHostMax) g_fake_next_host = kFakeIpHostMin;
        const uint8_t b3 = static_cast<uint8_t>(host & 0xFF);
        if (b3 == 0 || b3 == 255) continue;
        const uint32_t net = htonl(host);
        if (g_ip_to_name.count(net)) continue;
        DnsNameEntry e;
        e.name = qname;
        e.expire = std::chrono::steady_clock::now() + std::chrono::seconds(kFakeDnsTtl);
        g_ip_to_name[net] = std::move(e);
        g_name_to_fake[qname] = net;
        fakeip_save_unlocked();
        return net;
    }
    return 0;
}

// NODATA / empty-answer reply (AAAA, HTTPS, unknown types).
std::vector<uint8_t> dns_reply_nodata(const std::vector<uint8_t>& query) {
    if (query.size() < 12) return {};
    size_t off = dns_skip_name(query.data(), query.size(), 12);
    if (off + 4 > query.size()) return {};
    off += 4;
    std::vector<uint8_t> resp(query.begin(), query.begin() + static_cast<std::ptrdiff_t>(off));
    resp[2] = static_cast<uint8_t>((resp[2] & 0x01) | 0x80); // QR, keep RD
    resp[3] = 0x80; // RA
    resp[6] = resp[7] = 0;
    resp[8] = resp[9] = 0;
    resp[10] = resp[11] = 0;
    return resp;
}

// Single A answer pointing at a fake IP (name starts at offset 12 -> 0xC00C).
std::vector<uint8_t> dns_reply_a(const std::vector<uint8_t>& query, uint32_t ip_net) {
    if (query.size() < 12) return {};
    size_t off = dns_skip_name(query.data(), query.size(), 12);
    if (off + 4 > query.size()) return {};
    off += 4;
    std::vector<uint8_t> resp(query.begin(), query.begin() + static_cast<std::ptrdiff_t>(off));
    resp[2] = static_cast<uint8_t>((resp[2] & 0x01) | 0x80);
    resp[3] = 0x80;
    resp[6] = 0;
    resp[7] = 1; // ANCOUNT
    resp[8] = resp[9] = resp[10] = resp[11] = 0;
    resp.push_back(0xC0);
    resp.push_back(0x0C);
    resp.push_back(0x00);
    resp.push_back(0x01); // A
    resp.push_back(0x00);
    resp.push_back(0x01); // IN
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

void reinject(HANDLE h, const DivertAddr& addr, const uint8_t* packet, UINT len) {
    UINT sent = 0;
    g_send(h, packet, len, &sent, &addr);
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
    u_long nb = 1;
    ioctlsocket(s, FIONBIO, &nb);
    int rc = connect(s, res->ai_addr, static_cast<int>(res->ai_addrlen));
    freeaddrinfo(res);
    if (rc != 0 && WSAGetLastError() != WSAEWOULDBLOCK) {
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
        closesocket(s);
        return INVALID_SOCKET;
    }
    int soerr = 0;
    int slen = sizeof(soerr);
    getsockopt(s, SOL_SOCKET, SO_ERROR, reinterpret_cast<char*>(&soerr), &slen);
    if (soerr != 0) {
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
        closesocket(s);
        return INVALID_SOCKET;
    }
    char greply[2];
    if (!recvn(s, greply, 2) || greply[0] != 0x05 || greply[1] != 0x00) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

SOCKET socks5_connect(uint32_t dst_net, uint16_t dst_port_host, int timeout_sec) {
    SOCKET s = socks5_handshake(timeout_sec);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    uint8_t req[10];
    req[0] = 0x05;
    req[1] = 0x01;
    req[2] = 0x00;
    req[3] = 0x01; // ATYP IPv4
    std::memcpy(req + 4, &dst_net, 4);
    req[8] = static_cast<uint8_t>(dst_port_host >> 8);
    req[9] = static_cast<uint8_t>(dst_port_host);
    if (!send_all(s, req, 10) || !socks5_read_connect_reply(s)) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

// Browser-style remote DNS: CONNECT with hostname so the SOCKS5 upstream
// resolves and applies DOMAIN / GEOSITE rules.
SOCKET socks5_connect_host(const std::string& host, uint16_t dst_port_host, int timeout_sec) {
    if (host.empty() || host.size() > 255) return INVALID_SOCKET;
    SOCKET s = socks5_handshake(timeout_sec);
    if (s == INVALID_SOCKET) return INVALID_SOCKET;
    std::vector<uint8_t> req(5 + host.size() + 2);
    req[0] = 0x05;
    req[1] = 0x01;
    req[2] = 0x00;
    req[3] = 0x03; // ATYP DOMAIN
    req[4] = static_cast<uint8_t>(host.size());
    std::memcpy(req.data() + 5, host.data(), host.size());
    req[5 + host.size()] = static_cast<uint8_t>(dst_port_host >> 8);
    req[5 + host.size() + 1] = static_cast<uint8_t>(dst_port_host);
    if (!send_all(s, req.data(), req.size()) || !socks5_read_connect_reply(s)) {
        closesocket(s);
        return INVALID_SOCKET;
    }
    return s;
}

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

// Sequence number the phone has actually been shown. Queued-but-unsent
// bytes must not appear as a hole, or the phone drops the ACK and resets.
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
    uint8_t mss_opt[4] = {2, 4, 0x05, 0xB4}; // MSS 1460
    const bool syn = (s.flags & pkt::TCP_SYN) != 0;
    auto packet = pkt::build_tcp(
        f.key.dst, f.key.src, f.key.dport, f.key.sport,
        s.seq, f.rcv_nxt, s.flags, recv_window(f),
        s.data.empty() ? nullptr : s.data.data(), s.data.size(),
        g_ip_id++,
        syn ? mss_opt : nullptr, syn ? sizeof(mss_opt) : 0);
    inject(f.divert, f.addr, packet, true);
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
    inject(f.divert, f.addr, packet, true);
}

void send_rst_locked(Flow& f) {
    auto packet = pkt::build_tcp(
        f.key.dst, f.key.src, f.key.dport, f.key.sport,
        tx_seq(f), f.rcv_nxt, pkt::TCP_RST | pkt::TCP_ACK, 0,
        nullptr, 0, g_ip_id++);
    inject(f.divert, f.addr, packet, true);
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
        g_rx_bytes += len;
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
                if (o.fin && !f.fin_from_client &&
                    pkt::seq_diff(o.seq + static_cast<uint32_t>(o.data.size()), f.rcv_nxt) == 0) {
                    accept_payload_locked(f, nullptr, 0, true);
                }
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

    // Fake-IP must CONNECT by hostname — same as browser socks_remote_dns.
    if (fake && learned.empty()) {
        ++g_fakeip_miss;
        fail_rst("unknown fake-IP (flush phone DNS)");
        return;
    }

    // Reject bare public IPs (stale cache / Private DNS DoH). Force re-query
    // through our fake-IP DNS so SOCKS5 always owns resolution.
    if (!fake && !is_private_ip(f->key.dst)) {
        ++g_realip_reject;
        fail_rst("reject real-IP (use DHCP DNS; disable Private DNS / DoH)");
        return;
    }

    const std::string dst_label = !learned.empty()
        ? (learned + "/" + ip_to_string(f->key.dst))
        : ip_to_string(f->key.dst);

    SOCKET s = INVALID_SOCKET;
    bool used_domain = false;
    if (!learned.empty()) {
        s = socks5_connect_host(learned, f->key.dport, 15);
        if (s != INVALID_SOCKET) {
            used_domain = true;
            ++g_domain_connect;
        }
    } else if (is_private_ip(f->key.dst)) {
        s = socks5_connect(f->key.dst, f->key.dport, 15);
        if (s != INVALID_SOCKET) ++g_ip_connect;
    }
    {
        std::lock_guard<std::mutex> lock(f->mu);
        if (!f->alive) {
            if (s != INVALID_SOCKET) closesocket(s);
            s = INVALID_SOCKET;
        } else if (s == INVALID_SOCKET) {
            ++g_socks_fail;
            log_line("[-] SOCKS5 CONNECT failed " + ip_to_string(f->key.src) + ":" +
                     std::to_string(f->key.sport) + " -> " + dst_label + ":" +
                     std::to_string(f->key.dport) +
                     " (upstream SOCKS5/link refused or timed out)");
            send_rst_locked(*f);
        } else {
            f->sock = s;
            f->state = FlowState::Open;
            set_timeouts(s, std::max(30, g_cfg.idle_timeout_sec));
        }
    }
    if (s == INVALID_SOCKET || f->sock == INVALID_SOCKET) {
        erase_flow(f);
        return;
    }
    log_line(std::string("[+] TCP ") + ip_to_string(f->key.src) + ":" +
             std::to_string(f->key.sport) + " -> " + dst_label + ":" +
             std::to_string(f->key.dport) +
             (used_domain ? " (domain)" : " (ip)"));

    // Read the website reply while the phone is still sending. Waiting for the
    // phone to FIN first leaves the SOCKS response unread, so pages never load.
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
        shutdown(s, SD_BOTH);
        closesocket(s);
    }
    f->sock = INVALID_SOCKET;
    {
        // Keep answering ACKs until the phone has the bytes it was shown.
        // Dropping the flow here makes the phone retransmit into silence and reset.
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
    struct DnsGuard {
        ~DnsGuard() { --g_dns_inflight; }
    } guard;

    // Fake-IP DNS: never resolve for the phone. SOCKS5 CONNECT(domain) does
    // real resolution upstream — identical to browser remote DNS.
    const std::string qname = dns_qname(query.data(), query.size());
    const std::string client = ip_to_string(src) + ":" + std::to_string(sport);
    const uint16_t qtype = dns_qtype(query.data(), query.size());

    auto inject_dns = [&](const std::vector<uint8_t>& resp, const std::string& note) {
        if (resp.empty()) {
            ++g_dns_fail;
            log_line("[-] DNS build failed " + client + " q=" + qname);
            return;
        }
        auto packet = pkt::build_udp(dst, src, 53, sport, resp.data(), resp.size(), g_ip_id++);
        const uint64_t fail_before = g_send_fail.load();
        inject(divert, addr, packet, false);
        if (g_send_fail.load() > fail_before) {
            ++g_dns_fail;
            log_line("[-] DNS inject to AP failed " + client + " q=" + qname);
            return;
        }
        ++g_dns_ok;
        log_line("[+] DNS " + client + " q=" + qname + " " + note);
    };

    // AAAA / HTTPS(65) / SVCB(64) / anything except A -> NODATA
    if (qtype != 1) {
        if (qtype == 28) ++g_aaaa_stripped;
        inject_dns(dns_reply_nodata(query),
                   qtype == 28 ? "AAAA->NODATA" :
                   (qtype == 65 || qtype == 64) ? ("type" + std::to_string(qtype) + "->NODATA") :
                   ("type" + std::to_string(qtype) + "->NODATA"));
        return;
    }

    if (qname.empty() || qname == "?") {
        ++g_dns_fail;
        log_line("[-] DNS empty qname from " + client);
        return;
    }

    const uint32_t fake = fake_ip_alloc(qname);
    if (!fake) {
        ++g_dns_fail;
        log_line("[-] DNS fake-IP pool exhausted q=" + qname);
        return;
    }
    ++g_fakeip_dns;
    inject_dns(dns_reply_a(query, fake),
               "fake-IP " + ip_to_string(fake) + " (SOCKS5 will resolve)");
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
        std::shared_ptr<Flow> existing;
        {
            std::lock_guard<std::mutex> lock(g_map_mu);
            auto it = g_flows.find(key);
            if (it != g_flows.end() && it->second->alive) {
                existing = it->second;
            } else {
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
        }
        if (existing) {
            bool fresh = false;
            {
                std::lock_guard<std::mutex> lock(existing->mu);
                if (v.seq == existing->client_isn) {
                    existing->addr = addr;
                    existing->last_rx = std::chrono::steady_clock::now();
                    existing->peer_wnd = v.window ? v.window : existing->peer_wnd;
                    for (auto& s : existing->segs) {
                        if (s.flags & pkt::TCP_SYN) transmit_locked(*existing, s);
                    }
                } else {
                    fresh = true;
                    existing->alive = false;
                    existing->cv.notify_all();
                }
            }
            if (!fresh) return;
            close_flow_socket(existing);
            erase_flow(existing);
            handle_tcp(divert, addr, v);
            return;
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
        if (already > plen) {
            if (fin && !flow->fin_from_client &&
                pkt::seq_diff(v.seq + static_cast<uint32_t>(plen), flow->rcv_nxt) == 0) {
                accept_payload_locked(*flow, nullptr, 0, true);
            }
            send_ack_locked(*flow);
            flow->cv.notify_all();
            return;
        }
        if (already == plen) {
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

bool is_dhcp_udp(const pkt::Ipv4L4& v) {
    if (v.proto != 17) return false;
    // Client -> server 68->67, server -> client 67->68 (rare on inbound).
    return (v.sport == 68 && v.dport == 67) || (v.sport == 67 && v.dport == 68) ||
           v.dport == 67 || v.sport == 67;
}

void on_packet(HANDLE divert, DivertAddr addr, const uint8_t* packet, UINT len) {
    ++g_captured;
    // Diverted: Windows will not see this packet unless we reinject it.
    auto v = pkt::parse_ipv4(packet, len);
    if (!v.ok) {
        // IPv6 / non-IPv4: swallow so the OS never processes AP traffic.
        ++g_swallowed;
        return;
    }
    if (v.fragmented) {
        ++g_swallowed;
        return;
    }

    // Only DHCP is handed back to Windows (hotspot address lease).
    if (is_dhcp_udp(v)) {
        ++g_dhcp_pass;
        reinject(divert, addr, packet, len);
        return;
    }

    if (v.proto == 17 && v.dport == 53) {
        if (v.payload_len == 0 || v.payload_len > 1500) {
            ++g_swallowed;
            return;
        }
        if (g_dns_inflight.load() >= g_cfg.max_dns_inflight) {
            ++g_swallowed;
            return;
        }
        ++g_dns_inflight;
        std::vector<uint8_t> q(v.payload, v.payload + v.payload_len);
        std::thread(handle_dns, divert, addr, v.src_net, v.sport, v.dst_net, std::move(q)).detach();
        return;
    }

    if (v.proto == 6) {
        handle_tcp(divert, addr, v);
        return;
    }

    // Any other IP (QUIC/UDP/ICMP/...): owned by us → drop (do not reinject).
    ++g_swallowed;
}

HANDLE open_divert(const std::string& filter, int layer, int16_t priority, uint64_t flags) {
    HANDLE h = g_open(filter.c_str(), layer, priority, flags);
    if (h == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        std::string why = "WinDivertOpen failed (" + std::to_string(err) + ")";
        if (err == 5) why += ": this process is not running as Administrator";
        else if (err == 2) why += ": WinDivert64.sys was not found next to WinDivert.dll";
        else if (err == 577) why += ": driver signature was rejected";
        else if (err == 87) why += ": invalid filter/layer/flags";
        else if (err == 1275) why += ": driver blocked by Windows (vulnerable driver blocklist or memory integrity)";
        log_line("[-] " + why);
        log_line("    filter: " + filter);
        return nullptr;
    }
    if (g_set_param) {
        g_set_param(h, 0, 8192);
        g_set_param(h, 1, 8000);
        g_set_param(h, 2, 8ull << 20);
    }
    const char* kind = (flags & WINDIVERT_FLAG_DROP) ? "drop" : "capture";
    log_line(std::string("[*] ") + kind + ": " + filter);
    return h;
}

void recv_loop(HANDLE h) {
    std::vector<uint8_t> buf(65535);
    while (g_run) {
        UINT n = 0;
        DivertAddr addr{};
        if (!g_recv(h, buf.data(), static_cast<UINT>(buf.size()), &n, &addr)) {
            if (!g_run) break;
            continue;
        }
        on_packet(h, addr, buf.data(), n);
    }
}

BOOL WINAPI on_console(DWORD) {
    g_run = false;
    return TRUE;
}

// Disable Windows IP forwarding on non-AP NICs so ICS/SharedAccess cannot NAT
// AP client traffic out WLAN. Host-originated SOCKS5 still works (not forwarded).
struct ForwardingGuard {
    struct Item {
        NET_IFINDEX ifindex = 0;
        BOOLEAN was_enabled = FALSE;
    };
    std::vector<Item> saved;

    void arm(uint32_t ap_ifindex) {
        restore();
        PMIB_IPINTERFACE_TABLE table = nullptr;
        if (GetIpInterfaceTable(AF_INET, &table) != NO_ERROR || !table) {
            log_line("[!] GetIpInterfaceTable failed — cannot disable system forwarding");
            return;
        }
        for (ULONG i = 0; i < table->NumEntries; ++i) {
            MIB_IPINTERFACE_ROW row = table->Table[i];
            if (row.InterfaceIndex == 0 || row.InterfaceIndex == ap_ifindex) continue;
            if (!row.Connected) continue;
            if (!row.ForwardingEnabled) continue;
            Item it;
            it.ifindex = row.InterfaceIndex;
            it.was_enabled = row.ForwardingEnabled;
            row.ForwardingEnabled = FALSE;
            // SitePrefixLength must be set for SetIpInterfaceEntry on some builds.
            const DWORD err = SetIpInterfaceEntry(&row);
            if (err == NO_ERROR) {
                saved.push_back(it);
                log_line("[*] system Forwarding disabled on ifIndex=" +
                         std::to_string(static_cast<unsigned>(it.ifindex)) +
                         " (block ICS NAT)");
            } else {
                log_line("[!] SetIpInterfaceEntry(" +
                         std::to_string(static_cast<unsigned>(row.InterfaceIndex)) +
                         ") failed err=" + std::to_string(err));
            }
        }
        FreeMibTable(table);
        if (saved.empty()) {
            log_line("[!] no upstream Forwarding flags cleared (ICS may still NAT)");
        }
    }

    void restore() {
        for (Item& it : saved) {
            MIB_IPINTERFACE_ROW row;
            InitializeIpInterfaceEntry(&row);
            row.Family = AF_INET;
            row.InterfaceIndex = it.ifindex;
            if (GetIpInterfaceEntry(&row) != NO_ERROR) continue;
            row.ForwardingEnabled = it.was_enabled;
            SetIpInterfaceEntry(&row);
            log_line("[*] system Forwarding restored on ifIndex=" +
                     std::to_string(static_cast<unsigned>(it.ifindex)));
        }
        saved.clear();
    }

    ~ForwardingGuard() { restore(); }
};

bool ipv4_usable(uint32_t net) {
    const unsigned b0 = net & 0xFFu;
    const unsigned b1 = (net >> 8) & 0xFFu;
    if (b0 == 0 || b0 == 127) return false;
    if (b0 == 169 && b1 == 254) return false;
    return true;
}

bool ipv4_is_ics_gateway(uint32_t net) {
    return (net & 0xFFu) == 192 && ((net >> 8) & 0xFFu) == 168 &&
           ((net >> 16) & 0xFFu) == 137 && ((net >> 24) & 0xFFu) == 1;
}

bool resolve_adapter(Settings& cfg, bool log_fail) {
    ULONG sz = 32 * 1024;
    std::vector<uint8_t> mem(sz);
    auto* addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(mem.data());
    ULONG rc = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, nullptr, addrs, &sz);
    if (rc == ERROR_BUFFER_OVERFLOW) {
        mem.resize(sz);
        addrs = reinterpret_cast<IP_ADAPTER_ADDRESSES*>(mem.data());
        rc = GetAdaptersAddresses(AF_INET, GAA_FLAG_INCLUDE_GATEWAYS, nullptr, addrs, &sz);
    }
    if (rc != NO_ERROR) {
        log_line("[-] GetAdaptersAddresses failed");
        return false;
    }

    struct Nic {
        std::string name;
        std::string ip;
        int prefix = 24;
        uint32_t ifindex = 0;
        uint32_t net = 0;
        bool has_gateway = false;
    };
    std::vector<Nic> nics;
    std::string listing;
    const bool want_named = !cfg.ap_adapter.empty() && cfg.ap_adapter != "-" && cfg.ap_adapter != "auto";
    int named = -1;
    int ics = -1;
    int isolated = -1;

    for (auto* a = addrs; a; a = a->Next) {
        // A hotspot NIC often has 169.254.* first and 192.168.137.1 second.
        // Keep the usable address; do not drop the adapter because of the
        // link-local one.
        Nic best{};
        bool have = false;
        for (auto* u = a->FirstUnicastAddress; u; u = u->Next) {
            if (!u->Address.lpSockaddr || u->Address.lpSockaddr->sa_family != AF_INET) continue;
            auto* sa = reinterpret_cast<sockaddr_in*>(u->Address.lpSockaddr);
            Nic nic;
            nic.name = wide_to_utf8(a->FriendlyName);
            nic.net = sa->sin_addr.s_addr;
            nic.ip = ip_to_string(nic.net);
            nic.prefix = u->OnLinkPrefixLength;
            if (nic.prefix <= 0) nic.prefix = 24;
            nic.ifindex = a->IfIndex;
            nic.has_gateway = a->FirstGatewayAddress != nullptr;
            listing += "    " + nic.name + "  " + nic.ip + "/" + std::to_string(nic.prefix) +
                       " if=" + std::to_string(nic.ifindex) + "\n";
            if (!ipv4_usable(nic.net)) continue;
            if (!have || ipv4_is_ics_gateway(nic.net)) best = nic;
            have = true;
        }
        if (!have) continue;
        const int idx = static_cast<int>(nics.size());
        nics.push_back(best);
        if (want_named && best.name == cfg.ap_adapter) named = idx;
        if (ipv4_is_ics_gateway(best.net)) ics = idx;
        if (!best.has_gateway && isolated < 0) isolated = idx;
    }

    int pick = named;
    if (pick < 0) pick = ics;
    if (pick < 0) pick = isolated;
    if (pick < 0) {
        if (log_fail) {
            log_line("[-] No AP adapter with a real IPv4 address. Start the mobile hotspot first.");
            log_line(listing);
        }
        return false;
    }
    cfg.ap_adapter = nics[pick].name;
    cfg.ap_gateway = nics[pick].ip;
    cfg.ap_prefix = nics[pick].prefix;
    cfg.ap_ifindex = nics[pick].ifindex;
    log_line("[*] AP adapter " + cfg.ap_adapter + " " + cfg.ap_gateway + "/" +
             std::to_string(cfg.ap_prefix) + " ifindex=" + std::to_string(cfg.ap_ifindex));
    return true;
}

std::string dotted_host(uint32_t host) {
    in_addr a{};
    a.s_addr = htonl(host);
    return ip_to_string(a.s_addr);
}

void build_range(Settings& cfg) {
    cfg.gw_net = string_to_ip_net(cfg.ap_gateway);
    cfg.dns_net = string_to_ip_net(cfg.dns_server);
    const int p = cfg.ap_prefix;
    cfg.mask_host = (p <= 0) ? 0 : (p >= 32 ? 0xFFFFFFFFu : (0xFFFFFFFFu << (32 - p)));
    const uint32_t gw_h = ntohl(cfg.gw_net);
    const uint32_t network = gw_h & cfg.mask_host;
    const uint32_t broadcast = network | ~cfg.mask_host;
    cfg.first_host = network + 1;
    if (cfg.first_host == gw_h) ++cfg.first_host;
    cfg.last_host = broadcast - 1;
    if (cfg.mss < 200) cfg.mss = 200;
    if (cfg.mss > 1400) cfg.mss = 1400;
}

void retransmit_loop() {
    while (g_run) {
        std::this_thread::sleep_for(std::chrono::milliseconds(250));
        std::vector<std::shared_ptr<Flow>> copy;
        {
            std::lock_guard<std::mutex> lock(g_map_mu);
            copy.reserve(g_flows.size());
            for (auto& kv : g_flows) copy.push_back(kv.second);
        }
        const auto now = std::chrono::steady_clock::now();
        for (auto& f : copy) {
            std::lock_guard<std::mutex> lock(f->mu);
            if (!f->alive) continue;
            if (std::chrono::duration_cast<std::chrono::seconds>(now - f->last_rx).count() >=
                g_cfg.idle_timeout_sec) {
                send_rst_locked(*f);
                continue;
            }
            flush_send_locked(*f);
            for (auto& s : f->segs) {
                if (pkt::seq_diff(seg_end(s), f->snd_una) <= 0) continue;
                if (s.sends == 0) break;
                // Retransmit only the oldest in-flight segment. Resending the
                // whole window overruns the phone and resets the page.
                int rto = 500;
                for (int n = 1; n < s.sends && rto < 2000; ++n) rto *= 2;
                const auto age = std::chrono::duration_cast<std::chrono::milliseconds>(now - s.last_send);
                if (age.count() < rto) break;
                if (s.sends >= 24) {
                    send_rst_locked(*f);
                    break;
                }
                transmit_locked(*f, s);
                break;
            }
        }
        std::lock_guard<std::mutex> lock(g_map_mu);
        for (auto it = g_flows.begin(); it != g_flows.end();) {
            if (!it->second->alive) it = g_flows.erase(it);
            else ++it;
        }
    }
}

} // namespace

int main(int argc, char** argv) {
    const std::string path = (argc >= 2) ? argv[1] : "config/ap2socks5.json";
    try {
        JsonConfig j(path);
        g_cfg.ap_adapter = j.get_string("ap_adapter", g_cfg.ap_adapter);
        g_cfg.ap_gateway = j.get_string("ap_gateway", g_cfg.ap_gateway);
        g_cfg.ap_prefix = j.get_int("ap_prefix", g_cfg.ap_prefix);
        g_cfg.socks5_host = j.get_string("socks5_host", g_cfg.socks5_host);
        g_cfg.socks5_port = j.get_int("socks5_port", g_cfg.socks5_port);
        g_cfg.dns_server = j.get_string("dns_server", g_cfg.dns_server);
        g_cfg.dns_port = j.get_int("dns_port", g_cfg.dns_port);
        g_cfg.capture_layer = j.get_string("capture_layer", g_cfg.capture_layer);
        g_cfg.mss = j.get_int("mss", g_cfg.mss);
        g_cfg.idle_timeout_sec = j.get_int("idle_timeout_sec", g_cfg.idle_timeout_sec);
        g_cfg.max_connections = j.get_int("max_connections", g_cfg.max_connections);
        g_cfg.max_dns_inflight = j.get_int("max_dns_inflight", g_cfg.max_dns_inflight);
    } catch (const std::exception& e) {
        std::cerr << "[-] " << e.what() << "\n";
        return 1;
    }

    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        std::cerr << "[-] WSAStartup failed\n";
        return 1;
    }
    SetConsoleCtrlHandler(on_console, TRUE);

    bool adapter_ok = false;
    for (int attempt = 0; attempt < 20; ++attempt) {
        adapter_ok = resolve_adapter(g_cfg, attempt == 19);
        if (adapter_ok) break;
        Sleep(500);
    }
    if (!adapter_ok) {
        WSACleanup();
        return 1;
    }
    build_range(g_cfg);
    if (g_cfg.gw_net == 0 || g_cfg.first_host > g_cfg.last_host) {
        std::cerr << "[-] Invalid AP subnet\n";
        WSACleanup();
        return 1;
    }

    if (!load_windivert()) {
        std::cerr << "[-] WinDivert.dll not found next to ap2socks5.exe\n"
                  << "    Copy WinDivert.dll and WinDivert64.sys from WinDivert 2.2.2\n"
                  << "    https://github.com/basil00/WinDivert/releases\n";
        WSACleanup();
        return 1;
    }

    fakeip_load();

    const std::string range =
        "ip.SrcAddr >= " + dotted_host(g_cfg.first_host) +
        " and ip.SrcAddr <= " + dotted_host(g_cfg.last_host);
    // WinDivert rejects "not (addr >= x and addr <= y)" (error 87) — use < or >.
    const uint32_t net_h = ntohl(g_cfg.gw_net) & g_cfg.mask_host;
    const uint32_t bcast_h = net_h | ~g_cfg.mask_host;
    const std::string off_subnet =
        "(ip.DstAddr < " + dotted_host(net_h) +
        " or ip.DstAddr > " + dotted_host(bcast_h) + ")";
    const std::string leak = "ip and " + range + " and " + off_subnet;
    const std::string flow = "ip and " + range + " and (tcp or udp.DstPort == 53)";

    std::vector<HANDLE> handles;
    std::vector<HANDLE> drops;
    const int16_t prio_cap = WINDIVERT_PRIORITY_HIGHEST;
    const int16_t prio_drop = static_cast<int16_t>(WINDIVERT_PRIORITY_HIGHEST - 1);

    auto add_cap = [&](const std::string& f, int layer) {
        handles.push_back(open_divert(f, layer, prio_cap, 0));
    };
    auto add_drop = [&](const std::string& f, int layer) {
        drops.push_back(open_divert(f, layer, prio_drop, WINDIVERT_FLAG_DROP));
    };

    // Kill ICS NAT path at the IP stack (restore on exit).
    ForwardingGuard fwd_guard;
    fwd_guard.arm(g_cfg.ap_ifindex);

    if (g_cfg.ap_ifindex == 0) {
        log_line("[!] AP ifindex unknown — cannot exclusively claim the AP NIC");
    } else {
        const std::string ifs = "ifIdx == " + std::to_string(g_cfg.ap_ifindex);
        // 1) Claim every inbound L3 packet on the AP NIC (OS will not see it
        //    unless we reinject — only DHCP is reinjected).
        add_cap("inbound and " + ifs + " and (ip or ipv6)", WINDIVERT_LAYER_NETWORK);
        // 2) Block the Windows stack from transmitting on the AP NIC.
        //    Our replies use impostor inject and are not matched. DHCP offers
        //    from the built-in hotspot (udp/67) are allowed so leases work.
        add_drop("outbound and " + ifs + " and not impostor and ipv6", WINDIVERT_LAYER_NETWORK);
        add_drop("outbound and " + ifs + " and not impostor and ip and tcp", WINDIVERT_LAYER_NETWORK);
        add_drop("outbound and " + ifs + " and not impostor and ip and icmp", WINDIVERT_LAYER_NETWORK);
        add_drop("outbound and " + ifs +
                     " and not impostor and ip and udp and "
                     "udp.SrcPort != 67 and udp.DstPort != 68",
                 WINDIVERT_LAYER_NETWORK);
    }

    // 3) Backup: anything that still hits the forward plane from AP clients.
    add_cap(flow, WINDIVERT_LAYER_NETWORK_FORWARD);
    add_drop(leak, WINDIVERT_LAYER_NETWORK_FORWARD);
    add_drop("ipv6", WINDIVERT_LAYER_NETWORK_FORWARD);

    handles.erase(std::remove(handles.begin(), handles.end(), nullptr), handles.end());
    drops.erase(std::remove(drops.begin(), drops.end(), nullptr), drops.end());
    if (drops.empty()) {
        log_line("[!] AP exclusive shield incomplete — OS may still touch AP traffic");
    } else {
        log_line("[*] AP exclusive mode: inbound claimed, OS outbound blocked (DHCP/ARP excepted)");
    }
    // SEND_ONLY. "false" matches no packets.
    g_inject = g_open("false", WINDIVERT_LAYER_NETWORK, 0, WINDIVERT_FLAG_SEND_ONLY);
    if (!g_inject || g_inject == INVALID_HANDLE_VALUE) {
        log_line("[-] WinDivert send handle failed (" + std::to_string(GetLastError()) + ")");
        g_inject = nullptr;
    } else {
        log_line("[*] reply injection: NETWORK outbound");
    }
    if (handles.empty()) {
        std::cerr << "[-] No capture handle. Run this program as Administrator.\n";
        WSACleanup();
        return 1;
    }

    log_line("[*] AP2Socks5 gateway " + g_cfg.ap_gateway + " clients " +
             dotted_host(g_cfg.first_host) + " - " + dotted_host(g_cfg.last_host));
    log_line("[*] SOCKS5 " + g_cfg.socks5_host + ":" + std::to_string(g_cfg.socks5_port));
    log_line("[*] fake-IP DNS 198.18.0.0/15: phone never sees real A; SOCKS5 resolves (browser-style)");
    log_line("[*] OS must not own AP data-plane; uplink Forwarding off; SOCKS5=" +
             g_cfg.socks5_host + ":" + std::to_string(g_cfg.socks5_port));
    log_line("[*] Pass-through to OS: DHCP only. ARP stays at L2. All else: us or drop.");

    std::thread retx(retransmit_loop);
    std::vector<std::thread> readers;
    for (HANDLE h : handles) readers.emplace_back(recv_loop, h);

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
                 " dns_fail=" + std::to_string(g_dns_fail.load()) +
                 " aaaa_nodata=" + std::to_string(g_aaaa_stripped.load()) +
                 " socks_fail=" + std::to_string(g_socks_fail.load()) +
                 " domain=" + std::to_string(g_domain_connect.load()) +
                 " ip=" + std::to_string(g_ip_connect.load()) +
                 " fake_dns=" + std::to_string(g_fakeip_dns.load()) +
                 " fake_miss=" + std::to_string(g_fakeip_miss.load()) +
                 " realip_rej=" + std::to_string(g_realip_reject.load()) +
                 " dhcp=" + std::to_string(g_dhcp_pass.load()) +
                 " swallow=" + std::to_string(g_swallowed.load()) +
                 " rx=" + std::to_string(g_rx_bytes.load()) +
                 " tx=" + std::to_string(g_tx_bytes.load()) +
                 " send_fail=" + std::to_string(g_send_fail.load()));
    }

    for (HANDLE h : handles) {
        if (g_shutdown) g_shutdown(h, 0x3);
    }
    for (auto& t : readers) t.join();
    retx.join();
    {
        std::lock_guard<std::mutex> lock(g_map_mu);
        for (auto& kv : g_flows) close_flow_socket(kv.second);
        g_flows.clear();
    }
    for (HANDLE h : handles) g_close(h);
    for (HANDLE h : drops) g_close(h);
    if (g_inject) g_close(g_inject);
    fwd_guard.restore();
    WSACleanup();
    log_line("[*] AP2Socks5 stopped");
    return 0;
}
