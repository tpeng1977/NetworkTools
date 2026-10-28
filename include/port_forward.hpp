#ifndef VORTEX_PORT_FORWARD_HPP
#define VORTEX_PORT_FORWARD_HPP

#include "protocol.hpp"

#include <cctype>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace vortex {

// One listen→target pair after port lists are expanded and zipped by index.
struct PortMapEntry {
    uint16_t listen_port = 0;
    uint16_t target_port = 0;
};

struct PortForwardSpec {
    std::string listen_ip = "127.0.0.1";
    std::string target_ip = "127.0.0.1";
    std::vector<PortMapEntry> maps; // listen_port → target_port
    bool empty() const { return maps.empty(); }
};

inline void skip_json_ws(const std::string& text, size_t& pos) {
    while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) ++pos;
}

inline size_t matching_json_brace(const std::string& text, size_t open) {
    int depth = 0;
    bool in_str = false;
    for (size_t i = open; i < text.size(); ++i) {
        const char ch = text[i];
        if (in_str) {
            if (ch == '\\' && i + 1 < text.size()) {
                ++i;
                continue;
            }
            if (ch == '"') in_str = false;
            continue;
        }
        if (ch == '"') {
            in_str = true;
            continue;
        }
        if (ch == '{') ++depth;
        else if (ch == '}') {
            --depth;
            if (depth == 0) return i;
        }
    }
    return std::string::npos;
}

inline size_t matching_json_bracket(const std::string& text, size_t open) {
    int depth = 0;
    bool in_str = false;
    for (size_t i = open; i < text.size(); ++i) {
        const char ch = text[i];
        if (in_str) {
            if (ch == '\\' && i + 1 < text.size()) {
                ++i;
                continue;
            }
            if (ch == '"') in_str = false;
            continue;
        }
        if (ch == '"') {
            in_str = true;
            continue;
        }
        if (ch == '[') ++depth;
        else if (ch == ']') {
            --depth;
            if (depth == 0) return i;
        }
    }
    return std::string::npos;
}

inline std::string json_object_slice(const std::string& text, const std::string& key) {
    const std::string pattern = "\"" + key + "\"";
    size_t pos = text.find(pattern);
    if (pos == std::string::npos) return {};
    pos = text.find(':', pos + pattern.size());
    if (pos == std::string::npos) return {};
    ++pos;
    skip_json_ws(text, pos);
    if (pos >= text.size() || text[pos] != '{') return {};
    const size_t end = matching_json_brace(text, pos);
    if (end == std::string::npos) return {};
    return text.substr(pos, end - pos + 1);
}

inline std::string json_get_string_in(const std::string& text, const std::string& key,
                                      const std::string& def = "") {
    const std::string pattern = "\"" + key + "\"";
    size_t pos = text.find(pattern);
    if (pos == std::string::npos) return def;
    pos = text.find(':', pos + pattern.size());
    if (pos == std::string::npos) return def;
    ++pos;
    skip_json_ws(text, pos);
    if (pos >= text.size() || text[pos] != '"') return def;
    ++pos;
    std::string out;
    while (pos < text.size() && text[pos] != '"') {
        if (text[pos] == '\\' && pos + 1 < text.size()) {
            out.push_back(text[pos + 1]);
            pos += 2;
        } else {
            out.push_back(text[pos++]);
        }
    }
    return out;
}

// Expand a single port token: integer 8888 or range string "8891-8999" (inclusive).
inline std::vector<uint16_t> expand_port_token(const std::string& token) {
    std::vector<uint16_t> out;
    if (token.empty()) {
        throw std::runtime_error("empty port token");
    }
    const size_t dash = token.find('-');
    if (dash == std::string::npos) {
        int v = 0;
        try {
            size_t end = 0;
            v = std::stoi(token, &end);
            if (end != token.size()) throw std::runtime_error("bad");
        } catch (...) {
            throw std::runtime_error("invalid port: " + token);
        }
        if (v < 1 || v > 65535) throw std::runtime_error("port out of range: " + token);
        out.push_back(static_cast<uint16_t>(v));
        return out;
    }
    if (dash == 0 || dash + 1 >= token.size()) {
        throw std::runtime_error("invalid port range: " + token);
    }
    int a = 0;
    int b = 0;
    try {
        size_t end_a = 0;
        size_t end_b = 0;
        a = std::stoi(token.substr(0, dash), &end_a);
        b = std::stoi(token.substr(dash + 1), &end_b);
        if (end_a != dash || end_b != token.size() - dash - 1) throw std::runtime_error("bad");
    } catch (...) {
        throw std::runtime_error("invalid port range: " + token);
    }
    if (a < 1 || a > 65535 || b < 1 || b > 65535 || b < a) {
        throw std::runtime_error("invalid port range bounds: " + token);
    }
    const size_t n = static_cast<size_t>(b - a) + 1;
    if (n > 4096) {
        throw std::runtime_error("port range too large (max 4096): " + token);
    }
    out.reserve(n);
    for (int p = a; p <= b; ++p) out.push_back(static_cast<uint16_t>(p));
    return out;
}

// Parse JSON array mixing ints and "lo-hi" strings into expanded port list.
inline std::vector<uint16_t> parse_port_list_json(const std::string& arr_text,
                                                  const std::string& field_name) {
    std::vector<uint16_t> out;
    size_t pos = 0;
    skip_json_ws(arr_text, pos);
    if (pos >= arr_text.size() || arr_text[pos] != '[') {
        throw std::runtime_error(field_name + " must be a JSON array");
    }
    ++pos;
    while (true) {
        skip_json_ws(arr_text, pos);
        if (pos >= arr_text.size()) {
            throw std::runtime_error(field_name + ": truncated array");
        }
        if (arr_text[pos] == ']') break;
        if (arr_text[pos] == '"') {
            ++pos;
            std::string tok;
            while (pos < arr_text.size() && arr_text[pos] != '"') {
                if (arr_text[pos] == '\\' && pos + 1 < arr_text.size()) {
                    tok.push_back(arr_text[pos + 1]);
                    pos += 2;
                } else {
                    tok.push_back(arr_text[pos++]);
                }
            }
            if (pos >= arr_text.size() || arr_text[pos] != '"') {
                throw std::runtime_error(field_name + ": unterminated string");
            }
            ++pos;
            auto part = expand_port_token(tok);
            out.insert(out.end(), part.begin(), part.end());
        } else if (arr_text[pos] == '-' ||
                   (arr_text[pos] >= '0' && arr_text[pos] <= '9')) {
            size_t end = 0;
            int v = 0;
            try {
                v = std::stoi(arr_text.substr(pos), &end);
            } catch (...) {
                throw std::runtime_error(field_name + ": bad integer");
            }
            if (v < 1 || v > 65535) {
                throw std::runtime_error(field_name + ": port out of range");
            }
            out.push_back(static_cast<uint16_t>(v));
            pos += end;
        } else {
            throw std::runtime_error(field_name + ": unexpected token in port array");
        }
        skip_json_ws(arr_text, pos);
        if (pos < arr_text.size() && arr_text[pos] == ',') {
            ++pos;
            continue;
        }
        if (pos < arr_text.size() && arr_text[pos] == ']') break;
        throw std::runtime_error(field_name + ": expected ',' or ']'");
    }
    if (out.empty()) {
        throw std::runtime_error(field_name + " expands to empty port list");
    }
    if (out.size() > 4096) {
        throw std::runtime_error(field_name + " expands to more than 4096 ports");
    }
    return out;
}

inline std::string json_array_slice(const std::string& text, const std::string& key) {
    const std::string pattern = "\"" + key + "\"";
    size_t pos = text.find(pattern);
    if (pos == std::string::npos) return {};
    pos = text.find(':', pos + pattern.size());
    if (pos == std::string::npos) return {};
    ++pos;
    skip_json_ws(text, pos);
    if (pos >= text.size() || text[pos] != '[') return {};
    const size_t end = matching_json_bracket(text, pos);
    if (end == std::string::npos) return {};
    return text.substr(pos, end - pos + 1);
}

// Zip listen_ports[i] → target_ports[i]. Lengths must match after expansion.
inline std::vector<PortMapEntry> zip_port_maps(const std::vector<uint16_t>& listen_ports,
                                               const std::vector<uint16_t>& target_ports,
                                               const std::string& ctx) {
    if (listen_ports.size() != target_ports.size()) {
        throw std::runtime_error(
            ctx + ": listen/target port list length mismatch after expansion (" +
            std::to_string(listen_ports.size()) + " vs " +
            std::to_string(target_ports.size()) + ")");
    }
    std::vector<PortMapEntry> maps;
    maps.reserve(listen_ports.size());
    for (size_t i = 0; i < listen_ports.size(); ++i) {
        maps.push_back(PortMapEntry{listen_ports[i], target_ports[i]});
    }
    return maps;
}

// to_remote (ssh -R): listen on remote_* , target local_*
// to_local  (ssh -L): listen on local_*  , target remote_*
inline PortForwardSpec parse_to_remote_object(const std::string& obj) {
    PortForwardSpec s;
    if (obj.empty()) return s;
    s.listen_ip = json_get_string_in(obj, "remote_ip", "0.0.0.0");
    s.target_ip = json_get_string_in(obj, "local_ip", "127.0.0.1");
    const std::string r = json_array_slice(obj, "remote_ports");
    const std::string l = json_array_slice(obj, "local_ports");
    if (r.empty() && l.empty()) return s;
    if (r.empty() || l.empty()) {
        throw std::runtime_error("to_remote: both remote_ports and local_ports required");
    }
    auto rp = parse_port_list_json(r, "to_remote.remote_ports");
    auto lp = parse_port_list_json(l, "to_remote.local_ports");
    s.maps = zip_port_maps(rp, lp, "to_remote");
    return s;
}

inline PortForwardSpec parse_to_local_object(const std::string& obj) {
    PortForwardSpec s;
    if (obj.empty()) return s;
    s.listen_ip = json_get_string_in(obj, "local_ip", "127.0.0.1");
    s.target_ip = json_get_string_in(obj, "remote_ip", "127.0.0.1");
    const std::string r = json_array_slice(obj, "remote_ports");
    const std::string l = json_array_slice(obj, "local_ports");
    if (r.empty() && l.empty()) return s;
    if (r.empty() || l.empty()) {
        throw std::runtime_error("to_local: both remote_ports and local_ports required");
    }
    auto lp = parse_port_list_json(l, "to_local.local_ports");
    auto rp = parse_port_list_json(r, "to_local.remote_ports");
    s.maps = zip_port_maps(lp, rp, "to_local");
    return s;
}

// Wire helpers ----------------------------------------------------------------

inline std::vector<uint8_t> build_connect_target_host(const std::string& host, uint16_t port) {
    std::vector<uint8_t> wire;
    in_addr v4{};
    in6_addr v6{};
    if (inet_pton(AF_INET, host.c_str(), &v4) == 1) {
        wire.push_back(ATYP_IPV4);
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&v4);
        wire.insert(wire.end(), p, p + 4);
    } else if (inet_pton(AF_INET6, host.c_str(), &v6) == 1) {
        wire.push_back(ATYP_IPV6);
        const uint8_t* p = reinterpret_cast<const uint8_t*>(&v6);
        wire.insert(wire.end(), p, p + 16);
    } else {
        if (host.empty() || host.size() > 255) return {};
        wire.push_back(ATYP_DOMAIN);
        wire.push_back(static_cast<uint8_t>(host.size()));
        wire.insert(wire.end(), host.begin(), host.end());
    }
    wire.push_back(static_cast<uint8_t>((port >> 8) & 0xFF));
    wire.push_back(static_cast<uint8_t>(port & 0xFF));
    return wire;
}

// FWD_CONFIG payload v1:
//   [u8 ver=1][u8 flags]
//   to_remote: [u8 lip_len][listen_ip][u8 tip_len][target_ip][u16 n BE]
//              n × [u16 listen BE][u16 target BE]
//   to_local:  same
// flags: bit0 = enable_udp, bit1 = udp_mux_session (dedicated UDP relay worker)
constexpr uint8_t FWD_FLAG_UDP = 0x01;
constexpr uint8_t FWD_FLAG_UDP_MUX = 0x02;

inline void append_u16_be(std::vector<uint8_t>& out, uint16_t v) {
    out.push_back(static_cast<uint8_t>((v >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(v & 0xFF));
}

inline bool read_u16_be(const std::vector<uint8_t>& data, size_t& off, uint16_t& out) {
    if (off + 2 > data.size()) return false;
    out = static_cast<uint16_t>((data[off] << 8) | data[off + 1]);
    off += 2;
    return true;
}

inline bool read_len_string(const std::vector<uint8_t>& data, size_t& off, std::string& out) {
    if (off >= data.size()) return false;
    const size_t n = data[off++];
    if (off + n > data.size()) return false;
    out.assign(reinterpret_cast<const char*>(data.data() + off), n);
    off += n;
    return true;
}

inline bool append_fwd_section(std::vector<uint8_t>& out, const PortForwardSpec& spec) {
    if (spec.listen_ip.size() > 255 || spec.target_ip.size() > 255) return false;
    if (spec.maps.size() > 65535) return false;
    out.push_back(static_cast<uint8_t>(spec.listen_ip.size()));
    out.insert(out.end(), spec.listen_ip.begin(), spec.listen_ip.end());
    out.push_back(static_cast<uint8_t>(spec.target_ip.size()));
    out.insert(out.end(), spec.target_ip.begin(), spec.target_ip.end());
    append_u16_be(out, static_cast<uint16_t>(spec.maps.size()));
    for (const auto& m : spec.maps) {
        append_u16_be(out, m.listen_port);
        append_u16_be(out, m.target_port);
    }
    return true;
}

inline bool parse_fwd_section(const std::vector<uint8_t>& data, size_t& off,
                              PortForwardSpec& spec) {
    if (!read_len_string(data, off, spec.listen_ip)) return false;
    if (!read_len_string(data, off, spec.target_ip)) return false;
    uint16_t n = 0;
    if (!read_u16_be(data, off, n)) return false;
    spec.maps.clear();
    spec.maps.reserve(n);
    for (uint16_t i = 0; i < n; ++i) {
        uint16_t lp = 0;
        uint16_t tp = 0;
        if (!read_u16_be(data, off, lp) || !read_u16_be(data, off, tp)) return false;
        if (lp == 0 || tp == 0) return false;
        spec.maps.push_back(PortMapEntry{lp, tp});
    }
    return true;
}

inline std::vector<uint8_t> build_fwd_config_payload(const PortForwardSpec& to_remote,
                                                     const PortForwardSpec& to_local,
                                                     uint8_t flags) {
    std::vector<uint8_t> out;
    out.push_back(1); // version
    out.push_back(flags);
    if (!append_fwd_section(out, to_remote)) return {};
    if (!append_fwd_section(out, to_local)) return {};
    return out;
}

inline bool parse_fwd_config_payload(const std::vector<uint8_t>& data,
                                     PortForwardSpec& to_remote,
                                     PortForwardSpec& to_local,
                                     uint8_t& flags) {
    if (data.size() < 2 || data[0] != 1) return false;
    size_t off = 1;
    flags = data[off++];
    if (!parse_fwd_section(data, off, to_remote)) return false;
    if (!parse_fwd_section(data, off, to_local)) return false;
    return off == data.size();
}

// UDP_DATA: [u32 sid BE][u8 flags][optional host:port wire][payload]
// flags: bit0=has_addr, bit1=DIR_TO_LOCAL (ssh -L path; avoids sid clash with to_remote)
constexpr uint8_t UDP_FLAG_HAS_ADDR = 0x01;
constexpr uint8_t UDP_FLAG_TO_LOCAL = 0x02;

inline std::vector<uint8_t> build_udp_data_payload(uint32_t sid,
                                                   const std::string* addr_host,
                                                   uint16_t addr_port,
                                                   const uint8_t* payload,
                                                   size_t payload_len,
                                                   uint8_t extra_flags = 0) {
    std::vector<uint8_t> out;
    out.push_back(static_cast<uint8_t>((sid >> 24) & 0xFF));
    out.push_back(static_cast<uint8_t>((sid >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((sid >> 8) & 0xFF));
    out.push_back(static_cast<uint8_t>(sid & 0xFF));
    uint8_t flags = extra_flags;
    if (addr_host && !addr_host->empty() && addr_port != 0) {
        flags = static_cast<uint8_t>(flags | UDP_FLAG_HAS_ADDR);
        out.push_back(flags);
        auto wire = build_connect_target_host(*addr_host, addr_port);
        out.insert(out.end(), wire.begin(), wire.end());
    } else {
        out.push_back(flags);
    }
    if (payload_len && payload) {
        out.insert(out.end(), payload, payload + payload_len);
    }
    return out;
}

inline bool parse_udp_data_payload(const std::vector<uint8_t>& data,
                                   uint32_t& sid,
                                   bool& has_addr,
                                   std::string& addr_host,
                                   uint16_t& addr_port,
                                   std::vector<uint8_t>& payload,
                                   uint8_t* out_flags = nullptr) {
    if (data.size() < 5) return false;
    sid = (static_cast<uint32_t>(data[0]) << 24) | (static_cast<uint32_t>(data[1]) << 16) |
          (static_cast<uint32_t>(data[2]) << 8) | static_cast<uint32_t>(data[3]);
    const uint8_t flags = data[4];
    if (out_flags) *out_flags = flags;
    has_addr = (flags & UDP_FLAG_HAS_ADDR) != 0;
    size_t off = 5;
    addr_host.clear();
    addr_port = 0;
    if (has_addr) {
        std::vector<uint8_t> rest(data.begin() + static_cast<std::ptrdiff_t>(off), data.end());
        if (!parse_connect_target(rest, addr_host, addr_port)) return false;
        auto wire = build_connect_target_host(addr_host, addr_port);
        if (wire.empty() || off + wire.size() > data.size()) return false;
        off += wire.size();
    }
    payload.assign(data.begin() + static_cast<std::ptrdiff_t>(off), data.end());
    return true;
}

// UDP_CLOSE: [u32 sid BE][u8 flags]
// flags: bit1=UDP_FLAG_TO_LOCAL (same meaning as UDP_DATA; avoids sid-namespace clash)
inline std::vector<uint8_t> build_udp_close_payload(uint32_t sid, uint8_t flags = 0) {
    return {
        static_cast<uint8_t>((sid >> 24) & 0xFF),
        static_cast<uint8_t>((sid >> 16) & 0xFF),
        static_cast<uint8_t>((sid >> 8) & 0xFF),
        static_cast<uint8_t>(sid & 0xFF),
        flags,
    };
}

inline bool parse_udp_close_payload(const std::vector<uint8_t>& data, uint32_t& sid,
                                    uint8_t* out_flags = nullptr) {
    if (data.size() < 4) return false;
    sid = (static_cast<uint32_t>(data[0]) << 24) | (static_cast<uint32_t>(data[1]) << 16) |
          (static_cast<uint32_t>(data[2]) << 8) | static_cast<uint32_t>(data[3]);
    const uint8_t flags = (data.size() >= 5) ? data[4] : 0;
    if (out_flags) *out_flags = flags;
    return true;
}

} // namespace vortex

#endif // VORTEX_PORT_FORWARD_HPP
