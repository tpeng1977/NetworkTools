#ifndef VORTEX_CONFIG_HPP
#define VORTEX_CONFIG_HPP

#include <cctype>
#include <fstream>
#include <map>
#include <sstream>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

// Minimal JSON object reader for our flat config files (no nested objects).
class JsonConfig {
public:
    explicit JsonConfig(const std::string& path) {
        std::ifstream in(path);
        if (!in) {
            throw std::runtime_error("Cannot open config: " + path);
        }
        std::ostringstream ss;
        ss << in.rdbuf();
        text_ = ss.str();
    }

    std::string get_string(const std::string& key, const std::string& def = "") const {
        auto pos = find_key(key);
        if (pos == std::string::npos) return def;
        pos = text_.find(':', pos);
        if (pos == std::string::npos) return def;
        ++pos;
        skip_ws(pos);
        if (pos >= text_.size() || text_[pos] != '"') return def;
        ++pos;
        std::string out;
        while (pos < text_.size() && text_[pos] != '"') {
            if (text_[pos] == '\\' && pos + 1 < text_.size()) {
                out.push_back(text_[pos + 1]);
                pos += 2;
            } else {
                out.push_back(text_[pos++]);
            }
        }
        return out;
    }

    int get_int(const std::string& key, int def = 0) const {
        auto pos = find_key(key);
        if (pos == std::string::npos) return def;
        pos = text_.find(':', pos);
        if (pos == std::string::npos) return def;
        ++pos;
        skip_ws(pos);
        try {
            size_t end = 0;
            int v = std::stoi(text_.substr(pos), &end);
            return v;
        } catch (...) {
            return def;
        }
    }

    bool get_bool(const std::string& key, bool def = false) const {
        auto pos = find_key(key);
        if (pos == std::string::npos) return def;
        pos = text_.find(':', pos);
        if (pos == std::string::npos) return def;
        ++pos;
        skip_ws(pos);
        if (text_.compare(pos, 4, "true") == 0) return true;
        if (text_.compare(pos, 5, "false") == 0) return false;
        return def;
    }

private:
    std::string text_;

    void skip_ws(size_t& pos) const {
        while (pos < text_.size() && std::isspace(static_cast<unsigned char>(text_[pos]))) {
            ++pos;
        }
    }

    size_t find_key(const std::string& key) const {
        const std::string pattern = "\"" + key + "\"";
        return text_.find(pattern);
    }
};

struct ServerConfig {
    std::string bind_ip = "0.0.0.0";
    int bind_port = 18888;
    std::string master_secret = "VortexSecureNetwork2026_KeyMix";
    int padding_min = 0;
    int padding_max = 128;
    bool camouflage = true;
    int listen_backlog = 128;
    int idle_timeout_sec = 300;
    int max_payload = 32768;
    int max_connections = 2048;

    static ServerConfig load(const std::string& path) {
        JsonConfig j(path);
        ServerConfig c;
        c.bind_ip = j.get_string("bind_ip", c.bind_ip);
        c.bind_port = j.get_int("bind_port", c.bind_port);
        c.master_secret = j.get_string("master_secret", c.master_secret);
        c.padding_min = j.get_int("padding_min", c.padding_min);
        c.padding_max = j.get_int("padding_max", c.padding_max);
        c.camouflage = j.get_bool("camouflage", c.camouflage);
        c.listen_backlog = j.get_int("listen_backlog", c.listen_backlog);
        c.idle_timeout_sec = j.get_int("idle_timeout_sec", c.idle_timeout_sec);
        c.max_payload = j.get_int("max_payload", c.max_payload);
        c.max_connections = j.get_int("max_connections", c.max_connections);
        if (c.padding_min < 0) c.padding_min = 0;
        if (c.padding_max < c.padding_min) c.padding_max = c.padding_min;
        if (c.max_payload < 1024) c.max_payload = 1024;
        if (c.max_payload > 60000) c.max_payload = 60000;
        return c;
    }
};

struct ClientConfig {
    std::string socks5_bind_ip = "127.0.0.1";
    int socks5_bind_port = 11080;
    std::string server_ip = "127.0.0.1";
    int server_port = 18888;
    std::string master_secret = "VortexSecureNetwork2026_KeyMix";
    int padding_min = 0;
    int padding_max = 128;
    int listen_backlog = 128;
    int idle_timeout_sec = 300;
    int max_payload = 32768;

    static ClientConfig load(const std::string& path) {
        JsonConfig j(path);
        ClientConfig c;
        c.socks5_bind_ip = j.get_string("socks5_bind_ip", c.socks5_bind_ip);
        c.socks5_bind_port = j.get_int("socks5_bind_port", c.socks5_bind_port);
        c.server_ip = j.get_string("server_ip", c.server_ip);
        c.server_port = j.get_int("server_port", c.server_port);
        c.master_secret = j.get_string("master_secret", c.master_secret);
        c.padding_min = j.get_int("padding_min", c.padding_min);
        c.padding_max = j.get_int("padding_max", c.padding_max);
        c.listen_backlog = j.get_int("listen_backlog", c.listen_backlog);
        c.idle_timeout_sec = j.get_int("idle_timeout_sec", c.idle_timeout_sec);
        c.max_payload = j.get_int("max_payload", c.max_payload);
        if (c.padding_min < 0) c.padding_min = 0;
        if (c.padding_max < c.padding_min) c.padding_max = c.padding_min;
        if (c.max_payload < 1024) c.max_payload = 1024;
        if (c.max_payload > 60000) c.max_payload = 60000;
        return c;
    }
};

// activate_net.exe — local-app transparent proxy → SOCKS5 on multilink/smartlink.
struct ActivateNetConfig {
    std::string socks5_host = "127.0.0.1";
    int socks5_port = 11080;
    int mss = 1200;
    int idle_timeout_sec = 180;
    int max_connections = 2048;
    int max_dns_inflight = 64;
    bool log_connections = true;

    static ActivateNetConfig load(const std::string& path) {
        JsonConfig j(path);
        ActivateNetConfig c;
        c.socks5_host = j.get_string("socks5_host", "");
        if (c.socks5_host.empty()) {
            c.socks5_host = j.get_string("socks5_bind_ip", "127.0.0.1");
        }
        int port = j.get_int("socks5_port", 0);
        if (port <= 0) port = j.get_int("socks5_bind_port", 11080);
        c.socks5_port = port;
        c.mss = j.get_int("mss", c.mss);
        c.idle_timeout_sec = j.get_int("idle_timeout_sec", c.idle_timeout_sec);
        c.max_connections = j.get_int("max_connections", c.max_connections);
        c.max_dns_inflight = j.get_int("max_dns_inflight", c.max_dns_inflight);
        c.log_connections = j.get_bool("log_connections", c.log_connections);
        if (c.mss < 200) c.mss = 200;
        if (c.idle_timeout_sec < 1) c.idle_timeout_sec = 180;
        if (c.max_connections < 1) c.max_connections = 2048;
        if (c.max_dns_inflight < 1) c.max_dns_inflight = 64;
        if (c.socks5_port < 1 || c.socks5_port > 65535) c.socks5_port = 11080;
        return c;
    }
};

// Plain local SOCKS5: CONNECT then direct TCP relay (no Vortex tunnel).
struct LocalConfig {
    std::string socks5_bind_ip = "127.0.0.1";
    int socks5_bind_port = 11080;
    int listen_backlog = 128;
    int idle_timeout_sec = 300;
    int max_payload = 32768;

    static LocalConfig load(const std::string& path) {
        JsonConfig j(path);
        LocalConfig c;
        c.socks5_bind_ip = j.get_string("socks5_bind_ip", c.socks5_bind_ip);
        c.socks5_bind_port = j.get_int("socks5_bind_port", c.socks5_bind_port);
        c.listen_backlog = j.get_int("listen_backlog", c.listen_backlog);
        c.idle_timeout_sec = j.get_int("idle_timeout_sec", c.idle_timeout_sec);
        c.max_payload = j.get_int("max_payload", c.max_payload);
        if (c.max_payload < 1024) c.max_payload = 1024;
        if (c.max_payload > 60000) c.max_payload = 60000;
        if (c.listen_backlog < 1) c.listen_backlog = 128;
        if (c.idle_timeout_sec < 1) c.idle_timeout_sec = 300;
        return c;
    }
};

struct SmartlinkConfig {
    std::string socks5_bind_ip = "127.0.0.1";
    int socks5_bind_port = 11080;
    std::string server_ip = "127.0.0.1";
    int server_port = 18888;
    std::string master_secret = "VortexSecureNetwork2026_KeyMix";
    int padding_min = 0;
    int padding_max = 128;
    int listen_backlog = 128;
    int idle_timeout_sec = 300;
    int max_payload = 32768;
    std::string rules_path = "config/rules.yaml";
    std::string geoip_cn = "config/geo/geoip-cn.txt";
    std::string geosite_cn = "config/geo/geosite-cn.txt";
    bool log_decisions = true;

    static SmartlinkConfig load(const std::string& path) {
        JsonConfig j(path);
        SmartlinkConfig c;
        c.socks5_bind_ip = j.get_string("socks5_bind_ip", c.socks5_bind_ip);
        c.socks5_bind_port = j.get_int("socks5_bind_port", c.socks5_bind_port);
        c.server_ip = j.get_string("server_ip", c.server_ip);
        c.server_port = j.get_int("server_port", c.server_port);
        c.master_secret = j.get_string("master_secret", c.master_secret);
        c.padding_min = j.get_int("padding_min", c.padding_min);
        c.padding_max = j.get_int("padding_max", c.padding_max);
        c.listen_backlog = j.get_int("listen_backlog", c.listen_backlog);
        c.idle_timeout_sec = j.get_int("idle_timeout_sec", c.idle_timeout_sec);
        c.max_payload = j.get_int("max_payload", c.max_payload);
        c.rules_path = j.get_string("rules_path", c.rules_path);
        c.geoip_cn = j.get_string("geoip_cn", c.geoip_cn);
        c.geosite_cn = j.get_string("geosite_cn", c.geosite_cn);
        c.log_decisions = j.get_bool("log_decisions", c.log_decisions);
        if (c.padding_min < 0) c.padding_min = 0;
        if (c.padding_max < c.padding_min) c.padding_max = c.padding_min;
        if (c.max_payload < 1024) c.max_payload = 1024;
        if (c.max_payload > 60000) c.max_payload = 60000;
        return c;
    }
};

// One named upstream in multilink.json ("link1", "link2", ...).
struct LinkEndpoint {
    std::string name;
    std::string server_ip = "127.0.0.1";
    int server_port = 18888;
    std::string master_secret = "VortexSecureNetwork2026_KeyMix";
    // If set, CONNECT is sent as CMD_VIA_PEER so the server relays through a peer.
    std::string peer_secret;
    int padding_min = 0;
    int padding_max = 128;
    int idle_timeout_sec = 300;
    int max_payload = 32768;
};

// peer.exe — dials into server, registers with peer_secret, exits traffic for VIA_PEER.
struct PeerConfig {
    std::string server_ip = "127.0.0.1";
    int server_port = 18888;
    std::string master_secret = "VortexSecureNetwork2026_KeyMix";
    std::string peer_secret = "test_peer_secret";
    int padding_min = 8;
    int padding_max = 64;
    int idle_timeout_sec = 300;
    int max_payload = 32768;
    int workers = 4; // parallel sessions registered on the server
    int reconnect_ms = 2000;

    static PeerConfig load(const std::string& path) {
        JsonConfig j(path);
        PeerConfig c;
        c.server_ip = j.get_string("server_ip", c.server_ip);
        c.server_port = j.get_int("server_port", c.server_port);
        c.master_secret = j.get_string("master_secret", c.master_secret);
        c.peer_secret = j.get_string("peer_secret", c.peer_secret);
        c.padding_min = j.get_int("padding_min", c.padding_min);
        c.padding_max = j.get_int("padding_max", c.padding_max);
        c.idle_timeout_sec = j.get_int("idle_timeout_sec", c.idle_timeout_sec);
        c.max_payload = j.get_int("max_payload", c.max_payload);
        c.workers = j.get_int("workers", c.workers);
        c.reconnect_ms = j.get_int("reconnect_ms", c.reconnect_ms);
        if (c.padding_min < 0) c.padding_min = 0;
        if (c.padding_max < c.padding_min) c.padding_max = c.padding_min;
        if (c.max_payload < 1024) c.max_payload = 1024;
        if (c.max_payload > 60000) c.max_payload = 60000;
        if (c.workers < 1) c.workers = 1;
        if (c.workers > 64) c.workers = 64;
        if (c.reconnect_ms < 200) c.reconnect_ms = 200;
        if (c.peer_secret.empty()) {
            throw std::runtime_error("peer_secret must be non-empty");
        }
        return c;
    }
};

struct MultilinkConfig {
    std::string socks5_bind_ip = "127.0.0.1";
    int socks5_bind_port = 11080;
    int listen_backlog = 128;
    std::map<std::string, LinkEndpoint> links;
    std::string default_link; // first declared link name
    std::string rules_path = "config/multirules.yaml";
    std::string geoip_cn = "config/geo/geoip-cn.txt";
    std::string geosite_cn = "config/geo/geosite-cn.txt";
    bool log_decisions = true;

    const LinkEndpoint* find_link(const std::string& name) const {
        auto it = links.find(name);
        if (it != links.end()) return &it->second;
        if (name.empty() || name == "proxy") {
            it = links.find(default_link);
            if (it != links.end()) return &it->second;
        }
        return nullptr;
    }

    static MultilinkConfig load(const std::string& path);

private:
    static void normalize_link(LinkEndpoint& c) {
        if (c.padding_min < 0) c.padding_min = 0;
        if (c.padding_max < c.padding_min) c.padding_max = c.padding_min;
        if (c.max_payload < 1024) c.max_payload = 1024;
        if (c.max_payload > 60000) c.max_payload = 60000;
    }

    static void skip_ws(const std::string& text, size_t& pos) {
        while (pos < text.size() && std::isspace(static_cast<unsigned char>(text[pos]))) ++pos;
    }

    static size_t matching_brace(const std::string& text, size_t open) {
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

    static std::string object_slice(const std::string& text, const std::string& key) {
        const std::string pattern = "\"" + key + "\"";
        size_t pos = text.find(pattern);
        if (pos == std::string::npos) return {};
        pos = text.find(':', pos + pattern.size());
        if (pos == std::string::npos) return {};
        ++pos;
        skip_ws(text, pos);
        if (pos >= text.size() || text[pos] != '{') return {};
        const size_t end = matching_brace(text, pos);
        if (end == std::string::npos) return {};
        return text.substr(pos, end - pos + 1);
    }

    static std::string get_string_in(const std::string& text, const std::string& key, const std::string& def) {
        const std::string pattern = "\"" + key + "\"";
        size_t pos = text.find(pattern);
        if (pos == std::string::npos) return def;
        pos = text.find(':', pos + pattern.size());
        if (pos == std::string::npos) return def;
        ++pos;
        skip_ws(text, pos);
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

    static int get_int_in(const std::string& text, const std::string& key, int def) {
        const std::string pattern = "\"" + key + "\"";
        size_t pos = text.find(pattern);
        if (pos == std::string::npos) return def;
        pos = text.find(':', pos + pattern.size());
        if (pos == std::string::npos) return def;
        ++pos;
        skip_ws(text, pos);
        try {
            size_t end = 0;
            return std::stoi(text.substr(pos), &end);
        } catch (...) {
            return def;
        }
    }

    static bool get_bool_in(const std::string& text, const std::string& key, bool def) {
        const std::string pattern = "\"" + key + "\"";
        size_t pos = text.find(pattern);
        if (pos == std::string::npos) return def;
        pos = text.find(':', pos + pattern.size());
        if (pos == std::string::npos) return def;
        ++pos;
        skip_ws(text, pos);
        if (text.compare(pos, 4, "true") == 0) return true;
        if (text.compare(pos, 5, "false") == 0) return false;
        return def;
    }

    static LinkEndpoint parse_link(const std::string& name, const std::string& body) {
        LinkEndpoint e;
        e.name = name;
        e.server_ip = get_string_in(body, "server_ip", e.server_ip);
        e.server_port = get_int_in(body, "server_port", e.server_port);
        e.master_secret = get_string_in(body, "master_secret", e.master_secret);
        e.peer_secret = get_string_in(body, "peer_secret", e.peer_secret);
        e.padding_min = get_int_in(body, "padding_min", e.padding_min);
        e.padding_max = get_int_in(body, "padding_max", e.padding_max);
        e.idle_timeout_sec = get_int_in(body, "idle_timeout_sec", e.idle_timeout_sec);
        e.max_payload = get_int_in(body, "max_payload", e.max_payload);
        normalize_link(e);
        return e;
    }

    static std::vector<std::pair<std::string, std::string>> child_objects(const std::string& obj) {
        std::vector<std::pair<std::string, std::string>> out;
        if (obj.size() < 2 || obj.front() != '{' || obj.back() != '}') return out;
        size_t pos = 1;
        while (pos + 1 < obj.size()) {
            skip_ws(obj, pos);
            if (pos >= obj.size() || obj[pos] == '}') break;
            if (obj[pos] != '"') break;
            ++pos;
            std::string key;
            while (pos < obj.size() && obj[pos] != '"') {
                if (obj[pos] == '\\' && pos + 1 < obj.size()) {
                    key.push_back(obj[pos + 1]);
                    pos += 2;
                } else {
                    key.push_back(obj[pos++]);
                }
            }
            if (pos >= obj.size() || obj[pos] != '"') break;
            ++pos;
            skip_ws(obj, pos);
            if (pos >= obj.size() || obj[pos] != ':') break;
            ++pos;
            skip_ws(obj, pos);
            if (pos >= obj.size() || obj[pos] != '{') break;
            const size_t end = matching_brace(obj, pos);
            if (end == std::string::npos) break;
            out.emplace_back(key, obj.substr(pos, end - pos + 1));
            pos = end + 1;
            skip_ws(obj, pos);
            if (pos < obj.size() && obj[pos] == ',') ++pos;
        }
        return out;
    }
};

inline MultilinkConfig MultilinkConfig::load(const std::string& path) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("Cannot open config: " + path);
    std::ostringstream ss;
    ss << in.rdbuf();
    const std::string text = ss.str();

    MultilinkConfig c;
    c.socks5_bind_ip = get_string_in(text, "socks5_bind_ip", c.socks5_bind_ip);
    c.socks5_bind_port = get_int_in(text, "socks5_bind_port", c.socks5_bind_port);
    c.listen_backlog = get_int_in(text, "listen_backlog", c.listen_backlog);
    c.rules_path = get_string_in(text, "rules_path", c.rules_path);
    c.geoip_cn = get_string_in(text, "geoip_cn", c.geoip_cn);
    c.geosite_cn = get_string_in(text, "geosite_cn", c.geosite_cn);
    c.log_decisions = get_bool_in(text, "log_decisions", c.log_decisions);

    const std::string multi = object_slice(text, "multilink");
    if (multi.empty()) throw std::runtime_error("multilink object missing in " + path);

    for (const auto& kv : child_objects(multi)) {
        LinkEndpoint ep = parse_link(kv.first, kv.second);
        if (c.default_link.empty()) c.default_link = ep.name;
        c.links.emplace(ep.name, std::move(ep));
    }
    if (c.links.empty()) throw std::runtime_error("No links in multilink config: " + path);
    return c;
}

#endif // VORTEX_CONFIG_HPP
