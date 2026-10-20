#ifndef VORTEX_RULES_HPP
#define VORTEX_RULES_HPP

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_set>
#include <vector>

#ifdef _WIN32
#  ifndef WIN32_LEAN_AND_MEAN
#    define WIN32_LEAN_AND_MEAN
#  endif
#  include <winsock2.h>
#  include <ws2tcpip.h>
#else
#  include <arpa/inet.h>
#  include <netdb.h>
#  include <sys/socket.h>
#endif

// Clash-style rule list: first match wins.
// Actions: DIRECT, PROXY, or a named outbound (e.g. link1 / link2).
namespace rules {

enum class Action { Proxy, Direct };

enum class Kind {
    IpCidr,
    Domain,
    DomainSuffix,
    DomainKeyword,
    GeoIp,
    GeoSite,
    Match
};

struct Cidr {
    uint32_t network = 0; // host order
    uint32_t mask = 0;    // host order
};

struct Rule {
    Kind kind = Kind::Match;
    Action action = Action::Proxy;
    std::string outbound; // when Proxy: "proxy" or named link (link1, ...)
    bool no_resolve = false;
    Cidr cidr{};
    std::string value; // domain / keyword / geo code / geosite name
};

inline std::string to_lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

inline std::string trim(std::string s) {
    auto not_space = [](unsigned char c) { return !std::isspace(c); };
    s.erase(s.begin(), std::find_if(s.begin(), s.end(), not_space));
    s.erase(std::find_if(s.rbegin(), s.rend(), not_space).base(), s.end());
    return s;
}

inline bool parse_cidr(const std::string& text, Cidr& out) {
    const auto slash = text.find('/');
    if (slash == std::string::npos) return false;
    const std::string ip = text.substr(0, slash);
    int prefix = 0;
    try {
        prefix = std::stoi(text.substr(slash + 1));
    } catch (...) {
        return false;
    }
    if (prefix < 0 || prefix > 32) return false;
    in_addr a{};
    if (inet_pton(AF_INET, ip.c_str(), &a) != 1) return false;
    out.network = ntohl(a.s_addr);
    out.mask = prefix == 0 ? 0u : (0xFFFFFFFFu << (32 - prefix));
    out.network &= out.mask;
    return true;
}

inline bool cidr_contains(const Cidr& c, uint32_t host_order_ip) {
    return (host_order_ip & c.mask) == c.network;
}

inline bool is_private_ip(uint32_t host_order_ip) {
    const uint8_t b0 = static_cast<uint8_t>((host_order_ip >> 24) & 0xFF);
    const uint8_t b1 = static_cast<uint8_t>((host_order_ip >> 16) & 0xFF);
    if (b0 == 10) return true;
    if (b0 == 127) return true;
    if (b0 == 192 && b1 == 168) return true;
    if (b0 == 169 && b1 == 254) return true;
    if (b0 == 172 && b1 >= 16 && b1 <= 31) return true;
    if (b0 == 100 && b1 >= 64 && b1 <= 127) return true; // CGNAT
    if (b0 == 0) return true;
    return false;
}

inline bool load_cidr_file(const std::string& path, std::vector<Cidr>& out) {
    std::ifstream in(path);
    if (!in) return false;
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        Cidr c;
        if (parse_cidr(line, c)) out.push_back(c);
    }
    return true;
}

inline bool load_domain_file(const std::string& path, std::unordered_set<std::string>& out) {
    std::ifstream in(path);
    if (!in) return false;
    std::string line;
    while (std::getline(in, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';') continue;
        // Accept full / domain: / regexp: lines from Loyalsoldier lists.
        if (line.rfind("regexp:", 0) == 0) continue;
        if (line.rfind("full:", 0) == 0) line = line.substr(5);
        else if (line.rfind("domain:", 0) == 0) line = line.substr(7);
        line = to_lower(trim(line));
        if (!line.empty()) out.insert(std::move(line));
    }
    return true;
}

inline void parse_outbound(const std::string& s, Action& action, std::string& outbound) {
    const std::string u = to_lower(trim(s));
    if (u == "direct") {
        action = Action::Direct;
        outbound.clear();
        return;
    }
    action = Action::Proxy;
    // "proxy" keeps the legacy single-upstream name; anything else is a link id.
    outbound = u.empty() ? "proxy" : u;
}

inline bool parse_rule_line(std::string line, Rule& out) {
    line = trim(line);
    if (line.empty()) return false;
    if (line[0] == '#') return false;
    if (line.rfind("- ", 0) == 0) line = trim(line.substr(2));
    else if (line[0] == '-') line = trim(line.substr(1));

    std::vector<std::string> parts;
    {
        std::stringstream ss(line);
        std::string item;
        while (std::getline(ss, item, ',')) parts.push_back(trim(item));
    }
    if (parts.empty()) return false;

    const std::string type = to_lower(parts[0]);
    out.no_resolve = false;
    for (size_t i = 1; i < parts.size(); ++i) {
        if (to_lower(parts[i]) == "no-resolve") out.no_resolve = true;
    }

    auto set_action_at = [&](size_t idx) {
        if (idx < parts.size()) parse_outbound(parts[idx], out.action, out.outbound);
        else {
            out.action = Action::Proxy;
            out.outbound = "proxy";
        }
    };

    if (type == "match") {
        out.kind = Kind::Match;
        set_action_at(1);
        return true;
    }
    if (parts.size() < 3) return false;

    if (type == "ip-cidr") {
        out.kind = Kind::IpCidr;
        if (!parse_cidr(parts[1], out.cidr)) return false;
        set_action_at(2);
        return true;
    }
    if (type == "domain") {
        out.kind = Kind::Domain;
        out.value = to_lower(parts[1]);
        set_action_at(2);
        return true;
    }
    if (type == "domain-suffix") {
        out.kind = Kind::DomainSuffix;
        out.value = to_lower(parts[1]);
        set_action_at(2);
        return true;
    }
    if (type == "domain-keyword") {
        out.kind = Kind::DomainKeyword;
        out.value = to_lower(parts[1]);
        set_action_at(2);
        return true;
    }
    if (type == "geoip") {
        out.kind = Kind::GeoIp;
        out.value = to_lower(parts[1]);
        set_action_at(2);
        return true;
    }
    if (type == "geosite") {
        out.kind = Kind::GeoSite;
        out.value = to_lower(parts[1]);
        set_action_at(2);
        return true;
    }
    return false;
}

inline bool load_rules_yaml(const std::string& path, std::vector<Rule>& out) {
    std::ifstream in(path);
    if (!in) throw std::runtime_error("Cannot open rules: " + path);
    std::string line;
    bool in_rules = false;
    while (std::getline(in, line)) {
        const std::string raw = line;
        const std::string t = trim(line);
        if (t.empty() || t[0] == '#') continue;
        if (!in_rules) {
            if (t.rfind("rules:", 0) == 0) in_rules = true;
            continue;
        }
        Rule r;
        if (parse_rule_line(raw, r)) out.push_back(r);
    }
    if (out.empty()) throw std::runtime_error("No rules loaded from " + path);
    return true;
}

struct Decision {
    Action action = Action::Proxy;
    std::string outbound; // when Proxy: "proxy" or named link
    std::string matched; // human-readable rule tag
};

class Engine {
public:
    void load(const std::string& rules_path,
              const std::string& geoip_cn_path,
              const std::string& geosite_cn_path) {
        rules_.clear();
        cn_cidrs_.clear();
        cn_domains_.clear();
        load_rules_yaml(rules_path, rules_);
        if (!geoip_cn_path.empty()) {
            if (!load_cidr_file(geoip_cn_path, cn_cidrs_)) {
                throw std::runtime_error("Cannot open geoip list: " + geoip_cn_path);
            }
        }
        if (!geosite_cn_path.empty()) {
            if (!load_domain_file(geosite_cn_path, cn_domains_)) {
                throw std::runtime_error("Cannot open geosite list: " + geosite_cn_path);
            }
        }
    }

    size_t rule_count() const { return rules_.size(); }
    size_t cn_cidr_count() const { return cn_cidrs_.size(); }
    size_t cn_domain_count() const { return cn_domains_.size(); }

    // host: domain or dotted IPv4. resolved_ip_host: optional already-resolved IPv4 (host order).
    // has_ip: true if resolved_ip_host is valid.
    Decision decide(const std::string& host_in,
                    bool has_ip,
                    uint32_t resolved_ip_host,
                    bool allow_dns_resolve) const {
        const std::string host = to_lower(trim(host_in));
        bool ip_known = has_ip;
        uint32_t ip = resolved_ip_host;

        in_addr literal{};
        const bool host_is_ip = inet_pton(AF_INET, host.c_str(), &literal) == 1;
        if (!ip_known && host_is_ip) {
            ip_known = true;
            ip = ntohl(literal.s_addr);
        }
        // A cached DNS name must still match DOMAIN / GEOSITE rules even when
        // the SOCKS target is already an IPv4 address.
        const bool is_domain = !host.empty() && !host_is_ip;

        for (const Rule& r : rules_) {
            switch (r.kind) {
            case Kind::Match:
                return {r.action, r.outbound, "MATCH"};
            case Kind::Domain:
                if (is_domain && host == r.value) {
                    return {r.action, r.outbound, "DOMAIN," + r.value};
                }
                break;
            case Kind::DomainSuffix:
                if (is_domain && domain_suffix_match(host, r.value)) {
                    return {r.action, r.outbound, "DOMAIN-SUFFIX," + r.value};
                }
                break;
            case Kind::DomainKeyword:
                if (is_domain && host.find(r.value) != std::string::npos) {
                    return {r.action, r.outbound, "DOMAIN-KEYWORD," + r.value};
                }
                break;
            case Kind::GeoSite:
                if (is_domain && r.value == "cn" && geosite_cn_match(host)) {
                    return {r.action, r.outbound, "GEOSITE,cn"};
                }
                break;
            case Kind::IpCidr: {
                if (!ensure_ip(is_domain, r.no_resolve, allow_dns_resolve, host, ip_known, ip)) {
                    break;
                }
                if (ip_known && cidr_contains(r.cidr, ip)) {
                    return {r.action, r.outbound, "IP-CIDR"};
                }
                break;
            }
            case Kind::GeoIp: {
                if (!ensure_ip(is_domain, r.no_resolve, allow_dns_resolve, host, ip_known, ip)) {
                    break;
                }
                if (!ip_known) break;
                if (r.value == "private" && is_private_ip(ip)) {
                    return {r.action, r.outbound, "GEOIP,private"};
                }
                if (r.value == "cn" && geoip_cn_match(ip)) {
                    return {r.action, r.outbound, "GEOIP,CN"};
                }
                break;
            }
            }
        }
        return {Action::Proxy, "proxy", "MATCH(default)"};
    }

    bool resolve_ipv4(const std::string& host, uint32_t& out_host_order) const {
        in_addr literal{};
        if (inet_pton(AF_INET, host.c_str(), &literal) == 1) {
            out_host_order = ntohl(literal.s_addr);
            return true;
        }
        addrinfo hints{};
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_STREAM;
        addrinfo* res = nullptr;
        if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || !res) return false;
        bool ok = false;
        for (addrinfo* p = res; p; p = p->ai_next) {
            if (p->ai_family != AF_INET || !p->ai_addr) continue;
            auto* sa = reinterpret_cast<sockaddr_in*>(p->ai_addr);
            out_host_order = ntohl(sa->sin_addr.s_addr);
            ok = true;
            break;
        }
        freeaddrinfo(res);
        return ok;
    }

private:
    std::vector<Rule> rules_;
    std::vector<Cidr> cn_cidrs_;
    std::unordered_set<std::string> cn_domains_;

    static bool domain_suffix_match(const std::string& host, const std::string& suffix) {
        if (host == suffix) return true;
        if (host.size() <= suffix.size()) return false;
        if (host.compare(host.size() - suffix.size(), suffix.size(), suffix) != 0) return false;
        return host[host.size() - suffix.size() - 1] == '.';
    }

    bool geosite_cn_match(const std::string& host) const {
        if (cn_domains_.empty()) return false;
        std::string cur = host;
        while (true) {
            if (cn_domains_.count(cur)) return true;
            const auto dot = cur.find('.');
            if (dot == std::string::npos) break;
            cur = cur.substr(dot + 1);
        }
        return false;
    }

    bool geoip_cn_match(uint32_t host_order_ip) const {
        for (const Cidr& c : cn_cidrs_) {
            if (cidr_contains(c, host_order_ip)) return true;
        }
        return false;
    }

    bool ensure_ip(bool is_domain,
                   bool no_resolve,
                   bool allow_dns_resolve,
                   const std::string& host,
                   bool& ip_known,
                   uint32_t& ip) const {
        if (ip_known) return true;
        if (!is_domain) return false;
        if (no_resolve || !allow_dns_resolve) return false;
        return resolve_ipv4(host, ip) ? (ip_known = true, true) : false;
    }
};

inline const char* action_name(Action a) {
    return a == Action::Direct ? "DIRECT" : "PROXY";
}

inline std::string decision_name(const Decision& d) {
    if (d.action == Action::Direct) return "DIRECT";
    if (!d.outbound.empty() && d.outbound != "proxy") return d.outbound;
    return "PROXY";
}

} // namespace rules

#endif // VORTEX_RULES_HPP
