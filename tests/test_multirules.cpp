#include "config.hpp"
#include "rules.hpp"

#include <iostream>
#include <string>

#ifdef _WIN32
#  include <winsock2.h>
#endif

static int g_fail = 0;

static void expect(bool ok, const std::string& msg) {
    if (!ok) {
        std::cerr << "[FAIL] " << msg << "\n";
        ++g_fail;
    } else {
        std::cout << "[OK] " << msg << "\n";
    }
}

int main() {
#ifdef _WIN32
    WSADATA wsa{};
    WSAStartup(MAKEWORD(2, 2), &wsa);
#endif

    MultilinkConfig cfg;
    try {
        cfg = MultilinkConfig::load("config/multilink.json");
    } catch (const std::exception& e) {
        std::cerr << "[-] config: " << e.what() << "\n";
        return 1;
    }
    rules::Engine eng;
    try {
        eng.load(cfg.rules_path, cfg.geoip_cn, cfg.geosite_cn);
    } catch (const std::exception& e) {
        std::cerr << "[-] rules: " << e.what() << "\n";
        return 1;
    }

    std::cout << "rules_path=" << cfg.rules_path << " count=" << eng.rule_count()
              << " cn_cidr=" << eng.cn_cidr_count()
              << " cn_dom=" << eng.cn_domain_count() << "\n";
    expect(cfg.rules_path.find("multirules") != std::string::npos, "uses multirules.yaml");
    expect(eng.rule_count() >= 30, "multirules loaded enough entries");
    expect(cfg.find_link("link1") != nullptr, "link1 present");
    expect(cfg.find_link("link2") != nullptr, "link2 present");

    struct Case {
        const char* host;
        const char* expect_out;
        const char* match_sub;
    };
    const Case cases[] = {
        {"www.google.com", "link1", "google.com"},
        {"youtube.com", "link1", "youtube.com"},
        {"www.youtube.com", "link1", "youtube.com"},
        {"m.youtube.com", "link1", "youtube.com"},
        {"i.ytimg.com", "link1", "ytimg.com"},
        {"rr5---sn-a5meknds.googlevideo.com", "link1", "googlevideo.com"},
        {"www.gstatic.com", "link1", "gstatic.com"},
        {"fonts.googleapis.com", "link1", "googleapis.com"},
        {"www.googletagmanager.com", "link1", "googletagmanager.com"},
        {"ad.doubleclick.net", "link1", "doubleclick.net"},
        {"web.mit.edu", "link1", "MATCH"},
        {"api.github.com", "link1", "github"},
        {"ipv4.lookup.test-ipv6.com", "link2", "test-ipv6.com"},
        {"www.baidu.com", "DIRECT", "baidu.com"},
        {"www.bilibili.com", "DIRECT", "bilibili.com"},
        {"www.qq.com", "DIRECT", "qq.com"},
        {"www.nature.com", "DIRECT", "nature.com"},
        {"ieeexplore.ieee.org", "DIRECT", "ieee"},
    };

    for (const auto& c : cases) {
        const auto d = eng.decide(c.host, false, 0, false);
        const std::string out = rules::decision_name(d);
        const bool ok = out == c.expect_out &&
                        d.matched.find(c.match_sub) != std::string::npos;
        expect(ok, std::string(c.host) + " -> " + out + " (" + d.matched + ") expect " +
                       c.expect_out + " / " + c.match_sub);
    }

    // Domain rule must win over a poisoned CN IP.
    {
        const auto d = eng.decide("www.google.com", true, 0x01000101u, false);
        expect(rules::decision_name(d) == "link1" &&
                   d.matched.find("google.com") != std::string::npos,
               "google.com + poisoned CN IP -> link1 by domain");
    }
    {
        const auto d = eng.decide("www.youtube.com", true, 0x01000101u, false);
        expect(rules::decision_name(d) == "link1",
               "youtube.com + poisoned CN IP -> link1");
    }

    // Without domain, GEOIP,CN (no-resolve) still directs real CN IPs.
    {
        const auto d = eng.decide("1.0.1.1", true, 0x01000101u, false);
        expect(d.action == rules::Action::Direct && d.matched.find("GEOIP") != std::string::npos,
               "literal CN IP -> DIRECT GEOIP");
    }

    // allow_dns_resolve=true must not be required for domain decisions.
    {
        const auto a = eng.decide("www.gstatic.com", false, 0, false);
        const auto b = eng.decide("www.gstatic.com", false, 0, true);
        expect(rules::decision_name(a) == "link1" && rules::decision_name(b) == "link1",
               "gstatic link1 with or without DNS resolve flag");
    }

    if (g_fail) {
        std::cerr << g_fail << " failures\n";
        return 1;
    }
    std::cout << "All multirules tests passed\n";
    return 0;
}
