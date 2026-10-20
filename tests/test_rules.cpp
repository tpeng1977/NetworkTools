#include "rules.hpp"

#include <iostream>
#include <string>

static int g_fail = 0;

void expect(bool ok, const std::string& msg) {
    if (!ok) {
        std::cerr << "[FAIL] " << msg << "\n";
        ++g_fail;
    } else {
        std::cout << "[OK] " << msg << "\n";
    }
}

int main() {
    rules::Engine eng;
    try {
        eng.load("config/rules.yaml", "config/geo/geoip-cn.txt", "config/geo/geosite-cn.txt");
    } catch (const std::exception& e) {
        std::cerr << "[-] " << e.what() << "\n";
        return 1;
    }
    expect(eng.rule_count() >= 20, "loaded rules");
    expect(eng.cn_cidr_count() > 1000, "loaded CN CIDRs");
    expect(eng.cn_domain_count() > 1000, "loaded CN domains");

    auto d1 = eng.decide("www.google.com", false, 0, false);
    expect(d1.action == rules::Action::Proxy, "google -> PROXY");

    auto d2 = eng.decide("www.bilibili.com", false, 0, false);
    expect(d2.action == rules::Action::Direct, "bilibili -> DIRECT");

    auto d3 = eng.decide("api.github.com", false, 0, false);
    expect(d3.action == rules::Action::Proxy, "github keyword -> PROXY");

    auto d4 = eng.decide("openai.com", false, 0, false);
    expect(d4.action == rules::Action::Proxy, "openai -> PROXY");

    auto d5 = eng.decide("192.168.1.10", true, 0xC0A8010Au, false);
    expect(d5.action == rules::Action::Direct, "LAN IP -> DIRECT");

    // baidu.com is in geosite-cn; without DNS for GEOIP, GEOSITE should hit.
    auto d6 = eng.decide("www.baidu.com", false, 0, false);
    expect(d6.action == rules::Action::Direct, "baidu -> DIRECT");

    auto d7 = eng.decide("some-unknown-site.example", false, 0, false);
    expect(d7.action == rules::Action::Proxy, "unknown -> PROXY via MATCH");

    // CN IP 1.0.1.0/24 from the geoip list, as a literal IP target.
    auto d8 = eng.decide("1.0.1.1", true, 0x01000101u, false);
    expect(d8.action == rules::Action::Direct, "CN IP -> DIRECT via GEOIP");

    // Domain rules win even when the TCP target is already an IP (DNS cache).
    auto d9 = eng.decide("www.ieee.org", true, 0x01020304u, false);
    expect(d9.action == rules::Action::Direct && d9.matched.find("ieee.org") != std::string::npos,
           "ieee.org name + foreign IP -> DIRECT");
    auto d10 = eng.decide("www.google.com", true, 0x01000101u, false);
    expect(d10.action == rules::Action::Proxy && d10.matched.find("google.com") != std::string::npos,
           "google.com name + CN IP -> PROXY");

    if (g_fail) {
        std::cerr << g_fail << " failures\n";
        return 1;
    }
    std::cout << "All rule tests passed\n";
    return 0;
}
