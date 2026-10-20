#include "config.hpp"
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
    MultilinkConfig cfg;
    try {
        cfg = MultilinkConfig::load("config/multilink.json");
    } catch (const std::exception& e) {
        std::cerr << "[-] config: " << e.what() << "\n";
        return 1;
    }

    expect(cfg.links.size() == 2, "two links loaded");
    expect(cfg.default_link == "link1", "default link is link1");
    expect(cfg.socks5_bind_port == 11080, "socks5 bind port");
    expect(cfg.rules_path == "config/multirules.yaml", "rules path");

    const auto* l1 = cfg.find_link("link1");
    const auto* l2 = cfg.find_link("link2");
    expect(l1 && l1->server_ip == "69.194.11.7", "link1 upstream");
    expect(l2 && l2->server_ip == "38.47.99.237", "link2 upstream");
    expect(cfg.find_link("proxy") == l1, "proxy alias -> default link1");
    expect(cfg.find_link("missing") == nullptr, "unknown link is null");

    rules::Engine eng;
    try {
        eng.load(cfg.rules_path, cfg.geoip_cn, cfg.geosite_cn);
    } catch (const std::exception& e) {
        std::cerr << "[-] rules: " << e.what() << "\n";
        return 1;
    }
    expect(eng.rule_count() >= 20, "loaded multirules");

    auto d1 = eng.decide("www.google.com", false, 0, false);
    expect(d1.action == rules::Action::Proxy && d1.outbound == "link1",
           "google -> link1");
    expect(rules::decision_name(d1) == "link1", "decision_name link1");

    auto d2 = eng.decide("api.github.com", false, 0, false);
    expect(d2.action == rules::Action::Proxy && d2.outbound == "link1",
           "github -> link1");

    auto d3 = eng.decide("www.test-ipv6.com", false, 0, false);
    expect(d3.action == rules::Action::Proxy && d3.outbound == "link2",
           "test-ipv6 -> link2");

    auto d4 = eng.decide("api.bybit.com", false, 0, false);
    expect(d4.action == rules::Action::Proxy && d4.outbound == "link2",
           "bybit -> link2");

    auto d5 = eng.decide("polymarket.com", false, 0, false);
    expect(d5.action == rules::Action::Proxy && d5.outbound == "link2",
           "polymarket -> link2");

    auto d6 = eng.decide("www.bilibili.com", false, 0, false);
    expect(d6.action == rules::Action::Direct, "bilibili -> DIRECT");
    expect(rules::decision_name(d6) == "DIRECT", "decision_name DIRECT");

    auto d7 = eng.decide("some-unknown-site.example", false, 0, false);
    expect(d7.action == rules::Action::Proxy && d7.outbound == "link1",
           "unknown -> MATCH link1");

    // Legacy rules.yaml still maps PROXY.
    rules::Engine legacy;
    try {
        legacy.load("config/rules.yaml", cfg.geoip_cn, cfg.geosite_cn);
    } catch (const std::exception& e) {
        std::cerr << "[-] legacy rules: " << e.what() << "\n";
        return 1;
    }
    auto d8 = legacy.decide("www.google.com", false, 0, false);
    expect(d8.action == rules::Action::Proxy && d8.outbound == "proxy",
           "legacy PROXY outbound name");
    expect(rules::decision_name(d8) == "PROXY", "legacy decision_name PROXY");

    if (g_fail) {
        std::cerr << g_fail << " failures\n";
        return 1;
    }
    std::cout << "All multilink tests passed\n";
    return 0;
}
