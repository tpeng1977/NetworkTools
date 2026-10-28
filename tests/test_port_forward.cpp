#include "port_forward.hpp"

#include <cstdio>
#include <string>
#include <vector>

static int g_fail = 0;

static void expect(bool cond, const char* msg) {
    if (!cond) {
        std::fprintf(stderr, "FAIL: %s\n", msg);
        ++g_fail;
    } else {
        std::printf("PASS: %s\n", msg);
    }
}

int main() {
    // Single ports
    {
        auto a = vortex::expand_port_token("8888");
        expect(a.size() == 1 && a[0] == 8888, "expand single port");
    }
    // Range
    {
        auto a = vortex::expand_port_token("8891-8893");
        expect(a.size() == 3 && a[0] == 8891 && a[2] == 8893, "expand range");
    }
    // Mixed JSON array
    {
        const std::string arr = R"([8888, 8889, "8891-8893"])";
        auto ports = vortex::parse_port_list_json(arr, "test");
        expect(ports.size() == 5, "mixed list size");
        expect(ports[0] == 8888 && ports[1] == 8889 && ports[2] == 8891 && ports[4] == 8893,
               "mixed list values");
    }
    // Zip length mismatch
    {
        bool threw = false;
        try {
            vortex::zip_port_maps({1, 2}, {1}, "ctx");
        } catch (...) {
            threw = true;
        }
        expect(threw, "zip length mismatch throws");
    }
    // to_remote parse + map
    {
        const std::string obj = R"({
          "remote_ip": "0.0.0.0",
          "remote_ports": [18888, "18891-18892"],
          "local_ip": "127.0.0.1",
          "local_ports": [8888, "8891-8892"]
        })";
        auto spec = vortex::parse_to_remote_object(obj);
        expect(spec.listen_ip == "0.0.0.0" && spec.target_ip == "127.0.0.1", "to_remote ips");
        expect(spec.maps.size() == 3, "to_remote map count");
        expect(spec.maps[0].listen_port == 18888 && spec.maps[0].target_port == 8888,
               "to_remote pair0");
        expect(spec.maps[1].listen_port == 18891 && spec.maps[1].target_port == 8891,
               "to_remote pair1");
        expect(spec.maps[2].listen_port == 18892 && spec.maps[2].target_port == 8892,
               "to_remote pair2");
    }
    // to_local parse (listen=local, target=remote)
    {
        const std::string obj = R"({
          "remote_ip": "127.0.0.1",
          "remote_ports": [28888],
          "local_ip": "127.0.0.1",
          "local_ports": [38888]
        })";
        auto spec = vortex::parse_to_local_object(obj);
        expect(spec.listen_ip == "127.0.0.1" && spec.target_ip == "127.0.0.1", "to_local ips");
        expect(spec.maps.size() == 1 && spec.maps[0].listen_port == 38888 &&
                   spec.maps[0].target_port == 28888,
               "to_local pair");
    }
    // FWD_CONFIG round-trip
    {
        vortex::PortForwardSpec r;
        r.listen_ip = "0.0.0.0";
        r.target_ip = "127.0.0.1";
        r.maps.push_back({18888, 8888});
        vortex::PortForwardSpec l;
        l.listen_ip = "127.0.0.1";
        l.target_ip = "10.0.0.1";
        l.maps.push_back({38888, 28888});
        auto wire = vortex::build_fwd_config_payload(r, l, vortex::FWD_FLAG_UDP);
        expect(!wire.empty(), "fwd config build");
        vortex::PortForwardSpec r2, l2;
        uint8_t flags = 0;
        expect(vortex::parse_fwd_config_payload(wire, r2, l2, flags), "fwd config parse");
        expect(flags == vortex::FWD_FLAG_UDP, "fwd flags");
        expect(r2.maps.size() == 1 && r2.maps[0].listen_port == 18888 &&
                   r2.maps[0].target_port == 8888,
               "fwd remote round-trip");
        expect(l2.maps.size() == 1 && l2.maps[0].listen_port == 38888 &&
                   l2.target_ip == "10.0.0.1",
               "fwd local round-trip");
    }
    // connect target + UDP payload
    {
        auto tw = vortex::build_connect_target_host("127.0.0.1", 9);
        std::string h;
        uint16_t p = 0;
        expect(vortex::parse_connect_target(tw, h, p) && h == "127.0.0.1" && p == 9,
               "connect target ipv4");
        const uint8_t data[] = {1, 2, 3};
        std::string ah = "127.0.0.1";
        auto up = vortex::build_udp_data_payload(42, &ah, 9, data, 3);
        uint32_t sid = 0;
        bool has = false;
        std::string rh;
        uint16_t rp = 0;
        std::vector<uint8_t> pl;
        expect(vortex::parse_udp_data_payload(up, sid, has, rh, rp, pl), "udp parse");
        expect(sid == 42 && has && rh == "127.0.0.1" && rp == 9 && pl.size() == 3 && pl[2] == 3,
               "udp fields");
    }
    expect(vortex::CMD_FWD_CONFIG == 0x08 && vortex::CMD_UDP_DATA == 0x09 &&
               vortex::CMD_UDP_CLOSE == 0x0A,
           "fwd cmd ids");

    // mismatch remote/local lengths
    {
        bool threw = false;
        try {
            const std::string obj = R"({
              "remote_ip":"0.0.0.0","remote_ports":[1,2],
              "local_ip":"127.0.0.1","local_ports":[3]
            })";
            vortex::parse_to_remote_object(obj);
        } catch (...) {
            threw = true;
        }
        expect(threw, "to_remote length mismatch throws");
    }

    if (g_fail) {
        std::fprintf(stderr, "%d failure(s)\n", g_fail);
        return 1;
    }
    std::printf("All port-forward unit tests passed\n");
    return 0;
}
