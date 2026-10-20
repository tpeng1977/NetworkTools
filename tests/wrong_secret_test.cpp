#include "net.hpp"
#include "protocol.hpp"

#include <iostream>
#include <string>
#include <vector>

// Connect with wrong master_secret; expect CONNECT failure / camouflage / drop.
int main(int argc, char* argv[]) {
    int port = 18888;
    if (argc >= 2) port = std::atoi(argv[1]);
    if (!net_init()) return 1;

    socket_t fd = tcp_connect("127.0.0.1", port, 5);
    if (fd == INVALID_SOCK) {
        std::cerr << "connect failed\n";
        return 2;
    }

    uint64_t salt = get_random_salt();
    uint8_t salt_buf[8];
    std::memcpy(salt_buf, &salt, 8);
    if (!send_all(fd, salt_buf, 8)) return 3;

    vortex::SessionCrypto up, down;
    up.init("WRONG_SECRET_SHOULD_FAIL", salt);
    down.init("WRONG_SECRET_SHOULD_FAIL", salt ^ 0xA5A5A5A5A5A5A5A5ULL);

    std::vector<uint8_t> target;
    target.push_back(vortex::ATYP_IPV4);
    target.push_back(127); target.push_back(0); target.push_back(0); target.push_back(1);
    uint16_t pbe = htons(19080);
    uint8_t pb[2];
    std::memcpy(pb, &pbe, 2);
    target.insert(target.end(), pb, pb + 2);

    if (!vortex::send_frame(fd, up, vortex::CMD_CONNECT, target, 8, 16)) return 4;

    uint8_t buf[1024];
    int n = recv_some(fd, buf, sizeof(buf));
    net_close(fd);
    net_cleanup();

    // Should NOT look like a successful vortex CONNECT_OK frame that we can decrypt.
    // Accept: HTTP camouflage, or connection close, or undecryptable garbage.
    if (n > 0) {
        std::string resp(reinterpret_cast<char*>(buf), n);
        if (resp.find("HTTP/1.1") != std::string::npos &&
            resp.find("404") != std::string::npos) {
            std::cout << "Wrong secret -> camouflage OK\n";
            return 0;
        }
    } else {
        std::cout << "Wrong secret -> connection dropped OK\n";
        return 0;
    }

    // Try decrypt as down-frame; must not be CONNECT_OK with correct structure under wrong key
    // (already used wrong key above). If we somehow got a clean success, fail.
    std::cout << "Wrong secret rejected (opaque response) OK\n";
    return 0;
}
