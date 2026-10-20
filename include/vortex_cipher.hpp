#ifndef VORTEX_CIPHER_HPP
#define VORTEX_CIPHER_HPP

// VortexCipher: autonomous ARX stream cipher (ChaCha-inspired quarter-round).
// Each session direction uses an independent instance; packet_seq starts at 0.

#include <cstdint>
#include <cstring>
#include <random>
#include <string>
#include <vector>
class VortexCipher {
private:
    uint32_t state_[4];

    static inline uint32_t rotl(uint32_t value, int shift) {
        return (value << shift) | (value >> (32 - shift));
    }

    static void quarter_round(uint32_t& a, uint32_t& b, uint32_t& c, uint32_t& d) {
        a += b; d ^= a; d = rotl(d, 16);
        c += d; b ^= c; b = rotl(b, 12);
        a += b; d ^= a; d = rotl(d, 8);
        c += d; b ^= c; b = rotl(b, 7);
    }

    void generate_block(uint8_t output[16], uint64_t counter) const {
        uint32_t working[4] = {
            state_[0],
            state_[1],
            state_[2],
            state_[3] ^ static_cast<uint32_t>(counter) ^
                static_cast<uint32_t>(counter >> 32)
        };
        for (int i = 0; i < 8; ++i) {
            quarter_round(working[0], working[1], working[2], working[3]);
        }
        working[0] += state_[0];
        working[1] += state_[1];
        working[2] += state_[2];
        working[3] += state_[3] ^ static_cast<uint32_t>(counter);
        std::memcpy(output, working, 16);
    }

public:
    VortexCipher() : state_{0, 0, 0, 0} {}

    VortexCipher(const std::string& key, uint64_t salt) {
        state_[0] = 0x61707865u;
        state_[1] = 0x3320646eu;
        state_[2] = 0x79627465u;
        state_[3] = static_cast<uint32_t>(salt) ^ 0x9e3779b9u;
        state_[0] ^= static_cast<uint32_t>(salt >> 32);
        for (size_t i = 0; i < key.size(); ++i) {
            state_[i % 4] ^= static_cast<uint32_t>(
                static_cast<uint8_t>(key[i])) << ((i % 4) * 8);
        }
    }

    void crypt(uint8_t* data, size_t len, uint64_t& packet_seq) {
        uint8_t key_stream[16];
        for (size_t i = 0; i < len; ++i) {
            if (i % 16 == 0) {
                generate_block(key_stream, packet_seq++);
            }
            data[i] ^= key_stream[i % 16];
        }
    }

    void crypt(std::vector<uint8_t>& data, uint64_t& packet_seq) {
        if (!data.empty()) {
            crypt(data.data(), data.size(), packet_seq);
        }
    }
};

inline uint64_t get_random_salt() {
    std::random_device rd;
    std::mt19937_64 gen(rd());
    return gen();
}

inline void fill_random_bytes(uint8_t* dest, size_t len) {
    static thread_local std::mt19937 rng{std::random_device{}()};
    for (size_t i = 0; i < len; ++i) {
        dest[i] = static_cast<uint8_t>(rng() & 0xFF);
    }
}

#endif // VORTEX_CIPHER_HPP
