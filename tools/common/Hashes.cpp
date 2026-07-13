#include "Hashes.h"

#include <CommonCrypto/CommonDigest.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <stdexcept>

namespace address_tools {
namespace {

uint32_t rotate_left32(uint32_t value, unsigned int shift) {
    return (value << shift) | (value >> (32u - shift));
}

uint64_t rotate_right64(uint64_t value, unsigned int shift) {
    return (value >> shift) | (value << (64u - shift));
}

uint64_t load_be64(const uint8_t* input) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) {
        value = (value << 8) | input[i];
    }
    return value;
}

uint64_t load_le64(const uint8_t* input) {
    uint64_t value = 0;
    for (size_t i = 0; i < 8; ++i) {
        value |= static_cast<uint64_t>(input[i]) << (i * 8);
    }
    return value;
}

void store_be64(uint8_t* output, uint64_t value) {
    for (size_t i = 0; i < 8; ++i) {
        output[7 - i] = static_cast<uint8_t>(value >> (i * 8));
    }
}

void store_le64(uint8_t* output, uint64_t value) {
    for (size_t i = 0; i < 8; ++i) {
        output[i] = static_cast<uint8_t>(value >> (i * 8));
    }
}

void sha512_256_transform(uint64_t state[8], const uint8_t block[128]) {
    static constexpr uint64_t k[80] = {
        0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL,
        0xe9b5dba58189dbbcULL, 0x3956c25bf348b538ULL, 0x59f111f1b605d019ULL,
        0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL, 0xd807aa98a3030242ULL,
        0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
        0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL,
        0xc19bf174cf692694ULL, 0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL,
        0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL, 0x2de92c6f592b0275ULL,
        0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
        0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL,
        0xbf597fc7beef0ee4ULL, 0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL,
        0x06ca6351e003826fULL, 0x142929670a0e6e70ULL, 0x27b70a8546d22ffcULL,
        0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
        0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL,
        0x92722c851482353bULL, 0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL,
        0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL, 0xd192e819d6ef5218ULL,
        0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
        0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL,
        0x34b0bcb5e19b48a8ULL, 0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL,
        0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL, 0x748f82ee5defb2fcULL,
        0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
        0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL,
        0xc67178f2e372532bULL, 0xca273eceea26619cULL, 0xd186b8c721c0c207ULL,
        0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL, 0x06f067aa72176fbaULL,
        0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
        0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL,
        0x431d67c49c100d4cULL, 0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL,
        0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL};

    uint64_t words[80];
    for (size_t i = 0; i < 16; ++i) {
        words[i] = load_be64(block + i * 8);
    }
    for (size_t i = 16; i < 80; ++i) {
        const uint64_t s0 = rotate_right64(words[i - 15], 1) ^
                            rotate_right64(words[i - 15], 8) ^ (words[i - 15] >> 7);
        const uint64_t s1 = rotate_right64(words[i - 2], 19) ^
                            rotate_right64(words[i - 2], 61) ^ (words[i - 2] >> 6);
        words[i] = words[i - 16] + s0 + words[i - 7] + s1;
    }

    uint64_t a = state[0];
    uint64_t b = state[1];
    uint64_t c = state[2];
    uint64_t d = state[3];
    uint64_t e = state[4];
    uint64_t f = state[5];
    uint64_t g = state[6];
    uint64_t h = state[7];
    for (size_t i = 0; i < 80; ++i) {
        const uint64_t s1 = rotate_right64(e, 14) ^ rotate_right64(e, 18) ^
                            rotate_right64(e, 41);
        const uint64_t choice = (e & f) ^ (~e & g);
        const uint64_t temp1 = h + s1 + choice + k[i] + words[i];
        const uint64_t s0 = rotate_right64(a, 28) ^ rotate_right64(a, 34) ^
                            rotate_right64(a, 39);
        const uint64_t majority = (a & b) ^ (a & c) ^ (b & c);
        const uint64_t temp2 = s0 + majority;
        h = g;
        g = f;
        f = e;
        e = d + temp1;
        d = c;
        c = b;
        b = a;
        a = temp1 + temp2;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

uint32_t ripemd_function(size_t round, uint32_t x, uint32_t y, uint32_t z) {
    if (round < 16) return x ^ y ^ z;
    if (round < 32) return (x & y) | (~x & z);
    if (round < 48) return (x | ~y) ^ z;
    if (round < 64) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
}

uint32_t ripemd_left_constant(size_t round) {
    if (round < 16) return 0x00000000u;
    if (round < 32) return 0x5a827999u;
    if (round < 48) return 0x6ed9eba1u;
    if (round < 64) return 0x8f1bbcdcu;
    return 0xa953fd4eu;
}

uint32_t ripemd_right_constant(size_t round) {
    if (round < 16) return 0x50a28be6u;
    if (round < 32) return 0x5c4dd124u;
    if (round < 48) return 0x6d703ef3u;
    if (round < 64) return 0x7a6d76e9u;
    return 0x00000000u;
}

void ripemd_transform(uint32_t state[5], const uint8_t block[64]) {
    static constexpr uint8_t r1[80] = {
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
        3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
        1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
        4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13};
    static constexpr uint8_t r2[80] = {
        5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
        6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
        15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
        8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
        12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11};
    static constexpr uint8_t s1[80] = {
        11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
        7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
        11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
        11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
        9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6};
    static constexpr uint8_t s2[80] = {
        8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
        9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
        9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
        15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
        8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11};

    uint32_t words[16];
    for (size_t i = 0; i < 16; ++i) {
        words[i] = static_cast<uint32_t>(block[i * 4]) |
                   (static_cast<uint32_t>(block[i * 4 + 1]) << 8) |
                   (static_cast<uint32_t>(block[i * 4 + 2]) << 16) |
                   (static_cast<uint32_t>(block[i * 4 + 3]) << 24);
    }

    uint32_t al = state[0], bl = state[1], cl = state[2], dl = state[3], el = state[4];
    uint32_t ar = al, br = bl, cr = cl, dr = dl, er = el;
    for (size_t i = 0; i < 80; ++i) {
        uint32_t next = rotate_left32(al + ripemd_function(i, bl, cl, dl) + words[r1[i]] +
                                          ripemd_left_constant(i),
                                      s1[i]) +
                        el;
        al = el;
        el = dl;
        dl = rotate_left32(cl, 10);
        cl = bl;
        bl = next;

        next = rotate_left32(ar + ripemd_function(79 - i, br, cr, dr) + words[r2[i]] +
                                  ripemd_right_constant(i),
                              s2[i]) +
               er;
        ar = er;
        er = dr;
        dr = rotate_left32(cr, 10);
        cr = br;
        br = next;
    }

    const uint32_t temporary = state[1] + cl + dr;
    state[1] = state[2] + dl + er;
    state[2] = state[3] + el + ar;
    state[3] = state[4] + al + br;
    state[4] = state[0] + bl + cr;
    state[0] = temporary;
}

void blake2b_compress(uint64_t state[8],
                      const uint8_t block[128],
                      uint64_t count_low,
                      uint64_t count_high,
                      bool final_block) {
    static constexpr uint64_t iv[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
        0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
    static constexpr uint8_t sigma[12][16] = {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
        {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
        {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
        {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
        {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
        {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
        {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
        {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
        {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}};

    uint64_t message[16];
    uint64_t work[16];
    for (size_t i = 0; i < 16; ++i) message[i] = load_le64(block + i * 8);
    for (size_t i = 0; i < 8; ++i) {
        work[i] = state[i];
        work[i + 8] = iv[i];
    }
    work[12] ^= count_low;
    work[13] ^= count_high;
    if (final_block) work[14] = ~work[14];

    auto mix = [&](size_t a, size_t b, size_t c, size_t d, uint64_t x, uint64_t y) {
        work[a] = work[a] + work[b] + x;
        work[d] = rotate_right64(work[d] ^ work[a], 32);
        work[c] += work[d];
        work[b] = rotate_right64(work[b] ^ work[c], 24);
        work[a] = work[a] + work[b] + y;
        work[d] = rotate_right64(work[d] ^ work[a], 16);
        work[c] += work[d];
        work[b] = rotate_right64(work[b] ^ work[c], 63);
    };

    for (size_t round = 0; round < 12; ++round) {
        const uint8_t* s = sigma[round];
        mix(0, 4, 8, 12, message[s[0]], message[s[1]]);
        mix(1, 5, 9, 13, message[s[2]], message[s[3]]);
        mix(2, 6, 10, 14, message[s[4]], message[s[5]]);
        mix(3, 7, 11, 15, message[s[6]], message[s[7]]);
        mix(0, 5, 10, 15, message[s[8]], message[s[9]]);
        mix(1, 6, 11, 12, message[s[10]], message[s[11]]);
        mix(2, 7, 8, 13, message[s[12]], message[s[13]]);
        mix(3, 4, 9, 14, message[s[14]], message[s[15]]);
    }
    for (size_t i = 0; i < 8; ++i) state[i] ^= work[i] ^ work[i + 8];
}

}  // namespace

std::array<uint8_t, 32> sha256(const uint8_t* data, size_t size) {
    if (size > std::numeric_limits<CC_LONG>::max()) {
        throw std::length_error("SHA-256 input is too large");
    }
    std::array<uint8_t, 32> digest{};
    CC_SHA256(data, static_cast<CC_LONG>(size), digest.data());
    return digest;
}

std::array<uint8_t, 32> sha256(const std::vector<uint8_t>& data) {
    return sha256(data.data(), data.size());
}

std::array<uint8_t, 32> sha256d(const uint8_t* data, size_t size) {
    const auto first = sha256(data, size);
    return sha256(first.data(), first.size());
}

std::array<uint8_t, 32> sha512_256(const uint8_t* data, size_t size) {
    uint64_t state[8] = {
        0x22312194fc2bf72cULL, 0x9f555fa3c84c64c2ULL, 0x2393b86b6f53b151ULL,
        0x963877195940eabdULL, 0x96283ee2a88effe3ULL, 0xbe5e1e2553863992ULL,
        0x2b0199fc2c85b8aaULL, 0x0eb72ddc81c52ca2ULL};

    size_t offset = 0;
    while (size - offset >= 128) {
        sha512_256_transform(state, data + offset);
        offset += 128;
    }

    uint8_t final_blocks[256] = {};
    const size_t remaining = size - offset;
    if (remaining != 0) std::memcpy(final_blocks, data + offset, remaining);
    final_blocks[remaining] = 0x80;
    const size_t final_size = remaining < 112 ? 128 : 256;
    const uint64_t bit_length_low = static_cast<uint64_t>(size) << 3;
    const uint64_t bit_length_high = static_cast<uint64_t>(size) >> 61;
    store_be64(final_blocks + final_size - 16, bit_length_high);
    store_be64(final_blocks + final_size - 8, bit_length_low);
    sha512_256_transform(state, final_blocks);
    if (final_size == 256) sha512_256_transform(state, final_blocks + 128);

    std::array<uint8_t, 32> digest{};
    for (size_t i = 0; i < 4; ++i) store_be64(digest.data() + i * 8, state[i]);
    return digest;
}

std::array<uint8_t, 20> ripemd160(const uint8_t* data, size_t size) {
    uint32_t state[5] = {0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u,
                         0xc3d2e1f0u};
    size_t offset = 0;
    while (size - offset >= 64) {
        ripemd_transform(state, data + offset);
        offset += 64;
    }
    uint8_t final_blocks[128] = {};
    const size_t remaining = size - offset;
    if (remaining != 0) std::memcpy(final_blocks, data + offset, remaining);
    final_blocks[remaining] = 0x80;
    const size_t final_size = remaining < 56 ? 64 : 128;
    const uint64_t bit_length = static_cast<uint64_t>(size) << 3;
    store_le64(final_blocks + final_size - 8, bit_length);
    ripemd_transform(state, final_blocks);
    if (final_size == 128) ripemd_transform(state, final_blocks + 64);

    std::array<uint8_t, 20> digest{};
    for (size_t i = 0; i < 5; ++i) {
        digest[i * 4] = static_cast<uint8_t>(state[i]);
        digest[i * 4 + 1] = static_cast<uint8_t>(state[i] >> 8);
        digest[i * 4 + 2] = static_cast<uint8_t>(state[i] >> 16);
        digest[i * 4 + 3] = static_cast<uint8_t>(state[i] >> 24);
    }
    return digest;
}

std::vector<uint8_t> blake2b(const uint8_t* data, size_t size, size_t output_size) {
    if (output_size == 0 || output_size > 64) {
        throw std::invalid_argument("BLAKE2b output size must be 1..64 bytes");
    }
    static constexpr uint64_t iv[8] = {
        0x6a09e667f3bcc908ULL, 0xbb67ae8584caa73bULL, 0x3c6ef372fe94f82bULL,
        0xa54ff53a5f1d36f1ULL, 0x510e527fade682d1ULL, 0x9b05688c2b3e6c1fULL,
        0x1f83d9abfb41bd6bULL, 0x5be0cd19137e2179ULL};
    uint64_t state[8];
    std::copy(std::begin(iv), std::end(iv), state);
    state[0] ^= 0x01010000ULL ^ output_size;

    size_t offset = 0;
    uint64_t count_low = 0;
    uint64_t count_high = 0;
    while (size - offset > 128) {
        const uint64_t old = count_low;
        count_low += 128;
        if (count_low < old) ++count_high;
        blake2b_compress(state, data + offset, count_low, count_high, false);
        offset += 128;
    }

    uint8_t final_block[128] = {};
    const size_t remaining = size - offset;
    if (remaining != 0) std::memcpy(final_block, data + offset, remaining);
    const uint64_t old = count_low;
    count_low += remaining;
    if (count_low < old) ++count_high;
    blake2b_compress(state, final_block, count_low, count_high, true);

    uint8_t complete[64];
    for (size_t i = 0; i < 8; ++i) store_le64(complete + i * 8, state[i]);
    return std::vector<uint8_t>(complete, complete + output_size);
}

uint16_t crc16_xmodem(const uint8_t* data, size_t size) {
    uint16_t crc = 0;
    for (size_t i = 0; i < size; ++i) {
        crc ^= static_cast<uint16_t>(data[i]) << 8;
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc & 0x8000u) != 0 ? static_cast<uint16_t>((crc << 1) ^ 0x1021u)
                                       : static_cast<uint16_t>(crc << 1);
        }
    }
    return crc;
}

uint32_t crc32_ieee(const uint8_t* data, size_t size) {
    uint32_t crc = 0xffffffffu;
    for (size_t i = 0; i < size; ++i) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1) ^ (0xedb88320u & (0u - (crc & 1u)));
        }
    }
    return ~crc;
}

bool bytes_equal(const uint8_t* lhs, const uint8_t* rhs, size_t size) {
    uint8_t difference = 0;
    for (size_t i = 0; i < size; ++i) difference |= lhs[i] ^ rhs[i];
    return difference == 0;
}

}  // namespace address_tools
