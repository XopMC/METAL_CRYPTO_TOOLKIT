#include "VanityMode.h"

#include "../MetalBackend.h"
#include "../SecpPrecompute.h"
#include "../host_secp/secp256k1.h"
#include "../host_secp/secp256k1_field.h"
#include "../host_secp/secp256k1_group.h"
#include "../host_secp/secp256k1_scalar.h"
#include "../lib/Bech32.h"
#include "../lib/hash/ripemd160.h"
#include "../lib/hash/sha256.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

std::string encodeBase58(const std::uint8_t* bytes, std::size_t length);
std::string hash160ToBase58(const std::uint8_t hash160[20],
                            std::uint8_t prefix);

namespace vanity {
namespace {

constexpr std::uint32_t kThreadgroupSize = 128u;
constexpr std::uint64_t kCandidatesPerThread = 8u;
constexpr std::uint64_t kDefaultBatch = 1ull << 20u;
constexpr std::uint32_t kHitCapacity = 65536u;
constexpr std::size_t kMaximumPatternLength = 96u;
constexpr char kOrderText[] =
    "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

enum class Family : std::uint32_t {
    P2pkhCompressed = 1u,
    P2shP2wpkh = 2u,
    Bech32P2wpkh = 3u,
    Ethereum = 4u,
    Tron = 5u,
    P2pkhUncompressed = 6u,
};

struct GpuPattern {
    std::uint32_t family = 0u;
    std::uint32_t length = 0u;
    std::array<std::uint8_t, kMaximumPatternLength> text{};
};

struct GpuHit {
    std::array<std::uint8_t, 32> scalar{};
    std::uint32_t pattern_index = 0u;
    std::uint32_t family = 0u;
    std::uint32_t address_length = 0u;
    std::array<std::uint8_t, kMaximumPatternLength> address{};
};

static_assert(sizeof(GpuPattern) == 104u);
static_assert(sizeof(GpuHit) == 140u);

struct Pattern {
    Family family = Family::P2pkhCompressed;
    std::string glob;
    std::string display;
    std::string source;
    bool solved = false;
};

struct Options {
    std::vector<std::string> pattern_values;
    std::vector<std::string> pattern_files;
    std::vector<int> devices{0};
    std::string start = "1";
    std::string end = kOrderText;
    std::string split_key;
    std::string output_path;
    std::uint64_t batch = kDefaultBatch;
    bool random = false;
    bool save = false;
    bool silent = false;
};

struct HostPrecompute {
    std::vector<secp256k1_ge_storage> entries;
    std::size_t pitch = 0u;
    unsigned int windows = 0u;
    unsigned int bits = 12u;
};

struct DeviceBuffers {
    int device = -1;
    std::uint8_t* base_scalar = nullptr;
    GpuPattern* patterns = nullptr;
    std::uint8_t* split_public = nullptr;
    secp256k1_ge_storage* precompute = nullptr;
    GpuHit* hits = nullptr;
    std::uint32_t* hit_count = nullptr;
    std::uint64_t allocated = 0u;
};

std::string trim_copy(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1u);
}

std::string lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char c) {
                       return static_cast<char>(std::tolower(c));
                   });
    return value;
}

bool parse_u64(const std::string& raw, std::uint64_t& result) {
    const std::string value = trim_copy(raw);
    if (value.empty()) return false;
    std::size_t used = 0u;
    try {
        result = std::stoull(value, &used, 0);
    } catch (...) {
        return false;
    }
    return used == value.size();
}

bool parse_device_list(const std::string& raw,
                       std::vector<int>& devices,
                       std::string& error) {
    std::set<int> unique;
    std::stringstream input(raw);
    std::string item;
    while (std::getline(input, item, ',')) {
        item = trim_copy(item);
        std::uint64_t value = 0u;
        if (!parse_u64(item, value) ||
            value > static_cast<std::uint64_t>(
                std::numeric_limits<int>::max())) {
            error = "-device expects non-negative comma-separated indexes";
            return false;
        }
        unique.insert(static_cast<int>(value));
    }
    if (unique.empty()) {
        error = "-device selected no Metal devices";
        return false;
    }
    devices.assign(unique.begin(), unique.end());
    return true;
}

bool parse_options(int argc, char** argv, Options& options,
                   std::string& error) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i] == nullptr ? "" : argv[i];
        auto value = [&](const char* name) -> const char* {
            if (i + 1 >= argc || argv[i + 1] == nullptr) {
                error = std::string(name) + " requires a value";
                return nullptr;
            }
            return argv[++i];
        };
        if (arg == "-vanity") {
            continue;
        } else if (arg == "-pattern") {
            const char* raw = value("-pattern");
            if (raw == nullptr) return false;
            options.pattern_values.emplace_back(raw);
        } else if (arg == "-pattern-file") {
            const char* raw = value("-pattern-file");
            if (raw == nullptr) return false;
            options.pattern_files.emplace_back(raw);
        } else if (arg == "-start") {
            const char* raw = value("-start");
            if (raw == nullptr) return false;
            options.start = raw;
        } else if (arg == "-end") {
            const char* raw = value("-end");
            if (raw == nullptr) return false;
            options.end = raw;
        } else if (arg == "-split-key") {
            const char* raw = value("-split-key");
            if (raw == nullptr) return false;
            options.split_key = raw;
        } else if (arg == "-device") {
            const char* raw = value("-device");
            if (raw == nullptr ||
                !parse_device_list(raw, options.devices, error)) {
                return false;
            }
        } else if (arg == "-n") {
            const char* raw = value("-n");
            if (raw == nullptr ||
                !parse_u64(raw, options.batch) ||
                options.batch == 0u ||
                options.batch > std::numeric_limits<std::uint32_t>::max()) {
                if (error.empty()) {
                    error = "-n expects 1..4294967295 candidates";
                }
                return false;
            }
        } else if (arg == "-random") {
            options.random = true;
        } else if (arg == "-o") {
            const char* raw = value("-o");
            if (raw == nullptr) return false;
            options.output_path = raw;
        } else if (arg == "-save") {
            options.save = true;
        } else if (arg == "-silent") {
            options.silent = true;
        } else if (arg == "-help" || arg == "--help" || arg == "-h") {
            continue;
        } else {
            error = "unknown -vanity parameter '" + arg + "'";
            return false;
        }
    }
    if (options.pattern_values.empty() &&
        options.pattern_files.empty()) {
        error = "-vanity requires -pattern and/or -pattern-file";
        return false;
    }
    return true;
}

int hex_digit(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

bool decode_hex(const std::string& raw, std::vector<std::uint8_t>& bytes) {
    std::string value = trim_copy(raw);
    if (value.size() > 2u && value[0] == '0' &&
        (value[1] == 'x' || value[1] == 'X')) {
        value.erase(0u, 2u);
    }
    if ((value.size() & 1u) != 0u) return false;
    bytes.assign(value.size() / 2u, 0u);
    for (std::size_t i = 0u; i < bytes.size(); ++i) {
        const int high = hex_digit(value[2u * i]);
        const int low = hex_digit(value[2u * i + 1u]);
        if (high < 0 || low < 0) return false;
        bytes[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return true;
}

std::string hex_lower(const std::uint8_t* data, std::size_t size) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::size_t i = 0u; i < size; ++i) {
        output << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return output.str();
}

const char* family_name(Family family) {
    switch (family) {
    case Family::P2pkhCompressed: return "btc-p2pkh";
    case Family::P2shP2wpkh: return "btc-p2sh-p2wpkh";
    case Family::Bech32P2wpkh: return "btc-bech32";
    case Family::Ethereum: return "ethereum";
    case Family::Tron: return "tron";
    case Family::P2pkhUncompressed: return "btc-p2pkh-uncompressed";
    }
    return "unknown";
}

bool family_prefix(const std::string& raw, Family& family,
                   std::string& pattern) {
    const auto separator = raw.find(':');
    if (separator == std::string::npos) return false;
    const std::string tag = lower_copy(trim_copy(raw.substr(0u, separator)));
    if (tag == "p2pkh" || tag == "btc" || tag == "btc-p2pkh") {
        family = Family::P2pkhCompressed;
    } else if (tag == "p2pkh-u" || tag == "btc-p2pkh-u" ||
               tag == "btc-p2pkh-uncompressed") {
        family = Family::P2pkhUncompressed;
    } else if (tag == "p2sh" || tag == "btc-p2sh" ||
               tag == "p2sh-p2wpkh") {
        family = Family::P2shP2wpkh;
    } else if (tag == "bech32" || tag == "p2wpkh" ||
               tag == "btc-bech32") {
        family = Family::Bech32P2wpkh;
    } else if (tag == "eth" || tag == "ethereum") {
        family = Family::Ethereum;
    } else if (tag == "trx" || tag == "tron") {
        family = Family::Tron;
    } else {
        return false;
    }
    pattern = trim_copy(raw.substr(separator + 1u));
    return true;
}

bool infer_family(const std::string& pattern, Family& family) {
    if (pattern.rfind("bc1q", 0u) == 0u) {
        family = Family::Bech32P2wpkh;
        return true;
    }
    if (pattern.rfind("0x", 0u) == 0u) {
        family = Family::Ethereum;
        return true;
    }
    if (!pattern.empty() && pattern[0] == '1') {
        family = Family::P2pkhCompressed;
        return true;
    }
    if (!pattern.empty() && pattern[0] == '3') {
        family = Family::P2shP2wpkh;
        return true;
    }
    if (!pattern.empty() && pattern[0] == 'T') {
        family = Family::Tron;
        return true;
    }
    return false;
}

bool valid_pattern_character(Family family, char value) {
    if (value == '*' || value == '?') return true;
    static const std::string base58 =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    static const std::string bech32 =
        "0123456789abcdefghijklmnopqrstuvwxyz";
    if (family == Family::Ethereum) {
        return std::isxdigit(static_cast<unsigned char>(value)) != 0 ||
            value == 'x';
    }
    if (family == Family::Bech32P2wpkh) {
        return bech32.find(value) != std::string::npos ||
            value == 'b' || value == 'c';
    }
    return base58.find(value) != std::string::npos;
}

bool add_pattern(const std::string& raw, const std::string& source,
                 std::vector<Pattern>& patterns,
                 std::unordered_set<std::string>& unique,
                 std::string& error) {
    const std::string trimmed = trim_copy(raw);
    if (trimmed.empty() || trimmed[0] == '#') return true;
    Family family{};
    std::string glob;
    if (!family_prefix(trimmed, family, glob)) {
        glob = trimmed;
        if (!infer_family(glob, family)) {
            error = source +
                ": cannot infer address family; use p2pkh:, p2pkh-u:, p2sh:, bech32:, eth:, or tron:";
            return false;
        }
    }
    if (family == Family::Ethereum ||
        family == Family::Bech32P2wpkh) {
        glob = lower_copy(glob);
    }
    if (glob.empty()) {
        error = source + ": empty vanity pattern";
        return false;
    }
    for (char value : glob) {
        if (!valid_pattern_character(family, value)) {
            error = source + ": invalid character in vanity pattern";
            return false;
        }
    }
    const std::string display = glob;
    if (glob.find('*') == std::string::npos &&
        glob.find('?') == std::string::npos) {
        glob.push_back('*');
    }
    if (glob.size() > kMaximumPatternLength) {
        error = source + ": pattern exceeds 96 bytes";
        return false;
    }
    const std::string key =
        std::to_string(static_cast<std::uint32_t>(family)) + ":" + glob;
    if (!unique.insert(key).second) return true;
    patterns.push_back({family, glob, display, source, false});
    return true;
}

bool load_patterns(const Options& options, std::vector<Pattern>& patterns,
                   std::string& error) {
    std::unordered_set<std::string> unique;
    for (std::size_t i = 0u; i < options.pattern_values.size(); ++i) {
        if (!add_pattern(options.pattern_values[i],
                         "command line pattern " + std::to_string(i + 1u),
                         patterns, unique, error)) {
            return false;
        }
    }
    for (const std::string& path : options.pattern_files) {
        std::ifstream input(path);
        if (!input) {
            error = "cannot open pattern file '" + path + "'";
            return false;
        }
        std::string line;
        std::size_t line_number = 0u;
        while (std::getline(input, line)) {
            ++line_number;
            const auto comment = line.find('#');
            if (comment != std::string::npos) line.erase(comment);
            if (!add_pattern(line,
                             path + ":" + std::to_string(line_number),
                             patterns, unique, error)) {
                return false;
            }
        }
    }
    if (patterns.empty()) {
        error = "no usable vanity patterns were loaded";
        return false;
    }
    return true;
}

std::array<std::uint8_t, 32> u256_bytes(const modeinfra::U256& value) {
    std::array<std::uint8_t, 32> output{};
    for (std::size_t limb = 0u; limb < 4u; ++limb) {
        std::uint64_t word = value.limbs[limb];
        const std::size_t offset = (3u - limb) * 8u;
        for (std::size_t byte = 0u; byte < 8u; ++byte) {
            output[offset + 7u - byte] =
                static_cast<std::uint8_t>(word & 0xffu);
            word >>= 8u;
        }
    }
    return output;
}

bool shift_left_one(modeinfra::U256& value) {
    std::uint64_t carry = 0u;
    for (std::size_t i = 0u; i < 4u; ++i) {
        const std::uint64_t next = value.limbs[i] >> 63u;
        value.limbs[i] = (value.limbs[i] << 1u) | carry;
        carry = next;
    }
    return carry == 0u;
}

modeinfra::U256 random_below(const modeinfra::U256& modulus,
                             std::uint64_t& seed) {
    std::random_device entropy;
    seed = (static_cast<std::uint64_t>(entropy()) << 32u) ^ entropy() ^
        static_cast<std::uint64_t>(
            std::chrono::high_resolution_clock::now()
                .time_since_epoch().count());
    std::mt19937_64 generator(seed);
    modeinfra::U256 source{};
    for (auto& limb : source.limbs) limb = generator();
    modeinfra::U256 remainder{};
    for (int bit = 255; bit >= 0; --bit) {
        (void)shift_left_one(remainder);
        remainder.limbs[0] |=
            (source.limbs[static_cast<std::size_t>(bit) / 64u] >>
             (static_cast<unsigned>(bit) & 63u)) & 1u;
        if (modeinfra::compare(remainder, modulus) >= 0) {
            modeinfra::U256 reduced{};
            (void)modeinfra::subtract_checked(remainder, modulus, reduced);
            remainder = reduced;
        }
    }
    return remainder;
}

modeinfra::U256 rotated_ordinal(const modeinfra::U256& cursor,
                               const modeinfra::U256& offset,
                               const modeinfra::U256& width) {
    modeinfra::U256 threshold{};
    (void)modeinfra::subtract_checked(width, offset, threshold);
    modeinfra::U256 result{};
    if (modeinfra::compare(cursor, threshold) >= 0) {
        (void)modeinfra::subtract_checked(cursor, threshold, result);
    } else {
        (void)modeinfra::add_checked(cursor, offset, result);
    }
    return result;
}

std::uint64_t bounded_count(const modeinfra::U256& remaining,
                            std::uint64_t maximum) {
    if (remaining.limbs[1] != 0u || remaining.limbs[2] != 0u ||
        remaining.limbs[3] != 0u) {
        return maximum;
    }
    return std::min(remaining.limbs[0], maximum);
}

bool parse_public_key(const std::string& raw, secp256k1_ge& point,
                      std::array<std::uint8_t, 64>& xy,
                      std::string& error) {
    std::vector<std::uint8_t> bytes;
    if (!decode_hex(raw, bytes) ||
        (bytes.size() != 33u && bytes.size() != 65u)) {
        error = "-split-key expects a 33/65-byte secp256k1 public key";
        return false;
    }
    if (bytes.size() == 33u &&
        (bytes[0] == 0x02u || bytes[0] == 0x03u)) {
        secp256k1_fe x{};
        if (!secp256k1_fe_set_b32(&x, bytes.data() + 1u) ||
            !secp256k1_ge_set_xo_var(
                &point, &x, bytes[0] == 0x03u)) {
            error = "-split-key is not a valid secp256k1 public key";
            return false;
        }
    } else if (bytes.size() == 65u && bytes[0] == 0x04u) {
        secp256k1_fe x{};
        secp256k1_fe y{};
        if (!secp256k1_fe_set_b32(&x, bytes.data() + 1u) ||
            !secp256k1_fe_set_b32(&y, bytes.data() + 33u) ||
            !secp256k1_ge_set_xo_var(
                &point, &x, secp256k1_fe_is_odd(&y))) {
            error = "-split-key is not a valid secp256k1 public key";
            return false;
        }
        secp256k1_fe_normalize_var(&y);
        if (!secp256k1_fe_equal(&point.y, &y)) {
            error = "-split-key is not a valid secp256k1 public key";
            return false;
        }
    } else {
        error = "-split-key has an invalid public-key prefix";
        return false;
    }
    secp256k1_fe_normalize_var(&point.x);
    secp256k1_fe_normalize_var(&point.y);
    secp256k1_fe_get_b32(xy.data(), &point.x);
    secp256k1_fe_get_b32(xy.data() + 32u, &point.y);
    return true;
}

bool derive_public(const std::array<std::uint8_t, 32>& scalar_bytes,
                   const HostPrecompute& precompute,
                   const secp256k1_ge* split,
                   std::array<std::uint8_t, 65>& public_key) {
    secp256k1_scalar scalar{};
    int overflow = 0;
    secp256k1_scalar_set_b32(&scalar, scalar_bytes.data(), &overflow);
    if (overflow || secp256k1_scalar_is_zero(&scalar)) return false;
    secp256k1_gej point{};
    secp256k1_ecmult_big(
        &point, &scalar, precompute.entries.data(),
        precompute.pitch, static_cast<int>(precompute.windows),
        precompute.bits);
    if (split != nullptr) {
        secp256k1_gej combined{};
        secp256k1_gej_add_ge_var(&combined, &point, split, nullptr);
        point = combined;
    }
    if (point.infinity != 0) return false;
    secp256k1_ge affine{};
    secp256k1_ge_set_gej(&affine, &point);
    secp256k1_fe_normalize_var(&affine.x);
    secp256k1_fe_normalize_var(&affine.y);
    public_key[0] = 0x04u;
    secp256k1_fe_get_b32(public_key.data() + 1u, &affine.x);
    secp256k1_fe_get_b32(public_key.data() + 33u, &affine.y);
    return true;
}

void hash160_bytes(const std::uint8_t* data, std::size_t size,
                   std::array<std::uint8_t, 20>& output) {
    std::array<std::uint8_t, 32> digest{};
    sha256(const_cast<std::uint8_t*>(data), size, digest.data());
    ripemd160(digest.data(), 32, output.data());
}

std::uint64_t rotate_left(std::uint64_t value, unsigned shift) {
    return shift == 0u ? value :
        (value << shift) | (value >> (64u - shift));
}

void keccak_permute(std::uint64_t state[25]) {
    static constexpr std::uint64_t round_constants[24] = {
        0x0000000000000001ull, 0x0000000000008082ull,
        0x800000000000808aull, 0x8000000080008000ull,
        0x000000000000808bull, 0x0000000080000001ull,
        0x8000000080008081ull, 0x8000000000008009ull,
        0x000000000000008aull, 0x0000000000000088ull,
        0x0000000080008009ull, 0x000000008000000aull,
        0x000000008000808bull, 0x800000000000008bull,
        0x8000000000008089ull, 0x8000000000008003ull,
        0x8000000000008002ull, 0x8000000000000080ull,
        0x000000000000800aull, 0x800000008000000aull,
        0x8000000080008081ull, 0x8000000000008080ull,
        0x0000000080000001ull, 0x8000000080008008ull,
    };
    static constexpr unsigned rotations[24] = {
        1, 3, 6, 10, 15, 21, 28, 36,
        45, 55, 2, 14, 27, 41, 56, 8,
        25, 43, 62, 18, 39, 61, 20, 44,
    };
    static constexpr unsigned lanes[24] = {
        10, 7, 11, 17, 18, 3, 5, 16,
        8, 21, 24, 4, 15, 23, 19, 13,
        12, 2, 20, 14, 22, 9, 6, 1,
    };
    for (std::size_t round = 0u; round < 24u; ++round) {
        std::uint64_t column[5];
        for (std::size_t i = 0u; i < 5u; ++i) {
            column[i] = state[i] ^ state[i + 5u] ^ state[i + 10u] ^
                state[i + 15u] ^ state[i + 20u];
        }
        for (std::size_t i = 0u; i < 5u; ++i) {
            const std::uint64_t delta =
                column[(i + 4u) % 5u] ^
                rotate_left(column[(i + 1u) % 5u], 1u);
            for (std::size_t j = 0u; j < 25u; j += 5u) {
                state[j + i] ^= delta;
            }
        }
        std::uint64_t current = state[1];
        for (std::size_t i = 0u; i < 24u; ++i) {
            const std::size_t lane = lanes[i];
            const std::uint64_t next = state[lane];
            state[lane] = rotate_left(current, rotations[i]);
            current = next;
        }
        for (std::size_t row = 0u; row < 25u; row += 5u) {
            std::uint64_t values[5];
            for (std::size_t i = 0u; i < 5u; ++i) {
                values[i] = state[row + i];
            }
            for (std::size_t i = 0u; i < 5u; ++i) {
                state[row + i] =
                    values[i] ^ ((~values[(i + 1u) % 5u]) &
                                 values[(i + 2u) % 5u]);
            }
        }
        state[0] ^= round_constants[round];
    }
}

std::array<std::uint8_t, 32> keccak256(const std::uint8_t* data,
                                       std::size_t size) {
    constexpr std::size_t rate = 136u;
    std::uint64_t state[25] = {};
    std::uint8_t* bytes = reinterpret_cast<std::uint8_t*>(state);
    while (size >= rate) {
        for (std::size_t i = 0u; i < rate; ++i) bytes[i] ^= data[i];
        keccak_permute(state);
        data += rate;
        size -= rate;
    }
    for (std::size_t i = 0u; i < size; ++i) bytes[i] ^= data[i];
    bytes[size] ^= 0x01u;
    bytes[rate - 1u] ^= 0x80u;
    keccak_permute(state);
    std::array<std::uint8_t, 32> output{};
    std::copy(bytes, bytes + output.size(), output.begin());
    return output;
}

std::string base58check(std::uint8_t version,
                        const std::array<std::uint8_t, 20>& body) {
    std::array<std::uint8_t, 25> payload{};
    payload[0] = version;
    std::copy(body.begin(), body.end(), payload.begin() + 1u);
    std::array<std::uint8_t, 32> digest{};
    sha256(payload.data(), 21u, digest.data());
    sha256(digest.data(), digest.size(), digest.data());
    std::copy(digest.begin(), digest.begin() + 4u, payload.begin() + 21u);
    return encodeBase58(payload.data(), payload.size());
}

std::string address_for(Family family,
                        const std::array<std::uint8_t, 65>& public_key) {
    std::array<std::uint8_t, 33> compressed{};
    compressed[0] =
        static_cast<std::uint8_t>(0x02u + (public_key[64] & 1u));
    std::copy(public_key.begin() + 1u, public_key.begin() + 33u,
              compressed.begin() + 1u);
    if (family == Family::P2pkhCompressed) {
        std::array<std::uint8_t, 20> hash{};
        hash160_bytes(compressed.data(), compressed.size(), hash);
        return hash160ToBase58(hash.data(), 0u);
    }
    if (family == Family::P2pkhUncompressed) {
        std::array<std::uint8_t, 20> hash{};
        hash160_bytes(public_key.data(), public_key.size(), hash);
        return hash160ToBase58(hash.data(), 0u);
    }
    if (family == Family::P2shP2wpkh) {
        std::array<std::uint8_t, 20> key_hash{};
        hash160_bytes(compressed.data(), compressed.size(), key_hash);
        std::array<std::uint8_t, 22> redeem{};
        redeem[0] = 0u;
        redeem[1] = 20u;
        std::copy(key_hash.begin(), key_hash.end(), redeem.begin() + 2u);
        std::array<std::uint8_t, 20> script_hash{};
        hash160_bytes(redeem.data(), redeem.size(), script_hash);
        return hash160ToBase58(script_hash.data(), 5u);
    }
    if (family == Family::Bech32P2wpkh) {
        std::array<std::uint8_t, 20> hash{};
        hash160_bytes(compressed.data(), compressed.size(), hash);
        std::array<char, 96> output{};
        if (!segwit_addr_encode(
                output.data(), "bc", 0, hash.data(), hash.size())) {
            return {};
        }
        return output.data();
    }
    const auto digest = keccak256(public_key.data() + 1u, 64u);
    std::array<std::uint8_t, 20> account{};
    std::copy(digest.begin() + 12u, digest.end(), account.begin());
    if (family == Family::Tron) return base58check(0x41u, account);
    return "0x" + hex_lower(account.data(), account.size());
}

bool glob_match(const std::string& source, const std::string& pattern) {
    std::size_t input = 0u;
    std::size_t token = 0u;
    std::size_t restart = 0u;
    std::size_t star = std::string::npos;
    while (input < source.size()) {
        if (token < pattern.size() &&
            (pattern[token] == '?' || pattern[token] == source[input])) {
            ++input;
            ++token;
        } else if (token < pattern.size() && pattern[token] == '*') {
            star = token++;
            restart = input;
        } else if (star != std::string::npos) {
            token = star + 1u;
            input = ++restart;
        } else {
            return false;
        }
    }
    while (token < pattern.size() && pattern[token] == '*') ++token;
    return token == pattern.size();
}

bool metal_ok(metalError_t status, const char* operation,
              std::string& error) {
    if (status == metalSuccess) return true;
    error = std::string(operation) + ": " + metalGetErrorString(status);
    return false;
}

template <typename T>
bool allocate(T*& pointer, std::size_t bytes,
              const char* operation, std::string& error) {
    return metal_ok(
        metalMalloc(reinterpret_cast<void**>(&pointer),
                    std::max<std::size_t>(bytes, 1u)),
        operation, error);
}

void release_buffers(DeviceBuffers& buffers) {
    if (buffers.device >= 0) (void)metalSetDevice(buffers.device);
    if (buffers.base_scalar) metalFree(buffers.base_scalar);
    if (buffers.patterns) metalFree(buffers.patterns);
    if (buffers.split_public) metalFree(buffers.split_public);
    if (buffers.precompute) metalFree(buffers.precompute);
    if (buffers.hits) metalFree(buffers.hits);
    if (buffers.hit_count) metalFree(buffers.hit_count);
    buffers = DeviceBuffers{};
}

bool prepare_buffers(int device,
                     const std::vector<GpuPattern>& patterns,
                     const std::array<std::uint8_t, 64>& split_xy,
                     const HostPrecompute& precompute,
                     DeviceBuffers& buffers,
                     std::string& error) {
    buffers.device = device;
    const std::size_t pattern_bytes =
        patterns.size() * sizeof(GpuPattern);
    const std::size_t precompute_bytes =
        precompute.entries.size() * sizeof(secp256k1_ge_storage);
    if (!metal_ok(metalSetDevice(device), "select Metal device", error) ||
        !allocate(buffers.base_scalar, 32u,
                  "allocate vanity base", error) ||
        !allocate(buffers.patterns, pattern_bytes,
                  "allocate vanity patterns", error) ||
        !allocate(buffers.split_public, split_xy.size(),
                  "allocate vanity split key", error) ||
        !allocate(buffers.precompute, precompute_bytes,
                  "allocate vanity precompute", error) ||
        !allocate(buffers.hits, sizeof(GpuHit) * kHitCapacity,
                  "allocate vanity hits", error) ||
        !allocate(buffers.hit_count, sizeof(std::uint32_t),
                  "allocate vanity hit count", error)) {
        release_buffers(buffers);
        return false;
    }
    if (!metal_ok(
            metalMemcpy(buffers.patterns, patterns.data(), pattern_bytes,
                        metalMemcpyHostToDevice),
            "upload vanity patterns", error) ||
        !metal_ok(
            metalMemcpy(buffers.split_public, split_xy.data(),
                        split_xy.size(), metalMemcpyHostToDevice),
            "upload vanity split key", error) ||
        !metal_ok(
            metalMemcpy(buffers.precompute, precompute.entries.data(),
                        precompute_bytes, metalMemcpyHostToDevice),
            "upload vanity precompute", error)) {
        release_buffers(buffers);
        return false;
    }
    buffers.allocated =
        32u + pattern_bytes + split_xy.size() + precompute_bytes +
        sizeof(GpuHit) * kHitCapacity + sizeof(std::uint32_t);
    return true;
}

bool launch_batch(DeviceBuffers& buffers,
                  const std::array<std::uint8_t, 32>& base,
                  std::uint64_t count,
                  std::uint32_t pattern_count,
                  std::uint32_t family_mask,
                  bool split_enabled,
                  const HostPrecompute& precompute,
                  std::vector<GpuHit>& hits,
                  std::uint32_t& raw_count,
                  std::uint64_t& readback_ns,
                  std::string& error) {
    if (!metal_ok(metalSetDevice(buffers.device),
                  "select vanity device", error) ||
        !metal_ok(
            metalMemcpy(buffers.base_scalar, base.data(), base.size(),
                        metalMemcpyHostToDevice),
            "upload vanity base", error) ||
        !metal_ok(
            metalMemset(buffers.hit_count, 0u, sizeof(std::uint32_t)),
            "clear vanity hit count", error)) {
        return false;
    }
    const std::uint64_t thread_count =
        (count + kCandidatesPerThread - 1u) / kCandidatesPerThread;
    const std::uint32_t grid = static_cast<std::uint32_t>(
        (thread_count + kThreadgroupSize - 1u) / kThreadgroupSize);
    const std::uint32_t split_flag = split_enabled ? 1u : 0u;
    const std::uint64_t pitch =
        static_cast<std::uint64_t>(precompute.pitch);
    if (!metal_ok(
            metal_launch(
                "vanitySearch", grid, kThreadgroupSize,
                buffers.base_scalar, count,
                buffers.patterns, pattern_count, family_mask,
                buffers.split_public, split_flag,
                buffers.precompute, pitch,
                static_cast<std::uint32_t>(precompute.windows),
                static_cast<std::uint32_t>(precompute.bits),
                buffers.hits, buffers.hit_count, kHitCapacity),
            "launch vanity kernel", error) ||
        !metal_ok(
            metalDeviceSynchronize(),
            "synchronize vanity kernel", error)) {
        return false;
    }
    const auto started = std::chrono::steady_clock::now();
    if (!metal_ok(
            metalMemcpy(&raw_count, buffers.hit_count,
                        sizeof(raw_count), metalMemcpyDeviceToHost),
            "read vanity hit count", error)) {
        return false;
    }
    const std::uint32_t stored = std::min(raw_count, kHitCapacity);
    hits.resize(stored);
    if (stored != 0u &&
        !metal_ok(
            metalMemcpy(hits.data(), buffers.hits,
                        static_cast<std::size_t>(stored) * sizeof(GpuHit),
                        metalMemcpyDeviceToHost),
            "read vanity hits", error)) {
        return false;
    }
    readback_ns = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - started).count());
    return true;
}

std::string compressed_public_hex(
        const std::array<std::uint8_t, 65>& public_key) {
    std::array<std::uint8_t, 33> compressed{};
    compressed[0] =
        static_cast<std::uint8_t>(0x02u + (public_key[64] & 1u));
    std::copy(public_key.begin() + 1u, public_key.begin() + 33u,
              compressed.begin() + 1u);
    return hex_lower(compressed.data(), compressed.size());
}

} // namespace

bool requested(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (argv[i] != nullptr &&
            std::strcmp(argv[i], "-vanity") == 0) {
            return true;
        }
    }
    return false;
}

void print_help() {
    std::cout << R"HELP([!] MAIN MODE: -vanity  (GPU vanity address generation)
[!] ======================================================================
[!] Purpose:
[!] Search secp256k1 private keys whose derived address matches one or more
[!] prefix/suffix/wildcard patterns. All candidate point/hash work runs on
[!] Metal; every reported hit is independently verified on the host.
[!]
[!] Required:
[!] -pattern VALUE                 Repeatable pattern.
[!] -pattern-file FILE             One pattern per line; # comments allowed.
[!]
[!] Families:
[!] p2pkh:PATTERN                  BTC compressed P2PKH.
[!] p2pkh-u:PATTERN                BTC uncompressed P2PKH.
[!] p2sh:PATTERN                   BTC nested SegWit P2SH-P2WPKH.
[!] bech32:PATTERN                 BTC native SegWit P2WPKH (bc1q).
[!] eth:PATTERN                    Lowercase Ethereum 0x address.
[!] tron:PATTERN                   TRON Base58Check address.
[!] A leading 1, 3, bc1q, 0x, or T also selects the family automatically.
[!] A pattern without * or ? is a prefix. Use *suffix for suffix search,
[!] and ? for one arbitrary character.
[!]
[!] Domain / GPU:
[!] -start N -end N                Exact private interval [START,END), up to n.
[!] -random                        Cover the same interval once from a random rotation.
[!] -n N                           Candidates per GPU launch (default 1048576).
[!] -device LIST                   Metal device indexes, e.g. 0 or 0,1.
[!]
[!] Split-key:
[!] -split-key PUBKEY              Search addr(k_partial*G + PUBKEY).
[!] Output contains PARTIAL_PRIVATE; the owner reconstructs
[!] (k_partial + k_secret) mod n.
[!]
[!] Output:
[!] -o FILE                        Append verified results.
[!] -save                          Use VANITY_FOUND.txt when -o is absent.
[!] -silent                        Suppress result lines on stdout.
[!] Statistics are printed only by the toolkit SpeedThread as Key/s.
[!]
[!] Examples:
[!] ./METAL_CRYPTO_TOOLKIT -vanity -pattern 1Metal -random -save
[!] ./METAL_CRYPTO_TOOLKIT -vanity -pattern 'eth:0xdead*' -device 0
[!] ./METAL_CRYPTO_TOOLKIT -vanity -pattern 'tron:*XOP' -n 4194304
[!] ./METAL_CRYPTO_TOOLKIT -vanity -pattern-file patterns.txt -split-key 02...
[!]
[!] Limitations:
[!] This baseline performs exact GPU text matching for every selected family.
[!] Prefix compilation and resident multi-pattern indexes are optimized in the
[!] next candidates. A valid exhausted search returns 0 even with no match.
[!] CLI errors return 2; Metal/runtime failures return 1.
)HELP";
}

int run(int argc, char** argv, const RuntimeHooks& hooks) {
    Options options;
    std::string error;
    if (!parse_options(argc, argv, options, error)) {
        std::cerr << "[!] Vanity CLI error: " << error << " [!]\n";
        return 2;
    }
    std::vector<Pattern> patterns;
    if (!load_patterns(options, patterns, error)) {
        std::cerr << "[!] Vanity pattern error: " << error << " [!]\n";
        return 2;
    }
    modeinfra::U256 start{};
    modeinfra::U256 end{};
    modeinfra::U256 order{};
    modeinfra::U256 width{};
    if (!modeinfra::parse_u256(options.start, start, error) ||
        !modeinfra::parse_u256(options.end, end, error) ||
        !modeinfra::parse_u256(kOrderText, order, error) ||
        start.is_zero() || modeinfra::compare(start, end) >= 0 ||
        modeinfra::compare(end, order) > 0 ||
        !modeinfra::subtract_checked(end, start, width)) {
        std::cerr << "[!] Vanity domain error: -start/-end must define "
                     "[START,END) inside 1..n [!]\n";
        return 2;
    }
    int device_count = 0;
    if (!metal_ok(metalGetDeviceCount(&device_count),
                  "query Metal devices", error)) {
        std::cerr << "[!] Vanity runtime error: " << error << " [!]\n";
        return 1;
    }
    for (int device : options.devices) {
        if (device < 0 || device >= device_count) {
            std::cerr << "[!] Vanity CLI error: device index "
                      << device << " is unavailable [!]\n";
            return 2;
        }
    }

    HostPrecompute precompute;
    if (!build_secp256k1_precompute_table_host(
            precompute.bits, precompute.entries, precompute.pitch,
            precompute.windows, error)) {
        std::cerr << "[!] Vanity runtime error: " << error << " [!]\n";
        return 1;
    }
    secp256k1_ge split_point{};
    std::array<std::uint8_t, 64> split_xy{};
    const bool split_enabled = !options.split_key.empty();
    if (split_enabled &&
        !parse_public_key(
            options.split_key, split_point, split_xy, error)) {
        std::cerr << "[!] Vanity CLI error: " << error << " [!]\n";
        return 2;
    }

    std::vector<GpuPattern> gpu_patterns(patterns.size());
    std::uint32_t family_mask = 0u;
    for (std::size_t i = 0u; i < patterns.size(); ++i) {
        gpu_patterns[i].family =
            static_cast<std::uint32_t>(patterns[i].family);
        gpu_patterns[i].length =
            static_cast<std::uint32_t>(patterns[i].glob.size());
        std::copy(patterns[i].glob.begin(), patterns[i].glob.end(),
                  gpu_patterns[i].text.begin());
        family_mask |= 1u << gpu_patterns[i].family;
    }

    std::vector<DeviceBuffers> devices(options.devices.size());
    std::uint64_t allocated = 0u;
    for (std::size_t i = 0u; i < devices.size(); ++i) {
        if (!prepare_buffers(
                options.devices[i], gpu_patterns, split_xy,
                precompute, devices[i], error)) {
            for (auto& buffers : devices) release_buffers(buffers);
            std::cerr << "[!] Vanity runtime error: " << error << " [!]\n";
            return 1;
        }
        allocated += devices[i].allocated;
    }

    if (options.output_path.empty() && options.save) {
        options.output_path = "VANITY_FOUND.txt";
    }
    std::ofstream output;
    if (!options.output_path.empty()) {
        output.open(options.output_path, std::ios::app);
        if (!output) {
            for (auto& buffers : devices) release_buffers(buffers);
            std::cerr << "[!] Vanity runtime error: cannot open output file [!]\n";
            return 1;
        }
    }

    modeinfra::U256 offset{};
    std::uint64_t random_seed = 0u;
    if (options.random) {
        offset = random_below(width, random_seed);
        std::cout << "[!] Vanity random rotation seed: "
                  << random_seed << " [!]\n";
    }
    std::cout << "[!] Vanity patterns: " << patterns.size()
              << " | devices: " << devices.size()
              << " | batch: " << options.batch
              << " | split-key: " << (split_enabled ? "yes" : "no")
              << " [!]\n";

    modeinfra::ModeProgress& progress =
        modeinfra::global_mode_progress();
    progress.begin(
        "VANITY", modeinfra::ProgressUnit::Key,
        modeinfra::ProgressPhase::Search);
    progress.set_targets(patterns.size(), patterns.size(), 0u);
    progress.set_allocated_working_set(allocated);

    modeinfra::U256 cursor{};
    std::uint64_t founds = 0u;
    int result = 0;
    std::size_t device_slot = 0u;
    while (modeinfra::compare(cursor, width) < 0 &&
           founds < patterns.size()) {
        const modeinfra::U256 physical =
            options.random ? rotated_ordinal(cursor, offset, width) : cursor;
        modeinfra::U256 until_wrap{};
        if (!modeinfra::subtract_checked(width, physical, until_wrap)) {
            error = "internal vanity rotation underflow";
            result = 1;
            break;
        }
        std::uint64_t count = bounded_count(until_wrap, options.batch);
        modeinfra::U256 logical_remaining{};
        (void)modeinfra::subtract_checked(width, cursor, logical_remaining);
        count = std::min(count, bounded_count(logical_remaining, count));
        if (count == 0u) {
            error = "internal vanity scheduler produced an empty window";
            result = 1;
            break;
        }
        modeinfra::U256 base_value{};
        if (!modeinfra::add_checked(start, physical, base_value)) {
            error = "vanity scalar base overflow";
            result = 1;
            break;
        }
        const auto base = u256_bytes(base_value);
        DeviceBuffers& buffers = devices[device_slot++ % devices.size()];
        std::vector<GpuHit> hits;
        std::uint32_t raw_count = 0u;
        std::uint64_t readback_ns = 0u;
        while (!launch_batch(
                buffers, base, count,
                static_cast<std::uint32_t>(gpu_patterns.size()),
                family_mask, split_enabled, precompute,
                hits, raw_count, readback_ns, error)) {
            result = 1;
            break;
        }
        if (result != 0) break;
        if (raw_count > kHitCapacity) {
            if (count == 1u) {
                error = "vanity hit buffer overflow for one candidate";
                result = 1;
                break;
            }
            options.batch = std::max<std::uint64_t>(1u, count / 2u);
            continue;
        }

        for (const GpuHit& hit : hits) {
            if (hit.pattern_index >= patterns.size() ||
                hit.address_length > hit.address.size()) {
                error = "Metal returned an invalid vanity hit";
                result = 1;
                break;
            }
            Pattern& pattern = patterns[hit.pattern_index];
            if (pattern.solved ||
                hit.family != static_cast<std::uint32_t>(pattern.family)) {
                continue;
            }
            std::array<std::uint8_t, 65> public_key{};
            if (!derive_public(
                    hit.scalar, precompute,
                    split_enabled ? &split_point : nullptr,
                    public_key)) {
                error = "host rejected vanity scalar/public point";
                result = 1;
                break;
            }
            const std::string verified =
                address_for(pattern.family, public_key);
            const std::string gpu_address(
                reinterpret_cast<const char*>(hit.address.data()),
                hit.address_length);
            if (verified.empty() || verified != gpu_address ||
                !glob_match(verified, pattern.glob)) {
                error = "host verification rejected Metal vanity hit";
                result = 1;
                break;
            }
            const std::string key_label =
                split_enabled ? "PARTIAL_PRIVATE" : "PRIVATE";
            const std::string line =
                "[+] VANITY:PATTERN:" + pattern.display +
                ":SOURCE:" + pattern.source +
                ":FAMILY:" + family_name(pattern.family) +
                ":ADDRESS:" + verified +
                ":" + key_label + ":" +
                hex_lower(hit.scalar.data(), hit.scalar.size()) +
                ":PUBLIC:" + compressed_public_hex(public_key);
            if (!options.silent) std::cout << line << '\n';
            if (output) {
                output << line << '\n';
                output.flush();
            }
            pattern.solved = true;
            ++founds;
            if (hooks.increment_found) hooks.increment_found();
            progress.set_founds(founds);
            progress.set_targets(
                patterns.size(), patterns.size(), founds);
        }
        if (result != 0) break;
        if (hooks.add_completed) hooks.add_completed(count);
        progress.credit_completed(count, count, hits.size(), readback_ns);
        modeinfra::U256 next{};
        if (!modeinfra::add_checked(
                cursor, modeinfra::U256::from_u64(count), next)) {
            error = "vanity cursor overflow";
            result = 1;
            break;
        }
        cursor = next;
    }

    progress.set_phase(modeinfra::ProgressPhase::Verify);
    progress.end();
    for (auto& buffers : devices) release_buffers(buffers);
    if (result != 0) {
        std::cerr << "[!] Vanity runtime error: " << error << " [!]\n";
        return result;
    }
    std::cout << "[!] Vanity search complete. Solved "
              << founds << "/" << patterns.size() << " patterns. [!]\n";
    return 0;
}

} // namespace vanity
