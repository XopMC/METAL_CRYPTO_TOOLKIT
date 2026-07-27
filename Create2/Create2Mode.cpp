#include "Create2Mode.h"

#include "../MetalBackend.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstring>
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

namespace create2_mode {
namespace {

constexpr std::uint32_t kThreadgroupSize = 128u;
constexpr std::uint64_t kDefaultBatch = 1ull << 20u;
constexpr std::uint32_t kHitCapacity = 65536u;
constexpr std::size_t kMaximumPatternLength = 48u;

struct GpuPattern {
    std::uint32_t length = 0u;
    std::uint32_t reserved = 0u;
    std::array<std::uint8_t, kMaximumPatternLength> text{};
};

struct GpuHit {
    std::array<std::uint8_t, 32> salt{};
    std::uint32_t pattern_index = 0u;
    std::uint32_t reserved = 0u;
    std::array<std::uint8_t, 20> address{};
};

static_assert(sizeof(GpuPattern) == 56u);
static_assert(sizeof(GpuHit) == 60u);

struct Pattern {
    std::string glob;
    std::string display;
    std::string source;
    bool solved = false;
};

struct Options {
    std::vector<std::string> pattern_values;
    std::vector<std::string> pattern_files;
    std::vector<int> devices{0};
    std::string deployer;
    std::string init_code_hash;
    std::string salt_mask;
    std::string start = "0";
    std::string end;
    std::string output_path;
    std::uint64_t batch = kDefaultBatch;
    bool random = false;
    bool save = false;
    bool silent = false;
};

struct SaltTemplate {
    bool enabled = false;
    std::array<std::uint8_t, 32> bytes{};
    std::array<std::uint8_t, 64> positions{};
    std::uint32_t unknown_count = 0u;
};

struct DeviceBuffers {
    int device = -1;
    std::uint8_t* base_ordinal = nullptr;
    std::uint8_t* deployer = nullptr;
    std::uint8_t* init_code_hash = nullptr;
    std::uint8_t* salt_template = nullptr;
    std::uint8_t* unknown_positions = nullptr;
    GpuPattern* patterns = nullptr;
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
                   [](unsigned char byte) {
                       return static_cast<char>(std::tolower(byte));
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
        if (arg == "-create2") {
            continue;
        } else if (arg == "-pattern") {
            const char* raw = value("-pattern");
            if (raw == nullptr) return false;
            options.pattern_values.emplace_back(raw);
        } else if (arg == "-pattern-file") {
            const char* raw = value("-pattern-file");
            if (raw == nullptr) return false;
            options.pattern_files.emplace_back(raw);
        } else if (arg == "-deployer") {
            const char* raw = value("-deployer");
            if (raw == nullptr) return false;
            options.deployer = raw;
        } else if (arg == "-init-code-hash") {
            const char* raw = value("-init-code-hash");
            if (raw == nullptr) return false;
            options.init_code_hash = raw;
        } else if (arg == "-mask") {
            const char* raw = value("-mask");
            if (raw == nullptr) return false;
            options.salt_mask = raw;
        } else if (arg == "-start") {
            const char* raw = value("-start");
            if (raw == nullptr) return false;
            options.start = raw;
        } else if (arg == "-end") {
            const char* raw = value("-end");
            if (raw == nullptr) return false;
            options.end = raw;
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
                options.batch >
                    static_cast<std::uint64_t>(
                        std::numeric_limits<std::uint32_t>::max())) {
                if (error.empty()) {
                    error = "-n expects 1..4294967295 salts";
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
            error = "unknown -create2 parameter '" + arg + "'";
            return false;
        }
    }
    if (options.pattern_values.empty() &&
        options.pattern_files.empty()) {
        error = "-create2 requires -pattern and/or -pattern-file";
        return false;
    }
    if (options.deployer.empty()) {
        error = "-create2 requires -deployer";
        return false;
    }
    if (options.init_code_hash.empty()) {
        error = "-create2 requires -init-code-hash";
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

bool decode_hex_exact(const std::string& raw,
                      std::uint8_t* output,
                      std::size_t size) {
    std::string value = trim_copy(raw);
    if (value.size() > 2u && value[0] == '0' &&
        (value[1] == 'x' || value[1] == 'X')) {
        value.erase(0u, 2u);
    }
    if (value.size() != size * 2u) return false;
    for (std::size_t i = 0u; i < size; ++i) {
        const int high = hex_digit(value[2u * i]);
        const int low = hex_digit(value[2u * i + 1u]);
        if (high < 0 || low < 0) return false;
        output[i] = static_cast<std::uint8_t>((high << 4) | low);
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

bool add_pattern(const std::string& raw,
                 const std::string& source,
                 std::vector<Pattern>& patterns,
                 std::unordered_set<std::string>& unique,
                 std::string& error) {
    std::string glob = lower_copy(trim_copy(raw));
    if (glob.empty() || glob[0] == '#') return true;
    const auto separator = glob.find(':');
    if (separator != std::string::npos) {
        const std::string family = trim_copy(glob.substr(0u, separator));
        if (family != "eth" && family != "ethereum" &&
            family != "create2") {
            error = source + ": CREATE2 patterns must use eth: or create2:";
            return false;
        }
        glob = trim_copy(glob.substr(separator + 1u));
    }
    if (glob.empty()) {
        error = source + ": empty CREATE2 pattern";
        return false;
    }
    if (glob.rfind("0x", 0u) != 0u &&
        glob.front() != '*' && glob.front() != '?') {
        glob.insert(0u, "0x");
    }
    for (char value : glob) {
        if (value != '*' && value != '?' && value != 'x' &&
            hex_digit(value) < 0) {
            error = source + ": pattern contains a non-hex character";
            return false;
        }
    }
    const std::string display = glob;
    if (glob.find('*') == std::string::npos &&
        glob.find('?') == std::string::npos) {
        glob.push_back('*');
    }
    if (glob.size() > kMaximumPatternLength) {
        error = source + ": pattern exceeds 48 bytes";
        return false;
    }
    if (!unique.insert(glob).second) return true;
    patterns.push_back({glob, display, source, false});
    return true;
}

bool load_patterns(const Options& options,
                   std::vector<Pattern>& patterns,
                   std::string& error) {
    std::unordered_set<std::string> unique;
    for (std::size_t i = 0u; i < options.pattern_values.size(); ++i) {
        if (!add_pattern(
                options.pattern_values[i],
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
            if (!add_pattern(
                    line, path + ":" + std::to_string(line_number),
                    patterns, unique, error)) {
                return false;
            }
        }
    }
    if (patterns.empty()) {
        error = "no usable CREATE2 patterns were loaded";
        return false;
    }
    return true;
}

bool parse_salt_template(const std::string& raw,
                         SaltTemplate& result,
                         std::string& error) {
    if (raw.empty()) return true;
    std::string value = trim_copy(raw);
    if (value.size() > 2u && value[0] == '0' &&
        (value[1] == 'x' || value[1] == 'X')) {
        value.erase(0u, 2u);
    }
    if (value.size() != 64u) {
        error = "-mask expects exactly 64 hex/? nibbles";
        return false;
    }
    result.enabled = true;
    for (std::size_t i = 0u; i < value.size(); ++i) {
        const char token = value[i];
        if (token == '?') {
            result.positions[result.unknown_count++] =
                static_cast<std::uint8_t>(i);
            continue;
        }
        const int nibble = hex_digit(token);
        if (nibble < 0) {
            error = "-mask accepts only hex digits and ?";
            return false;
        }
        const std::size_t byte = i / 2u;
        if ((i & 1u) == 0u) {
            result.bytes[byte] =
                static_cast<std::uint8_t>(nibble << 4);
        } else {
            result.bytes[byte] |= static_cast<std::uint8_t>(nibble);
        }
    }
    return true;
}

modeinfra::U256 power_of_two(unsigned bits) {
    modeinfra::U256 value{};
    if (bits < 256u) {
        value.limbs[bits / 64u] =
            std::uint64_t{1} << (bits & 63u);
    }
    return value;
}

bool is_full_end_text(const std::string& raw) {
    const std::string value = lower_copy(trim_copy(raw));
    return value == "2^256" ||
        value == "0x10000000000000000000000000000000000000000000000000000000000000000";
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

std::uint64_t bounded_count_to_full(const modeinfra::U256& cursor,
                                    std::uint64_t maximum) {
    const std::uint64_t max =
        std::numeric_limits<std::uint64_t>::max();
    if (cursor.limbs[1] != max || cursor.limbs[2] != max ||
        cursor.limbs[3] != max) {
        return maximum;
    }
    const unsigned __int128 remaining =
        static_cast<unsigned __int128>(max) -
        static_cast<unsigned __int128>(cursor.limbs[0]) + 1u;
    return remaining < maximum
        ? static_cast<std::uint64_t>(remaining)
        : maximum;
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

std::array<std::uint8_t, 20> create2_address(
        const std::array<std::uint8_t, 20>& deployer,
        const std::array<std::uint8_t, 32>& salt,
        const std::array<std::uint8_t, 32>& init_code_hash) {
    std::array<std::uint8_t, 85> message{};
    message[0] = 0xffu;
    std::copy(deployer.begin(), deployer.end(), message.begin() + 1u);
    std::copy(salt.begin(), salt.end(), message.begin() + 21u);
    std::copy(
        init_code_hash.begin(), init_code_hash.end(),
        message.begin() + 53u);
    const auto digest = keccak256(message.data(), message.size());
    std::array<std::uint8_t, 20> address{};
    std::copy(digest.begin() + 12u, digest.end(), address.begin());
    return address;
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
    if (buffers.base_ordinal) metalFree(buffers.base_ordinal);
    if (buffers.deployer) metalFree(buffers.deployer);
    if (buffers.init_code_hash) metalFree(buffers.init_code_hash);
    if (buffers.salt_template) metalFree(buffers.salt_template);
    if (buffers.unknown_positions) metalFree(buffers.unknown_positions);
    if (buffers.patterns) metalFree(buffers.patterns);
    if (buffers.hits) metalFree(buffers.hits);
    if (buffers.hit_count) metalFree(buffers.hit_count);
    buffers = DeviceBuffers{};
}

bool prepare_buffers(
        int device,
        const std::array<std::uint8_t, 20>& deployer,
        const std::array<std::uint8_t, 32>& init_code_hash,
        const SaltTemplate& salt_template,
        const std::vector<GpuPattern>& patterns,
        DeviceBuffers& buffers,
        std::string& error) {
    buffers.device = device;
    const std::size_t pattern_bytes =
        patterns.size() * sizeof(GpuPattern);
    if (!metal_ok(metalSetDevice(device), "select Metal device", error) ||
        !allocate(buffers.base_ordinal, 32u,
                  "allocate CREATE2 base", error) ||
        !allocate(buffers.deployer, deployer.size(),
                  "allocate CREATE2 deployer", error) ||
        !allocate(buffers.init_code_hash, init_code_hash.size(),
                  "allocate CREATE2 init-code hash", error) ||
        !allocate(buffers.salt_template, salt_template.bytes.size(),
                  "allocate CREATE2 salt template", error) ||
        !allocate(buffers.unknown_positions,
                  salt_template.positions.size(),
                  "allocate CREATE2 template positions", error) ||
        !allocate(buffers.patterns, pattern_bytes,
                  "allocate CREATE2 patterns", error) ||
        !allocate(buffers.hits, sizeof(GpuHit) * kHitCapacity,
                  "allocate CREATE2 hits", error) ||
        !allocate(buffers.hit_count, sizeof(std::uint32_t),
                  "allocate CREATE2 hit count", error)) {
        release_buffers(buffers);
        return false;
    }
    if (!metal_ok(
            metalMemcpy(buffers.deployer, deployer.data(), deployer.size(),
                        metalMemcpyHostToDevice),
            "upload CREATE2 deployer", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.init_code_hash, init_code_hash.data(),
                init_code_hash.size(), metalMemcpyHostToDevice),
            "upload CREATE2 init-code hash", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.salt_template, salt_template.bytes.data(),
                salt_template.bytes.size(), metalMemcpyHostToDevice),
            "upload CREATE2 salt template", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.unknown_positions,
                salt_template.positions.data(),
                salt_template.positions.size(), metalMemcpyHostToDevice),
            "upload CREATE2 template positions", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.patterns, patterns.data(), pattern_bytes,
                metalMemcpyHostToDevice),
            "upload CREATE2 patterns", error)) {
        release_buffers(buffers);
        return false;
    }
    buffers.allocated =
        32u + deployer.size() + init_code_hash.size() +
        salt_template.bytes.size() + salt_template.positions.size() +
        pattern_bytes + sizeof(GpuHit) * kHitCapacity +
        sizeof(std::uint32_t);
    return true;
}

bool launch_batch(
        DeviceBuffers& buffers,
        const std::array<std::uint8_t, 32>& base,
        std::uint64_t count,
        const SaltTemplate& salt_template,
        std::uint32_t pattern_count,
        std::vector<GpuHit>& hits,
        std::uint32_t& raw_count,
        std::uint64_t& readback_ns,
        std::string& error) {
    if (!metal_ok(metalSetDevice(buffers.device),
                  "select CREATE2 device", error) ||
        !metal_ok(
            metalMemcpy(buffers.base_ordinal, base.data(), base.size(),
                        metalMemcpyHostToDevice),
            "upload CREATE2 base", error) ||
        !metal_ok(
            metalMemset(buffers.hit_count, 0u, sizeof(std::uint32_t)),
            "clear CREATE2 hit count", error)) {
        return false;
    }
    const std::uint32_t grid = static_cast<std::uint32_t>(
        (count + kThreadgroupSize - 1u) / kThreadgroupSize);
    const std::uint32_t template_enabled =
        salt_template.enabled ? 1u : 0u;
    if (!metal_ok(
            metal_launch(
                "create2Search", grid, kThreadgroupSize,
                buffers.base_ordinal, count,
                buffers.deployer, buffers.init_code_hash,
                buffers.salt_template, buffers.unknown_positions,
                salt_template.unknown_count, template_enabled,
                buffers.patterns, pattern_count,
                buffers.hits, buffers.hit_count, kHitCapacity),
            "launch CREATE2 kernel", error) ||
        !metal_ok(
            metalDeviceSynchronize(),
            "synchronize CREATE2 kernel", error)) {
        return false;
    }
    const auto started = std::chrono::steady_clock::now();
    if (!metal_ok(
            metalMemcpy(
                &raw_count, buffers.hit_count, sizeof(raw_count),
                metalMemcpyDeviceToHost),
            "read CREATE2 hit count", error)) {
        return false;
    }
    const std::uint32_t stored = std::min(raw_count, kHitCapacity);
    hits.resize(stored);
    if (stored != 0u &&
        !metal_ok(
            metalMemcpy(
                hits.data(), buffers.hits,
                static_cast<std::size_t>(stored) * sizeof(GpuHit),
                metalMemcpyDeviceToHost),
            "read CREATE2 hits", error)) {
        return false;
    }
    readback_ns = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - started).count());
    return true;
}

} // namespace

bool requested(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (argv[i] != nullptr &&
            std::strcmp(argv[i], "-create2") == 0) {
            return true;
        }
    }
    return false;
}

void print_help() {
    std::cout << R"HELP([!] MAIN MODE: -create2  (Ethereum CREATE2 salt search)
[!] ======================================================================
[!] Purpose:
[!] Search 32-byte CREATE2 salts whose deterministic Ethereum contract
[!] address matches one or more prefix/suffix/wildcard patterns.
[!] Metal computes keccak256(0xff || deployer || salt || init_code_hash);
[!] every reported address is recomputed independently on the host.
[!]
[!] Required:
[!] -deployer 0xADDRESS            Exact 20-byte CREATE2 deployer/factory.
[!] -init-code-hash 0xHASH         Exact 32-byte keccak256(init_code).
[!] -pattern VALUE                 Repeatable lowercase ETH address pattern.
[!] -pattern-file FILE             One pattern per line; # comments allowed.
[!] eth:/create2: prefixes are accepted. A pattern without * or ? is a prefix.
[!] Use *suffix for suffix matching and ? for one arbitrary hex character.
[!]
[!] Salt domain:
[!] -start N -end N                Exact ordinal interval [START,END).
[!]                                Decimal, 0xHEX, and 2^EXP are accepted.
[!]                                -end 2^256 selects the full remaining U256.
[!] -mask HEX/?                    Exactly 64 salt nibbles; each ? is one
[!]                                mixed-radix dimension filled by the ordinal.
[!]                                Without -end, the complete template domain
[!]                                is selected. Without -mask, salt=ordinal.
[!] -random                        Cover one finite interval from a random rotation.
[!] -n N                           Salts per Metal launch (default 1048576).
[!]
[!] GPU / MultiGPU:
[!] -device LIST                   Metal indexes, e.g. 0 or 0,1.
[!] Windows are assigned without overlap or gaps; large domains use U256.
[!] Hit overflow halves the uncredited batch and retries it without loss.
[!]
[!] Statistics / output:
[!] Only SpeedThreadFunc prints live statistics, as Addr/s.
[!] -o FILE                        Append verified results.
[!] -save                          Use CREATE2_FOUND.txt when -o is absent.
[!] -silent                        Suppress found-result lines on stdout.
[!] Output includes pattern source, address, full salt, deployer and init hash.
[!]
[!] Examples:
[!] ./METAL_CRYPTO_TOOLKIT -create2 -deployer 0x0000000000000000000000000000000000000000 \
[!]   -init-code-hash 0xbc36789e7a1e281436464229828f817d6612f7b477d66591ff96a9e064bcc98a \
[!]   -pattern 0x4d1a -start 0 -end 65536 -save
[!] ./METAL_CRYPTO_TOOLKIT -create2 -deployer 0xdead00000000000000000000000000000000beef \
[!]   -init-code-hash 0x0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef \
[!]   -pattern 'create2:0x0000*' -mask '000000000000000000000000????????????????????????????????????????' \
[!]   -random -device 0
[!]
[!] Limitations:
[!] Patterns are lowercase non-checksummed Ethereum addresses.
[!] -random requires a finite representable interval (not -end 2^256).
[!] Full U256 arithmetic does not make exhaustive 256-bit search practical.
[!] CLI errors return 2; Metal/runtime failures return 1.
)HELP";
}

int run(int argc, char** argv, const RuntimeHooks& hooks) {
    Options options;
    std::string error;
    if (!parse_options(argc, argv, options, error)) {
        std::cerr << "[!] CREATE2 CLI error: " << error << " [!]\n";
        return 2;
    }

    std::vector<Pattern> patterns;
    if (!load_patterns(options, patterns, error)) {
        std::cerr << "[!] CREATE2 pattern error: " << error << " [!]\n";
        return 2;
    }
    if (patterns.size() >
        static_cast<std::size_t>(
            std::numeric_limits<std::uint32_t>::max())) {
        std::cerr << "[!] CREATE2 CLI error: too many patterns [!]\n";
        return 2;
    }

    std::array<std::uint8_t, 20> deployer{};
    std::array<std::uint8_t, 32> init_code_hash{};
    if (!decode_hex_exact(
            options.deployer, deployer.data(), deployer.size())) {
        std::cerr << "[!] CREATE2 CLI error: -deployer expects exactly "
                     "20 bytes [!]\n";
        return 2;
    }
    if (!decode_hex_exact(
            options.init_code_hash,
            init_code_hash.data(), init_code_hash.size())) {
        std::cerr << "[!] CREATE2 CLI error: -init-code-hash expects "
                     "exactly 32 bytes [!]\n";
        return 2;
    }

    SaltTemplate salt_template;
    if (!parse_salt_template(
            options.salt_mask, salt_template, error)) {
        std::cerr << "[!] CREATE2 CLI error: " << error << " [!]\n";
        return 2;
    }

    modeinfra::U256 start{};
    if (!modeinfra::parse_u256(options.start, start, error)) {
        std::cerr << "[!] CREATE2 domain error: " << error << " [!]\n";
        return 2;
    }
    bool full_end = false;
    modeinfra::U256 end{};
    if (options.end.empty()) {
        if (salt_template.enabled) {
            const unsigned bits = salt_template.unknown_count * 4u;
            if (bits == 256u) {
                full_end = true;
            } else {
                end = power_of_two(bits);
            }
        } else {
            full_end = true;
        }
    } else if (is_full_end_text(options.end)) {
        full_end = true;
    } else if (!modeinfra::parse_u256(options.end, end, error)) {
        std::cerr << "[!] CREATE2 domain error: " << error << " [!]\n";
        return 2;
    }
    if (!full_end && modeinfra::compare(start, end) >= 0) {
        std::cerr << "[!] CREATE2 domain error: -start/-end must define "
                     "a non-empty [START,END) interval [!]\n";
        return 2;
    }
    if (salt_template.enabled &&
        salt_template.unknown_count < 64u) {
        const modeinfra::U256 natural_end =
            power_of_two(salt_template.unknown_count * 4u);
        if (full_end || modeinfra::compare(end, natural_end) > 0) {
            std::cerr << "[!] CREATE2 domain error: ordinal interval "
                         "exceeds the salt template space [!]\n";
            return 2;
        }
    }
    if (options.random && full_end) {
        std::cerr << "[!] CREATE2 CLI error: -random requires a finite "
                     "-end below 2^256 [!]\n";
        return 2;
    }

    int device_count = 0;
    if (!metal_ok(
            metalGetDeviceCount(&device_count),
            "query Metal devices", error)) {
        std::cerr << "[!] CREATE2 runtime error: " << error << " [!]\n";
        return 1;
    }
    for (int device : options.devices) {
        if (device < 0 || device >= device_count) {
            std::cerr << "[!] CREATE2 CLI error: device index "
                      << device << " is unavailable [!]\n";
            return 2;
        }
    }

    std::vector<GpuPattern> gpu_patterns(patterns.size());
    for (std::size_t i = 0u; i < patterns.size(); ++i) {
        gpu_patterns[i].length =
            static_cast<std::uint32_t>(patterns[i].glob.size());
        std::copy(
            patterns[i].glob.begin(), patterns[i].glob.end(),
            gpu_patterns[i].text.begin());
    }

    std::vector<DeviceBuffers> devices(options.devices.size());
    std::uint64_t allocated = 0u;
    for (std::size_t i = 0u; i < devices.size(); ++i) {
        if (!prepare_buffers(
                options.devices[i], deployer, init_code_hash,
                salt_template, gpu_patterns, devices[i], error)) {
            for (auto& buffers : devices) release_buffers(buffers);
            std::cerr << "[!] CREATE2 runtime error: "
                      << error << " [!]\n";
            return 1;
        }
        allocated += devices[i].allocated;
    }

    if (options.output_path.empty() && options.save) {
        options.output_path = "CREATE2_FOUND.txt";
    }
    std::ofstream output;
    if (!options.output_path.empty()) {
        output.open(options.output_path, std::ios::app);
        if (!output) {
            for (auto& buffers : devices) release_buffers(buffers);
            std::cerr << "[!] CREATE2 runtime error: cannot open "
                         "output file [!]\n";
            return 1;
        }
    }

    modeinfra::U256 width{};
    if (!full_end &&
        !modeinfra::subtract_checked(end, start, width)) {
        for (auto& buffers : devices) release_buffers(buffers);
        std::cerr << "[!] CREATE2 domain error: interval underflow [!]\n";
        return 2;
    }
    modeinfra::U256 offset{};
    std::uint64_t random_seed = 0u;
    if (options.random) {
        offset = random_below(width, random_seed);
        std::cout << "[!] CREATE2 random rotation seed: "
                  << random_seed << " [!]\n";
    }

    std::cout << "[!] CREATE2 patterns: " << patterns.size()
              << " | devices: " << devices.size()
              << " | batch: " << options.batch
              << " | salt: "
              << (salt_template.enabled ? "template" : "ordinal")
              << " [!]\n";

    modeinfra::ModeProgress& progress =
        modeinfra::global_mode_progress();
    progress.begin(
        "CREATE2", modeinfra::ProgressUnit::Address,
        modeinfra::ProgressPhase::Search);
    progress.set_targets(patterns.size(), patterns.size(), 0u);
    progress.set_allocated_working_set(allocated);

    modeinfra::U256 cursor = full_end ? start : modeinfra::U256{};
    std::uint64_t founds = 0u;
    int result = 0;
    std::size_t device_slot = 0u;
    bool full_done = false;
    while (founds < patterns.size() &&
           (full_end ? !full_done :
            modeinfra::compare(cursor, width) < 0)) {
        modeinfra::U256 base_ordinal{};
        std::uint64_t count = 0u;
        if (full_end) {
            base_ordinal = cursor;
            count = bounded_count_to_full(cursor, options.batch);
        } else {
            const modeinfra::U256 physical =
                options.random
                ? rotated_ordinal(cursor, offset, width)
                : cursor;
            modeinfra::U256 until_wrap{};
            (void)modeinfra::subtract_checked(
                width, physical, until_wrap);
            count = bounded_count(until_wrap, options.batch);
            modeinfra::U256 logical_remaining{};
            (void)modeinfra::subtract_checked(
                width, cursor, logical_remaining);
            count = std::min(
                count, bounded_count(logical_remaining, count));
            if (!modeinfra::add_checked(
                    start, physical, base_ordinal)) {
                error = "CREATE2 ordinal base overflow";
                result = 1;
                break;
            }
        }
        if (count == 0u) {
            error = "CREATE2 scheduler produced an empty window";
            result = 1;
            break;
        }

        DeviceBuffers& buffers =
            devices[device_slot++ % devices.size()];
        std::vector<GpuHit> hits;
        std::uint32_t raw_count = 0u;
        std::uint64_t readback_ns = 0u;
        if (!launch_batch(
                buffers, u256_bytes(base_ordinal), count,
                salt_template,
                static_cast<std::uint32_t>(gpu_patterns.size()),
                hits, raw_count, readback_ns, error)) {
            result = 1;
            break;
        }
        if (raw_count > kHitCapacity) {
            if (count == 1u) {
                error = "CREATE2 hit buffer overflow for one salt";
                result = 1;
                break;
            }
            options.batch =
                std::max<std::uint64_t>(1u, count / 2u);
            continue;
        }

        for (const GpuHit& hit : hits) {
            if (hit.pattern_index >= patterns.size()) {
                error = "Metal returned an invalid CREATE2 hit";
                result = 1;
                break;
            }
            Pattern& pattern = patterns[hit.pattern_index];
            if (pattern.solved) continue;
            const auto verified = create2_address(
                deployer, hit.salt, init_code_hash);
            const std::string address =
                "0x" + hex_lower(verified.data(), verified.size());
            if (verified != hit.address ||
                !glob_match(address, pattern.glob)) {
                error = "host verification rejected Metal CREATE2 hit";
                result = 1;
                break;
            }
            const std::string line =
                "[+] CREATE2:PATTERN:" + pattern.display +
                ":SOURCE:" + pattern.source +
                ":ADDRESS:" + address +
                ":SALT:" +
                hex_lower(hit.salt.data(), hit.salt.size()) +
                ":DEPLOYER:0x" +
                hex_lower(deployer.data(), deployer.size()) +
                ":INIT_CODE_HASH:0x" +
                hex_lower(init_code_hash.data(), init_code_hash.size());
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
        progress.credit_completed(
            count, count, hits.size(), readback_ns);
        modeinfra::U256 next{};
        if (full_end) {
            if (!modeinfra::add_checked(
                    cursor, modeinfra::U256::from_u64(count), next)) {
                full_done = true;
            } else {
                cursor = next;
            }
        } else {
            if (!modeinfra::add_checked(
                    cursor, modeinfra::U256::from_u64(count), next)) {
                error = "CREATE2 logical cursor overflow";
                result = 1;
                break;
            }
            cursor = next;
        }
    }

    progress.set_phase(modeinfra::ProgressPhase::Verify);
    progress.end();
    for (auto& buffers : devices) release_buffers(buffers);
    if (result != 0) {
        std::cerr << "[!] CREATE2 runtime error: " << error << " [!]\n";
        return result;
    }
    std::cout << "[!] CREATE2 search complete. Solved "
              << founds << "/" << patterns.size()
              << " patterns. [!]\n";
    return 0;
}

} // namespace create2_mode
