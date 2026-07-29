#include "AezeedMode.h"

#include "../MetalBackend.h"
#include "../RecoveryWordlistsEmbedded.h"
#include "../SecpPrecompute.h"
#include "../host_secp/secp256k1.h"
#include "../host_secp/secp256k1_field.h"
#include "../host_secp/secp256k1_group.h"
#include "../host_secp/secp256k1_scalar.h"
#include "../lib/hash/sha256.h"
#include "../sr25519-donna-32bit/dot.h"

#include <CommonCrypto/CommonHMAC.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace aezeed_mode {
namespace {

constexpr std::uint32_t kThreadgroupSize = 256u;
constexpr std::uint64_t kMaximumBatch = 4096u;
constexpr std::uint64_t kDefaultBatch = kMaximumBatch;
constexpr std::uint32_t kHitCapacity = 4096u;
constexpr std::uint64_t kRuntimeReserve =
    512ull * 1024ull * 1024ull;
constexpr std::uint64_t kPasswordStride = 128u;
constexpr std::uint32_t kKnownInternalVersions = 0x3u;

struct GpuConfig {
    std::array<std::uint8_t, 23> ciphertext{};
    std::array<std::uint8_t, 5> salt{};
    std::uint32_t maximum_birthday = 0xffffu;
    std::uint32_t known_internal_versions =
        kKnownInternalVersions;
};

struct alignas(8) GpuHit {
    std::uint64_t candidate_index = 0u;
    std::uint32_t password_len = 0u;
    std::uint32_t internal_version = 0u;
    std::uint32_t birthday = 0u;
    std::uint32_t reserved = 0u;
    std::array<std::uint8_t, 128> password{};
    std::array<std::uint8_t, 16> entropy{};
    std::array<std::uint8_t, 19> plaintext{};
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 5> padding{};
};

static_assert(sizeof(GpuConfig) == 36u);
static_assert(sizeof(GpuHit) == 224u);

struct Options {
    std::vector<std::string> recovery_values;
    std::vector<std::pair<std::string, bool>> password_inputs;
    std::vector<std::string> target_values;
    std::vector<std::string> entropy_values;
    std::string mask;
    std::string start;
    std::string end;
    std::string memory = "auto";
    std::string scrypt_memory;
    std::string output_path;
    std::vector<int> devices{0};
    std::uint64_t batch = kDefaultBatch;
    bool batch_explicit = false;
    bool save = false;
    bool silent = false;
};

struct CipherSeed {
    std::array<std::uint8_t, 33> encoded{};
    std::string source;
};

enum class TargetKind : std::uint8_t {
    EntropyHash,
    RootPublic,
    ExactEntropy,
};

struct Target {
    TargetKind kind = TargetKind::EntropyHash;
    std::array<std::uint8_t, 33> value{};
    std::size_t value_size = 0u;
    std::vector<std::string> origins;
    bool solved = false;
};

struct HostPrecompute {
    unsigned bits = 12u;
    std::vector<secp256k1_ge_storage> entries;
    std::size_t pitch = 0u;
    unsigned windows = 0u;
};

struct DeviceBuffers {
    int device = -1;
    char* passwords = nullptr;
    std::uint8_t* password_lengths = nullptr;
    std::uint8_t* scratch = nullptr;
    GpuHit* hits = nullptr;
    std::uint32_t* hit_count = nullptr;
    std::uint8_t* salt = nullptr;
    std::uint64_t capacity = 0u;
    std::uint64_t allocated = 0u;
};

std::string trim_copy(std::string text) {
    const std::size_t first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const std::size_t last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1u);
}

std::string lower_copy(std::string text) {
    std::transform(
        text.begin(), text.end(), text.begin(),
        [](unsigned char value) {
            return static_cast<char>(std::tolower(value));
        });
    return text;
}

bool parse_u64(const std::string& text, std::uint64_t& value) {
    try {
        std::size_t consumed = 0u;
        value = std::stoull(text, &consumed, 0);
        return consumed == text.size();
    } catch (...) {
        return false;
    }
}

bool decode_hex(
    const std::string& raw,
    std::vector<std::uint8_t>& output) {
    std::string text = trim_copy(raw);
    if (text.size() >= 2u && text[0] == '0' &&
        (text[1] == 'x' || text[1] == 'X')) {
        text.erase(0u, 2u);
    }
    if (text.empty() || (text.size() & 1u) != 0u) return false;
    output.clear();
    output.reserve(text.size() / 2u);
    for (std::size_t i = 0u; i < text.size(); i += 2u) {
        const auto digit = [](char value) -> int {
            if (value >= '0' && value <= '9') return value - '0';
            if (value >= 'a' && value <= 'f') return value - 'a' + 10;
            if (value >= 'A' && value <= 'F') return value - 'A' + 10;
            return -1;
        };
        const int high = digit(text[i]);
        const int low = digit(text[i + 1u]);
        if (high < 0 || low < 0) return false;
        output.push_back(
            static_cast<std::uint8_t>((high << 4u) | low));
    }
    return true;
}

std::string hex_string(
    const std::uint8_t* data, std::size_t size) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0u; i < size; ++i) {
        out << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return out.str();
}

std::vector<std::string> split_words(const std::string& text) {
    std::istringstream input(text);
    std::vector<std::string> words;
    std::string word;
    while (input >> word) words.push_back(lower_copy(word));
    return words;
}

bool parse_devices(
    const std::string& raw,
    std::vector<int>& devices,
    std::string& error) {
    std::set<int> unique;
    std::stringstream input(raw);
    std::string token;
    while (std::getline(input, token, ',')) {
        token = trim_copy(token);
        if (token.empty()) {
            error = "empty item in -device";
            return false;
        }
        const std::size_t dash = token.find('-');
        if (dash == std::string::npos) {
            std::uint64_t value = 0u;
            if (!parse_u64(token, value) ||
                value > static_cast<std::uint64_t>(
                    std::numeric_limits<int>::max())) {
                error = "invalid -device item '" + token + "'";
                return false;
            }
            unique.insert(static_cast<int>(value));
            continue;
        }
        std::uint64_t first = 0u;
        std::uint64_t last = 0u;
        if (!parse_u64(token.substr(0u, dash), first) ||
            !parse_u64(token.substr(dash + 1u), last) ||
            first > last || last > 1024u) {
            error = "invalid -device range '" + token + "'";
            return false;
        }
        for (std::uint64_t value = first; value <= last; ++value) {
            unique.insert(static_cast<int>(value));
        }
    }
    if (unique.empty()) {
        error = "-device list is empty";
        return false;
    }
    devices.assign(unique.begin(), unique.end());
    return true;
}

bool parse_options(
    int argc, char** argv, Options& options,
    std::string& error) {
    bool after_mode = false;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-aezeed") {
            after_mode = true;
            continue;
        }
        const auto require_value = [&](const char* flag) -> const char* {
            if (i + 1 >= argc) {
                error = std::string(flag) + " requires a value";
                return nullptr;
            }
            return argv[++i];
        };
        if (arg == "-recovery") {
            const char* value = require_value("-recovery");
            if (!value) return false;
            options.recovery_values.emplace_back(value);
        } else if (arg == "-pass") {
            const char* value = require_value("-pass");
            if (!value) return false;
            options.password_inputs.push_back({value, false});
        } else if (arg == "-i") {
            const char* value = require_value("-i");
            if (!value) return false;
            options.password_inputs.push_back({value, true});
        } else if (arg == "-target") {
            const char* value = require_value("-target");
            if (!value) return false;
            options.target_values.emplace_back(value);
        } else if (arg == "-entropy") {
            const char* value = require_value("-entropy");
            if (!value) return false;
            options.entropy_values.emplace_back(value);
        } else if (arg == "-mask") {
            const char* value = require_value("-mask");
            if (!value) return false;
            options.mask = value;
        } else if (arg == "-start") {
            const char* value = require_value("-start");
            if (!value) return false;
            options.start = value;
        } else if (arg == "-end") {
            const char* value = require_value("-end");
            if (!value) return false;
            options.end = value;
        } else if (arg == "-wallet-mem") {
            const char* value = require_value("-wallet-mem");
            if (!value) return false;
            options.memory = value;
        } else if (arg == "-wallet-scrypt-mem") {
            const char* value = require_value("-wallet-scrypt-mem");
            if (!value) return false;
            options.scrypt_memory = value;
        } else if (arg == "-n") {
            const char* value = require_value("-n");
            if (!value || !parse_u64(value, options.batch) ||
                options.batch == 0u ||
                options.batch > kMaximumBatch) {
                error = "-n must be in 1..4096";
                return false;
            }
            options.batch_explicit = true;
        } else if (arg == "-device") {
            const char* value = require_value("-device");
            if (!value ||
                !parse_devices(value, options.devices, error)) {
                return false;
            }
        } else if (arg == "-o") {
            const char* value = require_value("-o");
            if (!value) return false;
            options.output_path = value;
        } else if (arg == "-save") {
            options.save = true;
        } else if (arg == "-silent") {
            options.silent = true;
        } else if (arg == "-help" || arg == "--help" ||
                   arg == "-h" || arg == "help") {
            continue;
        } else if (!arg.empty() && arg[0] != '-' && after_mode) {
            options.recovery_values.push_back(arg);
        } else {
            error = "unsupported -aezeed argument '" + arg + "'";
            return false;
        }
    }
    if (options.recovery_values.empty()) {
        error = "-aezeed requires -recovery FILE or a 24-word mnemonic";
        return false;
    }
    const int candidate_modes =
        (!options.password_inputs.empty() ? 1 : 0) +
        (!options.mask.empty() ? 1 : 0) +
        ((!options.start.empty() || !options.end.empty()) ? 1 : 0);
    if (candidate_modes > 1) {
        error = "choose one password source: -pass/-i, -mask, or -start/-end";
        return false;
    }
    if ((!options.start.empty() || !options.end.empty()) &&
        (options.start.empty() || options.end.empty())) {
        error = "numeric password search requires both -start and -end";
        return false;
    }
    return true;
}

std::uint32_t crc32c(
    const std::uint8_t* data, std::size_t size) {
    std::uint32_t crc = 0xffffffffu;
    for (std::size_t i = 0u; i < size; ++i) {
        crc ^= data[i];
        for (unsigned bit = 0u; bit < 8u; ++bit) {
            const std::uint32_t mask =
                0u - (crc & 1u);
            crc = (crc >> 1u) ^ (0x82f63b78u & mask);
        }
    }
    return ~crc;
}

void pack_mnemonic(
    const std::array<std::uint16_t, 24>& words,
    std::array<std::uint8_t, 33>& encoded) {
    encoded.fill(0u);
    std::size_t bit_offset = 0u;
    for (const std::uint16_t word : words) {
        for (int bit = 10; bit >= 0; --bit, ++bit_offset) {
            if (((word >> bit) & 1u) != 0u) {
                encoded[bit_offset >> 3u] |=
                    static_cast<std::uint8_t>(
                        1u << (7u - (bit_offset & 7u)));
            }
        }
    }
}

bool valid_encoded_seed(
    const std::array<std::uint8_t, 33>& encoded) {
    if (encoded[0] != 0u) return false;
    const std::uint32_t expected =
        (static_cast<std::uint32_t>(encoded[29]) << 24u) |
        (static_cast<std::uint32_t>(encoded[30]) << 16u) |
        (static_cast<std::uint32_t>(encoded[31]) << 8u) |
        static_cast<std::uint32_t>(encoded[32]);
    return crc32c(encoded.data(), 29u) == expected;
}

const std::unordered_map<std::string, std::uint16_t>&
word_index() {
    static const auto index = [] {
        std::unordered_map<std::string, std::uint16_t> result;
        result.reserve(2048u);
        for (std::uint16_t i = 0u; i < 2048u; ++i) {
            result.emplace(kRecoveryWords_bip39_en[i], i);
        }
        return result;
    }();
    return index;
}

bool add_mnemonic_template(
    const std::string& phrase, const std::string& source,
    std::vector<CipherSeed>& seeds,
    std::uint64_t& template_candidates,
    std::string& error) {
    const std::vector<std::string> tokens = split_words(phrase);
    if (tokens.size() != 24u) {
        error = source + ": aezeed mnemonic must contain exactly 24 words";
        return false;
    }
    std::array<std::uint16_t, 24> words{};
    std::vector<std::size_t> unknown;
    for (std::size_t i = 0u; i < tokens.size(); ++i) {
        if (tokens[i] == "?" || tokens[i] == "*") {
            unknown.push_back(i);
            continue;
        }
        const auto found = word_index().find(tokens[i]);
        if (found == word_index().end()) {
            error = source + ": unknown English BIP39 word '" +
                tokens[i] + "'";
            return false;
        }
        words[i] = found->second;
    }
    if (unknown.size() > 2u) {
        error = source + ": at most two unknown words are supported";
        return false;
    }
    std::uint64_t combinations = 1u;
    for (std::size_t i = 0u; i < unknown.size(); ++i) {
        combinations *= 2048u;
    }
    template_candidates += combinations;
    const std::size_t before = seeds.size();
    for (std::uint64_t ordinal = 0u;
         ordinal < combinations; ++ordinal) {
        std::uint64_t value = ordinal;
        for (const std::size_t position : unknown) {
            words[position] =
                static_cast<std::uint16_t>(value & 2047u);
            value >>= 11u;
        }
        std::array<std::uint8_t, 33> encoded{};
        pack_mnemonic(words, encoded);
        if (valid_encoded_seed(encoded)) {
            seeds.push_back({encoded, source});
        }
    }
    if (seeds.size() == before) {
        error = source + ": no checksum-valid aezeed mnemonic";
        return false;
    }
    return true;
}

bool load_seeds(
    const Options& options,
    std::vector<CipherSeed>& seeds,
    std::uint64_t& template_candidates,
    std::string& error) {
    std::unordered_set<std::string> unique;
    for (const std::string& value : options.recovery_values) {
        std::error_code filesystem_error;
        if (std::filesystem::is_regular_file(
                value, filesystem_error) &&
            !filesystem_error) {
            std::ifstream input(value);
            if (!input) {
                error = "cannot open recovery file '" + value + "'";
                return false;
            }
            std::string line;
            std::size_t line_number = 0u;
            while (std::getline(input, line)) {
                ++line_number;
                const std::size_t comment = line.find('#');
                if (comment != std::string::npos) {
                    line.erase(comment);
                }
                line = trim_copy(line);
                if (line.empty()) continue;
                std::vector<CipherSeed> decoded;
                if (!add_mnemonic_template(
                        line, value + ":" +
                            std::to_string(line_number),
                        decoded, template_candidates, error)) {
                    return false;
                }
                for (CipherSeed& seed : decoded) {
                    const std::string key(
                        reinterpret_cast<const char*>(
                            seed.encoded.data()),
                        seed.encoded.size());
                    if (unique.insert(key).second) {
                        seeds.push_back(std::move(seed));
                    }
                }
            }
        } else {
            std::vector<CipherSeed> decoded;
            if (!add_mnemonic_template(
                    value, "argv recovery", decoded,
                    template_candidates, error)) {
                return false;
            }
            for (CipherSeed& seed : decoded) {
                const std::string key(
                    reinterpret_cast<const char*>(
                        seed.encoded.data()),
                    seed.encoded.size());
                if (unique.insert(key).second) {
                    seeds.push_back(std::move(seed));
                }
            }
        }
    }
    if (seeds.empty()) {
        error = "no checksum-valid aezeed cipherseeds";
        return false;
    }
    return true;
}

std::uint8_t gf_multiply(
    std::uint8_t left, std::uint8_t right) {
    std::uint8_t result = 0u;
    while (right != 0u) {
        if ((right & 1u) != 0u) result ^= left;
        left = static_cast<std::uint8_t>(
            (left << 1u) ^
            ((left & 0x80u) != 0u ? 0x1bu : 0u));
        right >>= 1u;
    }
    return result;
}

std::uint8_t aes_sbox(std::uint8_t value) {
    std::uint8_t inverse = 0u;
    if (value != 0u) {
        inverse = 1u;
        std::uint8_t base = value;
        unsigned exponent = 254u;
        while (exponent != 0u) {
            if ((exponent & 1u) != 0u) {
                inverse = gf_multiply(inverse, base);
            }
            base = gf_multiply(base, base);
            exponent >>= 1u;
        }
    }
    const auto rotate = [](std::uint8_t input, unsigned count) {
        return static_cast<std::uint8_t>(
            (input << count) | (input >> (8u - count)));
    };
    return static_cast<std::uint8_t>(
        inverse ^ rotate(inverse, 1u) ^
        rotate(inverse, 2u) ^ rotate(inverse, 3u) ^
        rotate(inverse, 4u) ^ 0x63u);
}

void aes_round(
    std::array<std::uint8_t, 16>& state,
    const std::uint8_t* key) {
    for (std::uint8_t& byte : state) byte = aes_sbox(byte);
    const auto previous = state;
    state[0] = previous[0];
    state[4] = previous[4];
    state[8] = previous[8];
    state[12] = previous[12];
    state[1] = previous[5];
    state[5] = previous[9];
    state[9] = previous[13];
    state[13] = previous[1];
    state[2] = previous[10];
    state[6] = previous[14];
    state[10] = previous[2];
    state[14] = previous[6];
    state[3] = previous[15];
    state[7] = previous[3];
    state[11] = previous[7];
    state[15] = previous[11];
    for (std::size_t column = 0u; column < 4u; ++column) {
        const std::size_t offset = column * 4u;
        const std::uint8_t a0 = state[offset];
        const std::uint8_t a1 = state[offset + 1u];
        const std::uint8_t a2 = state[offset + 2u];
        const std::uint8_t a3 = state[offset + 3u];
        state[offset] =
            gf_multiply(a0, 2u) ^ gf_multiply(a1, 3u) ^ a2 ^ a3;
        state[offset + 1u] =
            a0 ^ gf_multiply(a1, 2u) ^ gf_multiply(a2, 3u) ^ a3;
        state[offset + 2u] =
            a0 ^ a1 ^ gf_multiply(a2, 2u) ^ gf_multiply(a3, 3u);
        state[offset + 3u] =
            gf_multiply(a0, 3u) ^ a1 ^ a2 ^ gf_multiply(a3, 2u);
    }
    for (std::size_t i = 0u; i < state.size(); ++i) {
        state[i] ^= key[i];
    }
}

struct AezState {
    std::array<std::uint8_t, 48> extracted{};
    std::array<std::array<std::uint8_t, 16>, 2> I{};
    std::array<std::array<std::uint8_t, 16>, 3> J{};
    std::array<std::array<std::uint8_t, 16>, 8> L{};
};

void double_block(std::array<std::uint8_t, 16>& block) {
    const std::uint8_t first = block[0];
    for (std::size_t i = 0u; i < 15u; ++i) {
        block[i] = static_cast<std::uint8_t>(
            (block[i] << 1u) | (block[i + 1u] >> 7u));
    }
    block[15] = static_cast<std::uint8_t>(
        (block[15] << 1u) ^
        ((first & 0x80u) != 0u ? 0x87u : 0u));
}

std::array<std::uint8_t, 16> multiply_block(
    unsigned multiplier,
    const std::array<std::uint8_t, 16>& source) {
    std::array<std::uint8_t, 16> result{};
    auto term = source;
    while (multiplier != 0u) {
        if ((multiplier & 1u) != 0u) {
            for (std::size_t i = 0u; i < result.size(); ++i) {
                result[i] ^= term[i];
            }
        }
        double_block(term);
        multiplier >>= 1u;
    }
    return result;
}

std::array<std::uint8_t, 16> aez_aes4(
    const AezState& state,
    const std::array<std::uint8_t, 16>& j,
    const std::array<std::uint8_t, 16>& i,
    const std::array<std::uint8_t, 16>& l,
    const std::array<std::uint8_t, 16>& source) {
    std::array<std::uint8_t, 16> output{};
    for (std::size_t n = 0u; n < output.size(); ++n) {
        output[n] = source[n] ^ j[n] ^ i[n] ^ l[n];
    }
    aes_round(output, state.extracted.data() + 16u);
    aes_round(output, state.extracted.data());
    aes_round(output, state.extracted.data() + 32u);
    const std::array<std::uint8_t, 16> zero{};
    aes_round(output, zero.data());
    return output;
}

void aez_state_init(
    const std::array<std::uint8_t, 32>& key,
    AezState& state) {
    blake2b(
        key.data(), key.size(),
        state.extracted.data(), state.extracted.size());
    std::copy_n(state.extracted.begin(), 16u, state.I[0].begin());
    state.I[1] = state.I[0];
    double_block(state.I[1]);
    std::copy_n(
        state.extracted.begin() + 16u, 16u,
        state.J[0].begin());
    state.J[1] = state.J[0];
    double_block(state.J[1]);
    state.J[2] = state.J[1];
    double_block(state.J[2]);
    std::copy_n(
        state.extracted.begin() + 32u, 16u,
        state.L[1].begin());
    state.L[2] = state.L[1];
    double_block(state.L[2]);
    for (std::size_t n = 0u; n < 16u; ++n) {
        state.L[3][n] = state.L[2][n] ^ state.L[1][n];
    }
    state.L[4] = state.L[2];
    double_block(state.L[4]);
    for (std::size_t n = 0u; n < 16u; ++n) {
        state.L[5][n] = state.L[4][n] ^ state.L[1][n];
    }
    state.L[6] = state.L[3];
    double_block(state.L[6]);
    for (std::size_t n = 0u; n < 16u; ++n) {
        state.L[7][n] = state.L[6][n] ^ state.L[1][n];
    }
}

std::array<std::uint8_t, 16> aez_hash(
    const AezState& state,
    const std::array<std::uint8_t, 6>& ad) {
    std::array<std::uint8_t, 16> buffer{};
    buffer[15] = 32u;
    std::array<std::uint8_t, 16> j{};
    for (std::size_t n = 0u; n < 16u; ++n) {
        j[n] = state.J[0][n] ^ state.J[1][n];
    }
    auto result = aez_aes4(
        state, j, state.I[1], state.L[1], buffer);

    buffer.fill(0u);
    buffer[0] = 0x80u;
    auto temporary = aez_aes4(
        state, state.J[2], state.I[0],
        state.L[0], buffer);
    for (std::size_t n = 0u; n < 16u; ++n) {
        result[n] ^= temporary[n];
    }

    j = multiply_block(5u, state.J[0]);
    buffer.fill(0u);
    std::copy(ad.begin(), ad.end(), buffer.begin());
    buffer[6] = 0x80u;
    temporary = aez_aes4(
        state, j, state.I[0], state.L[0], buffer);
    for (std::size_t n = 0u; n < 16u; ++n) {
        result[n] ^= temporary[n];
    }
    return result;
}

std::array<std::uint8_t, 23> aez_tiny_decipher(
    const AezState& state,
    const std::array<std::uint8_t, 16>& delta,
    const std::array<std::uint8_t, 23>& input) {
    std::array<std::uint8_t, 16> left{};
    std::array<std::uint8_t, 16> right{};
    std::copy_n(input.begin(), 12u, left.begin());
    std::copy_n(input.begin() + 11u, 12u, right.begin());
    for (std::size_t n = 0u; n < 11u; ++n) {
        right[n] = static_cast<std::uint8_t>(
            (right[n] << 4u) | (right[n + 1u] >> 4u));
    }
    right[11] = static_cast<std::uint8_t>(right[11] << 4u);
    const std::array<std::uint8_t, 16> zero{};
    for (int j = 7; j >= 1; j -= 2) {
        std::array<std::uint8_t, 16> buffer{};
        std::copy_n(right.begin(), 12u, buffer.begin());
        buffer[11] =
            static_cast<std::uint8_t>((buffer[11] & 0xf0u) | 0x08u);
        for (std::size_t n = 0u; n < 16u; ++n) {
            buffer[n] ^= delta[n];
        }
        buffer[15] ^= static_cast<std::uint8_t>(j);
        auto temporary = aez_aes4(
            state, zero, state.I[1], state.L[6], buffer);
        for (std::size_t n = 0u; n < 16u; ++n) {
            left[n] ^= temporary[n];
        }

        buffer.fill(0u);
        std::copy_n(left.begin(), 12u, buffer.begin());
        buffer[11] =
            static_cast<std::uint8_t>((buffer[11] & 0xf0u) | 0x08u);
        for (std::size_t n = 0u; n < 16u; ++n) {
            buffer[n] ^= delta[n];
        }
        buffer[15] ^= static_cast<std::uint8_t>(j - 1);
        temporary = aez_aes4(
            state, zero, state.I[1], state.L[6], buffer);
        for (std::size_t n = 0u; n < 16u; ++n) {
            right[n] ^= temporary[n];
        }
    }
    std::array<std::uint8_t, 32> merged{};
    std::copy_n(right.begin(), 11u, merged.begin());
    std::copy_n(left.begin(), 12u, merged.begin() + 11u);
    for (int n = 22; n > 11; --n) {
        merged[static_cast<std::size_t>(n)] =
            static_cast<std::uint8_t>(
                (merged[static_cast<std::size_t>(n)] >> 4u) |
                (merged[static_cast<std::size_t>(n - 1)] << 4u));
    }
    merged[11] = static_cast<std::uint8_t>(
        (left[0] >> 4u) | (right[11] & 0xf0u));
    std::array<std::uint8_t, 23> output{};
    std::copy_n(merged.begin(), output.size(), output.begin());
    return output;
}

bool host_decipher(
    const GpuConfig& config,
    const std::array<std::uint8_t, 32>& key,
    std::array<std::uint8_t, 19>& plaintext) {
    AezState state;
    aez_state_init(key, state);
    std::array<std::uint8_t, 6> ad{};
    std::copy(config.salt.begin(), config.salt.end(), ad.begin() + 1u);
    const auto delta = aez_hash(state, ad);
    const auto decoded =
        aez_tiny_decipher(state, delta, config.ciphertext);
    std::uint8_t tag = 0u;
    for (std::size_t i = 19u; i < decoded.size(); ++i) {
        tag |= decoded[i];
    }
    if (tag != 0u) return false;
    std::copy_n(decoded.begin(), plaintext.size(), plaintext.begin());
    return true;
}

bool normalize_public_key(
    const std::vector<std::uint8_t>& bytes,
    std::array<std::uint8_t, 33>& compressed) {
    if (bytes.size() != 33u && bytes.size() != 65u) return false;
    secp256k1_ge point{};
    if (bytes.size() == 33u) {
        if (bytes[0] != 2u && bytes[0] != 3u) return false;
        secp256k1_fe x{};
        if (!secp256k1_fe_set_b32(&x, bytes.data() + 1u) ||
            !secp256k1_ge_set_xo_var(
                &point, &x, bytes[0] == 3u)) {
            return false;
        }
    } else {
        if (bytes[0] != 4u) return false;
        secp256k1_fe x{};
        secp256k1_fe y{};
        if (!secp256k1_fe_set_b32(&x, bytes.data() + 1u) ||
            !secp256k1_fe_set_b32(&y, bytes.data() + 33u)) {
            return false;
        }
        secp256k1_fe_normalize_var(&y);
        if (!secp256k1_ge_set_xo_var(
                &point, &x, secp256k1_fe_is_odd(&y)) ||
            !secp256k1_fe_equal(&point.y, &y)) {
            return false;
        }
    }
    secp256k1_pubkey public_key{};
    secp256k1_pubkey_save(&public_key, &point);
    return secp256k1_ec_pubkey_serialize(
        compressed.data(), compressed.size(),
        &public_key, true) != 0;
}

bool add_target_token(
    const std::string& token, const std::string& source,
    std::vector<Target>& targets,
    std::unordered_map<std::string, std::size_t>& unique,
    std::string& error) {
    std::vector<std::uint8_t> bytes;
    if (!decode_hex(token, bytes)) {
        error = source + ": target is not hexadecimal";
        return false;
    }
    Target target;
    std::string key;
    if (bytes.size() == 32u) {
        target.kind = TargetKind::EntropyHash;
        target.value_size = 32u;
        std::copy(bytes.begin(), bytes.end(), target.value.begin());
        key = "h:" + hex_string(bytes.data(), bytes.size());
    } else if (bytes.size() == 33u || bytes.size() == 65u) {
        target.kind = TargetKind::RootPublic;
        target.value_size = 33u;
        if (!normalize_public_key(bytes, target.value)) {
            error = source + ": invalid secp256k1 public key";
            return false;
        }
        key = "p:" + hex_string(
            target.value.data(), target.value_size);
    } else {
        error = source +
            ": target must be SHA256(entropy) or a 33/65-byte root public key";
        return false;
    }
    const auto found = unique.find(key);
    if (found != unique.end()) {
        targets[found->second].origins.push_back(source);
        return true;
    }
    target.origins.push_back(source);
    unique.emplace(key, targets.size());
    targets.push_back(std::move(target));
    return true;
}

bool load_targets(
    const Options& options,
    std::vector<Target>& targets,
    std::uint64_t& logical_targets,
    std::string& error) {
    std::unordered_map<std::string, std::size_t> unique;
    for (const std::string& value : options.target_values) {
        std::error_code filesystem_error;
        if (std::filesystem::is_regular_file(
                value, filesystem_error) &&
            !filesystem_error) {
            std::ifstream input(value);
            if (!input) {
                error = "cannot open target file '" + value + "'";
                return false;
            }
            std::string line;
            std::size_t line_number = 0u;
            while (std::getline(input, line)) {
                ++line_number;
                const std::size_t comment = line.find('#');
                if (comment != std::string::npos) line.erase(comment);
                std::istringstream fields(line);
                std::string token;
                if (!(fields >> token)) continue;
                ++logical_targets;
                if (!add_target_token(
                        token, value + ":" +
                            std::to_string(line_number),
                        targets, unique, error)) {
                    return false;
                }
            }
        } else {
            ++logical_targets;
            if (!add_target_token(
                    value, "argv target " +
                        std::to_string(logical_targets),
                    targets, unique, error)) {
                return false;
            }
        }
    }
    for (const std::string& value : options.entropy_values) {
        std::vector<std::uint8_t> bytes;
        if (!decode_hex(value, bytes) || bytes.size() != 16u) {
            error = "-entropy expects exactly 16 bytes of hex";
            return false;
        }
        ++logical_targets;
        Target target;
        target.kind = TargetKind::ExactEntropy;
        target.value_size = 16u;
        std::copy(bytes.begin(), bytes.end(), target.value.begin());
        const std::string key =
            "e:" + hex_string(bytes.data(), bytes.size());
        const auto found = unique.find(key);
        if (found != unique.end()) {
            targets[found->second].origins.push_back(
                "argv entropy " +
                std::to_string(logical_targets));
        } else {
            target.origins.push_back(
                "argv entropy " +
                std::to_string(logical_targets));
            unique.emplace(key, targets.size());
            targets.push_back(std::move(target));
        }
    }
    return true;
}

bool build_precompute(
    HostPrecompute& result, std::string& error) {
    return build_secp256k1_precompute_table_host(
        result.bits, result.entries, result.pitch,
        result.windows, error);
}

bool derive_root_public(
    const std::array<std::uint8_t, 16>& entropy,
    const HostPrecompute& precompute,
    std::array<std::uint8_t, 33>& output) {
    static constexpr char key[] = "Bitcoin seed";
    std::array<std::uint8_t, 64> digest{};
    CCHmac(
        kCCHmacAlgSHA512, key, sizeof(key) - 1u,
        entropy.data(), entropy.size(), digest.data());
    secp256k1_scalar scalar{};
    if (!secp256k1_scalar_set_b32_seckey(
            &scalar, digest.data())) {
        return false;
    }
    secp256k1_gej jacobian{};
    secp256k1_ecmult_big(
        &jacobian, &scalar, precompute.entries.data(),
        precompute.pitch,
        static_cast<int>(precompute.windows),
        precompute.bits);
    if (jacobian.infinity != 0) return false;
    secp256k1_ge point{};
    secp256k1_ge_set_gej(&point, &jacobian);
    secp256k1_pubkey public_key{};
    secp256k1_pubkey_save(&public_key, &point);
    return secp256k1_ec_pubkey_serialize(
        output.data(), output.size(),
        &public_key, true) != 0;
}

bool printable_password(
    const std::string& password, std::string& error) {
    if (password.size() >= kPasswordStride) {
        error = "aezeed passwords must be shorter than 128 bytes";
        return false;
    }
    for (const unsigned char byte : password) {
        if (byte < 0x20u || byte > 0x7eu) {
            error = "aezeed passwords must use printable ASCII";
            return false;
        }
    }
    return true;
}

std::string u256_decimal(modeinfra::U256 value) {
    if (value.is_zero()) return "0";
    std::string output;
    while (!value.is_zero()) {
        modeinfra::U256 quotient;
        std::uint64_t remainder = 0u;
        if (!modeinfra::divide(
                value, 10u, quotient, remainder)) {
            return {};
        }
        output.push_back(
            static_cast<char>('0' + remainder));
        value = quotient;
    }
    std::reverse(output.begin(), output.end());
    return output;
}

class PasswordStream {
public:
    bool initialize(
        const Options& options, std::string& error) {
        options_ = &options;
        if (!options.mask.empty()) {
            kind_ = Kind::Mask;
            if (!parse_mask(options.mask, error)) return false;
            if (!domain_.reset(radices_, error)) return false;
            cursor_ = {};
            end_ = domain_.size();
            return true;
        }
        if (!options.start.empty()) {
            kind_ = Kind::Range;
            if (!modeinfra::parse_u256(
                    options.start, cursor_, error) ||
                !modeinfra::parse_u256(
                    options.end, end_, error)) {
                return false;
            }
            if (modeinfra::compare(cursor_, end_) >= 0) {
                error = "-start must be lower than -end";
                return false;
            }
            return true;
        }
        kind_ = Kind::Inputs;
        if (options.password_inputs.empty()) {
            literal_.push_back("");
        }
        return true;
    }

    bool next(
        std::uint64_t maximum,
        std::vector<std::string>& output,
        std::string& error) {
        output.clear();
        if (kind_ == Kind::Mask) {
            return next_mask(maximum, output, error);
        }
        if (kind_ == Kind::Range) {
            return next_range(maximum, output, error);
        }
        return next_inputs(maximum, output, error);
    }

private:
    enum class Kind {
        Inputs,
        Mask,
        Range,
    };

    struct MaskPart {
        bool variable = false;
        char literal = 0;
        std::string alphabet;
    };

    bool parse_mask(
        const std::string& mask, std::string& error) {
        for (std::size_t i = 0u; i < mask.size();) {
            if (mask[i] != '?') {
                parts_.push_back({false, mask[i], {}});
                ++i;
                continue;
            }
            if (i + 1u >= mask.size()) {
                error = "dangling '?' in -mask";
                return false;
            }
            const char code = mask[i + 1u];
            if (code == '?') {
                parts_.push_back({false, '?', {}});
            } else {
                std::string alphabet;
                if (code == 'd') alphabet = "0123456789";
                else if (code == 'l') {
                    alphabet = "abcdefghijklmnopqrstuvwxyz";
                } else if (code == 'u') {
                    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                } else if (code == 'a') {
                    alphabet =
                        "0123456789abcdefghijklmnopqrstuvwxyz"
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
                } else {
                    error = std::string("unsupported -mask token ?") + code;
                    return false;
                }
                parts_.push_back({true, 0, alphabet});
                radices_.push_back(alphabet.size());
            }
            i += 2u;
        }
        if (parts_.size() >= kPasswordStride) {
            error = "expanded -mask password is too long";
            return false;
        }
        if (radices_.empty()) radices_.push_back(1u);
        return true;
    }

    std::string render_mask(
        const std::vector<std::uint64_t>& digits) const {
        std::string output;
        output.reserve(parts_.size());
        std::size_t digit = 0u;
        for (const MaskPart& part : parts_) {
            if (part.variable) {
                output.push_back(
                    part.alphabet[
                        static_cast<std::size_t>(
                            digits[digit++])]);
            } else {
                output.push_back(part.literal);
            }
        }
        return output;
    }

    bool next_mask(
        std::uint64_t maximum,
        std::vector<std::string>& output,
        std::string& error) {
        while (output.size() < maximum &&
               modeinfra::compare(cursor_, end_) < 0) {
            std::vector<std::uint64_t> digits;
            if (!domain_.decode(cursor_, digits, error)) return false;
            if (parts_.empty()) output.emplace_back();
            else output.push_back(render_mask(digits));
            modeinfra::U256 next;
            if (!modeinfra::add_checked(
                    cursor_, modeinfra::U256::from_u64(1u),
                    next)) {
                error = "mask ordinal overflow";
                return false;
            }
            cursor_ = next;
        }
        return true;
    }

    bool next_range(
        std::uint64_t maximum,
        std::vector<std::string>& output,
        std::string& error) {
        while (output.size() < maximum &&
               modeinfra::compare(cursor_, end_) < 0) {
            const std::string value = u256_decimal(cursor_);
            if (value.empty() ||
                !printable_password(value, error)) {
                if (error.empty()) error = "numeric password conversion failed";
                return false;
            }
            output.push_back(value);
            modeinfra::U256 next;
            if (!modeinfra::add_checked(
                    cursor_, modeinfra::U256::from_u64(1u),
                    next)) {
                error = "numeric password ordinal overflow";
                return false;
            }
            cursor_ = next;
        }
        return true;
    }

    bool open_next_input(std::string& error) {
        while (options_ != nullptr &&
               input_index_ < options_->password_inputs.size()) {
            const auto& entry =
                options_->password_inputs[input_index_++];
            std::error_code filesystem_error;
            const bool file =
                entry.second ||
                std::filesystem::is_regular_file(
                    entry.first, filesystem_error);
            if (!file) {
                if (!printable_password(entry.first, error)) return false;
                literal_.push_back(entry.first);
                return true;
            }
            file_.close();
            file_.clear();
            file_.open(entry.first);
            if (!file_) {
                error = "cannot open password file '" +
                    entry.first + "'";
                return false;
            }
            return true;
        }
        exhausted_ = true;
        return true;
    }

    bool next_inputs(
        std::uint64_t maximum,
        std::vector<std::string>& output,
        std::string& error) {
        while (output.size() < maximum) {
            if (!literal_.empty()) {
                output.push_back(std::move(literal_.front()));
                literal_.erase(literal_.begin());
                continue;
            }
            if (file_.is_open()) {
                std::string line;
                if (std::getline(file_, line)) {
                    if (!line.empty() && line.back() == '\r') {
                        line.pop_back();
                    }
                    if (!printable_password(line, error)) return false;
                    output.push_back(std::move(line));
                    continue;
                }
                file_.close();
            }
            if (exhausted_) break;
            if (!open_next_input(error)) return false;
        }
        return true;
    }

    Kind kind_ = Kind::Inputs;
    const Options* options_ = nullptr;
    std::size_t input_index_ = 0u;
    bool exhausted_ = false;
    std::ifstream file_;
    std::vector<std::string> literal_;
    std::vector<MaskPart> parts_;
    std::vector<std::uint64_t> radices_;
    modeinfra::MixedRadixDomain domain_;
    modeinfra::U256 cursor_;
    modeinfra::U256 end_;
};

std::uint64_t align_up(
    std::uint64_t value, std::uint64_t alignment) {
    const std::uint64_t remainder = value % alignment;
    return remainder == 0u
        ? value : value + alignment - remainder;
}

std::uint64_t scrypt_stride() {
    constexpr std::uint64_t n = 32768u;
    constexpr std::uint64_t block = 128u * 8u;
    return align_up(
        n * block + block + 4u + block, 256u);
}

bool metal_ok(
    metalError_t status, const char* action,
    std::string& error) {
    if (status == metalSuccess) return true;
    error = std::string(action) + ": " +
        metalGetErrorString(status);
    return false;
}

template <typename T>
bool allocate_buffer(
    T*& pointer, std::uint64_t bytes,
    const char* action, std::string& error) {
    return metal_ok(
        metalMalloc(
            reinterpret_cast<void**>(&pointer),
            static_cast<std::size_t>(
                std::max<std::uint64_t>(bytes, 1u))),
        action, error);
}

void release_buffers(DeviceBuffers& buffers) {
    if (buffers.device >= 0) {
        (void)metalSetDevice(buffers.device);
    }
    if (buffers.passwords) metalFree(buffers.passwords);
    if (buffers.password_lengths) metalFree(buffers.password_lengths);
    if (buffers.scratch) metalFree(buffers.scratch);
    if (buffers.hits) metalFree(buffers.hits);
    if (buffers.hit_count) metalFree(buffers.hit_count);
    if (buffers.salt) metalFree(buffers.salt);
    buffers = {};
}

bool prepare_buffers(
    int device, std::uint64_t capacity,
    std::uint64_t stride,
    DeviceBuffers& buffers, std::string& error) {
    buffers.device = device;
    if (!metal_ok(
            metalSetDevice(device), "select aezeed device", error) ||
        !allocate_buffer(
            buffers.passwords, capacity * kPasswordStride,
            "allocate aezeed passwords", error) ||
        !allocate_buffer(
            buffers.password_lengths, capacity,
            "allocate aezeed password lengths", error) ||
        !allocate_buffer(
            buffers.scratch, capacity * stride,
            "allocate aezeed scrypt scratch", error) ||
        !allocate_buffer(
            buffers.hits,
            static_cast<std::uint64_t>(kHitCapacity) *
                sizeof(GpuHit),
            "allocate aezeed hits", error) ||
        !allocate_buffer(
            buffers.hit_count, sizeof(std::uint32_t),
            "allocate aezeed hit count", error) ||
        !allocate_buffer(
            buffers.salt, 5u,
            "allocate aezeed salt", error)) {
        release_buffers(buffers);
        return false;
    }
    buffers.capacity = capacity;
    buffers.allocated =
        capacity * (kPasswordStride + 1u + stride) +
        static_cast<std::uint64_t>(kHitCapacity) *
            sizeof(GpuHit) + sizeof(std::uint32_t) + 5u;
    return true;
}

std::uint32_t launch_grid(std::uint64_t count) {
    return static_cast<std::uint32_t>(
        (count + kThreadgroupSize - 1u) /
        kThreadgroupSize * kThreadgroupSize);
}

bool launch_batch(
    DeviceBuffers& buffers, const GpuConfig& config,
    const std::vector<std::string>& passwords,
    std::size_t offset, std::size_t count,
    std::uint64_t candidate_base,
    std::uint64_t stride,
    std::vector<GpuHit>& hits,
    std::uint32_t& raw_count,
    std::uint64_t& readback_ns,
    std::string& error) {
    std::vector<char> packed(count * kPasswordStride, 0);
    std::vector<std::uint8_t> lengths(count, 0u);
    for (std::size_t i = 0u; i < count; ++i) {
        const std::string& password = passwords[offset + i];
        lengths[i] =
            static_cast<std::uint8_t>(password.size());
        std::copy(
            password.begin(), password.end(),
            packed.begin() + i * kPasswordStride);
    }
    if (!metal_ok(
            metalSetDevice(buffers.device),
            "select aezeed device", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.passwords, packed.data(), packed.size(),
                metalMemcpyHostToDevice),
            "upload aezeed passwords", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.password_lengths, lengths.data(),
                lengths.size(), metalMemcpyHostToDevice),
            "upload aezeed password lengths", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.salt, config.salt.data(),
                config.salt.size(), metalMemcpyHostToDevice),
            "upload aezeed salt", error) ||
        !metal_ok(
            metalMemset(
                buffers.hit_count, 0, sizeof(std::uint32_t)),
            "reset aezeed hit count", error) ||
        !metal_ok(
            metal_launch(
                "workerAezeed", launch_grid(count),
                kThreadgroupSize, config, buffers.passwords,
                buffers.password_lengths, candidate_base,
                static_cast<std::uint64_t>(count),
                buffers.scratch, stride, buffers.hits,
                buffers.hit_count, kHitCapacity, buffers.salt),
            "launch aezeed worker", error) ||
        !metal_ok(
            metalDeviceSynchronize(),
            "synchronize aezeed worker", error)) {
        return false;
    }
    const auto read_started = std::chrono::steady_clock::now();
    raw_count = 0u;
    if (!metal_ok(
            metalMemcpy(
                &raw_count, buffers.hit_count,
                sizeof(raw_count), metalMemcpyDeviceToHost),
            "read aezeed hit count", error)) {
        return false;
    }
    const std::uint32_t stored =
        std::min(raw_count, kHitCapacity);
    hits.resize(stored);
    if (stored != 0u &&
        !metal_ok(
            metalMemcpy(
                hits.data(), buffers.hits,
                static_cast<std::size_t>(stored) *
                    sizeof(GpuHit),
                metalMemcpyDeviceToHost),
            "read aezeed hits", error)) {
        return false;
    }
    readback_ns += static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() -
            read_started).count());
    return true;
}

std::uint64_t solved_logical_targets(
    const std::vector<Target>& targets) {
    std::uint64_t solved = 0u;
    for (const Target& target : targets) {
        if (target.solved) solved += target.origins.size();
    }
    return solved;
}

std::string join_origins(const std::vector<std::string>& origins) {
    std::ostringstream output;
    for (std::size_t i = 0u; i < origins.size(); ++i) {
        if (i != 0u) output << ",";
        output << origins[i];
    }
    return output.str();
}

std::string birthday_date(std::uint32_t birthday) {
    constexpr std::time_t genesis = 1231006505;
    const std::time_t timestamp =
        genesis + static_cast<std::time_t>(birthday) * 86400;
    std::tm result{};
    if (gmtime_r(&timestamp, &result) == nullptr) return {};
    char buffer[16]{};
    if (std::strftime(
            buffer, sizeof(buffer), "%Y-%m-%d", &result) == 0u) {
        return {};
    }
    return buffer;
}

bool verify_hit(
    const GpuHit& hit, const GpuConfig& config,
    const CipherSeed& seed,
    const HostPrecompute& precompute,
    std::vector<Target>& targets,
    std::string& result_line,
    std::uint64_t& exact_verifications,
    std::string& error) {
    ++exact_verifications;
    std::array<std::uint8_t, 19> plaintext{};
    if (!host_decipher(config, hit.key, plaintext) ||
        plaintext != hit.plaintext ||
        !std::equal(
            plaintext.begin() + 3u, plaintext.end(),
            hit.entropy.begin())) {
        error = "host AEZ verification rejected a Metal hit";
        return false;
    }
    const std::uint32_t internal_version = plaintext[0];
    const std::uint32_t birthday =
        (static_cast<std::uint32_t>(plaintext[1]) << 8u) |
        static_cast<std::uint32_t>(plaintext[2]);
    if (internal_version > 1u ||
        internal_version != hit.internal_version ||
        birthday != hit.birthday) {
        error = "host aezeed version/birthday verification failed";
        return false;
    }
    std::array<std::uint8_t, 16> entropy{};
    std::copy(
        plaintext.begin() + 3u, plaintext.end(),
        entropy.begin());
    std::array<std::uint8_t, 32> entropy_hash{};
    sha256(entropy.data(), entropy.size(), entropy_hash.data());
    std::array<std::uint8_t, 33> root_public{};
    if (!derive_root_public(entropy, precompute, root_public)) {
        error = "cannot derive BIP32 root public key";
        return false;
    }

    std::vector<std::string> matched;
    if (targets.empty()) {
        matched.push_back("authenticated-cipherseed");
    } else {
        for (Target& target : targets) {
            bool equal = false;
            if (target.kind == TargetKind::EntropyHash) {
                equal = std::equal(
                    entropy_hash.begin(), entropy_hash.end(),
                    target.value.begin());
            } else if (target.kind == TargetKind::RootPublic) {
                equal = std::equal(
                    root_public.begin(), root_public.end(),
                    target.value.begin());
            } else {
                equal = std::equal(
                    entropy.begin(), entropy.end(),
                    target.value.begin());
            }
            if (equal) {
                target.solved = true;
                matched.insert(
                    matched.end(),
                    target.origins.begin(), target.origins.end());
            }
        }
    }
    if (matched.empty()) {
        result_line.clear();
        return true;
    }
    const std::string password(
        reinterpret_cast<const char*>(hit.password.data()),
        hit.password_len);
    std::ostringstream output;
    output << "mode=aezeed"
           << " source=" << seed.source
           << " candidate=" << hit.candidate_index
           << " password="
           << (password.empty() ? "<default:aezeed>" : password)
           << " internal_version=" << internal_version
           << " birthday_days=" << birthday
           << " birthday=" << birthday_date(birthday)
           << " entropy=" << hex_string(
                entropy.data(), entropy.size())
           << " entropy_sha256=" << hex_string(
                entropy_hash.data(), entropy_hash.size())
           << " root_public=" << hex_string(
                root_public.data(), root_public.size())
           << " target=" << join_origins(matched);
    result_line = output.str();
    return true;
}

std::uint64_t saturating_add(
    std::uint64_t left, std::uint64_t right) {
    return right > std::numeric_limits<std::uint64_t>::max() - left
        ? std::numeric_limits<std::uint64_t>::max()
        : left + right;
}

}  // namespace

bool requested(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "-aezeed") return true;
    }
    return false;
}

void print_help() {
    std::cout << R"HELP(
[!] ================== AEZEED MODE ==================
[!]
[!] -aezeed                         Recover an LND aezeed/cipherseed password.
[!] -recovery FILE|"24 WORDS"       Repeatable mnemonic or one mnemonic per line.
[!] ? or *                          Unknown word; maximum two per mnemonic.
[!]
[!] Optional verification:
[!] -target VALUE|FILE              SHA256(entropy), or compressed/uncompressed
[!]                                 BIP32 root public key. Repeatable.
[!] -entropy HEX                    Exact 16-byte LND wallet entropy. Repeatable.
[!] Without a target, a valid AEZ tag plus known internal version is accepted.
[!]
[!] Password candidates:
[!] -pass VALUE|FILE                Literal password or an existing text file.
[!] -i FILE                         Streaming password dictionary; repeatable.
[!] -mask MASK                      ?d, ?l, ?u, ?a and ?? masks.
[!] -start N -end N                 Decimal-string passwords in [START,END).
[!] No source tests the LND default passphrase "aezeed".
[!]
[!] GPU / memory:
[!] -wallet-mem auto|all|NN%|SIZE   Unified-memory working-set budget.
[!] -wallet-scrypt-mem SPEC         Optional stricter scrypt scratch limit.
[!] -n N                            Maximum resident candidates/device, 1..4096.
[!] -device LIST                    Metal devices, for example 0 or 0,1.
[!] auto uses at most 50% of the current free recommended working set.
[!] all leaves 512 MiB for runtime. Default residency is memory-derived and
[!] allocated lazily. Each resident v0 job needs about 32 MiB.
[!]
[!] Statistics:
[!] The common SpeedThreadFunc is the only statistics writer. It reports
[!] KDF/s, primitive work, exact host verifications, target state, actual
[!] Metal working set and readback time. Work is credited after completion.
[!]
[!] Output:
[!] -save                           Append independently verified hits.
[!] -o FILE                         Output path (also enables saving).
[!] -silent                         Suppress found lines on the console.
[!]
[!] Examples:
[!]   ./METAL_CRYPTO_TOOLKIT -aezeed -recovery seed.txt
[!]   ./METAL_CRYPTO_TOOLKIT -aezeed -recovery seed.txt \
[!]     -pass passwords.txt -wallet-mem auto -save
[!]   ./METAL_CRYPTO_TOOLKIT -aezeed -recovery "above ... body" \
[!]     -entropy 81b637d86359e6960de795e41e0b4cfd -pass aezeed
[!]   ./METAL_CRYPTO_TOOLKIT -aezeed -recovery damaged.txt \
[!]     -target ROOT_PUBLIC_KEY -mask "secret?d?d" -wallet-mem all
[!]
[!] Limitations:
[!] English 24-word LND aezeed v0 containers only. Internal LND derivation
[!] versions 0 and 1 are recognized. Passwords are printable ASCII below
[!] 128 bytes. A checksum-valid mnemonic does not prove the password; every
[!] GPU hit is re-deciphered with AEZ-v5 and fully verified on the host.
[!]
[!] Errors:
[!] CLI/input errors return 2; Metal/runtime errors return 1; an exhausted
[!] valid search returns 0 even when no password is found.
[!] ======================================================================
[!] End of detailed help for -aezeed [!]
)HELP";
}

int run(int argc, char** argv, const RuntimeHooks& hooks) {
    Options options;
    std::string error;
    if (!parse_options(argc, argv, options, error)) {
        std::cerr << "[!] aezeed CLI error: " << error << " [!]\n";
        return 2;
    }
    std::vector<CipherSeed> seeds;
    std::uint64_t template_candidates = 0u;
    if (!load_seeds(
            options, seeds, template_candidates, error)) {
        std::cerr << "[!] aezeed input error: " << error << " [!]\n";
        return 2;
    }
    std::vector<Target> targets;
    std::uint64_t logical_targets = 0u;
    if (!load_targets(
            options, targets, logical_targets, error)) {
        std::cerr << "[!] aezeed target error: " << error << " [!]\n";
        return 2;
    }

    HostPrecompute precompute;
    if (!build_precompute(precompute, error)) {
        std::cerr << "[!] aezeed runtime error: "
                  << error << " [!]\n";
        return 1;
    }
    int device_count = 0;
    if (!metal_ok(
            metalGetDeviceCount(&device_count),
            "query aezeed devices", error)) {
        std::cerr << "[!] aezeed runtime error: "
                  << error << " [!]\n";
        return 1;
    }
    std::vector<modeinfra::MemoryDeviceInfo> device_info;
    for (const int device : options.devices) {
        if (device < 0 || device >= device_count) {
            std::cerr << "[!] aezeed CLI error: unavailable device "
                      << device << " [!]\n";
            return 2;
        }
        metalDeviceProp properties{};
        if (!metal_ok(
                metalGetDeviceProperties(&properties, device),
                "query aezeed device properties", error)) {
            std::cerr << "[!] aezeed runtime error: "
                      << error << " [!]\n";
            return 1;
        }
        device_info.push_back({
            properties.recommendedMaxWorkingSetSize,
            properties.currentAllocatedSize,
            properties.maxBufferLength,
            properties.hasUnifiedMemory != 0,
        });
    }
    const std::uint64_t stride = scrypt_stride();
    const std::uint64_t fixed =
        static_cast<std::uint64_t>(kHitCapacity) *
            sizeof(GpuHit) + sizeof(std::uint32_t) + 5u;
    const std::uint64_t one_candidate =
        stride + kPasswordStride + 1u;
    modeinfra::MemorySpec memory_spec;
    modeinfra::MemoryBudget budget;
    if (!modeinfra::parse_memory_spec(
            options.memory, memory_spec, error) ||
        !modeinfra::resolve_memory_budget(
            memory_spec, device_info,
            fixed + one_candidate, 0u, budget,
            error, kRuntimeReserve)) {
        std::cerr << "[!] aezeed memory error: "
                  << error << " [!]\n";
        return 2;
    }
    std::uint64_t per_device_budget = budget.per_device_budget;
    if (!options.scrypt_memory.empty()) {
        modeinfra::MemorySpec scratch_spec;
        modeinfra::MemoryBudget scratch_budget;
        if (!modeinfra::parse_memory_spec(
                options.scrypt_memory, scratch_spec, error) ||
            !modeinfra::resolve_memory_budget(
                scratch_spec, device_info, stride, 0u,
                scratch_budget, error, 0u)) {
            std::cerr << "[!] aezeed scrypt memory error: "
                      << error << " [!]\n";
            return 2;
        }
        per_device_budget = std::min(
            per_device_budget,
            fixed + scratch_budget.per_device_budget);
    }
    if (per_device_budget <= fixed + one_candidate) {
        std::cerr << "[!] aezeed memory error: selected budget "
                     "cannot hold one scrypt job [!]\n";
        return 1;
    }
    std::uint64_t capacity_ceiling =
        (per_device_budget - fixed) / one_candidate;
    capacity_ceiling = std::min<std::uint64_t>(
        capacity_ceiling, options.batch);
    capacity_ceiling = std::min<std::uint64_t>(
        capacity_ceiling,
        budget.max_buffer_length / stride);
    capacity_ceiling =
        std::max<std::uint64_t>(1u, capacity_ceiling);

    std::vector<DeviceBuffers> devices(options.devices.size());
    std::uint64_t allocated_bytes = 0u;

    std::ofstream output;
    if (options.save || !options.output_path.empty()) {
        const std::string path = options.output_path.empty()
            ? "result.txt" : options.output_path;
        output.open(path, std::ios::app);
        if (!output) {
            for (DeviceBuffers& buffers : devices) {
                release_buffers(buffers);
            }
            std::cerr << "[!] aezeed runtime error: cannot open '"
                      << path << "' [!]\n";
            return 1;
        }
    }

    std::cout << "[!] aezeed cipherseeds: " << seeds.size()
              << " | template candidates: " << template_candidates
              << " | targets: " << targets.size()
              << " unique/" << logical_targets
              << " logical | devices: " << devices.size()
              << " | resident ceiling/device: "
              << capacity_ceiling
              << " | scratch/job: " << stride
              << " [!]\n";

    modeinfra::ModeProgress& progress =
        modeinfra::global_mode_progress();
    progress.begin(
        "AEZEED", modeinfra::ProgressUnit::Kdf,
        modeinfra::ProgressPhase::Search);
    progress.set_targets(
        logical_targets == 0u ? seeds.size() : logical_targets,
        targets.empty() ? seeds.size() : targets.size(), 0u);
    progress.set_allocated_working_set(allocated_bytes);

    std::uint64_t founds = 0u;
    bool stop = false;
    int status = 0;
    const std::uint64_t combined_capacity =
        capacity_ceiling * devices.size();
    for (const CipherSeed& seed : seeds) {
        if (stop) break;
        GpuConfig config;
        std::copy_n(
            seed.encoded.begin() + 1u, 23u,
            config.ciphertext.begin());
        std::copy_n(
            seed.encoded.begin() + 24u, 5u,
            config.salt.begin());
        config.maximum_birthday = 0xffffu;
        PasswordStream stream;
        if (!stream.initialize(options, error)) {
            std::cerr << "[!] aezeed candidate error: "
                      << error << " [!]\n";
            status = 2;
            break;
        }
        std::uint64_t candidate_base = 0u;
        while (!stop) {
            std::vector<std::string> passwords;
            if (!stream.next(
                    combined_capacity, passwords, error)) {
                std::cerr << "[!] aezeed candidate error: "
                          << error << " [!]\n";
                status = 2;
                stop = true;
                break;
            }
            if (passwords.empty()) break;
            if (devices.front().capacity == 0u) {
                std::uint64_t resident =
                    (passwords.size() + devices.size() - 1u) /
                    devices.size();
                resident = std::min(
                    resident, capacity_ceiling);
                bool allocated = false;
                while (!allocated) {
                    allocated = true;
                    for (std::size_t i = 0u;
                         i < devices.size(); ++i) {
                        if (!prepare_buffers(
                                options.devices[i], resident,
                                stride, devices[i], error)) {
                            allocated = false;
                            break;
                        }
                    }
                    if (allocated) break;
                    for (DeviceBuffers& buffers : devices) {
                        release_buffers(buffers);
                    }
                    if (memory_spec.kind !=
                            modeinfra::MemoryKind::Auto ||
                        resident == 1u) {
                        std::cerr
                            << "[!] aezeed allocation error: "
                            << error << " [!]\n";
                        status = 1;
                        stop = true;
                        break;
                    }
                    resident = std::max<std::uint64_t>(
                        1u, resident / 2u);
                }
                if (stop) break;
                allocated_bytes = 0u;
                for (const DeviceBuffers& buffers : devices) {
                    allocated_bytes = saturating_add(
                        allocated_bytes, buffers.allocated);
                }
                progress.set_allocated_working_set(
                    allocated_bytes);
                std::cout
                    << "[!] aezeed pipeline: resident/device "
                    << resident << " | working set "
                    << allocated_bytes << " bytes [!]\n";
            }
            std::size_t offset = 0u;
            while (offset < passwords.size() && !stop) {
                for (DeviceBuffers& buffers : devices) {
                    if (offset >= passwords.size()) break;
                    const std::size_t count =
                        std::min<std::size_t>(
                            buffers.capacity,
                            passwords.size() - offset);
                    std::vector<GpuHit> hits;
                    std::uint32_t raw_count = 0u;
                    std::uint64_t readback_ns = 0u;
                    if (!launch_batch(
                            buffers, config, passwords,
                            offset, count,
                            candidate_base + offset, stride,
                            hits, raw_count, readback_ns,
                            error)) {
                        std::cerr
                            << "[!] aezeed runtime error: "
                            << error << " [!]\n";
                        status = 1;
                        stop = true;
                        break;
                    }
                    if (raw_count > kHitCapacity) {
                        std::cerr
                            << "[!] aezeed runtime error: hit "
                               "overflow; reduce -n and retry [!]\n";
                        status = 1;
                        stop = true;
                        break;
                    }
                    std::uint64_t verifications = 0u;
                    for (const GpuHit& hit : hits) {
                        std::string line;
                        if (!verify_hit(
                                hit, config, seed, precompute,
                                targets, line, verifications,
                                error)) {
                            std::cerr
                                << "[!] aezeed verification error: "
                                << error << " [!]\n";
                            status = 1;
                            stop = true;
                            break;
                        }
                        if (line.empty()) continue;
                        ++founds;
                        if (hooks.credit_found) {
                            hooks.credit_found();
                        }
                        progress.set_founds(founds);
                        if (!options.silent) {
                            std::cout << "[+] AEZEED_FOUND "
                                      << line << "\n";
                        }
                        if (output) {
                            output << line << "\n";
                            output.flush();
                        }
                        if (targets.empty() ||
                            solved_logical_targets(targets) >=
                                logical_targets) {
                            stop = true;
                            break;
                        }
                    }
                    progress.credit_completed(
                        count, count, verifications,
                        readback_ns);
                    if (hooks.credit_completed) {
                        hooks.credit_completed(count);
                    }
                    progress.set_targets(
                        logical_targets == 0u
                            ? seeds.size() : logical_targets,
                        targets.empty()
                            ? seeds.size() : targets.size(),
                        targets.empty()
                            ? founds
                            : solved_logical_targets(targets));
                    offset += count;
                    if (stop) break;
                }
            }
            candidate_base += passwords.size();
        }
    }
    progress.end();
    for (DeviceBuffers& buffers : devices) {
        release_buffers(buffers);
    }
    if (status != 0) return status;
    std::cout << "[!] aezeed search complete: found "
              << founds;
    if (!targets.empty()) {
        std::cout << " | solved "
                  << solved_logical_targets(targets)
                  << "/" << logical_targets
                  << " logical targets";
    }
    std::cout << " [!]\n";
    return 0;
}

}  // namespace aezeed_mode
