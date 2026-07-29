#include "Slip39Mode.h"
#include "Slip39Wordlist.generated.h"

#include "../MetalBackend.h"

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonKeyDerivation.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace slip39_mode {
namespace {

constexpr std::uint32_t kThreadgroupSize = 256u;
constexpr std::uint32_t kHitCapacity = 65536u;
constexpr std::uint64_t kDefaultBatch = 4096u;
constexpr std::uint64_t kMaximumBatch = kHitCapacity;
constexpr std::uint64_t kRuntimeReserve =
    512ull * 1024ull * 1024ull;
constexpr std::uint64_t kMaximumTemplateCombinations = 1000000u;
constexpr std::size_t kPasswordStride = 128u;

struct alignas(16) GpuConfig {
    std::array<std::uint8_t, 32> ciphertext{};
    std::uint32_t ciphertext_len = 0u;
    std::uint32_t identifier = 0u;
    std::uint32_t iteration_exponent = 0u;
    std::uint32_t extendable = 0u;
};

struct alignas(16) GpuTarget {
    std::array<std::uint8_t, 32> digest{};
    std::uint64_t prefix = 0u;
    std::uint64_t source_index = 0u;
};

struct alignas(8) GpuHit {
    std::uint64_t candidate_index = 0u;
    std::uint64_t target_index = 0u;
    std::uint32_t password_len = 0u;
    std::uint32_t secret_len = 0u;
    std::array<std::uint8_t, kPasswordStride> password{};
    std::array<std::uint8_t, 32> master_secret{};
};

struct GpuDerived {
    std::array<std::uint8_t, 32> digest{};
    std::array<std::uint8_t, 32> master_secret{};
    std::uint32_t valid = 0u;
    std::uint32_t reserved = 0u;
};

static_assert(sizeof(GpuConfig) == 48u);
static_assert(sizeof(GpuTarget) == 48u);
static_assert(sizeof(GpuHit) == 184u);
static_assert(sizeof(GpuDerived) == 72u);

struct Share {
    std::uint16_t identifier = 0u;
    bool extendable = false;
    std::uint8_t iteration_exponent = 0u;
    std::uint8_t group_index = 0u;
    std::uint8_t group_threshold = 0u;
    std::uint8_t group_count = 0u;
    std::uint8_t member_index = 0u;
    std::uint8_t member_threshold = 0u;
    std::vector<std::uint8_t> value;
    std::string mnemonic;
};

struct EncryptedMasterSecret {
    std::uint16_t identifier = 0u;
    bool extendable = false;
    std::uint8_t iteration_exponent = 0u;
    std::vector<std::uint8_t> ciphertext;
};

struct Occurrence {
    std::string source;
    std::string raw;
};

struct Target {
    std::array<std::uint8_t, 32> digest{};
    std::vector<Occurrence> occurrences;
    bool solved = false;
};

struct InputSpec {
    std::string value;
    bool force_file = false;
};

struct Options {
    std::vector<std::string> recovery_values;
    std::vector<std::string> target_values;
    std::vector<std::string> master_secret_values;
    std::vector<InputSpec> password_inputs;
    std::string mask;
    std::string start;
    std::string end;
    std::string memory = "auto";
    std::vector<int> devices{0};
    std::string output_path;
    std::uint64_t batch = 0u;
    bool batch_explicit = false;
    bool save = false;
    bool silent = false;
};

struct DeviceBuffers {
    int device = -1;
    char* password_data = nullptr;
    std::uint8_t* password_lengths = nullptr;
    GpuDerived* derived = nullptr;
    GpuTarget* targets = nullptr;
    GpuHit* hits = nullptr;
    std::uint32_t* hit_count = nullptr;
    std::uint64_t batch_capacity = 0u;
    std::uint64_t target_capacity = 0u;
    std::uint64_t allocated = 0u;
};

std::string trim_copy(const std::string& value) {
    std::size_t first = 0u;
    while (first < value.size() &&
           std::isspace(static_cast<unsigned char>(value[first]))) {
        ++first;
    }
    std::size_t last = value.size();
    while (last > first &&
           std::isspace(static_cast<unsigned char>(value[last - 1u]))) {
        --last;
    }
    return value.substr(first, last - first);
}

std::string lower_copy(std::string value) {
    std::transform(
        value.begin(), value.end(), value.begin(),
        [](unsigned char ch) {
            return static_cast<char>(std::tolower(ch));
        });
    return value;
}

std::vector<std::string> split_words(const std::string& text) {
    std::istringstream input(text);
    std::vector<std::string> result;
    std::string word;
    while (input >> word) result.push_back(lower_copy(word));
    return result;
}

std::string join_words(
    const std::vector<std::uint16_t>& indices) {
    std::ostringstream output;
    for (std::size_t i = 0u; i < indices.size(); ++i) {
        if (i != 0u) output << ' ';
        output << kSlip39Words[indices[i]];
    }
    return output.str();
}

const std::unordered_map<std::string, std::uint16_t>& word_map() {
    static const auto mapping = [] {
        std::unordered_map<std::string, std::uint16_t> result;
        result.reserve(kSlip39Words.size());
        for (std::size_t i = 0u; i < kSlip39Words.size(); ++i) {
            result.emplace(
                kSlip39Words[i], static_cast<std::uint16_t>(i));
        }
        return result;
    }();
    return mapping;
}

std::string hex_lower(const std::uint8_t* data, std::size_t size) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::size_t i = 0u; i < size; ++i) {
        output << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return output.str();
}

int hex_nibble(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

bool decode_hex(
    const std::string& raw,
    std::vector<std::uint8_t>& bytes) {
    const std::string text = trim_copy(raw);
    if (text.empty() || (text.size() & 1u) != 0u) return false;
    bytes.resize(text.size() / 2u);
    for (std::size_t i = 0u; i < bytes.size(); ++i) {
        const int high = hex_nibble(text[i * 2u]);
        const int low = hex_nibble(text[i * 2u + 1u]);
        if (high < 0 || low < 0) return false;
        bytes[i] =
            static_cast<std::uint8_t>((high << 4) | low);
    }
    return true;
}

bool decode_digest(
    const std::string& raw,
    std::array<std::uint8_t, 32>& digest) {
    std::vector<std::uint8_t> bytes;
    if (!decode_hex(raw, bytes) || bytes.size() != digest.size()) {
        return false;
    }
    std::copy(bytes.begin(), bytes.end(), digest.begin());
    return true;
}

std::array<std::uint8_t, 32> sha256(
    const std::uint8_t* data, std::size_t size) {
    std::array<std::uint8_t, 32> digest{};
    CC_SHA256(
        data, static_cast<CC_LONG>(size), digest.data());
    return digest;
}

std::uint64_t digest_prefix(
    const std::array<std::uint8_t, 32>& digest) {
    std::uint64_t result = 0u;
    for (std::size_t i = 0u; i < 8u; ++i) {
        result = (result << 8u) | digest[i];
    }
    return result;
}

bool parse_u64(
    const std::string& text, std::uint64_t& value) {
    if (text.empty()) return false;
    char* end = nullptr;
    errno = 0;
    const unsigned long long parsed =
        std::strtoull(text.c_str(), &end, 0);
    if (errno != 0 || end == text.c_str() || *end != '\0') {
        return false;
    }
    value = static_cast<std::uint64_t>(parsed);
    return true;
}

bool parse_devices(
    const std::string& text,
    std::vector<int>& devices,
    std::string& error) {
    devices.clear();
    std::size_t begin = 0u;
    while (begin <= text.size()) {
        const std::size_t comma = text.find(',', begin);
        const std::string token = trim_copy(text.substr(
            begin, comma == std::string::npos
                ? std::string::npos : comma - begin));
        if (token.empty()) {
            error = "-device contains an empty item";
            return false;
        }
        char* end = nullptr;
        errno = 0;
        const long parsed = std::strtol(token.c_str(), &end, 10);
        if (errno != 0 || end == token.c_str() || *end != '\0' ||
            parsed < 0 || parsed > std::numeric_limits<int>::max()) {
            error = "invalid Metal device '" + token + "'";
            return false;
        }
        devices.push_back(static_cast<int>(parsed));
        if (comma == std::string::npos) break;
        begin = comma + 1u;
    }
    std::sort(devices.begin(), devices.end());
    devices.erase(
        std::unique(devices.begin(), devices.end()), devices.end());
    return !devices.empty();
}

bool parse_options(
    int argc, char** argv, Options& options, std::string& error) {
    bool after_mode = false;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (arg == "-slip39") {
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
        } else if (arg == "-target" || arg == "-hash") {
            const char* value = require_value(arg.c_str());
            if (!value) return false;
            options.target_values.emplace_back(value);
        } else if (arg == "-master-secret") {
            const char* value = require_value("-master-secret");
            if (!value) return false;
            options.master_secret_values.emplace_back(value);
        } else if (arg == "-pass") {
            const char* value = require_value("-pass");
            if (!value) return false;
            options.password_inputs.push_back({value, false});
        } else if (arg == "-i") {
            const char* value = require_value("-i");
            if (!value) return false;
            options.password_inputs.push_back({value, true});
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
        } else if (arg == "-n") {
            const char* value = require_value("-n");
            if (!value) return false;
            if (!parse_u64(value, options.batch) ||
                options.batch == 0u) {
                error = "-n must be a positive integer";
                return false;
            }
            options.batch_explicit = true;
        } else if (arg == "-device") {
            const char* value = require_value("-device");
            if (!value ||
                !parse_devices(value, options.devices, error)) {
                return false;
            }
        } else if (arg == "-wallet-mem") {
            const char* value = require_value("-wallet-mem");
            if (!value) return false;
            options.memory = value;
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
            error = "unsupported -slip39 argument '" + arg + "'";
            return false;
        }
    }
    if (options.recovery_values.empty()) {
        error = "-slip39 requires shares through -recovery FILE";
        return false;
    }
    if (options.target_values.empty() &&
        options.master_secret_values.empty()) {
        error = "-slip39 requires -target SHA256 or -master-secret HEX";
        return false;
    }
    const int source_modes =
        (!options.password_inputs.empty() ? 1 : 0) +
        (!options.mask.empty() ? 1 : 0) +
        ((!options.start.empty() || !options.end.empty()) ? 1 : 0);
    if (source_modes > 1) {
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

std::uint32_t rs1024_polymod(
    const std::vector<std::uint16_t>& values,
    const char* customization) {
    static constexpr std::array<std::uint32_t, 10> generator{
        0xE0E040u, 0x1C1C080u, 0x3838100u, 0x7070200u,
        0xE0E0009u, 0x1C0C2412u, 0x38086C24u,
        0x3090FC48u, 0x21B1F890u, 0x3F3F120u
    };
    std::uint32_t checksum = 1u;
    const auto consume = [&](std::uint16_t value) {
        const std::uint32_t top = checksum >> 20u;
        checksum = ((checksum & 0xfffffu) << 10u) ^ value;
        for (std::size_t i = 0u; i < generator.size(); ++i) {
            if (((top >> i) & 1u) != 0u) {
                checksum ^= generator[i];
            }
        }
    };
    for (const unsigned char ch : std::string(customization)) {
        consume(ch);
    }
    for (const std::uint16_t value : values) consume(value);
    return checksum;
}

bool verify_checksum(
    const std::vector<std::uint16_t>& words,
    bool extendable) {
    return rs1024_polymod(
        words, extendable ? "shamir_extendable" : "shamir") == 1u;
}

std::uint32_t words_to_integer(
    const std::vector<std::uint16_t>& words,
    std::size_t offset, std::size_t count) {
    std::uint32_t value = 0u;
    for (std::size_t i = 0u; i < count; ++i) {
        value = value * 1024u + words[offset + i];
    }
    return value;
}

bool decode_share(
    const std::vector<std::uint16_t>& words,
    Share& share, std::string& error) {
    if (words.size() < 20u) {
        error = "SLIP-39 mnemonic must contain at least 20 words";
        return false;
    }
    const std::size_t value_words = words.size() - 7u;
    const std::size_t padding =
        (10u * value_words) % 16u;
    if (padding > 8u) {
        error = "invalid SLIP-39 mnemonic length";
        return false;
    }
    const std::uint32_t id_exp = words_to_integer(words, 0u, 2u);
    share.identifier =
        static_cast<std::uint16_t>(id_exp >> 5u);
    share.extendable = ((id_exp >> 4u) & 1u) != 0u;
    share.iteration_exponent =
        static_cast<std::uint8_t>(id_exp & 15u);
    if (!verify_checksum(words, share.extendable)) {
        error = "SLIP-39 RS1024 checksum mismatch";
        return false;
    }
    const std::uint32_t params =
        words_to_integer(words, 2u, 2u);
    share.group_index =
        static_cast<std::uint8_t>((params >> 16u) & 15u);
    share.group_threshold =
        static_cast<std::uint8_t>(((params >> 12u) & 15u) + 1u);
    share.group_count =
        static_cast<std::uint8_t>(((params >> 8u) & 15u) + 1u);
    share.member_index =
        static_cast<std::uint8_t>((params >> 4u) & 15u);
    share.member_threshold =
        static_cast<std::uint8_t>((params & 15u) + 1u);
    if (share.group_threshold > share.group_count ||
        share.group_index >= share.group_count) {
        error = "invalid SLIP-39 group parameters";
        return false;
    }

    const std::size_t byte_count =
        (10u * value_words - padding + 7u) / 8u;
    const unsigned first_bits =
        static_cast<unsigned>(10u - padding);
    if (words[4u] >= (1u << first_bits)) {
        error = "invalid SLIP-39 value padding";
        return false;
    }
    share.value.clear();
    share.value.reserve(byte_count);
    std::uint32_t accumulator = words[4u];
    unsigned bits = first_bits;
    for (std::size_t i = 4u; i + 3u < words.size(); ++i) {
        if (i != 4u) {
            accumulator = (accumulator << 10u) | words[i];
            bits += 10u;
        }
        while (bits >= 8u) {
            bits -= 8u;
            share.value.push_back(static_cast<std::uint8_t>(
                accumulator >> bits));
            accumulator &= bits == 0u
                ? 0u : ((1u << bits) - 1u);
        }
    }
    if (bits != 0u || share.value.size() != byte_count) {
        error = "invalid SLIP-39 value bit packing";
        return false;
    }
    share.mnemonic = join_words(words);
    return true;
}

bool parse_share_template(
    const std::string& line,
    std::vector<Share>& variants,
    std::uint64_t& examined,
    std::string& error) {
    const std::vector<std::string> tokens = split_words(line);
    if (tokens.size() < 20u) {
        error = "share has fewer than 20 words";
        return false;
    }
    std::vector<std::uint16_t> words(tokens.size());
    std::vector<std::size_t> unknown;
    for (std::size_t i = 0u; i < tokens.size(); ++i) {
        if (tokens[i] == "?" || tokens[i] == "*") {
            words[i] = 0u;
            unknown.push_back(i);
            continue;
        }
        const auto found = word_map().find(tokens[i]);
        if (found == word_map().end()) {
            error = "unknown SLIP-39 word '" + tokens[i] + "'";
            return false;
        }
        words[i] = found->second;
    }
    if (unknown.size() > 2u) {
        error = "at most two damaged words per share are supported";
        return false;
    }
    std::uint64_t domain = 1u;
    for (std::size_t i = 0u; i < unknown.size(); ++i) {
        domain *= 1024u;
    }
    examined += domain;
    variants.clear();
    for (std::uint64_t ordinal = 0u; ordinal < domain; ++ordinal) {
        std::uint64_t digits = ordinal;
        for (std::size_t i = unknown.size(); i > 0u; --i) {
            words[unknown[i - 1u]] =
                static_cast<std::uint16_t>(digits & 1023u);
            digits >>= 10u;
        }
        const std::uint32_t id_exp =
            words_to_integer(words, 0u, 2u);
        const bool extendable = ((id_exp >> 4u) & 1u) != 0u;
        if (!verify_checksum(words, extendable)) continue;
        Share share;
        std::string local_error;
        if (decode_share(words, share, local_error)) {
            variants.push_back(std::move(share));
        }
    }
    if (variants.empty()) {
        error = "share template has no checksum-valid completion";
        return false;
    }
    return true;
}

std::array<std::uint8_t, 255> gf_exp{};
std::array<std::uint8_t, 256> gf_log{};

void initialize_gf() {
    static bool initialized = false;
    if (initialized) return;
    std::uint16_t polynomial = 1u;
    for (std::size_t i = 0u; i < gf_exp.size(); ++i) {
        gf_exp[i] = static_cast<std::uint8_t>(polynomial);
        gf_log[polynomial] = static_cast<std::uint8_t>(i);
        polynomial = (polynomial << 1u) ^ polynomial;
        if ((polynomial & 0x100u) != 0u) polynomial ^= 0x11bu;
    }
    initialized = true;
}

struct RawShare {
    std::uint8_t x = 0u;
    std::vector<std::uint8_t> data;
};

bool interpolate(
    const std::vector<RawShare>& shares,
    std::uint8_t x,
    std::vector<std::uint8_t>& result,
    std::string& error) {
    if (shares.empty()) {
        error = "cannot interpolate an empty share set";
        return false;
    }
    const std::size_t length = shares.front().data.size();
    std::set<std::uint8_t> coordinates;
    for (const RawShare& share : shares) {
        if (share.data.size() != length ||
            !coordinates.insert(share.x).second) {
            error = "share coordinates must be unique and equally sized";
            return false;
        }
        if (share.x == x) {
            result = share.data;
            return true;
        }
    }
    initialize_gf();
    int log_product = 0;
    for (const RawShare& share : shares) {
        log_product += gf_log[share.x ^ x];
    }
    result.assign(length, 0u);
    for (const RawShare& share : shares) {
        int basis = log_product - gf_log[share.x ^ x];
        for (const RawShare& other : shares) {
            basis -= gf_log[share.x ^ other.x];
        }
        basis %= 255;
        if (basis < 0) basis += 255;
        for (std::size_t i = 0u; i < length; ++i) {
            if (share.data[i] != 0u) {
                result[i] ^= gf_exp[
                    (gf_log[share.data[i]] + basis) % 255];
            }
        }
    }
    return true;
}

bool recover_secret(
    std::uint8_t threshold,
    const std::vector<RawShare>& shares,
    std::vector<std::uint8_t>& secret,
    std::string& error) {
    if (shares.size() < threshold || threshold == 0u) {
        error = "insufficient shares for threshold";
        return false;
    }
    std::vector<RawShare> minimal(
        shares.begin(), shares.begin() + threshold);
    if (threshold == 1u) {
        secret = minimal.front().data;
        return true;
    }
    std::vector<std::uint8_t> digest_share;
    if (!interpolate(minimal, 255u, secret, error) ||
        !interpolate(minimal, 254u, digest_share, error) ||
        digest_share.size() < 4u) {
        if (error.empty()) error = "invalid SLIP-39 digest share";
        return false;
    }
    std::array<std::uint8_t, 32> digest{};
    CCHmac(
        kCCHmacAlgSHA256,
        digest_share.data() + 4u, digest_share.size() - 4u,
        secret.data(), secret.size(), digest.data());
    if (!std::equal(
            digest.begin(), digest.begin() + 4u,
            digest_share.begin())) {
        error = "SLIP-39 shared-secret digest mismatch";
        return false;
    }
    return true;
}

bool same_common(const Share& left, const Share& right) {
    return left.identifier == right.identifier &&
        left.extendable == right.extendable &&
        left.iteration_exponent == right.iteration_exponent &&
        left.group_threshold == right.group_threshold &&
        left.group_count == right.group_count;
}

bool recover_ems(
    const std::vector<Share>& shares,
    EncryptedMasterSecret& result,
    std::string& error) {
    if (shares.empty()) {
        error = "share set is empty";
        return false;
    }
    const Share& first = shares.front();
    std::map<std::uint8_t, std::map<std::uint8_t, Share>> groups;
    for (const Share& share : shares) {
        if (!same_common(first, share)) {
            error = "shares have mismatched common parameters";
            return false;
        }
        auto& members = groups[share.group_index];
        const auto existing = members.find(share.member_index);
        if (existing != members.end()) {
            if (existing->second.value != share.value) {
                error = "conflicting shares use the same member index";
                return false;
            }
            continue;
        }
        if (!members.empty() &&
            members.begin()->second.member_threshold !=
                share.member_threshold) {
            error = "shares in a group have mismatched member thresholds";
            return false;
        }
        members.emplace(share.member_index, share);
    }

    std::vector<RawShare> recovered_groups;
    for (const auto& group_entry : groups) {
        const auto& members = group_entry.second;
        if (members.empty()) continue;
        const std::uint8_t threshold =
            members.begin()->second.member_threshold;
        if (members.size() < threshold) continue;
        std::vector<RawShare> raw_members;
        for (const auto& member : members) {
            raw_members.push_back({
                member.first, member.second.value
            });
            if (raw_members.size() == threshold) break;
        }
        std::vector<std::uint8_t> group_secret;
        std::string local_error;
        if (!recover_secret(
                threshold, raw_members, group_secret, local_error)) {
            error = "group " + std::to_string(group_entry.first) +
                ": " + local_error;
            return false;
        }
        recovered_groups.push_back({
            group_entry.first, std::move(group_secret)
        });
        if (recovered_groups.size() == first.group_threshold) break;
    }
    if (recovered_groups.size() < first.group_threshold) {
        error = "insufficient complete SLIP-39 groups";
        return false;
    }
    if (!recover_secret(
            first.group_threshold, recovered_groups,
            result.ciphertext, error)) {
        return false;
    }
    if (result.ciphertext.size() < 16u ||
        result.ciphertext.size() > 32u ||
        (result.ciphertext.size() & 1u) != 0u) {
        error = "recovered encrypted master secret must be 16-32 even bytes";
        return false;
    }
    result.identifier = first.identifier;
    result.extendable = first.extendable;
    result.iteration_exponent = first.iteration_exponent;
    return true;
}

std::string ems_key(const EncryptedMasterSecret& ems) {
    return std::to_string(ems.identifier) + ":" +
        std::to_string(ems.extendable ? 1 : 0) + ":" +
        std::to_string(ems.iteration_exponent) + ":" +
        hex_lower(ems.ciphertext.data(), ems.ciphertext.size());
}

void enumerate_share_combinations(
    const std::vector<std::vector<Share>>& options,
    std::size_t index,
    std::vector<Share>& selected,
    std::uint64_t& visited,
    std::map<std::string, EncryptedMasterSecret>& recovered) {
    if (visited >= kMaximumTemplateCombinations) return;
    if (index == options.size()) {
        ++visited;
        EncryptedMasterSecret ems;
        std::string ignored;
        if (recover_ems(selected, ems, ignored)) {
            recovered.emplace(ems_key(ems), std::move(ems));
        }
        return;
    }
    for (const Share& share : options[index]) {
        selected.push_back(share);
        enumerate_share_combinations(
            options, index + 1u, selected, visited, recovered);
        selected.pop_back();
        if (visited >= kMaximumTemplateCombinations) return;
    }
}

bool load_share_lines(
    const std::vector<std::string>& values,
    std::vector<std::pair<std::string, std::string>>& lines,
    std::string& error) {
    for (const std::string& raw : values) {
        const std::filesystem::path path(raw);
        std::error_code ec;
        if (std::filesystem::is_regular_file(path, ec)) {
            std::ifstream input(path);
            if (!input) {
                error = "cannot open share file '" + raw + "'";
                return false;
            }
            std::string line;
            std::size_t line_number = 0u;
            while (std::getline(input, line)) {
                ++line_number;
                line = trim_copy(line);
                if (line.empty() || line[0] == '#') continue;
                lines.emplace_back(
                    raw + ":" + std::to_string(line_number), line);
            }
        } else {
            lines.emplace_back("inline", raw);
        }
    }
    if (lines.empty()) {
        error = "no SLIP-39 shares were loaded";
        return false;
    }
    return true;
}

bool build_ems_sets(
    const Options& options,
    std::vector<EncryptedMasterSecret>& results,
    std::uint64_t& template_candidates,
    std::string& error) {
    std::vector<std::pair<std::string, std::string>> lines;
    if (!load_share_lines(
            options.recovery_values, lines, error)) return false;
    std::vector<std::vector<Share>> variants;
    variants.reserve(lines.size());
    for (const auto& line : lines) {
        std::vector<Share> share_variants;
        std::string local_error;
        if (!parse_share_template(
                line.second, share_variants,
                template_candidates, local_error)) {
            error = line.first + ": " + local_error;
            return false;
        }
        variants.push_back(std::move(share_variants));
    }
    std::uint64_t combination_count = 1u;
    for (const auto& choices : variants) {
        if (choices.empty() ||
            combination_count >
                kMaximumTemplateCombinations / choices.size()) {
            error = "damaged-share combinations exceed the 1,000,000 safety limit";
            return false;
        }
        combination_count *= choices.size();
    }
    std::map<std::string, EncryptedMasterSecret> recovered;
    std::vector<Share> selected;
    std::uint64_t visited = 0u;
    enumerate_share_combinations(
        variants, 0u, selected, visited, recovered);
    if (recovered.empty()) {
        error = "no compatible threshold-complete SLIP-39 share set";
        return false;
    }
    for (auto& item : recovered) {
        results.push_back(std::move(item.second));
    }
    return true;
}

bool decrypt_ems(
    const EncryptedMasterSecret& ems,
    const std::string& password,
    std::vector<std::uint8_t>& master_secret,
    std::string& error) {
    if (password.size() >= kPasswordStride) {
        error = "SLIP-39 passphrase exceeds 127 bytes";
        return false;
    }
    if (!std::all_of(
            password.begin(), password.end(),
            [](unsigned char ch) {
                return ch >= 32u && ch <= 126u;
            })) {
        error = "SLIP-39 passphrase must contain printable ASCII only";
        return false;
    }
    const std::size_t half = ems.ciphertext.size() / 2u;
    std::vector<std::uint8_t> left(
        ems.ciphertext.begin(), ems.ciphertext.begin() + half);
    std::vector<std::uint8_t> right(
        ems.ciphertext.begin() + half, ems.ciphertext.end());
    std::vector<std::uint8_t> salt_prefix;
    if (!ems.extendable) {
        salt_prefix = {'s','h','a','m','i','r',
            static_cast<std::uint8_t>(ems.identifier >> 8u),
            static_cast<std::uint8_t>(ems.identifier)};
    }
    const std::uint32_t iterations =
        2500u << ems.iteration_exponent;
    for (int round = 3; round >= 0; --round) {
        std::string round_password;
        round_password.reserve(password.size() + 1u);
        round_password.push_back(static_cast<char>(round));
        round_password += password;
        std::vector<std::uint8_t> salt = salt_prefix;
        salt.insert(salt.end(), right.begin(), right.end());
        std::vector<std::uint8_t> block(half);
        const int status = CCKeyDerivationPBKDF(
            kCCPBKDF2, round_password.data(), round_password.size(),
            salt.data(), salt.size(), kCCPRFHmacAlgSHA256,
            iterations, block.data(), block.size());
        if (status != 0) {
            error = "CommonCrypto PBKDF2 failed";
            return false;
        }
        std::vector<std::uint8_t> next_right(half);
        for (std::size_t i = 0u; i < half; ++i) {
            next_right[i] = left[i] ^ block[i];
        }
        left = std::move(right);
        right = std::move(next_right);
    }
    master_secret = right;
    master_secret.insert(
        master_secret.end(), left.begin(), left.end());
    return true;
}

bool load_targets(
    const Options& options,
    std::vector<Target>& targets,
    std::uint64_t& logical,
    std::string& error) {
    std::map<std::array<std::uint8_t, 32>, std::size_t> unique;
    const auto add_target = [&](const std::array<std::uint8_t, 32>& digest,
                                const std::string& source,
                                const std::string& raw) {
        ++logical;
        auto found = unique.find(digest);
        if (found == unique.end()) {
            const std::size_t index = targets.size();
            unique.emplace(digest, index);
            Target target;
            target.digest = digest;
            target.occurrences.push_back({source, raw});
            targets.push_back(std::move(target));
        } else {
            targets[found->second].occurrences.push_back({source, raw});
        }
    };
    for (const std::string& raw : options.target_values) {
        const std::filesystem::path path(raw);
        std::error_code ec;
        if (std::filesystem::is_regular_file(path, ec)) {
            std::ifstream input(path);
            if (!input) {
                error = "cannot open target file '" + raw + "'";
                return false;
            }
            std::string line;
            std::size_t line_number = 0u;
            while (std::getline(input, line)) {
                ++line_number;
                line = trim_copy(line);
                if (line.empty() || line[0] == '#') continue;
                std::istringstream tokens(line);
                std::string token;
                tokens >> token;
                std::array<std::uint8_t, 32> digest{};
                if (!decode_digest(token, digest)) {
                    error = raw + ":" + std::to_string(line_number) +
                        ": target must be 64 hex SHA256";
                    return false;
                }
                add_target(
                    digest, raw + ":" + std::to_string(line_number),
                    token);
            }
        } else {
            std::array<std::uint8_t, 32> digest{};
            if (!decode_digest(raw, digest)) {
                error = "-target must be 64 hex SHA256 or an existing file";
                return false;
            }
            add_target(digest, "inline", raw);
        }
    }
    for (const std::string& raw : options.master_secret_values) {
        std::vector<std::uint8_t> secret;
        if (!decode_hex(raw, secret) ||
            secret.size() < 16u || secret.size() > 32u ||
            (secret.size() & 1u) != 0u) {
            error = "-master-secret must be 16-32 even bytes in hex";
            return false;
        }
        add_target(
            sha256(secret.data(), secret.size()),
            "master-secret", raw);
    }
    return !targets.empty();
}

class PasswordProvider {
public:
    explicit PasswordProvider(const Options& options)
        : options_(options) {}

    bool initialize(std::string& error) {
        if (!options_.mask.empty()) {
            if (!parse_mask(error)) return false;
            mode_ = Mode::Mask;
            return true;
        }
        if (!options_.start.empty()) {
            if (!parse_u64(options_.start, numeric_cursor_) ||
                !parse_u64(options_.end, numeric_end_) ||
                numeric_cursor_ >= numeric_end_) {
                error = "-start/-end must define a non-empty uint64 interval";
                return false;
            }
            mode_ = Mode::Numeric;
            return true;
        }
        if (options_.password_inputs.empty()) {
            mode_ = Mode::DefaultEmpty;
            return true;
        }
        mode_ = Mode::Inputs;
        return open_next_input(error);
    }

    bool next(std::size_t maximum,
              std::vector<std::string>& output,
              std::string& error) {
        output.clear();
        while (output.size() < maximum) {
            std::string value;
            if (!next_one(value, error)) break;
            if (value.size() >= kPasswordStride) {
                error = "password candidate exceeds 127 bytes";
                return false;
            }
            if (!std::all_of(
                    value.begin(), value.end(),
                    [](unsigned char ch) {
                        return ch >= 32u && ch <= 126u;
                    })) {
                error = "SLIP-39 password candidates must be printable ASCII";
                return false;
            }
            output.push_back(std::move(value));
        }
        return error.empty();
    }

private:
    enum class Mode { Inputs, Mask, Numeric, DefaultEmpty };
    const Options& options_;
    Mode mode_ = Mode::Inputs;
    std::size_t input_index_ = 0u;
    std::ifstream file_;
    bool literal_pending_ = false;
    std::string literal_;
    std::vector<std::string> mask_charsets_;
    std::uint64_t mask_cursor_ = 0u;
    std::uint64_t mask_end_ = 0u;
    std::uint64_t numeric_cursor_ = 0u;
    std::uint64_t numeric_end_ = 0u;
    bool empty_pending_ = true;

    bool parse_mask(std::string& error) {
        const std::string& mask = options_.mask;
        for (std::size_t i = 0u; i < mask.size(); ++i) {
            if (mask[i] != '?') {
                mask_charsets_.push_back(std::string(1u, mask[i]));
                continue;
            }
            if (++i >= mask.size()) {
                error = "-mask ends with an incomplete token";
                return false;
            }
            std::string chars;
            switch (mask[i]) {
            case 'd': chars = "0123456789"; break;
            case 'l': chars = "abcdefghijklmnopqrstuvwxyz"; break;
            case 'u': chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; break;
            case 'a':
                for (int ch = 32; ch <= 126; ++ch) {
                    chars.push_back(static_cast<char>(ch));
                }
                break;
            case '?': chars = "?"; break;
            default:
                error = "unsupported mask token ?" +
                    std::string(1u, mask[i]);
                return false;
            }
            mask_charsets_.push_back(std::move(chars));
        }
        if (mask_charsets_.size() >= kPasswordStride) {
            error = "-mask expands to more than 127 password bytes";
            return false;
        }
        mask_end_ = 1u;
        for (const std::string& chars : mask_charsets_) {
            if (mask_end_ >
                std::numeric_limits<std::uint64_t>::max() /
                    chars.size()) {
                error = "-mask domain exceeds uint64";
                return false;
            }
            mask_end_ *= chars.size();
        }
        return true;
    }

    bool open_next_input(std::string& error) {
        file_.close();
        literal_pending_ = false;
        while (input_index_ < options_.password_inputs.size()) {
            const InputSpec& spec =
                options_.password_inputs[input_index_++];
            const std::filesystem::path path(spec.value);
            std::error_code ec;
            const bool file =
                std::filesystem::is_regular_file(path, ec);
            if (spec.force_file && !file) {
                error = "password file does not exist: '" +
                    spec.value + "'";
                return false;
            }
            if (file) {
                file_.open(path);
                if (!file_) {
                    error = "cannot open password file '" +
                        spec.value + "'";
                    return false;
                }
                return true;
            }
            literal_ = spec.value;
            literal_pending_ = true;
            return true;
        }
        return false;
    }

    bool next_one(std::string& value, std::string& error) {
        if (mode_ == Mode::DefaultEmpty) {
            if (!empty_pending_) return false;
            empty_pending_ = false;
            value.clear();
            return true;
        }
        if (mode_ == Mode::Numeric) {
            if (numeric_cursor_ >= numeric_end_) return false;
            value = std::to_string(numeric_cursor_++);
            return true;
        }
        if (mode_ == Mode::Mask) {
            if (mask_cursor_ >= mask_end_) return false;
            std::uint64_t ordinal = mask_cursor_++;
            value.assign(mask_charsets_.size(), '\0');
            for (std::size_t i = mask_charsets_.size(); i > 0u; --i) {
                const std::string& chars = mask_charsets_[i - 1u];
                value[i - 1u] =
                    chars[ordinal % chars.size()];
                ordinal /= chars.size();
            }
            return true;
        }
        while (true) {
            if (literal_pending_) {
                literal_pending_ = false;
                value = literal_;
                return true;
            }
            if (file_.is_open()) {
                if (std::getline(file_, value)) {
                    if (!value.empty() && value.back() == '\r') {
                        value.pop_back();
                    }
                    if (!value.empty() && value[0] == '#') continue;
                    return true;
                }
            }
            if (!open_next_input(error)) return false;
        }
    }
};

bool metal_ok(
    metalError_t status, const char* action, std::string& error) {
    if (status == metalSuccess) return true;
    error = std::string(action) + ": " + metalGetErrorString(status);
    return false;
}

template <typename T>
bool allocate(
    T*& pointer, std::size_t bytes,
    const char* action, std::string& error) {
    return metal_ok(
        metalMalloc(
            reinterpret_cast<void**>(&pointer),
            std::max<std::size_t>(bytes, 1u)),
        action, error);
}

void release_buffers(DeviceBuffers& buffers) {
    if (buffers.device >= 0) (void)metalSetDevice(buffers.device);
    if (buffers.password_data) metalFree(buffers.password_data);
    if (buffers.password_lengths) metalFree(buffers.password_lengths);
    if (buffers.derived) metalFree(buffers.derived);
    if (buffers.targets) metalFree(buffers.targets);
    if (buffers.hits) metalFree(buffers.hits);
    if (buffers.hit_count) metalFree(buffers.hit_count);
    buffers = {};
}

bool prepare_buffers(
    int device,
    std::uint64_t batch_capacity,
    std::uint64_t target_capacity,
    DeviceBuffers& buffers,
    std::string& error) {
    buffers.device = device;
    if (!metal_ok(
            metalSetDevice(device), "select SLIP-39 device", error) ||
        !allocate(
            buffers.password_data,
            static_cast<std::size_t>(batch_capacity) *
                kPasswordStride,
            "allocate SLIP-39 password data", error) ||
        !allocate(
            buffers.password_lengths,
            static_cast<std::size_t>(batch_capacity),
            "allocate SLIP-39 password lengths", error) ||
        !allocate(
            buffers.derived,
            static_cast<std::size_t>(batch_capacity) *
                sizeof(GpuDerived),
            "allocate SLIP-39 derived buffer", error) ||
        !allocate(
            buffers.targets,
            static_cast<std::size_t>(target_capacity) *
                sizeof(GpuTarget),
            "allocate SLIP-39 target tile", error) ||
        !allocate(
            buffers.hits,
            static_cast<std::size_t>(kHitCapacity) *
                sizeof(GpuHit),
            "allocate SLIP-39 hits", error) ||
        !allocate(
            buffers.hit_count, sizeof(std::uint32_t),
            "allocate SLIP-39 hit count", error)) {
        release_buffers(buffers);
        return false;
    }
    buffers.batch_capacity = batch_capacity;
    buffers.target_capacity = target_capacity;
    buffers.allocated =
        batch_capacity *
            (kPasswordStride + 1u + sizeof(GpuDerived)) +
        target_capacity * sizeof(GpuTarget) +
        static_cast<std::uint64_t>(kHitCapacity) *
            sizeof(GpuHit) + sizeof(std::uint32_t);
    return true;
}

bool upload_passwords(
    DeviceBuffers& buffers,
    const std::vector<std::string>& passwords,
    std::string& error) {
    std::vector<char> data(passwords.size() * kPasswordStride, 0);
    std::vector<std::uint8_t> lengths(passwords.size(), 0u);
    for (std::size_t i = 0u; i < passwords.size(); ++i) {
        lengths[i] =
            static_cast<std::uint8_t>(passwords[i].size());
        std::copy(
            passwords[i].begin(), passwords[i].end(),
            data.begin() + i * kPasswordStride);
    }
    return metal_ok(
               metalSetDevice(buffers.device),
               "select SLIP-39 device", error) &&
        metal_ok(
            metalMemcpy(
                buffers.password_data, data.data(), data.size(),
                metalMemcpyHostToDevice),
            "upload SLIP-39 passwords", error) &&
        metal_ok(
            metalMemcpy(
                buffers.password_lengths, lengths.data(),
                lengths.size(), metalMemcpyHostToDevice),
            "upload SLIP-39 password lengths", error);
}

bool read_hits(
    DeviceBuffers& buffers,
    std::vector<GpuHit>& hits,
    std::uint32_t& raw_count,
    std::uint64_t& readback_ns,
    std::string& error) {
    const auto started = std::chrono::steady_clock::now();
    raw_count = 0u;
    if (!metal_ok(
            metalMemcpy(
                &raw_count, buffers.hit_count,
                sizeof(raw_count), metalMemcpyDeviceToHost),
            "read SLIP-39 hit count", error)) {
        return false;
    }
    const std::uint32_t stored =
        std::min(raw_count, kHitCapacity);
    hits.resize(stored);
    if (stored != 0u &&
        !metal_ok(
            metalMemcpy(
                hits.data(), buffers.hits,
                static_cast<std::size_t>(stored) * sizeof(GpuHit),
                metalMemcpyDeviceToHost),
            "read SLIP-39 hits", error)) {
        return false;
    }
    readback_ns += static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - started).count());
    return true;
}

std::uint32_t launch_grid(std::uint64_t count) {
    return static_cast<std::uint32_t>(
        (count + kThreadgroupSize - 1u) /
        kThreadgroupSize * kThreadgroupSize);
}

bool launch_fused(
    DeviceBuffers& buffers,
    const GpuConfig& config,
    const std::vector<std::string>& passwords,
    std::uint64_t candidate_base,
    const GpuTarget* targets,
    std::uint32_t target_count,
    std::vector<GpuHit>& hits,
    std::uint32_t& raw_count,
    std::uint64_t& readback_ns,
    std::string& error) {
    const std::uint64_t count = passwords.size();
    if (!upload_passwords(buffers, passwords, error) ||
        !metal_ok(
            metalMemcpy(
                buffers.targets, targets,
                static_cast<std::size_t>(target_count) *
                    sizeof(GpuTarget),
                metalMemcpyHostToDevice),
            "upload SLIP-39 targets", error) ||
        !metal_ok(
            metalMemset(
                buffers.hit_count, 0,
                sizeof(std::uint32_t)),
            "reset SLIP-39 hit count", error) ||
        !metal_ok(
            metal_launch(
                "workerSlip39Fused",
                launch_grid(count), kThreadgroupSize,
                config, buffers.password_data,
                buffers.password_lengths, candidate_base, count,
                buffers.targets, target_count, buffers.hits,
                buffers.hit_count, kHitCapacity),
            "launch fused SLIP-39 worker", error) ||
        !metal_ok(
            metalDeviceSynchronize(),
            "synchronize fused SLIP-39 worker", error)) {
        return false;
    }
    return read_hits(
        buffers, hits, raw_count, readback_ns, error);
}

bool launch_derive(
    DeviceBuffers& buffers,
    const GpuConfig& config,
    const std::vector<std::string>& passwords,
    std::string& error) {
    const std::uint64_t count = passwords.size();
    return upload_passwords(buffers, passwords, error) &&
        metal_ok(
            metal_launch(
                "workerSlip39Derive",
                launch_grid(count), kThreadgroupSize,
                config, buffers.password_data,
                buffers.password_lengths, count, buffers.derived),
            "launch SLIP-39 derive", error) &&
        metal_ok(
            metalDeviceSynchronize(),
            "synchronize SLIP-39 derive", error);
}

bool launch_lookup(
    DeviceBuffers& buffers,
    const GpuConfig& config,
    std::uint64_t candidate_base,
    std::uint64_t candidate_count,
    const GpuTarget* targets,
    std::uint32_t target_count,
    std::vector<GpuHit>& hits,
    std::uint32_t& raw_count,
    std::uint64_t& readback_ns,
    std::string& error) {
    if (!metal_ok(
            metalMemcpy(
                buffers.targets, targets,
                static_cast<std::size_t>(target_count) *
                    sizeof(GpuTarget),
                metalMemcpyHostToDevice),
            "upload SLIP-39 target tile", error) ||
        !metal_ok(
            metalMemset(
                buffers.hit_count, 0,
                sizeof(std::uint32_t)),
            "reset SLIP-39 hit count", error) ||
        !metal_ok(
            metal_launch(
                "workerSlip39Lookup",
                launch_grid(candidate_count), kThreadgroupSize,
                config, buffers.password_data,
                buffers.password_lengths, candidate_base,
                candidate_count, buffers.derived,
                buffers.targets, target_count, buffers.hits,
                buffers.hit_count, kHitCapacity),
            "launch SLIP-39 lookup", error) ||
        !metal_ok(
            metalDeviceSynchronize(),
            "synchronize SLIP-39 lookup", error)) {
        return false;
    }
    return read_hits(
        buffers, hits, raw_count, readback_ns, error);
}

std::uint64_t saturating_add(
    std::uint64_t left, std::uint64_t right) {
    return std::numeric_limits<std::uint64_t>::max() - left < right
        ? std::numeric_limits<std::uint64_t>::max()
        : left + right;
}

} // namespace

bool requested(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-slip39") == 0) return true;
    }
    return false;
}

void print_help() {
    std::cout << R"HELP([!] MAIN MODE: -slip39  (SLIP-0039 share and passphrase recovery)
[!]
[!] Purpose:
[!] Reconstruct an encrypted master secret from standard SLIP-39 shares,
[!] repair up to two unknown words per share, and search the optional
[!] printable-ASCII passphrase with a Metal Feistel/PBKDF2-HMAC-SHA256 worker.
[!]
[!] Share input:
[!] -recovery FILE                 One mnemonic share/template per line.
[!]                                Empty lines and # comments are ignored.
[!] -recovery "WORDS ..."          Inline share; repeat for multiple shares.
[!] ? or *                         Unknown word (maximum two per share).
[!] Group/member thresholds and RS1024 checksums are enforced exactly.
[!]
[!] Required verification:
[!] -target SHA256|FILE            SHA256(master-secret), 64 hex; repeatable.
[!] -master-secret HEX             Known 16-32 even-byte secret; repeatable.
[!]                                Its SHA256 is used as the target.
[!]
[!] Password candidates:
[!] -pass VALUE|FILE               Literal password or existing text file.
[!] -i FILE                        Streaming password dictionary; repeatable.
[!] -mask MASK                     ?d, ?l, ?u, ?a and ?? masks.
[!] -start N -end N                Decimal-string passwords in [START,END).
[!] No password source means the standard empty passphrase.
[!]
[!] GPU / memory:
[!] -wallet-mem auto|all|NN%|SIZE  Unified-memory working-set budget.
[!] -n N                           Maximum candidates per completed batch.
[!] -device LIST                   Metal devices, for example 0 or 0,1.
[!] Large target sets use one KDF pass followed by tiled GPU lookup.
[!] auto shrinks allocations after failure; explicit budgets are strict.
[!]
[!] Statistics:
[!] The common SpeedThreadFunc reports Pwd/s, Primitive/s, Verify/s,
[!] logical/resident/solved targets, allocated working set and readback time.
[!] A password is credited only after its Metal command buffer completes.
[!]
[!] Output:
[!] -save                          Append independently verified hits.
[!] -o FILE                        Output path (also enables saving).
[!] -silent                        Suppress found lines on the console.
[!]
[!] Examples:
[!]   ./METAL_CRYPTO_TOOLKIT -slip39 -recovery shares.txt \
[!]     -master-secret 00112233445566778899aabbccddeeff
[!]   ./METAL_CRYPTO_TOOLKIT -slip39 -recovery shares.txt \
[!]     -target targets.txt -i passwords.txt -wallet-mem auto -save
[!]   ./METAL_CRYPTO_TOOLKIT -slip39 -recovery damaged.txt \
[!]     -target SHA256HEX -mask "TREZOR?d?d" -wallet-mem all -device 0
[!]
[!] Limitations:
[!] English SLIP-39 only. Master secrets are 128-256 bits and passphrases
[!] must follow SLIP-39 printable-ASCII rules. This mode verifies the
[!] recovered master secret (or its SHA256), not a wallet derivation path.
[!] At most two unknown words are allowed per share and at most 1,000,000
[!] compatible template combinations are examined.
[!]
[!] Errors:
[!] CLI errors return 2; Metal/runtime errors return 1; a complete search
[!] returns 0 even when no target was found.
)HELP";
}

int run(int argc, char** argv, const RuntimeHooks& hooks) {
    Options options;
    std::string error;
    if (!parse_options(argc, argv, options, error)) {
        std::cerr << "[!] SLIP-39 CLI error: " << error << " [!]\n";
        return 2;
    }

    std::vector<EncryptedMasterSecret> ems_sets;
    std::uint64_t template_candidates = 0u;
    if (!build_ems_sets(
            options, ems_sets, template_candidates, error)) {
        std::cerr << "[!] SLIP-39 input error: " << error << " [!]\n";
        return 2;
    }
    std::vector<Target> targets;
    std::uint64_t logical_targets = 0u;
    if (!load_targets(
            options, targets, logical_targets, error)) {
        std::cerr << "[!] SLIP-39 target error: " << error << " [!]\n";
        return 2;
    }

    int device_count = 0;
    if (!metal_ok(
            metalGetDeviceCount(&device_count),
            "query SLIP-39 devices", error)) {
        std::cerr << "[!] SLIP-39 runtime error: "
                  << error << " [!]\n";
        return 1;
    }
    std::vector<modeinfra::MemoryDeviceInfo> memory_devices;
    for (const int device : options.devices) {
        if (device < 0 || device >= device_count) {
            std::cerr << "[!] SLIP-39 CLI error: device "
                      << device << " is unavailable [!]\n";
            return 2;
        }
        metalDeviceProp properties{};
        if (!metal_ok(
                metalGetDeviceProperties(&properties, device),
                "query SLIP-39 device", error)) {
            std::cerr << "[!] SLIP-39 runtime error: "
                      << error << " [!]\n";
            return 1;
        }
        memory_devices.push_back({
            properties.recommendedMaxWorkingSetSize,
            properties.currentAllocatedSize,
            properties.maxBufferLength,
            properties.hasUnifiedMemory != 0
        });
    }

    modeinfra::MemorySpec memory_spec;
    if (!modeinfra::parse_memory_spec(
            options.memory, memory_spec, error)) {
        std::cerr << "[!] SLIP-39 CLI error: "
                  << error << " [!]\n";
        return 2;
    }
    const std::uint64_t mandatory =
        kPasswordStride + 1u + sizeof(GpuDerived) +
        sizeof(GpuTarget) +
        static_cast<std::uint64_t>(kHitCapacity) *
            sizeof(GpuHit) + sizeof(std::uint32_t);
    modeinfra::MemoryBudget budget;
    if (!modeinfra::resolve_memory_budget(
            memory_spec, memory_devices, mandatory, 0u,
            budget, error, kRuntimeReserve)) {
        std::cerr << "[!] SLIP-39 memory error: "
                  << error << " [!]\n";
        return 1;
    }

    const std::uint64_t hit_bytes =
        static_cast<std::uint64_t>(kHitCapacity) *
            sizeof(GpuHit) + sizeof(std::uint32_t);
    if (budget.per_device_budget <= hit_bytes + mandatory) {
        std::cerr << "[!] SLIP-39 memory error: budget cannot hold "
                  << "one candidate and target [!]\n";
        return 1;
    }
    const std::uint64_t variable =
        budget.per_device_budget - hit_bytes;
    const std::uint64_t target_budget = variable / 3u;
    std::uint64_t target_capacity =
        std::max<std::uint64_t>(1u,
            std::min<std::uint64_t>(
                targets.size(),
                std::min<std::uint64_t>(
                    std::numeric_limits<std::uint32_t>::max(),
                    target_budget / sizeof(GpuTarget))));
    const std::uint64_t fixed =
        hit_bytes + target_capacity * sizeof(GpuTarget);
    std::uint64_t batch_capacity =
        (budget.per_device_budget - fixed) /
        (kPasswordStride + 1u + sizeof(GpuDerived));
    batch_capacity =
        std::max<std::uint64_t>(1u,
            std::min<std::uint64_t>(batch_capacity, kMaximumBatch));
    if (options.batch_explicit) {
        batch_capacity = std::min(batch_capacity, options.batch);
    } else {
        batch_capacity = std::min(batch_capacity, kDefaultBatch);
    }

    std::vector<DeviceBuffers> devices(options.devices.size());
    bool allocated = false;
    while (!allocated) {
        allocated = true;
        for (std::size_t i = 0u; i < devices.size(); ++i) {
            if (!prepare_buffers(
                    options.devices[i], batch_capacity,
                    target_capacity, devices[i], error)) {
                allocated = false;
                break;
            }
        }
        if (allocated) break;
        for (DeviceBuffers& buffers : devices) {
            release_buffers(buffers);
        }
        if (memory_spec.kind != modeinfra::MemoryKind::Auto ||
            (batch_capacity == 1u && target_capacity == 1u)) {
            std::cerr << "[!] SLIP-39 allocation error: "
                      << error << " [!]\n";
            return 1;
        }
        if (batch_capacity > 1u) batch_capacity /= 2u;
        else target_capacity =
            std::max<std::uint64_t>(1u, target_capacity / 2u);
    }

    std::uint64_t allocated_bytes = 0u;
    for (const DeviceBuffers& buffers : devices) {
        allocated_bytes =
            saturating_add(allocated_bytes, buffers.allocated);
    }

    std::vector<GpuTarget> gpu_targets;
    gpu_targets.reserve(targets.size());
    for (std::size_t i = 0u; i < targets.size(); ++i) {
        GpuTarget target;
        target.digest = targets[i].digest;
        target.prefix = digest_prefix(target.digest);
        target.source_index = i;
        gpu_targets.push_back(target);
    }
    std::sort(
        gpu_targets.begin(), gpu_targets.end(),
        [](const GpuTarget& left, const GpuTarget& right) {
            if (left.prefix != right.prefix) {
                return left.prefix < right.prefix;
            }
            return left.digest < right.digest;
        });

    bool use_fused = gpu_targets.size() <= target_capacity;
    if (const char* raw =
            std::getenv("METAL_SLIP39_PIPELINE")) {
        const std::string pipeline = lower_copy(trim_copy(raw));
        if (pipeline == "split") {
            use_fused = false;
        } else if (pipeline == "fused") {
            if (gpu_targets.size() > target_capacity) {
                for (auto& buffers : devices) release_buffers(buffers);
                std::cerr << "[!] SLIP-39 runtime error: forced fused "
                          << "pipeline cannot hold all targets [!]\n";
                return 1;
            }
            use_fused = true;
        } else if (!pipeline.empty() && pipeline != "auto") {
            for (auto& buffers : devices) release_buffers(buffers);
            std::cerr << "[!] SLIP-39 runtime error: "
                      << "METAL_SLIP39_PIPELINE expects auto, fused, "
                      << "or split [!]\n";
            return 1;
        }
    }

    std::ofstream output;
    if (options.save || !options.output_path.empty()) {
        const std::string path = options.output_path.empty()
            ? "result.txt" : options.output_path;
        output.open(path, std::ios::app);
        if (!output) {
            for (auto& buffers : devices) release_buffers(buffers);
            std::cerr << "[!] SLIP-39 runtime error: cannot open '"
                      << path << "' [!]\n";
            return 1;
        }
    }

    std::cout << "[!] SLIP-39 EMS sets: " << ems_sets.size()
              << " | share-template candidates: "
              << template_candidates << " | targets: "
              << targets.size() << " unique/" << logical_targets
              << " logical | devices: " << devices.size()
              << " | batch: " << batch_capacity
              << " | target tile: " << target_capacity
              << " | pipeline: " << (use_fused ? "fused" : "split")
              << " | working set: " << allocated_bytes
              << " bytes [!]\n";

    modeinfra::ModeProgress& progress =
        modeinfra::global_mode_progress();
    progress.begin(
        "SLIP39", modeinfra::ProgressUnit::Password,
        modeinfra::ProgressPhase::Search);
    progress.set_targets(
        logical_targets,
        std::min<std::uint64_t>(
            targets.size(), target_capacity), 0u);
    progress.set_allocated_working_set(allocated_bytes);

    std::uint64_t solved_logical = 0u;
    std::uint64_t founds = 0u;
    std::uint64_t global_candidate = 0u;
    std::size_t device_slot = 0u;
    int result = 0;
    for (std::size_t ems_index = 0u;
         ems_index < ems_sets.size() &&
         solved_logical < logical_targets; ++ems_index) {
        const EncryptedMasterSecret& ems = ems_sets[ems_index];
        GpuConfig config;
        std::copy(
            ems.ciphertext.begin(), ems.ciphertext.end(),
            config.ciphertext.begin());
        config.ciphertext_len =
            static_cast<std::uint32_t>(ems.ciphertext.size());
        config.identifier = ems.identifier;
        config.iteration_exponent = ems.iteration_exponent;
        config.extendable = ems.extendable ? 1u : 0u;

        PasswordProvider provider(options);
        if (!provider.initialize(error)) {
            result = 2;
            break;
        }
        while (solved_logical < logical_targets) {
            std::vector<std::string> passwords;
            if (!provider.next(
                    static_cast<std::size_t>(batch_capacity),
                    passwords, error)) {
                result = 2;
                break;
            }
            if (passwords.empty()) break;
            DeviceBuffers& buffers = devices[device_slot];
            std::vector<GpuHit> resolved_hits;
            std::uint64_t readback_ns = 0u;
            bool overflow = false;
            if (use_fused) {
                std::uint32_t raw_count = 0u;
                if (!launch_fused(
                        buffers, config, passwords,
                        global_candidate, gpu_targets.data(),
                        static_cast<std::uint32_t>(
                            gpu_targets.size()),
                        resolved_hits, raw_count,
                        readback_ns, error)) {
                    result = 1;
                    break;
                }
                overflow = raw_count > kHitCapacity;
            } else {
                if (!launch_derive(
                        buffers, config, passwords, error)) {
                    result = 1;
                    break;
                }
                for (std::size_t tile = 0u;
                     tile < gpu_targets.size(); tile +=
                         static_cast<std::size_t>(target_capacity)) {
                    const std::uint32_t tile_count =
                        static_cast<std::uint32_t>(
                            std::min<std::size_t>(
                                target_capacity,
                                gpu_targets.size() - tile));
                    std::vector<GpuHit> tile_hits;
                    std::uint32_t raw_count = 0u;
                    if (!launch_lookup(
                            buffers, config, global_candidate,
                            passwords.size(),
                            gpu_targets.data() + tile, tile_count,
                            tile_hits, raw_count, readback_ns,
                            error)) {
                        result = 1;
                        break;
                    }
                    if (raw_count > kHitCapacity) {
                        overflow = true;
                        break;
                    }
                    resolved_hits.insert(
                        resolved_hits.end(),
                        tile_hits.begin(), tile_hits.end());
                }
                if (result != 0) break;
            }
            if (overflow) {
                error = "SLIP-39 hit buffer overflow; reduce -n";
                result = 1;
                break;
            }

            std::uint64_t exact = 0u;
            for (const GpuHit& hit : resolved_hits) {
                ++exact;
                if (hit.target_index >= targets.size() ||
                    hit.candidate_index < global_candidate ||
                    hit.candidate_index >=
                        global_candidate + passwords.size()) {
                    error = "SLIP-39 GPU hit contains invalid indexes";
                    result = 1;
                    break;
                }
                const std::size_t local =
                    static_cast<std::size_t>(
                        hit.candidate_index - global_candidate);
                const std::string& password = passwords[local];
                if (hit.password_len != password.size() ||
                    !std::equal(
                        password.begin(), password.end(),
                        hit.password.begin())) {
                    error = "SLIP-39 GPU hit password mismatch";
                    result = 1;
                    break;
                }
                std::vector<std::uint8_t> master_secret;
                if (!decrypt_ems(
                        ems, password, master_secret, error)) {
                    result = 1;
                    break;
                }
                if (master_secret.size() != hit.secret_len ||
                    !std::equal(
                        master_secret.begin(), master_secret.end(),
                        hit.master_secret.begin())) {
                    error = "SLIP-39 GPU hit failed host Feistel verification";
                    result = 1;
                    break;
                }
                const auto digest =
                    sha256(master_secret.data(), master_secret.size());
                Target& target = targets[hit.target_index];
                if (digest != target.digest) {
                    error = "SLIP-39 GPU hit resolved to the wrong target";
                    result = 1;
                    break;
                }
                if (target.solved) continue;
                target.solved = true;
                solved_logical = saturating_add(
                    solved_logical, target.occurrences.size());
                ++founds;
                if (hooks.increment_found) hooks.increment_found();
                std::string sources;
                for (std::size_t i = 0u;
                     i < target.occurrences.size(); ++i) {
                    if (i != 0u) sources.push_back(',');
                    sources += target.occurrences[i].source;
                }
                const std::string line =
                    "[+] SLIP39_FOUND TARGET:" + sources +
                    " EMS:" + std::to_string(ems_index) +
                    " PASSWORD:" + password +
                    " MASTER_SECRET:" +
                    hex_lower(
                        master_secret.data(), master_secret.size()) +
                    " SHA256:" +
                    hex_lower(digest.data(), digest.size());
                if (!options.silent) std::cout << line << '\n';
                if (output) {
                    output << line << '\n';
                    output.flush();
                }
            }
            if (result != 0) break;
            const std::uint64_t completed = passwords.size();
            progress.credit_completed(
                completed,
                completed * 4u *
                    (2500u << ems.iteration_exponent),
                exact, readback_ns);
            progress.set_targets(
                logical_targets,
                std::min<std::uint64_t>(
                    targets.size(), target_capacity),
                solved_logical);
            progress.set_founds(founds);
            if (hooks.add_completed) hooks.add_completed(completed);
            global_candidate =
                saturating_add(global_candidate, completed);
            device_slot = (device_slot + 1u) % devices.size();
        }
        if (result != 0) break;
    }

    progress.end();
    for (DeviceBuffers& buffers : devices) {
        release_buffers(buffers);
    }
    if (result != 0) {
        std::cerr << "[!] SLIP-39 "
                  << (result == 2 ? "input" : "runtime")
                  << " error: " << error << " [!]\n";
        return result;
    }
    std::cout << "[!] SLIP-39 search complete: solved "
              << solved_logical << '/' << logical_targets
              << " logical targets [!]\n";
    return 0;
}

} // namespace slip39_mode
