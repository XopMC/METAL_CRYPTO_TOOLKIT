#include "AlgorandMode.h"

#include "../MetalBackend.h"
#include "../RecoveryWordlistsEmbedded.h"
#include "../tools/common/Hashes.h"

#include <CommonCrypto/CommonDigest.h>

extern "C" {
#include "../Monero/third_party/crypto-ops.h"
}

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
#include <set>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace algorand_mode {
namespace {

constexpr std::uint32_t kThreadgroupSize = 256u;
constexpr std::uint32_t kHitCapacity = 65536u;
constexpr std::uint64_t kDefaultBatch = 1ull << 16u;
constexpr std::uint64_t kMaximumBatch = 1ull << 22u;
constexpr std::uint64_t kRuntimeReserve =
    512ull * 1024ull * 1024ull;
constexpr std::uint16_t kUnknownWord = 0xffffu;
constexpr std::uint16_t kFlagValid = 1u;
constexpr std::uint16_t kFlagChecksumAny = 2u;

struct alignas(16) GpuCandidate {
    std::array<std::uint16_t, 24> words{};
    std::uint16_t checksum_word = 0u;
    std::uint16_t flags = 0u;
    std::uint32_t reserved0 = 0u;
    std::array<std::uint64_t, 4> ordinal{};
    std::uint64_t template_index = 0u;
};

struct alignas(8) GpuDerived {
    std::array<std::uint8_t, 32> public_key{};
    std::uint32_t checksum_word = 0u;
    std::uint32_t valid = 0u;
};

struct alignas(16) GpuTarget {
    std::array<std::uint8_t, 32> public_key{};
    std::uint64_t prefix = 0u;
    std::uint64_t source_index = 0u;
};

struct alignas(8) GpuHit {
    std::array<std::uint64_t, 4> ordinal{};
    std::uint64_t template_index = 0u;
    std::uint64_t target_index = 0u;
    std::array<std::uint8_t, 32> public_key{};
    std::uint32_t checksum_word = 0u;
    std::uint32_t reserved = 0u;
};

static_assert(sizeof(GpuCandidate) == 96u);
static_assert(sizeof(GpuDerived) == 40u);
static_assert(sizeof(GpuTarget) == 48u);
static_assert(sizeof(GpuHit) == 88u);

struct Occurrence {
    std::string source;
    std::string raw;
};

struct Target {
    std::array<std::uint8_t, 32> public_key{};
    std::vector<Occurrence> occurrences;
    bool solved = false;
};

struct SeedTemplate {
    std::array<std::uint16_t, 25> indices{};
    std::vector<std::size_t> unknown_positions;
    std::vector<std::uint64_t> radices;
    modeinfra::U256 domain_size = modeinfra::U256::from_u64(1u);
    std::string source;
    bool scramble = false;
    bool full_u256_domain = false;
};

struct Options {
    std::vector<std::string> target_values;
    std::vector<std::string> seed_values;
    std::vector<int> devices{0};
    std::string memory = "auto";
    std::string output_path;
    std::string start_text;
    std::string end_text;
    std::uint64_t batch = 0u;
    bool batch_explicit = false;
    bool scramble = false;
    bool save = false;
    bool silent = false;
};

struct DeviceBuffers {
    int device = -1;
    GpuCandidate* candidates = nullptr;
    GpuDerived* derived = nullptr;
    GpuTarget* targets = nullptr;
    GpuHit* hits = nullptr;
    std::uint32_t* hit_count = nullptr;
    std::uint64_t batch_capacity = 0u;
    std::uint64_t target_capacity = 0u;
    std::uint64_t allocated = 0u;
};

std::string trim_copy(std::string value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1u);
}

bool parse_u64(const std::string& raw, std::uint64_t& value) {
    const std::string text = trim_copy(raw);
    if (text.empty()) return false;
    std::size_t used = 0u;
    try {
        value = std::stoull(text, &used, 0);
    } catch (...) {
        return false;
    }
    return used == text.size();
}

bool is_full_u256_text(const std::string& raw) {
    std::string text = trim_copy(raw);
    std::transform(
        text.begin(), text.end(), text.begin(),
        [](unsigned char value) {
            return static_cast<char>(std::tolower(value));
        });
    return text == "2^256" ||
        text == "0x10000000000000000000000000000000000000000000000000000000000000000";
}

bool parse_devices(const std::string& raw,
                   std::vector<int>& devices,
                   std::string& error) {
    std::set<int> unique;
    std::stringstream input(raw);
    std::string token;
    while (std::getline(input, token, ',')) {
        std::uint64_t value = 0u;
        if (!parse_u64(token, value) ||
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
    bool after_mode = false;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i] == nullptr ? "" : argv[i];
        auto require_value = [&](const char* name) -> const char* {
            if (i + 1 >= argc || argv[i + 1] == nullptr) {
                error = std::string(name) + " requires a value";
                return nullptr;
            }
            return argv[++i];
        };
        if (arg == "-algorand") {
            after_mode = true;
        } else if (arg == "-target") {
            const char* value = require_value("-target");
            if (!value) return false;
            options.target_values.emplace_back(value);
        } else if (arg == "-i") {
            const char* value = require_value("-i");
            if (!value) return false;
            options.seed_values.emplace_back(value);
        } else if (arg == "-wallet-mem") {
            const char* value = require_value("-wallet-mem");
            if (!value) return false;
            options.memory = value;
        } else if (arg == "-device") {
            const char* value = require_value("-device");
            if (!value ||
                !parse_devices(value, options.devices, error)) {
                return false;
            }
        } else if (arg == "-n") {
            const char* value = require_value("-n");
            if (!value || !parse_u64(value, options.batch) ||
                options.batch == 0u || options.batch > kMaximumBatch) {
                error = "-n expects 1.." +
                    std::to_string(kMaximumBatch);
                return false;
            }
            options.batch_explicit = true;
        } else if (arg == "-start") {
            const char* value = require_value("-start");
            if (!value) return false;
            options.start_text = value;
        } else if (arg == "-end") {
            const char* value = require_value("-end");
            if (!value) return false;
            options.end_text = value;
        } else if (arg == "-scramble" ||
                   arg == "-algorand-scramble") {
            options.scramble = true;
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
            options.seed_values.push_back(arg);
        } else {
            error = "unsupported -algorand argument '" + arg + "'";
            return false;
        }
    }
    if (options.target_values.empty()) {
        error = "-algorand requires at least one -target";
        return false;
    }
    if (options.seed_values.empty()) {
        error = "-algorand requires at least one mnemonic/template through -i";
        return false;
    }
    return true;
}

bool decode_hex(const std::string& raw,
                std::array<std::uint8_t, 32>& bytes) {
    const std::string text = trim_copy(raw);
    if (text.size() != 64u) return false;
    const auto nibble = [](char ch) -> int {
        if (ch >= '0' && ch <= '9') return ch - '0';
        if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
        if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
        return -1;
    };
    for (std::size_t i = 0u; i < bytes.size(); ++i) {
        const int high = nibble(text[i * 2u]);
        const int low = nibble(text[i * 2u + 1u]);
        if (high < 0 || low < 0) return false;
        bytes[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return true;
}

std::string hex_lower(const std::uint8_t* data, std::size_t size) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0u; i < size; ++i) {
        out << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return out.str();
}

int base32_value(char ch) {
    if (ch >= 'A' && ch <= 'Z') return ch - 'A';
    if (ch >= 'a' && ch <= 'z') return ch - 'a';
    if (ch >= '2' && ch <= '7') return ch - '2' + 26;
    return -1;
}

bool decode_address(const std::string& raw,
                    std::array<std::uint8_t, 32>& public_key,
                    std::string& error) {
    const std::string text = trim_copy(raw);
    if (decode_hex(text, public_key)) return true;
    if (text.size() != 58u) {
        error = "Algorand target must be a 58-character address or 64 hex public key";
        return false;
    }
    std::array<std::uint8_t, 36> decoded{};
    std::uint32_t accumulator = 0u;
    unsigned bits = 0u;
    std::size_t output = 0u;
    for (char ch : text) {
        const int value = base32_value(ch);
        if (value < 0) {
            error = "Algorand address contains a non-Base32 character";
            return false;
        }
        accumulator = (accumulator << 5u) |
            static_cast<std::uint32_t>(value);
        bits += 5u;
        if (bits >= 8u) {
            bits -= 8u;
            if (output >= decoded.size()) {
                error = "Algorand address has excess Base32 data";
                return false;
            }
            decoded[output++] =
                static_cast<std::uint8_t>(accumulator >> bits);
            accumulator &= bits == 0u ? 0u : ((1u << bits) - 1u);
        }
    }
    if (output != decoded.size() ||
        (bits != 0u && accumulator != 0u)) {
        error = "Algorand address has invalid Base32 padding";
        return false;
    }
    std::copy_n(decoded.begin(), public_key.size(), public_key.begin());
    const auto digest =
        address_tools::sha512_256(public_key.data(), public_key.size());
    if (!std::equal(
            decoded.begin() + 32u, decoded.end(),
            digest.end() - 4u)) {
        error = "Algorand address checksum mismatch";
        return false;
    }
    return true;
}

std::string encode_address(
    const std::array<std::uint8_t, 32>& public_key) {
    static constexpr char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::array<std::uint8_t, 36> payload{};
    std::copy(public_key.begin(), public_key.end(), payload.begin());
    const auto digest =
        address_tools::sha512_256(public_key.data(), public_key.size());
    std::copy(digest.end() - 4u, digest.end(), payload.begin() + 32u);
    std::string result;
    result.reserve(58u);
    std::uint32_t accumulator = 0u;
    unsigned bits = 0u;
    for (std::uint8_t byte : payload) {
        accumulator = (accumulator << 8u) | byte;
        bits += 8u;
        while (bits >= 5u) {
            bits -= 5u;
            result.push_back(alphabet[(accumulator >> bits) & 31u]);
            accumulator &= bits == 0u ? 0u : ((1u << bits) - 1u);
        }
    }
    if (bits != 0u) {
        result.push_back(alphabet[(accumulator << (5u - bits)) & 31u]);
    }
    return result;
}

std::uint64_t target_prefix(
    const std::array<std::uint8_t, 32>& value) {
    std::uint64_t result = 0u;
    for (std::size_t i = 0u; i < 8u; ++i) {
        result = (result << 8u) | value[i];
    }
    return result;
}

bool path_is_file(const std::string& value) {
    std::error_code ec;
    return std::filesystem::is_regular_file(value, ec);
}

bool load_targets(const Options& options,
                  std::vector<Target>& targets,
                  std::uint64_t& logical,
                  std::string& error) {
    std::map<std::array<std::uint8_t, 32>, std::size_t> unique;
    auto add = [&](const std::string& raw,
                   const std::string& source) -> bool {
        std::array<std::uint8_t, 32> key{};
        if (!decode_address(raw, key, error)) {
            error = source + ": " + error;
            return false;
        }
        const auto found = unique.find(key);
        if (found == unique.end()) {
            unique.emplace(key, targets.size());
            Target target;
            target.public_key = key;
            target.occurrences.push_back({source, raw});
            targets.push_back(std::move(target));
        } else {
            targets[found->second].occurrences.push_back({source, raw});
        }
        if (logical == std::numeric_limits<std::uint64_t>::max()) {
            error = "logical target count overflows 64 bits";
            return false;
        }
        ++logical;
        return true;
    };
    for (std::size_t argument = 0u;
         argument < options.target_values.size(); ++argument) {
        const std::string& value = options.target_values[argument];
        if (!path_is_file(value)) {
            if (!add(value, "target#" + std::to_string(argument + 1u))) {
                return false;
            }
            continue;
        }
        std::ifstream input(value);
        if (!input) {
            error = "cannot open target file '" + value + "'";
            return false;
        }
        std::string line;
        std::size_t line_number = 0u;
        while (std::getline(input, line)) {
            ++line_number;
            const auto comment = line.find('#');
            if (comment != std::string::npos) line.resize(comment);
            std::istringstream words(line);
            std::string token;
            if (!(words >> token)) continue;
            if (!add(token, value + ":" + std::to_string(line_number))) {
                return false;
            }
        }
    }
    if (targets.empty()) {
        error = "no Algorand targets were loaded";
        return false;
    }
    return true;
}

const std::map<std::string, std::uint16_t>& word_index() {
    static const std::map<std::string, std::uint16_t> index = [] {
        std::map<std::string, std::uint16_t> result;
        for (std::uint16_t i = 0u; i < 2048u; ++i) {
            result.emplace(kRecoveryWords_bip39_en[i], i);
        }
        return result;
    }();
    return index;
}

std::vector<std::string> split_words(const std::string& phrase) {
    std::istringstream input(phrase);
    std::vector<std::string> words;
    std::string word;
    while (input >> word) words.push_back(word);
    return words;
}

bool factorial(std::uint64_t count, modeinfra::U256& result,
               std::string& error) {
    result = modeinfra::U256::from_u64(1u);
    for (std::uint64_t value = 2u; value <= count; ++value) {
        modeinfra::U256 next{};
        if (!modeinfra::multiply_checked(result, value, next)) {
            error = "permutation domain exceeds 256 bits";
            return false;
        }
        result = next;
    }
    return true;
}

bool multiset_domain(
    const std::array<std::uint16_t, 25>& words,
    modeinfra::U256& result,
    std::string& error) {
    if (!factorial(words.size(), result, error)) return false;
    std::map<std::uint16_t, std::uint64_t> counts;
    for (std::uint16_t word : words) ++counts[word];
    for (const auto& item : counts) {
        for (std::uint64_t divisor = 2u;
             divisor <= item.second; ++divisor) {
            modeinfra::U256 quotient{};
            std::uint64_t remainder = 0u;
            if (!modeinfra::divide(
                    result, divisor, quotient, remainder) ||
                remainder != 0u) {
                error = "internal multiset-domain division failed";
                return false;
            }
            result = quotient;
        }
    }
    return true;
}

bool parse_template(const std::string& phrase,
                    const std::string& source,
                    bool scramble,
                    SeedTemplate& result,
                    std::string& error) {
    const std::vector<std::string> words = split_words(phrase);
    if (words.size() != 25u) {
        error = source + ": Algorand mnemonic/template must have exactly 25 words";
        return false;
    }
    result = {};
    result.source = source;
    result.scramble = scramble;
    result.indices.fill(kUnknownWord);
    const auto& dictionary = word_index();
    for (std::size_t i = 0u; i < words.size(); ++i) {
        if (words[i] == "?" || words[i] == "*") {
            if (scramble) {
                error = source +
                    ": scramble mode requires 25 known words";
                return false;
            }
            result.unknown_positions.push_back(i);
            if (i < 24u) result.radices.push_back(i == 23u ? 8u : 2048u);
            continue;
        }
        const auto found = dictionary.find(words[i]);
        if (found == dictionary.end()) {
            error = source + ": unknown English word '" + words[i] + "'";
            return false;
        }
        result.indices[i] = found->second;
    }
    if (scramble) {
        if (!multiset_domain(result.indices, result.domain_size, error)) {
            error = source + ": " + error;
            return false;
        }
        return true;
    }
    if (result.indices[23] != kUnknownWord &&
        result.indices[23] > 7u) {
        error = source +
            ": data word 24 violates Algorand zero-padding (index must be 0..7)";
        return false;
    }
    result.domain_size = modeinfra::U256::from_u64(1u);
    for (std::size_t i = 0u; i < result.radices.size(); ++i) {
        const std::uint64_t radix = result.radices[i];
        modeinfra::U256 next{};
        if (!modeinfra::multiply_checked(
                result.domain_size, radix, next)) {
            if (i + 1u != result.radices.size()) {
                error = source + ": unknown-word domain exceeds 256 bits";
                return false;
            }
            result.full_u256_domain = true;
            result.domain_size = {};
            break;
        }
        result.domain_size = next;
    }
    return true;
}

bool load_templates(const Options& options,
                    std::vector<SeedTemplate>& templates,
                    std::string& error) {
    for (std::size_t argument = 0u;
         argument < options.seed_values.size(); ++argument) {
        const std::string& value = options.seed_values[argument];
        if (!path_is_file(value)) {
            SeedTemplate parsed;
            if (!parse_template(
                    value, "input#" + std::to_string(argument + 1u),
                    options.scramble, parsed, error)) {
                return false;
            }
            templates.push_back(std::move(parsed));
            continue;
        }
        std::ifstream input(value);
        if (!input) {
            error = "cannot open mnemonic file '" + value + "'";
            return false;
        }
        std::string line;
        std::size_t line_number = 0u;
        while (std::getline(input, line)) {
            ++line_number;
            const auto comment = line.find('#');
            if (comment != std::string::npos) line.resize(comment);
            line = trim_copy(line);
            if (line.empty()) continue;
            SeedTemplate parsed;
            if (!parse_template(
                    line, value + ":" + std::to_string(line_number),
                    options.scramble, parsed, error)) {
                return false;
            }
            templates.push_back(std::move(parsed));
        }
    }
    if (templates.empty()) {
        error = "no Algorand mnemonic templates were loaded";
        return false;
    }
    return true;
}

bool multiset_unrank(
    const std::array<std::uint16_t, 25>& source,
    const modeinfra::U256& ordinal,
    std::array<std::uint16_t, 25>& output,
    std::string& error) {
    std::map<std::uint16_t, std::uint64_t> counts;
    for (std::uint16_t word : source) ++counts[word];
    modeinfra::U256 total{};
    if (!multiset_domain(source, total, error) ||
        modeinfra::compare(ordinal, total) >= 0) {
        error = "scramble ordinal is outside the multiset domain";
        return false;
    }
    modeinfra::U256 rank = ordinal;
    std::uint64_t remaining = source.size();
    for (std::size_t position = 0u;
         position < output.size(); ++position) {
        bool selected = false;
        for (auto& item : counts) {
            if (item.second == 0u) continue;
            modeinfra::U256 scaled{};
            if (!modeinfra::multiply_checked(
                    total, item.second, scaled)) {
                error = "scramble block multiplication overflow";
                return false;
            }
            modeinfra::U256 block{};
            std::uint64_t remainder = 0u;
            if (!modeinfra::divide(
                    scaled, remaining, block, remainder) ||
                remainder != 0u) {
                error = "scramble block division failed";
                return false;
            }
            if (modeinfra::compare(rank, block) < 0) {
                output[position] = item.first;
                --item.second;
                total = block;
                --remaining;
                selected = true;
                break;
            }
            modeinfra::U256 next_rank{};
            if (!modeinfra::subtract_checked(rank, block, next_rank)) {
                error = "scramble rank underflow";
                return false;
            }
            rank = next_rank;
        }
        if (!selected) {
            error = "scramble unrank failed to select a word";
            return false;
        }
    }
    return true;
}

bool normal_words(
    const SeedTemplate& seed,
    const modeinfra::U256& ordinal,
    std::array<std::uint16_t, 25>& words,
    std::string& error) {
    if (!seed.full_u256_domain &&
        modeinfra::compare(ordinal, seed.domain_size) >= 0) {
        error = "template ordinal is outside its domain";
        return false;
    }
    words = seed.indices;
    modeinfra::U256 current = ordinal;
    std::size_t digit = 0u;
    for (std::size_t position : seed.unknown_positions) {
        if (position == 24u) continue;
        modeinfra::U256 quotient{};
        std::uint64_t remainder = 0u;
        if (!modeinfra::divide(
                current, seed.radices[digit],
                quotient, remainder)) {
            error = "unknown-word ordinal decode failed";
            return false;
        }
        words[position] = static_cast<std::uint16_t>(remainder);
        current = quotient;
        ++digit;
    }
    return true;
}

bool make_words(const SeedTemplate& seed,
                const modeinfra::U256& ordinal,
                std::array<std::uint16_t, 25>& words,
                std::string& error) {
    return seed.scramble
        ? multiset_unrank(seed.indices, ordinal, words, error)
        : normal_words(seed, ordinal, words, error);
}

bool pack_seed(const std::array<std::uint16_t, 25>& words,
               std::array<std::uint8_t, 32>& seed) {
    std::uint64_t accumulator = 0u;
    unsigned bits = 0u;
    std::size_t output = 0u;
    std::uint8_t padding = 0u;
    for (std::size_t i = 0u; i < 24u; ++i) {
        if (words[i] >= 2048u) return false;
        accumulator |= static_cast<std::uint64_t>(words[i]) << bits;
        bits += 11u;
        while (bits >= 8u) {
            const auto value =
                static_cast<std::uint8_t>(accumulator & 0xffu);
            if (output < seed.size()) seed[output] = value;
            else padding = value;
            ++output;
            accumulator >>= 8u;
            bits -= 8u;
        }
    }
    return output == 33u && padding == 0u;
}

std::uint16_t checksum_word(
    const std::array<std::uint8_t, 32>& seed) {
    const auto digest =
        address_tools::sha512_256(seed.data(), seed.size());
    return static_cast<std::uint16_t>(
        (static_cast<std::uint16_t>(digest[0]) |
         (static_cast<std::uint16_t>(digest[1]) << 8u)) & 0x7ffu);
}

bool make_candidate(const SeedTemplate& seed,
                    std::size_t template_index,
                    const modeinfra::U256& ordinal,
                    GpuCandidate& candidate,
                    std::string& error) {
    std::array<std::uint16_t, 25> words{};
    if (!make_words(seed, ordinal, words, error)) return false;
    candidate = {};
    std::copy_n(words.begin(), 24u, candidate.words.begin());
    candidate.checksum_word =
        words[24] == kUnknownWord ? 0u : words[24];
    candidate.flags = kFlagValid;
    if (words[24] == kUnknownWord) {
        candidate.flags |= kFlagChecksumAny;
    }
    candidate.ordinal = ordinal.limbs;
    candidate.template_index = template_index;
    return true;
}

bool host_public_key(
    const std::array<std::uint8_t, 32>& seed,
    std::array<std::uint8_t, 32>& public_key) {
    std::array<std::uint8_t, CC_SHA512_DIGEST_LENGTH> digest{};
    if (CC_SHA512(
            seed.data(), static_cast<CC_LONG>(seed.size()),
            digest.data()) == nullptr) {
        return false;
    }
    digest[0] &= 248u;
    digest[31] &= 63u;
    digest[31] |= 64u;
    ge_p3 point{};
    ge_scalarmult_base(&point, digest.data());
    ge_p3_tobytes(public_key.data(), &point);
    return true;
}

std::string render_phrase(
    const std::array<std::uint16_t, 25>& words) {
    std::ostringstream result;
    for (std::size_t i = 0u; i < words.size(); ++i) {
        if (i != 0u) result << ' ';
        result << kRecoveryWords_bip39_en[words[i]];
    }
    return result.str();
}

bool metal_ok(metalError_t status, const char* action,
              std::string& error) {
    if (status == metalSuccess) return true;
    error = std::string(action) + ": " + metalGetErrorString(status);
    return false;
}

template <typename T>
bool allocate(T*& pointer, std::size_t bytes,
              const char* action, std::string& error) {
    return metal_ok(
        metalMalloc(reinterpret_cast<void**>(&pointer),
                    std::max<std::size_t>(bytes, 1u)),
        action, error);
}

void release_buffers(DeviceBuffers& buffers) {
    if (buffers.device >= 0) (void)metalSetDevice(buffers.device);
    if (buffers.candidates) metalFree(buffers.candidates);
    if (buffers.derived) metalFree(buffers.derived);
    if (buffers.targets) metalFree(buffers.targets);
    if (buffers.hits) metalFree(buffers.hits);
    if (buffers.hit_count) metalFree(buffers.hit_count);
    buffers = {};
}

bool prepare_buffers(int device,
                     std::uint64_t batch_capacity,
                     std::uint64_t target_capacity,
                     DeviceBuffers& buffers,
                     std::string& error) {
    buffers.device = device;
    if (!metal_ok(metalSetDevice(device), "select Algorand device", error) ||
        !allocate(
            buffers.candidates,
            static_cast<std::size_t>(batch_capacity) *
                sizeof(GpuCandidate),
            "allocate Algorand candidates", error) ||
        !allocate(
            buffers.derived,
            static_cast<std::size_t>(batch_capacity) *
                sizeof(GpuDerived),
            "allocate Algorand derived keys", error) ||
        !allocate(
            buffers.targets,
            static_cast<std::size_t>(target_capacity) *
                sizeof(GpuTarget),
            "allocate Algorand target tile", error) ||
        !allocate(
            buffers.hits,
            static_cast<std::size_t>(kHitCapacity) * sizeof(GpuHit),
            "allocate Algorand hits", error) ||
        !allocate(
            buffers.hit_count, sizeof(std::uint32_t),
            "allocate Algorand hit count", error)) {
        release_buffers(buffers);
        return false;
    }
    buffers.batch_capacity = batch_capacity;
    buffers.target_capacity = target_capacity;
    buffers.allocated =
        batch_capacity * (sizeof(GpuCandidate) + sizeof(GpuDerived)) +
        target_capacity * sizeof(GpuTarget) +
        static_cast<std::uint64_t>(kHitCapacity) * sizeof(GpuHit) +
        sizeof(std::uint32_t);
    return true;
}

bool launch_derive(DeviceBuffers& buffers,
                   const std::vector<GpuCandidate>& candidates,
                   std::string& error) {
    const std::uint64_t count = candidates.size();
    const std::uint32_t grid = static_cast<std::uint32_t>(
        (count + kThreadgroupSize - 1u) / kThreadgroupSize *
        kThreadgroupSize);
    return metal_ok(
               metalSetDevice(buffers.device),
               "select Algorand device", error) &&
        metal_ok(
            metalMemcpy(
                buffers.candidates, candidates.data(),
                candidates.size() * sizeof(GpuCandidate),
                metalMemcpyHostToDevice),
            "upload Algorand candidates", error) &&
        metal_ok(
            metal_launch(
                "workerAlgorandDerive", grid, kThreadgroupSize,
                buffers.candidates, count, buffers.derived),
            "launch Algorand derive", error) &&
        metal_ok(
            metalDeviceSynchronize(),
            "synchronize Algorand derive", error);
}

bool launch_lookup(DeviceBuffers& buffers,
                   const GpuTarget* targets,
                   std::uint32_t target_count,
                   std::uint64_t candidate_count,
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
            "upload Algorand target tile", error) ||
        !metal_ok(
            metalMemset(
                buffers.hit_count, 0, sizeof(std::uint32_t)),
            "reset Algorand hit count", error)) {
        return false;
    }
    const std::uint32_t grid = static_cast<std::uint32_t>(
        (candidate_count + kThreadgroupSize - 1u) /
        kThreadgroupSize * kThreadgroupSize);
    if (!metal_ok(
            metal_launch(
                "workerAlgorandLookup", grid, kThreadgroupSize,
                buffers.candidates, buffers.derived, candidate_count,
                buffers.targets, target_count, buffers.hits,
                buffers.hit_count, kHitCapacity),
            "launch Algorand lookup", error) ||
        !metal_ok(
            metalDeviceSynchronize(),
            "synchronize Algorand lookup", error)) {
        return false;
    }
    const auto started = std::chrono::steady_clock::now();
    raw_count = 0u;
    if (!metal_ok(
            metalMemcpy(
                &raw_count, buffers.hit_count, sizeof(raw_count),
                metalMemcpyDeviceToHost),
            "read Algorand hit count", error)) {
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
            "read Algorand hits", error)) {
        return false;
    }
    readback_ns = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - started).count());
    return true;
}

bool launch_fused(DeviceBuffers& buffers,
                  const std::vector<GpuCandidate>& candidates,
                  const GpuTarget* targets,
                  std::uint32_t target_count,
                  std::vector<GpuHit>& hits,
                  std::uint32_t& raw_count,
                  std::uint64_t& readback_ns,
                  std::string& error) {
    const std::uint64_t candidate_count = candidates.size();
    if (!metal_ok(
            metalSetDevice(buffers.device),
            "select Algorand device", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.candidates, candidates.data(),
                candidates.size() * sizeof(GpuCandidate),
                metalMemcpyHostToDevice),
            "upload Algorand candidates", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.targets, targets,
                static_cast<std::size_t>(target_count) *
                    sizeof(GpuTarget),
                metalMemcpyHostToDevice),
            "upload Algorand target tile", error) ||
        !metal_ok(
            metalMemset(
                buffers.hit_count, 0, sizeof(std::uint32_t)),
            "reset Algorand hit count", error)) {
        return false;
    }
    const std::uint32_t grid = static_cast<std::uint32_t>(
        (candidate_count + kThreadgroupSize - 1u) /
        kThreadgroupSize * kThreadgroupSize);
    if (!metal_ok(
            metal_launch(
                "workerAlgorandFused", grid, kThreadgroupSize,
                buffers.candidates, candidate_count,
                buffers.targets, target_count, buffers.hits,
                buffers.hit_count, kHitCapacity),
            "launch fused Algorand pipeline", error) ||
        !metal_ok(
            metalDeviceSynchronize(),
            "synchronize fused Algorand pipeline", error)) {
        return false;
    }
    const auto started = std::chrono::steady_clock::now();
    raw_count = 0u;
    if (!metal_ok(
            metalMemcpy(
                &raw_count, buffers.hit_count, sizeof(raw_count),
                metalMemcpyDeviceToHost),
            "read Algorand hit count", error)) {
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
            "read Algorand hits", error)) {
        return false;
    }
    readback_ns = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - started).count());
    return true;
}

std::uint64_t bounded_count(const modeinfra::U256& remaining,
                            std::uint64_t maximum) {
    if (remaining.limbs[1] != 0u ||
        remaining.limbs[2] != 0u ||
        remaining.limbs[3] != 0u) {
        return maximum;
    }
    return std::min(remaining.limbs[0], maximum);
}

std::uint64_t bounded_count_to_full(
    const modeinfra::U256& cursor,
    std::uint64_t maximum) {
    const std::uint64_t max =
        std::numeric_limits<std::uint64_t>::max();
    if (cursor.limbs[1] != max ||
        cursor.limbs[2] != max ||
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

std::uint64_t saturating_add(std::uint64_t left,
                             std::uint64_t right) {
    return std::numeric_limits<std::uint64_t>::max() - left < right
        ? std::numeric_limits<std::uint64_t>::max()
        : left + right;
}

} // namespace

bool requested(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (argv[i] != nullptr &&
            std::strcmp(argv[i], "-algorand") == 0) {
            return true;
        }
    }
    return false;
}

void print_help() {
    std::cout << R"HELP([!] MAIN MODE: -algorand  (Algorand 25-word recovery)
[!] ======================================================================
[!] Purpose:
[!] Recover standard Algorand 25-word English mnemonics and verify the
[!] resulting Ed25519 public key against one or many addresses.
[!]
[!] Inputs:
[!] -i PHRASE_OR_FILE               Repeatable mnemonic/template input.
[!] A standalone ? or * is one unknown whole word. Files use one template
[!] per line; empty lines and # comments are ignored.
[!] -target ADDRESS|PUBLIC_HEX|FILE Repeatable 58-character Algorand address,
[!]                                 64-hex public key, or target file.
[!] Duplicate targets are derived once while source occurrences are retained.
[!]
[!] Search:
[!] -scramble                       Search unique permutations of 25 known
[!]                                 words with multiset rank/unrank.
[!] -start N / -end N               Checked U256 ordinal slice for every
[!]                                 template; decimal, 0xHEX, and the exact
[!]                                 -end 2^256 sentinel are accepted.
[!] Word 24 zero-padding and word 25 SHA-512/256 checksum are rejected before
[!] the expensive Ed25519 derivation.
[!]
[!] GPU / memory / MultiGPU:
[!] -wallet-mem auto|all|NN%|SIZE   Hard unified-memory working-set budget.
[!] -n N                            Optional candidate batch cap.
[!] -device LIST                    Deterministic non-overlapping devices.
[!] Candidate derivation is reused while massive target sets stream in tiles.
[!]
[!] Statistics:
[!] SpeedThreadFunc is the only live statistics printer and reports
[!] Candidate/s plus primitive/Verify rates after Metal completion/readback.
[!] Target count is never used as an artificial speed multiplier.
[!]
[!] Output:
[!] ALGORAND_FOUND TARGET:<source> TEMPLATE:<source> ADDRESS:<address>
[!] MNEMONIC:<25 words> SEED:<64hex> PUBLIC:<64hex>
[!] Every hit is independently checksum- and Ed25519-verified on the host.
[!]
[!] Examples:
[!] ./METAL_CRYPTO_TOOLKIT -algorand -i "abandon ... ?" \
[!]   -target ADDRESS -wallet-mem auto -save
[!] ./METAL_CRYPTO_TOOLKIT -algorand -i words.txt -scramble \
[!]   -target targets.txt -start 0 -end 1000000 -wallet-mem all -device 0
[!]
[!] Limitations:
[!] English 25-word Algorand mnemonics only. Search size remains exponential
[!] in unknown words and factorial in scramble mode. No-match completion is
[!] success; malformed CLI/input or runtime failures return nonzero.
)HELP";
}

int run(int argc, char** argv, const RuntimeHooks& hooks) {
    Options options;
    std::string error;
    if (!parse_options(argc, argv, options, error)) {
        std::cerr << "[!] Algorand CLI error: " << error << " [!]\n";
        return 2;
    }

    std::vector<Target> targets;
    std::uint64_t logical_targets = 0u;
    if (!load_targets(options, targets, logical_targets, error)) {
        std::cerr << "[!] Algorand target error: " << error << " [!]\n";
        return 2;
    }
    std::vector<SeedTemplate> templates;
    if (!load_templates(options, templates, error)) {
        std::cerr << "[!] Algorand template error: " << error << " [!]\n";
        return 2;
    }

    modeinfra::U256 configured_start{};
    if (!options.start_text.empty() &&
        !modeinfra::parse_u256(
            options.start_text, configured_start, error)) {
        std::cerr << "[!] Algorand CLI error: invalid -start: "
                  << error << " [!]\n";
        return 2;
    }
    modeinfra::U256 configured_end{};
    const bool has_end = !options.end_text.empty();
    const bool configured_full_end =
        has_end && is_full_u256_text(options.end_text);
    if (has_end && !configured_full_end &&
        !modeinfra::parse_u256(
            options.end_text, configured_end, error)) {
        std::cerr << "[!] Algorand CLI error: invalid -end: "
                  << error << " [!]\n";
        return 2;
    }
    for (const SeedTemplate& seed : templates) {
        const bool full_end =
            has_end ? configured_full_end : seed.full_u256_domain;
        const modeinfra::U256 end =
            has_end ? configured_end : seed.domain_size;
        const bool invalid_full =
            full_end && !seed.full_u256_domain;
        const bool invalid_finite =
            !full_end &&
            (modeinfra::compare(configured_start, end) >= 0 ||
             (!seed.full_u256_domain &&
              modeinfra::compare(end, seed.domain_size) > 0));
        if (invalid_full || invalid_finite) {
            std::cerr << "[!] Algorand CLI error: ordinal slice is outside "
                      << seed.source << " domain [!]\n";
            return 2;
        }
    }

    int device_count = 0;
    if (!metal_ok(
            metalGetDeviceCount(&device_count),
            "query Algorand devices", error)) {
        std::cerr << "[!] Algorand runtime error: " << error << " [!]\n";
        return 1;
    }
    std::vector<modeinfra::MemoryDeviceInfo> memory_devices;
    for (int device : options.devices) {
        if (device < 0 || device >= device_count) {
            std::cerr << "[!] Algorand CLI error: device " << device
                      << " is unavailable [!]\n";
            return 2;
        }
        metalDeviceProp properties{};
        if (!metal_ok(
                metalGetDeviceProperties(&properties, device),
                "query Algorand device", error)) {
            std::cerr << "[!] Algorand runtime error: "
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
        std::cerr << "[!] Algorand CLI error: " << error << " [!]\n";
        return 2;
    }
    const std::uint64_t mandatory =
        static_cast<std::uint64_t>(kHitCapacity) * sizeof(GpuHit) +
        sizeof(GpuCandidate) + sizeof(GpuDerived) + sizeof(GpuTarget) +
        sizeof(std::uint32_t);
    modeinfra::MemoryBudget budget;
    if (!modeinfra::resolve_memory_budget(
            memory_spec, memory_devices, mandatory, 0u,
            budget, error, kRuntimeReserve)) {
        std::cerr << "[!] Algorand memory error: " << error << " [!]\n";
        return 1;
    }

    const std::uint64_t hit_bytes =
        static_cast<std::uint64_t>(kHitCapacity) * sizeof(GpuHit) +
        sizeof(std::uint32_t);
    const std::uint64_t candidate_pair_bytes =
        sizeof(GpuCandidate) + sizeof(GpuDerived);
    const std::uint64_t variable_budget =
        budget.per_device_budget - hit_bytes - candidate_pair_bytes;
    const std::uint64_t target_bytes = std::min<std::uint64_t>(
        budget.per_device_budget / 3u, variable_budget / 2u);
    std::uint64_t target_capacity = std::max<std::uint64_t>(
        1u, std::min<std::uint64_t>(
            targets.size(),
            std::min<std::uint64_t>(
                std::numeric_limits<std::uint32_t>::max(),
                target_bytes / sizeof(GpuTarget))));
    const std::uint64_t fixed =
        static_cast<std::uint64_t>(kHitCapacity) * sizeof(GpuHit) +
        target_capacity * sizeof(GpuTarget) + sizeof(std::uint32_t);
    if (fixed >= budget.per_device_budget) {
        std::cerr << "[!] Algorand memory error: target/hit buffers exceed "
                  << "the selected budget [!]\n";
        return 1;
    }
    std::uint64_t batch_capacity =
        (budget.per_device_budget - fixed) /
        (sizeof(GpuCandidate) + sizeof(GpuDerived));
    batch_capacity = std::max<std::uint64_t>(1u, batch_capacity);
    batch_capacity = std::min(batch_capacity, kMaximumBatch);
    if (options.batch_explicit) {
        batch_capacity = std::min(batch_capacity, options.batch);
    } else {
        batch_capacity = std::min<std::uint64_t>(
            batch_capacity,
            memory_spec.kind == modeinfra::MemoryKind::All
                ? kMaximumBatch : kDefaultBatch);
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
        for (DeviceBuffers& buffers : devices) release_buffers(buffers);
        if (memory_spec.kind != modeinfra::MemoryKind::Auto ||
            (batch_capacity == 1u && target_capacity == 1u)) {
            std::cerr << "[!] Algorand allocation error: "
                      << error << " [!]\n";
            return 1;
        }
        if (batch_capacity > 1u) batch_capacity /= 2u;
        else target_capacity = std::max<std::uint64_t>(
            1u, target_capacity / 2u);
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
        target.public_key = targets[i].public_key;
        target.prefix = target_prefix(target.public_key);
        target.source_index = i;
        gpu_targets.push_back(target);
    }
    std::sort(
        gpu_targets.begin(), gpu_targets.end(),
        [](const GpuTarget& left, const GpuTarget& right) {
            if (left.prefix != right.prefix) {
                return left.prefix < right.prefix;
            }
            return left.public_key < right.public_key;
        });

    bool use_fused = gpu_targets.size() <= target_capacity;
    if (const char* override_value =
            std::getenv("METAL_ALGORAND_PIPELINE")) {
        const std::string pipeline = trim_copy(override_value);
        if (pipeline == "split") {
            use_fused = false;
        } else if (pipeline == "fused") {
            if (gpu_targets.size() > target_capacity) {
                for (auto& buffers : devices) release_buffers(buffers);
                std::cerr << "[!] Algorand runtime error: forced fused "
                          << "pipeline cannot hold all targets [!]\n";
                return 1;
            }
            use_fused = true;
        } else if (!pipeline.empty() && pipeline != "auto") {
            for (auto& buffers : devices) release_buffers(buffers);
            std::cerr << "[!] Algorand runtime error: "
                      << "METAL_ALGORAND_PIPELINE expects "
                      << "auto, fused, or split [!]\n";
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
            std::cerr << "[!] Algorand runtime error: cannot open '"
                      << path << "' [!]\n";
            return 1;
        }
    }

    std::cout << "[!] Algorand templates: " << templates.size()
              << " | targets: " << targets.size() << " unique/"
              << logical_targets << " logical | devices: "
              << devices.size() << " | batch: " << batch_capacity
              << " | target tile: " << target_capacity
              << " | pipeline: " << (use_fused ? "fused" : "split")
              << " | working set: " << allocated_bytes << " bytes [!]\n";

    modeinfra::ModeProgress& progress =
        modeinfra::global_mode_progress();
    progress.begin(
        "ALGORAND", modeinfra::ProgressUnit::Candidate,
        modeinfra::ProgressPhase::Search);
    progress.set_targets(
        logical_targets,
        std::min<std::uint64_t>(targets.size(), target_capacity), 0u);
    progress.set_allocated_working_set(allocated_bytes);

    std::uint64_t solved_logical = 0u;
    std::uint64_t founds = 0u;
    std::size_t device_slot = 0u;
    int result = 0;
    for (std::size_t template_index = 0u;
         template_index < templates.size() &&
         solved_logical < logical_targets; ++template_index) {
        const SeedTemplate& seed_template = templates[template_index];
        modeinfra::U256 cursor = configured_start;
        const bool full_end =
            has_end ? configured_full_end :
            seed_template.full_u256_domain;
        const modeinfra::U256 end =
            has_end ? configured_end : seed_template.domain_size;
        bool full_done = false;
        while ((full_end ? !full_done :
                modeinfra::compare(cursor, end) < 0) &&
               solved_logical < logical_targets) {
            std::uint64_t count = 0u;
            if (full_end) {
                count = bounded_count_to_full(
                    cursor, batch_capacity);
            } else {
                modeinfra::U256 remaining{};
                if (!modeinfra::subtract_checked(
                        end, cursor, remaining)) {
                    error = "Algorand scheduler underflow";
                    result = 1;
                    break;
                }
                count = bounded_count(remaining, batch_capacity);
            }
            if (count == 0u) {
                error = "Algorand scheduler produced an empty window";
                result = 1;
                break;
            }
            bool completed = false;
            while (!completed) {
                std::vector<GpuCandidate> candidates(
                    static_cast<std::size_t>(count));
                for (std::uint64_t i = 0u; i < count; ++i) {
                    modeinfra::U256 ordinal{};
                    if (!modeinfra::add_checked(
                            cursor, modeinfra::U256::from_u64(i),
                            ordinal) ||
                        !make_candidate(
                            seed_template, template_index, ordinal,
                            candidates[static_cast<std::size_t>(i)],
                            error)) {
                        result = 1;
                        break;
                    }
                }
                if (result != 0) break;
                DeviceBuffers& buffers = devices[device_slot];

                std::vector<GpuHit> resolved_hits;
                std::uint64_t readback_ns = 0u;
                bool retry = false;
                if (use_fused) {
                    std::uint32_t raw_count = 0u;
                    if (!launch_fused(
                            buffers, candidates, gpu_targets.data(),
                            static_cast<std::uint32_t>(
                                gpu_targets.size()),
                            resolved_hits, raw_count, readback_ns,
                            error)) {
                        result = 1;
                    } else if (raw_count > kHitCapacity) {
                        retry = true;
                    }
                } else {
                    if (!launch_derive(buffers, candidates, error)) {
                        result = 1;
                    }
                    for (std::size_t tile = 0u;
                         result == 0 && tile < gpu_targets.size();
                         tile += static_cast<std::size_t>(
                             target_capacity)) {
                        const std::uint32_t tile_count =
                            static_cast<std::uint32_t>(
                                std::min<std::size_t>(
                                    target_capacity,
                                    gpu_targets.size() - tile));
                        std::vector<GpuHit> tile_hits;
                        std::uint32_t raw_count = 0u;
                        std::uint64_t tile_readback = 0u;
                        if (!launch_lookup(
                                buffers, gpu_targets.data() + tile,
                                tile_count, count, tile_hits,
                                raw_count, tile_readback, error)) {
                            result = 1;
                            break;
                        }
                        readback_ns =
                            saturating_add(readback_ns, tile_readback);
                        if (raw_count > kHitCapacity) {
                            retry = true;
                            break;
                        }
                        resolved_hits.insert(
                            resolved_hits.end(),
                            tile_hits.begin(), tile_hits.end());
                    }
                }
                if (result != 0) break;
                if (retry) {
                    if (count == 1u) {
                        error = "Algorand hit buffer overflows for one candidate";
                        result = 1;
                        break;
                    }
                    count = std::max<std::uint64_t>(1u, count / 2u);
                    continue;
                }

                std::uint64_t exact = 0u;
                for (const GpuHit& hit : resolved_hits) {
                    ++exact;
                    if (hit.template_index >= templates.size() ||
                        hit.target_index >= targets.size()) {
                        error = "Algorand GPU hit has an invalid index";
                        result = 1;
                        break;
                    }
                    modeinfra::U256 ordinal{};
                    ordinal.limbs = hit.ordinal;
                    std::array<std::uint16_t, 25> words{};
                    if (!make_words(
                            templates[hit.template_index],
                            ordinal, words, error)) {
                        result = 1;
                        break;
                    }
                    std::array<std::uint8_t, 32> seed{};
                    if (!pack_seed(words, seed)) {
                        error = "Algorand GPU hit failed host padding verification";
                        result = 1;
                        break;
                    }
                    const std::uint16_t expected_checksum =
                        checksum_word(seed);
                    if (words[24] != kUnknownWord &&
                        words[24] != expected_checksum) {
                        error = "Algorand GPU hit failed host checksum verification";
                        result = 1;
                        break;
                    }
                    words[24] = expected_checksum;
                    std::array<std::uint8_t, 32> public_key{};
                    if (!host_public_key(seed, public_key) ||
                        public_key != hit.public_key ||
                        expected_checksum != hit.checksum_word) {
                        error = "Algorand GPU hit failed independent host Ed25519 derivation";
                        result = 1;
                        break;
                    }
                    Target& target = targets[hit.target_index];
                    if (target.public_key != public_key) {
                        error = "Algorand GPU hit resolved to the wrong target";
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
                        "[+] ALGORAND_FOUND TARGET:" + sources +
                        " TEMPLATE:" +
                        templates[hit.template_index].source +
                        " ADDRESS:" + encode_address(public_key) +
                        " MNEMONIC:" + render_phrase(words) +
                        " SEED:" +
                        hex_lower(seed.data(), seed.size()) +
                        " PUBLIC:" +
                        hex_lower(public_key.data(), public_key.size());
                    if (!options.silent) std::cout << line << '\n';
                    if (output) {
                        output << line << '\n';
                        output.flush();
                    }
                }
                if (result != 0) break;
                progress.credit_completed(count, count * 2u, exact, readback_ns);
                progress.set_targets(
                    logical_targets,
                    std::min<std::uint64_t>(
                        targets.size(), target_capacity),
                    solved_logical);
                progress.set_founds(founds);
                if (hooks.add_completed) hooks.add_completed(count);
                modeinfra::U256 next{};
                if (!modeinfra::add_checked(
                        cursor, modeinfra::U256::from_u64(count),
                        next)) {
                    if (full_end) {
                        full_done = true;
                    } else {
                        error = "Algorand scheduler overflow";
                        result = 1;
                        break;
                    }
                } else {
                    cursor = next;
                }
                device_slot = (device_slot + 1u) % devices.size();
                completed = true;
            }
            if (result != 0) break;
        }
        if (result != 0) break;
    }

    progress.end();
    for (DeviceBuffers& buffers : devices) release_buffers(buffers);
    if (result != 0) {
        std::cerr << "[!] Algorand runtime error: " << error << " [!]\n";
        return result;
    }
    std::cout << "[!] Algorand search complete: solved "
              << solved_logical << '/' << logical_targets
              << " logical targets [!]\n";
    return 0;
}

} // namespace algorand_mode
