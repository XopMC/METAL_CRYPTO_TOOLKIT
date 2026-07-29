#include "ChiaMode.h"

#include "../MetalBackend.h"
#include "../RecoveryWordlistsEmbedded.h"
#include "../bls12_381/Bls12381.h"
#include "../lib/hash/sha256.h"

#include <CoreFoundation/CoreFoundation.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <mutex>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace chia_mode {
namespace {

constexpr std::uint32_t kThreadgroupSize = 256u;
constexpr std::uint64_t kMaximumBatch = 16384u;
constexpr std::uint64_t kMnemonicStride = 256u;
constexpr std::uint64_t kSaltStride = 256u;
constexpr std::uint64_t kRuntimeReserve =
    512ull * 1024ull * 1024ull;
constexpr std::uint64_t kIndexLimit =
    1ull << 32u;

using Hash32 = std::array<std::uint8_t, 32>;
using Seed64 = std::array<std::uint8_t, 64>;

struct Options {
    std::vector<std::string> mnemonic_inputs;
    std::vector<std::string> seed_inputs;
    std::vector<std::string> passphrase_inputs;
    std::vector<std::string> target_inputs;
    std::vector<std::string> path_templates;
    std::string memory = "auto";
    std::string output_path;
    std::vector<int> devices{0};
    std::uint64_t batch = kMaximumBatch;
    std::uint64_t index_begin = 0u;
    std::uint64_t index_end = 1u;
    bool index_begin_set = false;
    bool index_end_set = false;
    bool save = false;
    bool silent = false;
};

struct TextCandidate {
    std::string text;
    std::string source;
};

enum class TargetKind : std::uint8_t {
    PublicKey = 1u,
    PuzzleHash = 2u,
};

struct Target {
    TargetKind kind = TargetKind::PublicKey;
    std::array<std::uint8_t, 48> value{};
    std::vector<std::string> origins;
    bool solved = false;
};

struct PathComponent {
    std::uint32_t value = 0u;
    bool hardened = true;
    bool variable = false;
};

struct PathPlan {
    std::string name;
    std::vector<PathComponent> components;
    std::uint64_t variable_offset = 0u;
    bool variable = false;
};

struct DeviceBuffers {
    int device = -1;
    char* mnemonics = nullptr;
    std::uint16_t* mnemonic_lengths = nullptr;
    std::uint8_t* salts = nullptr;
    std::uint16_t* salt_lengths = nullptr;
    std::uint8_t* seeds = nullptr;
    std::uint64_t capacity = 0u;
    std::uint64_t allocated = 0u;
};

std::string trim_copy(std::string value) {
    const std::size_t first =
        value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const std::size_t last =
        value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1u);
}

std::string lower_copy(std::string value) {
    std::transform(
        value.begin(), value.end(), value.begin(),
        [](unsigned char character) {
            return static_cast<char>(
                std::tolower(character));
        });
    return value;
}

bool parse_u64(const std::string& raw,
               std::uint64_t& value) {
    try {
        std::size_t consumed = 0u;
        value = std::stoull(raw, &consumed, 0);
        return consumed == raw.size();
    } catch (...) {
        return false;
    }
}

bool parse_devices(const std::string& raw,
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
        for (std::uint64_t value = first;
             value <= last; ++value) {
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

bool parse_options(int argc, char** argv,
                   Options& options,
                   std::string& error) {
    bool mode_seen = false;
    for (int index = 1; index < argc; ++index) {
        const std::string argument = argv[index];
        if (argument == "-chia") {
            mode_seen = true;
            continue;
        }
        const auto take = [&](const char* flag)
            -> const char* {
            if (index + 1 >= argc) {
                error = std::string(flag) +
                    " requires a value";
                return nullptr;
            }
            return argv[++index];
        };
        if (argument == "-i" ||
            argument == "-mnemonic") {
            const char* value = take(argument.c_str());
            if (value == nullptr) return false;
            options.mnemonic_inputs.emplace_back(value);
        } else if (argument == "-seed") {
            const char* value = take("-seed");
            if (value == nullptr) return false;
            options.seed_inputs.emplace_back(value);
        } else if (argument == "-pass" ||
                   argument == "-passphrase") {
            const char* value = take(argument.c_str());
            if (value == nullptr) return false;
            options.passphrase_inputs.emplace_back(value);
        } else if (argument == "-target") {
            const char* value = take("-target");
            if (value == nullptr) return false;
            options.target_inputs.emplace_back(value);
        } else if (argument == "-path-template" ||
                   argument == "-path") {
            const char* value = take(argument.c_str());
            if (value == nullptr) return false;
            options.path_templates.emplace_back(value);
        } else if (argument == "-wallet-mem") {
            const char* value = take("-wallet-mem");
            if (value == nullptr) return false;
            options.memory = value;
        } else if (argument == "-device") {
            const char* value = take("-device");
            if (value == nullptr ||
                !parse_devices(value, options.devices, error)) {
                return false;
            }
        } else if (argument == "-n") {
            const char* value = take("-n");
            if (value == nullptr ||
                !parse_u64(value, options.batch) ||
                options.batch == 0u ||
                options.batch > kMaximumBatch) {
                error = "-n must be in 1..16384";
                return false;
            }
        } else if (argument == "-start") {
            const char* value = take("-start");
            if (value == nullptr ||
                !parse_u64(value, options.index_begin) ||
                options.index_begin >= kIndexLimit) {
                error = "-start must be a uint32 index";
                return false;
            }
            options.index_begin_set = true;
        } else if (argument == "-end") {
            const char* value = take("-end");
            if (value == nullptr ||
                !parse_u64(value, options.index_end) ||
                options.index_end > kIndexLimit) {
                error = "-end must be in 1..2^32";
                return false;
            }
            options.index_end_set = true;
        } else if (argument == "-o") {
            const char* value = take("-o");
            if (value == nullptr) return false;
            options.output_path = value;
            options.save = true;
        } else if (argument == "-save") {
            options.save = true;
        } else if (argument == "-silent") {
            options.silent = true;
        } else if (argument == "-help" ||
                   argument == "--help") {
            continue;
        } else if (mode_seen && !argument.empty() &&
                   argument.front() != '-') {
            options.mnemonic_inputs.push_back(argument);
        } else {
            error = "unsupported option '" + argument + "'";
            return false;
        }
    }
    if (!mode_seen) {
        error = "-chia was not selected";
        return false;
    }
    if (options.target_inputs.empty()) {
        error = "at least one -target is required";
        return false;
    }
    if (options.mnemonic_inputs.empty() &&
        options.seed_inputs.empty()) {
        error = "provide -i/-mnemonic or -seed";
        return false;
    }
    if (!options.passphrase_inputs.empty() &&
        options.mnemonic_inputs.empty()) {
        error = "BIP39 passphrases require mnemonic input";
        return false;
    }
    if (options.index_begin_set != options.index_end_set) {
        error = "-start and -end must be specified together";
        return false;
    }
    if (options.index_begin >= options.index_end) {
        error = "-start must be lower than -end";
        return false;
    }
    if (options.path_templates.empty()) {
        options.path_templates.push_back("wallet-observer");
    }
    return true;
}

int hex_digit(char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') {
        return value - 'a' + 10;
    }
    if (value >= 'A' && value <= 'F') {
        return value - 'A' + 10;
    }
    return -1;
}

bool decode_hex(const std::string& raw,
                std::vector<std::uint8_t>& output) {
    std::string value = trim_copy(raw);
    if (value.size() >= 2u && value[0] == '0' &&
        (value[1] == 'x' || value[1] == 'X')) {
        value.erase(0u, 2u);
    }
    if (value.empty() || (value.size() & 1u) != 0u) {
        return false;
    }
    output.resize(value.size() / 2u);
    for (std::size_t index = 0u;
         index < output.size(); ++index) {
        const int high = hex_digit(value[index * 2u]);
        const int low = hex_digit(value[index * 2u + 1u]);
        if (high < 0 || low < 0) return false;
        output[index] = static_cast<std::uint8_t>(
            (high << 4u) | low);
    }
    return true;
}

std::string hex_string(const std::uint8_t* bytes,
                       std::size_t size) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::size_t index = 0u; index < size; ++index) {
        output << std::setw(2)
               << static_cast<unsigned>(bytes[index]);
    }
    return output.str();
}

bool load_lines_or_literal(
    const std::vector<std::string>& inputs,
    bool preserve_empty,
    std::vector<TextCandidate>& output,
    std::string& error) {
    for (const std::string& value : inputs) {
        std::error_code filesystem_error;
        if (std::filesystem::is_regular_file(
                value, filesystem_error) &&
            !filesystem_error) {
            std::ifstream input(value);
            if (!input) {
                error = "cannot open '" + value + "'";
                return false;
            }
            std::string line;
            std::size_t number = 0u;
            while (std::getline(input, line)) {
                ++number;
                if (!line.empty() && line.back() == '\r') {
                    line.pop_back();
                }
                if (!line.empty() && line.front() == '#') {
                    continue;
                }
                if (!preserve_empty) {
                    const std::size_t comment = line.find('#');
                    if (comment != std::string::npos) {
                        line.erase(comment);
                    }
                    line = trim_copy(line);
                }
                if (!line.empty() || preserve_empty) {
                    output.push_back({
                        line, value + ":" +
                            std::to_string(number)});
                }
            }
        } else {
            output.push_back({value, "argv"});
        }
    }
    return true;
}

bool normalize_nfkd(const std::string& input,
                    std::string& output,
                    std::string& error) {
    CFStringRef original = CFStringCreateWithBytes(
        kCFAllocatorDefault,
        reinterpret_cast<const UInt8*>(input.data()),
        static_cast<CFIndex>(input.size()),
        kCFStringEncodingUTF8, false);
    if (original == nullptr) {
        error = "input is not valid UTF-8";
        return false;
    }
    CFMutableStringRef normalized =
        CFStringCreateMutableCopy(
            kCFAllocatorDefault, 0, original);
    CFRelease(original);
    if (normalized == nullptr) {
        error = "cannot allocate normalized string";
        return false;
    }
    CFStringNormalize(
        normalized, kCFStringNormalizationFormKD);
    const CFIndex count = CFStringGetLength(normalized);
    const CFIndex capacity =
        CFStringGetMaximumSizeForEncoding(
            count, kCFStringEncodingUTF8) + 1;
    std::vector<char> buffer(
        static_cast<std::size_t>(capacity));
    const bool converted = CFStringGetCString(
        normalized, buffer.data(), capacity,
        kCFStringEncodingUTF8);
    CFRelease(normalized);
    if (!converted) {
        error = "cannot encode normalized UTF-8";
        return false;
    }
    output.assign(buffer.data());
    return true;
}

std::vector<std::string> split_words(
    const std::string& phrase) {
    std::istringstream input(phrase);
    std::vector<std::string> words;
    std::string word;
    while (input >> word) words.push_back(word);
    return words;
}

const std::unordered_map<std::string, std::uint16_t>&
bip39_index() {
    static const auto result = [] {
        std::unordered_map<std::string, std::uint16_t> index;
        index.reserve(2048u);
        for (std::uint16_t value = 0u;
             value < 2048u; ++value) {
            index.emplace(
                kRecoveryWords_bip39_en[value], value);
        }
        return index;
    }();
    return result;
}

bool valid_bip39(const std::string& phrase) {
    const std::vector<std::string> words =
        split_words(phrase);
    if (words.size() != 12u && words.size() != 15u &&
        words.size() != 18u && words.size() != 21u &&
        words.size() != 24u) {
        return false;
    }
    const std::size_t total_bits = words.size() * 11u;
    const std::size_t entropy_bits =
        total_bits * 32u / 33u;
    const std::size_t checksum_bits =
        total_bits - entropy_bits;
    std::vector<std::uint8_t> bits(total_bits, 0u);
    std::size_t bit = 0u;
    for (const std::string& word : words) {
        const auto found = bip39_index().find(word);
        if (found == bip39_index().end()) return false;
        for (int shift = 10; shift >= 0; --shift) {
            bits[bit++] = static_cast<std::uint8_t>(
                (found->second >> shift) & 1u);
        }
    }
    std::vector<std::uint8_t> entropy(
        entropy_bits / 8u, 0u);
    for (std::size_t index = 0u;
         index < entropy_bits; ++index) {
        entropy[index >> 3u] |=
            static_cast<std::uint8_t>(
                bits[index] <<
                (7u - (index & 7u)));
    }
    Hash32 digest{};
    sha256(
        entropy.data(), entropy.size(), digest.data());
    for (std::size_t index = 0u;
         index < checksum_bits; ++index) {
        if (bits[entropy_bits + index] !=
            ((digest[index >> 3u] >>
              (7u - (index & 7u))) & 1u)) {
            return false;
        }
    }
    return true;
}

bool load_mnemonics(
    const Options& options,
    std::vector<TextCandidate>& mnemonics,
    std::string& error) {
    std::vector<TextCandidate> raw;
    if (!load_lines_or_literal(
            options.mnemonic_inputs, false, raw, error)) {
        return false;
    }
    std::unordered_set<std::string> unique;
    for (const TextCandidate& item : raw) {
        std::string normalized;
        if (!normalize_nfkd(
                item.text, normalized, error)) {
            error = item.source + ": " + error;
            return false;
        }
        normalized = trim_copy(normalized);
        if (normalized.size() >= kMnemonicStride) {
            error = item.source +
                ": mnemonic exceeds 255 UTF-8 bytes";
            return false;
        }
        if (!valid_bip39(normalized)) continue;
        if (unique.insert(normalized).second) {
            mnemonics.push_back({
                normalized, item.source});
        }
    }
    if (!options.mnemonic_inputs.empty() &&
        mnemonics.empty()) {
        error = "no checksum-valid English BIP39 mnemonics";
        return false;
    }
    return true;
}

bool load_passphrases(
    const Options& options,
    std::vector<TextCandidate>& passphrases,
    std::string& error) {
    std::vector<TextCandidate> raw;
    if (options.passphrase_inputs.empty()) {
        raw.push_back({"", "default-empty"});
    } else if (!load_lines_or_literal(
                   options.passphrase_inputs, true,
                   raw, error)) {
        return false;
    }
    std::unordered_set<std::string> unique;
    for (const TextCandidate& item : raw) {
        std::string normalized;
        if (!normalize_nfkd(
                item.text, normalized, error)) {
            error = item.source + ": " + error;
            return false;
        }
        if (normalized.size() + 8u >= kSaltStride) {
            error = item.source +
                ": normalized passphrase exceeds 247 UTF-8 bytes";
            return false;
        }
        if (unique.insert(normalized).second) {
            passphrases.push_back({
                normalized, item.source});
        }
    }
    if (passphrases.empty()) {
        error = "passphrase source is empty";
        return false;
    }
    return true;
}

bool load_seeds(
    const Options& options,
    std::vector<std::pair<
        std::vector<std::uint8_t>, std::string>>& seeds,
    std::string& error) {
    std::vector<TextCandidate> raw;
    if (!load_lines_or_literal(
            options.seed_inputs, false, raw, error)) {
        return false;
    }
    std::unordered_set<std::string> unique;
    for (const TextCandidate& item : raw) {
        std::vector<std::uint8_t> seed;
        if (!decode_hex(item.text, seed) ||
            seed.size() < 32u || seed.size() > 64u) {
            error = item.source +
                ": seed must be 32..64 bytes of hex";
            return false;
        }
        const std::string identity(
            reinterpret_cast<const char*>(seed.data()),
            seed.size());
        if (unique.insert(identity).second) {
            seeds.push_back({std::move(seed), item.source});
        }
    }
    return true;
}

constexpr std::string_view kBech32Alphabet =
    "qpzry9x8gf2tvdw0s3jn54khce6mua7l";

std::uint32_t bech32_polymod(
    const std::vector<std::uint8_t>& values) {
    constexpr std::uint32_t generators[5] = {
        0x3b6a57b2u, 0x26508e6du, 0x1ea119fau,
        0x3d4233ddu, 0x2a1462b3u,
    };
    std::uint32_t checksum = 1u;
    for (const std::uint8_t value : values) {
        const std::uint32_t top = checksum >> 25u;
        checksum =
            ((checksum & 0x1ffffffu) << 5u) ^ value;
        for (std::uint32_t bit = 0u; bit < 5u; ++bit) {
            if (((top >> bit) & 1u) != 0u) {
                checksum ^= generators[bit];
            }
        }
    }
    return checksum;
}

bool convert_bits(const std::vector<std::uint8_t>& input,
                  unsigned from_bits,
                  unsigned to_bits,
                  bool pad,
                  std::vector<std::uint8_t>& output) {
    std::uint32_t accumulator = 0u;
    unsigned bits = 0u;
    const std::uint32_t maximum =
        (1u << to_bits) - 1u;
    const std::uint32_t maximum_accumulator =
        (1u << (from_bits + to_bits - 1u)) - 1u;
    for (const std::uint8_t value : input) {
        if ((value >> from_bits) != 0u) return false;
        accumulator =
            ((accumulator << from_bits) | value) &
            maximum_accumulator;
        bits += from_bits;
        while (bits >= to_bits) {
            bits -= to_bits;
            output.push_back(static_cast<std::uint8_t>(
                (accumulator >> bits) & maximum));
        }
    }
    if (pad) {
        if (bits != 0u) {
            output.push_back(static_cast<std::uint8_t>(
                (accumulator << (to_bits - bits)) &
                maximum));
        }
    } else if (bits >= from_bits ||
               ((accumulator << (to_bits - bits)) &
                maximum) != 0u) {
        return false;
    }
    return true;
}

bool decode_chia_address(const std::string& raw,
                         Hash32& puzzle_hash) {
    if (raw.size() > 90u || raw.size() < 8u) return false;
    bool lower = false;
    bool upper = false;
    for (const unsigned char character : raw) {
        if (character < 33u || character > 126u) {
            return false;
        }
        lower = lower || std::islower(character);
        upper = upper || std::isupper(character);
    }
    if (lower && upper) return false;
    const std::string value = lower_copy(raw);
    const std::size_t separator = value.rfind('1');
    if (separator == std::string::npos ||
        separator < 1u ||
        separator + 7u > value.size()) {
        return false;
    }
    const std::string human = value.substr(0u, separator);
    if (human != "xch" && human != "txch") return false;
    std::vector<std::uint8_t> data;
    data.reserve(value.size() - separator - 1u);
    for (std::size_t index = separator + 1u;
         index < value.size(); ++index) {
        const std::size_t found =
            kBech32Alphabet.find(value[index]);
        if (found == std::string_view::npos) return false;
        data.push_back(static_cast<std::uint8_t>(found));
    }
    std::vector<std::uint8_t> checksum_values;
    checksum_values.reserve(
        human.size() * 2u + 1u + data.size());
    for (const unsigned char character : human) {
        checksum_values.push_back(character >> 5u);
    }
    checksum_values.push_back(0u);
    for (const unsigned char character : human) {
        checksum_values.push_back(character & 31u);
    }
    checksum_values.insert(
        checksum_values.end(), data.begin(), data.end());
    if (bech32_polymod(checksum_values) !=
        0x2bc830a3u) {
        return false;
    }
    data.resize(data.size() - 6u);
    std::vector<std::uint8_t> decoded;
    if (!convert_bits(data, 5u, 8u, false, decoded) ||
        decoded.size() != puzzle_hash.size()) {
        return false;
    }
    std::copy(
        decoded.begin(), decoded.end(),
        puzzle_hash.begin());
    return true;
}

std::string target_identity(const Target& target) {
    const std::size_t size =
        target.kind == TargetKind::PublicKey ? 48u : 32u;
    std::string result;
    result.reserve(size + 1u);
    result.push_back(
        static_cast<char>(target.kind));
    result.append(
        reinterpret_cast<const char*>(target.value.data()),
        size);
    return result;
}

bool load_targets(const Options& options,
                  std::vector<Target>& targets,
                  std::uint64_t& logical,
                  std::string& error) {
    std::vector<TextCandidate> raw;
    if (!load_lines_or_literal(
            options.target_inputs, false, raw, error)) {
        return false;
    }
    std::unordered_map<std::string, std::size_t> unique;
    for (const TextCandidate& item : raw) {
        std::string token = item.text;
        const std::size_t space =
            token.find_first_of(" \t");
        if (space != std::string::npos) token.erase(space);
        Target target;
        std::vector<std::uint8_t> bytes;
        Hash32 puzzle_hash{};
        if (decode_hex(token, bytes) &&
            bytes.size() == 48u) {
            target.kind = TargetKind::PublicKey;
            std::copy(
                bytes.begin(), bytes.end(),
                target.value.begin());
            bls12_381::PublicKey public_key{};
            std::copy_n(
                target.value.begin(), public_key.size(),
                public_key.begin());
            if (!bls12_381::valid_public_key_compressed(
                    public_key)) {
                error = item.source +
                    ": target is not a valid compressed BLS public key";
                return false;
            }
        } else if (decode_hex(token, bytes) &&
                   bytes.size() == 32u) {
            target.kind = TargetKind::PuzzleHash;
            std::copy(
                bytes.begin(), bytes.end(),
                target.value.begin());
        } else if (decode_chia_address(
                       token, puzzle_hash)) {
            target.kind = TargetKind::PuzzleHash;
            std::copy(
                puzzle_hash.begin(), puzzle_hash.end(),
                target.value.begin());
        } else {
            error = item.source +
                ": target must be a 48-byte BLS public key, "
                "32-byte puzzle hash, or checksum-valid xch/txch address";
            return false;
        }
        const std::string identity =
            target_identity(target);
        const auto found = unique.find(identity);
        if (found == unique.end()) {
            target.origins.push_back(item.source);
            unique.emplace(identity, targets.size());
            targets.push_back(std::move(target));
        } else {
            targets[found->second].origins.push_back(
                item.source);
        }
        ++logical;
    }
    if (targets.empty()) {
        error = "target source is empty";
        return false;
    }
    return true;
}

PathComponent fixed_component(
    std::uint32_t value, bool hardened) {
    return {value, hardened, false};
}

PathComponent variable_component(bool hardened) {
    return {0u, hardened, true};
}

bool parse_custom_path(const std::string& raw,
                       PathPlan& plan,
                       std::string& error) {
    if (raw.find('\'') != std::string::npos) {
        error = "Chia custom paths use suffix n for hardened components";
        return false;
    }
    std::stringstream input(raw);
    std::string token;
    if (!std::getline(input, token, '/') || token != "m") {
        error = "custom path must start with m/";
        return false;
    }
    while (std::getline(input, token, '/')) {
        if (token.empty()) {
            error = "custom path contains an empty component";
            return false;
        }
        bool hardened = false;
        if (!token.empty() &&
            (token.back() == 'n' ||
             token.back() == 'N')) {
            hardened = true;
            token.pop_back();
        }
        if (token == "*" || token == "{index}") {
            if (plan.variable) {
                error = "custom path may contain one index placeholder";
                return false;
            }
            plan.components.push_back(
                variable_component(hardened));
            plan.variable = true;
            continue;
        }
        std::uint64_t value = 0u;
        if (!parse_u64(token, value) ||
            value >= kIndexLimit) {
            error = "invalid Chia path component '" +
                token + "'";
            return false;
        }
        plan.components.push_back(fixed_component(
            static_cast<std::uint32_t>(value),
            hardened));
    }
    if (plan.components.empty()) {
        error = "custom path has no components";
        return false;
    }
    plan.name = raw;
    return true;
}

bool parse_path_template(const std::string& raw,
                         PathPlan& plan,
                         std::string& error) {
    const std::string value = lower_copy(trim_copy(raw));
    plan.name = value;
    const auto hardened_prefix =
        [&](std::uint32_t purpose) {
            plan.components = {
                fixed_component(12381u, true),
                fixed_component(8444u, true),
                fixed_component(purpose, true),
            };
        };
    if (value == "farmer") {
        hardened_prefix(0u);
        plan.components.push_back(
            fixed_component(0u, true));
    } else if (value == "pool") {
        hardened_prefix(1u);
        plan.components.push_back(
            fixed_component(0u, true));
    } else if (value == "wallet") {
        hardened_prefix(2u);
        plan.components.push_back(
            variable_component(true));
        plan.variable = true;
    } else if (value == "wallet-observer" ||
               value == "wallet-unhardened") {
        plan.components = {
            fixed_component(12381u, false),
            fixed_component(8444u, false),
            fixed_component(2u, false),
            variable_component(false),
        };
        plan.variable = true;
        plan.name = "wallet-observer";
    } else if (value == "local") {
        hardened_prefix(3u);
        plan.components.push_back(
            fixed_component(0u, true));
    } else if (value == "backup") {
        hardened_prefix(4u);
        plan.components.push_back(
            fixed_component(0u, true));
    } else if (value == "singleton") {
        hardened_prefix(5u);
        plan.components.push_back(
            variable_component(true));
        plan.variable = true;
    } else if (value.rfind("pool-auth:", 0u) == 0u) {
        std::uint64_t pool_wallet = 0u;
        if (!parse_u64(
                value.substr(std::string("pool-auth:").size()),
                pool_wallet) ||
            pool_wallet >= 10000u) {
            error = "pool-auth template requires pool wallet 0..9999";
            return false;
        }
        hardened_prefix(6u);
        plan.components.push_back(
            variable_component(true));
        plan.variable = true;
        plan.variable_offset = pool_wallet * 10000u;
    } else if (value.rfind("m/", 0u) == 0u) {
        return parse_custom_path(raw, plan, error);
    } else {
        error = "unknown -path-template '" + raw + "'";
        return false;
    }
    return true;
}

std::string path_identity(const PathPlan& plan) {
    std::ostringstream output;
    output << plan.variable_offset << ":";
    for (const PathComponent& component : plan.components) {
        output << component.value << ":"
               << component.hardened << ":"
               << component.variable << "/";
    }
    return output.str();
}

bool load_paths(const Options& options,
                std::vector<PathPlan>& paths,
                std::string& error) {
    std::unordered_set<std::string> unique;
    bool any_variable = false;
    for (const std::string& raw : options.path_templates) {
        PathPlan plan;
        if (!parse_path_template(raw, plan, error)) {
            return false;
        }
        if (plan.variable &&
            plan.variable_offset + options.index_end >
                kIndexLimit) {
            error = "path index plus profile offset exceeds uint32";
            return false;
        }
        any_variable = any_variable || plan.variable;
        const std::string identity = path_identity(plan);
        if (unique.insert(identity).second) {
            paths.push_back(std::move(plan));
        }
    }
    if (!any_variable &&
        (options.index_begin_set || options.index_end_set)) {
        error = "-start/-end require a variable path template";
        return false;
    }
    return !paths.empty();
}

Hash32 sha256_bytes(const std::uint8_t* data,
                    std::size_t size) {
    Hash32 result{};
    std::vector<std::uint8_t> mutable_input;
    std::uint8_t empty = 0u;
    if (size != 0u) {
        mutable_input.assign(data, data + size);
    }
    sha256(
        size != 0u ? mutable_input.data() : &empty,
        size,
        result.data());
    return result;
}

Hash32 shatree_atom(const std::uint8_t* data,
                    std::size_t size) {
    std::vector<std::uint8_t> preimage(size + 1u);
    preimage[0] = 1u;
    if (size != 0u) {
        std::copy_n(
            data, size, preimage.begin() + 1u);
    }
    return sha256_bytes(preimage.data(), preimage.size());
}

Hash32 shatree_pair(const Hash32& left,
                    const Hash32& right) {
    std::array<std::uint8_t, 65> preimage{};
    preimage[0] = 2u;
    std::copy(
        left.begin(), left.end(),
        preimage.begin() + 1u);
    std::copy(
        right.begin(), right.end(),
        preimage.begin() + 33u);
    return sha256_bytes(preimage.data(), preimage.size());
}

const Hash32& default_hidden_puzzle_hash() {
    static constexpr Hash32 value = {
        0x71, 0x1d, 0x6c, 0x4e, 0x32, 0xc9, 0x2e, 0x53,
        0x17, 0x9b, 0x19, 0x94, 0x84, 0xcf, 0x8c, 0x89,
        0x75, 0x42, 0xbc, 0x57, 0xf2, 0xb2, 0x25, 0x82,
        0x79, 0x9f, 0x9d, 0x65, 0x7e, 0xec, 0x46, 0x99,
    };
    return value;
}

const Hash32& bls_scalar_order() {
    static constexpr Hash32 value = {
        0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
        0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
        0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
    };
    return value;
}

const Hash32& negative_two_to_256_mod_bls_order() {
    static constexpr Hash32 value = {
        0x5b, 0xc8, 0xf5, 0xf9, 0x7c, 0xd8, 0x77, 0xd8,
        0x99, 0xad, 0x88, 0x18, 0x1c, 0xe5, 0x88, 0x0f,
        0xfb, 0x38, 0xec, 0x08, 0xff, 0xfb, 0x13, 0xfc,
        0xff, 0xff, 0xff, 0xfd, 0x00, 0x00, 0x00, 0x03,
    };
    return value;
}

int compare_big_endian(const Hash32& left,
                       const Hash32& right) {
    for (std::size_t index = 0u; index < left.size(); ++index) {
        if (left[index] < right[index]) return -1;
        if (left[index] > right[index]) return 1;
    }
    return 0;
}

void subtract_big_endian(Hash32& left,
                         const Hash32& right) {
    std::uint16_t borrow = 0u;
    for (std::size_t position = left.size();
         position != 0u; --position) {
        const std::size_t index = position - 1u;
        const std::uint16_t subtrahend =
            static_cast<std::uint16_t>(right[index]) + borrow;
        const std::uint16_t value =
            static_cast<std::uint16_t>(left[index]);
        left[index] = static_cast<std::uint8_t>(
            value - subtrahend);
        borrow = value < subtrahend ? 1u : 0u;
    }
}

void add_big_endian(Hash32& left,
                    const Hash32& right) {
    std::uint16_t carry = 0u;
    for (std::size_t position = left.size();
         position != 0u; --position) {
        const std::size_t index = position - 1u;
        const std::uint16_t sum =
            static_cast<std::uint16_t>(left[index]) +
            static_cast<std::uint16_t>(right[index]) +
            carry;
        left[index] = static_cast<std::uint8_t>(sum);
        carry = static_cast<std::uint16_t>(sum >> 8u);
    }
}

Hash32 chia_signed_hash_residue(const Hash32& digest) {
    Hash32 residue = digest;
    const Hash32& order = bls_scalar_order();
    while (compare_big_endian(residue, order) >= 0) {
        subtract_big_endian(residue, order);
    }
    if ((digest[0] & 0x80u) != 0u) {
        add_big_endian(
            residue,
            negative_two_to_256_mod_bls_order());
        if (compare_big_endian(residue, order) >= 0) {
            subtract_big_endian(residue, order);
        }
    }
    return residue;
}

const Hash32& quoted_standard_puzzle_hash() {
    static constexpr Hash32 value = {
        0x98, 0x90, 0xa9, 0xbd, 0x13, 0x30, 0xfc, 0x3c,
        0x4f, 0x4a, 0xf0, 0xde, 0x86, 0x42, 0xdc, 0x31,
        0xb1, 0xd5, 0x25, 0xe2, 0xb1, 0x8e, 0x0f, 0xde,
        0x4e, 0xae, 0x07, 0x9a, 0xfb, 0x1b, 0x60, 0xa4,
    };
    return value;
}

struct CurryConstants {
    Hash32 q;
    Hash32 a;
    Hash32 c;
    Hash32 one;
    Hash32 nil_hash;
};

const CurryConstants& curry_constants() {
    static const CurryConstants constants = [] {
        const std::uint8_t one = 1u;
        const std::uint8_t two = 2u;
        const std::uint8_t four = 4u;
        return CurryConstants{
            shatree_atom(&one, 1u),
            shatree_atom(&two, 1u),
            shatree_atom(&four, 1u),
            shatree_atom(&one, 1u),
            shatree_atom(nullptr, 0u),
        };
    }();
    return constants;
}

bool derive_unhardened(
    const bls12_381::SecretKey& parent,
    std::uint32_t index,
    bls12_381::SecretKey& child,
    std::string& error) {
    bls12_381::PublicKey public_key{};
    if (!bls12_381::public_key_compressed(
            parent, public_key, error)) {
        return false;
    }
    std::array<std::uint8_t, 52> preimage{};
    std::copy(
        public_key.begin(), public_key.end(),
        preimage.begin());
    preimage[48] =
        static_cast<std::uint8_t>(index >> 24u);
    preimage[49] =
        static_cast<std::uint8_t>(index >> 16u);
    preimage[50] =
        static_cast<std::uint8_t>(index >> 8u);
    preimage[51] =
        static_cast<std::uint8_t>(index);
    const Hash32 digest =
        sha256_bytes(preimage.data(), preimage.size());
    return bls12_381::scalar_add_bytes_mod(
        parent, digest.data(), digest.size(),
        child, error);
}

bool derive_component(
    const bls12_381::SecretKey& parent,
    std::uint32_t index,
    bool hardened,
    bls12_381::SecretKey& child,
    std::string& error) {
    return hardened
        ? bls12_381::chia_legacy_child(
              parent, index, child, error)
        : derive_unhardened(
              parent, index, child, error);
}

bool derive_sequence(
    const bls12_381::SecretKey& start,
    const std::vector<PathComponent>& components,
    std::size_t begin,
    std::size_t end,
    std::uint64_t variable_index,
    std::uint64_t variable_offset,
    bls12_381::SecretKey& result,
    std::string& error) {
    result = start;
    for (std::size_t position = begin;
         position < end; ++position) {
        const PathComponent& component =
            components[position];
        const std::uint64_t actual =
            component.variable
                ? variable_offset + variable_index
                : component.value;
        if (actual >= kIndexLimit) {
            error = "derived Chia path index exceeds uint32";
            bls12_381::clear_secret(result);
            return false;
        }
        bls12_381::SecretKey child{};
        if (!derive_component(
                result,
                static_cast<std::uint32_t>(actual),
                component.hardened, child, error)) {
            bls12_381::clear_secret(result);
            return false;
        }
        bls12_381::clear_secret(result);
        result = child;
    }
    return true;
}

std::string path_text(const PathPlan& plan,
                      std::uint64_t variable_index) {
    std::ostringstream output;
    output << "m";
    for (const PathComponent& component : plan.components) {
        const std::uint64_t actual =
            component.variable
                ? plan.variable_offset + variable_index
                : component.value;
        output << "/" << actual;
        if (component.hardened) output << "n";
    }
    return output.str();
}

bool standard_puzzle_hash(
    const bls12_381::SecretKey& secret,
    const bls12_381::PublicKey& public_key,
    Hash32& puzzle_hash,
    bls12_381::PublicKey& synthetic_public_key,
    std::string& error) {
    std::array<std::uint8_t, 80> offset_preimage{};
    std::copy(
        public_key.begin(), public_key.end(),
        offset_preimage.begin());
    std::copy(
        default_hidden_puzzle_hash().begin(),
        default_hidden_puzzle_hash().end(),
        offset_preimage.begin() + public_key.size());
    const Hash32 offset = sha256_bytes(
        offset_preimage.data(), offset_preimage.size());
    const Hash32 signed_offset =
        chia_signed_hash_residue(offset);
    bls12_381::SecretKey synthetic_secret{};
    const bool zero_offset = std::all_of(
        signed_offset.begin(), signed_offset.end(),
        [](std::uint8_t value) { return value == 0u; });
    if (zero_offset) {
        synthetic_secret = secret;
    } else if (!bls12_381::scalar_add_bytes_mod(
                   secret,
                   signed_offset.data(),
                   signed_offset.size(),
                   synthetic_secret,
                   error)) {
        return false;
    }
    if (!bls12_381::public_key_compressed(
            synthetic_secret, synthetic_public_key,
            error)) {
        bls12_381::clear_secret(synthetic_secret);
        return false;
    }
    bls12_381::clear_secret(synthetic_secret);

    const Hash32 argument = shatree_atom(
        synthetic_public_key.data(),
        synthetic_public_key.size());
    const CurryConstants& constants =
        curry_constants();
    const Hash32 quoted_argument = shatree_pair(
        constants.q, argument);
    const Hash32 recursion_tail = shatree_pair(
        constants.one, constants.nil_hash);
    const Hash32 curried_values = shatree_pair(
        constants.c,
        shatree_pair(
            quoted_argument, recursion_tail));
    puzzle_hash = shatree_pair(
        constants.a,
        shatree_pair(
            quoted_standard_puzzle_hash(),
            shatree_pair(
                curried_values, constants.nil_hash)));
    return true;
}

std::string bytes_key(const std::uint8_t* data,
                      std::size_t size) {
    return std::string(
        reinterpret_cast<const char*>(data), size);
}

std::string join_origins(
    const std::vector<std::string>& origins) {
    std::ostringstream output;
    for (std::size_t index = 0u;
         index < origins.size(); ++index) {
        if (index != 0u) output << ",";
        output << origins[index];
    }
    return output.str();
}

bool verify_seed(
    const std::uint8_t* seed,
    std::size_t seed_size,
    const std::string& source,
    const std::string& passphrase,
    const Options& options,
    const std::vector<PathPlan>& paths,
    std::vector<Target>& targets,
    const std::unordered_map<std::string, std::size_t>&
        public_targets,
    const std::unordered_map<std::string, std::size_t>&
        puzzle_targets,
    std::uint64_t logical_targets,
    std::atomic<std::uint64_t>& solved_targets,
    std::mutex& target_mutex,
    std::vector<std::string>& found_lines,
    std::uint64_t& verifications,
    std::string& error) {
    bls12_381::SecretKey master{};
    if (!bls12_381::chia_legacy_master(
            seed, seed_size, master, error)) {
        return false;
    }
    for (const PathPlan& plan : paths) {
        if (solved_targets.load(
                std::memory_order_acquire) >=
            logical_targets) {
            break;
        }
        std::size_t variable_position =
            plan.components.size();
        for (std::size_t position = 0u;
             position < plan.components.size(); ++position) {
            if (plan.components[position].variable) {
                variable_position = position;
                break;
            }
        }
        bls12_381::SecretKey prefix{};
        const std::size_t prefix_end =
            plan.variable
                ? variable_position
                : plan.components.size();
        if (!derive_sequence(
                master, plan.components, 0u, prefix_end,
                0u, plan.variable_offset,
                prefix, error)) {
            bls12_381::clear_secret(master);
            return false;
        }
        const std::uint64_t begin =
            plan.variable ? options.index_begin : 0u;
        const std::uint64_t end =
            plan.variable ? options.index_end : 1u;
        for (std::uint64_t variable_index = begin;
             variable_index < end; ++variable_index) {
            bls12_381::SecretKey derived{};
            if (plan.variable) {
                if (!derive_sequence(
                        prefix, plan.components,
                        variable_position,
                        plan.components.size(),
                        variable_index,
                        plan.variable_offset,
                        derived, error)) {
                    bls12_381::clear_secret(prefix);
                    bls12_381::clear_secret(master);
                    return false;
                }
            } else {
                derived = prefix;
            }
            bls12_381::PublicKey public_key{};
            if (!bls12_381::public_key_compressed(
                    derived, public_key, error)) {
                bls12_381::clear_secret(derived);
                bls12_381::clear_secret(prefix);
                bls12_381::clear_secret(master);
                return false;
            }
            ++verifications;
            std::vector<std::size_t> matches;
            const auto public_match =
                public_targets.find(bytes_key(
                    public_key.data(),
                    public_key.size()));
            if (public_match != public_targets.end()) {
                matches.push_back(public_match->second);
            }
            Hash32 puzzle_hash{};
            bls12_381::PublicKey synthetic_public_key{};
            bool have_puzzle_hash = false;
            if (!puzzle_targets.empty()) {
                if (!standard_puzzle_hash(
                        derived, public_key, puzzle_hash,
                        synthetic_public_key, error)) {
                    bls12_381::clear_secret(derived);
                    bls12_381::clear_secret(prefix);
                    bls12_381::clear_secret(master);
                    return false;
                }
                have_puzzle_hash = true;
                const auto puzzle_match =
                    puzzle_targets.find(bytes_key(
                        puzzle_hash.data(),
                        puzzle_hash.size()));
                if (puzzle_match != puzzle_targets.end()) {
                    matches.push_back(
                        puzzle_match->second);
                }
            }
            if (!matches.empty()) {
                if (!have_puzzle_hash &&
                    !standard_puzzle_hash(
                        derived, public_key, puzzle_hash,
                        synthetic_public_key, error)) {
                    bls12_381::clear_secret(derived);
                    bls12_381::clear_secret(prefix);
                    bls12_381::clear_secret(master);
                    return false;
                }
                std::ostringstream origins;
                std::size_t accepted = 0u;
                {
                    std::lock_guard<std::mutex> lock(
                        target_mutex);
                    for (const std::size_t match : matches) {
                        Target& target = targets[match];
                        if (target.solved) continue;
                        target.solved = true;
                        solved_targets.fetch_add(
                            target.origins.size(),
                            std::memory_order_release);
                        if (accepted++ != 0u) origins << ";";
                        origins << join_origins(
                            target.origins);
                    }
                }
                if (accepted != 0u) {
                    std::ostringstream line;
                    line << "mode=chia source=" << source
                         << " passphrase_hex="
                         << hex_string(
                              reinterpret_cast<
                                  const std::uint8_t*>(
                                  passphrase.data()),
                              passphrase.size())
                         << " path="
                         << path_text(plan, variable_index)
                         << " seed="
                         << hex_string(seed, seed_size)
                         << " secret="
                         << hex_string(
                              derived.data(),
                              derived.size())
                         << " pubkey="
                         << hex_string(
                              public_key.data(),
                              public_key.size())
                         << " synthetic_pubkey="
                         << hex_string(
                              synthetic_public_key.data(),
                              synthetic_public_key.size())
                         << " puzzle_hash="
                         << hex_string(
                              puzzle_hash.data(),
                              puzzle_hash.size())
                         << " target=" << origins.str();
                    found_lines.push_back(line.str());
                }
            }
            bls12_381::clear_secret(derived);
            if (!plan.variable) break;
            if (solved_targets.load(
                    std::memory_order_acquire) >=
                logical_targets) {
                break;
            }
        }
        bls12_381::clear_secret(prefix);
    }
    bls12_381::clear_secret(master);
    return true;
}

bool metal_ok(metalError_t status,
              const char* action,
              std::string& error) {
    if (status == metalSuccess) return true;
    error = std::string(action) + ": " +
        metalGetErrorString(status);
    return false;
}

template <typename T>
bool allocate_buffer(T*& pointer,
                     std::uint64_t bytes,
                     const char* action,
                     std::string& error) {
    void* raw = nullptr;
    if (!metal_ok(
            metalMalloc(
                &raw, static_cast<std::size_t>(bytes)),
            action, error)) {
        return false;
    }
    pointer = static_cast<T*>(raw);
    return true;
}

void release_buffers(DeviceBuffers& buffers) {
    if (buffers.device >= 0) {
        (void)metalSetDevice(buffers.device);
    }
    if (buffers.mnemonics) metalFree(buffers.mnemonics);
    if (buffers.mnemonic_lengths) {
        metalFree(buffers.mnemonic_lengths);
    }
    if (buffers.salts) metalFree(buffers.salts);
    if (buffers.salt_lengths) {
        metalFree(buffers.salt_lengths);
    }
    if (buffers.seeds) metalFree(buffers.seeds);
    buffers = {};
}

bool prepare_buffers(int device,
                     std::uint64_t capacity,
                     DeviceBuffers& buffers,
                     std::string& error) {
    buffers.device = device;
    if (!metal_ok(
            metalSetDevice(device),
            "select Chia Metal device", error) ||
        !allocate_buffer(
            buffers.mnemonics,
            capacity * kMnemonicStride,
            "allocate Chia mnemonic buffer", error) ||
        !allocate_buffer(
            buffers.mnemonic_lengths,
            capacity * sizeof(std::uint16_t),
            "allocate Chia mnemonic lengths", error) ||
        !allocate_buffer(
            buffers.salts,
            capacity * kSaltStride,
            "allocate Chia salt buffer", error) ||
        !allocate_buffer(
            buffers.salt_lengths,
            capacity * sizeof(std::uint16_t),
            "allocate Chia salt lengths", error) ||
        !allocate_buffer(
            buffers.seeds, capacity * 64u,
            "allocate Chia seed buffer", error)) {
        release_buffers(buffers);
        return false;
    }
    buffers.capacity = capacity;
    buffers.allocated =
        capacity *
        (kMnemonicStride + sizeof(std::uint16_t) +
         kSaltStride + sizeof(std::uint16_t) + 64u);
    return true;
}

std::uint32_t launch_grid(std::uint64_t count) {
    return static_cast<std::uint32_t>(
        (count + kThreadgroupSize - 1u) /
        kThreadgroupSize * kThreadgroupSize);
}

bool launch_seed_batch(
    DeviceBuffers& buffers,
    const std::vector<TextCandidate>& mnemonics,
    const std::vector<TextCandidate>& passphrases,
    std::uint64_t ordinal,
    std::size_t count,
    std::vector<Seed64>& seeds,
    std::uint64_t& readback_ns,
    std::string& error) {
    std::vector<char> packed_mnemonics(
        count * kMnemonicStride, 0);
    std::vector<std::uint16_t> mnemonic_lengths(
        count, 0u);
    std::vector<std::uint8_t> packed_salts(
        count * kSaltStride, 0u);
    std::vector<std::uint16_t> salt_lengths(
        count, 0u);
    for (std::size_t lane = 0u; lane < count; ++lane) {
        const std::uint64_t candidate = ordinal + lane;
        const std::size_t mnemonic_index =
            static_cast<std::size_t>(
                candidate / passphrases.size());
        const std::size_t passphrase_index =
            static_cast<std::size_t>(
                candidate % passphrases.size());
        const std::string& mnemonic =
            mnemonics[mnemonic_index].text;
        const std::string salt =
            "mnemonic" +
            passphrases[passphrase_index].text;
        mnemonic_lengths[lane] =
            static_cast<std::uint16_t>(mnemonic.size());
        salt_lengths[lane] =
            static_cast<std::uint16_t>(salt.size());
        std::copy(
            mnemonic.begin(), mnemonic.end(),
            packed_mnemonics.begin() +
                lane * kMnemonicStride);
        std::copy(
            salt.begin(), salt.end(),
            packed_salts.begin() +
                lane * kSaltStride);
    }
    if (!metal_ok(
            metalSetDevice(buffers.device),
            "select Chia Metal device", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.mnemonics,
                packed_mnemonics.data(),
                packed_mnemonics.size(),
                metalMemcpyHostToDevice),
            "upload Chia mnemonics", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.mnemonic_lengths,
                mnemonic_lengths.data(),
                mnemonic_lengths.size() *
                    sizeof(mnemonic_lengths.front()),
                metalMemcpyHostToDevice),
            "upload Chia mnemonic lengths", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.salts, packed_salts.data(),
                packed_salts.size(),
                metalMemcpyHostToDevice),
            "upload Chia salts", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.salt_lengths,
                salt_lengths.data(),
                salt_lengths.size() *
                    sizeof(salt_lengths.front()),
                metalMemcpyHostToDevice),
            "upload Chia salt lengths", error) ||
        !metal_ok(
            metal_launch(
                "workerChiaSeed",
                launch_grid(count), kThreadgroupSize,
                buffers.mnemonics,
                buffers.mnemonic_lengths,
                buffers.salts,
                buffers.salt_lengths,
                static_cast<std::uint64_t>(count),
                buffers.seeds),
            "launch Chia seed worker", error) ||
        !metal_ok(
            metalDeviceSynchronize(),
            "synchronize Chia seed worker", error)) {
        return false;
    }
    const auto read_start =
        std::chrono::steady_clock::now();
    seeds.resize(count);
    if (!metal_ok(
            metalMemcpy(
                seeds.data(), buffers.seeds,
                count * sizeof(seeds.front()),
                metalMemcpyDeviceToHost),
            "read Chia seeds", error)) {
        return false;
    }
    readback_ns += static_cast<std::uint64_t>(
        std::chrono::duration_cast<
            std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() -
            read_start).count());
    return true;
}

bool query_devices(
    const Options& options,
    std::vector<modeinfra::MemoryDeviceInfo>& info,
    std::string& error) {
    int count = 0;
    if (!metal_ok(
            metalGetDeviceCount(&count),
            "query Metal devices", error)) {
        return false;
    }
    for (const int device : options.devices) {
        if (device < 0 || device >= count) {
            error = "unavailable Metal device " +
                std::to_string(device);
            return false;
        }
        metalDeviceProp properties{};
        if (!metal_ok(
                metalGetDeviceProperties(
                    &properties, device),
                "query Metal device properties", error)) {
            return false;
        }
        info.push_back({
            properties.recommendedMaxWorkingSetSize,
            properties.currentAllocatedSize,
            properties.maxBufferLength,
            properties.hasUnifiedMemory != 0,
        });
    }
    return true;
}

bool open_output(const Options& options,
                 std::ofstream& output,
                 std::string& error) {
    if (!options.save && options.output_path.empty()) {
        return true;
    }
    const std::string path = options.output_path.empty()
        ? "result.txt" : options.output_path;
    output.open(path, std::ios::app);
    if (!output) {
        error = "cannot open output '" + path + "'";
        return false;
    }
    return true;
}

void emit_found(const Options& options,
                const RuntimeHooks& hooks,
                std::ofstream& output,
                const std::string& line,
                std::uint64_t& founds,
                modeinfra::ModeProgress& progress) {
    ++founds;
    if (hooks.credit_found) hooks.credit_found();
    progress.set_founds(founds);
    if (!options.silent) {
        std::cout << "[+] CHIA_FOUND " << line << "\n";
    }
    if (output) {
        output << line << "\n";
        output.flush();
    }
}

std::uint64_t path_attempts(
    const Options& options,
    const std::vector<PathPlan>& paths) {
    std::uint64_t result = 0u;
    for (const PathPlan& path : paths) {
        const std::uint64_t count = path.variable
            ? options.index_end - options.index_begin
            : 1u;
        if (result >
            std::numeric_limits<std::uint64_t>::max() -
                count) {
            return std::numeric_limits<std::uint64_t>::max();
        }
        result += count;
    }
    return result;
}

int run_mode(const Options& options,
             const RuntimeHooks& hooks) {
    std::string error;
    std::vector<TextCandidate> mnemonics;
    std::vector<TextCandidate> passphrases;
    std::vector<std::pair<
        std::vector<std::uint8_t>, std::string>> raw_seeds;
    std::vector<Target> targets;
    std::vector<PathPlan> paths;
    std::uint64_t logical_targets = 0u;
    if (!load_mnemonics(options, mnemonics, error) ||
        !load_passphrases(options, passphrases, error) ||
        !load_seeds(options, raw_seeds, error) ||
        !load_targets(
            options, targets, logical_targets, error) ||
        !load_paths(options, paths, error)) {
        std::cerr << "[!] chia input error: "
                  << error << " [!]\n";
        return 2;
    }
    if (mnemonics.empty() && raw_seeds.empty()) {
        std::cerr << "[!] chia input error: no usable "
                     "mnemonic or seed candidates [!]\n";
        return 2;
    }
    if (!mnemonics.empty() &&
        passphrases.size() >
            std::numeric_limits<std::uint64_t>::max() /
                mnemonics.size()) {
        std::cerr << "[!] chia input error: mnemonic/passphrase "
                     "domain exceeds uint64 [!]\n";
        return 2;
    }
    const std::uint64_t kdf_candidates =
        static_cast<std::uint64_t>(mnemonics.size()) *
        static_cast<std::uint64_t>(passphrases.size());

    std::unordered_map<std::string, std::size_t>
        public_targets;
    std::unordered_map<std::string, std::size_t>
        puzzle_targets;
    public_targets.reserve(targets.size());
    puzzle_targets.reserve(targets.size());
    for (std::size_t index = 0u;
         index < targets.size(); ++index) {
        const Target& target = targets[index];
        if (target.kind == TargetKind::PublicKey) {
            public_targets.emplace(
                bytes_key(target.value.data(), 48u), index);
        } else {
            puzzle_targets.emplace(
                bytes_key(target.value.data(), 32u), index);
        }
    }

    std::vector<DeviceBuffers> devices;
    std::uint64_t allocated = 0u;
    if (kdf_candidates != 0u) {
        std::vector<modeinfra::MemoryDeviceInfo> device_info;
        if (!query_devices(options, device_info, error)) {
            std::cerr << "[!] chia runtime error: "
                      << error << " [!]\n";
            return 1;
        }
        const std::uint64_t per_candidate =
            kMnemonicStride + sizeof(std::uint16_t) +
            kSaltStride + sizeof(std::uint16_t) + 64u;
        modeinfra::MemorySpec memory_spec;
        modeinfra::MemoryBudget budget;
        if (!modeinfra::parse_memory_spec(
                options.memory, memory_spec, error) ||
            !modeinfra::resolve_memory_budget(
                memory_spec, device_info, per_candidate,
                0u, budget, error, kRuntimeReserve)) {
            std::cerr << "[!] chia memory error: "
                      << error << " [!]\n";
            return 2;
        }
        std::uint64_t capacity = std::min(
            std::min(options.batch, kdf_candidates),
            std::max<std::uint64_t>(
                1u,
                budget.per_device_budget / per_candidate));
        capacity = std::min(
            capacity,
            std::max<std::uint64_t>(
                1u,
                budget.max_buffer_length /
                    std::max(kMnemonicStride, kSaltStride)));
        for (;;) {
            devices.assign(options.devices.size(), {});
            bool prepared = true;
            for (std::size_t index = 0u;
                 index < devices.size(); ++index) {
                if (!prepare_buffers(
                        options.devices[index], capacity,
                        devices[index], error)) {
                    prepared = false;
                    break;
                }
            }
            if (prepared) break;
            for (DeviceBuffers& device : devices) {
                release_buffers(device);
            }
            if (memory_spec.kind !=
                    modeinfra::MemoryKind::Auto ||
                capacity == 1u) {
                std::cerr << "[!] chia allocation error: "
                          << error << " [!]\n";
                return 1;
            }
            capacity =
                std::max<std::uint64_t>(1u, capacity / 2u);
            error.clear();
        }
        for (const DeviceBuffers& device : devices) {
            allocated += device.allocated;
        }
    }

    std::ofstream output;
    if (!open_output(options, output, error)) {
        for (DeviceBuffers& device : devices) {
            release_buffers(device);
        }
        std::cerr << "[!] chia output error: "
                  << error << " [!]\n";
        return 1;
    }

    std::cout << "[!] chia BIP39/BLS recovery: "
              << mnemonics.size() << " mnemonic x "
              << passphrases.size() << " passphrase + "
              << raw_seeds.size() << " raw seed"
              << " | paths: " << paths.size()
              << "/" << path_attempts(options, paths)
              << " derivations per seed"
              << " | targets: " << targets.size()
              << " unique/" << logical_targets
              << " logical | devices: " << devices.size()
              << " | working set: " << allocated
              << " bytes [!]\n";

    modeinfra::ModeProgress& progress =
        modeinfra::global_mode_progress();
    progress.begin(
        "CHIA", modeinfra::ProgressUnit::Kdf,
        modeinfra::ProgressPhase::Search);
    progress.set_targets(
        logical_targets, targets.size(), 0u);
    progress.set_allocated_working_set(allocated);

    std::uint64_t founds = 0u;
    std::atomic<std::uint64_t> solved_targets{0u};
    std::mutex target_mutex;
    std::uint64_t ordinal = 0u;
    bool stop = false;
    while (ordinal < kdf_candidates && !stop) {
        for (DeviceBuffers& device : devices) {
            if (ordinal >= kdf_candidates || stop) break;
            const std::size_t count =
                static_cast<std::size_t>(
                    std::min<std::uint64_t>(
                        device.capacity,
                        kdf_candidates - ordinal));
            std::vector<Seed64> batch_seeds;
            std::uint64_t readback_ns = 0u;
            if (!launch_seed_batch(
                    device, mnemonics, passphrases,
                    ordinal, count, batch_seeds,
                    readback_ns, error)) {
                progress.end();
                for (DeviceBuffers& item : devices) {
                    release_buffers(item);
                }
                std::cerr << "[!] chia runtime error: "
                          << error << " [!]\n";
                return 1;
            }
            struct LaneResult {
                std::vector<std::string> lines;
                std::uint64_t verifications = 0u;
                std::string error;
                bool ok = true;
            };
            std::vector<LaneResult> results(count);
            std::atomic<std::size_t> next_lane{0u};
            const unsigned available_threads =
                std::max(
                    1u, std::thread::hardware_concurrency());
            const std::size_t worker_count = std::min(
                count,
                static_cast<std::size_t>(available_threads));
            const auto verify_lane = [&]() {
                for (;;) {
                    const std::size_t lane =
                        next_lane.fetch_add(
                            1u, std::memory_order_relaxed);
                    if (lane >= count) break;
                    const std::uint64_t candidate =
                        ordinal + lane;
                    const std::size_t mnemonic_index =
                        static_cast<std::size_t>(
                            candidate /
                            passphrases.size());
                    const std::size_t passphrase_index =
                        static_cast<std::size_t>(
                            candidate %
                            passphrases.size());
                    LaneResult& result = results[lane];
                    result.ok = verify_seed(
                        batch_seeds[lane].data(),
                        batch_seeds[lane].size(),
                        mnemonics[mnemonic_index].source,
                        passphrases[passphrase_index].text,
                        options, paths, targets,
                        public_targets, puzzle_targets,
                        logical_targets, solved_targets,
                        target_mutex, result.lines,
                        result.verifications,
                        result.error);
                }
            };
            std::vector<std::thread> workers;
            workers.reserve(worker_count);
            for (std::size_t index = 0u;
                 index < worker_count; ++index) {
                workers.emplace_back(verify_lane);
            }
            for (std::thread& worker : workers) {
                worker.join();
            }
            std::uint64_t verifications = 0u;
            for (LaneResult& result : results) {
                if (!result.ok) {
                    progress.end();
                    for (DeviceBuffers& item : devices) {
                        release_buffers(item);
                    }
                    std::cerr << "[!] chia verification error: "
                              << result.error << " [!]\n";
                    return 1;
                }
                verifications += result.verifications;
                for (const std::string& line : result.lines) {
                    emit_found(
                        options, hooks, output, line,
                        founds, progress);
                }
            }
            stop = solved_targets.load(
                std::memory_order_acquire) >=
                logical_targets;
            progress.credit_completed(
                count,
                static_cast<std::uint64_t>(count) * 2048u,
                verifications, readback_ns);
            if (hooks.credit_completed) {
                hooks.credit_completed(count);
            }
            progress.set_targets(
                logical_targets, targets.size(),
                solved_targets.load(
                    std::memory_order_acquire));
            ordinal += count;
        }
    }

    for (const auto& seed : raw_seeds) {
        if (stop) break;
        std::uint64_t verifications = 0u;
        std::vector<std::string> lines;
        if (!verify_seed(
                seed.first.data(), seed.first.size(),
                seed.second, "", options, paths, targets,
                public_targets, puzzle_targets,
                logical_targets, solved_targets,
                target_mutex, lines,
                verifications, error)) {
            progress.end();
            for (DeviceBuffers& item : devices) {
                release_buffers(item);
            }
            std::cerr << "[!] chia verification error: "
                      << error << " [!]\n";
            return 1;
        }
        for (const std::string& line : lines) {
            emit_found(
                options, hooks, output, line,
                founds, progress);
        }
        progress.credit_completed(
            1u, 0u, verifications, 0u);
        if (hooks.credit_completed) {
            hooks.credit_completed(1u);
        }
        progress.set_targets(
            logical_targets, targets.size(),
            solved_targets.load(
                std::memory_order_acquire));
        stop = solved_targets.load(
            std::memory_order_acquire) >=
            logical_targets;
    }

    progress.end();
    for (DeviceBuffers& device : devices) {
        release_buffers(device);
    }
    std::cout << "[!] chia search complete: found "
              << founds << " | solved "
              << solved_targets.load(
                     std::memory_order_acquire)
              << "/"
              << logical_targets
              << " logical targets [!]\n";
    return 0;
}

}  // namespace

bool requested(int argc, char** argv) {
    for (int index = 1; index < argc; ++index) {
        if (std::string(argv[index]) == "-chia") {
            return true;
        }
    }
    return false;
}

void print_help() {
    std::cout << R"HELP(
[!] ================== CHIA MODE ==================
[!]
[!] Purpose:
[!] Recover Chia keys from BIP39 mnemonic/passphrase candidates or raw
[!] seeds on Metal, then verify exact BLS public-key and standard wallet
[!] puzzle-hash targets.
[!]
[!] Inputs:
[!] -chia FILE                    Positional mnemonic file; repeatable.
[!] -i FILE                       Mnemonic file; repeatable.
[!] -mnemonic VALUE|FILE          Checksum-valid English BIP39 phrase(s).
[!] -seed HEX|FILE                Raw 32..64-byte seed(s); repeatable.
[!] -pass VALUE|FILE              BIP39 passphrase candidate(s).
[!] -passphrase VALUE|FILE        Alias for -pass.
[!] -target VALUE|FILE            Repeatable 48-byte compressed BLS key,
[!]                               32-byte puzzle hash, xch/txch address,
[!]                               or file with one target per line.
[!]
[!] Path profiles:
[!] -path-template farmer         m/12381n/8444n/0n/0n
[!] -path-template pool           m/12381n/8444n/1n/0n
[!] -path-template wallet         Hardened wallet index path.
[!] -path-template wallet-observer
[!]                               Observer/unhardened wallet index path
[!]                               (default).
[!] -path-template local|backup   Chia local or backup fixed path.
[!] -path-template singleton      Pool-wallet owner index path.
[!] -path-template pool-auth:N    Pool authentication path for pool wallet N.
[!] -path-template "m/.../{index}n"
[!]                               Custom path. Suffix n means hardened;
[!]                               plain components are observer/unhardened.
[!] -path PATH                    Alias for -path-template.
[!] -start N -end N               Variable index interval [N,END),
[!]                               default [0,1), with uint32 bounds.
[!] Multiple path templates are allowed and are deduplicated.
[!]
[!] GPU / memory / MultiGPU:
[!] -wallet-mem auto|all|NN%|SIZE Unified-memory budget.
[!] -n N                          Resident mnemonic/passphrase batch,
[!]                               1..16384.
[!] -device LIST                  Metal devices, for example 0 or 0,1.
[!] auto uses at most 50% of free recommended working set and may reduce
[!] the resident batch after allocation failure. all leaves 512 MiB for
[!] runtime. Large logical candidate domains are streamed in windows.
[!]
[!] Statistics:
[!] The common SpeedThreadFunc is the only statistics writer. It reports
[!] KDF/s, PBKDF2 primitive rounds, exact parallel host BLS derivations,
[!] logical/resident/solved targets, allocated Metal working set and
[!] completed readback time.
[!] Target count is never multiplied into KDF/s.
[!]
[!] Output:
[!] Every hit contains source, passphrase hex, exact path, seed, secret,
[!] compressed public key, synthetic public key and puzzle hash.
[!] -save                         Append verified hits to result.txt.
[!] -o FILE                       Output path (also enables saving).
[!] -silent                       Suppress found lines on the console.
[!]
[!] Examples:
[!]   ./METAL_CRYPTO_TOOLKIT -chia -i mnemonics.txt \
[!]     -target FARMER_PUBKEY -path-template farmer -save
[!]   ./METAL_CRYPTO_TOOLKIT -chia -i mnemonics.txt -pass passes.txt \
[!]     -target xch1... -path-template wallet-observer -start 0 -end 100
[!]   ./METAL_CRYPTO_TOOLKIT -chia -seed seed.hex \
[!]     -target PUZZLE_HASH -path-template wallet -start 0 -end 50
[!]   ./METAL_CRYPTO_TOOLKIT -chia -i mnemonics.txt \
[!]     -target targets.txt -path-template "m/12381n/8444n/2n/{index}n" \
[!]     -wallet-mem all -device 0
[!]
[!] Limitations:
[!] English BIP39 and Chia BLS12-381 derivation are supported. Standard
[!] puzzle verification implements p2_delegated_puzzle_or_hidden_puzzle
[!] with the canonical default hidden puzzle. Arbitrary Chialisp puzzles,
[!] unknown-word permutation generation and xpub-only recovery are outside
[!] this mode. Large path ranges remain computationally expensive.
[!]
[!] Errors:
[!] CLI/input errors return 2; Metal/runtime errors return 1; a valid
[!] exhausted search returns 0 even when no target is found.
[!] ===============================================
[!] End of detailed help for -chia [!]
)HELP";
}

int run(int argc, char** argv,
        const RuntimeHooks& hooks) {
    Options options;
    std::string error;
    if (!parse_options(argc, argv, options, error)) {
        std::cerr << "[!] chia CLI error: "
                  << error << " [!]\n";
        return 2;
    }
    return run_mode(options, hooks);
}

}  // namespace chia_mode
