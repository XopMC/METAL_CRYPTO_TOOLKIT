#include "MoneroMode.h"

#include "MoneroWordlists.generated.h"
#include "../MetalBackend.h"

#include <CommonCrypto/CommonKeyDerivation.h>

extern "C" {
#include "third_party/crypto-ops.h"
}

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstring>
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

namespace monero_mode {
namespace {

constexpr std::uint32_t kThreadgroupSize = 256u;
constexpr std::uint32_t kHitCapacity = 65536u;
constexpr std::uint64_t kDefaultBatch = 1ull << 16u;
constexpr std::uint64_t kMaximumBatch = 1ull << 22u;
constexpr std::uint64_t kRuntimeReserve =
    512ull * 1024ull * 1024ull;

enum class Scheme : std::uint32_t {
    Legacy = 1u,
    Polyseed = 2u,
};

struct alignas(16) GpuCandidate {
    std::array<std::uint8_t, 32> material{};
    std::uint32_t birthday = 0u;
    std::uint32_t features = 0u;
    std::uint32_t scheme = 0u;
    std::uint32_t valid = 0u;
    std::array<std::uint64_t, 4> ordinal{};
    std::uint64_t template_index = 0u;
    std::array<std::uint32_t, 2> reserved{};
};

struct alignas(16) GpuTarget {
    std::array<std::uint8_t, 32> spend_public{};
    std::array<std::uint8_t, 32> view_public{};
    std::uint64_t prefix = 0u;
    std::uint64_t source_index = 0u;
};

struct alignas(16) GpuDerived {
    std::array<std::uint8_t, 32> spend_private{};
    std::array<std::uint8_t, 32> view_private{};
    std::array<std::uint8_t, 32> spend_public{};
    std::array<std::uint8_t, 32> view_public{};
    std::uint32_t valid = 0u;
    std::array<std::uint32_t, 3> reserved{};
};

struct alignas(8) GpuHit {
    std::array<std::uint64_t, 4> ordinal{};
    std::uint64_t template_index = 0u;
    std::uint64_t target_index = 0u;
    std::uint32_t scheme = 0u;
    std::uint32_t reserved = 0u;
    std::array<std::uint8_t, 32> spend_private{};
    std::array<std::uint8_t, 32> view_private{};
    std::array<std::uint8_t, 32> spend_public{};
    std::array<std::uint8_t, 32> view_public{};
};

static_assert(sizeof(GpuCandidate) == 96u);
static_assert(sizeof(GpuTarget) == 80u);
static_assert(sizeof(GpuDerived) == 144u);
static_assert(sizeof(GpuHit) == 184u);

struct Occurrence {
    std::string source;
    std::string raw;
};

struct Target {
    std::array<std::uint8_t, 32> spend_public{};
    std::array<std::uint8_t, 32> view_public{};
    std::vector<Occurrence> occurrences;
    bool solved = false;
};

struct SeedTemplate {
    Scheme scheme = Scheme::Legacy;
    const MoneroWordlistView* wordlist = nullptr;
    std::vector<std::string> tokens;
    std::vector<std::int32_t> indices;
    std::vector<std::size_t> unknown_positions;
    modeinfra::MixedRadixDomain domain;
    std::string source;
};

struct Options {
    std::vector<std::string> target_values;
    std::vector<std::string> seed_values;
    std::vector<int> devices{0};
    std::string language = "auto";
    std::string memory = "auto";
    std::string output_path;
    std::uint64_t batch = 0u;
    bool batch_explicit = false;
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

std::string lower_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char ch) {
                       return static_cast<char>(std::tolower(ch));
                   });
    return value;
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
        if (arg == "-monero") {
            after_mode = true;
        } else if (arg == "-target") {
            const char* value = require_value("-target");
            if (!value) return false;
            options.target_values.emplace_back(value);
        } else if (arg == "-i") {
            const char* value = require_value("-i");
            if (!value) return false;
            options.seed_values.emplace_back(value);
        } else if (arg == "-monero-lang") {
            const char* value = require_value("-monero-lang");
            if (!value) return false;
            options.language = value;
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
            error = "unsupported -monero argument '" + arg + "'";
            return false;
        }
    }
    if (options.target_values.empty()) {
        error = "-monero requires at least one -target";
        return false;
    }
    if (options.seed_values.empty()) {
        error = "-monero requires at least one seed/template through -i";
        return false;
    }
    return true;
}

bool decode_hex(const std::string& raw,
                std::vector<std::uint8_t>& bytes) {
    const std::string text = trim_copy(raw);
    if (text.empty() || (text.size() & 1u) != 0u) return false;
    bytes.resize(text.size() / 2u);
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
        1,3,6,10,15,21,28,36,45,55,2,14,
        27,41,56,8,25,43,62,18,39,61,20,44,
    };
    static constexpr unsigned lanes[24] = {
        10,7,11,17,18,3,5,16,8,21,24,4,
        15,23,19,13,12,2,20,14,22,9,6,1,
    };
    for (std::size_t round = 0u; round < 24u; ++round) {
        std::uint64_t column[5];
        for (std::size_t i = 0u; i < 5u; ++i) {
            column[i] = state[i] ^ state[i + 5u] ^
                state[i + 10u] ^ state[i + 15u] ^ state[i + 20u];
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

std::array<std::uint8_t, 32> keccak256(
    const std::uint8_t* data, std::size_t size) {
    constexpr std::size_t rate = 136u;
    std::uint64_t state[25] = {};
    auto* bytes = reinterpret_cast<std::uint8_t*>(state);
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
    std::array<std::uint8_t, 32> result{};
    std::copy(bytes, bytes + result.size(), result.begin());
    return result;
}

bool decode_base58_block(const char* text, std::size_t encoded_size,
                         std::uint8_t* output,
                         std::size_t decoded_size) {
    static constexpr char alphabet[] =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::uint64_t value = 0u;
    for (std::size_t i = 0u; i < encoded_size; ++i) {
        const char* found = std::strchr(alphabet, text[i]);
        if (!found) return false;
        const std::uint64_t digit =
            static_cast<std::uint64_t>(found - alphabet);
        if (value >
            (std::numeric_limits<std::uint64_t>::max() - digit) / 58u) {
            return false;
        }
        value = value * 58u + digit;
    }
    if (decoded_size < 8u &&
        value >= (std::uint64_t{1} << (decoded_size * 8u))) {
        return false;
    }
    for (std::size_t i = 0u; i < decoded_size; ++i) {
        output[decoded_size - 1u - i] =
            static_cast<std::uint8_t>(value >> (i * 8u));
    }
    return true;
}

bool decode_monero_base58(const std::string& text,
                          std::vector<std::uint8_t>& output) {
    static constexpr std::size_t decoded_sizes[12] = {
        0u,0u,1u,2u,0u,3u,4u,5u,0u,6u,7u,8u
    };
    if (text.empty()) return false;
    const std::size_t full_blocks = text.size() / 11u;
    const std::size_t remainder = text.size() % 11u;
    if (remainder != 0u && decoded_sizes[remainder] == 0u) return false;
    const std::size_t final_size =
        remainder == 0u ? 0u : decoded_sizes[remainder];
    output.assign(full_blocks * 8u + final_size, 0u);
    for (std::size_t i = 0u; i < full_blocks; ++i) {
        if (!decode_base58_block(
                text.data() + i * 11u, 11u,
                output.data() + i * 8u, 8u)) {
            return false;
        }
    }
    if (remainder != 0u &&
        !decode_base58_block(
            text.data() + full_blocks * 11u, remainder,
            output.data() + full_blocks * 8u, final_size)) {
        return false;
    }
    return true;
}

bool parse_target_value(
    const std::string& raw,
    std::array<std::uint8_t, 32>& spend,
    std::array<std::uint8_t, 32>& view,
    std::string& error) {
    const auto valid_public_pair = [&]() {
        ge_p3 point{};
        if (ge_frombytes_vartime(&point, spend.data()) != 0 ||
            ge_frombytes_vartime(&point, view.data()) != 0) {
            error = "Monero target contains an invalid Ed25519 public key";
            return false;
        }
        return true;
    };
    const std::string text = trim_copy(raw);
    const auto colon = text.find(':');
    std::vector<std::uint8_t> first;
    std::vector<std::uint8_t> second;
    if (colon != std::string::npos &&
        decode_hex(text.substr(0u, colon), first) &&
        decode_hex(text.substr(colon + 1u), second) &&
        first.size() == 32u && second.size() == 32u) {
        std::copy(first.begin(), first.end(), spend.begin());
        std::copy(second.begin(), second.end(), view.begin());
        return valid_public_pair();
    }
    if (decode_hex(text, first) && first.size() == 64u) {
        std::copy(first.begin(), first.begin() + 32u, spend.begin());
        std::copy(first.begin() + 32u, first.end(), view.begin());
        return valid_public_pair();
    }
    std::vector<std::uint8_t> decoded;
    if (!decode_monero_base58(text, decoded) ||
        (decoded.size() != 69u && decoded.size() != 77u)) {
        error = "expected a Monero address or SPEND_HEX:VIEW_HEX";
        return false;
    }
    static constexpr std::uint8_t valid_tags[] = {
        18u,19u,42u,53u,54u,63u,24u,25u,36u
    };
    if (std::find(std::begin(valid_tags), std::end(valid_tags),
                  decoded[0]) == std::end(valid_tags)) {
        error = "unsupported Monero address network/type prefix";
        return false;
    }
    const bool integrated =
        decoded[0] == 19u || decoded[0] == 54u || decoded[0] == 25u;
    if ((integrated && decoded.size() != 77u) ||
        (!integrated && decoded.size() != 69u)) {
        error = "Monero address payload length does not match its prefix";
        return false;
    }
    const auto checksum =
        keccak256(decoded.data(), decoded.size() - 4u);
    if (!std::equal(
            checksum.begin(), checksum.begin() + 4u,
            decoded.end() - 4u)) {
        error = "Monero address checksum mismatch";
        return false;
    }
    std::copy(decoded.begin() + 1u, decoded.begin() + 33u,
              spend.begin());
    std::copy(decoded.begin() + 33u, decoded.begin() + 65u,
              view.begin());
    return valid_public_pair();
}

bool load_lines_or_value(const std::string& value,
                         bool first_token_only,
                         std::vector<std::pair<std::string, std::string>>& out,
                         std::string& error) {
    std::ifstream input(value);
    if (!input) {
        out.push_back({"inline", value});
        return true;
    }
    std::string line;
    std::uint64_t line_number = 0u;
    while (std::getline(input, line)) {
        ++line_number;
        const auto comment = line.find('#');
        if (comment != std::string::npos) line.resize(comment);
        line = trim_copy(line);
        if (line.empty()) continue;
        if (first_token_only) {
            const auto space = line.find_first_of(" \t");
            if (space != std::string::npos) line.resize(space);
        }
        out.push_back({
            value + "#" + std::to_string(line_number), line
        });
    }
    if (!input.eof()) {
        error = "failed while reading '" + value + "'";
        return false;
    }
    return true;
}

std::uint64_t target_prefix(
    const std::array<std::uint8_t, 32>& value) {
    std::uint64_t prefix = 0u;
    for (std::size_t i = 0u; i < 8u; ++i) {
        prefix = (prefix << 8u) | value[i];
    }
    return prefix;
}

bool load_targets(const Options& options,
                  std::vector<Target>& targets,
                  std::uint64_t& logical,
                  std::string& error) {
    std::map<std::array<std::uint8_t, 64>, std::size_t> unique;
    logical = 0u;
    for (const std::string& value : options.target_values) {
        std::vector<std::pair<std::string, std::string>> lines;
        if (!load_lines_or_value(value, true, lines, error)) return false;
        for (const auto& item : lines) {
            Target target;
            if (!parse_target_value(
                    item.second, target.spend_public,
                    target.view_public, error)) {
                error = item.first + ": " + error;
                return false;
            }
            std::array<std::uint8_t, 64> key{};
            std::copy(target.spend_public.begin(),
                      target.spend_public.end(), key.begin());
            std::copy(target.view_public.begin(),
                      target.view_public.end(), key.begin() + 32u);
            const auto found = unique.find(key);
            if (found == unique.end()) {
                target.occurrences.push_back({item.first, item.second});
                unique.emplace(key, targets.size());
                targets.push_back(std::move(target));
            } else {
                targets[found->second].occurrences.push_back(
                    {item.first, item.second});
            }
            if (logical != std::numeric_limits<std::uint64_t>::max()) {
                ++logical;
            }
        }
    }
    if (targets.empty()) {
        error = "no Monero targets were loaded";
        return false;
    }
    return true;
}

std::vector<std::string> split_words(const std::string& phrase) {
    std::stringstream input(phrase);
    std::vector<std::string> words;
    std::string word;
    while (input >> word) words.push_back(word);
    return words;
}

std::string utf8_prefix(const std::string& value,
                        unsigned codepoints) {
    std::size_t end = 0u;
    unsigned seen = 0u;
    while (end < value.size() && seen < codepoints) {
        const unsigned char ch =
            static_cast<unsigned char>(value[end]);
        std::size_t width = 1u;
        if ((ch & 0xe0u) == 0xc0u) width = 2u;
        else if ((ch & 0xf0u) == 0xe0u) width = 3u;
        else if ((ch & 0xf8u) == 0xf0u) width = 4u;
        if (end + width > value.size()) return value;
        end += width;
        ++seen;
    }
    return value.substr(0u, end);
}

int find_word(const MoneroWordlistView& list,
              const std::string& token) {
    for (std::size_t i = 0u; i < list.count; ++i) {
        const std::string word = list.words[i];
        if (token == word ||
            token == utf8_prefix(word, list.prefix_codepoints)) {
            return static_cast<int>(i);
        }
    }
    return -1;
}

bool language_selected(const std::string& requested,
                       const MoneroWordlistView& list) {
    const std::string wanted = lower_ascii(trim_copy(requested));
    return wanted == "auto" ||
        wanted == lower_ascii(list.id) ||
        wanted == lower_ascii(list.name);
}

bool parse_seed_template(
    const std::string& phrase,
    const std::string& source,
    const Options& options,
    SeedTemplate& result,
    std::string& error) {
    result.tokens = split_words(phrase);
    const MoneroWordlistView* lists = nullptr;
    std::size_t list_count = 0u;
    if (result.tokens.size() == 25u) {
        result.scheme = Scheme::Legacy;
        lists = kMoneroLegacyWordlists;
        list_count = kMoneroLegacyWordlistCount;
    } else if (result.tokens.size() == 16u) {
        result.scheme = Scheme::Polyseed;
        lists = kMoneroPolyseedWordlists;
        list_count = kMoneroPolyseedWordlistCount;
    } else {
        error = source +
            ": expected exactly 25 legacy or 16 Polyseed words";
        return false;
    }

    std::vector<const MoneroWordlistView*> matches;
    for (std::size_t li = 0u; li < list_count; ++li) {
        const MoneroWordlistView& list = lists[li];
        if (!language_selected(options.language, list)) continue;
        bool match = true;
        for (const std::string& token : result.tokens) {
            if (token != "?" && find_word(list, token) < 0) {
                match = false;
                break;
            }
        }
        if (match) matches.push_back(&list);
    }
    if (matches.empty()) {
        error = source +
            ": words do not match the selected Monero language";
        return false;
    }
    if (matches.size() != 1u) {
        error = source +
            ": language is ambiguous; use -monero-lang NAME";
        return false;
    }
    result.wordlist = matches[0];
    result.source = source;
    result.indices.assign(result.tokens.size(), -1);
    std::vector<std::uint64_t> radices;
    for (std::size_t i = 0u; i < result.tokens.size(); ++i) {
        if (result.tokens[i] == "?") {
            result.unknown_positions.push_back(i);
            radices.push_back(result.wordlist->count);
        } else {
            result.indices[i] =
            find_word(*result.wordlist, result.tokens[i]);
        }
    }
    // A complete phrase is still a one-candidate mixed-radix domain.  The
    // shared scheduler deliberately rejects an empty radix vector, so retain
    // one neutral radix and ignore its decoded digit below.
    if (radices.empty()) radices.push_back(1u);
    if (!result.domain.reset(radices, error)) {
        error = source + ": " + error;
        return false;
    }
    return true;
}

bool load_templates(const Options& options,
                    std::vector<SeedTemplate>& templates,
                    std::string& error) {
    for (const std::string& value : options.seed_values) {
        std::vector<std::pair<std::string, std::string>> lines;
        if (!load_lines_or_value(value, false, lines, error)) return false;
        for (const auto& item : lines) {
            SeedTemplate seed;
            if (!parse_seed_template(
                    item.second, item.first, options, seed, error)) {
                return false;
            }
            templates.push_back(std::move(seed));
        }
    }
    if (templates.empty()) {
        error = "no Monero seed templates were loaded";
        return false;
    }
    return true;
}

std::uint32_t crc32_bytes(const std::string& value) {
    std::uint32_t crc = 0xffffffffu;
    for (unsigned char byte : value) {
        crc ^= byte;
        for (unsigned bit = 0u; bit < 8u; ++bit) {
            crc = (crc >> 1u) ^
                (0xedb88320u & (0u - (crc & 1u)));
        }
    }
    return crc ^ 0xffffffffu;
}

std::uint16_t polyseed_mul2(std::uint16_t value) {
    static constexpr std::uint16_t table[8] =
        {5u,7u,1u,3u,13u,15u,9u,11u};
    if (value < 1024u) return static_cast<std::uint16_t>(value * 2u);
    return static_cast<std::uint16_t>(
        table[value % 8u] + 16u * ((value - 1024u) / 8u));
}

bool fill_indices(const SeedTemplate& seed,
                  const modeinfra::U256& ordinal,
                  std::vector<std::int32_t>& indices,
                  std::string& error) {
    std::vector<std::uint64_t> digits;
    if (!seed.domain.decode(ordinal, digits, error)) return false;
    indices = seed.indices;
    for (std::size_t i = 0u; i < seed.unknown_positions.size(); ++i) {
        indices[seed.unknown_positions[i]] =
            static_cast<std::int32_t>(digits[i]);
    }
    return true;
}

bool decode_legacy(const SeedTemplate& seed,
                   const std::vector<std::int32_t>& indices,
                   std::array<std::uint8_t, 32>& recovery) {
    std::string prefixes;
    for (std::size_t i = 0u; i < 24u; ++i) {
        prefixes += utf8_prefix(
            seed.wordlist->words[indices[i]],
            seed.wordlist->prefix_codepoints);
    }
    const std::size_t checksum_index = crc32_bytes(prefixes) % 24u;
    if (indices[24] != indices[checksum_index]) return false;
    const std::uint64_t count = seed.wordlist->count;
    for (std::size_t group = 0u; group < 8u; ++group) {
        const std::uint64_t w1 = indices[group * 3u];
        const std::uint64_t w2 = indices[group * 3u + 1u];
        const std::uint64_t w3 = indices[group * 3u + 2u];
        const std::uint64_t wide =
            w1 + count * (((count - w1) + w2) % count) +
            count * count * (((count - w2) + w3) % count);
        const std::uint32_t value = static_cast<std::uint32_t>(wide);
        if (value % count != w1) return false;
        recovery[group * 4u] = static_cast<std::uint8_t>(value);
        recovery[group * 4u + 1u] =
            static_cast<std::uint8_t>(value >> 8u);
        recovery[group * 4u + 2u] =
            static_cast<std::uint8_t>(value >> 16u);
        recovery[group * 4u + 3u] =
            static_cast<std::uint8_t>(value >> 24u);
    }
    return true;
}

bool decode_polyseed(const std::vector<std::int32_t>& indices,
                     std::array<std::uint8_t, 32>& secret,
                     std::uint32_t& birthday,
                     std::uint32_t& features) {
    std::uint16_t check = static_cast<std::uint16_t>(indices[15]);
    for (int i = 14; i >= 0; --i) {
        check = static_cast<std::uint16_t>(
            polyseed_mul2(check) ^ indices[i]);
    }
    if (check != 0u) return false;

    unsigned extra = 0u;
    unsigned secret_index = 0u;
    unsigned secret_bits = 0u;
    for (std::size_t i = 1u; i < 16u; ++i) {
        unsigned word = static_cast<unsigned>(indices[i]);
        extra = (extra << 1u) | (word & 1u);
        word >>= 1u;
        unsigned word_bits = 10u;
        while (word_bits != 0u) {
            if (secret_bits == 8u) {
                ++secret_index;
                secret_bits = 0u;
            }
            const unsigned chunk =
                std::min(word_bits, 8u - secret_bits);
            word_bits -= chunk;
            if (chunk < 8u) secret[secret_index] <<= chunk;
            secret[secret_index] |= static_cast<std::uint8_t>(
                (word >> word_bits) & ((1u << chunk) - 1u));
            secret_bits += chunk;
        }
    }
    birthday = extra & 1023u;
    features = extra >> 10u;
    return features == 0u;
}

bool make_candidate(const SeedTemplate& seed,
                    std::uint64_t template_index,
                    const modeinfra::U256& ordinal,
                    GpuCandidate& candidate,
                    std::string& error) {
    candidate = {};
    candidate.ordinal = ordinal.limbs;
    candidate.template_index = template_index;
    candidate.scheme = static_cast<std::uint32_t>(seed.scheme);
    std::vector<std::int32_t> indices;
    if (!fill_indices(seed, ordinal, indices, error)) return false;
    if (seed.scheme == Scheme::Legacy) {
        candidate.valid =
            decode_legacy(seed, indices, candidate.material) ? 1u : 0u;
    } else {
        candidate.valid = decode_polyseed(
            indices, candidate.material,
            candidate.birthday, candidate.features) ? 1u : 0u;
    }
    return true;
}

std::string render_phrase(const SeedTemplate& seed,
                          const modeinfra::U256& ordinal,
                          std::string& error) {
    std::vector<std::int32_t> indices;
    if (!fill_indices(seed, ordinal, indices, error)) return {};
    std::string phrase;
    for (std::size_t i = 0u; i < indices.size(); ++i) {
        if (i != 0u) phrase.push_back(' ');
        phrase += seed.wordlist->words[indices[i]];
    }
    return phrase;
}

bool derive_host(const GpuCandidate& candidate,
                 GpuDerived& result,
                 std::string& error) {
    std::array<std::uint8_t, 32> recovery = candidate.material;
    if (candidate.scheme ==
        static_cast<std::uint32_t>(Scheme::Polyseed)) {
        std::array<std::uint8_t, 32> salt = {
            'P','O','L','Y','S','E','E','D',' ','k','e','y',0,
            0xff,0xff,0xff
        };
        salt[20] = static_cast<std::uint8_t>(candidate.birthday);
        salt[21] = static_cast<std::uint8_t>(candidate.birthday >> 8u);
        salt[22] = static_cast<std::uint8_t>(candidate.birthday >> 16u);
        salt[23] = static_cast<std::uint8_t>(candidate.birthday >> 24u);
        salt[24] = static_cast<std::uint8_t>(candidate.features);
        salt[25] = static_cast<std::uint8_t>(candidate.features >> 8u);
        salt[26] = static_cast<std::uint8_t>(candidate.features >> 16u);
        salt[27] = static_cast<std::uint8_t>(candidate.features >> 24u);
        if (CCKeyDerivationPBKDF(
                kCCPBKDF2,
                reinterpret_cast<const char*>(candidate.material.data()),
                candidate.material.size(), salt.data(), salt.size(),
                kCCPRFHmacAlgSHA256, 10000u,
                recovery.data(), recovery.size()) != 0) {
            error = "host Polyseed PBKDF2 failed";
            return false;
        }
    }
    result.spend_private = recovery;
    sc_reduce32(result.spend_private.data());
    if (std::all_of(
            result.spend_private.begin(), result.spend_private.end(),
            [](std::uint8_t value) { return value == 0u; })) {
        error = "derived zero Monero spend scalar";
        return false;
    }
    ge_p3 point{};
    ge_scalarmult_base(&point, result.spend_private.data());
    ge_p3_tobytes(result.spend_public.data(), &point);
    result.view_private =
        keccak256(result.spend_private.data(), result.spend_private.size());
    sc_reduce32(result.view_private.data());
    ge_scalarmult_base(&point, result.view_private.data());
    ge_p3_tobytes(result.view_public.data(), &point);
    result.valid = 1u;
    return true;
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
    if (!metal_ok(metalSetDevice(device), "select Monero device", error) ||
        !allocate(
            buffers.candidates,
            static_cast<std::size_t>(batch_capacity) *
                sizeof(GpuCandidate),
            "allocate Monero candidates", error) ||
        !allocate(
            buffers.derived,
            static_cast<std::size_t>(batch_capacity) *
                sizeof(GpuDerived),
            "allocate Monero derived keys", error) ||
        !allocate(
            buffers.targets,
            static_cast<std::size_t>(target_capacity) *
                sizeof(GpuTarget),
            "allocate Monero target tile", error) ||
        !allocate(
            buffers.hits,
            static_cast<std::size_t>(kHitCapacity) * sizeof(GpuHit),
            "allocate Monero hits", error) ||
        !allocate(
            buffers.hit_count, sizeof(std::uint32_t),
            "allocate Monero hit count", error)) {
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
               "select Monero device", error) &&
        metal_ok(
            metalMemcpy(
                buffers.candidates, candidates.data(),
                candidates.size() * sizeof(GpuCandidate),
                metalMemcpyHostToDevice),
            "upload Monero candidates", error) &&
        metal_ok(
            metal_launch(
                "workerMoneroDerive", grid, kThreadgroupSize,
                buffers.candidates, count, buffers.derived),
            "launch Monero derive", error) &&
        metal_ok(
            metalDeviceSynchronize(),
            "synchronize Monero derive", error);
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
            "upload Monero target tile", error) ||
        !metal_ok(
            metalMemset(
                buffers.hit_count, 0, sizeof(std::uint32_t)),
            "reset Monero hit count", error)) {
        return false;
    }
    const std::uint32_t grid = static_cast<std::uint32_t>(
        (candidate_count + kThreadgroupSize - 1u) /
        kThreadgroupSize * kThreadgroupSize);
    if (!metal_ok(
            metal_launch(
                "workerMoneroLookup", grid, kThreadgroupSize,
                buffers.candidates, buffers.derived, candidate_count,
                buffers.targets, target_count, buffers.hits,
                buffers.hit_count, kHitCapacity),
            "launch Monero lookup", error) ||
        !metal_ok(
            metalDeviceSynchronize(),
            "synchronize Monero lookup", error)) {
        return false;
    }
    const auto started = std::chrono::steady_clock::now();
    raw_count = 0u;
    if (!metal_ok(
            metalMemcpy(
                &raw_count, buffers.hit_count, sizeof(raw_count),
                metalMemcpyDeviceToHost),
            "read Monero hit count", error)) {
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
            "read Monero hits", error)) {
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
            std::strcmp(argv[i], "-monero") == 0) {
            return true;
        }
    }
    return false;
}

void print_help() {
    std::cout << R"HELP([!] MAIN MODE: -monero  (legacy mnemonic / Polyseed recovery)
[!] ======================================================================
[!] Purpose:
[!] Recover a Monero wallet from a 25-word legacy mnemonic or 16-word
[!] Polyseed template and verify the exact private spend/view key pair
[!] against one or many standard, integrated, or subaddress targets.
[!]
[!] Inputs:
[!] -i PHRASE_OR_FILE               Repeatable seed/template input.
[!] A standalone ? is one unknown whole word. Files use one phrase per line;
[!] empty lines and # comments are ignored.
[!] -target ADDRESS|FILE            Repeatable Monero address or target file.
[!] -target SPEND_HEX:VIEW_HEX      Expert exact public-key pair.
[!] Duplicate targets are derived once while source occurrences are retained.
[!]
[!] Language / checksum:
[!] -monero-lang auto|NAME          Auto-detect by default; explicit NAME
[!]                                 resolves all-unknown/ambiguous templates.
[!] Official legacy and Polyseed language lists are embedded. Legacy CRC32
[!] and Polyseed GF(2^11) checksum pruning happen before expensive GPU work.
[!]
[!] GPU / memory / MultiGPU:
[!] -wallet-mem auto|all|NN%|SIZE   Hard unified-memory working-set budget.
[!] -n N                            Optional candidate batch cap.
[!] -device LIST                    Exact non-overlapping device scheduling.
[!] Derivation and lookup are split: each candidate performs PBKDF2/Keccak/
[!] Ed25519 once, while massive target sets stream through compact tiles.
[!]
[!] Statistics:
[!] SpeedThreadFunc is the only live statistics printer and reports
[!] Candidate/s plus primitive/Verify rates after Metal completion/readback.
[!] Target count is never used as an artificial speed multiplier.
[!]
[!] Output:
[!] MONERO_FOUND SCHEME:<legacy|polyseed> LANGUAGE:<name>
[!] TARGET:<source> MNEMONIC:<phrase> SPEND_PRIVATE:<64hex>
[!] VIEW_PRIVATE:<64hex> SPEND_PUBLIC:<64hex> VIEW_PUBLIC:<64hex>
[!] Every result is independently recomputed with Monero ref10 on the host.
[!]
[!] Examples:
[!] ./METAL_CRYPTO_TOOLKIT -monero -i legacy-template.txt \
[!]   -target 4... -monero-lang English -wallet-mem auto -save
[!] ./METAL_CRYPTO_TOOLKIT -monero -i polyseed-templates.txt \
[!]   -target targets.txt -wallet-mem all -device 0 -save -o monero_found.txt
[!]
[!] Limitations:
[!] Polyseed encrypted-feature phrases require decryption before this mode;
[!] unsupported feature bits are rejected. Search size remains exponential
[!] in the number of unknown words. No-match completion returns success;
[!] CLI/runtime errors return nonzero.
)HELP";
}

int run(int argc, char** argv, const RuntimeHooks& hooks) {
    Options options;
    std::string error;
    if (!parse_options(argc, argv, options, error)) {
        std::cerr << "[!] Monero CLI error: " << error << " [!]\n";
        return 2;
    }

    std::vector<Target> targets;
    std::uint64_t logical_targets = 0u;
    if (!load_targets(
            options, targets, logical_targets, error)) {
        std::cerr << "[!] Monero target error: " << error << " [!]\n";
        return 2;
    }
    std::vector<SeedTemplate> templates;
    if (!load_templates(options, templates, error)) {
        std::cerr << "[!] Monero template error: " << error << " [!]\n";
        return 2;
    }

    int device_count = 0;
    if (!metal_ok(
            metalGetDeviceCount(&device_count),
            "enumerate Metal devices", error)) {
        std::cerr << "[!] Monero runtime error: " << error << " [!]\n";
        return 1;
    }
    std::vector<modeinfra::MemoryDeviceInfo> memory_devices;
    for (int device : options.devices) {
        if (device < 0 || device >= device_count) {
            std::cerr << "[!] Monero CLI error: device " << device
                      << " is unavailable [!]\n";
            return 2;
        }
        metalDeviceProp properties{};
        if (!metal_ok(
                metalGetDeviceProperties(&properties, device),
                "query Monero device", error)) {
            std::cerr << "[!] Monero runtime error: " << error << " [!]\n";
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
        std::cerr << "[!] Monero CLI error: " << error << " [!]\n";
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
        std::cerr << "[!] Monero memory error: " << error << " [!]\n";
        return 1;
    }

    std::uint64_t target_capacity = std::max<std::uint64_t>(
        1u, std::min<std::uint64_t>(
            targets.size(),
            std::min<std::uint64_t>(
                std::numeric_limits<std::uint32_t>::max(),
                budget.per_device_budget / 3u / sizeof(GpuTarget))));
    const std::uint64_t fixed =
        static_cast<std::uint64_t>(kHitCapacity) * sizeof(GpuHit) +
        target_capacity * sizeof(GpuTarget) + sizeof(std::uint32_t);
    if (fixed >= budget.per_device_budget) {
        std::cerr << "[!] Monero memory error: target/hit buffers exceed "
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
            std::cerr << "[!] Monero allocation error: " << error
                      << " [!]\n";
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
        target.spend_public = targets[i].spend_public;
        target.view_public = targets[i].view_public;
        target.prefix = target_prefix(target.spend_public);
        target.source_index = i;
        gpu_targets.push_back(target);
    }
    std::sort(
        gpu_targets.begin(), gpu_targets.end(),
        [](const GpuTarget& left, const GpuTarget& right) {
            if (left.prefix != right.prefix) {
                return left.prefix < right.prefix;
            }
            if (left.spend_public != right.spend_public) {
                return left.spend_public < right.spend_public;
            }
            return left.view_public < right.view_public;
        });

    std::ofstream output;
    if (options.save || !options.output_path.empty()) {
        const std::string path = options.output_path.empty()
            ? "result.txt" : options.output_path;
        output.open(path, std::ios::app);
        if (!output) {
            for (auto& buffers : devices) release_buffers(buffers);
            std::cerr << "[!] Monero runtime error: cannot open '"
                      << path << "' [!]\n";
            return 1;
        }
    }

    std::cout << "[!] Monero templates: " << templates.size()
              << " | targets: " << targets.size() << " unique/"
              << logical_targets << " logical | devices: "
              << devices.size() << " | batch: " << batch_capacity
              << " | target tile: " << target_capacity
              << " | working set: " << allocated_bytes << " bytes [!]\n";

    modeinfra::ModeProgress& progress =
        modeinfra::global_mode_progress();
    progress.begin(
        "MONERO", modeinfra::ProgressUnit::Candidate,
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
        const SeedTemplate& seed = templates[template_index];
        modeinfra::U256 cursor{};
        const modeinfra::U256 end = seed.domain.size();
        while (modeinfra::compare(cursor, end) < 0 &&
               solved_logical < logical_targets) {
            modeinfra::U256 remaining{};
            if (!modeinfra::subtract_checked(end, cursor, remaining)) {
                error = "Monero scheduler underflow";
                result = 1;
                break;
            }
            std::uint64_t count =
                bounded_count(remaining, batch_capacity);
            if (count == 0u) {
                error = "Monero scheduler produced an empty window";
                result = 1;
                break;
            }
            bool completed = false;
            while (!completed) {
                std::vector<GpuCandidate> candidates(
                    static_cast<std::size_t>(count));
                std::uint64_t primitive_operations = 0u;
                for (std::uint64_t i = 0u; i < count; ++i) {
                    modeinfra::U256 ordinal{};
                    if (!modeinfra::add_checked(
                            cursor, modeinfra::U256::from_u64(i),
                            ordinal) ||
                        !make_candidate(
                            seed, template_index, ordinal,
                            candidates[static_cast<std::size_t>(i)],
                            error)) {
                        result = 1;
                        break;
                    }
                    if (candidates[static_cast<std::size_t>(i)].valid) {
                        primitive_operations = saturating_add(
                            primitive_operations,
                            seed.scheme == Scheme::Polyseed
                                ? 10003u : 3u);
                    }
                }
                if (result != 0) break;
                DeviceBuffers& buffers = devices[device_slot];
                if (!launch_derive(buffers, candidates, error)) {
                    result = 1;
                    break;
                }

                std::vector<GpuHit> resolved_hits;
                std::uint64_t readback_ns = 0u;
                bool retry = false;
                for (std::size_t tile = 0u;
                     tile < gpu_targets.size();
                     tile += static_cast<std::size_t>(target_capacity)) {
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
                            tile_count, count, tile_hits, raw_count,
                            tile_readback, error)) {
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
                if (result != 0) break;
                if (retry) {
                    if (count == 1u) {
                        error = "Monero hit buffer overflows for one candidate";
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
                        error = "Monero GPU hit has an invalid index";
                        result = 1;
                        break;
                    }
                    modeinfra::U256 ordinal{};
                    ordinal.limbs = hit.ordinal;
                    GpuCandidate candidate;
                    if (!make_candidate(
                            templates[hit.template_index],
                            hit.template_index, ordinal,
                            candidate, error) ||
                        candidate.valid == 0u) {
                        error = "Monero GPU hit failed mnemonic reconstruction";
                        result = 1;
                        break;
                    }
                    GpuDerived verified;
                    if (!derive_host(candidate, verified, error) ||
                        verified.spend_private != hit.spend_private ||
                        verified.view_private != hit.view_private ||
                        verified.spend_public != hit.spend_public ||
                        verified.view_public != hit.view_public) {
                        error = "Monero GPU hit failed independent host derivation";
                        result = 1;
                        break;
                    }
                    Target& target = targets[hit.target_index];
                    if (target.spend_public != verified.spend_public ||
                        target.view_public != verified.view_public) {
                        error = "Monero GPU hit resolved to the wrong target";
                        result = 1;
                        break;
                    }
                    if (target.solved) continue;
                    target.solved = true;
                    solved_logical = saturating_add(
                        solved_logical, target.occurrences.size());
                    ++founds;
                    if (hooks.increment_found) hooks.increment_found();
                    const SeedTemplate& matched =
                        templates[hit.template_index];
                    const std::string phrase =
                        render_phrase(matched, ordinal, error);
                    if (!error.empty() && phrase.empty()) {
                        result = 1;
                        break;
                    }
                    std::string sources;
                    for (std::size_t i = 0u;
                         i < target.occurrences.size(); ++i) {
                        if (i != 0u) sources.push_back(',');
                        sources += target.occurrences[i].source;
                    }
                    const std::string line =
                        "[+] MONERO_FOUND SCHEME:" +
                        std::string(
                            matched.scheme == Scheme::Legacy
                                ? "legacy" : "polyseed") +
                        " LANGUAGE:" + matched.wordlist->name +
                        " TARGET:" + sources +
                        " MNEMONIC:" + phrase +
                        " SPEND_PRIVATE:" +
                        hex_lower(
                            verified.spend_private.data(),
                            verified.spend_private.size()) +
                        " VIEW_PRIVATE:" +
                        hex_lower(
                            verified.view_private.data(),
                            verified.view_private.size()) +
                        " SPEND_PUBLIC:" +
                        hex_lower(
                            verified.spend_public.data(),
                            verified.spend_public.size()) +
                        " VIEW_PUBLIC:" +
                        hex_lower(
                            verified.view_public.data(),
                            verified.view_public.size());
                    if (!options.silent) std::cout << line << '\n';
                    if (output) {
                        output << line << '\n';
                        output.flush();
                    }
                }
                if (result != 0) break;
                progress.credit_completed(
                    count, primitive_operations, exact, readback_ns);
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
                    error = "Monero scheduler overflow";
                    result = 1;
                    break;
                }
                cursor = next;
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
        std::cerr << "[!] Monero runtime error: " << error << " [!]\n";
        return result;
    }
    std::cout << "[!] Monero search complete: solved "
              << solved_logical << '/' << logical_targets
              << " logical targets [!]\n";
    return 0;
}

} // namespace monero_mode
