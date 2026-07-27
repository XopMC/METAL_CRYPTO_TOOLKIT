#include "KeyRepairMode.h"

#include "../MetalBackend.h"
#include "../SecpPrecompute.h"
#include "../host_secp/secp256k1.h"
#include "../host_secp/secp256k1_field.h"
#include "../host_secp/secp256k1_group.h"
#include "../host_secp/secp256k1_scalar.h"
#include "../lib/hash/sha256.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <set>
#include <sstream>
#include <string>
#include <unordered_set>
#include <utility>
#include <vector>

namespace keyrepair {
namespace {

constexpr std::uint32_t kThreadgroupSize = 128u;
constexpr std::uint64_t kDefaultBatch = 1ull << 20u;
constexpr std::uint32_t kHitCapacity = 4096u;
constexpr std::uint32_t kMaximumMissing = 15u;
constexpr char kBase58Alphabet[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

enum class RepairType : std::uint32_t {
    Wif = 1u,
    Xprv = 2u,
    Xpub = 3u,
    Address = 4u,
    RawPrivate = 5u,
    RawPublic = 6u,
};

struct Hit {
    std::uint64_t ordinal = 0u;
    std::uint32_t decoded_len = 0u;
    std::uint32_t kind = 0u;
    std::array<std::uint8_t, 128> decoded{};
};

static_assert(sizeof(Hit) == 144u, "KeyRepair host/Metal hit layout mismatch");

struct InputTemplate {
    std::string text;
    std::string source;
    std::vector<std::uint32_t> missing;
    std::vector<std::uint8_t> device_text;
    std::array<std::uint8_t, 128> base58_prefix_little{};
    std::uint32_t base58_prefix_chars = 0u;
    std::uint32_t base58_prefix_little_len = 0u;
    std::uint32_t base58_prefix_leading = 0u;
    modeinfra::MixedRadixDomain domain;
    modeinfra::U256 combinations = modeinfra::U256::from_u64(1u);
};

struct Target {
    std::vector<std::uint8_t> serialized;
};

struct Options {
    RepairType type = RepairType::Wif;
    bool type_set = false;
    std::vector<std::string> inputs;
    std::vector<std::string> target_values;
    std::vector<int> devices{0};
    std::string output_path;
    bool save = false;
    bool silent = false;
    std::uint64_t batch = kDefaultBatch;
};

struct HostPrecompute {
    std::vector<secp256k1_ge_storage> entries;
    std::size_t pitch = 0u;
    unsigned int windows = 0u;
    unsigned int bits = 12u;
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

bool parse_u64(const std::string& text, std::uint64_t& out) {
    if (text.empty()) return false;
    std::size_t used = 0u;
    try {
        const unsigned long long parsed =
            std::stoull(text, &used, text.size() > 2u &&
                text[0] == '0' && (text[1] == 'x' || text[1] == 'X')
                    ? 16 : 10);
        if (used != text.size()) return false;
        out = static_cast<std::uint64_t>(parsed);
        return true;
    } catch (...) {
        return false;
    }
}

bool parse_type(const std::string& raw, RepairType& out) {
    const std::string value = lower_copy(raw);
    if (value == "wif") out = RepairType::Wif;
    else if (value == "xprv") out = RepairType::Xprv;
    else if (value == "xpub") out = RepairType::Xpub;
    else if (value == "address" || value == "base58-address")
        out = RepairType::Address;
    else if (value == "raw-private" || value == "raw-priv")
        out = RepairType::RawPrivate;
    else if (value == "raw-public" || value == "raw-pub")
        out = RepairType::RawPublic;
    else return false;
    return true;
}

const char* type_name(RepairType type) {
    switch (type) {
    case RepairType::Wif: return "WIF";
    case RepairType::Xprv: return "XPRV";
    case RepairType::Xpub: return "XPUB";
    case RepairType::Address: return "ADDRESS";
    case RepairType::RawPrivate: return "RAW_PRIVATE";
    case RepairType::RawPublic: return "RAW_PUBLIC";
    }
    return "UNKNOWN";
}

bool parse_device_list(const std::string& raw,
                       std::vector<int>& devices,
                       std::string& error) {
    std::set<int> unique;
    std::stringstream values(raw);
    std::string token;
    while (std::getline(values, token, ',')) {
        token = trim_copy(token);
        if (token.empty()) {
            error = "-device contains an empty element";
            return false;
        }
        std::size_t used = 0u;
        int device = -1;
        try {
            device = std::stoi(token, &used, 10);
        } catch (...) {
            error = "-device expects a comma-separated integer list";
            return false;
        }
        if (used != token.size() || device < 0) {
            error = "-device expects non-negative device indexes";
            return false;
        }
        unique.insert(device);
    }
    if (unique.empty()) {
        error = "-device list is empty";
        return false;
    }
    devices.assign(unique.begin(), unique.end());
    return true;
}

bool parse_options(int argc, char** argv, Options& options, std::string& error) {
    options.devices = {0};
    bool explicit_devices = false;
    for (int i = 1; i < argc; ++i) {
        const std::string arg(argv[i]);
        auto value = [&](const char* name) -> const char* {
            if (i + 1 >= argc) {
                error = std::string(name) + " requires a value";
                return nullptr;
            }
            return argv[++i];
        };
        if (arg == "-keyrepair") continue;
        if (arg == "-repair-type") {
            const char* raw = value("-repair-type");
            if (raw == nullptr) return false;
            if (!parse_type(raw, options.type)) {
                error = "unsupported -repair-type '" + std::string(raw) +
                    "' (use wif, xprv, xpub, address, raw-private, or raw-public)";
                return false;
            }
            options.type_set = true;
        } else if (arg == "-i") {
            const char* raw = value("-i");
            if (raw == nullptr) return false;
            options.inputs.emplace_back(raw);
        } else if (arg == "-target") {
            const char* raw = value("-target");
            if (raw == nullptr) return false;
            options.target_values.emplace_back(raw);
        } else if (arg == "-device") {
            const char* raw = value("-device");
            if (raw == nullptr) return false;
            if (!parse_device_list(raw, options.devices, error)) return false;
            explicit_devices = true;
        } else if (arg == "-o") {
            const char* raw = value("-o");
            if (raw == nullptr) return false;
            options.output_path = raw;
        } else if (arg == "-n") {
            const char* raw = value("-n");
            if (raw == nullptr) return false;
            if (!parse_u64(raw, options.batch) || options.batch == 0u) {
                error = "-n expects a positive candidate batch size";
                return false;
            }
            options.batch = std::min<std::uint64_t>(
                options.batch, std::numeric_limits<std::uint32_t>::max());
        } else if (arg == "-save") {
            options.save = true;
        } else if (arg == "-silent") {
            options.silent = true;
        } else if (arg == "-log") {
            const char* ignored = value("-log");
            if (ignored == nullptr) return false;
        } else if (!arg.empty() && arg[0] == '-') {
            error = "unknown -keyrepair parameter '" + arg + "'";
            return false;
        } else {
            options.inputs.push_back(arg);
        }
    }
    if (!options.type_set) {
        error = "-keyrepair requires -repair-type";
        return false;
    }
    if (options.inputs.empty()) {
        error = "-keyrepair requires at least one template through -i or a positional value";
        return false;
    }
    if (options.save && options.output_path.empty()) {
        options.output_path = "KEYREPAIR_FOUND.txt";
    }
    if (!explicit_devices) {
        options.devices = {0};
    }
    return true;
}

bool is_hex_or_missing(char c) {
    return c == '?' ||
        std::isxdigit(static_cast<unsigned char>(c)) != 0;
}

int base58_digit(char c) {
    const char* found = std::strchr(kBase58Alphabet, c);
    return found == nullptr ? -1 : static_cast<int>(found - kBase58Alphabet);
}

bool prepare_base58_template(InputTemplate& item, std::string& error) {
    item.device_text.resize(item.text.size(), 0u);
    for (std::size_t i = 0u; i < item.text.size(); ++i) {
        if (item.text[i] == '?') continue;
        const int digit = base58_digit(item.text[i]);
        if (digit < 0) {
            error = item.source + ": Base58 template contains an invalid character";
            return false;
        }
        item.device_text[i] = static_cast<std::uint8_t>(digit);
    }
    item.base58_prefix_chars = item.missing.empty()
        ? static_cast<std::uint32_t>(item.text.size())
        : item.missing.front();
    while (item.base58_prefix_leading < item.base58_prefix_chars &&
           item.device_text[item.base58_prefix_leading] == 0u) {
        ++item.base58_prefix_leading;
    }
    for (std::uint32_t i = item.base58_prefix_leading;
         i < item.base58_prefix_chars; ++i) {
        std::uint32_t carry = item.device_text[i];
        for (std::uint32_t j = 0u;
             j < item.base58_prefix_little_len; ++j) {
            carry +=
                static_cast<std::uint32_t>(item.base58_prefix_little[j]) *
                58u;
            item.base58_prefix_little[j] =
                static_cast<std::uint8_t>(carry & 0xffu);
            carry >>= 8u;
        }
        while (carry != 0u) {
            if (item.base58_prefix_little_len >=
                item.base58_prefix_little.size()) {
                error = item.source + ": Base58 prefix exceeds 128 decoded bytes";
                return false;
            }
            item.base58_prefix_little[item.base58_prefix_little_len++] =
                static_cast<std::uint8_t>(carry & 0xffu);
            carry >>= 8u;
        }
    }
    return true;
}

bool add_template(const std::string& raw,
                  const std::string& source,
                  RepairType type,
                  std::vector<InputTemplate>& out,
                  std::string& error) {
    const std::string text = trim_copy(raw);
    if (text.empty() || text[0] == '#') return true;
    InputTemplate item;
    item.text = text.substr(0u, text.find_first_of(" \t#"));
    item.source = source;
    const bool raw_hex =
        type == RepairType::RawPrivate || type == RepairType::RawPublic;
    const std::size_t expected =
        type == RepairType::RawPrivate ? 64u : 0u;
    if (raw_hex) {
        if ((expected != 0u && item.text.size() != expected) ||
            (type == RepairType::RawPublic &&
             item.text.size() != 66u && item.text.size() != 130u)) {
            error = source + ": raw template has an invalid hex length";
            return false;
        }
        for (char c : item.text) {
            if (!is_hex_or_missing(c)) {
                error = source + ": raw template accepts only hex digits and '?'";
                return false;
            }
        }
        item.device_text.assign(item.text.begin(), item.text.end());
    } else {
        if (item.text.empty() || item.text.size() > 128u) {
            error = source + ": Base58 template length must be 1..128";
            return false;
        }
        for (char c : item.text) {
            if (c == '?') continue;
            if (std::strchr(kBase58Alphabet, c) == nullptr) {
                error = source + ": Base58 template contains an invalid character";
                return false;
            }
        }
    }
    for (std::size_t i = 0u; i < item.text.size(); ++i) {
        if (item.text[i] == '?') {
            item.missing.push_back(static_cast<std::uint32_t>(i));
        }
    }
    if (item.missing.size() > kMaximumMissing) {
        error = source + ": at most " +
            std::to_string(kMaximumMissing) + " unknown positions are supported";
        return false;
    }
    if (!raw_hex && !prepare_base58_template(item, error)) return false;
    const std::uint64_t radix = raw_hex ? 16u : 58u;
    const std::vector<std::uint64_t> radices(
        std::max<std::size_t>(1u, item.missing.size()),
        item.missing.empty() ? 1u : radix);
    if (!item.domain.reset(radices, error)) {
        error = source + ": " + error;
        return false;
    }
    item.combinations = item.missing.empty()
        ? modeinfra::U256::from_u64(1u) : item.domain.size();
    out.push_back(std::move(item));
    return true;
}

bool load_templates(const Options& options,
                    std::vector<InputTemplate>& out,
                    std::string& error) {
    for (const std::string& input : options.inputs) {
        std::error_code ec;
        if (std::filesystem::is_regular_file(input, ec) && !ec) {
            std::ifstream file(input);
            if (!file) {
                error = "cannot open template file '" + input + "'";
                return false;
            }
            std::string line;
            std::size_t line_no = 0u;
            while (std::getline(file, line)) {
                ++line_no;
                if (!add_template(line, input + ":" + std::to_string(line_no),
                                  options.type, out, error)) {
                    return false;
                }
            }
        } else if (!add_template(input, "command line", options.type,
                                 out, error)) {
            return false;
        }
    }
    if (out.empty()) {
        error = "no repair templates were loaded";
        return false;
    }
    return true;
}

int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::vector<std::uint8_t> decode_hex(const std::string& text) {
    std::vector<std::uint8_t> out;
    if ((text.size() & 1u) != 0u) return out;
    out.reserve(text.size() / 2u);
    for (std::size_t i = 0u; i < text.size(); i += 2u) {
        const int high = hex_digit(text[i]);
        const int low = hex_digit(text[i + 1u]);
        if (high < 0 || low < 0) return {};
        out.push_back(static_cast<std::uint8_t>((high << 4) | low));
    }
    return out;
}

std::string hex_lower(const std::uint8_t* data, std::size_t size) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0u; i < size; ++i) {
        out << std::setw(2) << static_cast<unsigned>(data[i]);
    }
    return out.str();
}

bool parse_public_key(const std::vector<std::uint8_t>& bytes,
                      secp256k1_ge& point) {
    if (bytes.size() == 33u &&
        (bytes[0] == 0x02u || bytes[0] == 0x03u)) {
        secp256k1_fe x{};
        return secp256k1_fe_set_b32(&x, bytes.data() + 1u) != 0 &&
            secp256k1_ge_set_xo_var(&point, &x, bytes[0] == 0x03u) != 0;
    }
    if (bytes.size() == 65u && bytes[0] == 0x04u) {
        secp256k1_fe x{};
        secp256k1_fe y{};
        if (!secp256k1_fe_set_b32(&x, bytes.data() + 1u) ||
            !secp256k1_fe_set_b32(&y, bytes.data() + 33u) ||
            !secp256k1_ge_set_xo_var(
                &point, &x, secp256k1_fe_is_odd(&y))) {
            return false;
        }
        secp256k1_fe_normalize_var(&y);
        return secp256k1_fe_equal(&point.y, &y) != 0;
    }
    return false;
}

bool load_target_token(const std::string& token,
                       std::vector<Target>& targets,
                       std::unordered_set<std::string>& seen,
                       std::string& error) {
    const std::vector<std::uint8_t> bytes = decode_hex(trim_copy(token));
    secp256k1_ge point{};
    if (!parse_public_key(bytes, point)) {
        error = "target must be a valid 33/65-byte secp256k1 public key";
        return false;
    }
    secp256k1_fe_normalize_var(&point.x);
    secp256k1_fe_normalize_var(&point.y);
    std::array<std::uint8_t, 33> canonical{};
    canonical[0] = static_cast<std::uint8_t>(
        0x02u + secp256k1_fe_is_odd(&point.y));
    secp256k1_fe_get_b32(canonical.data() + 1u, &point.x);
    const std::string normalized =
        hex_lower(canonical.data(), canonical.size());
    if (seen.insert(normalized).second) targets.push_back({bytes});
    return true;
}

bool load_targets(const Options& options,
                  std::vector<Target>& targets,
                  std::string& error) {
    std::unordered_set<std::string> seen;
    for (const std::string& value : options.target_values) {
        std::error_code ec;
        if (std::filesystem::is_regular_file(value, ec) && !ec) {
            std::ifstream file(value);
            if (!file) {
                error = "cannot open target file '" + value + "'";
                return false;
            }
            std::string line;
            while (std::getline(file, line)) {
                line = trim_copy(line);
                if (line.empty() || line[0] == '#') continue;
                const std::string token = line.substr(
                    0u, line.find_first_of(" \t#"));
                if (!load_target_token(token, targets, seen, error)) return false;
            }
        } else if (!load_target_token(value, targets, seen, error)) {
            return false;
        }
    }
    if (options.type == RepairType::RawPrivate && targets.empty()) {
        error = "raw-private repair requires at least one related -target public key";
        return false;
    }
    return true;
}

bool decode_base58(const std::string& text,
                   std::vector<std::uint8_t>& decoded) {
    std::array<std::uint8_t, 128> little{};
    std::size_t little_len = 0u;
    std::size_t leading = 0u;
    while (leading < text.size() && text[leading] == '1') ++leading;
    for (std::size_t i = leading; i < text.size(); ++i) {
        const int digit = base58_digit(text[i]);
        if (digit < 0) return false;
        std::uint32_t carry = static_cast<std::uint32_t>(digit);
        for (std::size_t j = 0u; j < little_len; ++j) {
            carry += static_cast<std::uint32_t>(little[j]) * 58u;
            little[j] = static_cast<std::uint8_t>(carry & 0xffu);
            carry >>= 8u;
        }
        while (carry != 0u) {
            if (little_len >= little.size()) return false;
            little[little_len++] =
                static_cast<std::uint8_t>(carry & 0xffu);
            carry >>= 8u;
        }
    }
    decoded.assign(leading + little_len, 0u);
    for (std::size_t i = 0u; i < little_len; ++i) {
        decoded[leading + i] = little[little_len - 1u - i];
    }
    return decoded.size() >= 5u;
}

bool checksum_valid(const std::vector<std::uint8_t>& decoded) {
    if (decoded.size() < 5u) return false;
    std::array<std::uint8_t, 32> first{};
    std::array<std::uint8_t, 32> second{};
    sha256(const_cast<std::uint8_t*>(decoded.data()),
           decoded.size() - 4u, first.data());
    sha256(first.data(), first.size(), second.data());
    return std::memcmp(second.data(),
                       decoded.data() + decoded.size() - 4u, 4u) == 0;
}

std::string fill_template(const InputTemplate& item,
                          RepairType type,
                          const modeinfra::U256& ordinal,
                          std::string& error) {
    std::string value = item.text;
    const bool raw =
        type == RepairType::RawPrivate || type == RepairType::RawPublic;
    std::vector<std::uint64_t> digits;
    if (!item.domain.decode(ordinal, digits, error)) return {};
    for (std::size_t index = 0u; index < item.missing.size(); ++index) {
        const std::uint32_t position = item.missing[index];
        const std::uint64_t digit = digits[index];
        value[position] = raw
            ? static_cast<char>(digit < 10u
                ? '0' + digit : 'a' + digit - 10u)
            : kBase58Alphabet[digit];
    }
    return value;
}

bool scalar_valid(const std::uint8_t* data) {
    secp256k1_scalar scalar{};
    int overflow = 0;
    secp256k1_scalar_set_b32(&scalar, data, &overflow);
    return overflow == 0 && !secp256k1_scalar_is_zero(&scalar);
}

bool build_host_precompute(HostPrecompute& result, std::string& error) {
    return build_secp256k1_precompute_table_host(
        result.bits, result.entries, result.pitch, result.windows, error);
}

bool derive_public(const std::uint8_t private_key[32],
                   const HostPrecompute& precompute,
                   std::array<std::uint8_t, 65>& public_key) {
    secp256k1_scalar scalar{};
    int overflow = 0;
    secp256k1_scalar_set_b32(&scalar, private_key, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&scalar)) return false;
    secp256k1_gej jacobian{};
    secp256k1_ecmult_big(&jacobian, &scalar, precompute.entries.data(),
                         precompute.pitch,
                         static_cast<int>(precompute.windows),
                         precompute.bits);
    if (jacobian.infinity != 0) return false;
    secp256k1_ge point{};
    secp256k1_ge_set_gej(&point, &jacobian);
    secp256k1_fe_normalize_var(&point.x);
    secp256k1_fe_normalize_var(&point.y);
    public_key[0] = 0x04u;
    secp256k1_fe_get_b32(public_key.data() + 1u, &point.x);
    secp256k1_fe_get_b32(public_key.data() + 33u, &point.y);
    return true;
}

bool public_matches(const std::array<std::uint8_t, 65>& public_key,
                    const Target& target) {
    if (target.serialized.size() == 65u) {
        return std::equal(public_key.begin(), public_key.end(),
                          target.serialized.begin());
    }
    return target.serialized.size() == 33u &&
        target.serialized[0] ==
            static_cast<std::uint8_t>(0x02u + (public_key[64] & 1u)) &&
        std::equal(public_key.begin() + 1u, public_key.begin() + 33u,
                   target.serialized.begin() + 1u);
}

std::vector<std::uint8_t> serialize_public_point(secp256k1_ge point,
                                                 bool compressed) {
    secp256k1_fe_normalize_var(&point.x);
    secp256k1_fe_normalize_var(&point.y);
    std::vector<std::uint8_t> result(compressed ? 33u : 65u, 0u);
    if (compressed) {
        result[0] = static_cast<std::uint8_t>(
            0x02u + secp256k1_fe_is_odd(&point.y));
        secp256k1_fe_get_b32(result.data() + 1u, &point.x);
    } else {
        result[0] = 0x04u;
        secp256k1_fe_get_b32(result.data() + 1u, &point.x);
        secp256k1_fe_get_b32(result.data() + 33u, &point.y);
    }
    return result;
}

bool same_public_point(const std::vector<std::uint8_t>& left,
                       const std::vector<std::uint8_t>& right) {
    secp256k1_ge left_point{};
    secp256k1_ge right_point{};
    if (!parse_public_key(left, left_point) ||
        !parse_public_key(right, right_point)) {
        return false;
    }
    return serialize_public_point(left_point, true) ==
        serialize_public_point(right_point, true);
}

bool valid_base58_payload(RepairType type,
                          const std::vector<std::uint8_t>& decoded) {
    if (!checksum_valid(decoded)) return false;
    const std::size_t payload = decoded.size() - 4u;
    if (type == RepairType::Wif) {
        return (payload == 33u ||
                (payload == 34u && decoded[33] == 0x01u)) &&
            (decoded[0] == 0x80u || decoded[0] == 0xefu) &&
            scalar_valid(decoded.data() + 1u);
    }
    if (type == RepairType::Xprv || type == RepairType::Xpub) {
        if (payload != 78u) return false;
        const std::uint32_t version =
            (static_cast<std::uint32_t>(decoded[0]) << 24u) |
            (static_cast<std::uint32_t>(decoded[1]) << 16u) |
            (static_cast<std::uint32_t>(decoded[2]) << 8u) |
            static_cast<std::uint32_t>(decoded[3]);
        static const std::set<std::uint32_t> private_versions{
            0x0488ade4u, 0x049d7878u, 0x04b2430cu,
            0x0295b005u, 0x02aa7a99u, 0x04358394u};
        static const std::set<std::uint32_t> public_versions{
            0x0488b21eu, 0x049d7cb2u, 0x04b24746u,
            0x0295b43fu, 0x02aa7ed3u, 0x043587cfu};
        if (type == RepairType::Xprv) {
            return private_versions.count(version) != 0u &&
                decoded[45] == 0u && scalar_valid(decoded.data() + 46u);
        }
        if (public_versions.count(version) == 0u) return false;
        std::vector<std::uint8_t> key(
            decoded.begin() + 45u, decoded.begin() + 78u);
        secp256k1_ge point{};
        return parse_public_key(key, point);
    }
    return type == RepairType::Address && payload == 21u &&
        (decoded[0] == 0x00u || decoded[0] == 0x05u ||
         decoded[0] == 0x6fu || decoded[0] == 0xc4u);
}

bool hit_matches_targets(RepairType type,
                         const Hit& hit,
                         const std::vector<Target>& targets,
                         const HostPrecompute* precompute) {
    if (targets.empty()) return true;
    const std::uint8_t* private_key = nullptr;
    if (type == RepairType::Wif && hit.decoded_len >= 37u) {
        private_key = hit.decoded.data() + 1u;
    } else if (type == RepairType::Xprv && hit.decoded_len == 82u) {
        private_key = hit.decoded.data() + 46u;
    } else {
        return true;
    }
    if (precompute == nullptr) return false;
    std::array<std::uint8_t, 65> public_key{};
    if (!derive_public(private_key, *precompute, public_key)) return false;
    return std::any_of(targets.begin(), targets.end(),
                       [&](const Target& target) {
                           return public_matches(public_key, target);
                       });
}

bool metal_ok(metalError_t status,
              const std::string& operation,
              std::string& error) {
    if (status == metalSuccess) return true;
    error = operation + ": " + metalGetErrorString(status);
    return false;
}

template <typename T>
bool allocate_device(T*& pointer,
                     std::size_t bytes,
                     const std::string& name,
                     std::string& error) {
    return metal_ok(metalMalloc(&pointer, bytes), name, error);
}

struct DeviceBuffers {
    std::uint8_t* template_text = nullptr;
    std::uint32_t* missing = nullptr;
    std::uint32_t* start_digits = nullptr;
    std::uint8_t* base58_prefix_little = nullptr;
    std::uint8_t* target = nullptr;
    secp256k1_ge_storage* precompute = nullptr;
    Hit* hits = nullptr;
    std::uint32_t* hit_count = nullptr;
    std::uint64_t allocated = 0u;

    void release() {
        if (template_text) metalFree(template_text);
        if (missing) metalFree(missing);
        if (start_digits) metalFree(start_digits);
        if (base58_prefix_little) metalFree(base58_prefix_little);
        if (target) metalFree(target);
        if (precompute) metalFree(precompute);
        if (hits) metalFree(hits);
        if (hit_count) metalFree(hit_count);
        template_text = nullptr;
        missing = nullptr;
        start_digits = nullptr;
        base58_prefix_little = nullptr;
        target = nullptr;
        precompute = nullptr;
        hits = nullptr;
        hit_count = nullptr;
        allocated = 0u;
    }
    ~DeviceBuffers() { release(); }
};

bool prepare_buffers(const InputTemplate& item,
                     RepairType type,
                     const Target* target,
                     const HostPrecompute* precompute,
                     DeviceBuffers& buffers,
                     std::string& error) {
    const std::size_t template_bytes = item.text.size();
    const std::size_t missing_bytes =
        std::max<std::size_t>(1u, item.missing.size()) *
        sizeof(std::uint32_t);
    if (!allocate_device(buffers.template_text, template_bytes,
                         "allocate keyrepair template", error) ||
        !allocate_device(buffers.missing, missing_bytes,
                         "allocate keyrepair positions", error) ||
        !allocate_device(buffers.start_digits, missing_bytes,
                         "allocate keyrepair window digits", error) ||
        !allocate_device(buffers.hits,
                         sizeof(Hit) * kHitCapacity,
                         "allocate keyrepair hits", error) ||
        !allocate_device(buffers.hit_count,
                         sizeof(std::uint32_t),
                         "allocate keyrepair hit count", error)) {
        return false;
    }
    buffers.allocated += template_bytes + missing_bytes * 2u +
        sizeof(Hit) * kHitCapacity + sizeof(std::uint32_t);
    if (!metal_ok(metalMemcpy(buffers.template_text, item.device_text.data(),
                              template_bytes, metalMemcpyHostToDevice),
                  "upload keyrepair template", error) ||
        (!item.missing.empty() &&
         !metal_ok(metalMemcpy(buffers.missing, item.missing.data(),
                               item.missing.size() * sizeof(std::uint32_t),
                               metalMemcpyHostToDevice),
                   "upload keyrepair positions", error))) {
        return false;
    }
    if (type != RepairType::RawPrivate &&
        type != RepairType::RawPublic) {
        if (!allocate_device(
                buffers.base58_prefix_little,
                item.base58_prefix_little.size(),
                "allocate keyrepair Base58 prefix", error) ||
            !metal_ok(
                metalMemcpy(
                    buffers.base58_prefix_little,
                    item.base58_prefix_little.data(),
                    item.base58_prefix_little.size(),
                    metalMemcpyHostToDevice),
                "upload keyrepair Base58 prefix", error)) {
            return false;
        }
        buffers.allocated += item.base58_prefix_little.size();
    }
    if (target != nullptr) {
        if (!allocate_device(buffers.target, target->serialized.size(),
                             "allocate keyrepair target", error) ||
            !metal_ok(metalMemcpy(buffers.target, target->serialized.data(),
                                  target->serialized.size(),
                                  metalMemcpyHostToDevice),
                      "upload keyrepair target", error)) {
            return false;
        }
        buffers.allocated += target->serialized.size();
    }
    if (precompute != nullptr) {
        const std::size_t bytes =
            precompute->entries.size() * sizeof(secp256k1_ge_storage);
        if (!allocate_device(buffers.precompute, bytes,
                             "allocate keyrepair secp table", error) ||
            !metal_ok(metalMemcpy(buffers.precompute,
                                  precompute->entries.data(), bytes,
                                  metalMemcpyHostToDevice),
                      "upload keyrepair secp table", error)) {
            return false;
        }
        buffers.allocated += bytes;
    }
    return true;
}

bool verify_and_format(const InputTemplate& item,
                       RepairType type,
                       const Hit& hit,
                       const modeinfra::U256& window_start,
                       const std::vector<Target>& targets,
                       const HostPrecompute* precompute,
                       std::string& line) {
    modeinfra::U256 absolute_ordinal;
    if (!modeinfra::add_checked(
            window_start, modeinfra::U256::from_u64(hit.ordinal),
            absolute_ordinal) ||
        modeinfra::compare(absolute_ordinal, item.combinations) >= 0 ||
        hit.kind != static_cast<std::uint32_t>(type)) {
        return false;
    }
    std::string decode_error;
    const std::string value =
        fill_template(item, type, absolute_ordinal, decode_error);
    if (value.empty() && !item.text.empty()) return false;
    if (type == RepairType::RawPrivate) {
        const std::vector<std::uint8_t> private_key = decode_hex(value);
        if (private_key.size() != 32u || !scalar_valid(private_key.data()) ||
            precompute == nullptr) {
            return false;
        }
        std::array<std::uint8_t, 65> public_key{};
        if (!derive_public(private_key.data(), *precompute, public_key) ||
            !std::any_of(targets.begin(), targets.end(),
                         [&](const Target& target) {
                             return public_matches(public_key, target);
                         })) {
            return false;
        }
        line = "[+] KEYREPAIR:RAW_PRIVATE:SOURCE:" + item.source +
            ":PRIVATE:" + value + ":PUBLIC:" +
            hex_lower(public_key.data(), public_key.size());
        return true;
    }
    if (type == RepairType::RawPublic) {
        const std::vector<std::uint8_t> public_key = decode_hex(value);
        secp256k1_ge point{};
        if (!parse_public_key(public_key, point)) return false;
        if (!targets.empty() &&
            !std::any_of(targets.begin(), targets.end(),
                         [&](const Target& target) {
                             return same_public_point(
                                 target.serialized, public_key);
                         })) {
            return false;
        }
        line = "[+] KEYREPAIR:RAW_PUBLIC:SOURCE:" + item.source +
            ":PUBLIC:" + value;
        return true;
    }
    std::vector<std::uint8_t> decoded;
    if (!decode_base58(value, decoded) ||
        !valid_base58_payload(type, decoded) ||
        decoded.size() != hit.decoded_len ||
        !std::equal(decoded.begin(), decoded.end(), hit.decoded.begin()) ||
        !hit_matches_targets(type, hit, targets, precompute)) {
        return false;
    }
    line = "[+] KEYREPAIR:" + std::string(type_name(type)) +
        ":SOURCE:" + item.source + ":VALUE:" + value;
    if (type == RepairType::Wif) {
        line += ":PRIVATE:" +
            hex_lower(decoded.data() + 1u, 32u);
    } else if (type == RepairType::Xprv) {
        line += ":PRIVATE:" +
            hex_lower(decoded.data() + 46u, 32u);
    } else if (type == RepairType::Address) {
        line += ":PAYLOAD:" +
            hex_lower(decoded.data(), decoded.size() - 4u);
    }
    return true;
}

bool launch_batch(RepairType type,
                  const InputTemplate& item,
                  const Target* target,
                  const HostPrecompute* precompute,
                  DeviceBuffers& buffers,
                  const modeinfra::U256& start,
                  std::uint64_t count,
                  std::vector<Hit>& hits,
                  std::uint32_t& raw_count,
                  std::uint64_t& readback_ns,
                  std::string& error) {
    if (count == 0u || count > std::numeric_limits<std::uint32_t>::max()) {
        error = "invalid keyrepair batch size";
        return false;
    }
    if (!metal_ok(metalMemset(buffers.hit_count, 0,
                              sizeof(std::uint32_t)),
                  "clear keyrepair hit count", error)) {
        return false;
    }
    const std::uint32_t text_len =
        static_cast<std::uint32_t>(item.text.size());
    const std::uint32_t missing_count =
        static_cast<std::uint32_t>(item.missing.size());
    const std::uint32_t kind = static_cast<std::uint32_t>(type);
    const std::uint64_t range_count = count;
    std::vector<std::uint64_t> decoded_digits;
    if (!item.domain.decode(start, decoded_digits, error)) return false;
    std::vector<std::uint32_t> start_digits(decoded_digits.size(), 0u);
    std::transform(decoded_digits.begin(), decoded_digits.end(),
                   start_digits.begin(), [](std::uint64_t digit) {
                       return static_cast<std::uint32_t>(digit);
                   });
    if (!metal_ok(
            metalMemcpy(buffers.start_digits, start_digits.data(),
                        start_digits.size() * sizeof(std::uint32_t),
                        metalMemcpyHostToDevice),
            "upload keyrepair window digits", error)) {
        return false;
    }
    const std::uint32_t grid = static_cast<std::uint32_t>(
        (count + kThreadgroupSize - 1u) / kThreadgroupSize);
    metalError_t status = metalSuccess;
    if (type == RepairType::RawPrivate) {
        const std::uint32_t target_len =
            static_cast<std::uint32_t>(target->serialized.size());
        const std::uint64_t pitch =
            static_cast<std::uint64_t>(precompute->pitch);
        status = metal_launch("keyRepairRawPrivate", grid, kThreadgroupSize,
                              buffers.template_text, text_len,
                              buffers.missing, missing_count,
                              buffers.start_digits, range_count,
                              buffers.target, target_len,
                              buffers.precompute, pitch,
                              buffers.hits, buffers.hit_count, kHitCapacity);
    } else if (type == RepairType::RawPublic) {
        const std::uint32_t target_len = target == nullptr ? 0u :
            static_cast<std::uint32_t>(target->serialized.size());
        status = metal_launch("keyRepairRawPublic", grid, kThreadgroupSize,
                              buffers.template_text, text_len,
                              buffers.missing, missing_count,
                              buffers.start_digits, range_count,
                              buffers.target, target_len,
                              buffers.hits, buffers.hit_count, kHitCapacity);
    } else {
        status = metal_launch("keyRepairBase58Check", grid, kThreadgroupSize,
                              buffers.template_text, text_len,
                              buffers.missing, missing_count, kind,
                              buffers.start_digits, range_count,
                              buffers.base58_prefix_little,
                              item.base58_prefix_chars,
                              item.base58_prefix_little_len,
                              item.base58_prefix_leading,
                              buffers.hits, buffers.hit_count, kHitCapacity);
    }
    if (!metal_ok(status, "launch keyrepair kernel", error) ||
        !metal_ok(metalDeviceSynchronize(),
                  "synchronize keyrepair kernel", error)) {
        return false;
    }
    const auto read_started = std::chrono::steady_clock::now();
    if (!metal_ok(metalMemcpy(&raw_count, buffers.hit_count,
                              sizeof(raw_count), metalMemcpyDeviceToHost),
                  "read keyrepair hit count", error)) {
        return false;
    }
    const std::uint32_t stored = std::min(raw_count, kHitCapacity);
    hits.resize(stored);
    if (stored != 0u &&
        !metal_ok(metalMemcpy(hits.data(), buffers.hits,
                              static_cast<std::size_t>(stored) * sizeof(Hit),
                              metalMemcpyDeviceToHost),
                  "read keyrepair hits", error)) {
        return false;
    }
    readback_ns = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - read_started).count());
    return true;
}

bool emit_result(const std::string& line,
                 std::ofstream* output,
                 bool silent) {
    if (!silent) std::cout << line << '\n';
    if (output != nullptr) {
        *output << line << '\n';
        output->flush();
        return static_cast<bool>(*output);
    }
    return true;
}

} // namespace

bool requested(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-keyrepair") == 0) return true;
    }
    return false;
}

void print_help() {
    std::cout << R"HELP([!] MAIN MODE: -keyrepair  (GPU checksum-first key repair)
[!] ======================================================================
[!] Purpose:
[!] Recover limited unknown/corrupted positions in WIF, extended keys,
[!] raw secp256k1 keys, and Base58Check address payloads.
[!]
[!] Required:
[!] -repair-type TYPE              wif | xprv | xpub | address |
[!]                                raw-private | raw-public
[!] -i FILE|TEMPLATE               Template file or one literal template.
[!]                                Repeat -i or use positional templates.
[!]                                '?' marks an unknown Base58 or hex character.
[!]
[!] Related targets:
[!] -target PUBKEY|FILE            Repeatable 33/65-byte secp256k1 public key.
[!]                                Required for raw-private. Optional for WIF,
[!]                                xprv and raw-public as an identity check.
[!]
[!] GPU / scheduling:
[!] -device LIST                   Metal device indexes, comma separated.
[!] -n NUMBER                      Candidate window (default 1048576).
[!] Selected devices receive deterministic non-overlapping U256 shards.
[!] Every completed window is credited only after GPU completion/readback.
[!] Overflow is retried with a smaller uncredited window.
[!]
[!] Output:
[!] -o FILE                        Append verified results to FILE.
[!] -save                          Use KEYREPAIR_FOUND.txt when -o is absent.
[!] -silent                        Suppress result lines on stdout.
[!] Statistics are printed only by SpeedThreadFunc as Candidate/s and Verify/s.
[!]
[!] Examples:
[!] ./METAL_CRYPTO_TOOLKIT -keyrepair -repair-type wif -i "KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU73sVHnoW?" -n 128
[!] ./METAL_CRYPTO_TOOLKIT -keyrepair -repair-type raw-private -i "000000000000000000000000000000000000000000000000000000000000000?" -target 0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798
[!] ./METAL_CRYPTO_TOOLKIT -keyrepair -repair-type address -i "1BoatSLRHtKNngkdXEeobR76b53LETtpy?"
[!]
[!] Limitations:
[!] At most 15 unknown characters. Scheduling and device shards use exact U256;
[!] each GPU window remains bounded by the configured -n batch size.
[!] A checksum-valid address is reported only as an address/payload; it is never
[!] described as a recovered private key. Raw-private always needs a public-key
[!] target. Raw-public without a target may have multiple curve-valid answers.
[!]
[!] Errors:
[!] CLI/format errors return 2; Metal/runtime failures return 1; an exhausted
[!] valid search returns 0 even when no candidate is found.
)HELP";
}

int run(int argc, char** argv, const RuntimeHooks& hooks) {
    Options options;
    std::string error;
    if (!parse_options(argc, argv, options, error)) {
        std::cerr << "[!] KeyRepair CLI error: " << error << " [!]\n";
        return 2;
    }
    std::vector<InputTemplate> inputs;
    if (!load_templates(options, inputs, error)) {
        std::cerr << "[!] KeyRepair input error: " << error << " [!]\n";
        return 2;
    }
    std::vector<Target> targets;
    if (!load_targets(options, targets, error)) {
        std::cerr << "[!] KeyRepair target error: " << error << " [!]\n";
        return 2;
    }
    int device_count = 0;
    if (!metal_ok(metalGetDeviceCount(&device_count),
                  "query Metal devices", error)) {
        std::cerr << "[!] KeyRepair runtime error: " << error << " [!]\n";
        return 1;
    }
    for (int device : options.devices) {
        if (device >= device_count) {
            std::cerr << "[!] KeyRepair CLI error: Metal device " << device
                      << " is not available [!]\n";
            return 2;
        }
    }

    HostPrecompute precompute;
    const bool needs_precompute =
        options.type == RepairType::RawPrivate ||
        ((!targets.empty()) &&
         (options.type == RepairType::Wif ||
          options.type == RepairType::Xprv));
    if (needs_precompute &&
        !build_host_precompute(precompute, error)) {
        std::cerr << "[!] KeyRepair runtime error: " << error << " [!]\n";
        return 1;
    }

    std::ofstream output;
    if (!options.output_path.empty()) {
        output.open(options.output_path, std::ios::app);
        if (!output) {
            std::cerr << "[!] KeyRepair CLI error: cannot open output file '"
                      << options.output_path << "' [!]\n";
            return 2;
        }
    }

    modeinfra::U256 total_candidates{};
    for (const InputTemplate& input : inputs) {
        modeinfra::U256 next;
        if (!modeinfra::add_checked(
                total_candidates, input.combinations, next)) {
            std::cerr
                << "[!] KeyRepair input error: aggregate repair space "
                   "exceeds 256 bits [!]\n";
            return 2;
        }
        total_candidates = next;
    }

    modeinfra::ModeProgress& progress = modeinfra::global_mode_progress();
    progress.begin("KEYREPAIR", modeinfra::ProgressUnit::Candidate,
                   modeinfra::ProgressPhase::Load);
    progress.set_targets(inputs.size(), inputs.size(), 0u);
    progress.set_phase(modeinfra::ProgressPhase::Search);

    std::uint64_t founds = 0u;
    std::uint64_t solved = 0u;
    std::unordered_set<std::string> emitted;
    if (!options.silent) {
        std::cout << "[!] KeyRepair type: " << type_name(options.type)
                  << "; templates: " << inputs.size()
                  << "; candidate space: 0x"
                  << modeinfra::u256_hex(total_candidates)
                  << "; targets: " << targets.size() << " [!]\n";
    }

    for (std::size_t input_index = 0u;
         input_index < inputs.size(); ++input_index) {
        const InputTemplate& item = inputs[input_index];
        bool input_solved = false;
        const std::size_t target_passes =
            (options.type == RepairType::RawPrivate ||
             (options.type == RepairType::RawPublic && !targets.empty()))
                ? targets.size() : 1u;
        for (std::size_t target_index = 0u;
             target_index < target_passes && !input_solved;
             ++target_index) {
            const Target* target =
                target_passes == 1u &&
                !(options.type == RepairType::RawPrivate ||
                  (options.type == RepairType::RawPublic && !targets.empty()))
                    ? nullptr : &targets[target_index];
            Target normalized_target;
            if (target != nullptr &&
                options.type == RepairType::RawPublic &&
                target->serialized.size() != item.text.size() / 2u) {
                secp256k1_ge target_point{};
                if (!parse_public_key(target->serialized, target_point)) {
                    progress.end();
                    std::cerr
                        << "[!] KeyRepair runtime error: invalid normalized "
                           "raw-public target [!]\n";
                    return 1;
                }
                normalized_target.serialized = serialize_public_point(
                    target_point, item.text.size() == 66u);
                target = &normalized_target;
            }
            const HostPrecompute* host_precompute =
                needs_precompute ? &precompute : nullptr;
            for (std::size_t shard_index = 0u;
                 shard_index < options.devices.size() && !input_solved;
                 ++shard_index) {
                const int device = options.devices[shard_index];
                modeinfra::U256 shard_begin;
                modeinfra::U256 shard_count;
                if (!item.domain.split(
                        shard_index, options.devices.size(),
                        shard_begin, shard_count, error)) {
                    progress.end();
                    std::cerr << "[!] KeyRepair runtime error: "
                              << error << " [!]\n";
                    return 1;
                }
                if (shard_count.is_zero()) continue;
                modeinfra::U256 shard_end;
                if (!modeinfra::add_checked(
                        shard_begin, shard_count, shard_end)) {
                    progress.end();
                    std::cerr
                        << "[!] KeyRepair runtime error: shard end "
                           "overflows U256 [!]\n";
                    return 1;
                }
                if (!metal_ok(metalSetDevice(device),
                              "select Metal device", error)) {
                    progress.end();
                    std::cerr << "[!] KeyRepair runtime error: "
                              << error << " [!]\n";
                    return 1;
                }
                DeviceBuffers buffers;
                if (!prepare_buffers(item, options.type, target,
                                     host_precompute,
                                     buffers, error)) {
                    progress.end();
                    std::cerr << "[!] KeyRepair runtime error: "
                              << error << " [!]\n";
                    return 1;
                }
                progress.set_allocated_working_set(buffers.allocated);

                modeinfra::U256 cursor = shard_begin;
                std::uint64_t preferred_batch = options.batch;
                if (options.type == RepairType::RawPublic &&
                    target == nullptr) {
                    preferred_batch = std::min<std::uint64_t>(
                        preferred_batch, kHitCapacity);
                }
                while (modeinfra::compare(cursor, shard_end) < 0 &&
                       !input_solved) {
                    modeinfra::U256 remaining;
                    if (!modeinfra::subtract_checked(
                            shard_end, cursor, remaining)) {
                        progress.end();
                        std::cerr
                            << "[!] KeyRepair runtime error: invalid shard "
                               "cursor [!]\n";
                        return 1;
                    }
                    std::uint64_t batch = preferred_batch;
                    if (remaining.limbs[1] == 0u &&
                        remaining.limbs[2] == 0u &&
                        remaining.limbs[3] == 0u) {
                        batch = std::min(batch, remaining.limbs[0]);
                    }
                    bool completed = false;
                    while (!completed) {
                        std::vector<Hit> batch_hits;
                        std::uint32_t raw_count = 0u;
                        std::uint64_t readback_ns = 0u;
                        if (!launch_batch(
                                options.type, item, target,
                                host_precompute, buffers, cursor, batch,
                                batch_hits, raw_count, readback_ns, error)) {
                            progress.end();
                            std::cerr
                                << "[!] KeyRepair runtime error: "
                                << error << " [!]\n";
                            return 1;
                        }
                        if (raw_count > kHitCapacity) {
                            if (batch == 1u) {
                                progress.end();
                                std::cerr
                                    << "[!] KeyRepair runtime error: hit "
                                       "buffer overflow at one candidate [!]\n";
                                return 1;
                            }
                            batch =
                                std::max<std::uint64_t>(1u, batch / 2u);
                            continue;
                        }
                        completed = true;
                        std::uint64_t exact_verifications = 0u;
                        for (const Hit& hit : batch_hits) {
                            ++exact_verifications;
                            std::string line;
                            if (!verify_and_format(
                                    item, options.type, hit, cursor,
                                    targets, host_precompute, line) ||
                                !emitted.insert(line).second) {
                                continue;
                            }
                            if (!emit_result(
                                    line,
                                    output.is_open() ? &output : nullptr,
                                    options.silent)) {
                                progress.end();
                                std::cerr
                                    << "[!] KeyRepair runtime error: "
                                       "output write failed [!]\n";
                                return 1;
                            }
                            ++founds;
                            input_solved = true;
                            progress.set_founds(founds);
                            if (hooks.increment_found) {
                                hooks.increment_found();
                            }
                        }
                        progress.credit_completed(
                            batch, batch, exact_verifications, readback_ns);
                        if (hooks.add_completed) hooks.add_completed(batch);
                        modeinfra::U256 next;
                        if (!modeinfra::add_checked(
                                cursor,
                                modeinfra::U256::from_u64(batch), next)) {
                            progress.end();
                            std::cerr
                                << "[!] KeyRepair runtime error: window "
                                   "cursor overflows U256 [!]\n";
                            return 1;
                        }
                        cursor = next;
                    }
                }
            }
        }
        if (input_solved) ++solved;
        progress.set_targets(inputs.size(), inputs.size(), solved);
    }
    progress.set_phase(modeinfra::ProgressPhase::Verify);
    progress.end();
    if (!options.silent) {
        std::cout << "[!] KeyRepair completed. Found: " << founds
                  << " / " << inputs.size() << " template(s). [!]\n";
    }
    return 0;
}

} // namespace keyrepair
