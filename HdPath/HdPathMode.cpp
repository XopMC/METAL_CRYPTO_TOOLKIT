#include "HdPathMode.h"

#include "../MetalBackend.h"
#include "../SecpPrecompute.h"
#include "../host_secp/secp256k1.h"
#include "../host_secp/secp256k1_field.h"
#include "../host_secp/secp256k1_group.h"
#include "../host_secp/secp256k1_scalar.h"
#include "../lib/V/VBase58.h"
#include "../lib/hash/sha256.h"

#include <CommonCrypto/CommonDigest.h>
#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonKeyDerivation.h>
#include <CoreFoundation/CoreFoundation.h>

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
#include <set>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace hdpath {
namespace {

constexpr std::uint32_t kThreadgroupSize = 128u;
constexpr std::uint64_t kDefaultBatch = 1ull << 16u;
constexpr std::uint64_t kMaximumBatch =
    (static_cast<std::uint64_t>(
         std::numeric_limits<std::uint32_t>::max()) /
     kThreadgroupSize) *
    kThreadgroupSize;
constexpr std::uint32_t kHitCapacity = 65536u;
constexpr std::uint32_t kMaximumDepth = 32u;
constexpr std::uint64_t kRuntimeReserve = 512ull * 1024ull * 1024ull;

enum class RootKind : std::uint32_t {
    Private = 0u,
    Public = 1u,
};

struct GpuPathComponent {
    std::uint32_t kind = 0u;
    std::uint32_t base = 0u;
    std::uint32_t count = 0u;
    std::uint32_t values_offset = 0u;
};

struct alignas(16) GpuTarget {
    std::uint64_t prefix = 0u;
    std::uint32_t source_index = 0u;
    std::uint32_t reserved = 0u;
    std::array<std::uint8_t, 33> key{};
    std::array<std::uint8_t, 15> padding{};
};

struct alignas(16) GpuHit {
    std::array<std::uint64_t, 4> ordinal{};
    std::uint32_t target_index = 0u;
    std::uint32_t has_private = 0u;
    std::array<std::uint8_t, 32> private_key{};
    std::array<std::uint8_t, 33> public_key{};
    std::array<std::uint8_t, 7> padding{};
};

static_assert(sizeof(GpuPathComponent) == 16u);
static_assert(sizeof(GpuTarget) == 64u);
static_assert(sizeof(GpuHit) == 112u);

struct HostPrecompute {
    unsigned int bits = 8u;
    unsigned int windows = 0u;
    std::size_t pitch = 0u;
    std::vector<secp256k1_ge_storage> entries;
};

struct ExtendedPrivate {
    std::array<std::uint8_t, 32> key{};
    std::array<std::uint8_t, 32> chain{};
};

struct ExtendedPublic {
    std::array<std::uint8_t, 33> key{};
    std::array<std::uint8_t, 32> chain{};
};

struct Root {
    RootKind kind = RootKind::Private;
    ExtendedPrivate private_key;
    ExtendedPublic public_key;
    std::string source;
};

struct PathComponent {
    bool list = false;
    bool hardened = false;
    std::uint32_t base = 0u;
    std::vector<std::uint32_t> values;

    std::uint64_t radix() const {
        return list ? values.size() :
            static_cast<std::uint64_t>(values.empty() ? 0u : values[0]);
    }
};

struct PathTemplate {
    std::string text;
    std::string source;
    std::vector<PathComponent> components;
    std::vector<GpuPathComponent> gpu_components;
    std::vector<std::uint32_t> gpu_values;
    modeinfra::MixedRadixDomain domain;
};

struct TargetOccurrence {
    std::string source;
    std::string raw;
};

struct Target {
    std::array<std::uint8_t, 33> key{};
    std::vector<TargetOccurrence> occurrences;
    bool solved = false;
};

struct Options {
    std::string mnemonic;
    std::string mnemonic_passphrase;
    std::string seed;
    std::string xprv;
    std::string xpub;
    std::string descriptor;
    std::vector<std::string> target_values;
    std::vector<std::string> path_values;
    std::vector<int> devices{0};
    std::string wildcard_start = "0";
    std::string wildcard_end;
    std::string output_path;
    std::string memory = "auto";
    std::uint64_t batch = kDefaultBatch;
    bool save = false;
    bool silent = false;
};

struct DeviceBuffers {
    int device = -1;
    secp256k1_ge_storage* precompute = nullptr;
    std::uint8_t* root_private = nullptr;
    std::uint8_t* root_public = nullptr;
    std::uint8_t* root_chain = nullptr;
    GpuPathComponent* components = nullptr;
    std::uint32_t* component_values = nullptr;
    std::uint64_t* base_ordinal = nullptr;
    GpuTarget* targets = nullptr;
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
        if (arg == "-hdpath") {
            continue;
        } else if (arg == "-mnemonic") {
            const char* raw = value("-mnemonic");
            if (raw == nullptr) return false;
            options.mnemonic = raw;
        } else if (arg == "-pass") {
            const char* raw = value("-pass");
            if (raw == nullptr) return false;
            options.mnemonic_passphrase = raw;
        } else if (arg == "-seed") {
            const char* raw = value("-seed");
            if (raw == nullptr) return false;
            options.seed = raw;
        } else if (arg == "-xprv") {
            const char* raw = value("-xprv");
            if (raw == nullptr) return false;
            options.xprv = raw;
        } else if (arg == "-xpub") {
            const char* raw = value("-xpub");
            if (raw == nullptr) return false;
            options.xpub = raw;
        } else if (arg == "-descriptor") {
            const char* raw = value("-descriptor");
            if (raw == nullptr) return false;
            options.descriptor = raw;
        } else if (arg == "-target") {
            const char* raw = value("-target");
            if (raw == nullptr) return false;
            options.target_values.emplace_back(raw);
        } else if (arg == "-path-template") {
            const char* raw = value("-path-template");
            if (raw == nullptr) return false;
            options.path_values.emplace_back(raw);
        } else if (arg == "-start") {
            const char* raw = value("-start");
            if (raw == nullptr) return false;
            options.wildcard_start = raw;
        } else if (arg == "-end") {
            const char* raw = value("-end");
            if (raw == nullptr) return false;
            options.wildcard_end = raw;
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
                options.batch > kMaximumBatch) {
                if (error.empty()) {
                    error = "-n expects 1..4294967168 paths";
                }
                return false;
            }
        } else if (arg == "-wallet-mem") {
            const char* raw = value("-wallet-mem");
            if (raw == nullptr) return false;
            options.memory = raw;
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
            error = "unknown -hdpath parameter '" + arg + "'";
            return false;
        }
    }

    const unsigned roots =
        (!options.mnemonic.empty() ? 1u : 0u) +
        (!options.seed.empty() ? 1u : 0u) +
        (!options.xprv.empty() ? 1u : 0u) +
        (!options.xpub.empty() ? 1u : 0u) +
        (!options.descriptor.empty() ? 1u : 0u);
    if (roots != 1u) {
        error = "select exactly one root: -mnemonic, -seed, -xprv, "
                "-xpub, or -descriptor";
        return false;
    }
    if (options.target_values.empty()) {
        error = "-hdpath requires at least one -target";
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

bool decode_hex(const std::string& raw,
                std::vector<std::uint8_t>& output) {
    std::string value = trim_copy(raw);
    if (value.size() > 2u && value[0] == '0' &&
        (value[1] == 'x' || value[1] == 'X')) {
        value.erase(0u, 2u);
    }
    if (value.empty() || (value.size() & 1u) != 0u) return false;
    output.resize(value.size() / 2u);
    for (std::size_t i = 0u; i < output.size(); ++i) {
        const int high = hex_digit(value[i * 2u]);
        const int low = hex_digit(value[i * 2u + 1u]);
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
    CFMutableStringRef normalized = CFStringCreateMutableCopy(
        kCFAllocatorDefault, 0, original);
    CFRelease(original);
    if (normalized == nullptr) {
        error = "cannot allocate normalized UTF-8 string";
        return false;
    }
    CFStringNormalize(normalized, kCFStringNormalizationFormKD);
    const CFIndex length = CFStringGetLength(normalized);
    const CFIndex capacity =
        CFStringGetMaximumSizeForEncoding(length, kCFStringEncodingUTF8) + 1;
    std::vector<char> buffer(static_cast<std::size_t>(capacity));
    if (!CFStringGetCString(
            normalized, buffer.data(), capacity,
            kCFStringEncodingUTF8)) {
        CFRelease(normalized);
        error = "cannot encode normalized UTF-8 string";
        return false;
    }
    CFRelease(normalized);
    output.assign(buffer.data());
    return true;
}

void hmac_sha512(const std::uint8_t* key, std::size_t key_size,
                 const std::uint8_t* data, std::size_t data_size,
                 std::array<std::uint8_t, 64>& output) {
    CCHmac(kCCHmacAlgSHA512, key, key_size, data, data_size, output.data());
}

bool root_from_seed(const std::uint8_t* seed, std::size_t seed_size,
                    Root& root, std::string& error) {
    static constexpr std::uint8_t key[] = {
        'B','i','t','c','o','i','n',' ','s','e','e','d'
    };
    std::array<std::uint8_t, 64> digest{};
    hmac_sha512(key, sizeof(key), seed, seed_size, digest);
    secp256k1_scalar scalar{};
    if (!secp256k1_scalar_set_b32_seckey(&scalar, digest.data())) {
        error = "BIP32 master key is invalid";
        return false;
    }
    root.kind = RootKind::Private;
    std::copy(digest.begin(), digest.begin() + 32u,
              root.private_key.key.begin());
    std::copy(digest.begin() + 32u, digest.end(),
              root.private_key.chain.begin());
    return true;
}

bool root_from_mnemonic(const Options& options, Root& root,
                        std::string& error) {
    std::string mnemonic;
    std::string passphrase;
    if (!normalize_nfkd(options.mnemonic, mnemonic, error) ||
        !normalize_nfkd(options.mnemonic_passphrase, passphrase, error)) {
        return false;
    }
    const std::string salt = "mnemonic" + passphrase;
    std::array<std::uint8_t, 64> seed{};
    if (CCKeyDerivationPBKDF(
            kCCPBKDF2, mnemonic.data(), mnemonic.size(),
            reinterpret_cast<const std::uint8_t*>(salt.data()), salt.size(),
            kCCPRFHmacAlgSHA512, 2048u,
            seed.data(), seed.size()) != 0) {
        error = "PBKDF2-HMAC-SHA512 failed";
        return false;
    }
    root.source = "mnemonic";
    return root_from_seed(seed.data(), seed.size(), root, error);
}

bool decode_base58check(const std::string& text,
                        std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> decoded;
    if (!DecodeBase58(text, decoded) || decoded.size() < 5u) return false;
    std::array<std::uint8_t, 32> first{};
    std::array<std::uint8_t, 32> second{};
    sha256(decoded.data(), decoded.size() - 4u, first.data());
    sha256(first.data(), first.size(), second.data());
    if (!std::equal(second.begin(), second.begin() + 4u,
                    decoded.end() - 4u)) {
        return false;
    }
    payload.assign(decoded.begin(), decoded.end() - 4u);
    return true;
}

bool parse_public_key(const std::string& raw,
                      std::array<std::uint8_t, 33>& canonical,
                      std::string& error) {
    std::vector<std::uint8_t> bytes;
    if (!decode_hex(raw, bytes) ||
        (bytes.size() != 33u && bytes.size() != 65u)) {
        error = "expected a 33/65-byte secp256k1 public key";
        return false;
    }
    secp256k1_ge point{};
    if (bytes.size() == 33u &&
        (bytes[0] == 0x02u || bytes[0] == 0x03u)) {
        secp256k1_fe x{};
        if (!secp256k1_fe_set_b32(&x, bytes.data() + 1u) ||
            !secp256k1_ge_set_xo_var(
                &point, &x, bytes[0] == 0x03u)) {
            error = "public key is not on secp256k1";
            return false;
        }
    } else if (bytes.size() == 65u && bytes[0] == 0x04u) {
        secp256k1_fe x{};
        secp256k1_fe y{};
        if (!secp256k1_fe_set_b32(&x, bytes.data() + 1u) ||
            !secp256k1_fe_set_b32(&y, bytes.data() + 33u) ||
            !secp256k1_ge_set_xo_var(
                &point, &x, secp256k1_fe_is_odd(&y))) {
            error = "public key is not on secp256k1";
            return false;
        }
        secp256k1_fe_normalize_var(&y);
        if (!secp256k1_fe_equal(&point.y, &y)) {
            error = "uncompressed public key has an invalid y coordinate";
            return false;
        }
    } else {
        error = "public key has an invalid prefix";
        return false;
    }
    secp256k1_fe_normalize_var(&point.x);
    secp256k1_fe_normalize_var(&point.y);
    canonical[0] =
        static_cast<std::uint8_t>(0x02u + secp256k1_fe_is_odd(&point.y));
    secp256k1_fe_get_b32(canonical.data() + 1u, &point.x);
    return true;
}

bool root_from_extended(const std::string& text,
                        bool require_private,
                        Root& root,
                        std::string& error) {
    std::vector<std::uint8_t> payload;
    if (!decode_base58check(trim_copy(text), payload) ||
        payload.size() != 78u) {
        error = "extended key is not a valid 78-byte Base58Check payload";
        return false;
    }
    const std::uint32_t version =
        (std::uint32_t(payload[0]) << 24u) |
        (std::uint32_t(payload[1]) << 16u) |
        (std::uint32_t(payload[2]) << 8u) |
        std::uint32_t(payload[3]);
    const bool is_private =
        version == 0x0488ade4u || version == 0x04358394u;
    const bool is_public =
        version == 0x0488b21eu || version == 0x043587cfu;
    if ((!is_private && !is_public) ||
        (require_private && !is_private)) {
        error = require_private
            ? "-xprv requires xprv/tprv"
            : "unsupported extended-key version";
        return false;
    }
    const std::uint8_t* chain = payload.data() + 13u;
    const std::uint8_t* key = payload.data() + 45u;
    if (is_private) {
        if (key[0] != 0u) {
            error = "extended private key is missing its zero marker";
            return false;
        }
        secp256k1_scalar scalar{};
        if (!secp256k1_scalar_set_b32_seckey(&scalar, key + 1u)) {
            error = "extended private scalar is invalid";
            return false;
        }
        root.kind = RootKind::Private;
        std::copy(key + 1u, key + 33u, root.private_key.key.begin());
        std::copy(chain, chain + 32u, root.private_key.chain.begin());
    } else {
        std::array<std::uint8_t, 33> canonical{};
        if (!parse_public_key(
                hex_lower(key, 33u), canonical, error)) {
            error = "extended public key: " + error;
            return false;
        }
        root.kind = RootKind::Public;
        root.public_key.key = canonical;
        std::copy(chain, chain + 32u, root.public_key.chain.begin());
    }
    return true;
}

bool descriptor_root(const std::string& descriptor,
                     std::string& extended,
                     std::string& suffix,
                     std::string& error) {
    std::string value = trim_copy(descriptor);
    const auto checksum = value.find('#');
    if (checksum != std::string::npos) value.erase(checksum);
    static constexpr const char* prefixes[] = {
        "xprv", "xpub", "tprv", "tpub"
    };
    std::size_t begin = std::string::npos;
    for (const char* prefix : prefixes) {
        const auto at = value.find(prefix);
        if (at != std::string::npos &&
            (begin == std::string::npos || at < begin)) {
            begin = at;
        }
    }
    if (begin == std::string::npos) {
        error = "descriptor must contain xprv/xpub/tprv/tpub";
        return false;
    }
    const std::string alphabet =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    std::size_t end = begin;
    while (end < value.size() &&
           alphabet.find(value[end]) != std::string::npos) {
        ++end;
    }
    extended = value.substr(begin, end - begin);
    std::size_t suffix_end = end;
    while (suffix_end < value.size() &&
           value[suffix_end] != ')' &&
           value[suffix_end] != ',' &&
           value[suffix_end] != ']') {
        ++suffix_end;
    }
    suffix = value.substr(end, suffix_end - end);
    if (!suffix.empty()) suffix.insert(0u, "m");
    return true;
}

bool load_root(const Options& options, Root& root,
               std::string& descriptor_path,
               std::string& error) {
    if (!options.mnemonic.empty()) {
        return root_from_mnemonic(options, root, error);
    }
    if (!options.seed.empty()) {
        std::vector<std::uint8_t> seed;
        if (!decode_hex(options.seed, seed) ||
            seed.size() < 16u || seed.size() > 64u) {
            error = "-seed expects 16..64 bytes of hex";
            return false;
        }
        root.source = "seed";
        return root_from_seed(seed.data(), seed.size(), root, error);
    }
    if (!options.xprv.empty()) {
        root.source = "xprv";
        return root_from_extended(options.xprv, true, root, error);
    }
    if (!options.xpub.empty()) {
        root.source = "xpub";
        if (!root_from_extended(options.xpub, false, root, error)) {
            return false;
        }
        if (root.kind != RootKind::Public) {
            error = "-xpub requires xpub/tpub";
            return false;
        }
        return true;
    }
    std::string extended;
    if (!descriptor_root(
            options.descriptor, extended, descriptor_path, error)) {
        return false;
    }
    root.source = "descriptor";
    return root_from_extended(extended, false, root, error);
}

bool add_target(const std::string& raw,
                const std::string& source,
                std::vector<Target>& targets,
                std::unordered_map<std::string, std::size_t>& unique,
                std::string& error) {
    const std::string token = trim_copy(raw);
    if (token.empty() || token[0] == '#') return true;
    std::array<std::uint8_t, 33> key{};
    if (!parse_public_key(token, key, error)) {
        error = source + ": " + error;
        return false;
    }
    const std::string canonical = hex_lower(key.data(), key.size());
    const auto found = unique.find(canonical);
    const TargetOccurrence occurrence{source, token};
    if (found != unique.end()) {
        targets[found->second].occurrences.push_back(occurrence);
        return true;
    }
    unique.emplace(canonical, targets.size());
    targets.push_back(Target{key, {occurrence}, false});
    return true;
}

bool load_targets(const Options& options,
                  std::vector<Target>& targets,
                  std::string& error) {
    std::unordered_map<std::string, std::size_t> unique;
    for (std::size_t i = 0u; i < options.target_values.size(); ++i) {
        const std::string& value = options.target_values[i];
        std::ifstream input(value);
        if (input.good()) {
            std::string line;
            std::size_t line_number = 0u;
            while (std::getline(input, line)) {
                ++line_number;
                const auto comment = line.find('#');
                if (comment != std::string::npos) line.erase(comment);
                std::istringstream tokens(line);
                std::string token;
                tokens >> token;
                if (!add_target(
                        token, value + ":" + std::to_string(line_number),
                        targets, unique, error)) {
                    return false;
                }
            }
        } else if (!add_target(
                       value,
                       "command line target " + std::to_string(i + 1u),
                       targets, unique, error)) {
            return false;
        }
    }
    if (targets.empty()) {
        error = "no usable targets were loaded";
        return false;
    }
    return true;
}

bool parse_index(const std::string& raw,
                 std::uint32_t& index) {
    std::uint64_t value = 0u;
    if (!parse_u64(raw, value) || value >= 0x80000000ull) return false;
    index = static_cast<std::uint32_t>(value);
    return true;
}

bool wildcard_bounds(const Options& options,
                     std::uint32_t& start,
                     std::uint32_t& count,
                     std::string& error) {
    if (options.wildcard_end.empty()) {
        error = "a path wildcard requires finite -end";
        return false;
    }
    std::uint64_t first = 0u;
    std::uint64_t last = 0u;
    if (!parse_u64(options.wildcard_start, first) ||
        !parse_u64(options.wildcard_end, last) ||
        first >= last || last > 0x80000000ull) {
        error = "wildcard -start/-end must satisfy "
                "0 <= START < END <= 2147483648";
        return false;
    }
    start = static_cast<std::uint32_t>(first);
    count = static_cast<std::uint32_t>(last - first);
    return true;
}

bool parse_component(std::string token,
                     const Options& options,
                     PathComponent& component,
                     std::string& error) {
    token = trim_copy(token);
    if (token.empty()) {
        error = "empty path component";
        return false;
    }
    const char suffix = token.back();
    if (suffix == '\'' || suffix == 'h' || suffix == 'H') {
        component.hardened = true;
        token.pop_back();
    }
    if (token == "*") {
        std::uint32_t count = 0u;
        if (!wildcard_bounds(options, component.base, count, error)) {
            return false;
        }
        component.values.push_back(count);
        return true;
    }
    if (token.front() == '{' && token.back() == '}') {
        const std::string body = token.substr(1u, token.size() - 2u);
        const auto dash = body.find('-');
        if (dash != std::string::npos &&
            body.find(',') == std::string::npos) {
            std::uint32_t first = 0u;
            std::uint32_t last = 0u;
            if (!parse_index(body.substr(0u, dash), first) ||
                !parse_index(body.substr(dash + 1u), last) ||
                first > last) {
                error = "invalid inclusive path range '{" + body + "}'";
                return false;
            }
            component.base = first;
            component.values.push_back(last - first + 1u);
            return true;
        }
        component.list = true;
        std::stringstream input(body);
        std::string item;
        std::unordered_set<std::uint32_t> seen;
        while (std::getline(input, item, ',')) {
            std::uint32_t index = 0u;
            if (!parse_index(item, index)) {
                error = "invalid path list '{" + body + "}'";
                return false;
            }
            if (seen.insert(index).second) component.values.push_back(index);
        }
        if (component.values.empty()) {
            error = "path list is empty";
            return false;
        }
        return true;
    }
    std::uint32_t fixed = 0u;
    if (!parse_index(token, fixed)) {
        error = "invalid path index '" + token + "'";
        return false;
    }
    component.base = fixed;
    component.values.push_back(1u);
    return true;
}

bool parse_path_template(const std::string& raw,
                         const std::string& source,
                         const Options& options,
                         RootKind root_kind,
                         PathTemplate& result,
                         std::string& error) {
    result.text = trim_copy(raw);
    result.source = source;
    if (result.text.empty()) {
        error = source + ": path template is empty";
        return false;
    }
    std::string path = result.text;
    if (path == "m" || path == "M") {
        error = source + ": path template must contain at least one child";
        return false;
    }
    if (path.size() < 2u ||
        (path[0] != 'm' && path[0] != 'M') ||
        path[1] != '/') {
        error = source + ": path must start with m/";
        return false;
    }
    path.erase(0u, 2u);
    std::stringstream input(path);
    std::string token;
    while (std::getline(input, token, '/')) {
        PathComponent component;
        if (!parse_component(token, options, component, error)) {
            error = source + ": " + error;
            return false;
        }
        if (root_kind == RootKind::Public && component.hardened) {
            error = source +
                ": hardened descendants cannot be derived from xpub";
            return false;
        }
        result.components.push_back(std::move(component));
    }
    if (result.components.empty() ||
        result.components.size() > kMaximumDepth) {
        error = source + ": path depth must be 1..32";
        return false;
    }

    std::vector<std::uint64_t> radices;
    for (const PathComponent& component : result.components) {
        const std::uint64_t radix = component.radix();
        if (radix == 0u || radix > 0x80000000ull) {
            error = source + ": invalid path component cardinality";
            return false;
        }
        radices.push_back(radix);
        GpuPathComponent gpu;
        gpu.kind = component.list ? 1u : 0u;
        gpu.base = component.base |
            (component.hardened ? 0x80000000u : 0u);
        gpu.count = static_cast<std::uint32_t>(radix);
        gpu.values_offset =
            static_cast<std::uint32_t>(result.gpu_values.size());
        if (component.list) {
            for (std::uint32_t index : component.values) {
                result.gpu_values.push_back(
                    index | (component.hardened ? 0x80000000u : 0u));
            }
        }
        result.gpu_components.push_back(gpu);
    }
    if (!result.domain.reset(radices, error)) {
        error = source + ": " + error;
        return false;
    }
    return true;
}

bool load_path_templates(const Options& options,
                         const std::string& descriptor_path,
                         RootKind root_kind,
                         std::vector<PathTemplate>& templates,
                         std::string& error) {
    std::vector<std::pair<std::string, std::string>> raw;
    if (!descriptor_path.empty()) {
        raw.emplace_back(descriptor_path, "descriptor path");
    }
    for (std::size_t i = 0u; i < options.path_values.size(); ++i) {
        const std::string& value = options.path_values[i];
        std::ifstream input(value);
        if (input.good()) {
            std::string line;
            std::size_t line_number = 0u;
            while (std::getline(input, line)) {
                ++line_number;
                const auto comment = line.find('#');
                if (comment != std::string::npos) line.erase(comment);
                line = trim_copy(line);
                if (!line.empty()) {
                    raw.emplace_back(
                        line, value + ":" + std::to_string(line_number));
                }
            }
        } else {
            raw.emplace_back(
                value,
                "command line path " + std::to_string(i + 1u));
        }
    }
    if (raw.empty()) {
        error = "-hdpath requires -path-template unless the descriptor "
                "contains a derivation suffix";
        return false;
    }
    for (const auto& entry : raw) {
        PathTemplate parsed;
        if (!parse_path_template(
                entry.first, entry.second, options,
                root_kind, parsed, error)) {
            return false;
        }
        templates.push_back(std::move(parsed));
    }
    return true;
}

std::uint64_t target_prefix(
    const std::array<std::uint8_t, 33>& key) {
    std::uint64_t result = 0u;
    for (std::size_t i = 0u; i < 8u; ++i) {
        result = (result << 8u) | key[i];
    }
    return result;
}

bool build_precompute(HostPrecompute& result, std::string& error) {
    return build_secp256k1_precompute_table_host(
        result.bits, result.entries, result.pitch,
        result.windows, error);
}

bool derive_public_from_private(
    const std::array<std::uint8_t, 32>& private_key,
    const HostPrecompute& precompute,
    std::array<std::uint8_t, 33>& output) {
    secp256k1_scalar scalar{};
    if (!secp256k1_scalar_set_b32_seckey(
            &scalar, private_key.data())) {
        return false;
    }
    secp256k1_gej jacobian{};
    secp256k1_ecmult_big(
        &jacobian, &scalar, precompute.entries.data(),
        precompute.pitch, static_cast<int>(precompute.windows),
        precompute.bits);
    if (jacobian.infinity != 0) return false;
    secp256k1_ge point_value{};
    secp256k1_ge_set_gej(&point_value, &jacobian);
    secp256k1_pubkey point{};
    secp256k1_pubkey_save(&point, &point_value);
    return secp256k1_ec_pubkey_serialize(
        output.data(), output.size(), &point, true) != 0;
}

bool host_ckd_private_once(
    const ExtendedPrivate& parent,
    std::uint32_t index,
    const HostPrecompute& precompute,
    ExtendedPrivate& child) {
    std::array<std::uint8_t, 37> data{};
    if ((index & 0x80000000u) != 0u) {
        std::copy(parent.key.begin(), parent.key.end(), data.begin() + 1u);
    } else {
        std::array<std::uint8_t, 33> public_key{};
        if (!derive_public_from_private(parent.key, precompute, public_key)) {
            return false;
        }
        std::copy(public_key.begin(), public_key.end(), data.begin());
    }
    data[33] = static_cast<std::uint8_t>(index >> 24u);
    data[34] = static_cast<std::uint8_t>(index >> 16u);
    data[35] = static_cast<std::uint8_t>(index >> 8u);
    data[36] = static_cast<std::uint8_t>(index);
    std::array<std::uint8_t, 64> digest{};
    hmac_sha512(parent.chain.data(), parent.chain.size(),
                data.data(), data.size(), digest);
    std::array<std::uint8_t, 32> candidate = parent.key;
    if (!secp256k1_ec_seckey_tweak_add(
            candidate.data(), digest.data())) {
        return false;
    }
    child.key = candidate;
    std::copy(digest.begin() + 32u, digest.end(), child.chain.begin());
    return true;
}

bool host_ckd_private(
    const ExtendedPrivate& parent,
    std::uint32_t requested,
    const HostPrecompute& precompute,
    ExtendedPrivate& child,
    std::uint32_t& actual) {
    actual = requested;
    const std::uint32_t boundary =
        (requested & 0x80000000u) != 0u
        ? 0xffffffffu : 0x7fffffffu;
    for (;;) {
        if (host_ckd_private_once(
                parent, actual, precompute, child)) {
            return true;
        }
        if (actual == boundary) return false;
        ++actual;
    }
}

bool parse_compressed_host(
    const std::array<std::uint8_t, 33>& serialized,
    secp256k1_pubkey& output) {
    secp256k1_fe x{};
    secp256k1_ge point{};
    if ((serialized[0] != 0x02u && serialized[0] != 0x03u) ||
        !secp256k1_fe_set_b32(&x, serialized.data() + 1u) ||
        !secp256k1_ge_set_xo_var(
            &point, &x, serialized[0] == 0x03u)) {
        return false;
    }
    secp256k1_pubkey_save(&output, &point);
    return true;
}

bool host_ckd_public_once(
    const ExtendedPublic& parent,
    std::uint32_t index,
    const HostPrecompute& precompute,
    ExtendedPublic& child) {
    if ((index & 0x80000000u) != 0u) return false;
    std::array<std::uint8_t, 37> data{};
    std::copy(parent.key.begin(), parent.key.end(), data.begin());
    data[33] = static_cast<std::uint8_t>(index >> 24u);
    data[34] = static_cast<std::uint8_t>(index >> 16u);
    data[35] = static_cast<std::uint8_t>(index >> 8u);
    data[36] = static_cast<std::uint8_t>(index);
    std::array<std::uint8_t, 64> digest{};
    hmac_sha512(parent.chain.data(), parent.chain.size(),
                data.data(), data.size(), digest);

    secp256k1_scalar tweak{};
    int overflow = 0;
    secp256k1_scalar_set_b32(&tweak, digest.data(), &overflow);
    if (overflow) return false;
    secp256k1_pubkey point{};
    if (!parse_compressed_host(parent.key, point)) return false;
    if (!secp256k1_scalar_is_zero(&tweak)) {
        secp256k1_ge parent_point{};
        if (!secp256k1_pubkey_load(&parent_point, &point)) return false;
        secp256k1_gej sum{};
        secp256k1_gej_set_ge(&sum, &parent_point);
        secp256k1_gej tweak_point{};
        secp256k1_ecmult_big(
            &tweak_point, &tweak, precompute.entries.data(),
            precompute.pitch, static_cast<int>(precompute.windows),
            precompute.bits);
        secp256k1_gej_add_var(&sum, &sum, &tweak_point, nullptr);
        if (sum.infinity != 0) return false;
        secp256k1_ge result{};
        secp256k1_ge_set_gej(&result, &sum);
        secp256k1_pubkey_save(&point, &result);
    }
    if (!secp256k1_ec_pubkey_serialize(
            child.key.data(), child.key.size(), &point, true)) {
        return false;
    }
    std::copy(digest.begin() + 32u, digest.end(), child.chain.begin());
    return true;
}

bool host_ckd_public(
    const ExtendedPublic& parent,
    std::uint32_t requested,
    const HostPrecompute& precompute,
    ExtendedPublic& child,
    std::uint32_t& actual) {
    actual = requested;
    for (;;) {
        if (host_ckd_public_once(
                parent, actual, precompute, child)) {
            return true;
        }
        if (actual == 0x7fffffffu) return false;
        ++actual;
    }
}

bool decode_path(const PathTemplate& path,
                 const modeinfra::U256& ordinal,
                 std::vector<std::uint32_t>& indexes,
                 std::string& error) {
    std::vector<std::uint64_t> digits;
    if (!path.domain.decode(ordinal, digits, error)) return false;
    indexes.resize(path.components.size());
    for (std::size_t i = 0u; i < path.components.size(); ++i) {
        const PathComponent& component = path.components[i];
        std::uint32_t index = component.list
            ? component.values[static_cast<std::size_t>(digits[i])]
            : component.base + static_cast<std::uint32_t>(digits[i]);
        if (component.hardened) index |= 0x80000000u;
        indexes[i] = index;
    }
    return true;
}

bool verify_path(
    const Root& root,
    const PathTemplate& path,
    const modeinfra::U256& ordinal,
    const HostPrecompute& precompute,
    std::array<std::uint8_t, 33>& public_key,
    std::array<std::uint8_t, 32>& private_key,
    bool& has_private,
    std::vector<std::uint32_t>& actual_indexes,
    std::string& error) {
    std::vector<std::uint32_t> requested;
    if (!decode_path(path, ordinal, requested, error)) return false;
    actual_indexes.resize(requested.size());
    has_private = root.kind == RootKind::Private;
    if (has_private) {
        ExtendedPrivate current = root.private_key;
        for (std::size_t i = 0u; i < requested.size(); ++i) {
            ExtendedPrivate child;
            if (!host_ckd_private(
                    current, requested[i], precompute, child,
                    actual_indexes[i])) {
                error = "host CKDpriv failed";
                return false;
            }
            current = child;
        }
        private_key = current.key;
        if (!derive_public_from_private(
                private_key, precompute, public_key)) {
            error = "host public-key derivation failed";
            return false;
        }
    } else {
        ExtendedPublic current = root.public_key;
        for (std::size_t i = 0u; i < requested.size(); ++i) {
            ExtendedPublic child;
            if (!host_ckd_public(
                    current, requested[i], precompute, child,
                    actual_indexes[i])) {
                error = "host CKDpub failed";
                return false;
            }
            current = child;
        }
        public_key = current.key;
        private_key.fill(0u);
    }
    return true;
}

std::string format_path(
    const std::vector<std::uint32_t>& indexes) {
    std::ostringstream output;
    output << 'm';
    for (std::uint32_t index : indexes) {
        const bool hardened = (index & 0x80000000u) != 0u;
        output << '/' << (index & 0x7fffffffu);
        if (hardened) output << '\'';
    }
    return output.str();
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
        metalMalloc(&pointer, std::max<std::size_t>(bytes, 1u)),
        operation, error);
}

void release_buffers(DeviceBuffers& buffers) {
    const int device = buffers.device;
    if (device >= 0) (void)metalSetDevice(device);
    if (buffers.precompute) metalFree(buffers.precompute);
    if (buffers.root_private) metalFree(buffers.root_private);
    if (buffers.root_public) metalFree(buffers.root_public);
    if (buffers.root_chain) metalFree(buffers.root_chain);
    if (buffers.components) metalFree(buffers.components);
    if (buffers.component_values) metalFree(buffers.component_values);
    if (buffers.base_ordinal) metalFree(buffers.base_ordinal);
    if (buffers.targets) metalFree(buffers.targets);
    if (buffers.hits) metalFree(buffers.hits);
    if (buffers.hit_count) metalFree(buffers.hit_count);
    buffers = DeviceBuffers{};
}

bool prepare_buffers(
    int device,
    const Root& root,
    const HostPrecompute& precompute,
    const std::vector<GpuTarget>& targets,
    DeviceBuffers& buffers,
    std::string& error) {
    buffers.device = device;
    if (!metal_ok(metalSetDevice(device), "select Metal device", error)) {
        return false;
    }
    const std::size_t precompute_bytes =
        precompute.entries.size() * sizeof(secp256k1_ge_storage);
    const std::size_t target_bytes =
        targets.size() * sizeof(GpuTarget);
    if (!allocate(
            buffers.precompute, precompute_bytes,
            "allocate HDPath precompute", error) ||
        !allocate(
            buffers.root_private, 32u,
            "allocate HDPath private root", error) ||
        !allocate(
            buffers.root_public, 33u,
            "allocate HDPath public root", error) ||
        !allocate(
            buffers.root_chain, 32u,
            "allocate HDPath chain code", error) ||
        !allocate(
            buffers.components,
            kMaximumDepth * sizeof(GpuPathComponent),
            "allocate HDPath components", error) ||
        !allocate(
            buffers.component_values,
            sizeof(std::uint32_t),
            "allocate HDPath component values", error) ||
        !allocate(
            buffers.base_ordinal, 4u * sizeof(std::uint64_t),
            "allocate HDPath ordinal", error) ||
        !allocate(
            buffers.targets, target_bytes,
            "allocate HDPath targets", error) ||
        !allocate(
            buffers.hits,
            static_cast<std::size_t>(kHitCapacity) * sizeof(GpuHit),
            "allocate HDPath hits", error) ||
        !allocate(
            buffers.hit_count, sizeof(std::uint32_t),
            "allocate HDPath hit count", error)) {
        release_buffers(buffers);
        return false;
    }
    const std::array<std::uint8_t, 32> zero_private{};
    const std::uint8_t* private_source =
        root.kind == RootKind::Private
        ? root.private_key.key.data() : zero_private.data();
    const std::uint8_t* public_source = root.public_key.key.data();
    const std::uint8_t* chain_source =
        root.kind == RootKind::Private
        ? root.private_key.chain.data() : root.public_key.chain.data();
    if (!metal_ok(
            metalMemcpy(
                buffers.precompute, precompute.entries.data(),
                precompute_bytes, metalMemcpyHostToDevice),
            "upload HDPath precompute", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.root_private, private_source, 32u,
                metalMemcpyHostToDevice),
            "upload HDPath private root", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.root_public, public_source, 33u,
                metalMemcpyHostToDevice),
            "upload HDPath public root", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.root_chain, chain_source, 32u,
                metalMemcpyHostToDevice),
            "upload HDPath chain code", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.targets, targets.data(), target_bytes,
                metalMemcpyHostToDevice),
            "upload HDPath targets", error)) {
        release_buffers(buffers);
        return false;
    }
    buffers.allocated =
        precompute_bytes + 32u + 33u + 32u +
        kMaximumDepth * sizeof(GpuPathComponent) +
        sizeof(std::uint32_t) + 4u * sizeof(std::uint64_t) +
        target_bytes +
        static_cast<std::uint64_t>(kHitCapacity) * sizeof(GpuHit) +
        sizeof(std::uint32_t);
    return true;
}

bool ensure_component_values(DeviceBuffers& buffers,
                             std::size_t values,
                             std::string& error) {
    if (values <= 1u) return true;
    if (buffers.component_values) {
        metalFree(buffers.component_values);
        buffers.component_values = nullptr;
        buffers.allocated -= sizeof(std::uint32_t);
    }
    const std::size_t bytes = values * sizeof(std::uint32_t);
    if (!allocate(
            buffers.component_values, bytes,
            "allocate HDPath component value list", error)) {
        return false;
    }
    buffers.allocated += bytes;
    return true;
}

bool upload_template(DeviceBuffers& buffers,
                     const PathTemplate& path,
                     std::string& error) {
    if (!metal_ok(
            metalSetDevice(buffers.device),
            "select HDPath device", error) ||
        !ensure_component_values(
            buffers, path.gpu_values.size(), error) ||
        !metal_ok(
            metalMemcpy(
                buffers.components, path.gpu_components.data(),
                path.gpu_components.size() * sizeof(GpuPathComponent),
                metalMemcpyHostToDevice),
            "upload HDPath components", error)) {
        return false;
    }
    if (!path.gpu_values.empty() &&
        !metal_ok(
            metalMemcpy(
                buffers.component_values, path.gpu_values.data(),
                path.gpu_values.size() * sizeof(std::uint32_t),
                metalMemcpyHostToDevice),
            "upload HDPath component values", error)) {
        return false;
    }
    return true;
}

bool launch_batch(
    DeviceBuffers& buffers,
    const Root& root,
    const HostPrecompute& precompute,
    const PathTemplate& path,
    const modeinfra::U256& base,
    std::uint64_t count,
    std::uint32_t target_count,
    std::vector<GpuHit>& hits,
    std::uint32_t& raw_count,
    std::uint64_t& readback_ns,
    std::string& error) {
    if (!metal_ok(
            metalSetDevice(buffers.device),
            "select HDPath device", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.base_ordinal, base.limbs.data(),
                4u * sizeof(std::uint64_t), metalMemcpyHostToDevice),
            "upload HDPath ordinal", error) ||
        !metal_ok(
            metalMemset(
                buffers.hit_count, 0, sizeof(std::uint32_t)),
            "reset HDPath hit count", error)) {
        return false;
    }
    const std::uint64_t pitch =
        static_cast<std::uint64_t>(precompute.pitch);
    const std::uint32_t window_count = precompute.windows;
    const std::uint32_t window_bits = precompute.bits;
    const std::uint32_t root_kind =
        static_cast<std::uint32_t>(root.kind);
    const std::uint32_t component_count =
        static_cast<std::uint32_t>(path.gpu_components.size());
    const std::uint32_t grid = static_cast<std::uint32_t>(
        (count + kThreadgroupSize - 1u) / kThreadgroupSize *
        kThreadgroupSize);
    if (!metal_ok(
            metal_launch(
                "workerHdPath", grid, kThreadgroupSize,
                buffers.precompute, pitch, window_count, window_bits,
                buffers.root_private, buffers.root_public,
                buffers.root_chain, root_kind,
                buffers.components, buffers.component_values,
                component_count, buffers.base_ordinal,
                buffers.targets, target_count,
                buffers.hits, buffers.hit_count,
                kHitCapacity, count),
            "launch workerHdPath", error) ||
        !metal_ok(
            metalDeviceSynchronize(),
            "synchronize workerHdPath", error)) {
        return false;
    }
    const auto started = std::chrono::steady_clock::now();
    raw_count = 0u;
    if (!metal_ok(
            metalMemcpy(
                &raw_count, buffers.hit_count, sizeof(raw_count),
                metalMemcpyDeviceToHost),
            "read HDPath hit count", error)) {
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
            "read HDPath hits", error)) {
        return false;
    }
    readback_ns = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() - started).count());
    return true;
}

std::uint64_t bounded_count(const modeinfra::U256& remaining,
                            std::uint64_t maximum) {
    if (remaining.limbs[1] != 0u || remaining.limbs[2] != 0u ||
        remaining.limbs[3] != 0u) {
        return maximum;
    }
    return std::min(remaining.limbs[0], maximum);
}

} // namespace

bool requested(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (argv[i] != nullptr &&
            std::strcmp(argv[i], "-hdpath") == 0) {
            return true;
        }
    }
    return false;
}

void print_help() {
    std::cout << R"HELP([!] MAIN MODE: -hdpath  (GPU BIP32 derivation-path search)
[!] ======================================================================
[!] Purpose:
[!] Search unknown BIP32 child indexes/dimensions and match derived
[!] secp256k1 public keys. CKDpriv and CKDpub run on Metal; every hit is
[!] independently re-derived and verified on the host.
[!]
[!] Root input (select exactly one):
[!] -mnemonic "WORDS"              BIP39 mnemonic; optional -pass STRING.
[!] -seed HEX                      16..64-byte BIP32 seed.
[!] -xprv KEY / -xpub KEY          Mainnet/testnet extended key.
[!] -descriptor STRING             Descriptor containing xprv/xpub/tprv/tpub.
[!] Descriptor origin metadata is accepted; its key suffix becomes a path.
[!]
[!] Targets:
[!] -target KEY                    Repeatable 33/65-byte secp256k1 public key.
[!]                                An existing file is read one key per line;
[!]                                empty lines, comments, and trailing text
[!]                                after the first token are ignored.
[!] Duplicate public keys are searched once while preserving all sources.
[!]
[!] Path templates:
[!] -path-template VALUE           Repeatable template or existing text file.
[!] Fixed: m/44'/0'/0'/0/7
[!] Range: m/44'/0'/{0-9}'/0/{0-99999}   (inclusive braces)
[!] List:  m/44'/0'/{0,2,7}/0/{1,5,9}
[!] Wildcard: m/84'/0'/0'/0/* with -start N -end N for [START,END).
[!] Apostrophe or h/H marks hardened indexes. CKDpub rejects every hardened
[!] component before GPU execution.
[!]
[!] GPU / memory / MultiGPU:
[!] -device LIST                   Metal indexes, e.g. 0 or 0,1.
[!] -n N                           Paths per completed Metal launch.
[!] -wallet-mem auto|all|NN%|SIZE  Hard unified-memory working-set budget.
[!] Mixed-radix ordinals are checked U256 and assigned without gaps/overlap.
[!] Hit overflow halves and retries the uncredited window without loss.
[!]
[!] Statistics / output:
[!] SpeedThreadFunc is the only live statistics printer and reports Path/s.
[!] -o FILE                        Append verified results.
[!] -save                          Use HDPATH_FOUND.txt when -o is absent.
[!] -silent                        Suppress found-result lines on stdout.
[!] Private roots output the verified child private key; xpub roots output
[!] only the public key and path because private material is unavailable.
[!]
[!] Examples:
[!] ./METAL_CRYPTO_TOOLKIT -hdpath \
[!]   -seed 000102030405060708090a0b0c0d0e0f \
[!]   -path-template "m/{0-15}'" -target 035a784662a4a20a65bf6aab9ae98a6c068a81c52e4b032c0fb5400c706cfccc56
[!] ./METAL_CRYPTO_TOOLKIT -hdpath -xpub xpub... \
[!]   -path-template "m/0/*" -start 0 -end 100000 \
[!]   -target targets.txt -device 0 -save
[!] ./METAL_CRYPTO_TOOLKIT -hdpath \
[!]   -descriptor "wpkh([d34db33f/84h/0h/0h]xpub.../0/*)" \
[!]   -start 0 -end 100000 -target targets.txt -wallet-mem auto
[!]
[!] Limitations:
[!] BIP32/secp256k1 roots and exact public-key targets are supported.
[!] Hardened descendants from xpub are mathematically unavailable.
[!] U256 scheduling does not make enormous derivation domains practical.
[!] CLI errors return 2; Metal/runtime failures return 1.
)HELP";
}

int run(int argc, char** argv, const RuntimeHooks& hooks) {
    Options options;
    std::string error;
    if (!parse_options(argc, argv, options, error)) {
        std::cerr << "[!] HDPath CLI error: " << error << " [!]\n";
        return 2;
    }

    Root root;
    std::string descriptor_path;
    if (!load_root(options, root, descriptor_path, error)) {
        std::cerr << "[!] HDPath root error: " << error << " [!]\n";
        return 2;
    }
    std::vector<Target> targets;
    if (!load_targets(options, targets, error)) {
        std::cerr << "[!] HDPath target error: " << error << " [!]\n";
        return 2;
    }
    std::vector<PathTemplate> templates;
    if (!load_path_templates(
            options, descriptor_path, root.kind, templates, error)) {
        std::cerr << "[!] HDPath path error: " << error << " [!]\n";
        return 2;
    }

    HostPrecompute precompute;
    if (!build_precompute(precompute, error)) {
        std::cerr << "[!] HDPath runtime error: " << error << " [!]\n";
        return 1;
    }
    if (root.kind == RootKind::Private &&
        !derive_public_from_private(
            root.private_key.key, precompute, root.public_key.key)) {
        std::cerr << "[!] HDPath runtime error: cannot derive root public "
                     "key [!]\n";
        return 1;
    }

    std::vector<GpuTarget> gpu_targets(targets.size());
    for (std::size_t i = 0u; i < targets.size(); ++i) {
        gpu_targets[i].prefix = target_prefix(targets[i].key);
        gpu_targets[i].source_index = static_cast<std::uint32_t>(i);
        gpu_targets[i].key = targets[i].key;
    }
    std::sort(
        gpu_targets.begin(), gpu_targets.end(),
        [](const GpuTarget& left, const GpuTarget& right) {
            if (left.prefix != right.prefix) {
                return left.prefix < right.prefix;
            }
            return left.key < right.key;
        });

    int device_count = 0;
    if (!metal_ok(
            metalGetDeviceCount(&device_count),
            "query Metal devices", error)) {
        std::cerr << "[!] HDPath runtime error: " << error << " [!]\n";
        return 1;
    }
    std::vector<modeinfra::MemoryDeviceInfo> device_info;
    for (int device : options.devices) {
        if (device < 0 || device >= device_count) {
            std::cerr << "[!] HDPath CLI error: device index "
                      << device << " is unavailable [!]\n";
            return 2;
        }
        metalDeviceProp properties{};
        if (!metal_ok(
                metalGetDeviceProperties(&properties, device),
                "query Metal device properties", error)) {
            std::cerr << "[!] HDPath runtime error: " << error << " [!]\n";
            return 1;
        }
        device_info.push_back({
            properties.recommendedMaxWorkingSetSize,
            properties.currentAllocatedSize,
            properties.maxBufferLength,
            properties.hasUnifiedMemory != 0,
        });
    }
    const std::uint64_t mandatory =
        precompute.entries.size() * sizeof(secp256k1_ge_storage) +
        gpu_targets.size() * sizeof(GpuTarget) +
        static_cast<std::uint64_t>(kHitCapacity) * sizeof(GpuHit) +
        1024u * 1024u;
    modeinfra::MemorySpec memory_spec;
    modeinfra::MemoryBudget memory_budget;
    if (!modeinfra::parse_memory_spec(
            options.memory, memory_spec, error) ||
        !modeinfra::resolve_memory_budget(
            memory_spec, device_info, mandatory, 0u,
            memory_budget, error, kRuntimeReserve)) {
        std::cerr << "[!] HDPath memory error: " << error << " [!]\n";
        return 2;
    }

    std::vector<DeviceBuffers> devices(options.devices.size());
    std::uint64_t allocated = 0u;
    for (std::size_t i = 0u; i < devices.size(); ++i) {
        if (!prepare_buffers(
                options.devices[i], root, precompute,
                gpu_targets, devices[i], error)) {
            for (auto& buffers : devices) release_buffers(buffers);
            std::cerr << "[!] HDPath runtime error: "
                      << error << " [!]\n";
            return 1;
        }
        allocated += devices[i].allocated;
    }
    if (allocated > memory_budget.total_budget) {
        for (auto& buffers : devices) release_buffers(buffers);
        std::cerr << "[!] HDPath memory error: allocated working set "
                     "exceeds -wallet-mem [!]\n";
        return 2;
    }

    if (options.output_path.empty() && options.save) {
        options.output_path = "HDPATH_FOUND.txt";
    }
    std::ofstream output;
    if (!options.output_path.empty()) {
        output.open(options.output_path, std::ios::app);
        if (!output) {
            for (auto& buffers : devices) release_buffers(buffers);
            std::cerr << "[!] HDPath runtime error: cannot open output "
                         "file [!]\n";
            return 1;
        }
    }

    std::uint64_t logical_targets = 0u;
    for (const Target& target : targets) {
        logical_targets += target.occurrences.size();
    }
    std::cout << "[!] HDPath root: " << root.source
              << " | templates: " << templates.size()
              << " | targets: " << targets.size()
              << " unique/" << logical_targets
              << " logical | devices: " << devices.size()
              << " | batch: " << options.batch << " [!]\n";

    modeinfra::ModeProgress& progress =
        modeinfra::global_mode_progress();
    progress.begin(
        "HDPATH", modeinfra::ProgressUnit::Path,
        modeinfra::ProgressPhase::Search);
    progress.set_targets(logical_targets, targets.size(), 0u);
    progress.set_allocated_working_set(allocated);

    std::uint64_t solved_logical = 0u;
    std::uint64_t founds = 0u;
    int result = 0;
    std::size_t device_slot = 0u;
    for (const PathTemplate& path : templates) {
        if (solved_logical == logical_targets) break;
        for (DeviceBuffers& buffers : devices) {
            if (!upload_template(buffers, path, error)) {
                result = 1;
                break;
            }
        }
        if (result != 0) break;

        modeinfra::U256 cursor{};
        while (solved_logical < logical_targets &&
               modeinfra::compare(cursor, path.domain.size()) < 0) {
            modeinfra::U256 remaining{};
            if (!modeinfra::subtract_checked(
                    path.domain.size(), cursor, remaining)) {
                error = "HDPath scheduler underflow";
                result = 1;
                break;
            }
            const std::uint64_t count =
                bounded_count(remaining, options.batch);
            if (count == 0u) {
                error = "HDPath scheduler produced an empty window";
                result = 1;
                break;
            }
            DeviceBuffers& buffers =
                devices[device_slot++ % devices.size()];
            std::vector<GpuHit> hits;
            std::uint32_t raw_count = 0u;
            std::uint64_t readback_ns = 0u;
            if (!launch_batch(
                    buffers, root, precompute, path, cursor,
                    count, static_cast<std::uint32_t>(gpu_targets.size()),
                    hits, raw_count, readback_ns, error)) {
                result = 1;
                break;
            }
            if (raw_count > kHitCapacity) {
                if (count == 1u) {
                    error = "HDPath hit buffer overflow for one path";
                    result = 1;
                    break;
                }
                options.batch = std::max<std::uint64_t>(1u, count / 2u);
                continue;
            }

            for (const GpuHit& hit : hits) {
                if (hit.target_index >= gpu_targets.size()) {
                    error = "Metal returned an invalid HDPath target index";
                    result = 1;
                    break;
                }
                const GpuTarget& gpu_target =
                    gpu_targets[hit.target_index];
                if (gpu_target.source_index >= targets.size()) {
                    error = "Metal returned an invalid HDPath source index";
                    result = 1;
                    break;
                }
                Target& target = targets[gpu_target.source_index];
                if (target.solved) continue;
                modeinfra::U256 ordinal;
                ordinal.limbs = hit.ordinal;
                std::array<std::uint8_t, 33> verified_public{};
                std::array<std::uint8_t, 32> verified_private{};
                bool has_private = false;
                std::vector<std::uint32_t> actual_indexes;
                if (!verify_path(
                        root, path, ordinal, precompute,
                        verified_public, verified_private, has_private,
                        actual_indexes, error) ||
                    verified_public != target.key ||
                    verified_public != hit.public_key ||
                    has_private != (hit.has_private != 0u) ||
                    (has_private &&
                     verified_private != hit.private_key)) {
                    if (error.empty()) {
                        error =
                            "host verification rejected Metal HDPath hit; "
                            "host=" +
                            hex_lower(verified_public.data(),
                                      verified_public.size()) +
                            ", gpu=" +
                            hex_lower(hit.public_key.data(),
                                      hit.public_key.size());
                    }
                    result = 1;
                    break;
                }
                std::ostringstream line;
                line << "[+] HDPATH:PATH:" << format_path(actual_indexes)
                     << ":TEMPLATE:" << path.text
                     << ":ORDINAL:" << modeinfra::u256_hex(ordinal)
                     << ":PUB:" << hex_lower(
                            verified_public.data(),
                            verified_public.size());
                if (has_private) {
                    line << ":PRIV:" << hex_lower(
                        verified_private.data(), verified_private.size());
                } else {
                    line << ":PRIV:UNAVAILABLE";
                }
                line << ":TARGET_SOURCES:";
                for (std::size_t i = 0u;
                     i < target.occurrences.size(); ++i) {
                    if (i != 0u) line << ',';
                    line << target.occurrences[i].source;
                }
                if (!options.silent) std::cout << line.str() << '\n';
                if (output) {
                    output << line.str() << '\n';
                    output.flush();
                }
                target.solved = true;
                solved_logical += target.occurrences.size();
                ++founds;
                if (hooks.increment_found) hooks.increment_found();
                progress.set_founds(founds);
                progress.set_targets(
                    logical_targets, targets.size(), solved_logical);
            }
            if (result != 0) break;

            if (hooks.add_completed) hooks.add_completed(count);
            progress.credit_completed(
                count,
                count * path.components.size(),
                hits.size(), readback_ns);
            modeinfra::U256 next{};
            if (!modeinfra::add_checked(
                    cursor, modeinfra::U256::from_u64(count), next)) {
                error = "HDPath cursor overflow";
                result = 1;
                break;
            }
            cursor = next;
        }
        if (result != 0) break;
    }

    progress.set_phase(modeinfra::ProgressPhase::Verify);
    progress.end();
    for (auto& buffers : devices) release_buffers(buffers);
    if (result != 0) {
        std::cerr << "[!] HDPath runtime error: " << error << " [!]\n";
        return result;
    }
    std::cout << "[!] HDPath search complete. Solved "
              << solved_logical << "/" << logical_targets
              << " logical targets (" << founds
              << " unique). [!]\n";
    return 0;
}

} // namespace hdpath
