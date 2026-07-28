#include "WarpWalletMode.h"

#include "../MetalBackend.h"
#include "../SecpPrecompute.h"
#include "../host_secp/secp256k1.h"
#include "../host_secp/secp256k1_field.h"
#include "../host_secp/secp256k1_group.h"
#include "../host_secp/secp256k1_scalar.h"
#include "../lib/V/VBase58.h"
#include "../lib/hash/ripemd160.h"
#include "../lib/hash/sha256.h"

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

namespace warpwallet {
namespace {

constexpr std::uint32_t kThreadgroupSize = 256u;
constexpr std::uint32_t kHitCapacity = 65536u;
constexpr std::uint64_t kRuntimeReserve = 512ull * 1024ull * 1024ull;
constexpr std::uint64_t kDefaultLightBatch = 1ull << 16u;
constexpr std::uint32_t kPasswordStride = 128u;

enum class Profile : std::uint32_t {
    Warp = 1u,
    BrainwalletIo = 2u,
    BrainV2 = 3u,
    Rush = 4u,
};

struct alignas(16) GpuConfig {
    std::uint32_t profile = 0u;
    std::uint32_t salt_len = 0u;
    std::uint32_t target_count = 0u;
    std::uint32_t reserved = 0u;
    std::uint32_t window_count = 0u;
    std::uint32_t window_bits = 0u;
    std::uint32_t reserved2 = 0u;
    std::uint32_t reserved3 = 0u;
    std::uint32_t rush_checksum0 = 0u;
    std::uint32_t rush_checksum1 = 0u;
    std::uint32_t reserved4 = 0u;
    std::uint32_t reserved5 = 0u;
};

struct alignas(16) GpuTarget {
    std::array<std::uint8_t, 20> hash160{};
    std::uint32_t source_index = 0u;
    std::uint64_t prefix = 0u;
};

struct alignas(8) GpuHit {
    std::uint64_t candidate_index = 0u;
    std::uint32_t target_index = 0u;
    std::uint32_t password_len = 0u;
    std::array<std::uint8_t, 128> password{};
    std::array<std::uint8_t, 32> private_key{};
    std::array<std::uint8_t, 20> hash160{};
    std::uint32_t profile = 0u;
};

struct alignas(16) GpuDerived {
    std::array<std::uint8_t, 32> private_key{};
    std::uint8_t valid = 0u;
    std::array<std::uint8_t, 15> padding{};
};

struct alignas(16) GpuResolved {
    std::array<std::uint8_t, 20> hash160{};
    std::uint8_t valid = 0u;
    std::array<std::uint8_t, 11> padding{};
};

static_assert(sizeof(GpuConfig) == 48u);
static_assert(sizeof(GpuTarget) == 32u);
static_assert(sizeof(GpuHit) == 200u);
static_assert(sizeof(GpuDerived) == 48u);
static_assert(sizeof(GpuResolved) == 32u);

struct Occurrence {
    std::string source;
    std::string raw;
};

struct Target {
    std::array<std::uint8_t, 20> hash160{};
    std::vector<Occurrence> occurrences;
    bool solved = false;
};

struct Options {
    Profile profile = Profile::Warp;
    std::string profile_name = "warp";
    std::string salt;
    std::vector<std::string> target_values;
    std::vector<std::string> candidate_values;
    std::vector<int> devices{0};
    std::string memory = "auto";
    std::string scrypt_memory;
    std::string output_path;
    std::uint64_t batch = 0u;
    std::array<std::uint8_t, 5> rush_checksum{};
    bool rush_has_checksum = false;
    bool batch_explicit = false;
    bool save = false;
    bool silent = false;
};

struct HostPrecompute {
    unsigned int bits = 8u;
    unsigned int windows = 0u;
    std::size_t pitch = 0u;
    std::vector<secp256k1_ge_storage> entries;
};

struct DeviceBuffers {
    int device = -1;
    secp256k1_ge_storage* precompute = nullptr;
    GpuConfig* config = nullptr;
    std::uint8_t* salt = nullptr;
    char* passwords = nullptr;
    std::uint8_t* password_lengths = nullptr;
    GpuTarget* targets = nullptr;
    std::uint8_t* scratch = nullptr;
    GpuDerived* derived = nullptr;
    GpuResolved* resolved = nullptr;
    std::uint8_t* brain_key1 = nullptr;
    std::uint8_t* brain_key2 = nullptr;
    std::uint8_t* brain_key3 = nullptr;
    GpuHit* hits = nullptr;
    std::uint32_t* hit_count = nullptr;
    std::uint64_t capacity = 0u;
    std::uint64_t scratch_stride = 0u;
    std::uint64_t scratch_lanes = 0u;
    std::uint64_t allocated = 0u;
    std::uint64_t target_capacity = 0u;
    std::uint32_t target_count = 0u;
    std::uint32_t profile = 0u;
};

std::string trim_copy(std::string value) {
    const auto begin = value.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return {};
    const auto end = value.find_last_not_of(" \t\r\n");
    return value.substr(begin, end - begin + 1u);
}

std::string lower_copy(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(),
                   [](unsigned char ch) {
                       return static_cast<char>(std::tolower(ch));
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

bool parse_devices(const std::string& raw, std::vector<int>& result,
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
        error = "-device selected no Metal device";
        return false;
    }
    result.assign(unique.begin(), unique.end());
    return true;
}

bool parse_profile(const std::string& raw, Options& options,
                   std::string& error) {
    const auto colon = raw.find(':');
    const std::string name = lower_copy(trim_copy(raw.substr(0u, colon)));
    const std::string auxiliary =
        colon == std::string::npos ? "" : raw.substr(colon + 1u);
    if (name == "warp" || name == "warpwallet") {
        options.profile = Profile::Warp;
        options.profile_name = "warp";
    } else if (name == "brainwallet.io" || name == "brainwalletio") {
        options.profile = Profile::BrainwalletIo;
        options.profile_name = "brainwallet.io";
    } else if (name == "brainv2" || name == "brain-v2") {
        options.profile = Profile::BrainV2;
        options.profile_name = "brainv2";
    } else if (name == "rush" || name == "rushwallet") {
        options.profile = Profile::Rush;
        options.profile_name = "rush";
    } else {
        error = "unknown -profile '" + name + "'";
        return false;
    }
    options.salt = auxiliary;
    if (options.profile == Profile::Rush) {
        const auto nibble = [](char ch) -> int {
            if (ch >= '0' && ch <= '9') return ch - '0';
            if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
            if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
            return -1;
        };
        if (auxiliary.size() >= 11u &&
            auxiliary[auxiliary.size() - 11u] == '!') {
            bool checksum = true;
            for (std::size_t i = 0u; i < 5u; ++i) {
                const int high =
                    nibble(auxiliary[auxiliary.size() - 10u + i * 2u]);
                const int low =
                    nibble(auxiliary[auxiliary.size() - 9u + i * 2u]);
                if (high < 0 || low < 0) {
                    checksum = false;
                    break;
                }
                options.rush_checksum[i] =
                    static_cast<std::uint8_t>((high << 4) | low);
            }
            if (checksum) {
                options.rush_has_checksum = true;
                options.salt =
                    auxiliary.substr(0u, auxiliary.size() - 10u);
            }
        }
        if (options.salt.empty() || options.salt.back() != '!') {
            error = "rush profile expects PREFIX! or full "
                    "PREFIX!CHECKSUM10HEX fragment";
            return false;
        }
    }
    return true;
}

bool parse_options(int argc, char** argv, Options& options,
                   std::string& error) {
    bool saw_profile = false;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i] == nullptr ? "" : argv[i];
        auto value = [&](const char* name) -> const char* {
            if (i + 1 >= argc || argv[i + 1] == nullptr) {
                error = std::string(name) + " requires a value";
                return nullptr;
            }
            return argv[++i];
        };
        if (arg == "-warpwallet") {
            continue;
        } else if (arg == "-profile") {
            const char* raw = value("-profile");
            if (!raw || !parse_profile(raw, options, error)) return false;
            saw_profile = true;
        } else if (arg == "-target") {
            const char* raw = value("-target");
            if (!raw) return false;
            options.target_values.emplace_back(raw);
        } else if (arg == "-pass" || arg == "-i") {
            const char* raw = value(arg.c_str());
            if (!raw) return false;
            options.candidate_values.emplace_back(raw);
        } else if (arg == "-device") {
            const char* raw = value("-device");
            if (!raw || !parse_devices(raw, options.devices, error)) {
                return false;
            }
        } else if (arg == "-wallet-mem") {
            const char* raw = value("-wallet-mem");
            if (!raw) return false;
            options.memory = raw;
        } else if (arg == "-wallet-scrypt-mem") {
            const char* raw = value("-wallet-scrypt-mem");
            if (!raw) return false;
            options.scrypt_memory = raw;
        } else if (arg == "-n") {
            const char* raw = value("-n");
            if (!raw || !parse_u64(raw, options.batch) ||
                options.batch == 0u ||
                options.batch > std::numeric_limits<std::uint32_t>::max()) {
                error = "-n expects 1..4294967295";
                return false;
            }
            options.batch_explicit = true;
        } else if (arg == "-o") {
            const char* raw = value("-o");
            if (!raw) return false;
            options.output_path = raw;
        } else if (arg == "-save") {
            options.save = true;
        } else if (arg == "-silent") {
            options.silent = true;
        } else if (arg == "-help" || arg == "-h" || arg == "--help" ||
                   arg == "help") {
            continue;
        } else if (!arg.empty() && arg[0] != '-') {
            options.candidate_values.push_back(arg);
        } else {
            error = "unsupported -warpwallet argument '" + arg + "'";
            return false;
        }
    }
    if (!saw_profile) {
        error = "-warpwallet requires -profile NAME[:SALT]";
        return false;
    }
    if (options.target_values.empty()) {
        error = "-warpwallet requires at least one -target";
        return false;
    }
    if (options.candidate_values.empty()) {
        error = "-warpwallet requires -pass VALUE|FILE or -i FILE";
        return false;
    }
    if ((options.profile == Profile::Warp ||
         options.profile == Profile::BrainwalletIo ||
         options.profile == Profile::BrainV2) &&
        options.salt.empty()) {
        error = options.profile_name + " requires a non-empty salt after ':'";
        return false;
    }
    if (options.salt.size() >= kPasswordStride) {
        error = "profile salt/prefix must be shorter than 128 bytes";
        return false;
    }
    return true;
}

int hex_nibble(char ch) {
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

bool decode_hex20(const std::string& raw,
                  std::array<std::uint8_t, 20>& result) {
    std::string value = trim_copy(raw);
    if (value.rfind("0x", 0u) == 0u) value.erase(0u, 2u);
    if (value.size() != 40u) return false;
    for (std::size_t i = 0u; i < result.size(); ++i) {
        const int high = hex_nibble(value[i * 2u]);
        const int low = hex_nibble(value[i * 2u + 1u]);
        if (high < 0 || low < 0) return false;
        result[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return true;
}

void double_sha256(const std::uint8_t* data, std::size_t size,
                   std::array<std::uint8_t, 32>& result) {
    std::array<std::uint8_t, 32> first{};
    sha256(const_cast<std::uint8_t*>(data), size, first.data());
    sha256(first.data(), first.size(), result.data());
}

bool parse_target_token(const std::string& raw,
                        std::array<std::uint8_t, 20>& result,
                        std::string& error) {
    if (decode_hex20(raw, result)) return true;
    std::vector<unsigned char> decoded;
    if (!DecodeBase58(trim_copy(raw), decoded) || decoded.size() != 25u) {
        error = "expected a 20-byte hash160 hex or Base58Check P2PKH address";
        return false;
    }
    std::array<std::uint8_t, 32> checksum{};
    double_sha256(decoded.data(), 21u, checksum);
    if (!std::equal(checksum.begin(), checksum.begin() + 4u,
                    decoded.begin() + 21u)) {
        error = "P2PKH address checksum mismatch";
        return false;
    }
    std::copy(decoded.begin() + 1u, decoded.begin() + 21u, result.begin());
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

bool add_target(const std::string& raw, const std::string& source,
                std::map<std::string, Target>& unique,
                std::string& error) {
    std::array<std::uint8_t, 20> hash{};
    if (!parse_target_token(raw, hash, error)) {
        error = source + ": " + error;
        return false;
    }
    const std::string identity = hex_lower(hash.data(), hash.size());
    auto [entry, inserted] = unique.emplace(identity, Target{});
    if (inserted) entry->second.hash160 = hash;
    entry->second.occurrences.push_back({source, raw});
    return true;
}

bool load_targets(const Options& options, std::vector<Target>& targets,
                  std::string& error) {
    std::map<std::string, Target> unique;
    for (std::size_t i = 0u; i < options.target_values.size(); ++i) {
        const std::string& source = options.target_values[i];
        std::ifstream file(source);
        if (!file) {
            if (!add_target(source, "command line target " +
                    std::to_string(i + 1u), unique, error)) {
                return false;
            }
            continue;
        }
        std::string line;
        std::size_t line_number = 0u;
        while (std::getline(file, line)) {
            ++line_number;
            const auto comment = line.find('#');
            if (comment != std::string::npos) line.erase(comment);
            std::istringstream tokens(line);
            std::string token;
            if (!(tokens >> token)) continue;
            if (!add_target(token, source + ":" +
                    std::to_string(line_number), unique, error)) {
                return false;
            }
        }
    }
    for (auto& item : unique) targets.push_back(std::move(item.second));
    if (targets.empty()) {
        error = "target inputs contain no targets";
        return false;
    }
    if (targets.size() > std::numeric_limits<std::uint32_t>::max()) {
        error = "unique target count exceeds Metal uint index space";
        return false;
    }
    return true;
}

bool append_candidate(const std::string& raw,
                      std::vector<std::string>& result,
                      std::string& error) {
    std::string value = raw;
    if (!value.empty() && value.back() == '\r') value.pop_back();
    if (value.size() >= kPasswordStride) {
        error = "password exceeds the 127-byte profile limit";
        return false;
    }
    result.push_back(std::move(value));
    return true;
}

class CandidateReader {
public:
    explicit CandidateReader(const std::vector<std::string>& sources)
        : sources_(sources) {}

    bool next(std::uint64_t limit,
              std::vector<std::string>& candidates,
              std::uint64_t& candidate_base,
              std::string& error) {
        candidates.clear();
        candidate_base = completed_;
        while (candidates.size() < limit &&
               source_index_ < sources_.size()) {
            if (file_.is_open()) {
                std::string line;
                if (std::getline(file_, line)) {
                    if (!append_candidate(line, candidates, error)) {
                        return false;
                    }
                    ++completed_;
                    continue;
                }
                if (file_.bad()) {
                    error = "failed while reading password file '" +
                            sources_[source_index_] + "'";
                    return false;
                }
                file_.close();
                ++source_index_;
                continue;
            }

            file_.open(sources_[source_index_], std::ios::binary);
            if (file_) continue;
            file_.clear();
            if (!append_candidate(
                    sources_[source_index_], candidates, error)) {
                return false;
            }
            ++completed_;
            ++source_index_;
        }
        return true;
    }

    std::uint64_t completed() const {
        return completed_;
    }

private:
    const std::vector<std::string>& sources_;
    std::size_t source_index_ = 0u;
    std::ifstream file_;
    std::uint64_t completed_ = 0u;
};

std::uint64_t target_prefix(const std::array<std::uint8_t, 20>& hash) {
    std::uint64_t value = 0u;
    for (std::size_t i = 0u; i < 8u; ++i) {
        value = (value << 8u) | hash[i];
    }
    return value;
}

std::uint64_t align_up(std::uint64_t value, std::uint64_t alignment) {
    const std::uint64_t remainder = value % alignment;
    return remainder == 0u ? value : value + alignment - remainder;
}

std::uint64_t scrypt_stride(Profile profile) {
    if (profile == Profile::Warp ||
        profile == Profile::BrainwalletIo) {
        const std::uint64_t n = 1ull << 18u;
        const std::uint64_t block = 128ull * 8ull;
        return align_up(
            n * block + block + 4ull + block, 256ull);
    }
    if (profile == Profile::BrainV2) {
        const std::uint64_t n = 1ull << 16u;
        const std::uint64_t block = 128ull;
        const std::uint64_t b = block * 64ull;
        return align_up(n * block + b + 4ull + block, 256ull);
    }
    return 0u;
}

bool metal_ok(metalError_t status, const char* action,
              std::string& error) {
    if (status == metalSuccess) return true;
    error = std::string(action) + ": " + metalGetErrorString(status);
    return false;
}

template <typename T>
bool allocate(T*& pointer, std::size_t bytes, const char* action,
              std::string& error) {
    if (bytes == 0u) bytes = 1u;
    return metal_ok(
        metalMalloc(reinterpret_cast<void**>(&pointer), bytes),
        action, error);
}

void release(DeviceBuffers& buffers) {
    if (buffers.precompute) metalFree(buffers.precompute);
    if (buffers.config) metalFree(buffers.config);
    if (buffers.salt) metalFree(buffers.salt);
    if (buffers.passwords) metalFree(buffers.passwords);
    if (buffers.password_lengths) metalFree(buffers.password_lengths);
    if (buffers.targets) metalFree(buffers.targets);
    if (buffers.scratch) metalFree(buffers.scratch);
    if (buffers.derived) metalFree(buffers.derived);
    if (buffers.resolved) metalFree(buffers.resolved);
    if (buffers.brain_key1) metalFree(buffers.brain_key1);
    if (buffers.brain_key2) metalFree(buffers.brain_key2);
    if (buffers.brain_key3) metalFree(buffers.brain_key3);
    if (buffers.hits) metalFree(buffers.hits);
    if (buffers.hit_count) metalFree(buffers.hit_count);
    buffers = {};
}

bool derive_hash160(
    const std::array<std::uint8_t, 32>& private_key,
    const HostPrecompute& precompute,
    std::array<std::uint8_t, 20>& hash160) {
    secp256k1_scalar scalar{};
    if (!secp256k1_scalar_set_b32_seckey(
            &scalar, private_key.data())) return false;
    secp256k1_gej jacobian{};
    secp256k1_ecmult_big(
        &jacobian, &scalar, precompute.entries.data(),
        precompute.pitch, static_cast<int>(precompute.windows),
        precompute.bits);
    if (jacobian.infinity != 0) return false;
    secp256k1_ge point{};
    secp256k1_ge_set_gej(&point, &jacobian);
    secp256k1_pubkey public_key{};
    secp256k1_pubkey_save(&public_key, &point);
    std::array<std::uint8_t, 33> compressed{};
    if (secp256k1_ec_pubkey_serialize(
            compressed.data(), compressed.size(), &public_key, true) == 0) {
        return false;
    }
    std::array<std::uint8_t, 32> digest{};
    sha256(compressed.data(), compressed.size(), digest.data());
    ripemd160(digest.data(), digest.size(), hash160.data());
    return true;
}

bool prepare_device(
    int device,
    const HostPrecompute& precompute,
    const GpuConfig& config,
    const std::vector<std::uint8_t>& salt,
    std::uint64_t target_capacity,
    std::uint64_t capacity,
    std::uint64_t scratch_stride,
    std::uint64_t scratch_lanes,
    DeviceBuffers& buffers,
    std::string& error) {
    buffers.device = device;
    buffers.capacity = capacity;
    buffers.scratch_stride = scratch_stride;
    buffers.scratch_lanes = scratch_lanes;
    buffers.target_capacity = target_capacity;
    buffers.profile = config.profile;
    const std::uint64_t precompute_bytes =
        precompute.entries.size() * sizeof(secp256k1_ge_storage);
    const std::uint64_t password_bytes = capacity * kPasswordStride;
    const std::uint64_t length_bytes = capacity;
    const std::uint64_t target_bytes =
        target_capacity * sizeof(GpuTarget);
    const std::uint64_t scratch_bytes =
        scratch_lanes * scratch_stride;
    const std::uint64_t derived_bytes =
        capacity * sizeof(GpuDerived);
    const std::uint64_t resolved_bytes =
        capacity * sizeof(GpuResolved);
    const bool brain_v2 =
        config.profile == static_cast<std::uint32_t>(Profile::BrainV2);
    const std::uint64_t brain_key1_bytes =
        brain_v2 ? capacity * 16384u : 0u;
    const std::uint64_t brain_key2_bytes =
        brain_v2 ? capacity * 8192u : 0u;
    const std::uint64_t brain_key3_bytes =
        brain_v2 ? capacity * 16u : 0u;
    const std::uint64_t hit_bytes =
        static_cast<std::uint64_t>(kHitCapacity) * sizeof(GpuHit);
    if (!metal_ok(metalSetDevice(device), "select WarpWallet device", error) ||
        !allocate(buffers.precompute, precompute_bytes,
                  "allocate WarpWallet precompute", error) ||
        !allocate(buffers.config, sizeof(GpuConfig),
                  "allocate WarpWallet config", error) ||
        !allocate(buffers.salt, std::max<std::size_t>(salt.size(), 1u),
                  "allocate WarpWallet salt", error) ||
        !allocate(buffers.passwords, password_bytes,
                  "allocate WarpWallet passwords", error) ||
        !allocate(buffers.password_lengths, length_bytes,
                  "allocate WarpWallet password lengths", error) ||
        !allocate(buffers.targets, target_bytes,
                  "allocate WarpWallet targets", error) ||
        (scratch_bytes != 0u &&
         !allocate(buffers.scratch, scratch_bytes,
                   "allocate WarpWallet scrypt scratch", error)) ||
        !allocate(buffers.derived, derived_bytes,
                  "allocate WarpWallet derived scalars", error) ||
        !allocate(buffers.resolved, resolved_bytes,
                  "allocate WarpWallet resolved hash160", error) ||
        (brain_v2 &&
         !allocate(buffers.brain_key1, brain_key1_bytes,
                   "allocate Brainv2 key1", error)) ||
        (brain_v2 &&
         !allocate(buffers.brain_key2, brain_key2_bytes,
                   "allocate Brainv2 key2", error)) ||
        (brain_v2 &&
         !allocate(buffers.brain_key3, brain_key3_bytes,
                   "allocate Brainv2 key3", error)) ||
        !allocate(buffers.hits, hit_bytes,
                  "allocate WarpWallet hits", error) ||
        !allocate(buffers.hit_count, sizeof(std::uint32_t),
                  "allocate WarpWallet hit count", error)) {
        release(buffers);
        return false;
    }
    if (!metal_ok(
            metalMemcpy(buffers.precompute, precompute.entries.data(),
                        precompute_bytes, metalMemcpyHostToDevice),
            "upload WarpWallet precompute", error) ||
        !metal_ok(
            metalMemcpy(buffers.config, &config, sizeof(config),
                        metalMemcpyHostToDevice),
            "upload WarpWallet config", error) ||
        (!salt.empty() &&
         !metal_ok(
             metalMemcpy(buffers.salt, salt.data(), salt.size(),
                         metalMemcpyHostToDevice),
             "upload WarpWallet salt", error))) {
        release(buffers);
        return false;
    }
    buffers.allocated =
        precompute_bytes + sizeof(GpuConfig) +
        std::max<std::size_t>(salt.size(), 1u) + password_bytes +
        length_bytes + target_bytes + scratch_bytes + derived_bytes +
        resolved_bytes +
        brain_key1_bytes + brain_key2_bytes + brain_key3_bytes +
        hit_bytes +
        sizeof(std::uint32_t);
    return true;
}

bool run_batch(
    DeviceBuffers& buffers,
    const HostPrecompute& precompute,
    const std::vector<std::string>& candidates,
    const std::vector<GpuTarget>& targets,
    std::uint64_t local_begin,
    std::uint64_t candidate_base,
    std::uint64_t count,
    std::vector<GpuHit>& hits,
    std::uint32_t& raw_count,
    std::uint64_t& readback_ns,
    std::string& error) {
    std::vector<char> passwords(
        static_cast<std::size_t>(count) * kPasswordStride, 0);
    std::vector<std::uint8_t> lengths(
        static_cast<std::size_t>(count), 0u);
    for (std::uint64_t i = 0u; i < count; ++i) {
        const std::string& password =
            candidates[static_cast<std::size_t>(local_begin + i)];
        lengths[static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>(password.size());
        std::memcpy(passwords.data() + i * kPasswordStride,
                    password.data(), password.size());
    }
    if (!metal_ok(metalSetDevice(buffers.device),
                  "select WarpWallet device", error) ||
        !metal_ok(
            metalMemcpy(buffers.passwords, passwords.data(),
                        passwords.size(), metalMemcpyHostToDevice),
            "upload WarpWallet passwords", error) ||
        !metal_ok(
            metalMemcpy(buffers.password_lengths, lengths.data(),
                        lengths.size(), metalMemcpyHostToDevice),
            "upload WarpWallet password lengths", error) ||
        !metal_ok(
            metalMemset(buffers.hit_count, 0, sizeof(std::uint32_t)),
            "reset WarpWallet hit count", error)) {
        return false;
    }
    const std::uint64_t pitch =
        static_cast<std::uint64_t>(precompute.pitch);
    const std::uint32_t window_count = precompute.windows;
    const std::uint32_t window_bits = precompute.bits;
    const std::uint32_t grid = static_cast<std::uint32_t>(
        (count + kThreadgroupSize - 1u) / kThreadgroupSize *
        kThreadgroupSize);
    if (buffers.profile ==
        static_cast<std::uint32_t>(Profile::BrainV2)) {
        if (!metal_ok(
                metal_launch(
                    "workerBrainV2First", grid, kThreadgroupSize,
                    buffers.config, buffers.salt, buffers.passwords,
                    buffers.password_lengths, count, buffers.scratch,
                    buffers.scratch_stride, buffers.brain_key1),
                "launch workerBrainV2First", error)) {
            return false;
        }
        const std::uint64_t total_jobs = count * 256u;
        for (std::uint64_t job_base = 0u;
             job_base < total_jobs;
             job_base += buffers.scratch_lanes) {
            const std::uint64_t jobs = std::min<std::uint64_t>(
                buffers.scratch_lanes, total_jobs - job_base);
            const std::uint32_t middle_grid =
                static_cast<std::uint32_t>(
                    (jobs + kThreadgroupSize - 1u) /
                    kThreadgroupSize * kThreadgroupSize);
            if (!metal_ok(
                    metal_launch(
                        "workerBrainV2Middle", middle_grid,
                        kThreadgroupSize, buffers.brain_key1,
                        buffers.brain_key2, job_base, jobs,
                        buffers.scratch, buffers.scratch_stride),
                    "launch workerBrainV2Middle", error)) {
                return false;
            }
        }
        if (!metal_ok(
                metal_launch(
                    "workerBrainV2Last", grid, kThreadgroupSize,
                    buffers.passwords, buffers.password_lengths,
                    buffers.brain_key2, count, buffers.scratch,
                    buffers.scratch_stride, buffers.brain_key3),
                "launch workerBrainV2Last", error) ||
            !metal_ok(
                metal_launch(
                    "workerBrainV2Finalize", grid, kThreadgroupSize,
                    buffers.brain_key3, count, buffers.derived),
                "launch workerBrainV2Finalize", error)) {
            return false;
        }
    } else if (!metal_ok(
        metal_launch(
            "workerWarpWalletKdf", grid, kThreadgroupSize,
            buffers.config, buffers.salt, buffers.passwords,
            buffers.password_lengths, count, buffers.scratch,
            buffers.scratch_stride, buffers.derived),
        "launch workerWarpWalletKdf", error)) {
        return false;
    }
    if (!metal_ok(
            metal_launch(
                "workerWarpWalletHash160", grid, kThreadgroupSize,
                buffers.precompute, pitch, window_count, window_bits,
                buffers.derived, count, buffers.resolved),
            "launch workerWarpWalletHash160", error)) {
        return false;
    }
    for (std::uint64_t target_base = 0u;
         target_base < targets.size();
         target_base += buffers.target_capacity) {
        const std::uint64_t target_count64 =
            std::min<std::uint64_t>(
                buffers.target_capacity, targets.size() - target_base);
        const std::uint32_t target_count =
            static_cast<std::uint32_t>(target_count64);
        if (!metal_ok(
                metalMemcpy(
                    buffers.targets,
                    targets.data() + target_base,
                    static_cast<std::size_t>(target_count) *
                        sizeof(GpuTarget),
                    metalMemcpyHostToDevice),
                "upload WarpWallet target shard", error) ||
            !metal_ok(
                metal_launch(
                    "workerWarpWalletLookup", grid, kThreadgroupSize,
                    buffers.resolved, buffers.derived,
                    buffers.passwords, buffers.password_lengths,
                    candidate_base, count, buffers.targets, target_count,
                    buffers.profile, buffers.hits, buffers.hit_count,
                    kHitCapacity),
                "launch workerWarpWalletLookup", error)) {
            return false;
        }
    }
    if (!metal_ok(
            metalDeviceSynchronize(),
                  "synchronize workerWarpWallet pipeline", error)) {
        return false;
    }
    const auto started = std::chrono::steady_clock::now();
    raw_count = 0u;
    if (!metal_ok(
            metalMemcpy(&raw_count, buffers.hit_count, sizeof(raw_count),
                        metalMemcpyDeviceToHost),
            "read WarpWallet hit count", error)) {
        return false;
    }
    const std::uint32_t stored = std::min(raw_count, kHitCapacity);
    hits.resize(stored);
    if (stored != 0u &&
        !metal_ok(
            metalMemcpy(hits.data(), buffers.hits,
                        static_cast<std::size_t>(stored) * sizeof(GpuHit),
                        metalMemcpyDeviceToHost),
            "read WarpWallet hits", error)) {
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
            std::strcmp(argv[i], "-warpwallet") == 0) return true;
    }
    return false;
}

void print_help() {
    std::cout << R"HELP([!] MAIN MODE: -warpwallet  (historical memory-hard brainwallet profiles)
[!] ======================================================================
[!] Purpose:
[!] Derive secp256k1 private keys from password candidates with exact
[!] historical WarpWallet-family KDF profiles on Metal, then compare
[!] compressed Bitcoin P2PKH hash160 targets. Every hit is independently
[!] checked through the host secp256k1 implementation before output.
[!]
[!] Required arguments:
[!] -profile NAME:SALT
[!]   warp:SALT          WarpWallet scrypt(2^18,8,1) XOR
[!]                      PBKDF2-HMAC-SHA256(2^16).
[!]   brainwallet.io:SALT Legacy brainwallet.io scrypt profile.
[!]   brainv2:SALT       Brainv2 three-stage memory-hard profile.
[!]   rush:FRAGMENT       RushWallet full PREFIX!CHECKSUM10HEX fragment.
[!]                       PREFIX! alone is accepted without early rejection.
[!] -target VALUE        Repeatable 20-byte hash160 hex or Base58Check P2PKH.
[!]                      An existing file is read one target per line;
[!]                      blank lines, # comments and trailing text are ignored.
[!] -pass VALUE|FILE     Repeatable literal password or password file.
[!] -i FILE              Additional password file, read in bounded windows.
[!]
[!] GPU / memory / MultiGPU:
[!] -device LIST                     Metal indexes, e.g. 0 or 0,1.
[!] -wallet-mem auto|all|NN%|SIZE    Hard unified-memory working-set budget.
[!] -wallet-scrypt-mem SIZE          Optional stricter scrypt scratch budget.
[!] -n N                             Explicit active-candidate cap.
[!] Targets are sharded below maxBufferLength. KDF and secp/hash160 are
[!] counted and calculated once per password, never once per target shard.
[!]
[!] Statistics / output:
[!] SpeedThreadFunc is the only live statistics printer and reports KDF/s.
[!] -o FILE                          Append verified results.
[!] -save                            Use WARPWALLET_FOUND.txt by default.
[!] -silent                          Suppress found-result lines on stdout.
[!]
[!] Examples:
[!] ./METAL_CRYPTO_TOOLKIT -warpwallet -profile warp:email@example.com \
[!]   -pass passwords.txt -target 001122... -wallet-mem auto
[!] ./METAL_CRYPTO_TOOLKIT -warpwallet \
[!]   -profile rush:rush!e61ae7a87d \
[!]   -pass "correct horse battery staple" \
[!]   -target 1895f1392560ed5467adf9bed7dd4c37443bdfba
[!] ./METAL_CRYPTO_TOOLKIT -help -warpwallet
[!]
[!] Limitations:
[!] Passwords and profile salts/prefixes are currently limited to 127 bytes.
[!] Brainv2 performs 258 scrypt invocations per password and is very costly.
[!] Huge KDF spaces remain computationally expensive despite GPU execution.
[!] CLI errors return 2; runtime failures return 1; exhausted search returns 0.
)HELP";
}

int run(int argc, char** argv, const RuntimeHooks& hooks) {
    Options options;
    std::string error;
    if (!parse_options(argc, argv, options, error)) {
        std::cerr << "[!] WarpWallet CLI error: " << error << " [!]\n";
        return 2;
    }
    std::vector<Target> targets;
    if (!load_targets(options, targets, error)) {
        std::cerr << "[!] WarpWallet target error: " << error << " [!]\n";
        return 2;
    }
    HostPrecompute precompute;
    if (!build_secp256k1_precompute_table_host(
            precompute.bits, precompute.entries, precompute.pitch,
            precompute.windows, error)) {
        std::cerr << "[!] WarpWallet runtime error: " << error << " [!]\n";
        return 1;
    }
    std::vector<GpuTarget> gpu_targets(targets.size());
    for (std::size_t i = 0u; i < targets.size(); ++i) {
        gpu_targets[i].hash160 = targets[i].hash160;
        gpu_targets[i].source_index = static_cast<std::uint32_t>(i);
        gpu_targets[i].prefix = target_prefix(targets[i].hash160);
    }
    std::sort(gpu_targets.begin(), gpu_targets.end(),
              [](const GpuTarget& left, const GpuTarget& right) {
                  if (left.prefix != right.prefix) {
                      return left.prefix < right.prefix;
                  }
                  return left.hash160 < right.hash160;
              });

    std::vector<std::uint8_t> salt(options.salt.begin(), options.salt.end());
    if (options.profile == Profile::Warp) salt.push_back(1u);
    GpuConfig config{};
    config.profile = static_cast<std::uint32_t>(options.profile);
    config.salt_len = static_cast<std::uint32_t>(options.salt.size());
    config.target_count = static_cast<std::uint32_t>(gpu_targets.size());
    config.window_count = precompute.windows;
    config.window_bits = precompute.bits;
    if (options.rush_has_checksum) {
        config.reserved = 1u;
        config.rush_checksum0 =
            static_cast<std::uint32_t>(options.rush_checksum[0]) |
            (static_cast<std::uint32_t>(options.rush_checksum[1]) << 8u) |
            (static_cast<std::uint32_t>(options.rush_checksum[2]) << 16u) |
            (static_cast<std::uint32_t>(options.rush_checksum[3]) << 24u);
        config.rush_checksum1 = options.rush_checksum[4];
    }

    int device_count = 0;
    if (!metal_ok(metalGetDeviceCount(&device_count),
                  "query Metal devices", error)) {
        std::cerr << "[!] WarpWallet runtime error: " << error << " [!]\n";
        return 1;
    }
    std::vector<modeinfra::MemoryDeviceInfo> device_info;
    for (int device : options.devices) {
        if (device < 0 || device >= device_count) {
            std::cerr << "[!] WarpWallet CLI error: unavailable device "
                      << device << " [!]\n";
            return 2;
        }
        metalDeviceProp properties{};
        if (!metal_ok(metalGetDeviceProperties(&properties, device),
                      "query Metal device properties", error)) {
            std::cerr << "[!] WarpWallet runtime error: " << error << " [!]\n";
            return 1;
        }
        device_info.push_back({
            properties.recommendedMaxWorkingSetSize,
            properties.currentAllocatedSize,
            properties.maxBufferLength,
            properties.hasUnifiedMemory != 0,
        });
    }
    const std::uint64_t precompute_bytes =
        precompute.entries.size() * sizeof(secp256k1_ge_storage);
    const std::uint64_t base_fixed_per_device =
        precompute_bytes +
        static_cast<std::uint64_t>(kHitCapacity) * sizeof(GpuHit) +
        1024u * 1024u;
    modeinfra::MemorySpec memory_spec;
    modeinfra::MemoryBudget budget;
    if (!modeinfra::parse_memory_spec(options.memory, memory_spec, error) ||
        !modeinfra::resolve_memory_budget(
            memory_spec, device_info,
            base_fixed_per_device + sizeof(GpuTarget) + kPasswordStride,
            0u, budget, error, kRuntimeReserve)) {
        std::cerr << "[!] WarpWallet memory error: " << error << " [!]\n";
        return 2;
    }
    std::uint64_t per_device_budget = budget.per_device_budget;
    const std::uint64_t available_target_bytes =
        per_device_budget > base_fixed_per_device
        ? (per_device_budget - base_fixed_per_device) / 8u
        : 0u;
    const std::uint64_t target_capacity =
        std::min<std::uint64_t>({
            gpu_targets.size(),
            std::max<std::uint64_t>(
                1u, available_target_bytes / sizeof(GpuTarget)),
            budget.max_buffer_length / sizeof(GpuTarget),
            std::numeric_limits<std::uint32_t>::max(),
        });
    if (target_capacity == 0u) {
        std::cerr << "[!] WarpWallet memory error: no target shard fits the "
                     "selected working-set budget [!]\n";
        return 2;
    }
    const std::uint64_t fixed_per_device =
        base_fixed_per_device + target_capacity * sizeof(GpuTarget);
    if (!options.scrypt_memory.empty()) {
        modeinfra::MemorySpec scratch_spec;
        modeinfra::MemoryBudget scratch_budget;
        if (!modeinfra::parse_memory_spec(
                options.scrypt_memory, scratch_spec, error) ||
            !modeinfra::resolve_memory_budget(
                scratch_spec, device_info, 1u, 0u,
                scratch_budget, error, 0u)) {
            std::cerr << "[!] WarpWallet scrypt memory error: "
                      << error << " [!]\n";
            return 2;
        }
        per_device_budget = std::min(
            per_device_budget,
            fixed_per_device + scratch_budget.per_device_budget);
    }
    const std::uint64_t stride = scrypt_stride(options.profile);
    std::uint64_t capacity = 0u;
    std::uint64_t scratch_lanes = 0u;
    if (options.profile == Profile::BrainV2) {
        const std::uint64_t intermediate =
            kPasswordStride + 1u + sizeof(GpuDerived) +
            sizeof(GpuResolved) +
            16384u + 8192u + 16u;
        if (per_device_budget > fixed_per_device + intermediate) {
            capacity = 1u;
            scratch_lanes = std::min<std::uint64_t>(
                256u,
                (per_device_budget - fixed_per_device - intermediate) /
                    stride);
            scratch_lanes = std::min<std::uint64_t>(
                scratch_lanes, budget.max_buffer_length / stride);
        }
    } else {
        const std::uint64_t per_candidate =
            kPasswordStride + 1u + sizeof(GpuDerived) +
            sizeof(GpuResolved) + stride;
        capacity =
            per_device_budget > fixed_per_device
            ? (per_device_budget - fixed_per_device) / per_candidate
            : 0u;
        const std::uint64_t buffer_capacity =
            stride == 0u
            ? std::numeric_limits<std::uint32_t>::max()
            : budget.max_buffer_length / stride;
        capacity = std::min(capacity, buffer_capacity);
        capacity = std::min<std::uint64_t>(
            capacity, std::numeric_limits<std::uint32_t>::max());
        if (options.batch_explicit) {
            capacity = std::min(capacity, options.batch);
        }
        if (stride == 0u && !options.batch_explicit) {
            capacity = std::min(capacity, kDefaultLightBatch);
        }
        scratch_lanes = stride == 0u ? 0u : capacity;
    }
    if (capacity == 0u ||
        (options.profile == Profile::BrainV2 &&
         scratch_lanes == 0u)) {
        std::cerr << "[!] WarpWallet memory error: no candidate fits the "
                     "selected working-set budget [!]\n";
        return 2;
    }

    std::vector<DeviceBuffers> devices(options.devices.size());
    std::uint64_t allocated = 0u;
    for (std::size_t i = 0u; i < devices.size(); ++i) {
        if (!prepare_device(
                options.devices[i], precompute, config, salt,
                target_capacity, capacity, stride, scratch_lanes,
                devices[i], error)) {
            for (auto& device : devices) release(device);
            std::cerr << "[!] WarpWallet runtime error: " << error << " [!]\n";
            return 1;
        }
        allocated += devices[i].allocated;
    }
    if (allocated > budget.total_budget) {
        for (auto& device : devices) release(device);
        std::cerr << "[!] WarpWallet memory error: allocated working set "
                     "exceeds -wallet-mem [!]\n";
        return 2;
    }

    if (options.output_path.empty() && options.save) {
        options.output_path = "WARPWALLET_FOUND.txt";
    }
    std::ofstream output;
    if (!options.output_path.empty()) {
        output.open(options.output_path, std::ios::app);
        if (!output) {
            for (auto& device : devices) release(device);
            std::cerr << "[!] WarpWallet runtime error: cannot open output "
                         "file [!]\n";
            return 1;
        }
    }
    std::uint64_t logical_targets = 0u;
    for (const Target& target : targets) {
        logical_targets += target.occurrences.size();
    }
    std::cout << "[!] WarpWallet profile: " << options.profile_name
              << " | candidates: streaming"
              << " | targets: " << targets.size() << " unique/"
              << logical_targets << " logical | devices: "
              << devices.size() << " | active KDF lanes: "
              << capacity << " | target shard: " << target_capacity
              << " | scratch/lane: " << stride;
    if (options.profile == Profile::BrainV2) {
        std::cout << " | middle lanes: " << scratch_lanes;
    }
    std::cout << " [!]\n";

    modeinfra::ModeProgress& progress =
        modeinfra::global_mode_progress();
    progress.begin("WARPWALLET", modeinfra::ProgressUnit::Kdf,
                   modeinfra::ProgressPhase::Search);
    progress.set_targets(logical_targets, targets.size(), 0u);
    progress.set_allocated_working_set(allocated);

    CandidateReader reader(options.candidate_values);
    std::size_t device_slot = 0u;
    std::uint64_t founds = 0u;
    std::uint64_t solved_logical = 0u;
    int result = 0;
    while (solved_logical < logical_targets) {
        std::vector<std::string> candidates;
        std::uint64_t batch_base = 0u;
        if (!reader.next(capacity, candidates, batch_base, error)) {
            result = 2;
            break;
        }
        if (candidates.empty()) break;
        std::uint64_t local_cursor = 0u;
        while (local_cursor < candidates.size() &&
               solved_logical < logical_targets) {
            std::uint64_t count = candidates.size() - local_cursor;
            bool completed = false;
            while (!completed) {
            std::vector<GpuHit> hits;
            std::uint32_t raw_count = 0u;
            std::uint64_t readback_ns = 0u;
            DeviceBuffers& buffers = devices[device_slot];
            if (!run_batch(buffers, precompute, candidates, gpu_targets,
                           local_cursor, batch_base + local_cursor, count,
                           hits, raw_count, readback_ns, error)) {
                result = 1;
                break;
            }
            if (raw_count > kHitCapacity) {
                if (count == 1u) {
                    error = "hit buffer overflows for one password";
                    result = 1;
                    break;
                }
                count = std::max<std::uint64_t>(1u, count / 2u);
                continue;
            }
            std::uint64_t exact = 0u;
            for (const GpuHit& hit : hits) {
                if (hit.target_index >= targets.size() ||
                    hit.candidate_index < batch_base ||
                    hit.candidate_index >=
                        batch_base + candidates.size() ||
                    hit.password_len >= kPasswordStride) {
                    error = "GPU returned an invalid hit index";
                    result = 1;
                    break;
                }
                const std::uint32_t original = hit.target_index;
                if (original >= targets.size()) {
                    error = "GPU returned an invalid target mapping";
                    result = 1;
                    break;
                }
                ++exact;
                const std::string password(
                    reinterpret_cast<const char*>(hit.password.data()),
                    hit.password_len);
                const std::size_t candidate_offset =
                    static_cast<std::size_t>(
                        hit.candidate_index - batch_base);
                std::array<std::uint8_t, 20> verified_hash{};
                if (password != candidates[candidate_offset] ||
                    !derive_hash160(hit.private_key, precompute,
                                    verified_hash) ||
                    verified_hash != hit.hash160 ||
                    verified_hash != targets[original].hash160) {
                    error = "GPU hit failed full host secp256k1 verification";
                    result = 1;
                    break;
                }
                if (targets[original].solved) continue;
                targets[original].solved = true;
                solved_logical += targets[original].occurrences.size();
                ++founds;
                if (hooks.increment_found) hooks.increment_found();
                std::ostringstream line;
                line << "WARPWALLET_FOUND"
                     << " PROFILE:" << options.profile_name
                     << " TARGET:"
                     << hex_lower(verified_hash.data(), verified_hash.size())
                     << " PASSWORD:" << password
                     << " PRIVATE:"
                     << hex_lower(hit.private_key.data(), hit.private_key.size())
                     << " SOURCE:";
                for (std::size_t i = 0u;
                     i < targets[original].occurrences.size(); ++i) {
                    if (i != 0u) line << ",";
                    line << targets[original].occurrences[i].source;
                }
                if (!options.silent) std::cout << line.str() << "\n";
                if (output) {
                    output << line.str() << "\n";
                    output.flush();
                }
            }
            if (result != 0) break;
            if (hooks.add_completed) hooks.add_completed(count);
            progress.credit_completed(count, count, exact, readback_ns);
            progress.set_targets(
                logical_targets, targets.size(), solved_logical);
            progress.set_founds(founds);
            local_cursor += count;
            device_slot = (device_slot + 1u) % devices.size();
            completed = true;
            }
            if (result != 0) break;
        }
        if (result != 0) break;
    }
    progress.end();
    for (auto& device : devices) release(device);
    if (result != 0) {
        std::cerr << "[!] WarpWallet runtime error: " << error << " [!]\n";
    }
    return result;
}

} // namespace warpwallet
