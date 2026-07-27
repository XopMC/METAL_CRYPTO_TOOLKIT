#include "HammingMode.h"

#include "../MetalBackend.h"
#include "../SecpPrecompute.h"
#include "../host_secp/secp256k1.h"
#include "../host_secp/secp256k1_field.h"
#include "../host_secp/secp256k1_group.h"
#include "../host_secp/secp256k1_scalar.h"

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

namespace hamming {
namespace {

constexpr std::uint32_t kThreadgroupSize = 256u;
constexpr std::uint64_t kDefaultBatch = 1ull << 16u;
constexpr std::uint64_t kMaximumBatch =
    (static_cast<std::uint64_t>(
         std::numeric_limits<std::uint32_t>::max()) /
     kThreadgroupSize) *
    kThreadgroupSize;
constexpr std::uint32_t kHitCapacity = 65536u;
constexpr std::uint64_t kRuntimeReserve = 512ull * 1024ull * 1024ull;
constexpr std::size_t kChooseSide = 257u;

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
    std::uint32_t reserved = 0u;
    std::array<std::uint8_t, 32> private_key{};
    std::array<std::uint8_t, 33> public_key{};
    std::array<std::uint8_t, 7> padding{};
};

static_assert(sizeof(GpuTarget) == 64u);
static_assert(sizeof(GpuHit) == 112u);

struct HostPrecompute {
    unsigned int bits = 8u;
    unsigned int windows = 0u;
    std::size_t pitch = 0u;
    std::vector<secp256k1_ge_storage> entries;
};

struct Occurrence {
    std::string source;
    std::string raw;
};

struct Target {
    std::array<std::uint8_t, 33> key{};
    std::vector<Occurrence> occurrences;
    bool solved = false;
};

struct Options {
    std::string specification;
    std::vector<std::string> target_values;
    std::vector<int> devices{0};
    std::string start = "0";
    std::string end;
    std::string output_path;
    std::string memory = "auto";
    std::uint64_t batch = kDefaultBatch;
    bool save = false;
    bool silent = false;
};

struct Domain {
    std::array<std::uint8_t, 32> base{};
    std::array<std::uint8_t, 32> mask{};
    std::vector<std::uint8_t> mutable_bits;
    std::uint32_t distance = 0u;
    std::vector<modeinfra::U256> choose;
    std::vector<std::uint64_t> choose_flat;
    modeinfra::U256 size{};
};

struct DeviceBuffers {
    int device = -1;
    secp256k1_ge_storage* precompute = nullptr;
    std::uint8_t* base = nullptr;
    std::uint8_t* mutable_bits = nullptr;
    std::uint64_t* choose = nullptr;
    std::uint64_t* base_ordinal = nullptr;
    GpuTarget* targets = nullptr;
    GpuHit* hits = nullptr;
    std::uint32_t* hit_count = nullptr;
    std::uint64_t target_capacity = 0u;
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

bool decode_hex(const std::string& raw,
                std::vector<std::uint8_t>& bytes) {
    const std::string value = trim_copy(raw);
    if (value.empty() || (value.size() & 1u) != 0u) return false;
    bytes.resize(value.size() / 2u);
    for (std::size_t i = 0u; i < bytes.size(); ++i) {
        auto nibble = [](char ch) -> int {
            if (ch >= '0' && ch <= '9') return ch - '0';
            if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
            if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
            return -1;
        };
        const int high = nibble(value[i * 2u]);
        const int low = nibble(value[i * 2u + 1u]);
        if (high < 0 || low < 0) return false;
        bytes[i] = static_cast<std::uint8_t>((high << 4) | low);
    }
    return true;
}

std::string hex_lower(const std::uint8_t* bytes, std::size_t size) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0u; i < size; ++i) {
        out << std::setw(2) << static_cast<unsigned>(bytes[i]);
    }
    return out.str();
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
        auto require_value = [&](const char* name) -> const char* {
            if (i + 1 >= argc || argv[i + 1] == nullptr) {
                error = std::string(name) + " requires a value";
                return nullptr;
            }
            return argv[++i];
        };
        if (arg == "-priv") {
            continue;
        } else if (arg == "-hamming") {
            const char* value = require_value("-hamming");
            if (!value) return false;
            options.specification = value;
        } else if (arg == "-target") {
            const char* value = require_value("-target");
            if (!value) return false;
            options.target_values.emplace_back(value);
        } else if (arg == "-start") {
            const char* value = require_value("-start");
            if (!value) return false;
            options.start = value;
        } else if (arg == "-end") {
            const char* value = require_value("-end");
            if (!value) return false;
            options.end = value;
        } else if (arg == "-device") {
            const char* value = require_value("-device");
            if (!value ||
                !parse_device_list(value, options.devices, error)) {
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
        } else {
            error = "unsupported -priv -hamming argument '" + arg + "'";
            return false;
        }
    }
    if (options.specification.empty()) {
        error = "-priv -hamming requires BASE:DISTANCE[:MUTABLE_MASK]";
        return false;
    }
    if (options.target_values.empty()) {
        error = "-priv -hamming requires at least one -target";
        return false;
    }
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
            error = "uncompressed public key has invalid y";
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

bool add_target(const std::string& token, const std::string& source,
                std::map<std::string, Target>& unique,
                std::string& error) {
    std::array<std::uint8_t, 33> key{};
    if (!parse_public_key(token, key, error)) {
        error = source + ": " + error;
        return false;
    }
    const std::string identity = hex_lower(key.data(), key.size());
    auto [entry, inserted] = unique.emplace(identity, Target{});
    if (inserted) entry->second.key = key;
    entry->second.occurrences.push_back({source, token});
    return true;
}

bool load_targets(const Options& options,
                  std::vector<Target>& targets,
                  std::string& error) {
    std::map<std::string, Target> unique;
    for (std::size_t index = 0u;
         index < options.target_values.size(); ++index) {
        const std::string value = options.target_values[index];
        std::ifstream file(value);
        if (!file) {
            if (!add_target(
                    value, "command line target " +
                    std::to_string(index + 1u), unique, error)) {
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
            if (!add_target(
                    token, value + ":" + std::to_string(line_number),
                    unique, error)) {
                return false;
            }
        }
    }
    for (auto& entry : unique) {
        targets.push_back(std::move(entry.second));
    }
    if (targets.empty()) {
        error = "target inputs contained no public keys";
        return false;
    }
    if (targets.size() >
        static_cast<std::size_t>(
            std::numeric_limits<std::uint32_t>::max())) {
        error = "target count exceeds the Metal uint index space";
        return false;
    }
    return true;
}

std::size_t choose_index(std::uint32_t n, std::uint32_t k) {
    return static_cast<std::size_t>(n) * kChooseSide + k;
}

bool build_choose(Domain& domain, std::string& error) {
    domain.choose.assign(kChooseSide * kChooseSide, {});
    domain.choose[choose_index(0u, 0u)] =
        modeinfra::U256::from_u64(1u);
    for (std::uint32_t n = 1u; n <= 256u; ++n) {
        domain.choose[choose_index(n, 0u)] =
            modeinfra::U256::from_u64(1u);
        domain.choose[choose_index(n, n)] =
            modeinfra::U256::from_u64(1u);
        for (std::uint32_t k = 1u; k < n; ++k) {
            modeinfra::U256 sum{};
            if (!modeinfra::add_checked(
                    domain.choose[choose_index(n - 1u, k - 1u)],
                    domain.choose[choose_index(n - 1u, k)], sum)) {
                error = "C(" + std::to_string(n) + "," +
                    std::to_string(k) + ") exceeds U256";
                return false;
            }
            domain.choose[choose_index(n, k)] = sum;
        }
    }
    domain.choose_flat.resize(domain.choose.size() * 4u);
    for (std::size_t i = 0u; i < domain.choose.size(); ++i) {
        for (std::size_t limb = 0u; limb < 4u; ++limb) {
            domain.choose_flat[i * 4u + limb] =
                domain.choose[i].limbs[limb];
        }
    }
    return true;
}

bool parse_domain(const Options& options, Domain& domain,
                  std::string& error) {
    std::vector<std::string> parts;
    std::stringstream input(options.specification);
    std::string item;
    while (std::getline(input, item, ':')) parts.push_back(item);
    if (parts.size() != 2u && parts.size() != 3u) {
        error = "-hamming expects BASE:DISTANCE[:MUTABLE_MASK]";
        return false;
    }
    std::vector<std::uint8_t> bytes;
    if (!decode_hex(parts[0], bytes) || bytes.size() != 32u) {
        error = "BASE must be exactly 64 hexadecimal characters";
        return false;
    }
    std::copy(bytes.begin(), bytes.end(), domain.base.begin());
    std::uint64_t distance = 0u;
    if (!parse_u64(parts[1], distance) || distance > 256u) {
        error = "DISTANCE must be an integer in 0..256";
        return false;
    }
    domain.distance = static_cast<std::uint32_t>(distance);
    if (parts.size() == 3u) {
        if (!decode_hex(parts[2], bytes) || bytes.size() != 32u) {
            error = "MUTABLE_MASK must be exactly 64 hexadecimal characters";
            return false;
        }
        std::copy(bytes.begin(), bytes.end(), domain.mask.begin());
    } else {
        domain.mask.fill(0xffu);
    }
    for (std::uint32_t bit = 0u; bit < 256u; ++bit) {
        if ((domain.mask[bit >> 3u] &
             static_cast<std::uint8_t>(0x80u >> (bit & 7u))) != 0u) {
            domain.mutable_bits.push_back(
                static_cast<std::uint8_t>(bit));
        }
    }
    if (domain.distance > domain.mutable_bits.size()) {
        error = "DISTANCE exceeds popcount(MUTABLE_MASK)";
        return false;
    }
    if (!build_choose(domain, error)) return false;
    domain.size = domain.choose[choose_index(
        static_cast<std::uint32_t>(domain.mutable_bits.size()),
        domain.distance)];
    return true;
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

bool unrank(const Domain& domain, const modeinfra::U256& ordinal,
            std::array<std::uint8_t, 32>& result) {
    result = domain.base;
    modeinfra::U256 rank = ordinal;
    std::uint32_t remaining = domain.distance;
    for (std::uint32_t position = 0u;
         position < domain.mutable_bits.size() && remaining != 0u;
         ++position) {
        const std::uint32_t available =
            static_cast<std::uint32_t>(
                domain.mutable_bits.size() - position - 1u);
        const modeinfra::U256& selected =
            domain.choose[choose_index(available, remaining - 1u)];
        if (modeinfra::compare(rank, selected) < 0) {
            const std::uint32_t bit = domain.mutable_bits[position];
            result[bit >> 3u] ^=
                static_cast<std::uint8_t>(0x80u >> (bit & 7u));
            --remaining;
        } else if (!modeinfra::subtract_checked(
                       rank, selected, rank)) {
            return false;
        }
    }
    return remaining == 0u;
}

std::uint64_t target_prefix(
    const std::array<std::uint8_t, 33>& key) {
    std::uint64_t result = 0u;
    for (std::size_t i = 0u; i < 8u; ++i) {
        result = (result << 8u) | key[i];
    }
    return result;
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
    if (bytes == 0u) bytes = 1u;
    return metal_ok(
        metalMalloc(reinterpret_cast<void**>(&pointer), bytes),
        action, error);
}

void release_buffers(DeviceBuffers& buffers) {
    if (buffers.precompute) metalFree(buffers.precompute);
    if (buffers.base) metalFree(buffers.base);
    if (buffers.mutable_bits) metalFree(buffers.mutable_bits);
    if (buffers.choose) metalFree(buffers.choose);
    if (buffers.base_ordinal) metalFree(buffers.base_ordinal);
    if (buffers.targets) metalFree(buffers.targets);
    if (buffers.hits) metalFree(buffers.hits);
    if (buffers.hit_count) metalFree(buffers.hit_count);
    buffers = {};
}

bool prepare_buffers(
    int device,
    const Domain& domain,
    const HostPrecompute& precompute,
    std::uint64_t target_capacity,
    DeviceBuffers& buffers,
    std::string& error) {
    buffers.device = device;
    const std::size_t precompute_bytes =
        precompute.entries.size() * sizeof(secp256k1_ge_storage);
    const std::size_t mutable_bytes =
        std::max<std::size_t>(domain.mutable_bits.size(), 1u);
    const std::size_t choose_bytes =
        domain.choose_flat.size() * sizeof(std::uint64_t);
    const std::size_t target_bytes =
        static_cast<std::size_t>(target_capacity) * sizeof(GpuTarget);
    if (!metal_ok(
            metalSetDevice(device), "select Hamming device", error) ||
        !allocate(buffers.precompute, precompute_bytes,
                  "allocate Hamming precompute", error) ||
        !allocate(buffers.base, domain.base.size(),
                  "allocate Hamming base", error) ||
        !allocate(buffers.mutable_bits, mutable_bytes,
                  "allocate Hamming mutable bits", error) ||
        !allocate(buffers.choose, choose_bytes,
                  "allocate Hamming choose table", error) ||
        !allocate(buffers.base_ordinal, 4u * sizeof(std::uint64_t),
                  "allocate Hamming ordinal", error) ||
        !allocate(buffers.targets, target_bytes,
                  "allocate Hamming targets", error) ||
        !allocate(
            buffers.hits,
            static_cast<std::size_t>(kHitCapacity) * sizeof(GpuHit),
            "allocate Hamming hits", error) ||
        !allocate(buffers.hit_count, sizeof(std::uint32_t),
                  "allocate Hamming hit count", error)) {
        release_buffers(buffers);
        return false;
    }
    if (!metal_ok(
            metalMemcpy(
                buffers.precompute, precompute.entries.data(),
                precompute_bytes, metalMemcpyHostToDevice),
            "upload Hamming precompute", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.base, domain.base.data(), domain.base.size(),
                metalMemcpyHostToDevice),
            "upload Hamming base", error) ||
        (!domain.mutable_bits.empty() &&
         !metal_ok(
             metalMemcpy(
                 buffers.mutable_bits, domain.mutable_bits.data(),
                 domain.mutable_bits.size(), metalMemcpyHostToDevice),
             "upload Hamming mutable bits", error)) ||
        !metal_ok(
            metalMemcpy(
                buffers.choose, domain.choose_flat.data(), choose_bytes,
                metalMemcpyHostToDevice),
            "upload Hamming choose table", error)) {
        release_buffers(buffers);
        return false;
    }
    buffers.target_capacity = target_capacity;
    buffers.allocated =
        precompute_bytes + domain.base.size() + mutable_bytes +
        choose_bytes + 4u * sizeof(std::uint64_t) + target_bytes +
        static_cast<std::uint64_t>(kHitCapacity) * sizeof(GpuHit) +
        sizeof(std::uint32_t);
    return true;
}

bool launch_batch(
    DeviceBuffers& buffers,
    const Domain& domain,
    const HostPrecompute& precompute,
    const modeinfra::U256& base,
    std::uint64_t count,
    const GpuTarget* target_data,
    std::uint32_t target_count,
    std::vector<GpuHit>& hits,
    std::uint32_t& raw_count,
    std::uint64_t& readback_ns,
    std::string& error) {
    if (!metal_ok(
            metalSetDevice(buffers.device),
            "select Hamming device", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.targets, target_data,
                static_cast<std::size_t>(target_count) *
                    sizeof(GpuTarget),
                metalMemcpyHostToDevice),
            "upload Hamming target tile", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.base_ordinal, base.limbs.data(),
                4u * sizeof(std::uint64_t), metalMemcpyHostToDevice),
            "upload Hamming ordinal", error) ||
        !metal_ok(
            metalMemset(
                buffers.hit_count, 0, sizeof(std::uint32_t)),
            "reset Hamming hit count", error)) {
        return false;
    }
    const std::uint64_t pitch =
        static_cast<std::uint64_t>(precompute.pitch);
    const std::uint32_t mutable_count =
        static_cast<std::uint32_t>(domain.mutable_bits.size());
    const std::uint32_t grid = static_cast<std::uint32_t>(
        (count + kThreadgroupSize - 1u) / kThreadgroupSize *
        kThreadgroupSize);
    if (!metal_ok(
            metal_launch(
                "workerHamming", grid, kThreadgroupSize,
                buffers.precompute, pitch, precompute.windows,
                precompute.bits, buffers.base, buffers.mutable_bits,
                mutable_count, domain.distance, buffers.choose,
                buffers.base_ordinal, buffers.targets, target_count,
                buffers.hits, buffers.hit_count, kHitCapacity, count),
            "launch workerHamming", error) ||
        !metal_ok(
            metalDeviceSynchronize(),
            "synchronize workerHamming", error)) {
        return false;
    }
    const auto started = std::chrono::steady_clock::now();
    raw_count = 0u;
    if (!metal_ok(
            metalMemcpy(
                &raw_count, buffers.hit_count, sizeof(raw_count),
                metalMemcpyDeviceToHost),
            "read Hamming hit count", error)) {
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
            "read Hamming hits", error)) {
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
    bool has_priv = false;
    bool has_hamming = false;
    for (int i = 1; i < argc; ++i) {
        if (argv[i] == nullptr) continue;
        has_priv = has_priv || std::strcmp(argv[i], "-priv") == 0;
        has_hamming =
            has_hamming || std::strcmp(argv[i], "-hamming") == 0;
    }
    return has_priv && has_hamming;
}

void print_help() {
    std::cout << R"HELP([!] MAIN MODE: -priv -hamming  (exact Hamming-distance key search)
[!] ======================================================================
[!] Purpose:
[!] Search every secp256k1 private scalar at one exact bitwise Hamming
[!] distance from a known 256-bit base. A checked combinadic ordinal maps
[!] to each candidate exactly once; Metal derives public keys and every
[!] reported hit is independently reconstructed and verified on the host.
[!]
[!] Required arguments:
[!] -hamming BASE:DISTANCE[:MUTABLE_MASK]
[!]   BASE          exactly 64 hexadecimal private-key characters.
[!]   DISTANCE      exact number of toggled bits, 0..popcount(mask).
[!]   MUTABLE_MASK  optional 64-hex bit mask; 1=mutable, 0=fixed.
[!]                 Without a mask all 256 positions are mutable.
[!] Bit 0 is the most-significant bit of the normal big-endian hex scalar.
[!] -target KEY     Repeatable compressed/uncompressed secp256k1 public key.
[!]                 An existing file is read one key per line; comments,
[!]                 empty lines and trailing text are ignored.
[!] Duplicate keys are searched once while all original sources are kept.
[!]
[!] Ordinal range:
[!] -start N        First combinadic ordinal, default 0.
[!] -end N          Exclusive end, default C(popcount(mask),distance).
[!] N accepts decimal, 0xHEX and 2^EXP through the checked U256 scheduler.
[!]
[!] GPU / memory / MultiGPU:
[!] -device LIST                    Metal indexes, e.g. 0 or 0,1.
[!] -n N                            Candidates per completed Metal launch.
[!] -wallet-mem auto|all|NN%|SIZE   Hard unified-memory working-set budget.
[!] Target lists larger than one Metal buffer are streamed through bounded
[!] tiles. Windows are assigned without gaps or overlap. Hit overflow halves
[!] and retries the uncredited window, so work is never double-counted.
[!]
[!] Statistics / output:
[!] SpeedThreadFunc is the only live statistics printer and reports Key/s.
[!] -o FILE                         Append verified results.
[!] -save                           Use HAMMING_FOUND.txt when -o is absent.
[!] -silent                         Suppress found-result lines on stdout.
[!] Output includes ordinal, base, distance, mask, private/public key and
[!] every original target source.
[!]
[!] Examples:
[!] ./METAL_CRYPTO_TOOLKIT -priv \
[!]   -hamming 0000000000000000000000000000000000000000000000000000000000000001:2 \
[!]   -target 02... -wallet-mem auto
[!] ./METAL_CRYPTO_TOOLKIT -priv -hamming BASE:6:MASK \
[!]   -start 0 -end 0x100000 -target targets.txt -device 0 -save
[!] ./METAL_CRYPTO_TOOLKIT -help -priv -hamming
[!]
[!] Limitations:
[!] Only exact full secp256k1 public-key targets are accepted. Combinatorial
[!] U256 coverage does not make enormous Hamming spheres practical.
[!] CLI errors return 2; Metal/runtime failures return 1; an exhausted,
[!] correctly searched ordinal range returns 0 even when nothing is found.
)HELP";
}

int run(int argc, char** argv, const RuntimeHooks& hooks) {
    Options options;
    std::string error;
    if (!parse_options(argc, argv, options, error)) {
        std::cerr << "[!] Hamming CLI error: " << error << " [!]\n";
        return 2;
    }
    Domain domain;
    if (!parse_domain(options, domain, error)) {
        std::cerr << "[!] Hamming domain error: " << error << " [!]\n";
        return 2;
    }
    modeinfra::U256 start{};
    modeinfra::U256 end = domain.size;
    if (!modeinfra::parse_u256(options.start, start, error) ||
        (!options.end.empty() &&
         !modeinfra::parse_u256(options.end, end, error))) {
        std::cerr << "[!] Hamming ordinal error: " << error << " [!]\n";
        return 2;
    }
    if (modeinfra::compare(start, end) >= 0 ||
        modeinfra::compare(end, domain.size) > 0) {
        std::cerr << "[!] Hamming ordinal error: require "
                     "0 <= start < end <= C(n,k) [!]\n";
        return 2;
    }
    std::vector<Target> targets;
    if (!load_targets(options, targets, error)) {
        std::cerr << "[!] Hamming target error: " << error << " [!]\n";
        return 2;
    }
    HostPrecompute precompute;
    if (!build_precompute(precompute, error)) {
        std::cerr << "[!] Hamming runtime error: " << error << " [!]\n";
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
        std::cerr << "[!] Hamming runtime error: " << error << " [!]\n";
        return 1;
    }
    std::vector<modeinfra::MemoryDeviceInfo> device_info;
    for (int device : options.devices) {
        if (device < 0 || device >= device_count) {
            std::cerr << "[!] Hamming CLI error: device index "
                      << device << " is unavailable [!]\n";
            return 2;
        }
        metalDeviceProp properties{};
        if (!metal_ok(
                metalGetDeviceProperties(&properties, device),
                "query Metal device properties", error)) {
            std::cerr << "[!] Hamming runtime error: "
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
    const std::uint64_t mandatory_without_targets =
        precompute.entries.size() * sizeof(secp256k1_ge_storage) +
        domain.choose_flat.size() * sizeof(std::uint64_t) +
        static_cast<std::uint64_t>(kHitCapacity) * sizeof(GpuHit) +
        1024u * 1024u;
    modeinfra::MemorySpec memory_spec;
    modeinfra::MemoryBudget memory_budget;
    if (!modeinfra::parse_memory_spec(
            options.memory, memory_spec, error) ||
        !modeinfra::resolve_memory_budget(
            memory_spec, device_info, mandatory_without_targets +
                sizeof(GpuTarget), 0u,
            memory_budget, error, kRuntimeReserve)) {
        std::cerr << "[!] Hamming memory error: " << error << " [!]\n";
        return 2;
    }
    const std::uint64_t max_buffer_targets =
        memory_budget.max_buffer_length / sizeof(GpuTarget);
    const std::uint64_t budget_targets =
        memory_budget.per_device_budget > mandatory_without_targets
        ? (memory_budget.per_device_budget -
           mandatory_without_targets) / sizeof(GpuTarget)
        : 0u;
    const std::uint64_t target_capacity = std::min<std::uint64_t>(
        gpu_targets.size(),
        std::min(
            std::min(max_buffer_targets, budget_targets),
            static_cast<std::uint64_t>(
                std::numeric_limits<std::uint32_t>::max())));
    if (target_capacity == 0u) {
        std::cerr << "[!] Hamming memory error: no target fits the "
                     "selected working-set budget [!]\n";
        return 2;
    }
    std::vector<DeviceBuffers> devices(options.devices.size());
    std::uint64_t allocated = 0u;
    for (std::size_t i = 0u; i < devices.size(); ++i) {
        if (!prepare_buffers(
                options.devices[i], domain, precompute,
                target_capacity, devices[i], error)) {
            for (auto& buffers : devices) release_buffers(buffers);
            std::cerr << "[!] Hamming runtime error: "
                      << error << " [!]\n";
            return 1;
        }
        allocated += devices[i].allocated;
    }
    if (allocated > memory_budget.total_budget) {
        for (auto& buffers : devices) release_buffers(buffers);
        std::cerr << "[!] Hamming memory error: allocated working set "
                     "exceeds -wallet-mem [!]\n";
        return 2;
    }

    if (options.output_path.empty() && options.save) {
        options.output_path = "HAMMING_FOUND.txt";
    }
    std::ofstream output;
    if (!options.output_path.empty()) {
        output.open(options.output_path, std::ios::app);
        if (!output) {
            for (auto& buffers : devices) release_buffers(buffers);
            std::cerr << "[!] Hamming runtime error: cannot open output "
                         "file [!]\n";
            return 1;
        }
    }
    std::uint64_t logical_targets = 0u;
    for (const Target& target : targets) {
        logical_targets += target.occurrences.size();
    }
    std::cout << "[!] Hamming exact distance: " << domain.distance
              << " | mutable bits: " << domain.mutable_bits.size()
              << " | domain: 0x" << modeinfra::u256_hex(domain.size)
              << " | targets: " << targets.size() << " unique/"
              << logical_targets << " logical | devices: "
              << devices.size() << " | batch: " << options.batch
              << " | target tile: " << target_capacity
              << " [!]\n";

    modeinfra::ModeProgress& progress =
        modeinfra::global_mode_progress();
    progress.begin(
        "HAMMING", modeinfra::ProgressUnit::Key,
        modeinfra::ProgressPhase::Search);
    progress.set_targets(logical_targets, target_capacity, 0u);
    progress.set_allocated_working_set(allocated);

    modeinfra::U256 cursor = start;
    std::uint64_t solved_logical = 0u;
    std::uint64_t founds = 0u;
    std::size_t device_slot = 0u;
    int result = 0;
    while (modeinfra::compare(cursor, end) < 0 &&
           solved_logical < logical_targets) {
        modeinfra::U256 remaining{};
        if (!modeinfra::subtract_checked(end, cursor, remaining)) {
            error = "Hamming scheduler underflow";
            result = 1;
            break;
        }
        std::uint64_t count =
            bounded_count(remaining, options.batch);
        if (count == 0u) {
            error = "Hamming scheduler produced an empty window";
            result = 1;
            break;
        }
        bool completed = false;
        while (!completed) {
            struct ResolvedHit {
                GpuHit hit;
                std::uint32_t original_target = 0u;
            };
            std::vector<ResolvedHit> resolved_hits;
            std::uint64_t readback_ns = 0u;
            std::uint64_t primitive_operations = 0u;
            bool retry = false;
            DeviceBuffers& buffers = devices[device_slot];
            for (std::size_t tile_begin = 0u;
                 tile_begin < gpu_targets.size();
                 tile_begin += static_cast<std::size_t>(target_capacity)) {
                const std::uint32_t tile_count =
                    static_cast<std::uint32_t>(
                        std::min<std::size_t>(
                            target_capacity,
                            gpu_targets.size() - tile_begin));
                std::vector<GpuHit> tile_hits;
                std::uint32_t raw_count = 0u;
                std::uint64_t tile_readback_ns = 0u;
                if (!launch_batch(
                        buffers, domain, precompute, cursor, count,
                        gpu_targets.data() + tile_begin, tile_count,
                        tile_hits, raw_count, tile_readback_ns, error)) {
                    result = 1;
                    break;
                }
                readback_ns += tile_readback_ns;
                primitive_operations =
                    std::numeric_limits<std::uint64_t>::max() -
                        primitive_operations < count
                    ? std::numeric_limits<std::uint64_t>::max()
                    : primitive_operations + count;
                if (raw_count > kHitCapacity) {
                    retry = true;
                    break;
                }
                for (GpuHit& hit : tile_hits) {
                    if (hit.target_index >= tile_count) continue;
                    const std::uint32_t original =
                        gpu_targets[tile_begin + hit.target_index]
                            .source_index;
                    resolved_hits.push_back({hit, original});
                }
            }
            if (result != 0) break;
            if (retry) {
                if (count == 1u) {
                    error = "Hamming hit buffer overflows for one candidate";
                    result = 1;
                    break;
                }
                count = std::max<std::uint64_t>(1u, count / 2u);
                continue;
            }

            std::uint64_t exact = 0u;
            for (const ResolvedHit& resolved : resolved_hits) {
                const GpuHit& hit = resolved.hit;
                modeinfra::U256 ordinal{};
                ordinal.limbs = hit.ordinal;
                std::array<std::uint8_t, 32> private_key{};
                std::array<std::uint8_t, 33> public_key{};
                ++exact;
                if (!unrank(domain, ordinal, private_key) ||
                    private_key != hit.private_key ||
                    !derive_public_from_private(
                        private_key, precompute, public_key) ||
                    public_key != hit.public_key) {
                    error = "GPU hit failed full host reconstruction";
                    result = 1;
                    break;
                }
                const std::uint32_t original =
                    resolved.original_target;
                if (original >= targets.size() ||
                    targets[original].key != public_key) {
                    error = "GPU hit resolved to the wrong target";
                    result = 1;
                    break;
                }
                Target& target = targets[original];
                if (target.solved) continue;
                target.solved = true;
                solved_logical += target.occurrences.size();
                ++founds;
                if (hooks.increment_found) hooks.increment_found();
                std::string sources;
                for (std::size_t i = 0u;
                     i < target.occurrences.size(); ++i) {
                    if (i != 0u) sources += ',';
                    sources += target.occurrences[i].source;
                }
                const std::string line =
                    "[+] HAMMING FOUND ordinal=0x" +
                    modeinfra::u256_hex(ordinal) +
                    " base=" +
                    hex_lower(domain.base.data(), domain.base.size()) +
                    " distance=" + std::to_string(domain.distance) +
                    " mask=" +
                    hex_lower(domain.mask.data(), domain.mask.size()) +
                    " private=" +
                    hex_lower(private_key.data(), private_key.size()) +
                    " public=" +
                    hex_lower(public_key.data(), public_key.size()) +
                    " sources=" + sources;
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
                logical_targets, target_capacity, solved_logical);
            progress.set_founds(founds);
            if (hooks.add_completed) hooks.add_completed(count);
            modeinfra::U256 next{};
            if (!modeinfra::add_checked(
                    cursor, modeinfra::U256::from_u64(count), next)) {
                error = "Hamming scheduler overflow";
                result = 1;
                break;
            }
            cursor = next;
            device_slot = (device_slot + 1u) % devices.size();
            completed = true;
        }
        if (result != 0) break;
    }
    progress.end();
    for (auto& buffers : devices) release_buffers(buffers);
    if (result != 0) {
        std::cerr << "[!] Hamming runtime error: " << error << " [!]\n";
        return result;
    }
    std::cout << "[!] Hamming search complete: solved "
              << solved_logical << '/' << logical_targets
              << " logical targets [!]\n";
    return 0;
}

} // namespace hamming
