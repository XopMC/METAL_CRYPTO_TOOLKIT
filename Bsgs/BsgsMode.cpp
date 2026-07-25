#include "BsgsMode.h"

#include "../MetalBackend.h"
#include "../SecpPrecompute.h"
#include "../host_secp/secp256k1.h"
#include "../host_secp/secp256k1_field.h"
#include "../host_secp/secp256k1_group.h"
#include "../host_secp/secp256k1_scalar.h"
#include "../lib/hash/sha256.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <mutex>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace bsgs {
namespace {

constexpr std::uint32_t kThreadgroupSize = 128u;
constexpr std::uint64_t kWalkSize = 1024u;
constexpr std::uint32_t kMaxDevices = 32u;
constexpr std::uint32_t kMaxTableShards = 4u;
constexpr std::uint32_t kHitCapacity = 65536u;
constexpr std::uint32_t kWorkCapacity = 65536u;
// giant_count <= ceil(n / 2), so bit 255 is never set on a valid BSGS
// giant index and can safely tag the rare shifted-walk singular marker.
constexpr std::uint64_t kShiftedSingularMarker = 1ull << 63u;
constexpr std::uint64_t kRuntimeReserve = 512ull << 20u;
constexpr std::uint32_t kCacheVersion = 2u;
constexpr std::uint32_t kEndianMarker = 0x01020304u;
constexpr char kCacheMagic[8] = {'M', 'B', 'S', 'G', 'S', 'T', '2', '\0'};

std::uint64_t bucket_count_for(std::uint64_t entries,
                               std::uint64_t entries_per_bucket) {
    constexpr std::uint64_t kMaximumBucketCount = 1ull << 24u;
    const std::uint64_t desired = std::max<std::uint64_t>(
        1u,
        entries / entries_per_bucket +
            static_cast<std::uint64_t>(
                entries % entries_per_bucket != 0u));
    std::uint64_t count = 1u;
    while (count < desired && count < kMaximumBucketCount) {
        count <<= 1u;
    }
    return count;
}

std::uint64_t bucket_index_bytes(std::uint64_t entries,
                                 std::uint64_t entries_per_bucket) {
    return (bucket_count_for(entries, entries_per_bucket) + 1u) *
        sizeof(std::uint64_t);
}

class BigUInt {
public:
    static constexpr std::size_t kLimbs = 5u;

    BigUInt() = default;
    BigUInt(std::uint64_t value) { limbs_[0] = value; }

    bool is_zero() const {
        for (std::uint64_t limb : limbs_) {
            if (limb != 0u) return false;
        }
        return true;
    }

    int bit_length() const {
        for (std::size_t i = kLimbs; i-- > 0;) {
            if (limbs_[i] != 0u) {
                return static_cast<int>(i * 64u + 64u -
                    static_cast<std::size_t>(__builtin_clzll(limbs_[i])));
            }
        }
        return 0;
    }

    std::uint64_t low64() const { return limbs_[0]; }
    std::uint64_t limb(std::size_t index) const { return limbs_[index]; }

    BigUInt& operator+=(const BigUInt& other) {
        std::uint64_t carry = 0u;
        for (std::size_t i = 0; i < kLimbs; ++i) {
            const std::uint64_t rhs = other.limbs_[i] + carry;
            const bool rhs_overflow = rhs < other.limbs_[i];
            const std::uint64_t before = limbs_[i];
            limbs_[i] += rhs;
            carry = static_cast<std::uint64_t>(
                rhs_overflow || limbs_[i] < before);
        }
        return *this;
    }

    BigUInt& operator-=(const BigUInt& other) {
        std::uint64_t borrow = 0u;
        for (std::size_t i = 0; i < kLimbs; ++i) {
            const std::uint64_t rhs = other.limbs_[i] + borrow;
            const bool rhs_overflow = rhs < other.limbs_[i];
            const std::uint64_t before = limbs_[i];
            limbs_[i] -= rhs;
            borrow = static_cast<std::uint64_t>(
                rhs_overflow || before < rhs);
        }
        return *this;
    }

    BigUInt& operator<<=(unsigned shift) {
        if (shift == 0u || is_zero()) return *this;
        const std::size_t words = shift / 64u;
        const unsigned bits = shift & 63u;
        std::array<std::uint64_t, kLimbs> out{};
        for (std::size_t source = 0; source < kLimbs; ++source) {
            const std::size_t target = source + words;
            if (target >= kLimbs) continue;
            out[target] |= limbs_[source] << bits;
            if (bits != 0u && target + 1u < kLimbs) {
                out[target + 1u] |= limbs_[source] >> (64u - bits);
            }
        }
        limbs_ = out;
        return *this;
    }

    BigUInt& operator>>=(unsigned shift) {
        if (shift == 0u || is_zero()) return *this;
        const std::size_t words = shift / 64u;
        const unsigned bits = shift & 63u;
        std::array<std::uint64_t, kLimbs> out{};
        for (std::size_t target = 0; target < kLimbs; ++target) {
            const std::size_t source = target + words;
            if (source >= kLimbs) continue;
            out[target] |= limbs_[source] >> bits;
            if (bits != 0u && source + 1u < kLimbs) {
                out[target] |= limbs_[source + 1u] << (64u - bits);
            }
        }
        limbs_ = out;
        return *this;
    }

    BigUInt& operator%=(const BigUInt& modulus) {
        if (modulus.is_zero()) return *this;
        while (*this >= modulus) {
            int shift = bit_length() - modulus.bit_length();
            BigUInt aligned = modulus << static_cast<unsigned>(shift);
            if (aligned > *this) {
                --shift;
                aligned = modulus << static_cast<unsigned>(shift);
            }
            *this -= aligned;
        }
        return *this;
    }

    friend BigUInt operator+(BigUInt left, const BigUInt& right) {
        left += right;
        return left;
    }
    friend BigUInt operator-(BigUInt left, const BigUInt& right) {
        left -= right;
        return left;
    }
    friend BigUInt operator<<(BigUInt value, unsigned shift) {
        value <<= shift;
        return value;
    }
    friend BigUInt operator>>(BigUInt value, unsigned shift) {
        value >>= shift;
        return value;
    }
    friend BigUInt operator*(const BigUInt& value, std::uint64_t multiplier) {
        BigUInt out;
        unsigned __int128 carry = 0u;
        for (std::size_t i = 0; i < kLimbs; ++i) {
            const unsigned __int128 product =
                static_cast<unsigned __int128>(value.limbs_[i]) *
                multiplier + carry;
            out.limbs_[i] = static_cast<std::uint64_t>(product);
            carry = product >> 64u;
        }
        return out;
    }
    friend BigUInt operator/(BigUInt value, std::uint64_t divisor) {
        if (divisor == 0u) return BigUInt();
        unsigned __int128 remainder = 0u;
        for (std::size_t i = kLimbs; i-- > 0;) {
            const unsigned __int128 current =
                (remainder << 64u) | value.limbs_[i];
            value.limbs_[i] =
                static_cast<std::uint64_t>(current / divisor);
            remainder = current % divisor;
        }
        return value;
    }
    friend std::uint64_t operator%(const BigUInt& value,
                                   std::uint64_t divisor) {
        if (divisor == 0u) return 0u;
        unsigned __int128 remainder = 0u;
        for (std::size_t i = kLimbs; i-- > 0;) {
            remainder = ((remainder << 64u) | value.limbs_[i]) % divisor;
        }
        return static_cast<std::uint64_t>(remainder);
    }
    friend bool operator<(const BigUInt& a, const BigUInt& b) {
        for (std::size_t i = kLimbs; i-- > 0;) {
            if (a.limbs_[i] < b.limbs_[i]) return true;
            if (a.limbs_[i] > b.limbs_[i]) return false;
        }
        return false;
    }
    friend bool operator>(const BigUInt& a, const BigUInt& b) {
        return b < a;
    }
    friend bool operator>=(const BigUInt& a, const BigUInt& b) {
        return !(a < b);
    }

private:
    std::array<std::uint64_t, kLimbs> limbs_{};
};

const BigUInt& curve_order() {
    static const BigUInt order = [] {
        BigUInt value;
        const std::string text =
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
        for (char c : text) {
            value <<= 4u;
            const unsigned digit = c <= '9'
                ? static_cast<unsigned>(c - '0')
                : static_cast<unsigned>(c - 'A' + 10);
            value += BigUInt(digit);
        }
        return value;
    }();
    return order;
}

bool is_hex(const std::string& text) {
    return !text.empty() &&
        std::all_of(text.begin(), text.end(), [](unsigned char c) {
            return std::isxdigit(c) != 0;
        });
}

std::string lower_hex(std::string text) {
    std::transform(text.begin(), text.end(), text.begin(),
                   [](unsigned char c) {
                       return static_cast<char>(std::tolower(c));
                   });
    return text;
}

bool parse_scalar(std::string text, BigUInt& out) {
    if (text.size() > 2u && text[0] == '0' &&
        (text[1] == 'x' || text[1] == 'X')) {
        text.erase(0u, 2u);
    }
    if (text.empty() || text.size() > 64u || !is_hex(text)) return false;
    out = BigUInt();
    for (char c : text) {
        out <<= 4u;
        const unsigned digit = c <= '9'
            ? static_cast<unsigned>(c - '0')
            : static_cast<unsigned>(
                  std::tolower(static_cast<unsigned char>(c)) - 'a' + 10);
        out += BigUInt(digit);
    }
    return true;
}

std::array<std::uint8_t, 32> scalar_bytes(BigUInt value) {
    std::array<std::uint8_t, 32> out{};
    for (int i = 31; i >= 0; --i) {
        out[static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>(value.low64() & 0xffu);
        value >>= 8u;
    }
    return out;
}

std::array<std::uint64_t, 4> scalar_limbs(const BigUInt& value) {
    return {value.limb(0), value.limb(1), value.limb(2), value.limb(3)};
}

BigUInt from_limbs(const std::uint64_t limbs[4]) {
    BigUInt out;
    for (int i = 3; i >= 0; --i) {
        out <<= 64u;
        out += BigUInt(limbs[static_cast<std::size_t>(i)]);
    }
    return out;
}

std::string scalar_hex(const BigUInt& value) {
    const auto bytes = scalar_bytes(value);
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::uint8_t byte : bytes) {
        out << std::setw(2) << static_cast<unsigned>(byte);
    }
    return out.str();
}

std::uint64_t saturating_u64(const BigUInt& value) {
    for (std::size_t i = 1u; i < BigUInt::kLimbs; ++i) {
        if (value.limb(i) != 0u) {
            return std::numeric_limits<std::uint64_t>::max();
        }
    }
    return value.low64();
}

std::uint64_t min_u64(const BigUInt& value, std::uint64_t limit) {
    if (value.bit_length() > 64) return limit;
    return std::min(value.low64(), limit);
}

BigUInt ceil_div(const BigUInt& value, std::uint64_t divisor) {
    BigUInt quotient = value / divisor;
    if ((value % divisor) != 0u) quotient += BigUInt(1u);
    return quotient;
}

long double log2_value(const BigUInt& value) {
    const int bits = value.bit_length();
    if (bits == 0) return -std::numeric_limits<long double>::infinity();
    const unsigned shift = static_cast<unsigned>(std::max(0, bits - 64));
    const std::uint64_t prefix = (value >> shift).low64();
    return std::log2(static_cast<long double>(prefix)) +
        static_cast<long double>(shift);
}

struct SearchRange {
    BigUInt start;
    BigUInt end;
    int source_bits = 0;
};

enum class MemoryKind {
    Auto,
    All,
    Percent,
    Bytes,
};

struct MemorySpec {
    MemoryKind kind = MemoryKind::Auto;
    std::uint64_t value = 0u;
};

struct ShiftSpec {
    bool enabled = false;
    BigUInt start;
    BigUInt step{1u};
    std::uint64_t count = 0u;
};

struct Options {
    std::vector<std::string> target_values;
    std::vector<SearchRange> ranges;
    std::vector<int> devices;
    MemorySpec memory;
    ShiftSpec shifts;
    bool table_explicit = false;
    std::uint64_t table_size = 0u;
    bool cache_enabled = false;
    bool cache_rebuild = false;
    bool random_search = false;
    bool random_seed_explicit = false;
    std::uint64_t random_seed = 0u;
    std::uint64_t auto_table_cap =
        std::numeric_limits<std::uint64_t>::max();
    long double baby_to_giant_cost = 64.0L;
    std::filesystem::path cache_dir =
        std::filesystem::path("_local_artifacts") / "bsgs_tables";
    std::filesystem::path output_file = "result.txt";
};

bool parse_int(const std::string& text, int minimum, int maximum, int& out) {
    try {
        std::size_t used = 0u;
        const long long value = std::stoll(text, &used, 10);
        if (used != text.size() || value < minimum || value > maximum) {
            return false;
        }
        out = static_cast<int>(value);
        return true;
    } catch (...) {
        return false;
    }
}

bool append_number_list(const std::string& text,
                        int minimum,
                        int maximum,
                        std::vector<int>& values,
                        std::string& error) {
    std::stringstream input(text);
    std::string token;
    while (std::getline(input, token, ',')) {
        if (token.empty()) {
            error = "empty list item";
            return false;
        }
        const std::size_t dash = token.find('-');
        if (dash == std::string::npos) {
            int value = 0;
            if (!parse_int(token, minimum, maximum, value)) {
                error = "invalid value '" + token + "'";
                return false;
            }
            values.push_back(value);
            continue;
        }
        if (token.find('-', dash + 1u) != std::string::npos) {
            error = "invalid interval '" + token + "'";
            return false;
        }
        int first = 0;
        int last = 0;
        if (!parse_int(token.substr(0u, dash), minimum, maximum, first) ||
            !parse_int(token.substr(dash + 1u), minimum, maximum, last) ||
            first > last) {
            error = "invalid interval '" + token + "'";
            return false;
        }
        for (int value = first; value <= last; ++value) {
            values.push_back(value);
        }
    }
    return !values.empty();
}

bool parse_range(const std::string& text,
                 std::vector<SearchRange>& ranges,
                 std::string& error) {
    if (text.find(':') != std::string::npos) {
        if (!ranges.empty()) {
            error = "exact START:END cannot be combined with other ranges";
            return false;
        }
        const std::size_t colon = text.find(':');
        SearchRange range;
        if (colon == 0u || colon + 1u >= text.size() ||
            text.find(':', colon + 1u) != std::string::npos ||
            !parse_scalar(text.substr(0u, colon), range.start) ||
            !parse_scalar(text.substr(colon + 1u), range.end)) {
            error = "expected hexadecimal START:END";
            return false;
        }
        if (range.start >= range.end || range.end > curve_order()) {
            error = "expected 0 <= START < END <= secp256k1 order";
            return false;
        }
        ranges.push_back(range);
        return true;
    }

    std::vector<int> bits;
    if (!append_number_list(text, 1, 256, bits, error)) return false;
    for (int bit : bits) {
        SearchRange range;
        range.source_bits = bit;
        range.start = BigUInt(1u) << static_cast<unsigned>(bit - 1);
        range.end = bit == 256
            ? curve_order()
            : (BigUInt(1u) << static_cast<unsigned>(bit));
        if (range.start >= range.end) {
            error = "cannot construct " + std::to_string(bit) + "-bit range";
            return false;
        }
        ranges.push_back(range);
    }
    return true;
}

bool parse_devices(const std::string& text,
                   std::vector<int>& devices,
                   std::string& error) {
    std::vector<int> parsed;
    if (!append_number_list(text, 0, static_cast<int>(kMaxDevices) - 1,
                            parsed, error)) {
        return false;
    }
    int count = 0;
    if (metalGetDeviceCount(&count) != metalSuccess || count <= 0) {
        error = "Metal device enumeration failed";
        return false;
    }
    std::set<int> unique;
    for (int device : parsed) {
        if (device >= count) {
            error = "Metal GPU " + std::to_string(device) + " does not exist";
            return false;
        }
        unique.insert(device);
    }
    devices.assign(unique.begin(), unique.end());
    return !devices.empty();
}

bool parse_u64_value(const std::string& text,
                     std::uint64_t& out,
                     std::string& error) {
    try {
        if (text.rfind("2^", 0u) == 0u) {
            int exponent = 0;
            if (!parse_int(text.substr(2u), 0, 63, exponent)) {
                error = "2^EXP requires EXP in 0..63";
                return false;
            }
            out = 1ull << static_cast<unsigned>(exponent);
            return true;
        }
        std::size_t used = 0u;
        const int base =
            text.size() > 2u && text[0] == '0' &&
            (text[1] == 'x' || text[1] == 'X') ? 16 : 10;
        out = std::stoull(text, &used, base);
        if (used != text.size()) {
            error = "invalid integer '" + text + "'";
            return false;
        }
        return true;
    } catch (...) {
        error = "integer does not fit in 64 bits";
        return false;
    }
}

bool parse_memory(std::string text, MemorySpec& out, std::string& error) {
    const std::string lower = lower_hex(text);
    if (lower == "auto") {
        out = {MemoryKind::Auto, 0u};
        return true;
    }
    if (lower == "all") {
        out = {MemoryKind::All, 0u};
        return true;
    }
    if (!lower.empty() && lower.back() == '%') {
        std::uint64_t percent = 0u;
        if (!parse_u64_value(lower.substr(0u, lower.size() - 1u),
                             percent, error) ||
            percent == 0u || percent > 100u) {
            if (error.empty()) error = "percentage must be 1..100%";
            return false;
        }
        out = {MemoryKind::Percent, percent};
        return true;
    }
    std::uint64_t multiplier = 1ull << 20u;
    std::string number = lower;
    if (lower.size() > 3u &&
        lower.substr(lower.size() - 3u) == "mib") {
        number.resize(number.size() - 3u);
    } else if (lower.size() > 3u &&
               lower.substr(lower.size() - 3u) == "gib") {
        number.resize(number.size() - 3u);
        multiplier = 1ull << 30u;
    }
    std::uint64_t amount = 0u;
    if (!parse_u64_value(number, amount, error) || amount == 0u ||
        amount > std::numeric_limits<std::uint64_t>::max() / multiplier) {
        if (error.empty()) error = "memory size is invalid or overflows";
        return false;
    }
    out = {MemoryKind::Bytes, amount * multiplier};
    return true;
}

bool parse_shifts(const std::string& text,
                  ShiftSpec& out,
                  std::string& error) {
    std::vector<std::string> fields;
    std::stringstream input(text);
    std::string field;
    while (std::getline(input, field, ':')) fields.push_back(field);
    if (fields.size() < 2u || fields.size() > 3u ||
        fields[0].empty() || fields[1].empty() ||
        (fields.size() == 3u && fields[2].empty())) {
        error = "-bsgs-shifts expects HEX_START:COUNT[:HEX_STEP]";
        return false;
    }
    ShiftSpec parsed;
    parsed.enabled = true;
    if (!parse_scalar(fields[0], parsed.start) ||
        parsed.start >= curve_order()) {
        error = "-bsgs-shifts START must be a scalar below the curve order";
        return false;
    }
    if (!parse_u64_value(fields[1], parsed.count, error) ||
        parsed.count == 0u) {
        if (error.empty()) {
            error = "-bsgs-shifts COUNT must be in 1..18446744073709551615";
        }
        return false;
    }
    if (fields.size() == 3u &&
        (!parse_scalar(fields[2], parsed.step) ||
         parsed.step.is_zero())) {
        error = "-bsgs-shifts STEP must be a non-zero scalar";
        return false;
    }
    const BigUInt last =
        parsed.start + parsed.step * (parsed.count - 1u);
    if (last >= curve_order()) {
        error = "-bsgs-shifts sequence reaches or wraps the curve order";
        return false;
    }
    out = parsed;
    return true;
}

bool parse_options(int argc, char** argv, Options& options, std::string& error) {
    bool range_seen = false;
    bool exact_seen = false;
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        auto require_value = [&](std::string& value) {
            if (i + 1 >= argc) {
                error = arg + " requires a value";
                return false;
            }
            value = argv[++i];
            return true;
        };
        if (arg == "-bsgs" || arg == "-h" || arg == "-help" ||
            arg == "--help") {
            continue;
        }
        if (arg == "-target") {
            std::string value;
            if (!require_value(value)) return false;
            options.target_values.push_back(value);
            continue;
        }
        if (arg == "-range") {
            std::string value;
            if (!require_value(value)) return false;
            const bool exact = value.find(':') != std::string::npos;
            if (exact_seen || (exact && range_seen)) {
                error = "exact START:END cannot be combined with another -range";
                return false;
            }
            if (!parse_range(value, options.ranges, error)) return false;
            range_seen = true;
            exact_seen = exact;
            continue;
        }
        if (arg == "-device") {
            std::string value;
            if (!require_value(value) ||
                !parse_devices(value, options.devices, error)) {
                return false;
            }
            continue;
        }
        if (arg == "-bsgs-mem") {
            std::string value;
            if (!require_value(value) ||
                !parse_memory(value, options.memory, error)) {
                return false;
            }
            continue;
        }
        if (arg == "-bsgs-shifts") {
            std::string value;
            if (!require_value(value) ||
                options.shifts.enabled ||
                !parse_shifts(value, options.shifts, error)) {
                if (error.empty()) {
                    error = "-bsgs-shifts may be specified only once";
                }
                return false;
            }
            continue;
        }
        if (arg == "-bsgs-table") {
            std::string value;
            if (!require_value(value) ||
                !parse_u64_value(value, options.table_size, error) ||
                options.table_size == 0u) {
                if (error.empty()) error = "-bsgs-table requires N > 0";
                return false;
            }
            options.table_explicit = true;
            continue;
        }
        if (arg == "-bsgs-table-cache") {
            options.cache_enabled = true;
            continue;
        }
        if (arg == "-bsgs-table-dir") {
            std::string value;
            if (!require_value(value)) return false;
            options.cache_dir = value;
            options.cache_enabled = true;
            continue;
        }
        if (arg == "-bsgs-table-rebuild") {
            options.cache_rebuild = true;
            continue;
        }
        if (arg == "-random") {
            options.random_search = true;
            continue;
        }
        if (arg == "-bsgs-random-seed") {
            std::string value;
            if (!require_value(value) ||
                !parse_u64_value(value, options.random_seed, error)) {
                return false;
            }
            options.random_search = true;
            options.random_seed_explicit = true;
            continue;
        }
        if (arg == "-o") {
            std::string value;
            if (!require_value(value)) return false;
            options.output_file = value;
            continue;
        }
        error = "unknown BSGS option '" + arg + "'";
        return false;
    }
    if (options.target_values.empty()) {
        error = "-bsgs requires at least one -target";
        return false;
    }
    if (!range_seen || options.ranges.empty()) {
        error = "-bsgs requires at least one -range";
        return false;
    }
    if (options.cache_rebuild && !options.cache_enabled) {
        error = "-bsgs-table-rebuild requires -bsgs-table-cache or -bsgs-table-dir";
        return false;
    }
    if (options.random_search && !options.random_seed_explicit) {
        std::random_device entropy;
        const std::uint64_t clock =
            static_cast<std::uint64_t>(
                std::chrono::high_resolution_clock::now()
                    .time_since_epoch()
                    .count());
        options.random_seed =
            (static_cast<std::uint64_t>(entropy()) << 32u) ^
            static_cast<std::uint64_t>(entropy()) ^ clock;
    }
    return true;
}

std::vector<std::uint8_t> decode_hex(const std::string& text) {
    std::vector<std::uint8_t> out;
    if ((text.size() & 1u) != 0u || !is_hex(text)) return out;
    out.reserve(text.size() / 2u);
    auto nibble = [](char c) {
        return c <= '9'
            ? static_cast<unsigned>(c - '0')
            : static_cast<unsigned>(
                  std::tolower(static_cast<unsigned char>(c)) - 'a' + 10);
    };
    for (std::size_t i = 0u; i < text.size(); i += 2u) {
        out.push_back(static_cast<std::uint8_t>(
            (nibble(text[i]) << 4u) | nibble(text[i + 1u])));
    }
    return out;
}

struct HostPoint {
    secp256k1_ge value{};
    bool infinity = true;
};

struct HostPrecompute {
    std::vector<secp256k1_ge_storage> entries;
    std::size_t pitch = 0u;
    unsigned int windows = 0u;
    unsigned int bits = 12u;
};

bool build_host_precompute(HostPrecompute& result, std::string& error) {
    return build_secp256k1_precompute_table_host(
        result.bits,
        result.entries,
        result.pitch,
        result.windows,
        error);
}

secp256k1_scalar host_scalar(BigUInt value) {
    value %= curve_order();
    const auto bytes = scalar_bytes(value);
    secp256k1_scalar out{};
    int overflow = 0;
    secp256k1_scalar_set_b32(&out, bytes.data(), &overflow);
    return out;
}

HostPoint multiply_g(const BigUInt& scalar,
                     const HostPrecompute& precompute) {
    HostPoint out;
    const secp256k1_scalar value = host_scalar(scalar);
    if (secp256k1_scalar_is_zero(&value)) return out;
    secp256k1_gej jacobian{};
    secp256k1_ecmult_big(&jacobian,
                         &value,
                         precompute.entries.data(),
                         precompute.pitch,
                         static_cast<int>(precompute.windows),
                         precompute.bits);
    if (jacobian.infinity != 0) return out;
    secp256k1_ge_set_gej(&out.value, &jacobian);
    out.infinity = out.value.infinity != 0;
    return out;
}

bool parse_public_key(const std::string& text, HostPoint& out) {
    const auto bytes = decode_hex(text);
    if (bytes.size() != 33u && bytes.size() != 65u) return false;
    secp256k1_ge point{};
    if (bytes.size() == 33u) {
        if (bytes[0] != 2u && bytes[0] != 3u) return false;
        secp256k1_fe x{};
        if (!secp256k1_fe_set_b32(&x, bytes.data() + 1u) ||
            !secp256k1_ge_set_xo_var(&point, &x, bytes[0] == 3u)) {
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
    out.value = point;
    out.infinity = point.infinity != 0;
    return !out.infinity;
}

HostPoint negate_point(const HostPoint& point) {
    if (point.infinity) return point;
    HostPoint out = point;
    secp256k1_ge_neg(&out.value, &point.value);
    return out;
}

HostPoint add_points(const HostPoint& left, const HostPoint& right) {
    if (left.infinity) return right;
    if (right.infinity) return left;
    secp256k1_gej left_j{};
    secp256k1_gej sum{};
    secp256k1_gej_set_ge(&left_j, &left.value);
    secp256k1_gej_add_ge_var(&sum, &left_j, &right.value, nullptr);
    if (sum.infinity != 0) return {};
    HostPoint out;
    secp256k1_ge_set_gej(&out.value, &sum);
    out.infinity = out.value.infinity != 0;
    return out;
}

std::array<std::uint8_t, 64> point_bytes(const HostPoint& point) {
    std::array<std::uint8_t, 64> out{};
    if (point.infinity) return out;
    secp256k1_ge normalized = point.value;
    secp256k1_fe_normalize_var(&normalized.x);
    secp256k1_fe_normalize_var(&normalized.y);
    secp256k1_fe_get_b32(out.data(), &normalized.x);
    secp256k1_fe_get_b32(out.data() + 32u, &normalized.y);
    return out;
}

std::array<std::uint64_t, 8> point_limbs(const HostPoint& point) {
    std::array<std::uint64_t, 8> out{};
    const auto bytes = point_bytes(point);
    for (std::size_t coordinate = 0u; coordinate < 2u; ++coordinate) {
        for (std::size_t limb = 0u; limb < 4u; ++limb) {
            std::uint64_t value = 0u;
            const std::size_t base =
                coordinate * 32u + (3u - limb) * 8u;
            for (std::size_t byte = 0u; byte < 8u; ++byte) {
                value = (value << 8u) | bytes[base + byte];
            }
            out[coordinate * 4u + limb] = value;
        }
    }
    return out;
}

bool equal_points(const HostPoint& left, const HostPoint& right) {
    if (left.infinity || right.infinity) {
        return left.infinity == right.infinity;
    }
    return point_bytes(left) == point_bytes(right);
}

std::string point_uncompressed_hex(const HostPoint& point) {
    const auto bytes = point_bytes(point);
    std::ostringstream out;
    out << "04" << std::hex << std::setfill('0');
    for (std::uint8_t byte : bytes) {
        out << std::setw(2) << static_cast<unsigned>(byte);
    }
    return out.str();
}

struct TargetAlias {
    std::size_t ordinal = 0u;
    std::string source;
};

struct Target {
    HostPoint point;
    std::string normalized;
    std::vector<TargetAlias> aliases;
    std::atomic<bool> solved{false};

    Target() = default;
    Target(Target&& other) noexcept
        : point(other.point),
          normalized(std::move(other.normalized)),
          aliases(std::move(other.aliases)),
          solved(other.solved.load(std::memory_order_acquire)) {}
    Target& operator=(Target&& other) noexcept {
        point = other.point;
        normalized = std::move(other.normalized);
        aliases = std::move(other.aliases);
        solved.store(other.solved.load(std::memory_order_acquire),
                     std::memory_order_release);
        return *this;
    }
    Target(const Target&) = delete;
    Target& operator=(const Target&) = delete;
};

std::string trim_copy(std::string text) {
    const auto first = text.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) return {};
    const auto last = text.find_last_not_of(" \t\r\n");
    return text.substr(first, last - first + 1u);
}

bool add_target_token(const std::string& token,
                      const std::string& source,
                      std::size_t ordinal,
                      std::vector<Target>& targets,
                      std::unordered_map<std::string, std::size_t>& unique,
                      std::string& error) {
    const std::string hex = lower_hex(token);
    HostPoint point;
    if (!parse_public_key(hex, point)) {
        error = source +
            ": expected a valid 33-byte compressed or 65-byte uncompressed secp256k1 public key";
        return false;
    }
    const std::string normalized = point_uncompressed_hex(point);
    const auto found = unique.find(normalized);
    if (found != unique.end()) {
        targets[found->second].aliases.push_back({ordinal, source});
        return true;
    }
    Target target;
    target.point = point;
    target.normalized = normalized;
    target.aliases.push_back({ordinal, source});
    unique.emplace(normalized, targets.size());
    targets.push_back(std::move(target));
    return true;
}

bool load_targets(const Options& options,
                  std::vector<Target>& targets,
                  std::string& error) {
    std::unordered_map<std::string, std::size_t> unique;
    std::uintmax_t reserve_hint = options.target_values.size();
    for (const std::string& value : options.target_values) {
        std::error_code size_error;
        const std::filesystem::path path = value;
        if (std::filesystem::is_regular_file(path, size_error) &&
            !size_error) {
            const std::uintmax_t bytes =
                std::filesystem::file_size(path, size_error);
            if (!size_error) {
                const std::uintmax_t addition = bytes / 67u + 1u;
                const std::uintmax_t maximum =
                    std::numeric_limits<std::uint32_t>::max();
                reserve_hint = reserve_hint >= maximum - std::min(addition, maximum)
                    ? maximum
                    : reserve_hint + addition;
            }
        }
    }
    const std::size_t reserve_count = static_cast<std::size_t>(
        std::min<std::uintmax_t>(
            reserve_hint,
            static_cast<std::uintmax_t>(
                std::numeric_limits<std::uint32_t>::max())));
    targets.reserve(reserve_count);
    unique.reserve(reserve_count);
    std::size_t ordinal = 0u;
    for (std::size_t argument = 0u;
         argument < options.target_values.size();
         ++argument) {
        const std::filesystem::path path = options.target_values[argument];
        std::error_code status_error;
        const bool is_file =
            std::filesystem::is_regular_file(path, status_error);
        if (!status_error && is_file) {
            std::ifstream input(path);
            if (!input) {
                error = "cannot open target file '" + path.string() + "'";
                return false;
            }
            std::string line;
            std::size_t line_number = 0u;
            while (std::getline(input, line)) {
                ++line_number;
                line = trim_copy(line);
                if (line.empty() || line[0] == '#') continue;
                std::istringstream words(line);
                std::string token;
                words >> token;
                if (token.empty()) continue;
                ++ordinal;
                const std::string source =
                    path.string() + ":" + std::to_string(line_number);
                if (!add_target_token(token,
                                      source,
                                      ordinal,
                                      targets,
                                      unique,
                                      error)) {
                    return false;
                }
            }
            continue;
        }
        ++ordinal;
        if (!add_target_token(options.target_values[argument],
                              "argv:" + std::to_string(argument + 1u),
                              ordinal,
                              targets,
                              unique,
                              error)) {
            return false;
        }
    }
    if (targets.empty()) {
        error = "no public keys were loaded from -target";
        return false;
    }
    if (targets.size() >
        static_cast<std::size_t>(
            std::numeric_limits<std::uint32_t>::max())) {
        error = "more than 4294967295 unique BSGS targets are not supported";
        return false;
    }
    return true;
}

bool logical_target_count(const Options& options,
                          const std::vector<Target>& targets,
                          std::uint64_t& count,
                          std::string& error) {
    if (targets.size() >
        static_cast<std::size_t>(
            std::numeric_limits<std::uint64_t>::max())) {
        error = "BSGS target count does not fit in 64 bits";
        return false;
    }
    const std::uint64_t bases =
        static_cast<std::uint64_t>(targets.size());
    const std::uint64_t multiplier =
        options.shifts.enabled ? options.shifts.count : 1u;
    if (bases != 0u &&
        multiplier >
            std::numeric_limits<std::uint64_t>::max() / bases) {
        error = "base targets multiplied by -bsgs-shifts COUNT exceed the 64-bit target identifier space";
        return false;
    }
    count = bases * multiplier;
    if (count >
        std::numeric_limits<std::uint64_t>::max() - kWorkCapacity) {
        error = "BSGS reserves the last 65536 64-bit target identifiers for overflow-safe batching";
        return false;
    }
    return true;
}

struct alignas(8) BabyEntry {
    std::uint64_t fingerprint = 0u;
    std::uint64_t j = 0u;
};

struct alignas(8) BabyParams {
    std::uint64_t m = 0u;
    std::uint64_t group_offset = 0u;
    std::uint64_t output_capacity = 0u;
    std::uint32_t windows = 0u;
    std::uint32_t window_bits = 0u;
};

struct alignas(8) CenterProbe {
    std::uint64_t x[4]{};
    std::uint32_t offset = 0u;
    std::uint32_t odd_y = 0u;
};

struct alignas(8) WorkItem {
    std::uint64_t center_scalar[4]{};
    std::uint64_t giant_base[4]{};
    std::uint32_t target_slot = 0u;
    std::uint32_t reserved = 0u;
    std::uint64_t target_id = 0u;
};

struct alignas(8) SearchParams {
    std::uint64_t table_count = 0u;
    std::uint64_t shard_offsets[5]{};
    std::uint64_t giant_count[4]{};
    std::uint64_t m = 0u;
    std::uint64_t match_skip = 0u;
    std::uint32_t bucket_bits = 0u;
    std::uint32_t work_count = 0u;
    std::uint32_t hit_capacity = 0u;
    std::uint32_t windows = 0u;
    std::uint32_t window_bits = 0u;
    std::uint32_t field_begin = 0u;
    std::uint32_t field_end = 0u;
};

struct alignas(8) Hit {
    std::uint64_t giant_index[4]{};
    std::uint64_t j = 0u;
    std::uint64_t target_id = 0u;
};

struct alignas(8) ResolveParams {
    std::uint64_t width[4]{};
    std::uint64_t m = 0u;
    std::uint32_t hit_count = 0u;
    std::uint32_t reserved = 0u;
};

struct alignas(8) Resolved {
    std::uint64_t distance[4]{};
    std::uint64_t target_id = 0u;
    std::uint32_t valid = 0u;
    std::uint32_t reserved = 0u;
};

static_assert(sizeof(BabyEntry) == 16u, "BabyEntry layout");
static_assert(sizeof(CenterProbe) == 40u, "CenterProbe layout");
static_assert(sizeof(BabyParams) == 32u, "BabyParams layout");
static_assert(sizeof(WorkItem) == 80u, "WorkItem layout");
static_assert(sizeof(SearchParams) == 128u, "SearchParams layout");
static_assert(sizeof(Hit) == 48u, "Hit layout");
static_assert(sizeof(ResolveParams) == 48u, "ResolveParams layout");
static_assert(sizeof(Resolved) == 48u, "Resolved layout");

struct WalkTable {
    std::vector<std::uint64_t> gx;
    std::vector<std::uint64_t> gy;
    std::vector<CenterProbe> center_probes;
    std::array<std::uint64_t, 4> two_gnx{};
    std::array<std::uint64_t, 4> two_gny{};
};

WalkTable build_walk_table(const BigUInt& step,
                           const HostPrecompute& precompute) {
    WalkTable out;
    out.gx.resize(512u * 4u);
    out.gy.resize(512u * 4u);
    out.center_probes.reserve(512u);
    HostPoint current;
    const HostPoint increment = multiply_g(step, precompute);
    for (std::size_t i = 0u; i < 512u; ++i) {
        current = add_points(current, increment);
        const auto limbs = point_limbs(current);
        std::copy_n(limbs.data(), 4u, out.gx.data() + i * 4u);
        std::copy_n(limbs.data() + 4u, 4u, out.gy.data() + i * 4u);
        CenterProbe probe{};
        std::copy_n(limbs.data(), 4u, probe.x);
        probe.offset = static_cast<std::uint32_t>(i + 1u);
        probe.odd_y = static_cast<std::uint32_t>(limbs[4] & 1u);
        out.center_probes.push_back(probe);
    }
    std::sort(out.center_probes.begin(),
              out.center_probes.end(),
              [](const CenterProbe& a, const CenterProbe& b) {
                  for (int limb = 3; limb >= 0; --limb) {
                      if (a.x[static_cast<std::size_t>(limb)] !=
                          b.x[static_cast<std::size_t>(limb)]) {
                          return a.x[static_cast<std::size_t>(limb)] <
                              b.x[static_cast<std::size_t>(limb)];
                      }
                  }
                  return a.offset < b.offset;
              });
    const HostPoint two_gn = multiply_g(step * kWalkSize, precompute);
    const auto limbs = point_limbs(two_gn);
    std::copy_n(limbs.data(), 4u, out.two_gnx.data());
    std::copy_n(limbs.data() + 4u, 4u, out.two_gny.data());
    return out;
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

bool copy_to_device(void* destination,
                    const void* source,
                    std::size_t bytes,
                    const std::string& name,
                    std::string& error) {
    return metal_ok(
        metalMemcpy(destination, source, bytes, metalMemcpyHostToDevice),
        name,
        error);
}

bool copy_from_device(void* destination,
                      const void* source,
                      std::size_t bytes,
                      const std::string& name,
                      std::string& error) {
    return metal_ok(
        metalMemcpy(destination, source, bytes, metalMemcpyDeviceToHost),
        name,
        error);
}

struct Table {
    std::uint64_t m = 0u;
    std::vector<BabyEntry> entries;
    std::vector<std::uint64_t> bucket_offsets;
    std::uint32_t bucket_bits = 0u;
    std::uint32_t entries_per_bucket = 8u;
    bool from_cache = false;
    double build_seconds = 0.0;
    double load_seconds = 0.0;
};

void build_shifted_singular_matches(
    const Options& options,
    const Table& table,
    const HostPrecompute& precompute,
    std::vector<std::vector<std::uint64_t>>& matches) {
    matches.assign(kWalkSize, {});
    const HostPoint increment =
        multiply_g(options.shifts.step, precompute);
    HostPoint current;
    for (std::uint32_t distance = 1u;
         distance < kWalkSize;
         ++distance) {
        current = add_points(current, increment);
        const std::uint64_t fingerprint =
            point_limbs(current)[0];
        auto entry = std::lower_bound(
            table.entries.begin(),
            table.entries.end(),
            fingerprint,
            [](const BabyEntry& candidate,
               std::uint64_t value) {
                return candidate.fingerprint < value;
            });
        while (entry != table.entries.end() &&
               entry->fingerprint == fingerprint) {
            matches[distance].push_back(entry->j);
            ++entry;
        }
    }
}

void build_bucket_index(Table& table, std::uint32_t entries_per_bucket) {
    const std::uint64_t bucket_count =
        bucket_count_for(table.m, entries_per_bucket);
    std::uint32_t bits = 0u;
    for (std::uint64_t count = bucket_count; count > 1u; count >>= 1u) {
        ++bits;
    }
    table.bucket_bits = bits;
    table.entries_per_bucket = entries_per_bucket;
    table.bucket_offsets.assign(
        static_cast<std::size_t>(bucket_count + 1u),
        0u);
    for (const BabyEntry& entry : table.entries) {
        const std::uint64_t bucket = bits == 0u
            ? 0u
            : (entry.fingerprint >> (64u - bits));
        ++table.bucket_offsets[static_cast<std::size_t>(bucket + 1u)];
    }
    for (std::size_t i = 1u; i < table.bucket_offsets.size(); ++i) {
        table.bucket_offsets[i] += table.bucket_offsets[i - 1u];
    }
}

struct CacheManifest {
    char magic[8]{};
    std::uint32_t version = 0u;
    std::uint32_t endian = 0u;
    std::uint32_t entry_size = 0u;
    std::uint32_t shard_count = 0u;
    std::uint64_t m = 0u;
    std::uint64_t count = 0u;
    std::uint64_t shard_counts[4]{};
    std::uint8_t curve_id[32]{};
    std::uint8_t shard_sha256[4][32]{};
};

std::array<std::uint8_t, 32> digest_bytes(const void* data,
                                          std::size_t bytes) {
    std::array<std::uint8_t, 32> out{};
    sha256(reinterpret_cast<std::uint8_t*>(const_cast<void*>(data)),
           bytes,
           out.data());
    return out;
}

const std::array<std::uint8_t, 32>& curve_id() {
    static const std::array<std::uint8_t, 32> id = [] {
        const std::string name =
            "secp256k1:BSGS:fingerprint64:j64:negation-map:v2";
        return digest_bytes(name.data(), name.size());
    }();
    return id;
}

std::filesystem::path cache_path(const Options& options, std::uint64_t m) {
    return options.cache_dir / ("v2-m" + std::to_string(m));
}

bool read_binary_file(const std::filesystem::path& path,
                      std::vector<std::uint8_t>& data) {
    std::ifstream input(path, std::ios::binary);
    if (!input) return false;
    input.seekg(0, std::ios::end);
    const std::streamoff size = input.tellg();
    if (size < 0) return false;
    input.seekg(0, std::ios::beg);
    data.resize(static_cast<std::size_t>(size));
    if (!data.empty()) {
        input.read(reinterpret_cast<char*>(data.data()),
                   static_cast<std::streamsize>(data.size()));
    }
    return input.good() || input.eof();
}

bool load_cache(const Options& options,
                std::uint64_t m,
                std::uint32_t entries_per_bucket,
                Table& table,
                std::string& warning) {
    if (!options.cache_enabled || options.cache_rebuild) return false;
    const auto started = std::chrono::steady_clock::now();
    const std::filesystem::path directory = cache_path(options, m);
    std::ifstream manifest_file(directory / "manifest.bin", std::ios::binary);
    if (!manifest_file) return false;
    CacheManifest manifest{};
    manifest_file.read(reinterpret_cast<char*>(&manifest), sizeof(manifest));
    if (!manifest_file ||
        std::memcmp(manifest.magic, kCacheMagic, sizeof(kCacheMagic)) != 0 ||
        manifest.version != kCacheVersion ||
        manifest.endian != kEndianMarker ||
        manifest.entry_size != sizeof(BabyEntry) ||
        manifest.m != m ||
        manifest.count != m ||
        manifest.shard_count == 0u ||
        manifest.shard_count > kMaxTableShards ||
        std::memcmp(manifest.curve_id,
                    curve_id().data(),
                    curve_id().size()) != 0) {
        warning = "BSGS cache schema mismatch in '" + directory.string() + "'";
        return false;
    }
    table.entries.clear();
    try {
        table.entries.reserve(static_cast<std::size_t>(m));
    } catch (...) {
        warning = "BSGS cache table does not fit host address space";
        return false;
    }
    for (std::uint32_t shard = 0u; shard < manifest.shard_count; ++shard) {
        std::vector<std::uint8_t> bytes;
        const auto path =
            directory / ("shard-" + std::to_string(shard) + ".bin");
        const std::uint64_t count = manifest.shard_counts[shard];
        if (count > std::numeric_limits<std::size_t>::max() /
                    sizeof(BabyEntry) ||
            !read_binary_file(path, bytes) ||
            bytes.size() != static_cast<std::size_t>(count) *
                                sizeof(BabyEntry)) {
            warning = "BSGS cache shard is missing or truncated: '" +
                path.string() + "'";
            table.entries.clear();
            return false;
        }
        const auto digest = digest_bytes(bytes.data(), bytes.size());
        if (std::memcmp(digest.data(),
                        manifest.shard_sha256[shard],
                        digest.size()) != 0) {
            warning = "BSGS cache checksum mismatch: '" + path.string() + "'";
            table.entries.clear();
            return false;
        }
        const BabyEntry* entries =
            reinterpret_cast<const BabyEntry*>(bytes.data());
        table.entries.insert(table.entries.end(), entries, entries + count);
    }
    if (table.entries.size() != static_cast<std::size_t>(m)) {
        warning = "BSGS cache entry count mismatch";
        table.entries.clear();
        return false;
    }
    table.m = m;
    build_bucket_index(table, entries_per_bucket);
    table.from_cache = true;
    table.load_seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - started).count();
    return true;
}

bool write_atomic(const std::filesystem::path& path,
                  const void* data,
                  std::size_t bytes,
                  std::string& error) {
    const std::filesystem::path temporary = path.string() + ".part";
    {
        std::ofstream output(temporary,
                             std::ios::binary | std::ios::trunc);
        if (!output) {
            error = "cannot create cache file '" + temporary.string() + "'";
            return false;
        }
        if (bytes != 0u) {
            output.write(reinterpret_cast<const char*>(data),
                         static_cast<std::streamsize>(bytes));
        }
        output.flush();
        if (!output) {
            error = "cannot finish cache file '" + temporary.string() + "'";
            return false;
        }
    }
    std::error_code rename_error;
    std::filesystem::rename(temporary, path, rename_error);
    if (rename_error) {
        std::filesystem::remove(path, rename_error);
        rename_error.clear();
        std::filesystem::rename(temporary, path, rename_error);
    }
    if (rename_error) {
        error = "cannot atomically publish cache file '" + path.string() +
            "': " + rename_error.message();
        return false;
    }
    return true;
}

bool save_cache(const Options& options,
                const Table& table,
                std::string& error) {
    if (!options.cache_enabled) return true;
    const std::filesystem::path directory =
        cache_path(options, table.m);
    std::error_code directory_error;
    std::filesystem::create_directories(directory, directory_error);
    if (directory_error) {
        error = "cannot create BSGS cache directory: " +
            directory_error.message();
        return false;
    }
    CacheManifest manifest{};
    std::memcpy(manifest.magic, kCacheMagic, sizeof(kCacheMagic));
    manifest.version = kCacheVersion;
    manifest.endian = kEndianMarker;
    manifest.entry_size = sizeof(BabyEntry);
    manifest.m = table.m;
    manifest.count = table.entries.size();
    std::memcpy(manifest.curve_id,
                curve_id().data(),
                curve_id().size());

    const std::uint64_t shard_size =
        std::max<std::uint64_t>(1u,
            (table.m + kMaxTableShards - 1u) / kMaxTableShards);
    std::uint64_t offset = 0u;
    while (offset < table.m) {
        const std::uint32_t shard = manifest.shard_count++;
        const std::uint64_t count =
            std::min(shard_size, table.m - offset);
        manifest.shard_counts[shard] = count;
        const void* data = table.entries.data() + offset;
        const std::size_t bytes =
            static_cast<std::size_t>(count) * sizeof(BabyEntry);
        const auto digest = digest_bytes(data, bytes);
        std::memcpy(manifest.shard_sha256[shard],
                    digest.data(),
                    digest.size());
        const auto path =
            directory / ("shard-" + std::to_string(shard) + ".bin");

        bool already_complete = false;
        std::vector<std::uint8_t> existing;
        if (read_binary_file(path, existing) && existing.size() == bytes) {
            const auto existing_digest =
                digest_bytes(existing.data(), existing.size());
            already_complete = existing_digest == digest;
        }
        if (!already_complete && !write_atomic(path, data, bytes, error)) {
            return false;
        }
        offset += count;
    }
    return write_atomic(directory / "manifest.bin",
                        &manifest,
                        sizeof(manifest),
                        error);
}

struct MemoryPlan {
    std::uint64_t budget = 0u;
    std::uint64_t free_working_set = 0u;
    std::uint64_t max_buffer_length = 0u;
    std::uint64_t m = 0u;
    std::uint64_t estimated_peak = 0u;
    std::uint32_t entries_per_bucket = 8u;
    bool unified = false;
};

bool make_memory_plan(const Options& options,
                      const BigUInt& width,
                      std::uint64_t target_slots,
                      std::uint64_t active_targets,
                      MemoryPlan& plan,
                      std::string& error) {
    std::uint64_t minimum_free =
        std::numeric_limits<std::uint64_t>::max();
    std::uint64_t minimum_max_buffer =
        std::numeric_limits<std::uint64_t>::max();
    bool any_unified = false;
    for (int device : options.devices) {
        if (!metal_ok(metalSetDevice(device), "metalSetDevice", error)) {
            return false;
        }
        metalDeviceProp properties{};
        if (!metal_ok(metalGetDeviceProperties(&properties, device),
                      "metalGetDeviceProperties",
                      error)) {
            return false;
        }
        const std::uint64_t total =
            properties.recommendedMaxWorkingSetSize != 0u
            ? properties.recommendedMaxWorkingSetSize
            : properties.maxBufferLength;
        const std::uint64_t free =
            total > properties.currentAllocatedSize
            ? total - properties.currentAllocatedSize
            : 0u;
        minimum_free = std::min(minimum_free, free);
        minimum_max_buffer =
            std::min(minimum_max_buffer, properties.maxBufferLength);
        any_unified = any_unified || properties.hasUnifiedMemory != 0;
    }
    if (minimum_free == std::numeric_limits<std::uint64_t>::max() ||
        minimum_free <= kRuntimeReserve) {
        error = "not enough recommended Metal working set for BSGS runtime";
        return false;
    }
    switch (options.memory.kind) {
    case MemoryKind::Auto:
        plan.budget = minimum_free / 2u;
        break;
    case MemoryKind::All:
        plan.budget = minimum_free - kRuntimeReserve;
        break;
    case MemoryKind::Percent:
        plan.budget = static_cast<std::uint64_t>(
            (static_cast<unsigned __int128>(minimum_free) *
             options.memory.value) / 100u);
        break;
    case MemoryKind::Bytes:
        if (options.memory.value > minimum_free - kRuntimeReserve) {
            error = "requested -bsgs-mem exceeds the remaining recommended Metal working set";
            return false;
        }
        plan.budget = options.memory.value;
        break;
    }
    plan.free_working_set = minimum_free;
    plan.max_buffer_length = minimum_max_buffer;
    plan.unified = any_unified;

    // Each selected unified-memory GPU owns a table replica, while the sorted
    // host vector remains resident for cache/rebuild and exact verification.
    // Discrete devices have independent working-set budgets, so only the
    // largest per-device allocation constrains this plan.
    const std::uint64_t replicas = plan.unified
        ? static_cast<std::uint64_t>(options.devices.size()) + 1u
        : 1u;
    const std::uint64_t mandatory_replicas = plan.unified
        ? static_cast<std::uint64_t>(options.devices.size())
        : 1u;
    const unsigned __int128 target_bytes =
        static_cast<unsigned __int128>(target_slots) *
        8u * sizeof(std::uint64_t);
    const unsigned __int128 per_device_mandatory =
        static_cast<unsigned __int128>(32ull << 20u) + target_bytes;
    const unsigned __int128 mandatory =
        per_device_mandatory *
            std::max<std::uint64_t>(1u, mandatory_replicas) +
        (plan.unified ? target_bytes : 0u);
    if (mandatory >= plan.budget) {
        error = "-bsgs-mem is too small for the mandatory BSGS buffers";
        return false;
    }
    const std::uint64_t fixed = std::max<std::uint64_t>(
        static_cast<std::uint64_t>(mandatory),
        std::min<std::uint64_t>(plan.budget / 4u,
                                128ull << 20u));
    if (plan.budget <= fixed + sizeof(BabyEntry)) {
        error = "-bsgs-mem is too small for the mandatory BSGS buffers";
        return false;
    }
    const auto fits = [&](std::uint64_t m,
                          std::uint32_t entries_per_bucket,
                          std::uint64_t* estimated_peak) {
        if (m == 0u) return false;
        const std::uint64_t bucket_bytes =
            bucket_index_bytes(m, entries_per_bucket);
        if (plan.max_buffer_length != 0u) {
            if (bucket_bytes > plan.max_buffer_length) return false;
            const std::uint64_t shard_capacity =
                plan.max_buffer_length / sizeof(BabyEntry);
            if (shard_capacity == 0u ||
                static_cast<unsigned __int128>(m) >
                    static_cast<unsigned __int128>(shard_capacity) *
                    kMaxTableShards) {
                return false;
            }
        }
        const unsigned __int128 table_bytes =
            static_cast<unsigned __int128>(m) * sizeof(BabyEntry) +
            bucket_bytes;
        const unsigned __int128 peak =
            fixed + table_bytes * std::max<std::uint64_t>(1u, replicas);
        if (peak > plan.budget ||
            peak > std::numeric_limits<std::uint64_t>::max()) {
            return false;
        }
        if (estimated_peak != nullptr) {
            *estimated_peak = static_cast<std::uint64_t>(peak);
        }
        return true;
    };

    // Density eight is the memory-efficient production floor. Find its exact
    // capacity with a monotonic binary search because the power-of-two bucket
    // index cannot be represented by a constant bytes-per-entry estimate.
    std::uint64_t upper =
        (plan.budget - fixed) /
        (sizeof(BabyEntry) * std::max<std::uint64_t>(1u, replicas));
    if (plan.max_buffer_length != 0u) {
        const unsigned __int128 shard_capacity =
            static_cast<unsigned __int128>(
                plan.max_buffer_length / sizeof(BabyEntry)) *
            kMaxTableShards;
        upper = std::min<std::uint64_t>(
            upper,
            shard_capacity > std::numeric_limits<std::uint64_t>::max()
                ? std::numeric_limits<std::uint64_t>::max()
                : static_cast<std::uint64_t>(shard_capacity));
    }
    std::uint64_t low = 0u;
    std::uint64_t high = upper;
    while (low < high) {
        const std::uint64_t middle =
            low + (high - low) / 2u + 1u;
        if (fits(middle, 8u, nullptr)) {
            low = middle;
        } else {
            high = middle - 1u;
        }
    }
    const std::uint64_t capacity = low;
    if (capacity == 0u) {
        error = "-bsgs-mem leaves no room for baby steps";
        return false;
    }

    std::uint64_t desired = capacity;
    if (options.table_explicit) {
        desired = options.table_size;
        if (desired > capacity) {
            std::ostringstream message;
            message << "-bsgs-table " << desired
                    << " requires more than the " << plan.budget
                    << "-byte memory limit (maximum " << capacity << ")";
            error = message.str();
            return false;
        }
    } else {
        // Minimize M baby operations + T*N/(2M) giant operations.
        const long double log_width = log2_value(width);
        const long double target_count = std::max<long double>(
            1.0L, static_cast<long double>(active_targets));
        const long double log_optimal =
            (log_width + std::log2(target_count) -
             1.0L -
             std::log2(options.baby_to_giant_cost)) / 2.0L;
        if (log_optimal < 63.0L) {
            desired = static_cast<std::uint64_t>(
                std::max<long double>(1.0L, std::exp2(log_optimal)));
        }
        desired = std::min(desired, capacity);

        // A ready cache has zero construction cost in the BSGS operation
        // model. Consider every compatible cached M that fits the current
        // device set instead of requiring the cold-build optimum by name.
        if (options.cache_enabled && !options.cache_rebuild) {
            const auto modeled_cost = [&](std::uint64_t m,
                                           bool include_build) {
                const long double giant_work = std::exp2(
                    log_width + std::log2(target_count) - 1.0L -
                    std::log2(static_cast<long double>(m)));
                return giant_work +
                    (include_build
                         ? static_cast<long double>(m) *
                             options.baby_to_giant_cost
                         : 0.0L);
            };
            long double best_cost = modeled_cost(desired, true);
            std::error_code iteration_error;
            std::filesystem::directory_iterator iterator(
                options.cache_dir, iteration_error);
            const std::filesystem::directory_iterator end;
            while (!iteration_error && iterator != end) {
                const std::filesystem::directory_entry entry = *iterator;
                iterator.increment(iteration_error);
                std::error_code entry_error;
                if (!entry.is_directory(entry_error) || entry_error) {
                    continue;
                }
                const std::string name =
                    entry.path().filename().string();
                if (name.rfind("v2-m", 0u) != 0u) continue;
                std::uint64_t candidate = 0u;
                std::string parse_error;
                if (!parse_u64_value(name.substr(4u),
                                     candidate,
                                     parse_error) ||
                    candidate == 0u || candidate > capacity ||
                    !fits(candidate, 8u, nullptr)) {
                    continue;
                }
                CacheManifest manifest{};
                std::ifstream input(
                    entry.path() / "manifest.bin", std::ios::binary);
                input.read(reinterpret_cast<char*>(&manifest),
                           sizeof(manifest));
                if (!input ||
                    std::memcmp(manifest.magic,
                                kCacheMagic,
                                sizeof(kCacheMagic)) != 0 ||
                    manifest.version != kCacheVersion ||
                    manifest.endian != kEndianMarker ||
                    manifest.entry_size != sizeof(BabyEntry) ||
                    manifest.m != candidate ||
                    manifest.count != candidate ||
                    manifest.shard_count == 0u ||
                    manifest.shard_count > kMaxTableShards ||
                    std::memcmp(manifest.curve_id,
                                curve_id().data(),
                                curve_id().size()) != 0) {
                    continue;
                }
                const long double cost =
                    modeled_cost(candidate, false);
                if (cost < best_cost) {
                    best_cost = cost;
                    desired = candidate;
                }
            }
        }
    }
    plan.m = std::max<std::uint64_t>(1u, desired);
    plan.m = std::min(plan.m, options.auto_table_cap);
    static constexpr std::uint32_t kBucketDensities[] = {1u, 2u, 4u, 8u};
    bool selected = false;
    for (std::uint32_t density : kBucketDensities) {
        if (fits(plan.m, density, &plan.estimated_peak)) {
            plan.entries_per_bucket = density;
            selected = true;
            break;
        }
    }
    if (!selected) {
        std::ostringstream message;
        message << "-bsgs-table " << plan.m
                << " requires more than the " << plan.budget
                << "-byte memory limit (maximum " << capacity << ")";
        error = message.str();
        return false;
    }
    return true;
}

bool build_table_gpu(std::uint64_t m,
                     std::uint32_t entries_per_bucket,
                     int device,
                     const HostPrecompute& precompute,
                     const WalkTable& walk,
                     const RuntimeHooks& hooks,
                     Table& table,
                     std::string& error) {
    if (m > std::numeric_limits<std::size_t>::max() / sizeof(BabyEntry)) {
        error = "BSGS table does not fit host address space";
        return false;
    }
    if (!metal_ok(metalSetDevice(device), "metalSetDevice", error)) {
        return false;
    }
    secp256k1_ge_storage* precompute_device = nullptr;
    std::uint64_t* gx_device = nullptr;
    std::uint64_t* gy_device = nullptr;
    std::uint64_t* two_x_device = nullptr;
    std::uint64_t* two_y_device = nullptr;
    BabyEntry* output_device = nullptr;
    const auto release = [&] {
        (void)metalFree(output_device);
        (void)metalFree(two_y_device);
        (void)metalFree(two_x_device);
        (void)metalFree(gy_device);
        (void)metalFree(gx_device);
        (void)metalFree(precompute_device);
    };
    const std::size_t precompute_bytes =
        precompute.entries.size() * sizeof(secp256k1_ge_storage);
    const std::size_t walk_bytes =
        walk.gx.size() * sizeof(std::uint64_t);
    if (!allocate_device(precompute_device,
                         precompute_bytes,
                         "allocate BSGS precompute",
                         error) ||
        !allocate_device(gx_device, walk_bytes, "allocate BSGS Gx", error) ||
        !allocate_device(gy_device, walk_bytes, "allocate BSGS Gy", error) ||
        !allocate_device(two_x_device,
                         4u * sizeof(std::uint64_t),
                         "allocate BSGS 1024G x",
                         error) ||
        !allocate_device(two_y_device,
                         4u * sizeof(std::uint64_t),
                         "allocate BSGS 1024G y",
                         error) ||
        !copy_to_device(precompute_device,
                        precompute.entries.data(),
                        precompute_bytes,
                        "copy BSGS precompute",
                        error) ||
        !copy_to_device(gx_device,
                        walk.gx.data(),
                        walk_bytes,
                        "copy BSGS Gx",
                        error) ||
        !copy_to_device(gy_device,
                        walk.gy.data(),
                        walk_bytes,
                        "copy BSGS Gy",
                        error) ||
        !copy_to_device(two_x_device,
                        walk.two_gnx.data(),
                        4u * sizeof(std::uint64_t),
                        "copy BSGS 1024G x",
                        error) ||
        !copy_to_device(two_y_device,
                        walk.two_gny.data(),
                        4u * sizeof(std::uint64_t),
                        "copy BSGS 1024G y",
                        error)) {
        release();
        return false;
    }

    const std::uint64_t total_groups =
        (m + kWalkSize - 1u) / kWalkSize;
    const std::uint64_t chunk_groups =
        std::min<std::uint64_t>(total_groups, 2048u);
    const std::uint64_t output_capacity = chunk_groups * kWalkSize;
    if (!allocate_device(output_device,
                         static_cast<std::size_t>(output_capacity) *
                             sizeof(BabyEntry),
                         "allocate BSGS baby chunk",
                         error)) {
        release();
        return false;
    }

    try {
        table.entries.clear();
        table.entries.reserve(static_cast<std::size_t>(m));
    } catch (...) {
        release();
        error = "cannot reserve host memory for BSGS table";
        return false;
    }
    if (hooks.set_speed_context) {
        hooks.set_speed_context(SpeedPhase::TableBuild, m, 1.0, 1u);
    }
    const auto started = std::chrono::steady_clock::now();
    std::vector<BabyEntry> chunk(
        static_cast<std::size_t>(output_capacity));
    const std::uint64_t pitch =
        static_cast<std::uint64_t>(precompute.pitch);
    for (std::uint64_t group = 0u;
         group < total_groups;
         group += chunk_groups) {
        const std::uint64_t groups =
            std::min(chunk_groups, total_groups - group);
        const std::uint64_t entries = groups * kWalkSize;
        if (!metal_ok(metalMemset(output_device,
                                  0,
                                  static_cast<std::size_t>(entries) *
                                      sizeof(BabyEntry)),
                      "clear BSGS baby chunk",
                      error)) {
            release();
            return false;
        }
        const BabyParams params{
            m,
            group,
            entries,
            precompute.windows,
            precompute.bits
        };
        const std::uint32_t grid = static_cast<std::uint32_t>(
            (groups + kThreadgroupSize - 1u) / kThreadgroupSize);
        if (!metal_ok(metal_launch("bsgsGenerateBaby",
                                   grid,
                                   kThreadgroupSize,
                                   output_device,
                                   gx_device,
                                   gy_device,
                                   two_x_device,
                                   two_y_device,
                                   precompute_device,
                                   pitch,
                                   params),
                      "launch bsgsGenerateBaby",
                      error) ||
            !metal_ok(metalDeviceSynchronize(),
                      "synchronize bsgsGenerateBaby",
                      error) ||
            !copy_from_device(chunk.data(),
                              output_device,
                              static_cast<std::size_t>(entries) *
                                  sizeof(BabyEntry),
                              "read BSGS baby chunk",
                              error)) {
            release();
            return false;
        }
        std::uint64_t accepted = 0u;
        for (std::uint64_t i = 0u; i < entries; ++i) {
            if (chunk[static_cast<std::size_t>(i)].j != 0u &&
                chunk[static_cast<std::size_t>(i)].j <= m) {
                table.entries.push_back(
                    chunk[static_cast<std::size_t>(i)]);
                ++accepted;
            }
        }
        if (hooks.add_operations) hooks.add_operations(accepted);
    }
    release();
    if (table.entries.size() != static_cast<std::size_t>(m)) {
        error = "GPU baby generation returned " +
            std::to_string(table.entries.size()) + " entries, expected " +
            std::to_string(m);
        return false;
    }
    std::sort(table.entries.begin(),
              table.entries.end(),
              [](const BabyEntry& a, const BabyEntry& b) {
                  if (a.fingerprint != b.fingerprint) {
                      return a.fingerprint < b.fingerprint;
                  }
                  return a.j < b.j;
              });
    table.m = m;
    build_bucket_index(table, entries_per_bucket);
    table.build_seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - started).count();
    return true;
}

struct DeviceContext {
    int device = -1;
    std::uint32_t bucket_bits = 0u;
    metalDeviceProp properties{};
    BabyEntry* shards[kMaxTableShards]{};
    std::uint64_t shard_offsets[5]{};
    std::uint64_t* targets = nullptr;
    WorkItem* work = nullptr;
    std::uint64_t* gx = nullptr;
    std::uint64_t* gy = nullptr;
    std::uint64_t* two_x = nullptr;
    std::uint64_t* two_y = nullptr;
    CenterProbe* center_probes = nullptr;
    std::uint64_t* bucket_offsets = nullptr;
    secp256k1_ge_storage* precompute = nullptr;
    Hit* hits = nullptr;
    std::uint32_t* hit_count = nullptr;
    std::uint32_t* overflow = nullptr;
    Resolved* resolved = nullptr;

    void release() {
        if (device >= 0) (void)metalSetDevice(device);
        (void)metalFree(resolved);
        (void)metalFree(overflow);
        (void)metalFree(hit_count);
        (void)metalFree(hits);
        (void)metalFree(precompute);
        (void)metalFree(bucket_offsets);
        (void)metalFree(center_probes);
        (void)metalFree(two_y);
        (void)metalFree(two_x);
        (void)metalFree(gy);
        (void)metalFree(gx);
        (void)metalFree(work);
        (void)metalFree(targets);
        for (BabyEntry*& shard : shards) {
            (void)metalFree(shard);
            shard = nullptr;
        }
        resolved = nullptr;
        overflow = nullptr;
        hit_count = nullptr;
        hits = nullptr;
        precompute = nullptr;
        bucket_offsets = nullptr;
        center_probes = nullptr;
        two_y = nullptr;
        two_x = nullptr;
        gy = nullptr;
        gx = nullptr;
        work = nullptr;
        targets = nullptr;
    }
    ~DeviceContext() { release(); }
};

bool prepare_device(DeviceContext& context,
                    int device,
                    const Table& table,
                    const std::vector<std::uint64_t>& target_limbs,
                    const WalkTable& walk,
                    const HostPrecompute& precompute,
                    std::string& error) {
    context.device = device;
    context.bucket_bits = table.bucket_bits;
    if (!metal_ok(metalSetDevice(device), "metalSetDevice", error) ||
        !metal_ok(metalGetDeviceProperties(&context.properties, device),
                  "metalGetDeviceProperties",
                  error)) {
        return false;
    }
    const std::uint64_t max_entries =
        context.properties.maxBufferLength == 0u
        ? table.m
        : context.properties.maxBufferLength / sizeof(BabyEntry);
    if (max_entries == 0u) {
        error = "Metal maxBufferLength cannot hold one BSGS entry";
        return false;
    }
    const std::uint64_t shard_size =
        std::min(max_entries,
                 (table.m + kMaxTableShards - 1u) / kMaxTableShards);
    std::uint64_t offset = 0u;
    for (std::uint32_t shard = 0u; shard < kMaxTableShards; ++shard) {
        context.shard_offsets[shard] = offset;
        const std::uint64_t count =
            offset < table.m ? std::min(shard_size, table.m - offset) : 0u;
        const std::size_t bytes = static_cast<std::size_t>(
            std::max<std::uint64_t>(1u, count)) * sizeof(BabyEntry);
        if (!allocate_device(context.shards[shard],
                             bytes,
                             "allocate BSGS table shard",
                             error)) {
            return false;
        }
        if (count != 0u &&
            !copy_to_device(context.shards[shard],
                            table.entries.data() + offset,
                            static_cast<std::size_t>(count) *
                                sizeof(BabyEntry),
                            "copy BSGS table shard",
                            error)) {
            return false;
        }
        offset += count;
    }
    context.shard_offsets[kMaxTableShards] = offset;
    if (offset != table.m) {
        error = "BSGS table needs more than four Metal shards";
        return false;
    }

    const std::size_t targets_bytes =
        target_limbs.size() * sizeof(std::uint64_t);
    const std::size_t walk_bytes =
        walk.gx.size() * sizeof(std::uint64_t);
    const std::size_t precompute_bytes =
        precompute.entries.size() * sizeof(secp256k1_ge_storage);
    const std::size_t center_probe_bytes =
        walk.center_probes.size() * sizeof(CenterProbe);
    const std::size_t bucket_offset_bytes =
        table.bucket_offsets.size() * sizeof(std::uint64_t);
    if (context.properties.maxBufferLength != 0u &&
        bucket_offset_bytes > context.properties.maxBufferLength) {
        error = "Metal maxBufferLength cannot hold the BSGS bucket index";
        return false;
    }
    if (context.properties.maxBufferLength != 0u &&
        targets_bytes > context.properties.maxBufferLength) {
        error = "Metal maxBufferLength cannot hold the BSGS target table";
        return false;
    }
    if (!allocate_device(context.targets,
                         std::max<std::size_t>(targets_bytes, 8u),
                         "allocate BSGS targets",
                         error) ||
        !allocate_device(context.work,
                         kWorkCapacity * sizeof(WorkItem),
                         "allocate BSGS work",
                         error) ||
        !allocate_device(context.gx,
                         walk_bytes,
                         "allocate BSGS walk Gx",
                         error) ||
        !allocate_device(context.gy,
                         walk_bytes,
                         "allocate BSGS walk Gy",
                         error) ||
        !allocate_device(context.two_x,
                         4u * sizeof(std::uint64_t),
                         "allocate BSGS walk 1024G x",
                         error) ||
        !allocate_device(context.two_y,
                         4u * sizeof(std::uint64_t),
                         "allocate BSGS walk 1024G y",
                         error) ||
        !allocate_device(context.center_probes,
                         center_probe_bytes,
                         "allocate BSGS center probes",
                         error) ||
        !allocate_device(context.bucket_offsets,
                         bucket_offset_bytes,
                         "allocate BSGS bucket offsets",
                         error) ||
        !allocate_device(context.precompute,
                         precompute_bytes,
                         "allocate BSGS precompute",
                         error) ||
        !allocate_device(context.hits,
                         kHitCapacity * sizeof(Hit),
                         "allocate BSGS hits",
                         error) ||
        !allocate_device(context.hit_count,
                         sizeof(std::uint32_t),
                         "allocate BSGS hit count",
                         error) ||
        !allocate_device(context.overflow,
                         sizeof(std::uint32_t),
                         "allocate BSGS overflow flag",
                         error) ||
        !allocate_device(context.resolved,
                         kHitCapacity * 2u * sizeof(Resolved),
                         "allocate BSGS resolved hits",
                         error) ||
        !copy_to_device(context.targets,
                        target_limbs.data(),
                        targets_bytes,
                        "copy BSGS targets",
                        error) ||
        !copy_to_device(context.gx,
                        walk.gx.data(),
                        walk_bytes,
                        "copy BSGS walk Gx",
                        error) ||
        !copy_to_device(context.gy,
                        walk.gy.data(),
                        walk_bytes,
                        "copy BSGS walk Gy",
                        error) ||
        !copy_to_device(context.two_x,
                        walk.two_gnx.data(),
                        4u * sizeof(std::uint64_t),
                        "copy BSGS walk 1024G x",
                        error) ||
        !copy_to_device(context.two_y,
                        walk.two_gny.data(),
                        4u * sizeof(std::uint64_t),
                        "copy BSGS walk 1024G y",
                        error) ||
        !copy_to_device(context.center_probes,
                        walk.center_probes.data(),
                        center_probe_bytes,
                        "copy BSGS center probes",
                        error) ||
        !copy_to_device(context.bucket_offsets,
                        table.bucket_offsets.data(),
                        bucket_offset_bytes,
                        "copy BSGS bucket offsets",
                        error) ||
        !copy_to_device(context.precompute,
                        precompute.entries.data(),
                        precompute_bytes,
                        "copy BSGS precompute",
                        error)) {
        return false;
    }
    if (!metal_ok(metalGetDeviceProperties(&context.properties, device),
                  "refresh BSGS device properties",
                  error)) {
        return false;
    }
    return true;
}

struct RunShared {
    const Options* options = nullptr;
    const SearchRange* range = nullptr;
    const HostPrecompute* precompute = nullptr;
    std::vector<Target>* targets = nullptr;
    std::unordered_set<std::uint64_t>* shifted_solved = nullptr;
    const std::vector<std::vector<std::uint64_t>>*
        shifted_singular_matches = nullptr;
    const RuntimeHooks* hooks = nullptr;
    BigUInt width;
    BigUInt giant_count;
    BigUInt group_count;
    BigUInt random_group_offset;
    std::uint64_t m = 0u;
    std::uint64_t target_count = 0u;
    std::uint64_t random_group_stride = 0u;
    std::mutex result_mutex;
    std::mutex work_mutex;
    std::mutex error_mutex;
    BigUInt next_group;
    std::atomic<std::uint64_t> remaining_targets{0u};
    std::atomic<bool> failed{false};
    std::string error;
};

std::uint64_t splitmix64(std::uint64_t& state) {
    state += 0x9e3779b97f4a7c15ull;
    std::uint64_t value = state;
    value = (value ^ (value >> 30u)) * 0xbf58476d1ce4e5b9ull;
    value = (value ^ (value >> 27u)) * 0x94d049bb133111ebull;
    return value ^ (value >> 31u);
}

std::uint64_t gcd_with_big(const BigUInt& value, std::uint64_t candidate) {
    if (candidate == 0u) return value.is_zero() ? 0u : value.low64();
    std::uint64_t left = candidate;
    std::uint64_t right = value % candidate;
    while (right != 0u) {
        const std::uint64_t next = left % right;
        left = right;
        right = next;
    }
    return left;
}

BigUInt random_below(std::uint64_t& state, const BigUInt& limit) {
    if (limit.is_zero()) return {};
    BigUInt value;
    for (std::size_t limb = 0u; limb < 4u; ++limb) {
        value <<= 64u;
        value += BigUInt(splitmix64(state));
    }
    value %= limit;
    return value;
}

void configure_random_groups(RunShared& shared) {
    if (!shared.options->random_search ||
        shared.group_count.is_zero()) {
        return;
    }
    std::uint64_t state = shared.options->random_seed;
    for (std::size_t limb = 0u; limb < 4u; ++limb) {
        state ^= shared.range->start.limb(limb) +
            0x9e3779b97f4a7c15ull + (state << 6u) + (state >> 2u);
        state ^= shared.range->end.limb(limb) +
            0x9e3779b97f4a7c15ull + (state << 6u) + (state >> 2u);
    }
    state ^= shared.m + 0x9e3779b97f4a7c15ull +
        (state << 6u) + (state >> 2u);
    shared.random_group_offset =
        random_below(state, shared.group_count);
    if (shared.group_count.bit_length() == 1) {
        shared.random_group_stride = 0u;
        return;
    }
    std::uint64_t stride = splitmix64(state) | 1u;
    if (shared.group_count.bit_length() <= 64) {
        const std::uint64_t count = shared.group_count.low64();
        stride %= count;
        if (stride == 0u) stride = 1u;
    }
    while (gcd_with_big(shared.group_count, stride) != 1u) {
        if (stride > std::numeric_limits<std::uint64_t>::max() - 2u) {
            stride = 1u;
            break;
        }
        stride += 2u;
        if (shared.group_count.bit_length() <= 64 &&
            stride >= shared.group_count.low64()) {
            stride %= shared.group_count.low64();
            if (stride == 0u) stride = 1u;
        }
    }
    shared.random_group_stride = stride;
}

BigUInt first_actual_group(const RunShared& shared,
                           const BigUInt& logical_group) {
    if (!shared.options->random_search ||
        shared.random_group_stride == 0u) {
        return shared.options->random_search
            ? shared.random_group_offset
            : logical_group;
    }
    BigUInt actual =
        logical_group * shared.random_group_stride;
    actual += shared.random_group_offset;
    actual %= shared.group_count;
    return actual;
}

void advance_actual_group(const RunShared& shared,
                          BigUInt& actual_group) {
    if (!shared.options->random_search) {
        actual_group += BigUInt(1u);
        return;
    }
    if (shared.random_group_stride == 0u) return;
    actual_group += BigUInt(shared.random_group_stride);
    if (actual_group >= shared.group_count) {
        actual_group -= shared.group_count;
    }
}

void set_failure(RunShared& shared, const std::string& error) {
    std::lock_guard<std::mutex> lock(shared.error_mutex);
    if (!shared.failed.load(std::memory_order_relaxed)) {
        shared.error = error;
        shared.failed.store(true, std::memory_order_release);
    }
}

bool write_result(RunShared& shared,
                  std::uint64_t target_id,
                  const BigUInt& distance) {
    const bool shifted = shared.options->shifts.enabled;
    const std::uint64_t shifts_per_base =
        shifted ? shared.options->shifts.count : 1u;
    const std::uint64_t target_slot =
        shifted ? target_id / shifts_per_base : target_id;
    if (target_slot >= shared.targets->size()) return true;
    Target& target =
        (*shared.targets)[static_cast<std::size_t>(target_slot)];
    if ((!shifted &&
         target.solved.load(std::memory_order_acquire)) ||
        (shifted && shared.shifted_solved->count(target_id) != 0u)) {
        return true;
    }
    const BigUInt private_key = shared.range->start + distance;
    if (private_key >= shared.range->end) {
        return true;
    }
    BigUInt offset;
    HostPoint expected_point = target.point;
    std::string public_hex = target.normalized;
    BigUInt base_private = private_key;
    std::uint64_t shift_index = 0u;
    if (shifted) {
        shift_index = target_id % shifts_per_base;
        offset = shared.options->shifts.start +
            shared.options->shifts.step * shift_index;
        expected_point = add_points(
            target.point,
            negate_point(multiply_g(offset, *shared.precompute)));
        if (expected_point.infinity) return true;
        public_hex = point_uncompressed_hex(expected_point);
        base_private += offset;
        if (base_private >= curve_order()) base_private -= curve_order();
    }
    if (!equal_points(multiply_g(private_key, *shared.precompute),
                      expected_point)) {
        return true;
    }
    if (shifted) {
        if (!equal_points(multiply_g(base_private, *shared.precompute),
                          target.point)) {
            return true;
        }
        shared.shifted_solved->insert(target_id);
    } else {
        bool expected = false;
        if (!target.solved.compare_exchange_strong(
                expected, true, std::memory_order_acq_rel)) {
            return true;
        }
    }
    std::ofstream output(shared.options->output_file,
                         std::ios::app);
    if (!output) {
        if (shifted) {
            shared.shifted_solved->erase(target_id);
        } else {
            target.solved.store(false, std::memory_order_release);
        }
        set_failure(shared,
                    "cannot append output file '" +
                        shared.options->output_file.string() + "'");
        return false;
    }
    const std::string range_text =
        scalar_hex(shared.range->start) + ":" +
        scalar_hex(shared.range->end);
    const std::string private_hex = scalar_hex(private_key);
    for (const TargetAlias& alias : target.aliases) {
        output << "target=" << (target_id + 1u)
               << " source=" << alias.source;
        if (shifted) {
            output << " shift_index=" << shift_index
                   << " shift=" << scalar_hex(offset);
        }
        output << " public=" << public_hex
               << " range=" << range_text
               << " private=" << private_hex;
        if (shifted) {
            output << " base_public=" << target.normalized
                   << " base_private=" << scalar_hex(base_private);
        }
        output << "\n";
        std::cout << "\n[+] BSGS target " << (target_id + 1u)
                  << " (" << alias.source << ") found [!]\n"
                  << "[+] BSGS public: " << public_hex << "\n"
                  << "[+] BSGS range: " << range_text << "\n"
                  << "[+] BSGS private: " << private_hex << "\n";
        if (shifted) {
            std::cout << "[+] BSGS shift: " << scalar_hex(offset)
                      << "; base private: "
                      << scalar_hex(base_private) << "\n";
        }
    }
    output.flush();
    if (!output) {
        set_failure(shared, "failed while writing BSGS output");
        return false;
    }
    shared.remaining_targets.fetch_sub(1u, std::memory_order_acq_rel);
    if (shared.hooks->increment_found) {
        shared.hooks->increment_found();
    }
    return true;
}

bool is_shifted_singular_marker(const Hit& hit) {
    return (hit.giant_index[3] & kShiftedSingularMarker) != 0u;
}

bool process_shifted_singular_marker(RunShared& shared,
                                     const Hit& hit) {
    if (!is_shifted_singular_marker(hit) ||
        shared.shifted_singular_matches == nullptr ||
        hit.j >= kWalkSize ||
        hit.target_id >= shared.target_count) {
        return true;
    }
    std::uint64_t giant_limbs[4] = {
        hit.giant_index[0],
        hit.giant_index[1],
        hit.giant_index[2],
        hit.giant_index[3] & ~kShiftedSingularMarker
    };
    const BigUInt giant_index = from_limbs(giant_limbs);
    const BigUInt center =
        ((giant_index << 1u) + BigUInt(1u)) * shared.m;
    const std::uint32_t singular_field =
        static_cast<std::uint32_t>(hit.j);
    const std::uint64_t block_target_id = hit.target_id;
    const std::uint64_t shift_base =
        block_target_id % shared.options->shifts.count;
    const std::uint64_t field_count =
        std::min<std::uint64_t>(
            kWalkSize,
            shared.options->shifts.count - shift_base);
    for (std::uint32_t field = 0u;
         field < field_count;
         ++field) {
        if (field == singular_field) continue;
        const std::uint32_t distance_from_singular =
            field > singular_field
            ? field - singular_field
            : singular_field - field;
        const auto& matches =
            (*shared.shifted_singular_matches)
                [distance_from_singular];
        const std::uint64_t target_id =
            block_target_id + field;
        for (std::uint64_t j : matches) {
            const BigUInt baby(j);
            if (center >= baby) {
                const BigUInt candidate = center - baby;
                if (candidate < shared.width &&
                    !write_result(shared,
                                  target_id,
                                  candidate)) {
                    return false;
                }
            }
            if (j != 0u) {
                const BigUInt candidate = center + baby;
                if (candidate < shared.width &&
                    !write_result(shared,
                                  target_id,
                                  candidate)) {
                    return false;
                }
            }
        }
    }
    return true;
}

std::uint64_t work_item_operations(const WorkItem& item,
                                   const BigUInt& giant_count,
                                   std::uint32_t field_begin,
                                   std::uint32_t field_end,
                                   bool shifted_targets) {
    if (shifted_targets) {
        const std::uint32_t begin =
            std::min(field_begin, item.reserved);
        const std::uint32_t end =
            std::min(field_end, item.reserved);
        return end > begin ? end - begin : 0u;
    }
    const BigUInt begin =
        from_limbs(item.giant_base) + BigUInt(field_begin);
    if (begin >= giant_count || field_begin >= field_end) return 0u;
    return min_u64(giant_count - begin, field_end - field_begin);
}

bool execute_work(DeviceContext& context,
                  const std::vector<WorkItem>& items,
                  RunShared& shared,
                  std::uint32_t field_begin = 0u,
                  std::uint32_t field_end =
                      static_cast<std::uint32_t>(kWalkSize),
                  std::uint64_t match_skip = 0u) {
    if (items.empty()) return true;
    if (items.size() > kWorkCapacity) {
        const std::size_t middle = items.size() / 2u;
        const std::vector<WorkItem> left(items.begin(), items.begin() + middle);
        const std::vector<WorkItem> right(items.begin() + middle, items.end());
        return execute_work(context,
                            left,
                            shared,
                            field_begin,
                            field_end,
                            match_skip) &&
            execute_work(context,
                         right,
                         shared,
                         field_begin,
                         field_end,
                         match_skip);
    }
    std::string error;
    if (!copy_to_device(context.work,
                        items.data(),
                        items.size() * sizeof(WorkItem),
                        "copy BSGS work",
                        error) ||
        !metal_ok(metalMemset(context.hit_count, 0, sizeof(std::uint32_t)),
                  "clear BSGS hit count",
                  error) ||
        !metal_ok(metalMemset(context.overflow, 0, sizeof(std::uint32_t)),
                  "clear BSGS overflow flag",
                  error)) {
        set_failure(shared, error);
        return false;
    }
    SearchParams params{};
    params.table_count = shared.m;
    std::copy_n(context.shard_offsets, 5u, params.shard_offsets);
    const auto giant_limbs = scalar_limbs(shared.giant_count);
    std::copy_n(giant_limbs.data(), 4u, params.giant_count);
    params.m = shared.m;
    params.match_skip = match_skip;
    params.bucket_bits = context.bucket_bits;
    params.work_count = static_cast<std::uint32_t>(items.size());
    params.hit_capacity = kHitCapacity;
    params.windows = shared.precompute->windows;
    params.window_bits = shared.precompute->bits;
    params.field_begin = field_begin;
    params.field_end = field_end;
    const std::uint64_t pitch =
        static_cast<std::uint64_t>(shared.precompute->pitch);
    const std::uint32_t grid = static_cast<std::uint32_t>(
        (items.size() + kThreadgroupSize - 1u) / kThreadgroupSize);
    const char* lookup_kernel = shared.options->shifts.enabled
        ? "bsgsLookupShifted"
        : "bsgsLookupGiant";
    if (!metal_ok(metal_launch(lookup_kernel,
                               grid,
                               kThreadgroupSize,
                               context.shards[0],
                               context.shards[1],
                               context.shards[2],
                               context.shards[3],
                               context.targets,
                               context.work,
                               context.gx,
                               context.gy,
                               context.two_x,
                               context.two_y,
                               context.center_probes,
                               context.bucket_offsets,
                               context.precompute,
                               pitch,
                               context.hits,
                               context.hit_count,
                               context.overflow,
                               params),
                  std::string("launch ") + lookup_kernel,
                  error) ||
        !metal_ok(metalDeviceSynchronize(),
                  std::string("synchronize ") + lookup_kernel,
                  error)) {
        set_failure(shared, error);
        return false;
    }
    std::uint32_t overflow = 0u;
    std::uint32_t hit_count = 0u;
    if (!copy_from_device(&overflow,
                          context.overflow,
                          sizeof(overflow),
                          "read BSGS overflow",
                          error) ||
        !copy_from_device(&hit_count,
                          context.hit_count,
                          sizeof(hit_count),
                          "read BSGS hit count",
                          error)) {
        set_failure(shared, error);
        return false;
    }
    bool continue_collision_page = false;
    if (overflow != 0u || hit_count > kHitCapacity) {
        if (items.size() > 1u) {
            const std::size_t middle = items.size() / 2u;
            const std::vector<WorkItem> left(
                items.begin(), items.begin() + middle);
            const std::vector<WorkItem> right(
                items.begin() + middle, items.end());
            return execute_work(context,
                                left,
                                shared,
                                field_begin,
                                field_end,
                                match_skip) &&
                execute_work(context,
                             right,
                             shared,
                             field_begin,
                             field_end,
                             match_skip);
        }
        if (field_end - field_begin > 1u) {
            const std::uint32_t middle =
                field_begin + (field_end - field_begin) / 2u;
            return execute_work(context,
                                items,
                                shared,
                                field_begin,
                                middle,
                                match_skip) &&
                execute_work(context,
                             items,
                             shared,
                             middle,
                             field_end,
                             match_skip);
        }
        if (match_skip >
            std::numeric_limits<std::uint64_t>::max() - kHitCapacity) {
            set_failure(shared, "BSGS collision-page offset overflow");
            return false;
        }
        hit_count = kHitCapacity;
        continue_collision_page = true;
    }

    std::uint64_t operations = 0u;
    if (match_skip == 0u) {
        for (const WorkItem& item : items) {
            operations += work_item_operations(item,
                                               shared.giant_count,
                                               field_begin,
                                               field_end,
                                               shared.options->shifts.enabled);
        }
    }
    if (shared.hooks->add_operations) {
        shared.hooks->add_operations(operations);
    }
    if (hit_count == 0u) return true;

    std::vector<Hit> host_hits;
    if (shared.options->shifts.enabled) {
        host_hits.resize(hit_count);
        if (!copy_from_device(host_hits.data(),
                              context.hits,
                              host_hits.size() * sizeof(Hit),
                              "read BSGS shifted hits",
                              error)) {
            set_failure(shared, error);
            return false;
        }
    }

    ResolveParams resolve{};
    const auto width_limbs = scalar_limbs(shared.width);
    std::copy_n(width_limbs.data(), 4u, resolve.width);
    resolve.m = shared.m;
    resolve.hit_count = hit_count;
    const std::uint32_t resolve_grid =
        (hit_count + kThreadgroupSize - 1u) / kThreadgroupSize;
    if (!metal_ok(metal_launch("bsgsResolveHits",
                               resolve_grid,
                               kThreadgroupSize,
                               context.hits,
                               context.resolved,
                               resolve),
                  "launch bsgsResolveHits",
                  error) ||
        !metal_ok(metalDeviceSynchronize(),
                  "synchronize bsgsResolveHits",
                  error)) {
        set_failure(shared, error);
        return false;
    }
    std::vector<Resolved> resolved(
        static_cast<std::size_t>(hit_count) * 2u);
    if (!copy_from_device(resolved.data(),
                          context.resolved,
                          resolved.size() * sizeof(Resolved),
                          "read BSGS resolved hits",
                          error)) {
        set_failure(shared, error);
        return false;
    }
    {
        std::lock_guard<std::mutex> lock(shared.result_mutex);
        for (const Resolved& candidate : resolved) {
            if (candidate.valid == 0u ||
                candidate.target_id >= shared.target_count) {
                continue;
            }
            if (!write_result(shared,
                              candidate.target_id,
                              from_limbs(candidate.distance))) {
                return false;
            }
        }
        for (const Hit& hit : host_hits) {
            if (is_shifted_singular_marker(hit) &&
                !process_shifted_singular_marker(shared, hit)) {
                return false;
            }
        }
    }
    if (continue_collision_page) {
        return execute_work(context,
                            items,
                            shared,
                            field_begin,
                            field_end,
                            match_skip + kHitCapacity);
    }
    return true;
}

void search_device_regular(DeviceContext& context,
                           RunShared& shared) {
    const std::uint64_t active_targets =
        static_cast<std::uint64_t>(shared.targets->size());
    const std::uint64_t target_batch =
        std::max<std::uint64_t>(
            1u,
            std::min<std::uint64_t>(
                16384u, active_targets));
    const std::uint64_t groups_per_batch =
        std::max<std::uint64_t>(
            1u,
            kWorkCapacity / static_cast<std::uint64_t>(target_batch));
    for (;;) {
        if (shared.failed.load(std::memory_order_acquire)) return;
        const std::uint64_t remaining =
            shared.remaining_targets.load(std::memory_order_acquire);
        if (remaining == 0u) return;
        BigUInt group_index;
        {
            std::lock_guard<std::mutex> lock(shared.work_mutex);
            if (shared.next_group >= shared.group_count) return;
            group_index = shared.next_group;
            shared.next_group += BigUInt(groups_per_batch);
        }
        const std::uint64_t groups =
            min_u64(shared.group_count - group_index, groups_per_batch);
        std::vector<WorkItem> group_templates;
        group_templates.reserve(static_cast<std::size_t>(groups));
        BigUInt actual_group =
            first_actual_group(shared, group_index);
        for (std::uint64_t group = 0u; group < groups; ++group) {
            const BigUInt giant_base = actual_group * kWalkSize;
            BigUInt center_index =
                giant_base + BigUInt(kWalkSize / 2u);
            BigUInt center_scalar =
                ((center_index << 1u) + BigUInt(1u)) * shared.m;
            center_scalar %= curve_order();
            WorkItem item{};
            const auto center_limbs = scalar_limbs(center_scalar);
            const auto base_limbs = scalar_limbs(giant_base);
            std::copy_n(center_limbs.data(),
                        4u,
                        item.center_scalar);
            std::copy_n(base_limbs.data(), 4u, item.giant_base);
            group_templates.push_back(item);
            advance_actual_group(shared, actual_group);
        }
        for (std::uint64_t first_target = 0u;
             first_target < shared.target_count;) {
            std::vector<WorkItem> items;
            items.reserve(
                static_cast<std::size_t>(groups * target_batch));
            const std::uint64_t last_target =
                first_target +
                std::min(target_batch,
                         shared.target_count - first_target);
            for (std::uint64_t target_id = first_target;
                 target_id < last_target;
                 ++target_id) {
                const std::uint64_t target_slot =
                    target_id;
                if ((*shared.targets)[static_cast<std::size_t>(target_slot)]
                        .solved.load(std::memory_order_acquire)) {
                    continue;
                }
                for (const WorkItem& group_template :
                     group_templates) {
                    WorkItem item = group_template;
                    item.target_slot =
                        static_cast<std::uint32_t>(target_slot);
                    item.target_id = target_id;
                    items.push_back(item);
                }
            }
            if (!execute_work(context, items, shared)) {
                return;
            }
            first_target = last_target;
        }
    }
}

void search_device_shifted(DeviceContext& context,
                           RunShared& shared) {
    const std::uint64_t shifts_per_base =
        shared.options->shifts.count;
    std::vector<WorkItem> items;
    items.reserve(kWorkCapacity);
    const auto flush = [&]() {
        if (items.empty()) return true;
        const bool ok = execute_work(context, items, shared);
        items.clear();
        return ok;
    };
    for (;;) {
        if (shared.failed.load(std::memory_order_acquire) ||
            shared.remaining_targets.load(std::memory_order_acquire) == 0u) {
            return;
        }
        BigUInt logical_group;
        {
            std::lock_guard<std::mutex> lock(shared.work_mutex);
            if (shared.next_group >= shared.group_count) return;
            logical_group = shared.next_group;
            shared.next_group += BigUInt(1u);
        }
        const BigUInt actual_group =
            first_actual_group(shared, logical_group);
        const BigUInt giant_base = actual_group * kWalkSize;
        for (std::uint32_t giant_field = 0u;
             giant_field < kWalkSize;
             ++giant_field) {
            const BigUInt giant_index =
                giant_base + BigUInt(giant_field);
            if (giant_index >= shared.giant_count) break;
            BigUInt giant_scalar =
                ((giant_index << 1u) + BigUInt(1u)) * shared.m;
            giant_scalar %= curve_order();
            for (std::uint64_t target_slot = 0u;
                 target_slot < shared.targets->size();
                 ++target_slot) {
                const std::uint64_t target_id_base =
                    target_slot * shifts_per_base;
                for (std::uint64_t shift_base = 0u;
                     shift_base < shifts_per_base;
                     shift_base += kWalkSize) {
                    const std::uint32_t field_count =
                        static_cast<std::uint32_t>(
                            std::min<std::uint64_t>(
                                kWalkSize,
                                shifts_per_base - shift_base));
                    const std::uint64_t center_shift_index =
                        shift_base + kWalkSize / 2u;
                    BigUInt center_scalar =
                        giant_scalar +
                        shared.range->start +
                        shared.options->shifts.start +
                        shared.options->shifts.step *
                            center_shift_index;
                    center_scalar %= curve_order();
                    WorkItem item{};
                    const auto center_limbs =
                        scalar_limbs(center_scalar);
                    const auto giant_limbs =
                        scalar_limbs(giant_index);
                    std::copy_n(center_limbs.data(),
                                4u,
                                item.center_scalar);
                    std::copy_n(giant_limbs.data(),
                                4u,
                                item.giant_base);
                    item.target_slot =
                        static_cast<std::uint32_t>(target_slot);
                    item.reserved = field_count;
                    item.target_id =
                        target_id_base + shift_base;
                    items.push_back(item);
                    if (items.size() == kWorkCapacity &&
                        !flush()) {
                        return;
                    }
                }
            }
        }
        if (!flush()) return;
    }
}

void search_device(DeviceContext& context,
                   RunShared& shared) {
    if (shared.failed.load(std::memory_order_acquire)) return;
    std::string error;
    if (!metal_ok(metalSetDevice(context.device),
                  "metalSetDevice",
                  error)) {
        set_failure(shared, error);
        return;
    }
    if (shared.options->shifts.enabled) {
        search_device_shifted(context, shared);
    } else {
        search_device_regular(context, shared);
    }
}

std::size_t unsolved_count(const std::vector<Target>& targets) {
    return static_cast<std::size_t>(std::count_if(
        targets.begin(), targets.end(), [](const Target& target) {
            return !target.solved.load(std::memory_order_acquire);
        }));
}

std::uint64_t logical_unsolved_count(
    const Options& options,
    const std::vector<Target>& targets,
    const std::unordered_set<std::uint64_t>& shifted_solved,
    std::uint64_t target_count) {
    if (options.shifts.enabled) {
        return target_count -
            std::min<std::uint64_t>(
                target_count,
                static_cast<std::uint64_t>(shifted_solved.size()));
    }
    return static_cast<std::uint64_t>(unsolved_count(targets));
}

bool search_range(Options& options,
                  const SearchRange& range,
                  const HostPrecompute& precompute,
                  std::vector<Target>& targets,
                  std::unordered_set<std::uint64_t>& shifted_solved,
                  std::uint64_t target_count,
                  const RuntimeHooks& hooks,
                  std::map<std::uint64_t, std::shared_ptr<Table>>& tables,
                  std::uint64_t& attempted_m,
                  std::string& error) {
    const BigUInt width = range.end - range.start;
    MemoryPlan memory;
    const std::uint64_t active_target_count =
        logical_unsolved_count(options,
                               targets,
                               shifted_solved,
                               target_count);
    if (!make_memory_plan(options,
                          width,
                          targets.size(),
                          active_target_count,
                          memory,
                          error)) {
        return false;
    }
    attempted_m = memory.m;
    std::cout << "[!] BSGS engine: negation-map bucketed fingerprint64+j exact-candidate table [!]\n"
              << "[!] BSGS memory: " << memory.budget
              << " bytes, table M=" << memory.m
              << ", bucket~" << memory.entries_per_bucket
              << ", baby-cost~" << std::fixed << std::setprecision(1)
              << static_cast<double>(options.baby_to_giant_cost)
              << ", estimated peak=" << memory.estimated_peak
              << ", shards<=4, unified="
              << (memory.unified ? "yes" : "no") << " [!]\n";

    std::shared_ptr<Table> table;
    const auto existing = tables.find(memory.m);
    if (existing != tables.end()) {
        table = existing->second;
        if (table->entries_per_bucket != memory.entries_per_bucket) {
            build_bucket_index(*table, memory.entries_per_bucket);
        }
    } else {
        table = std::make_shared<Table>();
        std::string cache_warning;
        if (hooks.set_speed_context) {
            hooks.set_speed_context(SpeedPhase::CacheLoad,
                                    memory.m,
                                    1.0,
                                    1u);
        }
        if (!load_cache(options,
                        memory.m,
                        memory.entries_per_bucket,
                        *table,
                        cache_warning)) {
            if (!cache_warning.empty()) {
                std::cerr << "[!] Warning: " << cache_warning
                          << "; rebuilding [!]\n";
            }
            const WalkTable baby_walk =
                build_walk_table(BigUInt(1u), precompute);
            if (!build_table_gpu(memory.m,
                                 memory.entries_per_bucket,
                                 options.devices.front(),
                                 precompute,
                                 baby_walk,
                                 hooks,
                                 *table,
                                 error)) {
                return false;
            }
            if (!save_cache(options, *table, error)) return false;
        }
        tables.emplace(memory.m, table);
    }

    std::vector<std::vector<std::uint64_t>>
        shifted_singular_matches;
    if (options.shifts.enabled) {
        const auto singular_started =
            std::chrono::steady_clock::now();
        build_shifted_singular_matches(
            options,
            *table,
            precompute,
            shifted_singular_matches);
        const double singular_seconds =
            std::chrono::duration<double>(
                std::chrono::steady_clock::now() -
                singular_started).count();
        std::cout << "[!] BSGS shifted singular map: "
                  << (kWalkSize - 1u)
                  << " offsets in "
                  << std::fixed << std::setprecision(3)
                  << singular_seconds << " s [!]\n";
    }

    const HostPoint range_shift = options.shifts.enabled
        ? HostPoint()
        : negate_point(multiply_g(range.start, precompute));
    std::vector<std::uint64_t> target_limbs(targets.size() * 8u);
    for (std::size_t i = 0u; i < targets.size(); ++i) {
        if (targets[i].solved.load(std::memory_order_acquire)) {
            continue;
        }
        const HostPoint shifted_target = options.shifts.enabled
            ? targets[i].point
            : add_points(targets[i].point, range_shift);
        if (!options.shifts.enabled && shifted_target.infinity) {
            RunShared immediate;
            immediate.options = &options;
            immediate.range = &range;
            immediate.precompute = &precompute;
            immediate.targets = &targets;
            immediate.shifted_solved = &shifted_solved;
            immediate.hooks = &hooks;
            immediate.target_count = target_count;
            immediate.width = width;
            immediate.remaining_targets.store(
                1u, std::memory_order_release);
            if (!write_result(immediate, i, BigUInt(0u))) {
                error = immediate.error;
                return false;
            }
        }
        const auto limbs = point_limbs(shifted_target);
        std::copy(limbs.begin(),
                  limbs.end(),
                  target_limbs.begin() + i * 8u);
    }
    if (logical_unsolved_count(options,
                               targets,
                               shifted_solved,
                               target_count) == 0u) {
        return true;
    }

    const BigUInt lookup_walk_step = options.shifts.enabled
        ? options.shifts.step
        : BigUInt(memory.m) * 2u;
    const WalkTable giant_walk =
        build_walk_table(lookup_walk_step, precompute);
    std::vector<std::unique_ptr<DeviceContext>> contexts;
    for (int device : options.devices) {
        auto context = std::make_unique<DeviceContext>();
        if (!prepare_device(*context,
                            device,
                            *table,
                            target_limbs,
                            giant_walk,
                            precompute,
                            error)) {
            return false;
        }
        std::cout << "[!] BSGS GPU " << device << ": "
                  << context->properties.name
                  << ", recommended="
                  << context->properties.recommendedMaxWorkingSetSize
                  << ", allocated="
                  << context->properties.currentAllocatedSize
                  << ", maxBuffer="
                  << context->properties.maxBufferLength << " [!]\n";
        contexts.push_back(std::move(context));
    }

    RunShared shared;
    shared.options = &options;
    shared.range = &range;
    shared.precompute = &precompute;
    shared.targets = &targets;
    shared.shifted_solved = &shifted_solved;
    shared.shifted_singular_matches =
        options.shifts.enabled
        ? &shifted_singular_matches
        : nullptr;
    shared.hooks = &hooks;
    shared.width = width;
    shared.m = memory.m;
    shared.target_count = target_count;
    shared.giant_count = ceil_div(width, memory.m * 2u);
    shared.group_count = ceil_div(shared.giant_count, kWalkSize);
    const std::uint64_t active_targets_before_search =
        logical_unsolved_count(options,
                               targets,
                               shifted_solved,
                               target_count);
    shared.remaining_targets.store(
        active_targets_before_search,
        std::memory_order_release);
    configure_random_groups(shared);
    if (options.random_search) {
        std::cout << "[!] BSGS random order: seed="
                  << options.random_seed
                  << ", giant groups=" << scalar_hex(shared.group_count)
                  << ", offset="
                  << scalar_hex(shared.random_group_offset)
                  << ", stride=" << shared.random_group_stride
                  << ", round=" << kWalkSize
                  << " giant centers [!]\n";
    }
    const BigUInt total_ops =
        shared.giant_count *
        active_targets_before_search;
    if (hooks.set_speed_context) {
        hooks.set_speed_context(
            SpeedPhase::Search,
            saturating_u64(total_ops),
            static_cast<double>(memory.m) * 2.0,
            static_cast<std::uint32_t>(
                std::min<std::uint64_t>(
                    active_targets_before_search,
                    std::numeric_limits<std::uint32_t>::max())));
    }
    const auto started = std::chrono::steady_clock::now();
    std::vector<std::thread> workers;
    for (std::size_t i = 0u; i < contexts.size(); ++i) {
        workers.emplace_back([&, i] {
            search_device(*contexts[i], shared);
        });
    }
    for (std::thread& worker : workers) worker.join();
    if (shared.failed.load(std::memory_order_acquire)) {
        error = shared.error.empty() ? "BSGS device worker failed"
                                     : shared.error;
        return false;
    }
    const double search_seconds = std::chrono::duration<double>(
        std::chrono::steady_clock::now() - started).count();
    if (!table->from_cache &&
        table->build_seconds > 0.0 &&
        search_seconds > 0.0 &&
        logical_unsolved_count(options,
                               targets,
                               shifted_solved,
                               target_count) ==
            active_targets_before_search &&
        !total_ops.is_zero()) {
        const long double baby_rate =
            static_cast<long double>(memory.m) /
            table->build_seconds;
        const long double giant_rate =
            std::exp2(log2_value(total_ops)) / search_seconds;
        const long double measured = std::clamp(
            giant_rate / baby_rate, 8.0L, 512.0L);
        options.baby_to_giant_cost =
            options.baby_to_giant_cost * 0.25L + measured * 0.75L;
    }
    std::cout << "\n[!] BSGS table source: "
              << (table->from_cache ? "cache" : "built")
              << "; range complete, remaining targets="
              << logical_unsolved_count(options,
                                        targets,
                                        shifted_solved,
                                        target_count)
              << " [!]\n";
    return true;
}

} // namespace

bool requested(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-bsgs") == 0) return true;
    }
    return false;
}

void print_help() {
    std::cout << R"HELP(
[!] ==================== BSGS MODE ====================
[!]
[!] -bsgs                           Deterministic bounded secp256k1 BSGS search.
[!] -target VALUE                   Repeatable public key or a target-file path.
[!]                                 Keys: compressed 33-byte or uncompressed 65-byte hex.
[!]                                 File: first token per line; blank/# lines are ignored.
[!] -bsgs-shifts START:COUNT[:STEP] Search Q-(START+i*STEP)G without materializing
[!]                                 generated public keys; START/STEP are hex scalars.
[!] -range VALUE                    Bits 1..256: 64, 65-72, 64,80,96; or hex START:END.
[!] -bsgs-mem auto|all|NN%|SIZE     Hard table/pipeline memory budget.
[!]                                 Bare SIZE is MiB; MiB and GiB suffixes are accepted.
[!] -bsgs-table N                   Exact baby-step count: decimal, 0xHEX or 2^EXP.
[!] -bsgs-table-cache               Enable _local_artifacts/bsgs_tables.
[!] -bsgs-table-dir DIR             Enable cache in DIR.
[!] -bsgs-table-rebuild             Rebuild the enabled table cache.
[!] -random                         Visit every giant group once in randomized order.
[!] -bsgs-random-seed N             Reproducible 64-bit seed; also enables -random.
[!] -device LIST                    Metal devices: 0, 0,1,3 or 0-3.
[!] -o FILE                         Verified results, default result.txt.
[!]
[!] Algorithm:
[!] x(jG), 1<=j<=M, is stored once. Giant centers are spaced by 2M.
[!] Each x match resolves center-j and center+j and is then verified against
[!] the complete secp256k1 public key. Duplicate targets share one search.
[!] The exact fingerprint64+j backend keeps every collision candidate; its
[!] adaptive bucket index and target/work batch sizes are selected internally.
[!] Shift mode keeps only each base Q resident and carries a 64-bit logical
[!] target id through the GPU pipeline. Hundreds of millions of arithmetic
[!] shifts therefore do not allocate hundreds of millions of public keys.
[!] A shifted hit prints both its private key and the verified base private key.
[!]
[!] Memory:
[!] auto uses at most 50% of the free recommended Metal working set.
[!] Its time model balances measured baby-build and giant-search throughput;
[!] compatible ready caches participate with zero table-construction cost.
[!] all leaves 512 MiB for runtime/mandatory buffers. Apple Silicon unified
[!] memory is shared by CPU and GPU, so host storage and GPU replicas count.
[!] Explicit -bsgs-table never exceeds -bsgs-mem; an impossible request fails.
[!]
[!] Multi-GPU:
[!] All selected devices use the same M and replicated exact table. Giant
[!] groups are dynamically claimed without overlaps. Live TABLE/SEARCH stats
[!] are printed only by the toolkit SpeedThreadFunc.
[!] Random mode applies one bijective permutation to 1024-center giant groups.
[!] It starts each round at another pseudorandom group while preserving complete
[!] coverage: no group is skipped or repeated before the range is exhausted.
[!] SEARCH uses CUDA-compatible names: GStep/s is completed giant-center
[!] probes/s and EqKey/s is effective unique scalar coverage/s. This Metal
[!] negation map advances by 2M, so EqKey/s = GStep/s * 2 * table M.
[!]
[!] Examples:
[!] ./METAL_CRYPTO_TOOLKIT -bsgs -target 02... -range 48 -bsgs-mem auto
[!] ./METAL_CRYPTO_TOOLKIT -bsgs -target a.txt -target 03... -range 40,48-52 -bsgs-mem 16GiB -device 0
[!] ./METAL_CRYPTO_TOOLKIT -bsgs -target targets.txt -range 0x1000:0x2000 -bsgs-table 2^12 -bsgs-table-cache
[!] ./METAL_CRYPTO_TOOLKIT -bsgs -target targets.txt -range 56 -random -bsgs-random-seed 0x1234 -bsgs-mem 16GiB
[!] ./METAL_CRYPTO_TOOLKIT -bsgs -target 02... -range 64 -bsgs-mem all -bsgs-table-dir /Volumes/Fast/bsgs
[!] ./METAL_CRYPTO_TOOLKIT -bsgs -target 02145d...d1e16 -bsgs-shifts 0:100000000:1 -range 135 -bsgs-mem all
[!]
[!] Dense shifts are mathematically equivalent to searching the union of
[!] shifted scalar intervals. Overlapping intervals do not create free speedup.
[!]
[!] Full 256-bit arithmetic prevents truncation; it does not make an exhaustive
[!] 256-bit discrete-log search computationally practical.
[!]
)HELP";
}

int run(int argc, char** argv, const RuntimeHooks& hooks) {
    Options options;
    std::string error;
    if (!parse_options(argc, argv, options, error)) {
        std::cerr << "[!] BSGS error: " << error << " [!]\n";
        print_help();
        return 2;
    }
    if (options.devices.empty()) {
        int count = 0;
        if (metalGetDeviceCount(&count) != metalSuccess || count <= 0) {
            std::cerr << "[!] BSGS error: no Metal devices available [!]\n";
            return 1;
        }
        for (int device = 0;
             device < std::min<int>(count, kMaxDevices);
             ++device) {
            options.devices.push_back(device);
        }
    }

    std::vector<Target> targets;
    if (!load_targets(options, targets, error)) {
        std::cerr << "[!] BSGS error: " << error << " [!]\n";
        return 2;
    }
    std::uint64_t target_count = 0u;
    if (!logical_target_count(options, targets, target_count, error)) {
        std::cerr << "[!] BSGS error: " << error << " [!]\n";
        return 2;
    }
    std::cout << "[!] BSGS targets: " << target_count
              << " logical from " << targets.size()
              << " unique base point";
    if (targets.size() != 1u) std::cout << "s";
    std::cout << " and ";
    std::size_t aliases = 0u;
    for (const Target& target : targets) aliases += target.aliases.size();
    std::cout << aliases << " input records";
    if (options.shifts.enabled) {
        std::cout << "; compact shifts start="
                  << scalar_hex(options.shifts.start)
                  << ", count=" << options.shifts.count
                  << ", step=" << scalar_hex(options.shifts.step);
    }
    std::cout << " [!]\n";

    HostPrecompute precompute;
    if (!build_host_precompute(precompute, error)) {
        std::cerr << "[!] BSGS precompute error: " << error << " [!]\n";
        return 1;
    }
    std::map<std::uint64_t, std::shared_ptr<Table>> tables;
    std::unordered_set<std::uint64_t> shifted_solved;
    for (const SearchRange& range : options.ranges) {
        if (logical_unsolved_count(options,
                                   targets,
                                   shifted_solved,
                                   target_count) == 0u) {
            break;
        }
        for (;;) {
            std::uint64_t attempted_m = 0u;
            if (search_range(options,
                             range,
                             precompute,
                             targets,
                             shifted_solved,
                             target_count,
                             hooks,
                             tables,
                             attempted_m,
                             error)) {
                break;
            }
            const bool allocation_failure =
                error.find("allocate BSGS") != std::string::npos ||
                error.find("cannot reserve host memory") !=
                    std::string::npos;
            if (options.memory.kind != MemoryKind::Auto ||
                options.table_explicit ||
                !allocation_failure ||
                attempted_m <= 1u) {
                std::cerr << "[!] BSGS runtime error: "
                          << error << " [!]\n";
                return 1;
            }
            tables.erase(attempted_m);
            options.auto_table_cap = attempted_m / 2u;
            std::cerr << "[!] Warning: BSGS allocation failed at M="
                      << attempted_m << "; retrying auto mode at M<="
                      << options.auto_table_cap << " [!]\n";
            error.clear();
        }
    }
    if (hooks.set_speed_context) {
        hooks.set_speed_context(SpeedPhase::Idle, 0u, 0.0, 0u);
    }
    const std::uint64_t remaining =
        logical_unsolved_count(options,
                               targets,
                               shifted_solved,
                               target_count);
    std::cout << "\n[!] BSGS completed: "
              << (target_count - remaining)
              << "/" << target_count
              << " unique logical targets solved [!]\n";
    return 0;
}

} // namespace bsgs
