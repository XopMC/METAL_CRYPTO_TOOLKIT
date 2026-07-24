#include "KangarooMode.h"

#include "../MetalBackend.h"
#include "../SecpPrecompute.h"
#include "../host_secp/secp256k1.h"
#include "../host_secp/secp256k1_field.h"
#include "../host_secp/secp256k1_group.h"
#include "../host_secp/secp256k1_scalar.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iomanip>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <random>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <type_traits>
#include <unordered_map>
#include <utility>
#include <vector>

namespace kangaroo {
namespace {

class cpp_int {
public:
    static constexpr std::size_t kLimbs = 5;

    cpp_int() = default;

    template <typename T,
              typename = std::enable_if_t<std::is_integral_v<T>>>
    cpp_int(T value)
    {
        assign_integral(value);
    }

    explicit cpp_int(const char* text)
    {
        assign_hex(text == nullptr ? std::string() : std::string(text));
    }

    explicit cpp_int(const std::string& text)
    {
        assign_hex(text);
    }

    template <typename T>
    T convert_to() const
    {
        return static_cast<T>(limbs_[0]);
    }

    int bit_length() const
    {
        for (std::size_t i = kLimbs; i-- > 0;) {
            if (limbs_[i] != 0u) {
                return static_cast<int>(i * 64u + 64u -
                    static_cast<std::size_t>(__builtin_clzll(limbs_[i])));
            }
        }
        return 0;
    }

    bool negative() const
    {
        return negative_;
    }

    bool is_zero() const
    {
        return bit_length() == 0;
    }

    cpp_int operator-() const
    {
        cpp_int result = *this;
        if (!result.is_zero()) {
            result.negative_ = !result.negative_;
        }
        return result;
    }

    cpp_int& operator+=(const cpp_int& other)
    {
        if (negative_ == other.negative_) {
            add_magnitude(other);
        } else {
            const int comparison = compare_magnitude(other);
            if (comparison == 0) {
                limbs_.fill(0);
                negative_ = false;
            } else if (comparison > 0) {
                subtract_magnitude(other);
            } else {
                cpp_int copy = other;
                copy.subtract_magnitude(*this);
                *this = copy;
            }
        }
        normalize();
        return *this;
    }

    cpp_int& operator-=(const cpp_int& other)
    {
        return *this += -other;
    }

    cpp_int& operator<<=(int shift)
    {
        if (shift <= 0 || is_zero()) {
            return *this;
        }
        const std::size_t words = static_cast<std::size_t>(shift / 64);
        const unsigned bits = static_cast<unsigned>(shift & 63);
        std::array<std::uint64_t, kLimbs> result{};
        for (std::size_t source = 0; source < kLimbs; ++source) {
            const std::size_t target = source + words;
            if (target >= kLimbs) {
                continue;
            }
            result[target] |= limbs_[source] << bits;
            if (bits != 0u && target + 1u < kLimbs) {
                result[target + 1u] |= limbs_[source] >> (64u - bits);
            }
        }
        limbs_ = result;
        normalize();
        return *this;
    }

    cpp_int& operator>>=(int shift)
    {
        if (shift <= 0 || is_zero()) {
            return *this;
        }
        const std::size_t words = static_cast<std::size_t>(shift / 64);
        const unsigned bits = static_cast<unsigned>(shift & 63);
        std::array<std::uint64_t, kLimbs> result{};
        for (std::size_t target = 0; target < kLimbs; ++target) {
            const std::size_t source = target + words;
            if (source >= kLimbs) {
                continue;
            }
            result[target] |= limbs_[source] >> bits;
            if (bits != 0u && source + 1u < kLimbs) {
                result[target] |= limbs_[source + 1u] << (64u - bits);
            }
        }
        limbs_ = result;
        normalize();
        return *this;
    }

    cpp_int& operator&=(const cpp_int& other)
    {
        for (std::size_t i = 0; i < kLimbs; ++i) {
            limbs_[i] &= other.limbs_[i];
        }
        normalize();
        return *this;
    }

    cpp_int& operator|=(const cpp_int& other)
    {
        for (std::size_t i = 0; i < kLimbs; ++i) {
            limbs_[i] |= other.limbs_[i];
        }
        normalize();
        return *this;
    }

    cpp_int& operator%=(const cpp_int& modulus)
    {
        const bool was_negative = negative_;
        negative_ = false;
        cpp_int divisor = modulus;
        divisor.negative_ = false;
        if (divisor.is_zero()) {
            return *this;
        }
        while (compare_magnitude(divisor) >= 0) {
            int shift = bit_length() - divisor.bit_length();
            cpp_int aligned = divisor << shift;
            if (compare_magnitude(aligned) < 0) {
                --shift;
                aligned = divisor << shift;
            }
            subtract_magnitude(aligned);
        }
        negative_ = was_negative && !is_zero();
        return *this;
    }

    friend cpp_int operator+(cpp_int left, const cpp_int& right)
    {
        left += right;
        return left;
    }

    friend cpp_int operator-(cpp_int left, const cpp_int& right)
    {
        left -= right;
        return left;
    }

    friend cpp_int operator<<(cpp_int value, int shift)
    {
        value <<= shift;
        return value;
    }

    friend cpp_int operator>>(cpp_int value, int shift)
    {
        value >>= shift;
        return value;
    }

    friend cpp_int operator&(cpp_int left, const cpp_int& right)
    {
        left &= right;
        return left;
    }

    friend cpp_int operator|(cpp_int left, const cpp_int& right)
    {
        left |= right;
        return left;
    }

    friend cpp_int operator~(cpp_int value)
    {
        for (std::uint64_t& limb : value.limbs_) {
            limb = ~limb;
        }
        value.negative_ = false;
        return value;
    }

    friend cpp_int operator%(cpp_int value, const cpp_int& modulus)
    {
        value %= modulus;
        return value;
    }

    friend cpp_int operator*(const cpp_int& left, const cpp_int& right)
    {
        cpp_int result;
        for (std::size_t i = 0; i < kLimbs; ++i) {
            unsigned __int128 carry = 0;
            for (std::size_t j = 0; i + j < kLimbs; ++j) {
                const std::size_t out = i + j;
                const unsigned __int128 product =
                    static_cast<unsigned __int128>(left.limbs_[i]) *
                    right.limbs_[j] + result.limbs_[out] + carry;
                result.limbs_[out] = static_cast<std::uint64_t>(product);
                carry = product >> 64u;
            }
        }
        result.negative_ =
            (left.negative_ != right.negative_) && !result.is_zero();
        return result;
    }

    friend cpp_int operator/(cpp_int value, int divisor)
    {
        if (divisor == 0) {
            return value;
        }
        const bool divisor_negative = divisor < 0;
        const std::uint64_t absolute =
            static_cast<std::uint64_t>(divisor_negative ? -divisor : divisor);
        unsigned __int128 remainder = 0;
        for (std::size_t i = kLimbs; i-- > 0;) {
            const unsigned __int128 current =
                (remainder << 64u) | value.limbs_[i];
            value.limbs_[i] =
                static_cast<std::uint64_t>(current / absolute);
            remainder = current % absolute;
        }
        value.negative_ =
            (value.negative_ != divisor_negative) && !value.is_zero();
        return value;
    }

    friend bool operator==(const cpp_int& left, const cpp_int& right)
    {
        return left.negative_ == right.negative_ &&
            left.limbs_ == right.limbs_;
    }

    friend bool operator!=(const cpp_int& left, const cpp_int& right)
    {
        return !(left == right);
    }

    friend bool operator<(const cpp_int& left, const cpp_int& right)
    {
        if (left.negative_ != right.negative_) {
            return left.negative_;
        }
        const int comparison = left.compare_magnitude(right);
        return left.negative_ ? comparison > 0 : comparison < 0;
    }

    friend bool operator>(const cpp_int& left, const cpp_int& right)
    {
        return right < left;
    }

    friend bool operator<=(const cpp_int& left, const cpp_int& right)
    {
        return !(right < left);
    }

    friend bool operator>=(const cpp_int& left, const cpp_int& right)
    {
        return !(left < right);
    }

private:
    template <typename T>
    void assign_integral(T value)
    {
        limbs_.fill(0);
        negative_ = false;
        if constexpr (std::is_signed_v<T>) {
            if (value < 0) {
                negative_ = true;
                const auto magnitude =
                    static_cast<std::make_unsigned_t<T>>(-(value + 1));
                limbs_[0] = static_cast<std::uint64_t>(magnitude) + 1u;
                return;
            }
        }
        limbs_[0] = static_cast<std::uint64_t>(value);
    }

    void assign_hex(std::string text)
    {
        limbs_.fill(0);
        negative_ = false;
        if (!text.empty() && text[0] == '-') {
            negative_ = true;
            text.erase(text.begin());
        }
        if (text.size() >= 2u && text[0] == '0' &&
            (text[1] == 'x' || text[1] == 'X')) {
            text.erase(0, 2u);
        }
        for (char c : text) {
            const unsigned digit = c >= '0' && c <= '9'
                ? static_cast<unsigned>(c - '0')
                : static_cast<unsigned>(
                    std::tolower(static_cast<unsigned char>(c)) - 'a' + 10);
            *this <<= 4;
            limbs_[0] |= digit;
        }
        normalize();
    }

    int compare_magnitude(const cpp_int& other) const
    {
        for (std::size_t i = kLimbs; i-- > 0;) {
            if (limbs_[i] < other.limbs_[i]) {
                return -1;
            }
            if (limbs_[i] > other.limbs_[i]) {
                return 1;
            }
        }
        return 0;
    }

    void add_magnitude(const cpp_int& other)
    {
        std::uint64_t carry = 0;
        for (std::size_t i = 0; i < kLimbs; ++i) {
            const std::uint64_t before = limbs_[i];
            const std::uint64_t addend = other.limbs_[i] + carry;
            const bool addend_overflow = addend < other.limbs_[i];
            limbs_[i] = before + addend;
            carry = static_cast<std::uint64_t>(
                addend_overflow || limbs_[i] < before);
        }
    }

    void subtract_magnitude(const cpp_int& other)
    {
        std::uint64_t borrow = 0;
        for (std::size_t i = 0; i < kLimbs; ++i) {
            const std::uint64_t before = limbs_[i];
            const std::uint64_t subtrahend = other.limbs_[i] + borrow;
            const bool overflow = subtrahend < other.limbs_[i];
            limbs_[i] = before - subtrahend;
            borrow = static_cast<std::uint64_t>(
                overflow || before < subtrahend);
        }
    }

    void normalize()
    {
        if (is_zero()) {
            negative_ = false;
        }
    }

    std::array<std::uint64_t, kLimbs> limbs_{};
    bool negative_ = false;
};

using ScalarBytes = std::array<std::uint8_t, 32>;

constexpr std::uint32_t kMinJumpCount = 8;
constexpr std::uint32_t kMaxJumpCount = 512;
constexpr std::uint32_t kDefaultJumpCount = 512;
constexpr std::uint32_t kMinStepCount = 256;
constexpr std::uint32_t kMaxStepCount = 8192;
constexpr std::uint32_t kDefaultStepCount = 1000;
constexpr std::uint32_t kThreadgroupSize = 256;
constexpr std::uint32_t kKangaroosPerThread = 16;
constexpr std::uint32_t kCompactSotaKangaroosPerThread = 8;
constexpr std::uint32_t kDpCapacity = 256u * 1024u;
constexpr std::uint32_t kCompactDpSlots = 32u;
constexpr std::uint32_t kHerdMask = 3u;
constexpr std::uint32_t kTargetShift = 2u;
constexpr int kMaxDevices = 32;

std::uint32_t encode_wild_type(std::uint32_t herd_type,
                               std::uint32_t target_index)
{
    return (target_index << kTargetShift) | (herd_type & kHerdMask);
}

const cpp_int& curve_order()
{
    static const cpp_int value(
        "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");
    return value;
}

struct SearchRange {
    cpp_int start = 0;
    cpp_int end = 0;
    int source_bits = 0;
};

struct Options {
    std::string public_key_hex;
    std::vector<std::string> target_values;
    std::vector<SearchRange> ranges;
    std::vector<int> manual_exponents;
    int first_exponent = -1;
    int last_exponent = -1;
    double probability = 0.5;
    std::vector<int> devices;
    int dp_bits = 0;
    double max_factor = 0.0;
    std::uint32_t jump_count = kDefaultJumpCount;
    std::uint32_t step_count = kDefaultStepCount;
    bool cache_enabled = true;
    bool cache_rebuild = false;
    std::filesystem::path cache_dir =
        std::filesystem::path("_local_artifacts") / "kangaroo_dp";
    std::filesystem::path output_file = "result.txt";
    bool logging = false;
};

struct HostPoint {
    secp256k1_ge value{};
    bool infinity = true;
};

struct TargetInput {
    std::string public_key_hex;
    std::string source;
    HostPoint original;
    bool solved = false;
};

struct HostPrecompute {
    std::vector<secp256k1_ge_storage> entries;
    std::size_t pitch = 0;
    unsigned int windows = 0;
    unsigned int bits = 12;
};

struct Jump {
    HostPoint point;
    cpp_int distance;
};

struct alignas(8) KangarooStateHost {
    std::uint64_t x[4]{};
    std::uint64_t y[4]{};
    std::uint64_t distance[4]{};
    std::uint32_t type = 0;
    std::uint32_t flags = 0;
};

struct alignas(8) KangarooDpHost {
    std::uint64_t x0 = 0;
    std::uint64_t x1 = 0;
    std::uint64_t distance[4]{};
    std::uint32_t type = 0;
    std::uint32_t reserved = 0;
};

struct alignas(8) KangarooCompactDpXHost {
    std::uint64_t x0 = 0;
    std::uint64_t x1 = 0;
};

struct alignas(8) KangarooWalkParamsHost {
    std::uint32_t kangaroo_count = 0;
    std::uint32_t step_count = 0;
    std::uint32_t jump_count = 0;
    std::uint32_t jump_mask = 0;
    std::uint32_t dp_bits = 0;
    std::uint32_t dp_capacity = 0;
    std::uint32_t dp_slots = 0;
    std::uint32_t reserved = 0;
    std::uint64_t launch_index = 0;
};

struct KangarooInitParamsHost {
    std::uint32_t kangaroo_count = 0;
    std::uint32_t windows = 0;
    std::uint32_t window_bits = 0;
    std::uint32_t generation_mode = 0;
};

static_assert(sizeof(KangarooStateHost) == 104, "KangarooState host layout");
static_assert(sizeof(KangarooDpHost) == 56, "KangarooDP host layout");
static_assert(sizeof(KangarooCompactDpXHost) == 16,
              "KangarooCompactDpX host layout");
static_assert(sizeof(KangarooWalkParamsHost) == 40,
              "KangarooWalkParams host layout");
static_assert(sizeof(KangarooInitParamsHost) == 16, "KangarooInitParams host layout");

RuntimeHooks g_hooks{};

bool is_hex(const std::string& value)
{
    return !value.empty() &&
        std::all_of(value.begin(), value.end(), [](unsigned char c) {
            return std::isxdigit(c) != 0;
        });
}

std::string lower_hex(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return value;
}

bool parse_scalar(const std::string& text, cpp_int& result)
{
    std::string value = text;
    if (value.size() > 2 && value[0] == '0' &&
        (value[1] == 'x' || value[1] == 'X')) {
        value.erase(0, 2);
    }
    if (value.empty() || value.size() > 64 || !is_hex(value)) {
        return false;
    }
    result = 0;
    for (char c : value) {
        const unsigned digit = c >= '0' && c <= '9'
            ? static_cast<unsigned>(c - '0')
            : static_cast<unsigned>(std::tolower(static_cast<unsigned char>(c)) - 'a' + 10);
        result = (result << 4) | digit;
    }
    return true;
}

ScalarBytes scalar_bytes(cpp_int value)
{
    ScalarBytes bytes{};
    if (value < 0) {
        value = -value;
    }
    for (int i = 31; i >= 0 && value != 0; --i) {
        bytes[static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>((value & 0xff).convert_to<unsigned>());
        value >>= 8;
    }
    return bytes;
}

std::string scalar_hex(cpp_int value)
{
    const ScalarBytes bytes = scalar_bytes(value);
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::uint8_t byte : bytes) {
        out << std::setw(2) << static_cast<unsigned>(byte);
    }
    return out.str();
}

int bit_length(const cpp_int& value)
{
    if (value <= 0) {
        return 0;
    }
    return value.bit_length();
}

bool parse_int(const std::string& text, int minimum, int maximum, int& result)
{
    try {
        std::size_t used = 0;
        const long long parsed = std::stoll(text, &used, 10);
        if (used != text.size() || parsed < minimum || parsed > maximum) {
            return false;
        }
        result = static_cast<int>(parsed);
        return true;
    }
    catch (...) {
        return false;
    }
}

bool parse_double(const std::string& text,
                  double minimum,
                  double maximum,
                  double& result)
{
    try {
        std::size_t used = 0;
        const double parsed = std::stod(text, &used);
        if (used != text.size() || !std::isfinite(parsed) ||
            parsed < minimum || parsed > maximum) {
            return false;
        }
        result = parsed;
        return true;
    }
    catch (...) {
        return false;
    }
}

bool append_number_list(const std::string& text,
                        int minimum,
                        int maximum,
                        std::vector<int>& values,
                        std::string& error)
{
    std::stringstream stream(text);
    std::string token;
    while (std::getline(stream, token, ',')) {
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
        if (token.find('-', dash + 1) != std::string::npos) {
            error = "invalid interval '" + token + "'";
            return false;
        }
        int first = 0;
        int last = 0;
        if (!parse_int(token.substr(0, dash), minimum, maximum, first) ||
            !parse_int(token.substr(dash + 1), minimum, maximum, last) ||
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

bool parse_range_argument(const std::string& text,
                          std::vector<SearchRange>& ranges,
                          std::string& error)
{
    if (text.find(':') != std::string::npos) {
        if (!ranges.empty()) {
            error = "hex START:END cannot be combined with other ranges";
            return false;
        }
        const std::size_t colon = text.find(':');
        SearchRange range;
        if (colon == 0 || colon + 1 >= text.size() ||
            text.find(':', colon + 1) != std::string::npos ||
            !parse_scalar(text.substr(0, colon), range.start) ||
            !parse_scalar(text.substr(colon + 1), range.end)) {
            error = "expected hexadecimal START:END";
            return false;
        }
        if (range.start < 0 || range.start >= range.end ||
            range.end > curve_order()) {
            error = "expected 0 <= START < END <= secp256k1 order";
            return false;
        }
        ranges.push_back(range);
        return true;
    }

    std::vector<int> bits;
    if (!append_number_list(text, 1, 256, bits, error)) {
        return false;
    }
    for (int value : bits) {
        SearchRange range;
        range.source_bits = value;
        range.start = cpp_int(1) << (value - 1);
        range.end = value == 256 ? curve_order() : (cpp_int(1) << value);
        if (range.start >= range.end) {
            error = "cannot construct " + std::to_string(value) + "-bit range";
            return false;
        }
        ranges.push_back(std::move(range));
    }
    return true;
}

std::vector<std::uint8_t> decode_hex(const std::string& text)
{
    std::vector<std::uint8_t> result;
    if ((text.size() & 1u) != 0u || !is_hex(text)) {
        return result;
    }
    result.reserve(text.size() / 2u);
    for (std::size_t i = 0; i < text.size(); i += 2u) {
        const auto nibble = [](char c) -> unsigned {
            if (c >= '0' && c <= '9') {
                return static_cast<unsigned>(c - '0');
            }
            return static_cast<unsigned>(
                std::tolower(static_cast<unsigned char>(c)) - 'a' + 10);
        };
        result.push_back(static_cast<std::uint8_t>(
            (nibble(text[i]) << 4u) | nibble(text[i + 1u])));
    }
    return result;
}

bool build_host_precompute(HostPrecompute& result, std::string& error)
{
    return build_secp256k1_precompute_table_host(
        result.bits,
        result.entries,
        result.pitch,
        result.windows,
        error);
}

secp256k1_scalar host_scalar(cpp_int value)
{
    value %= curve_order();
    if (value < 0) {
        value += curve_order();
    }
    const ScalarBytes bytes = scalar_bytes(value);
    secp256k1_scalar result{};
    int overflow = 0;
    secp256k1_scalar_set_b32(&result, bytes.data(), &overflow);
    return result;
}

HostPoint multiply_g(const cpp_int& scalar, const HostPrecompute& precompute)
{
    HostPoint result;
    const secp256k1_scalar value = host_scalar(scalar);
    if (secp256k1_scalar_is_zero(&value)) {
        return result;
    }
    secp256k1_gej jacobian{};
    secp256k1_ecmult_big(
        &jacobian,
        &value,
        precompute.entries.data(),
        precompute.pitch,
        static_cast<int>(precompute.windows),
        precompute.bits);
    if (jacobian.infinity != 0) {
        return result;
    }
    secp256k1_ge affine{};
    secp256k1_ge_set_gej(&affine, &jacobian);
    result.value = affine;
    result.infinity = affine.infinity != 0;
    return result;
}

bool parse_public_key(const std::string& text, HostPoint& result)
{
    const std::vector<std::uint8_t> bytes = decode_hex(text);
    if (bytes.size() != 33u && bytes.size() != 65u) {
        return false;
    }
    secp256k1_ge point{};
    if (bytes.size() == 33u) {
        secp256k1_fe x{};
        if (!secp256k1_fe_set_b32(&x, bytes.data() + 1u) ||
            !secp256k1_ge_set_xo_var(&point, &x, bytes[0] == 3u)) {
            return false;
        }
    } else {
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
    result.value = point;
    result.infinity = point.infinity != 0;
    return !result.infinity;
}

HostPoint negate_point(const HostPoint& point)
{
    if (point.infinity) {
        return point;
    }
    HostPoint result = point;
    secp256k1_ge_neg(&result.value, &point.value);
    return result;
}

HostPoint add_points(const HostPoint& left, const HostPoint& right)
{
    if (left.infinity) {
        return right;
    }
    if (right.infinity) {
        return left;
    }
    secp256k1_gej left_jacobian{};
    secp256k1_gej sum{};
    secp256k1_gej_set_ge(&left_jacobian, &left.value);
    secp256k1_gej_add_ge_var(&sum, &left_jacobian, &right.value, nullptr);
    if (sum.infinity != 0) {
        return {};
    }
    HostPoint result;
    secp256k1_ge_set_gej(&result.value, &sum);
    result.infinity = result.value.infinity != 0;
    return result;
}

HostPoint subtract_scalar(const HostPoint& point,
                          const cpp_int& scalar,
                          const HostPrecompute& precompute)
{
    return add_points(point, negate_point(multiply_g(scalar, precompute)));
}

std::array<std::uint8_t, 64> point_bytes(const HostPoint& point)
{
    std::array<std::uint8_t, 64> result{};
    if (point.infinity) {
        return result;
    }
    secp256k1_ge normalized = point.value;
    secp256k1_fe_normalize_var(&normalized.x);
    secp256k1_fe_normalize_var(&normalized.y);
    secp256k1_fe_get_b32(result.data(), &normalized.x);
    secp256k1_fe_get_b32(result.data() + 32u, &normalized.y);
    return result;
}

bool equal_points(const HostPoint& left, const HostPoint& right)
{
    if (left.infinity || right.infinity) {
        return left.infinity == right.infinity;
    }
    return point_bytes(left) == point_bytes(right);
}

std::string point_uncompressed_hex(const HostPoint& point)
{
    if (point.infinity) {
        return "INFINITY";
    }
    const auto bytes = point_bytes(point);
    std::ostringstream out;
    out << "04" << std::hex << std::setfill('0');
    for (std::uint8_t byte : bytes) {
        out << std::setw(2) << static_cast<unsigned>(byte);
    }
    return out.str();
}

bool load_targets(const Options& options,
                  std::vector<TargetInput>& targets,
                  std::string& error)
{
    std::unordered_map<std::string, std::size_t> unique;
    const auto append = [&](const std::string& token,
                            const std::string& source) -> bool {
        const std::string key = lower_hex(token);
        const bool valid_size = key.size() == 66u || key.size() == 130u;
        const std::string prefix = key.size() >= 2u ? key.substr(0u, 2u) : "";
        if (!valid_size || !is_hex(key) ||
            (key.size() == 66u && prefix != "02" && prefix != "03") ||
            (key.size() == 130u && prefix != "04")) {
            error = "invalid secp256k1 public key at " + source;
            return false;
        }
        HostPoint point;
        if (!parse_public_key(key, point)) {
            error = "public key is not a valid secp256k1 point at " + source;
            return false;
        }
        const std::string identity = point_uncompressed_hex(point);
        if (unique.emplace(identity, targets.size()).second) {
            TargetInput target;
            target.public_key_hex = key;
            target.source = source;
            target.original = point;
            targets.push_back(std::move(target));
        }
        return true;
    };

    for (std::size_t argument = 0u;
         argument < options.target_values.size();
         ++argument) {
        const std::filesystem::path path = options.target_values[argument];
        std::error_code filesystem_error;
        if (std::filesystem::is_regular_file(path, filesystem_error) &&
            !filesystem_error) {
            std::ifstream input(path);
            if (!input) {
                error = "cannot open kangaroo target file " + path.string();
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
                std::istringstream fields(line);
                std::string token;
                if (!(fields >> token)) {
                    continue;
                }
                if (!append(token,
                            path.string() + ":" +
                                std::to_string(line_number))) {
                    return false;
                }
            }
            if (!input.eof()) {
                error = "failed while reading kangaroo target file " +
                    path.string();
                return false;
            }
        } else if (!append(options.target_values[argument],
                           "argv:" + std::to_string(argument + 1u))) {
            return false;
        }
    }
    if (targets.empty()) {
        error = "no public keys were loaded from -target/-hash";
        return false;
    }
    if (targets.size() >
        static_cast<std::size_t>(
            std::numeric_limits<std::uint32_t>::max() >> 2u)) {
        error = "too many unique kangaroo targets";
        return false;
    }
    return true;
}

std::array<std::uint64_t, 8> point_limbs(const HostPoint& point)
{
    std::array<std::uint64_t, 8> result{};
    const auto bytes = point_bytes(point);
    for (std::size_t coordinate = 0; coordinate < 2u; ++coordinate) {
        for (std::size_t limb = 0; limb < 4u; ++limb) {
            std::uint64_t value = 0;
            const std::size_t base = coordinate * 32u + (3u - limb) * 8u;
            for (std::size_t byte = 0; byte < 8u; ++byte) {
                value = (value << 8u) | bytes[base + byte];
            }
            result[coordinate * 4u + limb] = value;
        }
    }
    return result;
}

std::vector<int> random_exponent_chain(int first, int last, double probability)
{
    std::vector<int> result;
    if (first < last || first < 0 || last < 0) {
        return result;
    }
    result.push_back(first);
    if (first != last) {
        std::random_device random_device;
        std::mt19937_64 random(random_device());
        std::uniform_real_distribution<double> distribution(0.0, 1.0);
        for (int exponent = first - 1; exponent > last; --exponent) {
            if (distribution(random) < probability) {
                result.push_back(exponent);
            }
        }
        result.push_back(last);
    }
    return result;
}

cpp_int exponent_scalar(const std::vector<int>& exponents)
{
    cpp_int result = 0;
    for (int exponent : exponents) {
        result += cpp_int(1) << exponent;
    }
    return result % curve_order();
}

double auto_max_factor(int range_bits)
{
    if (range_bits <= 72) {
        return 5.0;
    }
    if (range_bits <= 96) {
        return 3.0;
    }
    return 2.0;
}

int auto_dp_bits(int range_bits)
{
    const double operations = 1.15 * std::pow(2.0, range_bits / 2.0);
    const double approximate = std::log2(operations / 1.0e7);
    return std::clamp(static_cast<int>(std::round(approximate)), 14, 60);
}

long double log2_value(const cpp_int& value)
{
    const int bits = bit_length(value);
    if (bits == 0) {
        return -std::numeric_limits<long double>::infinity();
    }
    const int shift = std::max(0, bits - 64);
    const std::uint64_t prefix = (value >> shift).convert_to<std::uint64_t>();
    return std::log2(static_cast<long double>(prefix)) +
        static_cast<long double>(shift);
}

double equivalent_keys_per_jump(const cpp_int& range_size, double max_factor)
{
    if (max_factor <= 0.0) {
        return 0.0;
    }
    const long double log2_size = log2_value(range_size);
    if (!std::isfinite(static_cast<double>(log2_size))) {
        return 0.0;
    }
    return static_cast<double>(
        std::exp2(log2_size / 2.0L) / (1.15L * max_factor));
}

double multi_equivalent_keys_per_jump(const cpp_int& range_size,
                                      double max_factor,
                                      std::size_t target_count)
{
    if (target_count <= 1u) {
        return equivalent_keys_per_jump(range_size, max_factor);
    }
    const long double shared_tame_work =
        1.0L + (2.0L / 3.0L) *
            static_cast<long double>(target_count - 1u);
    return equivalent_keys_per_jump(range_size, max_factor) *
        static_cast<double>(
            static_cast<long double>(target_count) / shared_tame_work);
}

cpp_int random_below(std::mt19937_64& random, const cpp_int& limit)
{
    if (limit <= 1) {
        return 0;
    }
    const int bits = bit_length(limit - 1);
    cpp_int result;
    do {
        result = 0;
        for (int generated = 0; generated < bits; generated += 64) {
            result |= cpp_int(random()) << generated;
        }
        if ((bits & 63) != 0) {
            result &= (cpp_int(1) << bits) - 1;
        }
    } while (result >= limit);
    return result;
}

std::array<std::uint64_t, 4> scalar_limbs(cpp_int value)
{
    std::array<std::uint64_t, 4> result{};
    const cpp_int mask = (cpp_int(1) << 64) - 1;
    for (std::size_t i = 0; i < result.size(); ++i) {
        result[i] = (value & mask).convert_to<std::uint64_t>();
        value >>= 64;
    }
    return result;
}

std::vector<Jump> build_jump_table(int range_bits,
                                   int shift_adjustment,
                                   std::uint32_t count,
                                   std::mt19937_64& random,
                                   const HostPrecompute& precompute)
{
    const int shift = std::max(1, range_bits + shift_adjustment);
    const cpp_int minimum = cpp_int(1) << shift;
    std::vector<Jump> result;
    result.reserve(count);
    for (std::uint32_t i = 0; i < count; ++i) {
        cpp_int distance = minimum + random_below(random, minimum);
        distance &= ~cpp_int(1);
        result.push_back(Jump{multiply_g(distance, precompute), distance});
    }
    return result;
}

std::vector<std::uint64_t> serialize_jumps(const std::vector<Jump>& jumps)
{
    std::vector<std::uint64_t> result(jumps.size() * 12u);
    for (std::size_t i = 0; i < jumps.size(); ++i) {
        const auto point = point_limbs(jumps[i].point);
        const auto distance = scalar_limbs(jumps[i].distance);
        std::copy(point.begin(), point.end(), result.begin() + i * 12u);
        result[i * 12u + 8u] = distance[0];
        result[i * 12u + 9u] = distance[1];
        result[i * 12u + 10u] = distance[2];
        result[i * 12u + 11u] = distance[3];
    }
    return result;
}

bool is_power_of_two(std::uint32_t value)
{
    return value != 0 && (value & (value - 1)) == 0;
}

bool parse_devices(const std::string& text,
                   std::vector<int>& devices,
                   std::string& error)
{
    std::vector<int> parsed;
    if (!append_number_list(text, 0, kMaxDevices - 1, parsed, error)) {
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

bool parse_options(int argc, char** argv, Options& options, std::string& error)
{
    bool range_seen = false;
    bool exact_range_seen = false;
    bool first_seen = false;
    bool last_seen = false;

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

        if (arg == "-kangaroo" || arg == "-h" || arg == "-help" || arg == "--help") {
            continue;
        }
        if (arg == "-target" || arg == "-hash") {
            std::string value;
            if (!require_value(value)) {
                return false;
            }
            options.target_values.push_back(value);
            continue;
        }
        if (arg == "-range") {
            std::string value;
            if (!require_value(value)) {
                return false;
            }
            const bool exact = value.find(':') != std::string::npos;
            if (exact_range_seen || (exact && range_seen)) {
                error = "hex START:END cannot be combined with another -range";
                return false;
            }
            if (!parse_range_argument(value, options.ranges, error)) {
                return false;
            }
            range_seen = true;
            exact_range_seen = exact;
            continue;
        }
        if (arg == "-first" || arg == "-last") {
            std::string value;
            int parsed = 0;
            if (!require_value(value) || !parse_int(value, 0, 255, parsed)) {
                if (error.empty()) {
                    error = arg + " expects 0..255";
                }
                return false;
            }
            if (arg == "-first") {
                options.first_exponent = parsed;
                first_seen = true;
            } else {
                options.last_exponent = parsed;
                last_seen = true;
            }
            continue;
        }
        if (arg == "-exp") {
            std::string value;
            if (!require_value(value)) {
                return false;
            }
            options.manual_exponents.clear();
            if (!append_number_list(value, 0, 255, options.manual_exponents, error)) {
                return false;
            }
            continue;
        }
        if (arg == "-prob") {
            std::string value;
            if (!require_value(value) ||
                !parse_double(value, 0.0, 1.0, options.probability)) {
                if (error.empty()) {
                    error = "-prob expects 0.0..1.0";
                }
                return false;
            }
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
        if (arg == "-dpbits") {
            std::string value;
            if (!require_value(value) ||
                !parse_int(value, 14, 60, options.dp_bits)) {
                if (error.empty()) {
                    error = "-dpbits expects 14..60";
                }
                return false;
            }
            continue;
        }
        if (arg == "-lim") {
            std::string value;
            if (!require_value(value) ||
                !parse_double(value,
                              std::numeric_limits<double>::min(),
                              1.0e9,
                              options.max_factor)) {
                if (error.empty()) {
                    error = "-lim expects a positive finite number";
                }
                return false;
            }
            continue;
        }
        if (arg == "-jumps") {
            std::string value;
            int parsed = 0;
            if (!require_value(value) ||
                !parse_int(value, kMinJumpCount, kMaxJumpCount, parsed) ||
                !is_power_of_two(static_cast<std::uint32_t>(parsed))) {
                if (error.empty()) {
                    error = "-jumps expects a power of two from 8 to 512";
                }
                return false;
            }
            options.jump_count = static_cast<std::uint32_t>(parsed);
            continue;
        }
        if (arg == "-kangsteps") {
            std::string value;
            int parsed = 0;
            if (!require_value(value) ||
                !parse_int(value, kMinStepCount, kMaxStepCount, parsed)) {
                if (error.empty()) {
                    error = "-kangsteps expects 256..8192";
                }
                return false;
            }
            options.step_count = static_cast<std::uint32_t>(parsed);
            continue;
        }
        if (arg == "-kangaroo-dp-dir") {
            std::string value;
            if (!require_value(value)) {
                return false;
            }
            options.cache_dir = value;
            continue;
        }
        if (arg == "-no-kangaroo-dp-cache") {
            options.cache_enabled = false;
            continue;
        }
        if (arg == "-kangaroo-dp-rebuild") {
            options.cache_rebuild = true;
            continue;
        }
        if (arg == "-o") {
            std::string value;
            if (!require_value(value)) {
                return false;
            }
            options.output_file = value;
            continue;
        }
        if (arg == "-log") {
            options.logging = true;
            continue;
        }
        error = "unknown kangaroo option '" + arg + "'";
        return false;
    }

    if (options.target_values.empty()) {
        error = "-kangaroo requires at least one -target HEX/file or -hash HEX";
        return false;
    }
    if (!range_seen || options.ranges.empty()) {
        error = "-kangaroo requires at least one -range";
        return false;
    }
    if (first_seen != last_seen) {
        error = "-first and -last must be specified together";
        return false;
    }
    if (first_seen && options.first_exponent < options.last_exponent) {
        error = "-first must be greater than or equal to -last";
        return false;
    }
    if (!options.manual_exponents.empty() && first_seen) {
        error = "-exp cannot be combined with -first/-last";
        return false;
    }
    if (options.cache_rebuild && !options.cache_enabled) {
        error = "-kangaroo-dp-rebuild cannot be combined with -no-kangaroo-dp-cache";
        return false;
    }
    return true;
}

struct DpKeyHash {
    std::size_t operator()(const std::array<std::uint8_t, 12>& key) const noexcept
    {
        std::uint64_t first = 0;
        std::uint32_t last = 0;
        std::memcpy(&first, key.data(), sizeof(first));
        std::memcpy(&last, key.data() + sizeof(first), sizeof(last));
        std::uint64_t mixed = first ^ (static_cast<std::uint64_t>(last) << 32u);
        mixed ^= mixed >> 33u;
        mixed *= 0xff51afd7ed558ccdULL;
        mixed ^= mixed >> 33u;
        return static_cast<std::size_t>(mixed);
    }
};

struct DpRecord {
    std::array<std::uint8_t, 12> x{};
    cpp_int distance = 0;
    std::uint32_t type = 0;

    std::uint32_t herd_type() const
    {
        return type & 3u;
    }

    std::uint32_t target_index() const
    {
        return type >> 2u;
    }
};

class DpDatabase {
public:
    explicit DpDatabase(bool preserve_collisions = false)
        : preserve_collisions_(preserve_collisions)
    {
    }

    void collisions_and_add(const DpRecord& record,
                            std::vector<DpRecord>& collisions)
    {
        collisions.clear();
        const auto primary = records_.find(record.x);
        if (primary == records_.end()) {
            records_.emplace(record.x, record);
            return;
        }
        collisions.push_back(primary->second);
        bool duplicate = false;
        duplicate =
            primary->second.type == record.type &&
            primary->second.distance == record.distance;
        const auto [first, last] = collision_records_.equal_range(record.x);
        for (auto position = first; position != last; ++position) {
            collisions.push_back(position->second);
            duplicate = duplicate ||
                (position->second.type == record.type &&
                 position->second.distance == record.distance);
        }
        if (preserve_collisions_ && !duplicate) {
            collision_records_.emplace(record.x, record);
        }
    }

    std::size_t size() const
    {
        return records_.size() + collision_records_.size();
    }

    void clear()
    {
        records_.clear();
        collision_records_.clear();
    }

    bool load(const std::filesystem::path& path,
              std::uint32_t range_bits,
              std::uint32_t dp_bits,
              std::uint32_t jump_count,
              std::string& error)
    {
        clear();
        std::ifstream input(path, std::ios::binary);
        std::array<std::uint8_t, 256> header{};
        if (!input.read(reinterpret_cast<char*>(header.data()),
                        static_cast<std::streamsize>(header.size()))) {
            error = "cannot read DP cache header";
            return false;
        }
        const auto read_u32 = [&](std::size_t offset) {
            return static_cast<std::uint32_t>(header[offset]) |
                (static_cast<std::uint32_t>(header[offset + 1u]) << 8u) |
                (static_cast<std::uint32_t>(header[offset + 2u]) << 16u) |
                (static_cast<std::uint32_t>(header[offset + 3u]) << 24u);
        };
        const bool version4 =
            std::memcmp(header.data(), "PSWDP4", 6u) == 0 && header[6] == 4u;
        const bool version3 =
            std::memcmp(header.data(), "PSWDP3", 6u) == 0 && header[6] == 3u;
        const bool version2 =
            std::memcmp(header.data(), "PSWDP2", 6u) == 0 && header[6] == 2u;
        const bool tame_only = (header[7] & 1u) != 0u;
        const bool compatible =
            tame_only &&
            ((version4 && read_u32(8u) == range_bits &&
              read_u32(12u) == dp_bits && read_u32(16u) == jump_count) ||
             (version3 && range_bits <= 170u && read_u32(8u) == range_bits &&
              read_u32(12u) == dp_bits && read_u32(16u) == jump_count) ||
             (version2 && range_bits <= 170u && jump_count == kDefaultJumpCount &&
              read_u32(8u) == range_bits && read_u32(12u) == dp_bits));
        if (!compatible) {
            error = "incompatible DP cache header";
            return false;
        }

        std::array<std::uint8_t, 2> count_bytes{};
        const std::size_t suffix_size = version4 ? 42u : 32u;
        std::array<std::uint8_t, 42> suffix{};
        for (std::uint32_t prefix = 0; prefix < (1u << 24u); ++prefix) {
            if (!input.read(reinterpret_cast<char*>(count_bytes.data()), 2)) {
                error = "truncated DP cache prefix table";
                clear();
                return false;
            }
            const std::uint32_t count = static_cast<std::uint32_t>(count_bytes[0]) |
                (static_cast<std::uint32_t>(count_bytes[1]) << 8u);
            for (std::uint32_t i = 0; i < count; ++i) {
                if (!input.read(reinterpret_cast<char*>(suffix.data()),
                                static_cast<std::streamsize>(suffix_size))) {
                    error = "truncated DP cache record";
                    clear();
                    return false;
                }
                DpRecord record;
                record.x[0] = static_cast<std::uint8_t>(prefix >> 16u);
                record.x[1] = static_cast<std::uint8_t>(prefix >> 8u);
                record.x[2] = static_cast<std::uint8_t>(prefix);
                std::copy_n(suffix.data(), 9u, record.x.data() + 3u);
                record.distance = 0;
                const int distance_bytes = version4 ? 32 : 22;
                for (int byte = distance_bytes - 1; byte >= 0; --byte) {
                    record.distance <<= 8;
                    record.distance += suffix[9u + static_cast<std::size_t>(byte)];
                }
                if ((suffix[9u + static_cast<std::size_t>(distance_bytes - 1)] &
                     0x80u) != 0u) {
                    record.distance -= cpp_int(1) << (distance_bytes * 8);
                }
                record.type = suffix[9u + static_cast<std::size_t>(distance_bytes)];
                records_.emplace(record.x, std::move(record));
            }
        }
        return true;
    }

    bool save(const std::filesystem::path& path,
              std::uint32_t range_bits,
              std::uint32_t dp_bits,
              std::uint32_t jump_count,
              std::string& error) const
    {
        std::error_code filesystem_error;
        std::filesystem::create_directories(path.parent_path(), filesystem_error);
        if (filesystem_error) {
            error = filesystem_error.message();
            return false;
        }

        std::vector<const DpRecord*> ordered;
        ordered.reserve(size());
        for (const auto& item : records_) {
            if (item.second.type == 0u) {
                ordered.push_back(&item.second);
            }
        }
        for (const auto& item : collision_records_) {
            if (item.second.type == 0u) {
                ordered.push_back(&item.second);
            }
        }
        const auto cache_prefix = [](const DpRecord* record) {
            return (static_cast<std::uint32_t>(record->x[0]) << 16u) |
                (static_cast<std::uint32_t>(record->x[1]) << 8u) |
                static_cast<std::uint32_t>(record->x[2]);
        };
        std::sort(ordered.begin(), ordered.end(),
                  [&](const DpRecord* left, const DpRecord* right) {
            const std::uint32_t left_prefix = cache_prefix(left);
            const std::uint32_t right_prefix = cache_prefix(right);
            return left_prefix != right_prefix
                ? left_prefix < right_prefix
                : left->x < right->x;
        });

        std::ofstream output(path, std::ios::binary | std::ios::trunc);
        if (!output) {
            error = "cannot create DP cache";
            return false;
        }
        const bool extended = range_bits > 170u;
        const int distance_bytes = extended ? 32 : 22;
        const std::size_t suffix_size = 9u +
            static_cast<std::size_t>(distance_bytes) + 1u;
        std::array<std::uint8_t, 256> header{};
        std::memcpy(header.data(), extended ? "PSWDP4" : "PSWDP3", 6u);
        header[6] = extended ? 4u : 3u;
        header[7] = 1u;
        const auto write_u32 = [&](std::size_t offset, std::uint32_t value) {
            header[offset] = static_cast<std::uint8_t>(value);
            header[offset + 1u] = static_cast<std::uint8_t>(value >> 8u);
            header[offset + 2u] = static_cast<std::uint8_t>(value >> 16u);
            header[offset + 3u] = static_cast<std::uint8_t>(value >> 24u);
        };
        write_u32(8u, range_bits);
        write_u32(12u, dp_bits);
        write_u32(16u, jump_count);
        output.write(reinterpret_cast<const char*>(header.data()),
                     static_cast<std::streamsize>(header.size()));

        std::size_t position = 0;
        std::array<std::uint8_t, 42> suffix{};
        for (std::uint32_t prefix = 0; prefix < (1u << 24u); ++prefix) {
            const std::size_t first = position;
            while (position < ordered.size()) {
                const auto& key = ordered[position]->x;
                const std::uint32_t record_prefix =
                    (static_cast<std::uint32_t>(key[0]) << 16u) |
                    (static_cast<std::uint32_t>(key[1]) << 8u) |
                    static_cast<std::uint32_t>(key[2]);
                if (record_prefix != prefix) {
                    break;
                }
                ++position;
            }
            const std::size_t count = position - first;
            if (count > std::numeric_limits<std::uint16_t>::max()) {
                error = "too many DP records for one cache prefix";
                return false;
            }
            const std::uint16_t short_count = static_cast<std::uint16_t>(count);
            const std::uint8_t count_bytes[2] = {
                static_cast<std::uint8_t>(short_count),
                static_cast<std::uint8_t>(short_count >> 8u)
            };
            output.write(reinterpret_cast<const char*>(count_bytes), 2);
            for (std::size_t i = first; i < position; ++i) {
                suffix.fill(0);
                const DpRecord& record = *ordered[i];
                std::copy_n(record.x.data() + 3u, 9u, suffix.data());
                cpp_int distance = record.distance;
                if (distance < 0) {
                    distance += cpp_int(1) << (distance_bytes * 8);
                }
                for (int byte = 0; byte < distance_bytes; ++byte) {
                    suffix[9u + byte] =
                        static_cast<std::uint8_t>((distance & 0xff).convert_to<unsigned>());
                    distance >>= 8;
                }
                suffix[9u + static_cast<std::size_t>(distance_bytes)] =
                    static_cast<std::uint8_t>(record.type);
                output.write(reinterpret_cast<const char*>(suffix.data()),
                             static_cast<std::streamsize>(suffix_size));
            }
        }
        output.flush();
        if (!output) {
            error = "failed while writing DP cache";
            return false;
        }
        return true;
    }

private:
    bool preserve_collisions_ = false;
    std::unordered_map<
        std::array<std::uint8_t, 12>, DpRecord, DpKeyHash> records_;
    std::unordered_multimap<
        std::array<std::uint8_t, 12>, DpRecord, DpKeyHash>
        collision_records_;
};

cpp_int signed_distance(const KangarooDpHost& point)
{
    cpp_int result = 0;
    for (int limb = 3; limb >= 0; --limb) {
        result <<= 64;
        result += point.distance[static_cast<std::size_t>(limb)];
    }
    if ((point.distance[3] >> 63u) != 0u) {
        result -= cpp_int(1) << 256;
    }
    return result;
}

DpRecord make_dp_record(const KangarooDpHost& point)
{
    DpRecord result;
    std::array<std::uint8_t, 16> x{};
    std::memcpy(x.data(), &point.x0, sizeof(point.x0));
    std::memcpy(x.data() + sizeof(point.x0), &point.x1, sizeof(point.x1));
    std::copy_n(x.begin(), result.x.size(), result.x.begin());
    result.distance = signed_distance(point);
    result.type = point.type;
    return result;
}

bool cache_header_compatible(const std::filesystem::path& path,
                             std::uint32_t range_bits,
                             std::uint32_t dp_bits,
                             std::uint32_t jump_count)
{
    std::ifstream input(path, std::ios::binary);
    std::array<std::uint8_t, 256> header{};
    if (!input.read(reinterpret_cast<char*>(header.data()),
                    static_cast<std::streamsize>(header.size()))) {
        return false;
    }
    const auto read_u32 = [&](std::size_t offset) {
        return static_cast<std::uint32_t>(header[offset]) |
            (static_cast<std::uint32_t>(header[offset + 1u]) << 8u) |
            (static_cast<std::uint32_t>(header[offset + 2u]) << 16u) |
            (static_cast<std::uint32_t>(header[offset + 3u]) << 24u);
    };
    const bool tame_only = (header[7] & 1u) != 0u;
    return tame_only &&
        ((std::memcmp(header.data(), "PSWDP4", 6u) == 0 && header[6] == 4u &&
          read_u32(8u) == range_bits && read_u32(12u) == dp_bits &&
          read_u32(16u) == jump_count) ||
         (range_bits <= 170u &&
          std::memcmp(header.data(), "PSWDP3", 6u) == 0 && header[6] == 3u &&
          read_u32(8u) == range_bits && read_u32(12u) == dp_bits &&
          read_u32(16u) == jump_count) ||
         (range_bits <= 170u &&
          std::memcmp(header.data(), "PSWDP2", 6u) == 0 && header[6] == 2u &&
          jump_count == kDefaultJumpCount && read_u32(8u) == range_bits &&
          read_u32(12u) == dp_bits));
}

std::filesystem::path cache_path(const Options& options,
                                 const SearchRange& range,
                                 int effective_bits,
                                 int dp_bits)
{
    std::ostringstream name;
    if (range.source_bits > 0) {
        name << range.source_bits << "_bit";
    } else {
        name << "range_" << effective_bits << "_bit";
    }
    name << "_dp" << dp_bits << "_j" << options.jump_count << ".dp";
    return options.cache_dir / name.str();
}

struct GpuContext {
    int device = -1;
    std::string name;
    std::uint32_t kangaroo_count = 0;
    std::uint32_t tame_count = 0;
    std::uint32_t target_count = 1;
    std::uint32_t dp_slots = kCompactDpSlots;
    std::uint64_t walker_budget = 0;
    KangarooStateHost* states = nullptr;
    std::uint64_t* jumps1 = nullptr;
    std::uint64_t* jumps2 = nullptr;
    std::uint64_t* jumps3 = nullptr;
    KangarooDpHost* output = nullptr;
    std::uint32_t* output_count = nullptr;
    secp256k1_ge_storage* precompute = nullptr;
    std::uint64_t* base_a = nullptr;
    std::uint64_t* base_b = nullptr;
    std::uint16_t* hop_metadata = nullptr;
    KangarooCompactDpXHost* compact_dp_x = nullptr;
    std::uint32_t* compact_dp_counts = nullptr;
    std::uint32_t* compact_replay_error = nullptr;
    bool compact170 = false;
    bool wide256 = false;
    bool compact170_fallback = false;
    bool wide256_fallback = false;

    void release()
    {
        if (device >= 0) {
            (void)metalSetDevice(device);
        }
        (void)metalFree(base_b);
        (void)metalFree(base_a);
        (void)metalFree(precompute);
        (void)metalFree(compact_replay_error);
        (void)metalFree(compact_dp_counts);
        (void)metalFree(compact_dp_x);
        (void)metalFree(hop_metadata);
        (void)metalFree(output_count);
        (void)metalFree(output);
        (void)metalFree(jumps3);
        (void)metalFree(jumps2);
        (void)metalFree(jumps1);
        (void)metalFree(states);
        base_b = nullptr;
        base_a = nullptr;
        precompute = nullptr;
        compact_replay_error = nullptr;
        compact_dp_counts = nullptr;
        compact_dp_x = nullptr;
        hop_metadata = nullptr;
        output_count = nullptr;
        output = nullptr;
        jumps3 = nullptr;
        jumps2 = nullptr;
        jumps1 = nullptr;
        states = nullptr;
    }

    ~GpuContext()
    {
        release();
    }
};

bool metal_ok(metalError_t status, const char* operation, std::string& error)
{
    if (status == metalSuccess) {
        return true;
    }
    error = std::string(operation) + ": " + metalGetErrorString(status);
    return false;
}

std::uint32_t auto_kangaroo_count(const metalDeviceProp& properties,
                                  int range_bits,
                                  std::size_t selected_devices)
{
    const std::uint64_t hardware =
        static_cast<std::uint64_t>(std::max(1, properties.multiProcessorCount)) *
        kThreadgroupSize * kKangaroosPerThread;
    const long double expected = 1.15L * std::exp2(range_bits / 2.0L);
    const std::uint64_t useful = static_cast<std::uint64_t>(std::max<long double>(
        1024.0L,
        expected / std::max<std::size_t>(1u, selected_devices) / 64.0L));
    std::uint64_t count = std::min<std::uint64_t>(hardware, useful);
    const std::uint64_t alignment =
        static_cast<std::uint64_t>(kThreadgroupSize) * kKangaroosPerThread;
    count = std::max<std::uint64_t>(alignment, (count / alignment) * alignment);
    return static_cast<std::uint32_t>(std::min<std::uint64_t>(
        count, std::numeric_limits<std::uint32_t>::max()));
}

std::uint32_t multi_kangaroo_count(const metalDeviceProp& properties,
                                   int range_bits,
                                   std::uint32_t step_count,
                                   std::uint32_t dp_slots,
                                   std::size_t selected_devices,
                                   std::size_t target_count,
                                   std::uint32_t& tame_count,
                                   std::uint64_t& walker_budget)
{
    const std::uint64_t base =
        auto_kangaroo_count(properties, range_bits, selected_devices);
    tame_count = static_cast<std::uint32_t>(base / 3u);
    if (target_count <= 1u) {
        walker_budget = 0u;
        return static_cast<std::uint32_t>(base);
    }

    const unsigned __int128 desired =
        static_cast<unsigned __int128>(tame_count) +
        static_cast<unsigned __int128>(base - tame_count) *
            target_count;
    const std::uint64_t free_working_set =
        properties.recommendedMaxWorkingSetSize >
                properties.currentAllocatedSize
            ? properties.recommendedMaxWorkingSetSize -
                properties.currentAllocatedSize
            : 0u;
    walker_budget = std::min<std::uint64_t>(
        16ull << 30u,
        free_working_set == 0u
            ? 4ull << 30u
            : free_working_set / 4u);
    const std::uint64_t fixed_reserve = 64ull << 20u;
    const std::uint64_t per_walker =
        sizeof(KangarooStateHost) +
        static_cast<std::uint64_t>(step_count) * sizeof(std::uint16_t) +
        static_cast<std::uint64_t>(dp_slots) *
            sizeof(KangarooCompactDpXHost) +
        sizeof(std::uint32_t);
    const std::uint64_t budget_walkers =
        walker_budget > fixed_reserve && per_walker != 0u
            ? (walker_budget - fixed_reserve) / per_walker
            : base;
    const std::uint64_t alignment =
        static_cast<std::uint64_t>(kThreadgroupSize) *
        kKangaroosPerThread;
    const std::uint64_t maximum_aligned =
        (static_cast<std::uint64_t>(
             std::numeric_limits<std::uint32_t>::max()) /
         alignment) *
        alignment;
    const std::uint64_t budget_aligned = std::max<std::uint64_t>(
        base,
        (budget_walkers / alignment) * alignment);
    const std::uint64_t desired_bounded = static_cast<std::uint64_t>(
        std::min<unsigned __int128>(desired, maximum_aligned));
    const std::uint64_t desired_aligned = std::min<std::uint64_t>(
        maximum_aligned,
        ((desired_bounded + alignment - 1u) / alignment) * alignment);
    const std::uint64_t count = std::max<std::uint64_t>(
        base,
        std::min(desired_aligned, budget_aligned));
    return static_cast<std::uint32_t>(count);
}

template <typename T>
bool allocate_device(T*& pointer, std::size_t bytes,
                     const char* name, std::string& error)
{
    return metal_ok(metalMalloc(&pointer, bytes), name, error);
}

bool copy_to_device(void* destination, const void* source,
                    std::size_t bytes, const char* name, std::string& error)
{
    return metal_ok(
        metalMemcpy(destination, source, bytes, metalMemcpyHostToDevice),
        name,
        error);
}

bool prepare_gpu_context(GpuContext& context,
                         int device,
                         int range_bits,
                         std::uint32_t step_count,
                         bool generation_mode,
                         std::size_t selected_devices,
                         const std::vector<HostPoint>& base_a,
                         const std::vector<HostPoint>& base_b,
                         const std::vector<std::uint64_t>& jumps1,
                         const std::vector<std::uint64_t>& jumps2,
                         const std::vector<std::uint64_t>& jumps3,
                         const HostPrecompute& precompute,
                         std::string& error)
{
    if (base_a.empty() || base_a.size() != base_b.size()) {
        error = "kangaroo target base table is empty or mismatched";
        return false;
    }
    context.device = device;
    if (!metal_ok(metalSetDevice(device), "metalSetDevice", error)) {
        return false;
    }
    metalDeviceProp properties{};
    if (!metal_ok(metalGetDeviceProperties(&properties, device),
                  "metalGetDeviceProperties", error)) {
        return false;
    }
    context.name = properties.name;
    context.target_count = static_cast<std::uint32_t>(base_a.size());
    context.dp_slots =
        !generation_mode && base_a.size() > 1u
            ? step_count
            : kCompactDpSlots;
    context.kangaroo_count = multi_kangaroo_count(
        properties,
        range_bits,
        step_count,
        context.dp_slots,
        selected_devices,
        generation_mode ? 1u : base_a.size(),
        context.tame_count,
        context.walker_budget);
    context.compact170 = range_bits <= 170;
    context.wide256 = range_bits > 170;

    std::vector<KangarooStateHost> initial(context.kangaroo_count);
    const std::uint64_t seed =
        0x6b616e6761726f6fULL ^ (static_cast<std::uint64_t>(device) << 32u) ^
        static_cast<std::uint64_t>(range_bits) ^
        (generation_mode ? 0x47454eULL : 0x534f4c5645ULL);
    std::mt19937_64 random(seed);
    const cpp_int tame_limit = cpp_int(1) << std::max(1, range_bits - 4);
    const cpp_int wild_limit = cpp_int(1) << std::max(1, range_bits - 1);
    for (std::uint32_t i = 0; i < context.kangaroo_count; ++i) {
        std::uint32_t type = 0u;
        if (!generation_mode && base_a.size() == 1u) {
            type = i < context.kangaroo_count / 3u ? 0u :
                (i < (context.kangaroo_count * 2u) / 3u ? 1u : 2u);
        } else if (!generation_mode && i >= context.tame_count) {
            const std::uint64_t wild_index =
                static_cast<std::uint64_t>(i - context.tame_count);
            const std::uint32_t target_index =
                static_cast<std::uint32_t>(
                    (wild_index / 2u) % base_a.size());
            type = encode_wild_type(
                1u + static_cast<std::uint32_t>(wild_index & 1u),
                target_index);
        }
        cpp_int distance = random_below(random, type == 0u ? tame_limit : wild_limit);
        if (type != 0u) {
            distance &= ~cpp_int(1);
        }
        if (distance == 0) {
            distance = 2;
        }
        const auto limbs = scalar_limbs(distance);
        initial[i].distance[0] = limbs[0];
        initial[i].distance[1] = limbs[1];
        initial[i].distance[2] = limbs[2];
        initial[i].distance[3] = limbs[3];
        initial[i].type = type;
    }

    const std::size_t state_bytes =
        initial.size() * sizeof(KangarooStateHost);
    const std::size_t jump_bytes = jumps1.size() * sizeof(std::uint64_t);
    const std::size_t output_bytes =
        static_cast<std::size_t>(kDpCapacity) * sizeof(KangarooDpHost);
    const std::size_t precompute_bytes =
        precompute.entries.size() * sizeof(secp256k1_ge_storage);
    if (!allocate_device(context.states, state_bytes, "kangaroo states", error) ||
        !allocate_device(context.jumps1, jump_bytes, "kangaroo jumps1", error) ||
        !allocate_device(context.jumps2, jump_bytes, "kangaroo jumps2", error) ||
        !allocate_device(context.jumps3, jump_bytes, "kangaroo jumps3", error) ||
        !allocate_device(context.output, output_bytes, "kangaroo DP output", error) ||
        !allocate_device(context.output_count, sizeof(std::uint32_t),
                         "kangaroo DP count", error) ||
        !allocate_device(context.precompute, precompute_bytes,
                         "kangaroo precompute", error) ||
        !allocate_device(context.base_a,
                         base_a.size() * 8u * sizeof(std::uint64_t),
                         "kangaroo base A", error) ||
        !allocate_device(context.base_b,
                         base_b.size() * 8u * sizeof(std::uint64_t),
                         "kangaroo base B", error)) {
        return false;
    }
    if (context.compact170 || context.wide256) {
        const std::size_t metadata_bytes =
            static_cast<std::size_t>(context.kangaroo_count) *
            static_cast<std::size_t>(step_count) * sizeof(std::uint16_t);
        const std::size_t compact_dp_bytes =
            static_cast<std::size_t>(context.kangaroo_count) *
            static_cast<std::size_t>(context.dp_slots) *
            sizeof(KangarooCompactDpXHost);
        const std::size_t compact_count_bytes =
            static_cast<std::size_t>(context.kangaroo_count) *
            sizeof(std::uint32_t);
        if (!allocate_device(context.hop_metadata,
                             metadata_bytes,
                             "compact170 hop metadata",
                             error) ||
            !allocate_device(context.compact_dp_x,
                             compact_dp_bytes,
                             "compact170 DP X scratch",
                             error) ||
            !allocate_device(context.compact_dp_counts,
                             compact_count_bytes,
                             "compact170 DP counts",
                             error) ||
            !allocate_device(context.compact_replay_error,
                             sizeof(std::uint32_t),
                             "compact170 replay status",
                             error)) {
            (void)metalFree(context.compact_replay_error);
            (void)metalFree(context.compact_dp_counts);
            (void)metalFree(context.compact_dp_x);
            (void)metalFree(context.hop_metadata);
            context.compact_replay_error = nullptr;
            context.compact_dp_counts = nullptr;
            context.compact_dp_x = nullptr;
            context.hop_metadata = nullptr;
            const bool was_compact170 = context.compact170;
            context.compact170 = false;
            context.wide256 = false;
            context.compact170_fallback = was_compact170;
            context.wide256_fallback = !was_compact170;
            error.clear();
        }
    }
    std::vector<std::uint64_t> base_a_limbs(base_a.size() * 8u);
    std::vector<std::uint64_t> base_b_limbs(base_b.size() * 8u);
    for (std::size_t target_index = 0u;
         target_index < base_a.size();
         ++target_index) {
        const auto a = point_limbs(base_a[target_index]);
        const auto b = point_limbs(base_b[target_index]);
        std::copy(a.begin(),
                  a.end(),
                  base_a_limbs.begin() + target_index * 8u);
        std::copy(b.begin(),
                  b.end(),
                  base_b_limbs.begin() + target_index * 8u);
    }
    if (!copy_to_device(context.states, initial.data(), state_bytes,
                        "copy kangaroo states", error) ||
        !copy_to_device(context.jumps1, jumps1.data(), jump_bytes,
                        "copy kangaroo jumps1", error) ||
        !copy_to_device(context.jumps2, jumps2.data(), jump_bytes,
                        "copy kangaroo jumps2", error) ||
        !copy_to_device(context.jumps3, jumps3.data(), jump_bytes,
                        "copy kangaroo jumps3", error) ||
        !copy_to_device(context.precompute, precompute.entries.data(),
                        precompute_bytes, "copy kangaroo precompute", error) ||
        !copy_to_device(context.base_a, base_a_limbs.data(),
                        base_a_limbs.size() * sizeof(std::uint64_t),
                        "copy kangaroo base A", error) ||
        !copy_to_device(context.base_b, base_b_limbs.data(),
                        base_b_limbs.size() * sizeof(std::uint64_t),
                        "copy kangaroo base B", error)) {
        return false;
    }
    const std::uint64_t pitch = static_cast<std::uint64_t>(precompute.pitch);
    const KangarooInitParamsHost params{
        context.kangaroo_count,
        precompute.windows,
        precompute.bits,
        generation_mode ? 1u : 0u
    };
    const std::uint32_t blocks =
        (context.kangaroo_count + kThreadgroupSize - 1u) / kThreadgroupSize;
    if (!metal_ok(
            metal_launch("kangarooInit", blocks, kThreadgroupSize,
                         context.states,
                         context.base_a,
                         context.base_b,
                         context.precompute,
                         pitch,
                         params),
            "kangarooInit",
            error) ||
        !metal_ok(metalDeviceSynchronize(), "kangarooInit synchronize", error)) {
        return false;
    }
    return true;
}

struct SolveResult {
    bool solved = false;
    bool limit_reached = false;
    cpp_int offset = 0;
    std::vector<cpp_int> offsets;
    std::vector<bool> solved_targets;
    std::string error;
    std::uint64_t operations = 0;
};

bool verify_offset(const cpp_int& candidate,
                   const cpp_int& range_size,
                   const HostPoint& target,
                   const HostPrecompute& precompute)
{
    return candidate >= 0 && candidate < range_size &&
        equal_points(multiply_g(candidate, precompute), target);
}

bool recover_collision(const DpRecord& left,
                       const DpRecord& right,
                       const cpp_int& half_range,
                       const cpp_int& range_size,
                       const std::vector<HostPoint>& targets,
                       const HostPrecompute& precompute,
                       std::uint32_t& target_index,
                       cpp_int& offset)
{
    if (left.type == right.type && left.distance == right.distance) {
        return false;
    }

    const std::uint32_t left_herd = left.herd_type();
    const std::uint32_t right_herd = right.herd_type();
    if (left_herd == 0u && right_herd == 0u) {
        return false;
    }
    target_index = left_herd == 0u
        ? right.target_index()
        : left.target_index();
    if (left_herd != 0u && right_herd != 0u &&
        left.target_index() != right.target_index()) {
        return false;
    }
    if (target_index >= targets.size()) {
        return false;
    }

    std::vector<cpp_int> candidates;
    if (left_herd == 0u || right_herd == 0u) {
        const cpp_int tame =
            left_herd == 0u ? left.distance : right.distance;
        const cpp_int wild =
            left_herd == 0u ? right.distance : left.distance;
        candidates = {
            half_range + tame - wild,
            half_range - tame - wild,
            half_range + tame + wild,
            half_range - tame + wild
        };
    } else {
        for (int left_sign : {-1, 1}) {
            for (int right_sign : {-1, 1}) {
                const cpp_int numerator =
                    cpp_int(left_sign) * left.distance +
                    cpp_int(right_sign) * right.distance;
                if ((numerator & 1) == 0) {
                    candidates.push_back(half_range + numerator / 2);
                }
            }
        }
    }
    std::sort(candidates.begin(), candidates.end());
    candidates.erase(std::unique(candidates.begin(), candidates.end()),
                     candidates.end());
    for (const cpp_int& candidate : candidates) {
        if (verify_offset(
                candidate,
                range_size,
                targets[target_index],
                precompute)) {
            offset = candidate;
            return true;
        }
    }
    return false;
}

SolveResult solve_points(const Options& options,
                         const std::vector<HostPoint>& targets,
                         const cpp_int& range_size,
                         int range_bits,
                         int dp_bits,
                         double requested_max_factor,
                         bool generation_mode,
                         DpDatabase& database,
                         const HostPrecompute& precompute)
{
    SolveResult result;
    if (targets.empty()) {
        result.error = "kangaroo target list is empty";
        return result;
    }
    result.offsets.resize(targets.size());
    result.solved_targets.assign(targets.size(), false);
    std::mt19937_64 jump_random(0);
    const auto jump_table1 = build_jump_table(
        range_bits, 3 - (range_bits / 2), options.jump_count,
        jump_random, precompute);
    const auto jump_table2 = build_jump_table(
        range_bits, -10, options.jump_count, jump_random, precompute);
    const auto jump_table3 = build_jump_table(
        range_bits, -12, options.jump_count, jump_random, precompute);
    const auto jumps1 = serialize_jumps(jump_table1);
    const auto jumps2 = serialize_jumps(jump_table2);
    const auto jumps3 = serialize_jumps(jump_table3);

    const cpp_int half_range = cpp_int(1) << (range_bits - 1);
    const HostPoint half_point = multiply_g(half_range, precompute);
    std::vector<HostPoint> base_a;
    std::vector<HostPoint> base_b;
    if (generation_mode) {
        base_a.push_back(half_point);
        base_b.push_back(negate_point(half_point));
    } else {
        base_a.reserve(targets.size());
        base_b.reserve(targets.size());
        for (const HostPoint& target : targets) {
            base_a.push_back(
                subtract_scalar(target, half_range, precompute));
            base_b.push_back(negate_point(base_a.back()));
        }
    }

    std::vector<std::unique_ptr<GpuContext>> contexts;
    contexts.reserve(options.devices.size());
    for (int device : options.devices) {
        auto context = std::make_unique<GpuContext>();
        if (!prepare_gpu_context(
                *context,
                device,
                range_bits,
                options.step_count,
                generation_mode,
                options.devices.size(),
                base_a,
                base_b,
                jumps1,
                jumps2,
                jumps3,
                precompute,
                result.error)) {
            return result;
        }
        std::cout << "[!] Metal GPU " << device << ": " << context->name
                  << ", kangaroos: " << context->kangaroo_count
                  << ", engine: "
                  << (context->compact170
                          ? "compact170"
                          : (context->wide256
                                 ? "wide256"
                                 : (context->compact170_fallback
                                 ? "legacy (compact170 VRAM fallback)"
                                  : (context->wide256_fallback
                                        ? "legacy (wide256 VRAM fallback)"
                                        : "legacy"))))
                  << (context->compact170 ? ", walk: SOTA+ group8" : "")
                  << (targets.size() > 1u
                          ? ", contour: multi-target shared-tame"
                          : ", contour: single-target")
                  << (targets.size() > 1u
                          ? ", targets: " + std::to_string(targets.size()) +
                                ", tame: " +
                                std::to_string(context->tame_count) +
                                ", replay slots: " +
                                std::to_string(context->dp_slots) +
                                ", VRAM budget: " +
                                std::to_string(context->walker_budget)
                          : "")
                  << " [!]\n";
        contexts.push_back(std::move(context));
    }
    if (contexts.empty()) {
        result.error = "no prepared Metal GPU is available";
        return result;
    }

    std::uint64_t operations_per_launch = 0;
    for (const auto& context : contexts) {
        const std::uint64_t operations =
            static_cast<std::uint64_t>(context->kangaroo_count) *
            options.step_count;
        if (operations >
            std::numeric_limits<std::uint64_t>::max() - operations_per_launch) {
            result.error = "kangaroo operation counter overflow";
            return result;
        }
        operations_per_launch += operations;
    }
    const long double expected_operations =
        1.15L * std::exp2(range_bits / 2.0L);
    const long double target_work_factor = generation_mode
        ? 1.0L
        : 1.0L +
            (2.0L / 3.0L) *
                static_cast<long double>(targets.size() - 1u);
    const double minimum_factor = static_cast<double>(
        static_cast<long double>(operations_per_launch) * 4.0L /
        expected_operations);
    const double max_factor = std::max(
        requested_max_factor *
            static_cast<double>(target_work_factor),
        minimum_factor);
    const long double max_operations =
        static_cast<long double>(max_factor) * expected_operations;
    std::vector<std::vector<KangarooDpHost>> host_outputs;
    host_outputs.reserve(contexts.size());
    for (std::size_t i = 0; i < contexts.size(); ++i) {
        host_outputs.emplace_back(kDpCapacity);
    }
    std::vector<DpRecord> collisions;
    std::size_t solved_count = 0u;

    std::uint64_t launch_index = 0;
    for (;;) {
        for (auto& context : contexts) {
            if (!metal_ok(metalSetDevice(context->device),
                          "metalSetDevice walk", result.error) ||
                !metal_ok(metalMemset(context->output_count, 0,
                                     sizeof(std::uint32_t)),
                          "clear kangaroo DP count", result.error)) {
                return result;
            }
            if ((context->compact170 || context->wide256) &&
                !metal_ok(metalMemset(context->compact_replay_error, 0,
                                     sizeof(std::uint32_t)),
                          "clear compact170 replay status", result.error)) {
                return result;
            }
            const KangarooWalkParamsHost params{
                context->kangaroo_count,
                options.step_count,
                options.jump_count,
                options.jump_count - 1u,
                static_cast<std::uint32_t>(dp_bits),
                kDpCapacity,
                context->dp_slots,
                0u,
                launch_index
            };
            const std::uint32_t walk_group_size = context->compact170
                ? kCompactSotaKangaroosPerThread
                : kKangaroosPerThread;
            const std::uint32_t walk_threads =
                (context->kangaroo_count + walk_group_size - 1u) /
                walk_group_size;
            const std::uint32_t blocks =
                (walk_threads + kThreadgroupSize - 1u) / kThreadgroupSize;
            if (context->compact170 || context->wide256) {
                const bool multi_target =
                    context->target_count > 1u;
                const char* walk_kernel = context->compact170
                    ? (multi_target
                           ? "kangarooWalkCompact8Multi"
                           : "kangarooWalkCompact8")
                    : (multi_target
                           ? "kangarooWalkCompactMulti"
                           : "kangarooWalkCompact");
                if (!metal_ok(
                        metal_launch(walk_kernel,
                                     blocks,
                                     kThreadgroupSize,
                                     context->states,
                                     context->jumps1,
                                     context->jumps2,
                                     context->jumps3,
                                     context->hop_metadata,
                                     context->compact_dp_x,
                                     context->compact_dp_counts,
                                     context->compact_replay_error,
                                     params),
                        walk_kernel,
                        result.error)) {
                    return result;
                }
                const std::uint32_t replay_blocks =
                    (context->kangaroo_count + kThreadgroupSize - 1u) /
                    kThreadgroupSize;
                const char* replay_kernel = context->compact170
                    ? (multi_target
                           ? "kangarooReplayCompactMulti"
                           : "kangarooReplayCompact")
                    : (multi_target
                           ? "kangarooReplayWideMulti"
                           : "kangarooReplayWide");
                if (!metal_ok(
                        metal_launch(replay_kernel,
                                     replay_blocks,
                                     kThreadgroupSize,
                                     context->states,
                                     context->jumps1,
                                     context->jumps2,
                                     context->jumps3,
                                     context->hop_metadata,
                                     context->compact_dp_x,
                                     context->compact_dp_counts,
                                     context->output,
                                     context->output_count,
                                     context->compact_replay_error,
                                     params),
                        replay_kernel,
                        result.error)) {
                    return result;
                }
            } else if (!metal_ok(
                           metal_launch("kangarooWalk",
                                        blocks,
                                        kThreadgroupSize,
                                        context->states,
                                        context->jumps1,
                                        context->jumps2,
                                        context->jumps3,
                                        context->output,
                                        context->output_count,
                                        params),
                           "kangarooWalk",
                           result.error)) {
                return result;
            }
        }

        if (operations_per_launch >
            std::numeric_limits<std::uint64_t>::max() - result.operations) {
            result.operations = std::numeric_limits<std::uint64_t>::max();
        } else {
            result.operations += operations_per_launch;
        }
        if (g_hooks.add_operations) {
            g_hooks.add_operations(operations_per_launch);
        }

        for (std::size_t context_index = 0;
             context_index < contexts.size();
             ++context_index) {
            GpuContext& context = *contexts[context_index];
            if (!metal_ok(metalSetDevice(context.device),
                          "metalSetDevice collect", result.error) ||
                !metal_ok(metalDeviceSynchronize(),
                          "kangarooWalk synchronize", result.error)) {
                return result;
            }
            std::uint32_t output_count = 0;
            if (context.compact170 || context.wide256) {
                std::uint32_t replay_error = 0;
                if (!metal_ok(
                        metalMemcpy(&replay_error,
                                    context.compact_replay_error,
                                    sizeof(replay_error),
                                    metalMemcpyDeviceToHost),
                        "read compact170 replay status",
                        result.error)) {
                    return result;
                }
                if (replay_error != 0u) {
                    std::vector<std::uint32_t> compact_counts(
                        context.kangaroo_count);
                    std::uint32_t max_compact_count = 0u;
                    if (metal_ok(
                            metalMemcpy(compact_counts.data(),
                                        context.compact_dp_counts,
                                        compact_counts.size() *
                                            sizeof(std::uint32_t),
                                        metalMemcpyDeviceToHost),
                            "read compact170 DP counts",
                            result.error)) {
                        max_compact_count = *std::max_element(
                            compact_counts.begin(), compact_counts.end());
                    }
                    std::ostringstream message;
                    message
                            << (context.compact170 ? "compact170" : "wide256")
                            << " replay overflow/mismatch (status "
                            << replay_error
                            << ", max per-walk DP " << max_compact_count
                            << "); increase -dpbits or reduce -kangsteps";
                    result.error = message.str();
                    return result;
                }
            }
            if (!metal_ok(
                    metalMemcpy(&output_count,
                                context.output_count,
                                sizeof(output_count),
                                metalMemcpyDeviceToHost),
                    "read kangaroo DP count",
                    result.error)) {
                return result;
            }
            if (output_count > kDpCapacity) {
                result.error =
                    "kangaroo DP output overflow; increase -dpbits";
                return result;
            }
            if (output_count != 0u &&
                !metal_ok(
                    metalMemcpy(host_outputs[context_index].data(),
                                context.output,
                                static_cast<std::size_t>(output_count) *
                                    sizeof(KangarooDpHost),
                                metalMemcpyDeviceToHost),
                    "read kangaroo DPs",
                    result.error)) {
                return result;
            }
            for (std::uint32_t i = 0; i < output_count; ++i) {
                const DpRecord record =
                    make_dp_record(host_outputs[context_index][i]);
                if (generation_mode && record.herd_type() != 0u) {
                    continue;
                }
                database.collisions_and_add(record, collisions);
                if (!generation_mode) {
                    for (const DpRecord& previous : collisions) {
                        std::uint32_t target_index = 0u;
                        cpp_int offset = 0;
                        if (recover_collision(previous,
                                              record,
                                              half_range,
                                              range_size,
                                              targets,
                                              precompute,
                                              target_index,
                                              offset) &&
                            !result.solved_targets[target_index]) {
                            result.solved_targets[target_index] = true;
                            result.offsets[target_index] = offset;
                            ++solved_count;
                            if (targets.size() == 1u) {
                                result.offset = offset;
                            }
                            if (solved_count == targets.size()) {
                                result.solved = true;
                                return result;
                            }
                        }
                    }
                }
            }
        }

        ++launch_index;
        if (static_cast<long double>(result.operations) >= max_operations) {
            result.limit_reached = true;
            return result;
        }
    }
}

SolveResult solve_point(const Options& options,
                        const HostPoint& target,
                        const cpp_int& range_size,
                        int range_bits,
                        int dp_bits,
                        double requested_max_factor,
                        bool generation_mode,
                        DpDatabase& database,
                        const HostPrecompute& precompute)
{
    return solve_points(options,
                        std::vector<HostPoint>{target},
                        range_size,
                        range_bits,
                        dp_bits,
                        requested_max_factor,
                        generation_mode,
                        database,
                        precompute);
}

bool append_result(const Options& options,
                   const std::vector<int>& exponents,
                   const HostPoint& point_after_subtract,
                   const cpp_int& low_key,
                   const cpp_int& full_key)
{
    std::ostringstream block;
    block << "Pub: " << options.public_key_hex << "\n";
    block << "Exps: ";
    for (std::size_t i = 0; i < exponents.size(); ++i) {
        if (i != 0u) {
            block << ",";
        }
        block << exponents[i];
    }
    block << "\nPub after subtract: "
          << point_uncompressed_hex(point_after_subtract);
    block << "\nk_low: " << scalar_hex(low_key);
    block << "\npriv: " << scalar_hex(full_key) << "\n\n";

    std::ofstream output(options.output_file, std::ios::app | std::ios::binary);
    if (!output) {
        std::cerr << "[!] Cannot open kangaroo output file: "
                  << options.output_file.string() << " [!]\n";
        return false;
    }
    const std::string text = block.str();
    output.write(text.data(), static_cast<std::streamsize>(text.size()));
    output.flush();
    return static_cast<bool>(output);
}

void append_log(const Options& options,
                const std::vector<int>& exponents,
                const HostPoint& point)
{
    if (!options.logging) {
        return;
    }
    const std::filesystem::path log_path =
        std::filesystem::path("_local_artifacts") / "kangaroo.log";
    std::error_code error;
    std::filesystem::create_directories(log_path.parent_path(), error);
    std::ofstream log(log_path, std::ios::app);
    if (!log) {
        return;
    }
    log << "Exps: ";
    for (std::size_t i = 0; i < exponents.size(); ++i) {
        if (i != 0u) {
            log << ",";
        }
        log << exponents[i];
    }
    log << "\nPub: " << point_uncompressed_hex(point) << "\n\n";
}

bool prepare_cache(const Options& options,
                   const SearchRange& range,
                   int effective_bits,
                   int dp_bits,
                   double max_factor,
                   const HostPoint& point,
                   const HostPrecompute& precompute,
                   DpDatabase& database)
{
    database.clear();
    if (!options.cache_enabled) {
        return true;
    }
    const std::filesystem::path path =
        cache_path(options, range, effective_bits, dp_bits);
    std::error_code filesystem_error;
    std::filesystem::create_directories(options.cache_dir, filesystem_error);
    if (filesystem_error) {
        std::cerr << "[!] Kangaroo DP cache directory error: "
                  << filesystem_error.message() << " [!]\n";
        return false;
    }

    if (!options.cache_rebuild &&
        cache_header_compatible(path,
                                static_cast<std::uint32_t>(effective_bits),
                                static_cast<std::uint32_t>(dp_bits),
                                options.jump_count)) {
        std::string error;
        if (database.load(path,
                          static_cast<std::uint32_t>(effective_bits),
                          static_cast<std::uint32_t>(dp_bits),
                          options.jump_count,
                          error)) {
            std::cout << "[!] Loaded kangaroo tame cache: " << path.string()
                      << ", DPs: " << database.size() << " [!]\n";
            return true;
        }
        std::cerr << "[!] Cannot load kangaroo DP cache: " << error << " [!]\n";
        return false;
    }

    if (std::filesystem::exists(path)) {
        std::filesystem::remove(path, filesystem_error);
        if (filesystem_error) {
            std::cerr << "[!] Cannot replace incompatible kangaroo DP cache: "
                      << filesystem_error.message() << " [!]\n";
            return false;
        }
    }

    std::cout << "[!] Building kangaroo tame cache: " << path.string() << " [!]\n";
    SolveResult generated = solve_point(
        options,
        point,
        cpp_int(1) << effective_bits,
        effective_bits,
        dp_bits,
        max_factor,
        true,
        database,
        precompute);
    if (!generated.error.empty()) {
        std::cerr << "[!] Kangaroo tame cache error: "
                  << generated.error << " [!]\n";
        return false;
    }
    if (!generated.limit_reached) {
        std::cerr << "[!] Kangaroo tame cache generation stopped unexpectedly [!]\n";
        return false;
    }
    std::string save_error;
    if (!database.save(path,
                       static_cast<std::uint32_t>(effective_bits),
                       static_cast<std::uint32_t>(dp_bits),
                       options.jump_count,
                       save_error)) {
        std::cerr << "[!] Cannot save kangaroo tame cache: "
                  << save_error << " [!]\n";
        return false;
    }
    std::cout << "[!] Saved kangaroo tame cache, DPs: "
              << database.size() << " [!]\n";
    return true;
}

bool append_target_result(const Options& options,
                          const TargetInput& target,
                          const std::vector<int>& exponents,
                          const HostPoint& point_after_subtract,
                          const cpp_int& low_key,
                          const cpp_int& full_key)
{
    Options target_options = options;
    target_options.public_key_hex = target.public_key_hex;
    return append_result(target_options,
                         exponents,
                         point_after_subtract,
                         low_key,
                         full_key);
}

bool all_targets_solved(const std::vector<TargetInput>& targets)
{
    return std::all_of(
        targets.begin(), targets.end(),
        [](const TargetInput& target) { return target.solved; });
}

int run_multi_target(Options& options,
                     std::vector<TargetInput>& targets,
                     const HostPrecompute& precompute,
                     const RuntimeHooks& hooks)
{
    const bool repeat_random_chain =
        options.manual_exponents.empty() && options.first_exponent >= 0;
    std::uint64_t chain_index = 0u;
    for (;;) {
        ++chain_index;
        std::vector<int> exponents;
        if (!options.manual_exponents.empty()) {
            exponents = options.manual_exponents;
        } else if (options.first_exponent >= 0) {
            exponents = random_exponent_chain(
                options.first_exponent,
                options.last_exponent,
                options.probability);
        }

        const cpp_int scalar_sum = exponent_scalar(exponents);
        std::vector<HostPoint> point_after_subtract(targets.size());
        for (std::size_t target_index = 0u;
             target_index < targets.size();
             ++target_index) {
            if (targets[target_index].solved) {
                continue;
            }
            point_after_subtract[target_index] = subtract_scalar(
                targets[target_index].original,
                scalar_sum,
                precompute);
            if (point_after_subtract[target_index].infinity) {
                if (!equal_points(
                        multiply_g(scalar_sum, precompute),
                        targets[target_index].original)) {
                    std::cerr
                        << "[!] Kangaroo verification failed for target "
                        << (target_index + 1u)
                        << " zero remainder [!]\n";
                    return 1;
                }
                if (!append_target_result(
                        options,
                        targets[target_index],
                        exponents,
                        point_after_subtract[target_index],
                        0,
                        scalar_sum)) {
                    return 1;
                }
                targets[target_index].solved = true;
                if (hooks.increment_found) hooks.increment_found();
            } else {
                Options target_options = options;
                target_options.public_key_hex =
                    targets[target_index].public_key_hex;
                append_log(
                    target_options,
                    exponents,
                    point_after_subtract[target_index]);
            }
        }
        if (all_targets_solved(targets)) {
            return 0;
        }

        std::cout << "[!] Kangaroo multi-target chain " << chain_index
                  << ", active: "
                  << std::count_if(
                         targets.begin(),
                         targets.end(),
                         [](const TargetInput& target) {
                             return !target.solved;
                         })
                  << "/" << targets.size()
                  << ", shared tame herd: enabled [!]\n";

        for (std::size_t range_index = 0u;
             range_index < options.ranges.size();
             ++range_index) {
            const SearchRange& range = options.ranges[range_index];
            const cpp_int range_size = range.end - range.start;
            if (range_size <= 0) {
                std::cerr << "[!] Kangaroo error: empty range [!]\n";
                return 2;
            }
            const int effective_bits =
                std::clamp(bit_length(range_size - 1), 32, 256);
            const int dp_bits = options.dp_bits > 0
                ? options.dp_bits
                : auto_dp_bits(effective_bits);
            const double base_max_factor = options.max_factor > 0.0
                ? options.max_factor
                : auto_max_factor(effective_bits);

            std::vector<std::size_t> active_indices;
            std::vector<HostPoint> points_to_solve;
            for (std::size_t target_index = 0u;
                 target_index < targets.size();
                 ++target_index) {
                if (targets[target_index].solved) {
                    continue;
                }
                const HostPoint point_to_solve = subtract_scalar(
                    point_after_subtract[target_index],
                    range.start,
                    precompute);
                if (point_to_solve.infinity) {
                    const cpp_int low_key = range.start;
                    const cpp_int full_key =
                        (scalar_sum + low_key) % curve_order();
                    if (!equal_points(
                            multiply_g(full_key, precompute),
                            targets[target_index].original) ||
                        !append_target_result(
                            options,
                            targets[target_index],
                            exponents,
                            point_after_subtract[target_index],
                            low_key,
                            full_key)) {
                        std::cerr
                            << "[!] Kangaroo range-start verification failed "
                            << "for target " << (target_index + 1u)
                            << " [!]\n";
                        return 1;
                    }
                    targets[target_index].solved = true;
                    if (hooks.increment_found) hooks.increment_found();
                    continue;
                }
                active_indices.push_back(target_index);
                points_to_solve.push_back(point_to_solve);
            }
            if (all_targets_solved(targets)) {
                return 0;
            }
            if (points_to_solve.empty()) {
                continue;
            }

            if (hooks.set_speed_context) {
                hooks.set_speed_context(
                    multi_equivalent_keys_per_jump(
                        range_size,
                        base_max_factor,
                        points_to_solve.size()));
            }
            DpDatabase database(points_to_solve.size() > 1u);
            if (!prepare_cache(options,
                               range,
                               effective_bits,
                               dp_bits,
                               base_max_factor,
                               points_to_solve.front(),
                               precompute,
                               database)) {
                return 1;
            }
            std::cout << "[!] Kangaroo multi-target range "
                      << (range_index + 1u)
                      << "/" << options.ranges.size()
                      << " [" << scalar_hex(range.start)
                      << " .. " << scalar_hex(range.end)
                      << "), active:" << points_to_solve.size()
                      << ", DP:" << dp_bits
                      << ", jumps:" << options.jump_count
                      << ", steps:" << options.step_count
                      << ", distance:"
                      << (effective_bits > 170 ? 256 : 176)
                      << "-bit [!]\n";

            SolveResult solved = solve_points(
                options,
                points_to_solve,
                range_size,
                effective_bits,
                dp_bits,
                base_max_factor,
                false,
                database,
                precompute);
            if (!solved.error.empty()) {
                std::cerr << "[!] Kangaroo multi-target solver error: "
                          << solved.error << " [!]\n";
                return 1;
            }
            for (std::size_t local_index = 0u;
                 local_index < solved.solved_targets.size();
                 ++local_index) {
                if (!solved.solved_targets[local_index]) {
                    continue;
                }
                const std::size_t target_index =
                    active_indices[local_index];
                const cpp_int low_key =
                    range.start + solved.offsets[local_index];
                const cpp_int full_key =
                    (scalar_sum + low_key) % curve_order();
                if (low_key < range.start || low_key >= range.end ||
                    !equal_points(
                        multiply_g(low_key, precompute),
                        point_after_subtract[target_index]) ||
                    !equal_points(
                        multiply_g(full_key, precompute),
                        targets[target_index].original)) {
                    std::cerr
                        << "[!] Kangaroo multi-target verification failed "
                        << "for target " << (target_index + 1u)
                        << " [!]\n";
                    return 1;
                }
                std::cout << "\n[+] Kangaroo target "
                          << (target_index + 1u)
                          << " (" << targets[target_index].source
                          << ") found [!]\n"
                          << "[+] Kangaroo k_low: "
                          << scalar_hex(low_key) << "\n"
                          << "[+] Kangaroo priv: "
                          << scalar_hex(full_key) << "\n";
                if (!append_target_result(
                        options,
                        targets[target_index],
                        exponents,
                        point_after_subtract[target_index],
                        low_key,
                        full_key)) {
                    return 1;
                }
                targets[target_index].solved = true;
                if (hooks.increment_found) hooks.increment_found();
            }
            if (all_targets_solved(targets)) {
                return 0;
            }
        }

        if (!repeat_random_chain) {
            break;
        }
        std::cout << "[!] Kangaroo multi-target chain " << chain_index
                  << " finished with unsolved targets; building the next "
                     "chain [!]\n";
    }

    const std::size_t solved_count = static_cast<std::size_t>(
        std::count_if(
            targets.begin(), targets.end(),
            [](const TargetInput& target) { return target.solved; }));
    std::cout << "[!] Kangaroo multi-target finished: "
              << solved_count << "/" << targets.size()
              << " solved [!]\n";
    return solved_count == targets.size() ? 0 : 1;
}

} // namespace

bool requested(int argc, char** argv)
{
    for (int i = 1; i < argc; ++i) {
        if (std::strcmp(argv[i], "-kangaroo") == 0) {
            return true;
        }
    }
    return false;
}

void print_help()
{
    std::cout << R"HELP(
[!] ================== KANGAROO MODE ==================
[!]
[!] -kangaroo                       Recover a secp256k1 private key in a bounded range.
[!] -target HEX|FILE / -hash HEX    Repeat a full public key, or load a target file.
[!] -range VALUE                    Bit ranges: 64,65-72 or exact hex START:END (1..256 bits).
[!] -first N -last N                Build a random descending exponent chain.
[!] -exp LIST                       Use an explicit exponent list instead.
[!] -prob P                         Intermediate exponent probability, default 0.5.
[!] -device LIST                    Metal devices, example: 0 or 0,1,3 or 0-3.
[!] -dpbits N                       Distinguished point bits, auto by default.
[!] -lim N                          Maximum operation factor, auto by default.
[!] -jumps N                        Power-of-two jump count 8..512, default 512.
[!] -kangsteps N                    Steps per launch 256..8192, default 1000.
[!] -kangaroo-dp-dir DIR            Tame DP cache directory.
[!] -no-kangaroo-dp-cache           Disable tame DP cache.
[!] -kangaroo-dp-rebuild            Rebuild the selected tame DP cache.
[!] -o FILE                         Output file, default result.txt.
[!] -log                            Append range details to _local_artifacts/kangaroo.log.
[!]
[!] Metal extension:
[!] PSWDP2/3 caches remain CUDA-compatible through 170 bits.
[!] Real 256-bit ranges use the PSWDP4 extended-distance cache format.
[!] More than one unique target automatically selects the shared-tame
[!] multi-target contour. Duplicate points are computed once. Target files
[!] use one key per line; blank lines and # comments are ignored.
[!] The multi-target walker pool grows with the target count and is bounded
[!] automatically by the free recommended Metal working set.
[!]
[!] Single-target example:
[!] ./METAL_CRYPTO_TOOLKIT -kangaroo -target 02... -range 64 -exp 63 -device 0
[!]
[!] Multi-target example:
[!] ./METAL_CRYPTO_TOOLKIT -kangaroo -target 02... -target targets.txt -range 64
[!]
)HELP";
}

int run(int argc, char** argv, const RuntimeHooks& hooks)
{
    Options options;
    std::string error;
    if (!parse_options(argc, argv, options, error)) {
        std::cerr << "[!] Kangaroo error: " << error << " [!]\n";
        print_help();
        return 2;
    }
    g_hooks = hooks;

    HostPrecompute precompute;
    if (!build_host_precompute(precompute, error)) {
        std::cerr << "[!] Kangaroo precompute error: " << error << " [!]\n";
        return 1;
    }
    std::vector<TargetInput> targets;
    if (!load_targets(options, targets, error)) {
        std::cerr << "[!] Kangaroo target error: "
                  << error << " [!]\n";
        return 2;
    }
    options.public_key_hex = targets.front().public_key_hex;
    const HostPoint original_public = targets.front().original;
    if (targets.size() > 1u) {
        std::cout << "[!] Kangaroo targets: " << targets.size()
                  << " unique; contour: multi-target shared-tame [!]\n";
    }

    if (options.devices.empty()) {
        int device_count = 0;
        if (metalGetDeviceCount(&device_count) != metalSuccess ||
            device_count <= 0) {
            std::cerr << "[!] Kangaroo error: no Metal devices available [!]\n";
            return 1;
        }
        for (int device = 0;
             device < std::min(device_count, kMaxDevices);
             ++device) {
            options.devices.push_back(device);
        }
    }

    if (targets.size() > 1u) {
        return run_multi_target(
            options, targets, precompute, hooks);
    }

    const bool repeat_random_chain =
        options.manual_exponents.empty() && options.first_exponent >= 0;
    std::uint64_t chain_index = 0;
    for (;;) {
        ++chain_index;
        std::vector<int> exponents;
        if (!options.manual_exponents.empty()) {
            exponents = options.manual_exponents;
        } else if (options.first_exponent >= 0) {
            exponents = random_exponent_chain(
                options.first_exponent,
                options.last_exponent,
                options.probability);
        }

        const cpp_int scalar_sum = exponent_scalar(exponents);
        const HostPoint point_after_subtract =
            subtract_scalar(original_public, scalar_sum, precompute);
        if (point_after_subtract.infinity) {
            if (!equal_points(multiply_g(scalar_sum, precompute),
                              original_public)) {
                std::cerr << "[!] Kangaroo verification failed for zero "
                             "remainder [!]\n";
                return 1;
            }
            if (!append_result(options,
                               exponents,
                               point_after_subtract,
                               0,
                               scalar_sum)) {
                return 1;
            }
            if (hooks.increment_found) {
                hooks.increment_found();
            }
            return 0;
        }

        append_log(options, exponents, point_after_subtract);
        std::cout << "[!] Kangaroo chain " << chain_index << ", exps:";
        for (int exponent : exponents) {
            std::cout << " " << exponent;
        }
        std::cout << " [!]\n";

        for (std::size_t range_index = 0;
             range_index < options.ranges.size();
             ++range_index) {
            const SearchRange& range = options.ranges[range_index];
            const cpp_int range_size = range.end - range.start;
            if (range_size <= 0) {
                std::cerr << "[!] Kangaroo error: empty range [!]\n";
                return 2;
            }
            const int effective_bits =
                std::clamp(bit_length(range_size - 1), 32, 256);
            const int dp_bits = options.dp_bits > 0
                ? options.dp_bits
                : auto_dp_bits(effective_bits);
            const double base_max_factor = options.max_factor > 0.0
                ? options.max_factor
                : auto_max_factor(effective_bits);
            const HostPoint point_to_solve =
                subtract_scalar(point_after_subtract, range.start, precompute);

            if (hooks.set_speed_context) {
                hooks.set_speed_context(
                    equivalent_keys_per_jump(range_size, base_max_factor));
            }
            if (point_to_solve.infinity) {
                const cpp_int low_key = range.start;
                const cpp_int full_key =
                    (scalar_sum + low_key) % curve_order();
                if (!equal_points(multiply_g(full_key, precompute),
                                  original_public)) {
                    std::cerr << "[!] Kangaroo range-start verification "
                                 "failed [!]\n";
                    return 1;
                }
                std::cout << "\n[+] Kangaroo found k_low: "
                          << scalar_hex(low_key) << "\n";
                std::cout << "[+] Kangaroo priv: "
                          << scalar_hex(full_key) << "\n";
                if (!append_result(options,
                                   exponents,
                                   point_after_subtract,
                                   low_key,
                                   full_key)) {
                    return 1;
                }
                if (hooks.increment_found) {
                    hooks.increment_found();
                }
                return 0;
            }

            DpDatabase database;
            if (!prepare_cache(options,
                               range,
                               effective_bits,
                               dp_bits,
                               base_max_factor,
                               point_to_solve,
                               precompute,
                               database)) {
                return 1;
            }
            std::cout << "[!] Kangaroo range " << (range_index + 1u)
                      << "/" << options.ranges.size()
                      << " [" << scalar_hex(range.start)
                      << " .. " << scalar_hex(range.end)
                      << "), DP:" << dp_bits
                      << ", jumps:" << options.jump_count
                      << ", steps:" << options.step_count
                      << ", distance:" << (effective_bits > 170 ? 256 : 176)
                      << "-bit [!]\n";

            SolveResult solved = solve_point(
                options,
                point_to_solve,
                range_size,
                effective_bits,
                dp_bits,
                base_max_factor,
                false,
                database,
                precompute);
            if (!solved.error.empty()) {
                std::cerr << "[!] Kangaroo solver error: "
                          << solved.error << " [!]\n";
                return 1;
            }
            if (!solved.solved) {
                if (solved.limit_reached) {
                    continue;
                }
                std::cerr << "[!] Kangaroo solver failed [!]\n";
                return 1;
            }

            const cpp_int low_key = range.start + solved.offset;
            if (low_key < range.start || low_key >= range.end ||
                !equal_points(multiply_g(low_key, precompute),
                              point_after_subtract)) {
                std::cerr << "[!] Kangaroo low-key verification failed [!]\n";
                return 1;
            }
            const cpp_int full_key =
                (scalar_sum + low_key) % curve_order();
            if (!equal_points(multiply_g(full_key, precompute),
                              original_public)) {
                std::cerr << "[!] Kangaroo full private-key verification "
                             "failed [!]\n";
                return 1;
            }
            std::cout << "\n[+] Kangaroo found k_low: "
                      << scalar_hex(low_key) << "\n";
            std::cout << "[+] Kangaroo priv: "
                      << scalar_hex(full_key) << "\n";
            if (!append_result(options,
                               exponents,
                               point_after_subtract,
                               low_key,
                               full_key)) {
                return 1;
            }
            if (hooks.increment_found) {
                hooks.increment_found();
            }
            return 0;
        }

        if (!repeat_random_chain) {
            break;
        }
        std::cout << "[!] Kangaroo chain " << chain_index
                  << " finished without a solution; building the next chain [!]\n";
    }

    std::cout << "[!] Kangaroo finished without a solution [!]\n";
    return 1;
}

} // namespace kangaroo
