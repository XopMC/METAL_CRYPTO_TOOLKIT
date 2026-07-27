#include "NonceMode.h"

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
#include <numeric>
#include <set>
#include <sstream>
#include <string>
#include <type_traits>
#include <unordered_set>
#include <utility>
#include <vector>

namespace nonce_mode {
namespace {

class cpp_int {
public:
    static constexpr std::size_t kLimbs = 5u;

    cpp_int() = default;

    template <typename T,
              typename = std::enable_if_t<std::is_integral_v<T>>>
    cpp_int(T value) {
        assign_integral(value);
    }

    explicit cpp_int(const char* text) {
        assign_text(text == nullptr ? std::string() : std::string(text));
    }

    explicit cpp_int(const std::string& text) {
        assign_text(text);
    }

    template <typename T>
    T convert_to() const {
        return static_cast<T>(limbs_[0]);
    }

    std::uint64_t limb(std::size_t index) const {
        return limbs_[index];
    }

    bool is_zero() const {
        for (std::uint64_t limb_value : limbs_) {
            if (limb_value != 0u) return false;
        }
        return true;
    }

    bool negative() const {
        return negative_;
    }

    int bit_length() const {
        for (std::size_t i = kLimbs; i-- > 0u;) {
            if (limbs_[i] != 0u) {
                return static_cast<int>(
                    i * 64u + 64u -
                    static_cast<std::size_t>(
                        __builtin_clzll(limbs_[i])));
            }
        }
        return 0;
    }

    bool bit(std::size_t index) const {
        return index < kLimbs * 64u &&
            ((limbs_[index / 64u] >> (index & 63u)) & 1u) != 0u;
    }

    cpp_int operator-() const {
        cpp_int result = *this;
        if (!result.is_zero()) result.negative_ = !result.negative_;
        return result;
    }

    cpp_int& operator+=(const cpp_int& other) {
        if (negative_ == other.negative_) {
            add_magnitude(other);
        } else {
            const int comparison = compare_magnitude(other);
            if (comparison == 0) {
                limbs_.fill(0u);
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

    cpp_int& operator-=(const cpp_int& other) {
        return *this += -other;
    }

    cpp_int& operator<<=(int shift) {
        if (shift <= 0 || is_zero()) return *this;
        const std::size_t words = static_cast<std::size_t>(shift / 64);
        const unsigned bits = static_cast<unsigned>(shift & 63);
        std::array<std::uint64_t, kLimbs> result{};
        for (std::size_t source = 0u; source < kLimbs; ++source) {
            const std::size_t target = source + words;
            if (target >= kLimbs) continue;
            result[target] |= limbs_[source] << bits;
            if (bits != 0u && target + 1u < kLimbs) {
                result[target + 1u] |=
                    limbs_[source] >> (64u - bits);
            }
        }
        limbs_ = result;
        normalize();
        return *this;
    }

    cpp_int& operator>>=(int shift) {
        if (shift <= 0 || is_zero()) return *this;
        const std::size_t words = static_cast<std::size_t>(shift / 64);
        const unsigned bits = static_cast<unsigned>(shift & 63);
        std::array<std::uint64_t, kLimbs> result{};
        for (std::size_t target = 0u; target < kLimbs; ++target) {
            const std::size_t source = target + words;
            if (source >= kLimbs) continue;
            result[target] |= limbs_[source] >> bits;
            if (bits != 0u && source + 1u < kLimbs) {
                result[target] |=
                    limbs_[source + 1u] << (64u - bits);
            }
        }
        limbs_ = result;
        normalize();
        return *this;
    }

    cpp_int& operator&=(const cpp_int& other) {
        for (std::size_t i = 0u; i < kLimbs; ++i) {
            limbs_[i] &= other.limbs_[i];
        }
        negative_ = false;
        return *this;
    }

    cpp_int& operator%=(const cpp_int& modulus) {
        const bool was_negative = negative_;
        negative_ = false;
        cpp_int divisor = modulus;
        divisor.negative_ = false;
        if (divisor.is_zero()) return *this;
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

    friend cpp_int operator+(cpp_int left, const cpp_int& right) {
        left += right;
        return left;
    }

    friend cpp_int operator-(cpp_int left, const cpp_int& right) {
        left -= right;
        return left;
    }

    friend cpp_int operator<<(cpp_int value, int shift) {
        value <<= shift;
        return value;
    }

    friend cpp_int operator>>(cpp_int value, int shift) {
        value >>= shift;
        return value;
    }

    friend cpp_int operator&(cpp_int left, const cpp_int& right) {
        left &= right;
        return left;
    }

    friend cpp_int operator%(cpp_int value, const cpp_int& modulus) {
        value %= modulus;
        return value;
    }

    friend bool operator==(const cpp_int& left, const cpp_int& right) {
        return left.negative_ == right.negative_ &&
            left.limbs_ == right.limbs_;
    }

    friend bool operator!=(const cpp_int& left, const cpp_int& right) {
        return !(left == right);
    }

    friend bool operator<(const cpp_int& left, const cpp_int& right) {
        if (left.negative_ != right.negative_) return left.negative_;
        const int comparison = left.compare_magnitude(right);
        return left.negative_ ? comparison > 0 : comparison < 0;
    }

    friend bool operator>(const cpp_int& left, const cpp_int& right) {
        return right < left;
    }

    friend bool operator<=(const cpp_int& left, const cpp_int& right) {
        return !(right < left);
    }

    friend bool operator>=(const cpp_int& left, const cpp_int& right) {
        return !(left < right);
    }

private:
    template <typename T>
    void assign_integral(T value) {
        limbs_.fill(0u);
        negative_ = false;
        if constexpr (std::is_signed_v<T>) {
            if (value < 0) {
                negative_ = true;
                const auto magnitude =
                    static_cast<std::make_unsigned_t<T>>(-(value + 1));
                limbs_[0] =
                    static_cast<std::uint64_t>(magnitude) + 1u;
                return;
            }
        }
        limbs_[0] = static_cast<std::uint64_t>(value);
    }

    void assign_text(std::string text) {
        limbs_.fill(0u);
        negative_ = false;
        if (!text.empty() && text[0] == '-') {
            negative_ = true;
            text.erase(text.begin());
        }
        bool hexadecimal = text.size() >= 2u &&
            text[0] == '0' &&
            (text[1] == 'x' || text[1] == 'X');
        if (hexadecimal) text.erase(0u, 2u);
        const std::uint32_t radix = hexadecimal ? 16u : 10u;
        for (char c : text) {
            const int digit =
                c >= '0' && c <= '9'
                ? c - '0'
                : c >= 'a' && c <= 'f'
                    ? c - 'a' + 10
                    : c >= 'A' && c <= 'F'
                        ? c - 'A' + 10 : -1;
            if (digit < 0 ||
                static_cast<std::uint32_t>(digit) >= radix) {
                limbs_.fill(0u);
                negative_ = false;
                return;
            }
            multiply_small(radix);
            add_small(static_cast<std::uint32_t>(digit));
        }
        normalize();
    }

    void multiply_small(std::uint32_t factor) {
        unsigned __int128 carry = 0u;
        for (std::size_t i = 0u; i < kLimbs; ++i) {
            const unsigned __int128 value =
                static_cast<unsigned __int128>(limbs_[i]) *
                    factor + carry;
            limbs_[i] = static_cast<std::uint64_t>(value);
            carry = value >> 64u;
        }
    }

    void add_small(std::uint32_t addend) {
        std::uint64_t carry = addend;
        for (std::size_t i = 0u; i < kLimbs && carry != 0u; ++i) {
            const std::uint64_t before = limbs_[i];
            limbs_[i] += carry;
            carry = limbs_[i] < before ? 1u : 0u;
        }
    }

    int compare_magnitude(const cpp_int& other) const {
        for (std::size_t i = kLimbs; i-- > 0u;) {
            if (limbs_[i] < other.limbs_[i]) return -1;
            if (limbs_[i] > other.limbs_[i]) return 1;
        }
        return 0;
    }

    void add_magnitude(const cpp_int& other) {
        std::uint64_t carry = 0u;
        for (std::size_t i = 0u; i < kLimbs; ++i) {
            const std::uint64_t before = limbs_[i];
            const std::uint64_t addend =
                other.limbs_[i] + carry;
            const bool addend_overflow =
                addend < other.limbs_[i];
            limbs_[i] = before + addend;
            carry = static_cast<std::uint64_t>(
                addend_overflow || limbs_[i] < before);
        }
    }

    void subtract_magnitude(const cpp_int& other) {
        std::uint64_t borrow = 0u;
        for (std::size_t i = 0u; i < kLimbs; ++i) {
            const std::uint64_t before = limbs_[i];
            const std::uint64_t subtrahend =
                other.limbs_[i] + borrow;
            const bool overflow =
                subtrahend < other.limbs_[i];
            limbs_[i] = before - subtrahend;
            borrow = static_cast<std::uint64_t>(
                overflow || before < subtrahend);
        }
    }

    void normalize() {
        if (is_zero()) negative_ = false;
    }

    std::array<std::uint64_t, kLimbs> limbs_{};
    bool negative_ = false;
};

constexpr std::uint32_t kThreadgroupSize = 128u;
constexpr std::uint64_t kDefaultBatch = 1ull << 20u;
constexpr std::uint32_t kHitCapacity = 4096u;
constexpr std::uint32_t kRangeSource = 0u;
constexpr std::uint32_t kMaskSource = 1u;
constexpr std::uint32_t kListSource = 2u;
constexpr char kOrderHex[] =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
constexpr char kFieldHex[] =
    "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";

enum class SignatureModel : std::uint32_t {
    Ecdsa = 1u,
    Bip340 = 2u,
};

enum class DomainKind {
    Range,
    Mask,
    CandidateList,
};

struct NonceHit {
    std::array<std::uint8_t, 32> nonce{};
    std::uint32_t record_index = 0u;
    std::uint32_t reserved = 0u;
};

static_assert(sizeof(NonceHit) == 40u,
              "Nonce host/Metal hit layout mismatch");

struct SignatureRecord {
    SignatureModel model = SignatureModel::Ecdsa;
    std::array<std::uint8_t, 32> r_bytes{};
    std::array<std::uint8_t, 32> s_bytes{};
    std::array<std::uint8_t, 32> message{};
    cpp_int r = 0;
    cpp_int s = 0;
    cpp_int z = 0;
    std::vector<std::uint8_t> public_key;
    std::array<std::uint8_t, 33> canonical_public{};
    std::string source;
    bool solved = false;
};

struct SearchDomain {
    DomainKind kind = DomainKind::Range;
    cpp_int range_start = 1;
    cpp_int range_end = 0;
    modeinfra::U256 size{};
    std::array<std::uint8_t, 32> mask_base{};
    std::vector<std::uint32_t> unknown_bits;
    std::vector<std::array<std::uint8_t, 32>> candidates;
};

struct Relation {
    bool set = false;
    cpp_int multiplier = 1;
    cpp_int addend = 0;
    std::string label;
};

struct Options {
    bool model_set = false;
    SignatureModel model = SignatureModel::Ecdsa;
    std::vector<std::string> inputs;
    std::vector<std::string> targets;
    std::vector<int> devices{0};
    std::string start = "1";
    std::string end = "0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
    std::string mask;
    std::string candidate_file;
    Relation relation;
    bool random = false;
    std::uint64_t random_seed = 0x4d4554414c4e4f4eull;
    std::uint64_t batch = kDefaultBatch;
    std::string output_path;
    bool save = false;
    bool silent = false;
};

struct HostPrecompute {
    std::vector<secp256k1_ge_storage> entries;
    std::size_t pitch = 0u;
    unsigned int windows = 0u;
    unsigned int bits = 12u;
};

const cpp_int& curve_order() {
    static const cpp_int value("0x" + std::string(kOrderHex));
    return value;
}

const cpp_int& field_prime() {
    static const cpp_int value("0x" + std::string(kFieldHex));
    return value;
}

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

std::vector<std::string> split(const std::string& value, char separator) {
    std::vector<std::string> result;
    std::stringstream stream(value);
    std::string token;
    while (std::getline(stream, token, separator)) {
        result.push_back(trim_copy(token));
    }
    return result;
}

int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

bool decode_hex_exact(const std::string& raw,
                      std::size_t expected,
                      std::vector<std::uint8_t>& out) {
    std::string text = trim_copy(raw);
    if (text.size() > 2u && text[0] == '0' &&
        (text[1] == 'x' || text[1] == 'X')) {
        text.erase(0u, 2u);
    }
    if (text.size() != expected * 2u) return false;
    out.assign(expected, 0u);
    for (std::size_t i = 0u; i < expected; ++i) {
        const int high = hex_digit(text[i * 2u]);
        const int low = hex_digit(text[i * 2u + 1u]);
        if (high < 0 || low < 0) return false;
        out[i] = static_cast<std::uint8_t>((high << 4) | low);
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

cpp_int bytes_to_int(const std::uint8_t* data, std::size_t size) {
    cpp_int value = 0;
    for (std::size_t i = 0u; i < size; ++i) {
        value <<= 8;
        value += data[i];
    }
    return value;
}

std::array<std::uint8_t, 32> int_to_bytes(cpp_int value) {
    std::array<std::uint8_t, 32> result{};
    for (int i = 31; i >= 0; --i) {
        result[static_cast<std::size_t>(i)] =
            static_cast<std::uint8_t>((value & 0xff).convert_to<unsigned>());
        value >>= 8;
    }
    return result;
}

cpp_int u256_to_int(const modeinfra::U256& value) {
    cpp_int result = 0;
    for (int i = 3; i >= 0; --i) {
        result <<= 64;
        result += value.limbs[static_cast<std::size_t>(i)];
    }
    return result;
}

bool int_to_u256(cpp_int value, modeinfra::U256& out) {
    if (value < 0 || value >= (cpp_int(1) << 256)) return false;
    const cpp_int mask = (cpp_int(1) << 64) - 1;
    for (std::size_t i = 0u; i < 4u; ++i) {
        out.limbs[i] =
            static_cast<std::uint64_t>((value & mask).convert_to<std::uint64_t>());
        value >>= 64;
    }
    return value == 0;
}

cpp_int mod(cpp_int value, const cpp_int& modulus) {
    value %= modulus;
    if (value < 0) value += modulus;
    return value;
}

cpp_int add_mod(cpp_int left,
                cpp_int right,
                const cpp_int& modulus) {
    left = mod(left, modulus);
    right = mod(right, modulus);
    cpp_int result = left + right;
    if (result >= modulus) result -= modulus;
    return result;
}

cpp_int multiply_mod(cpp_int left,
                     cpp_int right,
                     const cpp_int& modulus) {
    left = mod(left, modulus);
    right = mod(right, modulus);
    cpp_int result = 0;
    const int bits = right.bit_length();
    for (int bit = 0; bit < bits; ++bit) {
        if (right.bit(static_cast<std::size_t>(bit))) {
            result = add_mod(result, left, modulus);
        }
        left = add_mod(left, left, modulus);
    }
    return result;
}

cpp_int power_mod(cpp_int base,
                  cpp_int exponent,
                  const cpp_int& modulus) {
    cpp_int result = 1;
    base = mod(base, modulus);
    while (!exponent.is_zero()) {
        if (exponent.bit(0u)) {
            result = multiply_mod(result, base, modulus);
        }
        exponent >>= 1;
        if (!exponent.is_zero()) {
            base = multiply_mod(base, base, modulus);
        }
    }
    return result;
}

cpp_int inverse_mod(const cpp_int& value, const cpp_int& modulus) {
    const cpp_int normalized = mod(value, modulus);
    if (normalized == 0) return 0;
    return power_mod(normalized, modulus - 2, modulus);
}

bool parse_integer(std::string text, cpp_int& out) {
    text = trim_copy(text);
    if (text.empty()) return false;
    const bool negative = text[0] == '-';
    const std::size_t first = negative ? 1u : 0u;
    if (first == text.size()) return false;
    if (text.size() >= first + 2u && text[first] == '0' &&
        (text[first + 1u] == 'x' || text[first + 1u] == 'X')) {
        const std::string digits = text.substr(first + 2u);
        if (digits.empty() || digits.size() > 80u ||
            !std::all_of(
                digits.begin(), digits.end(),
                [](char c) { return hex_digit(c) >= 0; })) {
            return false;
        }
        out = cpp_int(
            (negative ? "-0x" : "0x") + digits);
        return true;
    }
    const std::string digits = text.substr(first);
    if (digits.size() == 64u &&
        std::all_of(
            digits.begin(), digits.end(),
            [](char c) { return hex_digit(c) >= 0; })) {
        out = cpp_int(
            (negative ? "-0x" : "0x") + digits);
        return true;
    }
    if (digits.size() > 96u ||
        !std::all_of(
            digits.begin(), digits.end(),
            [](char c) {
                return c >= '0' && c <= '9';
            })) {
        return false;
    }
    out = cpp_int(text);
    return true;
}

bool parse_u64(const std::string& text, std::uint64_t& out) {
    cpp_int value;
    if (!parse_integer(text, value) || value < 0 ||
        value > std::numeric_limits<std::uint64_t>::max()) {
        return false;
    }
    out = value.convert_to<std::uint64_t>();
    return true;
}

bool parse_model(const std::string& raw, SignatureModel& out) {
    const std::string value = lower_copy(raw);
    if (value == "ecdsa") {
        out = SignatureModel::Ecdsa;
        return true;
    }
    if (value == "bip340" || value == "schnorr") {
        out = SignatureModel::Bip340;
        return true;
    }
    return false;
}

const char* model_name(SignatureModel model) {
    return model == SignatureModel::Ecdsa ? "ECDSA" : "BIP340";
}

bool parse_device_list(const std::string& raw,
                       std::vector<int>& devices,
                       std::string& error) {
    std::set<int> unique;
    for (const std::string& part : split(raw, ',')) {
        cpp_int parsed;
        if (!parse_integer(part, parsed) || parsed < 0 ||
            parsed > std::numeric_limits<int>::max()) {
            error = "-device expects non-negative comma-separated indexes";
            return false;
        }
        unique.insert(parsed.convert_to<int>());
    }
    if (unique.empty()) {
        error = "-device selected no Metal devices";
        return false;
    }
    devices.assign(unique.begin(), unique.end());
    return true;
}

bool parse_relation(const std::string& raw,
                    Relation& relation,
                    std::string& error) {
    const std::vector<std::string> values = split(lower_copy(raw), ':');
    if (values.empty()) return false;
    relation = Relation{};
    relation.set = true;
    relation.label = raw;
    if (values[0] == "same" && values.size() == 1u) {
        return true;
    }
    if (values[0] == "add" && values.size() == 2u &&
        parse_integer(values[1], relation.addend)) {
        return true;
    }
    if (values[0] == "mul" && values.size() == 2u &&
        parse_integer(values[1], relation.multiplier)) {
        return true;
    }
    if (values[0] == "affine" && values.size() == 3u &&
        parse_integer(values[1], relation.multiplier) &&
        parse_integer(values[2], relation.addend)) {
        return true;
    }
    error = "-nonce-relation expects same, add:B, mul:A, or affine:A:B";
    return false;
}

bool parse_options(int argc,
                   char** argv,
                   Options& options,
                   std::string& error) {
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i] == nullptr ? "" : argv[i];
        auto value = [&](const char* name) -> const char* {
            if (i + 1 >= argc) {
                error = std::string(name) + " requires a value";
                return nullptr;
            }
            return argv[++i];
        };
        if (arg == "-nonce") {
            continue;
        } else if (arg == "-nonce-model") {
            const char* raw = value("-nonce-model");
            if (raw == nullptr || !parse_model(raw, options.model)) {
                if (error.empty()) error =
                    "-nonce-model expects ecdsa or bip340";
                return false;
            }
            options.model_set = true;
        } else if (arg == "-i") {
            const char* raw = value("-i");
            if (raw == nullptr) return false;
            options.inputs.emplace_back(raw);
        } else if (arg == "-target") {
            const char* raw = value("-target");
            if (raw == nullptr) return false;
            options.targets.emplace_back(raw);
        } else if (arg == "-start") {
            const char* raw = value("-start");
            if (raw == nullptr) return false;
            options.start = raw;
        } else if (arg == "-end") {
            const char* raw = value("-end");
            if (raw == nullptr) return false;
            options.end = raw;
        } else if (arg == "-mask") {
            const char* raw = value("-mask");
            if (raw == nullptr) return false;
            options.mask = raw;
        } else if (arg == "-nonce-candidates" ||
                   arg == "-nonce-lattice") {
            const char* raw = value(arg.c_str());
            if (raw == nullptr) return false;
            options.candidate_file = raw;
        } else if (arg == "-nonce-relation") {
            const char* raw = value("-nonce-relation");
            if (raw == nullptr ||
                !parse_relation(raw, options.relation, error)) {
                return false;
            }
        } else if (arg == "-random") {
            options.random = true;
        } else if (arg == "-nonce-seed") {
            const char* raw = value("-nonce-seed");
            if (raw == nullptr || !parse_u64(raw, options.random_seed)) {
                if (error.empty()) error =
                    "-nonce-seed expects an unsigned 64-bit integer";
                return false;
            }
        } else if (arg == "-n") {
            const char* raw = value("-n");
            if (raw == nullptr || !parse_u64(raw, options.batch) ||
                options.batch == 0u ||
                options.batch > std::numeric_limits<std::uint32_t>::max()) {
                if (error.empty()) error =
                    "-n expects 1..4294967295";
                return false;
            }
        } else if (arg == "-device") {
            const char* raw = value("-device");
            if (raw == nullptr ||
                !parse_device_list(raw, options.devices, error)) {
                return false;
            }
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
        } else if (!arg.empty() && arg[0] != '-') {
            options.inputs.push_back(arg);
        } else {
            error = "unknown -nonce parameter '" + arg + "'";
            return false;
        }
    }
    if (options.inputs.empty()) {
        error = "-nonce requires at least one -i RECORD|FILE";
        return false;
    }
    const unsigned domain_selectors =
        (!options.mask.empty() ? 1u : 0u) +
        (!options.candidate_file.empty() ? 1u : 0u);
    if (domain_selectors > 1u) {
        error = "-mask and -nonce-candidates/-nonce-lattice are mutually exclusive";
        return false;
    }
    if (options.random &&
        (!options.mask.empty() || !options.candidate_file.empty())) {
        error = "-random currently requires a bounded -start/-end range";
        return false;
    }
    return true;
}

bool parse_public_key(const std::vector<std::uint8_t>& bytes,
                      secp256k1_ge& point) {
    if (bytes.size() == 33u &&
        (bytes[0] == 0x02u || bytes[0] == 0x03u)) {
        secp256k1_fe x{};
        return secp256k1_fe_set_b32(&x, bytes.data() + 1u) != 0 &&
            secp256k1_ge_set_xo_var(
                &point, &x, bytes[0] == 0x03u) != 0;
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

bool canonicalize_target(const std::string& raw,
                         SignatureModel model,
                         std::vector<std::uint8_t>& original,
                         std::array<std::uint8_t, 33>& canonical,
                         std::string& error) {
    if (model == SignatureModel::Bip340) {
        std::vector<std::uint8_t> x;
        if (decode_hex_exact(raw, 32u, x)) {
            secp256k1_fe field_x{};
            secp256k1_ge point{};
            if (!secp256k1_fe_set_b32(&field_x, x.data()) ||
                !secp256k1_ge_set_xo_var(&point, &field_x, 0)) {
                error = "BIP340 target x is not a secp256k1 point";
                return false;
            }
            original = x;
            canonical[0] = 0x02u;
            std::copy(x.begin(), x.end(), canonical.begin() + 1u);
            return true;
        }
    }
    std::vector<std::uint8_t> bytes;
    if (!decode_hex_exact(raw, 33u, bytes) &&
        !decode_hex_exact(raw, 65u, bytes)) {
        error = model == SignatureModel::Bip340
            ? "BIP340 target must be 32-byte x-only or 33/65-byte public key"
            : "ECDSA target must be a 33/65-byte secp256k1 public key";
        return false;
    }
    secp256k1_ge point{};
    if (!parse_public_key(bytes, point)) {
        error = "target is not a valid secp256k1 public key";
        return false;
    }
    secp256k1_fe_normalize_var(&point.x);
    secp256k1_fe_normalize_var(&point.y);
    canonical[0] = model == SignatureModel::Bip340
        ? 0x02u
        : static_cast<std::uint8_t>(
            0x02u + secp256k1_fe_is_odd(&point.y));
    secp256k1_fe_get_b32(canonical.data() + 1u, &point.x);
    if (model == SignatureModel::Bip340) {
        secp256k1_fe x{};
        secp256k1_ge even{};
        if (!secp256k1_fe_set_b32(&x, canonical.data() + 1u) ||
            !secp256k1_ge_set_xo_var(&even, &x, 0)) {
            error = "BIP340 target x has no even-y secp256k1 point";
            return false;
        }
    }
    original = bytes;
    return true;
}

bool parse_signature_token(const std::string& raw,
                           const Options& options,
                           const std::string& source,
                           SignatureRecord& record,
                           std::string& target_text,
                           std::string& error) {
    std::string token = trim_copy(raw);
    if (token.empty() || token[0] == '#') return false;
    const std::size_t comment = token.find('#');
    if (comment != std::string::npos) token.erase(comment);
    token = trim_copy(token.substr(0u, token.find_first_of(" \t")));
    std::vector<std::string> values = split(token, ':');
    if (values.empty()) return false;

    SignatureModel model = options.model;
    if (parse_model(values[0], model)) {
        values.erase(values.begin());
    } else if (!options.model_set) {
        error = source +
            ": record needs ecdsa: or bip340: prefix when -nonce-model is absent";
        return false;
    }
    record = SignatureRecord{};
    record.model = model;
    record.source = source;
    std::vector<std::uint8_t> bytes;
    if (model == SignatureModel::Ecdsa) {
        if (values.size() != 3u && values.size() != 4u) {
            error = source +
                ": ECDSA record expects R:S:Z[:PUBKEY]";
            return false;
        }
        if (!decode_hex_exact(values[0], 32u, bytes)) {
            error = source + ": ECDSA r must be 32-byte hex";
            return false;
        }
        std::copy(bytes.begin(), bytes.end(), record.r_bytes.begin());
        if (!decode_hex_exact(values[1], 32u, bytes)) {
            error = source + ": ECDSA s must be 32-byte hex";
            return false;
        }
        std::copy(bytes.begin(), bytes.end(), record.s_bytes.begin());
        if (!decode_hex_exact(values[2], 32u, bytes)) {
            error = source + ": ECDSA z must be 32-byte hex";
            return false;
        }
        std::copy(bytes.begin(), bytes.end(), record.message.begin());
        if (values.size() == 4u) target_text = values[3];
    } else {
        if (values.size() != 2u && values.size() != 3u) {
            error = source +
                ": BIP340 record expects SIGNATURE64:MESSAGE32[:PUBKEY_X]";
            return false;
        }
        if (!decode_hex_exact(values[0], 64u, bytes)) {
            error = source + ": BIP340 signature must be 64-byte hex";
            return false;
        }
        std::copy(bytes.begin(), bytes.begin() + 32u,
                  record.r_bytes.begin());
        std::copy(bytes.begin() + 32u, bytes.end(),
                  record.s_bytes.begin());
        if (!decode_hex_exact(values[1], 32u, bytes)) {
            error = source + ": BIP340 message must be 32-byte hex";
            return false;
        }
        std::copy(bytes.begin(), bytes.end(), record.message.begin());
        if (values.size() == 3u) target_text = values[2];
    }
    record.r = bytes_to_int(record.r_bytes.data(), 32u);
    record.s = bytes_to_int(record.s_bytes.data(), 32u);
    record.z = bytes_to_int(record.message.data(), 32u);
    if (model == SignatureModel::Ecdsa) {
        if (record.r <= 0 || record.r >= curve_order() ||
            record.s <= 0 || record.s >= curve_order()) {
            error = source + ": ECDSA r/s must be in 1..n-1";
            return false;
        }
    } else if (record.r < 0 || record.r >= field_prime() ||
               record.s < 0 || record.s >= curve_order()) {
        error = source + ": BIP340 r must be in 0..p-1 and s in 0..n-1";
        return false;
    }
    return true;
}

bool load_target_values(const Options& options,
                        std::vector<std::string>& targets,
                        std::string& error) {
    for (const std::string& value : options.targets) {
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
                targets.push_back(
                    line.substr(0u, line.find_first_of(" \t#")));
            }
        } else {
            targets.push_back(value);
        }
    }
    return true;
}

bool load_records(const Options& options,
                  std::vector<SignatureRecord>& records,
                  std::string& error) {
    std::vector<std::pair<SignatureRecord, std::string>> pending;
    for (const std::string& input : options.inputs) {
        std::error_code ec;
        if (std::filesystem::is_regular_file(input, ec) && !ec) {
            std::ifstream file(input);
            if (!file) {
                error = "cannot open nonce input file '" + input + "'";
                return false;
            }
            std::string line;
            std::size_t line_no = 0u;
            while (std::getline(file, line)) {
                ++line_no;
                line = trim_copy(line);
                if (line.empty() || line[0] == '#') continue;
                SignatureRecord record;
                std::string target;
                if (!parse_signature_token(
                        line, options,
                        input + ":" + std::to_string(line_no),
                        record, target, error)) {
                    return false;
                }
                pending.emplace_back(std::move(record), std::move(target));
            }
        } else {
            SignatureRecord record;
            std::string target;
            if (!parse_signature_token(
                    input, options, "command line",
                    record, target, error)) {
                return false;
            }
            pending.emplace_back(std::move(record), std::move(target));
        }
    }
    std::vector<std::string> targets;
    if (!load_target_values(options, targets, error)) return false;
    for (std::size_t i = 0u; i < pending.size(); ++i) {
        SignatureRecord& record = pending[i].first;
        std::string target = pending[i].second;
        if (target.empty()) {
            if (targets.size() == 1u) target = targets.front();
            else if (targets.size() == pending.size()) target = targets[i];
            else {
                error = record.source +
                    ": target missing; use one shared -target, one per record, or include it in the record";
                return false;
            }
        }
        if (!canonicalize_target(
                target, record.model, record.public_key,
                record.canonical_public, error)) {
            error = record.source + ": " + error;
            return false;
        }
        records.push_back(std::move(record));
    }
    if (records.empty()) {
        error = "no nonce signature records were loaded";
        return false;
    }
    return true;
}

bool parse_mask(const std::string& raw,
                SearchDomain& domain,
                std::string& error) {
    const std::string mask = trim_copy(raw);
    domain.mask_base.fill(0u);
    domain.unknown_bits.clear();
    if (mask.size() == 64u) {
        for (std::size_t nibble = 0u; nibble < 64u; ++nibble) {
            const char c = mask[nibble];
            const std::uint32_t low_bit =
                static_cast<std::uint32_t>((63u - nibble) * 4u);
            if (c == '?') {
                for (std::uint32_t bit = 0u; bit < 4u; ++bit) {
                    domain.unknown_bits.push_back(low_bit + bit);
                }
                continue;
            }
            const int value = hex_digit(c);
            if (value < 0) {
                error = "-mask must be 64 hex/? nibbles or 256 binary 0/1/? bits";
                return false;
            }
            domain.mask_base[nibble / 2u] |=
                static_cast<std::uint8_t>(
                    value << (nibble % 2u == 0u ? 4u : 0u));
        }
    } else if (mask.size() == 256u) {
        for (std::size_t index = 0u; index < 256u; ++index) {
            const char c = mask[index];
            const std::uint32_t bit =
                static_cast<std::uint32_t>(255u - index);
            if (c == '?') {
                domain.unknown_bits.push_back(bit);
            } else if (c == '1') {
                domain.mask_base[index / 8u] |=
                    static_cast<std::uint8_t>(
                        1u << (7u - (index & 7u)));
            } else if (c != '0') {
                error = "-mask must be 64 hex/? nibbles or 256 binary 0/1/? bits";
                return false;
            }
        }
    } else {
        error = "-mask must contain exactly 64 nibbles or 256 bits";
        return false;
    }
    if (domain.unknown_bits.size() > 255u) {
        error = "-mask with 256 unknown bits is represented by -start 1 -end n";
        return false;
    }
    std::sort(domain.unknown_bits.begin(), domain.unknown_bits.end());
    const cpp_int size = cpp_int(1) << domain.unknown_bits.size();
    if (!int_to_u256(size, domain.size)) {
        error = "mask domain exceeds checked U256";
        return false;
    }
    domain.kind = DomainKind::Mask;
    return true;
}

bool load_candidate_file(const std::string& path,
                         SearchDomain& domain,
                         std::string& error) {
    std::ifstream file(path);
    if (!file) {
        error = "cannot open nonce candidate file '" + path + "'";
        return false;
    }
    std::unordered_set<std::string> seen;
    std::string line;
    std::size_t line_no = 0u;
    while (std::getline(file, line)) {
        ++line_no;
        line = trim_copy(line);
        if (line.empty() || line[0] == '#') continue;
        line = line.substr(0u, line.find_first_of(" \t,#"));
        cpp_int value;
        if (!parse_integer(line, value) ||
            value <= 0 || value >= curve_order()) {
            error = path + ":" + std::to_string(line_no) +
                ": nonce candidate must be in 1..n-1";
            return false;
        }
        const auto bytes = int_to_bytes(value);
        const std::string normalized =
            hex_lower(bytes.data(), bytes.size());
        if (seen.insert(normalized).second) {
            domain.candidates.push_back(bytes);
        }
    }
    if (domain.candidates.empty()) {
        error = "nonce candidate file is empty";
        return false;
    }
    domain.kind = DomainKind::CandidateList;
    if (!int_to_u256(domain.candidates.size(), domain.size)) {
        error = "nonce candidate count exceeds checked U256";
        return false;
    }
    return true;
}

bool prepare_domain(const Options& options,
                    SearchDomain& domain,
                    std::string& error) {
    if (!options.candidate_file.empty()) {
        return load_candidate_file(options.candidate_file, domain, error);
    }
    if (!options.mask.empty()) {
        return parse_mask(options.mask, domain, error);
    }
    if (!parse_integer(options.start, domain.range_start) ||
        !parse_integer(options.end, domain.range_end) ||
        domain.range_start <= 0 ||
        domain.range_end <= domain.range_start ||
        domain.range_end > curve_order()) {
        error = "-start/-end must define a nonce range [START,END) inside 1..n";
        return false;
    }
    domain.kind = DomainKind::Range;
    if (!int_to_u256(domain.range_end - domain.range_start, domain.size)) {
        error = "nonce range width exceeds checked U256";
        return false;
    }
    return true;
}

bool build_host_precompute(HostPrecompute& result, std::string& error) {
    return build_secp256k1_precompute_table_host(
        result.bits, result.entries, result.pitch, result.windows, error);
}

bool derive_public(const std::array<std::uint8_t, 32>& scalar_bytes,
                   const HostPrecompute& precompute,
                   std::array<std::uint8_t, 65>& public_key) {
    secp256k1_scalar scalar{};
    int overflow = 0;
    secp256k1_scalar_set_b32(&scalar, scalar_bytes.data(), &overflow);
    if (overflow || secp256k1_scalar_is_zero(&scalar)) return false;
    secp256k1_gej jacobian{};
    secp256k1_ecmult_big(
        &jacobian, &scalar, precompute.entries.data(),
        precompute.pitch, static_cast<int>(precompute.windows),
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
                    const std::array<std::uint8_t, 33>& expected,
                    bool require_even) {
    if (require_even && (public_key[64] & 1u) != 0u) return false;
    const std::uint8_t prefix =
        static_cast<std::uint8_t>(0x02u + (public_key[64] & 1u));
    return (require_even || prefix == expected[0]) &&
        std::equal(public_key.begin() + 1u,
                   public_key.begin() + 33u,
                   expected.begin() + 1u);
}

cpp_int bip340_challenge(const SignatureRecord& record) {
    static const std::string tag = "BIP0340/challenge";
    std::array<std::uint8_t, 32> tag_hash{};
    sha256(reinterpret_cast<std::uint8_t*>(
               const_cast<char*>(tag.data())),
           tag.size(), tag_hash.data());
    std::array<std::uint8_t, 160> payload{};
    std::copy(tag_hash.begin(), tag_hash.end(), payload.begin());
    std::copy(tag_hash.begin(), tag_hash.end(), payload.begin() + 32u);
    std::copy(record.r_bytes.begin(), record.r_bytes.end(),
              payload.begin() + 64u);
    std::copy(record.canonical_public.begin() + 1u,
              record.canonical_public.end(),
              payload.begin() + 96u);
    std::copy(record.message.begin(), record.message.end(),
              payload.begin() + 128u);
    std::array<std::uint8_t, 32> digest{};
    sha256(payload.data(), payload.size(), digest.data());
    return bytes_to_int(digest.data(), digest.size()) % curve_order();
}

bool nonce_matches_record(const SignatureRecord& record,
                          const cpp_int& nonce,
                          const HostPrecompute& precompute) {
    if (nonce <= 0 || nonce >= curve_order()) return false;
    std::array<std::uint8_t, 65> point{};
    if (!derive_public(int_to_bytes(nonce), precompute, point)) return false;
    const cpp_int x = bytes_to_int(point.data() + 1u, 32u);
    if (record.model == SignatureModel::Ecdsa) {
        return x % curve_order() == record.r;
    }
    return x == record.r && (point[64] & 1u) == 0u;
}

bool verify_ecdsa_equation(const SignatureRecord& record,
                           const cpp_int& nonce,
                           const cpp_int& private_key) {
    return multiply_mod(record.s, nonce, curve_order()) ==
        add_mod(
            record.z,
            multiply_mod(
                record.r, private_key, curve_order()),
            curve_order());
}

bool recover_private(const SignatureRecord& record,
                     const cpp_int& nonce,
                     const HostPrecompute& precompute,
                     cpp_int& private_key) {
    if (!nonce_matches_record(record, nonce, precompute)) return false;
    if (record.model == SignatureModel::Ecdsa) {
        private_key = multiply_mod(
            mod(
                multiply_mod(
                    record.s, nonce, curve_order()) -
                    record.z,
                curve_order()),
            inverse_mod(record.r, curve_order()),
            curve_order());
        if (private_key == 0 ||
            !verify_ecdsa_equation(record, nonce, private_key)) {
            return false;
        }
    } else {
        const cpp_int challenge = bip340_challenge(record);
        if (challenge == 0) return false;
        private_key = multiply_mod(
            mod(record.s - nonce, curve_order()),
            inverse_mod(challenge, curve_order()),
            curve_order());
        if (private_key == 0 ||
            add_mod(
                nonce,
                multiply_mod(
                    challenge, private_key, curve_order()),
                curve_order()) != record.s) {
            return false;
        }
    }
    std::array<std::uint8_t, 65> public_key{};
    if (!derive_public(
            int_to_bytes(private_key), precompute, public_key)) {
        return false;
    }
    return public_matches(
        public_key, record.canonical_public,
        record.model == SignatureModel::Bip340);
}

bool solve_relation(const SignatureRecord& first,
                    const SignatureRecord& second,
                    const Relation& relation,
                    const HostPrecompute& precompute,
                    cpp_int& private_key,
                    cpp_int& first_nonce,
                    cpp_int& second_nonce) {
    if (first.model != SignatureModel::Ecdsa ||
        second.model != SignatureModel::Ecdsa) {
        return false;
    }
    const cpp_int a = mod(relation.multiplier, curve_order());
    const cpp_int b = mod(relation.addend, curve_order());
    const cpp_int denominator = mod(
        multiply_mod(second.r, first.s, curve_order()) -
            multiply_mod(
                multiply_mod(
                    first.r, second.s, curve_order()),
                a, curve_order()),
        curve_order());
    if (denominator == 0) return false;
    const cpp_int numerator = mod(
        add_mod(
            multiply_mod(
                second.r, first.z, curve_order()),
            multiply_mod(
                multiply_mod(
                    first.r, second.s, curve_order()),
                b, curve_order()),
            curve_order()) -
            multiply_mod(
                first.r, second.z, curve_order()),
        curve_order());
    first_nonce = multiply_mod(
        numerator,
        inverse_mod(denominator, curve_order()),
        curve_order());
    second_nonce = add_mod(
        multiply_mod(a, first_nonce, curve_order()),
        b, curve_order());
    if (first_nonce == 0 || second_nonce == 0 ||
        !recover_private(first, first_nonce, precompute, private_key) ||
        !nonce_matches_record(second, second_nonce, precompute) ||
        !verify_ecdsa_equation(second, second_nonce, private_key)) {
        return false;
    }
    std::array<std::uint8_t, 65> public_key{};
    return derive_public(
               int_to_bytes(private_key), precompute, public_key) &&
        public_matches(public_key, second.canonical_public, false);
}

std::string format_result(const SignatureRecord& record,
                          const cpp_int& nonce,
                          const cpp_int& private_key,
                          const std::string& detail = {}) {
    const auto nonce_bytes = int_to_bytes(nonce);
    const auto private_bytes = int_to_bytes(private_key);
    std::string line = "[+] NONCE:" +
        std::string(model_name(record.model)) +
        ":SOURCE:" + record.source +
        ":NONCE:" + hex_lower(nonce_bytes.data(), nonce_bytes.size()) +
        ":PRIVATE:" +
        hex_lower(private_bytes.data(), private_bytes.size()) +
        ":PUBLIC:" +
        hex_lower(record.canonical_public.data(),
                  record.canonical_public.size());
    if (!detail.empty()) line += ":" + detail;
    return line;
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

bool split_domain(const modeinfra::U256& size,
                  std::uint64_t shard,
                  std::uint64_t shard_count,
                  modeinfra::U256& begin,
                  modeinfra::U256& count,
                  std::string& error) {
    modeinfra::U256 quotient;
    std::uint64_t remainder = 0u;
    if (shard_count == 0u || shard >= shard_count ||
        !modeinfra::divide(size, shard_count, quotient, remainder)) {
        error = "invalid nonce device shard";
        return false;
    }
    modeinfra::U256 scaled;
    modeinfra::U256 extra =
        modeinfra::U256::from_u64(std::min(shard, remainder));
    if (!modeinfra::multiply_checked(quotient, shard, scaled) ||
        !modeinfra::add_checked(scaled, extra, begin)) {
        error = "nonce shard start overflows U256";
        return false;
    }
    if (!modeinfra::add_checked(
            quotient,
            modeinfra::U256::from_u64(shard < remainder ? 1u : 0u),
            count)) {
        error = "nonce shard size overflows U256";
        return false;
    }
    return true;
}

std::uint64_t splitmix64(std::uint64_t& state) {
    std::uint64_t value = (state += 0x9e3779b97f4a7c15ull);
    value = (value ^ (value >> 30u)) * 0xbf58476d1ce4e5b9ull;
    value = (value ^ (value >> 27u)) * 0x94d049bb133111ebull;
    return value ^ (value >> 31u);
}

cpp_int gcd_int(cpp_int left, cpp_int right) {
    while (right != 0) {
        cpp_int remainder = left % right;
        left = right;
        right = remainder;
    }
    return left < 0 ? -left : left;
}

struct RandomPermutation {
    cpp_int multiplier = 1;
    cpp_int addend = 0;
};

RandomPermutation make_random_permutation(const cpp_int& size,
                                          std::uint64_t seed) {
    std::uint64_t state = seed;
    cpp_int multiplier = splitmix64(state);
    multiplier = mod(multiplier, size);
    if (multiplier == 0) multiplier = 1;
    while (gcd_int(multiplier, size) != 1) {
        multiplier += 1;
        if (multiplier >= size) multiplier = 1;
    }
    return {multiplier, mod(cpp_int(splitmix64(state)), size)};
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
                     const std::string& operation,
                     std::string& error) {
    return metal_ok(
        metalMalloc(&pointer, std::max<std::size_t>(bytes, 1u)),
        operation, error);
}

struct DeviceBuffers {
    std::uint8_t* base_nonce = nullptr;
    std::uint8_t* window_ordinal = nullptr;
    std::uint32_t* unknown_bits = nullptr;
    std::uint8_t* candidate_list = nullptr;
    std::uint8_t* target_x1 = nullptr;
    std::uint8_t* target_x2 = nullptr;
    secp256k1_ge_storage* precompute = nullptr;
    NonceHit* hits = nullptr;
    std::uint32_t* hit_count = nullptr;
    std::uint64_t allocated = 0u;

    void release() {
        if (base_nonce) metalFree(base_nonce);
        if (window_ordinal) metalFree(window_ordinal);
        if (unknown_bits) metalFree(unknown_bits);
        if (candidate_list) metalFree(candidate_list);
        if (target_x1) metalFree(target_x1);
        if (target_x2) metalFree(target_x2);
        if (precompute) metalFree(precompute);
        if (hits) metalFree(hits);
        if (hit_count) metalFree(hit_count);
        base_nonce = nullptr;
        window_ordinal = nullptr;
        unknown_bits = nullptr;
        candidate_list = nullptr;
        target_x1 = nullptr;
        target_x2 = nullptr;
        precompute = nullptr;
        hits = nullptr;
        hit_count = nullptr;
        allocated = 0u;
    }

    ~DeviceBuffers() {
        release();
    }
};

void ecdsa_x_targets(const SignatureRecord& record,
                     std::array<std::uint8_t, 32>& first,
                     std::array<std::uint8_t, 32>& second,
                     std::uint32_t& second_valid) {
    first = record.r_bytes;
    const cpp_int alternate = record.r + curve_order();
    second_valid = alternate < field_prime() ? 1u : 0u;
    second = second_valid ? int_to_bytes(alternate) : first;
}

bool prepare_buffers(const SignatureRecord& record,
                     const SearchDomain& domain,
                     const HostPrecompute& precompute,
                     std::uint64_t batch,
                     DeviceBuffers& buffers,
                     std::string& error) {
    const std::size_t unknown_bytes =
        std::max<std::size_t>(
            sizeof(std::uint32_t),
            domain.unknown_bits.size() * sizeof(std::uint32_t));
    const std::size_t list_bytes =
        static_cast<std::size_t>(batch) * 32u;
    const std::size_t precompute_bytes =
        precompute.entries.size() * sizeof(secp256k1_ge_storage);
    if (!allocate_device(
            buffers.base_nonce, 32u,
            "allocate nonce base", error) ||
        !allocate_device(
            buffers.window_ordinal, 32u,
            "allocate nonce window ordinal", error) ||
        !allocate_device(
            buffers.unknown_bits, unknown_bytes,
            "allocate nonce mask bits", error) ||
        !allocate_device(
            buffers.candidate_list, list_bytes,
            "allocate nonce candidate batch", error) ||
        !allocate_device(
            buffers.target_x1, 32u,
            "allocate nonce target x1", error) ||
        !allocate_device(
            buffers.target_x2, 32u,
            "allocate nonce target x2", error) ||
        !allocate_device(
            buffers.precompute, precompute_bytes,
            "allocate nonce secp256k1 table", error) ||
        !allocate_device(
            buffers.hits,
            sizeof(NonceHit) * kHitCapacity,
            "allocate nonce hits", error) ||
        !allocate_device(
            buffers.hit_count, sizeof(std::uint32_t),
            "allocate nonce hit count", error)) {
        return false;
    }
    buffers.allocated =
        64u + unknown_bytes + list_bytes + 64u +
        precompute_bytes + sizeof(NonceHit) * kHitCapacity +
        sizeof(std::uint32_t);
    std::array<std::uint8_t, 32> x1{};
    std::array<std::uint8_t, 32> x2{};
    std::uint32_t unused = 0u;
    if (record.model == SignatureModel::Ecdsa) {
        ecdsa_x_targets(record, x1, x2, unused);
    } else {
        x1 = record.r_bytes;
        x2 = x1;
    }
    const std::uint32_t zero = 0u;
    if (!metal_ok(
            metalMemcpy(
                buffers.target_x1, x1.data(), x1.size(),
                metalMemcpyHostToDevice),
            "upload nonce target x1", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.target_x2, x2.data(), x2.size(),
                metalMemcpyHostToDevice),
            "upload nonce target x2", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.precompute, precompute.entries.data(),
                precompute_bytes, metalMemcpyHostToDevice),
            "upload nonce secp256k1 table", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.hit_count, &zero, sizeof(zero),
                metalMemcpyHostToDevice),
            "initialize nonce hit count", error)) {
        return false;
    }
    if (!domain.unknown_bits.empty() &&
        !metal_ok(
            metalMemcpy(
                buffers.unknown_bits, domain.unknown_bits.data(),
                domain.unknown_bits.size() * sizeof(std::uint32_t),
                metalMemcpyHostToDevice),
            "upload nonce mask bits", error)) {
        return false;
    }
    return true;
}

bool build_batch_candidates(
        const Options& options,
        const SearchDomain& domain,
        const modeinfra::U256& cursor,
        std::uint64_t count,
        const RandomPermutation& permutation,
        std::vector<std::array<std::uint8_t, 32>>& values,
        std::string& error) {
    values.clear();
    values.reserve(static_cast<std::size_t>(count));
    const cpp_int first = u256_to_int(cursor);
    if (domain.kind == DomainKind::CandidateList) {
        if (first < 0 ||
            first + count > domain.candidates.size()) {
            error = "nonce candidate window is outside the file";
            return false;
        }
        const std::size_t begin = first.convert_to<std::size_t>();
        values.insert(
            values.end(), domain.candidates.begin() + begin,
            domain.candidates.begin() + begin +
                static_cast<std::size_t>(count));
        return true;
    }
    if (!options.random || domain.kind != DomainKind::Range) {
        return true;
    }
    const cpp_int size = domain.range_end - domain.range_start;
    for (std::uint64_t i = 0u; i < count; ++i) {
        const cpp_int ordinal = first + i;
        const cpp_int shuffled = add_mod(
            multiply_mod(
                permutation.multiplier, ordinal, size),
            permutation.addend, size);
        values.push_back(
            int_to_bytes(domain.range_start + shuffled));
    }
    return true;
}

bool launch_batch(const Options& options,
                  const SignatureRecord& record,
                  std::uint32_t record_index,
                  const SearchDomain& domain,
                  const HostPrecompute& precompute,
                  DeviceBuffers& buffers,
                  const modeinfra::U256& cursor,
                  std::uint64_t count,
                  const RandomPermutation& permutation,
                  std::vector<NonceHit>& hits,
                  std::uint32_t& raw_count,
                  std::uint64_t& readback_ns,
                  std::string& error) {
    if (count == 0u ||
        count > std::numeric_limits<std::uint32_t>::max()) {
        error = "invalid nonce batch size";
        return false;
    }
    std::uint32_t source = kRangeSource;
    std::array<std::uint8_t, 32> base{};
    std::array<std::uint8_t, 32> ordinal{};
    std::vector<std::array<std::uint8_t, 32>> candidates;
    if (!build_batch_candidates(
            options, domain, cursor, count,
            permutation, candidates, error)) {
        return false;
    }
    if (!candidates.empty()) {
        source = kListSource;
    } else if (domain.kind == DomainKind::Mask) {
        source = kMaskSource;
        base = domain.mask_base;
        ordinal = int_to_bytes(u256_to_int(cursor));
    } else {
        source = kRangeSource;
        base = int_to_bytes(
            domain.range_start + u256_to_int(cursor));
    }
    if (!metal_ok(
            metalMemcpy(
                buffers.base_nonce, base.data(), base.size(),
                metalMemcpyHostToDevice),
            "upload nonce batch base", error) ||
        !metal_ok(
            metalMemcpy(
                buffers.window_ordinal, ordinal.data(), ordinal.size(),
                metalMemcpyHostToDevice),
            "upload nonce window ordinal", error) ||
        (!candidates.empty() &&
         !metal_ok(
             metalMemcpy(
                 buffers.candidate_list, candidates.data(),
                 static_cast<std::size_t>(count) * 32u,
                 metalMemcpyHostToDevice),
             "upload nonce candidate batch", error)) ||
        !metal_ok(
            metalMemset(
                buffers.hit_count, 0, sizeof(std::uint32_t)),
            "clear nonce hit count", error)) {
        return false;
    }
    std::array<std::uint8_t, 32> x1{};
    std::array<std::uint8_t, 32> x2{};
    std::uint32_t x2_valid = 0u;
    if (record.model == SignatureModel::Ecdsa) {
        ecdsa_x_targets(record, x1, x2, x2_valid);
    }
    const std::uint32_t unknown_count =
        static_cast<std::uint32_t>(domain.unknown_bits.size());
    const std::uint32_t signature_model =
        static_cast<std::uint32_t>(record.model);
    const std::uint64_t pitch =
        static_cast<std::uint64_t>(precompute.pitch);
    const std::uint32_t windows = precompute.windows;
    const std::uint32_t window_bits = precompute.bits;
    const std::uint64_t range_count = count;
    constexpr std::uint64_t kCandidatesPerThread = 8u;
    const std::uint64_t thread_count =
        (count + kCandidatesPerThread - 1u) /
        kCandidatesPerThread;
    const std::uint32_t grid = static_cast<std::uint32_t>(
        (thread_count + kThreadgroupSize - 1u) /
        kThreadgroupSize);
    const metalError_t launched = metal_launch(
        "nonceSearch", grid, kThreadgroupSize,
        buffers.base_nonce, buffers.window_ordinal,
        buffers.unknown_bits, unknown_count,
        buffers.candidate_list, source,
        buffers.target_x1, buffers.target_x2,
        x2_valid, signature_model,
        buffers.precompute, pitch, windows, window_bits,
        range_count, record_index,
        buffers.hits, buffers.hit_count, kHitCapacity);
    if (!metal_ok(launched, "launch nonce kernel", error) ||
        !metal_ok(
            metalDeviceSynchronize(),
            "synchronize nonce kernel", error)) {
        return false;
    }
    const auto read_started = std::chrono::steady_clock::now();
    if (!metal_ok(
            metalMemcpy(
                &raw_count, buffers.hit_count,
                sizeof(raw_count), metalMemcpyDeviceToHost),
            "read nonce hit count", error)) {
        return false;
    }
    const std::uint32_t stored =
        std::min(raw_count, kHitCapacity);
    hits.resize(stored);
    if (stored != 0u &&
        !metal_ok(
            metalMemcpy(
                hits.data(), buffers.hits,
                static_cast<std::size_t>(stored) *
                    sizeof(NonceHit),
                metalMemcpyDeviceToHost),
            "read nonce hits", error)) {
        return false;
    }
    readback_ns = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now() -
            read_started).count());
    return true;
}

} // namespace

bool requested(int argc, char** argv) {
    for (int i = 1; i < argc; ++i) {
        if (argv[i] != nullptr &&
            std::strcmp(argv[i], "-nonce") == 0) {
            return true;
        }
    }
    return false;
}

void print_help() {
    std::cout << R"HELP([!] MAIN MODE: -nonce  (GPU secp256k1 nonce recovery)
[!] ======================================================================
[!] Purpose:
[!] Recover private keys from weak/bounded/template ECDSA or BIP340 nonces.
[!] The GPU verifies candidate R=kG points; every reported private key is
[!] independently reconstructed and fully checked on the CPU.
[!]
[!] Required inputs:
[!] -i RECORD|FILE                 Repeatable record or line-oriented file.
[!] -nonce-model ecdsa|bip340      Optional when every record has a prefix.
[!] ECDSA record:  ecdsa:R:S:Z[:PUBKEY]
[!] BIP340 record: bip340:SIG64:MESSAGE32[:PUBKEY_X]
[!] -target PUBKEY|FILE            One shared target or one target per record.
[!]                                ECDSA accepts 33/65-byte public keys;
[!]                                BIP340 also accepts 32-byte x-only keys.
[!]
[!] Candidate spaces:
[!] -start N -end N                Exact nonce interval [START,END), default
[!]                                [1,secp256k1_order).
[!] -mask MASK                     64 hex/? nibbles or 256 binary 0/1/? bits.
[!] -nonce-candidates FILE         Exact candidate scalars, one per line.
[!] -nonce-lattice FILE            Alias for CPU/lattice candidate output;
[!]                                candidates are verified by the Metal path.
[!] -random                        Deterministic bijective range order.
[!] -nonce-seed N                  64-bit permutation seed.
[!]
[!] Algebraic dependencies:
[!] Repeated ECDSA r values are solved as reused nonce on CPU before search.
[!] -nonce-relation same|add:B|mul:A|affine:A:B
[!]                                Solve k2=A*k1+B for the first two records.
[!]
[!] GPU / scheduling:
[!] -device LIST                   Metal device indexes, comma separated.
[!] -n NUMBER                      Candidate window, default 1048576.
[!] Checked U256 ordinals are split without gaps/overlaps. Overflowed hit
[!] windows are retried at half size and are never double-counted.
[!]
[!] Statistics / output:
[!] -o FILE                        Append verified results to FILE.
[!] -save                          Use NONCE_FOUND.txt when -o is absent.
[!] -silent                        Suppress result lines on stdout.
[!] Only SpeedThreadFunc prints live statistics: Nonce/s and Verify/s.
[!]
[!] Examples:
[!] ./METAL_CRYPTO_TOOLKIT -nonce -nonce-model ecdsa -i "R:S:Z:PUBKEY" -start 1 -end 0x1000000
[!] ./METAL_CRYPTO_TOOLKIT -nonce -i signatures.txt -mask "000000000000000000000000000000000000000000000000000000000000????"
[!] ./METAL_CRYPTO_TOOLKIT -nonce -i reused.txt -nonce-relation same
[!] ./METAL_CRYPTO_TOOLKIT -nonce -nonce-model bip340 -i "SIG64:MSG32" -target PUBKEY_X -nonce-lattice candidates.txt
[!]
[!] Limitations:
[!] This mode exploits already weak, related, bounded, templated, or externally
[!] preprocessed nonces. It does not make uniformly random 256-bit nonces
[!] searchable. The built-in relation solver handles two affine-related ECDSA
[!] nonces; general hidden-number lattices remain a CPU preprocessing task.
[!]
[!] Errors:
[!] CLI/input errors return 2; Metal/runtime failures return 1; an exhausted
[!] valid search returns 0 even when no key is found.
)HELP";
}

int run(int argc, char** argv, const RuntimeHooks& hooks) {
    Options options;
    std::string error;
    if (!parse_options(argc, argv, options, error)) {
        std::cerr << "[!] Nonce CLI error: " << error << " [!]\n";
        return 2;
    }
    std::vector<SignatureRecord> records;
    if (!load_records(options, records, error)) {
        std::cerr << "[!] Nonce input error: " << error << " [!]\n";
        return 2;
    }
    SearchDomain domain;
    if (!prepare_domain(options, domain, error)) {
        std::cerr << "[!] Nonce domain error: " << error << " [!]\n";
        return 2;
    }
    int device_count = 0;
    if (!metal_ok(
            metalGetDeviceCount(&device_count),
            "query Metal device count", error)) {
        std::cerr << "[!] Nonce runtime error: " << error << " [!]\n";
        return 1;
    }
    for (int device : options.devices) {
        if (device < 0 || device >= device_count) {
            std::cerr << "[!] Nonce CLI error: device index "
                      << device << " is unavailable [!]\n";
            return 2;
        }
    }
    HostPrecompute precompute;
    if (!build_host_precompute(precompute, error)) {
        std::cerr << "[!] Nonce runtime error: " << error << " [!]\n";
        return 1;
    }
    std::ofstream output;
    if (options.output_path.empty() && options.save) {
        options.output_path = "NONCE_FOUND.txt";
    }
    if (!options.output_path.empty()) {
        output.open(options.output_path, std::ios::app);
        if (!output) {
            std::cerr << "[!] Nonce runtime error: cannot open output file [!]\n";
            return 1;
        }
    }

    modeinfra::ModeProgress& progress =
        modeinfra::global_mode_progress();
    progress.begin(
        "NONCE", modeinfra::ProgressUnit::Nonce,
        modeinfra::ProgressPhase::Load);
    progress.set_targets(records.size(), records.size(), 0u);
    std::uint64_t founds = 0u;
    std::uint64_t solved = 0u;
    std::unordered_set<std::string> emitted;

    progress.set_phase(modeinfra::ProgressPhase::Verify);
    auto publish_relation =
        [&](std::size_t first_index,
            std::size_t second_index,
            const Relation& relation) -> bool {
        cpp_int private_key;
        cpp_int first_nonce;
        cpp_int second_nonce;
        if (!solve_relation(
                records[first_index], records[second_index],
                relation, precompute, private_key,
                first_nonce, second_nonce)) {
            return true;
        }
        std::string line = format_result(
            records[first_index], first_nonce, private_key,
            "RELATION:" + relation.label +
            ":SECOND_NONCE:" +
            hex_lower(
                int_to_bytes(second_nonce).data(), 32u) +
            ":SECOND_SOURCE:" +
            records[second_index].source);
        if (!emitted.insert(line).second) return true;
        if (!emit_result(
                line, output.is_open() ? &output : nullptr,
                options.silent)) {
            return false;
        }
        records[first_index].solved = true;
        records[second_index].solved = true;
        solved += first_index == second_index ? 1u : 2u;
        ++founds;
        progress.set_targets(records.size(), records.size(), solved);
        progress.set_founds(founds);
        progress.credit_completed(0u, 0u, 2u, 0u);
        if (hooks.increment_found) hooks.increment_found();
        return true;
    };

    if (options.relation.set && records.size() >= 2u) {
        if (!publish_relation(0u, 1u, options.relation)) {
            progress.end();
            std::cerr << "[!] Nonce runtime error: output write failed [!]\n";
            return 1;
        }
    } else {
        Relation reused;
        reused.set = true;
        reused.label = "same";
        Relation mirrored = reused;
        mirrored.multiplier = -1;
        mirrored.label = "mirrored";
        for (std::size_t left = 0u; left < records.size(); ++left) {
            if (records[left].model != SignatureModel::Ecdsa ||
                records[left].solved) {
                continue;
            }
            for (std::size_t right = left + 1u;
                 right < records.size(); ++right) {
                if (records[right].model == SignatureModel::Ecdsa &&
                    !records[right].solved &&
                    records[left].r == records[right].r) {
                    if (!publish_relation(left, right, reused)) {
                        progress.end();
                        std::cerr
                            << "[!] Nonce runtime error: output write failed [!]\n";
                        return 1;
                    }
                    if (!records[left].solved &&
                        !publish_relation(left, right, mirrored)) {
                        progress.end();
                        std::cerr
                            << "[!] Nonce runtime error: output write failed [!]\n";
                        return 1;
                    }
                }
            }
        }
    }

    progress.set_phase(modeinfra::ProgressPhase::Search);
    const RandomPermutation permutation =
        make_random_permutation(
            u256_to_int(domain.size), options.random_seed);
    for (std::size_t record_index = 0u;
         record_index < records.size(); ++record_index) {
        SignatureRecord& record = records[record_index];
        if (record.solved) continue;
        bool record_solved = false;
        for (std::size_t shard_index = 0u;
             shard_index < options.devices.size() &&
             !record_solved; ++shard_index) {
            modeinfra::U256 shard_begin;
            modeinfra::U256 shard_count;
            if (!split_domain(
                    domain.size, shard_index,
                    options.devices.size(),
                    shard_begin, shard_count, error)) {
                progress.end();
                std::cerr << "[!] Nonce runtime error: "
                          << error << " [!]\n";
                return 1;
            }
            if (shard_count.is_zero()) continue;
            modeinfra::U256 shard_end;
            if (!modeinfra::add_checked(
                    shard_begin, shard_count, shard_end)) {
                progress.end();
                std::cerr
                    << "[!] Nonce runtime error: shard end overflows U256 [!]\n";
                return 1;
            }
            if (!metal_ok(
                    metalSetDevice(options.devices[shard_index]),
                    "select Metal device", error)) {
                progress.end();
                std::cerr << "[!] Nonce runtime error: "
                          << error << " [!]\n";
                return 1;
            }
            DeviceBuffers buffers;
            if (!prepare_buffers(
                    record, domain, precompute,
                    options.batch, buffers, error)) {
                progress.end();
                std::cerr << "[!] Nonce runtime error: "
                          << error << " [!]\n";
                return 1;
            }
            progress.set_allocated_working_set(buffers.allocated);
            modeinfra::U256 cursor = shard_begin;
            std::uint64_t preferred_batch = options.batch;
            while (modeinfra::compare(cursor, shard_end) < 0 &&
                   !record_solved) {
                modeinfra::U256 remaining;
                if (!modeinfra::subtract_checked(
                        shard_end, cursor, remaining)) {
                    progress.end();
                    std::cerr
                        << "[!] Nonce runtime error: invalid shard cursor [!]\n";
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
                    std::vector<NonceHit> hits;
                    std::uint32_t raw_count = 0u;
                    std::uint64_t readback_ns = 0u;
                    if (!launch_batch(
                            options, record,
                            static_cast<std::uint32_t>(record_index),
                            domain, precompute, buffers,
                            cursor, batch, permutation,
                            hits, raw_count, readback_ns, error)) {
                        progress.end();
                        std::cerr << "[!] Nonce runtime error: "
                                  << error << " [!]\n";
                        return 1;
                    }
                    if (raw_count > kHitCapacity) {
                        if (batch == 1u) {
                            progress.end();
                            std::cerr
                                << "[!] Nonce runtime error: hit buffer overflow at one candidate [!]\n";
                            return 1;
                        }
                        batch = std::max<std::uint64_t>(1u, batch / 2u);
                        continue;
                    }
                    completed = true;
                    std::uint64_t verifications = 0u;
                    for (const NonceHit& hit : hits) {
                        ++verifications;
                        if (hit.record_index != record_index) continue;
                        const cpp_int nonce =
                            bytes_to_int(hit.nonce.data(), hit.nonce.size());
                        cpp_int private_key;
                        if (!recover_private(
                                record, nonce, precompute,
                                private_key)) {
                            continue;
                        }
                        const std::string line =
                            format_result(record, nonce, private_key);
                        if (!emitted.insert(line).second) continue;
                        if (!emit_result(
                                line,
                                output.is_open() ? &output : nullptr,
                                options.silent)) {
                            progress.end();
                            std::cerr
                                << "[!] Nonce runtime error: output write failed [!]\n";
                            return 1;
                        }
                        ++founds;
                        ++solved;
                        record.solved = true;
                        record_solved = true;
                        progress.set_founds(founds);
                        progress.set_targets(
                            records.size(), records.size(), solved);
                        if (hooks.increment_found) hooks.increment_found();
                    }
                    progress.credit_completed(
                        batch, batch, verifications, readback_ns);
                    if (hooks.add_completed) hooks.add_completed(batch);
                    modeinfra::U256 next;
                    if (!modeinfra::add_checked(
                            cursor,
                            modeinfra::U256::from_u64(batch),
                            next)) {
                        progress.end();
                        std::cerr
                            << "[!] Nonce runtime error: window cursor overflows U256 [!]\n";
                        return 1;
                    }
                    cursor = next;
                }
            }
        }
    }
    progress.set_phase(modeinfra::ProgressPhase::Verify);
    progress.end();
    if (!options.silent) {
        std::cout << "[!] Nonce completed. Solved: "
                  << solved << " / " << records.size()
                  << " signature record(s); verified result(s): "
                  << founds << ". [!]\n";
    }
    return 0;
}

} // namespace nonce_mode
