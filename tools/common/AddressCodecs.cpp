#include "AddressCodecs.h"

#include "Hashes.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <limits>
#include <string>

namespace address_tools {
namespace {

constexpr std::string_view kBase58Alphabet =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
constexpr std::string_view kRippleAlphabet =
    "rpshnaf39wBUDNEGHJKLM4PQRST7VWXYZ2bcdeCg65jkm8oFqi1tuvAxyz";
constexpr std::string_view kBech32Alphabet = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
constexpr std::string_view kC32Alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

enum class Bech32Encoding { invalid, bech32, bech32m };

struct Bech32Value {
    std::string hrp;
    std::vector<uint8_t> data;
    Bech32Encoding encoding = Bech32Encoding::invalid;
};

bool decode_hex(std::string_view input, std::vector<uint8_t>& output) {
    output.clear();
    if (input.size() >= 2 && input[0] == '0' && (input[1] == 'x' || input[1] == 'X')) {
        input.remove_prefix(2);
    }
    if (input.empty() || (input.size() & 1u) != 0) return false;
    auto value = [](char character) -> int {
        if (character >= '0' && character <= '9') return character - '0';
        if (character >= 'a' && character <= 'f') return character - 'a' + 10;
        if (character >= 'A' && character <= 'F') return character - 'A' + 10;
        return -1;
    };
    output.reserve(input.size() / 2);
    for (size_t i = 0; i < input.size(); i += 2) {
        const int high = value(input[i]);
        const int low = value(input[i + 1]);
        if (high < 0 || low < 0) {
            output.clear();
            return false;
        }
        output.push_back(static_cast<uint8_t>((high << 4) | low));
    }
    return true;
}

bool decode_hex_size(std::string_view input, size_t size, std::vector<uint8_t>& output) {
    return decode_hex(input, output) && output.size() == size;
}

bool decode_base_n(std::string_view input,
                   std::string_view alphabet,
                   uint32_t base,
                   std::vector<uint8_t>& output) {
    output.clear();
    if (input.empty() || alphabet.size() != base) return false;
    std::vector<uint8_t> little_endian;
    little_endian.reserve(input.size());
    for (char character : input) {
        const size_t position = alphabet.find(character);
        if (position == std::string_view::npos) {
            output.clear();
            return false;
        }
        uint32_t carry = static_cast<uint32_t>(position);
        for (uint8_t& byte : little_endian) {
            const uint32_t value = static_cast<uint32_t>(byte) * base + carry;
            byte = static_cast<uint8_t>(value);
            carry = value >> 8;
        }
        while (carry != 0) {
            little_endian.push_back(static_cast<uint8_t>(carry));
            carry >>= 8;
        }
    }

    size_t leading_zeroes = 0;
    while (leading_zeroes < input.size() && input[leading_zeroes] == alphabet[0]) {
        ++leading_zeroes;
    }
    output.assign(leading_zeroes, 0);
    output.insert(output.end(), little_endian.rbegin(), little_endian.rend());
    return true;
}

bool decode_base58(std::string_view input,
                   std::string_view alphabet,
                   std::vector<uint8_t>& output) {
    return decode_base_n(input, alphabet, 58, output);
}

bool decode_base58check(std::string_view input,
                        std::string_view alphabet,
                        std::vector<uint8_t>& payload) {
    std::vector<uint8_t> decoded;
    if (!decode_base58(input, alphabet, decoded) || decoded.size() < 5) return false;
    const size_t payload_size = decoded.size() - 4;
    const auto checksum = sha256d(decoded.data(), payload_size);
    if (!bytes_equal(checksum.data(), decoded.data() + payload_size, 4)) return false;
    payload.assign(decoded.begin(), decoded.begin() + static_cast<std::ptrdiff_t>(payload_size));
    return true;
}

bool convert_bits(const std::vector<uint8_t>& input,
                  int from_bits,
                  int to_bits,
                  bool pad,
                  std::vector<uint8_t>& output) {
    output.clear();
    uint32_t accumulator = 0;
    int bits = 0;
    const uint32_t max_value = (1u << to_bits) - 1u;
    const uint32_t max_accumulator = (1u << (from_bits + to_bits - 1)) - 1u;
    for (uint8_t value : input) {
        if ((value >> from_bits) != 0) return false;
        accumulator = ((accumulator << from_bits) | value) & max_accumulator;
        bits += from_bits;
        while (bits >= to_bits) {
            bits -= to_bits;
            output.push_back(static_cast<uint8_t>((accumulator >> bits) & max_value));
        }
    }
    if (pad) {
        if (bits != 0) output.push_back(static_cast<uint8_t>((accumulator << (to_bits - bits)) & max_value));
    } else if (bits >= from_bits ||
               (bits != 0 && ((accumulator << (to_bits - bits)) & max_value) != 0)) {
        output.clear();
        return false;
    }
    return true;
}

uint32_t bech32_polymod(const std::vector<uint8_t>& values) {
    static constexpr uint32_t generator[5] = {0x3b6a57b2u, 0x26508e6du, 0x1ea119fau,
                                               0x3d4233ddu, 0x2a1462b3u};
    uint32_t checksum = 1;
    for (uint8_t value : values) {
        const uint8_t top = static_cast<uint8_t>(checksum >> 25);
        checksum = ((checksum & 0x1ffffffu) << 5) ^ value;
        for (size_t i = 0; i < 5; ++i) {
            if (((top >> i) & 1u) != 0) checksum ^= generator[i];
        }
    }
    return checksum;
}

bool decode_bech32(std::string_view input, Bech32Value& output) {
    output = {};
    if (input.size() < 8 || input.size() > 1023) return false;
    bool has_lower = false;
    bool has_upper = false;
    std::string normalized;
    normalized.reserve(input.size());
    for (char character : input) {
        const unsigned char byte = static_cast<unsigned char>(character);
        if (byte < 33 || byte > 126) return false;
        has_lower |= std::islower(byte) != 0;
        has_upper |= std::isupper(byte) != 0;
        normalized.push_back(static_cast<char>(std::tolower(byte)));
    }
    if (has_lower && has_upper) return false;
    const size_t separator = normalized.rfind('1');
    if (separator == std::string::npos || separator == 0 || separator + 7 > normalized.size()) {
        return false;
    }
    output.hrp = normalized.substr(0, separator);
    std::vector<uint8_t> values;
    values.reserve(normalized.size() - separator - 1);
    for (size_t i = separator + 1; i < normalized.size(); ++i) {
        const size_t position = kBech32Alphabet.find(normalized[i]);
        if (position == std::string_view::npos) return false;
        values.push_back(static_cast<uint8_t>(position));
    }

    std::vector<uint8_t> checksum_values;
    checksum_values.reserve(output.hrp.size() * 2 + 1 + values.size());
    for (char character : output.hrp) checksum_values.push_back(static_cast<uint8_t>(character >> 5));
    checksum_values.push_back(0);
    for (char character : output.hrp) checksum_values.push_back(static_cast<uint8_t>(character & 31));
    checksum_values.insert(checksum_values.end(), values.begin(), values.end());
    const uint32_t checksum = bech32_polymod(checksum_values);
    if (checksum == 1) {
        output.encoding = Bech32Encoding::bech32;
    } else if (checksum == 0x2bc830a3u) {
        output.encoding = Bech32Encoding::bech32m;
    } else {
        return false;
    }
    output.data.assign(values.begin(), values.end() - 6);
    return true;
}

bool decode_rfc4648_base32(std::string_view input, std::vector<uint8_t>& output) {
    output.clear();
    if (input.empty()) return false;
    std::vector<uint8_t> values;
    values.reserve(input.size());
    bool padding_started = false;
    for (char character : input) {
        if (character == '=') {
            padding_started = true;
            continue;
        }
        if (padding_started) return false;
        const unsigned char upper = static_cast<unsigned char>(
            std::toupper(static_cast<unsigned char>(character)));
        uint8_t value = 0;
        if (upper >= 'A' && upper <= 'Z') {
            value = static_cast<uint8_t>(upper - 'A');
        } else if (upper >= '2' && upper <= '7') {
            value = static_cast<uint8_t>(upper - '2' + 26);
        } else {
            return false;
        }
        values.push_back(value);
    }
    return !values.empty() && convert_bits(values, 5, 8, false, output);
}

bool decode_base64(std::string_view input, std::vector<uint8_t>& output) {
    output.clear();
    if (input.empty()) return false;
    std::string normalized(input);
    const bool standard = normalized.find_first_of("+/") != std::string::npos;
    const bool url = normalized.find_first_of("-_") != std::string::npos;
    if (standard && url) return false;
    if (url) {
        std::replace(normalized.begin(), normalized.end(), '-', '+');
        std::replace(normalized.begin(), normalized.end(), '_', '/');
    }
    const size_t padding_position = normalized.find('=');
    if (padding_position != std::string::npos) {
        const size_t padding_size = normalized.size() - padding_position;
        if ((normalized.size() & 3u) != 0 || padding_size > 2 ||
            normalized.find_first_not_of('=', padding_position) != std::string::npos ||
            (padding_size == 1 && (padding_position & 3u) != 3) ||
            (padding_size == 2 && (padding_position & 3u) != 2)) {
            return false;
        }
    } else {
        if ((normalized.size() & 3u) == 1) return false;
        while ((normalized.size() & 3u) != 0) normalized.push_back('=');
    }

    auto value = [](char character) -> int {
        if (character >= 'A' && character <= 'Z') return character - 'A';
        if (character >= 'a' && character <= 'z') return character - 'a' + 26;
        if (character >= '0' && character <= '9') return character - '0' + 52;
        if (character == '+') return 62;
        if (character == '/') return 63;
        return -1;
    };

    for (size_t offset = 0; offset < normalized.size(); offset += 4) {
        const bool last = offset + 4 == normalized.size();
        const char c0 = normalized[offset];
        const char c1 = normalized[offset + 1];
        const char c2 = normalized[offset + 2];
        const char c3 = normalized[offset + 3];
        const int v0 = value(c0);
        const int v1 = value(c1);
        const int v2 = c2 == '=' ? 0 : value(c2);
        const int v3 = c3 == '=' ? 0 : value(c3);
        if (v0 < 0 || v1 < 0 || v2 < 0 || v3 < 0 || (!last && (c2 == '=' || c3 == '=')) ||
            (c2 == '=' && c3 != '=')) {
            output.clear();
            return false;
        }
        output.push_back(static_cast<uint8_t>((v0 << 2) | (v1 >> 4)));
        if (c2 == '=') {
            if ((v1 & 0x0f) != 0) return false;
            continue;
        }
        output.push_back(static_cast<uint8_t>((v1 << 4) | (v2 >> 2)));
        if (c3 == '=') {
            if ((v2 & 0x03) != 0) return false;
            continue;
        }
        output.push_back(static_cast<uint8_t>((v2 << 6) | v3));
    }
    return !output.empty();
}

uint64_t cashaddr_polymod(const std::vector<uint8_t>& values) {
    static constexpr uint64_t generator[5] = {0x98f2bc8e61ULL, 0x79b76d99e2ULL,
                                               0xf33e5fb3c4ULL, 0xae2eabe2a8ULL,
                                               0x1e4f43e470ULL};
    uint64_t checksum = 1;
    for (uint8_t value : values) {
        const uint8_t top = static_cast<uint8_t>(checksum >> 35);
        checksum = ((checksum & 0x07ffffffffULL) << 5) ^ value;
        for (size_t i = 0; i < 5; ++i) {
            if (((top >> i) & 1u) != 0) checksum ^= generator[i];
        }
    }
    return checksum ^ 1;
}

bool decode_cashaddr(std::string_view input, std::vector<uint8_t>& output) {
    output.clear();
    bool has_lower = false;
    bool has_upper = false;
    std::string normalized;
    normalized.reserve(input.size() + 12);
    for (char character : input) {
        const unsigned char byte = static_cast<unsigned char>(character);
        has_lower |= std::islower(byte) != 0;
        has_upper |= std::isupper(byte) != 0;
        normalized.push_back(static_cast<char>(std::tolower(byte)));
    }
    if (has_lower && has_upper) return false;
    size_t separator = normalized.rfind(':');
    std::string prefix;
    std::string payload;
    if (separator == std::string::npos) {
        prefix = "bitcoincash";
        payload = normalized;
    } else {
        prefix = normalized.substr(0, separator);
        payload = normalized.substr(separator + 1);
    }
    if (prefix.empty() || payload.size() < 8) return false;
    for (char character : prefix) {
        if (!((character >= 'a' && character <= 'z') ||
              (character >= '0' && character <= '9'))) {
            return false;
        }
    }
    std::vector<uint8_t> values;
    for (char character : prefix) values.push_back(static_cast<uint8_t>(character & 31));
    values.push_back(0);
    std::vector<uint8_t> payload_values;
    payload_values.reserve(payload.size());
    for (char character : payload) {
        const size_t position = kBech32Alphabet.find(character);
        if (position == std::string_view::npos) return false;
        payload_values.push_back(static_cast<uint8_t>(position));
    }
    values.insert(values.end(), payload_values.begin(), payload_values.end());
    if (cashaddr_polymod(values) != 0 || payload_values.size() <= 8) return false;
    payload_values.resize(payload_values.size() - 8);
    std::vector<uint8_t> decoded;
    if (!convert_bits(payload_values, 5, 8, false, decoded) || decoded.size() != 21) return false;
    const uint8_t version = decoded[0];
    if ((version & 0x80u) != 0 || (version & 0x07u) != 0) return false;
    output.assign(decoded.begin() + 1, decoded.end());
    return true;
}

bool read_cbor_length(const std::vector<uint8_t>& data,
                      size_t& offset,
                      size_t limit,
                      uint8_t expected_major,
                      uint64_t& value) {
    if (offset >= limit || limit > data.size()) return false;
    const uint8_t initial = data[offset++];
    if ((initial >> 5) != expected_major) return false;
    const uint8_t additional = initial & 31u;
    if (additional < 24) {
        value = additional;
        return true;
    }
    size_t bytes = 0;
    if (additional == 24) bytes = 1;
    else if (additional == 25) bytes = 2;
    else if (additional == 26) bytes = 4;
    else if (additional == 27) bytes = 8;
    else return false;
    if (offset + bytes > limit) return false;
    value = 0;
    for (size_t i = 0; i < bytes; ++i) value = (value << 8) | data[offset++];
    if ((additional == 24 && value < 24) || (additional == 25 && value <= 0xffu) ||
        (additional == 26 && value <= 0xffffu) ||
        (additional == 27 && value <= 0xffffffffu)) {
        return false;
    }
    return true;
}

bool validate_byron_payload(const std::vector<uint8_t>& data, size_t begin, size_t end) {
    size_t offset = begin;
    uint64_t value = 0;
    if (!read_cbor_length(data, offset, end, 4, value) || value != 3) return false;

    uint64_t root_size = 0;
    if (!read_cbor_length(data, offset, end, 2, root_size) || root_size != 28 ||
        root_size > end - offset) {
        return false;
    }
    offset += static_cast<size_t>(root_size);

    uint64_t attribute_count = 0;
    if (!read_cbor_length(data, offset, end, 5, attribute_count) || attribute_count > 2) {
        return false;
    }
    bool seen_derivation_path = false;
    bool seen_network_magic = false;
    for (uint64_t i = 0; i < attribute_count; ++i) {
        uint64_t key = 0;
        if (!read_cbor_length(data, offset, end, 0, key) || (key != 1 && key != 2)) {
            return false;
        }
        if ((key == 1 && seen_derivation_path) || (key == 2 && seen_network_magic)) {
            return false;
        }

        uint64_t attribute_size = 0;
        if (!read_cbor_length(data, offset, end, 2, attribute_size) ||
            attribute_size > end - offset) {
            return false;
        }
        const size_t attribute_end = offset + static_cast<size_t>(attribute_size);
        if (key == 1) {
            if (attribute_size == 0) return false;
            seen_derivation_path = true;
        } else {
            size_t nested_offset = offset;
            uint64_t network_magic = 0;
            if (!read_cbor_length(data, nested_offset, attribute_end, 0, network_magic) ||
                network_magic > 0xffffffffULL || nested_offset != attribute_end) {
                return false;
            }
            seen_network_magic = true;
        }
        offset = attribute_end;
    }

    uint64_t address_type = 0;
    return read_cbor_length(data, offset, end, 0, address_type) && address_type <= 2 &&
           offset == end;
}

bool validate_byron_cbor(const std::vector<uint8_t>& data) {
    size_t offset = 0;
    uint64_t value = 0;
    if (!read_cbor_length(data, offset, data.size(), 4, value) || value != 2) return false;
    if (!read_cbor_length(data, offset, data.size(), 6, value) || value != 24) return false;
    uint64_t payload_size = 0;
    if (!read_cbor_length(data, offset, data.size(), 2, payload_size) ||
        payload_size > data.size() - offset) {
        return false;
    }
    const size_t payload_offset = offset;
    offset += static_cast<size_t>(payload_size);
    uint64_t expected_crc = 0;
    if (!read_cbor_length(data, offset, data.size(), 0, expected_crc) ||
        expected_crc > 0xffffffffULL || offset != data.size() ||
        !validate_byron_payload(data, payload_offset, payload_offset + static_cast<size_t>(payload_size))) {
        return false;
    }
    return crc32_ieee(data.data() + payload_offset, static_cast<size_t>(payload_size)) == expected_crc;
}

bool read_cardano_pointer_uint(const std::vector<uint8_t>& payload, size_t& offset) {
    if (offset >= payload.size()) return false;
    uint64_t value = 0;
    size_t byte_count = 0;
    for (;;) {
        if (offset >= payload.size() || byte_count == 10) return false;
        const uint8_t byte = payload[offset++];
        const uint8_t low = byte & 0x7fu;
        if (byte_count == 0 && (byte & 0x80u) != 0 && low == 0) return false;
        if (value > (std::numeric_limits<uint64_t>::max() >> 7u) ||
            (value == (std::numeric_limits<uint64_t>::max() >> 7u) &&
             low > (std::numeric_limits<uint64_t>::max() & 0x7fu))) {
            return false;
        }
        value = (value << 7u) | low;
        ++byte_count;
        if ((byte & 0x80u) == 0) return true;
    }
}

bool decode_cardano_shelley(const Bech32Value& address, std::vector<uint8_t>& payload) {
    if (address.encoding != Bech32Encoding::bech32 ||
        (address.hrp != "addr" && address.hrp != "addr_test" && address.hrp != "stake" &&
         address.hrp != "stake_test") ||
        !convert_bits(address.data, 5, 8, false, payload) || payload.empty()) {
        return false;
    }
    const uint8_t type = payload[0] >> 4;
    const uint8_t network = payload[0] & 0x0fu;
    if (network > 1) return false;
    const bool stake_hrp = address.hrp == "stake" || address.hrp == "stake_test";
    const bool test_hrp = address.hrp == "addr_test" || address.hrp == "stake_test";
    if (network != (test_hrp ? 0u : 1u)) return false;
    if (stake_hrp) return (type == 14 || type == 15) && payload.size() == 29;
    if (type <= 3) return payload.size() == 57;
    if (type == 4 || type == 5) {
        if (payload.size() < 32) return false;
        size_t offset = 29;
        return read_cardano_pointer_uint(payload, offset) &&
               read_cardano_pointer_uint(payload, offset) &&
               read_cardano_pointer_uint(payload, offset) && offset == payload.size();
    }
    if (type == 6 || type == 7) return payload.size() == 29;
    return false;
}

}  // namespace

bool decode_cardano(std::string_view input, std::vector<uint8_t>& output) {
    output.clear();
    std::vector<uint8_t> decoded;
    Bech32Value bech32;
    if (decode_bech32(input, bech32) && decode_cardano_shelley(bech32, decoded)) {
        const auto digest = sha256(decoded);
        output.assign(digest.begin(), digest.end());
        return true;
    }
    if (!decode_base58(input, kBase58Alphabet, decoded) || !validate_byron_cbor(decoded)) return false;
    const auto digest = sha256(decoded);
    output.assign(digest.begin(), digest.end());
    return true;
}

bool decode_algorand(std::string_view input, std::vector<uint8_t>& output) {
    output.clear();
    if (input.size() != 58) return false;
    for (char character : input) {
        if (!((character >= 'A' && character <= 'Z') ||
              (character >= '2' && character <= '7'))) {
            return false;
        }
    }
    std::vector<uint8_t> decoded;
    if (!decode_rfc4648_base32(input, decoded) || decoded.size() != 36) return false;
    const auto checksum = sha512_256(decoded.data(), 32);
    if (!bytes_equal(checksum.data() + 28, decoded.data() + 32, 4)) return false;
    output.assign(decoded.begin(), decoded.begin() + 32);
    return true;
}

bool decode_multicoin_base58_bech32(std::string_view input,
                                    std::vector<uint8_t>& output) {
    output.clear();
    if (input.empty()) return false;
    std::vector<uint8_t> raw_hex;
    if (decode_hex(input, raw_hex) && (raw_hex.size() == 20 || raw_hex.size() == 32)) {
        output = std::move(raw_hex);
        return true;
    }

    const std::string lowered = [&] {
        std::string value(input);
        std::transform(value.begin(), value.end(), value.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return value;
    }();
    if (lowered.find(':') != std::string::npos || lowered[0] == 'q' || lowered[0] == 'p') {
        if (decode_cashaddr(input, output)) return true;
    }

    Bech32Value address;
    if (decode_bech32(input, address)) {
        if (input.size() > 90) return false;
        if (address.data.empty() || address.data[0] > 16) return false;
        const uint8_t witness_version = address.data[0];
        std::vector<uint8_t> program_data(address.data.begin() + 1, address.data.end());
        std::vector<uint8_t> program;
        if (!convert_bits(program_data, 5, 8, false, program)) return false;
        if (witness_version == 0) {
            if (address.encoding != Bech32Encoding::bech32 ||
                (program.size() != 20 && program.size() != 32)) {
                return false;
            }
            if (program.size() == 20) {
                output = std::move(program);
            } else {
                const auto digest = ripemd160(program.data(), program.size());
                output.assign(digest.begin(), digest.end());
            }
            return true;
        }
        if (witness_version == 1 && address.encoding == Bech32Encoding::bech32m &&
            program.size() == 32) {
            const auto digest = ripemd160(program.data(), program.size());
            output.assign(digest.begin(), digest.end());
            return true;
        }
        return false;
    }

    std::vector<uint8_t> payload;
    if (decode_base58check(input, kBase58Alphabet, payload) && payload.size() >= 21 &&
        payload.size() <= 24) {
        if (payload.size() == 21 && payload[0] == 0x41) return false;
        output.assign(payload.end() - 20, payload.end());
        return true;
    }
    return false;
}

bool decode_base64_raw(std::string_view input, std::vector<uint8_t>& output) {
    return decode_base64(input, output);
}

bool decode_cosmos(std::string_view input, std::vector<uint8_t>& output) {
    if (decode_hex_size(input, 20, output)) return true;
    if (input.size() > 90) return false;
    Bech32Value address;
    return decode_bech32(input, address) && address.encoding == Bech32Encoding::bech32 &&
           convert_bits(address.data, 5, 8, false, output) && output.size() == 20;
}

bool decode_ss58(std::string_view input, std::vector<uint8_t>& output) {
    output.clear();
    std::vector<uint8_t> decoded;
    if (!decode_base58(input, kBase58Alphabet, decoded) || decoded.empty()) return false;
    size_t prefix_size = 0;
    if (decoded[0] < 64) {
        prefix_size = 1;
    } else if (decoded[0] < 128 && decoded.size() >= 2) {
        prefix_size = 2;
        const uint32_t network = ((decoded[0] & 0x3fu) << 2) | (decoded[1] >> 6) |
                                 ((decoded[1] & 0x3fu) << 8);
        if (network < 64 || network > 16383) return false;
    } else {
        return false;
    }
    if (decoded.size() != prefix_size + 32 + 2) return false;
    static constexpr uint8_t prefix[] = {'S', 'S', '5', '8', 'P', 'R', 'E'};
    std::vector<uint8_t> checksum_input(std::begin(prefix), std::end(prefix));
    checksum_input.insert(checksum_input.end(), decoded.begin(), decoded.end() - 2);
    const auto checksum = blake2b(checksum_input.data(), checksum_input.size(), 64);
    if (!bytes_equal(checksum.data(), decoded.data() + decoded.size() - 2, 2)) return false;
    output.assign(decoded.begin() + static_cast<std::ptrdiff_t>(prefix_size), decoded.end() - 2);
    return true;
}

bool decode_filecoin(std::string_view input, std::vector<uint8_t>& output) {
    output.clear();
    if (input.size() < 3 || (input[0] != 'f' && input[0] != 't')) return false;
    for (char character : input) {
        if (std::isupper(static_cast<unsigned char>(character)) != 0 || character == '=') {
            return false;
        }
    }
    std::vector<uint8_t> decoded;
    std::vector<uint8_t> checksum_input;
    if (input[1] == '1') {
        if (!decode_rfc4648_base32(input.substr(2), decoded) || decoded.size() != 24) return false;
        checksum_input.push_back(1);
    } else if (input[1] == '4') {
        size_t separator = 2;
        while (separator < input.size() && std::isdigit(static_cast<unsigned char>(input[separator])) != 0) {
            ++separator;
        }
        if (separator == 2 || separator >= input.size() || input[separator] != 'f' ||
            input.substr(2, separator - 2) != "10" ||
            !decode_rfc4648_base32(input.substr(separator + 1), decoded) || decoded.size() != 24) {
            return false;
        }
        checksum_input.push_back(4);
        checksum_input.push_back(10);
    } else {
        return false;
    }
    checksum_input.insert(checksum_input.end(), decoded.begin(), decoded.begin() + 20);
    const auto checksum = blake2b(checksum_input.data(), checksum_input.size(), 4);
    if (!bytes_equal(checksum.data(), decoded.data() + 20, 4)) return false;
    output.assign(decoded.begin(), decoded.begin() + 20);
    return true;
}

bool decode_solana(std::string_view input, std::vector<uint8_t>& output) {
    return decode_base58(input, kBase58Alphabet, output) && output.size() == 32;
}

bool decode_stellar(std::string_view input, std::vector<uint8_t>& output) {
    output.clear();
    for (char character : input) {
        if (!((character >= 'A' && character <= 'Z') ||
              (character >= '2' && character <= '7'))) {
            return false;
        }
    }
    std::vector<uint8_t> decoded;
    if (!decode_rfc4648_base32(input, decoded)) return false;
    const bool account = decoded.size() == 35 && decoded[0] == (6u << 3);
    const bool muxed = decoded.size() == 43 && decoded[0] == (12u << 3);
    if (!account && !muxed) return false;
    const size_t payload_size = decoded.size() - 2;
    const uint16_t checksum = crc16_xmodem(decoded.data(), payload_size);
    const uint16_t encoded_checksum = static_cast<uint16_t>(decoded[payload_size]) |
                                      (static_cast<uint16_t>(decoded[payload_size + 1]) << 8);
    if (checksum != encoded_checksum) return false;
    output.assign(decoded.begin() + 1, decoded.begin() + 33);
    return true;
}

bool decode_stacks(std::string_view input, std::vector<uint8_t>& output) {
    output.clear();
    if (input.size() < 3) return false;
    std::string normalized(input);
    for (char& character : normalized) {
        character = static_cast<char>(std::toupper(static_cast<unsigned char>(character)));
        if (character == 'O') character = '0';
        else if (character == 'I' || character == 'L') character = '1';
    }
    if (normalized[0] != 'S') return false;
    const size_t version_position = kC32Alphabet.find(normalized[1]);
    if (version_position == std::string_view::npos ||
        (version_position != 20 && version_position != 21 && version_position != 22 &&
         version_position != 26)) {
        return false;
    }
    std::vector<uint8_t> decoded;
    if (!decode_base_n(std::string_view(normalized).substr(2), kC32Alphabet, 32, decoded) ||
        decoded.size() != 24) {
        return false;
    }
    std::vector<uint8_t> checksum_input;
    checksum_input.reserve(21);
    checksum_input.push_back(static_cast<uint8_t>(version_position));
    checksum_input.insert(checksum_input.end(), decoded.begin(), decoded.begin() + 20);
    const auto checksum = sha256d(checksum_input.data(), checksum_input.size());
    if (!bytes_equal(checksum.data(), decoded.data() + 20, 4)) return false;
    output.assign(decoded.begin(), decoded.begin() + 20);
    return true;
}

bool decode_ton(std::string_view input, std::vector<uint8_t>& output) {
    output.clear();
    const size_t colon = input.find(':');
    if (colon != std::string_view::npos) {
        if (input.find(':', colon + 1) != std::string_view::npos) return false;
        const std::string workchain(input.substr(0, colon));
        try {
            size_t parsed = 0;
            const long value = std::stol(workchain, &parsed, 10);
            if (parsed != workchain.size() || value < -128 || value > 127) return false;
        } catch (const std::exception&) {
            return false;
        }
        return decode_hex_size(input.substr(colon + 1), 32, output);
    }
    if (decode_hex_size(input, 32, output)) return true;

    std::vector<uint8_t> decoded;
    if (!decode_base64(input, decoded) || decoded.size() != 36) return false;
    const uint8_t tag = decoded[0];
    if (tag != 0x11 && tag != 0x51 && tag != 0x91 && tag != 0xd1) return false;
    const uint16_t checksum = crc16_xmodem(decoded.data(), 34);
    const uint16_t encoded = (static_cast<uint16_t>(decoded[34]) << 8) | decoded[35];
    if (checksum != encoded) return false;
    output.assign(decoded.begin() + 2, decoded.begin() + 34);
    return true;
}

bool decode_tron(std::string_view input, std::vector<uint8_t>& output) {
    if (decode_hex_size(input, 20, output)) return true;
    std::vector<uint8_t> payload;
    if (!decode_base58check(input, kBase58Alphabet, payload) || payload.size() != 21 ||
        payload[0] != 0x41) {
        return false;
    }
    output.assign(payload.begin() + 1, payload.end());
    return true;
}

bool decode_xrp(std::string_view input, std::vector<uint8_t>& output) {
    if (decode_hex_size(input, 20, output)) return true;
    std::vector<uint8_t> payload;
    if (!decode_base58check(input, kRippleAlphabet, payload) || payload.size() != 21 ||
        payload[0] != 0) {
        return false;
    }
    output.assign(payload.begin() + 1, payload.end());
    return true;
}

bool decode_tezos(std::string_view input, std::vector<uint8_t>& output) {
    output.clear();
    std::vector<uint8_t> payload;
    if (!decode_base58check(input, kBase58Alphabet, payload) || payload.size() != 23) return false;
    static constexpr uint8_t tz1[3] = {6, 161, 159};
    static constexpr uint8_t tz2[3] = {6, 161, 161};
    if (!bytes_equal(payload.data(), tz1, 3) && !bytes_equal(payload.data(), tz2, 3)) return false;
    output.assign(payload.begin() + 3, payload.end());
    return true;
}

}  // namespace address_tools
