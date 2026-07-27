#include "../lib/secp256k1/secp256k1.metalh"
#include "GPUHash.metalh"

using namespace metal;

enum VanityFamily : uint {
    VANITY_P2PKH_COMPRESSED = 1u,
    VANITY_P2SH_P2WPKH = 2u,
    VANITY_BECH32_P2WPKH = 3u,
    VANITY_ETHEREUM = 4u,
    VANITY_TRON = 5u,
    VANITY_P2PKH_UNCOMPRESSED = 6u,
};

struct VanityPattern {
    uint family;
    uint length;
    uchar text[96];
};

struct VanityHit {
    uchar scalar[32];
    uint pattern_index;
    uint family;
    uint address_length;
    uchar address[96];
};

constant uint VANITY_THREAD_CANDIDATES = 8u;
constant char VANITY_BASE58_ALPHABET[] =
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
constant char VANITY_BECH32_ALPHABET[] =
    "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
constant char VANITY_HEX_ALPHABET[] = "0123456789abcdef";

static inline void vanity_copy32(thread uchar out[32],
                                 const device uchar* in) {
    for (uint i = 0u; i < 32u; ++i) out[i] = in[i];
}

static inline bool vanity_add_index(thread uchar value[32], ulong addend) {
    ulong carry = addend;
    for (int i = 31; i >= 0 && carry != 0ul; --i) {
        const ulong sum = ulong(value[i]) + (carry & 0xfful);
        value[i] = uchar(sum & 0xfful);
        carry = (carry >> 8u) + (sum >> 8u);
    }
    return carry == 0ul;
}

static inline uint vanity_base58check(uchar version,
                                      const thread uchar body[20],
                                      thread uchar out[96]) {
    uchar payload[25];
    payload[0] = version;
    for (uint i = 0u; i < 20u; ++i) payload[1u + i] = body[i];
    uchar first[32];
    uchar second[32];
    SHA256(payload, 21u, first);
    SHA256(first, 32u, second);
    for (uint i = 0u; i < 4u; ++i) payload[21u + i] = second[i];

    uchar digits[40] = {};
    uint digit_count = 1u;
    uint leading_zeroes = 0u;
    while (leading_zeroes < 25u && payload[leading_zeroes] == 0u) {
        ++leading_zeroes;
    }
    for (uint i = 0u; i < 25u; ++i) {
        uint carry = uint(payload[i]);
        for (uint j = 0u; j < digit_count; ++j) {
            carry += uint(digits[j]) << 8u;
            digits[j] = uchar(carry % 58u);
            carry /= 58u;
        }
        while (carry != 0u && digit_count < 40u) {
            digits[digit_count++] = uchar(carry % 58u);
            carry /= 58u;
        }
    }
    uint length = 0u;
    for (uint i = 0u; i < leading_zeroes; ++i) out[length++] = '1';
    for (int i = int(digit_count) - 1; i >= 0; --i) {
        out[length++] = uchar(VANITY_BASE58_ALPHABET[digits[i]]);
    }
    return length;
}

static inline uint vanity_bech32_polymod_step(uint value) {
    const uint top = value >> 25u;
    value = (value & 0x1ffffffu) << 5u;
    value ^= (0u - ((top >> 0u) & 1u)) & 0x3b6a57b2u;
    value ^= (0u - ((top >> 1u) & 1u)) & 0x26508e6du;
    value ^= (0u - ((top >> 2u) & 1u)) & 0x1ea119fau;
    value ^= (0u - ((top >> 3u) & 1u)) & 0x3d4233ddu;
    value ^= (0u - ((top >> 4u) & 1u)) & 0x2a1462b3u;
    return value;
}

static inline uint vanity_bech32_p2wpkh(const thread uchar program[20],
                                        thread uchar out[96]) {
    uchar data[33] = {};
    uint accumulator = 0u;
    uint bits = 0u;
    uint data_length = 1u;
    data[0] = 0u;
    for (uint i = 0u; i < 20u; ++i) {
        accumulator = (accumulator << 8u) | uint(program[i]);
        bits += 8u;
        while (bits >= 5u) {
            bits -= 5u;
            data[data_length++] =
                uchar((accumulator >> bits) & 31u);
        }
    }
    if (bits != 0u) {
        data[data_length++] =
            uchar((accumulator << (5u - bits)) & 31u);
    }

    uint checksum = 1u;
    checksum = vanity_bech32_polymod_step(checksum) ^ uint('b' >> 5);
    checksum = vanity_bech32_polymod_step(checksum) ^ uint('c' >> 5);
    checksum = vanity_bech32_polymod_step(checksum);
    checksum = vanity_bech32_polymod_step(checksum) ^ uint('b' & 31);
    checksum = vanity_bech32_polymod_step(checksum) ^ uint('c' & 31);
    for (uint i = 0u; i < data_length; ++i) {
        checksum = vanity_bech32_polymod_step(checksum) ^ uint(data[i]);
    }
    for (uint i = 0u; i < 6u; ++i) {
        checksum = vanity_bech32_polymod_step(checksum);
    }
    checksum ^= 1u;

    uint length = 0u;
    out[length++] = 'b';
    out[length++] = 'c';
    out[length++] = '1';
    for (uint i = 0u; i < data_length; ++i) {
        out[length++] = uchar(VANITY_BECH32_ALPHABET[data[i]]);
    }
    for (uint i = 0u; i < 6u; ++i) {
        const uint shift = 5u * (5u - i);
        out[length++] =
            uchar(VANITY_BECH32_ALPHABET[(checksum >> shift) & 31u]);
    }
    return length;
}

static inline uint vanity_ethereum(const thread uchar body[20],
                                   thread uchar out[96]) {
    out[0] = '0';
    out[1] = 'x';
    for (uint i = 0u; i < 20u; ++i) {
        out[2u + 2u * i] =
            uchar(VANITY_HEX_ALPHABET[body[i] >> 4u]);
        out[3u + 2u * i] =
            uchar(VANITY_HEX_ALPHABET[body[i] & 15u]);
    }
    return 42u;
}

static inline bool vanity_glob_match(const thread uchar* address,
                                     uint address_length,
                                     const device VanityPattern& pattern) {
    uint source = 0u;
    uint token = 0u;
    int star = -1;
    uint restart = 0u;
    while (source < address_length) {
        if (token < pattern.length &&
            (pattern.text[token] == '?' ||
             pattern.text[token] == address[source])) {
            ++source;
            ++token;
            continue;
        }
        if (token < pattern.length && pattern.text[token] == '*') {
            star = int(token++);
            restart = source;
            continue;
        }
        if (star >= 0) {
            token = uint(star + 1);
            source = ++restart;
            continue;
        }
        return false;
    }
    while (token < pattern.length && pattern.text[token] == '*') ++token;
    return token == pattern.length;
}

static inline void vanity_emit_matches(
        const thread uchar scalar[32],
        uint family,
        const thread uchar* address,
        uint address_length,
        const device VanityPattern* patterns,
        uint pattern_count,
        device VanityHit* hits,
        device atomic_uint* hit_count,
        uint hit_capacity) {
    for (uint i = 0u; i < pattern_count; ++i) {
        if (patterns[i].family != family ||
            !vanity_glob_match(address, address_length, patterns[i])) {
            continue;
        }
        const uint slot = atomic_fetch_add_explicit(
            hit_count, 1u, memory_order_relaxed);
        if (slot >= hit_capacity) continue;
        for (uint j = 0u; j < 32u; ++j) hits[slot].scalar[j] = scalar[j];
        hits[slot].pattern_index = i;
        hits[slot].family = family;
        hits[slot].address_length = address_length;
        for (uint j = 0u; j < address_length; ++j) {
            hits[slot].address[j] = address[j];
        }
        for (uint j = address_length; j < 96u; ++j) {
            hits[slot].address[j] = 0u;
        }
    }
}

kernel void vanitySearch(
        const device uchar* base_scalar [[buffer(0)]],
        constant ulong& range_count [[buffer(1)]],
        const device VanityPattern* patterns [[buffer(2)]],
        constant uint& pattern_count [[buffer(3)]],
        constant uint& family_mask [[buffer(4)]],
        const device uchar* split_public_xy [[buffer(5)]],
        constant uint& split_enabled [[buffer(6)]],
        const constant secp256k1_ge_storage* prec [[buffer(7)]],
        constant ulong& prec_pitch [[buffer(8)]],
        constant uint& prec_windows [[buffer(9)]],
        constant uint& prec_window_bits [[buffer(10)]],
        device VanityHit* hits [[buffer(11)]],
        device atomic_uint* hit_count [[buffer(12)]],
        constant uint& hit_capacity [[buffer(13)]],
        uint tid [[thread_position_in_grid]]) {
    const ulong first = ulong(tid) * ulong(VANITY_THREAD_CANDIDATES);
    if (first >= range_count || pattern_count == 0u) return;

    secp256k1_ge split_point;
    if (split_enabled != 0u) {
        uchar split_x[32];
        uchar split_y[32];
#pragma unroll
        for (uint i = 0u; i < 32u; ++i) {
            split_x[i] = split_public_xy[i];
            split_y[i] = split_public_xy[32u + i];
        }
        if (!secp256k1_fe_set_b32(&split_point.x, split_x) ||
            !secp256k1_fe_set_b32(&split_point.y, split_y)) {
            return;
        }
        split_point.infinity = 0;
    }

    uchar scalars[VANITY_THREAD_CANDIDATES][32];
    secp256k1_gej jacobians[VANITY_THREAD_CANDIDATES];
    secp256k1_fe input_z[VANITY_THREAD_CANDIDATES];
    secp256k1_fe inverse_z[VANITY_THREAD_CANDIDATES];
    uint inverse_index[VANITY_THREAD_CANDIDATES];
    uint valid_count = 0u;
    secp256k1_ge generator = secp256k1_ge_const_g;
    secp256k1_gej walk;
    bool walk_ready = false;

#pragma unroll
    for (uint lane = 0u; lane < VANITY_THREAD_CANDIDATES; ++lane) {
        inverse_index[lane] = UINT_MAX;
        const ulong candidate_index = first + ulong(lane);
        if (candidate_index >= range_count) continue;
        vanity_copy32(scalars[lane], base_scalar);
        if (!vanity_add_index(scalars[lane], candidate_index)) continue;
        if (!walk_ready) {
            secp256k1_scalar scalar;
            if (!secp256k1_scalar_set_b32_seckey(
                    &scalar, scalars[lane])) {
                continue;
            }
            secp256k1_ecmult_big(
                &walk, &scalar, prec, size_t(prec_pitch),
                int(prec_windows), prec_window_bits);
            if (split_enabled != 0u) {
                secp256k1_gej combined;
                secp256k1_gej_add_ge_var(
                    &combined, &walk, &split_point, nullptr);
                walk = combined;
            }
            walk_ready = true;
        } else {
            secp256k1_gej next;
            secp256k1_gej_add_ge_var(
                &next, &walk, &generator, nullptr);
            walk = next;
        }
        jacobians[lane] = walk;
        if (jacobians[lane].infinity != 0) continue;
        inverse_index[lane] = valid_count;
        input_z[valid_count] = jacobians[lane].z;
        ++valid_count;
    }
    if (valid_count == 0u) return;
    secp256k1_fe_inv_all_var(valid_count, inverse_z, input_z);

#pragma unroll
    for (uint lane = 0u; lane < VANITY_THREAD_CANDIDATES; ++lane) {
        const uint z_index = inverse_index[lane];
        if (z_index == UINT_MAX) continue;
        secp256k1_ge point;
        secp256k1_ge_set_gej_zinv(
            &point, &jacobians[lane], &inverse_z[z_index]);
        secp256k1_fe_normalize_var(&point.x);
        secp256k1_fe_normalize_var(&point.y);
        uchar public_key[65];
        public_key[0] = 0x04u;
        secp256k1_fe_get_b32(public_key + 1u, &point.x);
        secp256k1_fe_get_b32(public_key + 33u, &point.y);

        uint compressed_words[8] = {};
        uchar compressed_hash[20];
        bool compressed_ready = false;
        if ((family_mask &
             ((1u << VANITY_P2PKH_COMPRESSED) |
              (1u << VANITY_P2SH_P2WPKH) |
              (1u << VANITY_BECH32_P2WPKH))) != 0u) {
            int skip = 0;
            _GetHash160Comp(
                public_key, skip,
                reinterpret_cast<thread uchar*>(compressed_words));
            for (uint i = 0u; i < 20u; ++i) {
                compressed_hash[i] =
                    reinterpret_cast<thread uchar*>(compressed_words)[i];
            }
            compressed_ready = true;
        }

        uchar address[96];
        uint address_length = 0u;
        if ((family_mask & (1u << VANITY_P2PKH_COMPRESSED)) != 0u &&
            compressed_ready) {
            address_length =
                vanity_base58check(0u, compressed_hash, address);
            vanity_emit_matches(
                scalars[lane], VANITY_P2PKH_COMPRESSED,
                address, address_length, patterns, pattern_count,
                hits, hit_count, hit_capacity);
        }
        if ((family_mask & (1u << VANITY_P2SH_P2WPKH)) != 0u &&
            compressed_ready) {
            uint nested_words[8] = {};
            for (uint i = 0u; i < 8u; ++i) {
                nested_words[i] = compressed_words[i];
            }
            _GetHash160P2SHCompFromHash(nested_words, nested_words);
            uchar nested[20];
            for (uint i = 0u; i < 20u; ++i) {
                nested[i] =
                    reinterpret_cast<thread uchar*>(nested_words)[i];
            }
            address_length = vanity_base58check(5u, nested, address);
            vanity_emit_matches(
                scalars[lane], VANITY_P2SH_P2WPKH,
                address, address_length, patterns, pattern_count,
                hits, hit_count, hit_capacity);
        }
        if ((family_mask & (1u << VANITY_BECH32_P2WPKH)) != 0u &&
            compressed_ready) {
            address_length =
                vanity_bech32_p2wpkh(compressed_hash, address);
            vanity_emit_matches(
                scalars[lane], VANITY_BECH32_P2WPKH,
                address, address_length, patterns, pattern_count,
                hits, hit_count, hit_capacity);
        }
        if ((family_mask & (1u << VANITY_P2PKH_UNCOMPRESSED)) != 0u) {
            uint uncompressed_words[8] = {};
            int skip = 0;
            _GetHash160(
                public_key, skip,
                reinterpret_cast<thread uchar*>(uncompressed_words));
            uchar uncompressed_hash[20];
            for (uint i = 0u; i < 20u; ++i) {
                uncompressed_hash[i] =
                    reinterpret_cast<thread uchar*>(uncompressed_words)[i];
            }
            address_length =
                vanity_base58check(0u, uncompressed_hash, address);
            vanity_emit_matches(
                scalars[lane], VANITY_P2PKH_UNCOMPRESSED,
                address, address_length, patterns, pattern_count,
                hits, hit_count, hit_capacity);
        }
        if ((family_mask &
             ((1u << VANITY_ETHEREUM) |
              (1u << VANITY_TRON))) != 0u) {
            uchar digest[32];
            keccak(reinterpret_cast<thread char*>(public_key + 1u),
                   64, digest, 32);
            uchar account[20];
            for (uint i = 0u; i < 20u; ++i) account[i] = digest[12u + i];
            if ((family_mask & (1u << VANITY_ETHEREUM)) != 0u) {
                address_length = vanity_ethereum(account, address);
                vanity_emit_matches(
                    scalars[lane], VANITY_ETHEREUM,
                    address, address_length, patterns, pattern_count,
                    hits, hit_count, hit_capacity);
            }
            if ((family_mask & (1u << VANITY_TRON)) != 0u) {
                address_length =
                    vanity_base58check(0x41u, account, address);
                vanity_emit_matches(
                    scalars[lane], VANITY_TRON,
                    address, address_length, patterns, pattern_count,
                    hits, hit_count, hit_capacity);
            }
        }
    }
}
