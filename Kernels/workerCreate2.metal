#include "GPUHash.metalh"

using namespace metal;

struct Create2Pattern {
    uint length;
    uint reserved;
    uchar text[48];
};

struct Create2Hit {
    uchar salt[32];
    uint pattern_index;
    uint reserved;
    uchar address[20];
};

constant char CREATE2_HEX[] = "0123456789abcdef";

static inline void create2_copy32(thread uchar out[32],
                                  const device uchar* in) {
#pragma unroll
    for (uint i = 0u; i < 32u; ++i) out[i] = in[i];
}

static inline bool create2_add_index(thread uchar value[32], ulong addend) {
    ulong carry = addend;
    for (int i = 31; i >= 0 && carry != 0ul; --i) {
        const ulong sum = ulong(value[i]) + (carry & 0xfful);
        value[i] = uchar(sum & 0xfful);
        carry = (carry >> 8u) + (sum >> 8u);
    }
    return carry == 0ul;
}

static inline void create2_materialize_salt(
        const thread uchar ordinal[32],
        const device uchar* salt_template,
        const device uchar* unknown_positions,
        uint unknown_count,
        uint template_enabled,
        thread uchar salt[32]) {
    if (template_enabled == 0u) {
#pragma unroll
        for (uint i = 0u; i < 32u; ++i) salt[i] = ordinal[i];
        return;
    }
#pragma unroll
    for (uint i = 0u; i < 32u; ++i) salt[i] = salt_template[i];
    for (uint i = 0u; i < unknown_count; ++i) {
        const uint source_nibble = unknown_count - 1u - i;
        const uint source_byte = 31u - source_nibble / 2u;
        const uint source_shift = (source_nibble & 1u) * 4u;
        const uchar nibble =
            uchar((ordinal[source_byte] >> source_shift) & 0x0fu);
        const uint target_nibble = uint(unknown_positions[i]);
        const uint target_byte = target_nibble / 2u;
        if ((target_nibble & 1u) == 0u) {
            salt[target_byte] =
                uchar((salt[target_byte] & 0x0fu) | (nibble << 4u));
        } else {
            salt[target_byte] =
                uchar((salt[target_byte] & 0xf0u) | nibble);
        }
    }
}

static inline bool create2_glob_match(
        const thread uchar address[42],
        const device Create2Pattern& pattern) {
    uint source = 0u;
    uint token = 0u;
    int star = -1;
    uint restart = 0u;
    while (source < 42u) {
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

kernel void create2Search(
        const device uchar* base_ordinal [[buffer(0)]],
        constant ulong& range_count [[buffer(1)]],
        const device uchar* deployer [[buffer(2)]],
        const device uchar* init_code_hash [[buffer(3)]],
        const device uchar* salt_template [[buffer(4)]],
        const device uchar* unknown_positions [[buffer(5)]],
        constant uint& unknown_count [[buffer(6)]],
        constant uint& template_enabled [[buffer(7)]],
        const device Create2Pattern* patterns [[buffer(8)]],
        constant uint& pattern_count [[buffer(9)]],
        device Create2Hit* hits [[buffer(10)]],
        device atomic_uint* hit_count [[buffer(11)]],
        constant uint& hit_capacity [[buffer(12)]],
        uint tid [[thread_position_in_grid]]) {
    const ulong index = ulong(tid);
    if (index >= range_count || pattern_count == 0u) return;

    uchar ordinal[32];
    create2_copy32(ordinal, base_ordinal);
    if (!create2_add_index(ordinal, index)) return;

    uchar salt[32];
    create2_materialize_salt(
        ordinal, salt_template, unknown_positions,
        unknown_count, template_enabled, salt);

    uchar message[85];
    message[0] = 0xffu;
#pragma unroll
    for (uint i = 0u; i < 20u; ++i) message[1u + i] = deployer[i];
#pragma unroll
    for (uint i = 0u; i < 32u; ++i) message[21u + i] = salt[i];
#pragma unroll
    for (uint i = 0u; i < 32u; ++i) {
        message[53u + i] = init_code_hash[i];
    }

    uchar digest[32];
    keccak(reinterpret_cast<thread char*>(message), 85, digest, 32);
    uchar address[42];
    address[0] = '0';
    address[1] = 'x';
#pragma unroll
    for (uint i = 0u; i < 20u; ++i) {
        const uchar byte = digest[12u + i];
        address[2u + 2u * i] = uchar(CREATE2_HEX[byte >> 4u]);
        address[3u + 2u * i] = uchar(CREATE2_HEX[byte & 0x0fu]);
    }

    for (uint i = 0u; i < pattern_count; ++i) {
        if (!create2_glob_match(address, patterns[i])) continue;
        const uint slot = atomic_fetch_add_explicit(
            hit_count, 1u, memory_order_relaxed);
        if (slot >= hit_capacity) continue;
#pragma unroll
        for (uint j = 0u; j < 32u; ++j) hits[slot].salt[j] = salt[j];
        hits[slot].pattern_index = i;
        hits[slot].reserved = 0u;
#pragma unroll
        for (uint j = 0u; j < 20u; ++j) {
            hits[slot].address[j] = digest[12u + j];
        }
    }
}
