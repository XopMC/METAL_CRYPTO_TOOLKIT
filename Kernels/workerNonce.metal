#include "../lib/secp256k1/secp256k1.metalh"

using namespace metal;

enum NonceSourceMode : uint {
    NONCE_SOURCE_RANGE = 0u,
    NONCE_SOURCE_MASK = 1u,
    NONCE_SOURCE_LIST = 2u,
};

enum NonceSignatureModel : uint {
    NONCE_MODEL_ECDSA = 1u,
    NONCE_MODEL_BIP340 = 2u,
};

struct NonceHit {
    uchar nonce[32];
    uint record_index;
    uint reserved;
};

static inline void nonce_copy32(thread uchar out[32],
                                const device uchar* in) {
    for (uint i = 0u; i < 32u; ++i) out[i] = in[i];
}

static inline bool nonce_add_tid(thread uchar value[32], uint tid) {
    ulong carry = ulong(tid);
    for (int i = 31; i >= 0 && carry != 0ul; --i) {
        const ulong sum = ulong(value[i]) + (carry & 0xfful);
        value[i] = uchar(sum & 0xfful);
        carry = (carry >> 8u) + (sum >> 8u);
    }
    return carry == 0ul;
}

static inline uint nonce_ordinal_bit(const thread uchar ordinal[32],
                                     uint bit_index) {
    if (bit_index >= 256u) return 0u;
    const uint byte_index = 31u - (bit_index >> 3u);
    return (uint(ordinal[byte_index]) >> (bit_index & 7u)) & 1u;
}

static inline bool nonce_equal32(const thread uchar left[32],
                                 const device uchar* right) {
    uint different = 0u;
    for (uint i = 0u; i < 32u; ++i) {
        different |= uint(left[i] ^ right[i]);
    }
    return different == 0u;
}

kernel void nonceSearch(const device uchar* base_nonce [[buffer(0)]],
                        const device uchar* window_ordinal [[buffer(1)]],
                        const device uint* unknown_bits [[buffer(2)]],
                        constant uint& unknown_count [[buffer(3)]],
                        const device uchar* candidate_list [[buffer(4)]],
                        constant uint& source_mode [[buffer(5)]],
                        const device uchar* target_x1 [[buffer(6)]],
                        const device uchar* target_x2 [[buffer(7)]],
                        constant uint& target_x2_valid [[buffer(8)]],
                        constant uint& signature_model [[buffer(9)]],
                        const constant secp256k1_ge_storage* prec [[buffer(10)]],
                        constant ulong& prec_pitch [[buffer(11)]],
                        constant uint& prec_windows [[buffer(12)]],
                        constant uint& prec_window_bits [[buffer(13)]],
                        constant ulong& range_count [[buffer(14)]],
                        constant uint& record_index [[buffer(15)]],
                        device NonceHit* hits [[buffer(16)]],
                        device atomic_uint* hit_count [[buffer(17)]],
                        constant uint& hit_capacity [[buffer(18)]],
                        uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= range_count) return;

    uchar nonce[32];
    if (source_mode == NONCE_SOURCE_LIST) {
        nonce_copy32(nonce, candidate_list + ulong(tid) * 32ul);
    } else if (source_mode == NONCE_SOURCE_RANGE) {
        nonce_copy32(nonce, base_nonce);
        if (!nonce_add_tid(nonce, tid)) return;
    } else if (source_mode == NONCE_SOURCE_MASK) {
        if (unknown_count > 255u) return;
        nonce_copy32(nonce, base_nonce);
        uchar ordinal[32];
        nonce_copy32(ordinal, window_ordinal);
        if (!nonce_add_tid(ordinal, tid)) return;
        for (uint i = 0u; i < unknown_count; ++i) {
            const uint destination = unknown_bits[i];
            if (destination >= 256u) return;
            const uint byte_index = 31u - (destination >> 3u);
            const uchar mask = uchar(1u << (destination & 7u));
            if (nonce_ordinal_bit(ordinal, i) != 0u) {
                nonce[byte_index] |= mask;
            } else {
                nonce[byte_index] &= uchar(~mask);
            }
        }
    } else {
        return;
    }

    secp256k1_scalar scalar;
    if (!secp256k1_scalar_set_b32_seckey(&scalar, nonce)) return;
    secp256k1_gej jacobian;
    secp256k1_ecmult_big(
        &jacobian, &scalar, prec, size_t(prec_pitch),
        int(prec_windows), prec_window_bits);
    if (jacobian.infinity != 0) return;
    secp256k1_ge point;
    secp256k1_ge_set_gej(&point, &jacobian);
    secp256k1_fe_normalize_var(&point.x);
    secp256k1_fe_normalize_var(&point.y);
    if (signature_model == NONCE_MODEL_BIP340 &&
        secp256k1_fe_is_odd(&point.y)) {
        return;
    }
    uchar x[32];
    secp256k1_fe_get_b32(x, &point.x);
    if (!nonce_equal32(x, target_x1) &&
        (target_x2_valid == 0u || !nonce_equal32(x, target_x2))) {
        return;
    }

    const uint slot = atomic_fetch_add_explicit(
        hit_count, 1u, memory_order_relaxed);
    if (slot >= hit_capacity) return;
    for (uint i = 0u; i < 32u; ++i) hits[slot].nonce[i] = nonce[i];
    hits[slot].record_index = record_index;
    hits[slot].reserved = 0u;
}
