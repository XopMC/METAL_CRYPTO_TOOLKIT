#include <metal_stdlib>
using namespace metal;

#include "WorkerPrivCommon.metalh"

struct HammingTarget {
    ulong prefix;
    uint source_index;
    uint reserved;
    uchar key[33];
    uchar padding[15];
};

struct HammingHit {
    ulong ordinal[4];
    uint target_index;
    uint reserved;
    uchar private_key[32];
    uchar public_key[33];
    uchar padding[7];
};

static inline bool hm_add_u64(thread ulong value[4], ulong addend) {
    const ulong previous = value[0];
    value[0] += addend;
    ulong carry = value[0] < previous ? 1ul : 0ul;
    for (uint i = 1u; i < 4u && carry != 0ul; ++i) {
        const ulong old = value[i];
        value[i] += carry;
        carry = value[i] < old ? 1ul : 0ul;
    }
    return carry == 0ul;
}

static inline int hm_compare(
    const thread ulong left[4],
    const device ulong* right) {
    for (int i = 3; i >= 0; --i) {
        const ulong r = right[uint(i)];
        if (left[uint(i)] < r) return -1;
        if (left[uint(i)] > r) return 1;
    }
    return 0;
}

static inline void hm_subtract(
    thread ulong left[4],
    const device ulong* right) {
    ulong borrow = 0ul;
    for (uint i = 0u; i < 4u; ++i) {
        const ulong r = right[i];
        const ulong with_borrow = r + borrow;
        const bool overflow = with_borrow < r;
        const ulong current = left[i];
        left[i] = current - with_borrow;
        borrow = (overflow || current < with_borrow) ? 1ul : 0ul;
    }
}

static inline const device ulong* hm_choose(
    const device ulong* table,
    uint n,
    uint k) {
    return table + (ulong(n) * 257ul + ulong(k)) * 4ul;
}

static inline ulong hm_prefix(const thread uchar key[33]) {
    ulong result = 0ul;
    for (uint i = 0u; i < 8u; ++i) {
        result = (result << 8u) | ulong(key[i]);
    }
    return result;
}

static inline bool hm_equal_key(
    const thread uchar key[33],
    const device uchar* candidate) {
    for (uint i = 0u; i < 33u; ++i) {
        if (key[i] != candidate[i]) return false;
    }
    return true;
}

static inline int hm_find_target(
    const thread uchar key[33],
    const device HammingTarget* targets,
    uint target_count) {
    const ulong prefix = hm_prefix(key);
    uint low = 0u;
    uint high = target_count;
    while (low < high) {
        const uint middle = low + ((high - low) >> 1u);
        if (targets[middle].prefix < prefix) low = middle + 1u;
        else high = middle;
    }
    for (uint i = low;
         i < target_count && targets[i].prefix == prefix;
         ++i) {
        if (hm_equal_key(key, targets[i].key)) return int(i);
    }
    return -1;
}

kernel void workerHamming(
    const constant secp256k1_ge_storage* precompute [[buffer(0)]],
    constant ulong& pitch_value [[buffer(1)]],
    constant uint& window_count [[buffer(2)]],
    constant uint& window_bits [[buffer(3)]],
    const device uchar* base_key [[buffer(4)]],
    const device uchar* mutable_bits [[buffer(5)]],
    constant uint& mutable_count [[buffer(6)]],
    constant uint& distance [[buffer(7)]],
    const device ulong* choose_table [[buffer(8)]],
    const device ulong* base_ordinal [[buffer(9)]],
    const device HammingTarget* targets [[buffer(10)]],
    constant uint& target_count [[buffer(11)]],
    device HammingHit* hits [[buffer(12)]],
    device atomic_uint* hit_count [[buffer(13)]],
    constant uint& hit_capacity [[buffer(14)]],
    constant ulong& candidate_count [[buffer(15)]],
    uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= candidate_count ||
        mutable_count > 256u ||
        distance > mutable_count) {
        return;
    }

    ulong ordinal[4];
    for (uint i = 0u; i < 4u; ++i) ordinal[i] = base_ordinal[i];
    if (!hm_add_u64(ordinal, ulong(tid))) return;
    ulong rank[4];
    for (uint i = 0u; i < 4u; ++i) rank[i] = ordinal[i];

    uchar private_key[32];
    for (uint i = 0u; i < 32u; ++i) private_key[i] = base_key[i];
    uint remaining = distance;
    for (uint position = 0u;
         position < mutable_count && remaining != 0u;
         ++position) {
        const uint available = mutable_count - position - 1u;
        if (remaining > available + 1u) return;
        const device ulong* selected_count =
            hm_choose(choose_table, available, remaining - 1u);
        if (hm_compare(rank, selected_count) < 0) {
            const uint bit = uint(mutable_bits[position]);
            private_key[bit >> 3u] ^=
                uchar(0x80u >> (bit & 7u));
            --remaining;
        } else {
            hm_subtract(rank, selected_count);
        }
    }
    if (remaining != 0u) return;

    secp256k1_scalar scalar;
    if (!secp256k1_scalar_set_b32_seckey(&scalar, private_key)) return;
    secp256k1_gej jacobian;
    secp256k1_ecmult_big(
        &jacobian, &scalar, precompute, size_t(pitch_value),
        int(window_count), window_bits);
    if (jacobian.infinity != 0) return;
    secp256k1_ge affine;
    secp256k1_ge_set_gej(&affine, &jacobian);
    secp256k1_pubkey point;
    secp256k1_pubkey_save(&point, &affine);
    uchar public_key[33];
    if (secp256k1_ec_pubkey_serialize(
            public_key, 33u, &point, true) == 0) {
        return;
    }
    const int target_index =
        hm_find_target(public_key, targets, target_count);
    if (target_index < 0) return;

    const uint slot = atomic_fetch_add_explicit(
        hit_count, 1u, memory_order_relaxed);
    if (slot >= hit_capacity) return;
    for (uint i = 0u; i < 4u; ++i) hits[slot].ordinal[i] = ordinal[i];
    hits[slot].target_index = uint(target_index);
    hits[slot].reserved = 0u;
    for (uint i = 0u; i < 32u; ++i) {
        hits[slot].private_key[i] = private_key[i];
    }
    for (uint i = 0u; i < 33u; ++i) {
        hits[slot].public_key[i] = public_key[i];
    }
}
