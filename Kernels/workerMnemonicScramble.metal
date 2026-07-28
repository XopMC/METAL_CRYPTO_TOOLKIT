#include <metal_stdlib>
#include "WorkerRecoveryCommon.metalh"

using namespace metal;

static inline bool ms_add_u64(thread ulong value[4], ulong addend) {
    const ulong old = value[0];
    value[0] += addend;
    ulong carry = value[0] < old ? 1ul : 0ul;
    for (uint i = 1u; i < 4u && carry != 0ul; ++i) {
        const ulong previous = value[i];
        value[i] += carry;
        carry = value[i] < previous ? 1ul : 0ul;
    }
    return carry == 0ul;
}

static inline int ms_compare_u256(
    const thread ulong left[4],
    const thread ulong right[4]) {
    for (int i = 3; i >= 0; --i) {
        if (left[uint(i)] < right[uint(i)]) return -1;
        if (left[uint(i)] > right[uint(i)]) return 1;
    }
    return 0;
}

struct MsU96 {
    uint words[3];
};

static inline bool ms_u96_from_u256(
    const thread ulong value[4],
    thread MsU96& result) {
    if (value[2] != 0ul || value[3] != 0ul ||
        (value[1] >> 32u) != 0ul) {
        return false;
    }
    result.words[0] = uint(value[0]);
    result.words[1] = uint(value[0] >> 32u);
    result.words[2] = uint(value[1]);
    return true;
}

static inline int ms_compare_u96(
    const thread MsU96& left,
    const thread MsU96& right) {
    for (int i = 2; i >= 0; --i) {
        if (left.words[uint(i)] < right.words[uint(i)]) return -1;
        if (left.words[uint(i)] > right.words[uint(i)]) return 1;
    }
    return 0;
}

static inline void ms_subtract_u96(
    thread MsU96& left,
    const thread MsU96& right) {
    uint borrow = 0u;
    for (uint i = 0u; i < 3u; ++i) {
        const ulong subtrahend =
            ulong(right.words[i]) + ulong(borrow);
        const ulong current = ulong(left.words[i]);
        left.words[i] = uint(current - subtrahend);
        borrow = current < subtrahend ? 1u : 0u;
    }
}

static inline bool ms_mul_small_u96(
    const thread MsU96& value,
    uint multiplier,
    thread MsU96& result) {
    ulong carry = 0ul;
    for (uint i = 0u; i < 3u; ++i) {
        const ulong product =
            ulong(value.words[i]) * ulong(multiplier) + carry;
        result.words[i] = uint(product);
        carry = product >> 32u;
    }
    return carry == 0ul;
}

static inline void ms_div_small_u96(
    const thread MsU96& value,
    uint divisor,
    thread MsU96& quotient) {
    ulong remainder = 0ul;
    for (int i = 2; i >= 0; --i) {
        const ulong dividend =
            (remainder << 32u) | ulong(value.words[uint(i)]);
        quotient.words[uint(i)] =
            uint(dividend / ulong(divisor));
        remainder = dividend % ulong(divisor);
    }
}

static inline bool ms_mul_div_u96(
    const thread MsU96& value,
    uint multiplier,
    uint divisor,
    thread MsU96& result) {
    MsU96 product;
    if (!ms_mul_small_u96(value, multiplier, product)) return false;
    ms_div_small_u96(product, divisor, result);
    return true;
}

kernel void workerMnemonicScramble(
    const device ushort* unique_ids [[buffer(0)]],
    const device ushort* initial_counts [[buffer(1)]],
    constant uint& unique_count [[buffer(2)]],
    const device ushort* output_template [[buffer(3)]],
    constant uint& words_count [[buffer(4)]],
    const device ushort* movable_positions [[buffer(5)]],
    constant uint& movable_count [[buffer(6)]],
    const device uint* allowed_masks [[buffer(7)]],
    const device ulong* base_ordinal [[buffer(8)]],
    const device ulong* domain_size [[buffer(9)]],
    constant ulong& range_count [[buffer(10)]],
    device ushort* out_ids [[buffer(11)]],
    device atomic_uint* out_count [[buffer(12)]],
    constant uint& out_capacity [[buffer(13)]],
    uint tid [[thread_position_in_grid]]) {
    if (ulong(tid) >= range_count ||
        unique_ids == nullptr || initial_counts == nullptr ||
        output_template == nullptr || movable_positions == nullptr ||
        allowed_masks == nullptr || base_ordinal == nullptr ||
        domain_size == nullptr || out_ids == nullptr || out_count == nullptr ||
        unique_count == 0u || unique_count > 24u ||
        words_count == 0u || words_count > 24u ||
        (words_count % 3u) != 0u || movable_count > words_count) {
        return;
    }

    ulong rank[4];
    ulong total[4];
    for (uint i = 0u; i < 4u; ++i) {
        rank[i] = base_ordinal[i];
        total[i] = domain_size[i];
    }
    if (!ms_add_u64(rank, ulong(tid)) ||
        ms_compare_u256(rank, total) >= 0) {
        return;
    }
    MsU96 rank96;
    MsU96 total96;
    if (!ms_u96_from_u256(rank, rank96) ||
        !ms_u96_from_u256(total, total96)) {
        return;
    }

    thread ushort ids[48];
    thread ushort counts[24];
    for (uint i = 0u; i < words_count; ++i) {
        ids[i] = output_template[i];
    }
    for (uint i = 0u; i < unique_count; ++i) {
        counts[i] = initial_counts[i];
    }

    uint remaining = movable_count;
    for (uint slot = 0u; slot < movable_count; ++slot) {
        const uint position = uint(movable_positions[slot]);
        if (position >= words_count || remaining == 0u) return;
        bool selected = false;
        for (uint candidate = 0u; candidate < unique_count; ++candidate) {
            const uint multiplicity = uint(counts[candidate]);
            if (multiplicity == 0u) continue;
            MsU96 branch;
            if (!ms_mul_div_u96(
                    total96, multiplicity, remaining, branch)) {
                return;
            }
            if (ms_compare_u96(rank96, branch) < 0) {
                if ((allowed_masks[slot] &
                     (1u << candidate)) == 0u) {
                    return;
                }
                ids[position] = unique_ids[candidate];
                counts[candidate] =
                    ushort(multiplicity - 1u);
                total96 = branch;
                selected = true;
                break;
            }
            ms_subtract_u96(rank96, branch);
        }
        if (!selected) return;
        --remaining;
    }
    if (remaining != 0u ||
        !recovery_checksum_valid_ids_dyn(
            ids, int(words_count))) {
        return;
    }

    const uint out_slot = atomic_fetch_add_explicit(
        out_count, 1u, memory_order_relaxed);
    if (out_slot >= out_capacity) return;
    device ushort* output =
        out_ids + size_t(out_slot) * size_t(words_count);
    for (uint i = 0u; i < words_count; ++i) {
        output[i] = ids[i];
    }
}
