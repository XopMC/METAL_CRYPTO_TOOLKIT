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

static inline int ms_compare(
    const thread ulong left[4],
    const thread ulong right[4]) {
    for (int i = 3; i >= 0; --i) {
        if (left[uint(i)] < right[uint(i)]) return -1;
        if (left[uint(i)] > right[uint(i)]) return 1;
    }
    return 0;
}

static inline void ms_subtract(
    thread ulong left[4],
    const thread ulong right[4]) {
    ulong borrow = 0ul;
    for (uint i = 0u; i < 4u; ++i) {
        const ulong with_borrow = right[i] + borrow;
        const bool overflow = with_borrow < right[i];
        const ulong current = left[i];
        left[i] = current - with_borrow;
        borrow = (overflow || current < with_borrow) ? 1ul : 0ul;
    }
}

static inline bool ms_mul_small(
    const thread ulong value[4],
    uint multiplier,
    thread ulong result[4]) {
    ulong carry = 0ul;
    for (uint i = 0u; i < 4u; ++i) {
        const ulong low = value[i] * ulong(multiplier);
        const ulong high = mulhi(value[i], ulong(multiplier));
        const ulong sum = low + carry;
        const ulong add_carry = sum < low ? 1ul : 0ul;
        result[i] = sum;
        carry = high + add_carry;
    }
    return carry == 0ul;
}

static inline void ms_div_small(
    const thread ulong value[4],
    uint divisor,
    thread ulong quotient[4]) {
    for (uint i = 0u; i < 4u; ++i) quotient[i] = 0ul;
    ulong remainder = 0ul;
    for (int limb = 3; limb >= 0; --limb) {
        const ulong source = value[uint(limb)];
        ulong q = 0ul;
        for (int bit = 63; bit >= 0; --bit) {
            remainder =
                (remainder << 1u) |
                ((source >> uint(bit)) & 1ul);
            if (remainder >= ulong(divisor)) {
                remainder -= ulong(divisor);
                q |= 1ul << uint(bit);
            }
        }
        quotient[uint(limb)] = q;
    }
}

static inline bool ms_mul_div(
    const thread ulong value[4],
    uint multiplier,
    uint divisor,
    thread ulong result[4]) {
    ulong product[4];
    if (!ms_mul_small(value, multiplier, product)) return false;
    ms_div_small(product, divisor, result);
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
        ms_compare(rank, total) >= 0) {
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
            ulong branch[4];
            if (!ms_mul_div(
                    total, multiplicity, remaining, branch)) {
                return;
            }
            if (ms_compare(rank, branch) < 0) {
                if ((allowed_masks[slot] &
                     (1u << candidate)) == 0u) {
                    return;
                }
                ids[position] = unique_ids[candidate];
                counts[candidate] =
                    ushort(multiplicity - 1u);
                for (uint i = 0u; i < 4u; ++i) {
                    total[i] = branch[i];
                }
                selected = true;
                break;
            }
            ms_subtract(rank, branch);
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
