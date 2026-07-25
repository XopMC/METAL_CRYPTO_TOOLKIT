#include "../lib/secp256k1/secp256k1.metalh"
#include "BsgsCore.metalh"
#include "../lib/secp256k1/GPUWalk.metalh"

#ifndef METAL_BSGS_TEST_FINGERPRINT_BITS
#define METAL_BSGS_TEST_FINGERPRINT_BITS 64
#endif

static inline ulong bsgs_fingerprint(ulong x) {
#if METAL_BSGS_TEST_FINGERPRINT_BITS == 0
    return 0ul;
#elif METAL_BSGS_TEST_FINGERPRINT_BITS < 64
    return x & ((1ul << METAL_BSGS_TEST_FINGERPRINT_BITS) - 1ul);
#else
    return x;
#endif
}

struct BsgsBabyEmitter {
    device BsgsBabyEntry* output;
    ulong m;
    ulong group_base;
    ulong output_base;
    ulong output_capacity;

    inline void operator()(thread ulong* x,
                           uchar odd_y,
                           int pk_field) thread {
        (void)odd_y;
        const ulong j = group_base + ulong(uint(pk_field)) + 1ul;
        const ulong slot = output_base + ulong(uint(pk_field));
        if (j == 0ul || j > m || slot >= output_capacity) {
            return;
        }
        output[slot].fingerprint = bsgs_fingerprint(x[0]);
        output[slot].j = j;
    }
};

kernel void bsgsGenerateBaby(
    device BsgsBabyEntry* output [[buffer(0)]],
    const device ulong* walk_gx [[buffer(1)]],
    const device ulong* walk_gy [[buffer(2)]],
    const device ulong* walk_2gnx [[buffer(3)]],
    const device ulong* walk_2gny [[buffer(4)]],
    constant secp256k1_ge_storage* precompute [[buffer(5)]],
    constant ulong& precompute_pitch [[buffer(6)]],
    constant BsgsBabyParams& params [[buffer(7)]],
    uint tid [[thread_position_in_grid]]) {
    const ulong group = params.group_offset + ulong(tid);
    const ulong group_base = group * ulong(BSGS_WALK_SIZE);
    if (group_base >= params.m && group_base != 0ul) {
        return;
    }
    // Shift the center by one so the first group spans 1..1024 instead of
    // touching the point at infinity at j=0 during the shared inversion.
    const ulong center_scalar =
        group_base + ulong(BSGS_WALK_SIZE / 2u) + 1ul;
    ulong scalar_limbs[4] = {center_scalar, 0ul, 0ul, 0ul};
    uchar scalar_bytes[32];
    bsgs_limbs_to_be32(scalar_limbs, scalar_bytes);
    secp256k1_scalar scalar;
    secp256k1_scalar_set_b32(&scalar, scalar_bytes, nullptr);
    secp256k1_gej center_j;
    secp256k1_ecmult_big(&center_j,
                         &scalar,
                         precompute,
                         precompute_pitch,
                         int(params.windows),
                         params.window_bits);
    if (center_j.infinity != 0) {
        return;
    }
    secp256k1_ge center;
    secp256k1_ge_set_gej(&center, &center_j);
    ulong center_x[4];
    ulong center_y[4];
    bsgs_ge_to_limbs(center, center_x, center_y);

    BsgsBabyEmitter emitter = {
        output,
        params.m,
        group_base,
        ulong(tid) * ulong(BSGS_WALK_SIZE),
        params.output_capacity
    };
    vanity_walk_batch_1024_parity(center_x,
                                  center_y,
                                  walk_gx,
                                  walk_gy,
                                  walk_2gnx,
                                  walk_2gny,
                                  false,
                                  emitter);
}

struct BsgsLookupEmitter {
    const device BsgsBabyEntry* shard0;
    const device BsgsBabyEntry* shard1;
    const device BsgsBabyEntry* shard2;
    const device BsgsBabyEntry* shard3;
    const device ulong* bucket_offsets;
    device BsgsHit* hits;
    device atomic_uint* hit_count;
    device atomic_uint* overflow;
    const constant BsgsSearchParams* params;
    ulong giant_base[4];
    ulong target_id_base;
    uint target_field_count;
    bool shifted_targets;

    inline void emit_hit(const thread ulong giant_index[4],
                         ulong j,
                         ulong target_id) thread {
        const uint slot =
            atomic_fetch_add_explicit(hit_count, 1u, memory_order_relaxed);
        if (slot >= params->hit_capacity) {
            atomic_store_explicit(overflow, 1u, memory_order_relaxed);
            return;
        }
        for (uint limb = 0u; limb < 4u; ++limb) {
            hits[slot].giant_index[limb] = giant_index[limb];
        }
        hits[slot].j = j;
        hits[slot].target_id = target_id;
    }

    inline void operator()(thread ulong* x,
                           uchar odd_y,
                           int pk_field) thread {
        (void)odd_y;
        const uint field = uint(pk_field);
        if (field < params->field_begin || field >= params->field_end) {
            return;
        }
        ulong giant_index[4];
        bsgs_copy256(giant_index, giant_base);
        ulong target_id = target_id_base;
        if (shifted_targets) {
            if (field >= target_field_count) return;
            target_id += ulong(field);
        } else {
            bsgs_u256_add_small(giant_index, ulong(field));
            if (!bsgs_u256_less(giant_index, params->giant_count)) {
                return;
            }
        }

        const ulong fingerprint = bsgs_fingerprint(x[0]);
        const ulong bucket = params->bucket_bits == 0u
            ? 0ul
            : (fingerprint >> ulong(64u - params->bucket_bits));
        ulong low = bucket_offsets[bucket];
        ulong high = bucket_offsets[bucket + 1ul];
        while (low < high) {
            const ulong middle = low + ((high - low) >> 1ul);
            const BsgsBabyEntry entry =
                bsgs_table_entry(middle,
                                 shard0,
                                 shard1,
                                 shard2,
                                 shard3,
                                 *params);
            const int comparison = bsgs_compare_key(fingerprint, entry);
            if (comparison > 0) {
                low = middle + 1ul;
            } else {
                high = middle;
            }
        }
        ulong match_ordinal = 0ul;
        for (ulong index = low; index < params->table_count; ++index) {
            const BsgsBabyEntry entry =
                bsgs_table_entry(index,
                                 shard0,
                                 shard1,
                                 shard2,
                                 shard3,
                                 *params);
            if (bsgs_compare_key(fingerprint, entry) != 0) {
                break;
            }
            if (match_ordinal >= params->match_skip) {
                emit_hit(giant_index, entry.j, target_id);
            }
            ++match_ordinal;
        }
    }
};

static inline void bsgs_emit_shifted_singular(
    uint singular_field,
    const constant BsgsSearchParams& params,
    uint field_count,
    thread BsgsLookupEmitter& emitter) {
    if (params.match_skip == 0ul &&
        singular_field < field_count &&
        singular_field >= params.field_begin &&
        singular_field < params.field_end) {
        ulong giant_index[4] = {
            emitter.giant_base[0],
            emitter.giant_base[1],
            emitter.giant_base[2],
            emitter.giant_base[3]
        };
        emitter.emit_hit(
            giant_index,
            0ul,
            emitter.target_id_base + ulong(singular_field));
    }
    if (params.match_skip == 0ul &&
        params.field_begin == 0u &&
        params.field_end == BSGS_WALK_SIZE) {
        ulong marker_index[4] = {
            emitter.giant_base[0],
            emitter.giant_base[1],
            emitter.giant_base[2],
            emitter.giant_base[3] | BSGS_SHIFTED_SINGULAR_MARKER
        };
        emitter.emit_hit(marker_index,
                         ulong(singular_field),
                         emitter.target_id_base);
    }
}

kernel void bsgsLookupGiant(
    const device BsgsBabyEntry* shard0 [[buffer(0)]],
    const device BsgsBabyEntry* shard1 [[buffer(1)]],
    const device BsgsBabyEntry* shard2 [[buffer(2)]],
    const device BsgsBabyEntry* shard3 [[buffer(3)]],
    const device ulong* targets [[buffer(4)]],
    const device BsgsWorkItem* work [[buffer(5)]],
    const device ulong* walk_gx [[buffer(6)]],
    const device ulong* walk_gy [[buffer(7)]],
    const device ulong* walk_2gnx [[buffer(8)]],
    const device ulong* walk_2gny [[buffer(9)]],
    const device BsgsCenterProbe* center_probes [[buffer(10)]],
    const device ulong* bucket_offsets [[buffer(11)]],
    constant secp256k1_ge_storage* precompute [[buffer(12)]],
    constant ulong& precompute_pitch [[buffer(13)]],
    device BsgsHit* hits [[buffer(14)]],
    device atomic_uint* hit_count [[buffer(15)]],
    device atomic_uint* overflow [[buffer(16)]],
    constant BsgsSearchParams& params [[buffer(17)]],
    uint tid [[thread_position_in_grid]]) {
    if (tid >= params.work_count) {
        return;
    }
    const device BsgsWorkItem& item = work[tid];
    const device ulong* target_limbs =
        targets + ulong(item.target_slot) * 8ul;
    secp256k1_ge target = bsgs_ge_from_limbs(target_limbs);

    ulong scalar_limbs[4];
    for (uint limb = 0u; limb < 4u; ++limb) {
        scalar_limbs[limb] = item.center_scalar[limb];
    }
    uchar scalar_bytes[32];
    bsgs_limbs_to_be32(scalar_limbs, scalar_bytes);
    secp256k1_scalar scalar;
    secp256k1_scalar_set_b32(&scalar, scalar_bytes, nullptr);

    secp256k1_gej center_j;
    if (secp256k1_scalar_is_zero(&scalar)) {
        secp256k1_gej_set_ge(&center_j, &target);
    } else {
        secp256k1_gej subtract_j;
        secp256k1_ecmult_big(&subtract_j,
                             &scalar,
                             precompute,
                             precompute_pitch,
                             int(params.windows),
                             params.window_bits);
        secp256k1_ge subtract;
        secp256k1_ge_set_gej(&subtract, &subtract_j);
        secp256k1_ge_neg(&subtract, &subtract);
        secp256k1_gej target_j;
        secp256k1_gej_set_ge(&target_j, &target);
        secp256k1_gej_add_ge_var(&center_j, &target_j, &subtract, nullptr);
    }

    BsgsLookupEmitter emitter = {
        shard0,
        shard1,
        shard2,
        shard3,
        bucket_offsets,
        hits,
        hit_count,
        overflow,
        &params,
        {item.giant_base[0],
         item.giant_base[1],
         item.giant_base[2],
         item.giant_base[3]},
        item.target_id,
        0u,
        false
    };

    if (center_j.infinity != 0) {
        const uint field = BSGS_WALK_SIZE / 2u;
        ulong center_index[4] = {
            item.giant_base[0],
            item.giant_base[1],
            item.giant_base[2],
            item.giant_base[3]
        };
        bsgs_u256_add_small(center_index, ulong(BSGS_WALK_SIZE / 2u));
        if (params.match_skip == 0ul &&
            field >= params.field_begin &&
            field < params.field_end &&
            bsgs_u256_less(center_index, params.giant_count)) {
            emitter.emit_hit(center_index, 0ul, item.target_id);
        }
        return;
    }

    secp256k1_ge center;
    secp256k1_ge_set_gej(&center, &center_j);
    ulong center_x[4];
    ulong center_y[4];
    bsgs_ge_to_limbs(center, center_x, center_y);

    // A target exactly on one of the giant centers makes one denominator in
    // the shared inversion zero. Resolve that j=0 case first so the remaining
    // walk never observes a singular batch.
    ulong probe_low = 0ul;
    ulong probe_high = ulong(BSGS_WALK_SIZE / 2u);
    while (probe_low < probe_high) {
        const ulong middle = probe_low + ((probe_high - probe_low) >> 1ul);
        const BsgsCenterProbe probe = center_probes[middle];
        if (bsgs_compare_x256(center_x, probe) > 0) {
            probe_low = middle + 1ul;
        } else {
            probe_high = middle;
        }
    }
    if (probe_low < ulong(BSGS_WALK_SIZE / 2u)) {
        const BsgsCenterProbe probe = center_probes[probe_low];
        if (bsgs_compare_x256(center_x, probe) == 0) {
            ulong center_index[4] = {
                item.giant_base[0],
                item.giant_base[1],
                item.giant_base[2],
                item.giant_base[3]
            };
            bsgs_u256_add_small(center_index,
                                ulong(BSGS_WALK_SIZE / 2u));
            const bool positive =
                uint(center_y[0] & 1ul) == probe.odd_y;
            const uint field = positive
                ? BSGS_WALK_SIZE / 2u + probe.offset
                : BSGS_WALK_SIZE / 2u - probe.offset;
            bool valid = true;
            if (positive) {
                bsgs_u256_add_small(center_index, ulong(probe.offset));
            } else {
                valid = bsgs_u256_sub_small(center_index,
                                             ulong(probe.offset));
            }
            ulong group_end[4] = {
                item.giant_base[0],
                item.giant_base[1],
                item.giant_base[2],
                item.giant_base[3]
            };
            bsgs_u256_add_small(group_end, ulong(BSGS_WALK_SIZE));
            valid = valid &&
                params.match_skip == 0ul &&
                field >= params.field_begin &&
                field < params.field_end &&
                bsgs_u256_less_thread(center_index, group_end) &&
                bsgs_u256_less(center_index, params.giant_count);
            if (valid) {
                emitter.emit_hit(center_index, 0ul, item.target_id);
            }
            return;
        }
    }
    vanity_walk_batch_1024_parity(center_x,
                                  center_y,
                                  walk_gx,
                                  walk_gy,
                                  walk_2gnx,
                                  walk_2gny,
                                  true,
                                  emitter);
}

kernel void bsgsLookupShifted(
    const device BsgsBabyEntry* shard0 [[buffer(0)]],
    const device BsgsBabyEntry* shard1 [[buffer(1)]],
    const device BsgsBabyEntry* shard2 [[buffer(2)]],
    const device BsgsBabyEntry* shard3 [[buffer(3)]],
    const device ulong* targets [[buffer(4)]],
    const device BsgsWorkItem* work [[buffer(5)]],
    const device ulong* walk_gx [[buffer(6)]],
    const device ulong* walk_gy [[buffer(7)]],
    const device ulong* walk_2gnx [[buffer(8)]],
    const device ulong* walk_2gny [[buffer(9)]],
    const device BsgsCenterProbe* center_probes [[buffer(10)]],
    const device ulong* bucket_offsets [[buffer(11)]],
    constant secp256k1_ge_storage* precompute [[buffer(12)]],
    constant ulong& precompute_pitch [[buffer(13)]],
    device BsgsHit* hits [[buffer(14)]],
    device atomic_uint* hit_count [[buffer(15)]],
    device atomic_uint* overflow [[buffer(16)]],
    constant BsgsSearchParams& params [[buffer(17)]],
    uint tid [[thread_position_in_grid]]) {
    if (tid >= params.work_count) return;
    const device BsgsWorkItem& item = work[tid];
    const device ulong* target_limbs =
        targets + ulong(item.target_slot) * 8ul;
    secp256k1_ge target = bsgs_ge_from_limbs(target_limbs);

    ulong scalar_limbs[4];
    for (uint limb = 0u; limb < 4u; ++limb) {
        scalar_limbs[limb] = item.center_scalar[limb];
    }
    uchar scalar_bytes[32];
    bsgs_limbs_to_be32(scalar_limbs, scalar_bytes);
    secp256k1_scalar scalar;
    secp256k1_scalar_set_b32(&scalar, scalar_bytes, nullptr);

    secp256k1_gej center_j;
    if (secp256k1_scalar_is_zero(&scalar)) {
        secp256k1_gej_set_ge(&center_j, &target);
    } else {
        secp256k1_gej subtract_j;
        secp256k1_ecmult_big(&subtract_j,
                             &scalar,
                             precompute,
                             precompute_pitch,
                             int(params.windows),
                             params.window_bits);
        secp256k1_ge subtract;
        secp256k1_ge_set_gej(&subtract, &subtract_j);
        secp256k1_ge_neg(&subtract, &subtract);
        secp256k1_gej target_j;
        secp256k1_gej_set_ge(&target_j, &target);
        secp256k1_gej_add_ge_var(&center_j, &target_j, &subtract, nullptr);
    }

    BsgsLookupEmitter emitter = {
        shard0,
        shard1,
        shard2,
        shard3,
        bucket_offsets,
        hits,
        hit_count,
        overflow,
        &params,
        {item.giant_base[0],
         item.giant_base[1],
         item.giant_base[2],
         item.giant_base[3]},
        item.target_id,
        item.reserved,
        true
    };

    if (center_j.infinity != 0) {
        bsgs_emit_shifted_singular(
            BSGS_WALK_SIZE / 2u,
            params,
            item.reserved,
            emitter);
        return;
    }

    secp256k1_ge center;
    secp256k1_ge_set_gej(&center, &center_j);
    ulong center_x[4];
    ulong center_y[4];
    bsgs_ge_to_limbs(center, center_x, center_y);

    ulong probe_low = 0ul;
    ulong probe_high = ulong(BSGS_WALK_SIZE / 2u);
    while (probe_low < probe_high) {
        const ulong middle = probe_low + ((probe_high - probe_low) >> 1ul);
        const BsgsCenterProbe probe = center_probes[middle];
        if (bsgs_compare_x256(center_x, probe) > 0) {
            probe_low = middle + 1ul;
        } else {
            probe_high = middle;
        }
    }
    if (probe_low < ulong(BSGS_WALK_SIZE / 2u)) {
        const BsgsCenterProbe probe = center_probes[probe_low];
        if (bsgs_compare_x256(center_x, probe) == 0) {
            const bool positive =
                uint(center_y[0] & 1ul) == probe.odd_y;
            const uint singular_field = positive
                ? BSGS_WALK_SIZE / 2u + probe.offset
                : BSGS_WALK_SIZE / 2u - probe.offset;
            bsgs_emit_shifted_singular(
                singular_field,
                params,
                item.reserved,
                emitter);
            return;
        }
    }
    vanity_walk_batch_1024_parity(center_x,
                                  center_y,
                                  walk_gx,
                                  walk_gy,
                                  walk_2gnx,
                                  walk_2gny,
                                  true,
                                  emitter);
}

kernel void bsgsResolveHits(
    const device BsgsHit* hits [[buffer(0)]],
    device BsgsResolved* resolved [[buffer(1)]],
    constant BsgsResolveParams& params [[buffer(2)]],
    uint tid [[thread_position_in_grid]]) {
    if (tid >= params.hit_count) {
        return;
    }
    const device BsgsHit& hit = hits[tid];
    ulong odd_index[4] = {
        hit.giant_index[0],
        hit.giant_index[1],
        hit.giant_index[2],
        hit.giant_index[3]
    };
    for (int limb = 3; limb > 0; --limb) {
        odd_index[uint(limb)] =
            (odd_index[uint(limb)] << 1ul) |
            (odd_index[uint(limb - 1)] >> 63ul);
    }
    odd_index[0] = (odd_index[0] << 1ul) | 1ul;
    ulong center[4];
    bsgs_u256_mul_small(odd_index, params.m, center);

    device BsgsResolved& minus = resolved[ulong(tid) * 2ul];
    device BsgsResolved& plus = resolved[ulong(tid) * 2ul + 1ul];
    minus.target_id = hit.target_id;
    plus.target_id = hit.target_id;
    minus.valid = 0u;
    plus.valid = 0u;
    if ((hit.giant_index[3] &
         BSGS_SHIFTED_SINGULAR_MARKER) != 0ul) {
        return;
    }

    ulong candidate[4];
    bsgs_copy256(candidate, center);
    if (bsgs_u256_sub_small(candidate, hit.j) &&
        bsgs_u256_less(candidate, params.width)) {
        for (uint limb = 0u; limb < 4u; ++limb) {
            minus.distance[limb] = candidate[limb];
        }
        minus.valid = 1u;
    }

    if (hit.j != 0ul) {
        bsgs_copy256(candidate, center);
        bsgs_u256_add_small(candidate, hit.j);
        if (bsgs_u256_less(candidate, params.width)) {
            for (uint limb = 0u; limb < 4u; ++limb) {
                plus.distance[limb] = candidate[limb];
            }
            plus.valid = 1u;
        }
    }
}
