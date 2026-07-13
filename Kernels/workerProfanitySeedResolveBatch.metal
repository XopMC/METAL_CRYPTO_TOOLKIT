#include "ProfanityRecoveryCommon.metalh"

kernel void workerProfanitySeedResolveBatch(device bool* isResult [[buffer(0)]],
                                            device bool* buffResult [[buffer(1)]],
                                            constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                                            constant ulong& precPitch [[buffer(3)]],
                                            constant uint& start_seed32 [[buffer(4)]],
                                            constant uint& seed_count [[buffer(5)]],
                                            constant ulong& lane_start [[buffer(6)]],
                                            constant ulong& lane_count [[buffer(7)]],
                                            constant ulong& pair_start [[buffer(8)]],
                                            constant ulong& pair_count [[buffer(9)]],
                                            const device uchar* target_pubkey [[buffer(10)]],
                                            constant uint& target_len [[buffer(11)]],
                                            const device ProfanityRecoveryHit* hits [[buffer(12)]],
                                            constant uint& hit_count [[buffer(13)]],
                                            device ProfanityVerifiedResult* profanity_results [[buffer(14)]],
                                            device atomic_uint* profanity_count [[buffer(15)]],
                                            constant uint& max_founds [[buffer(16)]],
                                            uint tid [[thread_position_in_grid]]) {
    const ulong tIx = ulong(tid);
    (void)lane_start;
    (void)lane_count;
    if (tIx >= pair_count || hit_count == 0u) {
        return;
    }

    const ulong group = pair_start + tIx;
    const ulong seed_delta_base = group * ulong(PROFANITY_THREAD_STEPS);
    if (seed_delta_base >= ulong(seed_count)) {
        return;
    }

    uchar pubKeys[PROFANITY_THREAD_STEPS * 65u];
    uchar prvKeys[PROFANITY_THREAD_STEPS * 32u];

    uint local_count = 0u;
    for (uint i = 0u; i < PROFANITY_THREAD_STEPS; ++i) {
        const ulong seed_delta = seed_delta_base + ulong(i);
        if (seed_delta >= ulong(seed_count)) {
            break;
        }
        const uint seed32 = start_seed32 + uint(seed_delta);
        profanity_private_bytes(seed32, 0ul, prvKeys + i * 32u);
        ++local_count;
    }
    if (local_count == 0u) {
        return;
    }

    secp256k1_ec_pubkey_create_serialized_batch_myunsafe(pubKeys,
                                                         prvKeys,
                                                         int(local_count),
                                                         precPtr,
                                                         size_t(precPitch));

    for (uint i = 0u; i < PROFANITY_THREAD_STEPS; ++i) {
        if (i >= local_count) {
            break;
        }
        const ulong seed_delta = seed_delta_base + ulong(i);
        const uint seed32 = start_seed32 + uint(seed_delta);
        const thread uchar* base_pub = pubKeys + i * 65u;

        for (uint h = 0u; h < hit_count; ++h) {
            bool x_match = true;
            for (int w = 0; w < 4; ++w) {
                const ulong a = profanity_load_le64(base_pub + 1 + uint(w) * 8u);
                const ulong b = profanity_load_le64(hits[h].x32 + uint(w) * 8u);
                if (a != b) {
                    x_match = false;
                }
            }
            if (!x_match) {
                continue;
            }

            uchar recovered_priv[32];
            profanity_private_bytes_lane_round(seed32,
                                               hits[h].lane_id,
                                               hits[h].offset,
                                               recovered_priv);
            uchar recovered_pub[65];
            secp256k1_ec_pubkey_create((thread secp256k1_pubkey*)&recovered_pub[1],
                                       recovered_priv,
                                       precPtr,
                                       size_t(precPitch));
            recovered_pub[0] = 0x04u;
            if (profanity_pubkey_matches_target(recovered_pub, target_pubkey, target_len)) {
                profanity_recovery_emit_verified(isResult,
                                                 buffResult,
                                                 seed32,
                                                 hits[h].lane_id,
                                                 hits[h].offset,
                                                 recovered_priv,
                                                 recovered_pub + 1,
                                                 profanity_results,
                                                 profanity_count,
                                                 max_founds);
            }
        }
    }
}
