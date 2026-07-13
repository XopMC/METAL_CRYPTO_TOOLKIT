#include "ProfanityRecoveryCommon.metalh"

kernel void workerProfanitySeedResolve(device bool* isResult [[buffer(0)]],
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

    const ulong pair = pair_start + tIx;
    const ulong seed_delta = pair;
    if (seed_delta >= ulong(seed_count)) {
        return;
    }
    const uint seed32 = start_seed32 + uint(seed_delta);

    uchar base_priv[32];
    profanity_private_bytes(seed32, 0ul, base_priv);

    uchar base_pub[65];
    secp256k1_ec_pubkey_create((thread secp256k1_pubkey*)&base_pub[1],
                               base_priv,
                               precPtr,
                               size_t(precPitch));
    base_pub[0] = 0x04u;

    for (uint h = 0u; h < hit_count; ++h) {
        bool x_match = true;
        for (int i = 0; i < 32; ++i) {
            if (base_pub[1 + i] != hits[h].x32[i]) {
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
