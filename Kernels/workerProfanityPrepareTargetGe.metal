#include "ProfanityRecoveryCommon.metalh"

kernel void workerProfanityPrepareTargetGe(const device uchar* target_pubkey [[buffer(0)]],
                                           constant uint& target_len [[buffer(1)]],
                                           device secp256k1_ge* target_ge [[buffer(2)]],
                                           device uint* target_ok [[buffer(3)]],
                                           uint tid [[thread_position_in_grid]]) {
    if (tid != 0u) {
        return;
    }
    secp256k1_ge q;
    const bool ok = profanity_target_pubkey_to_ge(target_pubkey, target_len, &q);
    if (ok) {
        *target_ge = q;
    }
    *target_ok = ok ? 1u : 0u;
}
