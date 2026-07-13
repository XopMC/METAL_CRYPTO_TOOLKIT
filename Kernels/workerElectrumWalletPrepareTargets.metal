#include "ElectrumWalletCommon.metalh"

kernel void workerElectrumWalletPrepareTargets(device ElectrumWalletTarget* targets [[buffer(0)]],
                                               device ElectrumWalletEcdhPrecomp* ecdh_precomp [[buffer(1)]],
                                               constant uint& ecdh_precomp_count [[buffer(2)]],
                                               constant uint& target_count [[buffer(3)]],
                                               uint tid [[thread_position_in_grid]],
                                               uint threads [[threads_per_grid]]) {
    const ulong stride = ulong(threads);
    for (ulong i = ulong(tid); i < ulong(target_count); i += stride) {
        device ElectrumWalletTarget& target = targets[i];
        target.ge_ready = 0u;
        if (target.kind != ELECTRUMWALLET_TARGET_BIE1) {
            continue;
        }
        if (target.precomp_index >= ecdh_precomp_count) {
            continue;
        }
        secp256k1_ge ge;
        if (!wallet_electrum_parse_pubkey(target.ephemeral_pubkey, &ge)) {
            continue;
        }
        secp256k1_ge_storage stored;
        secp256k1_ge_to_storage(&stored, &ge);
        target.ephemeral_ge = stored;
        if (ecdh_precomp != nullptr) {
            wallet_electrum_build_ecdh_precomp(&ge, &ecdh_precomp[target.precomp_index]);
        }
        target.ge_ready = 1u;
    }
}
