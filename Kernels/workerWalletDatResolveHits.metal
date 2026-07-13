#include "WalletDatResolveCommon.metalh"

kernel void workerWalletDatResolveHits(device bool* isResult [[buffer(0)]],
                                       device bool* buffResult [[buffer(1)]],
                                       const constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                                       constant ulong& precPitch [[buffer(3)]],
                                       const device WalletDatTarget* targets [[buffer(4)]],
                                       const device uchar* solved_flags [[buffer(5)]],
                                       constant uint& solved_count [[buffer(6)]],
                                       constant uchar& candidate_kind [[buffer(7)]],
                                       const device char* pass_data [[buffer(8)]],
                                       const device uchar* pass_lens [[buffer(9)]],
                                       constant uint& pass_count [[buffer(10)]],
                                       const device WalletMaskSpec* mask_spec [[buffer(11)]],
                                       const device WalletRangeSpec* range_spec [[buffer(12)]],
                                       const device WalletDatMasterHit* hits [[buffer(13)]],
                                       constant uint& hit_count [[buffer(14)]],
                                       device WalletModeResult* wallet_results [[buffer(15)]],
                                       device atomic_uint* wallet_count [[buffer(16)]],
                                       constant uint& max_founds [[buffer(17)]],
                                       constant uint& window_size [[buffer(18)]],
                                       constant uint& window_ecmult_size [[buffer(19)]],
                                       uint tid [[thread_position_in_grid]],
                                       uint threads [[threads_per_grid]]) {
    if (hits == nullptr || hit_count == 0u) {
        return;
    }
    const ulong stride = ulong(threads);
    for (ulong hit_idx = ulong(tid); hit_idx < ulong(hit_count); hit_idx += stride) {
        const device WalletDatMasterHit& hit = hits[hit_idx];
        const device WalletDatTarget& target = targets[hit.target_index];
        if (solved_flags != nullptr && target.target_index < solved_count && solved_flags[target.target_index] != 0u) {
            continue;
        }
        if (!walletdat_target_valid_for_master_check(target)) {
            continue;
        }
        uchar pass_local[WALLET_PASS_STRIDE];
        uint pass_len = 0u;
        if (!walletdat_load_candidate_pass(candidate_kind, pass_data, pass_lens, pass_count,
                                           mask_spec, range_spec, hit.candidate_index,
                                           pass_local, &pass_len)) {
            continue;
        }
        if (target.ckey_count == 0u) {
            wallet_emit_walletdat_mkey_result(isResult, buffResult, pass_local, pass_len,
                                              target.target_index, target.crypted_master,
                                              target.crypted_master_len, wallet_results,
                                              wallet_count, max_founds);
        } else {
            uchar key32[32];
            uchar iv16[16];
            for (int i = 0; i < 32; ++i) {
                key32[i] = hit.key32[i];
            }
            for (int i = 0; i < 16; ++i) {
                iv16[i] = hit.iv16[i];
            }
            walletdat_verify_and_emit_slow(isResult, buffResult, precPtr, precPitch,
                                           window_size, window_ecmult_size, target,
                                           pass_local, pass_len, key32, iv16,
                                           wallet_results, wallet_count, max_founds);
        }
    }
}
