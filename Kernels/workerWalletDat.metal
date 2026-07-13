#include "WalletDatResolveCommon.metalh"

kernel void workerWalletDat(device bool* isResult [[buffer(0)]],
                            device bool* buffResult [[buffer(1)]],
                            const constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                            constant ulong& precPitch [[buffer(3)]],
                            const device WalletDatTarget* targets [[buffer(4)]],
                            constant uint& target_count [[buffer(5)]],
                            const device uchar* solved_flags [[buffer(6)]],
                            constant uint& solved_count [[buffer(7)]],
                            constant uchar& candidate_kind [[buffer(8)]],
                            const device char* pass_data [[buffer(9)]],
                            const device uchar* pass_lens [[buffer(10)]],
                            constant uint& pass_count [[buffer(11)]],
                            const device WalletMaskSpec* mask_spec [[buffer(12)]],
                            const device WalletRangeSpec* range_spec [[buffer(13)]],
                            constant ulong& candidate_start [[buffer(14)]],
                            constant ulong& candidate_count [[buffer(15)]],
                            device WalletModeResult* wallet_results [[buffer(16)]],
                            device atomic_uint* wallet_count [[buffer(17)]],
                            constant uint& max_founds [[buffer(18)]],
                            constant uint& window_size [[buffer(19)]],
                            constant uint& window_ecmult_size [[buffer(20)]],
                            uint tid [[thread_position_in_grid]],
                            uint threads [[threads_per_grid]]) {
    if (candidate_count == 0ul || target_count == 0u) {
        return;
    }
    if (wallet_mul_overflows_u64_by_u32(candidate_count, target_count)) {
        return;
    }

    const ulong total_jobs = candidate_count * ulong(target_count);
    const ulong stride = ulong(threads);
    for (ulong job = ulong(tid); job < total_jobs; job += stride) {
        const ulong candidate_idx = job % candidate_count;
        const uint target_idx = uint(job / candidate_count);

        uchar pass_local[WALLET_PASS_STRIDE];
        uint pass_len = 0u;
        if (!walletdat_load_candidate_pass(candidate_kind, pass_data, pass_lens, pass_count, mask_spec, range_spec,
                                           candidate_start + candidate_idx, pass_local, &pass_len)) {
            continue;
        }

        const device WalletDatTarget& target = targets[target_idx];
        if (solved_flags != nullptr && target.target_index < solved_count && solved_flags[target.target_index] != 0u) {
            continue;
        }
        if (!walletdat_target_valid_for_master_check(target)) {
            continue;
        }
        uchar key32[32];
        uchar iv16[16];
        walletdat_kdf_sha512(pass_local, pass_len, target, key32, iv16);

        uint master_len = 0u;
        if (!wallet_aes256_cbc_check_pkcs7_tail(key32, iv16, target.crypted_master,
                                                target.crypted_master_len, &master_len)) {
            continue;
        }
        if (!walletdat_master_len_valid_for_target(target, master_len)) {
            continue;
        }
        if (target.ckey_count == 0u) {
            wallet_emit_walletdat_mkey_result(isResult, buffResult, pass_local, pass_len,
                                              target.target_index, target.crypted_master,
                                              target.crypted_master_len, wallet_results,
                                              wallet_count, max_founds);
        } else {
            walletdat_verify_and_emit_slow(isResult, buffResult, precPtr, precPitch,
                                           window_size, window_ecmult_size, target,
                                           pass_local, pass_len, key32, iv16,
                                           wallet_results, wallet_count, max_founds);
        }
    }
}
