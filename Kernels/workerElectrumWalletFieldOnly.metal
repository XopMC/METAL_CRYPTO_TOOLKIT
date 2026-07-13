#include "ElectrumWalletCommon.metalh"

kernel void workerElectrumWalletFieldOnly(device bool* isResult [[buffer(0)]],
                                          device bool* buffResult [[buffer(1)]],
                                          const constant ElectrumWalletTarget* targets [[buffer(2)]],
                                          const device uchar* ciphertext_pool [[buffer(3)]],
                                          constant uint& target_count [[buffer(4)]],
                                          const device uchar* solved_flags [[buffer(5)]],
                                          constant uint& solved_count [[buffer(6)]],
                                          constant uchar& candidate_kind [[buffer(7)]],
                                          const device char* pass_data [[buffer(8)]],
                                          const device uchar* pass_lens [[buffer(9)]],
                                          constant uint& pass_count [[buffer(10)]],
                                          const device WalletMaskSpec* mask_spec [[buffer(11)]],
                                          const device WalletRangeSpec* range_spec [[buffer(12)]],
                                          constant ulong& candidate_start [[buffer(13)]],
                                          constant ulong& candidate_count [[buffer(14)]],
                                          device WalletModeResult* wallet_results [[buffer(15)]],
                                          device atomic_uint* wallet_count [[buffer(16)]],
                                          constant uint& max_founds [[buffer(17)]],
                                          uint tid [[thread_position_in_grid]],
                                          uint threads [[threads_per_grid]]) {
    if (candidate_count == 0ul || target_count == 0u) {
        return;
    }
    const ulong stride = ulong(threads);
    for (ulong candidate_idx = ulong(tid); candidate_idx < candidate_count; candidate_idx += stride) {
        uchar pass_local[WALLET_PASS_STRIDE];
        uint pass_len = 0u;
        if (!walletdat_load_candidate_pass(candidate_kind, pass_data, pass_lens, pass_count,
                                           mask_spec, range_spec, candidate_start + candidate_idx,
                                           pass_local, &pass_len)) {
            continue;
        }

        uchar secret32[32];
        wallet_electrum_sha256d_password(pass_local, pass_len, secret32);

        for (uint target_idx = 0u; target_idx < target_count; ++target_idx) {
            const constant ElectrumWalletTarget& target = targets[target_idx];
            if (solved_flags != nullptr && target.target_index < solved_count && solved_flags[target.target_index] != 0u) {
                continue;
            }
            if (target.kind != ELECTRUMWALLET_TARGET_FIELD_V1) {
                continue;
            }
            if (target.ciphertext_len == 0u || target.ciphertext_len > WALLETDAT_MAX_CRYPTED_KEY_LEN ||
                ciphertext_pool == nullptr) {
                continue;
            }
            const device uchar* ciphertext = ciphertext_pool + target.ciphertext_offset;
            if (wallet_electrum_field_v1_check(secret32, target, ciphertext)) {
                wallet_emit_electrumwallet_result(isResult, buffResult, pass_local, pass_len,
                                                  target, wallet_results, wallet_count,
                                                  max_founds);
            }
        }
    }
}
