#include "WalletDatKdfCommon.metalh"

kernel void workerWalletDatKdfInit(const device WalletDatTarget* targets [[buffer(0)]],
                                   constant uint& target_count [[buffer(1)]],
                                   const device uchar* solved_flags [[buffer(2)]],
                                   constant uint& solved_count [[buffer(3)]],
                                   constant uchar& candidate_kind [[buffer(4)]],
                                   const device char* pass_data [[buffer(5)]],
                                   const device uchar* pass_lens [[buffer(6)]],
                                   constant uint& pass_count [[buffer(7)]],
                                   const device WalletMaskSpec* mask_spec [[buffer(8)]],
                                   const device WalletRangeSpec* range_spec [[buffer(9)]],
                                   constant ulong& candidate_start [[buffer(10)]],
                                   constant ulong& candidate_count [[buffer(11)]],
                                   device WalletDatKdfTmp* tmp [[buffer(12)]],
                                   constant ulong& tmp_capacity [[buffer(13)]],
                                   uint tid [[thread_position_in_grid]],
                                   uint threads [[threads_per_grid]]) {
    if (candidate_count == 0ul || target_count == 0u || tmp == nullptr) {
        return;
    }
    if (wallet_mul_overflows_u64_by_u32(candidate_count, target_count)) {
        return;
    }
    const ulong total_jobs = candidate_count * ulong(target_count);
    const ulong capped_jobs = total_jobs < tmp_capacity ? total_jobs : tmp_capacity;
    const ulong stride = ulong(threads);
    for (ulong job = ulong(tid); job < capped_jobs; job += stride) {
        tmp[job].active = 0u;
        const ulong candidate_idx = job % candidate_count;
        const uint target_idx = uint(job / candidate_count);
        const device WalletDatTarget& target = targets[target_idx];
        if (solved_flags != nullptr && target.target_index < solved_count && solved_flags[target.target_index] != 0u) {
            continue;
        }
        if (!walletdat_target_valid_for_master_check(target)) {
            continue;
        }

        uchar pass_local[WALLET_PASS_STRIDE];
        uint pass_len = 0u;
        if (!walletdat_load_candidate_pass(candidate_kind, pass_data, pass_lens, pass_count, mask_spec, range_spec,
                                           candidate_start + candidate_idx, pass_local, &pass_len)) {
            continue;
        }

        wallet_sha512_pass_salt_words(pass_local, pass_len, target.salt, target.salt_len, tmp[job].digest);
        tmp[job].active = 1u;
    }
}
