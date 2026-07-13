#include "WalletDatKdfCommon.metalh"

kernel void workerWalletDatGroupKdfCheck(const device WalletDatTarget* targets [[buffer(0)]],
                                         const device WalletDatGroup* groups [[buffer(1)]],
                                         constant uint& group_count [[buffer(2)]],
                                         const device uchar* solved_flags [[buffer(3)]],
                                         constant uint& solved_count [[buffer(4)]],
                                         constant ulong& candidate_start [[buffer(5)]],
                                         constant ulong& candidate_count [[buffer(6)]],
                                         const device WalletDatKdfTmp* tmp [[buffer(7)]],
                                         constant ulong& tmp_capacity [[buffer(8)]],
                                         device WalletDatMasterHit* hits [[buffer(9)]],
                                         device atomic_uint* hit_count [[buffer(10)]],
                                         constant uint& max_hits [[buffer(11)]],
                                         uint tid [[thread_position_in_grid]],
                                         uint threads [[threads_per_grid]]) {
    if (candidate_count == 0ul || group_count == 0u || targets == nullptr || groups == nullptr ||
        tmp == nullptr || hits == nullptr || hit_count == nullptr || max_hits == 0u) {
        return;
    }
    if (wallet_mul_overflows_u64_by_u32(candidate_count, group_count)) {
        return;
    }
    const ulong total_jobs = candidate_count * ulong(group_count);
    const ulong capped_jobs = total_jobs < tmp_capacity ? total_jobs : tmp_capacity;
    const ulong stride = ulong(threads);
    for (ulong job = ulong(tid); job < capped_jobs; job += stride) {
        if (tmp[job].active == 0u) {
            continue;
        }
        const ulong candidate_idx = job % candidate_count;
        const uint group_idx = uint(job / candidate_count);
        const device WalletDatGroup& group = groups[group_idx];

        uchar key32[32];
        uchar iv16[16];
        for (int i = 0; i < 4; ++i) {
            wallet_store_be64(key32 + i * 8, tmp[job].digest[i]);
        }
        for (int i = 0; i < 2; ++i) {
            wallet_store_be64(iv16 + i * 8, tmp[job].digest[4 + i]);
        }

        for (uint rel = 0u; rel < group.target_count; ++rel) {
            const uint target_idx = group.target_offset + rel;
            const device WalletDatTarget& target = targets[target_idx];
            if (solved_flags != nullptr && target.target_index < solved_count && solved_flags[target.target_index] != 0u) {
                continue;
            }
            if (!walletdat_target_valid_for_master_check(target)) {
                continue;
            }
            uint master_len = 0u;
            if (!wallet_aes256_cbc_check_pkcs7_tail(key32, iv16, target.crypted_master,
                                                    target.crypted_master_len, &master_len)) {
                continue;
            }
            if (!walletdat_master_len_valid_for_target(target, master_len)) {
                continue;
            }

            const uint ridx = atomic_fetch_add_explicit(hit_count, 1u, memory_order_relaxed);
            if (ridx >= max_hits) {
                continue;
            }
            device WalletDatMasterHit& out = hits[ridx];
            out.candidate_index = candidate_start + candidate_idx;
            out.target_index = target_idx;
            out.master_len = master_len;
            for (int i = 0; i < 32; ++i) {
                out.key32[i] = key32[i];
            }
            for (int i = 0; i < 16; ++i) {
                out.iv16[i] = iv16[i];
            }
        }
    }
}
