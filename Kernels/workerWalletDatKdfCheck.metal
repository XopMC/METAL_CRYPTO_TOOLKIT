#include "WalletDatKdfCommon.metalh"

kernel void workerWalletDatKdfCheck(const device WalletDatTarget* targets [[buffer(0)]],
                                    constant uint& target_count [[buffer(1)]],
                                    constant ulong& candidate_start [[buffer(2)]],
                                    constant ulong& candidate_count [[buffer(3)]],
                                    const device WalletDatKdfTmp* tmp [[buffer(4)]],
                                    constant ulong& tmp_capacity [[buffer(5)]],
                                    device WalletDatMasterHit* hits [[buffer(6)]],
                                    device atomic_uint* hit_count [[buffer(7)]],
                                    constant uint& max_hits [[buffer(8)]],
                                    uint tid [[thread_position_in_grid]],
                                    uint threads [[threads_per_grid]]) {
    if (candidate_count == 0ul || target_count == 0u || tmp == nullptr || hits == nullptr ||
        hit_count == nullptr || max_hits == 0u) {
        return;
    }
    if (wallet_mul_overflows_u64_by_u32(candidate_count, target_count)) {
        return;
    }
    const ulong total_jobs = candidate_count * ulong(target_count);
    const ulong capped_jobs = total_jobs < tmp_capacity ? total_jobs : tmp_capacity;
    const ulong stride = ulong(threads);
    for (ulong job = ulong(tid); job < capped_jobs; job += stride) {
        if (tmp[job].active == 0u) {
            continue;
        }
        const ulong candidate_idx = job % candidate_count;
        const uint target_idx = uint(job / candidate_count);
        const device WalletDatTarget& target = targets[target_idx];

        uchar key32[32];
        uchar iv16[16];
        for (int i = 0; i < 4; ++i) {
            wallet_store_be64(key32 + i * 8, tmp[job].digest[i]);
        }
        for (int i = 0; i < 2; ++i) {
            wallet_store_be64(iv16 + i * 8, tmp[job].digest[4 + i]);
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
