#include "WalletDatKdfCommon.metalh"

kernel void workerWalletDatMaster(const device WalletDatTarget* targets [[buffer(0)]],
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
                                  device WalletDatMasterHit* hits [[buffer(12)]],
                                  device atomic_uint* hit_count [[buffer(13)]],
                                  constant uint& max_hits [[buffer(14)]],
                                  uint tid [[thread_position_in_grid]],
                                  uint threads [[threads_per_grid]]) {
    if (candidate_count == 0ul || target_count == 0u || hits == nullptr ||
        hit_count == nullptr || max_hits == 0u) {
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
        const ulong absolute_candidate_idx = candidate_start + candidate_idx;

        uchar pass_local[WALLET_PASS_STRIDE];
        uint pass_len = 0u;
        if (!walletdat_load_candidate_pass(candidate_kind, pass_data, pass_lens, pass_count, mask_spec, range_spec,
                                           absolute_candidate_idx, pass_local, &pass_len)) {
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

        const uint ridx = atomic_fetch_add_explicit(hit_count, 1u, memory_order_relaxed);
        if (ridx >= max_hits) {
            continue;
        }
        device WalletDatMasterHit& out = hits[ridx];
        out.candidate_index = absolute_candidate_idx;
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
