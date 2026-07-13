#include "WalletDatKdfInitCommon.metalh"

kernel void workerWalletDatGroupKdfInit(const device WalletDatGroup* groups [[buffer(0)]],
                                        constant uint& group_count [[buffer(1)]],
                                        constant uchar& candidate_kind [[buffer(2)]],
                                        const device char* pass_data [[buffer(3)]],
                                        const device uchar* pass_lens [[buffer(4)]],
                                        constant uint& pass_count [[buffer(5)]],
                                        const device WalletMaskSpec* mask_spec [[buffer(6)]],
                                        const device WalletRangeSpec* range_spec [[buffer(7)]],
                                        constant ulong& candidate_start [[buffer(8)]],
                                        constant ulong& candidate_count [[buffer(9)]],
                                        device WalletDatKdfTmp* tmp [[buffer(10)]],
                                        constant ulong& tmp_capacity [[buffer(11)]],
                                        uint tid [[thread_position_in_grid]],
                                        uint threads [[threads_per_grid]]) {
    if (candidate_count == 0ul || group_count == 0u || groups == nullptr || tmp == nullptr) {
        return;
    }
    if (wallet_mul_overflows_u64_by_u32(candidate_count, group_count)) {
        return;
    }
    const ulong total_jobs = candidate_count * ulong(group_count);
    const ulong capped_jobs = total_jobs < tmp_capacity ? total_jobs : tmp_capacity;
    const ulong stride = ulong(threads);
    for (ulong job = ulong(tid); job < capped_jobs; job += stride) {
        tmp[job].active = 0u;
        const ulong candidate_idx = job % candidate_count;
        const uint group_idx = uint(job / candidate_count);
        const device WalletDatGroup& group = groups[group_idx];
        if (group.iterations == 0u || group.salt_len == 0u || group.salt_len > WALLET_MAX_SALT_LEN || group.target_count == 0u) {
            continue;
        }

        uchar pass_local[WALLET_PASS_STRIDE];
        uint pass_len = 0u;
        if (!walletdat_init_load_candidate_pass(candidate_kind, pass_data, pass_lens, pass_count, mask_spec, range_spec,
                                                candidate_start + candidate_idx, pass_local, &pass_len)) {
            continue;
        }

        walletdat_init_sha512_pass_salt_words(pass_local, pass_len, group.salt, group.salt_len, tmp[job].digest);
        tmp[job].active = 1u;
    }
}
