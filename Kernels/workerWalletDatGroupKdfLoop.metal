#include "WalletDatKdfCommon.metalh"

kernel void workerWalletDatGroupKdfLoop(const device WalletDatGroup* groups [[buffer(0)]],
                                        constant uint& group_count [[buffer(1)]],
                                        constant ulong& candidate_count [[buffer(2)]],
                                        constant uint& loop_pos [[buffer(3)]],
                                        constant uint& loop_count [[buffer(4)]],
                                        device WalletDatKdfTmp* tmp [[buffer(5)]],
                                        constant ulong& tmp_capacity [[buffer(6)]],
                                        uint tid [[thread_position_in_grid]],
                                        uint threads [[threads_per_grid]]) {
    if (candidate_count == 0ul || group_count == 0u || groups == nullptr || tmp == nullptr || loop_count == 0u) {
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
        const uint group_idx = uint(job / candidate_count);
        const uint iterations = groups[group_idx].iterations;
        if (loop_pos >= iterations) {
            continue;
        }
        const uint remaining = iterations - loop_pos;
        const uint todo = remaining < loop_count ? remaining : loop_count;
        ulong digest[8];
        for (int i = 0; i < 8; ++i) {
            digest[i] = tmp[job].digest[i];
        }
        for (uint i = 0u; i < todo; ++i) {
            wallet_sha512_digest64_once_words(digest);
        }
        for (int i = 0; i < 8; ++i) {
            tmp[job].digest[i] = digest[i];
        }
    }
}
