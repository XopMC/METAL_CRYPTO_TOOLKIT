#include "WalletDatKdfCommon.metalh"

kernel void workerWalletDatKdfLoop(const device WalletDatTarget* targets [[buffer(0)]],
                                   constant uint& target_count [[buffer(1)]],
                                   constant ulong& candidate_count [[buffer(2)]],
                                   constant uint& loop_pos [[buffer(3)]],
                                   constant uint& loop_count [[buffer(4)]],
                                   device WalletDatKdfTmp* tmp [[buffer(5)]],
                                   constant ulong& tmp_capacity [[buffer(6)]],
                                   uint tid [[thread_position_in_grid]],
                                   uint threads [[threads_per_grid]]) {
    if (candidate_count == 0ul || target_count == 0u || tmp == nullptr || loop_count == 0u) {
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
        const uint target_idx = uint(job / candidate_count);
        const uint iterations = targets[target_idx].iterations;
        if (loop_pos >= iterations) {
            continue;
        }
        const uint remaining = iterations - loop_pos;
        const uint todo = remaining < loop_count ? remaining : loop_count;
        for (uint i = 0u; i < todo; ++i) {
            wallet_sha512_digest64_once_words(tmp[job].digest);
        }
    }
}
