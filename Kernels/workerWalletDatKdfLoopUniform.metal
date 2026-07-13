#include "WalletDatKdfCommon.metalh"

kernel void workerWalletDatKdfLoopUniform(constant ulong& total_jobs [[buffer(0)]],
                                          constant uint& loop_count [[buffer(1)]],
                                          device WalletDatKdfTmp* tmp [[buffer(2)]],
                                          constant ulong& tmp_capacity [[buffer(3)]],
                                          uint tid [[thread_position_in_grid]],
                                          uint threads [[threads_per_grid]]) {
    if (total_jobs == 0ul || tmp == nullptr || loop_count == 0u) {
        return;
    }
    const ulong capped_jobs = total_jobs < tmp_capacity ? total_jobs : tmp_capacity;
    const ulong stride = ulong(threads);
    for (ulong job = ulong(tid); job < capped_jobs; job += stride) {
        if (tmp[job].active == 0u) {
            continue;
        }
        ulong digest[8];
        for (int i = 0; i < 8; ++i) {
            digest[i] = tmp[job].digest[i];
        }
        for (uint i = 0u; i < loop_count; ++i) {
            wallet_sha512_digest64_once_words(digest);
        }
        for (int i = 0; i < 8; ++i) {
            tmp[job].digest[i] = digest[i];
        }
    }
}
