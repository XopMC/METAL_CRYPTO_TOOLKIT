#include "WorkerRecoveryPipelineCommon.metalh"

kernel void workerRecoveryEvalBatch(device bool* isResult [[buffer(0)]],
                                    device bool* buffResult [[buffer(1)]],
                                    constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                                    constant ulong& precPitch [[buffer(3)]],
                                    const device ushort* batch_ids [[buffer(4)]],
                                    constant int& words_count [[buffer(5)]],
                                    constant uint& batch_count [[buffer(6)]],
                                    const device uint* d_derivations [[buffer(7)]],
                                    const device uint* derindex [[buffer(8)]],
                                    constant uint& der_indexes_size [[buffer(9)]],
                                    constant uint& der_start_index [[buffer(10)]],
                                    const device char* passwd [[buffer(11)]],
                                    constant uint& pass_size [[buffer(12)]],
                                    constant uint& starter_pass [[buffer(13)]],
                                    constant ulong& round [[buffer(14)]],
                                    constant uchar& m_mode [[buffer(15)]],
                                    const device uint* iterations [[buffer(16)]],
                                    constant uint& iterations_size [[buffer(17)]],
                                    constant bool& is_str [[buffer(18)]],
                                    constant bool& dub_mnem [[buffer(19)]],
                                    const device RecoveryRuntimeBuffers& runtime [[buffer(20)]],
                                    uint tid [[thread_position_in_grid]],
                                    uint stride [[threads_per_grid]]) {
    (void)starter_pass;
    (void)m_mode;
    (void)is_str;
    (void)dub_mnem;
    if (batch_ids == nullptr || d_derivations == nullptr || derindex == nullptr || batch_count == 0u ||
        words_count <= 0 || words_count > 48 || (words_count % 3) != 0 || pass_size > 128u) {
        return;
    }

    FoundBuffers found;
    if (!recovery_make_found_from_runtime(found, runtime)) {
        return;
    }
    const size_t words_stride = size_t(words_count);
    for (ulong idx = ulong(tid); idx < ulong(batch_count); idx += ulong(stride)) {
        const device ushort* src = batch_ids + idx * words_stride;
        thread ushort ids[48];
        for (int i = 0; i < words_count; ++i) {
            ids[i] = src[i];
        }
        recovery_eval_candidate_secp_ids(isResult, buffResult, tid, precPtr, size_t(precPitch),
                                         ids, words_count, d_derivations, derindex,
                                         der_indexes_size, der_start_index, passwd, pass_size,
                                         round, iterations, iterations_size, *runtime.config,
                                         runtime.customDict, *runtime.filters,
                                         *runtime.filterStorage, runtime.bloomStorage,
                                         runtime.xorStorage, runtime.xorUnStorage,
                                         runtime.xorUcStorage, runtime.xorHcStorage, found);
    }
}
