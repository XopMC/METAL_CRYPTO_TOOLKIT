#include "WorkerRecoveryPipelineCommon.metalh"

kernel void workerRecoveryEvalMasterBatch(device bool* isResult [[buffer(0)]],
                                          device bool* buffResult [[buffer(1)]],
                                          constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                                          constant ulong& precPitch [[buffer(3)]],
                                          const device ushort* batch_ids [[buffer(4)]],
                                          const device uint* batch_master_words [[buffer(5)]],
                                          constant int& words_count [[buffer(6)]],
                                          constant uint& batch_count [[buffer(7)]],
                                          const device uint* d_derivations [[buffer(8)]],
                                          const device uint* derindex [[buffer(9)]],
                                          constant uint& der_indexes_size [[buffer(10)]],
                                          constant uint& der_start_index [[buffer(11)]],
                                          const device char* passwd [[buffer(12)]],
                                          constant uint& pass_size [[buffer(13)]],
                                          constant uint& starter_pass [[buffer(14)]],
                                          constant ulong& round [[buffer(15)]],
                                          constant uchar& m_mode [[buffer(16)]],
                                          constant bool& is_str [[buffer(17)]],
                                          constant bool& dub_mnem [[buffer(18)]],
                                          const device RecoveryRuntimeBuffers& runtime [[buffer(19)]],
                                          uint tid [[thread_position_in_grid]],
                                          uint stride [[threads_per_grid]]) {
    (void)starter_pass;
    (void)m_mode;
    (void)is_str;
    (void)dub_mnem;
    if (batch_ids == nullptr || batch_master_words == nullptr || d_derivations == nullptr || derindex == nullptr || batch_count == 0u ||
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
        const device uint* master_src = batch_master_words + idx * ulong(RECOVERY_MASTER_WORDS_METAL);
        thread ushort ids[48];
        thread uint master_words[RECOVERY_MASTER_WORDS_METAL];
        bool empty_master = true;
        for (int i = 0; i < words_count; ++i) {
            ids[i] = src[i];
        }
        for (int i = 0; i < int(RECOVERY_MASTER_WORDS_METAL); ++i) {
            master_words[i] = master_src[i];
            if (master_words[i] != 0u) {
                empty_master = false;
            }
        }
        if (empty_master) {
            continue;
        }
        recovery_eval_master_secp_ids(isResult, buffResult, tid, precPtr, size_t(precPitch),
                                      ids, words_count, master_words, d_derivations, derindex,
                                      der_indexes_size, der_start_index, passwd, pass_size,
                                      round, *runtime.config, runtime.customDict,
                                      *runtime.filters, *runtime.filterStorage,
                                      runtime.bloomStorage, runtime.xorStorage,
                                      runtime.xorUnStorage, runtime.xorUcStorage,
                                      runtime.xorHcStorage, found);
    }
}
