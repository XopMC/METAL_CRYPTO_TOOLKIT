#include <metal_stdlib>
#include "WorkerRecoverySeedCommon.metalh"

using namespace metal;

kernel void workerRecoverySeedBatch(const device ushort* batch_ids [[buffer(0)]],
                                    constant int& words_count [[buffer(1)]],
                                    constant uint& batch_count [[buffer(2)]],
                                    const device char* passwd [[buffer(3)]],
                                    constant uint& pass_size [[buffer(4)]],
                                    const device uint* iterations [[buffer(5)]],
                                    constant uint& iterations_size [[buffer(6)]],
                                    device uint* batch_master_words [[buffer(7)]],
                                    device RuntimeConfig& config [[buffer(8)]],
                                    const device char* customDict [[buffer(9)]],
                                    uint tid [[thread_position_in_grid]],
                                    uint stride [[threads_per_grid]]) {
    if (batch_ids == nullptr || batch_master_words == nullptr || batch_count == 0u ||
        iterations == nullptr || iterations_size == 0u ||
        words_count <= 0 || words_count > 48 || (words_count % 3) != 0) {
        return;
    }

    const size_t words_stride = size_t(words_count);
    thread char phrase[512];

    for (ulong idx = ulong(tid); idx < ulong(batch_count); idx += ulong(stride)) {
        const device ushort* src_ids = batch_ids + (size_t(idx) * words_stride);
        device uint* out_master = batch_master_words + (size_t(idx) * size_t(RECOVERY_MASTER_WORDS_METAL));

        thread ushort ids[48];
        for (int i = 0; i < words_count; i++) {
            ids[i] = src_ids[i];
        }

        thread uint master_local[RECOVERY_MASTER_WORDS_METAL];
        const uint phrase_len = recovery_build_phrase_from_ids_metal(ids, words_count, config, customDict, phrase, uint(sizeof(phrase)));
        const bool ok = (phrase_len != 0u) &&
            recovery_build_master_words_from_phrase_metal(phrase, phrase_len, passwd, pass_size, iterations, iterations_size, config, master_local);

        if (!ok) {
            for (int i = 0; i < int(RECOVERY_MASTER_WORDS_METAL); ++i) {
                out_master[i] = 0u;
            }
        } else {
            for (int i = 0; i < int(RECOVERY_MASTER_WORDS_METAL); ++i) {
                out_master[i] = master_local[i];
            }
        }
    }
}
