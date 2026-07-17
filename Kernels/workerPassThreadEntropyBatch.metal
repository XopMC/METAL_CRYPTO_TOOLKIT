#include "WorkerPassThreadCommon.metalh"

kernel void workerPassThreadEntropyBatch(device bool* isResult [[buffer(0)]],
                                         device bool* buffResult [[buffer(1)]],
                                         constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                                         constant ulong& precPitch [[buffer(3)]],
                                         const device char* entropies [[buffer(4)]],
                                         const device uint* entropy_lengths [[buffer(5)]],
                                         constant uint& entropy_count [[buffer(6)]],
                                         const device uint* d_derivations [[buffer(7)]],
                                         const device uint* derindex [[buffer(8)]],
                                         constant uint& der_indexes_size [[buffer(9)]],
                                         constant uint& der_start_index [[buffer(10)]],
                                         const device char* passwords [[buffer(11)]],
                                         const device uchar* pass_lengths [[buffer(12)]],
                                         constant uint& pass_count [[buffer(13)]],
                                         constant bool& custom_size [[buffer(14)]],
                                         const device int* sizes [[buffer(15)]],
                                         constant uint& sizez_size [[buffer(16)]],
                                         constant uchar& entropy_mode [[buffer(17)]],
                                         const device uint* iterations [[buffer(18)]],
                                         constant uint& iterations_size [[buffer(19)]],
                                         constant ulong& round [[buffer(20)]],
                                         constant bool& dub_mnem [[buffer(21)]],
                                         const device WorkerRuntimeBuffers& runtime [[buffer(22)]],
                                         uint tid [[thread_position_in_grid]]) {
    (void)dub_mnem;
    if (pass_count == 0u || entropies == nullptr || entropy_lengths == nullptr) {
        return;
    }
    const uint entropy_index = tid / pass_count;
    if (entropy_index >= entropy_count) {
        return;
    }
    const uint pass_index = tid % pass_count;
    const device char* entropy = entropies + ulong(entropy_index) * 512ul;
    pass_thread_process_entropy_pair(isResult, buffResult, precPtr, precPitch, entropy,
                                     entropy_lengths[entropy_index], d_derivations, derindex,
                                     der_indexes_size, der_start_index, passwords, pass_lengths,
                                     pass_count, custom_size, sizes, sizez_size, entropy_mode,
                                     iterations, iterations_size, round, runtime, pass_index,
                                     ulong(tid));
}
