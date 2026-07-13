#include "WorkerPassThreadCommon.metalh"

kernel void workerPassThreadEntropy(device bool* isResult [[buffer(0)]],
                                    device bool* buffResult [[buffer(1)]],
                                    constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                                    constant ulong& precPitch [[buffer(3)]],
                                    const device char* single_entropy [[buffer(4)]],
                                    constant uint& single_entropy_len [[buffer(5)]],
                                    const device uint* d_derivations [[buffer(6)]],
                                    const device uint* derindex [[buffer(7)]],
                                    constant uint& der_indexes_size [[buffer(8)]],
                                    constant uint& der_start_index [[buffer(9)]],
                                    const device char* passwords [[buffer(10)]],
                                    const device uchar* pass_lengths [[buffer(11)]],
                                    constant uint& pass_count [[buffer(12)]],
                                    constant bool& custom_size [[buffer(13)]],
                                    const device int* sizes [[buffer(14)]],
                                    constant uint& sizez_size [[buffer(15)]],
                                    constant uchar& entropy_mode [[buffer(16)]],
                                    const device uint* iterations [[buffer(17)]],
                                    constant uint& iterations_size [[buffer(18)]],
                                    constant ulong& round [[buffer(19)]],
                                    constant bool& dub_mnem [[buffer(20)]],
                                    const device WorkerRuntimeBuffers& runtime [[buffer(21)]],
                                    uint tid [[thread_position_in_grid]]) {
    (void)dub_mnem;
    pass_thread_process_entropy(isResult, buffResult, precPtr, precPitch, single_entropy,
                                single_entropy_len, d_derivations, derindex, der_indexes_size,
                                der_start_index, passwords, pass_lengths, pass_count,
                                custom_size, sizes, sizez_size, entropy_mode, iterations,
                                iterations_size, round, runtime, tid);
}
