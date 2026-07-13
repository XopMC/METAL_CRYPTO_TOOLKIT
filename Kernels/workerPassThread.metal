#include "WorkerPassThreadCommon.metalh"

kernel void workerPassThread(device bool* isResult [[buffer(0)]],
                             device bool* buffResult [[buffer(1)]],
                             constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                             constant ulong& precPitch [[buffer(3)]],
                             const device char* single_mnem [[buffer(4)]],
                             constant uint& single_mnem_len [[buffer(5)]],
                             const device uint* d_derivations [[buffer(6)]],
                             const device uint* derindex [[buffer(7)]],
                             constant uint& der_indexes_size [[buffer(8)]],
                             constant uint& der_start_index [[buffer(9)]],
                             const device char* passwords [[buffer(10)]],
                             const device uchar* pass_lengths [[buffer(11)]],
                             constant uint& pass_count [[buffer(12)]],
                             constant ulong& round [[buffer(13)]],
                             constant uchar& m_mode [[buffer(14)]],
                             const device uint* iterations [[buffer(15)]],
                             constant uint& iterations_size [[buffer(16)]],
                             constant bool& is_str [[buffer(17)]],
                             constant bool& dub_mnem [[buffer(18)]],
                             const device WorkerRuntimeBuffers& runtime [[buffer(19)]],
                             uint tid [[thread_position_in_grid]]) {
    (void)dub_mnem;
    pass_thread_process_phrase(isResult, buffResult, precPtr, precPitch, single_mnem,
                               single_mnem_len, d_derivations, derindex, der_indexes_size,
                               der_start_index, passwords, pass_lengths, pass_count, round,
                               m_mode, iterations, iterations_size, is_str, runtime, tid);
}
