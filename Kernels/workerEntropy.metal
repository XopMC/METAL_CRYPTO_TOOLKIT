#include "WorkerMnemonicCommon.metalh"

kernel void workerEntropy(device bool* isResult [[buffer(0)]],
                          device bool* buffResult [[buffer(1)]],
                          constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                          constant ulong& precPitch [[buffer(3)]],
                          const device char* lines [[buffer(4)]],
                          const device uint* indexes [[buffer(5)]],
                          constant uint& indexes_size [[buffer(6)]],
                          const device uint* d_derivations [[buffer(7)]],
                          const device uint* derindex [[buffer(8)]],
                          constant uint& der_indexes_size [[buffer(9)]],
                          constant uint& der_start_index [[buffer(10)]],
                          const device char* passwd [[buffer(11)]],
                          constant uint& pass_size [[buffer(12)]],
                          constant uint& starter_pass [[buffer(13)]],
                          constant bool& custom_size [[buffer(14)]],
                          const device int* sizes [[buffer(15)]],
                          constant uint& sizez_size [[buffer(16)]],
                          constant uchar& entropy_mode [[buffer(17)]],
                          const device uint* iterations [[buffer(18)]],
                          constant uint& iterations_size [[buffer(19)]],
                          constant ulong& round [[buffer(20)]],
                          constant bool& dub_mnem [[buffer(21)]],
                          const device MnwRuntimeBuffers& runtime [[buffer(22)]],
                          uint tid [[thread_position_in_grid]]) {
    (void)dub_mnem;
    FoundBuffers found;
    if (!mnw_make_found_from_runtime(found, runtime)) {
        return;
    }
    mnw_worker_entropy_file(isResult, buffResult, precPtr, precPitch, lines, indexes,
                            indexes_size, d_derivations, derindex, der_indexes_size,
                            der_start_index, passwd, pass_size, starter_pass, custom_size,
                            sizes, sizez_size, entropy_mode, iterations, iterations_size,
                            round, tid, *runtime.config, *runtime.filters,
                            *runtime.filterStorage, runtime.bloomStorage,
                            runtime.xorStorage, runtime.xorUnStorage, runtime.xorUcStorage,
                            runtime.xorHcStorage, found, runtime.substratePaths,
                            runtime.customDict);
}
