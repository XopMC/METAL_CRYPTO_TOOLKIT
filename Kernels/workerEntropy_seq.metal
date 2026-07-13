#include "WorkerMnemonicCommon.metalh"

kernel void workerEntropy_seq(device bool* isResult [[buffer(0)]],
                              device bool* buffResult [[buffer(1)]],
                              constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                              constant ulong& precPitch [[buffer(3)]],
                              const device uint* d_derivations [[buffer(4)]],
                              const device uint* derindex [[buffer(5)]],
                              constant uint& der_indexes_size [[buffer(6)]],
                              constant uint& der_start_index [[buffer(7)]],
                              constant int& mode [[buffer(8)]],
                              const device uchar* start_point_dev [[buffer(9)]],
                              constant int& min_len [[buffer(10)]],
                              const device char* passwd [[buffer(11)]],
                              constant uint& pass_size [[buffer(12)]],
                              constant uint& starter_pass [[buffer(13)]],
                              constant bool& custom_size [[buffer(14)]],
                              constant int& custom_len [[buffer(15)]],
                              constant uchar& entropy_mode [[buffer(16)]],
                              constant uint& iter [[buffer(17)]],
                              constant ulong& round [[buffer(18)]],
                              constant bool& dub_mnem [[buffer(19)]],
                              const device MnwRuntimeBuffers& runtime [[buffer(20)]],
                              uint tid [[thread_position_in_grid]]) {
    (void)dub_mnem;
    FoundBuffers found;
    if (!mnw_make_found_from_runtime(found, runtime)) {
        return;
    }
    mnw_worker_entropy_seq(isResult, buffResult, precPtr, precPitch, d_derivations,
                           derindex, der_indexes_size, der_start_index, mode,
                           start_point_dev, min_len, passwd, pass_size, starter_pass,
                           custom_size, custom_len, entropy_mode, iter, round, tid,
                           *runtime.config, *runtime.filters, *runtime.filterStorage,
                           runtime.bloomStorage, runtime.xorStorage, runtime.xorUnStorage,
                           runtime.xorUcStorage, runtime.xorHcStorage, found,
                           runtime.substratePaths, runtime.customDict);
}
