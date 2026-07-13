#include "WorkerMnemonicCommon.metalh"

kernel void workerHmac_gen(device bool* isResult [[buffer(0)]],
                           device bool* buffResult [[buffer(1)]],
                           constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                           constant ulong& precPitch [[buffer(3)]],
                           const device uint* d_derivations [[buffer(4)]],
                           const device uint* derindex [[buffer(5)]],
                           constant uint& der_indexes_size [[buffer(6)]],
                           constant uint& der_start_index [[buffer(7)]],
                           constant ulong& seed_d [[buffer(8)]],
                           constant ulong& seed_count [[buffer(9)]],
                           constant bool& is_64 [[buffer(10)]],
                           constant int& entropy_len [[buffer(11)]],
                           constant int& mode [[buffer(12)]],
                           constant int& gen [[buffer(13)]],
                           constant ulong& round [[buffer(14)]],
                           const device MnwRuntimeBuffers& runtime [[buffer(15)]],
                           uint tid [[thread_position_in_grid]]) {
    FoundBuffers found;
    if (!mnw_make_found_from_runtime(found, runtime)) {
        return;
    }
    mnw_worker_gen(MNW_KIND_HMAC, isResult, buffResult, precPtr, precPitch, d_derivations,
                   derindex, der_indexes_size, der_start_index, seed_d, seed_count, is_64,
                   entropy_len, mode, gen, round, tid, *runtime.config, *runtime.filters,
                   *runtime.filterStorage, runtime.bloomStorage, runtime.xorStorage,
                   runtime.xorUnStorage, runtime.xorUcStorage, runtime.xorHcStorage,
                   found, runtime.substratePaths);
}
