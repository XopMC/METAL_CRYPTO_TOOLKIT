#include "WorkerMnemonicCommon.metalh"

kernel void workerSeed(device bool* isResult [[buffer(0)]],
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
                       constant ulong& round [[buffer(11)]],
                       const device MnwRuntimeBuffers& runtime [[buffer(12)]],
                       uint tid [[thread_position_in_grid]]) {
    FoundBuffers found;
    if (!mnw_make_found_from_runtime(found, runtime)) {
        return;
    }
    mnw_worker_file(MNW_KIND_SEED, isResult, buffResult, precPtr, precPitch, lines,
                    indexes, indexes_size, d_derivations, derindex, der_indexes_size,
                    der_start_index, round, tid, *runtime.config, *runtime.filters,
                    *runtime.filterStorage, runtime.bloomStorage, runtime.xorStorage,
                    runtime.xorUnStorage, runtime.xorUcStorage, runtime.xorHcStorage,
                    found, runtime.substratePaths);
}
