#include "WorkerBip32Common.metalh"

kernel void workerBip32(device bool* isResult [[buffer(0)]],
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
                        constant uchar& bip_mode [[buffer(11)]],
                        const device uint* iterations [[buffer(12)]],
                        constant uint& iterations_size [[buffer(13)]],
                        constant ulong& round [[buffer(14)]],
                        const device Bip32RuntimeBuffers& runtime [[buffer(15)]],
                        uint tid [[thread_position_in_grid]]) {
    FoundBuffers found;
    if (!bip32_make_found_from_runtime(found, runtime)) {
        return;
    }
    bip32_worker_file(isResult, buffResult, precPtr, precPitch, lines, indexes,
                      indexes_size, d_derivations, derindex, der_indexes_size,
                      der_start_index, bip_mode, iterations, iterations_size, round, tid,
                      *runtime.config, *runtime.filters, *runtime.filterStorage,
                      runtime.bloomStorage, runtime.xorStorage, runtime.xorUnStorage,
                      runtime.xorUcStorage, runtime.xorHcStorage, found,
                      runtime.substratePaths);
}
