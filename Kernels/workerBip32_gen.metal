#include "WorkerBip32Common.metalh"

kernel void workerBip32_gen(device bool* isResult [[buffer(0)]],
                            device bool* buffResult [[buffer(1)]],
                            constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                            constant ulong& precPitch [[buffer(3)]],
                            const device uint* d_derivations [[buffer(4)]],
                            const device uint* derindex [[buffer(5)]],
                            constant uint& der_indexes_size [[buffer(6)]],
                            constant uint& der_start_index [[buffer(7)]],
                            constant uchar& bip_mode [[buffer(8)]],
                            constant uint& iteration [[buffer(9)]],
                            constant ulong& seed_d [[buffer(10)]],
                            constant ulong& seed_count [[buffer(11)]],
                            constant bool& is_64 [[buffer(12)]],
                            constant int& entropy_len [[buffer(13)]],
                            constant int& mode [[buffer(14)]],
                            constant int& gen [[buffer(15)]],
                            constant ulong& round [[buffer(16)]],
                            const device Bip32RuntimeBuffers& runtime [[buffer(17)]],
                            uint tid [[thread_position_in_grid]]) {
    FoundBuffers found;
    if (!bip32_make_found_from_runtime(found, runtime)) {
        return;
    }
    bip32_worker_gen(isResult, buffResult, precPtr, precPitch, d_derivations, derindex,
                     der_indexes_size, der_start_index, bip_mode, iteration, seed_d,
                     seed_count, is_64, entropy_len, mode, gen, round, tid, *runtime.config,
                     *runtime.filters, *runtime.filterStorage, runtime.bloomStorage,
                     runtime.xorStorage, runtime.xorUnStorage, runtime.xorUcStorage,
                     runtime.xorHcStorage, found, runtime.substratePaths);
}
