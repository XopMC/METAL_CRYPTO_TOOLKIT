#include "WorkerBip32Common.metalh"

kernel void workerBip32_seq_hexset(device bool* isResult [[buffer(0)]],
                                   device bool* buffResult [[buffer(1)]],
                                   constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                                   constant ulong& precPitch [[buffer(3)]],
                                   const device uint* d_derivations [[buffer(4)]],
                                   const device uint* derindex [[buffer(5)]],
                                   constant uint& der_indexes_size [[buffer(6)]],
                                   constant uint& der_start_index [[buffer(7)]],
                                   const device uchar* hexset_start_digits [[buffer(8)]],
                                   const device uchar* hexset_lower_exact [[buffer(9)]],
                                   const device uchar* hexset_upper_exact [[buffer(10)]],
                                   const device uchar* hexset_alphabet [[buffer(11)]],
                                   constant uint& hexset_base [[buffer(12)]],
                                   constant uint& hexset_size [[buffer(13)]],
                                   constant ulong& gpu_stride [[buffer(14)]],
                                   constant uchar& bip_mode [[buffer(15)]],
                                   constant uint& iter [[buffer(16)]],
                                   constant ulong& round [[buffer(17)]],
                                   const device Bip32RuntimeBuffers& runtime [[buffer(18)]],
                                   uint tid [[thread_position_in_grid]]) {
    FoundBuffers found;
    if (!bip32_make_found_from_runtime(found, runtime)) {
        return;
    }
    bip32_worker_seq_hexset(false, isResult, buffResult, precPtr, precPitch, d_derivations,
                            derindex, der_indexes_size, der_start_index, hexset_start_digits,
                            hexset_lower_exact, hexset_upper_exact, hexset_alphabet,
                            hexset_base, hexset_size, gpu_stride, bip_mode, iter, round,
                            tid, *runtime.config, *runtime.filters, *runtime.filterStorage,
                            runtime.bloomStorage, runtime.xorStorage, runtime.xorUnStorage,
                            runtime.xorUcStorage, runtime.xorHcStorage, found,
                            runtime.substratePaths);
}
