#include "WorkerOldCommon.metalh"

kernel void workerOld_seq_hexset(device bool* isResult [[buffer(0)]],
                                 device bool* buffResult [[buffer(1)]],
                                 constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                                 constant ulong& precPitch [[buffer(3)]],
                                 const device uchar* hexset_start_digits [[buffer(4)]],
                                 const device uchar* hexset_lower_exact [[buffer(5)]],
                                 const device uchar* hexset_upper_exact [[buffer(6)]],
                                 const device uchar* hexset_alphabet [[buffer(7)]],
                                 constant uint& hexset_base [[buffer(8)]],
                                 constant uint& hexset_size [[buffer(9)]],
                                 constant ulong& gpu_stride [[buffer(10)]],
                                 constant ulong& round [[buffer(11)]],
                                 device RuntimeConfig& config [[buffer(12)]],
                                 device XorFilterState& filters [[buffer(13)]],
                                 device FilterStorageState& filter_storage [[buffer(14)]],
                                 const device uchar* bloom_storage [[buffer(15)]],
                                 const device uchar* xor_storage [[buffer(16)]],
                                 const device uchar* xor_un_storage [[buffer(17)]],
                                 const device uchar* xor_uc_storage [[buffer(18)]],
                                 const device uchar* xor_hc_storage [[buffer(19)]],
                                 device char* foundStrings [[buffer(20)]],
                                 device uchar* foundPrvKeys [[buffer(21)]],
                                 device uint* foundHash160 [[buffer(22)]],
                                 device uint* foundLen [[buffer(23)]],
                                 device uchar* foundType [[buffer(24)]],
                                 device uint* foundDerivations [[buffer(25)]],
                                 device uint* foundDerivations2 [[buffer(26)]],
                                 device long* foundRound [[buffer(27)]],
                                 device ulong* foundSeed [[buffer(28)]],
                                 device atomic_uint* resultsCount [[buffer(29)]],
                                 uint tid [[thread_position_in_grid]]) {
    if (hexset_size == 0u || hexset_size > 512u || gpu_stride == 0ul) {
        return;
    }

    FoundBuffers found;
    worker_old_init_found(found, config, foundStrings, foundPrvKeys, foundHash160, foundLen,
                          foundType, foundDerivations, foundDerivations2, foundRound,
                          foundSeed, resultsCount);

    char toHash[512];
    const ulong starter = ulong(tid) * gpu_stride;
    if (!hexset_materialize_candidate_exact(hexset_start_digits, hexset_size * 2u,
                                            hexset_alphabet, hexset_base, starter,
                                            reinterpret_cast<thread uchar*>(toHash))) {
        return;
    }
    if (!hexset_candidate_within_exact_bounds(reinterpret_cast<thread uchar*>(toHash),
                                             hexset_lower_exact, hexset_upper_exact, hexset_size)) {
        return;
    }

    worker_old_process_entropy_candidate(isResult, buffResult, toHash, hexset_size, precPtr,
                                         precPitch, round, false, 0ul, config, filters,
                                         filter_storage, bloom_storage, xor_storage,
                                         xor_un_storage, xor_uc_storage, xor_hc_storage, found);
}
