#include "WorkerOldCommon.metalh"

kernel void workerOld_gen(device bool* isResult [[buffer(0)]],
                          device bool* buffResult [[buffer(1)]],
                          constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                          constant ulong& precPitch [[buffer(3)]],
                          constant ulong& seed_d [[buffer(4)]],
                          constant ulong& seed_count [[buffer(5)]],
                          constant bool& is_64 [[buffer(6)]],
                          constant int& entropy_len [[buffer(7)]],
                          constant int& mode [[buffer(8)]],
                          constant int& gen [[buffer(9)]],
                          constant ulong& round [[buffer(10)]],
                          device RuntimeConfig& config [[buffer(11)]],
                          device XorFilterState& filters [[buffer(12)]],
                          device FilterStorageState& filter_storage [[buffer(13)]],
                          const device uchar* bloom_storage [[buffer(14)]],
                          const device uchar* xor_storage [[buffer(15)]],
                          const device uchar* xor_un_storage [[buffer(16)]],
                          const device uchar* xor_uc_storage [[buffer(17)]],
                          const device uchar* xor_hc_storage [[buffer(18)]],
                          device char* foundStrings [[buffer(19)]],
                          device uchar* foundPrvKeys [[buffer(20)]],
                          device uint* foundHash160 [[buffer(21)]],
                          device uint* foundLen [[buffer(22)]],
                          device uchar* foundType [[buffer(23)]],
                          device uint* foundDerivations [[buffer(24)]],
                          device uint* foundDerivations2 [[buffer(25)]],
                          device long* foundRound [[buffer(26)]],
                          device ulong* foundSeed [[buffer(27)]],
                          device atomic_uint* resultsCount [[buffer(28)]],
                          uint tid [[thread_position_in_grid]]) {
    const ulong seed_l = seed_d + ulong(tid);
    if (ulong(tid) >= seed_count) {
        return;
    }
    if (!is_64 && seed_l > 0xfffffffful) {
        return;
    }

    FoundBuffers found;
    worker_old_init_found(found, config, foundStrings, foundPrvKeys, foundHash160, foundLen,
                          foundType, foundDerivations, foundDerivations2, foundRound,
                          foundSeed, resultsCount);

    uchar entropy[512];
    if (!worker_old_entropy_fill(entropy_len, entropy, seed_l, is_64, mode, gen, config.skip64)) {
        return;
    }

    char toHash[512];
    const uint len = uint(entropy_len);
    for (uint i = 0u; i < len; ++i) {
        toHash[i] = char(entropy[i]);
    }

    worker_old_process_entropy_candidate(isResult, buffResult, toHash, len, precPtr, precPitch,
                                         round, true, seed_l, config, filters, filter_storage,
                                         bloom_storage, xor_storage, xor_un_storage, xor_uc_storage,
                                         xor_hc_storage, found);
}
