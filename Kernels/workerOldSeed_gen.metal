#include "WorkerOldCommon.metalh"

kernel void workerOldSeed_gen(device bool* isResult [[buffer(0)]],
                              device bool* buffResult [[buffer(1)]],
                              constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                              constant ulong& precPitch [[buffer(3)]],
                              constant ulong& seed_d [[buffer(4)]],
                              constant ulong& seed_count [[buffer(5)]],
                              constant bool& is_64 [[buffer(6)]],
                              constant int& entropy_len [[buffer(7)]],
                              constant int& mode [[buffer(8)]],
                              constant int& gen [[buffer(9)]],
                              constant bool& custom_size [[buffer(10)]],
                              constant int& custom_len [[buffer(11)]],
                              constant uchar& entropy_mode [[buffer(12)]],
                              constant uint& iter [[buffer(13)]],
                              constant ulong& round [[buffer(14)]],
                              device RuntimeConfig& config [[buffer(15)]],
                              device XorFilterState& filters [[buffer(16)]],
                              device FilterStorageState& filter_storage [[buffer(17)]],
                              const device uchar* bloom_storage [[buffer(18)]],
                              const device uchar* xor_storage [[buffer(19)]],
                              const device uchar* xor_un_storage [[buffer(20)]],
                              const device uchar* xor_uc_storage [[buffer(21)]],
                              device char* foundStrings [[buffer(22)]],
                              device uchar* foundPrvKeys [[buffer(23)]],
                              device uint* foundHash160 [[buffer(24)]],
                              device uint* foundLen [[buffer(25)]],
                              device uchar* foundType [[buffer(26)]],
                              device uint* foundDerivations [[buffer(27)]],
                              device long* foundRound [[buffer(28)]],
                              device ulong* foundSeed [[buffer(29)]],
                              device atomic_uint* resultsCount [[buffer(30)]],
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
                          foundType, foundDerivations, nullptr, foundRound, foundSeed,
                          resultsCount);

    uchar entropy[512];
    if (!worker_old_entropy_fill(entropy_len, entropy, seed_l, is_64, mode, gen, config.skip64)) {
        return;
    }

    char toHash[512];
    uint len = uint(entropy_len);
    for (uint i = 0u; i < len; ++i) {
        toHash[i] = char(entropy[i]);
    }
    worker_old_apply_seed_entropy_mode(toHash, len, entropy_mode, iter, config);
    if (custom_size) {
        len = (custom_len > 0) ? uint(custom_len) : 0u;
    }

    worker_old_process_seed_candidate(isResult, buffResult, toHash, len, precPtr, precPitch,
                                      round, true, seed_l, config, filters, filter_storage,
                                      bloom_storage, xor_storage, xor_un_storage, xor_uc_storage,
                                      nullptr, found);
}
