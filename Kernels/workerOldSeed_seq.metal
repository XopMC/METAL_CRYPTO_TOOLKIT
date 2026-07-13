#include "WorkerOldCommon.metalh"

kernel void workerOldSeed_seq(device bool* isResult [[buffer(0)]],
                              device bool* buffResult [[buffer(1)]],
                              constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                              constant ulong& precPitch [[buffer(3)]],
                              const device uchar* start_point_dev [[buffer(4)]],
                              constant int& min_len [[buffer(5)]],
                              constant int& mode [[buffer(6)]],
                              constant bool& custom_size [[buffer(7)]],
                              constant int& custom_len [[buffer(8)]],
                              constant uchar& entropy_mode [[buffer(9)]],
                              constant uint& iter [[buffer(10)]],
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
    if (start_point_dev == nullptr) {
        return;
    }

    FoundBuffers found;
    worker_old_init_found(found, config, foundStrings, foundPrvKeys, foundHash160, foundLen,
                          foundType, foundDerivations, foundDerivations2, foundRound,
                          foundSeed, resultsCount);

    char toHash[512];
    uint len = 0u;
    worker_old_build_seq_candidate(start_point_dev, min_len, mode, ulong(tid), false, toHash, len);
    worker_old_apply_seed_entropy_mode(toHash, len, entropy_mode, iter, config);
    if (custom_size) {
        len = (custom_len > 0) ? uint(custom_len) : 0u;
    }
    worker_old_process_seed_candidate(isResult, buffResult, toHash, len, precPtr, precPitch,
                                      round, false, 0ul, config, filters, filter_storage,
                                      bloom_storage, xor_storage, xor_un_storage, xor_uc_storage,
                                      xor_hc_storage, found);
}
