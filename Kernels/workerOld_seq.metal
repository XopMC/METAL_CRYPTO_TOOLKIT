#include "WorkerOldCommon.metalh"

kernel void workerOld_seq(device bool* isResult [[buffer(0)]],
                          device bool* buffResult [[buffer(1)]],
                          constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                          constant ulong& precPitch [[buffer(3)]],
                          const device uchar* start_point_dev [[buffer(4)]],
                          constant int& min_len [[buffer(5)]],
                          constant int& mode [[buffer(6)]],
                          constant ulong& round [[buffer(7)]],
                          device RuntimeConfig& config [[buffer(8)]],
                          device XorFilterState& filters [[buffer(9)]],
                          device FilterStorageState& filter_storage [[buffer(10)]],
                          const device uchar* bloom_storage [[buffer(11)]],
                          const device uchar* xor_storage [[buffer(12)]],
                          const device uchar* xor_un_storage [[buffer(13)]],
                          const device uchar* xor_uc_storage [[buffer(14)]],
                          const device uchar* xor_hc_storage [[buffer(15)]],
                          device char* foundStrings [[buffer(16)]],
                          device uchar* foundPrvKeys [[buffer(17)]],
                          device uint* foundHash160 [[buffer(18)]],
                          device uint* foundLen [[buffer(19)]],
                          device uchar* foundType [[buffer(20)]],
                          device uint* foundDerivations [[buffer(21)]],
                          device uint* foundDerivations2 [[buffer(22)]],
                          device long* foundRound [[buffer(23)]],
                          device ulong* foundSeed [[buffer(24)]],
                          device atomic_uint* resultsCount [[buffer(25)]],
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
    worker_old_build_seq_candidate(start_point_dev, min_len, mode, ulong(tid), true, toHash, len);
    worker_old_process_entropy_candidate(isResult, buffResult, toHash, len, precPtr, precPitch,
                                         round, false, 0ul, config, filters, filter_storage,
                                         bloom_storage, xor_storage, xor_un_storage, xor_uc_storage,
                                         xor_hc_storage, found);
}
