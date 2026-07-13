#include "WorkerOldCommon.metalh"

kernel void workerOldSeed(device bool* isResult [[buffer(0)]],
                          device bool* buffResult [[buffer(1)]],
                          const device char* lines [[buffer(2)]],
                          const device uint* indexes [[buffer(3)]],
                          constant uint& indexes_size [[buffer(4)]],
                          constant secp256k1_ge_storage* precPtr [[buffer(5)]],
                          constant ulong& precPitch [[buffer(6)]],
                          constant bool& custom_size [[buffer(7)]],
                          const device int* sizes [[buffer(8)]],
                          constant uint& sizez_size [[buffer(9)]],
                          constant uchar& entropy_mode [[buffer(10)]],
                          const device uint* iterations [[buffer(11)]],
                          constant uint& iterations_size [[buffer(12)]],
                          constant ulong& round [[buffer(13)]],
                          device RuntimeConfig& config [[buffer(14)]],
                          device XorFilterState& filters [[buffer(15)]],
                          device FilterStorageState& filter_storage [[buffer(16)]],
                          const device uchar* bloom_storage [[buffer(17)]],
                          const device uchar* xor_storage [[buffer(18)]],
                          const device uchar* xor_un_storage [[buffer(19)]],
                          const device uchar* xor_uc_storage [[buffer(20)]],
                          const device uchar* xor_hc_storage [[buffer(21)]],
                          device char* foundStrings [[buffer(22)]],
                          device uchar* foundPrvKeys [[buffer(23)]],
                          device uint* foundHash160 [[buffer(24)]],
                          device uint* foundLen [[buffer(25)]],
                          device uchar* foundType [[buffer(26)]],
                          device uint* foundDerivations [[buffer(27)]],
                          device uint* foundDerivations2 [[buffer(28)]],
                          device long* foundRound [[buffer(29)]],
                          device atomic_uint* resultsCount [[buffer(30)]],
                          uint tid [[thread_position_in_grid]]) {
    if (tid >= indexes_size || iterations == nullptr || sizes == nullptr) {
        return;
    }

    FoundBuffers found;
    worker_old_init_found(found, config, foundStrings, foundPrvKeys, foundHash160, foundLen,
                          foundType, foundDerivations, foundDerivations2, foundRound,
                          nullptr, resultsCount);

    for (uint num = 0u; num < iterations_size; ++num) {
        char toHash[512];
        uint len = 0u;
        if (!worker_old_read_indexed_line(lines, indexes, indexes_size, tid, toHash, len)) {
            return;
        }
        const uint iteration = iterations[num];
        worker_old_apply_seed_entropy_mode(toHash, len, entropy_mode, iteration, config);

        for (uint suz = 0u; suz < sizez_size; ++suz) {
            uint candidate_len = len;
            if (custom_size) {
                candidate_len = (sizes[suz] > 0) ? uint(sizes[suz]) : 0u;
            }
            worker_old_process_seed_candidate(isResult, buffResult, toHash, candidate_len,
                                              precPtr, precPitch, round, false, 0ul, config,
                                              filters, filter_storage, bloom_storage, xor_storage,
                                              xor_un_storage, xor_uc_storage, xor_hc_storage, found);
        }
    }
}
