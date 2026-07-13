#include "WorkerPRIVGenCommon.metalh"

kernel void workerPRIV_pattern(device bool* isResult [[buffer(0)]],
                               device bool* buffResult [[buffer(1)]],
                               constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                               constant ulong& precPitch [[buffer(3)]],
                               const device uchar* pattern_start_nibbles [[buffer(4)]],
                               constant uchar& pattern_len [[buffer(5)]],
                               constant ulong& gpu_stride [[buffer(6)]],
                               constant bool& cycle_last_nibble [[buffer(7)]],
                               constant ulong& round [[buffer(8)]],
                               device RuntimeConfig& config [[buffer(9)]],
                               device XorFilterState& filters [[buffer(10)]],
                               device FilterStorageState& filter_storage [[buffer(11)]],
                               const device uchar* bloom_storage [[buffer(12)]],
                               const device uchar* xor_storage [[buffer(13)]],
                               const device uchar* xor_un_storage [[buffer(14)]],
                               const device uchar* xor_uc_storage [[buffer(15)]],
                               const device uchar* xor_hc_storage [[buffer(16)]],
                               device uchar* foundPrvKeys [[buffer(17)]],
                               device uint* foundHash160 [[buffer(18)]],
                               device uchar* foundType [[buffer(19)]],
                               device long* foundRound [[buffer(20)]],
                               device ulong* foundSeed [[buffer(21)]],
                               device atomic_uint* resultsCount [[buffer(22)]],
                               const device SubstratePathDevice* substratePaths [[buffer(23)]],
                               uint tid [[thread_position_in_grid]]) {
    uchar prvKeys[PRIV_GEN_MAX_BATCH * 32u];
    const int count = priv_gen_pattern_variants(pattern_start_nibbles, pattern_len, gpu_stride,
                                                cycle_last_nibble, tid, prvKeys);
    if (count == 0) {
        return;
    }

    FoundBuffers found;
    priv_gen_init_found_minimal(found, config, foundPrvKeys, foundHash160, foundType,
                                foundRound, foundSeed, resultsCount);

    priv_gen_process_rounds(isResult, buffResult, prvKeys, count, round, precPtr, precPitch,
                            false, 0ul, nullptr, false, true, config, filters, filter_storage,
                            bloom_storage, xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage,
                            found, substratePaths);
}
