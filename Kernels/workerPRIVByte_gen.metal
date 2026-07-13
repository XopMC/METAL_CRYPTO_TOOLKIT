#include "WorkerPRIVGenCommon.metalh"

kernel void workerPRIVByte_gen(device bool* isResult [[buffer(0)]],
                               device bool* buffResult [[buffer(1)]],
                               constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                               constant ulong& precPitch [[buffer(3)]],
                               constant int& iteration [[buffer(4)]],
                               constant int& bytePosition [[buffer(5)]],
                               constant ulong& seed_d [[buffer(6)]],
                               constant ulong& seed_count [[buffer(7)]],
                               constant bool& is_64 [[buffer(8)]],
                               constant int& entropy_len [[buffer(9)]],
                               constant int& mode [[buffer(10)]],
                               constant int& gen [[buffer(11)]],
                               constant ulong& round [[buffer(12)]],
                               device RuntimeConfig& config [[buffer(13)]],
                               device XorFilterState& filters [[buffer(14)]],
                               device FilterStorageState& filter_storage [[buffer(15)]],
                               const device uchar* bloom_storage [[buffer(16)]],
                               const device uchar* xor_storage [[buffer(17)]],
                               const device uchar* xor_un_storage [[buffer(18)]],
                               const device uchar* xor_uc_storage [[buffer(19)]],
                               const device uchar* xor_hc_storage [[buffer(20)]],
                               device uchar* foundPrvKeys [[buffer(21)]],
                               device uint* foundHash160 [[buffer(22)]],
                               device uchar* foundType [[buffer(23)]],
                               device long* foundRound [[buffer(24)]],
                               device ulong* foundSeed [[buffer(25)]],
                               device atomic_uint* resultsCount [[buffer(26)]],
                               const device SubstratePathDevice* substratePaths [[buffer(27)]],
                               uint tid [[thread_position_in_grid]]) {
    if (bytePosition > 32 || bytePosition < 1) {
        return;
    }
    const ulong starter = ulong(tid);
    if (starter >= seed_count) {
        return;
    }
    if (!is_64 && (seed_d + starter) > 0xfffffffful) {
        return;
    }

    FoundBuffers found;
    priv_gen_init_found_minimal(found, config, foundPrvKeys, foundHash160, foundType,
                                foundRound, foundSeed, resultsCount);

    const ulong seed_l = seed_d + starter;
    uchar seed[32];
    priv_gen_seed_from_entropy(seed, seed_l, is_64, entropy_len, mode, gen, config.skip64, false);
    uchar prvKeys[PRIV_GEN_MAX_BATCH * 32u];
    priv_gen_byte_variants(seed, iteration, bytePosition, prvKeys);
    priv_gen_process_rounds(isResult, buffResult, prvKeys, int(PRIV_THREAD_STEPS), round, precPtr,
                            precPitch, true, seed_l, nullptr, true, false, config, filters,
                            filter_storage, bloom_storage, xor_storage, xor_un_storage, xor_uc_storage,
                            xor_hc_storage, found, substratePaths);
}
