#include "WorkerPRIVGenCommon.metalh"

kernel void workerPRIV_gen(device bool* isResult [[buffer(0)]],
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
                           device uchar* foundPrvKeys [[buffer(19)]],
                           device uint* foundHash160 [[buffer(20)]],
                           device uchar* foundType [[buffer(21)]],
                           device long* foundRound [[buffer(22)]],
                           device ulong* foundSeed [[buffer(23)]],
                           device atomic_uint* resultsCount [[buffer(24)]],
                           const device SubstratePathDevice* substratePaths [[buffer(25)]],
                           uint tid [[thread_position_in_grid]]) {
    const ulong starter = ulong(PRIV_THREAD_STEPS) * ulong(tid);
    if (starter >= seed_count) {
        return;
    }
    if (!is_64 && (seed_d + starter) > 0xfffffffful) {
        return;
    }

    FoundBuffers found;
    priv_gen_init_found_minimal(found, config, foundPrvKeys, foundHash160, foundType,
                                foundRound, foundSeed, resultsCount);

    uchar prvKeys[PRIV_GEN_MAX_BATCH * 32u];
    ulong keySeeds[PRIV_GEN_MAX_BATCH];
    for (uint n = 0u; n < PRIV_THREAD_STEPS; ++n) {
        const ulong seed_l = seed_d + starter + ulong(n);
        keySeeds[n] = seed_l;
        uchar seed[32];
        priv_gen_seed_from_entropy(seed, seed_l, is_64, entropy_len, mode, gen, config.skip64, true);
        priv_copy_thread_uchar(prvKeys + n * 32u, seed, 32u);
    }

    priv_gen_process_rounds(isResult, buffResult, prvKeys, int(PRIV_THREAD_STEPS), round, precPtr,
                            precPitch, true, 0ul, keySeeds, true, false, config, filters,
                            filter_storage, bloom_storage, xor_storage, xor_un_storage, xor_uc_storage,
                            xor_hc_storage, found, substratePaths);
}
