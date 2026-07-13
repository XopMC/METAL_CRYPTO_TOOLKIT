#include "WorkerPRIVGenCommon.metalh"

kernel void workerPRIV_hash(device bool* isResult [[buffer(0)]],
                            device bool* buffResult [[buffer(1)]],
                            const device char* lines [[buffer(2)]],
                            const device uint* indexes [[buffer(3)]],
                            constant uint& indexes_size [[buffer(4)]],
                            constant secp256k1_ge_storage* precPtr [[buffer(5)]],
                            constant ulong& precPitch [[buffer(6)]],
                            constant ulong& round [[buffer(7)]],
                            device RuntimeConfig& config [[buffer(8)]],
                            device XorFilterState& filters [[buffer(9)]],
                            device FilterStorageState& filter_storage [[buffer(10)]],
                            const device uchar* bloom_storage [[buffer(11)]],
                            const device uchar* xor_storage [[buffer(12)]],
                            const device uchar* xor_un_storage [[buffer(13)]],
                            const device uchar* xor_uc_storage [[buffer(14)]],
                            const device uchar* xor_hc_storage [[buffer(15)]],
                            device uchar* foundPrvKeys [[buffer(16)]],
                            device uint* foundHash160 [[buffer(17)]],
                            device uchar* foundType [[buffer(18)]],
                            device long* foundRound [[buffer(19)]],
                            device ulong* foundSeed [[buffer(20)]],
                            device atomic_uint* resultsCount [[buffer(21)]],
                            const device SubstratePathDevice* substratePaths [[buffer(22)]],
                            uint tid [[thread_position_in_grid]]) {
    if (tid >= indexes_size) {
        return;
    }

    FoundBuffers found;
    priv_gen_init_found_minimal(found, config, foundPrvKeys, foundHash160, foundType,
                                foundRound, foundSeed, resultsCount);

    uchar base_key[32];
    if (!priv_gen_read_indexed_key(lines, indexes, indexes_size, tid, config, base_key)) {
        return;
    }

    uchar prvKeys[PRIV_GEN_MAX_BATCH * 32u];
    priv_gen_hash_variants(base_key, prvKeys);
    priv_gen_process_rounds(isResult, buffResult, prvKeys, int(PRIV_THREAD_STEPS), round, precPtr,
                            precPitch, false, 0ul, nullptr, false, false, config, filters,
                            filter_storage, bloom_storage, xor_storage, xor_un_storage, xor_uc_storage,
                            xor_hc_storage, found, substratePaths);
}
