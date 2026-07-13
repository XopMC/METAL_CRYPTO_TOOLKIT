#include "WorkerPRIVGenCommon.metalh"

kernel void workerPRIV_byte(device bool* isResult [[buffer(0)]],
                            device bool* buffResult [[buffer(1)]],
                            const device char* lines [[buffer(2)]],
                            const device uint* indexes [[buffer(3)]],
                            constant uint& indexes_size [[buffer(4)]],
                            constant secp256k1_ge_storage* precPtr [[buffer(5)]],
                            constant ulong& precPitch [[buffer(6)]],
                            constant int& iteration [[buffer(7)]],
                            constant int& bytePosition [[buffer(8)]],
                            constant ulong& round [[buffer(9)]],
                            device RuntimeConfig& config [[buffer(10)]],
                            device XorFilterState& filters [[buffer(11)]],
                            device FilterStorageState& filter_storage [[buffer(12)]],
                            const device uchar* bloom_storage [[buffer(13)]],
                            const device uchar* xor_storage [[buffer(14)]],
                            const device uchar* xor_un_storage [[buffer(15)]],
                            const device uchar* xor_uc_storage [[buffer(16)]],
                            const device uchar* xor_hc_storage [[buffer(17)]],
                            device uchar* foundPrvKeys [[buffer(18)]],
                            device uint* foundHash160 [[buffer(19)]],
                            device uchar* foundType [[buffer(20)]],
                            device long* foundRound [[buffer(21)]],
                            device ulong* foundSeed [[buffer(22)]],
                            device atomic_uint* resultsCount [[buffer(23)]],
                            const device SubstratePathDevice* substratePaths [[buffer(24)]],
                            uint tid [[thread_position_in_grid]]) {
    if (tid >= indexes_size || bytePosition > 32 || bytePosition < 1) {
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
    priv_gen_byte_variants(base_key, iteration, bytePosition, prvKeys);
    priv_gen_process_rounds(isResult, buffResult, prvKeys, int(PRIV_THREAD_STEPS), round, precPtr,
                            precPitch, false, 0ul, nullptr, true, false, config, filters,
                            filter_storage, bloom_storage, xor_storage, xor_un_storage, xor_uc_storage,
                            xor_hc_storage, found, substratePaths);
}
