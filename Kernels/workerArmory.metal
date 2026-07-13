#include "WorkerArmoryCommon.metalh"

kernel void workerArmory(device bool* isResult [[buffer(0)]],
                         device bool* buffResult [[buffer(1)]],
                         const device char* lines [[buffer(2)]],
                         const device uint* indexes [[buffer(3)]],
                         constant uint& indexes_size [[buffer(4)]],
                         constant secp256k1_ge_storage* precPtr [[buffer(5)]],
                         constant ulong& precPitch [[buffer(6)]],
                         constant uint& child [[buffer(7)]],
                         constant ulong& round [[buffer(8)]],
                         device RuntimeConfig& config [[buffer(9)]],
                         device XorFilterState& filters [[buffer(10)]],
                         device FilterStorageState& filter_storage [[buffer(11)]],
                         const device uchar* bloom_storage [[buffer(12)]],
                         const device uchar* xor_storage [[buffer(13)]],
                         const device uchar* xor_un_storage [[buffer(14)]],
                         const device uchar* xor_uc_storage [[buffer(15)]],
                         const device uchar* xor_hc_storage [[buffer(16)]],
                         device char* foundStrings [[buffer(17)]],
                         device uchar* foundPrvKeys [[buffer(18)]],
                         device uint* foundHash160 [[buffer(19)]],
                         device uint* foundLen [[buffer(20)]],
                         device uchar* foundType [[buffer(21)]],
                         device uint* foundDerivations [[buffer(22)]],
                         device long* foundRound [[buffer(23)]],
                         device ulong* foundSeed [[buffer(24)]],
                         device atomic_uint* resultsCount [[buffer(25)]],
                         uint tid [[thread_position_in_grid]]) {
    char source[512];
    ulong len = 0ul;
    if (!armory_read_indexed_line(lines, indexes, indexes_size, tid, source, len)) {
        return;
    }

    FoundBuffers found;
    armory_make_found(found, config, foundStrings, foundPrvKeys, foundHash160, foundLen,
                      nullptr, foundType, foundDerivations, nullptr, foundRound,
                      foundSeed, resultsCount);
    WorkerEnv env;
    armory_init_env(env, isResult, buffResult, precPtr, precPitch, config, filters,
                    filter_storage, bloom_storage, xor_storage, xor_un_storage, xor_uc_storage,
                    xor_hc_storage, found, nullptr);

    uchar rootkey[65];
    uchar chaincode[32];
    if (!armory_easy16_materialize_root(source, len, rootkey, chaincode)) {
        return;
    }
    armory_process_root_and_chain(env, source, len, rootkey, chaincode, child, round,
                                  ulong(tid), false, 0ul, 0u, false, false);
}
