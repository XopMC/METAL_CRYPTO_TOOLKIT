#include "WorkerArmoryCommon.metalh"

kernel void workerArmory_gen(device bool* isResult [[buffer(0)]],
                             device bool* buffResult [[buffer(1)]],
                             constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                             constant ulong& precPitch [[buffer(3)]],
                             constant uint& child [[buffer(4)]],
                             constant ulong& seed_d [[buffer(5)]],
                             constant ulong& seed_count [[buffer(6)]],
                             constant bool& is_64 [[buffer(7)]],
                             constant int& entropy_len [[buffer(8)]],
                             constant int& mode [[buffer(9)]],
                             constant int& gen [[buffer(10)]],
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
                             device long* foundRound [[buffer(26)]],
                             device ulong* foundSeed [[buffer(27)]],
                             device atomic_uint* resultsCount [[buffer(28)]],
                             uint tid [[thread_position_in_grid]]) {
    const ulong seed_l = seed_d + ulong(tid);
    if (ulong(tid) >= seed_count || (!is_64 && seed_l > 0xfffffffful)) {
        return;
    }
    char source[512];
    if (!armory_entropy_fill(entropy_len, source, seed_l, is_64, mode, gen, config.skip64)) {
        return;
    }
    const ulong len = ulong(entropy_len);

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
                                  ulong(tid), true, seed_l, 0u, false, false);
}
