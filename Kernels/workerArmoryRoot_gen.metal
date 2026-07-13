#include "WorkerArmoryCommon.metalh"

kernel void workerArmoryRoot_gen(device bool* isResult [[buffer(0)]],
                                 device bool* buffResult [[buffer(1)]],
                                 constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                                 constant ulong& precPitch [[buffer(3)]],
                                 constant uint& child [[buffer(4)]],
                                 constant ulong& round [[buffer(5)]],
                                 constant uchar& m_mode [[buffer(6)]],
                                 constant uint& iteration [[buffer(7)]],
                                 constant bool& is_str [[buffer(8)]],
                                 constant ulong& seed_d [[buffer(9)]],
                                 constant ulong& seed_count [[buffer(10)]],
                                 constant bool& is_64 [[buffer(11)]],
                                 constant int& entropy_len [[buffer(12)]],
                                 constant int& mode [[buffer(13)]],
                                 constant int& gen [[buffer(14)]],
                                 const device WorkerRuntimeBuffers& runtime [[buffer(15)]],
                                 uint tid [[thread_position_in_grid]]) {
    const ulong seed_l = seed_d + ulong(tid);
    if (ulong(tid) >= seed_count || (!is_64 && seed_l > 0xfffffffful) ||
        runtime.config == nullptr || runtime.filters == nullptr ||
        runtime.filterStorage == nullptr) {
        return;
    }
    device RuntimeConfig& config = *runtime.config;
    char source[512];
    if (!armory_entropy_fill(entropy_len, source, seed_l, is_64, mode, gen, config.skip64)) {
        return;
    }
    const ulong source_len = ulong(entropy_len);
    char toHash[512];
    for (uint i = 0u; i < uint(source_len); ++i) {
        toHash[i] = source[i];
    }
    ulong len = source_len;
    armory_apply_root_mode(toHash, len, m_mode, iteration, config.utf8 != 0u,
                           is_str, false, config);

    FoundBuffers found;
    armory_make_found(found, config, runtime.foundStrings, runtime.foundPrvKeys,
                      runtime.foundHash160, runtime.foundLen, nullptr, runtime.foundType,
                      runtime.foundDerivations, nullptr, runtime.foundRound,
                      runtime.foundSeed, runtime.resultsCount);
    WorkerEnv env;
    armory_init_env(env, isResult, buffResult, precPtr, precPitch, config, *runtime.filters,
                    *runtime.filterStorage, runtime.bloomStorage, runtime.xorStorage,
                    runtime.xorUnStorage, runtime.xorUcStorage, runtime.xorHcStorage,
                    found, runtime.substratePaths);

    uchar rootkey[65];
    uchar chaincode[32];
    armory_root_materialize(toHash, len, rootkey, chaincode);
    armory_process_root_and_chain(env, source, source_len, rootkey, chaincode, child, round,
                                  ulong(tid), true, seed_l, iteration, true, true);
}
