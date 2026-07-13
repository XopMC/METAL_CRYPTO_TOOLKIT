#include "WorkerArmoryCommon.metalh"

kernel void workerArmoryRoot(device bool* isResult [[buffer(0)]],
                             device bool* buffResult [[buffer(1)]],
                             const device char* lines [[buffer(2)]],
                             const device uint* indexes [[buffer(3)]],
                             constant uint& indexes_size [[buffer(4)]],
                             constant secp256k1_ge_storage* precPtr [[buffer(5)]],
                             constant ulong& precPitch [[buffer(6)]],
                             constant uint& child [[buffer(7)]],
                             constant ulong& round [[buffer(8)]],
                             constant uchar& m_mode [[buffer(9)]],
                             const device uint* iterations [[buffer(10)]],
                             constant uint& iterations_size [[buffer(11)]],
                             constant bool& is_str [[buffer(12)]],
                             device RuntimeConfig& config [[buffer(13)]],
                             device XorFilterState& filters [[buffer(14)]],
                             device FilterStorageState& filter_storage [[buffer(15)]],
                             const device uchar* bloom_storage [[buffer(16)]],
                             const device uchar* xor_storage [[buffer(17)]],
                             const device uchar* xor_un_storage [[buffer(18)]],
                             const device uchar* xor_uc_storage [[buffer(19)]],
                             const device uchar* xor_hc_storage [[buffer(20)]],
                             device char* foundStrings [[buffer(21)]],
                             device uchar* foundPrvKeys [[buffer(22)]],
                             device uint* foundHash160 [[buffer(23)]],
                             device uint* foundLen [[buffer(24)]],
                             device uchar* foundType [[buffer(25)]],
                             device uint* foundDerivations [[buffer(26)]],
                             device long* foundRound [[buffer(27)]],
                             device ulong* foundSeed [[buffer(28)]],
                             device atomic_uint* resultsCount [[buffer(29)]],
                             uint tid [[thread_position_in_grid]]) {
    if (tid >= indexes_size || iterations_size == 0u) {
        return;
    }
    char source[512];
    ulong source_len = 0ul;
    if (!armory_read_indexed_line(lines, indexes, indexes_size, tid, source, source_len)) {
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

    for (uint n = 0u; n < iterations_size; ++n) {
        char toHash[512];
        for (uint i = 0u; i < uint(source_len); ++i) {
            toHash[i] = source[i];
        }
        ulong len = source_len;
        armory_apply_root_mode(toHash, len, m_mode, iterations[n], config.utf8 != 0u,
                               is_str, true, config);
        uchar rootkey[65];
        uchar chaincode[32];
        armory_root_materialize(toHash, len, rootkey, chaincode);
        armory_process_root_and_chain(env, source, source_len, rootkey, chaincode, child,
                                      round, ulong(tid), false, 0ul, iterations[n], true, true);
    }
}
