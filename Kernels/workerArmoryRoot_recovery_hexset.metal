#include "WorkerArmoryCommon.metalh"

kernel void workerArmoryRoot_recovery_hexset(device bool* isResult [[buffer(0)]],
                                             device bool* buffResult [[buffer(1)]],
                                             constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                                             constant ulong& precPitch [[buffer(3)]],
                                             constant uint& child [[buffer(4)]],
                                             constant ulong& round [[buffer(5)]],
                                             constant uchar& m_mode [[buffer(6)]],
                                             constant uint& iteration [[buffer(7)]],
                                             constant bool& is_str [[buffer(8)]],
                                             const device uchar* hexset_start_digits [[buffer(9)]],
                                             const device uchar* hexset_alphabet [[buffer(10)]],
                                             constant uint& hexset_base [[buffer(11)]],
                                             constant uint& hexset_size [[buffer(12)]],
                                             constant ulong& gpu_stride [[buffer(13)]],
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
                                             device long* foundRound [[buffer(28)]],
                                             device ulong* foundSeed [[buffer(29)]],
                                             device atomic_uint* resultsCount [[buffer(30)]],
                                             uint tid [[thread_position_in_grid]]) {
    if (hexset_size == 0u || hexset_size > 256u || gpu_stride == 0ul) {
        return;
    }
    const ulong starter = ulong(tid) * gpu_stride;
    char source[512];
    if (!recovery_hexset_materialize_candidate_exact(hexset_start_digits, hexset_size * 2u,
                                                     hexset_alphabet, hexset_base, starter,
                                                     reinterpret_cast<thread uchar*>(source))) {
        return;
    }
    char toHash[512];
    for (uint i = 0u; i < hexset_size; ++i) {
        toHash[i] = source[i];
    }
    ulong len = ulong(hexset_size);
    armory_apply_root_mode(toHash, len, m_mode, iteration, config.utf8 != 0u,
                           is_str, false, config);

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
    armory_root_materialize(toHash, len, rootkey, chaincode);
    armory_process_root_and_chain(env, source, ulong(hexset_size), rootkey, chaincode, child,
                                  round, starter, true, starter, iteration, true, true);
}
