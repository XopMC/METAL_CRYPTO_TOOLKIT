#include "WorkerArmoryCommon.metalh"

kernel void workerArmory_recovery_hexset(device bool* isResult [[buffer(0)]],
                                         device bool* buffResult [[buffer(1)]],
                                         constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                                         constant ulong& precPitch [[buffer(3)]],
                                         constant uint& child [[buffer(4)]],
                                         const device uchar* hexset_start_digits [[buffer(5)]],
                                         const device uchar* hexset_alphabet [[buffer(6)]],
                                         constant uint& hexset_base [[buffer(7)]],
                                         constant uint& hexset_size [[buffer(8)]],
                                         constant ulong& gpu_stride [[buffer(9)]],
                                         constant ulong& round [[buffer(10)]],
                                         device RuntimeConfig& config [[buffer(11)]],
                                         device XorFilterState& filters [[buffer(12)]],
                                         device FilterStorageState& filter_storage [[buffer(13)]],
                                         const device uchar* bloom_storage [[buffer(14)]],
                                         const device uchar* xor_storage [[buffer(15)]],
                                         const device uchar* xor_un_storage [[buffer(16)]],
                                         const device uchar* xor_uc_storage [[buffer(17)]],
                                         const device uchar* xor_hc_storage [[buffer(18)]],
                                         device char* foundStrings [[buffer(19)]],
                                         device uchar* foundPrvKeys [[buffer(20)]],
                                         device uint* foundHash160 [[buffer(21)]],
                                         device uint* foundLen [[buffer(22)]],
                                         device uchar* foundType [[buffer(23)]],
                                         device uint* foundDerivations [[buffer(24)]],
                                         device long* foundRound [[buffer(25)]],
                                         device ulong* foundSeed [[buffer(26)]],
                                         device atomic_uint* resultsCount [[buffer(27)]],
                                         uint tid [[thread_position_in_grid]]) {
    if (hexset_size == 0u || hexset_size > 256u || gpu_stride == 0ul) {
        return;
    }
    char source[512];
    if (!recovery_hexset_materialize_candidate_exact(hexset_start_digits, hexset_size * 2u,
                                                     hexset_alphabet, hexset_base,
                                                     ulong(tid) * gpu_stride,
                                                     reinterpret_cast<thread uchar*>(source))) {
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
    if (!armory_easy16_materialize_root(source, ulong(hexset_size), rootkey, chaincode)) {
        return;
    }
    armory_process_root_and_chain(env, source, ulong(hexset_size), rootkey, chaincode, child,
                                  round, ulong(tid) * gpu_stride, true,
                                  ulong(tid) * gpu_stride, 0u, false, false);
}
