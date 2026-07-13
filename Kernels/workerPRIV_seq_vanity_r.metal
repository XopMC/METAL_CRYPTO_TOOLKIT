#include "WorkerPRIVVanityCommon.metalh"

kernel void workerPRIV_seq_vanity_r(device bool* isResult [[buffer(0)]],
                                    device bool* buffResult [[buffer(1)]],
                                    constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                                    constant ulong& precPitch [[buffer(3)]],
                                    constant int& mode [[buffer(4)]],
                                    const device uchar* start_point [[buffer(5)]],
                                    constant ulong& step [[buffer(6)]],
                                    constant int& thread_steps_pub [[buffer(7)]],
                                    device ulong* startx_buf [[buffer(8)]],
                                    device ulong* starty_buf [[buffer(9)]],
                                    device RuntimeConfig& config [[buffer(10)]],
                                    device XorFilterState& filters [[buffer(11)]],
                                    device FilterStorageState& filter_storage [[buffer(12)]],
                                    const device uchar* bloom_storage [[buffer(13)]],
                                    const device uchar* xor_storage [[buffer(14)]],
                                    const device uchar* xor_un_storage [[buffer(15)]],
                                    const device uchar* xor_uc_storage [[buffer(16)]],
                                    const device uchar* xor_hc_storage [[buffer(17)]],
                                    device char* foundStrings [[buffer(18)]],
                                    device uchar* foundPrvKeys [[buffer(19)]],
                                    device uint* foundHash160 [[buffer(20)]],
                                    device uint* foundLen [[buffer(21)]],
                                    device uint* foundIter [[buffer(22)]],
                                    device uchar* foundType [[buffer(23)]],
                                    device uint* foundDerivations [[buffer(24)]],
                                    device uint* foundDerivations2 [[buffer(25)]],
                                    device char* foundPass [[buffer(26)]],
                                    device ushort* foundPassSize [[buffer(27)]],
                                    device long* foundRound [[buffer(28)]],
                                    device ulong* foundSeed [[buffer(29)]],
                                    device atomic_uint* resultsCount [[buffer(30)]],
                                    uint tid [[thread_position_in_grid]]) {
    (void)startx_buf;
    (void)starty_buf;
    FoundBuffers found;
    priv_vanity_make_found(foundStrings, foundPrvKeys, foundHash160, foundLen, foundIter,
                           foundType, foundDerivations, foundDerivations2, foundPass,
                           foundPassSize, foundRound, foundSeed, resultsCount, config, found);
    priv_vanity_run(PrivVanityKindR, isResult, buffResult, precPtr, precPitch, mode, start_point,
                    step, thread_steps_pub, config, filters, filter_storage, bloom_storage,
                    xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found, tid);
}
