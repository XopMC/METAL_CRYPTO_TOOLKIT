#include "WorkerBrainCommon.metalh"

kernel void workerBrain_recovery_hexset(device bool* isResult [[buffer(0)]],
                                        device bool* buffResult [[buffer(1)]],
                                        constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                                        constant ulong& precPitch [[buffer(3)]],
                                        constant ulong& round [[buffer(4)]],
                                        constant uchar& brain_mode [[buffer(5)]],
                                        const device uchar* hexset_start_digits [[buffer(6)]],
                                        const device uchar* hexset_lower_exact [[buffer(7)]],
                                        const device uchar* hexset_upper_exact [[buffer(8)]],
                                        const device uchar* hexset_alphabet [[buffer(9)]],
                                        constant uint& hexset_base [[buffer(10)]],
                                        constant uint& hexset_size [[buffer(11)]],
                                        constant ulong& gpu_stride [[buffer(12)]],
                                        constant uint& iter [[buffer(13)]],
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
                                        device uint* foundIter [[buffer(26)]],
                                        device uchar* foundType [[buffer(27)]],
                                        device long* foundRound [[buffer(28)]],
                                        device atomic_uint* resultsCount [[buffer(29)]],
                                        const device SubstratePathDevice* substratePaths [[buffer(30)]],
                                        uint tid [[thread_position_in_grid]]) {
    if (hexset_size == 0u || hexset_size > 256u || gpu_stride == 0ul) {
        return;
    }

    FoundBuffers found;
    brain_make_found(found, config, foundStrings, foundPrvKeys, foundHash160, foundLen,
                     foundIter, foundType, nullptr, nullptr, foundRound, resultsCount);

    char phrases[BRAIN_THREAD_STEPS][BRAIN_PHRASE_BYTES];
    uint lens[BRAIN_THREAD_STEPS];
    uchar prvKeys[BRAIN_THREAD_STEPS * 32u];
    int privKeyIx = 0;

    const ulong starter = ulong(BRAIN_THREAD_STEPS) * ulong(tid) * gpu_stride;
    for (uint n = 0u; n < BRAIN_THREAD_STEPS; ++n) {
        const ulong idx = starter + ulong(n) * gpu_stride;
        if (!brain_fill_hexset_phrase(phrases[privKeyIx], lens[privKeyIx], hexset_start_digits,
                                      hexset_lower_exact, hexset_upper_exact, hexset_alphabet,
                                      hexset_base, hexset_size, idx, true)) {
            continue;
        }
        brain_hash_key(phrases[privKeyIx], lens[privKeyIx], brain_mode, iter,
                       config.utf8 != 0u, false, prvKeys + uint(privKeyIx) * 32u);
        ++privKeyIx;
    }

    brain_process_rounds(isResult, buffResult, precPtr, precPitch, phrases, lens, prvKeys,
                         privKeyIx, round, iter, config, filters, filter_storage, bloom_storage,
                         xor_storage, xor_un_storage, xor_uc_storage, xor_hc_storage, found,
                         nullptr, false, substratePaths);
}
