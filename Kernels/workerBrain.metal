#include "WorkerBrainCommon.metalh"

kernel void workerBrain(device bool* isResult [[buffer(0)]],
                        device bool* buffResult [[buffer(1)]],
                        const device char* lines [[buffer(2)]],
                        const device uint* indexes [[buffer(3)]],
                        constant uint& indexes_size [[buffer(4)]],
                        constant secp256k1_ge_storage* precPtr [[buffer(5)]],
                        constant ulong& precPitch [[buffer(6)]],
                        constant ulong& round [[buffer(7)]],
                        constant uchar& brain_mode [[buffer(8)]],
                        const device uint* iterations [[buffer(9)]],
                        constant uint& iterations_size [[buffer(10)]],
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
                        device uint* foundIter [[buffer(23)]],
                        device uchar* foundType [[buffer(24)]],
                        device uint* foundDerivations [[buffer(25)]],
                        device uint* foundDerivations2 [[buffer(26)]],
                        device long* foundRound [[buffer(27)]],
                        device atomic_uint* resultsCount [[buffer(28)]],
                        const device SubstratePathDevice* substratePaths [[buffer(29)]],
                        uint tid [[thread_position_in_grid]]) {
    if (tid >= indexes_size || iterations_size == 0u) {
        return;
    }

    FoundBuffers found;
    brain_make_found(found, config, foundStrings, foundPrvKeys, foundHash160, foundLen,
                     foundIter, foundType, foundDerivations, foundDerivations2, foundRound,
                     resultsCount);

    char phrases[BRAIN_THREAD_STEPS][BRAIN_PHRASE_BYTES];
    uint lens[BRAIN_THREAD_STEPS];
    int privKeyIx = 0;

    ulong starter = ulong(BRAIN_THREAD_STEPS) * ulong(tid);
    while (privKeyIx < int(BRAIN_THREAD_STEPS) && starter < ulong(indexes_size)) {
        const uint len = (starter == 0ul) ? indexes[0] : (indexes[starter] - indexes[starter - 1ul]);
        const ulong offset = (starter == 0ul) ? 0ul : ulong(indexes[starter - 1ul]);
        lens[privKeyIx] = min(len, BRAIN_PHRASE_BYTES);
        brain_copy_device_phrase(phrases[privKeyIx], lines + offset, lens[privKeyIx]);
        ++privKeyIx;
        ++starter;
    }

    for (uint num = 0u; num < iterations_size; ++num) {
        uchar prvKeys[BRAIN_THREAD_STEPS * 32u];
        const uint iteration = iterations[num];
        for (int n = 0; n < privKeyIx; ++n) {
            brain_hash_key(phrases[n], lens[n], brain_mode, iteration,
                           config.utf8 != 0u, true, prvKeys + uint(n) * 32u);
        }
        brain_process_rounds(isResult, buffResult, precPtr, precPitch, phrases, lens, prvKeys,
                             privKeyIx, round, iteration, config, filters, filter_storage,
                             bloom_storage, xor_storage, xor_un_storage, xor_uc_storage,
                             xor_hc_storage, found, nullptr, false, substratePaths);
    }
}
