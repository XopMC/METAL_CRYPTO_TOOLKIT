#include "WorkerBrainCommon.metalh"

kernel void workerBrain_seq(device bool* isResult [[buffer(0)]],
                            device bool* buffResult [[buffer(1)]],
                            constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                            constant ulong& precPitch [[buffer(3)]],
                            constant ulong& round [[buffer(4)]],
                            constant uchar& brain_mode [[buffer(5)]],
                            constant int& mode [[buffer(6)]],
                            const device uchar* start_point_dev [[buffer(7)]],
                            constant int& min_len [[buffer(8)]],
                            constant uint& iter [[buffer(9)]],
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
                            device long* foundRound [[buffer(26)]],
                            device atomic_uint* resultsCount [[buffer(27)]],
                            const device SubstratePathDevice* substratePaths [[buffer(28)]],
                            uint tid [[thread_position_in_grid]]) {
    if (start_point_dev == nullptr) {
        return;
    }

    FoundBuffers found;
    brain_make_found(found, config, foundStrings, foundPrvKeys, foundHash160, foundLen,
                     foundIter, foundType, foundDerivations, foundDerivations2, foundRound,
                     resultsCount);

    char phrases[BRAIN_THREAD_STEPS][BRAIN_PHRASE_BYTES];
    uint lens[BRAIN_THREAD_STEPS];
    uchar prvKeys[BRAIN_THREAD_STEPS * 32u];

    const ulong starter = ulong(BRAIN_THREAD_STEPS) * ulong(tid) * config.seqStep;
    for (uint n = 0u; n < BRAIN_THREAD_STEPS; ++n) {
        const ulong idx = starter + ulong(n) * config.seqStep;
        brain_fill_seq_phrase(phrases[n], lens[n], start_point_dev, mode, min_len, idx);
        brain_hash_key(phrases[n], lens[n], brain_mode, iter, config.utf8 != 0u,
                       false, prvKeys + n * 32u);
    }

    brain_process_rounds(isResult, buffResult, precPtr, precPitch, phrases, lens, prvKeys,
                         int(BRAIN_THREAD_STEPS), round, iter, config, filters, filter_storage,
                         bloom_storage, xor_storage, xor_un_storage, xor_uc_storage,
                         xor_hc_storage, found, nullptr, false, substratePaths);
}
