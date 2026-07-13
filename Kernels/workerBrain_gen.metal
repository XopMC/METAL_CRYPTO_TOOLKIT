#include "WorkerBrainCommon.metalh"
#include "WorkerCommon.metalh"
#include "PrngCommon.metalh"

static inline bool brain_gen_entropy_fill(int entropy_len,
                                          thread char phrase[BRAIN_PHRASE_BYTES],
                                          ulong seed_l,
                                          bool is_64,
                                          int mode,
                                          int gen,
                                          ulong skip64) {
    if (entropy_len <= 0 || entropy_len > 256) {
        return false;
    }
    if (is_64) {
        uchar tmp[256];
        if (!prng64_entropy_fill(entropy_len, tmp, seed_l, mode, gen, skip64)) {
            return false;
        }
        for (int i = 0; i < entropy_len; ++i) {
            phrase[i] = char(tmp[i]);
        }
        for (uint i = uint(entropy_len); i < BRAIN_PHRASE_BYTES; ++i) {
            phrase[i] = 0;
        }
        return true;
    }
    if (seed_l > 0xfffffffful) {
        return false;
    }
    uchar tmp[256];
    if (!prng32_entropy_fill(entropy_len, tmp, uint(seed_l), mode, gen, skip64)) {
        return false;
    }
    for (int i = 0; i < entropy_len; ++i) {
        phrase[i] = char(tmp[i]);
    }
    for (uint i = uint(entropy_len); i < BRAIN_PHRASE_BYTES; ++i) {
        phrase[i] = 0;
    }
    return true;
}

kernel void workerBrain_gen(device bool* isResult [[buffer(0)]],
                            device bool* buffResult [[buffer(1)]],
                            constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                            constant ulong& precPitch [[buffer(3)]],
                            constant ulong& round [[buffer(4)]],
                            constant uchar& brain_mode [[buffer(5)]],
                            constant uint& iteration [[buffer(6)]],
                            constant ulong& seed_d [[buffer(7)]],
                            constant ulong& seed_count [[buffer(8)]],
                            constant bool& is_64 [[buffer(9)]],
                            constant int& entropy_len [[buffer(10)]],
                            constant int& mode [[buffer(11)]],
                            constant int& gen [[buffer(12)]],
                            const device WorkerRuntimeBuffers& runtime [[buffer(13)]],
                            uint tid [[thread_position_in_grid]]) {
    const ulong starter0 = ulong(BRAIN_THREAD_STEPS) * ulong(tid);
    if (starter0 >= seed_count || runtime.config == nullptr) {
        return;
    }

    device RuntimeConfig& config = *runtime.config;
    if (runtime.filters == nullptr || runtime.filterStorage == nullptr) {
        return;
    }

    FoundBuffers found;
    brain_make_found_with_seed(found, config, runtime.foundStrings, runtime.foundPrvKeys,
                               runtime.foundHash160, runtime.foundLen, runtime.foundIter,
                               runtime.foundType, runtime.foundDerivations,
                               runtime.foundDerivations2, runtime.foundRound,
                               runtime.foundSeed, runtime.resultsCount);

    char phrases[BRAIN_THREAD_STEPS][BRAIN_PHRASE_BYTES];
    uint lens[BRAIN_THREAD_STEPS];
    ulong seeds[BRAIN_THREAD_STEPS];
    uchar prvKeys[BRAIN_THREAD_STEPS * 32u];
    int privKeyIx = 0;

    for (; privKeyIx < int(BRAIN_THREAD_STEPS); ++privKeyIx) {
        const ulong localIndex = starter0 + ulong(privKeyIx);
        if (localIndex >= seed_count) {
            break;
        }
        const ulong seed_l = seed_d + localIndex;
        seeds[privKeyIx] = seed_l;
        lens[privKeyIx] = uint(clamp(entropy_len, 0, 256));
        for (uint z = 0u; z < BRAIN_PHRASE_BYTES; ++z) {
            phrases[privKeyIx][z] = 0;
        }
        if (!brain_gen_entropy_fill(entropy_len, phrases[privKeyIx], seed_l, is_64, mode, gen, config.skip64)) {
            continue;
        }
        lens[privKeyIx] = uint(entropy_len);
    }

    for (int n = 0; n < privKeyIx; ++n) {
        brain_hash_key(phrases[n], lens[n], brain_mode, iteration,
                       config.utf8 != 0u, true, prvKeys + uint(n) * 32u);
    }

    brain_process_rounds(isResult, buffResult, precPtr, precPitch, phrases, lens, prvKeys,
                         privKeyIx, round, iteration, config, *runtime.filters,
                         *runtime.filterStorage, runtime.bloomStorage, runtime.xorStorage,
                         runtime.xorUnStorage, runtime.xorUcStorage, runtime.xorHcStorage,
                         found, seeds, true, runtime.substratePaths);
}
