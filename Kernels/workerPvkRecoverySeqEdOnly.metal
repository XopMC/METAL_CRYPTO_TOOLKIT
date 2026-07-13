#include "WorkerRecoveryPipelineCommon.metalh"

kernel void workerPvkRecoverySeqEdOnly(device bool* isResult [[buffer(0)]],
                                       device bool* buffResult [[buffer(1)]],
                                       const device char* template_text [[buffer(2)]],
                                       constant uint& template_len [[buffer(3)]],
                                       const device uchar* start_private_key [[buffer(4)]],
                                       constant ulong& step [[buffer(5)]],
                                       constant ulong& range_start [[buffer(6)]],
                                       constant ulong& range_count [[buffer(7)]],
                                       constant uint& keys_per_thread [[buffer(8)]],
                                       constant uchar& launch_kind_raw [[buffer(9)]],
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
    (void)launch_kind_raw;
    if (start_private_key == nullptr || keys_per_thread == 0u) {
        return;
    }
    const ulong starter = range_start + ulong(tid) * ulong(keys_per_thread);
    const ulong end_index = range_start + range_count;
    if (starter >= end_index) {
        return;
    }

    FoundBuffers found;
    recovery_make_found_buffers(foundStrings, foundPrvKeys, foundHash160, foundLen, foundIter,
                                foundType, foundDerivations, foundDerivations2, foundPass,
                                foundPassSize, foundRound, foundSeed, resultsCount,
                                config.maxFounds, found);

    thread char phrase[512];
    thread uint phrase_len = 0u;
    recovery_template_phrase(template_text, template_len, phrase, phrase_len);

    thread uchar private_key[32];
    recovery_materialize_private_from_offset(start_private_key, step, starter, private_key);
    for (uint local = 0u; local < keys_per_thread; ++local) {
        const ulong candidate_index = starter + ulong(local);
        if (candidate_index >= end_index) {
            break;
        }
        if (local > 0u) {
            bump_key_256(private_key, step, true);
        }
        recovery_eval_ed_private_phrase(isResult, buffResult, tid, 0u, phrase, phrase_len,
                                        private_key, 0ul, nullptr, 0, 0u, config, filters,
                                        filter_storage, bloom_storage, xor_storage,
                                        xor_un_storage, xor_uc_storage, xor_hc_storage, found);
    }
}
