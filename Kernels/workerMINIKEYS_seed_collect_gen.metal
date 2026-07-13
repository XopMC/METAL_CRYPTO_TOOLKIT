#include "WorkerMinikeysSeedCommon.metalh"
#include "PrngCommon.metalh"

static inline bool minikey_seed_entropy_fill_gen(int entropy_len,
                                                 thread uchar entropy[512],
                                                 ulong seed_l,
                                                 bool is_64,
                                                 int mode,
                                                 int gen,
                                                 ulong skip64) {
    if (entropy_len <= 0 || entropy_len > 512) {
        return false;
    }
    if (is_64) {
        return prng64_entropy_fill(entropy_len, entropy, seed_l, mode, gen, skip64);
    }
    if (seed_l > 0xfffffffful) {
        return false;
    }
    return prng32_entropy_fill(entropy_len, entropy, uint(seed_l), mode, gen, skip64);
}

kernel void workerMINIKEYS_seed_collect_gen(constant ulong& seed_d [[buffer(0)]],
                                            constant ulong& seed_count [[buffer(1)]],
                                            constant bool& is_64 [[buffer(2)]],
                                            constant int& entropy_len [[buffer(3)]],
                                            constant int& mode [[buffer(4)]],
                                            constant int& gen [[buffer(5)]],
                                            const device uchar* sizes [[buffer(6)]],
                                            constant uint& sizes_count [[buffer(7)]],
                                            device uchar* out_valid_minikeys [[buffer(8)]],
                                            device uchar* out_valid_minikey_lens [[buffer(9)]],
                                            device atomic_uint* out_count [[buffer(10)]],
                                            device RuntimeConfig& config [[buffer(11)]],
                                            uint tIx [[thread_position_in_grid]],
                                            ushort simd_lane [[thread_index_in_simdgroup]]) {
    if (sizes == nullptr || out_valid_minikeys == nullptr ||
        out_valid_minikey_lens == nullptr || out_count == nullptr) {
        return;
    }
    if (sizes_count == 0u || ulong(tIx) >= seed_count) {
        return;
    }

    uchar entropy[512];
    const ulong seed_l = seed_d + ulong(tIx);
    if (!minikey_seed_entropy_fill_gen(entropy_len, entropy, seed_l, is_64, mode, gen, config.skip64)) {
        return;
    }

    for (uint size_ix = 0u; size_ix < sizes_count; ++size_ix) {
        uchar minikey[31];
        uchar minikey_len = 0u;
        const uchar target_len = sizes[size_ix];
        const bool produced = minikey_seed_private_from_seed(entropy, uint(entropy_len), target_len,
                                                            nullptr, minikey, &minikey_len);

        const uint slot = minikey_stage_reserve(out_count, produced, simd_lane);
        if (produced && slot != 0xffffffffu) {
            const ulong dst_mini = ulong(slot) * ulong(MINIKEY_STAGE_STRIDE);
            minikey_seed_copy_used_bytes(out_valid_minikeys + dst_mini, minikey, minikey_len);
            out_valid_minikey_lens[slot] = minikey_len;
        }
    }
}
