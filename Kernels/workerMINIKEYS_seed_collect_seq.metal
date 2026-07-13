#include "BigIntFunc.metalh"
#include "WorkerMinikeysSeedCommon.metalh"

kernel void workerMINIKEYS_seed_collect_seq(const device uchar* start_point_dev [[buffer(0)]],
                                            constant int& mode [[buffer(1)]],
                                            constant int& min_len [[buffer(2)]],
                                            const device uchar* sizes [[buffer(3)]],
                                            constant uint& sizes_count [[buffer(4)]],
                                            device uchar* out_valid_minikeys [[buffer(5)]],
                                            device uchar* out_valid_minikey_lens [[buffer(6)]],
                                            device atomic_uint* out_count [[buffer(7)]],
                                            device RuntimeConfig& config [[buffer(8)]],
                                            uint tIx [[thread_position_in_grid]],
                                            ushort simd_lane [[thread_index_in_simdgroup]]) {
    if (start_point_dev == nullptr || sizes == nullptr ||
        out_valid_minikeys == nullptr || out_valid_minikey_lens == nullptr || out_count == nullptr) {
        return;
    }
    if (sizes_count == 0u) {
        return;
    }

    const ulong starter = ulong(tIx) * config.seqStep;

    uint c[16];
    uint r[16];
    loadBE512toWords(start_point_dev, c);
    if (mode == 1) {
        add64to512_device(c, starter, r);
    } else {
        sub64from512_device(c, starter, r);
    }

    int len = sizeBE512_device(r);
    if (len < min_len) {
        len = min_len;
    }
    if (len < 1) {
        len = 1;
    }
    if (len > 64) {
        len = 64;
    }

    uchar seed_be[64];
    uchar seed_material[64];
    storeWordsToBE512(r, seed_be);
    for (int i = 0; i < len; ++i) {
        seed_material[i] = seed_be[64 - len + i];
    }

    for (uint size_ix = 0u; size_ix < sizes_count; ++size_ix) {
        uchar minikey[31];
        uchar minikey_len = 0u;
        const uchar target_len = sizes[size_ix];
        const bool produced = minikey_seed_private_from_seed(seed_material, uint(len), target_len,
                                                            nullptr, minikey, &minikey_len);

        const uint slot = minikey_stage_reserve(out_count, produced, simd_lane);
        if (produced && slot != 0xffffffffu) {
            const ulong dst_mini = ulong(slot) * ulong(MINIKEY_STAGE_STRIDE);
            minikey_seed_copy_used_bytes(out_valid_minikeys + dst_mini, minikey, minikey_len);
            out_valid_minikey_lens[slot] = minikey_len;
        }
    }
}
