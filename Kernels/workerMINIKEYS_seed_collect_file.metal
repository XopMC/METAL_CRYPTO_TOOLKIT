#include "WorkerMinikeysSeedCommon.metalh"

kernel void workerMINIKEYS_seed_collect_file(const device char* lines [[buffer(0)]],
                                             const device uint* indexes [[buffer(1)]],
                                             constant uint& indexes_size [[buffer(2)]],
                                             const device uchar* sizes [[buffer(3)]],
                                             constant uint& sizes_count [[buffer(4)]],
                                             device uchar* out_valid_minikeys [[buffer(5)]],
                                             device uchar* out_valid_minikey_lens [[buffer(6)]],
                                             device atomic_uint* out_count [[buffer(7)]],
                                             device RuntimeConfig& config [[buffer(8)]],
                                             uint tIx [[thread_position_in_grid]],
                                             ushort simd_lane [[thread_index_in_simdgroup]]) {
    if (lines == nullptr || indexes == nullptr || sizes == nullptr ||
        out_valid_minikeys == nullptr || out_valid_minikey_lens == nullptr || out_count == nullptr) {
        return;
    }
    if (tIx >= indexes_size || sizes_count == 0u) {
        return;
    }

    const uint begin = (tIx == 0u) ? 0u : indexes[tIx - 1u];
    const uint end = indexes[tIx];
    if (end < begin) {
        return;
    }

    const device char* line_ptr = lines + begin;
    uint char_len = end - begin;

    uchar seed_material[512];
    uint seed_len = 0u;

    if (config.isHex != 0u) {
        if ((char_len & 1u) != 0u) {
            return;
        }
        if (char_len > 1024u) {
            char_len = 1024u;
        }
        seed_len = char_len / 2u;
        if (seed_len > 512u) {
            seed_len = 512u;
        }

        for (uint i = 0u; i < seed_len; ++i) {
            const int hi = minikey_seed_hex_nibble(line_ptr[2u * i]);
            const int lo = minikey_seed_hex_nibble(line_ptr[2u * i + 1u]);
            if (hi < 0 || lo < 0) {
                return;
            }
            seed_material[i] = uchar((hi << 4) | lo);
        }
    } else {
        if (char_len > 512u) {
            char_len = 512u;
        }
        seed_len = char_len;
        for (uint i = 0u; i < seed_len; ++i) {
            seed_material[i] = uchar(line_ptr[i]);
        }
    }

    for (uint size_ix = 0u; size_ix < sizes_count; ++size_ix) {
        uchar minikey[31];
        uchar minikey_len = 0u;
        const uchar target_len = sizes[size_ix];
        const bool produced = minikey_seed_private_from_seed(seed_material, seed_len, target_len,
                                                            nullptr, minikey, &minikey_len);

        const uint slot = minikey_stage_reserve(out_count, produced, simd_lane);
        if (produced && slot != 0xffffffffu) {
            const ulong dst_mini = ulong(slot) * ulong(MINIKEY_STAGE_STRIDE);
            minikey_seed_copy_used_bytes(out_valid_minikeys + dst_mini, minikey, minikey_len);
            out_valid_minikey_lens[slot] = minikey_len;
        }
    }
}
