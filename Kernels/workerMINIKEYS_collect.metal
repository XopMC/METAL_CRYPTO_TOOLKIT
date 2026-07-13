#include "WorkerMinikeysCommon.metalh"

kernel void workerMINIKEYS_collect(const device uchar* suffix_start_base58 [[buffer(0)]],
                                   const device uchar* suffix_end_base58 [[buffer(1)]],
                                   constant uchar& suffix_len [[buffer(2)]],
                                   constant ulong& gpu_stride [[buffer(3)]],
                                   device uchar* out_valid_minikeys [[buffer(4)]],
                                   device uchar* out_valid_minikey_lens [[buffer(5)]],
                                   device atomic_uint* out_count [[buffer(6)]],
                                   constant uint& out_capacity [[buffer(7)]],
                                   uint tid [[thread_position_in_grid]],
                                   ushort simd_lane [[thread_index_in_simdgroup]]) {
    if (suffix_start_base58 == nullptr || suffix_end_base58 == nullptr ||
        suffix_len == 0u || suffix_len > 29u || gpu_stride == 0ul ||
        out_valid_minikeys == nullptr || out_valid_minikey_lens == nullptr ||
        out_count == nullptr || out_capacity == 0u) {
        return;
    }

    const uchar minikey_len = uchar(suffix_len + 1u);
    const ulong thread_base_start = ulong(tid) * ulong(MINIKEY_THREAD_STEPS);
    ulong thread_offset = 0ul;
    if (!minikey_mul_u64_checked(thread_base_start, gpu_stride, thread_offset)) {
        return;
    }

    uchar suffix_counter[29];
    for (uchar i = 0u; i < suffix_len; ++i) {
        suffix_counter[i] = suffix_start_base58[i];
    }
    if (!minikey_add_base58_counter(suffix_counter, suffix_len, thread_offset)) {
        return;
    }

    for (uint step = 0u; step < MINIKEY_THREAD_STEPS; ++step) {
        if (minikey_cmp_base58_counter(suffix_counter, suffix_end_base58, suffix_len) > 0) {
            break;
        }

        uchar msg_with_q[31];
        minikey_make_ascii_with_q(msg_with_q, suffix_counter, suffix_len);
        const bool valid = minikey_seed_check_with_q_fast(msg_with_q, minikey_len);
        const uint slot = minikey_stage_reserve(out_count, valid, simd_lane);
        if (slot != 0xffffffffu) {
            minikey_stage_emit(out_valid_minikeys, out_valid_minikey_lens, out_capacity,
                               slot, msg_with_q, minikey_len);
        }

        if (step + 1u < MINIKEY_THREAD_STEPS) {
            if (!minikey_add_base58_counter(suffix_counter, suffix_len, gpu_stride)) {
                break;
            }
        }
    }
}
