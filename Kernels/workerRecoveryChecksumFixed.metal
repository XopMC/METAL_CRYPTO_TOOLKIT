#include <metal_stdlib>
#include "WorkerRecoveryCommon.metalh"

using namespace metal;

kernel void workerRecoveryChecksumFixed(const device ushort* base_ids [[buffer(0)]],
                                        const device int* missing_positions [[buffer(1)]],
                                        constant int& missing_count [[buffer(2)]],
                                        constant ulong& range_start [[buffer(3)]],
                                        constant ulong& range_count [[buffer(4)]],
                                        device ushort* out_ids [[buffer(5)]],
                                        device atomic_uint* out_count [[buffer(6)]],
	                                        constant uint& out_capacity [[buffer(7)]],
	                                        constant int& words_count [[buffer(8)]],
	                                        uint tid [[thread_position_in_grid]],
	                                        uint stride [[threads_per_grid]]) {
    if (base_ids == nullptr || out_ids == nullptr || out_count == nullptr ||
        words_count <= 0 || words_count > 48 || (words_count % 3) != 0 ||
        missing_count < 0 || missing_count > words_count || missing_count > 48 ||
        (missing_count > 0 && missing_positions == nullptr)) {
        return;
    }

    thread ushort ids[48];
    thread int missing_pos_local[48];

    for (int i = 0; i < words_count; ++i) {
        ids[i] = base_ids[i];
    }
    for (int j = 0; j < missing_count; ++j) {
        const int pos = missing_positions[j];
        if (pos < 0 || pos >= words_count) {
            return;
        }
        missing_pos_local[j] = pos;
    }

    for (ulong local = ulong(tid); local < range_count; local += ulong(stride)) {
        ulong combo = range_start + local;

        for (int j = 0; j < missing_count; ++j) {
            const int pos = missing_pos_local[j];
            ids[pos] = ushort(combo & 0x7fful);
            combo >>= 11;
        }

        if (!recovery_checksum_valid_ids_fixed(ids, words_count)) {
            continue;
        }

        const uint slot = atomic_fetch_add_explicit(out_count, 1u, memory_order_relaxed);
        if (slot < out_capacity) {
            device ushort* dst = out_ids + (size_t(slot) * size_t(words_count));
            for (int i = 0; i < words_count; ++i) {
                dst[i] = ids[i];
            }
        }
    }
}
