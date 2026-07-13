#include "WorkerRecoveryPipelineCommon.metalh"

kernel void workerRecoveryFused(device bool* isResult [[buffer(0)]],
                                device bool* buffResult [[buffer(1)]],
                                constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                                constant ulong& precPitch [[buffer(3)]],
                                const device ushort* base_ids [[buffer(4)]],
                                constant int& words_count [[buffer(5)]],
                                const device int* missing_positions [[buffer(6)]],
                                constant int& missing_count [[buffer(7)]],
                                constant ulong& range_start [[buffer(8)]],
                                constant ulong& range_count [[buffer(9)]],
                                const device uint* d_derivations [[buffer(10)]],
                                const device uint* derindex [[buffer(11)]],
                                constant uint& der_indexes_size [[buffer(12)]],
                                constant uint& der_start_index [[buffer(13)]],
                                const device char* passwd [[buffer(14)]],
                                constant uint& pass_size [[buffer(15)]],
                                constant uint& starter_pass [[buffer(16)]],
                                constant ulong& round [[buffer(17)]],
                                constant uchar& m_mode [[buffer(18)]],
                                const device uint* iterations [[buffer(19)]],
                                constant uint& iterations_size [[buffer(20)]],
                                constant bool& is_str [[buffer(21)]],
                                constant bool& dub_mnem [[buffer(22)]],
                                device atomic_uint* valid_count [[buffer(23)]],
                                const device RecoveryRuntimeBuffers& runtime [[buffer(24)]],
                                uint tid [[thread_position_in_grid]],
                                uint stride [[threads_per_grid]]) {
    (void)starter_pass;
    (void)m_mode;
    (void)is_str;
    (void)dub_mnem;
    if (base_ids == nullptr || d_derivations == nullptr || derindex == nullptr || range_count == 0ul ||
        words_count <= 0 || words_count > 48 || (words_count % 3) != 0 ||
        missing_count < 0 || missing_count > words_count || missing_count > 48 ||
        pass_size > 128u || (missing_count > 0 && missing_positions == nullptr)) {
        return;
    }

    FoundBuffers found;
    if (!recovery_make_found_from_runtime(found, runtime)) {
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

    ulong valid_local = 0ul;
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
        ++valid_local;
        recovery_eval_candidate_secp_ids(isResult, buffResult, tid, precPtr, size_t(precPitch),
                                         ids, words_count, d_derivations, derindex,
                                         der_indexes_size, der_start_index, passwd, pass_size,
                                         round, iterations, iterations_size, *runtime.config,
                                         runtime.customDict, *runtime.filters,
                                         *runtime.filterStorage, runtime.bloomStorage,
                                         runtime.xorStorage, runtime.xorUnStorage,
                                         runtime.xorUcStorage, runtime.xorHcStorage, found);
    }
    recovery_atomic_add_u64(valid_count, valid_local);
}
