#include "WorkerCommon.metalh"

kernel void worker_seq(device bool* isResult [[buffer(0)]],
                       device bool* buffResult [[buffer(1)]],
                       constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                       constant ulong& precPitch [[buffer(3)]],
                       const device uint* d_derivations [[buffer(4)]],
                       const device uint* derindex [[buffer(5)]],
                       constant uint& der_indexes_size [[buffer(6)]],
                       constant uint& der_start_index [[buffer(7)]],
                       constant int& mode [[buffer(8)]],
                       const device uchar* start_point_dev [[buffer(9)]],
                       constant int& min_len [[buffer(10)]],
                       const device char* passwd [[buffer(11)]],
                       constant uint& pass_size [[buffer(12)]],
                       constant uint& starter_pass [[buffer(13)]],
                       constant ulong& round [[buffer(14)]],
                       constant uchar& m_mode [[buffer(15)]],
                       const device uint* iterations [[buffer(16)]],
                       constant uint& iterations_size [[buffer(17)]],
                       constant bool& is_str [[buffer(18)]],
                       constant bool& dub_mnem [[buffer(19)]],
                       const device WorkerRuntimeBuffers& runtime [[buffer(20)]],
                       uint tid [[thread_position_in_grid]]) {
    (void)dub_mnem;
    if (start_point_dev == nullptr || iterations == nullptr) {
        return;
    }

    WorkerEnv env;
    FoundBuffers found;
    if (!worker_init_env(env, found, isResult, buffResult, precPtr, precPitch, runtime)) {
        return;
    }

    const ulong starter = ulong(tid) * (*env.config).seqStep;
    for (uint num = 0u; num < iterations_size; ++num) {
        char toHash[512] = { 0 };
        ulong len = 0ul;
        worker_materialize_seq(toHash, len, mode, start_point_dev, min_len, starter);
        worker_transform_material(toHash, len, m_mode, iterations[num], (*env.config).utf8 != 0u, is_str);
        worker_process_candidate(env, toHash, len, d_derivations, derindex, der_indexes_size,
                                 der_start_index, passwd, pass_size, starter_pass, round,
                                 ulong(tid), false, 0ul, iterations[num], true);
    }
}
