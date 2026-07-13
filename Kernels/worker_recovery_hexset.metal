#include "WorkerCommon.metalh"

kernel void worker_recovery_hexset(device bool* isResult [[buffer(0)]],
                                   device bool* buffResult [[buffer(1)]],
                                   constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                                   constant ulong& precPitch [[buffer(3)]],
                                   const device uint* d_derivations [[buffer(4)]],
                                   const device uint* derindex [[buffer(5)]],
                                   constant uint& der_indexes_size [[buffer(6)]],
                                   constant uint& der_start_index [[buffer(7)]],
                                   const device uchar* hexset_start_digits [[buffer(8)]],
                                   const device uchar* hexset_lower_exact [[buffer(9)]],
                                   const device uchar* hexset_upper_exact [[buffer(10)]],
                                   const device uchar* hexset_alphabet [[buffer(11)]],
                                   constant uint& hexset_base [[buffer(12)]],
                                   constant uint& hexset_size [[buffer(13)]],
                                   constant ulong& gpu_stride [[buffer(14)]],
                                   const device char* passwd [[buffer(15)]],
                                   constant uint& pass_size [[buffer(16)]],
                                   constant uint& starter_pass [[buffer(17)]],
                                   constant ulong& round [[buffer(18)]],
                                   constant uchar& m_mode [[buffer(19)]],
                                   const device uint* iterations [[buffer(20)]],
                                   constant uint& iterations_size [[buffer(21)]],
                                   constant bool& is_str [[buffer(22)]],
                                   constant bool& dub_mnem [[buffer(23)]],
                                   const device WorkerRuntimeBuffers& runtime [[buffer(24)]],
                                   uint tid [[thread_position_in_grid]]) {
    (void)dub_mnem;
    if (hexset_size == 0u || hexset_size > 512u || gpu_stride == 0ul || iterations == nullptr) {
        return;
    }

    WorkerEnv env;
    FoundBuffers found;
    if (!worker_init_env(env, found, isResult, buffResult, precPtr, precPitch, runtime)) {
        return;
    }

    const ulong starter = ulong(tid) * gpu_stride;
    for (uint num = 0u; num < iterations_size; ++num) {
        char toHash[512] = { 0 };
        if (!worker_recovery_hexset_materialize_candidate_exact(hexset_start_digits, hexset_size * 2u,
                                                                hexset_alphabet, hexset_base, starter,
                                                                reinterpret_cast<thread uchar*>(toHash))) {
            return;
        }
        ulong len = ulong(hexset_size);
        worker_transform_material(toHash, len, m_mode, iterations[num], (*env.config).utf8 != 0u, is_str);
        worker_process_candidate(env, toHash, len, d_derivations, derindex, der_indexes_size,
                                 der_start_index, passwd, pass_size, starter_pass, round,
                                 ulong(tid), false, 0ul, iterations[num], true);
    }
}
