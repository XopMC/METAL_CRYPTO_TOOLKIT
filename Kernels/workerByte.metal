#include "WorkerByteCommon.metalh"

kernel void workerByte(device bool* isResult [[buffer(0)]],
                       device bool* buffResult [[buffer(1)]],
                       constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                       constant ulong& precPitch [[buffer(3)]],
                       const device char* lines [[buffer(4)]],
                       const device uint* indexes [[buffer(5)]],
                       constant uint& indexes_size [[buffer(6)]],
                       const device uint* d_derivations [[buffer(7)]],
                       const device uint* derindex [[buffer(8)]],
                       constant uint& der_indexes_size [[buffer(9)]],
                       constant uint& der_start_index [[buffer(10)]],
                       const device char* passwd [[buffer(11)]],
                       const device uint* pass_size [[buffer(12)]],
                       constant uint& pass_count [[buffer(13)]],
                       constant bool& dub_mnem [[buffer(14)]],
                       const device WorkerRuntimeBuffers& runtime [[buffer(15)]],
                       uint tid [[thread_position_in_grid]]) {
    if (tid >= indexes_size || lines == nullptr || indexes == nullptr) {
        return;
    }

    WorkerEnv env;
    FoundBuffers found;
    if (!worker_init_env(env, found, isResult, buffResult, precPtr, precPitch, runtime)) {
        return;
    }

    char raw[512] = { 0 };
    ulong raw_len = 0ul;
    if (!worker_read_indexed_line(raw, raw_len, lines, indexes, indexes_size, tid)) {
        return;
    }

    char save_hex[512] = { 0 };
    ulong save_hex_len = 0ul;
    byte_hex_phrase(raw, raw_len, save_hex, save_hex_len);

    const uint pass_count_dub = dub_mnem ? (pass_count + 1u) : pass_count;
    for (uint starter_pass = 0u; starter_pass < pass_count_dub; ++starter_pass) {
        const device char* passStart = nullptr;
        const thread char* threadPassStart = nullptr;
        uint passSize = 0u;
        if (dub_mnem && starter_pass == pass_count) {
            threadPassStart = raw;
            passSize = uint(raw_len);
        } else if (passwd != nullptr && pass_size != nullptr && starter_pass < pass_count) {
            const uint start = (starter_pass == 0u) ? 0u : pass_size[starter_pass - 1u];
            const uint end = pass_size[starter_pass];
            passStart = passwd + start;
            passSize = (end >= start) ? (end - start) : 0u;
        }

        byte_process_candidate(env, raw, raw_len, save_hex, save_hex_len,
                               d_derivations, derindex, der_indexes_size, der_start_index,
                               passStart, threadPassStart, passSize, starter_pass, ulong(tid));
    }
}
