#include <metal_stdlib>
using namespace metal;

#include "StrongholdArgon2Common.metalh"

kernel void workerStrongholdFinal(
    const constant StrongholdArgon2Options& options
        [[buffer(0)]],
    const device ulong* scratch [[buffer(1)]],
    device uchar* derived_keys [[buffer(2)]],
    uint candidate [[thread_position_in_grid]]) {
    if (candidate >= options.candidate_count) return;
    const device ulong* blocks =
        scratch + ulong(candidate) *
        ulong(options.memory_block_count) * 128ul;
    uchar key[32];
    stronghold_argon2_finalize(blocks, options, key);
    device uchar* output =
        derived_keys + ulong(candidate) * 32ul;
#pragma unroll
    for (uint index = 0u; index < 32u; ++index) {
        output[index] = key[index];
    }
}
