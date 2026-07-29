#include <metal_stdlib>
using namespace metal;

#include "StrongholdArgon2Common.metalh"

kernel void workerStrongholdFill(
    const constant StrongholdArgon2Options& options
        [[buffer(0)]],
    constant uint& pass [[buffer(1)]],
    constant uint& slice [[buffer(2)]],
    device ulong* scratch [[buffer(3)]],
    uint group [[threadgroup_position_in_grid]],
    uint local_thread [[thread_index_in_threadgroup]],
    uint threads_per_group [[threads_per_threadgroup]]) {
    const uint expected =
        options.parallelism *
        STRONGHOLD_ARGON2_THREADS_PER_LANE;
    if (group >= options.candidate_count ||
        threads_per_group != expected ||
        local_thread >= expected) {
        return;
    }
    const uint argon_lane =
        local_thread /
        STRONGHOLD_ARGON2_THREADS_PER_LANE;
    const uint lane_thread =
        local_thread &
        (STRONGHOLD_ARGON2_THREADS_PER_LANE - 1u);
    device ulong* blocks =
        scratch + ulong(group) *
        ulong(options.memory_block_count) * 128ul;
    stronghold_argon2_fill_segment(
        blocks, options, pass, slice,
        argon_lane, lane_thread);
}
