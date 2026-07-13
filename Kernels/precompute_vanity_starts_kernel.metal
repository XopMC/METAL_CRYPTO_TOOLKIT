#include <metal_stdlib>
#include "WorkerPRIVSeqNewCommon.metalh"

using namespace metal;

kernel void precompute_vanity_starts_kernel(device ulong* startx_buf [[buffer(0)]],
                                            device ulong* starty_buf [[buffer(1)]],
                                            constant int& thread_steps_pub [[buffer(2)]],
                                            device SecpWalkState& walkState [[buffer(3)]],
                                            uint3 gridPosition [[thread_position_in_grid]],
                                            uint3 threadPositionInThreadgroup [[thread_position_in_threadgroup]],
                                            uint3 threadsPerThreadgroup [[threads_per_threadgroup]],
                                            uint3 threadgroupPosition [[threadgroup_position_in_grid]]) {
    uint tIx = gridPosition.x;
    uint tidInGroup = threadPositionInThreadgroup.x;
    ulong starter = ulong(thread_steps_pub) * ulong(tIx);

    secp256k1_gej pstart;
    worker_priv_seq_walk_get_start_gej(&pstart, walkState, starter + ulong(VS_GRP_HALF_METAL));
    secp256k1_ge ge_start;
    secp256k1_ge_set_gej(&ge_start, &pstart);

    thread ulong sx[4];
    thread ulong sy[4];
    worker_priv_seq_fe_to_u64x4(sx, &ge_start.x);
    worker_priv_seq_fe_to_u64x4(sy, &ge_start.y);

    uint threadsPerGroup = threadsPerThreadgroup.x;
    device ulong* base_x = startx_buf + threadgroupPosition.x * 4u * threadsPerGroup;
    device ulong* base_y = starty_buf + threadgroupPosition.x * 4u * threadsPerGroup;
    worker_priv_seq_store256a(base_x, sx, tidInGroup, threadsPerGroup);
    worker_priv_seq_store256a(base_y, sy, tidInGroup, threadsPerGroup);
}
