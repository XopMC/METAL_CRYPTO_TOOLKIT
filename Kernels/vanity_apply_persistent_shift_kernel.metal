#include <metal_stdlib>
#include "WorkerPRIVSeqNewCommon.metalh"

using namespace metal;

kernel void vanity_apply_persistent_shift_kernel(device ulong* startx_buf [[buffer(0)]],
                                                 device ulong* starty_buf [[buffer(1)]],
                                                 device SecpWalkState& walkState [[buffer(2)]],
                                                 uint3 threadPositionInThreadgroup [[thread_position_in_threadgroup]],
                                                 uint3 threadsPerThreadgroup [[threads_per_threadgroup]],
                                                 uint3 threadgroupPosition [[threadgroup_position_in_grid]]) {
    if (startx_buf == nullptr || starty_buf == nullptr) {
        return;
    }

    uint threadsPerGroup = threadsPerThreadgroup.x;
    uint tidInGroup = threadPositionInThreadgroup.x;
    device ulong* base_x = startx_buf + threadgroupPosition.x * 4u * threadsPerGroup;
    device ulong* base_y = starty_buf + threadgroupPosition.x * 4u * threadsPerGroup;
    thread ulong sx[4];
    thread ulong sy[4];
    worker_priv_seq_load256a(sx, base_x, tidInGroup, threadsPerGroup);
    worker_priv_seq_load256a(sy, base_y, tidInGroup, threadsPerGroup);

    secp256k1_fe fx;
    secp256k1_fe fy;
    secp256k1_fe dx;
    secp256k1_fe dy;
    worker_priv_seq_u64x4_to_fe(&fx, sx);
    worker_priv_seq_u64x4_to_fe(&fy, sy);
    worker_priv_seq_u64x4_to_fe_device(&dx, walkState.vanityPersistShiftX);
    worker_priv_seq_u64x4_to_fe_device(&dy, walkState.vanityPersistShiftY);

    secp256k1_ge p;
    secp256k1_ge d;
    p.infinity = 0;
    p.x = fx;
    p.y = fy;
    d.infinity = 0;
    d.x = dx;
    d.y = dy;

    secp256k1_gej pj;
    secp256k1_gej_set_ge(&pj, &p);
    secp256k1_gej_add_ge(&pj, &pj, &d);

    secp256k1_ge r;
    secp256k1_ge_set_gej(&r, &pj);
    worker_priv_seq_fe_to_u64x4(sx, &r.x);
    worker_priv_seq_fe_to_u64x4(sy, &r.y);

    worker_priv_seq_store256a(base_x, sx, tidInGroup, threadsPerGroup);
    worker_priv_seq_store256a(base_y, sy, tidInGroup, threadsPerGroup);
}
