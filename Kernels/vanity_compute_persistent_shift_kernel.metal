#include <metal_stdlib>
#include "WorkerPRIVSeqNewCommon.metalh"

using namespace metal;

kernel void vanity_compute_persistent_shift_kernel(constant ulong& advance [[buffer(0)]],
                                                   device ulong* out_xy [[buffer(1)]],
                                                   device SecpWalkState& walkState [[buffer(2)]],
                                                   uint tIx [[thread_position_in_grid]]) {
    if (tIx != 0u) {
        return;
    }
    if (advance == 0ul) {
        for (int i = 0; i < 8; ++i) {
            if (out_xy != nullptr) {
                out_xy[i] = 0ul;
            }
            if (i < 4) {
                walkState.vanityPersistShiftX[i] = 0ul;
                walkState.vanityPersistShiftY[i] = 0ul;
            }
        }
        return;
    }

    secp256k1_ge h = walkState.h;
    secp256k1_gej hj;
    secp256k1_gej tmp;
    secp256k1_gej_set_ge(&hj, &h);
    secp256k1_gej_mul_u64_gej(&tmp, &hj, advance);

    secp256k1_ge d;
    secp256k1_ge_set_gej(&d, &tmp);
    thread ulong dx[4];
    thread ulong dy[4];
    worker_priv_seq_fe_to_u64x4(dx, &d.x);
    worker_priv_seq_fe_to_u64x4(dy, &d.y);
    for (int i = 0; i < 4; i++) {
        if (out_xy != nullptr) {
            out_xy[i] = dx[i];
            out_xy[4 + i] = dy[i];
        }
        walkState.vanityPersistShiftX[i] = dx[i];
        walkState.vanityPersistShiftY[i] = dy[i];
    }
}
