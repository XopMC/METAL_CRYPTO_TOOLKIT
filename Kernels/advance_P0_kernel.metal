#include <metal_stdlib>
#include "WorkerPRIVSeqNewCommon.metalh"

using namespace metal;

kernel void advance_P0_kernel(constant ulong& advance [[buffer(0)]],
                              device SecpWalkState& walkState [[buffer(1)]],
                              uint tIx [[thread_position_in_grid]]) {
    if (tIx != 0u) {
        return;
    }

    secp256k1_ge h = walkState.h;
    secp256k1_ge p0 = walkState.p0;
    secp256k1_gej hj;
    secp256k1_gej tmp;
    secp256k1_gej p0j;
    secp256k1_gej_set_ge(&hj, &h);
    secp256k1_gej_mul_u64_gej(&tmp, &hj, advance);
    secp256k1_gej_set_ge(&p0j, &p0);
    secp256k1_gej_add_var(&p0j, &p0j, &tmp, NULL);

    secp256k1_ge p0new;
    secp256k1_ge_set_gej(&p0new, &p0j);
    walkState.p0 = p0new;
}
