#include <metal_stdlib>
#include "WorkerPRIVSeqNewCommon.metalh"

using namespace metal;

kernel void compute_P0_H_kernel(constant uchar* start_point [[buffer(0)]],
                                constant ulong& step [[buffer(1)]],
                                constant secp256k1_ge_storage* precPtr [[buffer(2)]],
                                constant ulong& precPitch [[buffer(3)]],
                                constant int& mode [[buffer(4)]],
                                device SecpWalkState& walkState [[buffer(5)]],
                                constant uint& windowsSize [[buffer(6)]],
                                constant uint& ecmultWindowSize [[buffer(7)]],
                                uint tIx [[thread_position_in_grid]]) {
    if (tIx != 0u) {
        return;
    }

    secp256k1_scalar s_k0;
    secp256k1_scalar s_step;
    secp256k1_gej gej_P0;
    secp256k1_gej gej_H;

    thread uchar start_local[32];
    for (int i = 0; i < 32; i++) {
        start_local[i] = start_point[i];
    }

    secp256k1_scalar_set_b32(&s_k0, start_local, NULL);
    secp256k1_ecmult_big(&gej_P0, &s_k0, precPtr, precPitch, int(windowsSize), ecmultWindowSize);

    thread uchar step_be[32];
    for (int i = 0; i < 32; i++) {
        step_be[i] = 0;
    }
    for (int i = 0; i < 8; ++i) {
        step_be[31 - i] = uchar((step >> ulong(8 * i)) & 0xfful);
    }
    secp256k1_scalar_set_b32(&s_step, step_be, NULL);
    secp256k1_ecmult_big(&gej_H, &s_step, precPtr, precPitch, int(windowsSize), ecmultWindowSize);

    secp256k1_ge ge_P0;
    secp256k1_ge ge_H;
    secp256k1_ge_set_gej(&ge_P0, &gej_P0);
    secp256k1_ge_set_gej(&ge_H, &gej_H);

    if (mode < 0) {
        secp256k1_ge_neg(&ge_H, &ge_H);
    }

    walkState.p0 = ge_P0;
    walkState.h = ge_H;
}
