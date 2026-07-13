#include <metal_stdlib>
#include "WorkerPRIVSeqNewCommon.metalh"

using namespace metal;

kernel void vanity_set_step_table_kernel(constant ulong& step [[buffer(0)]],
                                         constant secp256k1_ge_storage* precPtr [[buffer(1)]],
                                         constant ulong& precPitch [[buffer(2)]],
                                         device ulong* gx_out [[buffer(3)]],
                                         device ulong* gy_out [[buffer(4)]],
                                         device ulong* _2gnx_out [[buffer(5)]],
                                         device ulong* _2gny_out [[buffer(6)]],
                                         constant uint& windowsSize [[buffer(7)]],
                                         constant uint& ecmultWindowSize [[buffer(8)]],
                                         uint tIx [[thread_position_in_grid]]) {
    if (tIx != 0u) {
        return;
    }

    thread uchar step_be[32];
    for (int i = 0; i < 32; i++) {
        step_be[i] = 0;
    }
    for (int i = 0; i < 8; i++) {
        step_be[31 - i] = uchar((step >> ulong(8 * i)) & 0xfful);
    }

    secp256k1_scalar s_step;
    secp256k1_scalar_set_b32(&s_step, step_be, NULL);

    secp256k1_gej hj;
    secp256k1_ecmult_big(&hj, &s_step, precPtr, precPitch, int(windowsSize), ecmultWindowSize);

    secp256k1_ge h;
    secp256k1_ge_set_gej(&h, &hj);

    secp256k1_gej pj;
    secp256k1_gej_set_ge(&pj, &h);
    secp256k1_ge ge_tmp;

    for (int i = 0; i < int(VS_GRP_TABLE_SIZE_METAL); i++) {
        secp256k1_ge_set_gej(&ge_tmp, &pj);
        thread ulong px[4];
        thread ulong py[4];
        worker_priv_seq_fe_to_u64x4(px, &ge_tmp.x);
        worker_priv_seq_fe_to_u64x4(py, &ge_tmp.y);
        for (int w = 0; w < 4; w++) {
            gx_out[i * 4 + w] = px[w];
        }
        for (int w = 0; w < 4; w++) {
            gy_out[i * 4 + w] = py[w];
        }
        if (i < int(VS_GRP_TABLE_SIZE_METAL) - 1) {
            secp256k1_gej_add_ge(&pj, &pj, &h);
        }
    }

    secp256k1_gej_double_var(&pj, &pj, NULL);
    secp256k1_ge_set_gej(&ge_tmp, &pj);
    thread ulong two_gnx[4];
    thread ulong two_gny[4];
    worker_priv_seq_fe_to_u64x4(two_gnx, &ge_tmp.x);
    worker_priv_seq_fe_to_u64x4(two_gny, &ge_tmp.y);
    for (int w = 0; w < 4; w++) {
        _2gnx_out[w] = two_gnx[w];
    }
    for (int w = 0; w < 4; w++) {
        _2gny_out[w] = two_gny[w];
    }
}
