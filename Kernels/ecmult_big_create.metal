#include <metal_stdlib>
#include "../KernelState.metalh"
#include "../lib/secp256k1/secp256k1.metalh"

using namespace metal;

kernel void ecmult_big_create(device secp256k1_gej* gej_temp [[buffer(0)]],
                              device secp256k1_fe* z_ratio [[buffer(1)]],
                              device secp256k1_ge_storage* precPtr [[buffer(2)]],
                              constant ulong& precPitch [[buffer(3)]],
                              constant uint& bits [[buffer(4)]],
                              uint tIx [[thread_position_in_grid]]) {
    if (tIx != 0u) {
        return;
    }

    uint windows;
    ulong window_size;
    ulong i;
    ulong row;
    secp256k1_fe fe_zinv;
    secp256k1_ge ge_temp;
    secp256k1_ge ge_window_one = secp256k1_ge_const_g;
    secp256k1_gej gej_window_base;

    windows = (256u / bits) + 1u;
    window_size = (1ul << (bits - 1u));

    secp256k1_gej_set_ge(&gej_window_base, &ge_window_one);

    secp256k1_fe z0;
    secp256k1_fe_set_int(&z0, 0);
    z_ratio[0] = z0;

    for (row = 0; row < windows; row++) {
        window_size = (row == windows - 1u ? (1ul << (256u % bits)) : (1ul << (bits - 1u)));

        if (row > 0) {
            for (i = 0; i < bits; i++) {
                secp256k1_gej_double_var(&gej_window_base, &gej_window_base, NULL);
            }
        }
        gej_temp[0] = gej_window_base;

        secp256k1_ge_set_gej(&ge_window_one, &gej_window_base);

        for (i = 1; i < window_size; i++) {
            secp256k1_gej prev = gej_temp[i - 1u];
            secp256k1_gej next;
            secp256k1_fe ratio;
            secp256k1_gej_add_ge_var(&next, &prev, &ge_window_one, &ratio);
            gej_temp[i] = next;
            z_ratio[i] = ratio;
        }

        i = window_size - 1u;
        secp256k1_gej last = gej_temp[i];
        secp256k1_fe_inv(&fe_zinv, &last.z);
        secp256k1_ge_set_gej_zinv(&ge_temp, &last, &fe_zinv);

        device char* prec_bytes = reinterpret_cast<device char*>(precPtr);
        device secp256k1_ge_storage* row_prec =
            reinterpret_cast<device secp256k1_ge_storage*>(prec_bytes + row * precPitch) + i;
        secp256k1_ge_storage stored;
        secp256k1_ge_to_storage(&stored, &ge_temp);
        *row_prec = stored;

        for (; i > 0; i--) {
            secp256k1_fe ratio = z_ratio[i];
            secp256k1_fe_mul(&fe_zinv, &fe_zinv, &ratio);

            secp256k1_gej prev = gej_temp[i - 1u];
            secp256k1_ge_set_gej_zinv(&ge_temp, &prev, &fe_zinv);

            device secp256k1_ge_storage* prev_row_prec =
                reinterpret_cast<device secp256k1_ge_storage*>(prec_bytes + row * precPitch) + (i - 1u);
            secp256k1_ge_to_storage(&stored, &ge_temp);
            *prev_row_prec = stored;
        }
    }
}
