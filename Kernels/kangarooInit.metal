#include "KangarooCore.metalh"
#include "../lib/secp256k1/secp256k1.metalh"

static inline void kangaroo_limbs_to_be32(const thread ulong limbs[4],
                                          thread uchar bytes[32]) {
    for (uint limb = 0u; limb < 4u; ++limb) {
        const ulong value = limbs[3u - limb];
        for (uint byte = 0u; byte < 8u; ++byte) {
            bytes[limb * 8u + byte] =
                uchar(value >> ulong(56u - byte * 8u));
        }
    }
}

static inline void kangaroo_be32_to_limbs(const thread uchar bytes[32],
                                          thread ulong limbs[4]) {
    for (uint limb = 0u; limb < 4u; ++limb) {
        ulong value = 0ul;
        for (uint byte = 0u; byte < 8u; ++byte) {
            value = (value << 8u) | ulong(bytes[limb * 8u + byte]);
        }
        limbs[3u - limb] = value;
    }
}

static inline secp256k1_ge kangaroo_ge_from_limbs(const device ulong* limbs) {
    ulong x_limbs[4];
    ulong y_limbs[4];
    for (uint i = 0u; i < 4u; ++i) {
        x_limbs[i] = limbs[i];
        y_limbs[i] = limbs[4u + i];
    }
    uchar x_bytes[32];
    uchar y_bytes[32];
    kangaroo_limbs_to_be32(x_limbs, x_bytes);
    kangaroo_limbs_to_be32(y_limbs, y_bytes);
    secp256k1_fe x;
    secp256k1_fe y;
    secp256k1_fe_set_b32(&x, x_bytes);
    secp256k1_fe_set_b32(&y, y_bytes);
    secp256k1_ge out;
    secp256k1_ge_set_xy(&out, &x, &y);
    return out;
}

kernel void kangarooInit(device KangarooState* states [[buffer(0)]],
                         const device ulong* base_a [[buffer(1)]],
                         const device ulong* base_b [[buffer(2)]],
                         constant secp256k1_ge_storage* precompute [[buffer(3)]],
                         constant ulong& precompute_pitch [[buffer(4)]],
                         constant KangarooInitParams& params [[buffer(5)]],
                         uint tid [[thread_position_in_grid]]) {
    if (tid >= params.kangaroo_count) {
        return;
    }

    device KangarooState& state = states[tid];
    uchar scalar_bytes[32];
    for (uint i = 0u; i < 8u; ++i) {
        scalar_bytes[i] = 0u;
    }
    ulong scalar_limbs[4] = {
        state.distance[0],
        state.distance[1],
        state.distance[2],
        state.distance[3]
    };
    kangaroo_limbs_to_be32(scalar_limbs, scalar_bytes);

    secp256k1_scalar scalar;
    secp256k1_scalar_set_b32(&scalar, scalar_bytes, nullptr);
    secp256k1_gej point;
    secp256k1_ecmult_big(&point,
                         &scalar,
                         precompute,
                         precompute_pitch,
                         int(params.windows),
                         params.window_bits);

    if (params.generation_mode == 0u && state.type != 0u) {
        const secp256k1_ge base =
            kangaroo_ge_from_limbs(state.type == 1u ? base_a : base_b);
        secp256k1_gej sum;
        secp256k1_gej_add_ge_var(&sum, &point, &base, nullptr);
        point = sum;
    }

    secp256k1_ge affine;
    secp256k1_ge_set_gej(&affine, &point);
    secp256k1_fe_normalize_var(&affine.x);
    secp256k1_fe_normalize_var(&affine.y);
    uchar x_bytes[32];
    uchar y_bytes[32];
    secp256k1_fe_get_b32(x_bytes, &affine.x);
    secp256k1_fe_get_b32(y_bytes, &affine.y);
    ulong x[4];
    ulong y[4];
    kangaroo_be32_to_limbs(x_bytes, x);
    kangaroo_be32_to_limbs(y_bytes, y);
    for (uint limb = 0u; limb < 4u; ++limb) {
        state.x[limb] = x[limb];
        state.y[limb] = y[limb];
    }
    state.flags = 0u;
}
