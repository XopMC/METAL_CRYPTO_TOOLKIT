#pragma once
#define ECMULT_BIG_TABLE
#include "../../Kernels/DeviceSupport.metalh"

#define SECP_THREAD thread
#define SECP_CONSTANT constant
#if defined(METAL_CRYPTO_NO_FUNCTION_CONSTANTS)
constant uint SECP_NOFC_ECMULT_WINDOW_SIZE_CONST[1] = { 16u };
constant uint SECP_NOFC_WINDOWS_SIZE_CONST[1] = { 17u };
#define SECP_RUNTIME_WINDOW_BITS (16u)
#define SECP_RUNTIME_WINDOWS (17u)
#define SECP_RUNTIME_WINDOW_SIZE (size_t{1} << (SECP_RUNTIME_WINDOW_BITS - 1u))
#define ECMULT_WINDOW_SIZE_CONST (SECP_NOFC_ECMULT_WINDOW_SIZE_CONST)
#define WINDOWS_SIZE_CONST (SECP_NOFC_WINDOWS_SIZE_CONST)
#else
#define SECP_ECMULT_WINDOW_SIZE_FC_INDEX 90u
#define SECP_WINDOWS_SIZE_FC_INDEX 91u
constant uint SECP_FC_ECMULT_WINDOW_SIZE [[function_constant(SECP_ECMULT_WINDOW_SIZE_FC_INDEX)]];
constant uint SECP_FC_WINDOWS_SIZE [[function_constant(SECP_WINDOWS_SIZE_FC_INDEX)]];
#define SECP_RUNTIME_WINDOW_BITS (is_function_constant_defined(SECP_FC_ECMULT_WINDOW_SIZE) ? SECP_FC_ECMULT_WINDOW_SIZE : 16u)
#define SECP_RUNTIME_WINDOWS (is_function_constant_defined(SECP_FC_WINDOWS_SIZE) ? SECP_FC_WINDOWS_SIZE : 17u)
#define SECP_RUNTIME_WINDOW_SIZE (size_t{1} << (SECP_RUNTIME_WINDOW_BITS - 1u))
#define ECMULT_WINDOW_SIZE_CONST (&SECP_FC_ECMULT_WINDOW_SIZE)
#define WINDOWS_SIZE_CONST (&SECP_FC_WINDOWS_SIZE)
#endif
#define ARCH 32

#ifdef _DEBUG
#define ECMULT_GEN_PREC_BITS 4
#else
#define ECMULT_GEN_PREC_BITS 8// 16
#endif

#define ECMULT_GEN_PREC_B ECMULT_GEN_PREC_BITS

#ifdef ECMULT_BIG_TABLE
#define ECMULT_GEN_PREC_G (1 << ECMULT_GEN_PREC_B)
#define ECMULT_GEN_PREC_N (256 / ECMULT_GEN_PREC_B)
#else
#define ECMULT_GEN_PREC_G (1 << ECMULT_GEN_PREC_B)
#define ECMULT_GEN_PREC_N (256 / ECMULT_GEN_PREC_B)
#endif

#define SECP_DEFAULT_ECMULT_WINDOW_SIZE (SECP_RUNTIME_WINDOW_BITS)
#define SECP_DEFAULT_WINDOWS_SIZE (SECP_RUNTIME_WINDOWS)
#define ECMULT_WINDOW_SIZE (SECP_RUNTIME_WINDOW_BITS)
#define WINDOWS (SECP_RUNTIME_WINDOWS)
#define WINDOW_SIZE (SECP_RUNTIME_WINDOW_SIZE)
#define ECMULT_TABLE_SIZE(w) ((256 / ECMULT_WINDOW_SIZE) * WINDOW_SIZE + (1 << (256 % ECMULT_WINDOW_SIZE)))


#define RIPEMD160_BLOCK_LENGTH 64
#define RIPEMD160_DIGEST_LENGTH 20
#define SECP256K1_FLAGS_TYPE_MASK ((1 << 8) - 1)
#define SECP256K1_FLAGS_TYPE_CONTEXT (1 << 0)
#define SECP256K1_FLAGS_TYPE_COMPRESSION (1 << 1)
#define SECP256K1_FLAGS_BIT_CONTEXT_VERIFY (1 << 8)
#define SECP256K1_FLAGS_BIT_CONTEXT_SIGN (1 << 9)
#define SECP256K1_FLAGS_BIT_CONTEXT_DECLASSIFY (1 << 10)
#define SECP256K1_FLAGS_BIT_COMPRESSION (1 << 8)
#define SECP256K1_EC_COMPRESSED (SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION)
#define SECP256K1_EC_UNCOMPRESSED (SECP256K1_FLAGS_TYPE_COMPRESSION)
#define SECP256K1_TAG_PUBKEY_EVEN 0x02
#define SECP256K1_TAG_PUBKEY_ODD 0x03
#define SECP256K1_TAG_PUBKEY_UNCOMPRESSED 0x04
#define SECP256K1_TAG_PUBKEY_HYBRID_EVEN 0x06
#define SECP256K1_TAG_PUBKEY_HYBRID_ODD 0x07

#define SECP256K1_FE_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {SECP256K1_FE_CONST_INNER((d7), (d6), (d5), (d4), (d3), (d2), (d1), (d0))}
#define SECP256K1_GE_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_CONST((i),(j),(k),(l),(m),(n),(o),(p)), 0}
#define SECP256K1_GE_CONST_INFINITY {SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 0), 1}


#define VERIFY_CHECK(cond) do { (void)(cond); } while(0)

#if ARCH==32
typedef struct {
    uint32_t n[10];
} secp256k1_fe;

typedef struct {
    uint32_t n[8];
} secp256k1_fe_storage;

typedef struct {
    uint32_t d[8];
} secp256k1_scalar;
#define SECP256K1_SCALAR_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {{(d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7)}}
#define SECP256K1_N_0 ((uint32_t)0xD0364141UL)
#define SECP256K1_N_1 ((uint32_t)0xBFD25E8CUL)
#define SECP256K1_N_2 ((uint32_t)0xAF48A03BUL)
#define SECP256K1_N_3 ((uint32_t)0xBAAEDCE6UL)
#define SECP256K1_N_4 ((uint32_t)0xFFFFFFFEUL)
#define SECP256K1_N_5 ((uint32_t)0xFFFFFFFFUL)
#define SECP256K1_N_6 ((uint32_t)0xFFFFFFFFUL)
#define SECP256K1_N_7 ((uint32_t)0xFFFFFFFFUL)
#define SECP256K1_N_C_0 (~SECP256K1_N_0 + 1)
#define SECP256K1_N_C_1 (~SECP256K1_N_1)
#define SECP256K1_N_C_2 (~SECP256K1_N_2)
#define SECP256K1_N_C_3 (~SECP256K1_N_3)
#define SECP256K1_N_C_4 (1)
#define SECP256K1_FE_CONST_INNER(d7, d6, d5, d4, d3, d2, d1, d0) { (d0) & 0x3FFFFFFUL, (((uint32_t)d0) >> 26) | (((uint32_t)(d1) & 0xFFFFFUL) << 6), (((uint32_t)d1) >> 20) | (((uint32_t)(d2) & 0x3FFFUL) << 12), (((uint32_t)d2) >> 14) | (((uint32_t)(d3) & 0xFFUL) << 18), (((uint32_t)d3) >> 8) | (((uint32_t)(d4) & 0x3UL) << 24), (((uint32_t)d4) >> 2) & 0x3FFFFFFUL,(((uint32_t)d4) >> 28) | (((uint32_t)(d5) & 0x3FFFFFUL) << 4), (((uint32_t)d5) >> 22) | (((uint32_t)(d6) & 0xFFFFUL) << 10), (((uint32_t)d6) >> 16) | (((uint32_t)(d7) & 0x3FFUL) << 16), (((uint32_t)d7) >> 10) }
#define SECP256K1_FE_STORAGE_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {{ (d0), (d1), (d2), (d3), (d4), (d5), (d6), (d7) }}
#else
typedef struct {
    /* X = sum(i=0..4, elem[i]*2^52) mod n */
    uint64_t n[5];
} secp256k1_fe;

typedef struct {
    uint64_t n[4];
} secp256k1_fe_storage;

typedef struct {
    uint64_t d[4];
} secp256k1_scalar;

#define SECP256K1_SCALAR_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {{((uint64_t)(d1)) << 32 | (d0), ((uint64_t)(d3)) << 32 | (d2), ((uint64_t)(d5)) << 32 | (d4), ((uint64_t)(d7)) << 32 | (d6)}}
#define SECP256K1_N_0 ((uint64_t)0xBFD25E8CD0364141ULL)
#define SECP256K1_N_1 ((uint64_t)0xBAAEDCE6AF48A03BULL)
#define SECP256K1_N_2 ((uint64_t)0xFFFFFFFFFFFFFFFEULL)
#define SECP256K1_N_3 ((uint64_t)0xFFFFFFFFFFFFFFFFULL)
#define SECP256K1_N_C_0 (~SECP256K1_N_0 + 1)
#define SECP256K1_N_C_1 (~SECP256K1_N_1)
#define SECP256K1_N_C_2 (1)
#define SECP256K1_N_H_0 ((uint64_t)0xDFE92F46681B20A0ULL)
#define SECP256K1_N_H_1 ((uint64_t)0x5D576E7357A4501DULL)
#define SECP256K1_N_H_2 ((uint64_t)0xFFFFFFFFFFFFFFFFULL)
#define SECP256K1_N_H_3 ((uint64_t)0x7FFFFFFFFFFFFFFFULL)

#define SECP256K1_FE_CONST_INNER(d7, d6, d5, d4, d3, d2, d1, d0) { \
    (d0) | (((uint64_t)(d1) & 0xFFFFFUL) << 32), \
    ((uint64_t)(d1) >> 20) | (((uint64_t)(d2)) << 12) | (((uint64_t)(d3) & 0xFFUL) << 44), \
    ((uint64_t)(d3) >> 8) | (((uint64_t)(d4) & 0xFFFFFFFUL) << 24), \
    ((uint64_t)(d4) >> 28) | (((uint64_t)(d5)) << 4) | (((uint64_t)(d6) & 0xFFFFUL) << 36), \
    ((uint64_t)(d6) >> 16) | (((uint64_t)(d7)) << 16) \
}

#define SECP256K1_FE_STORAGE_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {{ \
    (d0) | (((uint64_t)(d1)) << 32), \
    (d2) | (((uint64_t)(d3)) << 32), \
    (d4) | (((uint64_t)(d5)) << 32), \
    (d6) | (((uint64_t)(d7)) << 32) \
}}

#endif

typedef struct {
    secp256k1_fe x;
    secp256k1_fe y;
    int infinity;
} secp256k1_ge;

typedef struct {
    secp256k1_fe x;
    secp256k1_fe y;
    secp256k1_fe z;
    int infinity;
} secp256k1_gej;

typedef struct {
    secp256k1_fe_storage x;
    secp256k1_fe_storage y;
} secp256k1_ge_storage;

typedef struct {
    unsigned char data[64];
} secp256k1_pubkey;

typedef struct {
    int32_t v[9];
} secp256k1_modinv32_signed30;

typedef struct {
    // The modulus in signed30 notation, must be odd and in [3, 2^256].
    secp256k1_modinv32_signed30 modulus;

    // modulus^{-1} mod 2^30
    uint32_t modulus_inv30;
} secp256k1_modinv32_modinfo;



#define SECP256K1_GE_STORAGE_CONST(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p) {SECP256K1_FE_STORAGE_CONST((a),(b),(c),(d),(e),(f),(g),(h)), SECP256K1_FE_STORAGE_CONST((i),(j),(k),(l),(m),(n),(o),(p))}
#define SC SECP256K1_GE_STORAGE_CONST

#define SECP256K1_G SECP256K1_GE_CONST(\
    0x79BE667EUL, 0xF9DCBBACUL, 0x55A06295UL, 0xCE870B07UL,\
    0x029BFCDBUL, 0x2DCE28D9UL, 0x59F2815BUL, 0x16F81798UL,\
    0x483ADA77UL, 0x26A3C465UL, 0x5DA4FBFCUL, 0x0E1108A8UL,\
    0xFD17B448UL, 0xA6855419UL, 0x9C47D08FUL, 0xFB10D4B8UL\
)


REC_DEVICE  int secp256k1_ctz32_var(const uint32_t x);


/* inv256[i] = -(2*i+1)^-1 (mod 256) */
