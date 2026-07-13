/**********************************************************************
 * Copyright (c) 2016 Llamasoft                                       *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#pragma once
#ifndef _SECP256K1_BATCH_IMPL_H_
#define _SECP256K1_BATCH_IMPL_H_

#include <stddef.h>
#include "secp256k1_common.h"
#include "secp256k1_group.h"
#include "secp256k1.h"
#define THREAD_STEPS_local 32
#define THREAD_STEPS_BRUTE_local 64
#define THREAD_STEPS_BRAIN_local 16
#define WALK_CHUNK 64
#define THREAD_STEPS_PUB 64

typedef struct secp256k1_scratch_struct secp256k1_scratch;
typedef struct secp256k1_scratch_struct2 secp256k1_scratch2;
typedef struct secp256k1_scratch_struct3 secp256k1_scratch3;
typedef struct secp256k1_scratch_struct4 secp256k1_scratch4;
/* Scratch space for secp256k1_ec_pubkey_create_batch's temporary results. */
struct secp256k1_scratch_struct {
    /* Output from individual secp256k1_ecmult_gen. */
    secp256k1_gej gej[THREAD_STEPS_local];

    /* Input and output buffers for secp256k1_fe_inv_all_var. */
    secp256k1_fe  fe_in[THREAD_STEPS_local];
    secp256k1_fe  fe_out[THREAD_STEPS_local];
};
struct secp256k1_scratch_struct2 {
    /* Output from individual secp256k1_ecmult_gen. */
    secp256k1_gej gej[THREAD_STEPS_BRUTE_local];

    /* Input and output buffers for secp256k1_fe_inv_all_var. */
    secp256k1_fe  fe_in[THREAD_STEPS_BRUTE_local];
    secp256k1_fe  fe_out[THREAD_STEPS_BRUTE_local];
};
struct secp256k1_scratch_struct3 {
    secp256k1_gej gej;
    secp256k1_fe  fe_in;
    secp256k1_fe  fe_out;
};
struct secp256k1_scratch_struct4 {
    /* Output from individual secp256k1_ecmult_gen. */
    secp256k1_gej gej[THREAD_STEPS_BRAIN_local];

    /* Input and output buffers for secp256k1_fe_inv_all_var. */
    secp256k1_fe  fe_in[THREAD_STEPS_BRAIN_local];
    secp256k1_fe  fe_out[THREAD_STEPS_BRAIN_local];
};

typedef struct {
    secp256k1_gej gej[THREAD_STEPS_PUB];
    secp256k1_fe  fe_in[THREAD_STEPS_PUB];
    secp256k1_fe  fe_out[THREAD_STEPS_PUB];
} secp256k1_scratch_walk;

typedef struct {
    secp256k1_gej gej[1];
    secp256k1_fe  fe_in[1];
    secp256k1_fe  fe_out[1];
} secp256k1_scratch_walk_one;

extern METAL_DEVICE METAL_ALIGN(16) secp256k1_ge P0_global;  // k0 * G
extern METAL_DEVICE METAL_ALIGN(16) secp256k1_ge H_global;   // step * G / -step * G


METAL_DEVICE  size_t secp256k1_ec_pubkey_create_serialized_batch_myunsafe_brute(unsigned char* __restrict__  pubkeys, const unsigned char* __restrict__ privkeys, const int keyLen, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch);

METAL_DEVICE  size_t secp256k1_ec_pubkey_create_serialized_batch_myunsafe(unsigned char* __restrict__  pubkeys, const unsigned char* __restrict__ privkeys, const int keyLen, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch);

METAL_DEVICE  size_t secp256k1_ec_pubkey_create_serialized(unsigned char* __restrict__  pubkey, const unsigned char* __restrict__ privkey, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch);

METAL_DEVICE size_t secp256k1_ec_pubkey_create_serialized_batch_myunsafe_brain(unsigned char* __restrict__  pubkeys, const unsigned char* __restrict__ privkeys, const int keyLen, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch);

METAL_DEVICE  void pub_add_basepoint_batch_from_prec(unsigned char* __restrict__ pubKeys, int count, int sign, const secp256k1_ge_storage* __restrict__ precPtr);




METAL_DEVICE void secp256k1_ec_pubkey_from_walk_serialized(
    unsigned char* __restrict__ pubkeys,  // [THREAD_STEPS_PUB * 65]
    uint64_t starter);


//CHUNK


typedef struct {
    secp256k1_gej gej[WALK_CHUNK];
    secp256k1_fe  fe_in[WALK_CHUNK];
    secp256k1_fe  fe_out[WALK_CHUNK];
} secp256k1_walk_chunk_scratch;


template<int KEYS>
struct METAL_ALIGN(16) secp256k1_walk_chunk_scratch_mul {
    secp256k1_gej gej[KEYS];
    secp256k1_fe  fe_in[KEYS];
    secp256k1_fe  fe_out[KEYS];
};


METAL_DEVICE void secp256k1_walk_get_start_gej(
    secp256k1_gej* __restrict__ Pstart,
    uint64_t starter);

METAL_DEVICE void secp256k1_walk_emit_chunk_uncompressed(
    secp256k1_gej* __restrict__ P,
    unsigned char* __restrict__ out_pubkeys65);


template <typename Fn>
METAL_DEVICE void secp256k1_walk_for_each_chunk(
    uint64_t starter, int threas_steps_pub,
    Fn&& fn_process_chunk);



// Multi chunks


template<int KEYS>
METAL_DEVICE void secp256k1_walk_emit_chunk_uncompressed_ct(
    secp256k1_gej* __restrict__ P,
    unsigned char* __restrict__ out_pubkeys65)
{
    METAL_ALIGN(16) secp256k1_walk_chunk_scratch_mul<KEYS> scr;
    METAL_ALIGN(16) secp256k1_ge H = H_global;

#pragma unroll
    for (int i = 0; i < KEYS; ++i) {
        scr.gej[i] = *P;
        scr.fe_in[i] = P->z;
        secp256k1_gej_add_ge(P, P, &H);
    }

    secp256k1_fe_inv_all_var(KEYS, scr.fe_out, scr.fe_in);

#pragma unroll
    for (int i = 0; i < KEYS; ++i) {
        METAL_ALIGN(16) secp256k1_ge ge_pub;
        secp256k1_ge_set_gej_zinv(&ge_pub, &scr.gej[i], &scr.fe_out[i]);

        size_t dummy;
        secp256k1_eckey_pubkey_serialize(&ge_pub, &out_pubkeys65[65 * i], &dummy, false);
    }
}


template<int KEYS, typename Fn>
METAL_DEVICE void secp256k1_walk_for_every_chunk_ct(
    uint64_t starter, int thread_steps_pub, Fn&& fn_process_chunk)
{
    METAL_ALIGN(16) secp256k1_gej P;
    secp256k1_walk_get_start_gej(&P, starter);

    METAL_ALIGN(16) unsigned char pubChunk[KEYS * 65];

#pragma unroll
    for (int chunk = 0; chunk < (thread_steps_pub / KEYS); ++chunk) {
        secp256k1_walk_emit_chunk_uncompressed_ct<KEYS>(&P, pubChunk);
        fn_process_chunk(pubChunk, chunk);
    }
}


template<int KEYS, typename Fn>
METAL_DEVICE void secp256k1_walk_for_every_point_ct(
    uint64_t starter,
    int thread_steps_pub,
    Fn&& fn_process_point)
{
    METAL_ALIGN(16) secp256k1_gej P;
    secp256k1_walk_get_start_gej(&P, starter);
    METAL_ALIGN(16) secp256k1_ge H = H_global;

    METAL_ALIGN(16) secp256k1_walk_chunk_scratch_mul<KEYS> scr;

    int pkFieldBase = 0;

#pragma unroll
    for (int chunk = 0; chunk < (thread_steps_pub / KEYS); ++chunk) {

#pragma unroll
        for (int i = 0; i < KEYS; ++i) {
            scr.gej[i] = P;
            scr.fe_in[i] = P.z;
            secp256k1_gej_add_ge(&P, &P, &H);
        }

        secp256k1_fe_inv_all_var(KEYS, scr.fe_out, scr.fe_in);

#pragma unroll
        for (int i = 0; i < KEYS; ++i) {
            METAL_ALIGN(16) secp256k1_ge ge_pub;
            secp256k1_ge_set_gej_zinv(&ge_pub, &scr.gej[i], &scr.fe_out[i]);

            int pkField = pkFieldBase + i;
            fn_process_point(ge_pub, pkField);
        }

        pkFieldBase += KEYS;
    }
}


#endif
