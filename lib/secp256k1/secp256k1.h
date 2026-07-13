#pragma once
#include "secp256k1_common.h"

REC_DEVICE  void memczero(SECP_THREAD void* s, size_t len, int flag);


REC_DEVICE  uint64_t secp256k1_scalar_shr_any(SECP_THREAD secp256k1_scalar* __restrict__ s, unsigned int n);


REC_DEVICE  int64_t secp256k1_scalar_sdigit_single(SECP_THREAD secp256k1_scalar* __restrict__  s, const unsigned int w);

REC_DEVICE  void secp256k1_ecmult_gen_fast(SECP_THREAD secp256k1_gej* r, SECP_THREAD secp256k1_scalar* gn, const SECP_CONSTANT secp256k1_ge_storage _prec[ECMULT_GEN_PREC_N][ECMULT_GEN_PREC_G]);

REC_DEVICE REC_NOINLINE void secp256k1_ecmult_gen(SECP_THREAD secp256k1_gej* r, SECP_THREAD secp256k1_scalar* gn);


REC_DEVICE REC_NOINLINE void secp256k1_pubkey_save(SECP_THREAD secp256k1_pubkey* pubkey, SECP_THREAD secp256k1_ge* ge);


REC_DEVICE  int secp256k1_ec_pubkey_xyz(SECP_THREAD secp256k1_gej* pj, const SECP_THREAD unsigned char* seckey, const SECP_CONSTANT secp256k1_ge_storage _prec[ECMULT_GEN_PREC_N][ECMULT_GEN_PREC_G]);


/** Multiply with the generator: R = a*G.
 *
 *  Args:   bmul:   pointer to an ecmult_big_context (cannot be NULL)
 *  Out:    r:      set to a*G where G is the generator (cannot be NULL)
 *  In:     a:      the scalar to multiply the generator by (cannot be NULL)
 */
REC_DEVICE  void secp256k1_ecmult_big(SECP_THREAD secp256k1_gej* __restrict__ r, const SECP_THREAD secp256k1_scalar* __restrict__ a, const SECP_CONSTANT secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const int windowLimit = SECP_DEFAULT_WINDOWS_SIZE, const unsigned int windowEcmultLimit = SECP_DEFAULT_ECMULT_WINDOW_SIZE);




REC_DEVICE  int secp256k1_eckey_privkey_tweak_add(SECP_THREAD secp256k1_scalar* key, const SECP_THREAD secp256k1_scalar* tweak);


REC_DEVICE  int secp256k1_ec_seckey_tweak_add(SECP_THREAD unsigned char* seckey, const SECP_THREAD unsigned char* tweak);






REC_DEVICE  int secp256k1_pubkey_load(SECP_THREAD secp256k1_ge* ge, const SECP_THREAD secp256k1_pubkey* pubkey);

REC_DEVICE  int secp256k1_eckey_pubkey_serialize(SECP_THREAD secp256k1_ge* elem, SECP_THREAD unsigned char* pub, SECP_THREAD size_t* size, const bool compressed);

REC_DEVICE  int secp256k1_ec_pubkey_serialize(SECP_THREAD unsigned char* output, size_t outputlen, const SECP_THREAD secp256k1_pubkey* pubkey, bool flags);

REC_DEVICE
void serialized_public_key(SECP_THREAD uint8_t* pub, SECP_THREAD uint8_t* serialized_key);

REC_DEVICE  int secp256k1_ec_pubkey_create(SECP_THREAD secp256k1_pubkey* pubkey, const SECP_THREAD unsigned char* seckey, const SECP_CONSTANT secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch);
REC_DEVICE  int secp256k1_ec_pubkey_create_ge(SECP_THREAD secp256k1_ge* ge, const SECP_THREAD unsigned char* seckey, const SECP_CONSTANT secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch);


REC_DEVICE  int secp256k1_ec_pubkey_tweak_add_xonly(SECP_THREAD unsigned char* pubkey_x, const SECP_THREAD unsigned char* tweak);


REC_DEVICE  int secp256k1_ec_pubkey_tweak_add(SECP_THREAD secp256k1_pubkey* pubkey, const SECP_THREAD unsigned char* tweak);


REC_DEVICE  int secp256k1_ec_pubkey_add(SECP_THREAD secp256k1_pubkey* result, const SECP_THREAD secp256k1_pubkey* pubkey, const SECP_THREAD unsigned char* tweak);
