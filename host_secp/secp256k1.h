#pragma once
#include "secp256k1_common.h"

METAL_DEVICE  void memczero(void* s, size_t len, int flag);


METAL_DEVICE  uint64_t secp256k1_scalar_shr_any(secp256k1_scalar* __restrict__ s, unsigned int n);


METAL_DEVICE  int64_t secp256k1_scalar_sdigit_single(secp256k1_scalar* __restrict__  s, const unsigned int w);

METAL_DEVICE  void secp256k1_ecmult_gen_fast(secp256k1_gej* r, secp256k1_scalar* gn, const secp256k1_ge_storage _prec[ECMULT_GEN_PREC_N][ECMULT_GEN_PREC_G]);

METAL_DEVICE METAL_NOINLINE void secp256k1_ecmult_gen(secp256k1_gej* r, secp256k1_scalar* gn);


METAL_DEVICE METAL_NOINLINE void secp256k1_pubkey_save(secp256k1_pubkey* pubkey, secp256k1_ge* ge);


METAL_DEVICE  int secp256k1_ec_pubkey_xyz(secp256k1_gej* pj, const unsigned char* seckey, secp256k1_ge_storage _prec[ECMULT_GEN_PREC_N][ECMULT_GEN_PREC_G]);


/** Multiply with the generator: R = a*G.
 *
 *  Args:   bmul:   pointer to an ecmult_big_context (cannot be NULL)
 *  Out:    r:      set to a*G where G is the generator (cannot be NULL)
 *  In:     a:      the scalar to multiply the generator by (cannot be NULL)
 */
METAL_DEVICE  void secp256k1_ecmult_big(secp256k1_gej* __restrict__ r, const secp256k1_scalar* __restrict__ a, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch, const int windowLimit = WINDOWS_SIZE_CONST[0], const unsigned int windowEcmultLimit = ECMULT_WINDOW_SIZE_CONST[0]);




METAL_DEVICE  int secp256k1_eckey_privkey_tweak_add(secp256k1_scalar* key, const secp256k1_scalar* tweak);


METAL_DEVICE  int secp256k1_ec_seckey_tweak_add(unsigned char* seckey, const unsigned char* tweak);






METAL_DEVICE  int secp256k1_pubkey_load(secp256k1_ge* ge, const secp256k1_pubkey* pubkey);

METAL_DEVICE  int secp256k1_eckey_pubkey_serialize(secp256k1_ge* elem, unsigned char* pub, size_t* size, const bool compressed);

METAL_DEVICE  int secp256k1_ec_pubkey_serialize(unsigned char* output, size_t outputlen, const secp256k1_pubkey* pubkey, bool flags);

METAL_DEVICE
void serialized_public_key(uint8_t* pub, uint8_t* serialized_key);

METAL_DEVICE  int secp256k1_ec_pubkey_create(secp256k1_pubkey* pubkey, const unsigned char* seckey, const secp256k1_ge_storage* __restrict__ precPtr, const size_t precPitch);


METAL_DEVICE  int secp256k1_ec_pubkey_tweak_add_xonly(unsigned char* pubkey_x, const unsigned char* tweak);


METAL_DEVICE  int secp256k1_ec_pubkey_tweak_add(secp256k1_pubkey* pubkey, const unsigned char* tweak);


METAL_DEVICE  int secp256k1_ec_pubkey_add(secp256k1_pubkey* result, const secp256k1_pubkey* pubkey, const unsigned char* tweak);