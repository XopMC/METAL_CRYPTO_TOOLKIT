/*
   This is based on isislovecruft's implementation (https://github.com/isislovecruft/ristretto-donna), fix some issues and make it working.
*/

#ifndef __ristretto255_H__
#define __ristretto255_H__
#include "ed25519-donna/ed25519-donna.h"
#include "ed25519-donna/modm-donna-32bit.h"
typedef uint8_t ristretto255_hash_output[64];

REC_DEVICE uint8_t uint8_32_ct_eq(const thread unsigned char a[32], const thread unsigned char b[32]);

REC_DEVICE int ristretto_decode(thread ge25519 *element, const thread unsigned char bytes[32]);
REC_DEVICE void ristretto_encode(thread unsigned char bytes[32], const thread ge25519 element);
REC_DEVICE void ristretto_from_uniform_bytes(thread ge25519 *element, const thread unsigned char bytes[64]);
REC_DEVICE int ristretto_ct_eq(const thread ge25519 *a, const thread ge25519 *b);
REC_DEVICE void ge25519_scalarmult_tg(thread ge25519 *r, const thread ge25519 *p1, const thread bignum256modm s1);






#endif
