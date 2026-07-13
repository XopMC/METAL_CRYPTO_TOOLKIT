#ifndef ED25519_H
#define ED25519_H


#if defined(__cplusplus)
extern "C" {
#endif

typedef unsigned char ed25519_signature[64];
typedef unsigned char ed25519_public_key[32];
typedef unsigned char ed25519_secret_key[32];

typedef unsigned char curved25519_key[32];


REC_DEVICE void set_scalar();
REC_DEVICE void set_hash();
REC_DEVICE void set_le();
REC_DEVICE void ed25519_publickey(const ed25519_secret_key sk, ed25519_public_key pk);
REC_DEVICE void ed25519_key_to_pub(const ed25519_secret_key sk, ed25519_public_key pk);

REC_DEVICE void curved25519_scalarmult_basepoint(curved25519_key pk, const curved25519_key e);

REC_DEVICE void add_modL_from_bytes(uint8_t out32[32], const uint8_t inX[32], const uint8_t inY[32]);

#if defined(__cplusplus)
}
#endif


#endif // ED25519_H
