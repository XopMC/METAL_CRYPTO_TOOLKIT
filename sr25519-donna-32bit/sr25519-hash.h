#ifndef __SR25519_HASH_H__
#define __SR25519_HASH_H__

#include "sha2.h"

typedef SHA512_CTX sr25519_hash_context;

REC_DEVICE  void
sr25519_hash_init(thread sr25519_hash_context* ctx);

REC_DEVICE  void
sr25519_hash_update(thread sr25519_hash_context* ctx, const thread uint8_t* in, size_t inlen);


REC_DEVICE  void
sr25519_hash_final(thread sr25519_hash_context* ctx, thread uint8_t* hash);


REC_DEVICE  void
sr25519_hash(thread uint8_t* hash, const thread uint8_t* in, size_t inlen);



#endif
