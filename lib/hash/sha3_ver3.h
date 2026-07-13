#pragma once
#include "MetalBackend.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>



/*** Keccak-f[1600] ***/
METAL_DEVICE  void keccakf(void* state);



/** The sponge-based hash construction. **/
METAL_DEVICE  void hashing(
	uint8_t* out,
	size_t outlen,
	uint8_t const* in,
	size_t inlen,
	size_t rate,
	uint8_t delim
);


METAL_DEVICE  void keccak(const char* __restrict__ message, int message_len, unsigned char* __restrict__ output, int output_len);






// ---------------- Keccak-f[1600] -----------------------------------------



METAL_DEVICE  void keccak_f1600(uint64_t state[25]);

// ---------------- SHA3-256 (Keccak) --------------------------------------

METAL_DEVICE  void sha3_256(const char* __restrict__ message, int message_len, unsigned char* __restrict__ output);

// ---------------- BLAKE2b-256 --------------------------------------------



METAL_DEVICE  void Blake2b_256(const uint8_t* data, size_t len, uint8_t out[32]);

METAL_DEVICE void Blake2b_224(const uint8_t* data, size_t len, uint8_t out[28]);

METAL_DEVICE void Blake2b_160(const uint8_t* data, size_t len, uint8_t out[20]);
