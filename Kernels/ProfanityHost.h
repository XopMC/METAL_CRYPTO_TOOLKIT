#pragma once

#include <stdint.h>
#include "uint128_t.h"

static constexpr uint64_t PROFANITY_BASEPOINT_X_TAG64 = 0x50524f46414e5831ULL; // "PROFANX1"
static constexpr uint64_t PROFANITY_FNV64_OFFSET = 0xcbf29ce484222325ULL;
static constexpr uint64_t PROFANITY_FNV64_PRIME = 0x100000001b3ULL;

struct ProfanitySeedWords {
	uint64_t s[4];
};

struct ProfanityXKeys {
	uint64_t key64;
	uint128_t key128;
};

struct ProfanityRecoveryHit {
	uint8_t x32[32];
	uint64_t offset;
	uint64_t lane_id;
	uint8_t filter_type;
	uint8_t reserved[7];
};

struct ProfanityVerifiedResult {
	uint8_t priv[32];
	uint8_t x32[32];
	uint8_t payload[32];
	uint64_t lane_id;
	uint64_t round;
	uint32_t seed32;
	uint8_t type;
	uint8_t payload_len;
	uint8_t reserved[2];
};

using ProfanityRecoveryVerifiedResult = ProfanityVerifiedResult;

struct ProfanityWalkState {
	uint64_t x[4];
	uint64_t y[4];
};

METAL_HOST METAL_DEVICE METAL_FORCEINLINE static uint64_t profanity_rotl64(uint64_t v, unsigned r)
{
	return (v << (r & 63u)) | (v >> ((64u - r) & 63u));
}

METAL_HOST METAL_DEVICE METAL_FORCEINLINE static uint64_t profanity_mix64(uint64_t h)
{
	h ^= h >> 33;
	h *= UINT64_C(0xff51afd7ed558ccd);
	h ^= h >> 33;
	h *= UINT64_C(0xc4ceb9fe1a85ec53);
	h ^= h >> 33;
	return h;
}

METAL_HOST METAL_DEVICE METAL_FORCEINLINE static uint64_t profanity_load_be64(const uint8_t* p)
{
	uint64_t v = 0;
#pragma unroll
	for (int i = 0; i < 8; ++i) {
		v = (v << 8) | (uint64_t)p[i];
	}
	return v;
}

METAL_HOST METAL_DEVICE METAL_FORCEINLINE static void profanity_store_be64(uint8_t* p, uint64_t v)
{
#pragma unroll
	for (int i = 7; i >= 0; --i) {
		p[i] = (uint8_t)(v & 0xffu);
		v >>= 8;
	}
}

METAL_HOST METAL_DEVICE METAL_FORCEINLINE static void profanity_store_x32_from_u64x4(const uint64_t x[4], uint8_t out32[32])
{
	profanity_store_be64(out32 + 0, x[3]);
	profanity_store_be64(out32 + 8, x[2]);
	profanity_store_be64(out32 + 16, x[1]);
	profanity_store_be64(out32 + 24, x[0]);
}

METAL_HOST METAL_DEVICE METAL_FORCEINLINE static uint64_t profanity_load_le64(const uint8_t* p)
{
	uint64_t v = 0;
#pragma unroll
	for (int i = 7; i >= 0; --i) {
		v = (v << 8) | (uint64_t)p[i];
	}
	return v;
}

METAL_HOST METAL_DEVICE METAL_FORCEINLINE static void profanity_store_le64(uint8_t* p, uint64_t v)
{
#pragma unroll
	for (int i = 0; i < 8; ++i) {
		p[i] = (uint8_t)(v & 0xffu);
		v >>= 8;
	}
}

METAL_HOST METAL_DEVICE METAL_FORCEINLINE static uint64_t profanity_fnv1a_64_20(const uint8_t input20[20])
{
	uint64_t h = PROFANITY_FNV64_OFFSET;
#pragma unroll
	for (int i = 0; i < 20; ++i) {
		h ^= (uint64_t)input20[i];
		h *= PROFANITY_FNV64_PRIME;
	}
	return h;
}

METAL_HOST METAL_DEVICE METAL_FORCEINLINE static void profanity_x_filter_value20_from_x32(const uint8_t x32[32], uint8_t out20[20])
{
	// Basepoint filters store the first 20 bytes of canonical affine X.
#pragma unroll
	for (int i = 0; i < 20; ++i) {
		out20[i] = x32[i];
	}
}

METAL_HOST METAL_DEVICE METAL_FORCEINLINE static ProfanityXKeys profanity_x_key_from_x32(const uint8_t x32[32])
{
	uint8_t raw20[20];
	profanity_x_filter_value20_from_x32(x32, raw20);

	uint8_t masked20[20];
#pragma unroll
	for (int i = 0; i < 20; ++i) {
		masked20[i] = raw20[i];
	}
	masked20[3] &= masked20[16];
	masked20[7] &= masked20[17];
	masked20[11] &= masked20[18];
	masked20[15] &= masked20[19];

	ProfanityXKeys out;
	// Compressed/ultra/hyper hex_to_xor modes hash the original 20 bytes.
	out.key64 = profanity_fnv1a_64_20(raw20);
	// Uncompressed hex_to_xor masks selected bytes, then stores two 64-bit keys.
	out.key128 = uint128_t(profanity_load_le64(masked20 + 8), profanity_load_le64(masked20 + 0));
	return out;
}

class ProfanityMT19937_64 {
	static constexpr int NN = 312;
	static constexpr int MM = 156;
	static constexpr uint64_t MATRIX_A = UINT64_C(0xB5026F5AA96619E9);
	static constexpr uint64_t UM = UINT64_C(0xFFFFFFFF80000000);
	static constexpr uint64_t LM = UINT64_C(0x7FFFFFFF);

	uint64_t mt[NN];
	int mti;

public:
	METAL_HOST METAL_DEVICE explicit ProfanityMT19937_64(uint64_t seed)
	{
		mt[0] = seed;
		for (mti = 1; mti < NN; ++mti) {
			mt[mti] = UINT64_C(6364136223846793005) * (mt[mti - 1] ^ (mt[mti - 1] >> 62)) + (uint64_t)mti;
		}
	}

	METAL_HOST METAL_DEVICE uint64_t next()
	{
		uint64_t x;
		int i;
		if (mti >= NN) {
			for (i = 0; i < NN - MM; ++i) {
				x = (mt[i] & UM) | (mt[i + 1] & LM);
				mt[i] = mt[i + MM] ^ (x >> 1) ^ ((x & 1ULL) ? MATRIX_A : UINT64_C(0));
			}
			for (; i < NN - 1; ++i) {
				x = (mt[i] & UM) | (mt[i + 1] & LM);
				mt[i] = mt[i + (MM - NN)] ^ (x >> 1) ^ ((x & 1ULL) ? MATRIX_A : UINT64_C(0));
			}
			x = (mt[NN - 1] & UM) | (mt[0] & LM);
			mt[NN - 1] = mt[MM - 1] ^ (x >> 1) ^ ((x & 1ULL) ? MATRIX_A : UINT64_C(0));
			mti = 0;
		}
		x = mt[mti++];
		x ^= (x >> 29) & UINT64_C(0x5555555555555555);
		x ^= (x << 17) & UINT64_C(0x71D67FFFEDA60000);
		x ^= (x << 37) & UINT64_C(0xFFF7EEE000000000);
		x ^= (x >> 43);
		return x;
	}
};

METAL_HOST METAL_DEVICE METAL_FORCEINLINE static ProfanitySeedWords profanity_seed_words(uint32_t seed32)
{
	ProfanityMT19937_64 mt((uint64_t)seed32);
	ProfanitySeedWords out;
	out.s[0] = mt.next();
	out.s[1] = mt.next();
	out.s[2] = mt.next();
	out.s[3] = mt.next();
	return out;
}

METAL_HOST METAL_DEVICE METAL_FORCEINLINE static void profanity_words_add_offset64(ProfanitySeedWords& w, uint64_t offset)
{
	const uint64_t old0 = w.s[0];
	w.s[0] += offset;
	uint64_t carry = (w.s[0] < old0) ? 1ULL : 0ULL;
	for (int i = 1; i < 4 && carry; ++i) {
		const uint64_t old = w.s[i];
		w.s[i] += carry;
		carry = (w.s[i] < old) ? 1ULL : 0ULL;
	}
}

METAL_HOST METAL_DEVICE METAL_FORCEINLINE static void profanity_words_add_lane_round(
	ProfanitySeedWords& w,
	uint64_t lane_id,
	uint64_t round)
{
	// Matches vulnerable Profanity printResult: low word += round, then carry, then foundId in high word.
	w.s[0] += round;
	uint64_t carry = (w.s[0] < round) ? 1ULL : 0ULL;
	w.s[1] += carry;
	carry = (w.s[1] == 0ULL) ? 1ULL : 0ULL;
	w.s[2] += carry;
	carry = (w.s[2] == 0ULL) ? 1ULL : 0ULL;
	w.s[3] += carry + lane_id;
}

METAL_HOST METAL_DEVICE METAL_FORCEINLINE static void profanity_words_to_private_bytes(const ProfanitySeedWords& base, uint64_t offset, uint8_t out32[32])
{
	ProfanitySeedWords w = base;
	profanity_words_add_offset64(w, offset);
	profanity_store_be64(out32 + 0, w.s[3]);
	profanity_store_be64(out32 + 8, w.s[2]);
	profanity_store_be64(out32 + 16, w.s[1]);
	profanity_store_be64(out32 + 24, w.s[0]);
}

METAL_HOST METAL_DEVICE METAL_FORCEINLINE static void profanity_words_to_private_bytes_lane_round(
	const ProfanitySeedWords& base,
	uint64_t lane_id,
	uint64_t round,
	uint8_t out32[32])
{
	ProfanitySeedWords w = base;
	profanity_words_add_lane_round(w, lane_id, round);
	profanity_store_be64(out32 + 0, w.s[3]);
	profanity_store_be64(out32 + 8, w.s[2]);
	profanity_store_be64(out32 + 16, w.s[1]);
	profanity_store_be64(out32 + 24, w.s[0]);
}

METAL_HOST METAL_DEVICE METAL_FORCEINLINE static void profanity_private_bytes(uint32_t seed32, uint64_t offset, uint8_t out32[32])
{
	ProfanitySeedWords w = profanity_seed_words(seed32);
	profanity_words_to_private_bytes(w, offset, out32);
}

METAL_HOST METAL_DEVICE METAL_FORCEINLINE static void profanity_private_bytes_lane_round(
	uint32_t seed32,
	uint64_t lane_id,
	uint64_t round,
	uint8_t out32[32])
{
	ProfanitySeedWords w = profanity_seed_words(seed32);
	profanity_words_to_private_bytes_lane_round(w, lane_id, round, out32);
}
