#pragma once

#include <stdint.h>

static constexpr uint32_t XP_OPENSSL_PATH_COUNT = 54u;
static constexpr uint64_t XP_OPENSSL_ALL_PATH_MASK = (1ull << XP_OPENSSL_PATH_COUNT) - 1ull;
static constexpr uint8_t XP_OPENSSL_ARCH_LE32 = 0u;
static constexpr uint8_t XP_OPENSSL_ARCH_LE64 = 1u;
static constexpr uint8_t XP_OPENSSL_ARCH_COUNT = 2u;
static constexpr uint8_t XP_OPENSSL_ARCH_NONE = 0xffu;
static constexpr uint32_t XP_CGR_LABEL_MAX = 32u;
static constexpr uint32_t XP_CGR_CHAIN_MAX = 4u;
static constexpr uint32_t XP_SSLEAY_ITERATIONS = 4u;
static constexpr uint32_t XP_SSLEAY_SLICE_LEN = 10u;
static constexpr uint32_t XP_REPLAY_PAYLOAD_MAX = 80u;

enum XpReplayProfileKind : uint8_t {
	XP_PROFILE_OPENSSL = 1u,
	XP_PROFILE_CGR_STATE = 2u,
	XP_PROFILE_CGR_BRIDGE = 3u,
	XP_PROFILE_SSLEAY_STIR = 4u,
	XP_PROFILE_CGR_XOR = 5u,
	XP_PROFILE_CGR_CHAIN = 6u,
	XP_PROFILE_CGR_CHAIN_BRIDGE = 7u,
	XP_PROFILE_RAW32 = 8u,
	XP_PROFILE_RANDSTORM_JSBN = 9u,
	XP_PROFILE_RANDSTORM_V8INIT = 12u,
	XP_PROFILE_PHPCOINADDRESS = 16u,
	XP_PROFILE_RANDSTORM_CRYPTO1_JSBN = 17u,
	XP_PROFILE_BLUEWALLET_ISAAC = 18u,
	XP_PROFILE_TIME_LCG_DIRECT = 19u,
	XP_PROFILE_JAVA_LCG_DIRECT = 20u,
	XP_PROFILE_SHA256_DIRECT = 21u,
	XP_PROFILE_PID_HASH_DIRECT = 22u,
	XP_PROFILE_LOWBITS_DIRECT = 23u,
	XP_PROFILE_TIME_MT = 24u,
	XP_PROFILE_ELLIPTIC_PHP_RAND_HMACDRBG = 25u,
	XP_PROFILE_PYBTC_MT = 26u,
	XP_PROFILE_NANO_JAVA_RANDOM = 27u,
	XP_PROFILE_PYWALLET_TS_WEAK = 28u,
};

static constexpr uint32_t XP_RANDSTORM_PROFILE_COUNT = 4u;
static constexpr uint64_t XP_RANDSTORM_ALL_PROFILE_MASK = (1ull << XP_RANDSTORM_PROFILE_COUNT) - 1ull;

struct XpCgrStateInput {
	uint8_t state20[20];
	uint8_t aux20[20];
	uint8_t outbuf_prefix20[20];
	uint8_t chain_aux20[XP_CGR_CHAIN_MAX][20];
	uint8_t chain_prefix20[XP_CGR_CHAIN_MAX][20];
	uint8_t label[XP_CGR_LABEL_MAX];
	uint8_t label_len;
	uint8_t transition_count;
	uint8_t xor_mask;
	uint8_t reserved[1];
};

struct XpSsleayInput {
	uint8_t local_md[XP_SSLEAY_ITERATIONS][20];
	uint8_t md_c[XP_SSLEAY_ITERATIONS][8];
	uint8_t input_buf[XP_SSLEAY_ITERATIONS][XP_SSLEAY_SLICE_LEN];
	uint8_t state_slice[XP_SSLEAY_ITERATIONS][XP_SSLEAY_SLICE_LEN];
	uint8_t input_len[XP_SSLEAY_ITERATIONS];
	uint8_t label[XP_CGR_LABEL_MAX];
	uint8_t iter_count;
	uint8_t out_len;
	uint8_t label_len;
	uint8_t reserved[4];
};

struct XpReplayResult {
	uint8_t priv[32];
	uint8_t payload[XP_REPLAY_PAYLOAD_MAX];
	uint8_t profile_kind;
	uint8_t path_id;
	uint8_t type;
	uint8_t payload_len;
	uint32_t pid;
	uint32_t key_index;
	uint32_t line_index;
	uint64_t source_state;
	uint32_t seed_time0;
	uint32_t seed_time1;
	uint8_t reserved[4];
};

METAL_HOST METAL_DEVICE METAL_FORCEINLINE static const char* xp_openssl_path_name(uint32_t path)
{
	switch (path) {
	case 0: return "0.3.24";
	case 1: return "0.8.6-d";
	case 2: return "0.8.6-qt";
	case 3: return "0.9.1-d";
	case 4: return "0.9.4-d";
	case 5: return "unknownA";
	case 6: return "unknownB";
	case 7: return "unknownC";
	case 8: return "unknownD";
	case 9: return "unknownE";
	case 10: return "unknownF";
	case 11: return "unknownG";
	case 12: return "unknownH";
	case 13: return "unknownI";
	case 14: return "unknownJ";
	case 15: return "unknownK";
	case 16: return "unknownA0";
	case 17: return "unknownA1";
	case 18: return "unknownA2";
	case 19: return "unknownA3";
	case 20: return "unknownA4";
	case 21: return "unknownB0";
	case 22: return "unknownB1";
	case 23: return "unknownB2";
	case 24: return "unknownB3";
	case 25: return "unknownC0";
	case 26: return "unknownC1";
	case 27: return "unknownC2";
	case 28: return "unknownD0";
	case 29: return "unknownD1";
	case 30: return "unknownD2";
	case 31: return "unknownD3";
	case 32: return "unknownD4";
	case 33: return "unknownD5";
	case 34: return "unknownE0";
	case 35: return "unknownA0x";
	case 36: return "unknownA1x";
	case 37: return "unknownA2x";
	case 38: return "unknownA3x";
	case 39: return "unknownA4x";
	case 40: return "unknownB0x";
	case 41: return "unknownB1x";
	case 42: return "unknownB2x";
	case 43: return "unknownB3x";
	case 44: return "unknownC0x";
	case 45: return "unknownC1x";
	case 46: return "unknownC2x";
	case 47: return "unknownD0x";
	case 48: return "unknownD1x";
	case 49: return "unknownD2x";
	case 50: return "unknownD3x";
	case 51: return "unknownD4x";
	case 52: return "unknownD5x";
	case 53: return "unknownE0x";
	default: return "unknown";
	}
}

METAL_HOST METAL_DEVICE METAL_FORCEINLINE static const char* xp_randstorm_profile_name(uint32_t profile)
{
	switch (profile) {
	case 0: return "v8-2011";
	case 1: return "v8-2015";
	case 2: return "spidermonkey-lcg48";
	case 3: return "jsc-weakrandom";
	default: return "unknown";
	}
}

METAL_HOST METAL_DEVICE METAL_FORCEINLINE static int xp_randstorm_profile_gen(uint32_t profile)
{
	switch (profile) {
	case 0: return 211;
	case 1: return 212;
	case 2: return 213;
	case 3: return 214;
	default: return 0;
	}
}

METAL_HOST METAL_DEVICE METAL_FORCEINLINE static uint32_t xp_randstorm_profile_from_mask_index(uint64_t mask, uint32_t ordinal)
{
	uint32_t seen = 0u;
	for (uint32_t i = 0u; i < XP_RANDSTORM_PROFILE_COUNT; ++i) {
		if ((mask & (1ull << i)) == 0ull) continue;
		if (seen == ordinal) return i;
		++seen;
	}
	return XP_RANDSTORM_PROFILE_COUNT;
}

METAL_HOST METAL_DEVICE METAL_FORCEINLINE static const char* xp_openssl_arch_name(uint8_t arch)
{
	switch (arch) {
	case XP_OPENSSL_ARCH_LE32: return "le32";
	case XP_OPENSSL_ARCH_LE64: return "le64";
	default: return "unknown";
	}
}

#define XP_MD5_ROTL(x,n) (((x) << (n)) | ((x) >> (32 - (n))))
#define XP_MD5_F(x,y,z)  (((x) & (y)) | ((~(x)) & (z)))
#define XP_MD5_G(x,y,z)  (((x) & (z)) | ((y) & (~(z))))
#define XP_MD5_H(x,y,z)  ((x) ^ (y) ^ (z))
#define XP_MD5_I(x,y,z)  ((y) ^ ((x) | (~(z))))

struct XpMd5Ctx {
	uint32_t a, b, c, d;
	uint8_t buf[64];
	uint32_t buflen;
	uint64_t total;
};

METAL_DEVICE METAL_FORCEINLINE static uint32_t xp_md5_k(int i)
{
	static const uint32_t K[64] = {
		0xd76aa478u,0xe8c7b756u,0x242070dbu,0xc1bdceeeu,0xf57c0fafu,0x4787c62au,0xa8304613u,0xfd469501u,
		0x698098d8u,0x8b44f7afu,0xffff5bb1u,0x895cd7beu,0x6b901122u,0xfd987193u,0xa679438eu,0x49b40821u,
		0xf61e2562u,0xc040b340u,0x265e5a51u,0xe9b6c7aau,0xd62f105du,0x02441453u,0xd8a1e681u,0xe7d3fbc8u,
		0x21e1cde6u,0xc33707d6u,0xf4d50d87u,0x455a14edu,0xa9e3e905u,0xfcefa3f8u,0x676f02d9u,0x8d2a4c8au,
		0xfffa3942u,0x8771f681u,0x6d9d6122u,0xfde5380cu,0xa4beea44u,0x4bdecfa9u,0xf6bb4b60u,0xbebfbc70u,
		0x289b7ec6u,0xeaa127fau,0xd4ef3085u,0x04881d05u,0xd9d4d039u,0xe6db99e5u,0x1fa27cf8u,0xc4ac5665u,
		0xf4292244u,0x432aff97u,0xab9423a7u,0xfc93a039u,0x655b59c3u,0x8f0ccc92u,0xffeff47du,0x85845dd1u,
		0x6fa87e4fu,0xfe2ce6e0u,0xa3014314u,0x4e0811a1u,0xf7537e82u,0xbd3af235u,0x2ad7d2bbu,0xeb86d391u
	};
	return K[i];
}

METAL_DEVICE METAL_FORCEINLINE static int xp_md5_s(int i)
{
	static const int S[64] = {
		7,12,17,22, 7,12,17,22, 7,12,17,22, 7,12,17,22,
		5, 9,14,20, 5, 9,14,20, 5, 9,14,20, 5, 9,14,20,
		4,11,16,23, 4,11,16,23, 4,11,16,23, 4,11,16,23,
		6,10,15,21, 6,10,15,21, 6,10,15,21, 6,10,15,21
	};
	return S[i];
}

METAL_DEVICE static void xp_md5_transform(uint32_t state[4], const uint8_t block[64])
{
	uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
	uint32_t M[16];
#pragma unroll
	for (int i = 0; i < 16; ++i) {
		M[i] = (uint32_t)block[i * 4] | ((uint32_t)block[i * 4 + 1] << 8) |
			((uint32_t)block[i * 4 + 2] << 16) | ((uint32_t)block[i * 4 + 3] << 24);
	}
	for (int i = 0; i < 64; ++i) {
		uint32_t f, g;
		if (i < 16) { f = XP_MD5_F(b, c, d); g = (uint32_t)i; }
		else if (i < 32) { f = XP_MD5_G(b, c, d); g = (uint32_t)((5 * i + 1) & 15); }
		else if (i < 48) { f = XP_MD5_H(b, c, d); g = (uint32_t)((3 * i + 5) & 15); }
		else { f = XP_MD5_I(b, c, d); g = (uint32_t)((7 * i) & 15); }
		f = f + a + xp_md5_k(i) + M[g];
		a = d; d = c; c = b;
		b = b + XP_MD5_ROTL(f, xp_md5_s(i));
	}
	state[0] += a; state[1] += b; state[2] += c; state[3] += d;
}

METAL_DEVICE static void xp_md5_init(XpMd5Ctx* ctx)
{
	ctx->a = 0x67452301u; ctx->b = 0xefcdab89u; ctx->c = 0x98badcfeu; ctx->d = 0x10325476u;
	ctx->buflen = 0u; ctx->total = 0ull;
}

METAL_DEVICE static void xp_md5_update(XpMd5Ctx* ctx, const uint8_t* data, uint32_t len)
{
	ctx->total += len;
	uint32_t i = 0u;
	if (ctx->buflen) {
		uint32_t need = 64u - ctx->buflen;
		uint32_t take = (len < need) ? len : need;
		for (uint32_t j = 0u; j < take; ++j) ctx->buf[ctx->buflen + j] = data[j];
		ctx->buflen += take;
		if (ctx->buflen == 64u) {
			xp_md5_transform(&ctx->a, ctx->buf);
			ctx->buflen = 0u;
		}
		i = take;
	}
	while (i + 64u <= len) {
		xp_md5_transform(&ctx->a, data + i);
		i += 64u;
	}
	if (i < len) {
		ctx->buflen = len - i;
		for (uint32_t j = 0u; j < ctx->buflen; ++j) ctx->buf[j] = data[i + j];
	}
}

METAL_DEVICE static void xp_md5_final(uint8_t digest[16], XpMd5Ctx* ctx)
{
	uint64_t bits = ctx->total * 8ull;
	uint8_t pad = 0x80u;
	xp_md5_update(ctx, &pad, 1u);
	uint8_t zero = 0u;
	while (ctx->buflen != 56u) xp_md5_update(ctx, &zero, 1u);
	uint8_t len_bytes[8];
#pragma unroll
	for (int i = 0; i < 8; ++i) len_bytes[i] = (uint8_t)(bits >> (i * 8));
	xp_md5_update(ctx, len_bytes, 8u);
	uint32_t s[4] = { ctx->a, ctx->b, ctx->c, ctx->d };
#pragma unroll
	for (int i = 0; i < 4; ++i) {
		digest[i * 4] = (uint8_t)s[i];
		digest[i * 4 + 1] = (uint8_t)(s[i] >> 8);
		digest[i * 4 + 2] = (uint8_t)(s[i] >> 16);
		digest[i * 4 + 3] = (uint8_t)(s[i] >> 24);
	}
}

METAL_DEVICE static void xp_md5_direct(const uint8_t* data, uint32_t len, uint8_t digest[16])
{
	XpMd5Ctx ctx;
	xp_md5_init(&ctx);
	xp_md5_update(&ctx, data, len);
	xp_md5_final(digest, &ctx);
}

METAL_DEVICE static void xp_sha1_short_message(const uint8_t* data, uint32_t len, uint8_t out20[20]);

static constexpr int XP_STATE_SIZE = 1023;
static constexpr int XP_MD_DIGEST_LENGTH = 20;
static constexpr int XP_DUMMY_SEED_LEN = 20;

struct XpRandState {
	uint8_t state[XP_STATE_SIZE + XP_MD_DIGEST_LENGTH];
	uint8_t md[XP_MD_DIGEST_LENGTH];
	uint64_t md_count[2];
	int state_index;
	int state_num;
	double entropy;
	int initialized;
	int stirred_pool;
	uint32_t thc_pid;
};

METAL_DEVICE static void xp_memzero(uint8_t* p, int n)
{
	for (int i = 0; i < n; ++i) p[i] = 0u;
}

METAL_DEVICE static void xp_hitme(XpRandState* rs, uint32_t n)
{
	if (n == 0u) {
		xp_memzero(rs->state, XP_STATE_SIZE + XP_MD_DIGEST_LENGTH);
		xp_memzero(rs->md, XP_MD_DIGEST_LENGTH);
		rs->md_count[0] = 0;
		rs->md_count[1] = 0;
		rs->state_index = 0;
		rs->state_num = 0;
		rs->entropy = 0.0;
		rs->initialized = 0;
		rs->stirred_pool = 0;
		rs->thc_pid = 0u;
		return;
	}
	rs->thc_pid = n;
}

METAL_DEVICE METAL_FORCEINLINE static void xp_append_le_word(uint8_t* dst, int& pos, uint64_t val, uint32_t bytes)
{
	if (bytes == 4u) {
		dst[pos++] = (uint8_t)val;
		dst[pos++] = (uint8_t)(val >> 8);
		dst[pos++] = (uint8_t)(val >> 16);
		dst[pos++] = (uint8_t)(val >> 24);
		return;
	}
#pragma unroll
	for (int i = 0; i < 8; ++i) {
		dst[pos++] = (uint8_t)(val >> (i * 8));
	}
}

METAL_DEVICE METAL_FORCEINLINE static uint32_t xp_openssl_word_bytes(uint8_t arch)
{
	return (arch == XP_OPENSSL_ARCH_LE32) ? 4u : 8u;
}

METAL_DEVICE static void xp_ssleay_rand_add(XpRandState* rs, int num, double add_entropy, uint32_t word_bytes)
{
	int st_idx = rs->state_index;
	uint64_t md_c[2] = { rs->md_count[0], rs->md_count[1] };
	uint8_t local_md[XP_MD_DIGEST_LENGTH];
#pragma unroll
	for (int i = 0; i < XP_MD_DIGEST_LENGTH; ++i) local_md[i] = rs->md[i];

	rs->state_index += num;
	if (rs->state_index >= XP_STATE_SIZE) {
		rs->state_index %= XP_STATE_SIZE;
		rs->state_num = XP_STATE_SIZE;
	}
	else if (rs->state_num < XP_STATE_SIZE) {
		if (rs->state_index > rs->state_num) rs->state_num = rs->state_index;
	}
	rs->md_count[1] += (num / XP_MD_DIGEST_LENGTH) + ((num % XP_MD_DIGEST_LENGTH) > 0);

	for (int i = 0; i < num; i += XP_MD_DIGEST_LENGTH) {
		int j = num - i;
		if (j > XP_MD_DIGEST_LENGTH) j = XP_MD_DIGEST_LENGTH;
		uint8_t md_in[80];
		int pos = 0;
#pragma unroll
		for (int k = 0; k < XP_MD_DIGEST_LENGTH; ++k) md_in[pos++] = local_md[k];
		for (int k = 0; k < j; ++k) md_in[pos++] = rs->state[(st_idx + k) % XP_STATE_SIZE];
		for (int b = 0; b < 2; ++b) {
			xp_append_le_word(md_in, pos, md_c[b], word_bytes);
		}
		xp_sha1_short_message(md_in, (uint32_t)pos, local_md);
		md_c[1]++;
		for (int k = 0; k < j; ++k) {
			rs->state[st_idx] ^= local_md[k];
			st_idx++;
			if (st_idx >= XP_STATE_SIZE) st_idx = 0;
		}
	}
#pragma unroll
	for (int k = 0; k < XP_MD_DIGEST_LENGTH; ++k) rs->md[k] ^= local_md[k];
	rs->entropy += add_entropy;
}

METAL_DEVICE static void xp_rand_poll(XpRandState* rs, uint32_t word_bytes)
{
	xp_ssleay_rand_add(rs, 32, 32.0, word_bytes);
	xp_ssleay_rand_add(rs, (int)word_bytes, 0.0, word_bytes);
	xp_ssleay_rand_add(rs, (int)word_bytes, 0.0, word_bytes);
	xp_ssleay_rand_add(rs, (int)word_bytes, 0.0, word_bytes);
}

METAL_DEVICE static void xp_ssleay_rand_bytes(XpRandState* rs, uint8_t* buf, int num, uint32_t word_bytes)
{
	uint32_t curr_pid = rs->thc_pid;
	if (!rs->initialized) {
		xp_rand_poll(rs, word_bytes);
		rs->initialized = 1;
	}
	const int ok = (rs->entropy >= 32.0);
	if (!rs->stirred_pool) {
		int n = XP_STATE_SIZE;
		while (n > 0) {
			xp_ssleay_rand_add(rs, XP_DUMMY_SEED_LEN, 0.0, word_bytes);
			n -= XP_DUMMY_SEED_LEN;
		}
		if (ok) rs->stirred_pool = 1;
	}

	int st_idx = rs->state_index;
	const int st_num = rs->state_num;
	uint64_t md_c[2] = { rs->md_count[0], rs->md_count[1] };
	uint8_t local_md[XP_MD_DIGEST_LENGTH];
#pragma unroll
	for (int i = 0; i < XP_MD_DIGEST_LENGTH; ++i) local_md[i] = rs->md[i];
	const int num_ceil = ((num + 9) / 10) * 10;
	rs->state_index += num_ceil;
	if (rs->state_index > rs->state_num) rs->state_index %= rs->state_num;
	rs->md_count[0] += 1;

	while (num > 0) {
		int j = (num >= 10) ? 10 : num;
		num -= j;
		uint8_t md_in[80];
		int pos = 0;
		if (curr_pid) {
			md_in[pos++] = (uint8_t)curr_pid;
			md_in[pos++] = (uint8_t)(curr_pid >> 8);
			md_in[pos++] = (uint8_t)(curr_pid >> 16);
			md_in[pos++] = (uint8_t)(curr_pid >> 24);
			curr_pid = 0u;
		}
#pragma unroll
		for (int k = 0; k < XP_MD_DIGEST_LENGTH; ++k) md_in[pos++] = local_md[k];
		for (int b = 0; b < 2; ++b) {
			xp_append_le_word(md_in, pos, md_c[b], word_bytes);
		}
#pragma unroll
		for (int k = 0; k < 10; ++k) md_in[pos++] = rs->state[(st_idx + k) % st_num];
		xp_sha1_short_message(md_in, (uint32_t)pos, local_md);
#pragma unroll
		for (int i = 0; i < 10; ++i) {
			rs->state[st_idx] ^= local_md[i];
			st_idx++;
			if (st_idx >= st_num) st_idx = 0;
			if (i < j) *buf++ = local_md[i + 10];
		}
	}

	uint8_t md_in[80];
	int pos = 0;
	for (int b = 0; b < 2; ++b) {
		xp_append_le_word(md_in, pos, md_c[b], word_bytes);
	}
#pragma unroll
	for (int k = 0; k < XP_MD_DIGEST_LENGTH; ++k) md_in[pos++] = local_md[k];
#pragma unroll
	for (int k = 0; k < XP_MD_DIGEST_LENGTH; ++k) md_in[pos++] = rs->md[k];
	xp_sha1_short_message(md_in, (uint32_t)pos, rs->md);
}

METAL_DEVICE METAL_FORCEINLINE static void xp_openssl_path_ops(uint32_t path, int setup[6], int gen[4])
{
	static const int16_t SETUP[XP_OPENSSL_PATH_COUNT][6] = {
		{-3,-3,0,0,0,0}, {-2,-3,-3,0,0,0}, {-3,-2,-3,0,0,0}, {1800,-2,-3,-3,0,0}, {-2,1800,-3,-3,0,0},
		{0,0,0,0,0,0}, {0,0,0,0,0,0}, {-3,0,0,0,0,0}, {-3,-3,0,0,0,0}, {-3,0,0,0,0,0},
		{-3,-3,-3,0,0,0}, {-3,-3,-3,-3,0,0}, {-3,-3,-2,0,0,0}, {-3,-3,-2,-3,0,0}, {-3,-3,-2,-3,-3,0},
		{-3,-2,-2,-3,0,0}, {-3,-3,-3,-3,0,0}, {-2,-3,-3,-3,0,0}, {-3,-2,-3,-3,0,0}, {-3,-3,-2,-3,0,0},
		{-3,-3,-3,-2,0,0}, {-3,-3,-3,0,0,0}, {-2,-3,-3,0,0,0}, {-3,-2,-3,0,0,0}, {-3,-3,-2,0,0,0},
		{-3,-3,0,0,0,0}, {-2,-3,0,0,0,0}, {-3,-2,0,0,0,0}, {-3,-3,-3,-3,-3,0}, {-2,-3,-3,-3,-3,0},
		{-3,-2,-3,-3,-3,0}, {-3,-3,-2,-3,-3,0}, {-3,-3,-3,-2,-3,0}, {-3,-3,-3,-3,-2,0}, {-3,0,0,0,0,0},
		{-3,-3,-3,-3,0,0}, {-2,-3,-3,-3,0,0}, {-3,-2,-3,-3,0,0}, {-3,-3,-2,-3,0,0}, {-3,-3,-3,-2,0,0},
		{-3,-3,-3,0,0,0}, {-2,-3,-3,0,0,0}, {-3,-2,-3,0,0,0}, {-3,-3,-2,0,0,0}, {-3,-3,0,0,0,0},
		{-2,-3,0,0,0,0}, {-3,-2,0,0,0,0}, {-3,-3,-3,-3,-3,0}, {-2,-3,-3,-3,-3,0}, {-3,-2,-3,-3,-3,0},
		{-3,-3,-2,-3,-3,0}, {-3,-3,-3,-2,-3,0}, {-3,-3,-3,-3,-2,0}, {-3,0,0,0,0,0}
	};
	static const int8_t GEN[XP_OPENSSL_PATH_COUNT][4] = {
		{-3,-1,0,0}, {-3,-1,0,0}, {-3,-1,0,0}, {-1,0,0,0}, {-1,0,0,0},
		{-1,0,0,0}, {-3,-1,0,0}, {-1,0,0,0}, {-1,0,0,0}, {-3,-1,0,0},
		{-3,-1,0,0}, {-3,-1,0,0}, {-3,-1,0,0}, {-3,-1,0,0}, {-3,-1,0,0},
		{-3,-1,0,0}, {-3,-1,0,0}, {-3,-1,0,0}, {-3,-1,0,0}, {-3,-1,0,0},
		{-3,-1,0,0}, {-3,-1,0,0}, {-3,-1,0,0}, {-3,-1,0,0}, {-3,-1,0,0},
		{-3,-1,0,0}, {-3,-1,0,0}, {-3,-1,0,0}, {-3,-1,0,0}, {-3,-1,0,0},
		{-3,-1,0,0}, {-3,-1,0,0}, {-3,-1,0,0}, {-3,-1,0,0}, {-3,-1,0,0},
		{-1,0,0,0}, {-1,0,0,0}, {-1,0,0,0}, {-1,0,0,0}, {-1,0,0,0},
		{-1,0,0,0}, {-1,0,0,0}, {-1,0,0,0}, {-1,0,0,0}, {-1,0,0,0},
		{-1,0,0,0}, {-1,0,0,0}, {-1,0,0,0}, {-1,0,0,0}, {-1,0,0,0},
		{-1,0,0,0}, {-1,0,0,0}, {-1,0,0,0}, {-1,0,0,0}
	};
#pragma unroll
	for (int i = 0; i < 6; ++i) setup[i] = SETUP[path][i];
#pragma unroll
	for (int i = 0; i < 4; ++i) gen[i] = GEN[path][i];
}

METAL_DEVICE static void xp_openssl_run_setup(XpRandState* rs, uint32_t path, uint8_t arch)
{
	const uint32_t word_bytes = xp_openssl_word_bytes(arch);
	int setup[6], gen_unused[4];
	xp_openssl_path_ops(path, setup, gen_unused);
	for (int i = 0; i < 6; ++i) {
		const int op = setup[i];
		if (op == 0) break;
		if (op == -2) {
			uint8_t tmp[32];
			xp_ssleay_rand_bytes(rs, tmp, 32, word_bytes);
		}
		else if (op == -3) {
			xp_ssleay_rand_add(rs, 8, 0.0, word_bytes);
		}
		else if (op > 0) {
			uint8_t tmp[8];
			for (int n = 0; n < op; ++n) xp_ssleay_rand_bytes(rs, tmp, 8, word_bytes);
		}
	}
}

METAL_DEVICE METAL_FORCEINLINE static bool xp_secp256k1_priv_in_range(const uint8_t priv32[32])
{
	static const uint8_t ORDER[32] = {
		0xffu,0xffu,0xffu,0xffu,0xffu,0xffu,0xffu,0xffu,
		0xffu,0xffu,0xffu,0xffu,0xffu,0xffu,0xffu,0xfeu,
		0xbau,0xaeu,0xdcu,0xe6u,0xafu,0x48u,0xa0u,0x3bu,
		0xbfu,0xd2u,0x5eu,0x8cu,0xd0u,0x36u,0x41u,0x41u
	};
	bool nonzero = false;
#pragma unroll
	for (int i = 0; i < 32; ++i) {
		if (priv32[i] != 0u) nonzero = true;
	}
	if (!nonzero) return false;
	for (int i = 0; i < 32; ++i) {
		if (priv32[i] < ORDER[i]) return true;
		if (priv32[i] > ORDER[i]) return false;
	}
	return false;
}

METAL_DEVICE static bool xp_openssl_ec_keygen_priv(XpRandState* rs, uint8_t arch, uint8_t priv32[32])
{
	const uint32_t word_bytes = xp_openssl_word_bytes(arch);
	for (int attempt = 0; attempt < 100; ++attempt) {
		// OpenSSL 0.9.8c BN_rand() mixes time(&tim) before RAND_bytes().
		xp_ssleay_rand_add(rs, (int)word_bytes, 0.0, word_bytes);
		xp_ssleay_rand_bytes(rs, priv32, 32, word_bytes);
		if (xp_secp256k1_priv_in_range(priv32)) return true;
	}
	return false;
}

METAL_DEVICE static bool xp_openssl_next_priv(XpRandState* rs, uint32_t path, uint8_t arch, uint8_t priv32[32])
{
	const uint32_t word_bytes = xp_openssl_word_bytes(arch);
	int setup_unused[6], gen[4];
	xp_openssl_path_ops(path, setup_unused, gen);
	for (int i = 0; i < 4; ++i) {
		const int op = gen[i];
		if (op == 0) break;
		if (op == -1) {
			return xp_openssl_ec_keygen_priv(rs, arch, priv32);
		}
		if (op == -3) {
			xp_ssleay_rand_add(rs, 8, 0.0, word_bytes);
		}
	}
	return false;
}

METAL_DEVICE static uint32_t xp_path_from_mask_index(uint64_t path_mask, uint32_t index)
{
	uint32_t seen = 0u;
	for (uint32_t p = 0u; p < XP_OPENSSL_PATH_COUNT; ++p) {
		if (path_mask & (1ull << p)) {
			if (seen == index) return p;
			seen++;
		}
	}
	return 0xffffffffu;
}

METAL_DEVICE METAL_FORCEINLINE static uint32_t xp_sha1_rotl(uint32_t x, uint32_t n)
{
	return (x << n) | (x >> (32u - n));
}

METAL_DEVICE static void xp_sha1_compress20_zero(const uint8_t in20[20], uint8_t out20[20])
{
	uint32_t w[80];
#pragma unroll
	for (int i = 0; i < 5; ++i) {
		w[i] = ((uint32_t)in20[i * 4] << 24) | ((uint32_t)in20[i * 4 + 1] << 16) |
			((uint32_t)in20[i * 4 + 2] << 8) | (uint32_t)in20[i * 4 + 3];
	}
	w[5] = 0u;
#pragma unroll
	for (int i = 6; i < 16; ++i) w[i] = 0u;
	for (int i = 16; i < 80; ++i) {
		w[i] = xp_sha1_rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
	}
	uint32_t a = 0x67452301u, b = 0xefcdab89u, c = 0x98badcfeu, d = 0x10325476u, e = 0xc3d2e1f0u;
	for (int i = 0; i < 80; ++i) {
		uint32_t f, k;
		if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5a827999u; }
		else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1u; }
		else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdcu; }
		else { f = b ^ c ^ d; k = 0xca62c1d6u; }
		uint32_t t = xp_sha1_rotl(a, 5) + f + e + k + w[i];
		e = d; d = c; c = xp_sha1_rotl(b, 30); b = a; a = t;
	}
	uint32_t h[5] = {
		0x67452301u + a, 0xefcdab89u + b, 0x98badcfeu + c, 0x10325476u + d, 0xc3d2e1f0u + e
	};
#pragma unroll
	for (int i = 0; i < 5; ++i) {
		out20[i * 4] = (uint8_t)(h[i] >> 24);
		out20[i * 4 + 1] = (uint8_t)(h[i] >> 16);
		out20[i * 4 + 2] = (uint8_t)(h[i] >> 8);
		out20[i * 4 + 3] = (uint8_t)h[i];
	}
}

METAL_DEVICE static void xp_sha1_process_block(const uint8_t block[64], uint32_t h[5])
{
	uint32_t w[80];
#pragma unroll
	for (int i = 0; i < 16; ++i) {
		w[i] = ((uint32_t)block[i * 4] << 24) | ((uint32_t)block[i * 4 + 1] << 16) |
			((uint32_t)block[i * 4 + 2] << 8) | (uint32_t)block[i * 4 + 3];
	}
	for (int i = 16; i < 80; ++i) {
		w[i] = xp_sha1_rotl(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
	}
	uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
	for (int i = 0; i < 80; ++i) {
		uint32_t f, k;
		if (i < 20) { f = (b & c) | ((~b) & d); k = 0x5a827999u; }
		else if (i < 40) { f = b ^ c ^ d; k = 0x6ed9eba1u; }
		else if (i < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8f1bbcdcu; }
		else { f = b ^ c ^ d; k = 0xca62c1d6u; }
		uint32_t t = xp_sha1_rotl(a, 5) + f + e + k + w[i];
		e = d; d = c; c = xp_sha1_rotl(b, 30); b = a; a = t;
	}
	h[0] += a;
	h[1] += b;
	h[2] += c;
	h[3] += d;
	h[4] += e;
}

METAL_DEVICE static void xp_sha1_short_message(const uint8_t* data, uint32_t len, uint8_t out20[20])
{
	uint32_t h[5] = {
		0x67452301u, 0xefcdab89u, 0x98badcfeu, 0x10325476u, 0xc3d2e1f0u
	};
	uint8_t block[64];
#pragma unroll
	for (int i = 0; i < 64; ++i) block[i] = 0u;
	const uint32_t first_len = (len < 64u) ? len : 64u;
	for (uint32_t i = 0; i < first_len; ++i) block[i] = data[i];
	const uint64_t bits = (uint64_t)len * 8ull;
	if (len < 56u) {
		block[len] = 0x80u;
#pragma unroll
		for (int i = 0; i < 8; ++i) {
			block[56 + i] = (uint8_t)(bits >> (56 - i * 8));
		}
		xp_sha1_process_block(block, h);
	}
	else {
		if (len < 64u) block[len] = 0x80u;
		xp_sha1_process_block(block, h);
#pragma unroll
		for (int i = 0; i < 64; ++i) block[i] = 0u;
		if (len == 64u) block[0] = 0x80u;
#pragma unroll
		for (int i = 0; i < 8; ++i) {
			block[56 + i] = (uint8_t)(bits >> (56 - i * 8));
		}
		xp_sha1_process_block(block, h);
	}
#pragma unroll
	for (int i = 0; i < 5; ++i) {
		out20[i * 4] = (uint8_t)(h[i] >> 24);
		out20[i * 4 + 1] = (uint8_t)(h[i] >> 16);
		out20[i * 4 + 2] = (uint8_t)(h[i] >> 8);
		out20[i * 4 + 3] = (uint8_t)h[i];
	}
}

METAL_DEVICE static void xp_add160_be(const uint8_t a[20], const uint8_t b[20], uint8_t out[20], uint8_t plus_one)
{
	uint32_t carry = plus_one ? 1u : 0u;
	for (int i = 19; i >= 0; --i) {
		const uint32_t s = (uint32_t)a[i] + (uint32_t)b[i] + carry;
		out[i] = (uint8_t)s;
		carry = s >> 8;
	}
}

METAL_DEVICE static void xp_xor20(const uint8_t a[20], const uint8_t b[20], uint8_t out[20])
{
#pragma unroll
	for (int i = 0; i < 20; ++i) {
		out[i] = (uint8_t)(a[i] ^ b[i]);
	}
}

METAL_DEVICE static void xp_cgr_transition_device(
	const uint8_t state20[20],
	const uint8_t aux20[20],
	uint8_t priv32[32],
	uint8_t state20_after[20])
{
	uint8_t xval[20], out20_a[20], state_a[20], out20_b[20];
	xp_add160_be(state20, aux20, xval, 0u);
	xp_sha1_compress20_zero(xval, out20_a);
	xp_add160_be(state20, out20_a, state_a, 1u);
	xp_add160_be(state_a, aux20, xval, 0u);
	xp_sha1_compress20_zero(xval, out20_b);
	xp_add160_be(state_a, out20_b, state20_after, 1u);
#pragma unroll
	for (int i = 0; i < 20; ++i) priv32[i] = out20_a[i];
#pragma unroll
	for (int i = 0; i < 12; ++i) priv32[20 + i] = out20_b[i];
}

METAL_DEVICE static void xp_cgr_state_generate_priv_device(const XpCgrStateInput* in, uint8_t profile_kind, uint8_t priv32[32])
{
	uint8_t state[20];
#pragma unroll
	for (int i = 0; i < 20; ++i) state[i] = in->state20[i];

	uint8_t count = in->transition_count;
	if (count == 0u) count = 1u;
	if (count > XP_CGR_CHAIN_MAX) count = XP_CGR_CHAIN_MAX;
	uint8_t xor_mask = in->xor_mask;
	if (in->transition_count == 0u &&
		(profile_kind == XP_PROFILE_CGR_BRIDGE || profile_kind == XP_PROFILE_CGR_XOR || profile_kind == XP_PROFILE_CGR_CHAIN_BRIDGE)) {
		xor_mask = 1u;
	}

	uint8_t local_priv[32];
	uint8_t next_state[20];
	for (uint8_t t = 0u; t < count; ++t) {
		uint8_t aux[20];
		const uint8_t* raw = (in->transition_count == 0u && t == 0u) ? in->aux20 : in->chain_aux20[t];
		const uint8_t* prefix = (in->transition_count == 0u && t == 0u) ? in->outbuf_prefix20 : in->chain_prefix20[t];
		if (xor_mask & (1u << t)) {
			xp_xor20(raw, prefix, aux);
		}
		else {
#pragma unroll
			for (int i = 0; i < 20; ++i) aux[i] = raw[i];
		}
		xp_cgr_transition_device(state, aux, local_priv, next_state);
#pragma unroll
		for (int i = 0; i < 20; ++i) state[i] = next_state[i];
	}
#pragma unroll
	for (int i = 0; i < 32; ++i) priv32[i] = local_priv[i];
}

METAL_DEVICE static bool xp_ssleay_stir_generate_priv_device(const XpSsleayInput* in, uint8_t priv32[32])
{
	if (in == nullptr || in->out_len != 32u || in->iter_count == 0u || in->iter_count > XP_SSLEAY_ITERATIONS) {
		return false;
	}
	uint32_t written = 0u;
	for (uint32_t iter = 0u; iter < in->iter_count && written < 32u; ++iter) {
		uint8_t msg[20 + 8 + XP_SSLEAY_SLICE_LEN + XP_SSLEAY_SLICE_LEN];
		uint32_t pos = 0u;
#pragma unroll
		for (int i = 0; i < 20; ++i) msg[pos++] = in->local_md[iter][i];
#pragma unroll
		for (int i = 0; i < 8; ++i) msg[pos++] = in->md_c[iter][i];
		const uint32_t input_len = (in->input_len[iter] <= XP_SSLEAY_SLICE_LEN) ? in->input_len[iter] : XP_SSLEAY_SLICE_LEN;
		for (uint32_t i = 0; i < input_len; ++i) msg[pos++] = in->input_buf[iter][i];
#pragma unroll
		for (int i = 0; i < (int)XP_SSLEAY_SLICE_LEN; ++i) msg[pos++] = in->state_slice[iter][i];
		uint8_t digest[20];
		xp_sha1_short_message(msg, pos, digest);
		for (int j = 10; j < 20 && written < 32u; ++j) {
			priv32[written++] = digest[j];
		}
	}
	return written == 32u;
}
