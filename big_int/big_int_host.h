#pragma once

#include <cstdint>

//---------------------------------------------------


//---------------------------------------------------


inline void array32_to_4x64_le(const uint8_t arr_be[32], uint64_t out_le[4])
{
    for (int i = 0; i < 4; i++) {
        out_le[i] =
            ((uint64_t)arr_be[31 - (i * 8 + 0)] << 0) |
            ((uint64_t)arr_be[31 - (i * 8 + 1)] << 8) |
            ((uint64_t)arr_be[31 - (i * 8 + 2)] << 16) |
            ((uint64_t)arr_be[31 - (i * 8 + 3)] << 24) |
            ((uint64_t)arr_be[31 - (i * 8 + 4)] << 32) |
            ((uint64_t)arr_be[31 - (i * 8 + 5)] << 40) |
            ((uint64_t)arr_be[31 - (i * 8 + 6)] << 48) |
            ((uint64_t)arr_be[31 - (i * 8 + 7)] << 56);
    }
}

inline void array4x64_le_to32(const uint64_t in_le[4], uint8_t out_be[32])
{
    for (int i = 0; i < 4; i++) {
        uint64_t w = in_le[i];
        out_be[31 - (i * 8 + 0)] = (uint8_t)(w >> 0);
        out_be[31 - (i * 8 + 1)] = (uint8_t)(w >> 8);
        out_be[31 - (i * 8 + 2)] = (uint8_t)(w >> 16);
        out_be[31 - (i * 8 + 3)] = (uint8_t)(w >> 24);
        out_be[31 - (i * 8 + 4)] = (uint8_t)(w >> 32);
        out_be[31 - (i * 8 + 5)] = (uint8_t)(w >> 40);
        out_be[31 - (i * 8 + 6)] = (uint8_t)(w >> 48);
        out_be[31 - (i * 8 + 7)] = (uint8_t)(w >> 56);
    }
}


inline void array64_to_8x64_le(const uint8_t arr_be[64], uint64_t out_le[8])
{
    for (int i = 0; i < 8; i++) {
        out_le[i] =
            ((uint64_t)arr_be[63 - (i * 8 + 0)] << 0) |
            ((uint64_t)arr_be[63 - (i * 8 + 1)] << 8) |
            ((uint64_t)arr_be[63 - (i * 8 + 2)] << 16) |
            ((uint64_t)arr_be[63 - (i * 8 + 3)] << 24) |
            ((uint64_t)arr_be[63 - (i * 8 + 4)] << 32) |
            ((uint64_t)arr_be[63 - (i * 8 + 5)] << 40) |
            ((uint64_t)arr_be[63 - (i * 8 + 6)] << 48) |
            ((uint64_t)arr_be[63 - (i * 8 + 7)] << 56);
    }
}

inline void array8x64_le_to64(const uint64_t in_le[8], uint8_t out_be[64])
{
    for (int i = 0; i < 8; i++) {
        uint64_t w = in_le[i];
        out_be[63 - (i * 8 + 0)] = (uint8_t)(w >> 0);
        out_be[63 - (i * 8 + 1)] = (uint8_t)(w >> 8);
        out_be[63 - (i * 8 + 2)] = (uint8_t)(w >> 16);
        out_be[63 - (i * 8 + 3)] = (uint8_t)(w >> 24);
        out_be[63 - (i * 8 + 4)] = (uint8_t)(w >> 32);
        out_be[63 - (i * 8 + 5)] = (uint8_t)(w >> 40);
        out_be[63 - (i * 8 + 6)] = (uint8_t)(w >> 48);
        out_be[63 - (i * 8 + 7)] = (uint8_t)(w >> 56);
    }
}


inline void array128_to_16x64_le(const uint8_t arr_be[128], uint64_t out_le[16])
{
    for (int i = 0; i < 16; i++) {
        out_le[i] =
            ((uint64_t)arr_be[127 - (i * 8 + 0)] << 0) |
            ((uint64_t)arr_be[127 - (i * 8 + 1)] << 8) |
            ((uint64_t)arr_be[127 - (i * 8 + 2)] << 16) |
            ((uint64_t)arr_be[127 - (i * 8 + 3)] << 24) |
            ((uint64_t)arr_be[127 - (i * 8 + 4)] << 32) |
            ((uint64_t)arr_be[127 - (i * 8 + 5)] << 40) |
            ((uint64_t)arr_be[127 - (i * 8 + 6)] << 48) |
            ((uint64_t)arr_be[127 - (i * 8 + 7)] << 56);
    }
}

inline void array16x64_le_to128(const uint64_t in_le[16], uint8_t out_be[128])
{
    for (int i = 0; i < 16; i++) {
        uint64_t w = in_le[i];
        out_be[127 - (i * 8 + 0)] = (uint8_t)(w >> 0);
        out_be[127 - (i * 8 + 1)] = (uint8_t)(w >> 8);
        out_be[127 - (i * 8 + 2)] = (uint8_t)(w >> 16);
        out_be[127 - (i * 8 + 3)] = (uint8_t)(w >> 24);
        out_be[127 - (i * 8 + 4)] = (uint8_t)(w >> 32);
        out_be[127 - (i * 8 + 5)] = (uint8_t)(w >> 40);
        out_be[127 - (i * 8 + 6)] = (uint8_t)(w >> 48);
        out_be[127 - (i * 8 + 7)] = (uint8_t)(w >> 56);
    }
}


inline void array256_to_32x64_le(const uint8_t arr_be[256], uint64_t out_le[32])
{
    for (int i = 0; i < 32; i++) {
        out_le[i] =
            ((uint64_t)arr_be[255 - (i * 8 + 0)] << 0) |
            ((uint64_t)arr_be[255 - (i * 8 + 1)] << 8) |
            ((uint64_t)arr_be[255 - (i * 8 + 2)] << 16) |
            ((uint64_t)arr_be[255 - (i * 8 + 3)] << 24) |
            ((uint64_t)arr_be[255 - (i * 8 + 4)] << 32) |
            ((uint64_t)arr_be[255 - (i * 8 + 5)] << 40) |
            ((uint64_t)arr_be[255 - (i * 8 + 6)] << 48) |
            ((uint64_t)arr_be[255 - (i * 8 + 7)] << 56);
    }
}

inline void array32x64_le_to256(const uint64_t in_le[32], uint8_t out_be[256])
{
    for (int i = 0; i < 32; i++) {
        uint64_t w = in_le[i];
        out_be[255 - (i * 8 + 0)] = (uint8_t)(w >> 0);
        out_be[255 - (i * 8 + 1)] = (uint8_t)(w >> 8);
        out_be[255 - (i * 8 + 2)] = (uint8_t)(w >> 16);
        out_be[255 - (i * 8 + 3)] = (uint8_t)(w >> 24);
        out_be[255 - (i * 8 + 4)] = (uint8_t)(w >> 32);
        out_be[255 - (i * 8 + 5)] = (uint8_t)(w >> 40);
        out_be[255 - (i * 8 + 6)] = (uint8_t)(w >> 48);
        out_be[255 - (i * 8 + 7)] = (uint8_t)(w >> 56);
    }
}


inline void array512_to_64x64_le(const uint8_t arr_be[512], uint64_t out_le[64])
{
    for (int i = 0; i < 64; i++) {
        out_le[i] =
            ((uint64_t)arr_be[511 - (i * 8 + 0)] << 0) |
            ((uint64_t)arr_be[511 - (i * 8 + 1)] << 8) |
            ((uint64_t)arr_be[511 - (i * 8 + 2)] << 16) |
            ((uint64_t)arr_be[511 - (i * 8 + 3)] << 24) |
            ((uint64_t)arr_be[511 - (i * 8 + 4)] << 32) |
            ((uint64_t)arr_be[511 - (i * 8 + 5)] << 40) |
            ((uint64_t)arr_be[511 - (i * 8 + 6)] << 48) |
            ((uint64_t)arr_be[511 - (i * 8 + 7)] << 56);
    }
}

inline void array64x64_le_to512(const uint64_t in_le[64], uint8_t out_be[512])
{
    for (int i = 0; i < 64; i++) {
        uint64_t w = in_le[i];
        out_be[511 - (i * 8 + 0)] = (uint8_t)(w >> 0);
        out_be[511 - (i * 8 + 1)] = (uint8_t)(w >> 8);
        out_be[511 - (i * 8 + 2)] = (uint8_t)(w >> 16);
        out_be[511 - (i * 8 + 3)] = (uint8_t)(w >> 24);
        out_be[511 - (i * 8 + 4)] = (uint8_t)(w >> 32);
        out_be[511 - (i * 8 + 5)] = (uint8_t)(w >> 40);
        out_be[511 - (i * 8 + 6)] = (uint8_t)(w >> 48);
        out_be[511 - (i * 8 + 7)] = (uint8_t)(w >> 56);
    }
}


inline void array1024_to_128x64_le(const uint8_t arr_be[1024], uint64_t out_le[128])
{
    for (int i = 0; i < 128; i++) {
        out_le[i] =
            ((uint64_t)arr_be[1023 - (i * 8 + 0)] << 0) |
            ((uint64_t)arr_be[1023 - (i * 8 + 1)] << 8) |
            ((uint64_t)arr_be[1023 - (i * 8 + 2)] << 16) |
            ((uint64_t)arr_be[1023 - (i * 8 + 3)] << 24) |
            ((uint64_t)arr_be[1023 - (i * 8 + 4)] << 32) |
            ((uint64_t)arr_be[1023 - (i * 8 + 5)] << 40) |
            ((uint64_t)arr_be[1023 - (i * 8 + 6)] << 48) |
            ((uint64_t)arr_be[1023 - (i * 8 + 7)] << 56);
    }
}

inline void array128x64_le_to1024(const uint64_t in_le[128], uint8_t out_be[1024])
{
    for (int i = 0; i < 128; i++) {
        uint64_t w = in_le[i];
        out_be[1023 - (i * 8 + 0)] = (uint8_t)(w >> 0);
        out_be[1023 - (i * 8 + 1)] = (uint8_t)(w >> 8);
        out_be[1023 - (i * 8 + 2)] = (uint8_t)(w >> 16);
        out_be[1023 - (i * 8 + 3)] = (uint8_t)(w >> 24);
        out_be[1023 - (i * 8 + 4)] = (uint8_t)(w >> 32);
        out_be[1023 - (i * 8 + 5)] = (uint8_t)(w >> 40);
        out_be[1023 - (i * 8 + 6)] = (uint8_t)(w >> 48);
        out_be[1023 - (i * 8 + 7)] = (uint8_t)(w >> 56);
    }
}

// Fixed-width host arithmetic uses Clang's native 128-bit integer support.

inline void add64to256_host(const uint64_t in[4],
    uint64_t       val64,
    uint64_t       out[4])
{
    unsigned long long carry = 0ULL;

    for (int i = 0; i < 4; i++) {
        __uint128_t sum = (__uint128_t)in[i] + (i == 0 ? val64 : 0ULL) + carry;
        out[i] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);


        if (!carry) {
            for (int j = i + 1; j < 4; j++) out[j] = in[j];
            return;
        }
    }


    if (carry) {
        for (int i = 0; i < 4; i++) out[i] = 0xFFFFFFFFFFFFFFFF;
    }
}

inline void sub64from256_host(const uint64_t in[4],
    uint64_t       val64,
    uint64_t       out[4])
{
    unsigned long long borrow = 0ULL;

    for (int i = 0; i < 4; i++) {
        __int128 diff = (__int128)in[i] - (i == 0 ? val64 : 0ULL) - borrow;
        out[i] = (uint64_t)diff;
        borrow = (diff < 0);


        if (!borrow) {
            for (int j = i + 1; j < 4; j++) out[j] = in[j];
            return;
        }
    }


    if (borrow) {
        for (int i = 0; i < 4; i++) out[i] = 0;
    }
}

#include <stdint.h>

static inline uint64_t umul128_lo(uint64_t a, uint64_t b, uint64_t* hi) {
    __uint128_t p = ((__uint128_t)a) * ((__uint128_t)b);
    *hi = (uint64_t)(p >> 64);
    return (uint64_t)p;
}

static inline uint8_t addcarry_u64_portable(uint8_t carry_in, uint64_t x, uint64_t y, uint64_t* out) {
    uint64_t s1 = x + y;
    uint8_t c1 = (s1 < x);            // carry �� x+y
    uint64_t s2 = s1 + (uint64_t)carry_in;
    uint8_t c2 = (s2 < s1);           // carry �� +carry_in
    *out = s2;
    return (uint8_t)(c1 | c2);
}

static inline uint8_t subborrow_u64_portable(uint8_t borrow_in, uint64_t x, uint64_t y, uint64_t* out) {
    uint8_t b1 = (x < y);             // borrow �� x-y
    uint64_t d1 = x - y;
    uint8_t b2 = (d1 < (uint64_t)borrow_in); // borrow �� -borrow_in
    uint64_t d2 = d1 - (uint64_t)borrow_in;
    *out = d2;
    return (uint8_t)(b1 | b2);
}

// add128to256_host: adds 128 to 256 host.
inline void add128to256_host(const uint64_t in[4], uint64_t a, uint64_t b, uint64_t out[4]) {
    uint64_t hi;
    uint64_t lo = umul128_lo(a, b, &hi);

    uint8_t carry = 0;
    carry = addcarry_u64_portable(carry, in[0], lo, &out[0]);
    carry = addcarry_u64_portable(carry, in[1], hi, &out[1]);
    carry = addcarry_u64_portable(carry, in[2], 0ULL, &out[2]);
    carry = addcarry_u64_portable(carry, in[3], 0ULL, &out[3]);

    if (carry) {
        out[0] = out[1] = out[2] = out[3] = 0xFFFFFFFFFFFFFFFFULL;
    }
}

// sub128from256_host: subtracts 128 from 256 host.
inline void sub128from256_host(const uint64_t in[4], uint64_t a, uint64_t b, uint64_t out[4]) {
    uint64_t hi;
    uint64_t lo = umul128_lo(a, b, &hi);

    uint8_t borrow = 0;
    borrow = subborrow_u64_portable(borrow, in[0], lo, &out[0]);
    borrow = subborrow_u64_portable(borrow, in[1], hi, &out[1]);
    borrow = subborrow_u64_portable(borrow, in[2], 0ULL, &out[2]);
    borrow = subborrow_u64_portable(borrow, in[3], 0ULL, &out[3]);

    if (borrow) {
        out[0] = out[1] = out[2] = out[3] = 0ULL;
    }
}



// add64to512_host: adds 64 to 512 host.
inline void add64to512_host(const uint64_t in[8], uint64_t val64, uint64_t out[8])
{
    unsigned long long carry = 0ULL;
    for (int i = 0; i < 8; i++) {
        __uint128_t sum = (__uint128_t)in[i] + (i == 0 ? val64 : 0ULL) + carry;
        out[i] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
        if (!carry) {
            for (int j = i + 1; j < 8; j++) out[j] = in[j];
            return;
        }
    }
    if (carry) {
        for (int i = 0; i < 8; i++) out[i] = 0xFFFFFFFFFFFFFFFFULL;
    }
}

// sub64from512_host: subtracts 64 from 512 host.
inline void sub64from512_host(const uint64_t in[8], uint64_t val64, uint64_t out[8])
{
    unsigned long long borrow = 0ULL;
    for (int i = 0; i < 8; i++) {
        __int128 diff = (__int128)in[i] - (i == 0 ? val64 : 0ULL) - borrow;
        out[i] = (uint64_t)diff;
        borrow = (diff < 0);
        if (!borrow) {
            for (int j = i + 1; j < 8; j++) out[j] = in[j];
            return;
        }
    }
    if (borrow) {
        for (int i = 0; i < 8; i++) out[i] = 0ULL;
    }
}

//-----------------------------------------------
// 1024 ���
inline void add64to1024_host(const uint64_t in[16], uint64_t val64, uint64_t out[16])
{
    unsigned long long carry = 0ULL;
    for (int i = 0; i < 16; i++) {
        __uint128_t sum = (__uint128_t)in[i] + (i == 0 ? val64 : 0ULL) + carry;
        out[i] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
        if (!carry) {
            for (int j = i + 1; j < 16; j++) out[j] = in[j];
            return;
        }
    }
    if (carry) {
        for (int i = 0; i < 16; i++) out[i] = 0xFFFFFFFFFFFFFFFFULL;
    }
}

// sub64from1024_host: subtracts 64 from 1024 host.
inline void sub64from1024_host(const uint64_t in[16], uint64_t val64, uint64_t out[16])
{
    unsigned long long borrow = 0ULL;
    for (int i = 0; i < 16; i++) {
        __int128 diff = (__int128)in[i] - (i == 0 ? val64 : 0ULL) - borrow;
        out[i] = (uint64_t)diff;
        borrow = (diff < 0);
        if (!borrow) {
            for (int j = i + 1; j < 16; j++) out[j] = in[j];
            return;
        }
    }
    if (borrow) {
        for (int i = 0; i < 16; i++) out[i] = 0ULL;
    }
}

//-----------------------------------------------
// 2048 ���
inline void add64to2048_host(const uint64_t in[32], uint64_t val64, uint64_t out[32])
{
    unsigned long long carry = 0ULL;
    for (int i = 0; i < 32; i++) {
        __uint128_t sum = (__uint128_t)in[i] + (i == 0 ? val64 : 0ULL) + carry;
        out[i] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
        if (!carry) {
            for (int j = i + 1; j < 32; j++) out[j] = in[j];
            return;
        }
    }
    if (carry) {
        for (int i = 0; i < 32; i++) out[i] = 0xFFFFFFFFFFFFFFFFULL;
    }
}

// sub64from2048_host: subtracts 64 from 2048 host.
inline void sub64from2048_host(const uint64_t in[32], uint64_t val64, uint64_t out[32])
{
    unsigned long long borrow = 0ULL;
    for (int i = 0; i < 32; i++) {
        __int128 diff = (__int128)in[i] - (i == 0 ? val64 : 0ULL) - borrow;
        out[i] = (uint64_t)diff;
        borrow = (diff < 0);
        if (!borrow) {
            for (int j = i + 1; j < 32; j++) out[j] = in[j];
            return;
        }
    }
    if (borrow) {
        for (int i = 0; i < 32; i++) out[i] = 0ULL;
    }
}

//-----------------------------------------------
// 4096 ���
inline void add64to4096_host(const uint64_t in[64], uint64_t val64, uint64_t out[64])
{
    unsigned long long carry = 0ULL;
    for (int i = 0; i < 64; i++) {
        __uint128_t sum = (__uint128_t)in[i] + (i == 0 ? val64 : 0ULL) + carry;
        out[i] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
        if (!carry) {
            for (int j = i + 1; j < 64; j++) out[j] = in[j];
            return;
        }
    }
    if (carry) {
        for (int i = 0; i < 64; i++) out[i] = 0xFFFFFFFFFFFFFFFFULL;
    }
}

// sub64from4096_host: subtracts 64 from 4096 host.
inline void sub64from4096_host(const uint64_t in[64], uint64_t val64, uint64_t out[64])
{
    unsigned long long borrow = 0ULL;
    for (int i = 0; i < 64; i++) {
        __int128 diff = (__int128)in[i] - (i == 0 ? val64 : 0ULL) - borrow;
        out[i] = (uint64_t)diff;
        borrow = (diff < 0);
        if (!borrow) {
            for (int j = i + 1; j < 64; j++) out[j] = in[j];
            return;
        }
    }
    if (borrow) {
        for (int i = 0; i < 64; i++) out[i] = 0ULL;
    }
}

//-----------------------------------------------
// 8192 ���
inline void add64to8192_host(const uint64_t in[128], uint64_t val64, uint64_t out[128])
{
    unsigned long long carry = 0ULL;
    for (int i = 0; i < 128; i++) {
        __uint128_t sum = (__uint128_t)in[i] + (i == 0 ? val64 : 0ULL) + carry;
        out[i] = (uint64_t)sum;
        carry = (uint64_t)(sum >> 64);
        if (!carry) {
            for (int j = i + 1; j < 128; j++) out[j] = in[j];
            return;
        }
    }
    if (carry) {
        for (int i = 0; i < 128; i++) out[i] = 0xFFFFFFFFFFFFFFFFULL;
    }
}

// sub64from8192_host: subtracts 64 from 8192 host.
inline void sub64from8192_host(const uint64_t in[128], uint64_t val64, uint64_t out[128])
{
    unsigned long long borrow = 0ULL;
    for (int i = 0; i < 128; i++) {
        __int128 diff = (__int128)in[i] - (i == 0 ? val64 : 0ULL) - borrow;
        out[i] = (uint64_t)diff;
        borrow = (diff < 0);
        if (!borrow) {
            for (int j = i + 1; j < 128; j++) out[j] = in[j];
            return;
        }
    }
    if (borrow) {
        for (int i = 0; i < 128; i++) out[i] = 0ULL;
    }
}


//---------------------------------------------------



//---------------------------------------------------
inline int cmp256_host(const uint8_t A[32], const uint8_t B[32])
{

    for (int i = 0; i < 32; i++)
    {
        if (A[i] < B[i]) return -1;
        if (A[i] > B[i]) return 1;
    }
    return 0;
}
// cmp_host: checks whether host is valid.
inline int cmp_host(const uint8_t* A, const uint8_t* B, int size)
{

    for (int i = 0; i < size; i++)
    {
        if (A[i] < B[i]) return -1;
        if (A[i] > B[i]) return 1;
    }
    return 0;
}

static inline unsigned clz64_portable(uint64_t x) {
    if (x == 0) return 64;

    unsigned n = 0;
    for (int i = 7; i >= 0; --i) {
        uint8_t b = (uint8_t)(x >> (i * 8));
        if (b == 0) { n += 8; continue; }
        unsigned zb = 0;
        if ((b & 0xF0) == 0) { zb += 4; b <<= 4; }
        if ((b & 0xC0) == 0) { zb += 2; b <<= 2; }
        if ((b & 0x80) == 0) { zb += 1; }
        return n + zb;
    }
    return 64;
}

uint64_t sizeBE_64(const uint64_t* c, uint64_t n_words) {
    for (uint64_t i = n_words; i-- > 0; ) {
        uint64_t w = c[i];
        if (w != 0) {
            unsigned lzb_bytes = clz64_portable(w) / 8;
            unsigned sig_bytes = 8u - lzb_bytes;
            return i * 8u + sig_bytes;
        }
    }
    return 0;
}



//---------------------------------------------------
// Random bytes
//---------------------------------------------------


static inline uint64_t rotl64(uint64_t x, int k) { return (x << k) | (x >> (64 - k)); }
struct Xoshiro256ss {
    uint64_t s[4];
    Xoshiro256ss() {
        uint64_t z = 0x9E3779B97F4A7C15ull ^ (uintptr_t)this;
        for (int i = 0; i < 4; ++i) { z += 0x9E3779B97F4A7C15ull; z ^= z >> 30; z *= 0xBF58476D1CE4E5B9ull; z ^= z >> 27; z *= 0x94D049BB133111EBull; z ^= z >> 31; s[i] = z; }
    }
    inline uint64_t next() {
        uint64_t* x = s;
        uint64_t const result = rotl64(x[1] * 5, 7) * 9;
        uint64_t const t = x[1] << 17;
        x[2] ^= x[0]; x[3] ^= x[1]; x[1] ^= x[2]; x[0] ^= x[3]; x[2] ^= t; x[3] = rotl64(x[3], 45);
        return result;
    }
// bytes: applies one internal step of the PRNG round.
    inline void bytes(uint8_t* dst, size_t n) {
        size_t i = 0;
        while (i < n) {
            uint64_t r = next();
            for (int k = 0; k < 8 && i < n; ++k, ++i) {
                dst[i] = (uint8_t)(r >> 56);
                r <<= 8;
            }
        }
    }
};
static thread_local Xoshiro256ss g_rng;

// BE-compare: -1,0,1
static inline int cmp_be(const uint8_t* x, const uint8_t* y, size_t n) {
    for (size_t i = 0; i < n; ++i) { if (x[i] != y[i]) return (x[i] < y[i]) ? -1 : 1; }
    return 0;
}
// out = x - y (BE)
static inline void sub_be(const uint8_t* x, const uint8_t* y, uint8_t* out, size_t n) {
    int b = 0; for (size_t i = n; i-- > 0;) { int t = (int)x[i] - (int)y[i] - b; if (t < 0) { t += 256; b = 1; } else b = 0; out[i] = (uint8_t)t; }
}
// out = x + y (BE)
static inline void add_be(const uint8_t* x, const uint8_t* y, uint8_t* out, size_t n) {
    int c = 0; for (size_t i = n; i-- > 0;) { int t = (int)x[i] + (int)y[i] + c; out[i] = (uint8_t)(t & 0xFF); c = t >> 8; }
}

// random_bytes_seq: generates bytes seq.
void random_bytes_seq(const uint8_t* a, const uint8_t* b, uint8_t* out, size_t size) {
    const uint8_t* lo = a; const uint8_t* hi = b;
    if (cmp_be(a, b, size) > 0) { lo = b; hi = a; }

    const size_t MAX = 4096;
    uint8_t range[MAX], rnd[MAX];
    if (size > MAX) size = MAX;
    sub_be(hi, lo, range, size);

    bool allz = true; for (size_t i = 0; i < size; ++i) { if (range[i]) { allz = false; break; } }
    if (allz) { memcpy(out, lo, size); return; }

    size_t off = 0; while (off < size && range[off] == 0) ++off;
    size_t m = size - off;
    uint8_t* R = range + off;
    uint8_t* X = rnd + off;
    uint8_t top = R[0];
    int lz = 0;
    if ((top & 0xF0) == 0) { lz += 4; top <<= 4; }
    if ((top & 0xC0) == 0) { lz += 2; top <<= 2; }
    if ((top & 0x80) == 0) { lz += 1; }
    int bits = 8 - lz;
    uint8_t mask = (bits == 8) ? 0xFFu : (uint8_t)((1u << bits) - 1u);

    for (;;) {
        if (off) std::memset(rnd, 0, off);
        g_rng.bytes(X, m);
        X[0] &= mask;
        if (cmp_be(X, R, m) <= 0) break;
    }

    add_be(lo, rnd, out, size);
}

// random_bytes: generates bytes.
static inline void random_bytes(uint8_t* out, size_t size, int bytes_count)
{
    if (bytes_count < 0) bytes_count = 0;
    size_t n = (size_t)bytes_count;
    if (n > size) n = size;

    size_t start = size - n;
    if (start > 0) memset(out, 0, start);
    if (n > 0) g_rng.bytes(out + start, n);
}
