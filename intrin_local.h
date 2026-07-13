#pragma once

#include <stdint.h>

static inline unsigned char _subborrow_u64(unsigned char borrow, uint64_t a, uint64_t b, uint64_t* diff) {
    uint64_t temp = a - b;
    unsigned char borrow1 = (a < b) ? 1 : 0;
    uint64_t result = temp - borrow;
    unsigned char borrow2 = (temp < borrow) ? 1 : 0;
    *diff = result;
    return (borrow1 || borrow2) ? 1 : 0;
}


static inline uint64_t _umul128(uint64_t a, uint64_t b, uint64_t* high) {
    unsigned __int128 r = (unsigned __int128)a * b;
    *high = (uint64_t)(r >> 64);
    return (uint64_t)r;
}

static inline uint64_t __shiftright128(uint64_t low, uint64_t high, uint8_t shift) {
    if (shift == 0)
        return low;
    else if (shift < 64)
        return (low >> shift) | (high << (64 - shift));
    else if (shift < 128)
        return high >> (shift - 64);
    else
        return 0;
}

static inline uint64_t __shiftleft128(uint64_t low, uint64_t high, uint8_t shift) {
    if (shift == 0)
        return high;
    else if (shift < 64)
        return (high << shift) | (low >> (64 - shift));
    else if (shift < 128)
        return low << (shift - 64);
    else
        return 0;
}

static inline uint64_t _tzcnt_u64(uint64_t x) {
    return x ? __builtin_ctzll(x) : 64;
}

static inline uint64_t _lzcnt_u64(uint64_t x) {
    return x ? __builtin_clzll(x) : 64;
}

static inline uint64_t _bzhi_u64(uint64_t x, uint32_t n) {
    if (n >= 64)
        return x;
    return x & ((1ULL << n) - 1);
}

static inline uint32_t _udiv64(uint64_t a, uint32_t b, uint32_t* remainder) {
    *remainder = (uint32_t)(a % b);
    return (uint32_t)(a / b);
}

static inline uint64_t _udiv128(uint64_t nHi, uint64_t nLo, uint64_t d, uint64_t* rem) {
    uint64_t quotient = 0;
    uint64_t r = nHi;
    for (int i = 63; i >= 0; i--) {
        r = (r << 1) | ((nLo >> i) & 1ULL);
        if (r >= d) {
            r -= d;
            quotient |= (1ULL << i);
        }
    }
    *rem = r;
    return quotient;
}
