#pragma once
/*
    Public domain by Andrew M. <liquidsun@gmail.com>
*/


/*
    Arithmetic modulo the group order n = 2^252 +  27742317777372353535851937790883648493 = 7237005577332262213973186563042994240857116359379907606001950938285454250989

    k = 32
    b = 1 << 8 = 256
    m = 2^252 + 27742317777372353535851937790883648493 = 0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed
    mu = floor( b^(k*2) / m ) = 0xfffffffffffffffffffffffffffffffeb2106215d086329a7ed9ce5a30a2c131b
*/



typedef uint32_t bignum256modm_element_t;
typedef bignum256modm_element_t bignum256modm[9];

#define ED25519_THREAD thread
#define ED25519_THREAD_CONST thread const


REC_DEVICE  bignum256modm_element_t
lt_modm(bignum256modm_element_t a, bignum256modm_element_t b);

/* see HAC, Alg. 14.42 Step 4 */
REC_DEVICE  void
reduce256_modm(bignum256modm r);

/*
    Barrett reduction,  see HAC, Alg. 14.42

    Instead of passing in x, pre-process in to q1 and r1 for efficiency
*/
REC_DEVICE  void
barrett_reduce256_modm(bignum256modm r, const bignum256modm q1, const bignum256modm r1);

/* addition modulo m */
REC_DEVICE  void
add256_modm(bignum256modm r, const bignum256modm x, const bignum256modm y);

REC_DEVICE  void
neg256_modm(bignum256modm r, const bignum256modm x);

/*  const bignum256modm twoP = { */
/*     0x5cf5d3ed, 0x60498c68, 0x6f79cd64, 0x77be77a7, 0x40000013, 0x3fffffff, 0x3fffffff, 0x3fffffff, 0xfff */
/* }; */

/* subtraction x-y % m */
REC_DEVICE  void
sub256_modm(bignum256modm r, const bignum256modm x, const bignum256modm y);

REC_DEVICE  int is_reduced256_modm(const bignum256modm in);

/* multiplication modulo m */
REC_DEVICE  void
mul256_modm(bignum256modm r, const bignum256modm x, const bignum256modm y);

REC_DEVICE  void
expand256_modm(bignum256modm out, ED25519_THREAD_CONST unsigned char* in, size_t len);

REC_DEVICE  void
expand_raw256_modm(bignum256modm out, const unsigned char in[32]);

REC_DEVICE  void
contract256_modm(unsigned char out[32], const bignum256modm in);

REC_DEVICE  void
contract256_window4_modm(signed char r[64], const bignum256modm in);

REC_DEVICE void
contract256_window5_modm(signed char r[52], const bignum256modm in);

REC_DEVICE  void
contract256_slidingwindow_modm(signed char r[256], const bignum256modm s, int windowsize);


/*
    helpers for batch verifcation, are allowed to be vartime
*/

/* out = a - b, a must be larger than b */
REC_DEVICE  void
sub256_modm_batch(bignum256modm out, const bignum256modm a, const bignum256modm b, size_t limbsize);

/* is a < b */
REC_DEVICE  int
lt256_modm_batch(const bignum256modm a, const bignum256modm b, size_t limbsize);

/* is a <= b */
REC_DEVICE  int
lte256_modm_batch(const bignum256modm a, const bignum256modm b, size_t limbsize);


/* is a == 0 */
REC_DEVICE  int
iszero256_modm_batch(const bignum256modm a);

/* is a == 1 */
REC_DEVICE  int
isone256_modm_batch(const bignum256modm a);

/* can a fit in to (at most) 128 bits */
REC_DEVICE  int
isatmost128bits256_modm_batch(const bignum256modm a);
