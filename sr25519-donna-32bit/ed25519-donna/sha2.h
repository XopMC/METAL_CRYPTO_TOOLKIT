#ifndef __SHA2_H__
#define __SHA2_H__



#define SHA1_BLOCK_LENGTH 64
#define SHA1_DIGEST_LENGTH 20
#define SHA1_DIGEST_STRING_LENGTH (SHA1_DIGEST_LENGTH * 2 + 1)
#define SHA256_BLOCK_LENGTH 64
#define SHA256_DIGEST_LENGTH 32
#define SHA256_DIGEST_STRING_LENGTH (SHA256_DIGEST_LENGTH * 2 + 1)
#define SHA512_BLOCK_LENGTH 128
#define SHA512_DIGEST_LENGTH 64
#define SHA512_DIGEST_STRING_LENGTH (SHA512_DIGEST_LENGTH * 2 + 1)

#define ED25519_THREAD thread
#define ED25519_THREAD_CONST thread const

typedef struct _SHA1_CTX {
    uint32_t state[5];
    uint64_t bitcount;
    uint32_t buffer[SHA1_BLOCK_LENGTH/sizeof(uint32_t)];
} SHA1_CTX;

typedef struct _SHA256_CTX {
    uint32_t state[8];
    uint64_t bitcount;
    uint32_t buffer[SHA256_BLOCK_LENGTH/sizeof(uint32_t)];
} SHA256_CTX;

typedef struct _SHA512_CTX {
    uint64_t state[8];
    uint64_t bitcount[2];
    uint64_t buffer[SHA512_BLOCK_LENGTH/sizeof(uint64_t)];
} SHA512_CTX;

/*** ENDIAN REVERSAL MACROS *******************************************/
#ifndef LITTLE_ENDIAN
#define LITTLE_ENDIAN 1234
#define BIG_ENDIAN    4321
#endif

#ifndef BYTE_ORDER
#define BYTE_ORDER LITTLE_ENDIAN
#endif

#if BYTE_ORDER == LITTLE_ENDIAN
#define REVERSE32(w,x)	{ \
    uint32_t tmp = (w); \
    tmp = (tmp >> 16) | (tmp << 16); \
    (x) = ((tmp & 0xff00ff00UL) >> 8) | ((tmp & 0x00ff00ffUL) << 8); \
}

#define REVERSE64(w,x)	{ \
    uint64_t tmp = (w); \
    tmp = (tmp >> 32) | (tmp << 32); \
    tmp = ((tmp & 0xff00ff00ff00ff00ULL) >> 8) | \
          ((tmp & 0x00ff00ff00ff00ffULL) << 8); \
    (x) = ((tmp & 0xffff0000ffff0000ULL) >> 16) | \
          ((tmp & 0x0000ffff0000ffffULL) << 16); \
}
#endif /* BYTE_ORDER == LITTLE_ENDIAN */


REC_DEVICE void sha512_Transform(ED25519_THREAD_CONST uint64_t* state_in, ED25519_THREAD_CONST uint64_t* data, ED25519_THREAD uint64_t* state_out);
REC_DEVICE void sha512_Init(ED25519_THREAD SHA512_CTX* context);
REC_DEVICE void sha512_Update(ED25519_THREAD SHA512_CTX* context, ED25519_THREAD_CONST uint8_t* data, size_t len);
REC_DEVICE void sha512_Final(ED25519_THREAD SHA512_CTX* context, uint8_t digest[SHA512_DIGEST_LENGTH]);
REC_DEVICE void sha512_Raw(ED25519_THREAD_CONST uint8_t* data, size_t len, uint8_t digest[SHA512_DIGEST_LENGTH]);







#endif
