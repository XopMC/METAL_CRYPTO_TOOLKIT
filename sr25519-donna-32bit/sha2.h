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


REC_DEVICE void sha1_Transform(const thread uint32_t* state_in, const thread uint32_t* data, thread uint32_t* state_out);
REC_DEVICE void sha1_Init(thread SHA1_CTX *);
REC_DEVICE void sha1_Update(thread SHA1_CTX*, const thread uint8_t*, size_t);
REC_DEVICE void sha1_Final(thread SHA1_CTX*, thread uint8_t[SHA1_DIGEST_LENGTH]);
REC_DEVICE thread char* sha1_End(thread SHA1_CTX*, thread char[SHA1_DIGEST_STRING_LENGTH]);
REC_DEVICE void sha1_Raw(const thread uint8_t*, size_t, thread uint8_t[SHA1_DIGEST_LENGTH]);
REC_DEVICE thread char* sha1_Data(const thread uint8_t*, size_t, thread char[SHA1_DIGEST_STRING_LENGTH]);

REC_DEVICE void sha256_Transform(const thread uint32_t* state_in, const thread uint32_t* data, thread uint32_t* state_out);
REC_DEVICE void sha256_Init(thread SHA256_CTX *);
REC_DEVICE void sha256_Update(thread SHA256_CTX*, const thread uint8_t*, size_t);
REC_DEVICE void sha256_Final(thread SHA256_CTX*, thread uint8_t[SHA256_DIGEST_LENGTH]);
REC_DEVICE thread char* sha256_End(thread SHA256_CTX*, thread char[SHA256_DIGEST_STRING_LENGTH]);
REC_DEVICE void sha256_Raw(const thread uint8_t*, size_t, thread uint8_t[SHA256_DIGEST_LENGTH]);
REC_DEVICE thread char* sha256_Data(const thread uint8_t*, size_t, thread char[SHA256_DIGEST_STRING_LENGTH]);

REC_DEVICE void sha512_Transform(const thread uint64_t* state_in, const thread uint64_t* data, thread uint64_t* state_out);
REC_DEVICE void sha512_Init(thread SHA512_CTX*);
REC_DEVICE void sha512_Update(thread SHA512_CTX*, const thread uint8_t*, size_t);
REC_DEVICE void sha512_Final(thread SHA512_CTX*, thread uint8_t[SHA512_DIGEST_LENGTH]);
REC_DEVICE thread char* sha512_End(thread SHA512_CTX*, thread char[SHA512_DIGEST_STRING_LENGTH]);
REC_DEVICE void sha512_Raw(const thread uint8_t*, size_t, thread uint8_t[SHA512_DIGEST_LENGTH]);
REC_DEVICE thread char* sha512_Data(const thread uint8_t*, size_t, thread char[SHA512_DIGEST_STRING_LENGTH]);







#endif
