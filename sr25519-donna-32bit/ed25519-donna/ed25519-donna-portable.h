
#define ED25519_THREAD thread
#define ED25519_THREAD_CONST thread const


/* endian */

REC_DEVICE  inline void U32TO8_LE(ED25519_THREAD unsigned char* p, const uint32_t v);

REC_DEVICE  inline uint32_t U8TO32_LE(ED25519_THREAD_CONST unsigned char* p);
