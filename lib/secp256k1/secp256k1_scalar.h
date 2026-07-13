REC_DEVICE  int secp256k1_scalar_is_zero(const SECP_THREAD secp256k1_scalar* __restrict__ a);

REC_DEVICE  int secp256k1_scalar_reduce(SECP_THREAD secp256k1_scalar* __restrict__ r, uint32_t overflow);

REC_DEVICE  int secp256k1_scalar_check_overflow(const SECP_THREAD secp256k1_scalar* __restrict__ a);

REC_DEVICE  void secp256k1_scalar_set_int(SECP_THREAD secp256k1_scalar* r, unsigned int v);

REC_DEVICE  void secp256k1_scalar_get_b32(SECP_THREAD unsigned char* bin, const SECP_THREAD secp256k1_scalar* __restrict__ a);

REC_DEVICE  void secp256k1_scalar_set_b32(SECP_THREAD secp256k1_scalar* __restrict__ r, const SECP_THREAD unsigned char* __restrict__ b32, SECP_THREAD int* __restrict__ overflow);

REC_DEVICE REC_NOINLINE int secp256k1_scalar_set_b32_seckey(SECP_THREAD secp256k1_scalar* r, const SECP_THREAD unsigned char* __restrict__ bin);

REC_DEVICE REC_NOINLINE void secp256k1_scalar_cmov(SECP_THREAD secp256k1_scalar* r, const SECP_THREAD secp256k1_scalar* a, int flag);

REC_DEVICE  int secp256k1_scalar_add(SECP_THREAD secp256k1_scalar* r, const SECP_THREAD secp256k1_scalar* __restrict__ a, const SECP_THREAD secp256k1_scalar* __restrict__ b);

REC_DEVICE  void secp256k1_scalar_clear(SECP_THREAD secp256k1_scalar* r);

REC_DEVICE  unsigned int secp256k1_scalar_get_bits(const SECP_THREAD secp256k1_scalar* __restrict__ a, unsigned int offset, unsigned int count);

REC_DEVICE  int secp256k1_scalar_shr_int(SECP_THREAD secp256k1_scalar* __restrict__ r, int n);

REC_DEVICE void secp256k1_scalar_mul(SECP_THREAD secp256k1_scalar* r, const SECP_THREAD secp256k1_scalar* a, const SECP_THREAD secp256k1_scalar* b);
