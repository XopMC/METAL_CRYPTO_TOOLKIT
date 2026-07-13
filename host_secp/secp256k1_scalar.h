METAL_DEVICE  int secp256k1_scalar_is_zero(const secp256k1_scalar* __restrict__ a);

METAL_DEVICE  int secp256k1_scalar_reduce(secp256k1_scalar* __restrict__ r, uint32_t overflow);

METAL_DEVICE  int secp256k1_scalar_check_overflow(const secp256k1_scalar* __restrict__ a);

METAL_DEVICE  void secp256k1_scalar_set_int(secp256k1_scalar* r, unsigned int v);

METAL_DEVICE  void secp256k1_scalar_get_b32(unsigned char* bin, const secp256k1_scalar* __restrict__ a);

METAL_DEVICE  void secp256k1_scalar_set_b32(secp256k1_scalar* __restrict__ r, const unsigned char* __restrict__ b32, int* __restrict__ overflow);

METAL_DEVICE METAL_NOINLINE int secp256k1_scalar_set_b32_seckey(secp256k1_scalar* r, const unsigned char* __restrict__ bin);

METAL_DEVICE METAL_NOINLINE void secp256k1_scalar_cmov(secp256k1_scalar* r, const secp256k1_scalar* a, int flag);

METAL_DEVICE  int secp256k1_scalar_add(secp256k1_scalar* r, const secp256k1_scalar* __restrict__ a, const secp256k1_scalar* __restrict__ b);

METAL_DEVICE  void secp256k1_scalar_clear(secp256k1_scalar* r);

METAL_DEVICE  unsigned int secp256k1_scalar_get_bits(const secp256k1_scalar* __restrict__ a, unsigned int offset, unsigned int count);

METAL_DEVICE  int secp256k1_scalar_shr_int(secp256k1_scalar* __restrict__ r, int n);

METAL_DEVICE void secp256k1_scalar_mul(secp256k1_scalar* r, const secp256k1_scalar* a, const secp256k1_scalar* b);
