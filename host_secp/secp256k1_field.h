
METAL_DEVICE  void secp256k1_fe_from_storage(secp256k1_fe* __restrict__ r, const secp256k1_fe_storage* __restrict__ a);

METAL_DEVICE  void secp256k1_fe_sqr_inner(uint32_t* __restrict__ r, const uint32_t* __restrict__ a);

METAL_DEVICE  void secp256k1_fe_sqr(secp256k1_fe* __restrict__ r, const secp256k1_fe* __restrict__ a);

METAL_DEVICE  void secp256k1_fe_normalize(secp256k1_fe* __restrict__ r);

METAL_DEVICE  void secp256k1_fe_normalize_weak(secp256k1_fe* __restrict__ r);

METAL_DEVICE  void secp256k1_fe_mul_inner(uint32_t* __restrict__ r, const uint32_t* __restrict__ a, const uint32_t* __restrict__  b);

METAL_DEVICE  void secp256k1_fe_mul(secp256k1_fe* __restrict__ r, const secp256k1_fe* __restrict__ a, const secp256k1_fe* __restrict__ b);

METAL_DEVICE  void secp256k1_fe_add(secp256k1_fe* __restrict__ r, const secp256k1_fe* __restrict__ a);

METAL_DEVICE  int secp256k1_fe_set_b32(secp256k1_fe* __restrict__ r, const unsigned char* __restrict__  a);

METAL_DEVICE  void secp256k1_fe_negate(secp256k1_fe* __restrict__ r, const secp256k1_fe* __restrict__ a, const int m);

METAL_DEVICE  void secp256k1_fe_half(secp256k1_fe* __restrict__ r);

METAL_DEVICE  int secp256k1_fe_normalizes_to_zero(secp256k1_fe* __restrict__ r);

METAL_DEVICE  void secp256k1_fe_mul_int(secp256k1_fe* __restrict__ r, int a);

METAL_DEVICE  void secp256k1_fe_set_int(secp256k1_fe* __restrict__ r, int a);

METAL_DEVICE  void secp256k1_fe_cmov(secp256k1_fe* __restrict__ r, const secp256k1_fe* __restrict__ a, int flag);

METAL_DEVICE  int secp256k1_fe_equal(const secp256k1_fe* __restrict__ a, const secp256k1_fe* __restrict__ b);

METAL_DEVICE  int secp256k1_fe_sqrt(secp256k1_fe* __restrict__ r, const secp256k1_fe* __restrict__ a);

METAL_DEVICE  int secp256k1_fe_is_odd(const secp256k1_fe* __restrict__ a);

METAL_DEVICE  int secp256k1_fe_normalizes_to_zero_var(secp256k1_fe* __restrict__ r);

METAL_DEVICE  void secp256k1_fe_normalize_var(secp256k1_fe* __restrict__ r);

METAL_DEVICE  void secp256k1_fe_clear(secp256k1_fe* __restrict__ a);

METAL_DEVICE  void secp256k1_fe_to_signed30(secp256k1_modinv32_signed30* __restrict__ r, const secp256k1_fe* __restrict__ a);

METAL_DEVICE  void secp256k1_fe_from_signed30(secp256k1_fe* __restrict__ r, const secp256k1_modinv32_signed30* __restrict__ a);

METAL_DEVICE  void secp256k1_fe_inv(secp256k1_fe* __restrict__ r, const secp256k1_fe* __restrict__ a);

METAL_DEVICE  void secp256k1_fe_inv_var(secp256k1_fe* __restrict__ r, const secp256k1_fe* __restrict__ a);

METAL_DEVICE  void secp256k1_fe_to_storage(secp256k1_fe_storage* __restrict__ r, const secp256k1_fe* __restrict__ a);

METAL_DEVICE  void secp256k1_fe_get_b32(unsigned char* __restrict__ r, const secp256k1_fe* __restrict__ a);

METAL_DEVICE  void secp256k1_fe_inv_all_var(const size_t len, secp256k1_fe* __restrict__ r, const secp256k1_fe* __restrict__ a);