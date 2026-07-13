
REC_DEVICE  void secp256k1_fe_from_storage(SECP_THREAD secp256k1_fe* __restrict__ r, const SECP_CONSTANT secp256k1_fe_storage* __restrict__ a);

REC_DEVICE  void secp256k1_fe_sqr_inner(SECP_THREAD uint32_t* __restrict__ r, const SECP_THREAD uint32_t* __restrict__ a);

REC_DEVICE  void secp256k1_fe_sqr(SECP_THREAD secp256k1_fe* __restrict__ r, const SECP_THREAD secp256k1_fe* __restrict__ a);

REC_DEVICE  void secp256k1_fe_normalize(SECP_THREAD secp256k1_fe* __restrict__ r);

REC_DEVICE  void secp256k1_fe_normalize_weak(SECP_THREAD secp256k1_fe* __restrict__ r);

REC_DEVICE  void secp256k1_fe_mul_inner(SECP_THREAD uint32_t* __restrict__ r, const SECP_THREAD uint32_t* __restrict__ a, const SECP_THREAD uint32_t* __restrict__  b);

REC_DEVICE  void secp256k1_fe_mul(SECP_THREAD secp256k1_fe* __restrict__ r, const SECP_THREAD secp256k1_fe* __restrict__ a, const SECP_THREAD secp256k1_fe* __restrict__ b);

REC_DEVICE  void secp256k1_fe_add(SECP_THREAD secp256k1_fe* __restrict__ r, const SECP_THREAD secp256k1_fe* __restrict__ a);

REC_DEVICE  int secp256k1_fe_set_b32(SECP_THREAD secp256k1_fe* __restrict__ r, const SECP_THREAD unsigned char* __restrict__  a);

REC_DEVICE  void secp256k1_fe_negate(SECP_THREAD secp256k1_fe* __restrict__ r, const SECP_THREAD secp256k1_fe* __restrict__ a, const int m);

REC_DEVICE  void secp256k1_fe_half(SECP_THREAD secp256k1_fe* __restrict__ r);

REC_DEVICE  int secp256k1_fe_normalizes_to_zero(SECP_THREAD secp256k1_fe* __restrict__ r);

REC_DEVICE  void secp256k1_fe_mul_int(SECP_THREAD secp256k1_fe* __restrict__ r, int a);

REC_DEVICE  void secp256k1_fe_set_int(SECP_THREAD secp256k1_fe* __restrict__ r, int a);

REC_DEVICE  void secp256k1_fe_cmov(SECP_THREAD secp256k1_fe* __restrict__ r, const SECP_THREAD secp256k1_fe* __restrict__ a, int flag);

REC_DEVICE  int secp256k1_fe_equal(const SECP_THREAD secp256k1_fe* __restrict__ a, const SECP_THREAD secp256k1_fe* __restrict__ b);

REC_DEVICE  int secp256k1_fe_sqrt(SECP_THREAD secp256k1_fe* __restrict__ r, const SECP_THREAD secp256k1_fe* __restrict__ a);

REC_DEVICE  int secp256k1_fe_is_odd(const SECP_THREAD secp256k1_fe* __restrict__ a);

REC_DEVICE  int secp256k1_fe_normalizes_to_zero_var(SECP_THREAD secp256k1_fe* __restrict__ r);

REC_DEVICE  void secp256k1_fe_normalize_var(SECP_THREAD secp256k1_fe* __restrict__ r);

REC_DEVICE  void secp256k1_fe_clear(SECP_THREAD secp256k1_fe* __restrict__ a);

REC_DEVICE  void secp256k1_fe_to_signed30(SECP_THREAD secp256k1_modinv32_signed30* __restrict__ r, const SECP_THREAD secp256k1_fe* __restrict__ a);

REC_DEVICE  void secp256k1_fe_from_signed30(SECP_THREAD secp256k1_fe* __restrict__ r, const SECP_THREAD secp256k1_modinv32_signed30* __restrict__ a);

REC_DEVICE  void secp256k1_fe_inv(SECP_THREAD secp256k1_fe* __restrict__ r, const SECP_THREAD secp256k1_fe* __restrict__ a);

REC_DEVICE  void secp256k1_fe_inv_var(SECP_THREAD secp256k1_fe* __restrict__ r, const SECP_THREAD secp256k1_fe* __restrict__ a);

REC_DEVICE  void secp256k1_fe_to_storage(SECP_THREAD secp256k1_fe_storage* __restrict__ r, const SECP_THREAD secp256k1_fe* __restrict__ a);

REC_DEVICE  void secp256k1_fe_get_b32(SECP_THREAD unsigned char* __restrict__ r, const SECP_THREAD secp256k1_fe* __restrict__ a);

REC_DEVICE  void secp256k1_fe_inv_all_var(const size_t len, SECP_THREAD secp256k1_fe* __restrict__ r, const SECP_THREAD secp256k1_fe* __restrict__ a);