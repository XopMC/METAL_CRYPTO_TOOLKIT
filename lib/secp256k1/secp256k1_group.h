


REC_DEVICE  void secp256k1_ge_from_storage(SECP_THREAD secp256k1_ge* __restrict__ r, const SECP_CONSTANT secp256k1_ge_storage* __restrict__ a);
REC_DEVICE  void secp256k1_ge_from_storage_ldg(SECP_THREAD secp256k1_ge* __restrict__ r, const SECP_CONSTANT secp256k1_ge_storage* __restrict__ a);

REC_DEVICE  int secp256k1_ge_set_xquad(SECP_THREAD secp256k1_ge* __restrict__ r, const SECP_THREAD secp256k1_fe* __restrict__ x);

REC_DEVICE  int secp256k1_ge_set_xo_var(SECP_THREAD secp256k1_ge* __restrict__ r, const SECP_THREAD secp256k1_fe* __restrict__ x, int odd);

REC_DEVICE  void secp256k1_gej_set_ge(SECP_THREAD secp256k1_gej* __restrict__ r, const SECP_THREAD secp256k1_ge* __restrict__ a);

REC_DEVICE  void secp256k1_gej_double_nonzero(SECP_THREAD secp256k1_gej* __restrict__ r, const SECP_THREAD secp256k1_gej* __restrict__ a);

REC_DEVICE  void secp256k1_gej_neg(SECP_THREAD secp256k1_gej* __restrict__ r, const SECP_THREAD secp256k1_gej* __restrict__ a);

REC_DEVICE  void secp256k1_gej_double_var(SECP_THREAD secp256k1_gej* __restrict__ r, const SECP_THREAD secp256k1_gej* __restrict__ a, SECP_THREAD secp256k1_fe* rzr);

REC_DEVICE  void secp256k1_gej_add_var(SECP_THREAD secp256k1_gej* __restrict__ r, const SECP_THREAD secp256k1_gej* __restrict__ a, const SECP_THREAD secp256k1_gej* __restrict__ b, SECP_THREAD secp256k1_fe* rzr);

REC_DEVICE  void secp256k1_gej_set_infinity(SECP_THREAD secp256k1_gej* __restrict__ r);

REC_DEVICE  void secp256k1_gej_add_ge_var(SECP_THREAD secp256k1_gej* __restrict__ r, const SECP_THREAD secp256k1_gej* __restrict__ a, const SECP_THREAD secp256k1_ge* __restrict__ b, SECP_THREAD secp256k1_fe* rzr);

REC_DEVICE  void secp256k1_gej_add_ge(SECP_THREAD secp256k1_gej* __restrict__ r, const SECP_THREAD secp256k1_gej* __restrict__ a, const SECP_THREAD secp256k1_ge* __restrict__ b);

REC_DEVICE  void secp256k1_ge_clear(SECP_THREAD secp256k1_ge* r);



REC_DEVICE REC_NOINLINE void secp256k1_ge_set_gej(SECP_THREAD secp256k1_ge* __restrict__ r, SECP_THREAD secp256k1_gej* __restrict__ a);

REC_DEVICE  void secp256k1_ge_set_gej_zinv(SECP_THREAD secp256k1_ge* __restrict__ r, const SECP_THREAD secp256k1_gej* __restrict__ a, const SECP_THREAD secp256k1_fe* __restrict__ zi);



REC_DEVICE  void secp256k1_ge_to_storage(SECP_THREAD secp256k1_ge_storage* __restrict__ r, const SECP_THREAD secp256k1_ge* __restrict__ a);

REC_DEVICE  void secp256k1_ge_set_xy(SECP_THREAD secp256k1_ge* __restrict__ r, const SECP_THREAD secp256k1_fe* __restrict__ x, const SECP_THREAD secp256k1_fe* __restrict__ y);

REC_DEVICE  int secp256k1_ge_is_infinity(const SECP_THREAD secp256k1_ge* __restrict__ a);

REC_DEVICE  void secp256k1_ge_set_infinity(SECP_THREAD secp256k1_ge* __restrict__  r);

REC_DEVICE  void secp256k1_ge_set_all_gej_var(SECP_THREAD secp256k1_ge* __restrict__ r, const SECP_THREAD secp256k1_gej* __restrict__ a, size_t len);


REC_DEVICE   void secp256k1_ge_neg(SECP_THREAD secp256k1_ge* __restrict__ r, const SECP_THREAD secp256k1_ge* __restrict__ a);

REC_DEVICE void secp256k1_gej_mul_u64_gej(SECP_THREAD secp256k1_gej* __restrict__ r, const SECP_THREAD secp256k1_gej* __restrict__ P, uint64_t k);