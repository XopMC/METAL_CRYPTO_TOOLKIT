


METAL_DEVICE  void secp256k1_ge_from_storage(secp256k1_ge* __restrict__ r, const secp256k1_ge_storage* __restrict__ a);
METAL_DEVICE  void secp256k1_ge_from_storage_ldg(secp256k1_ge* __restrict__ r, const secp256k1_ge_storage* __restrict__ a);

METAL_DEVICE  int secp256k1_ge_set_xquad(secp256k1_ge* __restrict__ r, const secp256k1_fe* __restrict__ x);

METAL_DEVICE  int secp256k1_ge_set_xo_var(secp256k1_ge* __restrict__ r, const secp256k1_fe* __restrict__ x, int odd);

METAL_DEVICE  void secp256k1_gej_set_ge(secp256k1_gej* __restrict__ r, const secp256k1_ge* __restrict__ a);

METAL_DEVICE  void secp256k1_gej_double_nonzero(secp256k1_gej* __restrict__ r, const secp256k1_gej* __restrict__ a);

METAL_DEVICE  void secp256k1_gej_neg(secp256k1_gej* __restrict__ r, const secp256k1_gej* __restrict__ a);

METAL_DEVICE  void secp256k1_gej_double_var(secp256k1_gej* __restrict__ r, const secp256k1_gej* __restrict__ a, secp256k1_fe* rzr);

METAL_DEVICE  void secp256k1_gej_add_var(secp256k1_gej* __restrict__ r, const secp256k1_gej* __restrict__ a, const secp256k1_gej* __restrict__ b, secp256k1_fe* rzr);

METAL_DEVICE  void secp256k1_gej_set_infinity(secp256k1_gej* __restrict__ r);

METAL_DEVICE  void secp256k1_gej_add_ge_var(secp256k1_gej* __restrict__ r, const secp256k1_gej* __restrict__ a, const secp256k1_ge* __restrict__ b, secp256k1_fe* rzr);

METAL_DEVICE  void secp256k1_gej_add_ge(secp256k1_gej* __restrict__ r, const secp256k1_gej* __restrict__ a, const secp256k1_ge* __restrict__ b);

METAL_DEVICE  void secp256k1_ge_clear(secp256k1_ge* r);



METAL_DEVICE METAL_NOINLINE void secp256k1_ge_set_gej(secp256k1_ge* __restrict__ r, secp256k1_gej* __restrict__ a);

METAL_DEVICE  void secp256k1_ge_set_gej_zinv(secp256k1_ge* __restrict__ r, const secp256k1_gej* __restrict__ a, const secp256k1_fe* __restrict__ zi);



METAL_DEVICE  void secp256k1_ge_to_storage(secp256k1_ge_storage* __restrict__ r, const secp256k1_ge* __restrict__ a);

METAL_DEVICE  void secp256k1_ge_set_xy(secp256k1_ge* __restrict__ r, const secp256k1_fe* __restrict__ x, const secp256k1_fe* __restrict__ y);

METAL_DEVICE  int secp256k1_ge_is_infinity(const secp256k1_ge* __restrict__ a);

METAL_DEVICE  void secp256k1_ge_set_infinity(secp256k1_ge* __restrict__  r);

METAL_DEVICE  void secp256k1_ge_set_all_gej_var(secp256k1_ge* __restrict__ r, const secp256k1_gej* __restrict__ a, size_t len);


METAL_DEVICE   void secp256k1_ge_neg(secp256k1_ge* __restrict__ r, const secp256k1_ge* __restrict__ a);

METAL_DEVICE void secp256k1_gej_mul_u64_gej(secp256k1_gej* __restrict__ r, const secp256k1_gej* __restrict__ P, uint64_t k);