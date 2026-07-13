#pragma once
REC_DEVICE  void
curve25519_pow_two5mtwo0_two250mtwo0(bignum25519 b);

/*
 * z^(p - 2) = z(2^255 - 21)
 */
REC_DEVICE  void
curve25519_recip(bignum25519 out, const bignum25519 z);

/*
 * z^((p-5)/8) = z^(2^252 - 3)
 */
REC_DEVICE  void
curve25519_pow_two252m3(bignum25519 two252m3, const bignum25519 z);
