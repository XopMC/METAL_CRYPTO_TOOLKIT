/***********************************************************************
 * Copyright (c) 2020 Peter Dettman                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODINV32_IMPL_H
#define SECP256K1_MODINV32_IMPL_H

#include <stdlib.h>

 /* This file implements modular inversion based on the paper "Fast constant-time gcd computation and
  * modular inversion" by Daniel J. Bernstein and Bo-Yin Yang.
  *
  * For an explanation of the algorithm, see doc/safegcd_implementation.md. This file contains an
  * implementation for N=30, using 30-bit signed limbs represented as int32_t.
  */

/* Take as input a signed30 number in range (-2*modulus,modulus), and add a multiple of the modulus
 * to it to bring it to range [0,modulus). If sign < 0, the input will also be negated in the
 * process. The input must have limbs in range (-2^30,2^30). The output will have limbs in range
 * [0,2^30). */
METAL_DEVICE  void secp256k1_modinv32_normalize_30(secp256k1_modinv32_signed30* __restrict__  r, int32_t sign, const secp256k1_modinv32_modinfo* __restrict__ modinfo);

/* Data type for transition matrices (see section 3 of explanation).
 *
 * t = [ u  v ]
 *     [ q  r ]
 */
typedef struct METAL_ALIGN(16) {
    int32_t u, v, q, r;
} secp256k1_modinv32_trans2x2;

/* Compute the transition matrix and zeta for 30 divsteps.
 *
 * Input:  zeta: initial zeta
 *         f0:   bottom limb of initial f
 *         g0:   bottom limb of initial g
 * Output: t: transition matrix
 * Return: final zeta
 *
 * Implements the divsteps_n_matrix function from the explanation.
 */
METAL_DEVICE  int32_t secp256k1_modinv32_divsteps_30(int32_t zeta, uint32_t f0, uint32_t g0, secp256k1_modinv32_trans2x2* __restrict__  t);

/* Compute the transition matrix and eta for 30 divsteps (variable time).
 *
 * Input:  eta: initial eta
 *         f0:  bottom limb of initial f
 *         g0:  bottom limb of initial g
 * Output: t: transition matrix
 * Return: final eta
 *
 * Implements the divsteps_n_matrix_var function from the explanation.
 */
METAL_DEVICE  int32_t secp256k1_modinv32_divsteps_30_var(int32_t eta, uint32_t f0, uint32_t g0, secp256k1_modinv32_trans2x2* __restrict__   t);

/* Compute (t/2^30) * [d, e] mod modulus, where t is a transition matrix for 30 divsteps.
 *
 * On input and output, d and e are in range (-2*modulus,modulus). All output limbs will be in range
 * (-2^30,2^30).
 *
 * This implements the update_de function from the explanation.
 */
METAL_DEVICE  void secp256k1_modinv32_update_de_30(secp256k1_modinv32_signed30* __restrict__  d, secp256k1_modinv32_signed30* __restrict__ e, const secp256k1_modinv32_trans2x2* __restrict__ t, const secp256k1_modinv32_modinfo* __restrict__ modinfo);

/* Compute (t/2^30) * [f, g], where t is a transition matrix for 30 divsteps.
 *
 * This implements the update_fg function from the explanation.
 */
METAL_DEVICE  void secp256k1_modinv32_update_fg_30(secp256k1_modinv32_signed30* __restrict__  f, secp256k1_modinv32_signed30* __restrict__  g, const secp256k1_modinv32_trans2x2* __restrict__  t);

/* Compute (t/2^30) * [f, g], where t is a transition matrix for 30 divsteps.
 *
 * Version that operates on a variable number of limbs in f and g.
 *
 * This implements the update_fg function from the explanation in modinv64_impl.h.
 */
METAL_DEVICE  void secp256k1_modinv32_update_fg_30_var(int len, secp256k1_modinv32_signed30* __restrict__  f, secp256k1_modinv32_signed30* __restrict__  g, const secp256k1_modinv32_trans2x2* __restrict__  t);

/* Compute the inverse of x modulo modinfo->modulus, and replace x with it (constant time in x). */
METAL_DEVICE  void secp256k1_modinv32(secp256k1_modinv32_signed30* __restrict__ x, const secp256k1_modinv32_modinfo* __restrict__  modinfo);

/* Compute the inverse of x modulo modinfo->modulus, and replace x with it (variable time). */
METAL_DEVICE  void secp256k1_modinv32_var(secp256k1_modinv32_signed30* __restrict__  x, const secp256k1_modinv32_modinfo* __restrict__  modinfo);

#endif /* SECP256K1_MODINV32_IMPL_H */