/*
    conversions
*/
#pragma once
#include "modm-donna-32bit.h"

#define ED25519_THREAD thread
#define ED25519_THREAD_CONST thread const
#define ED25519_CONSTANT constant

REC_DEVICE   void
ge25519_p1p1_to_partial(ED25519_THREAD ge25519* r, ED25519_THREAD_CONST ge25519_p1p1* p);

REC_DEVICE   void
ge25519_p1p1_to_full(ED25519_THREAD ge25519* r, ED25519_THREAD_CONST ge25519_p1p1* p);

REC_DEVICE  void
ge25519_full_to_pniels(ED25519_THREAD ge25519_pniels* p, ED25519_THREAD_CONST ge25519* r);

/*
    adding & doubling
*/

REC_DEVICE  void
ge25519_add_p1p1(ED25519_THREAD ge25519_p1p1* r, ED25519_THREAD_CONST ge25519* p, ED25519_THREAD_CONST ge25519* q);


REC_DEVICE  void
ge25519_double_p1p1(ED25519_THREAD ge25519_p1p1* r, ED25519_THREAD_CONST ge25519* p);

REC_DEVICE  void
ge25519_nielsadd2_p1p1(ED25519_THREAD ge25519_p1p1* r, ED25519_THREAD_CONST ge25519* p, ED25519_THREAD_CONST ge25519_niels* q, unsigned char signbit);

REC_DEVICE  void
ge25519_pnielsadd_p1p1(ED25519_THREAD ge25519_p1p1* r, ED25519_THREAD_CONST ge25519* p, ED25519_THREAD_CONST ge25519_pniels* q, unsigned char signbit);

REC_DEVICE  void
ge25519_double_partial(ED25519_THREAD ge25519* r, ED25519_THREAD_CONST ge25519* p);

REC_DEVICE  void
ge25519_double(ED25519_THREAD ge25519* r, ED25519_THREAD_CONST ge25519* p);

REC_DEVICE  void
ge25519_add(ED25519_THREAD ge25519* r, ED25519_THREAD_CONST ge25519* p, ED25519_THREAD_CONST ge25519* q);

REC_DEVICE  void
ge25519_nielsadd2(ED25519_THREAD ge25519* r, ED25519_THREAD_CONST ge25519_niels* q);

REC_DEVICE  void
ge25519_pnielsadd(ED25519_THREAD ge25519_pniels* r, ED25519_THREAD_CONST ge25519* p, ED25519_THREAD_CONST ge25519_pniels* q);


/*
    pack & unpack
*/

REC_DEVICE  void
ge25519_pack(unsigned char r[32], ED25519_THREAD_CONST ge25519* p);



/* computes [s1]p1 + [s2]basepoint */
REC_DEVICE  void
ge25519_double_scalarmult_vartime(ED25519_THREAD ge25519* r, ED25519_THREAD_CONST ge25519* p1, ED25519_THREAD_CONST bignum256modm s1, ED25519_THREAD_CONST bignum256modm s2);



#if !defined(HAVE_GE25519_SCALARMULT_BASE_CHOOSE_NIELS)

REC_DEVICE  uint32_t
ge25519_windowb_equal(uint32_t b, uint32_t c);

REC_DEVICE  void
ge25519_scalarmult_base_choose_niels(ED25519_THREAD ge25519_niels* t, ED25519_CONSTANT uint8_t table[416][96], uint32_t pos, signed char b);

#endif /* HAVE_GE25519_SCALARMULT_BASE_CHOOSE_NIELS */


/* computes [s]basepoint */
REC_DEVICE  void
ge25519_scalarmult_base_niels(ED25519_THREAD ge25519* r, ED25519_CONSTANT uint8_t basepoint_table[416][96], const bignum256modm s);
