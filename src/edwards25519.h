/*
 * Copyright (c) 2015, Google Inc.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/*
 *  crypto/curve25519/internal.h
 *  crypto/curve25519/curve25519.h
 */

#ifndef edwards25519_h
#define edwards25519_h

#include <stdint.h>
#include <string.h>

#if defined(__cplusplus)
extern "C" {
#endif

#pragma mark - internal.h

#if defined(OPENSSL_ARM) && !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_APPLE)
#define BORINGSSL_X25519_NEON

// x25519_NEON is defined in asm/x25519-arm.S.
void x25519_NEON(uint8_t out[32], const uint8_t scalar[32],
                 const uint8_t point[32]);
#endif

#if defined(_MSC_VER)
#  if defined(_M_IA64) || defined(_M_X64)
#    define SIZEOF_SIZE_T 8
#    define SIZEOF_VOIDP  8
#  elif defined(_M_IX86)
#    define SIZEOF_SIZE_T 4
#    define SIZEOF_VOIDP  4
#  else
#    error "Unsupported MSVC platform"
#  endif
#elif defined(__GNUG__) || defined(__clang__)
#  if defined(__x86_64__) || defined(__ia64__)
#    define SIZEOF_SIZE_T 8
#    define SIZEOF_VOIDP  8
#  elif defined(__i386__)
#    define SIZEOF_SIZE_T 4
#    define SIZEOF_VOIDP  4
#  else
#    error "Unsupported GCC platform"
#  endif
#endif

#if SIZEOF_SIZE_T >= 8
#define BORINGSSL_CURVE25519_64BIT
typedef __int128_t int128_t;
typedef __uint128_t uint128_t;
#endif

#if defined(BORINGSSL_CURVE25519_64BIT)

#define TOBN(hi, lo) ((BN_ULONG)(hi) << 32 | (lo))

// fe means field element. Here the field is \Z/(2^255-19). An element t,
// entries t[0]...t[4], represents the integer t[0]+2^51 t[1]+2^102 t[2]+2^153
// t[3]+2^204 t[4].
// fe limbs are bounded by 1.125*2^51.
// Multiplication and carrying produce fe from fe_loose.
typedef struct fe { uint64_t v[5]; } fe;

// fe_loose limbs are bounded by 3.375*2^51.
// Addition and subtraction produce fe_loose from (fe, fe).
typedef struct fe_loose { uint64_t v[5]; } fe_loose;
#else

#define TOBN(hi, lo) (lo), (hi)

// fe means field element. Here the field is \Z/(2^255-19). An element t,
// entries t[0]...t[9], represents the integer t[0]+2^26 t[1]+2^51 t[2]+2^77
// t[3]+2^102 t[4]+...+2^230 t[9].
// fe limbs are bounded by 1.125*2^26,1.125*2^25,1.125*2^26,1.125*2^25,etc.
// Multiplication and carrying produce fe from fe_loose.
typedef struct fe { uint32_t v[10]; } fe;

// fe_loose limbs are bounded by 3.375*2^26,3.375*2^25,3.375*2^26,3.375*2^25,etc.
// Addition and subtraction produce fe_loose from (fe, fe).
typedef struct fe_loose { uint32_t v[10]; } fe_loose;
#endif

// ge means group element.
//
// Here the group is the set of pairs (x,y) of field elements (see fe.h)
// satisfying -x^2 + y^2 = 1 + d x^2y^2
// where d = -121665/121666.
//
// Representations:
//   ge_p2 (projective): (X:Y:Z) satisfying x=X/Z, y=Y/Z
//   ge_p3 (extended): (X:Y:Z:T) satisfying x=X/Z, y=Y/Z, XY=ZT
//   ge_p1p1 (completed): ((X:Z),(Y:T)) satisfying x=X/Z, y=Y/T
//   ge_precomp (Duif): (y+x,y-x,2dxy)

typedef struct {
  fe X;
  fe Y;
  fe Z;
} ge_p2;

typedef struct {
  fe X;
  fe Y;
  fe Z;
  fe T;
} ge_p3;

typedef struct {
  fe_loose X;
  fe_loose Y;
  fe_loose Z;
  fe_loose T;
} ge_p1p1;

typedef struct {
  fe_loose yplusx;
  fe_loose yminusx;
  fe_loose xy2d;
} ge_precomp;

typedef struct {
  fe_loose YplusX;
  fe_loose YminusX;
  fe_loose Z;
  fe_loose T2d;
} ge_cached;

void x25519_ge_tobytes(uint8_t s[32], const ge_p2 *h);
int x25519_ge_frombytes_vartime(ge_p3 *h, const uint8_t s[32]);
void x25519_ge_p3_to_cached(ge_cached *r, const ge_p3 *p);
void x25519_ge_p1p1_to_p2(ge_p2 *r, const ge_p1p1 *p);
void x25519_ge_p1p1_to_p3(ge_p3 *r, const ge_p1p1 *p);
void x25519_ge_add(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q);
void x25519_ge_sub(ge_p1p1 *r, const ge_p3 *p, const ge_cached *q);
void x25519_ge_scalarmult_small_precomp(ge_p3 *h, const uint8_t a[32], const uint8_t precomp_table[15 * 2 * 32]);
void x25519_ge_scalarmult_base(ge_p3 *h, const uint8_t a[32]);
void x25519_ge_scalarmult(ge_p2 *r, const uint8_t *scalar, const ge_p3 *A);
void x25519_sc_reduce(uint8_t s[64]);

// .... misc

static inline uint64_t CRYPTO_load_u64_le(const void *in) {
  uint64_t v;
  memcpy(&v, in, sizeof(v));
  return v;
}

#pragma mark - curve25519.h

// Curve25519.
//
// Curve25519 is an elliptic curve. See https://tools.ietf.org/html/rfc7748.


// X25519.
//
// X25519 is the Diffie-Hellman primitive built from curve25519. It is
// sometimes referred to as “curve25519”, but “X25519” is a more precise name.
// See http://cr.yp.to/ecdh.html and https://tools.ietf.org/html/rfc7748.

#define X25519_PRIVATE_KEY_LEN 32
#define X25519_PUBLIC_VALUE_LEN 32
#define X25519_SHARED_KEY_LEN 32

// X25519_keypair sets |out_public_value| and |out_private_key| to a freshly
// generated, public–private key pair.
void X25519_keypair(uint8_t out_public_value[32],
                                   uint8_t out_private_key[32]);

// X25519 writes a shared key to |out_shared_key| that is calculated from the
// given private key and the peer's public value. It returns one on success and
// zero on error.
//
// Don't use the shared key directly, rather use a KDF and also include the two
// public values as inputs.
int X25519(uint8_t out_shared_key[32],
                          const uint8_t private_key[32],
                          const uint8_t peer_public_value[32]);

// X25519_public_from_private calculates a Diffie-Hellman public value from the
// given private key and writes it to |out_public_value|.
void X25519_public_from_private(uint8_t out_public_value[32],
                                               const uint8_t private_key[32]);


// Ed25519.
//
// Ed25519 is a signature scheme using a twisted-Edwards curve that is
// birationally equivalent to curve25519.
//
// Note that, unlike RFC 8032's formulation, our private key representation
// includes a public key suffix to make multiple key signing operations with the
// same key more efficient. The RFC 8032 private key is referred to in this
// implementation as the "seed" and is the first 32 bytes of our private key.

#define ED25519_PRIVATE_KEY_LEN 64
#define ED25519_PUBLIC_KEY_LEN 32
#define ED25519_SIGNATURE_LEN 64

// ED25519_keypair sets |out_public_key| and |out_private_key| to a freshly
// generated, public–private key pair.
void ED25519_keypair(uint8_t out_public_key[32],
                                    uint8_t out_private_key[64]);

// ED25519_sign sets |out_sig| to be a signature of |message_len| bytes from
// |message| using |private_key|. It returns one on success or zero on
// allocation failure.
int ED25519_sign(uint8_t out_sig[64], const uint8_t *message,
                                size_t message_len,
                                const uint8_t private_key[64]);

// ED25519_verify returns one iff |signature| is a valid signature, by
// |public_key| of |message_len| bytes from |message|. It returns zero
// otherwise.
int ED25519_verify(const uint8_t *message, size_t message_len,
                                  const uint8_t signature[64],
                                  const uint8_t public_key[32]);

// ED25519_keypair_from_seed calculates a public and private key from an
// Ed25519 “seed”. Seed values are not exposed by this API (although they
// happen to be the first 32 bytes of a private key) so this function is for
// interoperating with systems that may store just a seed instead of a full
// private key.
void ED25519_keypair_from_seed(uint8_t out_public_key[32],
                                              uint8_t out_private_key[64],
                                              const uint8_t seed[32]);


#if defined(__cplusplus)
}  // extern C
#endif

#endif /* edwards25519_h */
