/*
 * EVER/IP(R)
 * Copyright (c) 2017 kristopher tate & connectFree Corporation.
 * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * *
 * This project may be licensed under the terms of the ConnectFree Reference
 * Source License (CF-RSL). Corporate and Academic licensing terms are also
 * available. Please contact <licensing@connectfree.co.jp> for details.
 *
 * connectFree, the connectFree logo, and EVER/IP are registered trademarks
 * of connectFree Corporation in Japan and other countries. connectFree
 * trademarks and branding may not be used without express writen permission
 * of connectFree. Please remove all trademarks and branding before use.
 *
 * See the LICENSE file at the root of this project for complete information.
 *
 */

#include <re.h>
#include <everip.h>
#include <sodium.h>

/*
DISCLOSURE:
Knowhow from this mailing list:
https://moderncrypto.org/mail-archive/curves/2014/000205.html

and this public domain repo:
https://github.com/trevp/ref10_extract/blob/master/ed25519/additions/sign_modified.c
*/

typedef int32_t fe[10];
#define ge_p3 crypto_core_curve25519_ref10_ge_p3
typedef struct {
    fe X;
    fe Y;
    fe Z;
    fe T;
} ge_p3;

#define ge_p3_tobytes crypto_core_curve25519_ref10_ge_p3_tobytes
extern void ge_p3_tobytes(unsigned char *,const ge_p3 *);

#define ge_scalarmult_base crypto_core_curve25519_ref10_ge_scalarmult_base
extern void ge_scalarmult_base(ge_p3 *,const unsigned char *);

#define sc_reduce crypto_core_curve25519_ref10_sc_reduce
#define sc_muladd crypto_core_curve25519_ref10_sc_muladd

extern void sc_reduce(unsigned char *);
extern void sc_muladd(unsigned char *,const unsigned char *,const unsigned char *,const unsigned char *);

inline void cryptosign_pk_fromskpk(uint8_t pk[32], uint8_t skpk[64])
{
  memcpy(pk, &skpk[32], 32);
}

void cryptosign_bytes(uint8_t skpk[64], uint8_t *m, size_t mlen)
{
  ge_p3 R;
  uint8_t az[64];
  uint8_t r[64];
  uint8_t hram[64];

  if (mlen < 64)
    return;

  memcpy(az, skpk, 32);
  randombytes_buf(&az[32], 32);
  crypto_hash_sha512(az,az,64);
  memcpy(az, skpk, 32);
  az[0] &= 248;
  az[31] &= 63;
  az[31] |= 64;

  // hash message + secret number
  memcpy(m+32, &az[32], 32);
  crypto_hash_sha512(r, m+32, mlen-32);

  // Replace secret number with public key
  memcpy(m+32, &skpk[32], 32);

  // push pointMul(r) to message
  sc_reduce(r);
  ge_scalarmult_base(&R,r);
  ge_p3_tobytes(m, &R);

  crypto_hash_sha512(hram, m, mlen);
  sc_reduce(hram);
  sc_muladd(m+32, hram, az, r);
}

int cryptosign_bytes_verify(uint8_t pk[32], uint8_t *s, uint8_t *m, size_t mlen)
{
  return crypto_sign_verify_detached(s, m, mlen, pk);
}

void cryptosign_skpk_fromcurve25519(uint8_t skpk[64], uint8_t sk[32])
{
  ge_p3 A;
  memcpy(skpk, sk, 32);
  skpk[0] &= 248;
  skpk[31] &= 63;
  skpk[31] |= 64;
  ge_scalarmult_base(&A, skpk);
  ge_p3_tobytes(&skpk[32], &A);
}
