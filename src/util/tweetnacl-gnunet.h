/*
      This file has been placed in the public domain.

      Based on TweetNaCl version 20140427

      Originally obtained from:
      https://tweetnacl.cr.yp.to/20140427/tweetnacl.h

      SPDX-License-Identifier: 0BSD
 */


#ifndef TWEETNACL_H
#define TWEETNACL_H
#include <stdint.h>


#define GNUNET_TWEETNACL_SIGN_SECRETKEYBYTES 64
#define GNUNET_TWEETNACL_SIGN_PUBLICBYTES 32
#define GNUNET_TWEETNACL_SCALARMULT_BYTES 32

int
GNUNET_TWEETNACL_scalarmult_curve25519 (uint8_t *,
                                        const uint8_t *,
                                        const uint8_t *);
extern int
GNUNET_TWEETNACL_scalarmult_curve25519_base (uint8_t *,
                                             const uint8_t *);
void
GNUNET_TWEETNACL_sign_pk_from_seed (uint8_t *pk, const uint8_t *seed);

void
GNUNET_TWEETNACL_sign_sk_from_seed (uint8_t *sk, const uint8_t *seed);

int
GNUNET_TWEETNACL_sign_ed25519_pk_to_curve25519 (uint8_t *x25519_pk,
                                                const uint8_t *ed25519_pk);

int
GNUNET_TWEETNACL_sign_detached_verify (const uint8_t *sig,
                                       const uint8_t *m,
                                       uint64_t n,
                                       const uint8_t *pk);

int
GNUNET_TWEETNACL_sign_detached (uint8_t *sig,
                                const uint8_t *m,
                                uint64_t n,
                                const uint8_t *sk);
#endif
