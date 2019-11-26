/*
      This file has been placed in the public domain.

      Based on TweetNaCl version 20140427

      Originally obtained from:
      https://tweetnacl.cr.yp.to/20140427/tweetnacl.h
 */


#ifndef TWEETNACL_H
#define TWEETNACL_H
#include <stdint.h>
#define crypto_scalarmult_PRIMITIVE "curve25519"
#define crypto_scalarmult crypto_scalarmult_curve25519
#define crypto_scalarmult_base crypto_scalarmult_curve25519_base
#define crypto_scalarmult_BYTES crypto_scalarmult_curve25519_BYTES
#define crypto_scalarmult_SCALARBYTES crypto_scalarmult_curve25519_SCALARBYTES
#define crypto_scalarmult_IMPLEMENTATION \
  crypto_scalarmult_curve25519_IMPLEMENTATION
#define crypto_scalarmult_VERSION crypto_scalarmult_curve25519_VERSION
#define crypto_scalarmult_curve25519_tweet_BYTES 32
#define crypto_scalarmult_curve25519_tweet_SCALARBYTES 32
extern int crypto_scalarmult_curve25519_tweet (uint8_t *,
                                               const uint8_t *,
                                               const uint8_t *);
extern int crypto_scalarmult_curve25519_tweet_base (uint8_t *,
                                                    const uint8_t *);
#define crypto_scalarmult_curve25519_tweet_VERSION "-"
#define crypto_scalarmult_curve25519 crypto_scalarmult_curve25519_tweet
#define crypto_scalarmult_curve25519_base \
  crypto_scalarmult_curve25519_tweet_base
#define crypto_scalarmult_curve25519_BYTES \
  crypto_scalarmult_curve25519_tweet_BYTES
#define crypto_scalarmult_curve25519_SCALARBYTES \
  crypto_scalarmult_curve25519_tweet_SCALARBYTES
#define crypto_scalarmult_curve25519_VERSION \
  crypto_scalarmult_curve25519_tweet_VERSION
#define crypto_scalarmult_curve25519_IMPLEMENTATION \
  "crypto_scalarmult/curve25519/tweet"
#define crypto_sign_PRIMITIVE "ed25519"
#define crypto_sign crypto_sign_ed25519
#define crypto_sign_BYTES crypto_sign_ed25519_BYTES
#define crypto_sign_PUBLICKEYBYTES crypto_sign_ed25519_PUBLICKEYBYTES
#define crypto_sign_SECRETKEYBYTES crypto_sign_ed25519_SECRETKEYBYTES
#define crypto_sign_IMPLEMENTATION crypto_sign_ed25519_IMPLEMENTATION
#define crypto_sign_VERSION crypto_sign_ed25519_VERSION
#define crypto_sign_ed25519_tweet_BYTES 64
#define crypto_sign_ed25519_tweet_PUBLICKEYBYTES 32
#define crypto_sign_ed25519_tweet_SECRETKEYBYTES 64
extern int crypto_sign_ed25519_tweet (uint8_t *,
                                      uint64_t *,
                                      const uint8_t *,
                                      uint64_t,
                                      const uint8_t *);
extern int crypto_sign_ed25519_tweet_open (uint8_t *,
                                           uint64_t *,
                                           const uint8_t *,
                                           uint64_t,
                                           const uint8_t *);
extern int crypto_sign_ed25519_tweet_keypair (uint8_t *,uint8_t *);
#define crypto_sign_ed25519_tweet_VERSION "-"
#define crypto_sign_ed25519 crypto_sign_ed25519_tweet
#define crypto_sign_ed25519_open crypto_sign_ed25519_tweet_open
#define crypto_sign_ed25519_keypair crypto_sign_ed25519_tweet_keypair
#define crypto_sign_ed25519_BYTES crypto_sign_ed25519_tweet_BYTES
#define crypto_sign_ed25519_PUBLICKEYBYTES \
  crypto_sign_ed25519_tweet_PUBLICKEYBYTES
#define crypto_sign_ed25519_SECRETKEYBYTES \
  crypto_sign_ed25519_tweet_SECRETKEYBYTES
#define crypto_sign_ed25519_VERSION crypto_sign_ed25519_tweet_VERSION
#define crypto_sign_ed25519_IMPLEMENTATION "crypto_sign/ed25519/tweet"
void crypto_sign_pk_from_seed (uint8_t *pk, const uint8_t *seed);
void crypto_sign_sk_from_seed (uint8_t *sk, const uint8_t *seed);
int crypto_sign_ed25519_pk_to_curve25519 (uint8_t *x25519_pk,
                                          const uint8_t *ed25519_pk);
int crypto_sign_detached_verify (const uint8_t *sig,
                                 const uint8_t *m,
                                 uint64_t n,
                                 const uint8_t *pk);
int crypto_sign_detached (uint8_t *sig,
                          const uint8_t *m,
                          uint64_t n,
                          const uint8_t *sk);
#endif
