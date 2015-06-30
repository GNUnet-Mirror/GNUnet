/*
  This file is part of GNUnet
  Copyright (C) 2014,2015 Christian Grothoff (and other contributing authors)

  GNUnet is free software; you can redistribute it and/or modify it under the
  terms of the GNU General Public License as published by the Free Software
  Foundation; either version 3, or (at your option) any later version.

  GNUnet is distributed in the hope that it will be useful, but WITHOUT ANY
  WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
  A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

  You should have received a copy of the GNU General Public License along with
  TALER; see the file COPYING.  If not, If not, see <http://www.gnu.org/licenses/>
*/

/**
 * @file util/test_crypto_rsa.c
 * @brief testcase for utility functions for RSA cryptography
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */
#include "platform.h"
#include "gnunet_util_lib.h"

#define KEY_SIZE 1024


int
main (int argc,
      char *argv[])
{
#define RND_BLK_SIZE 4096
  unsigned char rnd_blk[RND_BLK_SIZE];
  struct GNUNET_CRYPTO_rsa_PrivateKey *priv;
  struct GNUNET_CRYPTO_rsa_PrivateKey *priv_copy;
  struct GNUNET_CRYPTO_rsa_PublicKey *pub;
  struct GNUNET_CRYPTO_rsa_PublicKey *pub_copy;
  struct GNUNET_CRYPTO_rsa_BlindingKey *bkey;
  struct GNUNET_CRYPTO_rsa_Signature *sig;
  struct GNUNET_CRYPTO_rsa_Signature *sig_copy;
  struct GNUNET_CRYPTO_rsa_Signature *bsig;
  struct GNUNET_HashCode hash;
  char *blind_buf;
  size_t bsize;

  GNUNET_log_setup ("test-rsa", "WARNING", NULL);
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
                              rnd_blk,
                              RND_BLK_SIZE);
  GNUNET_CRYPTO_hash (rnd_blk,
                      RND_BLK_SIZE,
                      &hash);
  priv = GNUNET_CRYPTO_rsa_private_key_create (KEY_SIZE);
  priv_copy = GNUNET_CRYPTO_rsa_private_key_dup (priv);
  GNUNET_assert (NULL != priv_copy);
  GNUNET_assert (0 == GNUNET_CRYPTO_rsa_private_key_cmp (priv, priv_copy));
  pub = GNUNET_CRYPTO_rsa_private_key_get_public (priv);
  /* Encoding */
  size_t size;
  char *enc;
  enc = NULL;
  size = GNUNET_CRYPTO_rsa_private_key_encode (priv, &enc);
  /* Decoding */
  GNUNET_CRYPTO_rsa_private_key_free (priv);
  priv = NULL;
  priv = GNUNET_CRYPTO_rsa_private_key_decode (enc, size);
  GNUNET_assert (NULL != priv);
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK,
                              enc, size);
  GNUNET_assert (NULL == GNUNET_CRYPTO_rsa_private_key_decode (enc, size));
  (void) fprintf (stderr, "The above warning is expected.\n");
  GNUNET_free (enc);

  /* try ordinary sig first */
  sig = GNUNET_CRYPTO_rsa_sign (priv,
                        &hash,
                        sizeof (hash));
  sig_copy = GNUNET_CRYPTO_rsa_signature_dup (sig);
  GNUNET_assert (NULL != sig);
  GNUNET_assert (0 == GNUNET_CRYPTO_rsa_signature_cmp (sig, sig_copy));
  pub_copy = GNUNET_CRYPTO_rsa_public_key_dup (pub);
  GNUNET_assert (NULL != pub_copy);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_rsa_verify (&hash, sig, pub_copy));
  /* corrupt our hash and see if the signature is still valid */
  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_WEAK, &hash,
                              sizeof (struct GNUNET_HashCode));
  GNUNET_assert (GNUNET_OK != GNUNET_CRYPTO_rsa_verify (&hash,
                                                        sig,
                                                        pub));
  (void) fprintf (stderr, "The above warning is expected.\n");
  GNUNET_CRYPTO_rsa_signature_free (sig);


  /* test blind signing */
  bkey = GNUNET_CRYPTO_rsa_blinding_key_create (KEY_SIZE);
  bsize = GNUNET_CRYPTO_rsa_blind (&hash,
                           bkey,
                           pub,
                           &blind_buf);
  GNUNET_assert (0 != bsize);
  bsig = GNUNET_CRYPTO_rsa_sign (priv,
                        blind_buf,
                        bsize);
  GNUNET_free (blind_buf);
  sig = GNUNET_CRYPTO_rsa_unblind (bsig,
                           bkey,
                           pub);
  GNUNET_CRYPTO_rsa_signature_free (bsig);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_rsa_verify (&hash, sig, pub));
  GNUNET_CRYPTO_rsa_signature_free (sig);
  GNUNET_CRYPTO_rsa_signature_free (sig_copy);
  GNUNET_CRYPTO_rsa_private_key_free (priv);
  GNUNET_CRYPTO_rsa_private_key_free (priv_copy);
  GNUNET_CRYPTO_rsa_public_key_free (pub);
  GNUNET_CRYPTO_rsa_public_key_free (pub_copy);
  GNUNET_CRYPTO_rsa_blinding_key_free (bkey);
  return 0;
}
