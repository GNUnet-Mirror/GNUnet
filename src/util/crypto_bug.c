/*
     This file is part of GNUnet.
     Copyright (C) 2018 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/

/**
 * @file util/crypto_bug.c
 * @brief work around unidentified public key cryptography bug
 * @author Christian Grothoff
 */

/**
 * Enable work-around.  Will cause code to call #check_eddsa_key() to
 * see if we have a bad key, and if so, create a new one.
 */
#define CRYPTO_BUG 0


#if CRYPTO_BUG
/**
 * Check if ECDH works with @a priv_dsa and this version
 * of libgcrypt.
 *
 * @param priv_dsa key to check
 * @return #GNUNET_OK if key passes
 */
static int
check_eddsa_key (const struct GNUNET_CRYPTO_EddsaPrivateKey *priv_dsa)
{
  struct GNUNET_CRYPTO_EcdhePrivateKey *priv_ecdh;
  struct GNUNET_CRYPTO_EddsaPublicKey id1;
  struct GNUNET_CRYPTO_EcdhePublicKey id2;
  struct GNUNET_HashCode dh[2];

  GNUNET_CRYPTO_eddsa_key_get_public (priv_dsa,
                                      &id1);
  for (unsigned int j=0;j<4;j++)
  {
    priv_ecdh = GNUNET_CRYPTO_ecdhe_key_create ();
    /* Extract public keys */
    GNUNET_CRYPTO_ecdhe_key_get_public (priv_ecdh,
                                        &id2);
    /* Do ECDH */
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_eddsa_ecdh (priv_dsa,
                                             &id2,
                                             &dh[0]));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_ecdh_eddsa (priv_ecdh,
                                             &id1,
                                             &dh[1]));
    /* Check that both DH results are equal. */
    if (0 != memcmp (&dh[0],
                     &dh[1],
                     sizeof (struct GNUNET_HashCode)))
    {
      GNUNET_break (0); /* bad EdDSA key! */
      return GNUNET_SYSERR;
    }
    GNUNET_free (priv_ecdh);
  }
  return GNUNET_OK;
}
#endif
