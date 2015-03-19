/*
     This file is part of GNUnet.
     Copyright (C) 2002-2015 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.

*/
/**
 * @file util/test_crypto_ecdh_ecdsa.c
 * @brief testcase for ECC DH key exchange with EdDSA private keys.
 * @author Christian Grothoff
 * @author Bart Polot
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <gcrypt.h>


static int
test_pk()
{
  struct GNUNET_CRYPTO_EcdsaPrivateKey *priv1;
  struct GNUNET_CRYPTO_EcdhePrivateKey priv2;
  struct GNUNET_CRYPTO_EcdsaPublicKey pub1;
  struct GNUNET_CRYPTO_EcdhePublicKey pub2;
  struct GNUNET_CRYPTO_EcdhePublicKey pub1c;

  /* Generate, cast keys */
  priv1 = GNUNET_CRYPTO_ecdsa_key_create ();
  memcpy (&priv2,
          priv1,
          sizeof (priv2));

  /* Extract public keys */
  GNUNET_CRYPTO_ecdsa_key_get_public (priv1, &pub1);
  GNUNET_CRYPTO_ecdhe_key_get_public (&priv2, &pub2);

  GNUNET_CRYPTO_ecdsa_public_to_ecdhe (&pub1, &pub1c);
  if (0 == memcmp (&pub1c,
                   &pub2,
                   sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey)))
  {
    GNUNET_free (priv1);
    return 0;
  }
  GNUNET_free (priv1);
  return 1;
}


static int
test_ecdh()
{
  struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_dsa1;
  struct GNUNET_CRYPTO_EcdsaPrivateKey *priv_dsa2;
  struct GNUNET_CRYPTO_EcdsaPublicKey id1;
  struct GNUNET_CRYPTO_EcdsaPublicKey id2;
  struct GNUNET_CRYPTO_EcdhePublicKey id1c;
  struct GNUNET_CRYPTO_EcdhePublicKey id2c;

  struct GNUNET_CRYPTO_EcdhePrivateKey *priv1;
  struct GNUNET_CRYPTO_EcdhePrivateKey *priv2;
  struct GNUNET_CRYPTO_EcdhePublicKey pub2;
  struct GNUNET_HashCode dh[3];

  /* Generate, cast keys */
  priv_dsa1 = GNUNET_CRYPTO_ecdsa_key_create ();
  priv_dsa2 = GNUNET_CRYPTO_ecdsa_key_create ();
  priv1 = (struct GNUNET_CRYPTO_EcdhePrivateKey *) priv_dsa1;
  priv2 = (struct GNUNET_CRYPTO_EcdhePrivateKey *) priv_dsa2;

  /* Extract public keys */
  GNUNET_CRYPTO_ecdsa_key_get_public (priv_dsa1, &id1);
  GNUNET_CRYPTO_ecdsa_key_get_public (priv_dsa2, &id2);
  GNUNET_CRYPTO_ecdhe_key_get_public (priv2, &pub2);

  /* Do ECDH */
  GNUNET_CRYPTO_ecdsa_public_to_ecdhe (&id2,
                                       &id2c);
  GNUNET_CRYPTO_ecdsa_public_to_ecdhe (&id1,
                                       &id1c);
  GNUNET_CRYPTO_ecc_ecdh (priv1,
                          &id2c,
                          &dh[0]);
  GNUNET_CRYPTO_ecc_ecdh (priv2,
                          &id1c,
                          &dh[1]);
  GNUNET_CRYPTO_ecc_ecdh (priv1, &pub2, &dh[2]);

  /* Check that both DH results are equal. */
  GNUNET_assert (0 == memcmp (&dh[0], &dh[1],
			      sizeof (struct GNUNET_HashCode)));

  /* FIXME: Maybe it should be the same as with ECDHE. */
  // GNUNET_assert (0 == memcmp (&dh[1], &dh[2],
  //                            sizeof (struct GNUNET_HashCode)));
  // GNUNET_assert (0 == memcmp (&id1, &pub1,
  //                            sizeof (struct GNUNET_CRYPTO_EcdhePublicKey)));

  /* Free */
  GNUNET_free (priv1);
  GNUNET_free (priv2);
  return 0;
}


int
main (int argc, char *argv[])
{
  if (! gcry_check_version ("1.6.0"))
  {
    FPRINTF (stderr,
             _("libgcrypt has not the expected version (version %s is required).\n"),
             "1.6.0");
    return 0;
  }
  if (getenv ("GNUNET_GCRYPT_DEBUG"))
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u , 0);
  GNUNET_log_setup ("test-crypto-ecdh-ecdsa", "WARNING", NULL);
  if (0 != test_pk())
    return 1;
  if (0 != test_ecdh())
    return 1;
  return 0;
}


/* end of test_crypto_ecdh_ecdsa.c */
