/*
     This file is part of GNUnet.
     Copyright (C) 2002-2015 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
    
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later

*/
/**
 * @file util/test_crypto_ecdh_eddsa.c
 * @brief testcase for ECC DH key exchange with EdDSA private keys.
 * @author Christian Grothoff
 * @author Bart Polot
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <gcrypt.h>


static int
test_ecdh()
{
  struct GNUNET_CRYPTO_EddsaPrivateKey *priv_dsa;
  struct GNUNET_CRYPTO_EcdhePrivateKey *priv_ecdh;
  struct GNUNET_CRYPTO_EddsaPublicKey id1;
  struct GNUNET_CRYPTO_EcdhePublicKey id2;
  struct GNUNET_HashCode dh[2];

  /* Generate keys */
  priv_dsa = GNUNET_CRYPTO_eddsa_key_create ();
  GNUNET_CRYPTO_eddsa_key_get_public (priv_dsa,
                                      &id1);
  for (unsigned int j=0;j<4;j++)
  {
    fprintf (stderr, ",");
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
    GNUNET_assert (0 == memcmp (&dh[0],
                                &dh[1],
                                sizeof (struct GNUNET_HashCode)));
    GNUNET_free (priv_ecdh);
  }
  GNUNET_free (priv_dsa);
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
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u, 0);
  GNUNET_log_setup ("test-crypto-ecdh-eddsa", "WARNING", NULL);
  for (unsigned int i=0;i<4;i++)
  {
    fprintf (stderr,
             ".");
    if (0 != test_ecdh())
      return 1;
  }
  return 0;
}


/* end of test_crypto_ecdh_eddsa.c */
