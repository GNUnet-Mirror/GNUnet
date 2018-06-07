/*
     This file is part of GNUnet.
     Copyright (C) 2002-2013 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

*/
/**
 * @file util/test_crypto_ecdhe.c
 * @brief testcase for ECC ECDHE public key crypto
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include <gcrypt.h>


int
main (int argc, char *argv[])
{
  struct GNUNET_CRYPTO_EcdhePrivateKey *priv1;
  struct GNUNET_CRYPTO_EcdhePrivateKey *priv2;
  struct GNUNET_CRYPTO_EcdhePublicKey pub1;
  struct GNUNET_CRYPTO_EcdhePublicKey pub2;
  struct GNUNET_HashCode ecdh1;
  struct GNUNET_HashCode ecdh2;

  if (! gcry_check_version ("1.6.0"))
  {
    FPRINTF (stderr,
             _
             ("libgcrypt has not the expected version (version %s is required).\n"),
             "1.6.0");
    return 0;
  }
  if (getenv ("GNUNET_GCRYPT_DEBUG"))
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u , 0);
  GNUNET_log_setup ("test-crypto-ecdhe", "WARNING", NULL);

  for (unsigned int i=0;i<100;i++)
  {
    fprintf (stderr,
             ".");
    priv1 = GNUNET_CRYPTO_ecdhe_key_create ();
    priv2 = GNUNET_CRYPTO_ecdhe_key_create ();
    GNUNET_CRYPTO_ecdhe_key_get_public (priv1, &pub1);
    GNUNET_CRYPTO_ecdhe_key_get_public (priv2, &pub2);
    GNUNET_CRYPTO_ecc_ecdh (priv1, &pub2, &ecdh1);
    GNUNET_CRYPTO_ecc_ecdh (priv2, &pub1, &ecdh2);
    GNUNET_assert (0 == memcmp (&ecdh1, &ecdh2,
                                sizeof (struct GNUNET_HashCode)));
    GNUNET_free (priv1);
    GNUNET_free (priv2);
  }
  return 0;
}

/* end of test_crypto_ecdhe.c */
