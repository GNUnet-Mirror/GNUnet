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

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later

 */
/**
 * @file util/test_crypto_ecdsa.c
 * @brief testcase for ECC ECDSA public key crypto
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include <gcrypt.h>

#define ITER 25

#define PERF GNUNET_YES


static struct GNUNET_CRYPTO_EcdsaPrivateKey key;


static int
testSignVerify (void)
{
  struct GNUNET_CRYPTO_EcdsaSignature sig;
  struct GNUNET_CRYPTO_EccSignaturePurpose purp;
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;
  struct GNUNET_TIME_Absolute start;
  int ok = GNUNET_OK;

  fprintf (stderr, "%s", "W");
  GNUNET_CRYPTO_ecdsa_key_get_public (&key,
                                      &pkey);
  start = GNUNET_TIME_absolute_get ();
  purp.size = htonl (sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose));
  purp.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TEST);

  for (unsigned int i = 0; i < ITER; i++)
  {
    fprintf (stderr, "%s", ".");
    fflush (stderr);
    if (GNUNET_SYSERR ==
        GNUNET_CRYPTO_ecdsa_sign_ (&key,
                                   &purp,
                                   &sig))
    {
      fprintf (stderr,
               "GNUNET_CRYPTO_ecdsa_sign returned SYSERR\n");
      ok = GNUNET_SYSERR;
      continue;
    }
    if (GNUNET_SYSERR ==
        GNUNET_CRYPTO_ecdsa_verify_ (GNUNET_SIGNATURE_PURPOSE_TEST,
                                     &purp,
                                     &sig,
                                     &pkey))
    {
      fprintf (stderr,
               "GNUNET_CRYPTO_ecdsa_verify failed!\n");
      ok = GNUNET_SYSERR;
      continue;
    }
    if (GNUNET_SYSERR !=
        GNUNET_CRYPTO_ecdsa_verify_ (
          GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_OWN,
          &purp,
          &sig,
          &pkey))
    {
      fprintf (stderr,
               "GNUNET_CRYPTO_ecdsa_verify failed to fail!\n");
      ok = GNUNET_SYSERR;
      continue;
    }
  }
  printf ("%d ECDSA sign/verify operations %s\n",
          ITER,
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));
  return ok;
}


static int
testDeriveSignVerify (void)
{
  struct GNUNET_CRYPTO_EcdsaSignature sig;
  struct GNUNET_CRYPTO_EccSignaturePurpose purp;
  struct GNUNET_CRYPTO_EcdsaPrivateKey *dpriv;
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;
  struct GNUNET_CRYPTO_EcdsaPublicKey dpub;
  struct GNUNET_CRYPTO_EcdsaPublicKey dpub2;

  dpriv = GNUNET_CRYPTO_ecdsa_private_key_derive (&key,
                                                  "test-derive",
                                                  "test-CTX");
  GNUNET_CRYPTO_ecdsa_key_get_public (&key,
                                      &pkey);
  GNUNET_CRYPTO_ecdsa_public_key_derive (&pkey,
                                         "test-derive",
                                         "test-CTX",
                                         &dpub);
  GNUNET_CRYPTO_ecdsa_key_get_public (dpriv, &dpub2);
  purp.size = htonl (sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose));
  purp.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TEST);

  if (0 != GNUNET_memcmp (&dpub.q_y, &dpub2.q_y))
  {
    fprintf (stderr, "%s", "key derivation failed\n");
    GNUNET_free (dpriv);
    return GNUNET_SYSERR;
  }

  if (GNUNET_SYSERR ==
      GNUNET_CRYPTO_ecdsa_sign_ (dpriv,
                                 &purp,
                                 &sig))
  {
    fprintf (stderr, "%s", "GNUNET_CRYPTO_ecdsa_sign returned SYSERR\n");
    GNUNET_free (dpriv);
    return GNUNET_SYSERR;
  }
  if (GNUNET_SYSERR ==
      GNUNET_CRYPTO_ecdsa_verify_ (GNUNET_SIGNATURE_PURPOSE_TEST,
                                   &purp,
                                   &sig,
                                   &dpub))
  {
    fprintf (stderr,
             "GNUNET_CRYPTO_ecdsa_verify failed!\n");
    GNUNET_free (dpriv);
    return GNUNET_SYSERR;
  }
  if (GNUNET_SYSERR !=
      GNUNET_CRYPTO_ecdsa_verify_ (GNUNET_SIGNATURE_PURPOSE_TEST,
                                   &purp,
                                   &sig,
                                   &pkey))
  {
    fprintf (stderr,
             "GNUNET_CRYPTO_ecdsa_verify failed to fail!\n");
    GNUNET_free (dpriv);
    return GNUNET_SYSERR;
  }
  if (GNUNET_SYSERR !=
      GNUNET_CRYPTO_ecdsa_verify_ (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_OWN,
                                   &purp,
                                   &sig,
                                   &dpub))
  {
    fprintf (stderr,
             "GNUNET_CRYPTO_ecdsa_verify failed to fail!\n");
    GNUNET_free (dpriv);
    return GNUNET_SYSERR;
  }
  GNUNET_free (dpriv);
  return GNUNET_OK;
}


#if PERF
static int
testSignPerformance (void)
{
  struct GNUNET_CRYPTO_EccSignaturePurpose purp;
  struct GNUNET_CRYPTO_EcdsaSignature sig;
  struct GNUNET_CRYPTO_EcdsaPublicKey pkey;
  int i;
  struct GNUNET_TIME_Absolute start;
  int ok = GNUNET_OK;

  purp.size = htonl (sizeof(struct GNUNET_CRYPTO_EccSignaturePurpose));
  purp.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TEST);
  fprintf (stderr, "%s", "W");
  GNUNET_CRYPTO_ecdsa_key_get_public (key, &pkey);
  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < ITER; i++)
  {
    fprintf (stderr, "%s", "."); fflush (stderr);
    if (GNUNET_SYSERR == GNUNET_CRYPTO_ecdsa_sign_ (key, &purp, &sig))
    {
      fprintf (stderr, "%s",
               "GNUNET_CRYPTO_ecdsa_sign returned SYSERR\n");
      ok = GNUNET_SYSERR;
      continue;
    }
  }
  printf ("%d ECC sign operations %s\n", ITER,
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));
  return ok;
}


#endif


static void
perf_keygen (void)
{
  struct GNUNET_TIME_Absolute start;
  struct GNUNET_CRYPTO_EcdsaPrivateKey pk;

  fprintf (stderr, "%s", "W");
  start = GNUNET_TIME_absolute_get ();
  for (unsigned int i = 0; i < 10; i++)
  {
    fprintf (stderr, ".");
    fflush (stderr);
    GNUNET_CRYPTO_ecdsa_key_create (&pk);
  }
  fflush (stderr);
  printf ("10 ECDSA keys created in %s\n",
          GNUNET_STRINGS_relative_time_to_string (
            GNUNET_TIME_absolute_get_duration (start),
            GNUNET_YES));
}


int
main (int argc, char *argv[])
{
  int failure_count = 0;

  if (! gcry_check_version ("1.6.0"))
  {
    fprintf (stderr,
             "libgcrypt has not the expected version (version %s is required).\n",
             "1.6.0");
    return 0;
  }
  if (getenv ("GNUNET_GCRYPT_DEBUG"))
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u, 0);
  GNUNET_log_setup ("test-crypto-ecc", "WARNING", NULL);
  GNUNET_CRYPTO_ecdsa_key_create (&key);
  if (GNUNET_OK != testDeriveSignVerify ())
  {
    failure_count++;
    fprintf (stderr,
             "\n\n%d TESTS FAILED!\n\n", failure_count);
    return -1;
  }
#if PERF
  if (GNUNET_OK != testSignPerformance ())
    failure_count++;
#endif
  if (GNUNET_OK != testSignVerify ())
    failure_count++;
  perf_keygen ();

  if (0 != failure_count)
  {
    fprintf (stderr,
             "\n\n%d TESTS FAILED!\n\n",
             failure_count);
    return -1;
  }
  return 0;
}


/* end of test_crypto_ecdsa.c */
