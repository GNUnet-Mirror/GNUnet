/*
     This file is part of GNUnet.
     Copyright (C) 2002-2013 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.

*/
/**
 * @file util/test_crypto_eddsa.c
 * @brief testcase for ECC public key crypto
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include <gcrypt.h>

#define ITER 25

#define KEYFILE "/tmp/test-gnunet-crypto-eddsa.key"

#define PERF GNUNET_YES


static struct GNUNET_CRYPTO_EddsaPrivateKey *key;


static int
testSignVerify ()
{
  struct GNUNET_CRYPTO_EddsaSignature sig;
  struct GNUNET_CRYPTO_EccSignaturePurpose purp;
  struct GNUNET_CRYPTO_EddsaPublicKey pkey;
  int i;
  struct GNUNET_TIME_Absolute start;
  int ok = GNUNET_OK;

  FPRINTF (stderr, "%s",  "W");
  GNUNET_CRYPTO_eddsa_key_get_public (key, &pkey);
  start = GNUNET_TIME_absolute_get ();
  purp.size = htonl (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose));
  purp.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TEST);

  for (i = 0; i < ITER; i++)
  {
    FPRINTF (stderr, "%s",  "."); fflush (stderr);
    if (GNUNET_SYSERR == GNUNET_CRYPTO_eddsa_sign (key, &purp, &sig))
    {
      FPRINTF (stderr, "%s",  "GNUNET_CRYPTO_eddsa_sign returned SYSERR\n");
      ok = GNUNET_SYSERR;
      continue;
    }
    if (GNUNET_SYSERR ==
        GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_PURPOSE_TEST, &purp, &sig,
                                  &pkey))
    {
      printf ("GNUNET_CRYPTO_eddsa_verify failed!\n");
      ok = GNUNET_SYSERR;
      continue;
    }
    if (GNUNET_SYSERR !=
        GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_OWN,
                                  &purp, &sig, &pkey))
    {
      printf ("GNUNET_CRYPTO_eddsa_verify failed to fail!\n");
      ok = GNUNET_SYSERR;
      continue;
    }
  }
  printf ("%d EdDSA sign/verify operations %s\n", ITER,
          GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_duration (start), GNUNET_YES));
  return ok;
}


#if PERF
static int
testSignPerformance ()
{
  struct GNUNET_CRYPTO_EccSignaturePurpose purp;
  struct GNUNET_CRYPTO_EddsaSignature sig;
  struct GNUNET_CRYPTO_EddsaPublicKey pkey;
  int i;
  struct GNUNET_TIME_Absolute start;
  int ok = GNUNET_OK;

  purp.size = htonl (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose));
  purp.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TEST);
  FPRINTF (stderr, "%s",  "W");
  GNUNET_CRYPTO_eddsa_key_get_public (key, &pkey);
  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < ITER; i++)
  {
    FPRINTF (stderr, "%s",  "."); fflush (stderr);
    if (GNUNET_SYSERR == GNUNET_CRYPTO_eddsa_sign (key, &purp, &sig))
    {
      FPRINTF (stderr, "%s",  "GNUNET_CRYPTO_eddsa_sign returned SYSERR\n");
      ok = GNUNET_SYSERR;
      continue;
    }
  }
  printf ("%d EdDSA sign operations %s\n", ITER,
          GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_duration (start),
						  GNUNET_YES));
  return ok;
}
#endif


static int
testCreateFromFile ()
{
  struct GNUNET_CRYPTO_EddsaPublicKey p1;
  struct GNUNET_CRYPTO_EddsaPublicKey p2;

  key = GNUNET_CRYPTO_eddsa_key_create_from_file (KEYFILE);
  GNUNET_assert (NULL != key);
  GNUNET_CRYPTO_eddsa_key_get_public (key, &p1);
  GNUNET_free (key);
  key = GNUNET_CRYPTO_eddsa_key_create_from_file (KEYFILE);
  GNUNET_assert (NULL != key);
  GNUNET_CRYPTO_eddsa_key_get_public (key, &p2);
  GNUNET_assert (0 == memcmp (&p1, &p2, sizeof (p1)));
  GNUNET_free (key);
  GNUNET_assert (0 == UNLINK (KEYFILE));
  key = GNUNET_CRYPTO_eddsa_key_create_from_file (KEYFILE);
  GNUNET_assert (NULL != key);
  GNUNET_CRYPTO_eddsa_key_get_public (key, &p2);
  GNUNET_assert (0 != memcmp (&p1, &p2, sizeof (p1)));
  GNUNET_free (key);
  return GNUNET_OK;
}


static void
perf_keygen ()
{
  struct GNUNET_TIME_Absolute start;
  struct GNUNET_CRYPTO_EddsaPrivateKey *pk;
  int i;

  FPRINTF (stderr, "%s",  "W");
  start = GNUNET_TIME_absolute_get ();
  for (i=0;i<10;i++)
  {
    fprintf (stderr, "."); fflush (stderr);
    pk = GNUNET_CRYPTO_eddsa_key_create ();
    GNUNET_free (pk);
  }
  for (;i<25;i++)
    fprintf (stderr, ".");
  fflush (stderr);
  printf ("10 EdDSA keys created in %s\n",
          GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_duration (start), GNUNET_YES));
}


int
main (int argc, char *argv[])
{
  int failure_count = 0;

  if (! gcry_check_version ("1.6.0"))
  {
    FPRINTF (stderr,
             _("libgcrypt has not the expected version (version %s is required).\n"),
             "1.6.0");
    return 0;
  }
  if (getenv ("GNUNET_GCRYPT_DEBUG"))
    gcry_control (GCRYCTL_SET_DEBUG_FLAGS, 1u , 0);
  GNUNET_log_setup ("test-crypto-eddsa", "WARNING", NULL);
  key = GNUNET_CRYPTO_eddsa_key_create ();
#if PERF
  if (GNUNET_OK != testSignPerformance ())
    failure_count++;
#endif
  if (GNUNET_OK != testSignVerify ())
    failure_count++;
  GNUNET_free (key);
  if (GNUNET_OK != testCreateFromFile ())
    failure_count++;
  GNUNET_assert (0 == UNLINK (KEYFILE));
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

/* end of test_crypto_eddsa.c */
