/*
     This file is part of GNUnet.
     Copyright (C) 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file util/test_crypto_ksk.c
 * @brief testcase for util/crypto_ksk.c
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_time_lib.h"

#define TESTSTRING "Hello World\0"
#define MAX_TESTVAL 20
#define UNIQUE_ITER 6
#define ITER 25


static int
testMultiKey (const char *word)
{
  GNUNET_HashCode in;
  struct GNUNET_CRYPTO_RsaPrivateKey *hostkey;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey1;
  int i;

  fprintf (stderr, "Testing KBlock key uniqueness (%s) ", word);
  GNUNET_CRYPTO_hash (word, strlen (word), &in);
  hostkey = GNUNET_CRYPTO_rsa_key_create_from_hash (&in);
  if (hostkey == NULL)
    {
      GNUNET_break (0);
      return GNUNET_SYSERR;
    }
  GNUNET_CRYPTO_rsa_key_get_public (hostkey, &pkey);
  /*
     for (i=0;i<sizeof(struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded);i++)
     printf("%02x", ((unsigned char*) &pkey)[i]);
     printf("\n"); */
  GNUNET_CRYPTO_rsa_key_free (hostkey);
  for (i = 0; i < UNIQUE_ITER; i++)
    {
      fprintf (stderr, ".");
      hostkey = GNUNET_CRYPTO_rsa_key_create_from_hash (&in);
      if (hostkey == NULL)
        {
          GNUNET_break (0);
          fprintf (stderr, " ERROR\n");
          return GNUNET_SYSERR;
        }
      GNUNET_CRYPTO_rsa_key_get_public (hostkey, &pkey1);
      GNUNET_CRYPTO_rsa_key_free (hostkey);
      if (0 !=
          memcmp (&pkey, &pkey1,
                  sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded)))
        {
          GNUNET_break (0);
          fprintf (stderr, " ERROR\n");
          return GNUNET_SYSERR;
        }
    }
  fprintf (stderr, " OK\n");
  return GNUNET_OK;
}


static int
testEncryptDecrypt (struct GNUNET_CRYPTO_RsaPrivateKey *hostkey)
{
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;
  struct GNUNET_CRYPTO_RsaEncryptedData target;
  char result[MAX_TESTVAL];
  int i;
  struct GNUNET_TIME_Absolute start;
  int ok;

  fprintf (stderr, "W");
  GNUNET_CRYPTO_rsa_key_get_public (hostkey, &pkey);

  ok = 0;
  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < ITER; i++)
    {
      fprintf (stderr, ".");
      if (GNUNET_SYSERR == GNUNET_CRYPTO_rsa_encrypt (TESTSTRING,
                                                      strlen (TESTSTRING) + 1,
                                                      &pkey, &target))
        {
          fprintf (stderr, "GNUNET_CRYPTO_rsa_encrypt returned SYSERR\n");
          ok++;
          continue;
        }
      if (-1 == GNUNET_CRYPTO_rsa_decrypt (hostkey,
                                           &target, result,
                                           strlen (TESTSTRING) + 1))
        {
          fprintf (stderr, "GNUNET_CRYPTO_rsa_decrypt returned SYSERR\n");
          ok++;
          continue;
        }
      if (strncmp (TESTSTRING, result, strlen (TESTSTRING)) != 0)
        {
          printf ("%s != %.*s - testEncryptDecrypt failed!\n",
                  TESTSTRING, MAX_TESTVAL, result);
          ok++;
          continue;
        }
    }
  printf ("%d RSA encrypt/decrypt operations %llums (%d failures)\n",
          ITER,
          (unsigned long long)
          GNUNET_TIME_absolute_get_duration (start).value, ok);
  if (ok == 0)
    return GNUNET_OK;
  else
    return GNUNET_SYSERR;
}

static int
testSignVerify (struct GNUNET_CRYPTO_RsaPrivateKey *hostkey)
{
  struct GNUNET_CRYPTO_RsaSignature sig;
  struct GNUNET_CRYPTO_RsaSignaturePurpose purp;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;
  int i;
  struct GNUNET_TIME_Absolute start;
  int ok = GNUNET_OK;

  fprintf (stderr, "W");
  GNUNET_CRYPTO_rsa_key_get_public (hostkey, &pkey);
  start = GNUNET_TIME_absolute_get ();
  purp.size = htonl (sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose));
  purp.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TEST);
  for (i = 0; i < ITER; i++)
    {
      fprintf (stderr, ".");
      if (GNUNET_SYSERR == GNUNET_CRYPTO_rsa_sign (hostkey, &purp, &sig))
        {
          fprintf (stderr, "GNUNET_CRYPTO_rsa_sign returned SYSERR\n");
          ok = GNUNET_SYSERR;
          continue;
        }
      if (GNUNET_SYSERR ==
          GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_TEST,
                                    &purp, &sig, &pkey))
        {
          printf ("GNUNET_CRYPTO_rsa_verify failed!\n");
          ok = GNUNET_SYSERR;
          continue;
        }
      if (GNUNET_SYSERR !=
          GNUNET_CRYPTO_rsa_verify
          (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_OWN, &purp, &sig, &pkey))
        {
          printf ("GNUNET_CRYPTO_rsa_verify failed to fail!\n");
          ok = GNUNET_SYSERR;
          continue;
        }
    }
  printf ("%d RSA sign/verify operations %llums\n",
          ITER,
          (unsigned long long)
          GNUNET_TIME_absolute_get_duration (start).value);
  return ok;
}


int
main (int argc, char *argv[])
{
  int failureCount = 0;
  GNUNET_HashCode in;
  struct GNUNET_CRYPTO_RsaPrivateKey *hostkey;

  GNUNET_log_setup ("test-crypto-ksk", "WARNING", NULL);
  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK, &in);
  hostkey = GNUNET_CRYPTO_rsa_key_create_from_hash (&in);
  if (hostkey == NULL)
    {
      printf ("\nGNUNET_CRYPTO_rsa_key_create_from_hash failed!\n");
      return 1;
    }

  if (GNUNET_OK != testMultiKey ("foo"))
    failureCount++;
  if (GNUNET_OK != testMultiKey ("bar"))
    failureCount++;
  if (GNUNET_OK != testEncryptDecrypt (hostkey))
    failureCount++;
  if (GNUNET_OK != testSignVerify (hostkey))
    failureCount++;
  GNUNET_CRYPTO_rsa_key_free (hostkey);

  if (failureCount != 0)
    {
      printf ("\n\n%d TESTS FAILED!\n\n", failureCount);
      return -1;
    }
  return 0;
}
