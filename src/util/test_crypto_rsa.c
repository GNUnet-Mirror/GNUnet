/*
     This file is part of GNUnet.
     (C) 2002, 2003, 2004, 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file util/test_crypto_rsa.c
 * @brief testcase for RSA public key crypto
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"

#define TESTSTRING "Hello World\0"
#define MAX_TESTVAL sizeof(struct GNUNET_CRYPTO_AesSessionKey)
#define ITER 25
#define KEYFILE "/tmp/test-gnunet-crypto-rsa.key"

#define PERF GNUNET_YES

static struct GNUNET_CRYPTO_RsaPrivateKey *key;


static int
testEncryptDecrypt ()
{
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;
  struct GNUNET_CRYPTO_RsaEncryptedData target;
  char result[MAX_TESTVAL];
  int i;
  struct GNUNET_TIME_Absolute start;
  int ok;

  FPRINTF (stderr, "%s",  "W");
  GNUNET_CRYPTO_rsa_key_get_public (key, &pkey);
  ok = 0;
  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < ITER; i++)
  {
    FPRINTF (stderr, "%s",  ".");
    if (GNUNET_SYSERR ==
        GNUNET_CRYPTO_rsa_encrypt (TESTSTRING, strlen (TESTSTRING) + 1, &pkey,
                                   &target))
    {
      FPRINTF (stderr, "%s",  "GNUNET_CRYPTO_rsa_encrypt returned SYSERR\n");
      ok++;
      continue;
    }
    if (-1 ==
        GNUNET_CRYPTO_rsa_decrypt (key, &target, result,
                                   strlen (TESTSTRING) + 1))
    {
      FPRINTF (stderr, "%s",  "GNUNET_CRYPTO_rsa_decrypt returned SYSERR\n");
      ok++;
      continue;

    }
    if (strncmp (TESTSTRING, result, strlen (TESTSTRING)) != 0)
    {
      printf ("%s != %.*s - testEncryptDecrypt failed!\n", TESTSTRING,
              (int) MAX_TESTVAL, result);
      ok++;
      continue;
    }
  }
  printf ("%d RSA encrypt/decrypt operations %s (%d failures)\n", 
	  ITER,
          GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_duration (start), GNUNET_YES), 
	  ok);
  if (ok == 0)
    return GNUNET_OK;
  return GNUNET_SYSERR;
}


#if PERF
static int
testEncryptPerformance ()
{
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;
  struct GNUNET_CRYPTO_RsaEncryptedData target;
  int i;
  struct GNUNET_TIME_Absolute start;
  int ok;

  FPRINTF (stderr, "%s",  "W");
  GNUNET_CRYPTO_rsa_key_get_public (key, &pkey);
  ok = 0;
  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < ITER; i++)
  {
    FPRINTF (stderr, "%s",  ".");
    if (GNUNET_SYSERR ==
        GNUNET_CRYPTO_rsa_encrypt (TESTSTRING, strlen (TESTSTRING) + 1, &pkey,
                                   &target))
    {
      FPRINTF (stderr, "%s",  "GNUNET_CRYPTO_rsa_encrypt returned SYSERR\n");
      ok++;
      continue;
    }
  }
  printf ("%d RSA encrypt operations %llu ms (%d failures)\n", ITER,
          (unsigned long long)
          GNUNET_TIME_absolute_get_duration (start).rel_value, ok);
  if (ok != 0)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}
#endif

static int
testEncryptDecryptSK ()
{
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;
  struct GNUNET_CRYPTO_RsaEncryptedData target;
  struct GNUNET_CRYPTO_AesSessionKey insk;
  struct GNUNET_CRYPTO_AesSessionKey outsk;
  int i;
  struct GNUNET_TIME_Absolute start;
  int ok;

  FPRINTF (stderr, "%s",  "W");
  GNUNET_CRYPTO_rsa_key_get_public (key, &pkey);
  ok = 0;
  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < ITER; i++)
  {
    FPRINTF (stderr, "%s",  ".");
    GNUNET_CRYPTO_aes_create_session_key (&insk);
    if (GNUNET_SYSERR ==
        GNUNET_CRYPTO_rsa_encrypt (&insk,
                                   sizeof (struct GNUNET_CRYPTO_AesSessionKey),
                                   &pkey, &target))
    {
      FPRINTF (stderr, "%s",  "GNUNET_CRYPTO_rsa_encrypt returned SYSERR\n");
      ok++;
      continue;
    }
    if (-1 ==
        GNUNET_CRYPTO_rsa_decrypt (key, &target, &outsk,
                                   sizeof (struct GNUNET_CRYPTO_AesSessionKey)))
    {
      FPRINTF (stderr, "%s",  "GNUNET_CRYPTO_rsa_decrypt returned SYSERR\n");
      ok++;
      continue;
    }
    if (0 !=
        memcmp (&insk, &outsk, sizeof (struct GNUNET_CRYPTO_AesSessionKey)))
    {
      printf ("testEncryptDecryptSK failed!\n");
      ok++;
      continue;
    }
  }
  printf ("%d RSA encrypt/decrypt SK operations %s (%d failures)\n", 
	  ITER,
          GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_duration (start), GNUNET_YES), 
	  ok);
  if (ok != 0)
    return GNUNET_SYSERR;
  return GNUNET_OK;
}


static int
testSignVerify ()
{
  struct GNUNET_CRYPTO_RsaSignature sig;
  struct GNUNET_CRYPTO_RsaSignaturePurpose purp;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;
  int i;
  struct GNUNET_TIME_Absolute start;
  int ok = GNUNET_OK;

  FPRINTF (stderr, "%s",  "W");
  GNUNET_CRYPTO_rsa_key_get_public (key, &pkey);
  start = GNUNET_TIME_absolute_get ();
  purp.size = htonl (sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose));
  purp.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TEST);

  for (i = 0; i < ITER; i++)
  {
    FPRINTF (stderr, "%s",  ".");
    if (GNUNET_SYSERR == GNUNET_CRYPTO_rsa_sign (key, &purp, &sig))
    {
      FPRINTF (stderr, "%s",  "GNUNET_CRYPTO_rsa_sign returned SYSERR\n");
      ok = GNUNET_SYSERR;
      continue;
    }
    if (GNUNET_SYSERR ==
        GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_TEST, &purp, &sig,
                                  &pkey))
    {
      printf ("GNUNET_CRYPTO_rsa_verify failed!\n");
      ok = GNUNET_SYSERR;
      continue;
    }
    if (GNUNET_SYSERR !=
        GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_TRANSPORT_PONG_OWN,
                                  &purp, &sig, &pkey))
    {
      printf ("GNUNET_CRYPTO_rsa_verify failed to fail!\n");
      ok = GNUNET_SYSERR;
      continue;
    }
  }
  printf ("%d RSA sign/verify operations %s\n", ITER,
          GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_duration (start), GNUNET_YES));
  return ok;
}


#if PERF
static int
testSignPerformance ()
{
  struct GNUNET_CRYPTO_RsaSignaturePurpose purp;
  struct GNUNET_CRYPTO_RsaSignature sig;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pkey;
  int i;
  struct GNUNET_TIME_Absolute start;
  int ok = GNUNET_OK;

  purp.size = htonl (sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose));
  purp.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_TEST);
  FPRINTF (stderr, "%s",  "W");
  GNUNET_CRYPTO_rsa_key_get_public (key, &pkey);
  start = GNUNET_TIME_absolute_get ();
  for (i = 0; i < ITER; i++)
  {
    FPRINTF (stderr, "%s",  ".");
    if (GNUNET_SYSERR == GNUNET_CRYPTO_rsa_sign (key, &purp, &sig))
    {
      FPRINTF (stderr, "%s",  "GNUNET_CRYPTO_rsa_sign returned SYSERR\n");
      ok = GNUNET_SYSERR;
      continue;
    }
  }
  printf ("%d RSA sign operations %llu ms\n", ITER,
          (unsigned long long)
          GNUNET_TIME_absolute_get_duration (start).rel_value);
  return ok;
}
#endif


static int
testCreateFromFile ()
{
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded p1;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded p2;

  key = GNUNET_CRYPTO_rsa_key_create_from_file (KEYFILE);
  GNUNET_assert (NULL != key);
  GNUNET_CRYPTO_rsa_key_get_public (key, &p1);
  GNUNET_CRYPTO_rsa_key_free (key);
  key = GNUNET_CRYPTO_rsa_key_create_from_file (KEYFILE);
  GNUNET_assert (NULL != key);
  GNUNET_CRYPTO_rsa_key_get_public (key, &p2);
  GNUNET_assert (0 == memcmp (&p1, &p2, sizeof (p1)));
  GNUNET_CRYPTO_rsa_key_free (key);
  GNUNET_assert (0 == UNLINK (KEYFILE));
  key = GNUNET_CRYPTO_rsa_key_create_from_file (KEYFILE);
  GNUNET_assert (NULL != key);
  GNUNET_CRYPTO_rsa_key_get_public (key, &p2);
  GNUNET_assert (0 != memcmp (&p1, &p2, sizeof (p1)));
  return GNUNET_OK;
}


static void
key_cont (void *cls,
	  struct GNUNET_CRYPTO_RsaPrivateKey *pk,
	  const char *emsg)
{
  const char *txt = cls;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pub1;
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded pub2;

  GNUNET_assert (0 == strcmp ("ok", txt));
  GNUNET_CRYPTO_rsa_key_get_public (pk, &pub1);
  GNUNET_CRYPTO_rsa_key_get_public (key, &pub2);
  GNUNET_assert (0 == memcmp (&pub1, &pub2, 
			      sizeof (pub1)));
  GNUNET_CRYPTO_rsa_key_free (pk);
}


static void
test_async_creation (void *cls,
		     const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_CRYPTO_RsaKeyGenerationContext *gc;

  gc = GNUNET_CRYPTO_rsa_key_create_start (KEYFILE,
					   &key_cont, 
					   (void*) "bug");
  GNUNET_CRYPTO_rsa_key_create_stop (gc);
  gc = GNUNET_CRYPTO_rsa_key_create_start (KEYFILE,
					   &key_cont, 
					   (void*) "ok");
}


int
main (int argc, char *argv[])
{
  int failureCount = 0;

  GNUNET_log_setup ("test-crypto-rsa", "WARNING", NULL);
  GNUNET_CRYPTO_random_disable_entropy_gathering ();
  if (GNUNET_OK != testCreateFromFile ())
    failureCount++;
  GNUNET_SCHEDULER_run (&test_async_creation, NULL);
#if PERF
  if (GNUNET_OK != testEncryptPerformance ())
    failureCount++;
  if (GNUNET_OK != testSignPerformance ())
    failureCount++;
#endif
  if (GNUNET_OK != testEncryptDecryptSK ())
    failureCount++;
  if (GNUNET_OK != testEncryptDecrypt ())
    failureCount++;
  if (GNUNET_OK != testSignVerify ())
    failureCount++;
  GNUNET_CRYPTO_rsa_key_free (key);
  GNUNET_assert (0 == UNLINK (KEYFILE));

  if (failureCount != 0)
  {
    printf ("\n\n%d TESTS FAILED!\n\n", failureCount);
    return -1;
  }
  return 0;
}                               /* end of main */
