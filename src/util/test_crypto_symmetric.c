/*
     This file is part of GNUnet.
     Copyright (C) 2002, 2003, 2004, 2006 Christian Grothoff (and other contributing authors)

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
 * @author Christian Grothoff
 * @file util/test_crypto_symmetric.c
 * @brief test for AES ciphers
 */
#include "platform.h"
#include "gnunet_util_lib.h"

#define TESTSTRING "Hello World!"
#define INITVALUE "InitializationVectorValueinitializationvectorvalue"

static int
testSymcipher ()
{
  struct GNUNET_CRYPTO_SymmetricSessionKey key;
  char result[100];
  int size;
  char res[100];

  GNUNET_CRYPTO_symmetric_create_session_key (&key);
  size =
      GNUNET_CRYPTO_symmetric_encrypt (TESTSTRING, strlen (TESTSTRING) + 1, &key,
                                 (const struct
                                  GNUNET_CRYPTO_SymmetricInitializationVector *)
                                 INITVALUE, result);
  if (size == -1)
  {
    printf ("symciphertest failed: encryptBlock returned %d\n", size);
    return 1;
  }
  size =
      GNUNET_CRYPTO_symmetric_decrypt (result, size, &key,
                                 (const struct
                                  GNUNET_CRYPTO_SymmetricInitializationVector *)
                                 INITVALUE, res);
  if (strlen (TESTSTRING) + 1 != size)
  {
    printf ("symciphertest failed: decryptBlock returned %d\n", size);
    return 1;
  }
  if (0 != strcmp (res, TESTSTRING))
  {
    printf ("symciphertest failed: %s != %s\n", res, TESTSTRING);
    return 1;
  }
  else
    return 0;
}


static int
verifyCrypto ()
{
  struct GNUNET_CRYPTO_SymmetricSessionKey key;
  char result[GNUNET_CRYPTO_AES_KEY_LENGTH];
  char *res;
  int ret;

  unsigned char plain[] =
  {
    29, 128, 192, 253, 74, 171, 38, 187, 84, 219, 76, 76, 209, 118, 33, 249,
    172, 124, 96, 9, 157, 110, 8, 215, 200, 63, 69, 230, 157, 104, 247, 164
  };
  unsigned char raw_key_aes[] =
  {
    106, 74, 209, 88, 145, 55, 189, 135, 125, 180, 225, 108, 183, 54, 25,
    169, 129, 188, 131, 75, 227, 245, 105, 10, 225, 15, 115, 159, 148, 184,
    34, 191
  };
  unsigned char raw_key_twofish[] =
  {
    145, 55, 189, 135, 125, 180, 225, 108, 183, 54, 25,
    169, 129, 188, 131, 75, 227, 245, 105, 10, 225, 15, 115, 159, 148, 184,
    34, 191, 106, 74, 209, 88
  };
  unsigned char encrresult[] =
  {
    155, 88, 106, 174, 124, 172, 47, 149, 85, 15, 208, 176, 65, 124, 155,
    74, 215, 25, 177, 231, 162, 109, 165, 4, 133, 165, 93, 44, 213, 77,
    206, 204, 1
  };

  res = NULL;
  ret = 0;

  memcpy (key.aes_key, raw_key_aes, GNUNET_CRYPTO_AES_KEY_LENGTH);
  memcpy (key.twofish_key, raw_key_twofish, GNUNET_CRYPTO_AES_KEY_LENGTH);
  if (GNUNET_CRYPTO_AES_KEY_LENGTH !=
      GNUNET_CRYPTO_symmetric_encrypt (plain, GNUNET_CRYPTO_AES_KEY_LENGTH, &key,
                                       (const struct
                                        GNUNET_CRYPTO_SymmetricInitializationVector *)
                                       "testtesttesttesttesttesttesttest",
                                       result))
  {
    printf ("Wrong return value from encrypt block.\n");
    ret = 1;
    goto error;
  }

  if (0 != memcmp (encrresult, result, GNUNET_CRYPTO_AES_KEY_LENGTH))
  {
    int i;
    printf ("Encrypted result wrong.\n");
    for (i=0;i<GNUNET_CRYPTO_AES_KEY_LENGTH;i++)
      printf ("%u, ", (uint8_t) result[i]);
    ret = 1;
    goto error;
  }

  res = GNUNET_malloc (GNUNET_CRYPTO_AES_KEY_LENGTH);
  if (GNUNET_CRYPTO_AES_KEY_LENGTH !=
      GNUNET_CRYPTO_symmetric_decrypt (result, GNUNET_CRYPTO_AES_KEY_LENGTH, &key,
                                 (const struct
                                  GNUNET_CRYPTO_SymmetricInitializationVector *)
                                 "testtesttesttesttesttesttesttest", res))
  {
    printf ("Wrong return value from decrypt block.\n");
    ret = 1;
    goto error;
  }
  if (0 != memcmp (res, plain, GNUNET_CRYPTO_AES_KEY_LENGTH))
  {
    printf ("Decrypted result does not match input.\n");
    ret = 1;
  }
error:
  GNUNET_free_non_null (res);
  return ret;
}


int
main (int argc, char *argv[])
{
  int failureCount = 0;

  GNUNET_log_setup ("test-crypto-aes", "WARNING", NULL);
  GNUNET_assert (strlen (INITVALUE) >
                 sizeof (struct GNUNET_CRYPTO_SymmetricInitializationVector));
  failureCount += testSymcipher ();
  failureCount += verifyCrypto ();

  if (failureCount != 0)
  {
    printf ("%d TESTS FAILED!\n", failureCount);
    return -1;
  }
  return 0;
}

/* end of test_crypto_aes.c */
