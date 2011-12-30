/*
     This file is part of GNUnet.
     (C) 2003, 2004, 2005, 2006 Christian Grothoff (and other contributing authors)

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
 * @author Krista Bennett
 * @author Christian Grothoff
 * @file util/test_crypto_aes_weak.c
 * @brief AES weak key test.
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_crypto_lib.h"
#include <gcrypt.h>

#define MAX_WEAK_KEY_TRIALS 100000
#define GENERATE_WEAK_KEYS GNUNET_NO
#define WEAK_KEY_TESTSTRING "I hate weak keys."

static void
printWeakKey (struct GNUNET_CRYPTO_AesSessionKey *key)
{
  int i;

  for (i = 0; i < GNUNET_CRYPTO_AES_KEY_LENGTH; i++)
  {
    printf ("%x ", (int) (key->key[i]));
  }
}

static int
testWeakKey ()
{
  char result[100];
  char res[100];
  int size;
  struct GNUNET_CRYPTO_AesSessionKey weak_key;
  struct GNUNET_CRYPTO_AesInitializationVector INITVALUE;

  memset (&INITVALUE, 42,
          sizeof (struct GNUNET_CRYPTO_AesInitializationVector));
  /* sorry, this is not a weak key -- I don't have
   * any at the moment! */
  weak_key.key[0] = (char) (0x4c);
  weak_key.key[1] = (char) (0x31);
  weak_key.key[2] = (char) (0xc6);
  weak_key.key[3] = (char) (0x2b);
  weak_key.key[4] = (char) (0xc1);
  weak_key.key[5] = (char) (0x5f);
  weak_key.key[6] = (char) (0x4d);
  weak_key.key[7] = (char) (0x1f);
  weak_key.key[8] = (char) (0x31);
  weak_key.key[9] = (char) (0xaa);
  weak_key.key[10] = (char) (0x12);
  weak_key.key[11] = (char) (0x2e);
  weak_key.key[12] = (char) (0xb7);
  weak_key.key[13] = (char) (0x82);
  weak_key.key[14] = (char) (0xc0);
  weak_key.key[15] = (char) (0xb6);
  weak_key.key[16] = (char) (0x4d);
  weak_key.key[17] = (char) (0x1f);
  weak_key.key[18] = (char) (0x31);
  weak_key.key[19] = (char) (0xaa);
  weak_key.key[20] = (char) (0x4c);
  weak_key.key[21] = (char) (0x31);
  weak_key.key[22] = (char) (0xc6);
  weak_key.key[23] = (char) (0x2b);
  weak_key.key[24] = (char) (0xc1);
  weak_key.key[25] = (char) (0x5f);
  weak_key.key[26] = (char) (0x4d);
  weak_key.key[27] = (char) (0x1f);
  weak_key.key[28] = (char) (0x31);
  weak_key.key[29] = (char) (0xaa);
  weak_key.key[30] = (char) (0xaa);
  weak_key.key[31] = (char) (0xaa);
  /* memset(&weak_key, 0, 32); */
  weak_key.crc32 =
      htonl (GNUNET_CRYPTO_crc32_n (&weak_key, GNUNET_CRYPTO_AES_KEY_LENGTH));

  size =
      GNUNET_CRYPTO_aes_encrypt (WEAK_KEY_TESTSTRING,
                                 strlen (WEAK_KEY_TESTSTRING) + 1, &weak_key,
                                 &INITVALUE, result);

  if (size == -1)
  {
    GNUNET_break (0);
    return 1;
  }

  size = GNUNET_CRYPTO_aes_decrypt (result, size, &weak_key, &INITVALUE, res);

  if ((strlen (WEAK_KEY_TESTSTRING) + 1) != size)
  {
    GNUNET_break (0);
    return 1;
  }
  if (0 != strcmp (res, WEAK_KEY_TESTSTRING))
  {
    GNUNET_break (0);
    return 1;
  }
  else
    return 0;
}

static int
getWeakKeys ()
{
  struct GNUNET_CRYPTO_AesSessionKey sessionkey;
  int number_of_weak_keys = 0;
  int number_of_runs;

  gcry_cipher_hd_t handle;
  int rc;

  for (number_of_runs = 0; number_of_runs < MAX_WEAK_KEY_TRIALS;
       number_of_runs++)
  {

    if (number_of_runs % 1000 == 0)
      FPRINTF (stderr, "%s",  ".");
    /*printf("Got to run number %d.\n", number_of_runs); */
    GNUNET_CRYPTO_aes_create_session_key (&sessionkey);

    rc = gcry_cipher_open (&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CFB,
                           0);

    if (rc)
    {
      printf ("testweakkey: gcry_cipher_open failed on trial %d. %s\n",
              number_of_runs, gcry_strerror (rc));
      continue;
    }

    rc = gcry_cipher_setkey (handle, &sessionkey, GNUNET_CRYPTO_AES_KEY_LENGTH);

    if ((char) rc == GPG_ERR_WEAK_KEY)
    {
      printf ("\nWeak key (in hex): ");
      printWeakKey (&sessionkey);
      printf ("\n");
      number_of_weak_keys++;
    }
    else if (rc)
    {
      printf ("\nUnexpected error generating keys. Error is %s\n",
              gcry_strerror (rc));
    }

    gcry_cipher_close (handle);

  }

  return number_of_weak_keys;
}

int
main (int argc, char *argv[])
{
  int weak_keys;

  GNUNET_log_setup ("test-crypto-aes-weak", "WARNING", NULL);
  GNUNET_CRYPTO_random_disable_entropy_gathering ();
  if (GENERATE_WEAK_KEYS)
  {
    weak_keys = getWeakKeys ();

    if (weak_keys == 0)
    {
      printf ("\nNo weak keys found in %d runs.\n", MAX_WEAK_KEY_TRIALS);
    }
    else
    {
      printf ("\n%d weak keys found in %d runs.\n", weak_keys,
              MAX_WEAK_KEY_TRIALS);
    }
  }

  if (testWeakKey () != 0)
    return -1;
  return 0;
}

/* end of weakkeytest.c */
