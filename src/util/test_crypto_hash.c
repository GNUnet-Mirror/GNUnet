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
 * @author Christian Grothoff
 * @file util/test_crypto_hash.c
 * @brief Test for crypto_hash.c
 */
#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_crypto_lib.h"
#include "gnunet_scheduler_lib.h"

static char block[65536];

#define FILENAME "testblock.dat"

static int
test (int number)
{
  GNUNET_HashCode h1;
  GNUNET_HashCode h2;
  struct GNUNET_CRYPTO_HashAsciiEncoded enc;

  memset (&h1, number, sizeof (GNUNET_HashCode));
  GNUNET_CRYPTO_hash_to_enc (&h1, &enc);
  if (GNUNET_OK != GNUNET_CRYPTO_hash_from_string ((char *) &enc, &h2))
  {
    printf ("enc2hash failed!\n");
    return 1;
  }
  if (0 != memcmp (&h1, &h2, sizeof (GNUNET_HashCode)))
    return 1;
  return 0;
}

static int
testEncoding ()
{
  int i;

  for (i = 0; i < 255; i++)
    if (0 != test (i))
      return 1;
  return 0;
}

static int
testArithmetic ()
{
  static struct GNUNET_CRYPTO_AesSessionKey zskey;
  static struct GNUNET_CRYPTO_AesInitializationVector ziv;
  GNUNET_HashCode h1;
  GNUNET_HashCode h2;
  GNUNET_HashCode d;
  GNUNET_HashCode s;
  struct GNUNET_CRYPTO_AesSessionKey skey;
  struct GNUNET_CRYPTO_AesInitializationVector iv;

  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK, &h1);
  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK, &h2);
  if (GNUNET_CRYPTO_hash_distance_u32 (&h1, &h2) !=
      GNUNET_CRYPTO_hash_distance_u32 (&h2, &h1))
    return 1;
  GNUNET_CRYPTO_hash_difference (&h1, &h2, &d);
  GNUNET_CRYPTO_hash_sum (&h1, &d, &s);
  if (0 != GNUNET_CRYPTO_hash_cmp (&s, &h2))
    return 1;
  GNUNET_CRYPTO_hash_xor (&h1, &h2, &d);
  GNUNET_CRYPTO_hash_xor (&h1, &d, &s);
  if (0 != GNUNET_CRYPTO_hash_cmp (&s, &h2))
    return 1;
  if (0 != GNUNET_CRYPTO_hash_xorcmp (&s, &h2, &h1))
    return 1;
  if (-1 != GNUNET_CRYPTO_hash_xorcmp (&h1, &h2, &h1))
    return 1;
  if (1 != GNUNET_CRYPTO_hash_xorcmp (&h1, &h2, &h2))
    return 1;
  memset (&d, 0xF0, sizeof (d));
  if (0 != GNUNET_CRYPTO_hash_get_bit (&d, 3))
    return 1;
  if (1 != GNUNET_CRYPTO_hash_get_bit (&d, 6))
    return 1;
  memset (&d, 0, sizeof (d));
  GNUNET_CRYPTO_hash_to_aes_key (&d, &skey, &iv);
  if ((0 != memcmp (&skey, &zskey, sizeof (skey) - sizeof (unsigned int))) ||
      (0 != memcmp (&iv, &ziv, sizeof (iv))))
    return 1;
  return 0;
}

static void
finished_task (void *cls, const GNUNET_HashCode * res)
{
  int *ret = cls;
  GNUNET_HashCode want;

  GNUNET_CRYPTO_hash (block, sizeof (block), &want);
  if (0 != memcmp (res, &want, sizeof (want)))
    *ret = 2;
  else
    *ret = 0;
}


static void
file_hasher (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_assert (NULL !=
                 GNUNET_CRYPTO_hash_file (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                          FILENAME, 1024, &finished_task, cls));
}


static int
testFileHash ()
{
  int ret;
  FILE *f;

  memset (block, 42, sizeof (block) / 2);
  memset (&block[sizeof (block) / 2], 43, sizeof (block) / 2);
  GNUNET_assert (NULL != (f = FOPEN (FILENAME, "w+")));
  GNUNET_break (sizeof (block) == fwrite (block, 1, sizeof (block), f));
  GNUNET_break (0 == FCLOSE (f));
  ret = 1;
  GNUNET_SCHEDULER_run (&file_hasher, &ret);
  GNUNET_break (0 == UNLINK (FILENAME));
  return ret;
}


int
main (int argc, char *argv[])
{
  int failureCount = 0;
  int i;

  GNUNET_log_setup ("test-crypto-hash", "WARNING", NULL);
  for (i = 0; i < 10; i++)
    failureCount += testEncoding ();
  failureCount += testArithmetic ();
  failureCount += testFileHash ();
  if (failureCount != 0)
    return 1;
  return 0;
}

/* end of hashingtest.c */
