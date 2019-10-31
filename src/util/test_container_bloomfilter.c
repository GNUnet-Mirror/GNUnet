/*
     This file is part of GNUnet.
     Copyright (C) 2004, 2009 GNUnet e.V.

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
 * @file util/test_container_bloomfilter.c
 * @brief Testcase for the bloomfilter.
 * @author Christian Grothoff
 * @author Igor Wronsky
 */

#include "platform.h"
#include "gnunet_util_lib.h"

#define K 4
#define SIZE 65536
#define TESTFILE "/tmp/bloomtest.dat"

/**
 * Generate a random hashcode.
 */
static void
nextHC (struct GNUNET_HashCode *hc)
{
  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK, hc);
}


static int
add_iterator (void *cls, struct GNUNET_HashCode *next)
{
  int *ret = cls;
  struct GNUNET_HashCode pos;

  if (0 == (*ret)--)
    return GNUNET_NO;
  nextHC (&pos);
  *next = pos;
  return GNUNET_YES;
}


int
main (int argc, char *argv[])
{
  struct GNUNET_CONTAINER_BloomFilter *bf;
  struct GNUNET_CONTAINER_BloomFilter *bfi;
  struct GNUNET_HashCode tmp;
  int i;
  int ok1;
  int ok2;
  int falseok;
  char buf[SIZE];
  struct stat sbuf;

  GNUNET_log_setup ("test-container-bloomfilter", "WARNING", NULL);
  GNUNET_CRYPTO_seed_weak_random (1);
  if (0 == stat (TESTFILE, &sbuf))
    if (0 != unlink (TESTFILE))
      GNUNET_log_strerror_file (GNUNET_ERROR_TYPE_ERROR, "unlink", TESTFILE);
  bf = GNUNET_CONTAINER_bloomfilter_load (TESTFILE, SIZE, K);

  for (i = 0; i < 200; i++)
  {
    nextHC (&tmp);
    GNUNET_CONTAINER_bloomfilter_add (bf, &tmp);
  }
  GNUNET_CRYPTO_seed_weak_random (1);
  ok1 = 0;
  for (i = 0; i < 200; i++)
  {
    nextHC (&tmp);
    if (GNUNET_CONTAINER_bloomfilter_test (bf, &tmp) == GNUNET_YES)
      ok1++;
  }
  if (ok1 != 200)
  {
    printf ("Got %d elements out of"
            "200 expected after insertion.\n",
            ok1);
    GNUNET_CONTAINER_bloomfilter_free (bf);
    return -1;
  }
  if (GNUNET_OK != GNUNET_CONTAINER_bloomfilter_get_raw_data (bf, buf, SIZE))
  {
    GNUNET_CONTAINER_bloomfilter_free (bf);
    return -1;
  }

  GNUNET_CONTAINER_bloomfilter_free (bf);

  bf = GNUNET_CONTAINER_bloomfilter_load (TESTFILE, SIZE, K);
  GNUNET_assert (bf != NULL);
  bfi = GNUNET_CONTAINER_bloomfilter_init (buf, SIZE, K);
  GNUNET_assert (bfi != NULL);

  GNUNET_CRYPTO_seed_weak_random (1);
  ok1 = 0;
  ok2 = 0;
  for (i = 0; i < 200; i++)
  {
    nextHC (&tmp);
    if (GNUNET_CONTAINER_bloomfilter_test (bf, &tmp) == GNUNET_YES)
      ok1++;
    if (GNUNET_CONTAINER_bloomfilter_test (bfi, &tmp) == GNUNET_YES)
      ok2++;
  }
  if (ok1 != 200)
  {
    printf ("Got %d elements out of 200 "
            "expected after reloading.\n",
            ok1);
    GNUNET_CONTAINER_bloomfilter_free (bf);
    GNUNET_CONTAINER_bloomfilter_free (bfi);
    return -1;
  }

  if (ok2 != 200)
  {
    printf ("Got %d elements out of 200 "
            "expected after initialization.\n",
            ok2);
    GNUNET_CONTAINER_bloomfilter_free (bf);
    GNUNET_CONTAINER_bloomfilter_free (bfi);
    return -1;
  }

  GNUNET_CRYPTO_seed_weak_random (1);
  for (i = 0; i < 100; i++)
  {
    nextHC (&tmp);
    GNUNET_CONTAINER_bloomfilter_remove (bf, &tmp);
    GNUNET_CONTAINER_bloomfilter_remove (bfi, &tmp);
  }

  GNUNET_CRYPTO_seed_weak_random (1);

  ok1 = 0;
  ok2 = 0;
  for (i = 0; i < 200; i++)
  {
    nextHC (&tmp);
    if (GNUNET_CONTAINER_bloomfilter_test (bf, &tmp) == GNUNET_YES)
      ok1++;
    if (GNUNET_CONTAINER_bloomfilter_test (bfi, &tmp) == GNUNET_YES)
      ok2++;
  }

  if (ok1 != 100)
  {
    printf ("Expected 100 elements in loaded filter"
            " after adding 200 and deleting 100, got %d\n",
            ok1);
    GNUNET_CONTAINER_bloomfilter_free (bf);
    GNUNET_CONTAINER_bloomfilter_free (bfi);
    return -1;
  }
  if (ok2 != 200)
  {
    printf ("Expected 200 elements in initialized filter"
            " after adding 200 and deleting 100 "
            "(which should do nothing for a filter not backed by a file), got %d\n",
            ok2);
    GNUNET_CONTAINER_bloomfilter_free (bf);
    GNUNET_CONTAINER_bloomfilter_free (bfi);
    return -1;
  }

  GNUNET_CRYPTO_seed_weak_random (3);

  GNUNET_CONTAINER_bloomfilter_clear (bf);
  falseok = 0;
  for (i = 0; i < 1000; i++)
  {
    nextHC (&tmp);
    if (GNUNET_CONTAINER_bloomfilter_test (bf, &tmp) == GNUNET_YES)
      falseok++;
  }
  if (falseok > 0)
  {
    GNUNET_CONTAINER_bloomfilter_free (bf);
    GNUNET_CONTAINER_bloomfilter_free (bfi);
    return -1;
  }

  if (GNUNET_OK != GNUNET_CONTAINER_bloomfilter_or (bf, buf, SIZE))
  {
    GNUNET_CONTAINER_bloomfilter_free (bf);
    GNUNET_CONTAINER_bloomfilter_free (bfi);
    return -1;
  }

  GNUNET_CRYPTO_seed_weak_random (2);
  i = 20;
  GNUNET_CONTAINER_bloomfilter_resize (bfi, &add_iterator, &i, SIZE * 2, K);

  GNUNET_CRYPTO_seed_weak_random (2);
  i = 20;
  GNUNET_CONTAINER_bloomfilter_resize (bf, &add_iterator, &i, SIZE * 2, K);
  GNUNET_CRYPTO_seed_weak_random (2);

  ok1 = 0;
  ok2 = 0;
  for (i = 0; i < 20; i++)
  {
    nextHC (&tmp);
    if (GNUNET_CONTAINER_bloomfilter_test (bf, &tmp) == GNUNET_YES)
      ok1++;
    if (GNUNET_CONTAINER_bloomfilter_test (bfi, &tmp) == GNUNET_YES)
      ok2++;
  }

  if (ok1 != 20)
  {
    printf ("Expected 20 elements in resized file-backed filter"
            " after adding 20, got %d\n",
            ok1);
    GNUNET_CONTAINER_bloomfilter_free (bf);
    GNUNET_CONTAINER_bloomfilter_free (bfi);
    return -1;
  }
  if (ok2 != 20)
  {
    printf ("Expected 20 elements in resized filter"
            " after adding 20, got %d\n",
            ok2);
    GNUNET_CONTAINER_bloomfilter_free (bf);
    GNUNET_CONTAINER_bloomfilter_free (bfi);
    return -1;
  }


  GNUNET_CONTAINER_bloomfilter_free (bf);
  GNUNET_CONTAINER_bloomfilter_free (bfi);

  GNUNET_break (0 == unlink (TESTFILE));
  return 0;
}
