/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file consensus/gnunet-consensus-ibf
 * @brief tool for reconciling data with invertible bloom filters
 * @author Florian Dold
 */


#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_container_lib.h"
#include "gnunet_util_lib.h"

#include "ibf.h"

static unsigned int asize = 10;
static unsigned int bsize = 10;
static unsigned int csize = 10;
static unsigned int hash_num = 3;
static unsigned int ibf_size = 80;


static struct GNUNET_CONTAINER_MultiHashMap *set_a;
static struct GNUNET_CONTAINER_MultiHashMap *set_b;
/* common elements in a and b */
static struct GNUNET_CONTAINER_MultiHashMap *set_c;

static struct InvertibleBloomFilter *ibf_a;
static struct InvertibleBloomFilter *ibf_b;



static int
insert_iterator (void *cls,
                 const struct GNUNET_HashCode *key,
                 void *value)
{
  struct InvertibleBloomFilter *ibf = (struct InvertibleBloomFilter *) cls;
  ibf_insert (ibf, key);
  return GNUNET_YES;
}


static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_HashCode id;
  int i;
  int side;
  int res;
  struct GNUNET_TIME_Absolute start_time;
  struct GNUNET_TIME_Relative delta_time;

  set_a = GNUNET_CONTAINER_multihashmap_create (((asize == 0) ? 1 : (asize + csize)),
                                                 GNUNET_NO);
  set_b = GNUNET_CONTAINER_multihashmap_create (((bsize == 0) ? 1 : (bsize + csize)),
                                                GNUNET_NO);
  set_c = GNUNET_CONTAINER_multihashmap_create (((csize == 0) ? 1 : csize),
                                                GNUNET_NO);

  printf ("hash-num=%u, size=%u, #(A-B)=%u, #(B-A)=%u, #(A&B)=%u\n",
          hash_num, ibf_size, asize, bsize, csize);

  i = 0;
  while (i < asize)
  {
    GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK, &id);
    if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (set_a, &id))
      continue;
    GNUNET_CONTAINER_multihashmap_put (
        set_a, &id, NULL, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    i++;
  }
  i = 0;
  while (i < bsize)
  {
    GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK, &id);
    if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (set_a, &id))
      continue;
    if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (set_b, &id))
      continue;
    GNUNET_CONTAINER_multihashmap_put (
        set_b, &id, NULL, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    i++;
  }
  i = 0;
  while (i < csize)
  {
    GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_WEAK, &id);
    if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (set_a, &id))
      continue;
    if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains (set_b, &id))
      continue;
    GNUNET_CONTAINER_multihashmap_put (
        set_c, &id, NULL, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY);
    i++;
  }

  ibf_a = ibf_create (ibf_size, hash_num, 0);
  ibf_b = ibf_create (ibf_size, hash_num, 0);

  start_time = GNUNET_TIME_absolute_get ();

  GNUNET_CONTAINER_multihashmap_iterate (set_a, &insert_iterator, ibf_a);
  GNUNET_CONTAINER_multihashmap_iterate (set_b, &insert_iterator, ibf_b);
  GNUNET_CONTAINER_multihashmap_iterate (set_c, &insert_iterator, ibf_a);
  GNUNET_CONTAINER_multihashmap_iterate (set_c, &insert_iterator, ibf_b);

  delta_time = GNUNET_TIME_absolute_get_duration (start_time);

  printf ("encoded in: %s\n", GNUNET_STRINGS_relative_time_to_string (delta_time, GNUNET_NO));

  ibf_subtract (ibf_a, ibf_b);


  start_time = GNUNET_TIME_absolute_get ();

  for (;;)
  {
    res = ibf_decode (ibf_a, &side, &id);
    if (GNUNET_SYSERR == res) 
    {
      printf ("decode failed\n");
      return;
    }
    if (GNUNET_NO == res)
    {
      if ((0 == GNUNET_CONTAINER_multihashmap_size (set_b)) &&
          (0 == GNUNET_CONTAINER_multihashmap_size (set_a)))
      {
        delta_time = GNUNET_TIME_absolute_get_duration (start_time);
        printf ("decoded successfully in: %s\n", GNUNET_STRINGS_relative_time_to_string (delta_time, GNUNET_NO));
      }
      else
        printf ("decode missed elements\n");
      return;
    }

    if (side == 1)
      res = GNUNET_CONTAINER_multihashmap_remove (set_a, &id, NULL);
    if (side == -1)
      res = GNUNET_CONTAINER_multihashmap_remove (set_b, &id, NULL);
    if (GNUNET_YES != res)
    {
      printf ("decoded wrong element\n");
      return;
    }
  }
}

int
main (int argc, char **argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'A', "asize", NULL,
     gettext_noop ("number of element in set A-B"), 1,
     &GNUNET_GETOPT_set_uint, &asize},
    {'B', "bsize", NULL,
     gettext_noop ("number of element in set B-A"), 1,
     &GNUNET_GETOPT_set_uint, &bsize},
    {'C', "csize", NULL,
     gettext_noop ("number of common elements in A and B"), 1,
     &GNUNET_GETOPT_set_uint, &csize},
    {'k', "hash-num", NULL,
     gettext_noop ("hash num"), 1,
     &GNUNET_GETOPT_set_uint, &hash_num},
    {'s', "ibf-size", NULL,
     gettext_noop ("ibf size"), 1,
     &GNUNET_GETOPT_set_uint, &ibf_size},
    GNUNET_GETOPT_OPTION_END
  };
  GNUNET_PROGRAM_run2 (argc, argv, "gnunet-consensus-ibf",
                      "help",
                      options, &run, NULL, GNUNET_YES);
  return 0;
}

