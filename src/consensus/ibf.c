/*
      This file is part of GNUnet
      (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file consensus/ibf.c
 * @brief implementation of the invertible bloom filter
 * @author Florian Dold
 */

#include "platform.h"
#include "gnunet_common.h"
#include "ibf.h"


struct PureCells
{
  int index;
  struct PureCells *next;
  struct PureCells *prev;
};

struct InvertibleBloomFilter
{
  /**
   * How many cells does this IBF have?
   */
  int size;

  /**
   * In how many cells do we hash one element?
   * Usually 4 or 3.
   */
  int hash_num;

  /**
   * Salt for mingling hashes
   */
  int salt;

  /**
   * How many times has a bucket been hit?
   * Can be negative, as a result of IBF subtraction.
   */
  int8_t *count;

  /**
   * xor sums of the elements' hash codes, used to identify the elements.
   */
  GNUNET_HashCode *id_sum;

  /**
   * xor sums of the "hash of the hash".
   */
  GNUNET_HashCode *hash_sum;

  struct PureCells *pure_head;
  struct PureCells *pure_tail;

  /**
   * GNUNET_YES: fresh list is deprecated
   * GNUNET_NO: fresh list is up to date
   */
  int pure_fresh;
};


/**
 * Create an invertible bloom filter.
 */
struct InvertibleBloomFilter *
ibf_create(int size, int hash_num)
{
  struct InvertibleBloomFilter *ibf;

  ibf = GNUNET_malloc (sizeof (struct InvertibleBloomFilter));
  ibf->count = GNUNET_malloc (size * sizeof uint8_t);
  ibf->id_sum = GNUNET_malloc (size * sizeof (struct GNUNET_HashCode));
  ibf->hash_sum = GNUNET_malloc (size * sizeof (struct GNUNET_HashCode));
  ibf->size = size;
  ibf->hash_num = hash_num;
}


/**
 * Insert an element into an IBF.
 */
void
ibf_insert (struct InvertibleBloomFilter *ibf, struct GNUNET_HashCode *id)
{
  struct GNUNET_HashCode key;
  struct GNUNET_HashCode id_hash;
  int i;

  key = *id;
  GNUNET_hash (id, sizeof (struct GNUNET_HashCode), &id_hash);

  for (i = 0; i < ibf->hash_num; i++)
  {
    int bucket;
    int j;
    if ((i != 0) && (i % 16) == 0)
    {
      GNUNET_hash (&key, sizeof (struct GNUNET_HashCode), &key);
    }
    bucket = hash.bits[i%16] % ibf->size;

    /* count<0 can happen after ibf subtraction, but then no insert should be done */
    GNUNET_assert (ibf->count[bucket] >= 0);

    ibf->count[bucket]++;

    for (j=0; j < 16; j++)
    {
      ibf->id_sum.bits[j] ^= &id;
      ibf->hash_sum.bits[j] ^= &id_hash;
    }

  }
}


/**
 * Update the linked list of pure cells, if not fresh anymore
 */
void
update_pure (struct InvertibleBloomFilter *ibf)
{
  if (GNUNET_YES == ibf->pure_fresh)
  {
    return;
  }

  ibf->pure_fresh = GNUNET_YES;
}

/**
 * Decode and remove an element from the IBF, if possible.
 *
 * @param ibf the invertible bloom filter to decode
 * @param ret_id the hash code of the decoded element, if successful
 * @param side sign of the cell's count where the decoded element came from.
 *             A negative sign indicates that the element was recovered resides in an IBF
 *             that was previously subtracted from.
 * @return GNUNET_YES if decoding an element was successful, GNUNET_NO if the IBF is empty,
 *         GNUNET_SYSERR if the decoding has faile
 */
int
ibf_decode (struct InvertibleBloomFilter *ibf, int *ret_side, struct GNUNET_HashCode *ret_id)
{
  struct GNUNET_HashCode hash;
  struct PureCells *pure;
  int count;

  GNUNET_assert (NULL != ibf);
  GNUNET_assert (NULL != red_id);
  GNUNET_assert (NULL != side);

  update_pure (ibf);

  pure = ibf->pure_head;
  ibf->pure_head = pure->next;

  if (NULL == pure)
  {
    int i;
    for (i = 0; i < ibf->size; i++)
    {
      int j;
      if (0 != ibf->count[i])
        return GNUNET_SYSERR;
      for (j = 0; j < 16; ++j)
        if ((0 != ibf->hash_sum[i].bits[j]) || (0 != ibf->id_sum[i].bits[j]))
          return GNUNET_SYSERR;
      return GNUNET_NO;
    }
  }

  GNUNET_CRYPTO_hash (ibf->id_sum[pure->idx], sizeof (struct GNUNET_HashCode), &hash);

  if (0 == memcmp (&hash, ibf->hash_sum[pure->idx]))
  {
    struct GNUNET_HashCode key;
    int i;

    *ret_side = ibf->count[pure->index];
    *ret_id = ibf->id_sum[pure->index];

    key = *ibf->id_sum[pure->index];

    /* delete the item from all buckets */
    for (i = 0; i < ibf->hash_num; i++)
    {
      int bucket;
      int j;
      if ((i != 0) && (i % 16) == 0)
      {
        GNUNET_hash (&key, sizeof (struct GNUNET_HashCode), &key);
      }
      bucket = hash.bits[i%16] % ibf->size;

      ibf->count[bucket] -= count;

      for (j=0; j < 16; j++)
      {
        ibf->id_sum.bits[j] ^= &id;
        ibf->hash_sum.bits[j] ^= &id_hash;
      }
      return GNUNET_YES;
  }
  return GNUNET_SYSERR;
}



/**
 * Subtract ibf2 from ibf1, storing the result in ibf1.
 * The two IBF's must have the same parameters size and hash_num.
 *
 * @return a newly allocated invertible bloom filter
 */
void
ibf_subtract (struct InvertibleBloomFilter *ibf1, struct InvertibleBloomFilter *ibf2)
{
  /* FIXME */
}

