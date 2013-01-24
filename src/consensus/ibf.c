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


#include "ibf.h"


/**
 * Create an invertible bloom filter.
 *
 * @param size number of IBF buckets
 * @param hash_num number of buckets one element is hashed in
 * @param salt salt for mingling hashes, different salt may
 *        result in less (or more) collisions
 * @return the newly created invertible bloom filter
 */
struct InvertibleBloomFilter *
ibf_create (unsigned int size, unsigned int hash_num, uint32_t salt)
{
  struct InvertibleBloomFilter *ibf;

  ibf = GNUNET_malloc (sizeof (struct InvertibleBloomFilter));
  ibf->count = GNUNET_malloc (size * sizeof (uint8_t));
  ibf->id_sum = GNUNET_malloc (size * sizeof (struct GNUNET_HashCode));
  ibf->hash_sum = GNUNET_malloc (size * sizeof (struct GNUNET_HashCode));
  ibf->size = size;
  ibf->hash_num = hash_num;

  return ibf;
}



/**
 * Insert an element into an IBF, with either positive or negative sign.
 *
 * @param ibf the IBF
 * @param id the element's hash code
 * @param side the sign of side determines the sign of the 
 *        inserted element.
 */
void
ibf_insert_on_side (struct InvertibleBloomFilter *ibf,
                    const struct GNUNET_HashCode *key,
                    int side)
{
  struct GNUNET_HashCode bucket_indices;
  struct GNUNET_HashCode key_copy;
  struct GNUNET_HashCode key_hash;
  unsigned int i;


  GNUNET_assert ((1 == side) || (-1 == side));
  GNUNET_assert (NULL != ibf);

  {
    int used_buckets[ibf->hash_num];

    /* copy the key, if key and an entry in the IBF alias */
    key_copy = *key;

    bucket_indices = key_copy;
    GNUNET_CRYPTO_hash (key, sizeof (struct GNUNET_HashCode), &key_hash);
    
    for (i = 0; i < ibf->hash_num; i++)
    {
      unsigned int bucket;
      unsigned int j;
      int collided;
    
      if ( (0 != i) &&
	   (0 == (i % 16)) )
	GNUNET_CRYPTO_hash (&bucket_indices, sizeof (struct GNUNET_HashCode),
			    &bucket_indices);
      
      bucket = bucket_indices.bits[i%16] % ibf->size;
      collided = GNUNET_NO;
      for (j = 0; j < i; j++)
	if (used_buckets[j] == bucket)
	  collided = GNUNET_YES;
      if (GNUNET_YES == collided)
	{
	  used_buckets[i] = -1;
	  continue;
	}
      used_buckets[i] = bucket;
      
      ibf->count[bucket] += side;

      GNUNET_CRYPTO_hash_xor (&key_copy, &ibf->id_sum[bucket],
			      &ibf->id_sum[bucket]);
      GNUNET_CRYPTO_hash_xor (&key_hash, &ibf->hash_sum[bucket],
			      &ibf->hash_sum[bucket]);
    }
  }
}

/**
 * Insert an element into an IBF.
 *
 * @param ibf the IBF
 * @param id the element's hash code
 */
void
ibf_insert (struct InvertibleBloomFilter *ibf, const struct GNUNET_HashCode *key)
{
  ibf_insert_on_side (ibf, key, 1);
}

static int
ibf_is_empty (struct InvertibleBloomFilter *ibf)
{
  int i;
  for (i = 0; i < ibf->size; i++)
  {
    int j;
    if (0 != ibf->count[i])
      return GNUNET_NO;
    for (j = 0; j < 16; ++j)
    {
      if (0 != ibf->hash_sum[i].bits[j])
        return GNUNET_NO;
      if (0 != ibf->id_sum[i].bits[j])
        return GNUNET_NO;
    }
  }
  return GNUNET_YES;
}


/**
 * Decode and remove an element from the IBF, if possible.
 *
 * @param ibf the invertible bloom filter to decode
 * @param side sign of the cell's count where the decoded element came from.
 *             A negative sign indicates that the element was recovered
 *             resides in an IBF that was previously subtracted from.
 * @param ret_id the hash code of the decoded element, if successful
 * @return GNUNET_YES if decoding an element was successful,
 *         GNUNET_NO if the IBF is empty,
 *         GNUNET_SYSERR if the decoding has failed
 */
int
ibf_decode (struct InvertibleBloomFilter *ibf,
            int *ret_side, struct GNUNET_HashCode *ret_id)
{
  struct GNUNET_HashCode hash;
  int i;

  GNUNET_assert (NULL != ibf);

  for (i = 0; i < ibf->size; i++)
  {
    if ((1 != ibf->count[i]) && (-1 != ibf->count[i]))
      continue;

    GNUNET_CRYPTO_hash (&ibf->id_sum[i], sizeof (struct GNUNET_HashCode), &hash);

    if (0 != memcmp (&hash, &ibf->hash_sum[i], sizeof (struct GNUNET_HashCode)))
      continue;

    if (NULL != ret_side)
      *ret_side = ibf->count[i];
    if (NULL != ret_id)
      *ret_id = ibf->id_sum[i];

    /* insert on the opposite side, effectively removing the element */
    ibf_insert_on_side (ibf, &ibf->id_sum[i], -ibf->count[i]);

    return GNUNET_YES;
  }

  if (GNUNET_YES == ibf_is_empty (ibf))
    return GNUNET_NO;
  return GNUNET_SYSERR;
}



/**
 * Subtract ibf2 from ibf1, storing the result in ibf1.
 * The two IBF's must have the same parameters size and hash_num.
 *
 * @param ibf1 IBF that is subtracted from
 * @param ibf2 IBF that will be subtracted from ibf1
 */
void
ibf_subtract (struct InvertibleBloomFilter *ibf1, struct InvertibleBloomFilter *ibf2)
{
  int i;

  GNUNET_assert (ibf1->size == ibf2->size);
  GNUNET_assert (ibf1->hash_num == ibf2->hash_num);
  GNUNET_assert (ibf1->salt == ibf2->salt);

  for (i = 0; i < ibf1->size; i++)
  {
    ibf1->count[i] -= ibf2->count[i];
    GNUNET_CRYPTO_hash_xor (&ibf1->id_sum[i], &ibf2->id_sum[i],
                            &ibf1->id_sum[i]);
    GNUNET_CRYPTO_hash_xor (&ibf1->hash_sum[i], &ibf2->hash_sum[i], 
                            &ibf1->hash_sum[i]);
  }
}

/**
 * Create a copy of an IBF, the copy has to be destroyed properly.
 *
 * @param ibf the IBF to copy
 */
struct InvertibleBloomFilter *
ibf_dup (struct InvertibleBloomFilter *ibf)
{
  struct InvertibleBloomFilter *copy;
  copy = GNUNET_malloc (sizeof *copy);
  copy->hash_num = ibf->hash_num;
  copy->salt = ibf->salt;
  copy->size = ibf->size;
  copy->hash_sum = GNUNET_memdup (ibf->hash_sum, ibf->size * sizeof (struct GNUNET_HashCode));
  copy->id_sum = GNUNET_memdup (ibf->id_sum, ibf->size * sizeof (struct GNUNET_HashCode));
  copy->count = GNUNET_memdup (ibf->count, ibf->size * sizeof (uint8_t));
  return copy;
}

/**
 * Destroy all resources associated with the invertible bloom filter.
 * No more ibf_*-functions may be called on ibf after calling destroy.
 *
 * @param ibf the intertible bloom filter to destroy
 */
void
ibf_destroy (struct InvertibleBloomFilter *ibf)
{
  GNUNET_free (ibf->hash_sum);
  GNUNET_free (ibf->id_sum);
  GNUNET_free (ibf->count);
  GNUNET_free (ibf);
}
