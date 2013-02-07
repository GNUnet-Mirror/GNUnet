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
 * Create a key from a hashcode.
 *
 * @param hash the hashcode
 * @return a key
 */
uint64_t
ibf_key_from_hashcode (const struct GNUNET_HashCode *hash)
{
  return GNUNET_ntohll (*(uint64_t *) hash);
}


/**
 * Create a hashcode from a key, by replicating the key
 * until the hascode is filled
 *
 * @param key the key
 * @param dst hashcode to store the result in
 */
void
ibf_hashcode_from_key (uint64_t key, struct GNUNET_HashCode *dst)
{
  uint64_t *p;
  int i;
  p = (uint64_t *) dst;
  for (i = 0; i < 8; i++)
    *p++ = key;
}


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
ibf_create (uint32_t size, unsigned int hash_num, uint32_t salt)
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
 * Store unique bucket indices for the specified key in dst.
 */
static inline void
ibf_get_indices (const struct InvertibleBloomFilter *ibf,
                 uint64_t key, int *dst)
{
  struct GNUNET_HashCode bucket_indices;
  unsigned int filled = 0;
  int i;
  GNUNET_CRYPTO_hash (&key, sizeof key, &bucket_indices);
  for (i = 0; filled < ibf->hash_num; i++)
  {
    unsigned int bucket;
    unsigned int j;
    if ( (0 != i) && (0 == (i % 16)) )
      GNUNET_CRYPTO_hash (&bucket_indices, sizeof (struct GNUNET_HashCode), &bucket_indices);
    bucket = bucket_indices.bits[i] % ibf->size;
    for (j = 0; j < filled; j++)
      if (dst[j] == bucket)
        goto try_next;;
    dst[filled++] = bucket;
    try_next: ;
  }
}


static void
ibf_insert_into  (struct InvertibleBloomFilter *ibf,
                  uint64_t key,
                  const int *buckets, int side)
{
  int i;
  struct GNUNET_HashCode key_hash_sha;
  uint32_t key_hash;
  GNUNET_CRYPTO_hash (&key, sizeof key, &key_hash_sha);
  key_hash = key_hash_sha.bits[0];
  for (i = 0; i < ibf->hash_num; i++)
  {
    const int bucket = buckets[i];
    ibf->count[bucket] += side;
    ibf->id_sum[bucket] ^= key;
    ibf->hash_sum[bucket] ^= key_hash;
  }
}


/**
 * Insert an element into an IBF.
 *
 * @param ibf the IBF
 * @param id the element's hash code
 */
void
ibf_insert (struct InvertibleBloomFilter *ibf, uint64_t key)
{
  int buckets[ibf->hash_num];
  ibf_get_indices (ibf, key, buckets);
  ibf_insert_into (ibf, key, buckets, 1);
}

/**
 * Test is the IBF is empty, i.e. all counts, keys and key hashes are zero.
 */
static int
ibf_is_empty (struct InvertibleBloomFilter *ibf)
{
  int i;
  for (i = 0; i < ibf->size; i++)
  {
    if (0 != ibf->count[i])
      return GNUNET_NO;
    if (0 != ibf->hash_sum[i])
      return GNUNET_NO;
    if (0 != ibf->id_sum[i])
      return GNUNET_NO;
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
            int *ret_side, uint64_t *ret_id)
{
  uint32_t hash;
  int i;
  struct GNUNET_HashCode key_hash_sha;
  int buckets[ibf->hash_num];

  GNUNET_assert (NULL != ibf);

  for (i = 0; i < ibf->size; i++)
  {
    int j;
    int hit;

    /* we can only decode from pure buckets */
    if ((1 != ibf->count[i]) && (-1 != ibf->count[i]))
      continue;

    GNUNET_CRYPTO_hash (&ibf->id_sum[i], sizeof (uint64_t), &key_hash_sha);
    hash = key_hash_sha.bits[0];

    /* test if the hash matches the key */
    if (hash != ibf->hash_sum[i])
      continue;

    /* test if key in bucket hits its own location,
     * if not, the key hash was subject to collision */
    hit = GNUNET_NO;
    ibf_get_indices (ibf, ibf->id_sum[i], buckets);
    for (j = 0; j < ibf->hash_num; j++)
      if (buckets[j] == i)
        hit = GNUNET_YES;

    if (GNUNET_NO == hit)
      continue;

    if (NULL != ret_side)
      *ret_side = ibf->count[i];
    if (NULL != ret_id)
      *ret_id = ibf->id_sum[i];

    /* insert on the opposite side, effectively removing the element */
    ibf_insert_into (ibf, ibf->id_sum[i], buckets, -ibf->count[i]);

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
ibf_subtract (struct InvertibleBloomFilter *ibf1, const struct InvertibleBloomFilter *ibf2)
{
  int i;

  GNUNET_assert (ibf1->size == ibf2->size);
  GNUNET_assert (ibf1->hash_num == ibf2->hash_num);
  GNUNET_assert (ibf1->salt == ibf2->salt);

  for (i = 0; i < ibf1->size; i++)
  {
    ibf1->count[i] -= ibf2->count[i];
    ibf1->hash_sum[i] ^= ibf2->hash_sum[i];
    ibf1->id_sum[i] ^= ibf2->id_sum[i];
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
