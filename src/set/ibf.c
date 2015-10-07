/*
      This file is part of GNUnet
      Copyright (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file set/ibf.c
 * @brief implementation of the invertible bloom filter
 * @author Florian Dold
 */

#include "ibf.h"

/**
 * Compute the key's hash from the key.
 * Redefine to use a different hash function.
 */
#define IBF_KEY_HASH_VAL(k) (GNUNET_CRYPTO_crc32_n (&(k), sizeof (struct IBF_KeyHash)))

/**
 * Create a key from a hashcode.
 *
 * @param hash the hashcode
 * @return a key
 */
struct IBF_Key
ibf_key_from_hashcode (const struct GNUNET_HashCode *hash)
{
  /* FIXME: endianess */
  return *(struct IBF_Key *) hash;
}

/**
 * Create a hashcode from a key, by replicating the key
 * until the hascode is filled
 *
 * @param key the key
 * @param dst hashcode to store the result in
 */
void
ibf_hashcode_from_key (struct IBF_Key key, struct GNUNET_HashCode *dst)
{
  struct IBF_Key *p;
  unsigned int i;
  const unsigned int keys_per_hashcode = sizeof (struct GNUNET_HashCode) / sizeof (struct IBF_Key);
  p = (struct IBF_Key *) dst;
  for (i = 0; i < keys_per_hashcode; i++)
    *p++ = key;
}


/**
 * Create an invertible bloom filter.
 *
 * @param size number of IBF buckets
 * @param hash_num number of buckets one element is hashed in
 * @return the newly created invertible bloom filter
 */
struct InvertibleBloomFilter *
ibf_create (uint32_t size, uint8_t hash_num)
{
  struct InvertibleBloomFilter *ibf;

  GNUNET_assert (0 != size);

  ibf = GNUNET_new (struct InvertibleBloomFilter);
  ibf->count = GNUNET_malloc_large (size * sizeof (uint8_t));
  ibf->key_sum = GNUNET_malloc_large (size * sizeof (struct IBF_Key));
  ibf->key_hash_sum = GNUNET_malloc_large (size * sizeof (struct IBF_KeyHash));
  ibf->size = size;
  ibf->hash_num = hash_num;

  return ibf;
}

/**
 * Store unique bucket indices for the specified key in dst.
 */
static inline void
ibf_get_indices (const struct InvertibleBloomFilter *ibf,
                 struct IBF_Key key, int *dst)
{
  uint32_t filled;
  uint32_t i;
  uint32_t bucket;

  bucket = GNUNET_CRYPTO_crc32_n (&key, sizeof key);
  for (i = 0, filled=0; filled < ibf->hash_num; i++)
  {
    unsigned int j;
    uint64_t x;
    for (j = 0; j < filled; j++)
      if (dst[j] == bucket)
        goto try_next;
    dst[filled++] = bucket % ibf->size;
    try_next: ;
    x = ((uint64_t) bucket << 32) | i;
    bucket = GNUNET_CRYPTO_crc32_n (&x, sizeof x);
  }
}


static void
ibf_insert_into  (struct InvertibleBloomFilter *ibf,
                  struct IBF_Key key,
                  const int *buckets, int side)
{
  int i;

  for (i = 0; i < ibf->hash_num; i++)
  {
    const int bucket = buckets[i];
    ibf->count[bucket].count_val += side;
    ibf->key_sum[bucket].key_val ^= key.key_val;
    ibf->key_hash_sum[bucket].key_hash_val
        ^= IBF_KEY_HASH_VAL (key);
  }
}


/**
 * Insert a key into an IBF.
 *
 * @param ibf the IBF
 * @param key the element's hash code
 */
void
ibf_insert (struct InvertibleBloomFilter *ibf, struct IBF_Key key)
{
  int buckets[ibf->hash_num];
  GNUNET_assert (ibf->hash_num <= ibf->size);
  ibf_get_indices (ibf, key, buckets);
  ibf_insert_into (ibf, key, buckets, 1);
}


/**
 * Remove a key from an IBF.
 *
 * @param ibf the IBF
 * @param key the element's hash code
 */
void
ibf_remove (struct InvertibleBloomFilter *ibf, struct IBF_Key key)
{
  int buckets[ibf->hash_num];
  GNUNET_assert (ibf->hash_num <= ibf->size);
  ibf_get_indices (ibf, key, buckets);
  ibf_insert_into (ibf, key, buckets, -1);
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
    if (0 != ibf->count[i].count_val)
      return GNUNET_NO;
    if (0 != ibf->key_hash_sum[i].key_hash_val)
      return GNUNET_NO;
    if (0 != ibf->key_sum[i].key_val)
      return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Decode and remove an element from the IBF, if possible.
 *
 * @param ibf the invertible bloom filter to decode
 * @param ret_side sign of the cell's count where the decoded element came from.
 *                 A negative sign indicates that the element was recovered
 *                 resides in an IBF that was previously subtracted from.
 * @param ret_id receives the hash code of the decoded element, if successful
 * @return GNUNET_YES if decoding an element was successful,
 *         GNUNET_NO if the IBF is empty,
 *         GNUNET_SYSERR if the decoding has failed
 */
int
ibf_decode (struct InvertibleBloomFilter *ibf,
            int *ret_side, struct IBF_Key *ret_id)
{
  struct IBF_KeyHash hash;
  int i;
  int buckets[ibf->hash_num];

  GNUNET_assert (NULL != ibf);

  for (i = 0; i < ibf->size; i++)
  {
    int j;
    int hit;

    /* we can only decode from pure buckets */
    if ((1 != ibf->count[i].count_val) && (-1 != ibf->count[i].count_val))
      continue;

    hash.key_hash_val = IBF_KEY_HASH_VAL (ibf->key_sum[i]);

    /* test if the hash matches the key */
    if (hash.key_hash_val != ibf->key_hash_sum[i].key_hash_val)
      continue;

    /* test if key in bucket hits its own location,
     * if not, the key hash was subject to collision */
    hit = GNUNET_NO;
    ibf_get_indices (ibf, ibf->key_sum[i], buckets);
    for (j = 0; j < ibf->hash_num; j++)
      if (buckets[j] == i)
        hit = GNUNET_YES;

    if (GNUNET_NO == hit)
      continue;

    if (NULL != ret_side)
      *ret_side = ibf->count[i].count_val;
    if (NULL != ret_id)
      *ret_id = ibf->key_sum[i];

    /* insert on the opposite side, effectively removing the element */
    ibf_insert_into (ibf, ibf->key_sum[i], buckets, -ibf->count[i].count_val);

    return GNUNET_YES;
  }

  if (GNUNET_YES == ibf_is_empty (ibf))
    return GNUNET_NO;
  return GNUNET_SYSERR;
}


/**
 * Write buckets from an ibf to a buffer.
 * Exactly (IBF_BUCKET_SIZE*ibf->size) bytes are written to buf.
 *
 * @param ibf the ibf to write
 * @param start with which bucket to start
 * @param count how many buckets to write
 * @param buf buffer to write the data to
 */
void
ibf_write_slice (const struct InvertibleBloomFilter *ibf, uint32_t start, uint32_t count, void *buf)
{
  struct IBF_Key *key_dst;
  struct IBF_KeyHash *key_hash_dst;
  struct IBF_Count *count_dst;

  GNUNET_assert (start + count <= ibf->size);

  /* copy keys */
  key_dst = (struct IBF_Key *) buf;
  memcpy (key_dst, ibf->key_sum + start, count * sizeof *key_dst);
  key_dst += count;
  /* copy key hashes */
  key_hash_dst = (struct IBF_KeyHash *) key_dst;
  memcpy (key_hash_dst, ibf->key_hash_sum + start, count * sizeof *key_hash_dst);
  key_hash_dst += count;
  /* copy counts */
  count_dst = (struct IBF_Count *) key_hash_dst;
  memcpy (count_dst, ibf->count + start, count * sizeof *count_dst);
}


/**
 * Read buckets from a buffer into an ibf.
 *
 * @param buf pointer to the buffer to read from
 * @param start which bucket to start at
 * @param count how many buckets to read
 * @param ibf the ibf to read from
 */
void
ibf_read_slice (const void *buf, uint32_t start, uint32_t count, struct InvertibleBloomFilter *ibf)
{
  struct IBF_Key *key_src;
  struct IBF_KeyHash *key_hash_src;
  struct IBF_Count *count_src;

  GNUNET_assert (count > 0);
  GNUNET_assert (start + count <= ibf->size);

  /* copy keys */
  key_src = (struct IBF_Key *) buf;
  memcpy (ibf->key_sum + start, key_src, count * sizeof *key_src);
  key_src += count;
  /* copy key hashes */
  key_hash_src = (struct IBF_KeyHash *) key_src;
  memcpy (ibf->key_hash_sum + start, key_hash_src, count * sizeof *key_hash_src);
  key_hash_src += count;
  /* copy counts */
  count_src = (struct IBF_Count *) key_hash_src;
  memcpy (ibf->count + start, count_src, count * sizeof *count_src);
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

  for (i = 0; i < ibf1->size; i++)
  {
    ibf1->count[i].count_val -= ibf2->count[i].count_val;
    ibf1->key_hash_sum[i].key_hash_val ^= ibf2->key_hash_sum[i].key_hash_val;
    ibf1->key_sum[i].key_val ^= ibf2->key_sum[i].key_val;
  }
}


/**
 * Create a copy of an IBF, the copy has to be destroyed properly.
 *
 * @param ibf the IBF to copy
 */
struct InvertibleBloomFilter *
ibf_dup (const struct InvertibleBloomFilter *ibf)
{
  struct InvertibleBloomFilter *copy;
  copy = GNUNET_malloc (sizeof *copy);
  copy->hash_num = ibf->hash_num;
  copy->size = ibf->size;
  copy->key_hash_sum = GNUNET_memdup (ibf->key_hash_sum, ibf->size * sizeof (struct IBF_KeyHash));
  copy->key_sum = GNUNET_memdup (ibf->key_sum, ibf->size * sizeof (struct IBF_Key));
  copy->count = GNUNET_memdup (ibf->count, ibf->size * sizeof (struct IBF_Count));
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
  GNUNET_free (ibf->key_sum);
  GNUNET_free (ibf->key_hash_sum);
  GNUNET_free (ibf->count);
  GNUNET_free (ibf);
}

