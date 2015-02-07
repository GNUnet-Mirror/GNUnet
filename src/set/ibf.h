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
      Free Software Foundation, Inc., 59 Temple Place - Suite 330,
      Boston, MA 02111-1307, USA.
*/

/**
 * @file set/ibf.h
 * @brief invertible bloom filter
 * @author Florian Dold
 */

#ifndef GNUNET_CONSENSUS_IBF_H
#define GNUNET_CONSENSUS_IBF_H

#include "platform.h"
#include "gnunet_util_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Keys that can be inserted into and removed from an IBF.
 */
struct IBF_Key
{
  uint64_t key_val;
};


/**
 * Hash of an IBF key.
 */
struct IBF_KeyHash
{
  uint32_t key_hash_val;
};


/**
 * Type of the count field of IBF buckets.
 */
struct IBF_Count
{
  int8_t count_val;
};


/**
 * Size of one ibf bucket in bytes
 */
#define IBF_BUCKET_SIZE (sizeof (struct IBF_Count) + sizeof (struct IBF_Key) + \
    sizeof (struct IBF_KeyHash))


/**
 * Invertible bloom filter (IBF).
 *
 * An IBF is a counting bloom filter that has the ability to restore
 * the hashes of its stored elements with high probability.
 */
struct InvertibleBloomFilter
{
  /**
   * How many cells does this IBF have?
   */
  uint32_t size;

  /**
   * In how many cells do we hash one element?
   * Usually 4 or 3.
   */
  uint8_t hash_num;

  /**
   * Xor sums of the elements' keys, used to identify the elements.
   * Array of 'size' elements.
   */
  struct IBF_Key *key_sum;

  /**
   * Xor sums of the hashes of the keys of inserted elements.
   * Array of 'size' elements.
   */
  struct IBF_KeyHash *key_hash_sum;

  /**
   * How many times has a bucket been hit?
   * Can be negative, as a result of IBF subtraction.
   * Array of 'size' elements.
   */
  struct IBF_Count *count;
};


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
ibf_write_slice (const struct InvertibleBloomFilter *ibf, uint32_t start, uint32_t count, void *buf);


/**
 * Read buckets from a buffer into an ibf.
 *
 * @param buf pointer to the buffer to read from
 * @param start which bucket to start at
 * @param count how many buckets to read
 * @param ibf the ibf to read from
 */
void
ibf_read_slice (const void *buf, uint32_t start, uint32_t count, struct InvertibleBloomFilter *ibf);


/**
 * Create a key from a hashcode.
 *
 * @param hash the hashcode
 * @return a key
 */
struct IBF_Key
ibf_key_from_hashcode (const struct GNUNET_HashCode *hash);


/**
 * Create a hashcode from a key, by replicating the key
 * until the hascode is filled
 *
 * @param key the key
 * @param dst hashcode to store the result in
 */
void
ibf_hashcode_from_key (struct IBF_Key key, struct GNUNET_HashCode *dst);


/**
 * Create an invertible bloom filter.
 *
 * @param size number of IBF buckets
 * @param hash_num number of buckets one element is hashed in, usually 3 or 4
 * @return the newly created invertible bloom filter
 */
struct InvertibleBloomFilter *
ibf_create (uint32_t size, uint8_t hash_num);


/**
 * Insert a key into an IBF.
 *
 * @param ibf the IBF
 * @param key the element's hash code
 */
void
ibf_insert (struct InvertibleBloomFilter *ibf, struct IBF_Key key);


/**
 * Remove a key from an IBF.
 *
 * @param ibf the IBF
 * @param key the element's hash code
 */
void
ibf_remove (struct InvertibleBloomFilter *ibf, struct IBF_Key key);


/**
 * Subtract ibf2 from ibf1, storing the result in ibf1.
 * The two IBF's must have the same parameters size and hash_num.
 *
 * @param ibf1 IBF that is subtracted from
 * @param ibf2 IBF that will be subtracted from ibf1
 */
void
ibf_subtract (struct InvertibleBloomFilter *ibf1, const struct InvertibleBloomFilter *ibf2);


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
ibf_decode (struct InvertibleBloomFilter *ibf, int *ret_side, struct IBF_Key *ret_id);


/**
 * Create a copy of an IBF, the copy has to be destroyed properly.
 *
 * @param ibf the IBF to copy
 */
struct InvertibleBloomFilter *
ibf_dup (const struct InvertibleBloomFilter *ibf);


/**
 * Destroy all resources associated with the invertible bloom filter.
 * No more ibf_*-functions may be called on ibf after calling destroy.
 *
 * @param ibf the intertible bloom filter to destroy
 */
void
ibf_destroy (struct InvertibleBloomFilter *ibf);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

