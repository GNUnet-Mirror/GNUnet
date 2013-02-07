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
 * @file consensus/ibf.h
 * @brief invertible bloom filter
 * @author Florian Dold
 */

#ifndef GNUNET_CONSENSUS_IBF_H
#define GNUNET_CONSENSUS_IBF_H

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_util_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Size of one ibf bucket in bytes
 */
#define IBF_BUCKET_SIZE (8+4+1)


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
  unsigned int hash_num;

  /**
   * Salt for mingling hashes
   */
  uint32_t salt;

  /**
   * xor sums of the elements' hash codes, used to identify the elements.
   */
  uint64_t *id_sum;

  /**
   * xor sums of the "hash of the hash".
   */
  uint32_t *hash_sum;

  /**
   * How many times has a bucket been hit?
   * Can be negative, as a result of IBF subtraction.
   */
  int8_t *count;
};


/**
 * Create a key from a hashcode.
 *
 * @param hash the hashcode
 * @return a key
 */
uint64_t
ibf_key_from_hashcode (const struct GNUNET_HashCode *hash);


/**
 * Create a hashcode from a key, by replicating the key
 * until the hascode is filled
 *
 * @param key the key
 * @param dst hashcode to store the result in
 */
void
ibf_hashcode_from_key (uint64_t key, struct GNUNET_HashCode *dst);


/**
 * Create an invertible bloom filter.
 *
 * @param size number of IBF buckets
 * @param hash_num number of buckets one element is hashed in, usually 3 or 4
 * @param salt salt for mingling hashes, different salt may
 *        result in less (or more) collisions
 * @return the newly created invertible bloom filter
 */
struct InvertibleBloomFilter *
ibf_create(uint32_t size, unsigned int hash_num, uint32_t salt);


/**
 * Insert an element into an IBF.
 *
 * @param ibf the IBF
 * @param id the element's hash code
 */
void
ibf_insert (struct InvertibleBloomFilter *ibf, uint64_t id);


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
 * @param side sign of the cell's count where the decoded element came from.
 *             A negative sign indicates that the element was recovered resides in an IBF
 *             that was previously subtracted from.
 * @param ret_id the hash code of the decoded element, if successful
 * @return GNUNET_YES if decoding an element was successful, GNUNET_NO if the IBF is empty,
 *         GNUNET_SYSERR if the decoding has faile
 */
int
ibf_decode (struct InvertibleBloomFilter *ibf, int *side, uint64_t *ret_id);


/**
 * Create a copy of an IBF, the copy has to be destroyed properly.
 *
 * @param ibf the IBF to copy
 */
struct InvertibleBloomFilter *
ibf_dup (struct InvertibleBloomFilter *ibf);

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

