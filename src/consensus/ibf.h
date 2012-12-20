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
 * Opaque handle to an invertible bloom filter (IBF).
 *
 * An IBF is a counting bloom filter that has the ability to restore
 * the hashes of its stored elements with high probability.
 */
struct InvertibleBloomFilter;


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
ibf_create(unsigned int size, unsigned int hash_num, uint32_t salt);


/**
 * Insert an element into an IBF.
 *
 * @param ibf the IBF
 * @param id the element's hash code
 */
void
ibf_insert (struct InvertibleBloomFilter *ibf, const struct GNUNET_HashCode *id);


/**
 * Subtract ibf2 from ibf1, storing the result in ibf1.
 * The two IBF's must have the same parameters size and hash_num.
 */
void
ibf_subtract (struct InvertibleBloomFilter *ibf1, struct InvertibleBloomFilter *ibf2);


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
ibf_decode (struct InvertibleBloomFilter *ibf, int *side, struct GNUNET_HashCode *ret_id);


/**
 * Create a copy of an IBF, the copy has to be destroyed properly.
 *
 * @param ibf the IBF to copy
 */
struct InvertibleBloomFilter *
ibf_dup (struct InvertibleBloomFilter *ibf);


/*
ibf_hton ();

ibf_ntoh ();

ibf_get_nbo_size ();
*/

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

