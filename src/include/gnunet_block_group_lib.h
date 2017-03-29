/*
     This file is part of GNUnet.
     Copyright (C) 2010 GNUnet e.V.

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
 * @author Christian Grothoff
 *
 * @file
 * Library for creating block groups (to be used by block plugins)
 *
 * @defgroup block  Block group library
 * Library for data group management
 * @{
 */
#ifndef GNUNET_BLOCK_GROUP_LIB_H
#define GNUNET_BLOCK_GROUP_LIB_H

#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * How many bytes should a bloomfilter be if we have already seen
 * entry_count responses?  Sized so that do not have to
 * re-size the filter too often (to keep it cheap).
 *
 * Since other peers will also add entries but not resize the filter,
 * we should generally pick a slightly larger size than what the
 * strict math would suggest.
 *
 * @param entry_count expected number of entries in the Bloom filter
 * @param k number of bits set per entry
 * @return must be a power of two and smaller or equal to 2^15.
 */
size_t
GNUNET_BLOCK_GROUP_compute_bloomfilter_size (unsigned int entry_count,
                                             unsigned int k);


/**
 * Create a new block group that filters duplicates using a Bloom filter.
 *
 * @param ctx block context in which the block group is created
 * @param bf_size size of the Bloom filter
 * @param bf_k K-value for the Bloom filter
 * @param type block type
 * @param nonce random value used to seed the group creation
 * @param raw_data optional serialized prior state of the group, NULL if unavailable/fresh
 * @param raw_data_size number of bytes in @a raw_data, 0 if unavailable/fresh
 * @return block group handle, NULL if block groups are not supported
 *         by this @a type of block (this is not an error)
 */
struct GNUNET_BLOCK_Group *
GNUNET_BLOCK_GROUP_bf_create (void *cls,
                              size_t bf_size,
                              unsigned int bf_k,
                              enum GNUNET_BLOCK_Type type,
                              uint32_t nonce,
                              const void *raw_data,
                              size_t raw_data_size);


/**
 * Test if @a hc is contained in the Bloom filter of @a bg.  If so,
 * return #GNUNET_YES.  If not, add @a hc to the Bloom filter and
 * return #GNUNET_NO.
 *
 * @param bg block group to use for testing
 * @param hc hash of element to evaluate
 * @return #GNUNET_YES if @a hc is (likely) a duplicate
 *         #GNUNET_NO if @a hc was definitively not in @bg (but now is)
 */
int
GNUNET_BLOCK_GROUP_bf_test_and_set (struct GNUNET_BLOCK_Group *bg,
                                    const struct GNUNET_HashCode *hc);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef GNUNET_BLOCK_GROUP_LIB_H */
#endif

/** @} */  /* end of group */

/* end of gnunet_block_group_lib.h */
