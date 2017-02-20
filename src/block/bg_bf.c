/*
     This file is part of GNUnet
     Copyright (C) 2017 GNUnet e.V.

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
 * @file block/bg_bf.c
 * @brief implementation of a block group using a Bloom filter
 *        to drop duplicate blocks
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_block_group_lib.h"
#include "gnunet_block_plugin.h"


/**
 * Internal data structure for a block group.
 */
struct BfGroupInternals
{
  /**
   * A Bloom filter to weed out duplicate replies probabilistically.
   */
  struct GNUNET_CONTAINER_BloomFilter *bf;

  /**
   * Set from the nonce to mingle the hashes before going into the @e bf.
   */
  uint32_t bf_mutator;

  /**
   * Size of @a bf.
   */
  uint32_t bf_size;

};


/**
 * Serialize state of a block group.
 *
 * @param bg group to serialize
 * @param[out] raw_data set to the serialized state
 * @param[out] raw_data_size set to the number of bytes in @a raw_data
 * @return #GNUNET_OK on success, #GNUNET_NO if serialization is not
 *         supported, #GNUNET_SYSERR on error
 */
static int
bf_group_serialize_cb (struct GNUNET_BLOCK_Group *bg,
                       void **raw_data,
                       size_t *raw_data_size)
{
  struct BfGroupInternals *gi = bg->internal_cls;
  char *raw;

  raw = GNUNET_malloc (gi->bf_size);
  if (GNUNET_OK !=
      GNUNET_CONTAINER_bloomfilter_get_raw_data (gi->bf,
                                                 raw,
                                                 gi->bf_size))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  *raw_data = raw;
  *raw_data_size = gi->bf_size;
  return GNUNET_OK;
}


/**
 * Destroy resources used by a block group.
 *
 * @param bg group to destroy, NULL is allowed
 */
static void
bf_group_destroy_cb (struct GNUNET_BLOCK_Group *bg)
{
  struct BfGroupInternals *gi = bg->internal_cls;

  GNUNET_CONTAINER_bloomfilter_free (gi->bf);
  GNUNET_free (gi);
  GNUNET_free (bg);
}


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
                              size_t raw_data_size)
{
  struct BfGroupInternals *gi;
  struct GNUNET_BLOCK_Group *bg;

  gi = GNUNET_new (struct BfGroupInternals);
  gi->bf = GNUNET_CONTAINER_bloomfilter_init ((bf_size != raw_data_size) ? NULL : raw_data,
                                              bf_size,
                                              bf_k);
  gi->bf_mutator = nonce;
  gi->bf_size = bf_size;
  bg = GNUNET_new (struct GNUNET_BLOCK_Group);
  bg->type = type;
  bg->serialize_cb = &bf_group_serialize_cb;
  bg->destroy_cb = &bf_group_destroy_cb;
  bg->internal_cls = gi;
  return bg;
}


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
                                    const struct GNUNET_HashCode *hc)
{
  struct BfGroupInternals *gi = bg->internal_cls;
  struct GNUNET_HashCode mhash;

  GNUNET_BLOCK_mingle_hash (hc,
                            gi->bf_mutator,
                            &mhash);
  if (GNUNET_YES ==
      GNUNET_CONTAINER_bloomfilter_test (gi->bf,
                                         &mhash))
    return GNUNET_YES;
  GNUNET_CONTAINER_bloomfilter_add (gi->bf,
                                    &mhash);
  return GNUNET_NO;
}


/* end of bg_bf.c */
