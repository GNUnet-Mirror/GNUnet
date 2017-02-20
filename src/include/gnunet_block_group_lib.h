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
