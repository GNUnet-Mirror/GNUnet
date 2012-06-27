/*
     This file is part of GNUnet.
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @author Bartlomiej Polot
 * @file mesh/mesh_block_lib.h
 */

#ifndef MESH_BLOCK_LIB_H_
#define MESH_BLOCK_LIB_H_

#ifdef __cplusplus
extern "C"
{
#if 0
  /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "platform.h"
#include "block_mesh.h"

/**
 * Check if the regex block is well formed, including all edges
 *
 * @param block The start of the block.
 * @param size The size of the block.
 *
 * @return GNUNET_OK in case it's fine, GNUNET_SYSERR otherwise.
 */
int
GNUNET_MESH_regex_block_check (const struct MeshRegexBlock *block,
                               size_t size);

/**
 * Iterator over edges in a block.
 *
 * @param cls Closure.
 * @param token Token that follows to next state.
 * @param len Lenght of token.
 * @param key Hash of next state.
 *
 * @return GNUNET_YES if should keep iterating, GNUNET_NO otherwise.
 */
typedef int (*GNUNET_MESH_EgdeIterator)(void *cls,
                                        const char *token,
                                        size_t len,
                                        const struct GNUNET_HashCode *key);


/**
 * Iterate over all edges of a block of a regex state.
 *
 * @param cls Closure for the iterator.
 * @param block Block to iterate over.
 * @param size Size of block.
 * @param iterator Function to call on each edge in the block.
 *
 * @return GNUNET_SYSERR if an error has been encountered, GNUNET_OK otherwise
 */
int
GNUNET_MESH_regex_block_iterate (void *cls,
                                 const struct MeshRegexBlock *block,
                                 size_t size,
                                 GNUNET_MESH_EgdeIterator iterator);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef MESH_BLOCK_LIB_H */
#endif
/* end of mesh_block_lib.h */
