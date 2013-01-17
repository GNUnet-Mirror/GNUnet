/*
     This file is part of GNUnet.
     (C) 2012,2013 Christian Grothoff (and other contributing authors)

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
 * @file regex/regex_block_lib.h
 */

#ifndef REGEX_BLOCK_LIB_H_
#define REGEX_BLOCK_LIB_H_

#ifdef __cplusplus
extern "C"
{
#if 0
  /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "platform.h"
#include "block_regex.h"

/**
 * Check if the regex block is well formed, including all edges
 *
 * @param block The start of the block.
 * @param size The size of the block.
 * @param xquery String describing the edge we are looking for.
 *
 * @return GNUNET_OK in case it's fine.
 *         GNUNET_NO in case the xquery is not found.
 *         GNUNET_SYSERR if the block is invalid.
 */
int
GNUNET_REGEX_block_check (const struct RegexBlock *block,
                          size_t size,
                          const char *xquery);

/**
 * Iterator over edges in a block.
 *
 * @param cls Closure.
 * @param token Token that follows to next state.
 * @param len Length of token.
 * @param key Hash of next state.
 *
 * @return GNUNET_YES if should keep iterating, GNUNET_NO otherwise.
 */
typedef int (*GNUNET_REGEX_EgdeIterator)(void *cls,
                                         const char *token,
                                         size_t len,
                                         const struct GNUNET_HashCode *key);


/**
 * Iterate over all edges of a block of a regex state.
 *
 * @param block Block to iterate over.
 * @param size Size of block.
 * @param iterator Function to call on each edge in the block.
 * @param iter_cls Closure for the iterator.
 *
 * @return GNUNET_SYSERR if an error has been encountered, GNUNET_OK otherwise
 */
int
GNUNET_REGEX_block_iterate (const struct RegexBlock *block,
                            size_t size,
                            GNUNET_REGEX_EgdeIterator iterator,
                            void *iter_cls);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef REGEX_BLOCK_LIB_H */
#endif
/* end of regex_block_lib.h */
