/*
     This file is part of GNUnet.
     Copyright (C) 2012,2013 Christian Grothoff (and other contributing authors)

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
 * @brief common function to manipulate blocks stored by regex in the DHT
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
 * Representation of a Regex node (and edges) in the DHT.
 */
struct RegexBlock;


/**
 * Edge representation.
 */
struct REGEX_BLOCK_Edge
{
  /**
   * Label of the edge.  FIXME: might want to not consume exactly multiples of 8 bits, need length!
   */
  const char *label;

  /**
   * Destionation of the edge.
   */
  struct GNUNET_HashCode destination;
};


/**
 * Check if the given 'proof' matches the given 'key'.
 *
 * @param proof partial regex of a state
 * @param proof_len number of bytes in 'proof'
 * @param key hash of a state.
 *
 * @return GNUNET_OK if the proof is valid for the given key.
 */
int
REGEX_BLOCK_check_proof (const char *proof,
			 size_t proof_len,
			 const struct GNUNET_HashCode *key);


/**
 * Check if the regex block is well formed, including all edges.
 *
 * @param block The start of the block.
 * @param size The size of the block.
 * @param query the query for the block
 * @param xquery String describing the edge we are looking for.
 *               Can be NULL in case this is a put block.
 *
 * @return GNUNET_OK in case it's fine.
 *         GNUNET_NO in case the xquery exists and is not found (IRRELEVANT).
 *         GNUNET_SYSERR if the block is invalid.
 */
int
REGEX_BLOCK_check (const struct RegexBlock *block,
		   size_t size,
		   const struct GNUNET_HashCode *query,
		   const char *xquery);


/* FIXME: might want to use 'struct REGEX_BLOCK_Edge' here instead of 3 arguments! */

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
typedef int (*REGEX_INTERNAL_EgdeIterator)(void *cls,
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
 * @return GNUNET_SYSERR if an error has been encountered.
 *         GNUNET_OK if no error has been encountered.
 *           Note that if the iterator stops the iteration by returning
 *         GNUNET_NO, the block will no longer be checked for further errors.
 *           The return value will be GNUNET_OK meaning that no errors were
 *         found until the edge last notified to the iterator, but there might
 *         be errors in further edges.
 */
int
REGEX_BLOCK_iterate (const struct RegexBlock *block,
                            size_t size,
                            REGEX_INTERNAL_EgdeIterator iterator,
                            void *iter_cls);

/**
 * Obtain the key that a particular block is to be stored under.
 *
 * @param block block to get the key from
 * @param block_len number of bytes in block
 * @param key where to store the key
 * @return GNUNET_OK on success, GNUNET_SYSERR if the block is malformed
 */
int
REGEX_BLOCK_get_key (const struct RegexBlock *block,
		     size_t block_len,
		     struct GNUNET_HashCode *key);


/**
 * Test if this block is marked as being an accept state.
 *
 * @param block block to test
 * @param size number of bytes in block
 * @return GNUNET_YES if the block is accepting, GNUNET_NO if not
 */
int
GNUNET_BLOCK_is_accepting (const struct RegexBlock *block,
			   size_t block_len);


/**
 * Construct a regex block to be stored in the DHT.
 *
 * @param proof proof string for the block
 * @param num_edges number of edges in the block
 * @param edges the edges of the block
 * @param accepting is this an accepting state
 * @param rsize set to the size of the returned block (OUT-only)
 * @return the regex block, NULL on error
 */
struct RegexBlock *
REGEX_BLOCK_create (const char *proof,
		    unsigned int num_edges,
		    const struct REGEX_BLOCK_Edge *edges,
		    int accepting,
		    size_t *rsize);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* ifndef REGEX_BLOCK_LIB_H */
#endif
/* end of regex_block_lib.h */
