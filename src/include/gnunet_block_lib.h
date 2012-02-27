/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_block_lib.h
 * @brief library for data block manipulation
 * @author Christian Grothoff
 */
#ifndef GNUNET_BLOCK_LIB_H
#define GNUNET_BLOCK_LIB_H

#include "gnunet_util_lib.h"
#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Blocks in the datastore and the datacache must have a unique type.
 */
enum GNUNET_BLOCK_Type
{
    /**
     * Any type of block, used as a wildcard when searching.  Should
     * never be attached to a specific block.
     */
  GNUNET_BLOCK_TYPE_ANY = 0,

    /**
     * Data block (leaf) in the CHK tree.
     */
  GNUNET_BLOCK_TYPE_FS_DBLOCK = 1,

    /**
     * Inner block in the CHK tree.
     */
  GNUNET_BLOCK_TYPE_FS_IBLOCK = 2,

    /**
     * Type of a block representing a keyword search result.  Note that
     * the values for KBLOCK, SBLOCK and NBLOCK must be consecutive.
     */
  GNUNET_BLOCK_TYPE_FS_KBLOCK = 3,

    /**
     * Type of a block that is used to advertise content in a namespace.
     */
  GNUNET_BLOCK_TYPE_FS_SBLOCK = 4,

    /**
     * Type of a block that is used to advertise a namespace.
     */
  GNUNET_BLOCK_TYPE_FS_NBLOCK = 5,

    /**
     * Type of a block representing a block to be encoded on demand from disk.
     * Should never appear on the network directly.
     */
  GNUNET_BLOCK_TYPE_FS_ONDEMAND = 6,

    /**
     * Type of a block that contains a HELLO for a peer (for
     * DHT find-peer operations).
     */
  GNUNET_BLOCK_TYPE_DHT_HELLO = 7,

    /**
     * Block for testing.
     */
  GNUNET_BLOCK_TYPE_TEST = 8,

    /**
     * Block for storing .gnunet-domains
     */
  GNUNET_BLOCK_TYPE_DNS = 10,

    /**
     * Block for storing record data
     */
  GNUNET_BLOCK_TYPE_GNS_NAMERECORD = 11
};


/**
 * Possible ways for how a block may relate to a query.
 */
enum GNUNET_BLOCK_EvaluationResult
{
    /**
     * Valid result, and there may be more.
     */
  GNUNET_BLOCK_EVALUATION_OK_MORE = 0,

    /**
     * Last possible valid result.
     */
  GNUNET_BLOCK_EVALUATION_OK_LAST = 1,

    /**
     * Valid result, but suppressed because it is a duplicate.
     */
  GNUNET_BLOCK_EVALUATION_OK_DUPLICATE = 2,

    /**
     * Block does not match query (invalid result)
     */
  GNUNET_BLOCK_EVALUATION_RESULT_INVALID = 3,

    /**
     * Query is valid, no reply given.
     */
  GNUNET_BLOCK_EVALUATION_REQUEST_VALID = 4,

    /**
     * Query format does not match block type (invalid query).  For
     * example, xquery not given or xquery_size not appropriate for
     * type.
     */
  GNUNET_BLOCK_EVALUATION_REQUEST_INVALID = 5,

    /**
     * Specified block type not supported by this plugin.
     */
  GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED = 6
};


/**
 * Handle to an initialized block library.
 */
struct GNUNET_BLOCK_Context;


/**
 * Mingle hash with the mingle_number to produce different bits.
 *
 * @param in original hash code
 * @param mingle_number number for hash permutation
 * @param hc where to store the result.
 */
void
GNUNET_BLOCK_mingle_hash (const GNUNET_HashCode * in, uint32_t mingle_number,
                          GNUNET_HashCode * hc);


/**
 * Create a block context.  Loads the block plugins.
 *
 * @param cfg configuration to use
 * @return NULL on error
 */
struct GNUNET_BLOCK_Context *
GNUNET_BLOCK_context_create (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Destroy the block context.
 *
 * @param ctx context to destroy
 */
void
GNUNET_BLOCK_context_destroy (struct GNUNET_BLOCK_Context *ctx);


/**
 * Function called to validate a reply or a request.  For
 * request evaluation, simply pass "NULL" for the reply_block.
 * Note that it is assumed that the reply has already been
 * matched to the key (and signatures checked) as it would
 * be done with the "get_key" function.
 *
 * @param ctx block contxt
 * @param type block type
 * @param query original query (hash)
 * @param bf pointer to bloom filter associated with query; possibly updated (!)
 * @param bf_mutator mutation value for bf
 * @param xquery extrended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in xquery
 * @param reply_block response to validate
 * @param reply_block_size number of bytes in reply block
 * @return characterization of result
 */
enum GNUNET_BLOCK_EvaluationResult
GNUNET_BLOCK_evaluate (struct GNUNET_BLOCK_Context *ctx,
                       enum GNUNET_BLOCK_Type type,
                       const GNUNET_HashCode * query,
                       struct GNUNET_CONTAINER_BloomFilter **bf,
                       int32_t bf_mutator, const void *xquery,
                       size_t xquery_size, const void *reply_block,
                       size_t reply_block_size);


/**
 * Function called to obtain the key for a block.
 *
 * @param ctx block context
 * @param type block type
 * @param block block to get the key for
 * @param block_size number of bytes in block
 * @param key set to the key (query) for the given block
 * @return GNUNET_YES on success,
 *         GNUNET_NO if the block is malformed
 *         GNUNET_SYSERR if type not supported
 *         (or if extracting a key from a block of this type does not work)
 */
int
GNUNET_BLOCK_get_key (struct GNUNET_BLOCK_Context *ctx,
                      enum GNUNET_BLOCK_Type type, const void *block,
                      size_t block_size, GNUNET_HashCode * key);



/**
 * Construct a bloom filter that would filter out the given
 * results.
 *
 * @param bf_mutator mutation value to use
 * @param seen_results results already seen
 * @param seen_results_count number of entries in 'seen_results'
 * @return NULL if seen_results_count is 0, otherwise a BF
 *         that would match the given results.
 */
struct GNUNET_CONTAINER_BloomFilter *
GNUNET_BLOCK_construct_bloomfilter (int32_t bf_mutator,
                                    const GNUNET_HashCode * seen_results,
                                    unsigned int seen_results_count);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


/* ifndef GNUNET_BLOCK_LIB_H */
#endif
/* end of gnunet_block_lib.h */
