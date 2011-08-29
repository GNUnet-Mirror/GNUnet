/*
     This file is part of GNUnet
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
 * @file include/gnunet_block_plugin.h
 * @brief API for block plugins.  Each block plugin must conform to
 *        the API specified by this header.
 * @author Christian Grothoff
 */
#ifndef PLUGIN_BLOCK_H
#define PLUGIN_BLOCK_H

#include "gnunet_util_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_block_lib.h"


/**
 * Function called to validate a reply or a request.  For
 * request evaluation, simply pass "NULL" for the reply_block.
 * Note that it is assumed that the reply has already been
 * matched to the key (and signatures checked) as it would
 * be done with the "get_key" function.
 *
 * @param cls closure
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
typedef enum
    GNUNET_BLOCK_EvaluationResult (*GNUNET_BLOCK_EvaluationFunction) (void *cls,
                                                                      enum
                                                                      GNUNET_BLOCK_Type
                                                                      type,
                                                                      const
                                                                      GNUNET_HashCode
                                                                      * query,
                                                                      struct
                                                                      GNUNET_CONTAINER_BloomFilter
                                                                      ** bf,
                                                                      int32_t
                                                                      bf_mutator,
                                                                      const void
                                                                      *xquery,
                                                                      size_t
                                                                      xquery_size,
                                                                      const void
                                                                      *reply_block,
                                                                      size_t
                                                                      reply_block_size);


/**
 * Function called to obtain the key for a block.
 *
 * @param cls closure
 * @param type block type
 * @param block block to get the key for
 * @param block_size number of bytes in block
 * @param key set to the key (query) for the given block
 * @return GNUNET_YES on success,
 *         GNUNET_NO if the block is malformed
 *         GNUNET_SYSERR if type not supported
 *         (or if extracting a key from a block of this type does not work)
 */
typedef int (*GNUNET_BLOCK_GetKeyFunction) (void *cls,
                                            enum GNUNET_BLOCK_Type type,
                                            const void *block,
                                            size_t block_size,
                                            GNUNET_HashCode * key);



/**
 * Each plugin is required to return a pointer to a struct of this
 * type as the return value from its entry point.
 */
struct GNUNET_BLOCK_PluginFunctions
{

  /**
   * Closure for all of the callbacks.
   */
  void *cls;

  /**
   * 0-terminated array of block types supported by this plugin.
   */
  const enum GNUNET_BLOCK_Type *types;

  /**
   * Main function of a block plugin.  Allows us to check if a
   * block matches a query.
   */
  GNUNET_BLOCK_EvaluationFunction evaluate;

  /**
   * Obtain the key for a given block (if possible).
   */
  GNUNET_BLOCK_GetKeyFunction get_key;

};


#endif
