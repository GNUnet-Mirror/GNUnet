/*
     This file is part of GNUnet
     Copyright (C) 2010 Christian Grothoff (and other contributing authors)

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
 * @file block/plugin_block_test.c
 * @brief block plugin to test the DHT as a simple key-value store;
 *        this plugin simply accepts any (new) response for any key
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_block_plugin.h"


/**
 * Number of bits we set per entry in the bloomfilter.
 * Do not change!
 */
#define BLOOMFILTER_K 16

/**
 * Function called to validate a reply or a request.  For
 * request evaluation, simply pass "NULL" for the reply_block.
 *
 * @param cls closure
 * @param type block type
 * @param eo control flags
 * @param query original query (hash)
 * @param bf pointer to bloom filter associated with query; possibly updated (!)
 * @param bf_mutator mutation value for @a bf
 * @param xquery extrended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in @a xquery
 * @param reply_block response to validate
 * @param reply_block_size number of bytes in @a reply_block
 * @return characterization of result
 */
static enum GNUNET_BLOCK_EvaluationResult
block_plugin_test_evaluate (void *cls,
                            enum GNUNET_BLOCK_Type type,
                            enum GNUNET_BLOCK_EvaluationOptions eo,
                            const struct GNUNET_HashCode *query,
                            struct GNUNET_CONTAINER_BloomFilter **bf,
                            int32_t bf_mutator,
                            const void *xquery,
                            size_t xquery_size,
                            const void *reply_block,
                            size_t reply_block_size)
{
  struct GNUNET_HashCode chash;
  struct GNUNET_HashCode mhash;

  if ( GNUNET_BLOCK_TYPE_TEST != type)
    return GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED;
  if (0 != xquery_size)
  {
    GNUNET_break_op (0);
    return GNUNET_BLOCK_EVALUATION_REQUEST_INVALID;
  }
  if (NULL == reply_block)
    return GNUNET_BLOCK_EVALUATION_REQUEST_VALID;

  if (NULL != bf)
  {
    GNUNET_CRYPTO_hash (reply_block, reply_block_size, &chash);
    GNUNET_BLOCK_mingle_hash (&chash, bf_mutator, &mhash);
    if (NULL != *bf)
    {
      if (GNUNET_YES == GNUNET_CONTAINER_bloomfilter_test (*bf, &mhash))
        return GNUNET_BLOCK_EVALUATION_OK_DUPLICATE;
    }
    else
    {
      *bf = GNUNET_CONTAINER_bloomfilter_init (NULL, 8, BLOOMFILTER_K);
    }
    GNUNET_CONTAINER_bloomfilter_add (*bf, &mhash);
  }
  return GNUNET_BLOCK_EVALUATION_OK_MORE;
}


/**
 * Function called to obtain the key for a block.
 *
 * @param cls closure
 * @param type block type
 * @param block block to get the key for
 * @param block_size number of bytes in @a block
 * @param key set to the key (query) for the given block
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if type not supported
 *         (or if extracting a key from a block of this type does not work)
 */
static int
block_plugin_test_get_key (void *cls, enum GNUNET_BLOCK_Type type,
                           const void *block, size_t block_size,
                           struct GNUNET_HashCode * key)
{
  /* always fails since there is no fixed relationship between
   * keys and values for test values */
  return GNUNET_SYSERR;
}


/**
 * Entry point for the plugin.
 *
 * @param cls NULL
 * @return the exported block API
 */
void *
libgnunet_plugin_block_test_init (void *cls)
{
  static enum GNUNET_BLOCK_Type types[] =
  {
    GNUNET_BLOCK_TYPE_TEST,
    GNUNET_BLOCK_TYPE_ANY       /* end of list */
  };
  struct GNUNET_BLOCK_PluginFunctions *api;

  api = GNUNET_new (struct GNUNET_BLOCK_PluginFunctions);
  api->evaluate = &block_plugin_test_evaluate;
  api->get_key = &block_plugin_test_get_key;
  api->types = types;
  return api;
}


/**
 * Exit point from the plugin.
 *
 * @param cls the return value from #libgnunet_plugin_block_test_init
 * @return NULL
 */
void *
libgnunet_plugin_block_test_done (void *cls)
{
  struct GNUNET_BLOCK_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}

/* end of plugin_block_test.c */
