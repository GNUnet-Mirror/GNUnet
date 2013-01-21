/*
     This file is part of GNUnet
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
 * @file mesh/plugin_block_mesh.c
 * @brief blocks used for mesh peer discovery
 * @author Bartlomiej Polot
 */

#include "platform.h"
#include "gnunet_block_plugin.h"
#include "block_mesh.h"

/**
 * Number of bits we set per entry in the bloomfilter.
 * Do not change!
 */
#define BLOOMFILTER_K 16


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
static enum GNUNET_BLOCK_EvaluationResult
block_plugin_mesh_evaluate (void *cls, enum GNUNET_BLOCK_Type type,
                            const struct GNUNET_HashCode * query,
                            struct GNUNET_CONTAINER_BloomFilter **bf,
                            int32_t bf_mutator, const void *xquery,
                            size_t xquery_size, const void *reply_block,
                            size_t reply_block_size)
{
  struct GNUNET_HashCode chash;
  struct GNUNET_HashCode mhash;

  switch (type)
  {
    case GNUNET_BLOCK_TYPE_MESH_PEER:
      if (0 != xquery_size)
      {
        GNUNET_break_op (0);
        return GNUNET_BLOCK_EVALUATION_REQUEST_INVALID;
      }
      if (NULL == reply_block)
        return GNUNET_BLOCK_EVALUATION_REQUEST_VALID;
      if (sizeof (struct PBlock) != reply_block_size)  
        return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;  
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

      return GNUNET_BLOCK_EVALUATION_OK_LAST;


    case GNUNET_BLOCK_TYPE_MESH_PEER_BY_TYPE:
      /* FIXME: have an xquery? not sure */
      if (0 != xquery_size)
      {
        GNUNET_break_op (0);
        return GNUNET_BLOCK_EVALUATION_REQUEST_INVALID;
      }
      if (NULL == reply_block)
        return GNUNET_BLOCK_EVALUATION_REQUEST_VALID;
      if (sizeof (struct PBlock) != reply_block_size)
      {
        GNUNET_break_op(0);
        return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
      }
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

    default:
      return GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED;
  }
}


/**
 * Function called to obtain the key for a block.
 *
 * @param cls closure
 * @param type block type
 * @param block block to get the key for
 * @param block_size number of bytes in block
 * @param key set to the key (query) for the given block
 * @return GNUNET_OK on success, GNUNET_SYSERR if type not supported
 *         (or if extracting a key from a block of this type does not work)
 */
static int
block_plugin_mesh_get_key (void *cls, enum GNUNET_BLOCK_Type type,
                           const void *block, size_t block_size,
                           struct GNUNET_HashCode * key)
{
  const struct PBlock *pb;
  pb = block;

  switch (type)
  {
  case GNUNET_BLOCK_TYPE_MESH_PEER:
    if (sizeof (struct PBlock) != block_size)
      return GNUNET_SYSERR;
    *key = pb->id.hashPubKey;
    return GNUNET_OK;
  case GNUNET_BLOCK_TYPE_MESH_PEER_BY_TYPE:
    GNUNET_CRYPTO_hash (&pb->type, sizeof(GNUNET_MESH_ApplicationType), key);
    return GNUNET_OK;
  default:
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
}


/**
 * Entry point for the plugin.
 */
void *
libgnunet_plugin_block_mesh_init (void *cls)
{
  static enum GNUNET_BLOCK_Type types[] =
  {
    GNUNET_BLOCK_TYPE_MESH_PEER,
    GNUNET_BLOCK_TYPE_MESH_PEER_BY_TYPE,
    GNUNET_BLOCK_TYPE_ANY       /* end of list */
  };
  struct GNUNET_BLOCK_PluginFunctions *api;

  api = GNUNET_malloc (sizeof (struct GNUNET_BLOCK_PluginFunctions));
  api->evaluate = &block_plugin_mesh_evaluate;
  api->get_key = &block_plugin_mesh_get_key;
  api->types = types;
  return api;
}


/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_block_mesh_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}

/* end of plugin_block_mesh.c */
