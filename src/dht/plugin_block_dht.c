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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
*/

/**
 * @file dht/plugin_block_dht.c
 * @brief block plugin for DHT internals (right now, find-peer requests only);
 *        other plugins should be used to store "useful" data in the
 *        DHT (see fs block plugin)
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_hello_lib.h"
#include "gnunet_block_plugin.h"

#define DEBUG_DHT GNUNET_EXTRA_LOGGING


/**
 * Function called to validate a reply or a request.  For
 * request evaluation, simply pass "NULL" for the @a reply_block.
 *
 * @param cls closure
 * @param type block type
 * @param eo control flags
 * @param query original query (hash)
 * @param bf pointer to bloom filter associated with query; possibly updated (!)
 * @param bf_mutator mutation value for @a bf
 * @param xquery extended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in @a xquery
 * @param reply_block response to validate
 * @param reply_block_size number of bytes in @a reply_block
 * @return characterization of result
 */
static enum GNUNET_BLOCK_EvaluationResult
block_plugin_dht_evaluate (void *cls,
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
  struct GNUNET_HashCode mhash;
  const struct GNUNET_HELLO_Message *hello;
  struct GNUNET_PeerIdentity pid;
  const struct GNUNET_MessageHeader *msg;
  struct GNUNET_HashCode phash;

  if (type != GNUNET_BLOCK_TYPE_DHT_HELLO)
    return GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED;
  if (xquery_size != 0)
  {
    GNUNET_break_op (0);
    return GNUNET_BLOCK_EVALUATION_REQUEST_INVALID;
  }
  if (NULL == reply_block)
    return GNUNET_BLOCK_EVALUATION_REQUEST_VALID;
  if (reply_block_size < sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
  }
  msg = reply_block;
  if (reply_block_size != ntohs (msg->size))
  {
    GNUNET_break_op (0);
    return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
  }
  hello = reply_block;
  if (GNUNET_OK != GNUNET_HELLO_get_id (hello, &pid))
  {
    GNUNET_break_op (0);
    return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
  }
  if (NULL != bf)
  {
    GNUNET_CRYPTO_hash (&pid, sizeof (pid), &phash);
    GNUNET_BLOCK_mingle_hash (&phash, bf_mutator, &mhash);
    if (NULL != *bf)
    {
      if (GNUNET_YES == GNUNET_CONTAINER_bloomfilter_test (*bf, &mhash))
        return GNUNET_BLOCK_EVALUATION_OK_DUPLICATE;
    }
    else
    {
      *bf = GNUNET_CONTAINER_bloomfilter_init (NULL, 8,
                                               GNUNET_CONSTANTS_BLOOMFILTER_K);
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
 * @param block_size number of bytes @a block
 * @param key set to the key (query) for the given block
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if type not supported
 *         (or if extracting a key from a block of this type does not work)
 */
static int
block_plugin_dht_get_key (void *cls, enum GNUNET_BLOCK_Type type,
                          const void *block, size_t block_size,
                          struct GNUNET_HashCode * key)
{
  const struct GNUNET_MessageHeader *msg;
  const struct GNUNET_HELLO_Message *hello;
  struct GNUNET_PeerIdentity *pid;

  if (type != GNUNET_BLOCK_TYPE_DHT_HELLO)
    return GNUNET_SYSERR;
  if (block_size < sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "block-dht",
                     _("Block not of type %u\n"), GNUNET_BLOCK_TYPE_DHT_HELLO);
    return GNUNET_NO;
  }
  msg = block;
  if (block_size != ntohs (msg->size))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "block-dht",
                     _("Size mismatch for block\n"),
                     GNUNET_BLOCK_TYPE_DHT_HELLO);
    return GNUNET_NO;
  }
  hello = block;
  memset (key, 0, sizeof (*key));
  pid = (struct GNUNET_PeerIdentity *) key;
  if (GNUNET_OK != GNUNET_HELLO_get_id (hello, pid))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "block-dht",
                     _("Block of type %u is malformed\n"),
                     GNUNET_BLOCK_TYPE_DHT_HELLO);
    return GNUNET_NO;
  }
  return GNUNET_OK;
}


/**
 * Entry point for the plugin.
 */
void *
libgnunet_plugin_block_dht_init (void *cls)
{
  static enum GNUNET_BLOCK_Type types[] =
  {
    GNUNET_BLOCK_TYPE_DHT_HELLO,
    GNUNET_BLOCK_TYPE_ANY       /* end of list */
  };
  struct GNUNET_BLOCK_PluginFunctions *api;

  api = GNUNET_new (struct GNUNET_BLOCK_PluginFunctions);
  api->evaluate = &block_plugin_dht_evaluate;
  api->get_key = &block_plugin_dht_get_key;
  api->types = types;
  return api;
}


/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_block_dht_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}

/* end of plugin_block_dht.c */
