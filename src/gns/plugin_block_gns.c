/*
     This file is part of GNUnet
     Copyright (C) 2010-2013 Christian Grothoff (and other contributing authors)

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
 * @file gns/plugin_block_gns.c
 * @brief blocks used for GNS records
 * @author Martin Schanzenbach
 */

#include "platform.h"
#include "gnunet_block_plugin.h"
#include "gnunet_namestore_service.h"
#include "gnunet_signatures.h"

/**
 * Number of bits we set per entry in the bloomfilter.
 * Do not change! -from fs
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
 * @param eo control flags
 * @param query original query (hash)
 * @param bf pointer to bloom filter associated with @a query; possibly updated (!)
 * @param bf_mutator mutation value for @a bf
 * @param xquery extrended query data (can be NULL, depending on @a type)
 * @param xquery_size number of bytes in @a xquery
 * @param reply_block response to validate
 * @param reply_block_size number of bytes in @a reply_block
 * @return characterization of result
 */
static enum GNUNET_BLOCK_EvaluationResult
block_plugin_gns_evaluate (void *cls,
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
  const struct GNUNET_GNSRECORD_Block *block;
  struct GNUNET_HashCode h;
  struct GNUNET_HashCode chash;
  struct GNUNET_HashCode mhash;

  if (type != GNUNET_BLOCK_TYPE_GNS_NAMERECORD)
    return GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED;
  if (NULL == reply_block)
  {
    if (0 != xquery_size)
    {
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_REQUEST_INVALID;
    }
    return GNUNET_BLOCK_EVALUATION_REQUEST_VALID;
  }

  /* this is a reply */
  if (reply_block_size < sizeof (struct GNUNET_GNSRECORD_Block))
    {
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
    }
  block = reply_block;
  if (ntohl (block->purpose.size) + sizeof (struct GNUNET_CRYPTO_EcdsaSignature) + sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey) !=
      reply_block_size)
    {
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
    }
  GNUNET_CRYPTO_hash (&block->derived_key,
		      sizeof (block->derived_key),
		      &h);
  if (0 != memcmp (&h, query, sizeof (struct GNUNET_HashCode)))
    {
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
    }
  if (GNUNET_OK !=
      GNUNET_GNSRECORD_block_verify (block))
    {
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
    }
  if (NULL != bf)
    {
      GNUNET_CRYPTO_hash (reply_block, reply_block_size, &chash);
      GNUNET_BLOCK_mingle_hash (&chash, bf_mutator, &mhash);
      if (NULL != *bf)
	{
	  if (GNUNET_YES == GNUNET_CONTAINER_bloomfilter_test(*bf, &mhash))
	    return GNUNET_BLOCK_EVALUATION_OK_DUPLICATE;
	}
      else
	{
	  *bf = GNUNET_CONTAINER_bloomfilter_init(NULL, 8, BLOOMFILTER_K);
	}
      GNUNET_CONTAINER_bloomfilter_add(*bf, &mhash);
    }
  return GNUNET_BLOCK_EVALUATION_OK_MORE;
}


/**
 * Function called to obtain the key for a block.
 *
 * @param cls closure
 * @param type block type
 * @param reply_block block to get the key for
 * @param reply_block_size number of bytes in @a reply_block
 * @param key set to the key (query) for the given block
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if type not supported
 *         (or if extracting a key from a block of this type does not work)
 */
static int
block_plugin_gns_get_key (void *cls, enum GNUNET_BLOCK_Type type,
                         const void *reply_block, size_t reply_block_size,
                         struct GNUNET_HashCode *key)
{
  const struct GNUNET_GNSRECORD_Block *block;

  if (type != GNUNET_BLOCK_TYPE_GNS_NAMERECORD)
    return GNUNET_SYSERR;
  if (reply_block_size < sizeof (struct GNUNET_GNSRECORD_Block))
    {
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
    }
  block = reply_block;
  GNUNET_CRYPTO_hash (&block->derived_key,
		      sizeof (block->derived_key),
		      key);
  return GNUNET_OK;
}


/**
 * Entry point for the plugin.
 */
void *
libgnunet_plugin_block_gns_init (void *cls)
{
  static enum GNUNET_BLOCK_Type types[] =
  {
    GNUNET_BLOCK_TYPE_GNS_NAMERECORD,
    GNUNET_BLOCK_TYPE_ANY       /* end of list */
  };
  struct GNUNET_BLOCK_PluginFunctions *api;

  api = GNUNET_new (struct GNUNET_BLOCK_PluginFunctions);
  api->evaluate = &block_plugin_gns_evaluate;
  api->get_key = &block_plugin_gns_get_key;
  api->types = types;
  return api;
}


/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_block_gns_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}

/* end of plugin_block_gns.c */
