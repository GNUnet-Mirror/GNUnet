/*
     This file is part of GNUnet
     Copyright (C) 2010-2013 GNUnet e.V.

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
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_block_group_lib.h"
#include "gnunet_block_plugin.h"
#include "gnunet_namestore_service.h"
#include "gnunet_signatures.h"

/**
 * Number of bits we set per entry in the bloomfilter.
 * Do not change! -from fs
 */
#define BLOOMFILTER_K 16

/**
 * How big is the BF we use for GNS blocks?
 */
#define GNS_BF_SIZE 8


/**
 * Create a new block group.
 *
 * @param ctx block context in which the block group is created
 * @param type type of the block for which we are creating the group
 * @param nonce random value used to seed the group creation
 * @param raw_data optional serialized prior state of the group, NULL if unavailable/fresh
 * @param raw_data_size number of bytes in @a raw_data, 0 if unavailable/fresh
 * @param va variable arguments specific to @a type
 * @return block group handle, NULL if block groups are not supported
 *         by this @a type of block (this is not an error)
 */
static struct GNUNET_BLOCK_Group *
block_plugin_gns_create_group (void *cls,
                               enum GNUNET_BLOCK_Type type,
                               uint32_t nonce,
                               const void *raw_data,
                               size_t raw_data_size,
                               va_list va)
{
  return GNUNET_BLOCK_GROUP_bf_create (cls,
                                       GNS_BF_SIZE,
                                       BLOOMFILTER_K,
                                       type,
                                       nonce,
                                       raw_data,
                                       raw_data_size);
}


/**
 * Function called to validate a reply or a request.  For
 * request evaluation, simply pass "NULL" for the reply_block.
 * Note that it is assumed that the reply has already been
 * matched to the key (and signatures checked) as it would
 * be done with the "get_key" function.
 *
 * @param cls closure
 * @param type block type
 * @param bg block group to use for evaluation
 * @param eo control flags
 * @param query original query (hash)
 * @param xquery extrended query data (can be NULL, depending on @a type)
 * @param xquery_size number of bytes in @a xquery
 * @param reply_block response to validate
 * @param reply_block_size number of bytes in @a reply_block
 * @return characterization of result
 */
static enum GNUNET_BLOCK_EvaluationResult
block_plugin_gns_evaluate (void *cls,
                           enum GNUNET_BLOCK_Type type,
                           struct GNUNET_BLOCK_Group *bg,
                           enum GNUNET_BLOCK_EvaluationOptions eo,
                           const struct GNUNET_HashCode *query,
                           const void *xquery,
                           size_t xquery_size,
                           const void *reply_block,
                           size_t reply_block_size)
{
  const struct GNUNET_GNSRECORD_Block *block;
  struct GNUNET_HashCode h;
  struct GNUNET_HashCode chash;

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
  GNUNET_CRYPTO_hash (reply_block,
                      reply_block_size,
                      &chash);
  if (GNUNET_YES ==
      GNUNET_BLOCK_GROUP_bf_test_and_set (bg,
                                          &chash))
    return GNUNET_BLOCK_EVALUATION_OK_DUPLICATE;
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
block_plugin_gns_get_key (void *cls,
                          enum GNUNET_BLOCK_Type type,
                          const void *reply_block,
                          size_t reply_block_size,
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
  api->create_group = &block_plugin_gns_create_group;
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
