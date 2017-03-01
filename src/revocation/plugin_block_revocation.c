/*
     This file is part of GNUnet
     Copyright (C) 2017 GNUnet e.V.

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
 * @file block/plugin_block_revocation.c
 * @brief revocation for a block plugin
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_signatures.h"
#include "gnunet_block_plugin.h"
#include "gnunet_block_group_lib.h"
#include "revocation.h"
#include "gnunet_revocation_service.h"

#define DEBUG_REVOCATION GNUNET_EXTRA_LOGGING

/**
 * Number of bits we set per entry in the bloomfilter.
 * Do not change!
 */
#define BLOOMFILTER_K 16


/**
 * How big is the BF we use for DHT blocks?
 */
#define REVOCATION_BF_SIZE 8


/**
 * Context used inside the plugin.
 */
struct InternalContext
{

  unsigned int matching_bits;

};


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
block_plugin_revocation_create_group (void *cls,
                                      enum GNUNET_BLOCK_Type type,
                                      uint32_t nonce,
                                      const void *raw_data,
                                      size_t raw_data_size,
                                      va_list va)
{
  unsigned int bf_size;
  const char *guard;

  guard = va_arg (va, const char *);
  if (0 == strcmp (guard,
                   "seen-set-size"))
    bf_size = GNUNET_BLOCK_GROUP_compute_bloomfilter_size (va_arg (va, unsigned int),
                                                           BLOOMFILTER_K);
  else if (0 == strcmp (guard,
                        "filter-size"))
    bf_size = va_arg (va, unsigned int);
  else
  {
    GNUNET_break (0);
    bf_size = REVOCATION_BF_SIZE;
  }
  GNUNET_break (NULL == va_arg (va, const char *));
  return GNUNET_BLOCK_GROUP_bf_create (cls,
                                       bf_size,
                                       BLOOMFILTER_K,
                                       type,
                                       nonce,
                                       raw_data,
                                       raw_data_size);
}


/**
 * Function called to validate a reply or a request.  For
 * request evaluation, simply pass "NULL" for the reply_block.
 *
 * @param cls our `struct InternalContext`
 * @param ctx context
 * @param type block type
 * @param group block group to use
 * @param eo control flags
 * @param query original query (hash)
 * @param xquery extrended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in xquery
 * @param reply_block response to validate
 * @param reply_block_size number of bytes in reply block
 * @return characterization of result
 */
static enum GNUNET_BLOCK_EvaluationResult
block_plugin_revocation_evaluate (void *cls,
                                  struct GNUNET_BLOCK_Context *ctx,
                                  enum GNUNET_BLOCK_Type type,
                                  struct GNUNET_BLOCK_Group *group,
                                  enum GNUNET_BLOCK_EvaluationOptions eo,
                                  const struct GNUNET_HashCode *query,
                                  const void *xquery,
                                  size_t xquery_size,
                                  const void *reply_block,
                                  size_t reply_block_size)
{
  struct InternalContext *ic = cls;
  struct GNUNET_HashCode chash;
  const struct RevokeMessage *rm = reply_block;

  if (NULL == reply_block)
    return GNUNET_BLOCK_EVALUATION_REQUEST_VALID;
  if (reply_block_size != sizeof (*rm))
  {
    GNUNET_break_op (0);
    return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
  }
  if (GNUNET_YES !=
      GNUNET_REVOCATION_check_pow (&rm->public_key,
                                   rm->proof_of_work,
                                   ic->matching_bits))
  {
    GNUNET_break_op (0);
    return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
  }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecdsa_verify (GNUNET_SIGNATURE_PURPOSE_REVOCATION,
                                  &rm->purpose,
                                  &rm->signature,
                                  &rm->public_key))
  {
    GNUNET_break_op (0);
    return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
  }
  GNUNET_CRYPTO_hash (&rm->public_key,
                      sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey),
                      &chash);
  if (GNUNET_YES ==
      GNUNET_BLOCK_GROUP_bf_test_and_set (group,
                                          &chash))
    return GNUNET_BLOCK_EVALUATION_OK_DUPLICATE;
  return GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED;
}


/**
 * Function called to obtain the key for a block.
 *
 * @param cls closure
 * @param type block type
 * @param block block to get the key for
 * @param block_size number of bytes in block
 * @param key set to the key (query) for the given block
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if type not supported
 *         (or if extracting a key from a block of this type does not work)
 */
static int
block_plugin_revocation_get_key (void *cls,
                                 enum GNUNET_BLOCK_Type type,
                                 const void *block,
                                 size_t block_size,
                                 struct GNUNET_HashCode *key)
{
  const struct RevokeMessage *rm = block;

  if (block_size != sizeof (*rm))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  GNUNET_CRYPTO_hash (&rm->public_key,
                      sizeof (struct GNUNET_CRYPTO_EcdsaPublicKey),
                      key);
  return GNUNET_OK;
}


/**
 * Entry point for the plugin.
 *
 * @param cls the configuration to use
 */
void *
libgnunet_plugin_block_revocation_init (void *cls)
{
  static enum GNUNET_BLOCK_Type types[] =
  {
    GNUNET_BLOCK_TYPE_REVOCATION,
    GNUNET_BLOCK_TYPE_ANY       /* end of list */
  };
  const struct GNUNET_CONFIGURATION_Handle *cfg = cls;
  struct GNUNET_BLOCK_PluginFunctions *api;
  struct InternalContext *ic;
  unsigned long long matching_bits;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (cfg,
                                             "REVOCATION",
                                             "WORKBITS",
                                             &matching_bits))
    return NULL;

  api = GNUNET_new (struct GNUNET_BLOCK_PluginFunctions);
  api->evaluate = &block_plugin_revocation_evaluate;
  api->get_key = &block_plugin_revocation_get_key;
  api->create_group = &block_plugin_revocation_create_group;
  api->types = types;
  ic = GNUNET_new (struct InternalContext);
  ic->matching_bits = (unsigned int) matching_bits;
  api->cls = ic;
  return api;
}


/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_block_revocation_done (void *cls)
{
  struct GNUNET_BLOCK_PluginFunctions *api = cls;
  struct InternalContext *ic = api->cls;

  GNUNET_free (ic);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_block_revocation.c */
