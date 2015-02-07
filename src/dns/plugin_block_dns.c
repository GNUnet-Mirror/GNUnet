/*
     This file is part of GNUnet
     Copyright (C) 2013 Christian Grothoff (and other contributing authors)

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
 * @file dns/plugin_block_dns.c
 * @brief block plugin for advertising a DNS exit service
 * @author Christian Grothoff
 *
 * Note that this plugin might more belong with EXIT and PT
 * as those two are using this type of block.  Still, this
 * might be a natural enough place for people to find the code...
 */
#include "platform.h"
#include "gnunet_block_plugin.h"
#include "block_dns.h"
#include "gnunet_signatures.h"


/**
 * Function called to validate a reply or a request.  For
 * request evaluation, simply pass "NULL" for the reply_block.
 *
 * @param cls closure
 * @param type block type
 * @param query original query (hash)
 * @param bf pointer to bloom filter associated with query; possibly updated (!)
 * @param bf_mutator mutation value for bf
 * @param xquery extended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in @a xquery
 * @param reply_block response to validate
 * @param reply_block_size number of bytes in @a reply_block
 * @return characterization of result
 */
static enum GNUNET_BLOCK_EvaluationResult
block_plugin_dns_evaluate (void *cls, enum GNUNET_BLOCK_Type type,
                           const struct GNUNET_HashCode * query,
                           struct GNUNET_CONTAINER_BloomFilter **bf,
                           int32_t bf_mutator, const void *xquery,
                           size_t xquery_size, const void *reply_block,
                           size_t reply_block_size)
{
  const struct GNUNET_DNS_Advertisement *ad;

  switch (type)
  {
  case GNUNET_BLOCK_TYPE_DNS:
    if (0 != xquery_size)
      return GNUNET_BLOCK_EVALUATION_REQUEST_INVALID;

    if (0 == reply_block_size)
      return GNUNET_BLOCK_EVALUATION_REQUEST_VALID;

    if (sizeof (struct GNUNET_DNS_Advertisement) != reply_block_size)
    {
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
    }
    ad = reply_block;

    if (ntohl (ad->purpose.size) !=
        sizeof (struct GNUNET_DNS_Advertisement) -
        sizeof (struct GNUNET_CRYPTO_EddsaSignature))
    {
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
    }
    if (0 ==
        GNUNET_TIME_absolute_get_remaining (GNUNET_TIME_absolute_ntoh
                                            (ad->expiration_time)).rel_value_us)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "DNS advertisement has expired\n");
      return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
    }
    if (GNUNET_OK !=
        GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_PURPOSE_DNS_RECORD,
				  &ad->purpose,
				  &ad->signature,
				  &ad->peer.public_key))
    {
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
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
 * @param block_size number of bytes in @a block
 * @param key set to the key (query) for the given block
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if type not supported
 *         (or if extracting a key from a block of this type does not work)
 */
static int
block_plugin_dns_get_key (void *cls,
			  enum GNUNET_BLOCK_Type type,
                          const void *block,
			  size_t block_size,
                          struct GNUNET_HashCode *key)
{
  /* we cannot extract a key from a block of this type */
  return GNUNET_SYSERR;
}


/**
 * Entry point for the plugin.
 */
void *
libgnunet_plugin_block_dns_init (void *cls)
{
  static enum GNUNET_BLOCK_Type types[] =
  {
    GNUNET_BLOCK_TYPE_DNS,
    GNUNET_BLOCK_TYPE_ANY       /* end of list */
  };
  struct GNUNET_BLOCK_PluginFunctions *api;

  api = GNUNET_new (struct GNUNET_BLOCK_PluginFunctions);
  api->evaluate = &block_plugin_dns_evaluate;
  api->get_key = &block_plugin_dns_get_key;
  api->types = types;
  return api;
}


/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_block_dns_done (void *cls)
{
  struct GNUNET_BLOCK_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}

/* end of plugin_block_dns.c */
