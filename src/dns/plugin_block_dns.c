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
 * @file dns/plugin_block_dns.c
 * @brief block plugin for storing .gnunet-bindings
 * @author Philipp Tölke
 */

#include "platform.h"
#include "gnunet_block_plugin.h"
#include "block_dns.h"
#include "gnunet_signatures.h"

#define DEBUG_DHT GNUNET_EXTRA_LOGGING

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
 * @param xquery_size number of bytes in xquery
 * @param reply_block response to validate
 * @param reply_block_size number of bytes in reply block
 * @return characterization of result
 */
static enum GNUNET_BLOCK_EvaluationResult
block_plugin_dns_evaluate (void *cls, enum GNUNET_BLOCK_Type type,
                           const GNUNET_HashCode * query,
                           struct GNUNET_CONTAINER_BloomFilter **bf,
                           int32_t bf_mutator, const void *xquery,
                           size_t xquery_size, const void *reply_block,
                           size_t reply_block_size)
{
  switch (type)
  {
  case GNUNET_BLOCK_TYPE_DNS:
    if (xquery_size != 0)
      return GNUNET_BLOCK_EVALUATION_REQUEST_INVALID;

    if (reply_block_size == 0)
      return GNUNET_BLOCK_EVALUATION_REQUEST_VALID;

    if (reply_block_size != sizeof (struct GNUNET_DNS_Record))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "DNS-Block is invalid: reply_block_size=%d != %d\n",
                  reply_block_size, sizeof (struct GNUNET_DNS_Record));
      return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
    }

    const struct GNUNET_DNS_Record *rec = reply_block;

    if (ntohl (rec->purpose.size) !=
        sizeof (struct GNUNET_DNS_Record) -
        sizeof (struct GNUNET_CRYPTO_RsaSignature))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "DNS-Block is invalid: rec->purpose.size=%d != %d\n",
                  ntohl (rec->purpose.size),
                  sizeof (struct GNUNET_DNS_Record) -
                  sizeof (struct GNUNET_CRYPTO_RsaSignature));
      return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
    }

    if (GNUNET_TIME_relative_get_zero ().rel_value ==
        GNUNET_TIME_absolute_get_remaining (GNUNET_TIME_absolute_ntoh
                                            (rec->expiration_time)).rel_value)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "DNS-Block is invalid: Timeout\n");
      return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
    }

    if (GNUNET_OK !=
        GNUNET_CRYPTO_rsa_verify (htonl (GNUNET_SIGNATURE_PURPOSE_DNS_RECORD),
                                  &rec->purpose, &rec->signature, &rec->peer))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "DNS-Block is invalid: invalid signature\n");
      return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
    }

    /* How to decide whether there are no more? */
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
block_plugin_dns_get_key (void *cls, enum GNUNET_BLOCK_Type type,
                          const void *block, size_t block_size,
                          GNUNET_HashCode * key)
{
  if (type != GNUNET_BLOCK_TYPE_DNS)
    return GNUNET_SYSERR;
  const struct GNUNET_DNS_Record *rec = block;

  memcpy (key, &rec->service_descriptor, sizeof (GNUNET_HashCode));
  return GNUNET_OK;
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

  api = GNUNET_malloc (sizeof (struct GNUNET_BLOCK_PluginFunctions));
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
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}

/* end of plugin_block_dns.c */
