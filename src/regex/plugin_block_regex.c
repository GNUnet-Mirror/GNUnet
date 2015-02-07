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
 * @file regex/plugin_block_regex.c
 * @brief blocks used for regex storage and search
 * @author Bartlomiej Polot
 */

#include "platform.h"
#include "gnunet_block_plugin.h"
#include "block_regex.h"
#include "regex_block_lib.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"


/**
 * Function called to validate a reply or a request of type
 * GNUNET_BLOCK_TYPE_REGEX.
 * For request evaluation, pass "NULL" for the reply_block.
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
evaluate_block_regex (void *cls, enum GNUNET_BLOCK_Type type,
                      const struct GNUNET_HashCode *query,
                      struct GNUNET_CONTAINER_BloomFilter **bf,
                      int32_t bf_mutator, const void *xquery,
                      size_t xquery_size, const void *reply_block,
                      size_t reply_block_size)
{
  if (NULL == reply_block)
  {
    if (0 != xquery_size)
      {
        const char *s;

        s = (const char *) xquery;
        if ('\0' != s[xquery_size - 1]) /* must be valid 0-terminated string */
          {
            GNUNET_break_op (0);
            return GNUNET_BLOCK_EVALUATION_REQUEST_INVALID;
          }
      }
    return GNUNET_BLOCK_EVALUATION_REQUEST_VALID;
  }
  if (0 != xquery_size)
  {
    const char *s;

    s = (const char *) xquery;
    if ('\0' != s[xquery_size - 1]) /* must be valid 0-terminated string */
    {
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_REQUEST_INVALID;
    }
  }
  else if (NULL != query)
  {
    /* xquery is required for regex GETs, at least an empty string */
    GNUNET_break_op (0);
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "type %d, query %p, xquery %p\n",
                type, query, xquery);
    return GNUNET_BLOCK_EVALUATION_REQUEST_INVALID;
  }
  switch (REGEX_BLOCK_check (reply_block,
			     reply_block_size,
			     query,
			     xquery))
  {
    case GNUNET_SYSERR:
      GNUNET_break_op(0);
      return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
    case GNUNET_NO:
      /* xquery missmatch, can happen */
      return GNUNET_BLOCK_EVALUATION_RESULT_IRRELEVANT;
    default:
      break;
  }
  if (NULL != bf)
  {
    struct GNUNET_HashCode chash;
    struct GNUNET_HashCode mhash;

    GNUNET_CRYPTO_hash (reply_block, reply_block_size, &chash);
    GNUNET_BLOCK_mingle_hash (&chash, bf_mutator, &mhash);
    if (NULL != *bf)
    {
      if (GNUNET_YES == GNUNET_CONTAINER_bloomfilter_test (*bf, &mhash))
        return GNUNET_BLOCK_EVALUATION_OK_DUPLICATE;
    }
    else
    {
      *bf = GNUNET_CONTAINER_bloomfilter_init (NULL, 8, GNUNET_CONSTANTS_BLOOMFILTER_K);
    }
    GNUNET_CONTAINER_bloomfilter_add (*bf, &mhash);
  }
  return GNUNET_BLOCK_EVALUATION_OK_MORE;
}


/**
 * Function called to validate a reply or a request of type
 * GNUNET_BLOCK_TYPE_REGEX_ACCEPT.
 * For request evaluation, pass "NULL" for the reply_block.
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
evaluate_block_regex_accept (void *cls, enum GNUNET_BLOCK_Type type,
                             const struct GNUNET_HashCode * query,
                             struct GNUNET_CONTAINER_BloomFilter **bf,
                             int32_t bf_mutator, const void *xquery,
                             size_t xquery_size, const void *reply_block,
                             size_t reply_block_size)
{
  const struct RegexAcceptBlock *rba;

  if (0 != xquery_size)
  {
    GNUNET_break_op (0);
    return GNUNET_BLOCK_EVALUATION_REQUEST_INVALID;
  }
  if (NULL == reply_block)
    return GNUNET_BLOCK_EVALUATION_REQUEST_VALID;
  if (sizeof (struct RegexAcceptBlock) != reply_block_size)
  {
    GNUNET_break_op(0);
    return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
  }
  rba = reply_block;
  if (ntohl (rba->purpose.size) !=
      sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
      sizeof (struct GNUNET_TIME_AbsoluteNBO) +
      sizeof (struct GNUNET_HashCode))
  {
    GNUNET_break_op(0);
    return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
  }
  if (0 == GNUNET_TIME_absolute_get_remaining (GNUNET_TIME_absolute_ntoh (rba->expiration_time)).rel_value_us)
  {
    /* technically invalid, but can happen without an error, so
       we're nice by reporting it as a 'duplicate' */
    return GNUNET_BLOCK_EVALUATION_OK_DUPLICATE;
  }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_PURPOSE_REGEX_ACCEPT,
				&rba->purpose,
				&rba->signature,
				&rba->peer.public_key))
  {
    GNUNET_break_op(0);
    return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
  }
  if (NULL != bf)
  {
    struct GNUNET_HashCode chash;
    struct GNUNET_HashCode mhash;

    GNUNET_CRYPTO_hash (reply_block, reply_block_size, &chash);
    GNUNET_BLOCK_mingle_hash (&chash, bf_mutator, &mhash);
    if (NULL != *bf)
    {
      if (GNUNET_YES == GNUNET_CONTAINER_bloomfilter_test (*bf, &mhash))
        return GNUNET_BLOCK_EVALUATION_OK_DUPLICATE;
    }
    else
    {
      *bf = GNUNET_CONTAINER_bloomfilter_init (NULL, 8, GNUNET_CONSTANTS_BLOOMFILTER_K);
    }
    GNUNET_CONTAINER_bloomfilter_add (*bf, &mhash);
  }
  return GNUNET_BLOCK_EVALUATION_OK_MORE;
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
block_plugin_regex_evaluate (void *cls, enum GNUNET_BLOCK_Type type,
                             const struct GNUNET_HashCode * query,
                             struct GNUNET_CONTAINER_BloomFilter **bf,
                             int32_t bf_mutator, const void *xquery,
                             size_t xquery_size, const void *reply_block,
                             size_t reply_block_size)
{
  enum GNUNET_BLOCK_EvaluationResult result;

  switch (type)
  {
    case GNUNET_BLOCK_TYPE_REGEX:
      result = evaluate_block_regex (cls, type, query, bf, bf_mutator,
                                     xquery, xquery_size,
                                     reply_block, reply_block_size);
      break;
    case GNUNET_BLOCK_TYPE_REGEX_ACCEPT:
      result = evaluate_block_regex_accept (cls, type, query, bf, bf_mutator,
                                            xquery, xquery_size,
                                            reply_block, reply_block_size);
      break;

    default:
      result = GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED;
  }
  return result;
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
block_plugin_regex_get_key (void *cls, enum GNUNET_BLOCK_Type type,
                            const void *block, size_t block_size,
                            struct GNUNET_HashCode * key)
{
  switch (type)
  {
    case GNUNET_BLOCK_TYPE_REGEX:
      if (GNUNET_OK !=
	  REGEX_BLOCK_get_key (block, block_size,
			       key))
      {
	GNUNET_break_op (0);
	return GNUNET_NO;
      }
      return GNUNET_OK;
    case GNUNET_BLOCK_TYPE_REGEX_ACCEPT:
      if (sizeof (struct RegexAcceptBlock) != block_size)
      {
	GNUNET_break_op (0);
	return GNUNET_NO;
      }
      *key = ((struct RegexAcceptBlock *) block)->key;
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
libgnunet_plugin_block_regex_init (void *cls)
{
  static enum GNUNET_BLOCK_Type types[] =
  {
    GNUNET_BLOCK_TYPE_REGEX,
    GNUNET_BLOCK_TYPE_REGEX_ACCEPT,
    GNUNET_BLOCK_TYPE_ANY       /* end of list */
  };
  struct GNUNET_BLOCK_PluginFunctions *api;

  api = GNUNET_new (struct GNUNET_BLOCK_PluginFunctions);
  api->evaluate = &block_plugin_regex_evaluate;
  api->get_key = &block_plugin_regex_get_key;
  api->types = types;
  return api;
}


/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_block_regex_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}

/* end of plugin_block_regex.c */
