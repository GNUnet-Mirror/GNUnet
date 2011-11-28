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
 * @file fs/plugin_block_fs.c
 * @brief blocks used for file-sharing
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_block_plugin.h"
#include "block_fs.h"
#include "gnunet_signatures.h"

#define DEBUG_FS_BLOCK GNUNET_EXTRA_LOGGING

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
block_plugin_fs_evaluate (void *cls, enum GNUNET_BLOCK_Type type,
                          const GNUNET_HashCode * query,
                          struct GNUNET_CONTAINER_BloomFilter **bf,
                          int32_t bf_mutator, const void *xquery,
                          size_t xquery_size, const void *reply_block,
                          size_t reply_block_size)
{
  const struct SBlock *sb;
  GNUNET_HashCode chash;
  GNUNET_HashCode mhash;
  const GNUNET_HashCode *nsid;
  GNUNET_HashCode sh;

  switch (type)
  {
  case GNUNET_BLOCK_TYPE_FS_DBLOCK:
  case GNUNET_BLOCK_TYPE_FS_IBLOCK:
    if (xquery_size != 0)
    {
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_REQUEST_INVALID;
    }
    if (reply_block == NULL)
      return GNUNET_BLOCK_EVALUATION_REQUEST_VALID;
    return GNUNET_BLOCK_EVALUATION_OK_LAST;
  case GNUNET_BLOCK_TYPE_FS_KBLOCK:
  case GNUNET_BLOCK_TYPE_FS_NBLOCK:
    if (xquery_size != 0)
    {
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_REQUEST_INVALID;
    }
    if (reply_block == NULL)
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
  case GNUNET_BLOCK_TYPE_FS_SBLOCK:
    if (xquery_size != sizeof (GNUNET_HashCode))
    {
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_REQUEST_INVALID;
    }
    if (reply_block == NULL)
      return GNUNET_BLOCK_EVALUATION_REQUEST_VALID;
    nsid = xquery;
    if (reply_block_size < sizeof (struct SBlock))
    {
      GNUNET_break_op (0);
      return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
    }
    sb = reply_block;
    GNUNET_CRYPTO_hash (&sb->subspace,
                        sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                        &sh);
    if (0 != memcmp (nsid, &sh, sizeof (GNUNET_HashCode)))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, "block-fs",
                       _
                       ("Reply mismatched in terms of namespace.  Discarded.\n"));
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
block_plugin_fs_get_key (void *cls, enum GNUNET_BLOCK_Type type,
                         const void *block, size_t block_size,
                         GNUNET_HashCode * key)
{
  const struct KBlock *kb;
  const struct SBlock *sb;
  const struct NBlock *nb;

  switch (type)
  {
  case GNUNET_BLOCK_TYPE_FS_DBLOCK:
  case GNUNET_BLOCK_TYPE_FS_IBLOCK:
    GNUNET_CRYPTO_hash (block, block_size, key);
    return GNUNET_OK;
  case GNUNET_BLOCK_TYPE_FS_KBLOCK:
    if (block_size < sizeof (struct KBlock))
    {
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
    kb = block;
    if (block_size - sizeof (struct KBlock) !=
        ntohl (kb->purpose.size) -
        sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) -
        sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded))
    {
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
    if (GNUNET_OK !=
        GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_FS_KBLOCK,
                                  &kb->purpose, &kb->signature, &kb->keyspace))
    {
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
    if (key != NULL)
      GNUNET_CRYPTO_hash (&kb->keyspace,
                          sizeof (struct
                                  GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                          key);
    return GNUNET_OK;
  case GNUNET_BLOCK_TYPE_FS_SBLOCK:
    if (block_size < sizeof (struct SBlock))
    {
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
    sb = block;
    if (block_size !=
        ntohl (sb->purpose.size) + sizeof (struct GNUNET_CRYPTO_RsaSignature))
    {
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
    if (GNUNET_OK !=
        GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_FS_SBLOCK,
                                  &sb->purpose, &sb->signature, &sb->subspace))
    {
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
    if (key != NULL)
      *key = sb->identifier;
    return GNUNET_OK;
  case GNUNET_BLOCK_TYPE_FS_NBLOCK:
    if (block_size < sizeof (struct NBlock))
    {
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
    nb = block;
    if (block_size - sizeof (struct NBlock) !=
        ntohl (nb->ns_purpose.size) -
        sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) -
        sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded))
    {
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
    if (block_size !=
        ntohl (nb->ksk_purpose.size) +
        sizeof (struct GNUNET_CRYPTO_RsaSignature))
    {
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
    if (GNUNET_OK !=
        GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_FS_NBLOCK_KSIG,
                                  &nb->ksk_purpose, &nb->ksk_signature,
                                  &nb->keyspace))
    {
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
    if (GNUNET_OK !=
        GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_FS_NBLOCK,
                                  &nb->ns_purpose, &nb->ns_signature,
                                  &nb->subspace))
    {
      GNUNET_break_op (0);
      return GNUNET_NO;
    }
    /* FIXME: we used to xor ID with NSID,
     * why not here? */
    if (key != NULL)
      GNUNET_CRYPTO_hash (&nb->keyspace,
                          sizeof (struct
                                  GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
                          key);
    return GNUNET_OK;
  default:
    return GNUNET_SYSERR;
  }
}


/**
 * Entry point for the plugin.
 */
void *
libgnunet_plugin_block_fs_init (void *cls)
{
  static enum GNUNET_BLOCK_Type types[] =
  {
    GNUNET_BLOCK_TYPE_FS_DBLOCK,
    GNUNET_BLOCK_TYPE_FS_IBLOCK,
    GNUNET_BLOCK_TYPE_FS_KBLOCK,
    GNUNET_BLOCK_TYPE_FS_SBLOCK,
    GNUNET_BLOCK_TYPE_FS_NBLOCK,
    GNUNET_BLOCK_TYPE_ANY       /* end of list */
  };
  struct GNUNET_BLOCK_PluginFunctions *api;

  api = GNUNET_malloc (sizeof (struct GNUNET_BLOCK_PluginFunctions));
  api->evaluate = &block_plugin_fs_evaluate;
  api->get_key = &block_plugin_fs_get_key;
  api->types = types;
  return api;
}


/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_block_fs_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}

/* end of plugin_block_fs.c */
