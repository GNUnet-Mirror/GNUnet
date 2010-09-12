/*
     This file is part of GNUnet.
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
 * @file block/block.c
 * @brief library for data block manipulation
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_block_lib.h"
#include "plugin_block.h"

/**
 * Check if the given KBlock is well-formed.
 *
 * @param kb the kblock data (or at least "dsize" bytes claiming to be one)
 * @param dsize size of "kb" in bytes; check for < sizeof(struct KBlock)!
 * @param query where to store the query that this block answers
 * @return GNUNET_OK if this is actually a well-formed KBlock
 */
static int
check_kblock (const struct KBlock *kb,
	      size_t dsize,
	      GNUNET_HashCode *query)
{
  if (dsize < sizeof (struct KBlock))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (dsize - sizeof (struct KBlock) !=
      ntohl (kb->purpose.size) 
      - sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) 
      - sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) ) 
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_FS_KBLOCK,
				&kb->purpose,
				&kb->signature,
				&kb->keyspace)) 
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (query != NULL)
    GNUNET_CRYPTO_hash (&kb->keyspace,
			sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
			query);
  return GNUNET_OK;
}


/**
 * Check if the given NBlock is well-formed.
 *
 * @param nb the nblock data (or at least "dsize" bytes claiming to be one)
 * @param dsize size of "nb" in bytes; check for < sizeof(struct NBlock)!
 * @param query where to store the query that this block answers
 * @return GNUNET_OK if this is actually a well-formed NBlock
 */
static int
check_nblock (const struct NBlock *nb,
	      size_t dsize,
	      GNUNET_HashCode *query)
{
  if (dsize < sizeof (struct NBlock))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (dsize - sizeof (struct NBlock) !=
      ntohl (nb->ns_purpose.size) 
      - sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) 
      - sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded) ) 
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (dsize !=
      ntohl (nb->ksk_purpose.size) + sizeof (struct GNUNET_CRYPTO_RsaSignature))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_FS_NBLOCK_KSIG,
				&nb->ksk_purpose,
				&nb->ksk_signature,
				&nb->keyspace)) 
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_FS_NBLOCK,
				&nb->ns_purpose,
				&nb->ns_signature,
				&nb->subspace)) 
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (query != NULL)
    GNUNET_CRYPTO_hash (&nb->keyspace,
			sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded),
			query);
  return GNUNET_OK;
}


/**
 * Check if the given SBlock is well-formed.
 *
 * @param sb the sblock data (or at least "dsize" bytes claiming to be one)
 * @param dsize size of "kb" in bytes; check for < sizeof(struct SBlock)!
 * @param query where to store the query that this block answers
 * @return GNUNET_OK if this is actually a well-formed SBlock
 */
static int
check_sblock (const struct SBlock *sb,
	      size_t dsize,
	      GNUNET_HashCode *query)
{
  if (dsize < sizeof (struct SBlock))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (dsize !=
      ntohl (sb->purpose.size) + sizeof (struct GNUNET_CRYPTO_RsaSignature))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_FS_SBLOCK,
				&sb->purpose,
				&sb->signature,
				&sb->subspace)) 
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (query != NULL)
    *query = sb->identifier;
  return GNUNET_OK;
}


/**
 * Check if the given block is well-formed (and of the given type).
 *
 * @param type type of the block
 * @param block the block data (or at least "size" bytes claiming to be one)
 * @param size size of "kb" in bytes; check that it is large enough
 * @param query where to store the query that this block answers
 * @return GNUNET_OK if this is actually a well-formed block,
 *         GNUNET_NO if we could not determine the query,
 *         GNUNET_SYSERR if the block is malformed
 */
int
GNUNET_BLOCK_check_block (enum GNUNET_BLOCK_Type type,
			  const void *block,
			  size_t size,
			  GNUNET_HashCode *query)
{
  /* first, validate! */
  switch (type)
    {
    case GNUNET_BLOCK_TYPE_DBLOCK:
    case GNUNET_BLOCK_TYPE_IBLOCK:
      GNUNET_CRYPTO_hash (block, size, query);
      break;
    case GNUNET_BLOCK_TYPE_KBLOCK:
      if (GNUNET_OK !=
	  check_kblock (block,
			size,
			query))
	return GNUNET_SYSERR;
      break;
    case GNUNET_BLOCK_TYPE_SBLOCK:
      if (GNUNET_OK !=
	  check_sblock (block,
			size,
			query))
	return GNUNET_SYSERR;
      break;
    case GNUNET_BLOCK_TYPE_NBLOCK:
      if (GNUNET_OK !=
	  check_nblock (block,
			size,
			query))
	return GNUNET_SYSERR;
      return GNUNET_OK;
    case GNUNET_BLOCK_TYPE_ONDEMAND:
      if (size != sizeof (struct OnDemandBlock))
	return GNUNET_SYSERR;
      memset (query, 0, sizeof (GNUNET_HashCode));      
      return GNUNET_NO;
    default:
      /* unknown block type */
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  return GNUNET_OK;
}

/* ***************** NEW API ******************* */

/**
 * Handle for a plugin.
 */
struct Plugin
{
  /**
   * Name of the shared library.
   */ 
  char *library_name;
  
  /**
   * Plugin API.
   */
  struct GNUNET_BLOCK_PluginFunctions *api;
};

/**
 * Handle to an initialized block library.
 */
struct GNUNET_BLOCK_Context
{
  /**
   * NULL-terminated array of our plugins.
   */
  struct Plugin **plugins;

  /**
   * Our configuration.
   */ 
  const struct GNUNET_CONFIGURATION_Handle *cfg;
};


/**
 * Create a block context.  Loads the block plugins.
 *
 * @param cfg configuration to use
 * @return NULL on error
 */
struct GNUNET_BLOCK_Context *
GNUNET_BLOCK_context_create (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_BLOCK_Context *ctx;
  unsigned int num_plugins;

  ctx = GNUNET_malloc (sizeof (struct GNUNET_BLOCK_Context));
  ctx->cfg = cfg;
  num_plugins = 0;
  /* FIXME: actually load plugins... */
  GNUNET_array_append (ctx->plugins,
		       num_plugins,
		       NULL);
  return ctx;
}


/**
 * Destroy the block context.
 *
 * @param ctx context to destroy
 */
void
GNUNET_BLOCK_context_destroy (struct GNUNET_BLOCK_Context *ctx)
{
  unsigned int i;
  struct Plugin *plugin;

  i = 0;
  while (NULL != (plugin = ctx->plugins[i]))
    {
      GNUNET_break (NULL == 
		    GNUNET_PLUGIN_unload (plugin->library_name,
					  plugin->api));
      GNUNET_free (plugin->library_name);
      GNUNET_free (plugin);
      i++;
    }
  GNUNET_free (ctx->plugins);
  GNUNET_free (ctx);
}


/**
 * Find a plugin for the given type.
 *
 * @param ctx context to search
 * @param type type to look for
 * @return NULL if no matching plugin exists
 */
static struct GNUNET_BLOCK_PluginFunctions *
find_plugin (struct GNUNET_BLOCK_Context *ctx,
	     enum GNUNET_BLOCK_Type type)
{
  struct Plugin *plugin;
  unsigned int i;
  unsigned int j;

  i = 0;
  while (NULL != (plugin = ctx->plugins[i]))
    {
      j = 0;
      while (0 != (plugin->api->types[j]))
	{
	  if (type == plugin->api->types[j])
	    return plugin->api;
	  j++;
	}
      i++;
    }
  return NULL;
}


/**
 * Function called to validate a reply or a request.  For
 * request evaluation, simply pass "NULL" for the reply_block.
 * Note that it is assumed that the reply has already been 
 * matched to the key (and signatures checked) as it would
 * be done with the "get_key" function.
 *
 * @param ctx block contxt
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
enum GNUNET_BLOCK_EvaluationResult
GNUNET_BLOCK_evaluate (struct GNUNET_BLOCK_Context *ctx,
		       enum GNUNET_BLOCK_Type type,
		       const GNUNET_HashCode *query,
		       struct GNUNET_CONTAINER_BloomFilter **bf,
		       int32_t bf_mutator,
		       const void *xquery,
		       size_t xquery_size,
		       const void *reply_block,
		       size_t reply_block_size)
{
  struct GNUNET_BLOCK_PluginFunctions *plugin = find_plugin (ctx, type);

  if (plugin == NULL)
    return GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED;
  return plugin->evaluate (plugin->cls,
			   type, query, bf, bf_mutator,
			   xquery, xquery_size, reply_block, reply_block_size);
}


/**
 * Function called to obtain the key for a block.
 *
 * @param ctx block context
 * @param type block type
 * @param block block to get the key for
 * @param block_size number of bytes in block
 * @param key set to the key (query) for the given block
 * @return GNUNET_OK on success, GNUNET_SYSERR if type not supported
 *         (or if extracting a key from a block of this type does not work)
 */
int
GNUNET_BLOCK_get_key (struct GNUNET_BLOCK_Context *ctx,
		      enum GNUNET_BLOCK_Type type,
		      const void *block,
		      size_t block_size,
		      GNUNET_HashCode *key)
{
  struct GNUNET_BLOCK_PluginFunctions *plugin = find_plugin (ctx, type);

  if (plugin == NULL)
    return GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED;
  return plugin->get_key (plugin->cls,
			  type, block, block_size, key);
}


/* end of block.c */
