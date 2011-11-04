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
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_block_lib.h"
#include "gnunet_block_plugin.h"


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
   * Array of our plugins.
   */
  struct Plugin **plugins;

  /**
   * Size of the 'plugins' array.
   */
  unsigned int num_plugins;

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;
};


/**
 * Mingle hash with the mingle_number to produce different bits.
 *
 * @param in original hash code
 * @param mingle_number number for hash permutation
 * @param hc where to store the result.
 */
void
GNUNET_BLOCK_mingle_hash (const GNUNET_HashCode * in, uint32_t mingle_number,
                          GNUNET_HashCode * hc)
{
  GNUNET_HashCode m;

  GNUNET_CRYPTO_hash (&mingle_number, sizeof (uint32_t), &m);
  GNUNET_CRYPTO_hash_xor (&m, in, hc);
}


/**
 * Add a plugin to the list managed by the block library.
 *
 * @param cls the block context
 * @param library_name name of the plugin
 * @param lib_ret the plugin API
 */
static void
add_plugin (void *cls, const char *library_name, void *lib_ret)
{
  struct GNUNET_BLOCK_Context *ctx = cls;
  struct GNUNET_BLOCK_PluginFunctions *api = lib_ret;
  struct Plugin *plugin;

  GNUNET_log (GNUNET_ERROR_TYPE_INFO, _("Loading block plugin `%s'\n"),
              library_name);
  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->api = api;
  plugin->library_name = GNUNET_strdup (library_name);
  GNUNET_array_append (ctx->plugins, ctx->num_plugins, plugin);
}



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

  ctx = GNUNET_malloc (sizeof (struct GNUNET_BLOCK_Context));
  ctx->cfg = cfg;
  GNUNET_PLUGIN_load_all ("libgnunet_plugin_block_", NULL, &add_plugin, ctx);
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

  for (i = 0; i < ctx->num_plugins; i++)
  {
    plugin = ctx->plugins[i];
    GNUNET_break (NULL ==
                  GNUNET_PLUGIN_unload (plugin->library_name, plugin->api));
    GNUNET_free (plugin->library_name);
    GNUNET_free (plugin);
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
find_plugin (struct GNUNET_BLOCK_Context *ctx, enum GNUNET_BLOCK_Type type)
{
  struct Plugin *plugin;
  unsigned int i;
  unsigned int j;

  for (i = 0; i < ctx->num_plugins; i++)
  {
    plugin = ctx->plugins[i];
    j = 0;
    while (0 != (plugin->api->types[j]))
    {
      if (type == plugin->api->types[j])
        return plugin->api;
      j++;
    }
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
 * @param xquery extended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in xquery
 * @param reply_block response to validate
 * @param reply_block_size number of bytes in reply block
 * @return characterization of result
 */
enum GNUNET_BLOCK_EvaluationResult
GNUNET_BLOCK_evaluate (struct GNUNET_BLOCK_Context *ctx,
                       enum GNUNET_BLOCK_Type type,
                       const GNUNET_HashCode * query,
                       struct GNUNET_CONTAINER_BloomFilter **bf,
                       int32_t bf_mutator, const void *xquery,
                       size_t xquery_size, const void *reply_block,
                       size_t reply_block_size)
{
  struct GNUNET_BLOCK_PluginFunctions *plugin = find_plugin (ctx, type);

  if (plugin == NULL)
    return GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED;
  return plugin->evaluate (plugin->cls, type, query, bf, bf_mutator, xquery,
                           xquery_size, reply_block, reply_block_size);
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
                      enum GNUNET_BLOCK_Type type, const void *block,
                      size_t block_size, GNUNET_HashCode * key)
{
  struct GNUNET_BLOCK_PluginFunctions *plugin = find_plugin (ctx, type);

  if (plugin == NULL)
    return GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED;
  return plugin->get_key (plugin->cls, type, block, block_size, key);
}


/**
 * How many bytes should a bloomfilter be if we have already seen
 * entry_count responses?  Note that GNUNET_CONSTANTS_BLOOMFILTER_K gives us the number
 * of bits set per entry.  Furthermore, we should not re-size the
 * filter too often (to keep it cheap).
 *
 * Since other peers will also add entries but not resize the filter,
 * we should generally pick a slightly larger size than what the
 * strict math would suggest.
 *
 * @return must be a power of two and smaller or equal to 2^15.
 */
static size_t
compute_bloomfilter_size (unsigned int entry_count)
{
  size_t size;
  unsigned int ideal = (entry_count * GNUNET_CONSTANTS_BLOOMFILTER_K) / 4;
  uint16_t max = 1 << 15;

  if (entry_count > max)
    return max;
  size = 8;
  while ((size < max) && (size < ideal))
    size *= 2;
  if (size > max)
    return max;
  return size;
}


/**
 * Construct a bloom filter that would filter out the given
 * results.
 *
 * @param bf_mutator mutation value to use
 * @param seen_results results already seen
 * @param seen_results_count number of entries in 'seen_results'
 * @return NULL if seen_results_count is 0, otherwise a BF
 *         that would match the given results.
 */
struct GNUNET_CONTAINER_BloomFilter *
GNUNET_BLOCK_construct_bloomfilter (int32_t bf_mutator,
                                    const GNUNET_HashCode * seen_results,
                                    unsigned int seen_results_count)
{
  struct GNUNET_CONTAINER_BloomFilter *bf;
  GNUNET_HashCode mhash;
  unsigned int i;
  size_t nsize;

  nsize = compute_bloomfilter_size (seen_results_count);
  bf = GNUNET_CONTAINER_bloomfilter_init (NULL, nsize,
                                          GNUNET_CONSTANTS_BLOOMFILTER_K);
  for (i = 0; i < seen_results_count; i++)
  {
    GNUNET_BLOCK_mingle_hash (&seen_results[i], bf_mutator, &mhash);
    GNUNET_CONTAINER_bloomfilter_add (bf, &mhash);
  }
  return bf;
}


/* end of block.c */
