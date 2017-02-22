/*
     This file is part of GNUnet.
     Copyright (C) 2010, 2017 GNUnet e.V.

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
GNUNET_BLOCK_mingle_hash (const struct GNUNET_HashCode *in,
			  uint32_t mingle_number,
                          struct GNUNET_HashCode *hc)
{
  struct GNUNET_HashCode m;

  GNUNET_CRYPTO_hash (&mingle_number,
                      sizeof (uint32_t),
                      &m);
  GNUNET_CRYPTO_hash_xor (&m,
                          in,
                          hc);
}


/**
 * Add a plugin to the list managed by the block library.
 *
 * @param cls the block context
 * @param library_name name of the plugin
 * @param lib_ret the plugin API
 */
static void
add_plugin (void *cls,
	    const char *library_name,
	    void *lib_ret)
{
  struct GNUNET_BLOCK_Context *ctx = cls;
  struct GNUNET_BLOCK_PluginFunctions *api = lib_ret;
  struct Plugin *plugin;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Loading block plugin `%s'\n",
              library_name);
  plugin = GNUNET_new (struct Plugin);
  plugin->api = api;
  plugin->library_name = GNUNET_strdup (library_name);
  GNUNET_array_append (ctx->plugins,
                       ctx->num_plugins,
                       plugin);
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

  ctx = GNUNET_new (struct GNUNET_BLOCK_Context);
  ctx->cfg = cfg;
  GNUNET_PLUGIN_load_all ("libgnunet_plugin_block_",
                          NULL,
                          &add_plugin,
                          ctx);
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
                  GNUNET_PLUGIN_unload (plugin->library_name,
                                        plugin->api));
    GNUNET_free (plugin->library_name);
    GNUNET_free (plugin);
  }
  GNUNET_free (ctx->plugins);
  GNUNET_free (ctx);
}


/**
 * Serialize state of a block group.
 *
 * @param bg group to serialize
 * @param[out] nonce set to the nonce of the @a bg
 * @param[out] raw_data set to the serialized state
 * @param[out] raw_data_size set to the number of bytes in @a raw_data
 * @return #GNUNET_OK on success, #GNUNET_NO if serialization is not
 *         supported, #GNUNET_SYSERR on error
 */
int
GNUNET_BLOCK_group_serialize (struct GNUNET_BLOCK_Group *bg,
                              uint32_t *nonce,
                              void **raw_data,
                              size_t *raw_data_size)
{
  *nonce = 0;
  *raw_data = NULL;
  *raw_data_size = 0;
  if (NULL == bg)
    return GNUNET_NO;
  if (NULL == bg->serialize_cb)
    return GNUNET_NO;
  return bg->serialize_cb (bg,
                           nonce,
                           raw_data,
                           raw_data_size);
}


/**
 * Destroy resources used by a block group.
 *
 * @param bg group to destroy, NULL is allowed
 */
void
GNUNET_BLOCK_group_destroy (struct GNUNET_BLOCK_Group *bg)
{
  if (NULL == bg)
    return;
  bg->destroy_cb (bg);
}


/**
 * Try merging two block groups.  Afterwards, @a bg1 should remain
 * valid and contain the rules from both @a bg1 and @bg2, and
 * @a bg2 should be destroyed (as part of this call).  The latter
 * should happen even if merging is not supported.
 *
 * @param[in,out] bg1 first group to merge, is updated
 * @param bg2 second group to merge, is destroyed
 * @return #GNUNET_OK on success,
 *         #GNUNET_NO if merge failed due to different nonce
 *         #GNUNET_SYSERR if merging is not supported
 */
int
GNUNET_BLOCK_group_merge (struct GNUNET_BLOCK_Group *bg1,
                          struct GNUNET_BLOCK_Group *bg2)
{
  int ret;

  if (NULL == bg2)
    return GNUNET_OK;
  if (NULL == bg1)
  {
    bg2->destroy_cb (bg2);
    return GNUNET_OK;
  }
  if (NULL == bg1->merge_cb)
    return GNUNET_SYSERR;
  GNUNET_assert (bg1->merge_cb == bg1->merge_cb);
  ret = bg1->merge_cb (bg1,
                       bg2);
  bg2->destroy_cb (bg2);
  return ret;
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
  unsigned int j;

  for (unsigned i = 0; i < ctx->num_plugins; i++)
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
 * Create a new block group.
 *
 * @param ctx block context in which the block group is created
 * @param type type of the block for which we are creating the group
 * @param nonce random value used to seed the group creation
 * @param raw_data optional serialized prior state of the group, NULL if unavailable/fresh
 * @param raw_data_size number of bytes in @a raw_data, 0 if unavailable/fresh
 * @return block group handle, NULL if block groups are not supported
 *         by this @a type of block (this is not an error)
 */
struct GNUNET_BLOCK_Group *
GNUNET_BLOCK_group_create (struct GNUNET_BLOCK_Context *ctx,
                           enum GNUNET_BLOCK_Type type,
                           uint32_t nonce,
                           const void *raw_data,
                           size_t raw_data_size,
                           ...)
{
  struct GNUNET_BLOCK_PluginFunctions *plugin;
  struct GNUNET_BLOCK_Group *bg;
  va_list ap;

  plugin = find_plugin (ctx,
                        type);
  if (NULL == plugin->create_group)
    return NULL;
  va_start (ap,
            raw_data_size);
  bg = plugin->create_group (plugin->cls,
                             type,
                             nonce,
                             raw_data,
                             raw_data_size,
                             ap);
  va_end (ap);
  return bg;
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
 * @param block block group to use
 * @param eo control flags
 * @param query original query (hash)
 * @param xquery extended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in @a xquery
 * @param reply_block response to validate
 * @param reply_block_size number of bytes in @a reply_block
 * @return characterization of result
 */
enum GNUNET_BLOCK_EvaluationResult
GNUNET_BLOCK_evaluate (struct GNUNET_BLOCK_Context *ctx,
                       enum GNUNET_BLOCK_Type type,
                       struct GNUNET_BLOCK_Group *group,
                       enum GNUNET_BLOCK_EvaluationOptions eo,
                       const struct GNUNET_HashCode *query,
                       const void *xquery,
                       size_t xquery_size,
                       const void *reply_block,
                       size_t reply_block_size)
{
  struct GNUNET_BLOCK_PluginFunctions *plugin = find_plugin (ctx,
                                                             type);

  if (NULL == plugin)
    return GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED;
  return plugin->evaluate (plugin->cls,
                           type,
                           group,
                           eo,
                           query,
                           xquery,
                           xquery_size,
                           reply_block,
                           reply_block_size);
}


/**
 * Function called to obtain the key for a block.
 *
 * @param ctx block context
 * @param type block type
 * @param block block to get the key for
 * @param block_size number of bytes in @a block
 * @param key set to the key (query) for the given block
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if type not supported
 *         (or if extracting a key from a block of this type does not work)
 */
int
GNUNET_BLOCK_get_key (struct GNUNET_BLOCK_Context *ctx,
                      enum GNUNET_BLOCK_Type type,
                      const void *block,
                      size_t block_size,
                      struct GNUNET_HashCode *key)
{
  struct GNUNET_BLOCK_PluginFunctions *plugin = find_plugin (ctx,
                                                             type);

  if (plugin == NULL)
    return GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED;
  return plugin->get_key (plugin->cls,
                          type,
                          block,
                          block_size,
                          key);
}


/**
 * Update block group to filter out the given results.  Note that the
 * use of a hash for seen results implies that the caller magically
 * knows how the specific block engine hashes for filtering
 * duplicates, so this API may not always apply.
 *
 * @param bf_mutator mutation value to use
 * @param seen_results results already seen
 * @param seen_results_count number of entries in @a seen_results
 * @return #GNUNET_SYSERR if not supported, #GNUNET_OK on success
 */
int
GNUNET_BLOCK_group_set_seen (struct GNUNET_BLOCK_Group *bg,
                             const struct GNUNET_HashCode *seen_results,
                             unsigned int seen_results_count)
{
  if (NULL == bg)
    return GNUNET_OK;
  if (NULL == bg->mark_seen_cb)
    return GNUNET_SYSERR;
  bg->mark_seen_cb (bg,
                    seen_results,
                    seen_results_count);
  return GNUNET_OK;
}


/* end of block.c */
