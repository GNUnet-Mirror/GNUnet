/*
     This file is part of GNUnet
     Copyright (C) 2017 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
    
     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/**
 * @file set/plugin_block_set_test.c
 * @brief set test block, recognizes elements with non-zero first byte as invalid
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_block_plugin.h"
#include "gnunet_block_group_lib.h"


/**
 * Function called to validate a reply or a request.  For
 * request evaluation, simply pass "NULL" for the reply_block.
 *
 * @param cls closure
 * @param ctx block context
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
block_plugin_set_test_evaluate (void *cls,
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
  if ( (NULL == reply_block) ||
       (reply_block_size == 0) ||
       (0 != ((char *) reply_block)[0]) )
    return GNUNET_BLOCK_EVALUATION_RESULT_INVALID;
  return GNUNET_BLOCK_EVALUATION_OK_MORE;
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
block_plugin_set_test_get_key (void *cls,
                               enum GNUNET_BLOCK_Type type,
                               const void *block,
                               size_t block_size,
			       struct GNUNET_HashCode *key)
{
  return GNUNET_SYSERR;
}


/**
 * Entry point for the plugin.
 */
void *
libgnunet_plugin_block_set_test_init (void *cls)
{
  static enum GNUNET_BLOCK_Type types[] =
  {
    GNUNET_BLOCK_TYPE_SET_TEST,
    GNUNET_BLOCK_TYPE_ANY       /* end of list */
  };
  struct GNUNET_BLOCK_PluginFunctions *api;

  api = GNUNET_new (struct GNUNET_BLOCK_PluginFunctions);
  api->evaluate = &block_plugin_set_test_evaluate;
  api->get_key = &block_plugin_set_test_get_key;
  api->types = types;
  return api;
}


/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_block_set_test_done (void *cls)
{
  struct GNUNET_BLOCK_PluginFunctions *api = cls;

  GNUNET_free (api);
  return NULL;
}

/* end of plugin_block_set_test.c */
