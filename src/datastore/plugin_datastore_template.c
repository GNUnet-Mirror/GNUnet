/*
     This file is part of GNUnet
     Copyright (C) 2009, 2011 GNUnet e.V.

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
 * @file datastore/plugin_datastore_template.c
 * @brief template-based datastore backend
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_datastore_plugin.h"


/**
 * Context for all functions in this plugin.
 */
struct Plugin
{
  /**
   * Our execution environment.
   */
  struct GNUNET_DATASTORE_PluginEnvironment *env;
};


/**
 * Get an estimate of how much space the database is
 * currently using.
 *
 * @param cls our "struct Plugin*"
 * @return number of bytes used on disk
 */
static void
template_plugin_estimate_size (void *cls, unsigned long long *estimate)
{
  if (NULL == estimate)
    return;
  GNUNET_break (0);
  *estimate = 0;
}


/**
 * Store an item in the datastore.
 *
 * @param cls closure
 * @param key key for the item
 * @param absent true if the key was not found in the bloom filter
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param replication replication-level for the content
 * @param expiration expiration time for the content
 * @param cont continuation called with success or failure status
 * @param cont_cls continuation closure
 */
static void
template_plugin_put (void *cls,
                     const struct GNUNET_HashCode *key,
                     bool absent,
                     uint32_t size,
                     const void *data,
                     enum GNUNET_BLOCK_Type type,
                     uint32_t priority,
                     uint32_t anonymity,
                     uint32_t replication,
                     struct GNUNET_TIME_Absolute expiration,
                     PluginPutCont cont,
                     void *cont_cls)
{
  GNUNET_break (0);
  cont (cont_cls, key, size, GNUNET_SYSERR, "not implemented");
}


/**
 * Get one of the results for a particular key in the datastore.
 *
 * @param cls closure
 * @param next_uid return the result with lowest uid >= next_uid
 * @param random if true, return a random result instead of using next_uid
 * @param key maybe NULL (to match all entries)
 * @param type entries of which type are relevant?
 *     Use 0 for any type.
 * @param proc function to call on each matching value;
 *        will be called with NULL if nothing matches
 * @param proc_cls closure for proc
 */
static void
template_plugin_get_key (void *cls,
                         uint64_t next_uid,
                         bool random,
                         const struct GNUNET_HashCode *key,
                         enum GNUNET_BLOCK_Type type,
                         PluginDatumProcessor proc,
                         void *proc_cls)
{
  GNUNET_break (0);
}



/**
 * Get a random item for replication.  Returns a single, not expired,
 * random item from those with the highest replication counters.  The
 * item's replication counter is decremented by one IF it was positive
 * before.  Call 'proc' with all values ZERO or NULL if the datastore
 * is empty.
 *
 * @param cls closure
 * @param proc function to call the value (once only).
 * @param proc_cls closure for proc
 */
static void
template_plugin_get_replication (void *cls, PluginDatumProcessor proc,
                                 void *proc_cls)
{
  GNUNET_break (0);
}


/**
 * Get a random item for expiration.  Call 'proc' with all values ZERO
 * or NULL if the datastore is empty.
 *
 * @param cls closure
 * @param proc function to call the value (once only).
 * @param proc_cls closure for proc
 */
static void
template_plugin_get_expiration (void *cls, PluginDatumProcessor proc,
                                void *proc_cls)
{
  GNUNET_break (0);
}


/**
 * Call the given processor on an item with zero anonymity.
 *
 * @param cls our "struct Plugin*"
 * @param next_uid return the result with lowest uid >= next_uid
 * @param type entries of which type should be considered?
 *        Must not be zero (ANY).
 * @param proc function to call on the matching value;
 *        will be called with NULL if no value matches
 * @param proc_cls closure for proc
 */
static void
template_plugin_get_zero_anonymity (void *cls, uint64_t next_uid,
                                    enum GNUNET_BLOCK_Type type,
                                    PluginDatumProcessor proc, void *proc_cls)
{
  GNUNET_break (0);
}


/**
 * Drop database.
 */
static void
template_plugin_drop (void *cls)
{
  GNUNET_break (0);
}


/**
 * Get all of the keys in the datastore.
 *
 * @param cls closure
 * @param proc function to call on each key
 * @param proc_cls closure for proc
 */
static void
template_get_keys (void *cls,
		   PluginKeyProcessor proc,
		   void *proc_cls)
{
  proc (proc_cls, NULL, 0);
}


/**
 * Remove a particular key in the datastore.
 *
 * @param cls closure
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param cont continuation called with success or failure status
 * @param cont_cls continuation closure for @a cont
 */
static void
template_plugin_remove_key (void *cls,
                            const struct GNUNET_HashCode *key,
                            uint32_t size,
                            const void *data,
                            PluginRemoveCont cont,
                            void *cont_cls)
{
  GNUNET_break (0);
  cont (cont_cls, key, size, GNUNET_SYSERR, "not implemented");
}


/**
 * Entry point for the plugin.
 *
 * @param cls the "struct GNUNET_DATASTORE_PluginEnvironment*"
 * @return our "struct Plugin*"
 */
void *
libgnunet_plugin_datastore_template_init (void *cls)
{
  struct GNUNET_DATASTORE_PluginEnvironment *env = cls;
  struct GNUNET_DATASTORE_PluginFunctions *api;
  struct Plugin *plugin;

  plugin = GNUNET_new (struct Plugin);
  plugin->env = env;
  api = GNUNET_new (struct GNUNET_DATASTORE_PluginFunctions);
  api->cls = plugin;
  api->estimate_size = &template_plugin_estimate_size;
  api->put = &template_plugin_put;
  api->get_key = &template_plugin_get_key;
  api->get_replication = &template_plugin_get_replication;
  api->get_expiration = &template_plugin_get_expiration;
  api->get_zero_anonymity = &template_plugin_get_zero_anonymity;
  api->drop = &template_plugin_drop;
  api->get_keys = &template_get_keys;
  api->remove_key = &template_plugin_remove_key;
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, "template",
                   _("Template database running\n"));
  return api;
}


/**
 * Exit point from the plugin.
 * @param cls our "struct Plugin*"
 * @return always NULL
 */
void *
libgnunet_plugin_datastore_template_done (void *cls)
{
  struct GNUNET_DATASTORE_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_datastore_template.c */
