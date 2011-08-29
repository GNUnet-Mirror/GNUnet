/*
     This file is part of GNUnet
     (C) 2009, 2011 Christian Grothoff (and other contributing authors)

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
static unsigned long long
template_plugin_estimate_size (void *cls)
{
  GNUNET_break (0);
  return 0;
}


/**
 * Store an item in the datastore.
 *
 * @param cls closure
 * @param key key for the item
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param replication replication-level for the content
 * @param expiration expiration time for the content
 * @param msg set to error message
 * @return GNUNET_OK on success
 */
static int
template_plugin_put (void *cls, const GNUNET_HashCode * key, uint32_t size,
                     const void *data, enum GNUNET_BLOCK_Type type,
                     uint32_t priority, uint32_t anonymity,
                     uint32_t replication,
                     struct GNUNET_TIME_Absolute expiration, char **msg)
{
  GNUNET_break (0);
  *msg = GNUNET_strdup ("not implemented");
  return GNUNET_SYSERR;
}


/**
 * Get one of the results for a particular key in the datastore.
 *
 * @param cls closure
 * @param offset offset of the result (modulo num-results);
 *               specific ordering does not matter for the offset
 * @param key maybe NULL (to match all entries)
 * @param vhash hash of the value, maybe NULL (to
 *        match all values that have the right key).
 *        Note that for DBlocks there is no difference
 *        betwen key and vhash, but for other blocks
 *        there may be!
 * @param type entries of which type are relevant?
 *     Use 0 for any type.
 * @param proc function to call on each matching value;
 *        will be called with NULL if nothing matches
 * @param proc_cls closure for proc
 */
static void
template_plugin_get_key (void *cls, uint64_t offset,
                         const GNUNET_HashCode * key,
                         const GNUNET_HashCode * vhash,
                         enum GNUNET_BLOCK_Type type, PluginDatumProcessor proc,
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
 * Update the priority for a particular key in the datastore.  If
 * the expiration time in value is different than the time found in
 * the datastore, the higher value should be kept.  For the
 * anonymity level, the lower value is to be used.  The specified
 * priority should be added to the existing priority, ignoring the
 * priority in value.
 *
 * Note that it is possible for multiple values to match this put.
 * In that case, all of the respective values are updated.
 *
 * @param cls our "struct Plugin*"
 * @param uid unique identifier of the datum
 * @param delta by how much should the priority
 *     change?  If priority + delta < 0 the
 *     priority should be set to 0 (never go
 *     negative).
 * @param expire new expiration time should be the
 *     MAX of any existing expiration time and
 *     this value
 * @param msg set to error message
 * @return GNUNET_OK on success
 */
static int
template_plugin_update (void *cls, uint64_t uid, int delta,
                        struct GNUNET_TIME_Absolute expire, char **msg)
{
  GNUNET_break (0);
  *msg = GNUNET_strdup ("not implemented");
  return GNUNET_SYSERR;
}


/**
 * Call the given processor on an item with zero anonymity.
 *
 * @param cls our "struct Plugin*"
 * @param offset offset of the result (modulo num-results);
 *               specific ordering does not matter for the offset
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param proc function to call on each matching value;
 *        will be called  with NULL if no value matches
 * @param proc_cls closure for proc
 */
static void
template_plugin_get_zero_anonymity (void *cls, uint64_t offset,
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

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->env = env;
  api = GNUNET_malloc (sizeof (struct GNUNET_DATASTORE_PluginFunctions));
  api->cls = plugin;
  api->estimate_size = &template_plugin_estimate_size;
  api->put = &template_plugin_put;
  api->update = &template_plugin_update;
  api->get_key = &template_plugin_get_key;
  api->get_replication = &template_plugin_get_replication;
  api->get_expiration = &template_plugin_get_expiration;
  api->get_zero_anonymity = &template_plugin_get_zero_anonymity;
  api->drop = &template_plugin_drop;
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
