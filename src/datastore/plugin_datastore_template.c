/*
     This file is part of GNUnet
     (C) 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
#include "plugin_datastore.h"


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
 * @return number of bytes used on disk
 */
static unsigned long long template_plugin_get_size (void *cls)
{
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
 * @param expiration expiration time for the content
 * @param msg set to error message
 * @return GNUNET_OK on success
 */
static int
template_plugin_put (void *cls,
		   const GNUNET_HashCode * key,
		   uint32_t size,
		   const void *data,
		   uint32_t type,
		   uint32_t priority,
		   uint32_t anonymity,
		     struct GNUNET_TIME_Absolute expiration,
		     char **msg)
{
  *msg = GNUNET_strdup ("not implemented");
  return GNUNET_SYSERR;
}


/**
 * Iterate over the results for a particular key
 * in the datastore.
 *
 * @param cls closure
 * @param key maybe NULL (to match all entries)
 * @param vhash hash of the value, maybe NULL (to
 *        match all values that have the right key).
 *        Note that for DBlocks there is no difference
 *        betwen key and vhash, but for other blocks
 *        there may be!
 * @param type entries of which type are relevant?
 *     Use 0 for any type.
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 */
static void
template_plugin_get (void *cls,
		   const GNUNET_HashCode * key,
		   const GNUNET_HashCode * vhash,
		   uint32_t type,
		   GNUNET_DATASTORE_Iterator iter, void *iter_cls)
{
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
template_plugin_update (void *cls,
			unsigned long long uid,
			int delta, struct GNUNET_TIME_Absolute expire,
			char **msg)
{
  *msg = GNUNET_strdup ("not implemented");
  return GNUNET_SYSERR;
}


/**
 * Select a subset of the items in the datastore and call
 * the given iterator for each of them.
 *
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 */
static void
template_plugin_iter_low_priority (void *cls,
			uint32_t type,
			GNUNET_DATASTORE_Iterator iter,
			void *iter_cls)
{
}



/**
 * Select a subset of the items in the datastore and call
 * the given iterator for each of them.
 *
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 */
static void
template_plugin_iter_zero_anonymity (void *cls,
			uint32_t type,
			GNUNET_DATASTORE_Iterator iter,
			void *iter_cls)
{
}



/**
 * Select a subset of the items in the datastore and call
 * the given iterator for each of them.
 *
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 */
static void
template_plugin_iter_ascending_expiration (void *cls,
			uint32_t type,
			GNUNET_DATASTORE_Iterator iter,
			void *iter_cls)
{
}



/**
 * Select a subset of the items in the datastore and call
 * the given iterator for each of them.
 *
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 */
static void
template_plugin_iter_migration_order (void *cls,
			uint32_t type,
			GNUNET_DATASTORE_Iterator iter,
			void *iter_cls)
{
}



/**
 * Select a subset of the items in the datastore and call
 * the given iterator for each of them.
 *
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 */
static void
template_plugin_iter_all_now (void *cls,
			uint32_t type,
			GNUNET_DATASTORE_Iterator iter,
			void *iter_cls)
{
}


/**
 * Drop database.
 */
static void 
template_plugin_drop (void *cls)
{
}


/**
 * Entry point for the plugin.
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
  api->get_size = &template_plugin_get_size;
  api->put = &template_plugin_put;
  api->get = &template_plugin_get;
  api->update = &template_plugin_update;
  api->iter_low_priority = &template_plugin_iter_low_priority;
  api->iter_zero_anonymity = &template_plugin_iter_zero_anonymity;
  api->iter_ascending_expiration = &template_plugin_iter_ascending_expiration;
  api->iter_migration_order = &template_plugin_iter_migration_order;
  api->iter_all_now = &template_plugin_iter_all_now;
  api->drop = &template_plugin_drop;
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
                   "template", _("Template database running\n"));
  return api;
}


/**
 * Exit point from the plugin.
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
