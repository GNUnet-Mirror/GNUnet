/*
     This file is part of GNUnet
     Copyright (C) 2006, 2009, 2015 GNUnet e.V.

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
 * @author Christian Grothoff
 *
 * @file
 * API for database backends for the datacache
 *
 * @defgroup datacache-plugin  Data Cache plugin API
 * API for database backends for the datacache
 * @{
 */
#ifndef PLUGIN_DATACACHE_H
#define PLUGIN_DATACACHE_H

#include "gnunet_datacache_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Function called by plugins to notify the datacache
 * about content deletions.
 *
 * @param cls closure
 * @param key key of the content that was deleted
 * @param size number of bytes that were made available
 */
typedef void
(*GNUNET_DATACACHE_DeleteNotifyCallback) (void *cls,
                                          const struct GNUNET_HashCode *key,
                                          size_t size);


/**
 * The datastore service will pass a pointer to a struct
 * of this type as the first and only argument to the
 * entry point of each datastore plugin.
 */
struct GNUNET_DATACACHE_PluginEnvironment
{

  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Configuration section to use.
   */
  const char *section;

  /**
   * Closure to use for callbacks.
   */
  void *cls;

  /**
   * Function to call whenever the plugin needs to
   * discard content that it was asked to store.
   */
  GNUNET_DATACACHE_DeleteNotifyCallback delete_notify;

  /**
   * How much space are we allowed to use?
   */
  unsigned long long quota;

};


/**
 * @brief struct returned by the initialization function of the plugin
 */
struct GNUNET_DATACACHE_PluginFunctions
{

  /**
   * Closure to pass to all plugin functions.
   */
  void *cls;

  /**
   * Store an item in the datastore.
   *
   * @param cls closure (internal context for the plugin)
   * @param key key to store the value under
   * @param xor_distance how close is @a key to our PID?
   * @param size number of bytes in @a data
   * @param data data to store
   * @param type type of the value
   * @param discard_time when to discard the value in any case
   * @param path_info_len number of entries in @a path_info
   * @param path_info a path through the network
   * @return 0 if duplicate, -1 on error, number of bytes used otherwise
   */
  ssize_t (*put) (void *cls,
                  const struct GNUNET_HashCode *key,
                  uint32_t xor_distance,
                  size_t size,
		  const char *data,
                  enum GNUNET_BLOCK_Type type,
		  struct GNUNET_TIME_Absolute discard_time,
		  unsigned int path_info_len,
		  const struct GNUNET_PeerIdentity *path_info);

  /**
   * Iterate over the results for a particular key
   * in the datastore.
   *
   * @param cls closure (internal context for the plugin)
   * @param key key to look for
   * @param type entries of which type are relevant?
   * @param iter maybe NULL (to just count)
   * @param iter_cls closure for @a iter
   * @return the number of results found
   */
  unsigned int (*get) (void *cls,
                       const struct GNUNET_HashCode *key,
                       enum GNUNET_BLOCK_Type type,
                       GNUNET_DATACACHE_Iterator iter,
                       void *iter_cls);

  /**
   * Delete the entry with the lowest expiration value
   * from the datacache right now.
   *
   * @param cls closure (internal context for the plugin)
   * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
   */
  int (*del) (void *cls);

  /**
   * Return a random value from the datastore.
   *
   * @param cls closure (internal context for the plugin)
   * @param iter maybe NULL (to just count)
   * @param iter_cls closure for @a iter
   * @return the number of results found (zero or one)
   */
  unsigned int (*get_random) (void *cls,
                              GNUNET_DATACACHE_Iterator iter,
                              void *iter_cls);


  /**
   * Iterate over the results that are "close" to a particular key in
   * the datacache.  "close" is defined as numerically larger than @a
   * key (when interpreted as a circular address space), with small
   * distance.
   *
   * @param cls closure (internal context for the plugin)
   * @param key area of the keyspace to look into
   * @param num_results number of results that should be returned to @a iter
   * @param iter maybe NULL (to just count)
   * @param iter_cls closure for @a iter
   * @return the number of results found
   */
  unsigned int (*get_closest) (void *cls,
                               const struct GNUNET_HashCode *key,
                               unsigned int num_results,
                               GNUNET_DATACACHE_Iterator iter,
                               void *iter_cls);

};


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */
