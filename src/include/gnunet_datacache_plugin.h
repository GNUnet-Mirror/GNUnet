/*
     This file is part of GNUnet
     (C) 2006, 2009 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_datacache_plugin.h
 * @brief API for database backends for the datacache
 * @author Christian Grothoff
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
typedef void (*GNUNET_DATACACHE_DeleteNotifyCallback) (void *cls,
                                                       const GNUNET_HashCode *
                                                       key, size_t size);


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
   * @param size number of bytes in data
   * @param data data to store
   * @param type type of the value
   * @param discard_time when to discard the value in any case
   * @return 0 on error, number of bytes used otherwise
   */
       size_t (*put) (void *cls, const GNUNET_HashCode * key, size_t size,
                      const char *data, enum GNUNET_BLOCK_Type type,
                      struct GNUNET_TIME_Absolute discard_time);


  /**
   * Iterate over the results for a particular key
   * in the datastore.
   *
   * @param cls closure (internal context for the plugin)
   * @param key
   * @param type entries of which type are relevant?
   * @param iter maybe NULL (to just count)
   * @param iter_cls closure for iter
   * @return the number of results found
   */
  unsigned int (*get) (void *cls, const GNUNET_HashCode * key,
                       enum GNUNET_BLOCK_Type type,
                       GNUNET_DATACACHE_Iterator iter, void *iter_cls);


  /**
   * Delete the entry with the lowest expiration value
   * from the datacache right now.
   *
   * @param cls closure (internal context for the plugin)
   * @return GNUNET_OK on success, GNUNET_SYSERR on error
   */
  int (*del) (void *cls);


};


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_datacache_plugin.h */
#endif
