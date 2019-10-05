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

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @author Christian Grothoff
 *
 * @file
 * API for the database backend plugins.
 *
 * @defgroup datastore-plugin  Data Store service plugin API
 * API for the database backend plugins.
 * @{
 */
#ifndef PLUGIN_DATASTORE_H
#define PLUGIN_DATASTORE_H

#include "gnunet_block_lib.h"
#include "gnunet_configuration_lib.h"
#include "gnunet_datastore_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_scheduler_lib.h"


/**
 * How many bytes of overhead will we assume per entry
 * in any DB (for reservations)?
 */
#define GNUNET_DATASTORE_ENTRY_OVERHEAD 256


/**
 * Function invoked to notify service of disk utilization
 * changes.
 *
 * @param cls closure
 * @param delta change in disk utilization,
 *        0 for "reset to empty"
 */
typedef void
(*GNUNET_DATASTORE_DiskUtilizationChange) (void *cls,
                                           int delta);


/**
 * The datastore service will pass a pointer to a struct
 * of this type as the first and only argument to the
 * entry point of each datastore plugin.
 */
struct GNUNET_DATASTORE_PluginEnvironment
{
  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Function to call on disk utilization change.
   */
  GNUNET_DATASTORE_DiskUtilizationChange duc;

  /**
   * Closure.
   */
  void *cls;
};


/**
 * An processor over a set of items stored in the datastore.
 *
 * @param cls closure
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param replication replication-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum
 * @return #GNUNET_OK to keep the item
 *         #GNUNET_NO to delete the item
 */
typedef int
(*PluginDatumProcessor) (void *cls,
                         const struct GNUNET_HashCode *key,
                         uint32_t size,
                         const void *data,
                         enum GNUNET_BLOCK_Type type,
                         uint32_t priority,
                         uint32_t anonymity,
                         uint32_t replication,
                         struct GNUNET_TIME_Absolute expiration,
                         uint64_t uid);


/**
 * Get an estimate of how much space the database is
 * currently using.
 *
 * NB: estimate is an output parameter because emscripten cannot handle
 * returning 64-bit integers from dynamically loaded modules.
 *
 * @param cls closure
 * @param estimate location to store estimate
 * @return number of bytes used on disk
 */
typedef void
(*PluginEstimateSize) (void *cls,
                       unsigned long long *estimate);


/**
 * Put continuation.
 *
 * @param cls closure
 * @param key key for the item stored
 * @param size size of the item stored
 * @param status #GNUNET_OK if inserted, #GNUNET_NO if updated,
 *        or #GNUNET_SYSERROR if error
 * @param msg error message on error
 */
typedef void
(*PluginPutCont) (void *cls,
                  const struct GNUNET_HashCode *key,
                  uint32_t size,
                  int status,
                  const char *msg);


/**
 * Store an item in the datastore.  If the item is already present,
 * the priorities and replication levels are summed up and the higher
 * expiration time and lower anonymity level is used.
 *
 * @param cls closure
 * @param key key for the item
 * @param absent true if the key was not found in the bloom filter
 * @param size number of bytes in @a data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param replication replication-level for the content
 * @param expiration expiration time for the content
 * @param cont continuation called with success or failure status
 * @param cont_cls continuation closure for @a cont
 */
typedef void
(*PluginPut) (void *cls,
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
              void *cont_cls);


/**
 * An processor over a set of keys stored in the datastore.
 *
 * @param cls closure
 * @param key key in the data store, if NULL iteration is finished
 * @param count how many values are stored under this key in the datastore
 */
typedef void
(*PluginKeyProcessor) (void *cls,
                       const struct GNUNET_HashCode *key,
                       unsigned int count);


/**
 * Get all of the keys in the datastore.
 *
 * @param cls closure
 * @param proc function to call on each key
 * @param proc_cls closure for @a proc
 */
typedef void
(*PluginGetKeys) (void *cls,
                  PluginKeyProcessor proc,
                  void *proc_cls);


/**
 * Get one of the results for a particular key in the datastore.
 *
 * @param cls closure
 * @param next_uid return the result with lowest uid >= next_uid
 * @param random if true, return a random result instead of using next_uid
 * @param key maybe NULL (to match all entries)
 * @param type entries of which type are relevant?
 *     Use 0 for any type.
 * @param proc function to call on the matching value;
 *        will be called with NULL if nothing matches
 * @param proc_cls closure for @a proc
 */
typedef void
(*PluginGetKey) (void *cls,
                 uint64_t next_uid,
                 bool random,
                 const struct GNUNET_HashCode *key,
                 enum GNUNET_BLOCK_Type type,
                 PluginDatumProcessor proc,
                 void *proc_cls);


/**
 * Remove continuation.
 *
 * @param cls closure
 * @param key key for the content removed
 * @param size number of bytes removed
 * @param status #GNUNET_OK if removed, #GNUNET_NO if not found,
 *        or #GNUNET_SYSERROR if error
 * @param msg error message on error
 */
typedef void
(*PluginRemoveCont) (void *cls,
                     const struct GNUNET_HashCode *key,
                     uint32_t size,
                     int status,
                     const char *msg);


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
typedef void
(*PluginRemoveKey) (void *cls,
                    const struct GNUNET_HashCode *key,
                    uint32_t size,
                    const void *data,
                    PluginRemoveCont cont,
                    void *cont_cls);


/**
 * Get a random item (additional constraints may apply depending on
 * the specific implementation).  Calls @a proc with all values ZERO or
 * NULL if no item applies, otherwise @a proc is called once and only
 * once with an item.
 *
 * @param cls closure
 * @param proc function to call the value (once only).
 * @param proc_cls closure for @a proc
 */
typedef void
(*PluginGetRandom) (void *cls,
                    PluginDatumProcessor proc,
                    void *proc_cls);


/**
 * Select a single item from the datastore (among those applicable).
 *
 * @param cls closure
 * @param next_uid return the result with lowest uid >= next_uid
 * @param type entries of which type should be considered?
 *        Must not be zero (ANY).
 * @param proc function to call on the matching value;
 *        will be called with NULL if no value matches
 * @param proc_cls closure for @a proc
 */
typedef void
(*PluginGetType) (void *cls,
                  uint64_t next_uid,
                  enum GNUNET_BLOCK_Type type,
                  PluginDatumProcessor proc,
                  void *proc_cls);


/**
 * Drop database.
 *
 * @param cls closure
 */
typedef void
(*PluginDrop) (void *cls);


/**
 * Each plugin is required to return a pointer to a struct of this
 * type as the return value from its entry point.
 */
struct GNUNET_DATASTORE_PluginFunctions
{
  /**
   * Closure to use for all of the following callbacks
   * (except "next_request").
   */
  void *cls;

  /**
   * Calculate the current on-disk size of the SQ store.  Estimates
   * are fine, if that's the only thing available.
   */
  PluginEstimateSize estimate_size;

  /**
   * Function to store an item in the datastore.
   */
  PluginPut put;

  /**
   * Get a particular datum matching a given hash from the datastore.
   */
  PluginGetKey get_key;

  /**
   * Get datum (of the specified type) with anonymity level zero.
   */
  PluginGetType get_zero_anonymity;

  /**
   * Function to get a random item with high replication score from
   * the database, lowering the item's replication score.  Returns a
   * single random item from those with the highest replication
   * counters.  The item's replication counter is decremented by one
   * IF it was positive before.
   */
  PluginGetRandom get_replication;

  /**
   * Function to get a random expired item or, if none are expired,
   * either the oldest entry or one with a low priority (depending
   * on what was efficiently implementable).
   */
  PluginGetRandom get_expiration;

  /**
   * Delete the database.  The next operation is
   * guaranteed to be unloading of the module.
   */
  PluginDrop drop;

  /**
   * Iterate over all keys in the database.
   */
  PluginGetKeys get_keys;

  /**
   * Function to remove an item from the database.
   */
  PluginRemoveKey remove_key;
};

#endif

/** @} */  /* end of group */
