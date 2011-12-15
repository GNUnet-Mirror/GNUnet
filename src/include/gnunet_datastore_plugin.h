/*
     This file is part of GNUnet
     (C) 2009, 2011 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_datastore_plugin.h
 * @brief API for the database backend plugins.
 * @author Christian Grothoff
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
typedef void (*DiskUtilizationChange) (void *cls, int delta);


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
  DiskUtilizationChange duc;

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
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum
 *
 * @return GNUNET_OK to keep the item
 *         GNUNET_NO to delete the item
 */
typedef int (*PluginDatumProcessor) (void *cls, const GNUNET_HashCode * key,
                                     uint32_t size, const void *data,
                                     enum GNUNET_BLOCK_Type type,
                                     uint32_t priority, uint32_t anonymity,
                                     struct GNUNET_TIME_Absolute expiration,
                                     uint64_t uid);

/**
 * Get an estimate of how much space the database is
 * currently using.
 *
 * @param cls closure
 * @return number of bytes used on disk
 */
typedef unsigned long long (*PluginEstimateSize) (void *cls);


/**
 * Store an item in the datastore.  If the item is already present,
 * the priorities and replication levels are summed up and the higher
 * expiration time and lower anonymity level is used.
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
 * @param msg set to an error message (on failure)
 * @return GNUNET_OK on success,
 *         GNUNET_SYSERR on failure
 */
typedef int (*PluginPut) (void *cls, const GNUNET_HashCode * key, uint32_t size,
                          const void *data, enum GNUNET_BLOCK_Type type,
                          uint32_t priority, uint32_t anonymity,
                          uint32_t replication,
                          struct GNUNET_TIME_Absolute expiration, char **msg);


/**
 * An processor over a set of keys stored in the datastore.
 *
 * @param cls closure
 * @param key key in the data store
 * @param count how many values are stored under this key in the datastore
 */
typedef void (*PluginKeyProcessor) (void *cls, 
				   const GNUNET_HashCode *key,
				   unsigned int count);


/**
 * Get all of the keys in the datastore.
 *
 * @param cls closure
 * @param proc function to call on each key
 * @param proc_cls closure for proc
 */
typedef void (*PluginGetKeys) (void *cls,
			       PluginKeyProcessor proc, void *proc_cls);


/**
 * Get one of the results for a particular key in the datastore.
 *
 * @param cls closure
 * @param offset offset of the result (modulo num-results);
 *               specific ordering does not matter for the offset
 * @param key key to match, never NULL
 * @param vhash hash of the value, maybe NULL (to
 *        match all values that have the right key).
 *        Note that for DBlocks there is no difference
 *        betwen key and vhash, but for other blocks
 *        there may be!
 * @param type entries of which type are relevant?
 *     Use 0 for any type.
 * @param min find the smallest key that is larger than the given min,
 *            NULL for no minimum (return smallest key)
 * @param proc function to call on the matching value;
 *        proc should be called with NULL if there is no result
 * @param proc_cls closure for proc
 */
typedef void (*PluginGetKey) (void *cls, uint64_t offset,
                              const GNUNET_HashCode * key,
                              const GNUNET_HashCode * vhash,
                              enum GNUNET_BLOCK_Type type,
                              PluginDatumProcessor proc, void *proc_cls);


/**
 * Get a random item (additional constraints may apply depending on
 * the specific implementation).  Calls 'proc' with all values ZERO or
 * NULL if no item applies, otherwise 'proc' is called once and only
 * once with an item.
 *
 * @param cls closure
 * @param proc function to call the value (once only).
 * @param proc_cls closure for proc
 */
typedef void (*PluginGetRandom) (void *cls, PluginDatumProcessor proc,
                                 void *proc_cls);




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
 * @param cls closure
 * @param uid unique identifier of the datum
 * @param delta by how much should the priority
 *     change?  If priority + delta < 0 the
 *     priority should be set to 0 (never go
 *     negative).
 * @param expire new expiration time should be the
 *     MAX of any existing expiration time and
 *     this value
 * @param msg set to an error message (on error)
 * @return GNUNET_OK on success
 */
typedef int (*PluginUpdate) (void *cls, uint64_t uid, int delta,
                             struct GNUNET_TIME_Absolute expire, char **msg);


/**
 * Select a single item from the datastore at the specified offset
 * (among those applicable).
 *
 * @param cls closure
 * @param offset offset of the result (modulo num-results);
 *               specific ordering does not matter for the offset
 * @param type entries of which type should be considered?
 *        Must not be zero (ANY).
 * @param proc function to call on the matching value
 * @param proc_cls closure for proc
 */
typedef void (*PluginGetType) (void *cls, uint64_t offset,
                               enum GNUNET_BLOCK_Type type,
                               PluginDatumProcessor proc, void *proc_cls);


/**
 * Drop database.
 *
 * @param cls closure
 */
typedef void (*PluginDrop) (void *cls);



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
   * Update the priority for a particular key in the datastore.  If
   * the expiration time in value is different than the time found in
   * the datastore, the higher value should be kept.  For the
   * anonymity level, the lower value is to be used.  The specified
   * priority should be added to the existing priority, ignoring the
   * priority in value.
   */
  PluginUpdate update;

  /**
   * Get a particular datum matching a given hash from the datastore.
   */
  PluginGetKey get_key;

  /**
   * Get datum (of the specified type) with anonymity level zero.
   * This function is allowed to ignore the 'offset' argument
   * and instead return a random result (with zero anonymity of
   * the correct type) if implementing an offset is expensive.
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
  
};


#endif
