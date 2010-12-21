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
typedef void (*DiskUtilizationChange)(void *cls,
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
  DiskUtilizationChange duc;

  /**
   * Closure.
   */
  void *cls;

};


/**
 * Function invoked on behalf of a "PluginIterator"
 * asking the database plugin to call the iterator
 * with the next item.
 *
 * @param next_cls whatever argument was given
 *        to the PluginIterator as "next_cls".
 * @param end_it set to GNUNET_YES if we
 *        should terminate the iteration early
 *        (iterator should be still called once more
 *         to signal the end of the iteration).
 */
typedef void (*PluginNextRequest)(void *next_cls,
				  int end_it);


/**
 * An iterator over a set of items stored in the datastore.
 *
 * @param cls closure
 * @param next_cls closure to pass to the "next" function.
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 *
 * @return GNUNET_SYSERR to abort the iteration, GNUNET_OK to continue
 *         (continue on call to "next", of course),
 *         GNUNET_NO to delete the item and continue (if supported)
 */
typedef int (*PluginIterator) (void *cls,
			       void *next_cls,
			       const GNUNET_HashCode * key,
			       uint32_t size,
			       const void *data,
			       enum GNUNET_BLOCK_Type type,
			       uint32_t priority,
			       uint32_t anonymity,
			       struct GNUNET_TIME_Absolute
			       expiration, 
			       uint64_t uid);

/**
 * Get an estimate of how much space the database is
 * currently using.
 *
 * @param cls closure
 * @return number of bytes used on disk
 */
typedef unsigned long long (*PluginGetSize) (void *cls);


/**
 * Store an item in the datastore.  If the item is already present,
 * the priorities are summed up and the higher expiration time and
 * lower anonymity level is used.
 *
 * @param cls closure
 * @param key key for the item
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param msg set to an error message (on failure)
 * @return GNUNET_OK on success, GNUNET_NO if the content
 *         was already present (and may have been updated);
 *         GNUNET_SYSERR on failure
 */
typedef int (*PluginPut) (void *cls,
			  const GNUNET_HashCode * key,
			  uint32_t size,
			  const void *data,
			  enum GNUNET_BLOCK_Type type,
			  uint32_t priority,
			  uint32_t anonymity,
			  struct GNUNET_TIME_Absolute expiration,
			   char **msg);


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
 * @param iter function to call on each matching value; however,
 *        after the first call to "iter", the plugin must wait
 *        until "NextRequest" was called before giving the iterator
 *        the next item; finally, the "iter" should be called once
 *        once with a NULL value at the end ("next_cls" should be NULL
 *        for that last call)
 * @param iter_cls closure for iter
 */
typedef void (*PluginGet) (void *cls,
			   const GNUNET_HashCode * key,
			   const GNUNET_HashCode * vhash,
			   enum GNUNET_BLOCK_Type type,
			   PluginIterator iter, void *iter_cls);


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
typedef int (*PluginUpdate) (void *cls,
			     uint64_t uid,
			     int delta, struct GNUNET_TIME_Absolute expire,
			     char **msg);


/**
 * Select a subset of the items in the datastore and call
 * the given iterator for each of them.
 *
 * @param cls closure
 * @param type entries of which type should be considered?
 *        Use 0 for any type.
 * @param iter function to call on each matching value; however,
 *        after the first call to "iter", the plugin must wait
 *        until "NextRequest" was called before giving the iterator
 *        the next item; finally, the "iter" should be called once
 *        once with a NULL value at the end ("next_cls" should be NULL
 *        for that last call)
 * @param iter_cls closure for iter
 */
typedef void (*PluginSelector) (void *cls,
                                enum GNUNET_BLOCK_Type type,
                                PluginIterator iter,
                                void *iter_cls);

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
   * Get the current on-disk size of the SQ store.  Estimates are
   * fine, if that's the only thing available.
   */
  PluginGetSize get_size;

  /**
   * Function to store an item in the datastore.
   */
  PluginPut put;

  /**
   * Function called by iterators whenever they want the next value;
   * note that unlike all of the other callbacks, this one does get a
   * the "next_cls" closure which is usually different from the "cls"
   * member of this struct!
   */
  PluginNextRequest next_request;

  /**
   * Function to iterate over the results for a particular key
   * in the datastore.
   */
  PluginGet get;

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
   * Iterate over the items in the datastore in ascending
   * order of priority.
   */
  PluginSelector iter_low_priority;

  /**
   * Iterate over content with anonymity zero.
   */
  PluginSelector iter_zero_anonymity;

  /**
   * Iterate over the items in the datastore in ascending order of
   * expiration time. 
   */
  PluginSelector iter_ascending_expiration;

  /**
   * Iterate over the items in the datastore in migration
   * order.  Call the given function on the next item only
   * (and then signal 'end' with a second call).  This is
   * a significant difference from all the other iterators!
   */
  PluginSelector iter_migration_order;

  /**
   * Iterate over all the items in the datastore
   * as fast as possible in a single transaction
   * (can lock datastore while this happens, focus
   * is on doing it fast).
   */
  PluginSelector iter_all_now;

  /**
   * Delete the database.  The next operation is
   * guaranteed to be unloading of the module.
   */
  PluginDrop drop;

};


#endif
