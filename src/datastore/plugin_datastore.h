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
 * @file datastore/plugin_datastore.h
 * @brief API for the database backend plugins.
 * @author Christian Grothoff
 *
 * TODO:
 * - consider defining enumeration or at least typedef
 *   for the type of "type" (instead of using uint32_t)
 */
#ifndef PLUGIN_DATASTORE_H
#define PLUGIN_DATASTORE_H

#include "gnunet_configuration_lib.h"
#include "gnunet_scheduler_lib.h"
#include "gnunet_datastore_service.h"

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
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Scheduler to use.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

};


/**
 * Get an estimate of how much space the database is
 * currently using.
 * @return number of bytes used on disk
 */
typedef unsigned long long (*GNUNET_DATASTORE_GetSize) (void *cls);


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
 */
typedef void
  (*GNUNET_DATASTORE_Put) (void *cls,
                           const GNUNET_HashCode * key,
                           uint32_t size,
                           const void *data,
                           unit32_t type,
                           uint32_t priority,
                           uint32_t anonymity,
                           struct GNUNET_TIME_Absolute expiration);


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
typedef void
  (*GNUNET_DATASTORE_Get) (void *cls,
                           const GNUNET_HashCode * key,
                           const GNUNET_HashCode * vhash,
                           uint32_t type,
                           GNUNET_DATASTORE_Iterator iter, void *iter_cls);


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
 */
typedef void
  (*GNUNET_DATASTORE_Update) (void *cls,
                              unsigned long long uid,
                              int delta, struct GNUNET_TIME_Absolute expire);


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
typedef void
  (*GNUNET_DATASTORE_Selector) (void *cls,
                                uint32_t type,
                                GNUNET_DATASTORE_Iterator iter,
                                void *iter_cls);

/**
 * Drop database.
 */
typedef void (*GNUNET_DATASTORE_Drop) (void *cls);



/**
 * Each plugin is required to return a pointer to a struct of this
 * type as the return value from its entry point.
 */
struct GNUNET_DATASTORE_PluginFunctions
{

  /**
   * Closure to use for all of the following callbacks.
   */
  void *cls;

  /**
   * Get the current on-disk size of the SQ store.  Estimates are
   * fine, if that's the only thing available.
   */
  GNUNET_DATASTORE_GetSize size;

  /**
   * Function to store an item in the datastore.
   */
  GNUNET_DATASTORE_Put put;

  /**
   * Function to iterate over the results for a particular key
   * in the datastore.
   */
  GNUNET_DATASTORE_Get get;

  /**
   * Update the priority for a particular key in the datastore.  If
   * the expiration time in value is different than the time found in
   * the datastore, the higher value should be kept.  For the
   * anonymity level, the lower value is to be used.  The specified
   * priority should be added to the existing priority, ignoring the
   * priority in value.
   */
  GNUNET_DATASTORE_Update update;

  /**
   * Iterate over the items in the datastore in ascending
   * order of priority.
   */
  GNUNET_DATASTORE_Selector iter_low_priority;

  /**
   * Iterate over content with anonymity zero.
   */
  GNUNET_DATASTORE_Selector iter_zero_anonymity;

  /**
   * Iterate over the items in the datastore in ascending
   * order of expiration time.
   */
  GNUNET_DATSTORE_Selector iter_ascending_expiration;

  /**
   * Iterate over the items in the datastore in migration
   * order.
   */
  GNUNET_DATASTORE_Selector iter_migration_order;

  /**
   * Iterate over all the items in the datastore
   * as fast as possible in a single transaction
   * (can lock datastore while this happens, focus
   * is on doing it fast).
   */
  GNUNET_DATASTORE_Selector iter_all_now;

  /**
   * Delete the database.  The next operation is
   * guaranteed to be unloading of the module.
   */
  GNUNET_DATASTORE_Drop drop;

};


#endif
