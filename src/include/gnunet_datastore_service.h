/*
     This file is part of GNUnet
     Copyright (C) 2004, 2005, 2006, 2007, 2009, 2010, 2011 GNUnet e.V.

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
 * datastore service
 *
 * @defgroup datastore  Data Store service
 * Data store for files stored on a GNUnet node.
 *
 * Provides an API that can be used manage the
 * datastore for files stored on a GNUnet node.
 * Note that the datastore is NOT responsible for
 * on-demand encoding, that is achieved using
 * a special kind of entry.
 *
 * @{
 */

#ifndef GNUNET_DATASTORE_SERVICE_H
#define GNUNET_DATASTORE_SERVICE_H

#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * Entry in the queue.
 */
struct GNUNET_DATASTORE_QueueEntry;

/**
 * Handle to the datastore service.
 */
struct GNUNET_DATASTORE_Handle;

/**
 * Maximum size of a value that can be stored in the datastore.
 */
#define GNUNET_DATASTORE_MAX_VALUE_SIZE 65536

/**
 * Connect to the datastore service.
 *
 * @param cfg configuration to use
 * @return handle to use to access the service
 */
struct GNUNET_DATASTORE_Handle *
GNUNET_DATASTORE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Disconnect from the datastore service (and free
 * associated resources).
 *
 * @param h handle to the datastore
 * @param drop set to #GNUNET_YES to delete all data in datastore (!)
 */
void
GNUNET_DATASTORE_disconnect (struct GNUNET_DATASTORE_Handle *h,
                             int drop);


/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure
 * @param success #GNUNET_SYSERR on failure
 *                #GNUNET_NO if content was already there
 *                #GNUNET_YES (or other positive value) on success
 * @param min_expiration minimum expiration time required for 0-priority content to be stored
 *                by the datacache at this time, zero for unknown, forever if we have no
 *                space for 0-priority content
 * @param msg NULL on success, otherwise an error message
 */
typedef void
(*GNUNET_DATASTORE_ContinuationWithStatus) (void *cls,
                                            int32_t success,
                                            struct GNUNET_TIME_Absolute
                                            min_expiration,
                                            const char *msg);


/**
 * Reserve space in the datastore.  This function should be used
 * to avoid "out of space" failures during a longer sequence of "put"
 * operations (for example, when a file is being inserted).
 *
 * @param h handle to the datastore
 * @param amount how much space (in bytes) should be reserved (for content only)
 * @param entries how many entries will be created (to calculate per-entry overhead)
 * @param cont continuation to call when done; "success" will be set to
 *             a positive reservation value if space could be reserved.
 * @param cont_cls closure for @a cont
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel; note that even if NULL is returned, the callback will be invoked
 *         (or rather, will already have been invoked)
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_reserve (struct GNUNET_DATASTORE_Handle *h,
                          uint64_t amount,
                          uint32_t entries,
                          GNUNET_DATASTORE_ContinuationWithStatus cont,
                          void *cont_cls);


/**
 * Store an item in the datastore.  If the item is already present,
 * the priorities and replication values are summed up and the higher
 * expiration time and lower anonymity level is used.
 *
 * @param h handle to the datastore
 * @param rid reservation ID to use (from "reserve"); use 0 if no
 *            prior reservation was made
 * @param key key for the value
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param replication how often should the content be replicated to other peers?
 * @param expiration expiration time for the content
 * @param queue_priority ranking of this request in the priority queue
 * @param max_queue_size at what queue size should this request be dropped
 *        (if other requests of higher priority are in the queue)
 * @param cont continuation to call when done
 * @param cont_cls closure for @a cont
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel; note that even if NULL is returned, the callback will be invoked
 *         (or rather, will already have been invoked)
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_put (struct GNUNET_DATASTORE_Handle *h,
                      uint32_t rid,
                      const struct GNUNET_HashCode *key,
                      size_t size,
                      const void *data,
                      enum GNUNET_BLOCK_Type type,
                      uint32_t priority,
                      uint32_t anonymity,
                      uint32_t replication,
                      struct GNUNET_TIME_Absolute expiration,
                      unsigned int queue_priority,
                      unsigned int max_queue_size,
                      GNUNET_DATASTORE_ContinuationWithStatus cont,
                      void *cont_cls);


/**
 * Signal that all of the data for which a reservation was made has
 * been stored and that whatever excess space might have been reserved
 * can now be released.
 *
 * @param h handle to the datastore
 * @param rid reservation ID (value of "success" in original continuation
 *        from the "reserve" function).
 * @param queue_priority ranking of this request in the priority queue
 * @param max_queue_size at what queue size should this request be dropped
 *        (if other requests of higher priority are in the queue)
 * @param queue_priority ranking of this request in the priority queue
 * @param max_queue_size at what queue size should this request be dropped
 *        (if other requests of higher priority are in the queue)
 * @param cont continuation to call when done
 * @param cont_cls closure for @a cont
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel; note that even if NULL is returned, the callback will be invoked
 *         (or rather, will already have been invoked)
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_release_reserve (struct GNUNET_DATASTORE_Handle *h,
                                  uint32_t rid, unsigned int queue_priority,
                                  unsigned int max_queue_size,
                                  GNUNET_DATASTORE_ContinuationWithStatus cont,
                                  void *cont_cls);


/**
 * Explicitly remove some content from the database.  @a cont will be
 * called with status #GNUNET_OK if content was removed, #GNUNET_NO if
 * no matching entry was found and #GNUNET_SYSERR on all other types
 * of errors.
 *
 * @param h handle to the datastore
 * @param key key for the value
 * @param size number of bytes in @a data
 * @param data content stored
 * @param queue_priority ranking of this request in the priority queue
 * @param max_queue_size at what queue size should this request be dropped
 *        (if other requests of higher priority are in the queue)
 * @param cont continuation to call when done
 * @param cont_cls closure for @a cont
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel; note that even if NULL is returned, the callback will be invoked
 *         (or rather, will already have been invoked)
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_remove (struct GNUNET_DATASTORE_Handle *h,
                         const struct GNUNET_HashCode *key,
                         size_t size,
                         const void *data,
                         unsigned int queue_priority,
                         unsigned int max_queue_size,
                         GNUNET_DATASTORE_ContinuationWithStatus cont,
                         void *cont_cls);


/**
 * Process a datum that was stored in the datastore.
 *
 * @param cls closure
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param replication how often should the content be replicated to other peers?
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 */
typedef void
(*GNUNET_DATASTORE_DatumProcessor) (void *cls,
                                    const struct GNUNET_HashCode *key,
                                    size_t size,
                                    const void *data,
                                    enum GNUNET_BLOCK_Type type,
                                    uint32_t priority,
                                    uint32_t anonymity,
                                    uint32_t replication,
                                    struct GNUNET_TIME_Absolute expiration,
                                    uint64_t uid);


/**
 * Get a result for a particular key from the datastore.  The processor
 * will only be called once.
 *
 * @param h handle to the datastore
 * @param next_uid return the result with lowest uid >= next_uid
 * @param random if true, return a random result instead of using next_uid
 * @param key maybe NULL (to match all entries)
 * @param type desired type, 0 for any
 * @param queue_priority ranking of this request in the priority queue
 * @param max_queue_size at what queue size should this request be dropped
 *        (if other requests of higher priority are in the queue)
 * @param proc function to call on a matching value;
 *        or with a NULL value if no datum matches
 * @param proc_cls closure for @a proc
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_get_key (struct GNUNET_DATASTORE_Handle *h,
                          uint64_t next_uid,
                          bool random,
                          const struct GNUNET_HashCode *key,
                          enum GNUNET_BLOCK_Type type,
                          unsigned int queue_priority,
                          unsigned int max_queue_size,
                          GNUNET_DATASTORE_DatumProcessor proc,
                          void *proc_cls);


/**
 * Get a single zero-anonymity value from the datastore.
 *
 * @param h handle to the datastore
 * @param next_uid return the result with lowest uid >= next_uid
 * @param queue_priority ranking of this request in the priority queue
 * @param max_queue_size at what queue size should this request be dropped
 *        (if other requests of higher priority are in the queue)
 * @param type allowed type for the operation (never zero)
 * @param proc function to call on a random value; it
 *        will be called once with a value (if available)
 *        or with NULL if none value exists.
 * @param proc_cls closure for proc
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_get_zero_anonymity (struct GNUNET_DATASTORE_Handle *h,
                                     uint64_t next_uid,
                                     unsigned int queue_priority,
                                     unsigned int max_queue_size,
                                     enum GNUNET_BLOCK_Type type,
                                     GNUNET_DATASTORE_DatumProcessor proc,
                                     void *proc_cls);


/**
 * Get a random value from the datastore for content replication.
 * Returns a single, random value among those with the highest
 * replication score, lowering positive replication scores by one for
 * the chosen value (if only content with a replication score exists,
 * a random value is returned and replication scores are not changed).
 *
 * @param h handle to the datastore
 * @param queue_priority ranking of this request in the priority queue
 * @param max_queue_size at what queue size should this request be dropped
 *        (if other requests of higher priority are in the queue)
 * @param proc function to call on a random value; it
 *        will be called once with a value (if available)
 *        and always once with a value of NULL.
 * @param proc_cls closure for @a proc
 * @return NULL if the entry was not queued, otherwise a handle that can be used to
 *         cancel
 */
struct GNUNET_DATASTORE_QueueEntry *
GNUNET_DATASTORE_get_for_replication (struct GNUNET_DATASTORE_Handle *h,
                                      unsigned int queue_priority,
                                      unsigned int max_queue_size,
                                      GNUNET_DATASTORE_DatumProcessor proc,
                                      void *proc_cls);



/**
 * Cancel a datastore operation.  The final callback from the
 * operation must not have been done yet.
 *
 * @param qe operation to cancel
 */
void
GNUNET_DATASTORE_cancel (struct GNUNET_DATASTORE_QueueEntry *qe);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

#endif

/** @} */  /* end of group */
