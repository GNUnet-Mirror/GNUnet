/*
     This file is part of GNUnet
     (C) 2004, 2005, 2006, 2007, 2009 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_datastore_service.h
 * @brief API that can be used manage the
 *   datastore for files stored on a GNUnet node;
 *   note that the datastore is NOT responsible for
 *   on-demand encoding, that is achieved using
 *   a special kind of entry.
 * @author Christian Grothoff
 */

#ifndef GNUNET_DATASTORE_SERVICE_H
#define GNUNET_DATASTORE_SERVICE_H

#include "gnunet_util_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/**
 * FIXME.
 */
#define GNUNET_DATASTORE_BLOCKTYPE_ANY 0

/**
 * FIXME.
 */
#define GNUNET_DATASTORE_BLOCKTYPE_DBLOCK 1

/**
 * FIXME.
 */
#define GNUNET_DATASTORE_BLOCKTYPE_IBLOCK 2

/**
 * FIXME.
 */
#define GNUNET_DATASTORE_BLOCKTYPE_KBLOCK 3

/**
 * FIXME.
 */
#define GNUNET_DATASTORE_BLOCKTYPE_SBLOCK 4

/**
 * FIXME.
 */
#define GNUNET_DATASTORE_BLOCKTYPE_ONDEMAND 5

/**
 * FIXME.
 */
#define GNUNET_DATASTORE_BLOCKTYPE_SKBLOCK 6 /* not yet used */


/**
 * Handle to the datastore service.
 */
struct GNUNET_DATASTORE_Handle;


/**
 * Connect to the datastore service.
 *
 * @param cfg configuration to use
 * @param sched scheduler to use
 * @return handle to use to access the service
 */
struct GNUNET_DATASTORE_Handle *GNUNET_DATASTORE_connect (const struct
                                                          GNUNET_CONFIGURATION_Handle
                                                          *cfg,
                                                          struct
                                                          GNUNET_SCHEDULER_Handle
                                                          *sched);


/**
 * Disconnect from the datastore service (and free
 * associated resources).
 *
 * @param h handle to the datastore
 * @param drop set to GNUNET_YES to delete all data in datastore (!)
 */
void GNUNET_DATASTORE_disconnect (struct GNUNET_DATASTORE_Handle *h,
				  int drop);


/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure
 * @param success GNUNET_SYSERR on failure
 * @param msg NULL on success, otherwise an error message
 */
typedef void (*GNUNET_DATASTORE_ContinuationWithStatus)(void *cls,
							int success,
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
 * @param cont_cls closure for cont
 * @param timeout how long to wait at most for a response
 */
void
GNUNET_DATASTORE_reserve (struct GNUNET_DATASTORE_Handle *h,
			  uint64_t amount,
			  uint32_t entries,
			  GNUNET_DATASTORE_ContinuationWithStatus cont,
			  void *cont_cls,
			  struct GNUNET_TIME_Relative timeout);


/**
 * Store an item in the datastore.  If the item is already present,
 * the priorities are summed up and the higher expiration time and
 * lower anonymity level is used.
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
 * @param expiration expiration time for the content
 * @param timeout timeout for the operation
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 */
void
GNUNET_DATASTORE_put (struct GNUNET_DATASTORE_Handle *h,
		      int rid,
                      const GNUNET_HashCode * key,
                      uint32_t size,
                      const void *data,
                      uint32_t type,
                      uint32_t priority,
                      uint32_t anonymity,
                      struct GNUNET_TIME_Absolute expiration,
                      struct GNUNET_TIME_Relative timeout,
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
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @param timeout how long to wait at most for a response
 */
void
GNUNET_DATASTORE_release_reserve (struct GNUNET_DATASTORE_Handle *h,
				  int rid,
				  GNUNET_DATASTORE_ContinuationWithStatus cont,
				  void *cont_cls,
				  struct GNUNET_TIME_Relative timeout);


/**
 * Update a value in the datastore.
 *
 * @param h handle to the datastore
 * @param uid identifier for the value
 * @param priority how much to increase the priority of the value
 * @param expiration new expiration value should be MAX of existing and this argument
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @param timeout how long to wait at most for a response
 */
void
GNUNET_DATASTORE_update (struct GNUNET_DATASTORE_Handle *h,
			 unsigned long long uid,
			 uint32_t priority,
			 struct GNUNET_TIME_Absolute expiration,
			 GNUNET_DATASTORE_ContinuationWithStatus cont,
			 void *cont_cls,
			 struct GNUNET_TIME_Relative timeout);


/**
 * An iterator over a set of items stored in the datastore.
 *
 * @param cls closure
 * @param key key for the content
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 * @param uid unique identifier for the datum;
 *        maybe 0 if no unique identifier is available
 */
typedef void (*GNUNET_DATASTORE_Iterator) (void *cls,
					   const GNUNET_HashCode * key,
					   uint32_t size,
					   const void *data,
					   uint32_t type,
					   uint32_t priority,
					   uint32_t anonymity,
					   struct GNUNET_TIME_Absolute
					   expiration, uint64_t uid);


/**
 * Iterate over the results for a particular key
 * in the datastore.  The iterator will only be called
 * once initially; if the first call did contain a
 * result, further results can be obtained by calling
 * "GNUNET_DATASTORE_get_next" with the given argument.
 *
 * @param h handle to the datastore
 * @param key maybe NULL (to match all entries)
 * @param type desired type, 0 for any
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 * @param timeout how long to wait at most for a response
 */
void
GNUNET_DATASTORE_get (struct GNUNET_DATASTORE_Handle *h,
                      const GNUNET_HashCode * key,
		      uint32_t type,
                      GNUNET_DATASTORE_Iterator iter, 
		      void *iter_cls,
		      struct GNUNET_TIME_Relative timeout);


/**
 * Function called to trigger obtaining the next result
 * from the datastore.
 * 
 * @param h handle to the datastore
 * @param more GNUNET_YES to get moxre results, GNUNET_NO to abort
 *        iteration (with a final call to "iter" with key/data == NULL).
 */
void
GNUNET_DATASTORE_get_next (struct GNUNET_DATASTORE_Handle *h,
			   int more);


/**
 * Get a random value from the datastore.
 *
 * @param h handle to the datastore
 * @param iter function to call on a random value; it
 *        will be called once with a value (if available)
 *        and always once with a value of NULL.
 * @param iter_cls closure for iter
 * @param timeout how long to wait at most for a response
 */
void
GNUNET_DATASTORE_get_random (struct GNUNET_DATASTORE_Handle *h,
                             GNUNET_DATASTORE_Iterator iter, void *iter_cls,
			     struct GNUNET_TIME_Relative timeout);


/**
 * Explicitly remove some content from the database.
 * The "cont"inuation will be called with status
 * "GNUNET_OK" if content was removed, "GNUNET_NO"
 * if no matching entry was found and "GNUNET_SYSERR"
 * on all other types of errors.
 *
 * @param h handle to the datastore
 * @param key key for the value
 * @param size number of bytes in data
 * @param data content stored
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @param timeout how long to wait at most for a response
 */
void
GNUNET_DATASTORE_remove (struct GNUNET_DATASTORE_Handle *h,
                         const GNUNET_HashCode *key,
                         uint32_t size, const void *data,
			 GNUNET_DATASTORE_ContinuationWithStatus cont,
			 void *cont_cls,
			 struct GNUNET_TIME_Relative timeout);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_datastore_service.h */
#endif
