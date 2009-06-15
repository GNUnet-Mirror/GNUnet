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
 * Handle to the datastore service.
 */
struct GNUNET_DATASTORE_Handle;


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
 *
 * @return GNUNET_SYSERR to abort the iteration, GNUNET_OK to continue,
 *         GNUNET_NO to delete the item and continue (if supported)
 */
typedef int (*GNUNET_DATASTORE_Iterator) (void *cls,
                                          const GNUNET_HashCode * key,
                                          uint32_t size,
                                          const void *data,
                                          uint32_t type,
                                          uint32_t priority,
                                          uint32_t anonymity,
                                          struct GNUNET_TIME_Absolute
                                          expiration, unsigned long long uid);

/**
 * Connect to the datastore service.
 *
 * @param cfg configuration to use
 * @param sched scheduler to use
 * @return handle to use to access the service
 */
struct GNUNET_DATASTORE_Handle *GNUNET_DATASTORE_connect (struct
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
 * Get the current on-disk size of the datastore.
 * @param h handle to the datastore
 * @return size estimate, -1 if datastore is not available (yet)
 */
unsigned long long GNUNET_DATASTORE_size (struct GNUNET_DATASTORE_Handle *h);


/**
 * Store an item in the datastore.  If the item is already present,
 * the priorities are summed up and the higher expiration time and
 * lower anonymity level is used.
 *
 * @param h handle to the datastore
 * @param key key for the value
 * @param size number of bytes in data
 * @param data content stored
 * @param type type of the content
 * @param priority priority of the content
 * @param anonymity anonymity-level for the content
 * @param expiration expiration time for the content
 */
void
GNUNET_DATASTORE_put (struct GNUNET_DATASTORE_Handle *h,
                      const GNUNET_HashCode * key,
                      uint32_t size,
                      const void *data,
                      uint32_t type,
                      uint32_t priority,
                      uint32_t anonymity,
                      struct GNUNET_TIME_Absolute expiration);

/**
 * Iterate over the results for a particular key
 * in the datastore.
 *
 * @param h handle to the datastore
 * @param key maybe NULL (to match all entries)
 * @param type desired type, 0 for any
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 */
void
GNUNET_DATASTORE_get (struct GNUNET_DATASTORE_Handle *h,
                      const GNUNET_HashCode * key,
                      uint32_t type,
                      GNUNET_DATASTORE_Iterator iter, void *iter_cls);


/**
 * Get a random value from the datastore.
 *
 * @param h handle to the datastore
 * @param iter function to call on a random value; it
 *        will be called once with a value (if available)
 *        and always once with a value of NULL.
 * @param iter_cls closure for iter
 */
void
GNUNET_DATASTORE_get_random (struct GNUNET_DATASTORE_Handle *h,
                             GNUNET_DATASTORE_Iterator iter, void *iter_cls);


/**
 * Explicitly remove some content from the database.
 *
 * @param h handle to the datastore
 * @param key key for the value
 * @param size number of bytes in data
 * @param data content stored
 */
void
GNUNET_DATASTORE_remove (struct GNUNET_DATASTORE_Handle *h,
                         const GNUNET_HashCode *key,
                         uint32_t size, const void *data);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_datastore_service.h */
#endif
