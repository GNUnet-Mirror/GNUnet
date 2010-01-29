/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file fs/gnunet-service-fs_drq.h
 * @brief queueing of requests to the datastore service
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_FS_DRQ_H
#define GNUNET_SERVICE_FS_DRQ_H

#include "gnunet_datastore_service.h"
#include "gnunet_util_lib.h"


/**
 * Handle for pending, abortable requests for the datastore.
 */
struct DatastoreRequestQueue;


/**
 * Iterate over the results for a particular key
 * in the datastore.  The iterator will only be called
 * once initially; if the first call did contain a
 * result, further results can be obtained by calling
 * "GNUNET_DATASTORE_get_next" with the given argument.
 *
 * @param key maybe NULL (to match all entries)
 * @param type desired type, 0 for any
 * @param iter function to call on each matching value;
 *        will be called once with a NULL value at the end
 * @param iter_cls closure for iter
 * @param timeout how long to wait at most for a response
 */
struct DatastoreRequestQueue *
GNUNET_FS_drq_get (const GNUNET_HashCode * key,
		   uint32_t type,
		   GNUNET_DATASTORE_Iterator iter, 
		   void *iter_cls,
		   struct GNUNET_TIME_Relative timeout);



void
GNUNET_FS_drq_get_cancel (struct DatastoreRequestQueue *drq);


/**
 * Function called to trigger obtaining the next result
 * from the datastore.  Must be called (directly or indirectly)
 * from the 'iter' callback given to 'GNUNET_FS_drq_get'.
 * Not calling 'get_next' means no other datastore
 * interactions (other than remove) will happen.
 * 
 * @param more GNUNET_YES to get more results, GNUNET_NO to abort
 *        iteration (with a final call to "iter" with key/data == NULL).
 */
void
GNUNET_FS_drq_get_next (int more);


/**
 * Explicitly remove some content from the database.
 * The "cont"inuation will be called with status
 * "GNUNET_OK" if content was removed, "GNUNET_NO"
 * if no matching entry was found and "GNUNET_SYSERR"
 * on all other types of errors.
 *
 * @param key key for the value
 * @param size number of bytes in data
 * @param data content stored
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @param timeout how long to wait at most for a response
 */
void
GNUNET_FS_drq_remove (const GNUNET_HashCode *key,
		      uint32_t size, const void *data,
		      GNUNET_DATASTORE_ContinuationWithStatus cont,
		      void *cont_cls,
		      struct GNUNET_TIME_Relative timeout);



/**
 * Explicitly remove some content from the database.
 * The "cont"inuation will be called with status
 * "GNUNET_OK" if content was removed, "GNUNET_NO"
 * if no matching entry was found and "GNUNET_SYSERR"
 * on all other types of errors.
 *
 * @param key key for the value
 * @param size number of bytes in data
 * @param data content stored
 * @param cont continuation to call when done
 * @param cont_cls closure for cont
 * @param timeout how long to wait at most for a response
 */
void
GNUNET_FS_drq_remove (const GNUNET_HashCode *key,
		      uint32_t size, const void *data,
		      GNUNET_DATASTORE_ContinuationWithStatus cont,
		      void *cont_cls,
		      struct GNUNET_TIME_Relative timeout);
/**
 * Setup datastore request queues.
 * 
 * @param s scheduler to use
 * @param c configuration to use
 * @return GNUNET_OK on success
 */
int 
GNUNET_FS_drq_init (struct GNUNET_SCHEDULER_Handle *s,
		    const struct GNUNET_CONFIGURATION_Handle *c);



/* end of gnunet-service-fs_drq.h */
#endif
