/*
     This file is part of GNUnet
     Copyright (C) 2012, 2013 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 3, or (at your
     option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     General Public License for more details.

     You should have received a copy of the GNU General Public License
     along with GNUnet; see the file COPYING.  If not, write to the
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file include/gnunet_namecache_service.h
 * @brief API that can be used to store naming information on a GNUnet node;
 *        Naming information can either be records for which this peer/user
 *        is authoritative, or blocks which are cached, encrypted naming
 *        data from other peers.
 * @author Christian Grothoff
 */
#ifndef GNUNET_NAMECACHE_SERVICE_H
#define GNUNET_NAMECACHE_SERVICE_H

#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"
#include "gnunet_namestore_service.h"

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
struct GNUNET_NAMECACHE_QueueEntry;

/**
 * Handle to the namecache service.
 */
struct GNUNET_NAMECACHE_Handle;

/**
 * Maximum size of a value that can be stored in the namecache.
 */
#define GNUNET_NAMECACHE_MAX_VALUE_SIZE (63 * 1024)


/**
 * Connect to the namecache service.
 *
 * @param cfg configuration to use
 * @return handle to use to access the service
 */
struct GNUNET_NAMECACHE_Handle *
GNUNET_NAMECACHE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg);


/**
 * Disconnect from the namecache service (and free associated
 * resources).  Must not be called from within operation callbacks of
 * the API.
 *
 * @param h handle to the namecache
 */
void
GNUNET_NAMECACHE_disconnect (struct GNUNET_NAMECACHE_Handle *h);


/**
 * Continuation called to notify client about result of the
 * operation.
 *
 * @param cls closure
 * @param success #GNUNET_SYSERR on failure (including timeout/queue drop/failure to validate)
 *                #GNUNET_NO if content was already there or not found
 *                #GNUNET_YES (or other positive value) on success
 * @param emsg NULL on success, otherwise an error message
 */
typedef void (*GNUNET_NAMECACHE_ContinuationWithStatus) (void *cls,
                                                         int32_t success,
                                                         const char *emsg);



/**
 * Store an item in the namecache.  If the item is already present,
 * it is replaced with the new record.
 *
 * @param h handle to the namecache
 * @param block block to store
 * @param cont continuation to call when done
 * @param cont_cls closure for @a cont
 * @return handle to abort the request
 */
struct GNUNET_NAMECACHE_QueueEntry *
GNUNET_NAMECACHE_block_cache (struct GNUNET_NAMECACHE_Handle *h,
			      const struct GNUNET_GNSRECORD_Block *block,
			      GNUNET_NAMECACHE_ContinuationWithStatus cont,
			      void *cont_cls);


/**
 * Process a record that was stored in the namecache.
 *
 * @param cls closure
 * @param block block that was stored in the namecache
 */
typedef void (*GNUNET_NAMECACHE_BlockProcessor) (void *cls,
						 const struct GNUNET_GNSRECORD_Block *block);


/**
 * Get a result for a particular key from the namecache.  The processor
 * will only be called once.
 *
 * @param h handle to the namecache
 * @param derived_hash hash of zone key combined with name to lookup
 *        then at the end once with NULL
 * @param proc function to call on the matching block, or with
 *        NULL if there is no matching block
 * @param proc_cls closure for @a proc
 * @return a handle that can be used to cancel
 */
struct GNUNET_NAMECACHE_QueueEntry *
GNUNET_NAMECACHE_lookup_block (struct GNUNET_NAMECACHE_Handle *h,
			       const struct GNUNET_HashCode *derived_hash,
			       GNUNET_NAMECACHE_BlockProcessor proc, void *proc_cls);


/**
 * Cancel a namecache operation.  The final callback from the
 * operation must not have been done yet.  Must be called on any
 * namecache operation that has not yet completed prior to calling
 * #GNUNET_NAMECACHE_disconnect.
 *
 * @param qe operation to cancel
 */
void
GNUNET_NAMECACHE_cancel (struct GNUNET_NAMECACHE_QueueEntry *qe);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of gnunet_namecache_service.h */
#endif
