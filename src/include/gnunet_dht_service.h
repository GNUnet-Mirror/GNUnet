/*
      This file is part of GNUnet
      (C) 2004, 2005, 2006, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file include/gnunet_dht_service.h
 * @brief API to the DHT service
 * @author Christian Grothoff
 */

#ifndef GNUNET_DHT_SERVICE_H
#define GNUNET_DHT_SERVICE_H

#include "gnunet_util_lib.h"

#ifdef __cplusplus
extern "C"
{
#if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif


/**
 * Connection to the DHT service.
 */
struct GNUNET_DHT_Handle;


/**
 * Initialize the connection with the DHT service.
 * 
 * @param cfg configuration to use
 * @param sched scheduler to use
 * @return NULL on error
 */
struct GNUNET_DHT_Handle *
GNUNET_DHT_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
		    struct GNUNET_SCHEDULER_Handle *sched);


/**
 * Shutdown connection with the DHT service.
 *
 * @param h connection to shut down
 */
void
GNUNET_DHT_connect (struct GNUNET_DHT_Handle *h);


/**
 * Handle to control a GET operation.
 */
struct GNUNET_DHT_GetHandle;


/**
 * Iterator called on each result obtained for a GET
 * operation.
 *
 * @param cls closure
 * @param exp when will this value expire
 * @param key key of the result
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 */
typedef void (*GNUNET_DHT_Iterator)(void *cls,
				    struct GNUNET_TIME_Absolute exp,
				    const GNUNET_HashCode * key,
				    uint32_t type,
				    uint32_t size,
				    const void *data);
		      

/**
 * Perform an asynchronous GET operation on the DHT identified.
 *
 * @param h handle to the DHT service
 * @param type expected type of the response object
 * @param key the key to look up
 * @param iter function to call on each result
 * @param iter_cls closure for iter
 * @return handle to stop the async get
 */
struct GNUNET_DHT_GetHandle *
GNUNET_DHT_get_start (struct GNUNET_DHT_Handle *h,
		      uint32_t type,
		      const GNUNET_HashCode * key,
		      GNUNET_DHT_Iterator iter,
		      void *iter_cls);


/**
 * Stop async DHT-get.  Frees associated resources.
 *
 * @param record GET operation to stop.
 */
void
GNUNET_DHT_get_stop (struct GNUNET_DHT_GetHandle *record);


/**
 * Perform a PUT operation on the DHT identified by 'table' storing
 * a binding of 'key' to 'value'.  The peer does not have to be part
 * of the table (if so, we will attempt to locate a peer that is!)
 *
 * @param h handle to DHT service
 * @param key the key to store under
 * @param type type of the value
 * @param size number of bytes in data; must be less than 64k
 * @param data the data to store
 * @param exp desired expiration time for the value
 * @param cont continuation to call when done; 
 *             reason will be TIMEOUT on error,
 *             reason will be PREREQ_DONE on success
 * @param cont_cls closure for cont
 * 
 */
int GNUNET_DHT_put (struct GNUNET_DHT_Handle *h, 
		    const GNUNET_HashCode * key,
		    uint32_t type, 		    
		    uint32_t size, 
		    const char *data,
		    struct GNUNET_TIME_Relative exp,
		    GNUNET_SCHEDULER_Task cont,
		    void *cont_cls);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif 
/* gnunet_dht_service.h */
