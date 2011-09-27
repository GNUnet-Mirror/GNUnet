/*
      This file is part of GNUnet
      (C) 2004, 2005, 2006, 2008, 2009, 2011 Christian Grothoff (and other contributing authors)

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
#include "gnunet_block_lib.h"
#include "gnunet_hello_lib.h"

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
 * Handle to control a get operation.
 */
struct GNUNET_DHT_GetHandle;

/**
 * Handle to control a find peer operation.
 */
struct GNUNET_DHT_FindPeerHandle;


/**
 * Options for routing.
 */
enum GNUNET_DHT_RouteOption
{
    /**
     * Default.  Do nothing special.
     */
  GNUNET_DHT_RO_NONE = 0,

    /**
     * Each peer along the way should look at 'enc' (otherwise
     * only the k-peers closest to the key should look at it).
     */
  GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE = 1,

    /**
     * We should keep track of the route that the message
     * took in the P2P network.
     */
  GNUNET_DHT_RO_RECORD_ROUTE = 2,

  /**
   * This is a 'FIND-PEER' request, so approximate results are fine.
   */
  GNUNET_DHT_RO_FIND_PEER = 4,

    /**
     * Possible message option for query key randomization.
     */
  GNUNET_DHT_RO_BART = 8
};


/**
 * Initialize the connection with the DHT service.
 *
 * @param cfg configuration to use
 * @param ht_len size of the internal hash table to use for
 *               processing multiple GET/FIND requests in parallel
 * @return NULL on error
 */
struct GNUNET_DHT_Handle *
GNUNET_DHT_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    unsigned int ht_len);


/**
 * Shutdown connection with the DHT service.
 *
 * @param handle connection to shut down
 */
void
GNUNET_DHT_disconnect (struct GNUNET_DHT_Handle *handle);


/* *************** Standard API: get and put ******************* */

/**
 * Perform a PUT operation storing data in the DHT.
 *
 * @param handle handle to DHT service
 * @param key the key to store under
 * @param desired_replication_level estimate of how many
 *                nearest peers this request should reach
 * @param options routing options for this message
 * @param type type of the value
 * @param size number of bytes in data; must be less than 64k
 * @param data the data to store
 * @param exp desired expiration time for the value
 * @param timeout how long to wait for transmission of this request
 * @param cont continuation to call when done (transmitting request to service)
 * @param cont_cls closure for cont
 */
void
GNUNET_DHT_put (struct GNUNET_DHT_Handle *handle, const GNUNET_HashCode * key,
                uint32_t desired_replication_level,
                enum GNUNET_DHT_RouteOption options,
                enum GNUNET_BLOCK_Type type, size_t size, const char *data,
                struct GNUNET_TIME_Absolute exp,
                struct GNUNET_TIME_Relative timeout, GNUNET_SCHEDULER_Task cont,
                void *cont_cls);


/**
 * Iterator called on each result obtained for a DHT
 * operation that expects a reply
 *
 * @param cls closure
 * @param exp when will this value expire
 * @param key key of the result
 * @param get_path peers on reply path (or NULL if not recorded)
 * @param get_path_length number of entries in get_path
 * @param put_path peers on the PUT path (or NULL if not recorded)
 * @param put_path_length number of entries in get_path
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 */
typedef void (*GNUNET_DHT_GetIterator) (void *cls,
                                        struct GNUNET_TIME_Absolute exp,
                                        const GNUNET_HashCode * key,
                                        const struct GNUNET_PeerIdentity *get_path,
					unsigned int get_path_length,
                                        const struct GNUNET_PeerIdentity *put_path,
					unsigned int put_path_length,
                                        enum GNUNET_BLOCK_Type type,
                                        size_t size, const void *data);



/**
 * Perform an asynchronous GET operation on the DHT identified. See
 * also "GNUNET_BLOCK_evaluate".
 *
 * @param handle handle to the DHT service
 * @param timeout how long to wait for transmission of this request to the service
 * @param type expected type of the response object
 * @param key the key to look up
 * @param desired_replication_level estimate of how many
                  nearest peers this request should reach
 * @param options routing options for this message
 * @param xquery extended query data (can be NULL, depending on type)
 * @param xquery_size number of bytes in xquery
 * @param iter function to call on each result
 * @param iter_cls closure for iter
 *
 * @return handle to stop the async get
 */
struct GNUNET_DHT_GetHandle *
GNUNET_DHT_get_start (struct GNUNET_DHT_Handle *handle,
                      struct GNUNET_TIME_Relative timeout,
                      enum GNUNET_BLOCK_Type type, const GNUNET_HashCode * key,
                      uint32_t desired_replication_level,
                      enum GNUNET_DHT_RouteOption options,
                      const void *xquery,
                      size_t xquery_size, GNUNET_DHT_GetIterator iter,
                      void *iter_cls);


/**
 * Stop async DHT-get.  Frees associated resources.
 *
 * @param get_handle GET operation to stop.
 *
 * On return get_handle will no longer be valid, caller
 * must not use again!!!
 */
void
GNUNET_DHT_get_stop (struct GNUNET_DHT_GetHandle *get_handle);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
/* gnunet_dht_service.h */
