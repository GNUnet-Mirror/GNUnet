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
 * Default republication frequency for stored data in the DHT.
 */
#define GNUNET_DHT_DEFAULT_REPUBLISH_FREQUENCY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_MINUTES, 60)



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
 * Opaque handle to cancel a PUT operation.
 */
struct GNUNET_DHT_PutHandle;


/**
 * Type of a PUT continuation.  You must not call
 * "GNUNET_DHT_disconnect" in this continuation.
 *
 * @param cls closure
 * @param success GNUNET_OK if the PUT was transmitted,
 *                GNUNET_NO on timeout,
 *                GNUNET_SYSERR on disconnect from service
 *                after the PUT message was transmitted
 *                (so we don't know if it was received or not)
 */
typedef void (*GNUNET_DHT_PutContinuation)(void *cls,
					   int success);


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
 *        You must not call "GNUNET_DHT_disconnect" in this continuation
 * @param cont_cls closure for cont
 * @return handle to cancel the "PUT" operation, NULL on error
 *        (size too big)
 */
struct GNUNET_DHT_PutHandle *
GNUNET_DHT_put (struct GNUNET_DHT_Handle *handle, const GNUNET_HashCode * key,
                uint32_t desired_replication_level,
                enum GNUNET_DHT_RouteOption options,
                enum GNUNET_BLOCK_Type type, size_t size, const char *data,
                struct GNUNET_TIME_Absolute exp,
                struct GNUNET_TIME_Relative timeout,
		GNUNET_DHT_PutContinuation cont,
                void *cont_cls);


/**
 * Cancels a DHT PUT operation.  Note that the PUT request may still
 * go out over the network (we can't stop that); However, if the PUT
 * has not yet been sent to the service, cancelling the PUT will stop
 * this from happening (but there is no way for the user of this API
 * to tell if that is the case).  The only use for this API is to 
 * prevent a later call to 'cont' from "GNUNET_DHT_put" (i.e. because
 * the system is shutting down).
 *
 * @param ph put operation to cancel ('cont' will no longer be called)
 */
void
GNUNET_DHT_put_cancel (struct GNUNET_DHT_PutHandle *ph);


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
                                        const struct GNUNET_PeerIdentity *
                                        get_path, unsigned int get_path_length,
                                        const struct GNUNET_PeerIdentity *
                                        put_path, unsigned int put_path_length,
                                        enum GNUNET_BLOCK_Type type,
                                        size_t size, const void *data);



/**
 * Perform an asynchronous GET operation on the DHT identified. See
 * also "GNUNET_BLOCK_evaluate".
 *
 * @param handle handle to the DHT service
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
                      enum GNUNET_BLOCK_Type type, const GNUNET_HashCode * key,
                      uint32_t desired_replication_level,
                      enum GNUNET_DHT_RouteOption options, const void *xquery,
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


/* *************** Extended API: monitor ******************* */

/**
 * Handle to monitor requests
 */
struct GNUNET_DHT_MonitorHandle;

/**
 * Callback called on each GET request going through the DHT.
 *
 * @param cls Closure.
 * @param options Options, for instance RecordRoute, DemultiplexEverywhere.
 * @param type The type of data in the request.
 * @param hop_count Hop count so far.
 * @param path_length number of entries in path (or 0 if not recorded).
 * @param path peers on the GET path (or NULL if not recorded).
 * @param desired_replication_level Desired replication level.
 * @param key Key of the requested data.
 */
typedef void (*GNUNET_DHT_MonitorGetCB) (void *cls,
                                         enum GNUNET_DHT_RouteOption options,
                                         enum GNUNET_BLOCK_Type type,
                                         uint32_t hop_count,
                                         uint32_t desired_replication_level, 
                                         unsigned int path_length,
                                         const struct GNUNET_PeerIdentity *path,
                                         const GNUNET_HashCode * key);

/**
 * Callback called on each GET reply going through the DHT.
 *
 * @param cls Closure.
 * @param type The type of data in the result.
 * @param get_path Peers on GET path (or NULL if not recorded).
 * @param get_path_length number of entries in get_path.
 * @param put_path peers on the PUT path (or NULL if not recorded).
 * @param put_path_length number of entries in get_path.
 * @param exp Expiration time of the data.
 * @param key Key of the data.
 * @param data Pointer to the result data.
 * @param size Number of bytes in data.
 */
typedef void (*GNUNET_DHT_MonitorGetRespCB) (void *cls,
                                             enum GNUNET_BLOCK_Type type,
                                             const struct GNUNET_PeerIdentity
                                             *get_path,
                                             unsigned int get_path_length,
                                             const struct GNUNET_PeerIdentity
                                             * put_path,
                                             unsigned int put_path_length,
                                             struct GNUNET_TIME_Absolute exp,
                                             const GNUNET_HashCode * key,
                                             const void *data,
                                             size_t size);

/**
 * Callback called on each PUT request going through the DHT.
 *
 * @param cls Closure.
 * @param options Options, for instance RecordRoute, DemultiplexEverywhere.
 * @param type The type of data in the request.
 * @param hop_count Hop count so far.
 * @param path_length number of entries in path (or 0 if not recorded).
 * @param path peers on the PUT path (or NULL if not recorded).
 * @param desired_replication_level Desired replication level.
 * @param exp Expiration time of the data.
 * @param key Key under which data is to be stored.
 * @param data Pointer to the data carried.
 * @param size Number of bytes in data.
 */
typedef void (*GNUNET_DHT_MonitorPutCB) (void *cls,
                                         enum GNUNET_DHT_RouteOption options,
                                         enum GNUNET_BLOCK_Type type,
                                         uint32_t hop_count,
                                         uint32_t desired_replication_level, 
                                         unsigned int path_length,
                                         const struct GNUNET_PeerIdentity *path,
                                         struct GNUNET_TIME_Absolute exp,
                                         const GNUNET_HashCode * key,
                                         const void *data,
                                         size_t size);

/**
 * Start monitoring the local DHT service.
 *
 * @param handle Handle to the DHT service.
 * @param type Type of blocks that are of interest.
 * @param key Key of data of interest, NULL for all.
 * @param get_cb Callback to process monitored get messages.
 * @param get_resp_cb Callback to process monitored get response messages.
 * @param put_cb Callback to process monitored put messages.
 * @param cb_cls Closure for cb.
 *
 * @return Handle to stop monitoring.
 */
struct GNUNET_DHT_MonitorHandle *
GNUNET_DHT_monitor_start (struct GNUNET_DHT_Handle *handle,
                          enum GNUNET_BLOCK_Type type,
                          const GNUNET_HashCode *key,
                          GNUNET_DHT_MonitorGetCB get_cb,
                          GNUNET_DHT_MonitorGetRespCB get_resp_cb,
                          GNUNET_DHT_MonitorPutCB put_cb,
                          void *cb_cls);


/**
 * Stop monitoring.
 *
 * @param handle The handle to the monitor request returned by monitor_start.
 *
 * On return handle will no longer be valid, caller must not use again!!!
 */
void
GNUNET_DHT_monitor_stop (struct GNUNET_DHT_MonitorHandle *handle);


#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
/* gnunet_dht_service.h */
