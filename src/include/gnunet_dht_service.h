/*
      This file is part of GNUnet
      (C) 2004, 2005, 2006, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * K-value that must be used for the bloom filter 'GET'
 * queries.
 */
#define GNUNET_DHT_GET_BLOOMFILTER_K 16

/**
 * Non-intelligent default DHT GET replication.
 * Should be chosen by application if anything about
 * the network is known.
 */
#define DEFAULT_GET_REPLICATION 5

/**
 * Non-intelligent default DHT PUT replication.
 * Should be chosen by application if anything about
 * the network is known.
 */
#define DEFAULT_PUT_REPLICATION 8

/**
 * Connection to the DHT service.
 */
struct GNUNET_DHT_Handle;

/**
 * Handle to control a route operation.
 */
struct GNUNET_DHT_RouteHandle;

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
     * Possible message option for query key randomization.
     */
    GNUNET_DHT_RO_BART = 4
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
GNUNET_DHT_put (struct GNUNET_DHT_Handle *handle,
                const GNUNET_HashCode * key,
                uint32_t desired_replication_level,
                enum GNUNET_DHT_RouteOption options,
                enum GNUNET_BLOCK_Type type,
                size_t size,
                const char *data,
                struct GNUNET_TIME_Absolute exp,
                struct GNUNET_TIME_Relative timeout,
                GNUNET_SCHEDULER_Task cont,
                void *cont_cls);


/**
 * Iterator called on each result obtained for a DHT
 * operation that expects a reply
 *
 * @param cls closure
 * @param exp when will this value expire
 * @param key key of the result
 * @param get_path NULL-terminated array of pointers
 *                 to the peers on reverse GET path (or NULL if not recorded)
 * @param put_path NULL-terminated array of pointers
 *                 to the peers on the PUT path (or NULL if not recorded)
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 */
typedef void (*GNUNET_DHT_GetIterator)(void *cls,
				       struct GNUNET_TIME_Absolute exp,
				       const GNUNET_HashCode * key,
				       const struct GNUNET_PeerIdentity * const *get_path,
				       const struct GNUNET_PeerIdentity * const *put_path,
				       enum GNUNET_BLOCK_Type type,
				       size_t size,
				       const void *data);



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
 * @param bf bloom filter associated with query (can be NULL)
 * @param bf_mutator mutation value for bf
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
                      enum GNUNET_BLOCK_Type type,
                      const GNUNET_HashCode * key,
                      uint32_t desired_replication_level,
                      enum GNUNET_DHT_RouteOption options,
                      const struct GNUNET_CONTAINER_BloomFilter *bf,
                      int32_t bf_mutator,
                      const void *xquery,
                      size_t xquery_size,
                      GNUNET_DHT_GetIterator iter,
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


/* ******** Special high-level API for finding peers *********** */

/**
 * Iterator called on each result obtained from a find peer
 * operation
 *
 * @param cls closure
 * @param peer hello of a target (peer near key)
 */
typedef void (*GNUNET_DHT_FindPeerProcessor)(void *cls,
					     const struct GNUNET_HELLO_Message *peer);


/**
 * Perform an asynchronous FIND PEER operation on the DHT.
 *
 * @param handle handle to the DHT service
 * @param timeout timeout for this request to be sent to the
 *        service
 * @param key the key to look up
 * @param options routing options for this message
 * @param proc function to call on each result
 * @param proc_cls closure for proc
 * @return handle to stop the async get, NULL on error
 */
struct GNUNET_DHT_FindPeerHandle *
GNUNET_DHT_find_peer_start (struct GNUNET_DHT_Handle *handle,
			    struct GNUNET_TIME_Relative timeout,
			    const GNUNET_HashCode *key,
			    enum GNUNET_DHT_RouteOption options,
			    GNUNET_DHT_FindPeerProcessor proc,
			    void *proc_cls);


/**
 * Stop async find peer.  Frees associated resources.
 *
 * @param find_peer_handle GET operation to stop.
 */
void
GNUNET_DHT_find_peer_stop (struct GNUNET_DHT_FindPeerHandle *find_peer_handle);



/* ***** Special low-level API providing generic routeing abstraction ***** */

/**
 * Iterator called on each result obtained from a generic route
 * operation
 *
 * @param cls closure
 * @param key key that was used
 * @param outgoing_path NULL-terminated array of pointers
 *                      to the peers on reverse outgoing
 *                      path (or NULL if not recorded)
 *                 to the peers on the PUT path (or NULL if not recorded)
 * @param reply response
 */
typedef void (*GNUNET_DHT_ReplyProcessor)(void *cls,
					  const GNUNET_HashCode *key,
					  const struct GNUNET_PeerIdentity * const *outgoing_path,
                                          const struct GNUNET_MessageHeader *reply);


/**
 * Perform an asynchronous ROUTE_START operation on the DHT.
 *
 * @param handle handle to the DHT service
 * @param key the key to look up
 * @param desired_replication_level how many peers should ultimately receive
 *                this message (advisory only, target may be too high for the
 *                given DHT or not hit exactly).
 * @param options options for routing
 * @param enc send the encapsulated message to a peer close to the key
 * @param timeout when to abort with an error if we fail to get
 *                a confirmation for the request (when necessary) or how long
 *                to wait for transmission to the service; only applies
 *                if 'iter' is NULL
 * @param iter function to call on each result, NULL if no replies are expected
 * @param iter_cls closure for iter
 * @param cont continuation to call when the request has been transmitted
 *             the first time to the service
 * @param cont_cls closure for cont
 * @return handle to stop the request, NULL if the request is "fire and forget"
 */
struct GNUNET_DHT_RouteHandle *
GNUNET_DHT_route_start (struct GNUNET_DHT_Handle *handle,
			const GNUNET_HashCode *key,
			uint32_t desired_replication_level,
			enum GNUNET_DHT_RouteOption options,
			const struct GNUNET_MessageHeader *enc,
			struct GNUNET_TIME_Relative timeout,
			GNUNET_DHT_ReplyProcessor iter,
			void *iter_cls,
			GNUNET_SCHEDULER_Task cont,
			void *cont_cls);



/**
 * Stop async route operation.  Frees associated resources.
 *
 * @param route_handle  operation to stop.
 */
void
GNUNET_DHT_route_stop (struct GNUNET_DHT_RouteHandle *route_handle);


/* ***** Special API for controlling DHT routing maintenance ******* */


/**
 * Send a message to the DHT telling it to issue a single find
 * peer request using the peers unique identifier as key.  This
 * is used to fill the routing table, and is normally controlled
 * by the DHT itself.  However, for testing and perhaps more
 * close control over the DHT, this can be explicitly managed.
 *
 * @param cont continuation to call when done (transmitting request to service)
 * @param cont_cls closure for cont
 * @param handle handle to the DHT service
 */
void
GNUNET_DHT_find_peers (struct GNUNET_DHT_Handle *handle,
		       GNUNET_SCHEDULER_Task cont,
		       void *cont_cls);

/* ***** Special API for testing robustness with malicious peers ******* */

#if HAVE_MALICIOUS
/* Note that these functions are NOT considered to be part of the
   "official" API and hence are NOT subjected to library versioning;
   only developers testing GNUnet's robustness should have any use for
   them, applications should never use them.  Applications must NOT
   define "HAVE_MALICIOUS" before including this header. */

/**
 * Send a message to the DHT telling it to start dropping
 * all requests received.
 *
 * @param handle handle to the DHT service
 * @param cont continuation to call when done (transmitting request to service)
 * @param cont_cls closure for cont
 *
 */
void 
GNUNET_DHT_set_malicious_dropper (struct GNUNET_DHT_Handle *handle, GNUNET_SCHEDULER_Task cont,
    void *cont_cls);


/**
 * Send a message to the DHT telling it to start issuing random PUT
 * requests every 'frequency' milliseconds.
 *
 * @param handle handle to the DHT service
 * @param frequency delay between sending malicious messages
 * @param cont continuation to call when done (transmitting request to service)
 * @param cont_cls closure for cont
 */
void 
GNUNET_DHT_set_malicious_putter (struct GNUNET_DHT_Handle *handle,
         struct GNUNET_TIME_Relative frequency, GNUNET_SCHEDULER_Task cont,
          void *cont_cls);


/**
 * Send a message to the DHT telling it to start issuing random GET
 * requests every 'frequency' milliseconds.
 *
 * @param handle handle to the DHT service
 * @param frequency delay between sending malicious messages
 * @param cont continuation to call when done (transmitting request to service)
 * @param cont_cls closure for cont
 */
void
GNUNET_DHT_set_malicious_getter (struct GNUNET_DHT_Handle *handle,
         struct GNUNET_TIME_Relative frequency, GNUNET_SCHEDULER_Task cont,
          void *cont_cls);


#endif

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
/* gnunet_dht_service.h */
