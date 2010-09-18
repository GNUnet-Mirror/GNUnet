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
 * Iterator called on each result obtained from a generic route
 * operation
 */
typedef void (*GNUNET_DHT_MessageCallback)(void *cls,
                                           int code);

/**
 * Initialize the connection with the DHT service.
 *
 * @param sched scheduler to use
 * @param cfg configuration to use
 * @param ht_len size of the internal hash table to use for
 *               processing multiple GET/FIND requests in parallel
 * @return NULL on error
 */
struct GNUNET_DHT_Handle *
GNUNET_DHT_connect (struct GNUNET_SCHEDULER_Handle *sched,
                    const struct GNUNET_CONFIGURATION_Handle *cfg,
                    unsigned int ht_len);


/**
 * Shutdown connection with the DHT service.
 *
 * @param handle connection to shut down
 */
void
GNUNET_DHT_disconnect (struct GNUNET_DHT_Handle *handle);


/**
 * Perform a PUT operation on the DHT identified by 'table' storing
 * a binding of 'key' to 'value'.  The peer does not have to be part
 * of the table (if so, we will attempt to locate a peer that is!)
 *
 * @param handle handle to DHT service
 * @param key the key to store under
 * @param type type of the value
 * @param size number of bytes in data; must be less than 64k
 * @param data the data to store
 * @param exp desired expiration time for the data
 * @param timeout when to abort with an error if we fail to get
 *                a confirmation for the PUT from the local DHT service
 * @param cont continuation to call when done;
 *             reason will be TIMEOUT on error,
 *             reason will be PREREQ_DONE on success
 * @param cont_cls closure for cont
 */
void
GNUNET_DHT_put (struct GNUNET_DHT_Handle *handle,
                const GNUNET_HashCode * key,
                enum GNUNET_BLOCK_Type type,
                uint32_t size,
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
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 */
typedef void (*GNUNET_DHT_GetIterator)(void *cls,
				       struct GNUNET_TIME_Absolute exp,
				       const GNUNET_HashCode * key,
				       enum GNUNET_BLOCK_Type type,
				       uint32_t size,
				       const void *data);



/**
 * Perform an asynchronous GET operation on the DHT.
 *
 * @param handle handle to the DHT service
 * @param timeout timeout for this request to be sent to the
 *        service (this is NOT a timeout for receiving responses)
 * @param type expected type of the response object (GNUNET_BLOCK_TYPE_FS_*)
 * @param key the key to look up
 * @param iter function to call on each result
 * @param iter_cls closure for iter
 * @param cont continuation to call once message sent (and it is now
 *             safe to do another operation on the DHT)
 * @param cont_cls closure for continuation
 * @return handle to stop the async get, NULL on error (two
 *         concurrent operations scheduled)
 */
struct GNUNET_DHT_GetHandle *
GNUNET_DHT_get_start (struct GNUNET_DHT_Handle *handle,
                      struct GNUNET_TIME_Relative timeout,
                      enum GNUNET_BLOCK_Type type,
                      const GNUNET_HashCode * key,
                      GNUNET_DHT_GetIterator iter,
                      void *iter_cls,
                      GNUNET_SCHEDULER_Task cont,
                      void *cont_cls);


/**
 * Stop async DHT-get.  Frees associated resources.
 *
 * @param get_handle GET operation to stop.
 * @param cont continuation to call once this message is sent to the service 
 * @param cont_cls closure for the continuation
 */
void
GNUNET_DHT_get_stop (struct GNUNET_DHT_GetHandle *get_handle, 
		     GNUNET_SCHEDULER_Task cont, 
		     void *cont_cls);


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
    GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE = 1
  };


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
 * @param options routing options for this message
 * @param key the key to look up
 * @param proc function to call on each result
 * @param proc_cls closure for proc
 * @param cont continuation to call once message sent
 * @param cont_cls closure for continuation
 * @return handle to stop the async get, NULL on error
 */
struct GNUNET_DHT_FindPeerHandle *
GNUNET_DHT_find_peer_start (struct GNUNET_DHT_Handle *handle,
			    struct GNUNET_TIME_Relative timeout,
			    enum GNUNET_DHT_RouteOption options,
			    const GNUNET_HashCode * key,
			    GNUNET_DHT_FindPeerProcessor proc,
			    void *proc_cls,
			    GNUNET_SCHEDULER_Task cont,
			    void *cont_cls);


/**
 * Stop async find peer.  Frees associated resources.
 *
 * @param find_peer_handle GET operation to stop.
 * @param cont continuation to call once this message is sent to the service
 * @param cont_cls closure for the continuation
 */
void
GNUNET_DHT_find_peer_stop (struct GNUNET_DHT_FindPeerHandle *find_peer_handle,
			   GNUNET_SCHEDULER_Task cont, 
			   void *cont_cls);


/**
 * Iterator called on each result obtained from a generic route
 * operation
 *
 * @param cls closure
 * @param reply response
 */
typedef void (*GNUNET_DHT_ReplyProcessor)(void *cls,
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
 *                to wait for transmission to the service
 * @param iter function to call on each result, NULL if no replies are expected
 * @param iter_cls closure for iter
 * @param cont continuation to call when done, GNUNET_SYSERR if failed
 *             GNUNET_OK otherwise
 * @param cont_cls closure for cont
 * @return handle to stop the request
 */
struct GNUNET_DHT_RouteHandle *
GNUNET_DHT_route_start (struct GNUNET_DHT_Handle *handle,
			const GNUNET_HashCode *key,
			unsigned int desired_replication_level,
			enum GNUNET_DHT_RouteOption options,
			const struct GNUNET_MessageHeader *enc,
			struct GNUNET_TIME_Relative timeout,
			GNUNET_DHT_ReplyProcessor iter,
			void *iter_cls,
			GNUNET_SCHEDULER_Task cont,
			void *cont_cls);


/**
 * Stop async route stop.  Frees associated resources.
 *
 * @param route_handle  operation to stop.
 * @param cont continuation to call once this message is sent to the service
 * @param cont_cls closure for the continuation
 */
void
GNUNET_DHT_route_stop (struct GNUNET_DHT_RouteHandle *route_handle,
		       GNUNET_SCHEDULER_Task cont, 
		       void *cont_cls);

/**
 * Send a message to the DHT telling it to start issuing random GET
 * requests every 'frequency' milliseconds.
 *
 * @param handle handle to the DHT service
 * @param frequency delay (in milliseconds) between sending malicious messages
 * @param cont continuation to call once the message is sent
 * @param cont_cls closure for continuation
 *
 * @return GNUNET_YES if the control message was sent, GNUNET_NO if not
 */
int GNUNET_DHT_set_malicious_getter (struct GNUNET_DHT_Handle *handle, int frequency, GNUNET_SCHEDULER_Task cont, void *cont_cls);

/**
 * Send a message to the DHT telling it to issue a single find
 * peer request using the peers unique identifier as key.  This
 * is used to fill the routing table, and is normally controlled
 * by the DHT itself.  However, for testing and perhaps more
 * close control over the DHT, this can be explicitly managed.
 *
 * @param handle handle to the DHT service
 * @param cont continuation to call once the message is sent
 * @param cont_cls closure for continuation
 *
 * @return GNUNET_YES if the control message was sent, GNUNET_NO if not
 */
int GNUNET_DHT_find_peers (struct GNUNET_DHT_Handle *handle,
                           GNUNET_SCHEDULER_Task cont, void *cont_cls);

/**
 * Send a message to the DHT telling it to start dropping
 * all requests received.
 *
 * @param handle handle to the DHT service
 * @param cont continuation to call once the message is sent
 * @param cont_cls closure for continuation
 *
 * @return GNUNET_YES if the control message was sent, GNUNET_NO if not
 */
int GNUNET_DHT_set_malicious_dropper (struct GNUNET_DHT_Handle *handle, GNUNET_SCHEDULER_Task cont, void *cont_cls);

/**
 * Send a message to the DHT telling it to start issuing random PUT
 * requests every 'frequency' milliseconds.
 *
 * @param handle handle to the DHT service
 * @param frequency delay (in milliseconds) between sending malicious messages
 * @param cont continuation to call once the message is sent
 * @param cont_cls closure for continuation
 *
 * @return GNUNET_YES if the control message was sent, GNUNET_NO if not
 */
int GNUNET_DHT_set_malicious_putter (struct GNUNET_DHT_Handle *handle, int frequency, GNUNET_SCHEDULER_Task cont, void *cont_cls);

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif


#endif
/* gnunet_dht_service.h */
