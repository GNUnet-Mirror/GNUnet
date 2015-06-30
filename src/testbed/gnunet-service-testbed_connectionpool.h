/*
  This file is part of GNUnet.
  Copyright (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/gnunet-service-testbed_connectionpool.h
 * @brief Interface for connection pooling subroutines
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */


/**
 * The request handle for obtaining a pooled connection
 */
struct GST_ConnectionPool_GetHandle;


/**
 * The type of service
 */
enum GST_ConnectionPool_Service
{
  /**
   * Transport service
   */
  GST_CONNECTIONPOOL_SERVICE_TRANSPORT = 1,

  /**
   * Core service
   */
  GST_CONNECTIONPOOL_SERVICE_CORE
};


/**
 * Initialise the connection pool.
 *
 * @param size the size of the connection pool.  Each entry in the connection
 *   pool can handle a connection to each of the services enumerated in
 *   #GST_ConnectionPool_Service
 */
void
GST_connection_pool_init (unsigned int size);


/**
 * Cleanup the connection pool
 */
void
GST_connection_pool_destroy ();

/**
 * Functions of this type are called when the needed handle is available for
 * usage. These functions are to be registered with the function
 * GST_connection_pool_get_handle(). The corresponding handles will be set upon
 * success.  If they are not set, then it signals an error while opening the
 * handles.
 *
 * @param cls the closure passed to GST_connection_pool_get_handle()
 * @param ch the handle to CORE. Can be NULL if it is not requested
 * @param th the handle to TRANSPORT. Can be NULL if it is not requested
 * @param peer_id the identity of the peer. Will be NULL if ch is NULL. In other
 *          cases, its value being NULL means that CORE connection has failed.
 */
typedef void
(*GST_connection_pool_connection_ready_cb) (void *cls,
                                            struct GNUNET_CORE_Handle * ch,
                                            struct GNUNET_TRANSPORT_Handle * th,
                                            const struct GNUNET_PeerIdentity *
                                            peer_id);


/**
 * Callback to notify when the target peer given to
 * GST_connection_pool_get_handle() is connected.
 *
 * @param cls the closure given to GST_connection_pool_get_handle() for this
 *   callback
 * @param target the peer identity of the target peer
 */
typedef void
(*GST_connection_pool_peer_connect_notify) (void *cls,
                                            const struct GNUNET_PeerIdentity
                                            *target);


/**
 * Get a connection handle to @a service.  If the connection is opened before
 * and the connection handle is present in the connection pool, it is returned
 * through @a cb.  @a peer_id is used for the lookup in the connection pool.  If
 * the connection handle is not present in the connection pool, a new connection
 * handle is opened for the @a service using @a cfg.  Additionally, @a target,
 * @a connect_notify_cb can be specified to get notified when @a target is
 * connected at @a service.
 *
 * @note @a connect_notify_cb will not be called if @a target is
 * already connected @a service level. Use
 * GNUNET_TRANSPORT_check_peer_connected() or a similar function from the
 * respective @a service's API to check if the target peer is already connected or
 * not. @a connect_notify_cb will be called only once or never (in case @a target
 * cannot be connected or is already connected).
 *
 * @param peer_id the index of the peer
 * @param cfg the configuration with which the transport handle has to be
 *          created if it was not present in the cache
 * @param service the service of interest
 * @param cb the callback to notify when the transport handle is available
 * @param cb_cls the closure for @a cb
 * @param target the peer identify of the peer whose connection to our TRANSPORT
 *          subsystem will be notified through the @a connect_notify_cb. Can be NULL
 * @param connect_notify_cb the callback to call when the @a target peer is
 *          connected. This callback will only be called once or never again (in
 *          case the target peer cannot be connected). Can be NULL
 * @param connect_notify_cb_cls the closure for @a connect_notify_cb
 * @return the handle which can be used cancel or mark that the handle is no
 *           longer being used
 */
struct GST_ConnectionPool_GetHandle *
GST_connection_pool_get_handle (unsigned int peer_id,
                                const struct GNUNET_CONFIGURATION_Handle *cfg,
                                enum GST_ConnectionPool_Service service,
                                GST_connection_pool_connection_ready_cb cb,
                                void *cb_cls,
                                const struct GNUNET_PeerIdentity *target,
                                GST_connection_pool_peer_connect_notify connect_notify_cb,
                                void *connect_notify_cb_cls);


/**
 * Relinquish a #GST_ConnectionPool_GetHandle object.  If the connection
 * associated with the object is currently being used by other
 * #GST_ConnectionPool_GetHandle objects, it is left in the connection pool.  If
 * no other objects are using the connection and the connection pool is not full
 * then it is placed in a LRU queue.  If the connection pool is full, then
 * connections from the LRU queue are evicted and closed to create place for this
 * connection.  If the connection pool if full and the LRU queue is empty, then
 * the connection is closed.
 *
 * @param gh the handle
 */
void
GST_connection_pool_get_handle_done (struct GST_ConnectionPool_GetHandle *gh);


/* End of gnunet-service-testbed_connectionpool.h */
