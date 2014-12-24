/*
  This file is part of GNUnet.
  (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/gnunet-service-testbed_connectionpool.c
 * @brief connection pooling for connections to peers' services
 * @author Sree Harsha Totakura <sreeharsha@totakura.in>
 */

#include "gnunet-service-testbed.h"
#include "gnunet-service-testbed_connectionpool.h"
#include "testbed_api_operations.h"

/**
 * Redefine LOG with a changed log component string
 */
#ifdef LOG
#undef LOG
#endif
#define LOG(kind,...)                                   \
  GNUNET_log_from (kind, "testbed-connectionpool", __VA_ARGS__)


/**
 * Time to expire a cache entry
 */
#define CACHE_EXPIRY                            \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)


/**
 * The request handle for obtaining a pooled connection
 */
struct GST_ConnectionPool_GetHandle;


/**
 * A pooled connection
 */
struct PooledConnection
{
  /**
   * Next ptr for placing this object in the DLL of least recently used pooled
   * connections
   */
  struct PooledConnection *next;

  /**
   * Prev ptr for placing this object in the DLL of the least recently used
   * pooled connections
   */
  struct PooledConnection *prev;

  /**
   * The transport handle to the peer corresponding to this entry; can be NULL
   */
  struct GNUNET_TRANSPORT_Handle *handle_transport;

  /**
   * The core handle to the peer corresponding to this entry; can be NULL
   */
  struct GNUNET_CORE_Handle *handle_core;

  /**
   * The operation handle for transport handle
   */
  struct GNUNET_TESTBED_Operation *op_transport;

  /**
   * The operation handle for core handle
   */
  struct GNUNET_TESTBED_Operation *op_core;

  /**
   * The peer identity of this peer. Will be set upon opening a connection to
   * the peers CORE service. Will be NULL until then and after the CORE
   * connection is closed
   */
  struct GNUNET_PeerIdentity *peer_identity;

  /**
   * The configuration of the peer. Should be not NULL as long as the core_handle
   * or transport_handle are valid
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * DLL head for the queue to serve notifications when a peer is connected
   */
  struct GST_ConnectionPool_GetHandle *head_notify;

  /**
   * DLL tail for the queue to serve notifications when a peer is connected
   */
  struct GST_ConnectionPool_GetHandle *tail_notify;

  /**
   * DLL head for the queue of #GST_ConnectionPool_GetHandle requests that are
   * waiting for this connection to be opened
   */
  struct GST_ConnectionPool_GetHandle *head_waiting;

  /**
   * DLL tail for the queue of #GST_ConnectionPool_GetHandle requests that are
   * waiting for this connection to be opened
   */
  struct GST_ConnectionPool_GetHandle *tail_waiting;

  /**
   * The task to expire this connection from the connection pool
   */
  struct GNUNET_SCHEDULER_Task * expire_task;

  /**
   * The task to notify a waiting #GST_ConnectionPool_GetHandle object
   */
  struct GNUNET_SCHEDULER_Task * notify_task;

  /**
   * Number of active requests using this pooled connection
   */
  unsigned int demand;

  /**
   * Is this entry in LRU
   */
  int in_lru;

  /**
   * Is this entry present in the connection pool
   */
  int in_pool;

  /**
   * The index of this peer
   */
  uint32_t index;
};


/**
 * The request handle for obtaining a pooled connection
 */
struct GST_ConnectionPool_GetHandle
{
  /**
   * The next ptr for inclusion in the notification DLLs.  At first the object
   * is placed in the waiting DLL of the corresponding #PooledConnection
   * object.  After the handle is opened it is moved to the notification DLL if
   * @p connect_notify_cb and @p target are not NULL
   */
  struct GST_ConnectionPool_GetHandle *next;

  /**
   * The prev ptr for inclusion in the notification DLLs
   */
  struct GST_ConnectionPool_GetHandle *prev;

  /**
   * The pooled connection object this handle corresponds to
   */
  struct PooledConnection *entry;

  /**
   * The cache callback to call when a handle is available
   */
  GST_connection_pool_connection_ready_cb cb;

  /**
   * The closure for the above callback
   */
  void *cb_cls;

  /**
   * The peer identity of the target peer. When this target peer is connected,
   * call the notify callback
   */
  const struct GNUNET_PeerIdentity *target;

  /**
   * The callback to be called for serving notification that the target peer is
   * connected
   */
  GST_connection_pool_peer_connect_notify connect_notify_cb;

  /**
   * The closure for the notify callback
   */
  void *connect_notify_cb_cls;

  /**
   * The service we want to connect to
   */
  enum GST_ConnectionPool_Service service;

  /**
   * Did we call the pool_connection_ready_cb already?
   */
  int connection_ready_called;

  /**
   * Are we waiting for any peer connect notifications?
   */
  int notify_waiting;
};


/**
 * A hashmap for quickly finding connections in the connection pool
 */
static struct GNUNET_CONTAINER_MultiHashMap32 *map;

/**
 * DLL head for maitaining the least recently used #PooledConnection objects.
 * The head is the least recently used object.
 */
static struct PooledConnection *head_lru;

/**
 * DLL tail for maitaining the least recently used #PooledConnection objects
 */
static struct PooledConnection *tail_lru;

/**
 * DLL head for maintaining #PooledConnection objects that are not added into
 * the connection pool as it was full at the time the object's creation
 * FIXME
 */
static struct PooledConnection *head_not_pooled;

/**
 * DLL tail for maintaining #PooledConnection objects that are not added into
 * the connection pool as it was full at the time the object's creation
 */
static struct PooledConnection *tail_not_pooled;

/**
 * The maximum number of entries that can be present in the connection pool
 */
static unsigned int max_size;


/**
 * Cancel the expiration task of the give #PooledConnection object
 *
 * @param entry the #PooledConnection object
 */
static void
expire_task_cancel (struct PooledConnection *entry);


/**
 * Destroy a #PooledConnection object
 *
 * @param entry the #PooledConnection object
 */
static void
destroy_pooled_connection (struct PooledConnection *entry)
{
  GNUNET_assert ((NULL == entry->head_notify) && (NULL == entry->tail_notify));
  GNUNET_assert ((NULL == entry->head_waiting) && (NULL ==
                                                   entry->tail_waiting));
  GNUNET_assert (0 == entry->demand);
  expire_task_cancel (entry);
  if (entry->in_lru)
    GNUNET_CONTAINER_DLL_remove (head_lru, tail_lru, entry);
  if (entry->in_pool)
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap32_remove (map,
                                                           entry->index,
                                                           entry));
  if (NULL != entry->notify_task)
  {
    GNUNET_SCHEDULER_cancel (entry->notify_task);
    entry->notify_task = NULL;
  }
  LOG_DEBUG ("Cleaning up handles of a pooled connection\n");
  if (NULL != entry->handle_transport)
    GNUNET_assert (NULL != entry->op_transport);
  if (NULL != entry->op_transport)
  {
    GNUNET_TESTBED_operation_done (entry->op_transport);
    entry->op_transport = NULL;
  }
  if (NULL != entry->op_core)
  {
    GNUNET_TESTBED_operation_done (entry->op_core);
    entry->op_core = NULL;
  }
  GNUNET_assert (NULL == entry->handle_core);
  GNUNET_assert (NULL == entry->handle_transport);
  GNUNET_CONFIGURATION_destroy (entry->cfg);
  GNUNET_free (entry);
}


/**
 * Expire a #PooledConnection object
 *
 * @param cls the #PooledConnection object
 * @param tc scheduler task context
 */
static void
expire (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PooledConnection *entry = cls;

  entry->expire_task = NULL;
  destroy_pooled_connection (entry);
}


/**
 * Cancel the expiration task of the give #PooledConnection object
 *
 * @param entry the #PooledConnection object
 */
static void
expire_task_cancel (struct PooledConnection *entry)
{
  if (NULL != entry->expire_task)
  {
    GNUNET_SCHEDULER_cancel (entry->expire_task);
    entry->expire_task = NULL;
  }
}


/**
 * Function to add a #PooledConnection object into LRU and begin the expiry task
 *
 * @param entry the #PooledConnection object
 */
static void
add_to_lru (struct PooledConnection *entry)
{
  GNUNET_assert (0 == entry->demand);
  GNUNET_assert (!entry->in_lru);
  GNUNET_CONTAINER_DLL_insert_tail (head_lru, tail_lru, entry);
  entry->in_lru = GNUNET_YES;
  GNUNET_assert (NULL == entry->expire_task);
  entry->expire_task = GNUNET_SCHEDULER_add_delayed (CACHE_EXPIRY,
                                                     &expire, entry);
}


/**
 * Function to find a #GST_ConnectionPool_GetHandle which is waiting for one of
 * the handles in given entry which are now available.
 *
 * @param entry the pooled connection whose active list has to be searched
 * @param head the starting list element in the GSTCacheGetHandle where the
 *          search has to be begin
 * @return a suitable GSTCacheGetHandle whose handle ready notify callback
 *           hasn't been called yet. NULL if no such suitable GSTCacheGetHandle
 *           is found
 */
static struct GST_ConnectionPool_GetHandle *
search_waiting (const struct PooledConnection *entry,
                struct GST_ConnectionPool_GetHandle *head)
{
  struct GST_ConnectionPool_GetHandle *gh;

  for (gh = head; NULL != gh; gh = gh->next)
  {
    switch (gh->service)
    {
    case GST_CONNECTIONPOOL_SERVICE_CORE:
      if (NULL == entry->handle_core)
        continue;
      if (NULL == entry->peer_identity)
        continue;               /* CORE connection isn't ready yet */
      break;
    case GST_CONNECTIONPOOL_SERVICE_TRANSPORT:
      if (NULL == entry->handle_transport)
        continue;
      break;
    }
    break;
  }
  return gh;
}


/**
 * A handle in the #PooledConnection object pointed by @a cls is ready and there
 * is a #GST_ConnectionPool_GetHandle object waiting in the waiting list.  This
 * function retrieves that object and calls the handle ready callback.  It
 * further schedules itself if there are similar waiting objects which can be notified.
 *
 * @param cls the #PooledConnection object
 * @param tc the task context from scheduler
 */
static void
connection_ready (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct PooledConnection *entry = cls;
  struct GST_ConnectionPool_GetHandle *gh;
  struct GST_ConnectionPool_GetHandle *gh_next;

  GNUNET_assert (NULL != entry->notify_task);
  entry->notify_task = NULL;
  gh = search_waiting (entry, entry->head_waiting);
  GNUNET_assert (NULL != gh);
  gh_next = NULL;
  if (NULL != gh->next)
    gh_next = search_waiting (entry, gh->next);
  GNUNET_CONTAINER_DLL_remove (entry->head_waiting, entry->tail_waiting, gh);
  gh->connection_ready_called = 1;
  if (NULL != gh_next)
    entry->notify_task = GNUNET_SCHEDULER_add_now (&connection_ready, entry);
  if ( (NULL != gh->target) && (NULL != gh->connect_notify_cb) )
  {
    GNUNET_CONTAINER_DLL_insert_tail (entry->head_notify, entry->tail_notify,
                                      gh);
    gh->notify_waiting = 1;
  }
  LOG_DEBUG ("Connection ready for handle type %u\n", gh->service);
  gh->cb (gh->cb_cls, entry->handle_core, entry->handle_transport,
          entry->peer_identity);
}


/**
 * Function called from peer connect notify callbacks from CORE and TRANSPORT
 * connections. This function calls the pending peer connect notify callbacks
 * which are queued in an entry.
 *
 * @param cls the #PooledConnection object
 * @param peer the peer that connected
 * @param service the service where this notification has originated
 */
static void
peer_connect_notify_cb (void *cls, const struct GNUNET_PeerIdentity *peer,
                        const enum GST_ConnectionPool_Service service)
{
  struct PooledConnection *entry = cls;
  struct GST_ConnectionPool_GetHandle *gh;
  struct GST_ConnectionPool_GetHandle *gh_next;
  GST_connection_pool_peer_connect_notify cb;
  void *cb_cls;

  for (gh = entry->head_notify; NULL != gh;)
  {
    GNUNET_assert (NULL != gh->target);
    GNUNET_assert (NULL != gh->connect_notify_cb);
    GNUNET_assert (gh->connection_ready_called);
    if (service != gh->service)
    {
      gh = gh->next;
      continue;
    }
    if (0 != memcmp (gh->target, peer, sizeof (struct GNUNET_PeerIdentity)))
    {
      gh = gh->next;
      continue;
    }
    cb = gh->connect_notify_cb;
    cb_cls = gh->connect_notify_cb_cls;
    gh_next = gh->next;
    GNUNET_CONTAINER_DLL_remove (entry->head_notify, entry->tail_notify, gh);
    gh->notify_waiting = 0;
    LOG_DEBUG ("Peer connected to peer %u at service %u\n", entry->index, gh->service);
    gh = gh_next;
    cb (cb_cls, peer);
  }
}


/**
 * Function called to notify transport users that another
 * peer connected to us.
 *
 * @param cls the #PooledConnection object
 * @param peer the peer that connected
 */
static void
transport_peer_connect_notify_cb (void *cls,
                                  const struct GNUNET_PeerIdentity *peer)
{
  struct PooledConnection *entry = cls;

  peer_connect_notify_cb (entry, peer, GST_CONNECTIONPOOL_SERVICE_TRANSPORT);
}


/**
 * Function called when resources for opening a connection to TRANSPORT are
 * available.
 *
 * @param cls the #PooledConnection object
 */
static void
opstart_get_handle_transport (void *cls)
{
  struct PooledConnection *entry = cls;

  GNUNET_assert (NULL != entry);
  LOG_DEBUG ("Opening a transport connection to peer %u\n", entry->index);
  entry->handle_transport =
      GNUNET_TRANSPORT_connect (entry->cfg, NULL, entry, NULL,
                                &transport_peer_connect_notify_cb, NULL);
  if (NULL == entry->handle_transport)
  {
    GNUNET_break (0);
    return;
  }
  if (0 == entry->demand)
    return;
  if (NULL != entry->notify_task)
    return;
  if (NULL != search_waiting (entry, entry->head_waiting))
  {
    entry->notify_task = GNUNET_SCHEDULER_add_now (&connection_ready, entry);
    return;
  }
}


/**
 * Function called when the operation responsible for opening a TRANSPORT
 * connection is marked as done.
 *
 * @param cls the cache entry
 */
static void
oprelease_get_handle_transport (void *cls)
{
  struct PooledConnection *entry = cls;

  if (NULL == entry->handle_transport)
    return;
  GNUNET_TRANSPORT_disconnect (entry->handle_transport);
  entry->handle_transport = NULL;
}


/**
 * Method called whenever a given peer connects at CORE level
 *
 * @param cls the #PooledConnection object
 * @param peer peer identity this notification is about
 */
static void
core_peer_connect_cb (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  struct PooledConnection *entry = cls;

  peer_connect_notify_cb (entry, peer, GST_CONNECTIONPOOL_SERVICE_CORE);
}


/**
 * Function called after GNUNET_CORE_connect has succeeded (or failed
 * for good).  Note that the private key of the peer is intentionally
 * not exposed here; if you need it, your process should try to read
 * the private key file directly (which should work if you are
 * authorized...).  Implementations of this function must not call
 * GNUNET_CORE_disconnect (other than by scheduling a new task to
 * do this later).
 *
 * @param cls the #PooledConnection object
 * @param my_identity ID of this peer, NULL if we failed
 */
static void
core_startup_cb (void *cls,
                 const struct GNUNET_PeerIdentity *my_identity)
{
  struct PooledConnection *entry = cls;

  if (NULL == my_identity)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_assert (NULL == entry->peer_identity);
  entry->peer_identity = GNUNET_new (struct GNUNET_PeerIdentity);
  memcpy (entry->peer_identity,
          my_identity,
          sizeof (struct GNUNET_PeerIdentity));
  if (0 == entry->demand)
    return;
  if (NULL != entry->notify_task)
    return;
  if (NULL != search_waiting (entry, entry->head_waiting))
  {
    entry->notify_task = GNUNET_SCHEDULER_add_now (&connection_ready, entry);
    return;
  }
}


/**
 * Function called when resources for opening a connection to CORE are
 * available.
 *
 * @param cls the #PooledConnection object
 */
static void
opstart_get_handle_core (void *cls)
{
  struct PooledConnection *entry = cls;
  const struct GNUNET_CORE_MessageHandler no_handlers[] = {
    {NULL, 0, 0}
  };

  GNUNET_assert (NULL != entry);
  LOG_DEBUG ("Opening a CORE connection to peer %u\n", entry->index);
  entry->handle_core =
      GNUNET_CORE_connect (entry->cfg, entry,        /* closure */
                           &core_startup_cb, /* core startup notify */
                           &core_peer_connect_cb,    /* peer connect notify */
                           NULL,     /* peer disconnect notify */
                           NULL,     /* inbound notify */
                           GNUNET_NO,        /* inbound header only? */
                           NULL,     /* outbound notify */
                           GNUNET_NO,        /* outbound header only? */
                           no_handlers);
}


/**
 * Function called when the operation responsible for opening a TRANSPORT
 * connection is marked as done.
 *
 * @param cls the #PooledConnection object
 */
static void
oprelease_get_handle_core (void *cls)
{
  struct PooledConnection *entry = cls;

  if (NULL == entry->handle_core)
    return;
  GNUNET_CORE_disconnect (entry->handle_core);
  entry->handle_core = NULL;
  GNUNET_free_non_null (entry->peer_identity);
  entry->peer_identity = NULL;
}


/**
 * This function will be called for every #PooledConnection object in @p map
 *
 * @param cls NULL
 * @param key current key code
 * @param value the #PooledConnection object
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
static int
cleanup_iterator (void *cls,
                  uint32_t key,
                  void *value)
{
  struct PooledConnection *entry = value;

  GNUNET_assert (NULL != entry);
  destroy_pooled_connection (entry);
  return GNUNET_YES;
}


/**
 * Initialise the connection pool.
 *
 * @param size the size of the connection pool.  Each entry in the connection
 *   pool can handle a connection to each of the services enumerated in
 *   #GST_ConnectionPool_Service
 */
void
GST_connection_pool_init (unsigned int size)
{
  max_size = size;
  if (0 == max_size)
    return;
  GNUNET_assert (NULL == map);
  map = GNUNET_CONTAINER_multihashmap32_create (((size * 3) / 4) + 1);
}


/**
 * Cleanup the connection pool
 */
void
GST_connection_pool_destroy ()
{
  struct PooledConnection *entry;

  if (NULL != map)
  {
    GNUNET_assert (GNUNET_SYSERR !=
                   GNUNET_CONTAINER_multihashmap32_iterate (map,
                                                            &cleanup_iterator,
                                                            NULL));
    GNUNET_CONTAINER_multihashmap32_destroy (map);
    map = NULL;
  }
  while (NULL != (entry = head_lru))
  {
    GNUNET_CONTAINER_DLL_remove (head_lru, tail_lru, entry);
    destroy_pooled_connection (entry);
  }
  GNUNET_assert (NULL == head_not_pooled);
}


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
                                void *connect_notify_cb_cls)
{
  struct GST_ConnectionPool_GetHandle *gh;
  struct PooledConnection *entry;
  struct GNUNET_TESTBED_Operation *op;
  void *handle;
  uint32_t peer_id32;

  peer_id32 = (uint32_t) peer_id;
  handle = NULL;
  entry = NULL;
  if (NULL != map)
    entry = GNUNET_CONTAINER_multihashmap32_get (map, peer_id32);
  if (NULL != entry)
  {
    if (entry->in_lru)
    {
      GNUNET_assert (0 == entry->demand);
      expire_task_cancel (entry);
      GNUNET_CONTAINER_DLL_remove (head_lru, tail_lru, entry);
      entry->in_lru = GNUNET_NO;
    }
    switch (service)
    {
    case GST_CONNECTIONPOOL_SERVICE_TRANSPORT:
      handle = entry->handle_transport;
      if (NULL != handle)
        LOG_DEBUG ("Found TRANSPORT handle for peer %u\n",
                   entry->index);
      break;
    case GST_CONNECTIONPOOL_SERVICE_CORE:
      handle = entry->handle_core;
      if (NULL != handle)
        LOG_DEBUG ("Found CORE handle for peer %u\n",
                   entry->index);
      break;
    }
  }
  else
  {
    entry = GNUNET_new (struct PooledConnection);
    entry->index = peer_id32;
    if ((NULL != map)
        && (GNUNET_CONTAINER_multihashmap32_size (map) < max_size))
    {
      GNUNET_assert (GNUNET_OK ==
                     GNUNET_CONTAINER_multihashmap32_put (map,
                                                          entry->index,
                                                          entry,
                                                          GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
      entry->in_pool = GNUNET_YES;
    }
    else
    {
      GNUNET_CONTAINER_DLL_insert_tail (head_not_pooled, tail_not_pooled, entry);
    }
    entry->cfg = GNUNET_CONFIGURATION_dup (cfg);
  }
  entry->demand++;
  gh = GNUNET_new (struct GST_ConnectionPool_GetHandle);
  gh->entry = entry;
  gh->cb = cb;
  gh->cb_cls = cb_cls;
  gh->target = target;
  gh->connect_notify_cb = connect_notify_cb;
  gh->connect_notify_cb_cls = connect_notify_cb_cls;
  gh->service = service;
  GNUNET_CONTAINER_DLL_insert (entry->head_waiting, entry->tail_waiting, gh);
  if (NULL != handle)
  {
    if (NULL == entry->notify_task)
    {
      if (NULL != search_waiting (entry, entry->head_waiting))
        entry->notify_task = GNUNET_SCHEDULER_add_now (&connection_ready, entry);
    }
    return gh;
  }
  op = NULL;
  switch (gh->service)
  {
  case GST_CONNECTIONPOOL_SERVICE_TRANSPORT:
    if (NULL != entry->op_transport)
      return gh;                /* Operation pending */
    op = GNUNET_TESTBED_operation_create_ (entry, &opstart_get_handle_transport,
                                           &oprelease_get_handle_transport);
    entry->op_transport = op;
    break;
  case GST_CONNECTIONPOOL_SERVICE_CORE:
    if (NULL != entry->op_core)
      return gh;                /* Operation pending */
    op = GNUNET_TESTBED_operation_create_ (entry, &opstart_get_handle_core,
                                           &oprelease_get_handle_core);
    entry->op_core = op;
    break;
  }
  GNUNET_TESTBED_operation_queue_insert_ (GST_opq_openfds, op);
  GNUNET_TESTBED_operation_begin_wait_ (op);
  return gh;
}


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
GST_connection_pool_get_handle_done (struct GST_ConnectionPool_GetHandle *gh)
{
  struct PooledConnection *entry;

  entry = gh->entry;
  LOG_DEBUG ("Cleaning up get handle %p for service %u, peer %u\n",
             gh,
             gh->service, entry->index);
  if (!gh->connection_ready_called)
  {
    GNUNET_CONTAINER_DLL_remove (entry->head_waiting, entry->tail_waiting, gh);
    if ( (NULL == search_waiting (entry, entry->head_waiting))
         && (NULL != entry->notify_task) )
    {
      GNUNET_SCHEDULER_cancel (entry->notify_task);
      entry->notify_task = NULL;
    }
  }
  if (gh->notify_waiting)
  {
    GNUNET_CONTAINER_DLL_remove (entry->head_notify, entry->tail_notify, gh);
    gh->notify_waiting = 0;
  }
  GNUNET_free (gh);
  gh = NULL;
  GNUNET_assert (!entry->in_lru);
  if (!entry->in_pool)
    GNUNET_CONTAINER_DLL_remove (head_not_pooled, tail_not_pooled, entry);
  if (NULL != map)
  {
    if (GNUNET_YES == GNUNET_CONTAINER_multihashmap32_contains (map,
                                                                entry->index))
      goto unallocate;
    if (GNUNET_CONTAINER_multihashmap32_size (map) == max_size)
    {
      if (NULL == head_lru)
        goto unallocate;
      destroy_pooled_connection (head_lru);
    }
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap32_put (map,
                                                        entry->index,
                                                        entry,
                                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
    entry->in_pool = GNUNET_YES;
  }

 unallocate:
  GNUNET_assert (0 < entry->demand);
  entry->demand--;
  if (0 != entry->demand)
    return;
  if (entry->in_pool)
  {
    add_to_lru (entry);
    return;
  }
  destroy_pooled_connection (entry);
}
