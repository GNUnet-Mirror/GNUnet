/*
  This file is part of GNUnet.
  (C) 2008--2013 Christian Grothoff (and other contributing authors)

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
 * @file testbed/gnunet-service-testbed_cache.c
 * @brief testbed cache implementation
 * @author Sree Harsha Totakura
 */
#include "gnunet-service-testbed.h"

/**
 * Redefine LOG with a changed log component string
 */
#ifdef LOG
#undef LOG
#endif
#define LOG(kind,...)                                   \
  GNUNET_log_from (kind, "testbed-cache", __VA_ARGS__)


/**
 * Time to expire a cache entry
 */
#define CACHE_EXPIRY                            \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)


/**
 * Type of cache-get requests
 */
enum CacheGetType
{
  /**
   * Get transport handle
   */
  CGT_TRANSPORT_HANDLE = 1,

  /**
   * Get core handle
   */
  CGT_CORE_HANDLE
};


/**
 * The cache-get request handle
 */
struct GSTCacheGetHandle;


/**
 * This context structure is used to maintain a queue of notifications to check
 * which of them are to be notified when a peer is connected.
 */
struct ConnectNotifyContext
{
  /**
   * The next ptr for the DLL
   */
  struct ConnectNotifyContext *next;

  /**
   * The prev ptr for the DLL
   */
  struct ConnectNotifyContext *prev;

  /**
   * The peer identity of the target peer. When this target peer is connected,
   * call the notify callback
   */
  const struct GNUNET_PeerIdentity *target;

  /**
   * The notify callback to be called when the target peer is connected
   */
  GST_cache_peer_connect_notify cb;

  /**
   * The closure for the notify callback
   */
  void *cb_cls;

  /**
   * The GSTCacheGetHandle reposible for creating this context
   */
  struct GSTCacheGetHandle *cgh;

};


/**
 * The cache-get request handle
 */
struct GSTCacheGetHandle
{
  /**
   * The next ptr for the DLL. Used in struct CacheEntry
   */
  struct GSTCacheGetHandle *next;

  /**
   * The prev ptr for the DLL. Used in struct CacheEntry
   */
  struct GSTCacheGetHandle *prev;

  /**
   * The cache entry object this handle corresponds to
   */
  struct CacheEntry *entry;

  /**
   * The cache callback to call when a handle is available
   */
  GST_cache_handle_ready_cb cb;

  /**
   * The closure for the above callback
   */
  void *cb_cls;

  /**
   * The peer connect notify context created for this handle; can be NULL
   */
  struct ConnectNotifyContext *nctxt;

  /**
   * The type of this cache-get request
   */
  enum CacheGetType type;

  /**
   * Did we call the cache callback already?
   */
  int notify_called;
};

/**
 * Cache entry
 */
struct CacheEntry
{
  /**
   * DLL next ptr for least recently used cache entries
   */
  struct CacheEntry *next;

  /**
   * DLL prev ptr for least recently used cache entries
   */
  struct CacheEntry *prev;

  /**
   * The transport handle to the peer corresponding to this entry; can be NULL
   */
  struct GNUNET_TRANSPORT_Handle *transport_handle;

  /**
   * The operation handle for transport handle
   */
  struct GNUNET_TESTBED_Operation *transport_op;

  /**
   * The core handle to the peer corresponding to this entry; can be NULL
   */
  struct GNUNET_CORE_Handle *core_handle;

  /**
   * The operation handle for core handle
   */
  struct GNUNET_TESTBED_Operation *core_op;

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
   * The key for this entry
   */
  struct GNUNET_HashCode key;

  /**
   * The HELLO message
   */
  struct GNUNET_MessageHeader *hello;

  /**
   * the head of the CacheGetHandle queue
   */
  struct GSTCacheGetHandle *cgh_qhead;

  /**
   * the tail of the CacheGetHandle queue
   */
  struct GSTCacheGetHandle *cgh_qtail;

  /**
   * DLL head for the queue of notifications contexts to check which of them are to
   * be notified when a peer is connected.
   */
  struct ConnectNotifyContext *nctxt_qhead;

  /**
   * DLL tail for the queue of notifications contexts to check which of them are to
   * be notified when a peer is connected.
   */
  struct ConnectNotifyContext *nctxt_qtail;

  /**
   * The task that calls the cache callback
   */
  GNUNET_SCHEDULER_TaskIdentifier notify_task;

  /**
   * The task to expire this cache entry, free any handlers it has opened and
   * mark their corresponding operations as done.
   */
  GNUNET_SCHEDULER_TaskIdentifier expire_task;

  /**
   * Number of operations this cache entry is being used
   */
  unsigned int demand;

  /**
   * The id of the peer this entry corresponds to
   */
  unsigned int peer_id;

  /**
   * Is this entry in LRU cache queue?
   */
  unsigned int in_lru;
};


/**
 * Hashmap to maintain cache
 */
static struct GNUNET_CONTAINER_MultiHashMap *cache;

/**
 * DLL head for least recently used cache entries; least recently used
 * cache items are at the head. The cache enties are added to this queue when
 * their demand becomes zero. They are removed from the queue when they are
 * needed by any operation.
 */
static struct CacheEntry *lru_cache_head;

/**
 * DLL tail for least recently used cache entries; recently used cache
 * items are at the tail.The cache enties are added to this queue when
 * their demand becomes zero. They are removed from the queue when they are
 * needed by any operation.
 */
static struct CacheEntry *lru_cache_tail;

/**
 * the size of the LRU queue
 */
static unsigned int lru_cache_size;

/**
 * the threshold size for the LRU queue
 */
static unsigned int lru_cache_threshold_size;

/**
 * The total number of elements in cache
 */
static unsigned int cache_size;


/**
 * Looks up in the cache and returns the entry
 *
 * @param key the peer identity of the peer whose corresponding entry has to be
 *          looked up
 * @return the HELLO message; NULL if not found
 */
static struct CacheEntry *
cache_lookup (const struct GNUNET_HashCode *key)
{
  struct CacheEntry *entry;

  if (NULL == cache)
    return NULL;
  entry = GNUNET_CONTAINER_multihashmap_get (cache, key);
  return entry;
}


/**
 * Function to disconnect the core and transport handles; free the existing
 * configuration; and remove from the LRU cache list. The entry is left to be in
 * the hash table so that the HELLO can still be found later
 *
 * @param entry the cache entry
 */
static void
close_handles (struct CacheEntry *entry)
{
  struct ConnectNotifyContext *ctxt;

  GNUNET_assert (0 == entry->demand);
  if (GNUNET_YES == entry->in_lru)
  {
    GNUNET_assert (0 < lru_cache_size);
    if (GNUNET_SCHEDULER_NO_TASK != entry->expire_task)
    {
      GNUNET_SCHEDULER_cancel (entry->expire_task);
      entry->expire_task = GNUNET_SCHEDULER_NO_TASK;
    }
    GNUNET_CONTAINER_DLL_remove (lru_cache_head, lru_cache_tail, entry);
    lru_cache_size--;
    entry->in_lru = GNUNET_NO;
  }
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == entry->expire_task);
  while (NULL != (ctxt = entry->nctxt_qhead))
  {
    GNUNET_CONTAINER_DLL_remove (entry->nctxt_qhead, entry->nctxt_qtail, ctxt);
    GNUNET_free (ctxt);
  }
  LOG_DEBUG ("Cleaning up handles from an entry in cache\n");
  if (NULL != entry->transport_handle)
    GNUNET_assert (NULL != entry->transport_op);
  if (NULL != entry->transport_op)
  {
    GNUNET_TESTBED_operation_done (entry->transport_op);
    entry->transport_op = NULL;    
  }
  if (NULL != entry->core_op)
  {
    GNUNET_TESTBED_operation_done (entry->core_op);
    entry->core_op = NULL;
  }
  GNUNET_assert (NULL == entry->core_handle);
  if (NULL != entry->cfg)
  {
    GNUNET_CONFIGURATION_destroy (entry->cfg);
    entry->cfg = NULL;
  }
}


/**
 * The task to expire this cache entry, free any handlers it has opened and
 * mark their corresponding operations as done.
 *
 * @param cls the CacheEntry
 * @param tc the scheduler task context
 */
static void
expire_cache_entry (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CacheEntry *entry = cls;

  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != entry->expire_task);
  entry->expire_task = GNUNET_SCHEDULER_NO_TASK;
  close_handles (entry);
}


/**
 * Creates a new cache entry and then puts it into the cache's hashtable.
 *
 * @param key the hash code to use for inserting the newly created entry
 * @param peer_id the index of the peer to tag the newly created entry
 * @return the newly created entry
 */
static struct CacheEntry *
add_entry (const struct GNUNET_HashCode *key, unsigned int peer_id)
{
  struct CacheEntry *entry;

  entry = GNUNET_malloc (sizeof (struct CacheEntry));
  entry->peer_id = peer_id;
  memcpy (&entry->key, key, sizeof (struct GNUNET_HashCode));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (cache, &entry->key, entry,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
  cache_size++;
  return entry;
}


/**
 * Function to find a suitable GSTCacheGetHandle which is waiting for one of the
 * handles in given entry to be available.
 *
 * @param entry the cache entry whose GSTCacheGetHandle list has to be searched
 * @param head the starting list element in the GSTCacheGetHandle where the
 *          search has to be begin
 * @return a suitable GSTCacheGetHandle whose handle ready notify callback
 *           hasn't been called yet. NULL if no such suitable GSTCacheGetHandle
 *           is found
 */
static struct GSTCacheGetHandle *
search_suitable_cgh (const struct CacheEntry *entry,
                     const struct GSTCacheGetHandle *head)
{
  const struct GSTCacheGetHandle *cgh;

  for (cgh = head; NULL != cgh; cgh = cgh->next)
  {
    if (GNUNET_YES == cgh->notify_called)
      return NULL;
    switch (cgh->type)
    {
    case CGT_TRANSPORT_HANDLE:
      if (NULL == entry->transport_handle)
        continue;
      break;
    case CGT_CORE_HANDLE:
      if (NULL == entry->core_handle)
        continue;
      if (NULL == entry->peer_identity) /* Our CORE connection isn't ready yet */
        continue;
      break;
    }
    break;
  }
  return (struct GSTCacheGetHandle *) cgh;
}


/**
 * Task to call the handle ready notify callback of a queued GSTCacheGetHandle
 * of an entry when one or all of its handles are available.
 *
 * @param cls the cache entry
 * @param tc the task context from scheduler
 */
static void
call_cgh_cb (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CacheEntry *entry = cls;
  struct GSTCacheGetHandle *cgh;
  const struct GSTCacheGetHandle *cgh2;

  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != entry->notify_task);
  entry->notify_task = GNUNET_SCHEDULER_NO_TASK;
  cgh = search_suitable_cgh (entry, entry->cgh_qhead);
  GNUNET_assert (NULL != cgh);
  cgh2 = NULL;
  if (NULL != cgh->next)
    cgh2 = search_suitable_cgh (entry, cgh->next);
  GNUNET_CONTAINER_DLL_remove (entry->cgh_qhead, entry->cgh_qtail, cgh);
  cgh->notify_called = GNUNET_YES;
  GNUNET_CONTAINER_DLL_insert_tail (entry->cgh_qhead, entry->cgh_qtail, cgh);
  if (NULL != cgh2)
    entry->notify_task = GNUNET_SCHEDULER_add_now (&call_cgh_cb, entry);
  if (NULL != cgh->nctxt)
  {                             /* Register the peer connect notify callback */
    GNUNET_CONTAINER_DLL_insert_tail (entry->nctxt_qhead, entry->nctxt_qtail,
                                      cgh->nctxt);
  }
  LOG_DEBUG ("Calling notify for handle type %u\n", cgh->type);
  cgh->cb (cgh->cb_cls, entry->core_handle, entry->transport_handle,
           entry->peer_identity);
}


/**
 * Function called from peer connect notify callbacks from CORE and TRANSPORT
 * connections. This function calls the pendning peer connect notify callbacks
 * which are queued in an entry.
 *
 * @param cls the cache entry
 * @param peer the peer that connected
 * @param type the type of the handle this notification corresponds to
 */
static void
peer_connect_notify_cb (void *cls, const struct GNUNET_PeerIdentity *peer,
                        const enum CacheGetType type)
{
  struct CacheEntry *entry = cls;
  struct ConnectNotifyContext *ctxt;
  struct ConnectNotifyContext *ctxt2;
  GST_cache_peer_connect_notify cb;
  void *cb_cls;


  for (ctxt = entry->nctxt_qhead; NULL != ctxt;)
  {
    GNUNET_assert (NULL != ctxt->cgh);
    if (type != ctxt->cgh->type)
    {
      ctxt = ctxt->next;
      continue;
    }
    if (0 != memcmp (ctxt->target, peer, sizeof (struct GNUNET_PeerIdentity)))
    {
      ctxt = ctxt->next;
      continue;
    }
    cb = ctxt->cb;
    cb_cls = ctxt->cb_cls;
    ctxt->cgh->nctxt = NULL;
    ctxt2 = ctxt->next;
    GNUNET_CONTAINER_DLL_remove (entry->nctxt_qhead, entry->nctxt_qtail, ctxt);
    GNUNET_free (ctxt);
    ctxt = ctxt2;
    cb (cb_cls, peer);
  }
  if (NULL == ctxt)
    return;

}


/**
 * Function called to notify transport users that another
 * peer connected to us.
 *
 * @param cls closure
 * @param peer the peer that connected
 */
static void
transport_peer_connect_notify_cb (void *cls,
                                  const struct GNUNET_PeerIdentity *peer)
{
  peer_connect_notify_cb (cls, peer, CGT_TRANSPORT_HANDLE);
}


/**
 * Function called when resources for opening a connection to TRANSPORT are
 * available.
 *
 * @param cls the cache entry
 */
static void
opstart_get_handle_transport (void *cls)
{
  struct CacheEntry *entry = cls;

  GNUNET_assert (NULL != entry);
  LOG_DEBUG ("Opening a transport connection to peer %u\n", entry->peer_id);
  entry->transport_handle =
      GNUNET_TRANSPORT_connect (entry->cfg, NULL, entry, NULL,
                                &transport_peer_connect_notify_cb, NULL);
  if (NULL == entry->transport_handle)
  {
    GNUNET_break (0);
    return;
  }
  if (0 == entry->demand)
    return;
  if (GNUNET_SCHEDULER_NO_TASK != entry->notify_task)
    return;
  if (NULL != search_suitable_cgh (entry, entry->cgh_qhead))
    entry->notify_task = GNUNET_SCHEDULER_add_now (&call_cgh_cb, entry);
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
  struct CacheEntry *entry = cls;

  if (NULL == entry->transport_handle)
    return;
  GNUNET_TRANSPORT_disconnect (entry->transport_handle);
  entry->transport_handle = NULL;
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
 * @param cls closure
 * @param server handle to the server, NULL if we failed
 * @param my_identity ID of this peer, NULL if we failed
 */
static void
core_startup_cb (void *cls, struct GNUNET_CORE_Handle *server,
                 const struct GNUNET_PeerIdentity *my_identity)
{
  struct CacheEntry *entry = cls;

  if (NULL == my_identity)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_assert (NULL == entry->peer_identity);
  GNUNET_break (NULL != server);
  entry->core_handle = server;
  entry->peer_identity = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
  memcpy (entry->peer_identity, my_identity,
          sizeof (struct GNUNET_PeerIdentity));
  if (0 == entry->demand)
    return;
  if (GNUNET_SCHEDULER_NO_TASK != entry->notify_task)
    return;
  if (NULL != search_suitable_cgh (entry, entry->cgh_qhead))
    entry->notify_task = GNUNET_SCHEDULER_add_now (&call_cgh_cb, entry);
}


/**
 * Method called whenever a given peer connects at CORE level
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
core_peer_connect_cb (void *cls, const struct GNUNET_PeerIdentity *peer)
{
  peer_connect_notify_cb (cls, peer, CGT_CORE_HANDLE);
}


/**
 * Function called when resources for opening a connection to CORE are
 * available.
 *
 * @param cls the cache entry
 */
static void
opstart_get_handle_core (void *cls)
{
  struct CacheEntry *entry = cls;

  const struct GNUNET_CORE_MessageHandler no_handlers[] = {
    {NULL, 0, 0}
  };

  GNUNET_assert (NULL != entry);
  LOG_DEBUG ("Opening a CORE connection to peer %u\n", entry->peer_id);
  entry->core_handle =
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
 * @param cls the cache entry
 */
static void
oprelease_get_handle_core (void *cls)
{
  struct CacheEntry *entry = cls;

  if (NULL == entry->core_handle)
    return;
  GNUNET_CORE_disconnect (entry->core_handle);
  entry->core_handle = NULL;
  GNUNET_free_non_null (entry->peer_identity);
  entry->peer_identity = NULL;
}


/**
 * Function to get a handle with given configuration. The type of the handle is
 * implicitly provided in the GSTCacheGetHandle. If the handle is already cached
 * before, it will be retured in the given callback; the peer_id is used to
 * lookup in the cache; if not, a new operation is started to open the transport
 * handle and will be given in the callback when it is available.
 *
 * @param peer_id the index of the peer
 * @param cgh the CacheGetHandle
 * @param cfg the configuration with which the transport handle has to be
 *          created if it was not present in the cache
 * @param target the peer identify of the peer whose connection to
 *          TRANSPORT/CORE (depending on the type of 'cgh') subsystem will be
 *          notified through the connect_notify_cb. Can be NULL
 * @param connect_notify_cb the callback to call when the given target peer is
 *          connected. This callback will only be called once or never again (in
 *          case the target peer cannot be connected). Can be NULL
 * @param connect_notify_cb_cls the closure for the above callback
 * @return the handle which can be used to cancel or mark that the handle is no
 *           longer being used
 */
static struct GSTCacheGetHandle *
cache_get_handle (unsigned int peer_id, struct GSTCacheGetHandle *cgh,
                  const struct GNUNET_CONFIGURATION_Handle *cfg,
                  const struct GNUNET_PeerIdentity *target,
                  GST_cache_peer_connect_notify connect_notify_cb,
                  void *connect_notify_cb_cls)
{
  struct GNUNET_HashCode key;
  void *handle;
  struct CacheEntry *entry;
  struct ConnectNotifyContext *ctxt;
  struct GNUNET_TESTBED_Operation *op;

  GNUNET_assert (0 != cgh->type);
  GNUNET_CRYPTO_hash (&peer_id, sizeof (peer_id), &key);
  handle = NULL;
  entry = cache_lookup (&key);
  if (NULL != entry)
  {
    if (GNUNET_YES == entry->in_lru)
    {
      GNUNET_assert (0 == entry->demand);
      GNUNET_assert (0 < lru_cache_size);
      if (GNUNET_SCHEDULER_NO_TASK != entry->expire_task)
      {
        GNUNET_SCHEDULER_cancel (entry->expire_task);
        entry->expire_task = GNUNET_SCHEDULER_NO_TASK;
      }
      GNUNET_CONTAINER_DLL_remove (lru_cache_head, lru_cache_tail, entry);
      lru_cache_size--;
      entry->in_lru = GNUNET_NO;
    }
    switch (cgh->type)
    {
    case CGT_TRANSPORT_HANDLE:
      handle = entry->transport_handle;
      if (NULL != handle)
        LOG_DEBUG ("Found TRANSPORT handle in cache for peer %u\n",
                   entry->peer_id);
      break;
    case CGT_CORE_HANDLE:
      handle = entry->core_handle;
      if (NULL != handle)
        LOG_DEBUG ("Found CORE handle in cache for peer %u\n", entry->peer_id);
      break;
    }
  }
  if (NULL == entry)
    entry = add_entry (&key, peer_id);
  if (NULL == entry->cfg)
    entry->cfg = GNUNET_CONFIGURATION_dup (cfg);
  entry->demand++;
  cgh->entry = entry;
  GNUNET_CONTAINER_DLL_insert (entry->cgh_qhead, entry->cgh_qtail, cgh);
  if ((NULL != target) && (NULL != connect_notify_cb))
  {
    ctxt = GNUNET_malloc (sizeof (struct ConnectNotifyContext));
    ctxt->target = target;
    ctxt->cb = connect_notify_cb;
    ctxt->cb_cls = connect_notify_cb_cls;
    GNUNET_assert (NULL == cgh->nctxt);
    cgh->nctxt = ctxt;
    ctxt->cgh = cgh;
  }
  if (NULL != handle)
  {
    if (GNUNET_SCHEDULER_NO_TASK == entry->notify_task)
    {
      if (NULL != search_suitable_cgh (entry, entry->cgh_qhead))
        entry->notify_task = GNUNET_SCHEDULER_add_now (&call_cgh_cb, entry);
    }
    return cgh;
  }
  op = NULL;
  switch (cgh->type)
  {
  case CGT_TRANSPORT_HANDLE:
    if (NULL != entry->transport_op)
      return cgh;
    op = GNUNET_TESTBED_operation_create_ (entry, &opstart_get_handle_transport,
                                           &oprelease_get_handle_transport);
    entry->transport_op = op;
    break;
  case CGT_CORE_HANDLE:
    if (NULL != entry->core_op)
      return cgh;
    op = GNUNET_TESTBED_operation_create_ (entry, &opstart_get_handle_core,
                                           &oprelease_get_handle_core);
    entry->core_op = op;
    break;
  default:
    GNUNET_assert (0);
  }
  GNUNET_TESTBED_operation_queue_insert_ (GST_opq_openfds, op);
  GNUNET_TESTBED_operation_begin_wait_ (op);
  return cgh;
}


/**
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
cache_clear_iterator (void *cls, const struct GNUNET_HashCode *key, void *value)
{
  struct CacheEntry *entry = value;
  static unsigned int ncleared;

  GNUNET_assert (NULL != entry);
  GNUNET_break (0 == entry->demand);
  LOG_DEBUG ("Clearing entry %u of %u\n", ++ncleared, cache_size);
  GNUNET_assert (GNUNET_YES == 
                 GNUNET_CONTAINER_multihashmap_remove (cache, key, value));
  close_handles (entry);
  GNUNET_free_non_null (entry->hello);
  GNUNET_break (GNUNET_SCHEDULER_NO_TASK == entry->expire_task);
  GNUNET_assert (NULL == entry->transport_handle);
  GNUNET_assert (NULL == entry->transport_op);
  GNUNET_assert (NULL == entry->core_handle);
  GNUNET_assert (NULL == entry->core_op);
  GNUNET_assert (NULL == entry->cfg);
  GNUNET_assert (NULL == entry->cgh_qhead);
  GNUNET_assert (NULL == entry->cgh_qtail);
  GNUNET_assert (NULL == entry->nctxt_qhead);
  GNUNET_assert (NULL == entry->nctxt_qtail);
  GNUNET_free (entry);
  return GNUNET_YES;
}


/**
 * Clear cache
 */
void
GST_cache_clear ()
{
  GNUNET_CONTAINER_multihashmap_iterate (cache, &cache_clear_iterator, NULL);
  GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap_size (cache));
  GNUNET_CONTAINER_multihashmap_destroy (cache);
  cache = NULL;
  lru_cache_size = 0;
  lru_cache_threshold_size = 0;
  cache_size = 0;
  lru_cache_head = NULL;
  lru_cache_tail = NULL;
}


/**
 * Initializes the cache
 *
 * @param size the size of the cache
 */
void
GST_cache_init (unsigned int size)
{
  if (0 == size)
    return;
  lru_cache_threshold_size = size;
  if (size > 1)
    size = size / 2;
  cache = GNUNET_CONTAINER_multihashmap_create (size, GNUNET_YES);
}


/**
 * Mark the GetCacheHandle as being done if a handle has been provided already
 * or as being cancelled if the callback for the handle hasn't been called.
 *
 * @param cgh the CacheGetHandle handle
 */
void
GST_cache_get_handle_done (struct GSTCacheGetHandle *cgh)
{
  struct CacheEntry *entry;

  entry = cgh->entry;
  GNUNET_assert (NULL != entry);
  GNUNET_assert (0 < entry->demand);
  entry->demand--;
  if (GNUNET_SCHEDULER_NO_TASK != entry->notify_task)
  {
    GNUNET_SCHEDULER_cancel (entry->notify_task);
    entry->notify_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_CONTAINER_DLL_remove (entry->cgh_qhead, entry->cgh_qtail, cgh);
  if (NULL != cgh->nctxt)
  {
    GNUNET_assert (cgh == cgh->nctxt->cgh);
    if (GNUNET_YES == cgh->notify_called)
      GNUNET_CONTAINER_DLL_remove (entry->nctxt_qhead, entry->nctxt_qtail,
                                   cgh->nctxt);
    GNUNET_free (cgh->nctxt);
  }
  GNUNET_free (cgh);
  if (0 == entry->demand)
  {
    entry->expire_task =
        GNUNET_SCHEDULER_add_delayed (CACHE_EXPIRY, &expire_cache_entry, entry);
    GNUNET_CONTAINER_DLL_insert_tail (lru_cache_head, lru_cache_tail, entry);
    lru_cache_size++;
    entry->in_lru = GNUNET_YES;
    if (lru_cache_size > lru_cache_threshold_size)
      close_handles (lru_cache_head);
  }
  else
  {
    if (NULL != search_suitable_cgh (entry, entry->cgh_qhead))
      entry->notify_task = GNUNET_SCHEDULER_add_now (&call_cgh_cb, entry);
  }
}


/**
 * Get a transport handle with the given configuration.  If the handle is
 * already cached before, it will be retured in the given callback; the peer_id
 * is used to lookup in the cache; if not, a new operation is started to open the
 * transport handle and will be given in the callback when it is available.
 *
 * @param peer_id the index of the peer
 * @param cfg the configuration with which the transport handle has to be
 *          created if it was not present in the cache
 * @param cb the callback to notify when the transport handle is available
 * @param cb_cls the closure for the above callback
 * @param target the peer identify of the peer whose connection to our TRANSPORT
 *          subsystem will be notified through the connect_notify_cb. Can be NULL
 * @param connect_notify_cb the callback to call when the given target peer is
 *          connected. This callback will only be called once or never again (in
 *          case the target peer cannot be connected). Can be NULL
 * @param connect_notify_cb_cls the closure for the above callback
 * @return the handle which can be used to cancel or mark that the handle is no
 *           longer being used
 */
struct GSTCacheGetHandle *
GST_cache_get_handle_transport (unsigned int peer_id,
                                const struct GNUNET_CONFIGURATION_Handle *cfg,
                                GST_cache_handle_ready_cb cb, void *cb_cls,
                                const struct GNUNET_PeerIdentity *target,
                                GST_cache_peer_connect_notify connect_notify_cb,
                                void *connect_notify_cb_cls)
{
  struct GSTCacheGetHandle *cgh;

  cgh = GNUNET_malloc (sizeof (struct GSTCacheGetHandle));
  cgh->cb = cb;
  cgh->cb_cls = cb_cls;
  cgh->type = CGT_TRANSPORT_HANDLE;
  return cache_get_handle (peer_id, cgh, cfg, target, connect_notify_cb,
                           connect_notify_cb_cls);
}


/**
 * Get a CORE handle with the given configuration. If the handle is already
 * cached before, it will be retured in the given callback; the peer_id is used
 * to lookup in the cache. If the handle is not cached before, a new operation
 * is started to open the CORE handle and will be given in the callback when it
 * is available along with the peer identity
 *
 * @param peer_id the index of the peer
 * @param cfg the configuration with which the transport handle has to be
 *          created if it was not present in the cache
 * @param cb the callback to notify when the transport handle is available
 * @param cb_cls the closure for the above callback
 * @param target the peer identify of the peer whose connection to our CORE
 *          subsystem will be notified through the connect_notify_cb. Can be NULL
 * @param connect_notify_cb the callback to call when the given target peer is
 *          connected. This callback will only be called once or never again (in
 *          case the target peer cannot be connected). Can be NULL
 * @param connect_notify_cb_cls the closure for the above callback
 * @return the handle which can be used to cancel or mark that the handle is no
 *           longer being used
 */
struct GSTCacheGetHandle *
GST_cache_get_handle_core (unsigned int peer_id,
                           const struct GNUNET_CONFIGURATION_Handle *cfg,
                           GST_cache_handle_ready_cb cb, void *cb_cls,
                           const struct GNUNET_PeerIdentity *target,
                           GST_cache_peer_connect_notify connect_notify_cb,
                           void *connect_notify_cb_cls)
{
  struct GSTCacheGetHandle *cgh;

  cgh = GNUNET_malloc (sizeof (struct GSTCacheGetHandle));
  cgh->cb = cb;
  cgh->cb_cls = cb_cls;
  cgh->type = CGT_CORE_HANDLE;
  return cache_get_handle (peer_id, cgh, cfg, target, connect_notify_cb,
                           connect_notify_cb_cls);
}


/**
 * Looks up in the hello cache and returns the HELLO of the given peer
 *
 * @param peer_id the index of the peer whose HELLO has to be looked up
 * @return the HELLO message; NULL if not found
 */
const struct GNUNET_MessageHeader *
GST_cache_lookup_hello (const unsigned int peer_id)
{
  struct CacheEntry *entry;
  struct GNUNET_HashCode key;

  LOG_DEBUG ("Looking up HELLO for peer %u\n", peer_id);
  GNUNET_CRYPTO_hash (&peer_id, sizeof (peer_id), &key);
  entry = cache_lookup (&key);
  if (NULL == entry)
    return NULL;
  if (NULL != entry->hello)
    LOG_DEBUG ("HELLO found for peer %u\n", peer_id);
  return entry->hello;
}


/**
 * Caches the HELLO of the given peer. Updates the HELLO if it was already
 * cached before
 *
 * @param peer_id the peer identity of the peer whose HELLO has to be cached
 * @param hello the HELLO message
 */
void
GST_cache_add_hello (const unsigned int peer_id,
                     const struct GNUNET_MessageHeader *hello)
{
  struct CacheEntry *entry;
  struct GNUNET_HashCode key;

  GNUNET_CRYPTO_hash (&peer_id, sizeof (peer_id), &key);
  entry = GNUNET_CONTAINER_multihashmap_get (cache, &key);
  if (NULL == entry)
    entry = add_entry (&key, peer_id);
  GNUNET_free_non_null (entry->hello);
  entry->hello = GNUNET_copy_message (hello);
}

/* end of gnunet-service-testbed_hc.c */
