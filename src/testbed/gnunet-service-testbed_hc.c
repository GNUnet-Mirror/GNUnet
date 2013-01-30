/*
  This file is part of GNUnet.
  (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file testbed/gnunet-service-testbed_hc.h
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


enum CacheGetType
{    
  CGT_TRANSPORT_HANDLE = 1
};


struct GSTCacheGetHandle
{
  struct GSTCacheGetHandle *next;

  struct GSTCacheGetHandle *prev;

  struct CacheEntry *entry;
  
  GST_cache_callback cb;
   
  void *cb_cls;

  struct ConnectNotifyContext *nctxt;

  enum CacheGetType type;

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
   * Number of operations this cache entry is being used
   */
  unsigned int demand;

  /**
   * The id of the peer this entry corresponds to
   */
  unsigned int peer_id;
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
 * @param id the peer identity of the peer whose corresponding entry has to be looked up
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


static struct CacheEntry *
cache_lookup_handles (const struct GNUNET_HashCode *pid,
                      struct GNUNET_TRANSPORT_Handle **th)
{
  struct CacheEntry *entry;
  
  GNUNET_assert (NULL != th);
  entry = cache_lookup (pid);  
  if (NULL == entry)
    return NULL;
  if (NULL != entry->transport_handle)
    *th = entry->transport_handle;
  return entry;
}


static void
cache_remove (struct CacheEntry *entry)
{
  /* We keep the entry in the hash table so that the HELLO can still be found
     in cache; we will however disconnect the core and transport handles */
  GNUNET_assert (0 == entry->demand);
  if ((NULL != entry->next) || (NULL != entry->prev))
    GNUNET_CONTAINER_DLL_remove (lru_cache_head, lru_cache_tail, entry);
  LOG_DEBUG ("Cleaning up handles from an entry in cache\n");
  if (NULL != entry->transport_handle)
  {
    GNUNET_assert (NULL != entry->transport_op);
    GNUNET_TESTBED_operation_done (entry->transport_op);
    entry->transport_op = NULL;
  }
  if (NULL != entry->cfg)
  {
    GNUNET_CONFIGURATION_destroy (entry->cfg);
    entry->cfg = NULL;
  }
}


static struct CacheEntry *
add_entry (const struct GNUNET_HashCode *key, unsigned int peer_id)
{
  struct CacheEntry *entry;

  entry = GNUNET_malloc (sizeof (struct CacheEntry));
  entry->peer_id = peer_id;
  memcpy (&entry->key, key, sizeof (struct GNUNET_HashCode));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (cache, &entry->key,
                                                    entry,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
  cache_size++;
  return entry;
}


static void
call_cgh_cb (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CacheEntry *entry = cls;
  struct GSTCacheGetHandle *cgh;

  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != entry->notify_task);
  entry->notify_task = GNUNET_SCHEDULER_NO_TASK;
  cgh = entry->cgh_qhead;
  GNUNET_assert (GNUNET_NO == cgh->notify_called);
  GNUNET_CONTAINER_DLL_remove (entry->cgh_qhead, entry->cgh_qtail, cgh);
  cgh->notify_called = GNUNET_YES;
  GNUNET_CONTAINER_DLL_insert_tail (entry->cgh_qhead, entry->cgh_qtail, cgh);
  if (GNUNET_NO == entry->cgh_qhead->notify_called)
    entry->notify_task = GNUNET_SCHEDULER_add_now (&call_cgh_cb, entry);
  switch (cgh->type)
  {
  case CGT_TRANSPORT_HANDLE:
    cgh->cb (cgh->cb_cls, NULL, entry->transport_handle);
    break;
  }
}

/**
 * Function called to notify transport users that another
 * peer connected to us.
 *
 * @param cls closure
 * @param peer the peer that connected
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
static void 
peer_connect_notify_cb (void *cls,
                        const struct GNUNET_PeerIdentity *peer,
                        const struct GNUNET_ATS_Information *ats,
                        uint32_t ats_count)
{
  struct CacheEntry *entry = cls;
  struct ConnectNotifyContext *ctxt;
  GST_cache_peer_connect_notify cb;
  void *cb_cls;

  
  for (ctxt=entry->nctxt_qhead; NULL != ctxt; ctxt=ctxt->next)
  {
    if (0 == memcmp (ctxt->target, peer, sizeof (struct GNUNET_PeerIdentity)))
      break;
  }
  if (NULL == ctxt)
    return;
  cb = ctxt->cb;
  cb_cls = ctxt->cb_cls;
  GNUNET_assert (NULL != ctxt->cgh);
  ctxt->cgh->nctxt = NULL;
  GNUNET_CONTAINER_DLL_remove (entry->nctxt_qhead, entry->nctxt_qtail, ctxt);
  GNUNET_free (ctxt);
  cb (cb_cls, peer);
}


static void
opstart_get_handle_transport (void *cls)
{
  struct CacheEntry *entry = cls;

  GNUNET_assert (NULL != entry);
  LOG_DEBUG ("Opening a transport connection to peer %u\n", entry->peer_id);
  entry->transport_handle = GNUNET_TRANSPORT_connect (entry->cfg,
                                                      NULL, entry,
                                                      NULL,
                                                      &peer_connect_notify_cb,
                                                      NULL);
  if (NULL == entry->transport_handle)
  {
    GNUNET_break (0);
    return;
  }
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == entry->notify_task);
  if (0 == entry->demand)
    return;
  if (GNUNET_NO == entry->cgh_qhead->notify_called)
    entry->notify_task = GNUNET_SCHEDULER_add_now (&call_cgh_cb, entry);
}


static void
oprelease_get_handle_transport (void *cls)
{
  struct CacheEntry *entry = cls;
  struct ConnectNotifyContext *ctxt;
  
  while (NULL != (ctxt = entry->nctxt_qhead))
  {
    GNUNET_CONTAINER_DLL_remove (entry->nctxt_qhead, entry->nctxt_qtail, ctxt);
    GNUNET_free (ctxt);
  }
  if (NULL == entry->transport_handle)
    return;
  GNUNET_TRANSPORT_disconnect (entry->transport_handle);
  entry->transport_handle = NULL;
}


static struct GSTCacheGetHandle *
cache_get_handle (unsigned int peer_id,
                  struct GSTCacheGetHandle *cgh,
                  const struct GNUNET_CONFIGURATION_Handle *cfg,
                  const struct GNUNET_PeerIdentity *target,
                  GST_cache_peer_connect_notify connect_notify_cb,
                  void *connect_notify_cb_cls)
{
  struct GNUNET_HashCode key;
  void *handle;
  struct CacheEntry *entry;
  struct ConnectNotifyContext *ctxt;

  GNUNET_assert (0 != cgh->type);
  GNUNET_CRYPTO_hash (&peer_id, sizeof (peer_id), &key);
  handle = NULL;
  entry = NULL;
  switch (cgh->type)
  {
  case CGT_TRANSPORT_HANDLE:
    entry = cache_lookup_handles (&key, (struct GNUNET_TRANSPORT_Handle **) &handle);
    break;
  }
  if (NULL != handle)
  {
    GNUNET_assert (NULL != entry);
    LOG_DEBUG ("Found existing transport handle in cache\n");
    if (0 == entry->demand)
      GNUNET_CONTAINER_DLL_remove (lru_cache_head, lru_cache_tail, entry);
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
    GNUNET_CONTAINER_DLL_insert_tail (entry->nctxt_qhead, entry->nctxt_qtail, ctxt);
  }
  if ((NULL != entry->transport_handle)
      && (GNUNET_SCHEDULER_NO_TASK == entry->notify_task))
  {
    entry->notify_task = GNUNET_SCHEDULER_add_now (&call_cgh_cb, entry);
    return cgh;
  }
  if (NULL != entry->transport_op)
    return cgh;
  switch (cgh->type)
  {
  case CGT_TRANSPORT_HANDLE:
    GNUNET_assert (NULL == entry->transport_op);
    entry->transport_op = GNUNET_TESTBED_operation_create_ (entry, &opstart_get_handle_transport,
                                                            &oprelease_get_handle_transport);
    GNUNET_TESTBED_operation_queue_insert_ (GST_opq_openfds,
                                            entry->transport_op);
    GNUNET_TESTBED_operation_begin_wait_ (entry->transport_op);
    break;
  }
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
cache_clear_iterator (void *cls,
                      const struct GNUNET_HashCode * key,
                      void *value)
{
  struct CacheEntry *entry = value;
  static unsigned int ncleared;

  GNUNET_assert (NULL != entry);
  GNUNET_break (0 == entry->demand);
  LOG_DEBUG ("Clearing entry %u of %u\n", ++ncleared, cache_size);
  GNUNET_CONTAINER_multihashmap_remove (cache, key, value);
  if (0 == entry->demand)
    cache_remove (entry);
  GNUNET_free_non_null (entry->hello);
  GNUNET_break (NULL == entry->transport_handle);
  GNUNET_break (NULL == entry->cfg);
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
    GNUNET_CONTAINER_DLL_remove (entry->nctxt_qhead, entry->nctxt_qtail, cgh->nctxt);
    GNUNET_free (cgh->nctxt);
  }
  
  if (0 == entry->demand)
  {
    GNUNET_CONTAINER_DLL_insert_tail (lru_cache_head, lru_cache_tail, entry);
    if (lru_cache_size > lru_cache_threshold_size)
      cache_remove (lru_cache_head);
  }
  else
  {
    if (GNUNET_NO == entry->cgh_qhead->notify_called)
      entry->notify_task = GNUNET_SCHEDULER_add_now (&call_cgh_cb, entry);
  }
  GNUNET_free (cgh);
}


/**
 * Get a transport handle with the given configuration. If the handle is already
 * cached before, it will be retured in the given callback; the peer_id is used to lookup in the
 * cache. If not a new operation is started to open the transport handle and
 * will be given in the callback when it is available.
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
 * @return the handle which can be used cancel or mark that the handle is no
 *           longer being used
 */
struct GSTCacheGetHandle *
GST_cache_get_handle_transport (unsigned int peer_id,
                                const struct GNUNET_CONFIGURATION_Handle *cfg,
                                GST_cache_callback cb,
                                void *cb_cls,
                                const struct GNUNET_PeerIdentity *target,
                                GST_cache_peer_connect_notify connect_notify_cb,
                                void *connect_notify_cb_cls)
{
  struct GSTCacheGetHandle *cgh;

  cgh = GNUNET_malloc (sizeof (struct GSTCacheGetHandle));
  cgh->cb = cb;
  cgh->cb_cls = cb_cls;
  cgh->type = CGT_TRANSPORT_HANDLE;
  return cache_get_handle (peer_id, cgh, cfg,
                           target, connect_notify_cb, connect_notify_cb_cls);
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
 * @param id the peer identity of the peer whose HELLO has to be cached
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
