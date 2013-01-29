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


#ifdef LOG
#undef LOG
#endif

#define LOG(kind,...)                                   \
  GNUNET_log_from (kind, "testbed-cache", __VA_ARGS__)

/* #define LOG_DEBUG(...)                          \ */
/*   LOG (GNUNET_ERROR_TYPE_DEBUG, __VA_ARGS__) */


enum CacheGetType
{    
  CGT_TRANSPORT_HANDLE = 1
};


struct GSTCacheGetHandle
{
  struct GNUNET_TESTBED_Operation *op;
  
  struct CacheEntry *entry;
  
  struct GNUNET_CORE_Handle *ch;

  struct GNUNET_TRANSPORT_Handle *th;
  
  void *handle;

  GST_cache_callback cb;
   
  void *cb_cls;

  GNUNET_SCHEDULER_TaskIdentifier notify_task;

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
   * The cache get handle which created this entry. Will be NULL after the
   * operation for creating a core or transport handler is started, i.e. in the
   * function opstart_get_handle_transport
   */
  struct GSTCacheGetHandle *cgh;

  /**
   * The key for this entry
   */
  struct GNUNET_HashCode key;

  /**
   * The HELLO message
   */
  struct GNUNET_MessageHeader *hello;

  /**
   * Number of operations this cache entry is being used
   */
  unsigned int demand;
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
  
  GNUNET_assert ((NULL != th));
  entry = cache_lookup (pid);  
  if (NULL == entry)
    return NULL;
  if (0 == entry->demand)
    GNUNET_CONTAINER_DLL_remove (lru_cache_head, lru_cache_tail, entry);
  if ((NULL != th) && (NULL != entry->transport_handle))
    *th = entry->transport_handle;
  return entry;
}


static void
cache_remove (struct CacheEntry *entry)
{
  /* We keep the entry in the hash table so that the HELLO can still be found
     in cache; we will however disconnect the core and transport handles */
  GNUNET_assert (0 == entry->demand);
  GNUNET_assert (NULL != entry->cfg);
  GNUNET_CONTAINER_DLL_remove (lru_cache_head, lru_cache_tail, entry);
  if (NULL != entry->transport_handle)
  {
    GNUNET_assert (NULL != entry->transport_op);
    GNUNET_TESTBED_operation_done (entry->transport_op);
    entry->transport_op = NULL;
  }
  GNUNET_CONFIGURATION_destroy (entry->cfg);
  entry->cfg = NULL;
}


static struct CacheEntry *
add_entry (const struct GNUNET_HashCode *key)
{
  struct CacheEntry *entry;

  entry = GNUNET_malloc (sizeof (struct CacheEntry));
  memcpy (&entry->key, key, sizeof (struct GNUNET_HashCode));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (cache, &entry->key,
                                                    entry,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
  return entry;
}


static void
cache_notify_callback (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GSTCacheGetHandle *cgh = cls;
  
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != cgh->notify_task);
  cgh->notify_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_assert (NULL != cgh->entry);
  cgh->entry->demand++;
  cgh->notify_called = GNUNET_YES;
  switch (cgh->type)
  {
  case CGT_TRANSPORT_HANDLE:
    cgh->cb (cgh->cb_cls, NULL, cgh->handle);
    break;
  }
}


static void
opstart_get_handle_transport (void *cls)
{
  struct CacheEntry *entry = cls;
  struct GSTCacheGetHandle *cgh = entry->cgh;

  GNUNET_assert (NULL != entry);
  GNUNET_assert (NULL != cgh);
  GNUNET_assert (NULL != entry->cfg);
  LOG_DEBUG ("Opening a transport connection\n");
  entry->cgh = NULL;
  entry->transport_handle = GNUNET_TRANSPORT_connect (entry->cfg,
                                                      NULL, NULL,
                                                      NULL,
                                                      NULL,
                                                      NULL);
  if (NULL == entry->transport_handle)
  {
    GNUNET_break (0);
    return;
  }
  cgh->handle = entry->transport_handle;
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == cgh->notify_task);
  cgh->notify_task = GNUNET_SCHEDULER_add_now (&cache_notify_callback, cgh);
}


static void
oprelease_get_handle_transport (void *cls)
{
  struct CacheEntry *entry = cls;

  if (NULL == entry->transport_handle)
    return;
  GNUNET_TRANSPORT_disconnect (entry->transport_handle);
  entry->transport_handle = NULL;
}


static struct GSTCacheGetHandle *
cache_get_handle (unsigned int peer_id,
                  struct GSTCacheGetHandle *cgh,
                  const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_HashCode key;
  struct GNUNET_CORE_Handle *ch;
  void *handle;
  struct CacheEntry *entry;

  GNUNET_assert (0 != cgh->type);
  GNUNET_CRYPTO_hash (&peer_id, sizeof (peer_id), &key);
  ch = NULL;
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
    cgh->entry = entry;
    cgh->ch = ch;
    cgh->handle = handle;
    cgh->notify_task = GNUNET_SCHEDULER_add_now (&cache_notify_callback, cgh);
    return cgh;
  }
  if (NULL == entry)
    entry = add_entry (&key);
  if (NULL == entry->cfg)
    entry->cfg = GNUNET_CONFIGURATION_dup (cfg);
  cgh->entry = entry;
  entry->cgh = cgh;
  switch (cgh->type)
  {
  case CGT_TRANSPORT_HANDLE:
    GNUNET_assert (NULL == entry->transport_op);
    LOG_DEBUG ("Creating an operation for opening transport handle");
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

  GNUNET_assert (NULL != entry);
  GNUNET_CONTAINER_multihashmap_remove (cache, key, value);
  GNUNET_free_non_null (entry->hello);
  GNUNET_break (NULL == entry->transport_handle);
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
  if (GNUNET_SCHEDULER_NO_TASK != cgh->notify_task)
    GNUNET_SCHEDULER_cancel (cgh->notify_task);
  if (GNUNET_YES == cgh->notify_called)
  {
    cgh->entry->demand--;
    if (0 == cgh->entry->demand)
    {
      GNUNET_CONTAINER_DLL_insert_tail (lru_cache_head, lru_cache_tail, cgh->entry);
      if (lru_cache_size > lru_cache_threshold_size)
        cache_remove (lru_cache_head);
    }
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
 * @return the handle which can be used cancel or mark that the handle is no
 *           longer being used
 */
struct GSTCacheGetHandle *
GST_cache_get_handle_transport (unsigned int peer_id,
                                const struct GNUNET_CONFIGURATION_Handle *cfg,
                                GST_cache_callback cb,
                                void *cb_cls)
{
  struct GSTCacheGetHandle *cgh;

  cgh = GNUNET_malloc (sizeof (struct GSTCacheGetHandle));
  cgh->cb = cb;
  cgh->cb_cls = cb_cls;
  cgh->type = CGT_TRANSPORT_HANDLE;
  return cache_get_handle (peer_id, cgh, cfg);
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
  
  GNUNET_CRYPTO_hash (&peer_id, sizeof (peer_id), &key);
  entry = cache_lookup (&key);
  if (NULL == entry)
    return NULL;
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
    entry = add_entry (&key);
  GNUNET_free_non_null (entry->hello);
  entry->hello = GNUNET_copy_message (hello);
}

/* end of gnunet-service-testbed_hc.c */
