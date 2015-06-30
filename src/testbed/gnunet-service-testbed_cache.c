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
   * The HELLO message
   */
  struct GNUNET_MessageHeader *hello;

  /**
   * The id of the peer this entry corresponds to
   */
  unsigned int peer_id;
};


/**
 * Hashmap to maintain cache
 */
static struct GNUNET_CONTAINER_MultiHashMap32 *cache;

/**
 * DLL head for least recently used cache entries; least recently used
 * cache items are at the head. The cache enties are added to this queue when
 * their demand becomes zero. They are removed from the queue when they are
 * needed by any operation.
 */
static struct CacheEntry *cache_head;

/**
 * DLL tail for least recently used cache entries; recently used cache
 * items are at the tail.The cache enties are added to this queue when
 * their demand becomes zero. They are removed from the queue when they are
 * needed by any operation.
 */
static struct CacheEntry *cache_tail;

/**
 * Maximum number of elements to cache
 */
static unsigned int cache_size;


/**
 * Looks up in the cache and returns the entry
 *
 * @param peer_id the peer identity of the peer whose corresponding entry has to
 *          be looked up
 * @return the HELLO message; NULL if not found
 */
static struct CacheEntry *
cache_lookup (unsigned int peer_id)
{
  struct CacheEntry *entry;

  GNUNET_assert (NULL != cache);
  entry = GNUNET_CONTAINER_multihashmap32_get (cache, peer_id);
  if (NULL == entry)
    return NULL;
  GNUNET_CONTAINER_DLL_remove (cache_head, cache_tail, entry);
  GNUNET_CONTAINER_DLL_insert_tail (cache_head, cache_tail, entry);
  return entry;
}


/**
 * Free the resources occupied by a cache entry
 *
 * @param entry the cache entry to free
 */
static void
free_entry (struct CacheEntry *entry)
{
  GNUNET_CONTAINER_DLL_remove (cache_head, cache_tail, entry);
  GNUNET_free_non_null (entry->hello);
  GNUNET_free (entry);
}


/**
 * Creates a new cache entry and then puts it into the cache's hashtable.
 *
 * @param peer_id the index of the peer to tag the newly created entry
 * @return the newly created entry
 */
static struct CacheEntry *
add_entry (unsigned int peer_id)
{
  struct CacheEntry *entry;

  GNUNET_assert (NULL != cache);
  if (cache_size == GNUNET_CONTAINER_multihashmap32_size (cache))
  {
    /* remove the LRU head */
    entry = cache_head;
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap32_remove (cache, (uint32_t)
                                                           entry->peer_id,
                                                           entry));
    free_entry (entry);
  }
  entry = GNUNET_new (struct CacheEntry);
  entry->peer_id = peer_id;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap32_put (cache,
                                                      (uint32_t) peer_id,
                                                      entry,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
  GNUNET_CONTAINER_DLL_insert_tail (cache_head, cache_tail, entry);
  return entry;
}


/**
 * Iterator over hash map entries.
 *
 * @param cls closure
 * @param key current key
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to
 *         iterate,
 *         GNUNET_NO if not.
 */
static int
cache_clear_iterator (void *cls, uint32_t key, void *value)
{
  struct CacheEntry *entry = value;

  GNUNET_assert (NULL != entry);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap32_remove (cache, key, value));
  free_entry (entry);
  return GNUNET_YES;
}


/**
 * Clear cache
 */
void
GST_cache_clear ()
{
  if (NULL != cache)
  {
    GNUNET_CONTAINER_multihashmap32_iterate (cache, &cache_clear_iterator, NULL);
    GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap32_size (cache));
    GNUNET_CONTAINER_multihashmap32_destroy (cache);
    cache = NULL;
  }
  cache_size = 0;
  cache_head = NULL;
  cache_tail = NULL;
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
  cache_size = size;
  cache = GNUNET_CONTAINER_multihashmap32_create (cache_size);
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

  LOG_DEBUG ("Looking up HELLO for peer %u\n", peer_id);
  if (NULL == cache)
  {
    LOG_DEBUG ("Caching disabled\n");
    return NULL;
  }
  entry = cache_lookup (peer_id);
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

  if (NULL == cache)
    return;
  entry = cache_lookup (peer_id);
  if (NULL == entry)
    entry = add_entry (peer_id);
  GNUNET_free_non_null (entry->hello);
  entry->hello = GNUNET_copy_message (hello);
}

/* end of gnunet-service-testbed_hc.c */
