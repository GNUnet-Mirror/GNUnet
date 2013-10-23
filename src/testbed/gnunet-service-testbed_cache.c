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
   * The peer identity of this peer. Will be set upon opening a connection to
   * the peers CORE service. Will be NULL until then and after the CORE
   * connection is closed
   */
  struct GNUNET_PeerIdentity *peer_identity;

  /**
   * The key for this entry
   */
  struct GNUNET_HashCode key;

  /**
   * The HELLO message
   */
  struct GNUNET_MessageHeader *hello;

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
  LOG_DEBUG ("Clearing entry %u of %u\n", ++ncleared, cache_size);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (cache, key, value));
  GNUNET_free_non_null (entry->hello);
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
