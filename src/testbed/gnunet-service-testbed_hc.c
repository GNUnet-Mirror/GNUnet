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
   * The key for this entry
   */
  struct GNUNET_HashCode key;

  /**
   * The HELLO message
   */
  struct GNUNET_MessageHeader *hello;
};

/**
 * Hashmap to maintain cache
 */
static struct GNUNET_CONTAINER_MultiHashMap *cache;

/**
 * DLL head for least recently used cache entries; least recently used
 * cache items are at the head
 */
static struct CacheEntry *lru_hcache_head;

/**
 * DLL tail for least recently used cache entries; recently used cache
 * items are at the tail
 */
static struct CacheEntry *lru_hcache_tail;

/**
 * The size of cache
 */
static unsigned int cache_size;


/**
 * Looks up in the cache and returns the HELLO of the given peer
 *
 * @param id the peer identity of the peer whose HELLO has to be looked up
 * @return the HELLO message; NULL if not found
 */
const struct GNUNET_MessageHeader *
GST_cache_lookup (const struct GNUNET_PeerIdentity *id)
{
  struct CacheEntry *entry;

  if (NULL == cache)
    return NULL;
  entry = GNUNET_CONTAINER_multihashmap_get (cache, &id->hashPubKey);
  if (NULL == entry)
    return NULL;
  GNUNET_CONTAINER_DLL_remove (lru_hcache_head, lru_hcache_tail, entry);
  GNUNET_CONTAINER_DLL_insert_tail (lru_hcache_head, lru_hcache_tail, entry);
  return entry->hello;
}


/**
 * Removes the given cache entry from cache and frees its resources
 *
 * @param entry the entry to remove
 */
static void
GST_cache_remove (struct CacheEntry *entry)
{
  GNUNET_CONTAINER_DLL_remove (lru_hcache_head, lru_hcache_tail, entry);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (cache, &entry->key,
                                                       entry));
  GNUNET_free (entry->hello);
  GNUNET_free (entry);
}


/**
 * Caches the HELLO of the given peer. Updates the HELLO if it was already
 * cached before
 *
 * @param id the peer identity of the peer whose HELLO has to be cached
 * @param hello the HELLO message
 */
void
GST_cache_add (const struct GNUNET_PeerIdentity *id,
                     const struct GNUNET_MessageHeader *hello)
{
  struct CacheEntry *entry;

  if (NULL == cache)
    return;
  entry = GNUNET_CONTAINER_multihashmap_get (cache, &id->hashPubKey);
  if (NULL == entry)
  {
    entry = GNUNET_malloc (sizeof (struct CacheEntry));
    memcpy (&entry->key, &id->hashPubKey, sizeof (struct GNUNET_HashCode));
    if (GNUNET_CONTAINER_multihashmap_size (cache) == cache_size)
    {
      GNUNET_assert (NULL != lru_hcache_head);
      GST_cache_remove (lru_hcache_head);
    }
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put (cache, &entry->key,
                                                      entry,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
  }
  else
  {
    GNUNET_CONTAINER_DLL_remove (lru_hcache_head, lru_hcache_tail, entry);
    GNUNET_free (entry->hello);
  }
  entry->hello = GNUNET_copy_message (hello);
  GNUNET_CONTAINER_DLL_insert_tail (lru_hcache_head, lru_hcache_tail, entry);
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
  if (size > 1)
    size = size / 2;
  cache = GNUNET_CONTAINER_multihashmap_create (size, GNUNET_YES);
}


/**
 * Clear cache
 */
void
GST_cache_clear ()
{
  if (NULL != cache)
    GNUNET_assert (GNUNET_CONTAINER_multihashmap_size (cache) <=
                   cache_size);
  while (NULL != lru_hcache_head)
    GST_cache_remove (lru_hcache_head);
  if (NULL != cache)
  {
    GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap_size (cache));
    GNUNET_CONTAINER_multihashmap_destroy (cache);
  }
}

/* end of gnunet-service-testbed_hc.c */
