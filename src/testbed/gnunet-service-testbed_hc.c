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
 * Hello cache entry
 */
struct HelloCacheEntry
{
  /**
   * DLL next ptr for least recently used hello cache entries
   */
  struct HelloCacheEntry *next;

  /**
   * DLL prev ptr for least recently used hello cache entries
   */
  struct HelloCacheEntry *prev;

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
 * Hashmap to maintain HELLO cache
 */
static struct GNUNET_CONTAINER_MultiHashMap *hello_cache;

/**
 * DLL head for least recently used hello cache entries; least recently used
 * cache items are at the head
 */
static struct HelloCacheEntry *lru_hcache_head;

/**
 * DLL tail for least recently used hello cache entries; recently used cache
 * items are at the tail
 */
static struct HelloCacheEntry *lru_hcache_tail;

/**
 * The size of HELLO cache
 */
static unsigned int hello_cache_size;


/**
 * Looks up in the hello cache and returns the HELLO of the given peer
 *
 * @param id the peer identity of the peer whose HELLO has to be looked up
 * @return the HELLO message; NULL if not found
 */
const struct GNUNET_MessageHeader *
TESTBED_hello_cache_lookup (const struct GNUNET_PeerIdentity *id)
{
  struct HelloCacheEntry *entry;

  if (NULL == hello_cache)
    return NULL;
  entry = GNUNET_CONTAINER_multihashmap_get (hello_cache, &id->hashPubKey);
  if (NULL == entry)
    return NULL;
  GNUNET_CONTAINER_DLL_remove (lru_hcache_head, lru_hcache_tail, entry);
  GNUNET_CONTAINER_DLL_insert_tail (lru_hcache_head, lru_hcache_tail, entry);
  return entry->hello;
}


/**
 * Removes the given hello cache centry from hello cache and frees its resources
 *
 * @param entry the entry to remove
 */
static void
TESTBED_hello_cache_remove (struct HelloCacheEntry *entry)
{
  GNUNET_CONTAINER_DLL_remove (lru_hcache_head, lru_hcache_tail, entry);
  GNUNET_assert (GNUNET_YES == 
                 GNUNET_CONTAINER_multihashmap_remove (hello_cache,
                                                       &entry->key,
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
TESTBED_hello_cache_add (const struct GNUNET_PeerIdentity *id,
                         const struct GNUNET_MessageHeader *hello)
{
  struct HelloCacheEntry *entry;
  
  if (NULL == hello_cache)
    return;
  entry = GNUNET_CONTAINER_multihashmap_get (hello_cache, &id->hashPubKey);
  if (NULL == entry)
  {
    entry = GNUNET_malloc (sizeof (struct HelloCacheEntry));
    memcpy (&entry->key, &id->hashPubKey, sizeof (struct GNUNET_HashCode));
    if (GNUNET_CONTAINER_multihashmap_size (hello_cache) == hello_cache_size)
    {
      GNUNET_assert (NULL != lru_hcache_head);
      TESTBED_hello_cache_remove (lru_hcache_head);
    }
    GNUNET_assert (GNUNET_OK == GNUNET_CONTAINER_multihashmap_put 
                   (hello_cache,
                    &entry->key,
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
TESTBED_cache_init (unsigned int size)
{
  if (0 == size)
    return;
  hello_cache_size = size;
  if (size > 1)
    size = size / 2;
  hello_cache = GNUNET_CONTAINER_multihashmap_create (size, GNUNET_YES);
}


/**
 * Clear cache
 */
void
TESTBED_cache_clear ()
{
  if (NULL != hello_cache)
    GNUNET_assert
        (GNUNET_CONTAINER_multihashmap_size (hello_cache) <= hello_cache_size);
  while (NULL != lru_hcache_head)
    TESTBED_hello_cache_remove (lru_hcache_head);
  if (NULL != hello_cache)
  {
    GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap_size (hello_cache));
    GNUNET_CONTAINER_multihashmap_destroy (hello_cache);
  }
}

/* end of gnunet-service-testbed_hc.c */
