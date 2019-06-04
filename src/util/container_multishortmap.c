/*
     This file is part of GNUnet.
     Copyright (C) 2008, 2012 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/
/**
 * @file util/container_multishortmap.c
 * @brief hash map where the same key may be present multiple times
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"

#define LOG(kind, ...) \
  GNUNET_log_from (kind, "util-container-multishortmap", __VA_ARGS__)

/**
 * Maximum recursion depth for callbacks of
 * #GNUNET_CONTAINER_multihashmap_get_multiple() themselve s
 * again calling #GNUNET_CONTAINER_multihashmap_get_multiple().
 * Should be totally excessive, but if violated we die.
 */
#define NEXT_CACHE_SIZE 16


/**
 * An entry in the hash map with the full key.
 */
struct BigMapEntry
{

  /**
   * Value of the entry.
   */
  void *value;

  /**
   * If there is a hash collision, we create a linked list.
   */
  struct BigMapEntry *next;

  /**
   * Key for the entry.
   */
  struct GNUNET_ShortHashCode key;
};


/**
 * An entry in the hash map with just a pointer to the key.
 */
struct SmallMapEntry
{

  /**
   * Value of the entry.
   */
  void *value;

  /**
   * If there is a hash collision, we create a linked list.
   */
  struct SmallMapEntry *next;

  /**
   * Key for the entry.
   */
  const struct GNUNET_ShortHashCode *key;
};


/**
 * Entry in the map.
 */
union MapEntry
{
  /**
   * Variant used if map entries only contain a pointer to the key.
   */
  struct SmallMapEntry *sme;

  /**
   * Variant used if map entries contain the full key.
   */
  struct BigMapEntry *bme;
};


/**
 * Internal representation of the hash map.
 */
struct GNUNET_CONTAINER_MultiShortmap
{
  /**
   * All of our buckets.
   */
  union MapEntry *map;

  /**
   * Number of entries in the map.
   */
  unsigned int size;

  /**
   * Length of the "map" array.
   */
  unsigned int map_length;

  /**
   * #GNUNET_NO if the map entries are of type 'struct BigMapEntry',
   * #GNUNET_YES if the map entries are of type 'struct SmallMapEntry'.
   */
  int use_small_entries;

  /**
   * Counts the destructive modifications (grow, remove)
   * to the map, so that iterators can check if they are still valid.
   */
  unsigned int modification_counter;

  /**
   * Map entries indicating iteration positions currently
   * in use by #GNUNET_CONTAINER_multihashmap_get_multiple().
   * Only used up to @e next_cache_off.
   */
  union MapEntry next_cache[NEXT_CACHE_SIZE];

  /**
   * Offset of @e next_cache entries in use, must be smaller
   * than #NEXT_CACHE_SIZE.
   */
  unsigned int next_cache_off;
};


/**
 * Cursor into a multishortmap.
 * Allows to enumerate elements asynchronously.
 */
struct GNUNET_CONTAINER_MultiShortmapIterator
{
  /**
   * Position in the bucket 'idx'
   */
  union MapEntry me;

  /**
   * Current bucket index.
   */
  unsigned int idx;

  /**
   * Modification counter as observed on the map when the iterator
   * was created.
   */
  unsigned int modification_counter;

  /**
   * Map that we are iterating over.
   */
  const struct GNUNET_CONTAINER_MultiShortmap *map;
};


/**
 * Create a multi hash map.
 *
 * @param len initial size (map will grow as needed)
 * @param do_not_copy_keys #GNUNET_NO is always safe and should be used by default;
 *                         #GNUNET_YES means that on 'put', the 'key' does not have
 *                         to be copied as the destination of the pointer is
 *                         guaranteed to be life as long as the value is stored in
 *                         the hashmap.  This can significantly reduce memory
 *                         consumption, but of course is also a recipie for
 *                         heap corruption if the assumption is not true.  Only
 *                         use this if (1) memory use is important in this case and
 *                         (2) you have triple-checked that the invariant holds
 * @return NULL on error
 */
struct GNUNET_CONTAINER_MultiShortmap *
GNUNET_CONTAINER_multishortmap_create (unsigned int len, int do_not_copy_keys)
{
  struct GNUNET_CONTAINER_MultiShortmap *map;

  GNUNET_assert (len > 0);
  map = GNUNET_new (struct GNUNET_CONTAINER_MultiShortmap);
  map->map = GNUNET_malloc_large (len * sizeof (union MapEntry));
  if (NULL == map->map)
  {
    GNUNET_free (map);
    return NULL;
  }
  map->map_length = len;
  map->use_small_entries = do_not_copy_keys;
  return map;
}


/**
 * Destroy a hash map.  Will not free any values
 * stored in the hash map!
 *
 * @param map the map
 */
void
GNUNET_CONTAINER_multishortmap_destroy (
  struct GNUNET_CONTAINER_MultiShortmap *map)
{
  GNUNET_assert (0 == map->next_cache_off);
  for (unsigned int i = 0; i < map->map_length; i++)
  {
    union MapEntry me;

    me = map->map[i];
    if (map->use_small_entries)
    {
      struct SmallMapEntry *sme;
      struct SmallMapEntry *nxt;

      nxt = me.sme;
      while (NULL != (sme = nxt))
      {
        nxt = sme->next;
        GNUNET_free (sme);
      }
      me.sme = NULL;
    }
    else
    {
      struct BigMapEntry *bme;
      struct BigMapEntry *nxt;

      nxt = me.bme;
      while (NULL != (bme = nxt))
      {
        nxt = bme->next;
        GNUNET_free (bme);
      }
      me.bme = NULL;
    }
  }
  GNUNET_free (map->map);
  GNUNET_free (map);
}


/**
 * Compute the index of the bucket for the given key.
 *
 * @param map hash map for which to compute the index
 * @param key what key should the index be computed for
 * @return offset into the "map" array of "map"
 */
static unsigned int
idx_of (const struct GNUNET_CONTAINER_MultiShortmap *map,
        const struct GNUNET_ShortHashCode *key)
{
  unsigned int kx;

  GNUNET_assert (NULL != map);
  GNUNET_memcpy (&kx, key, sizeof (kx));
  return kx % map->map_length;
}


/**
 * Get the number of key-value pairs in the map.
 *
 * @param map the map
 * @return the number of key value pairs
 */
unsigned int
GNUNET_CONTAINER_multishortmap_size (
  const struct GNUNET_CONTAINER_MultiShortmap *map)
{
  return map->size;
}


/**
 * Given a key find a value in the map matching the key.
 *
 * @param map the map
 * @param key what to look for
 * @return NULL if no value was found; note that
 *   this is indistinguishable from values that just
 *   happen to be NULL; use "contains" to test for
 *   key-value pairs with value NULL
 */
void *
GNUNET_CONTAINER_multishortmap_get (
  const struct GNUNET_CONTAINER_MultiShortmap *map,
  const struct GNUNET_ShortHashCode *key)
{
  union MapEntry me;

  me = map->map[idx_of (map, key)];
  if (map->use_small_entries)
  {
    for (struct SmallMapEntry *sme = me.sme; NULL != sme; sme = sme->next)
      if (0 == GNUNET_memcmp (key, sme->key))
        return sme->value;
  }
  else
  {
    for (struct BigMapEntry *bme = me.bme; NULL != bme; bme = bme->next)
      if (0 == GNUNET_memcmp (key, &bme->key))
        return bme->value;
  }
  return NULL;
}


/**
 * Iterate over all entries in the map.
 *
 * @param map the map
 * @param it function to call on each entry
 * @param it_cls extra argument to @a it
 * @return the number of key value pairs processed,
 *         #GNUNET_SYSERR if it aborted iteration
 */
int
GNUNET_CONTAINER_multishortmap_iterate (
  struct GNUNET_CONTAINER_MultiShortmap *map,
  GNUNET_CONTAINER_ShortmapIterator it,
  void *it_cls)
{
  int count;
  union MapEntry me;
  union MapEntry *ce;
  struct GNUNET_ShortHashCode kc;

  count = 0;
  GNUNET_assert (NULL != map);
  ce = &map->next_cache[map->next_cache_off];
  GNUNET_assert (++map->next_cache_off < NEXT_CACHE_SIZE);
  for (unsigned int i = 0; i < map->map_length; i++)
  {
    me = map->map[i];
    if (map->use_small_entries)
    {
      struct SmallMapEntry *sme;

      ce->sme = me.sme;
      while (NULL != (sme = ce->sme))
      {
        ce->sme = sme->next;
        if ((NULL != it) && (GNUNET_OK != it (it_cls, sme->key, sme->value)))
        {
          GNUNET_assert (--map->next_cache_off < NEXT_CACHE_SIZE);
          return GNUNET_SYSERR;
        }
        count++;
      }
    }
    else
    {
      struct BigMapEntry *bme;

      ce->bme = me.bme;
      while (NULL != (bme = ce->bme))
      {
        ce->bme = bme->next;
        if (NULL != it)
        {
          kc = bme->key;
          if (GNUNET_OK != it (it_cls, &kc, bme->value))
          {
            GNUNET_assert (--map->next_cache_off < NEXT_CACHE_SIZE);
            return GNUNET_SYSERR;
          }
        }
        count++;
      }
    }
  }
  GNUNET_assert (--map->next_cache_off < NEXT_CACHE_SIZE);
  return count;
}


/**
 * We are about to free() the @a bme, make sure it is not in
 * the list of next values for any iterator in the @a map's next_cache.
 *
 * @param map the map to check
 * @param bme the entry that is about to be free'd
 */
static void
update_next_cache_bme (struct GNUNET_CONTAINER_MultiShortmap *map,
                       const struct BigMapEntry *bme)
{
  for (unsigned int i = 0; i < map->next_cache_off; i++)
    if (map->next_cache[i].bme == bme)
      map->next_cache[i].bme = bme->next;
}


/**
 * We are about to free() the @a sme, make sure it is not in
 * the list of next values for any iterator in the @a map's next_cache.
 *
 * @param map the map to check
 * @param sme the entry that is about to be free'd
 */
static void
update_next_cache_sme (struct GNUNET_CONTAINER_MultiShortmap *map,
                       const struct SmallMapEntry *sme)
{
  for (unsigned int i = 0; i < map->next_cache_off; i++)
    if (map->next_cache[i].sme == sme)
      map->next_cache[i].sme = sme->next;
}


/**
 * Remove the given key-value pair from the map.  Note that if the
 * key-value pair is in the map multiple times, only one of the pairs
 * will be removed.
 *
 * @param map the map
 * @param key key of the key-value pair
 * @param value value of the key-value pair
 * @return #GNUNET_YES on success, #GNUNET_NO if the key-value pair
 *  is not in the map
 */
int
GNUNET_CONTAINER_multishortmap_remove (
  struct GNUNET_CONTAINER_MultiShortmap *map,
  const struct GNUNET_ShortHashCode *key,
  const void *value)
{
  union MapEntry me;
  unsigned int i;

  map->modification_counter++;
  i = idx_of (map, key);
  me = map->map[i];
  if (map->use_small_entries)
  {
    struct SmallMapEntry *p = NULL;

    for (struct SmallMapEntry *sme = me.sme; NULL != sme; sme = sme->next)
    {
      if ((0 == GNUNET_memcmp (key, sme->key)) && (value == sme->value))
      {
        if (NULL == p)
          map->map[i].sme = sme->next;
        else
          p->next = sme->next;
        update_next_cache_sme (map, sme);
        GNUNET_free (sme);
        map->size--;
        return GNUNET_YES;
      }
      p = sme;
    }
  }
  else
  {
    struct BigMapEntry *p = NULL;

    for (struct BigMapEntry *bme = me.bme; NULL != bme; bme = bme->next)
    {
      if ((0 == GNUNET_memcmp (key, &bme->key)) && (value == bme->value))
      {
        if (NULL == p)
          map->map[i].bme = bme->next;
        else
          p->next = bme->next;
        update_next_cache_bme (map, bme);
        GNUNET_free (bme);
        map->size--;
        return GNUNET_YES;
      }
      p = bme;
    }
  }
  return GNUNET_NO;
}


/**
 * Remove all entries for the given key from the map.
 * Note that the values would not be "freed".
 *
 * @param map the map
 * @param key identifies values to be removed
 * @return number of values removed
 */
int
GNUNET_CONTAINER_multishortmap_remove_all (
  struct GNUNET_CONTAINER_MultiShortmap *map,
  const struct GNUNET_ShortHashCode *key)
{
  union MapEntry me;
  unsigned int i;
  int ret;

  map->modification_counter++;

  ret = 0;
  i = idx_of (map, key);
  me = map->map[i];
  if (map->use_small_entries)
  {
    struct SmallMapEntry *sme;
    struct SmallMapEntry *p;

    p = NULL;
    sme = me.sme;
    while (NULL != sme)
    {
      if (0 == GNUNET_memcmp (key, sme->key))
      {
        if (NULL == p)
          map->map[i].sme = sme->next;
        else
          p->next = sme->next;
        update_next_cache_sme (map, sme);
        GNUNET_free (sme);
        map->size--;
        if (NULL == p)
          sme = map->map[i].sme;
        else
          sme = p->next;
        ret++;
      }
      else
      {
        p = sme;
        sme = sme->next;
      }
    }
  }
  else
  {
    struct BigMapEntry *bme;
    struct BigMapEntry *p;

    p = NULL;
    bme = me.bme;
    while (NULL != bme)
    {
      if (0 == GNUNET_memcmp (key, &bme->key))
      {
        if (NULL == p)
          map->map[i].bme = bme->next;
        else
          p->next = bme->next;
        update_next_cache_bme (map, bme);
        GNUNET_free (bme);
        map->size--;
        if (NULL == p)
          bme = map->map[i].bme;
        else
          bme = p->next;
        ret++;
      }
      else
      {
        p = bme;
        bme = bme->next;
      }
    }
  }
  return ret;
}


/**
 * Check if the map contains any value under the given
 * key (including values that are NULL).
 *
 * @param map the map
 * @param key the key to test if a value exists for it
 * @return #GNUNET_YES if such a value exists,
 *         #GNUNET_NO if not
 */
int
GNUNET_CONTAINER_multishortmap_contains (
  const struct GNUNET_CONTAINER_MultiShortmap *map,
  const struct GNUNET_ShortHashCode *key)
{
  union MapEntry me;

  me = map->map[idx_of (map, key)];
  if (map->use_small_entries)
  {
    for (struct SmallMapEntry *sme = me.sme; NULL != sme; sme = sme->next)
      if (0 == GNUNET_memcmp (key, sme->key))
        return GNUNET_YES;
  }
  else
  {
    for (struct BigMapEntry *bme = me.bme; NULL != bme; bme = bme->next)
      if (0 == GNUNET_memcmp (key, &bme->key))
        return GNUNET_YES;
  }
  return GNUNET_NO;
}


/**
 * Check if the map contains the given value under the given
 * key.
 *
 * @param map the map
 * @param key the key to test if a value exists for it
 * @param value value to test for
 * @return #GNUNET_YES if such a value exists,
 *         #GNUNET_NO if not
 */
int
GNUNET_CONTAINER_multishortmap_contains_value (
  const struct GNUNET_CONTAINER_MultiShortmap *map,
  const struct GNUNET_ShortHashCode *key,
  const void *value)
{
  union MapEntry me;

  me = map->map[idx_of (map, key)];
  if (map->use_small_entries)
  {
    for (struct SmallMapEntry *sme = me.sme; NULL != sme; sme = sme->next)
      if ((0 == GNUNET_memcmp (key, sme->key)) && (sme->value == value))
        return GNUNET_YES;
  }
  else
  {
    for (struct BigMapEntry *bme = me.bme; NULL != bme; bme = bme->next)
      if ((0 == GNUNET_memcmp (key, &bme->key)) && (bme->value == value))
        return GNUNET_YES;
  }
  return GNUNET_NO;
}


/**
 * Grow the given map to a more appropriate size.
 *
 * @param map the hash map to grow
 */
static void
grow (struct GNUNET_CONTAINER_MultiShortmap *map)
{
  union MapEntry *old_map;
  union MapEntry *new_map;
  unsigned int old_len;
  unsigned int new_len;
  unsigned int idx;

  old_map = map->map;
  old_len = map->map_length;
  new_len = old_len * 2;
  if (0 == new_len) /* 2^31 * 2 == 0 */
    new_len = old_len; /* never use 0 */
  if (new_len == old_len)
    return; /* nothing changed */
  new_map = GNUNET_malloc_large (new_len * sizeof (union MapEntry));
  if (NULL == new_map)
    return; /* grow not possible */
  map->modification_counter++;
  map->map_length = new_len;
  map->map = new_map;
  for (unsigned int i = 0; i < old_len; i++)
  {
    if (map->use_small_entries)
    {
      struct SmallMapEntry *sme;

      while (NULL != (sme = old_map[i].sme))
      {
        old_map[i].sme = sme->next;
        idx = idx_of (map, sme->key);
        sme->next = new_map[idx].sme;
        new_map[idx].sme = sme;
      }
    }
    else
    {
      struct BigMapEntry *bme;

      while (NULL != (bme = old_map[i].bme))
      {
        old_map[i].bme = bme->next;
        idx = idx_of (map, &bme->key);
        bme->next = new_map[idx].bme;
        new_map[idx].bme = bme;
      }
    }
  }
  GNUNET_free (old_map);
}


/**
 * Store a key-value pair in the map.
 *
 * @param map the map
 * @param key key to use
 * @param value value to use
 * @param opt options for put
 * @return #GNUNET_OK on success,
 *         #GNUNET_NO if a value was replaced (with REPLACE)
 *         #GNUNET_SYSERR if #GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY was the option and the
 *                       value already exists
 */
int
GNUNET_CONTAINER_multishortmap_put (
  struct GNUNET_CONTAINER_MultiShortmap *map,
  const struct GNUNET_ShortHashCode *key,
  void *value,
  enum GNUNET_CONTAINER_MultiHashMapOption opt)
{
  union MapEntry me;
  unsigned int i;

  i = idx_of (map, key);
  if ((opt != GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE) &&
      (opt != GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    me = map->map[i];
    if (map->use_small_entries)
    {
      for (struct SmallMapEntry *sme = me.sme; NULL != sme; sme = sme->next)
        if (0 == GNUNET_memcmp (key, sme->key))
        {
          if (opt == GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY)
            return GNUNET_SYSERR;
          sme->value = value;
          return GNUNET_NO;
        }
    }
    else
    {
      for (struct BigMapEntry *bme = me.bme; NULL != bme; bme = bme->next)
        if (0 == GNUNET_memcmp (key, &bme->key))
        {
          if (opt == GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY)
            return GNUNET_SYSERR;
          bme->value = value;
          return GNUNET_NO;
        }
    }
  }
  if (map->size / 3 >= map->map_length / 4)
  {
    grow (map);
    i = idx_of (map, key);
  }
  if (map->use_small_entries)
  {
    struct SmallMapEntry *sme;

    sme = GNUNET_new (struct SmallMapEntry);
    sme->key = key;
    sme->value = value;
    sme->next = map->map[i].sme;
    map->map[i].sme = sme;
  }
  else
  {
    struct BigMapEntry *bme;

    bme = GNUNET_new (struct BigMapEntry);
    bme->key = *key;
    bme->value = value;
    bme->next = map->map[i].bme;
    map->map[i].bme = bme;
  }
  map->size++;
  return GNUNET_OK;
}


/**
 * Iterate over all entries in the map that match a particular key.
 *
 * @param map the map
 * @param key key that the entries must correspond to
 * @param it function to call on each entry
 * @param it_cls extra argument to @a it
 * @return the number of key value pairs processed,
 *         #GNUNET_SYSERR if it aborted iteration
 */
int
GNUNET_CONTAINER_multishortmap_get_multiple (
  struct GNUNET_CONTAINER_MultiShortmap *map,
  const struct GNUNET_ShortHashCode *key,
  GNUNET_CONTAINER_ShortmapIterator it,
  void *it_cls)
{
  int count;
  union MapEntry me;
  union MapEntry *ce;

  ce = &map->next_cache[map->next_cache_off];
  GNUNET_assert (++map->next_cache_off < NEXT_CACHE_SIZE);
  count = 0;
  me = map->map[idx_of (map, key)];
  if (map->use_small_entries)
  {
    struct SmallMapEntry *sme;

    ce->sme = me.sme;
    while (NULL != (sme = ce->sme))
    {
      ce->sme = sme->next;
      if (0 != GNUNET_memcmp (key, sme->key))
        continue;
      if ((NULL != it) && (GNUNET_OK != it (it_cls, key, sme->value)))
      {
        GNUNET_assert (--map->next_cache_off < NEXT_CACHE_SIZE);
        return GNUNET_SYSERR;
      }
      count++;
    }
  }
  else
  {
    struct BigMapEntry *bme;

    ce->bme = me.bme;
    while (NULL != (bme = ce->bme))
    {
      ce->bme = bme->next;
      if (0 != GNUNET_memcmp (key, &bme->key))
        continue;
      if ((NULL != it) && (GNUNET_OK != it (it_cls, key, bme->value)))
      {
        GNUNET_assert (--map->next_cache_off < NEXT_CACHE_SIZE);
        return GNUNET_SYSERR;
      }
      count++;
    }
  }
  GNUNET_assert (--map->next_cache_off < NEXT_CACHE_SIZE);
  return count;
}


/**
 * @ingroup hashmap
 * Call @a it on a random value from the map, or not at all
 * if the map is empty.  Note that this function has linear
 * complexity (in the size of the map).
 *
 * @param map the map
 * @param it function to call on a random entry
 * @param it_cls extra argument to @a it
 * @return the number of key value pairs processed, zero or one.
 */
unsigned int
GNUNET_CONTAINER_multishortmap_get_random (
  const struct GNUNET_CONTAINER_MultiShortmap *map,
  GNUNET_CONTAINER_ShortmapIterator it,
  void *it_cls)
{
  unsigned int off;
  union MapEntry me;

  if (0 == map->size)
    return 0;
  if (NULL == it)
    return 1;
  off = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE, map->size);
  for (unsigned int idx = 0; idx < map->map_length; idx++)
  {
    me = map->map[idx];
    if (map->use_small_entries)
    {
      for (struct SmallMapEntry *sme = me.sme; NULL != sme; sme = sme->next)
      {
        if (0 == off)
        {
          if (GNUNET_OK != it (it_cls, sme->key, sme->value))
            return GNUNET_SYSERR;
          return 1;
        }
        off--;
      }
    }
    else
    {
      for (struct BigMapEntry *bme = me.bme; NULL != bme; bme = bme->next)
      {
        if (0 == off)
        {
          if (GNUNET_OK != it (it_cls, &bme->key, bme->value))
            return GNUNET_SYSERR;
          return 1;
        }
        off--;
      }
    }
  }
  GNUNET_break (0);
  return GNUNET_SYSERR;
}


/**
 * Create an iterator for a multishortmap.
 * The iterator can be used to retrieve all the elements in the multishortmap
 * one by one, without having to handle all elements at once (in contrast to
 * #GNUNET_CONTAINER_multishortmap_iterate).  Note that the iterator can not be
 * used anymore if elements have been removed from 'map' after the creation of
 * the iterator, or 'map' has been destroyed.  Adding elements to 'map' may
 * result in skipped or repeated elements.
 *
 * @param map the map to create an iterator for
 * @return an iterator over the given multishortmap 'map'
 */
struct GNUNET_CONTAINER_MultiShortmapIterator *
GNUNET_CONTAINER_multishortmap_iterator_create (
  const struct GNUNET_CONTAINER_MultiShortmap *map)
{
  struct GNUNET_CONTAINER_MultiShortmapIterator *iter;

  iter = GNUNET_new (struct GNUNET_CONTAINER_MultiShortmapIterator);
  iter->map = map;
  iter->modification_counter = map->modification_counter;
  iter->me = map->map[0];
  return iter;
}


/**
 * Retrieve the next element from the hash map at the iterator's position.
 * If there are no elements left, GNUNET_NO is returned, and 'key' and 'value'
 * are not modified.
 * This operation is only allowed if no elements have been removed from the
 * multishortmap since the creation of 'iter', and the map has not been destroyed.
 * Adding elements may result in repeating or skipping elements.
 *
 * @param iter the iterator to get the next element from
 * @param key pointer to store the key in, can be NULL
 * @param value pointer to store the value in, can be NULL
 * @return #GNUNET_YES we returned an element,
 *         #GNUNET_NO if we are out of elements
 */
int
GNUNET_CONTAINER_multishortmap_iterator_next (
  struct GNUNET_CONTAINER_MultiShortmapIterator *iter,
  struct GNUNET_ShortHashCode *key,
  const void **value)
{
  /* make sure the map has not been modified */
  GNUNET_assert (iter->modification_counter == iter->map->modification_counter);

  /* look for the next entry, skipping empty buckets */
  while (1)
  {
    if (iter->idx >= iter->map->map_length)
      return GNUNET_NO;
    if (GNUNET_YES == iter->map->use_small_entries)
    {
      if (NULL != iter->me.sme)
      {
        if (NULL != key)
          *key = *iter->me.sme->key;
        if (NULL != value)
          *value = iter->me.sme->value;
        iter->me.sme = iter->me.sme->next;
        return GNUNET_YES;
      }
    }
    else
    {
      if (NULL != iter->me.bme)
      {
        if (NULL != key)
          *key = iter->me.bme->key;
        if (NULL != value)
          *value = iter->me.bme->value;
        iter->me.bme = iter->me.bme->next;
        return GNUNET_YES;
      }
    }
    iter->idx += 1;
    if (iter->idx < iter->map->map_length)
      iter->me = iter->map->map[iter->idx];
  }
}


/**
 * Destroy a multishortmap iterator.
 *
 * @param iter the iterator to destroy
 */
void
GNUNET_CONTAINER_multishortmap_iterator_destroy (
  struct GNUNET_CONTAINER_MultiShortmapIterator *iter)
{
  GNUNET_free (iter);
}


/* end of container_multishortmap.c */
