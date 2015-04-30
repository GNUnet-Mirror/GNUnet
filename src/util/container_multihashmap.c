/*
     This file is part of GNUnet.
     Copyright (C) 2008, 2012 Christian Grothoff (and other contributing authors)

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
 * @file util/container_multihashmap.c
 * @brief hash map where the same key may be present multiple times
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_util_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

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
  struct GNUNET_HashCode key;

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
  const struct GNUNET_HashCode *key;

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
struct GNUNET_CONTAINER_MultiHashMap
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
};


/**
 * Cursor into a multihashmap.
 * Allows to enumerate elements asynchronously.
 */
struct GNUNET_CONTAINER_MultiHashMapIterator
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
  const struct GNUNET_CONTAINER_MultiHashMap *map;
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
struct GNUNET_CONTAINER_MultiHashMap *
GNUNET_CONTAINER_multihashmap_create (unsigned int len,
				      int do_not_copy_keys)
{
  struct GNUNET_CONTAINER_MultiHashMap *map;

  GNUNET_assert (len > 0);
  map = GNUNET_new (struct GNUNET_CONTAINER_MultiHashMap);
  map->map = GNUNET_malloc (len * sizeof (union MapEntry));
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
GNUNET_CONTAINER_multihashmap_destroy (struct GNUNET_CONTAINER_MultiHashMap
                                       *map)
{
  unsigned int i;
  union MapEntry me;

  for (i = 0; i < map->map_length; i++)
  {
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
idx_of (const struct GNUNET_CONTAINER_MultiHashMap *map,
        const struct GNUNET_HashCode *key)
{
  GNUNET_assert (map != NULL);
  return (*(unsigned int *) key) % map->map_length;
}


/**
 * Get the number of key-value pairs in the map.
 *
 * @param map the map
 * @return the number of key value pairs
 */
unsigned int
GNUNET_CONTAINER_multihashmap_size (const struct GNUNET_CONTAINER_MultiHashMap
                                    *map)
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
GNUNET_CONTAINER_multihashmap_get (const struct GNUNET_CONTAINER_MultiHashMap *map,
                                   const struct GNUNET_HashCode *key)
{
  union MapEntry me;

  me = map->map[idx_of (map, key)];
  if (map->use_small_entries)
  {
    struct SmallMapEntry *sme;

    for (sme = me.sme; NULL != sme; sme = sme->next)
      if (0 == memcmp (key, sme->key, sizeof (struct GNUNET_HashCode)))
	return sme->value;
  }
  else
  {
    struct BigMapEntry *bme;

    for (bme = me.bme; NULL != bme; bme = bme->next)
      if (0 == memcmp (key, &bme->key, sizeof (struct GNUNET_HashCode)))
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
GNUNET_CONTAINER_multihashmap_iterate (const struct
                                       GNUNET_CONTAINER_MultiHashMap *map,
                                       GNUNET_CONTAINER_HashMapIterator it,
                                       void *it_cls)
{
  int count;
  unsigned int i;
  union MapEntry me;
  struct GNUNET_HashCode kc;

  count = 0;
  GNUNET_assert (NULL != map);
  for (i = 0; i < map->map_length; i++)
  {
    me = map->map[i];
    if (map->use_small_entries)
    {
      struct SmallMapEntry *sme;
      struct SmallMapEntry *nxt;

      nxt = me.sme;
      while (NULL != (sme = nxt))
      {
	nxt = sme->next;
	if (NULL != it)
	{
	  if (GNUNET_OK != it (it_cls, sme->key, sme->value))
	    return GNUNET_SYSERR;
	}
	count++;
      }
    }
    else
    {
      struct BigMapEntry *bme;
      struct BigMapEntry *nxt;

      nxt = me.bme;
      while (NULL != (bme = nxt))
      {
	nxt = bme->next;
	if (NULL != it)
	{
	  kc = bme->key;
	  if (GNUNET_OK != it (it_cls, &kc, bme->value))
	    return GNUNET_SYSERR;
	}
	count++;
      }
    }
  }
  return count;
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
GNUNET_CONTAINER_multihashmap_remove (struct GNUNET_CONTAINER_MultiHashMap *map,
                                      const struct GNUNET_HashCode *key,
				      const void *value)
{
  union MapEntry me;
  unsigned int i;

  map->modification_counter++;

  i = idx_of (map, key);
  me = map->map[i];
  if (map->use_small_entries)
  {
    struct SmallMapEntry *sme;
    struct SmallMapEntry *p;

    p = NULL;
    for (sme = me.sme; NULL != sme; sme = sme->next)
    {
      if ((0 == memcmp (key, sme->key, sizeof (struct GNUNET_HashCode))) &&
	  (value == sme->value))
      {
	if (NULL == p)
	  map->map[i].sme = sme->next;
	else
	  p->next = sme->next;
	GNUNET_free (sme);
	map->size--;
	return GNUNET_YES;
      }
      p = sme;
    }
  }
  else
  {
    struct BigMapEntry *bme;
    struct BigMapEntry *p;

    p = NULL;
    for (bme = me.bme; NULL != bme; bme = bme->next)
    {
      if ((0 == memcmp (key, &bme->key, sizeof (struct GNUNET_HashCode))) &&
	  (value == bme->value))
      {
	if (NULL == p)
	  map->map[i].bme = bme->next;
	else
	  p->next = bme->next;
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
GNUNET_CONTAINER_multihashmap_remove_all (struct GNUNET_CONTAINER_MultiHashMap *map,
                                          const struct GNUNET_HashCode *key)
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
      if (0 == memcmp (key, sme->key, sizeof (struct GNUNET_HashCode)))
      {
	if (NULL == p)
	  map->map[i].sme = sme->next;
	else
	  p->next = sme->next;
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
      if (0 == memcmp (key, &bme->key, sizeof (struct GNUNET_HashCode)))
      {
	if (NULL == p)
	  map->map[i].bme = bme->next;
	else
	  p->next = bme->next;
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
 * Callback used to remove all entries from the map.
 *
 * @param cls the `struct GNUNET_CONTAINER_MultiHashMap`
 * @param key the key
 * @param value the value
 * @return #GNUNET_OK (continue to iterate)
 */
static int
remove_all (void *cls,
            const struct GNUNET_HashCode *key,
            void *value)
{
  struct GNUNET_CONTAINER_MultiHashMap *map = cls;

  GNUNET_CONTAINER_multihashmap_remove (map,
                                        key,
                                        value);
  return GNUNET_OK;
}


/**
 * @ingroup hashmap
 * Remove all entries from the map.
 * Note that the values would not be "freed".
 *
 * @param map the map
 * @return number of values removed
 */
unsigned int
GNUNET_CONTAINER_multihashmap_clear (struct GNUNET_CONTAINER_MultiHashMap *map)
{
  unsigned int ret;

  ret = map->size;
  GNUNET_CONTAINER_multihashmap_iterate (map,
                                         &remove_all,
                                         map);
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
GNUNET_CONTAINER_multihashmap_contains (const struct
                                        GNUNET_CONTAINER_MultiHashMap *map,
                                        const struct GNUNET_HashCode *key)
{
  union MapEntry me;

  me = map->map[idx_of (map, key)];
  if (map->use_small_entries)
  {
    struct SmallMapEntry *sme;

    for (sme = me.sme; NULL != sme; sme = sme->next)
      if (0 == memcmp (key, sme->key, sizeof (struct GNUNET_HashCode)))
	return GNUNET_YES;
  }
  else
  {
    struct BigMapEntry *bme;

    for (bme = me.bme; NULL != bme; bme = bme->next)
      if (0 == memcmp (key, &bme->key, sizeof (struct GNUNET_HashCode)))
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
GNUNET_CONTAINER_multihashmap_contains_value (const struct
                                              GNUNET_CONTAINER_MultiHashMap
                                              *map, const struct GNUNET_HashCode *key,
                                              const void *value)
{
  union MapEntry me;

  me = map->map[idx_of (map, key)];
  if (map->use_small_entries)
  {
    struct SmallMapEntry *sme;

    for (sme = me.sme; NULL != sme; sme = sme->next)
      if ( (0 == memcmp (key, sme->key, sizeof (struct GNUNET_HashCode))) &&
	   (sme->value == value) )
	return GNUNET_YES;
  }
  else
  {
    struct BigMapEntry *bme;

    for (bme = me.bme; NULL != bme; bme = bme->next)
      if ( (0 == memcmp (key, &bme->key, sizeof (struct GNUNET_HashCode))) &&
	   (bme->value == value) )
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
grow (struct GNUNET_CONTAINER_MultiHashMap *map)
{
  union MapEntry *old_map;
  union MapEntry *new_map;
  unsigned int old_len;
  unsigned int new_len;
  unsigned int idx;
  unsigned int i;

  map->modification_counter++;

  old_map = map->map;
  old_len = map->map_length;
  new_len = old_len * 2;
  new_map = GNUNET_malloc (sizeof (union MapEntry) * new_len);
  map->map_length = new_len;
  map->map = new_map;
  for (i = 0; i < old_len; i++)
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
 *         #GNUNET_SYSERR if UNIQUE_ONLY was the option and the
 *                       value already exists
 */
int
GNUNET_CONTAINER_multihashmap_put (struct GNUNET_CONTAINER_MultiHashMap *map,
                                   const struct GNUNET_HashCode *key,
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
      struct SmallMapEntry *sme;

      for (sme = me.sme; NULL != sme; sme = sme->next)
	if (0 == memcmp (key, sme->key, sizeof (struct GNUNET_HashCode)))
	{
	  if (opt == GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY)
	    return GNUNET_SYSERR;
	  sme->value = value;
	  return GNUNET_NO;
	}
    }
    else
    {
      struct BigMapEntry *bme;

      for (bme = me.bme; NULL != bme; bme = bme->next)
	if (0 == memcmp (key, &bme->key, sizeof (struct GNUNET_HashCode)))
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
 * @param it_cls extra argument to it
 * @return the number of key value pairs processed,
 *         #GNUNET_SYSERR if it aborted iteration
 */
int
GNUNET_CONTAINER_multihashmap_get_multiple (const struct
                                            GNUNET_CONTAINER_MultiHashMap *map,
                                            const struct GNUNET_HashCode *key,
                                            GNUNET_CONTAINER_HashMapIterator it,
                                            void *it_cls)
{
  int count;
  union MapEntry me;

  count = 0;
  me = map->map[idx_of (map, key)];
  if (map->use_small_entries)
  {
    struct SmallMapEntry *sme;
    struct SmallMapEntry *nxt;

    nxt = me.sme;
    while (NULL != (sme = nxt))
    {
      nxt = sme->next;
      if (0 != memcmp (key, sme->key, sizeof (struct GNUNET_HashCode)))
	continue;
      if ((it != NULL) && (GNUNET_OK != it (it_cls, key, sme->value)))
	return GNUNET_SYSERR;
      count++;
    }
  }
  else
  {
    struct BigMapEntry *bme;
    struct BigMapEntry *nxt;

    nxt = me.bme;
    while (NULL != (bme = nxt))
    {
      nxt = bme->next;
      if (0 != memcmp (key, &bme->key, sizeof (struct GNUNET_HashCode)))
	continue;
      if ((it != NULL) && (GNUNET_OK != it (it_cls, key, bme->value)))
	return GNUNET_SYSERR;
      count++;
    }
  }
  return count;
}


/**
 * @ingroup hashmap
 * Call @a it on a random value from the map, or not at all
 * if the map is empty. Note that this function has linear
 * complexity (in the size of the map).
 *
 * @param map the map
 * @param it function to call on a random entry
 * @param it_cls extra argument to @a it
 * @return the number of key value pairs processed, zero or one.
 */
unsigned int
GNUNET_CONTAINER_multihashmap_get_random (const struct GNUNET_CONTAINER_MultiHashMap *map,
                                          GNUNET_CONTAINER_HashMapIterator it,
                                          void *it_cls)
{
  unsigned int off;
  unsigned int idx;
  union MapEntry me;

  if (0 == map->size)
    return 0;
  if (NULL == it)
    return 1;
  off = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                  map->size);
  for (idx = 0; idx < map->map_length; idx++)
  {
    me = map->map[idx];
    if (map->use_small_entries)
    {
      struct SmallMapEntry *sme;
      struct SmallMapEntry *nxt;

      nxt = me.sme;
      while (NULL != (sme = nxt))
      {
        nxt = sme->next;
        if (0 == off)
        {
          if (GNUNET_OK != it (it_cls,
                               sme->key,
                               sme->value))
            return GNUNET_SYSERR;
          return 1;
        }
        off--;
      }
    }
    else
    {
      struct BigMapEntry *bme;
      struct BigMapEntry *nxt;

      nxt = me.bme;
      while (NULL != (bme = nxt))
      {
        nxt = bme->next;
        if (0 == off)
        {
          if (GNUNET_OK != it (it_cls,
                               &bme->key, bme->value))
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
 * Create an iterator for a multihashmap.
 * The iterator can be used to retrieve all the elements in the multihashmap
 * one by one, without having to handle all elements at once (in contrast to
 * GNUNET_CONTAINER_multihashmap_iterate()).  Note that the iterator can not be
 * used anymore if elements have been removed from 'map' after the creation of
 * the iterator, or 'map' has been destroyed.  Adding elements to 'map' may
 * result in skipped or repeated elements.
 *
 * @param map the map to create an iterator for
 * @return an iterator over the given multihashmap 'map'
 */
struct GNUNET_CONTAINER_MultiHashMapIterator *
GNUNET_CONTAINER_multihashmap_iterator_create (const struct GNUNET_CONTAINER_MultiHashMap *map)
{
  struct GNUNET_CONTAINER_MultiHashMapIterator *iter;

  iter = GNUNET_new (struct GNUNET_CONTAINER_MultiHashMapIterator);
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
 * multihashmap since the creation of 'iter', and the map has not been destroyed.
 * Adding elements may result in repeating or skipping elements.
 *
 * @param iter the iterator to get the next element from
 * @param key pointer to store the key in, can be NULL
 * @param value pointer to store the value in, can be NULL
 * @return #GNUNET_YES we returned an element,
 *         #GNUNET_NO if we are out of elements
 */
int
GNUNET_CONTAINER_multihashmap_iterator_next (struct GNUNET_CONTAINER_MultiHashMapIterator *iter,
                                             struct GNUNET_HashCode *key,
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
 * Destroy a multihashmap iterator.
 *
 * @param iter the iterator to destroy
 */
void
GNUNET_CONTAINER_multihashmap_iterator_destroy (struct GNUNET_CONTAINER_MultiHashMapIterator *iter)
{
  GNUNET_free (iter);
}


/* end of container_multihashmap.c */
