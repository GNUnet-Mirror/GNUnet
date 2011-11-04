/*
     This file is part of GNUnet.
     (C) 2008 Christian Grothoff (and other contributing authors)

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
 * @file util/container_multihashmap.c
 * @brief hash map where the same key may be present multiple times
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_common.h"
#include "gnunet_container_lib.h"
#include "gnunet_crypto_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind, "util", __VA_ARGS__)

/**
 * An entry in the hash map.
 */
struct MapEntry
{

  /**
   * Key for the entry.
   */
  GNUNET_HashCode key;

  /**
   * Value of the entry.
   */
  void *value;

  /**
   * If there is a hash collision, we create a linked list.
   */
  struct MapEntry *next;

};

/**
 * Internal representation of the hash map.
 */
struct GNUNET_CONTAINER_MultiHashMap
{

  /**
   * All of our buckets.
   */
  struct MapEntry **map;

  /**
   * Number of entries in the map.
   */
  unsigned int size;

  /**
   * Length of the "map" array.
   */
  unsigned int map_length;
};


/**
 * Create a multi hash map.
 *
 * @param len initial size (map will grow as needed)
 * @return NULL on error
 */
struct GNUNET_CONTAINER_MultiHashMap *
GNUNET_CONTAINER_multihashmap_create (unsigned int len)
{
  struct GNUNET_CONTAINER_MultiHashMap *ret;

  GNUNET_assert (len > 0);
  ret = GNUNET_malloc (sizeof (struct GNUNET_CONTAINER_MultiHashMap));
  ret->map = GNUNET_malloc (len * sizeof (struct MapEntry *));
  ret->map_length = len;
  return ret;
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
  struct MapEntry *e;

  for (i = 0; i < map->map_length; i++)
  {
    while (NULL != (e = map->map[i]))
    {
      map->map[i] = e->next;
      GNUNET_free (e);
    }
  }
  GNUNET_free (map->map);
  GNUNET_free (map);
}


/**
 * Compute the index of the bucket for the given key.
 *
 * @param m hash map for which to compute the index
 * @param key what key should the index be computed for
 * @return offset into the "map" array of "m"
 */
static unsigned int
idx_of (const struct GNUNET_CONTAINER_MultiHashMap *m,
        const GNUNET_HashCode * key)
{
  GNUNET_assert (m != NULL);
  return (*(unsigned int *) key) % m->map_length;
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
GNUNET_CONTAINER_multihashmap_get (const struct GNUNET_CONTAINER_MultiHashMap
                                   *map, const GNUNET_HashCode * key)
{
  struct MapEntry *e;

  e = map->map[idx_of (map, key)];
  while (e != NULL)
  {
    if (0 == memcmp (key, &e->key, sizeof (GNUNET_HashCode)))
      return e->value;
    e = e->next;
  }
  return NULL;
}


/**
 * Iterate over all entries in the map.
 *
 * @param map the map
 * @param it function to call on each entry
 * @param it_cls extra argument to it
 * @return the number of key value pairs processed,
 *         GNUNET_SYSERR if it aborted iteration
 */
int
GNUNET_CONTAINER_multihashmap_iterate (const struct
                                       GNUNET_CONTAINER_MultiHashMap *map,
                                       GNUNET_CONTAINER_HashMapIterator it,
                                       void *it_cls)
{
  int count;
  unsigned int i;
  struct MapEntry *e;
  struct MapEntry *n;
  GNUNET_HashCode kc;

  count = 0;
  GNUNET_assert (map != NULL);
  for (i = 0; i < map->map_length; i++)
  {
    n = map->map[i];
    while (NULL != (e = n))
    {
      n = e->next;
      if (NULL != it)
      {
        kc = e->key;
        if (GNUNET_OK != it (it_cls, &kc, e->value))
          return GNUNET_SYSERR;
      }
      count++;
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
 * @return GNUNET_YES on success, GNUNET_NO if the key-value pair
 *  is not in the map
 */
int
GNUNET_CONTAINER_multihashmap_remove (struct GNUNET_CONTAINER_MultiHashMap *map,
                                      const GNUNET_HashCode * key, void *value)
{
  struct MapEntry *e;
  struct MapEntry *p;
  unsigned int i;

  i = idx_of (map, key);
  p = NULL;
  e = map->map[i];
  while (e != NULL)
  {
    if ((0 == memcmp (key, &e->key, sizeof (GNUNET_HashCode))) &&
        (value == e->value))
    {
      if (p == NULL)
        map->map[i] = e->next;
      else
        p->next = e->next;
      GNUNET_free (e);
      map->size--;
      return GNUNET_YES;
    }
    p = e;
    e = e->next;
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
GNUNET_CONTAINER_multihashmap_remove_all (struct GNUNET_CONTAINER_MultiHashMap
                                          *map, const GNUNET_HashCode * key)
{
  struct MapEntry *e;
  struct MapEntry *p;
  unsigned int i;
  int ret;

  ret = 0;
  i = idx_of (map, key);
  p = NULL;
  e = map->map[i];
  while (e != NULL)
  {
    if (0 == memcmp (key, &e->key, sizeof (GNUNET_HashCode)))
    {
      if (p == NULL)
        map->map[i] = e->next;
      else
        p->next = e->next;
      GNUNET_free (e);
      map->size--;
      if (p == NULL)
        e = map->map[i];
      else
        e = p->next;
      ret++;
    }
    else
    {
      p = e;
      e = e->next;
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
 * @return GNUNET_YES if such a value exists,
 *         GNUNET_NO if not
 */
int
GNUNET_CONTAINER_multihashmap_contains (const struct
                                        GNUNET_CONTAINER_MultiHashMap *map,
                                        const GNUNET_HashCode * key)
{
  struct MapEntry *e;

  e = map->map[idx_of (map, key)];
  while (e != NULL)
  {
    if (0 == memcmp (key, &e->key, sizeof (GNUNET_HashCode)))
      return GNUNET_YES;
    e = e->next;
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
 * @return GNUNET_YES if such a value exists,
 *         GNUNET_NO if not
 */
int
GNUNET_CONTAINER_multihashmap_contains_value (const struct
                                              GNUNET_CONTAINER_MultiHashMap
                                              *map, const GNUNET_HashCode * key,
                                              const void *value)
{
  struct MapEntry *e;

  e = map->map[idx_of (map, key)];
  while (e != NULL)
  {
    if ((0 == memcmp (key, &e->key, sizeof (GNUNET_HashCode))) &&
        (e->value == value))
      return GNUNET_YES;
    e = e->next;
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
  struct MapEntry **old_map;
  struct MapEntry **new_map;
  struct MapEntry *e;
  unsigned int old_len;
  unsigned int new_len;
  unsigned int idx;
  unsigned int i;

  old_map = map->map;
  old_len = map->map_length;
  new_len = old_len * 2;
  new_map = GNUNET_malloc (sizeof (struct MapEntry *) * new_len);
  map->map_length = new_len;
  map->map = new_map;
  for (i = 0; i < old_len; i++)
  {
    while (NULL != (e = old_map[i]))
    {
      old_map[i] = e->next;
      idx = idx_of (map, &e->key);
      e->next = new_map[idx];
      new_map[idx] = e;
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
 * @return GNUNET_OK on success,
 *         GNUNET_NO if a value was replaced (with REPLACE)
 *         GNUNET_SYSERR if UNIQUE_ONLY was the option and the
 *                       value already exists
 */
int
GNUNET_CONTAINER_multihashmap_put (struct GNUNET_CONTAINER_MultiHashMap *map,
                                   const GNUNET_HashCode * key, void *value,
                                   enum GNUNET_CONTAINER_MultiHashMapOption opt)
{
  struct MapEntry *e;
  unsigned int i;

  i = idx_of (map, key);
  if ((opt != GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE) &&
      (opt != GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    e = map->map[i];
    while (e != NULL)
    {
      if (0 == memcmp (key, &e->key, sizeof (GNUNET_HashCode)))
      {
        if (opt == GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY)
          return GNUNET_SYSERR;
        e->value = value;
        return GNUNET_NO;
      }
      e = e->next;
    }
  }
  if (map->size / 3 >= map->map_length / 4)
  {
    grow (map);
    i = idx_of (map, key);
  }
  e = GNUNET_malloc (sizeof (struct MapEntry));
  e->key = *key;
  e->value = value;
  e->next = map->map[i];
  map->map[i] = e;
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
 *         GNUNET_SYSERR if it aborted iteration
 */
int
GNUNET_CONTAINER_multihashmap_get_multiple (const struct
                                            GNUNET_CONTAINER_MultiHashMap *map,
                                            const GNUNET_HashCode * key,
                                            GNUNET_CONTAINER_HashMapIterator it,
                                            void *it_cls)
{
  int count;
  struct MapEntry *e;
  struct MapEntry *n;

  count = 0;
  n = map->map[idx_of (map, key)];
  while (NULL != (e = n))
  {
    n = e->next;
    if (0 != memcmp (key, &e->key, sizeof (GNUNET_HashCode)))
      continue;
    if ((it != NULL) && (GNUNET_OK != it (it_cls, key, e->value)))
      return GNUNET_SYSERR;
    count++;
  }
  return count;
}


/* end of container_multihashmap.c */
