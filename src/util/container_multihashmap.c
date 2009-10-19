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

/**
 *
 */
struct MapEntry
{
  GNUNET_HashCode key;
  void *value;
  struct MapEntry *next;
};

/**
 *
 */
struct GNUNET_CONTAINER_MultiHashMap
{

  struct MapEntry **map;

  unsigned int size;

  unsigned int map_length;
};


struct GNUNET_CONTAINER_MultiHashMap *
GNUNET_CONTAINER_multihashmap_create (unsigned int len)
{
  struct GNUNET_CONTAINER_MultiHashMap *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_CONTAINER_MultiHashMap));
  ret->size = 0;
  ret->map = GNUNET_malloc (len * sizeof (struct MapEntry *));
  memset (ret->map, 0, len * sizeof (struct MapEntry *));
  ret->map_length = len;
  return ret;
}


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

static unsigned int
idx_of (const struct GNUNET_CONTAINER_MultiHashMap *m,
        const GNUNET_HashCode * key)
{
  return (*(unsigned int *) key) % m->map_length;
}


unsigned int
GNUNET_CONTAINER_multihashmap_size (const struct GNUNET_CONTAINER_MultiHashMap
                                    *map)
{
  return map->size;
}


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


int
GNUNET_CONTAINER_multihashmap_iterate (const struct
                                       GNUNET_CONTAINER_MultiHashMap *map,
                                       GNUNET_CONTAINER_HashMapIterator it,
                                       void *cls)
{
  int count;
  unsigned int i;
  struct MapEntry *e;

  count = 0;
  for (i = 0; i < map->map_length; i++)
    {
      e = map->map[i];
      while (e != NULL)
        {
          if ((NULL != it) && (GNUNET_OK != it (cls, &e->key, e->value)))
            return GNUNET_SYSERR;
          count++;
          e = e->next;
        }
    }
  return count;
}


int
GNUNET_CONTAINER_multihashmap_remove (struct GNUNET_CONTAINER_MultiHashMap
                                      *map, const GNUNET_HashCode * key,
                                      void *value)
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


int
GNUNET_CONTAINER_multihashmap_contains (const struct
                                        GNUNET_CONTAINER_MultiHashMap *map,
                                        const GNUNET_HashCode * key)
{
  struct MapEntry *e;
  unsigned int i;

  i = idx_of (map, key);
  e = map->map[i];
  while (e != NULL)
    {
      if (0 == memcmp (key, &e->key, sizeof (GNUNET_HashCode)))
        return GNUNET_YES;
      e = e->next;
    }
  return GNUNET_NO;
}


static void
grow (struct GNUNET_CONTAINER_MultiHashMap *map)
{
  struct MapEntry **old;
  struct MapEntry *e;
  unsigned int i;
  unsigned int l;

  old = map->map;
  l = map->map_length;
  map->map_length *= 2;
  map->map = GNUNET_malloc (sizeof (struct MapEntry *) * map->map_length);
  memset (map->map, 0, sizeof (struct MapEntry *) * map->map_length);
  for (i = 0; i < l; i++)
    {
      while (NULL != (e = old[i]))
        {
          old[i] = e->next;
          e->next = map->map[idx_of (map, &e->key)];
          map->map[idx_of (map, &e->key)] = e;
        }
    }
  GNUNET_free (old);
}


int
GNUNET_CONTAINER_multihashmap_put (struct GNUNET_CONTAINER_MultiHashMap *map,
                                   const GNUNET_HashCode * key,
                                   void *value,
                                   enum GNUNET_CONTAINER_MultiHashMapOption
                                   opt)
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
          if ((0 == memcmp (key, &e->key, sizeof (GNUNET_HashCode))) &&
              (value == e->value))
            {
              if (opt == GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY)
                return GNUNET_SYSERR;
              e->value = value;
              return GNUNET_NO;
            }
          e = e->next;
        }
    }
  if (map->size / 3 > map->map_length / 4)
    grow (map);
  e = GNUNET_malloc (sizeof (struct MapEntry));
  e->key = *key;
  e->value = value;
  e->next = map->map[i];
  map->map[i] = e;
  map->size++;
  return GNUNET_OK;
}


int
GNUNET_CONTAINER_multihashmap_get_multiple (const struct
                                            GNUNET_CONTAINER_MultiHashMap
                                            *map, const GNUNET_HashCode * key,
                                            GNUNET_CONTAINER_HashMapIterator
                                            it, void *cls)
{
  int count;
  struct MapEntry *e;

  count = 0;
  e = map->map[idx_of (map, key)];
  while (e != NULL)
    {
      if (0 == memcmp (key, &e->key, sizeof (GNUNET_HashCode)))
        {
          if ((it != NULL) && (GNUNET_OK != it (&e->key, e->value, cls)))
            return GNUNET_SYSERR;
          count++;
        }
      e = e->next;
    }
  return count;
}


void *
GNUNET_CONTAINER_multihashmap_get_random (const struct
                                          GNUNET_CONTAINER_MultiHashMap *map)
{
  unsigned int rand;
  struct MapEntry *e;
  e = NULL;

  if (map->size == 0)
    return NULL;

  while (e == NULL)
    {
      rand =
        GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                  map->map_length);
      e = map->map[rand];
    }

  return e->value;
}

/* end of container_multihashmap.c */
