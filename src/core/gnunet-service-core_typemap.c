/*
     This file is part of GNUnet.
     Copyright (C) 2011-2014 Christian Grothoff (and other contributing authors)

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
 * @file core/gnunet-service-core_typemap.c
 * @brief management of map that specifies which message types this peer supports
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_transport_service.h"
#include "gnunet-service-core.h"
#include "gnunet-service-core_sessions.h"
#include "gnunet-service-core_typemap.h"
#include <zlib.h>


/**
 * A type map describing which messages a given neighbour is able
 * to process.
 */
struct GSC_TypeMap
{
  uint32_t bits[(UINT16_MAX + 1) / 32];
};

/**
 * Bitmap of message types this peer is able to handle.
 */
static struct GSC_TypeMap my_type_map;

/**
 * Counters for message types this peer is able to handle.
 */
static uint8_t map_counters[UINT16_MAX + 1];

/**
 * Current hash of our (uncompressed) type map.
 * Lazily computed when needed.
 */
static struct GNUNET_HashCode my_tm_hash;

/**
 * Is #my_tm_hash() current with respect to our type map?
 */
static int hash_current;


/**
 * Our type map changed, recompute its hash.
 */
static void
rehash_typemap ()
{
  hash_current = GNUNET_NO;
}


/**
 * Hash the contents of a type map.
 *
 * @param tm map to hash
 * @param hc where to store the hash code
 */
void
GSC_TYPEMAP_hash (const struct GSC_TypeMap *tm,
                  struct GNUNET_HashCode *hc)
{
  GNUNET_CRYPTO_hash (tm,
                      sizeof (struct GSC_TypeMap),
                      hc);
}


/**
 * Check if the given hash matches our current type map.
 *
 * @param hc hash code to check if it matches our type map
 * @return #GNUNET_YES if the hash matches, #GNUNET_NO if not
 */
int
GSC_TYPEMAP_check_hash (const struct GNUNET_HashCode *hc)
{
  if (GNUNET_NO == hash_current)
  {
    GSC_TYPEMAP_hash (&my_type_map,
                      &my_tm_hash);
    hash_current = GNUNET_YES;
  }
  return (0 == memcmp (hc, &my_tm_hash, sizeof (struct GNUNET_HashCode)))
    ? GNUNET_YES : GNUNET_NO;
}


/**
 * Compute a type map message for this peer.
 *
 * @return this peers current type map message.
 */
struct GNUNET_MessageHeader *
GSC_TYPEMAP_compute_type_map_message ()
{
  char *tmp;
  uLongf dlen;
  struct GNUNET_MessageHeader *hdr;

#ifdef compressBound
  dlen = compressBound (sizeof (my_type_map));
#else
  dlen = sizeof (my_type_map) + (sizeof (my_type_map) / 100) + 20;
  /* documentation says 100.1% oldSize + 12 bytes, but we
   * should be able to overshoot by more to be safe */
#endif
  hdr = GNUNET_malloc (dlen + sizeof (struct GNUNET_MessageHeader));
  tmp = (char *) &hdr[1];
  if ((Z_OK !=
       compress2 ((Bytef *) tmp, &dlen, (const Bytef *) &my_type_map,
                  sizeof (my_type_map), 9)) || (dlen >= sizeof (my_type_map)))
  {
    /* compression failed, use uncompressed map */
    dlen = sizeof (my_type_map);
    memcpy (tmp, &my_type_map, sizeof (my_type_map));
    hdr->type = htons (GNUNET_MESSAGE_TYPE_CORE_BINARY_TYPE_MAP);
  }
  else
  {
    /* compression worked, use compressed map */
    hdr->type = htons (GNUNET_MESSAGE_TYPE_CORE_COMPRESSED_TYPE_MAP);
  }
  hdr->size = htons ((uint16_t) dlen + sizeof (struct GNUNET_MessageHeader));
  return hdr;
}


/**
 * Extract a type map from a TYPE_MAP message.
 *
 * @param msg a type map message
 * @return NULL on error
 */
struct GSC_TypeMap *
GSC_TYPEMAP_get_from_message (const struct GNUNET_MessageHeader *msg)
{
  struct GSC_TypeMap *ret;
  uint16_t size;
  uLongf dlen;

  size = ntohs (msg->size);
  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_CORE_BINARY_TYPE_MAP:
    GNUNET_STATISTICS_update (GSC_stats, gettext_noop ("# type maps received"),
                              1, GNUNET_NO);
    if (size != sizeof (struct GSC_TypeMap))
    {
      GNUNET_break_op (0);
      return NULL;
    }
    ret = GNUNET_new (struct GSC_TypeMap);
    memcpy (ret, &msg[1], sizeof (struct GSC_TypeMap));
    return ret;
  case GNUNET_MESSAGE_TYPE_CORE_COMPRESSED_TYPE_MAP:
    GNUNET_STATISTICS_update (GSC_stats, gettext_noop ("# type maps received"),
                              1, GNUNET_NO);
    ret = GNUNET_new (struct GSC_TypeMap);
    dlen = sizeof (struct GSC_TypeMap);
    if ((Z_OK !=
         uncompress ((Bytef *) ret, &dlen, (const Bytef *) &msg[1],
                     (uLong) size)) || (dlen != sizeof (struct GSC_TypeMap)))
    {
      GNUNET_break_op (0);
      GNUNET_free (ret);
      return NULL;
    }
    return ret;
  default:
    GNUNET_break (0);
    return NULL;
  }
}


/**
 * Send my type map to all connected peers (it got changed).
 */
static void
broadcast_my_type_map ()
{
  struct GNUNET_MessageHeader *hdr;

  hdr = GSC_TYPEMAP_compute_type_map_message ();
  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop ("# updates to my type map"), 1,
                            GNUNET_NO);
  GSC_SESSIONS_broadcast_typemap (hdr);
  GNUNET_free (hdr);
}


/**
 * Add a set of types to our type map.
 *
 * @param types array of message types supported by this peer
 * @param tlen number of entries in @a types
 */
void
GSC_TYPEMAP_add (const uint16_t *types,
                 unsigned int tlen)
{
  unsigned int i;
  int changed;

  changed = GNUNET_NO;
  for (i = 0; i < tlen; i++)
  {
    if (0 == map_counters[types[i]]++)
    {
      my_type_map.bits[types[i] / 32] |= (1 << (types[i] % 32));
      changed = GNUNET_YES;
    }
  }
  if (GNUNET_YES == changed)
  {
    rehash_typemap ();
    broadcast_my_type_map ();
  }
}


/**
 * Remove a set of types from our type map.
 *
 * @param types array of types to remove
 * @param tlen length of the @a types array
 */
void
GSC_TYPEMAP_remove (const uint16_t *types,
                    unsigned int tlen)
{
  unsigned int i;
  int changed;

  changed = GNUNET_NO;
  for (i = 0; i < tlen; i++)
  {
    if (0 == --map_counters[types[i]])
    {
      my_type_map.bits[types[i] / 32] &= ~(1 << (types[i] % 32));
      changed = GNUNET_YES;
    }
  }
  if (GNUNET_YES == changed)
  {
    rehash_typemap ();
    broadcast_my_type_map ();
  }
}


/**
 * Test if any of the types from the types array is in the
 * given type map.
 *
 * @param tmap map to test
 * @param types array of types
 * @param tcnt number of entries in @a types
 * @return #GNUNET_YES if a type is in the map, #GNUNET_NO if not
 */
int
GSC_TYPEMAP_test_match (const struct GSC_TypeMap *tmap,
                        const uint16_t *types,
                        unsigned int tcnt)
{
  unsigned int i;

  if (NULL == tmap)
    return GNUNET_NO;
  if (0 == tcnt)
    return GNUNET_YES;          /* matches all */
  for (i = 0; i < tcnt; i++)
    if (0 != (tmap->bits[types[i] / 32] & (1 << (types[i] % 32))))
      return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * Add additional types to a given typemap.
 *
 * @param tmap map to extend (not changed)
 * @param types array of types to add
 * @param tcnt number of entries in @a types
 * @return updated type map (fresh copy)
 */
struct GSC_TypeMap *
GSC_TYPEMAP_extend (const struct GSC_TypeMap *tmap,
                    const uint16_t *types,
                    unsigned int tcnt)
{
  struct GSC_TypeMap *ret;
  unsigned int i;

  ret = GNUNET_new (struct GSC_TypeMap);
  if (NULL != tmap)
    memcpy (ret, tmap, sizeof (struct GSC_TypeMap));
  for (i = 0; i < tcnt; i++)
    ret->bits[types[i] / 32] |= (1 << (types[i] % 32));
  return ret;
}


/**
 * Create an empty type map.
 *
 * @return an empty type map
 */
struct GSC_TypeMap *
GSC_TYPEMAP_create ()
{
  return GNUNET_new (struct GSC_TypeMap);
}


/**
 * Free the given type map.
 *
 * @param tmap a type map
 */
void
GSC_TYPEMAP_destroy (struct GSC_TypeMap *tmap)
{
  GNUNET_free (tmap);
}


/**
 * Initialize typemap subsystem.
 */
void
GSC_TYPEMAP_init ()
{
  /* nothing to do */
}


/**
 * Shutdown typemap subsystem.
 */
void
GSC_TYPEMAP_done ()
{
  /* nothing to do */
}

/* end of gnunet-service-core_typemap.c */
