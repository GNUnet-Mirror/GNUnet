/*
     This file is part of GNUnet.
     Copyright (C)

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
 * @file rps/gnunet-service-rps_custommap.c
 * @brief utilities for managing (information about) peers
 * @author Julius Bünger
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet-service-rps_custommap.h"
#include <inttypes.h>

#define LOG(kind, ...) GNUNET_log_from(kind,"rps-peers",__VA_ARGS__)


/**
 * Peer map to store peers with specialised use-cases (push_list, pull_list,
 * view, ...)
 *
 * It is aimed for use as unordered list-like structures that can be indexed.
 * Main use-case:
 *
 *  permut = GNUNET_CRYPTO_random_permute (GNUNET_CRYPTO_QUALITY_STRONG,
 *                                         CustomPeerMap_size (peer_map));
 *  for (i = 0; i < some_border; i++)
 *    some_array[i] = *CustomPeerMap_get_peer_by_index (peer_map, permut[i]);
 *  for (i = some_border; i < CustomPeerMap_size (peer_map); i++)
 *    other_array[i-some_border] =
 *      *CustomPeerMap_get_peer_by_index (peer_map, permut[i]);
 *
 * This list is expected to
 * - be altered in small steps frequently
 * - be cleared regularily
 * - often being queried whether a peer is contained
 * - alter indices of peers
 * - contain continous indices 0 <= i < len
 * - not contain duplicate peers
 */
struct CustomPeerMap
{
  /**
   * Multihashmap to be able to access a random index
   */
  struct GNUNET_CONTAINER_MultiHashMap32 *hash_map;

  /**
   * Peermap to quickly check whether a peer is contained
   */
  struct GNUNET_CONTAINER_MultiPeerMap *peer_map;
};


/**
 * Create an empty peermap.
 *
 * @param len the initial length for the internal maps
 *
 * @return the newly created custom peer map
 */
struct CustomPeerMap *
CustomPeerMap_create (unsigned int len)
{
  struct CustomPeerMap *c_peer_map;

  c_peer_map = GNUNET_new (struct CustomPeerMap);
  c_peer_map->hash_map = GNUNET_CONTAINER_multihashmap32_create (len);
  c_peer_map->peer_map = GNUNET_CONTAINER_multipeermap_create (len, GNUNET_NO);
  return c_peer_map;
}

/**
 * Get the size of the custom peer map
 *
 * @param c_peer_map the custom peer map to look in
 *
 * @return size of the map
 */
int
CustomPeerMap_size (const struct CustomPeerMap *c_peer_map)
{
  GNUNET_assert (GNUNET_CONTAINER_multihashmap32_size (c_peer_map->hash_map) ==
                 GNUNET_CONTAINER_multipeermap_size (c_peer_map->peer_map));
  return GNUNET_CONTAINER_multipeermap_size (c_peer_map->peer_map);
}

/**
 * Insert peer into the custom peer map
 *
 * @param c_peer_map the custom peer map to insert peer
 * @param peer the peer to insert
 *
 * @return GNUNET_OK if map did not contain peer previously
 *         GNUNET_NO if map did contain peer previously
 */
int
CustomPeerMap_put (const struct CustomPeerMap *c_peer_map,
                   const struct GNUNET_PeerIdentity *peer)
{
  uint32_t *index;
  struct GNUNET_PeerIdentity *p;

  GNUNET_assert (GNUNET_CONTAINER_multihashmap32_size (c_peer_map->hash_map) ==
                 GNUNET_CONTAINER_multipeermap_size (c_peer_map->peer_map));
  if (GNUNET_NO == GNUNET_CONTAINER_multipeermap_contains (c_peer_map->peer_map,
                                                           peer))
  {
    /* Need to store the index of the peer in the peermap to be able to remove
     * it properly */
    index = GNUNET_new (uint32_t);
    *index = CustomPeerMap_size (c_peer_map);
    p = GNUNET_new (struct GNUNET_PeerIdentity);
    *p = *peer;
    GNUNET_CONTAINER_multipeermap_put (c_peer_map->peer_map, peer, index,
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    GNUNET_CONTAINER_multihashmap32_put (c_peer_map->hash_map, *index, p,
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    GNUNET_assert (GNUNET_CONTAINER_multihashmap32_size (c_peer_map->hash_map) ==
                   GNUNET_CONTAINER_multipeermap_size (c_peer_map->peer_map));
    return GNUNET_OK;
  }
  return GNUNET_NO;
}

/**
 * Check whether custom peer map contains a peer
 *
 * @param c_peer_map the custom peer map to look in
 * @param peer the peer to check for
 *
 * @return GNUNET_OK if map contains peer
 *         GNUNET_NO  otherwise
 */
int
CustomPeerMap_contains_peer (const struct CustomPeerMap *c_peer_map,
                             const struct GNUNET_PeerIdentity *peer)
{
  return GNUNET_CONTAINER_multipeermap_contains (c_peer_map->peer_map, peer);
}

/**
 * Get index of peer in custom peer map
 *
 * @param c_peer_map the custom peer map to look in
 * @param peer the peer to get the index from
 *
 * @return the index
 */
static uint32_t *
CustomPeerMap_get_index_pointer (const struct CustomPeerMap *c_peer_map,
                                 const struct GNUNET_PeerIdentity *peer)
{
  uint32_t *index;

  GNUNET_assert (GNUNET_YES == CustomPeerMap_contains_peer (c_peer_map, peer));
  index = GNUNET_CONTAINER_multipeermap_get (c_peer_map->peer_map, peer);
  return index;
}

/**
 * Remove peer from custom peer map
 *
 * @param c_peer_map the custom peer map to remove the peer from
 * @param peer the peer to remove
 *
 * @return GNUNET_OK if map contained peer and removed it successfully
 *         GNUNET_NO if map does not contain peer
 */
int
CustomPeerMap_remove_peer (const struct CustomPeerMap *c_peer_map,
                           const struct GNUNET_PeerIdentity *peer)
{
  uint32_t *index;
  struct GNUNET_PeerIdentity *p;
  uint32_t *last_index;
  struct GNUNET_PeerIdentity *last_p;

  if (GNUNET_NO == CustomPeerMap_contains_peer (c_peer_map, peer))
  {
    return GNUNET_NO;
  }
  index = CustomPeerMap_get_index_pointer (c_peer_map, peer);
  GNUNET_assert (*index < CustomPeerMap_size (c_peer_map));
  /* Need to get the pointer stored in the hashmap to free it */
  p = GNUNET_CONTAINER_multihashmap32_get (c_peer_map->hash_map, *index);
  GNUNET_assert (NULL != p);
  GNUNET_CONTAINER_multihashmap32_remove_all (c_peer_map->hash_map, *index);
  GNUNET_CONTAINER_multipeermap_remove_all (c_peer_map->peer_map, peer);
  if (*index != CustomPeerMap_size (c_peer_map))
  { /* fill 'gap' with peer at last index */
    last_p =
      GNUNET_CONTAINER_multihashmap32_get (c_peer_map->hash_map,
                                           CustomPeerMap_size (c_peer_map));
    GNUNET_assert (NULL != last_p);
    last_index = GNUNET_CONTAINER_multipeermap_get (c_peer_map->peer_map, last_p);
    GNUNET_assert (NULL != last_index);
    GNUNET_assert (CustomPeerMap_size (c_peer_map) == *last_index);
    GNUNET_CONTAINER_multihashmap32_put (c_peer_map->hash_map, *index, last_p,
        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
    GNUNET_CONTAINER_multihashmap32_remove_all (c_peer_map->hash_map, *last_index);
    *last_index = *index;
  }
  GNUNET_free (index);
  GNUNET_free (p);
  GNUNET_assert (GNUNET_CONTAINER_multihashmap32_size (c_peer_map->hash_map) ==
                 GNUNET_CONTAINER_multipeermap_size (c_peer_map->peer_map));
  return GNUNET_OK;
}

/**
 * Get a peer by index
 *
 * @param c_peer_map the custom peer map to look in
 * @param index the index of the peer to get
 *
 * @return peer to the corresponding index.
 *         if this index is not known, return NULL
 */
struct GNUNET_PeerIdentity *
CustomPeerMap_get_peer_by_index (const struct CustomPeerMap *c_peer_map,
                                 uint32_t index)
{
  if (GNUNET_YES ==
      GNUNET_CONTAINER_multihashmap32_contains (c_peer_map->hash_map, index))
  {
    return GNUNET_CONTAINER_multihashmap32_get (c_peer_map->hash_map, index);
  }
  return NULL;
}

/**
 * Remove peer from custom peer map by index
 *
 * @param c_peer_map the custom peer map to remove the peer from
 * @param index the index of the peer to remove
 *
 * @return GNUNET_OK if map contained peer and removed it successfully
 *         GNUNET_NO if map does not contain (index of) peer
 */
int
CustomPeerMap_remove_peer_by_index (const struct CustomPeerMap *c_peer_map,
                                    uint32_t index)
{
  uint32_t *index_p;
  struct GNUNET_PeerIdentity *peer;

  if (index >= CustomPeerMap_size (c_peer_map))
  {
    return GNUNET_NO;
  }
  GNUNET_assert (GNUNET_CONTAINER_multihashmap32_size (c_peer_map->hash_map) ==
                 GNUNET_CONTAINER_multipeermap_size (c_peer_map->peer_map));
  if (GNUNET_NO ==
      GNUNET_CONTAINER_multihashmap32_contains (c_peer_map->hash_map, index))
  {
    return GNUNET_NO;
  }
  peer = CustomPeerMap_get_peer_by_index (c_peer_map, index);
  GNUNET_assert (NULL != peer);
  index_p = CustomPeerMap_get_index_pointer (c_peer_map, peer);
  GNUNET_assert (index == *index_p);
  CustomPeerMap_remove_peer (c_peer_map, peer);
  GNUNET_assert (GNUNET_CONTAINER_multihashmap32_size (c_peer_map->hash_map) ==
                 GNUNET_CONTAINER_multipeermap_size (c_peer_map->peer_map));
  return GNUNET_OK;
}

/**
 * Clear the custom peer map
 *
 * @param c_peer_map the custom peer map to look in
 *
 * @return size of the map
 */
void
CustomPeerMap_clear (const struct CustomPeerMap *c_peer_map)
{
  while (0 < CustomPeerMap_size (c_peer_map))
  {
    GNUNET_assert (GNUNET_YES ==
        GNUNET_CONTAINER_multihashmap32_contains (c_peer_map->hash_map,
          CustomPeerMap_size (c_peer_map) -1));
    CustomPeerMap_remove_peer_by_index (c_peer_map, CustomPeerMap_size (c_peer_map) -1);
  }
  GNUNET_assert (0 == CustomPeerMap_size (c_peer_map));
}

/**
 * Destroy peermap.
 *
 * @param c_peer_map the map to destroy
 */
void
CustomPeerMap_destroy (struct CustomPeerMap *c_peer_map)
{
  CustomPeerMap_clear (c_peer_map);
  GNUNET_CONTAINER_multihashmap32_destroy (c_peer_map->hash_map);
  GNUNET_CONTAINER_multipeermap_destroy   (c_peer_map->peer_map);
  GNUNET_free (c_peer_map);
}

/* end of gnunet-service-rps_custommap.c */
