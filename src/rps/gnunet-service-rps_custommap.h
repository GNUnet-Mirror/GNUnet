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
 * @file rps/gnunet-service-rps_custommap.h
 * @brief utilities for managing (information about) peers
 * @author Julius Bünger
 */
#include "gnunet_util_lib.h"
#include <inttypes.h>


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
struct CustomPeerMap;


/**
 * Create an empty peermap.
 *
 * @param len the initial length for the internal maps
 *
 * @return the newly created custom peer map
 */
struct CustomPeerMap *
CustomPeerMap_create (unsigned int len);

/**
 * Get the size of the custom peer map
 *
 * @param c_peer_map the custom peer map to look in
 *
 * @return size of the map
 */
int
CustomPeerMap_size (const struct CustomPeerMap *c_peer_map);

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
                   const struct GNUNET_PeerIdentity *peer);

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
                             const struct GNUNET_PeerIdentity *peer);

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
                           const struct GNUNET_PeerIdentity *peer);

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
                                 uint32_t index);

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
                                    uint32_t index);

/**
 * Clear the custom peer map
 *
 * @param c_peer_map the custom peer map to look in
 *
 * @return size of the map
 */
void
CustomPeerMap_clear (const struct CustomPeerMap *c_peer_map);

/**
 * Destroy peermap.
 *
 * @param c_peer_map the map to destroy
 */
void
CustomPeerMap_destroy (struct CustomPeerMap *c_peer_map);

/* end of gnunet-service-rps_custommap.h */
