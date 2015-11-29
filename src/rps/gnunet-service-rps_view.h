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
 * @file rps/gnunet-service-rps_view.h
 * @brief wrapper around the "local view"
 * @author Julius Bünger
 */
#include "gnunet_util_lib.h"
#include <inttypes.h>


/**
 * Create an empty view.
 *
 * @param len the maximum length for the view
 */
void
View_create (unsigned int len);

/**
 * Change length of view
 *
 * @param len the (maximum) length for the view
 */
void
View_change_len (unsigned int len);

/**
 * Get the view as an array
 *
 * @return the view in array representation
 */
const struct GNUNET_PeerIdentity *
View_get_as_array ();

/**
 * Get the size of the view
 *
 * @return current number of actually contained peers
 */
unsigned int
View_size ();

/**
 * Insert peer into the view
 *
 * @param peer the peer to insert
 *
 * @return GNUNET_OK if peer was actually inserted
 *         GNUNET_NO if peer was not inserted
 */
int
View_put (const struct GNUNET_PeerIdentity *peer);

/**
 * Check whether view contains a peer
 *
 * @param peer the peer to check for
 *
 * @return GNUNET_OK if view contains peer
 *         GNUNET_NO otherwise
 */
int
View_contains_peer (const struct GNUNET_PeerIdentity *peer);

/**
 * Remove peer from view
 *
 * @param peer the peer to remove
 *
 * @return GNUNET_OK if view contained peer and removed it successfully
 *         GNUNET_NO if view does not contain peer
 */
int
View_remove_peer (const struct GNUNET_PeerIdentity *peer);

/**
 * Get a peer by index
 *
 * @param index the index of the peer to get
 *
 * @return peer to the corresponding index.
 *         NULL if this index is not known
 */
const struct GNUNET_PeerIdentity *
View_get_peer_by_index (uint32_t index);

/**
 * Clear the custom peer map
 *
 * @param c_peer_map the custom peer map to look in
 *
 * @return size of the map
 */
void
View_clear ();

/**
 * Destroy peermap.
 *
 * @param c_peer_map the map to destroy
 */
void
View_destroy ();

/* end of gnunet-service-rps_view.h */
