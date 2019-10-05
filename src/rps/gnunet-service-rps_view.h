/*
     This file is part of GNUnet.
     Copyright (C)

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
 * @file rps/gnunet-service-rps_view.h
 * @brief wrapper around the "local view"
 * @author Julius Bünger
 */
#include "gnunet_util_lib.h"
#include <inttypes.h>

struct View;

/**
 * Create an empty view.
 *
 * @param len the maximum length for the view
 * @return The newly created view
 */
struct View *
View_create (unsigned int len);


/**
 * Change length of view
 *
 * If size is decreased, peers with higher indices are removed.
 *
 * @param view The view that is changed
 * @param len the (maximum) length for the view
 */
void
View_change_len (struct View *view,
                 unsigned int len);

/**
 * Get the view as an array
 *
 * @return the view in array representation
 */
const struct GNUNET_PeerIdentity *
View_get_as_array (const struct View *view);


/**
 * Get the size of the view
 *
 * @param view The view of which the size should be returned
 * @return current number of actually contained peers
 */
unsigned int
View_size (const struct View *view);


/**
 * Insert peer into the view
 *
 * @param view The view to put the peer into
 * @param peer the peer to insert
 *
 * @return GNUNET_OK if peer was actually inserted
 *         GNUNET_NO if peer was not inserted
 */
int
View_put (struct View *view,
          const struct GNUNET_PeerIdentity *peer);


/**
 * Check whether view contains a peer
 *
 * @param view The which is checked for a peer
 * @param peer the peer to check for
 *
 * @return GNUNET_OK if view contains peer
 *         GNUNET_NO otherwise
 */
int
View_contains_peer (const struct View *view,
                    const struct GNUNET_PeerIdentity *peer);


/**
 * Remove peer from view
 *
 * @param view The view of which to remove the peer
 * @param peer the peer to remove
 *
 * @return GNUNET_OK if view contained peer and removed it successfully
 *         GNUNET_NO if view does not contain peer
 */
int
View_remove_peer (struct View *view,
                  const struct GNUNET_PeerIdentity *peer);


/**
 * Get a peer by index
 *
 * @param view the view of which to get the peer
 * @param index the index of the peer to get
 *
 * @return peer to the corresponding index.
 *         NULL if this index is not known
 */
const struct GNUNET_PeerIdentity *
View_get_peer_by_index (const struct View *view,
                        uint32_t index);


/**
 * Clear the view
 *
 * @param view The view to clear
 */
void
View_clear (struct View *view);


/**
 * Destroy view.
 *
 * @param view the view to destroy
 */
void
View_destroy (struct View *view);

/* end of gnunet-service-rps_view.h */
