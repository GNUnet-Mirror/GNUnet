
/*
     This file is part of GNUnet.
     Copyright (C) 2001-2017 GNUnet e.V.

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
 * @file cadet/gnunet-service-cadet-new_peer.h
 * @brief Information we track per peer.
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_CADET_PEER_H
#define GNUNET_SERVICE_CADET_PEER_H

#include "gnunet-service-cadet-new.h"
#include "gnunet_hello_lib.h"


/**
 * Get the static string for a peer ID.
 *
 * @param peer Peer.
 *
 * @return Static string for it's ID.
 */
const char *
GCP_2s (const struct CadetPeer *peer);


/**
 * Retrieve the CadetPeer stucture associated with the
 * peer. Optionally create one and insert it in the appropriate
 * structures if the peer is not known yet.
 *
 * @param peer_id Full identity of the peer.
 * @param create #GNUNET_YES if a new peer should be created if unknown.
 *               #GNUNET_NO to return NULL if peer is unknown.
 * @return Existing or newly created peer structure.
 *         NULL if unknown and not requested @a create
 */
struct CadetPeer *
GCP_get (const struct GNUNET_PeerIdentity *peer_id,
         int create);


/**
 * Obtain the peer identity for a `struct CadetPeer`.
 *
 * @param cp our peer handle
 * @param[out] peer_id where to write the peer identity
 */
void
GCP_id (struct CadetPeer *cp,
        struct GNUNET_PeerIdentity *peer_id);


/**
 * Iterate over all known peers.
 *
 * @param iter Iterator.
 * @param cls Closure for @c iter.
 */
void
GCP_iterate_all (GNUNET_CONTAINER_PeerMapIterator iter,
                 void *cls);


/**
 * Count the number of known paths toward the peer.
 *
 * @param peer Peer to get path info.
 * @return Number of known paths.
 */
unsigned int
GCP_count_paths (const struct CadetPeer *peer);


/**
 * Peer path iterator.
 *
 * @param cls Closure.
 * @param peer Peer this path is towards.
 * @param path Path itself
 * @return #GNUNET_YES if should keep iterating.
 *         #GNUNET_NO otherwise.
 *
 * FIXME: peer argument should be redundant; remove!
 */
typedef int
(*GCP_PathIterator) (void *cls,
                     struct CadetPeer *peer,
                     struct CadetPeerPath *path);


/**
 * Iterate over the paths to a peer.
 *
 * @param peer Peer to get path info.
 * @param callback Function to call for every path.
 * @param callback_cls Closure for @a callback.
 * @return Number of iterated paths.
 */
unsigned int
GCP_iterate_paths (struct CadetPeer *peer,
                   GCP_PathIterator callback,
                   void *callback_cls);


/**
 * Remove an entry from the DLL of all of the paths that this peer is on.
 *
 * @param cp peer to modify
 * @param entry an entry on a path
 * @param off offset of this peer on the path
 */
void
GCP_path_entry_remove (struct CadetPeer *cp,
                       struct CadetPeerPathEntry *entry,
                       unsigned int off);


/**
 * Add an entry to the DLL of all of the paths that this peer is on.
 *
 * @param cp peer to modify
 * @param entry an entry on a path
 * @param off offset of this peer on the path
 */
void
GCP_path_entry_add (struct CadetPeer *cp,
                    struct CadetPeerPathEntry *entry,
                    unsigned int off);


/**
 * Get the tunnel towards a peer.
 *
 * @param peer Peer to get from.
 * @param create #GNUNET_YES to create a tunnel if we do not have one
 * @return Tunnel towards peer.
 */
struct CadetTunnel *
GCP_get_tunnel (struct CadetPeer *peer,
                int create);


/**
 * The tunnel to the given peer no longer exists, remove it from our
 * data structures, and possibly clean up the peer itself.
 *
 * @param peer the peer affected
 * @param t the dead tunnel
 */
void
GCP_drop_tunnel (struct CadetPeer *peer,
                 struct CadetTunnel *t);


/**
 * We got a HELLO for a @a peer, remember it, and possibly
 * trigger adequate actions (like trying to connect).
 *
 * @param peer the peer we got a HELLO for
 * @param hello the HELLO to remember
 */
void
GCP_set_hello (struct CadetPeer *peer,
               const struct GNUNET_HELLO_Message *hello);


/**
 * Clean up all entries about all peers.
 * Must only be called after all tunnels, CORE-connections and
 * connections are down.
 */
void
GCP_destroy_all_peers (void);


#endif
