
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
 * @return the peer identity
 */
const struct GNUNET_PeerIdentity *
GCP_get_id (struct CadetPeer *cp);


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
 * @param cp Peer to get path info.
 * @return Number of known paths.
 */
unsigned int
GCP_count_paths (const struct CadetPeer *cp);


/**
 * Peer path iterator.
 *
 * @param cls Closure.
 * @param path Path itself
 * @param off offset of the target peer in @a path
 * @return #GNUNET_YES if should keep iterating.
 *         #GNUNET_NO otherwise.
 */
typedef int
(*GCP_PathIterator) (void *cls,
                     struct CadetPeerPath *path,
                     unsigned int off);


/**
 * Iterate over the paths to a peer.
 *
 * @param cp Peer to get path info.
 * @param callback Function to call for every path.
 * @param callback_cls Closure for @a callback.
 * @return Number of iterated paths.
 */
unsigned int
GCP_iterate_paths (struct CadetPeer *cp,
                   GCP_PathIterator callback,
                   void *callback_cls);


/**
 * Iterate over the paths to @a peer where
 * @a peer is at distance @a dist from us.
 *
 * @param peer Peer to get path info.
 * @param dist desired distance of @a peer to us on the path
 * @param callback Function to call for every path.
 * @param callback_cls Closure for @a callback.
 * @return Number of iterated paths.
 */
unsigned int
GCP_iterate_paths_at (struct CadetPeer *peer,
                      unsigned int dist,
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
 * @param cp Peer to get from.
 * @param create #GNUNET_YES to create a tunnel if we do not have one
 * @return Tunnel towards peer.
 */
struct CadetTunnel *
GCP_get_tunnel (struct CadetPeer *cp,
                int create);


/**
 * The tunnel to the given peer no longer exists, remove it from our
 * data structures, and possibly clean up the peer itself.
 *
 * @param cp the peer affected
 * @param t the dead tunnel
 */
void
GCP_drop_tunnel (struct CadetPeer *cp,
                 struct CadetTunnel *t);


/**
 * Try adding a @a path to this @a cp.  If the peer already
 * has plenty of paths, return NULL.
 *
 * @param cp peer to which the @a path leads to
 * @param path a path looking for an owner; may not be fully initialized yet!
 * @param off offset of @a cp in @a path
 * @return NULL if this peer does not care to become a new owner,
 *         otherwise the node in the peer's path heap for the @a path.
 */
struct GNUNET_CONTAINER_HeapNode *
GCP_attach_path (struct CadetPeer *cp,
                 struct CadetPeerPath *path,
                 unsigned int off);


/**
 * This peer can no longer own @a path as the path
 * has been extended and a peer further down the line
 * is now the new owner.
 *
 * @param cp old owner of the @a path
 * @param path path where the ownership is lost
 * @param hn note in @a cp's path heap that must be deleted
 */
void
GCP_detach_path (struct CadetPeer *cp,
                 struct CadetPeerPath *path,
                 struct GNUNET_CONTAINER_HeapNode *hn);


/**
 * We got a HELLO for a @a cp, remember it, and possibly
 * trigger adequate actions (like trying to connect).
 *
 * @param cp the peer we got a HELLO for
 * @param hello the HELLO to remember
 */
void
GCP_set_hello (struct CadetPeer *cp,
               const struct GNUNET_HELLO_Message *hello);


/**
 * Clean up all entries about all peers.
 * Must only be called after all tunnels, CORE-connections and
 * connections are down.
 */
void
GCP_destroy_all_peers (void);


#endif
