/*
     This file is part of GNUnet.
     (C) 2001 - 2011 Christian Grothoff (and other contributing authors)

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
 * @file mesh/mesh_tunnel_tree.h
 * @brief Tunnel tree handling functions
 * @author Bartlomiej Polot
 */

#include "mesh.h"


/**
 * Invert the path
 *
 * @param p the path to invert
 */
void
path_invert (struct MeshPeerPath *path);



/**
 * Destroy the path and free any allocated resources linked to it
 *
 * @param p the path to destroy
 *
 * @return GNUNET_OK on success
 */
int
path_destroy (struct MeshPeerPath *p);


/**
 * Find the first peer whom to send a packet to go down this path
 *
 * @param t The tunnel to use
 * @param peer The peerinfo of the peer we are trying to reach
 *
 * @return peerinfo of the peer who is the first hop in the tunnel
 *         NULL on error
 */
struct GNUNET_PeerIdentity *
path_get_first_hop (struct MeshTunnel *t, struct MeshPeerInfo *peer);


/**
 * Get the length of a path
 *
 * @param path The path to measure, with the local peer at any point of it
 *
 * @return Number of hops to reach destination
 *         UINT_MAX in case the peer is not in the path
 */
unsigned int
path_get_length (struct MeshPeerPath *path);


/**
 * Get the cost of the path relative to the already built tunnel tree
 *
 * @param t The tunnel to which compare
 * @param path The individual path to reach a peer
 *
 * @return Number of hops to reach destination, UINT_MAX in case the peer is not
 * in the path
 */
unsigned int
path_get_cost (struct MeshTunnel *t, struct MeshPeerPath *path);

/**
 * Add the path to the peer and update the path used to reach it in case this
 * is the shortest.
 *
 * @param peer_info Destination peer to add the path to.
 * @param path New path to add. Last peer must be the peer in arg 1.
 *             Path will be either used of freed if already known.
 */
void
path_add_to_peer (struct MeshPeerInfo *peer_info, struct MeshPeerPath *path);


/**
 * Send keepalive packets for a peer
 *
 * @param cls unused
 * @param tc unused
 */
void
path_refresh (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Recursively find the given peer in the tree.
 *
 * @param t Tunnel where to look for the peer.
 * @param peer Peer to find
 *
 * @return Pointer to the node of the peer. NULL if not found.
 */
struct MeshTunnelPathNode *
tunnel_find_peer (struct MeshTunnelPathNode *root, GNUNET_PEER_Id peer_id);


/**
 * Recusively mark peer and children as disconnected, notify client
 *
 * @param parent Node to be clean, potentially with children
 * @param nc Notification context to use to alert the client
 */
void
tunnel_mark_peers_disconnected (struct MeshTunnelPathNode *parent,
                                struct GNUNET_SERVER_NotificationContext *nc);


/**
 * Delete the current path to the peer, including all now unused relays.
 * The destination peer is NOT destroyed, it is returned in order to either set
 * a new path to it or destroy it explicitly, taking care of it's child nodes.
 *
 * @param t Tunnel where to delete the path from.
 * @param peer Destination peer whose path we want to remove.
 * @param nc Notification context to alert the client of disconnected peers.
 *
 * @return pointer to the pathless node, NULL on error
 */
struct MeshTunnelPathNode *
tunnel_del_path (struct MeshTunnel *t, GNUNET_PEER_Id peer_id,
                 struct GNUNET_SERVER_NotificationContext *nc);


/**
 * Return a newly allocated individual path to reach a peer from the local peer,
 * according to the path tree of some tunnel.
 *
 * @param t Tunnel from which to read the path tree
 * @param peer_info Destination peer to whom we want a path
 *
 * @return A newly allocated individual path to reach the destination peer.
 *         Path must be destroyed afterwards.
 */
struct MeshPeerPath *
tunnel_get_path_to_peer(struct MeshTunnel *t, struct MeshPeerInfo *peer_info);


/**
 * Integrate a stand alone path into the tunnel tree.
 *
 * @param t Tunnel where to add the new path.
 * @param p Path to be integrated.
 * @param nc Notification context to alert clients of peers
 *           temporarily disconnected
 *
 * @return GNUNET_OK in case of success.
 *         GNUNET_SYSERR in case of error.
 */
int
tunnel_add_path (struct MeshTunnel *t, const struct MeshPeerPath *p);


/**
 * Add a peer to a tunnel, accomodating paths accordingly and initializing all
 * needed rescources.
 *
 * @param t Tunnel we want to add a new peer to
 * @param peer PeerInfo of the peer being added
 *
 */
void
tunnel_add_peer (struct MeshTunnel *t, struct MeshPeerInfo *peer);