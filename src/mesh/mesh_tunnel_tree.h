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

/******************************************************************************/
/************************      DATA STRUCTURES     ****************************/
/******************************************************************************/

/**
 * Information regarding a possible path to reach a single peer
 */
struct MeshPeerPath
{

    /**
     * Linked list
     */
  struct MeshPeerPath *next;
  struct MeshPeerPath *prev;

    /**
     * List of all the peers that form the path from origin to target.
     */
  GNUNET_PEER_Id *peers;

    /**
     * Number of peers (hops) in the path
     */
  unsigned int length;

};


/**
 * Node of path tree for a tunnel
 */
struct MeshTunnelTreeNode
{
  /**
   * Tunnel this node belongs to (and therefore tree)
   */
  struct MeshTunnel *t;

  /**
   * Peer this node describes
   */
  GNUNET_PEER_Id peer;

  /**
   * Parent node in the tree
   */
  struct MeshTunnelTreeNode *parent;

  /**
   * Array of children
   */
  struct MeshTunnelTreeNode *children;

  /**
   * Number of children
   */
  unsigned int nchildren;

    /**
     * Status of the peer in the tunnel
     */
  enum MeshPeerState status;
};


/**
 * Tree to reach all peers in the tunnel
 */
struct MeshTunnelTree
{
  /**
   * How often to refresh the path
   */
  struct GNUNET_TIME_Relative refresh;

  /**
   * Tunnel this path belongs to
   */
  struct MeshTunnel *t;

  /**
   * Root node of peer tree
   */
  struct MeshTunnelTreeNode *root;

  /**
   * Node that represents our position in the tree (for non local tunnels)
   */
  struct MeshTunnelTreeNode *me;

  /**
   * Cache of all peers and the first hop to them.
   * Indexed by Peer_Identity, contains a pointer to the PeerIdentity
   * of 1st hop.
   */
  struct GNUNET_CONTAINER_MultiHashMap *first_hops;

};


/******************************************************************************/
/*************************        FUNCTIONS       *****************************/
/******************************************************************************/


/**
 * Method called whenever a node has been marked as disconnected.
 *
 * @param node peer identity the tunnel stopped working with
 */
typedef void (*MeshNodeDisconnectCB) (const struct MeshTunnelTreeNode * node);


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
path_get_first_hop (struct MeshTunnelTree *t, GNUNET_PEER_Id peer);


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
path_get_cost (struct MeshTunnelTree *t, struct MeshPeerPath *path);


/**
 * Recursively find the given peer in the tree.
 *
 * @param t Tunnel where to look for the peer.
 * @param peer Peer to find
 *
 * @return Pointer to the node of the peer. NULL if not found.
 */
struct MeshTunnelTreeNode *
tunnel_find_peer (struct MeshTunnelTreeNode *root, GNUNET_PEER_Id peer_id);


/**
 * Recusively mark peer and children as disconnected, notify client
 *
 * @param parent Node to be clean, potentially with children
 * @param cb Callback to use to notify about disconnected peers
 */
void
tunnel_mark_peers_disconnected (struct MeshTunnelTreeNode *parent,
                                MeshNodeDisconnectCB cb);


/**
 * Delete the current path to the peer, including all now unused relays.
 * The destination peer is NOT destroyed, it is returned in order to either set
 * a new path to it or destroy it explicitly, taking care of it's child nodes.
 *
 * @param t Tunnel where to delete the path from.
 * @param peer Destination peer whose path we want to remove.
 * @param cb Callback to use to notify about disconnected peers
 *
 * @return pointer to the pathless node, NULL on error
 */
struct MeshTunnelTreeNode *
tunnel_del_path (struct MeshTunnelTree *t, GNUNET_PEER_Id peer_id,
                 MeshNodeDisconnectCB cb);


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
tunnel_get_path_to_peer(struct MeshTunnelTree *t, GNUNET_PEER_Id peer);


/**
 * Integrate a stand alone path into the tunnel tree.
 *
 * @param t Tunnel where to add the new path.
 * @param p Path to be integrated.
 * @param cb Callback to use to notify about peers temporarily disconnecting
 *
 * @return GNUNET_OK in case of success.
 *         GNUNET_SYSERR in case of error.
 */
int
tunnel_add_path (struct MeshTunnelTree *t, const struct MeshPeerPath *p,
                 MeshNodeDisconnectCB cb);