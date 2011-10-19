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
 * @file mesh/mesh_tree_tree.h
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
   * DLL of siblings
   */
  struct MeshTunnelTreeNode *next;

  /**
   * DLL of siblings
   */
  struct MeshTunnelTreeNode *prev;

  /**
   * DLL of children
   */
  struct MeshTunnelTreeNode *children_head;

  /**
   * DLL of children
   */
  struct MeshTunnelTreeNode *children_tail;

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
   * DLL of disconneted nodes
   */
  struct MeshTunnelTreeNode *disconnected_head;

  /**
   * DLL of disconneted nodes
   */
  struct MeshTunnelTreeNode *disconnected_tail;

  /**
   * Cache of all peers and the first hop to them.
   * Indexed by PeerIdentity, contains a pointer to the PeerIdentity
   * of 1st hop.
   */
  struct GNUNET_CONTAINER_MultiHashMap *first_hops;

};


/******************************************************************************/
/*************************        FUNCTIONS       *****************************/
/******************************************************************************/

/**
 * Create a new path
 *
 * @param lenght How many hops will the path have.
 *
 * @return A newly allocated path with a peer array of the specified length.
 */
struct MeshPeerPath *
path_new (unsigned int length);


/**
 * Invert the path
 *
 * @param p the path to invert
 */
void
path_invert (struct MeshPeerPath *p);


/**
 * Duplicate a path, incrementing short peer's rc.
 *
 * @param p The path to duplicate.
 */
struct MeshPeerPath *
path_duplicate (struct MeshPeerPath *path);


/**
 * Find the first peer whom to send a packet to go down this path
 *
 * @param t The tunnel tree to use
 * @param peer The peerinfo of the peer we are trying to reach
 *
 * @return peerinfo of the peer who is the first hop in the tunnel
 *         NULL on error
 */
struct GNUNET_PeerIdentity *
path_get_first_hop (struct MeshTunnelTree *t,
                    GNUNET_PEER_Id peer);


/**
 * Get the length of a path
 *
 * @param p The path to measure, with the local peer at any point of it
 *
 * @return Number of hops to reach destination
 *         UINT_MAX in case the peer is not in the path
 */
unsigned int
path_get_length (struct MeshPeerPath *p);


/**
 * Get the cost of the path relative to the already built tunnel tree
 *
 * @param t The tunnel tree to which compare
 * @param path The individual path to reach a peer
 *
 * @return Number of hops to reach destination, UINT_MAX in case the peer is not
 * in the path
 */
unsigned int
path_get_cost (struct MeshTunnelTree *t,
               struct MeshPeerPath *path);


/**
 * Destroy the path and free any allocated resources linked to it
 *
 * @param p the path to destroy
 *
 * @return GNUNET_OK on success
 */
int
path_destroy (struct MeshPeerPath *p);


/******************************************************************************/

/**
 * Method called whenever a node has been marked as disconnected.
 *
 * @param node peer identity the tunnel stopped working with
 */
typedef void (*MeshNodeDisconnectCB) (const struct MeshTunnelTreeNode * node);


/**
 * Create a new tunnel tree associated to a tunnel
 *
 * @param t Tunnel this tree will represent
 * @param peer A short peer id of the root of the tree
 *
 * @return A newly allocated and initialized tunnel tree
 */
struct MeshTunnelTree *
tree_new (struct MeshTunnel *t, GNUNET_PEER_Id peer);


/**
 * Recursively find the given peer in the tree.
 *
 * @param parent Parent node where to start looking.
 * @param peer Short ID of peer to find.
 *
 * @return Pointer to the node of the peer. NULL if not found.
 */
struct MeshTunnelTreeNode *
tree_find_peer (struct MeshTunnelTreeNode *parent,
                GNUNET_PEER_Id peer);


/**
 * Recusively update the info about what is the first hop to reach the node
 *
 * @param tree Tree this nodes belongs to
 * @param parent Node to be start updating
 * @param hop If known, ID of the first hop.
 *            If not known, NULL to find out and pass on children.
 */
void
tree_update_first_hops (struct MeshTunnelTree *tree,
                        struct MeshTunnelTreeNode *parent,
                        struct GNUNET_PeerIdentity *hop);

/**
 * Delete the current path to the peer, including all now unused relays.
 * The destination peer is NOT destroyed, it is returned in order to either set
 * a new path to it or destroy it explicitly, taking care of it's child nodes.
 *
 * @param t Tunnel tree where to delete the path from.
 * @param peer Destination peer whose path we want to remove.
 * @param cb Callback to use to notify about which peers are going to be
 *           disconnected.
 *
 * @return pointer to the pathless node.
 *         NULL when not found
 */
struct MeshTunnelTreeNode *
tree_del_path (struct MeshTunnelTree *t,
               GNUNET_PEER_Id peer,
               MeshNodeDisconnectCB cb);


/**
 * Return a newly allocated individual path to reach a peer from the local peer,
 * according to the path tree of some tunnel.
 *
 * @param t Tunnel from which to read the path tree
 * @param peer Destination peer to whom we want a path
 *
 * @return A newly allocated individual path to reach the destination peer.
 *         Path must be destroyed afterwards.
 */
struct MeshPeerPath *
tree_get_path_to_peer(struct MeshTunnelTree *t,
                      GNUNET_PEER_Id peer);


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
tree_add_path (struct MeshTunnelTree *t,
               const struct MeshPeerPath *p,
               MeshNodeDisconnectCB cb);


/**
 * Notifies a tree that a connection it might be using is broken.
 * Marks all peers down the paths as disconnected and notifies the client.
 *
 * @param t Tree to use.
 * @param p1 Short id of one of the peers (order unimportant)
 * @param p2 Short id of one of the peers (order unimportant)
 * @param cb Function to call for every peer that is marked as disconnected.
 *
 * @return Short ID of the first disconnected peer in the tree.
 */
GNUNET_PEER_Id
tree_notify_connection_broken (struct MeshTunnelTree *t,
                               GNUNET_PEER_Id p1,
                               GNUNET_PEER_Id p2,
                               MeshNodeDisconnectCB cb);


/**
 * Deletes a peer from a tunnel, marking its children as disconnected.
 *
 * @param t Tunnel tree to use.
 * @param peer Short ID of the peer to remove from the tunnel tree.
 * @param cb Callback to notify client of disconnected peers.
 *
 * @return GNUNET_OK or GNUNET_SYSERR
 */
int
tree_del_peer (struct MeshTunnelTree *t,
               GNUNET_PEER_Id peer,
               MeshNodeDisconnectCB cb);

/**
 * Print the tree on stderr
 *
 * @param t The tree
 */
void
tree_debug(struct MeshTunnelTree *t);


/**
 * Destroy the whole tree and free all used memory and Peer_Ids
 *
 * @param t Tree to be destroyed
 */
void
tree_destroy (struct MeshTunnelTree *t);
