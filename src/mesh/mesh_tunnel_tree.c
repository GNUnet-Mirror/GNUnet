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
 * @file mesh/mesh_tunnel_tree.c
 * @brief Tunnel tree handling functions
 * @author Bartlomiej Polot
 */

#include "mesh.h"
#include "mesh_tunnel_tree.h"

#define MESH_TREE_DEBUG GNUNET_YES


/**
 * Node of path tree for a tunnel
 */
struct MeshTunnelTreeNode
{
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


/**
 * Create a new path
 *
 * @param length How many hops will the path have.
 *
 * @return A newly allocated path with a peer array of the specified length.
 */
struct MeshPeerPath *
path_new (unsigned int length)
{
  struct MeshPeerPath *p;

  p = GNUNET_malloc (sizeof (struct MeshPeerPath));
  if (length > 0)
  {
    p->length = length;
    p->peers = GNUNET_malloc (length * sizeof (GNUNET_PEER_Id));
  }
  return p;
}


/**
 * Invert the path
 *
 * @param path the path to invert
 */
void
path_invert (struct MeshPeerPath *path)
{
  GNUNET_PEER_Id aux;
  unsigned int i;

  for (i = 0; i < path->length / 2; i++)
  {
    aux = path->peers[i];
    path->peers[i] = path->peers[path->length - i - 1];
    path->peers[path->length - i - 1] = aux;
  }
}


/**
 * Duplicate a path, incrementing short peer's rc.
 *
 * @param path The path to duplicate.
 */
struct MeshPeerPath *
path_duplicate (struct MeshPeerPath *path)
{
  struct MeshPeerPath *aux;
  unsigned int i;

  aux = path_new (path->length);
  memcpy (aux->peers, path->peers, path->length * sizeof (GNUNET_PEER_Id));
  for (i = 0; i < path->length; i++)
    GNUNET_PEER_change_rc (path->peers[i], 1);
  return aux;
}


/**
 * Recusively update the info about what is the first hop to reach the node
 *
 * @param tree Tree this nodes belongs to.
 * @param parent The node form which to start updating.
 * @param hop If known, ID of the first hop.
 *            If not known, NULL to find out and pass on children.
 */
static void
tree_node_update_first_hops (struct MeshTunnelTree *tree,
                             struct MeshTunnelTreeNode *parent,
                             struct GNUNET_PeerIdentity *hop);


/**
 * Get the length of a path.
 *
 * @param path The path to measure, with the local peer at any point of it.
 *
 * @return Number of hops to reach destination.
 *         UINT_MAX in case the peer is not in the path.
 */
unsigned int
path_get_length (struct MeshPeerPath *path)
{
  if (NULL == path)
    return UINT_MAX;
  return path->length;
}


/**
 * Destroy the path and free any allocated resources linked to it
 *
 * @param p the path to destroy
 *
 * @return GNUNET_OK on success
 */
int
path_destroy (struct MeshPeerPath *p)
{
  if (NULL == p)
    return GNUNET_OK;
  GNUNET_PEER_decrement_rcs (p->peers, p->length);
  GNUNET_free_non_null (p->peers);
  GNUNET_free (p);
  return GNUNET_OK;
}



/**
 * Allocates and initializes a new node.
 * Sets ID and parent of the new node and inserts it in the DLL of the parent
 *
 * @param parent Node that will be the parent from the new node, NULL for root
 * @param peer Short Id of the new node
 *
 * @return Newly allocated node
 */
static struct MeshTunnelTreeNode *
tree_node_new (struct MeshTunnelTreeNode *parent, GNUNET_PEER_Id peer)
{
  struct MeshTunnelTreeNode *node;

  node = GNUNET_malloc (sizeof (struct MeshTunnelTreeNode));
  node->peer = peer;
  GNUNET_PEER_change_rc (peer, 1);
  node->parent = parent;
  if (NULL != parent)
    GNUNET_CONTAINER_DLL_insert (parent->children_head, parent->children_tail,
                                 node);

  return node;
}


/**
 * Recursively find the given peer.
 *
 * @param parent Node where to start looking.
 * @param peer_id Short ID of the peer to find.
 *
 * @return Pointer to the node of the peer. NULL if not found.
 */
static struct MeshTunnelTreeNode *
tree_node_find_peer (struct MeshTunnelTreeNode *parent, GNUNET_PEER_Id peer_id)
{
  struct MeshTunnelTreeNode *n;
  struct MeshTunnelTreeNode *r;

  if (parent->peer == peer_id)
    return parent;
  for (n = parent->children_head; NULL != n; n = n->next)
  {
    r = tree_node_find_peer (n, peer_id);
    if (NULL != r)
      return r;
  }
  return NULL;
}


/**
 * Recusively update the info about what is the first hop to reach the node
 *
 * @param tree Tree this nodes belongs to.
 * @param parent ID from node form which to start updating.
 * @param hop If known, ID of the first hop.
 *            If not known, NULL to find out and pass on children.
 */
static void
tree_node_update_first_hops (struct MeshTunnelTree *tree,
                             struct MeshTunnelTreeNode *parent,
                             struct GNUNET_PeerIdentity *hop)
{
  struct GNUNET_PeerIdentity pi;
  struct GNUNET_PeerIdentity *copy;
  struct GNUNET_PeerIdentity id;
  struct MeshTunnelTreeNode *n;

#if MESH_TREE_DEBUG
  GNUNET_PEER_resolve (parent->peer, &id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tree:   Finding first hop for %s.\n",
              GNUNET_i2s (&id));
#endif
  if (NULL == hop)
  {
    struct MeshTunnelTreeNode *aux;
    struct MeshTunnelTreeNode *old;

    aux = old = parent;
    while (aux != tree->me)
    {
#if MESH_TREE_DEBUG
      GNUNET_PEER_resolve (aux->peer, &id);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tree:   ... checking %s.\n",
                  GNUNET_i2s (&id));
#endif
      old = aux;
      aux = aux->parent;
      GNUNET_assert (NULL != aux);
    }
#if MESH_TREE_DEBUG
    GNUNET_PEER_resolve (old->peer, &id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tree:   It's %s!\n",
                GNUNET_i2s (&id));
#endif
    hop = &pi;
    GNUNET_PEER_resolve (old->peer, hop);
  }
  GNUNET_PEER_resolve (parent->peer, &id);
  copy = GNUNET_CONTAINER_multihashmap_get (tree->first_hops, &id.hashPubKey);
  if (NULL == copy)
    copy = GNUNET_malloc (sizeof (struct GNUNET_PeerIdentity));
  *copy = *hop;

  (void) GNUNET_CONTAINER_multihashmap_put (tree->first_hops, &id.hashPubKey,
                                            copy,
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_REPLACE);

  for (n = parent->children_head; NULL != n; n = n->next)
  {
    tree_node_update_first_hops (tree, n, hop);
  }
}


static void
tree_node_debug (struct MeshTunnelTreeNode *n, uint16_t level)
{
  struct MeshTunnelTreeNode *c;
  struct GNUNET_PeerIdentity id;;
  uint16_t i;

  for (i = 0; i < level; i++)
    FPRINTF (stderr, "%s",  "  ");
  if (n->status == MESH_PEER_READY)
    FPRINTF (stderr, "%s",  "#");
  if (n->status == MESH_PEER_SEARCHING)
    FPRINTF (stderr, "%s",  "+");
  if (n->status == MESH_PEER_RELAY)
    FPRINTF (stderr, "%s",  "-");
  if (n->status == MESH_PEER_RECONNECTING)
    FPRINTF (stderr, "%s",  "*");

  GNUNET_PEER_resolve (n->peer, &id);
  FPRINTF (stderr, "%s, [%u, %p] ", GNUNET_i2s (&id), n->peer, n);
  if (NULL != n->parent)
  {
    GNUNET_PEER_resolve (n->parent->peer, &id);
    FPRINTF (stderr, "(-> %s [%u])\n", GNUNET_i2s (&id), n->parent->peer);
  }
  else
    FPRINTF (stderr, "%s",  "(root)\n");
  for (c = n->children_head; NULL != c; c = c->next)
    tree_node_debug (c, level + 1);
}


/**
 * Destroys and frees the node and all children
 *
 * @param parent Parent node to be destroyed
 */
static void
tree_node_destroy (struct MeshTunnelTreeNode *parent)
{
  struct MeshTunnelTreeNode *n;
  struct MeshTunnelTreeNode *next;

#if MESH_TREE_DEBUG
  struct GNUNET_PeerIdentity id;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tree: Destroying node %u\n",
              parent->peer);
  GNUNET_PEER_resolve (parent->peer, &id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tree:   (%s)\n", GNUNET_i2s (&id));
#endif
  n = parent->children_head;
  while (NULL != n)
  {
    next = n->next;
    tree_node_destroy (n);
    n = next;
  }
  GNUNET_PEER_change_rc (parent->peer, -1);
  if (NULL != parent->parent)
    GNUNET_CONTAINER_DLL_remove (parent->parent->children_head,
                                 parent->parent->children_tail, parent);
  GNUNET_free (parent);
}



/**
 * Create a new tree.
 *
 * @param peer A short peer id of the root of the tree.
 *
 * @return A newly allocated and initialized tunnel tree.
 */
struct MeshTunnelTree *
tree_new (GNUNET_PEER_Id peer)
{
  struct MeshTunnelTree *tree;

  tree = GNUNET_malloc (sizeof (struct MeshTunnelTree));
  tree->first_hops = GNUNET_CONTAINER_multihashmap_create (32);
  tree->root = tree_node_new (NULL, peer);
  tree->root->status = MESH_PEER_ROOT;

  if (1 == peer)
  {
    tree->me = tree->root;
  }

  return tree;
}


/**
 * Set the status of a node.
 *
 * @param tree Tree.
 * @param peer A short peer id of the node.
 * @param status New status to set.
 */
void
tree_set_status (struct MeshTunnelTree *tree, GNUNET_PEER_Id peer,
                 enum MeshPeerState status)
{
  struct MeshTunnelTreeNode *n;

  n = tree_find_peer (tree, peer);
  if (NULL == n)
    return;
  n->status = status;
}


/**
 * Get the status of a node.
 *
 * @param tree Tree whose node's status we want to now.
 * @param peer A short peer id of the node.
 *
 * @return Status of the peer.
 */
enum MeshPeerState
tree_get_status (struct MeshTunnelTree *tree, GNUNET_PEER_Id peer)
{
  struct MeshTunnelTreeNode *n;

  n = tree_find_peer (tree, peer);
  if (NULL == n)
    return MESH_PEER_INVALID;
  return n->status;
}


/**
 * Get the id of the predecessor of the local node.
 *
 * @param tree Tree whose local id we want to now.
 *
 * @return Short peer id of local peer.
 */
GNUNET_PEER_Id
tree_get_predecessor (struct MeshTunnelTree *tree)
{
  if (NULL != tree->me && NULL != tree->me->parent)
    return tree->me->parent->peer;
  else
    return (GNUNET_PEER_Id) 0;
}


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
tree_get_first_hop (struct MeshTunnelTree *t, GNUNET_PEER_Id peer)
{
  struct GNUNET_PeerIdentity id;
  struct GNUNET_PeerIdentity *r;

  GNUNET_PEER_resolve (peer, &id);
  r = GNUNET_CONTAINER_multihashmap_get (t->first_hops, &id.hashPubKey);
  if (NULL == r)
  {
    struct MeshTunnelTreeNode *n;

    n = tree_find_peer (t, peer);
    if (NULL != t->me && NULL != n)
    {
      tree_node_update_first_hops (t, n, NULL);
      r = GNUNET_CONTAINER_multihashmap_get (t->first_hops, &id.hashPubKey);
      GNUNET_assert (NULL != r);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  "Tree structure inconsistent! me: %p, n: %p", t->me, n);
      GNUNET_break (0);
    }
  }

  return r;
}


/**
 * Find the given peer in the tree.
 *
 * @param tree Tree where to look for the peer.
 * @param peer_id Short ID of the peer to find.
 *
 * @return Pointer to the node of the peer. NULL if not found.
 */
struct MeshTunnelTreeNode *
tree_find_peer (struct MeshTunnelTree *tree, GNUNET_PEER_Id peer_id)
{
  return tree_node_find_peer (tree->root, peer_id);
}


/**
 * Recusively mark peer and children as disconnected, notify client
 *
 * @param tree Tree this node belongs to
 * @param parent Node to be clean, potentially with children
 * @param cb Callback to use to notify about disconnected peers.
 * @param cbcls Closure for cb.
 */
static void
tree_mark_peers_disconnected (struct MeshTunnelTree *tree,
                              struct MeshTunnelTreeNode *parent,
                              MeshTreeCallback cb, void *cbcls)
{
  struct GNUNET_PeerIdentity *pi;
  struct GNUNET_PeerIdentity id;
  struct MeshTunnelTreeNode *n;

  for (n = parent->children_head; NULL != n; n = n->next)
  {
    tree_mark_peers_disconnected (tree, n, cb, cbcls);
  }
  if (MESH_PEER_READY == parent->status)
  {
    if (NULL != cb)
      cb (cbcls, parent->peer);
    parent->status = MESH_PEER_RECONNECTING;
  }

  /* Remove and free info about first hop */
  GNUNET_PEER_resolve (parent->peer, &id);
  pi = GNUNET_CONTAINER_multihashmap_get (tree->first_hops, &id.hashPubKey);
  GNUNET_CONTAINER_multihashmap_remove_all (tree->first_hops, &id.hashPubKey);
  if (NULL != pi)
    GNUNET_free (pi);
}


/**
 * Iterate over all children of the local node.
 *
 * @param tree Tree to use. Must have "me" set.
 * @param cb Callback to call over each child.
 * @param cls Closure.
 */
void
tree_iterate_children (struct MeshTunnelTree *tree, MeshTreeCallback cb,
                       void *cls)
{
  struct MeshTunnelTreeNode *n;

  if (NULL == tree->me)
  {
    GNUNET_break (0);
    return;
  }
  for (n = tree->me->children_head; NULL != n; n = n->next)
  {
    cb (cls, n->peer);
  }
}


/**
 * Recusively update the info about what is the first hop to reach the node
 *
 * @param tree Tree this nodes belongs to.
 * @param parent_id Short ID from node form which to start updating.
 * @param hop If known, ID of the first hop.
 *            If not known, NULL to find out and pass on children.
 */
void
tree_update_first_hops (struct MeshTunnelTree *tree, GNUNET_PEER_Id parent_id,
                        struct GNUNET_PeerIdentity *hop)
{
  tree_node_update_first_hops (tree, tree_find_peer (tree, parent_id), hop);
}


/**
 * Delete the current path to the peer, including all now unused relays.
 * The destination peer is NOT destroyed, it is returned in order to either set
 * a new path to it or destroy it explicitly, taking care of it's child nodes.
 *
 * @param t Tunnel tree where to delete the path from.
 * @param peer_id Short ID of the destination peer whose path we want to remove.
 * @param cb Callback to use to notify about disconnected peers.
 * @param cbcls Closure for cb.
 *
 * @return pointer to the pathless node.
 *         NULL when not found
 */
struct MeshTunnelTreeNode *
tree_del_path (struct MeshTunnelTree *t, GNUNET_PEER_Id peer_id,
               MeshTreeCallback cb, void *cbcls)
{
  struct MeshTunnelTreeNode *parent;
  struct MeshTunnelTreeNode *node;
  struct MeshTunnelTreeNode *n;

#if MESH_TREE_DEBUG
  struct GNUNET_PeerIdentity id;

  GNUNET_PEER_resolve (peer_id, &id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tree:   Deleting path to %s.\n",
              GNUNET_i2s (&id));
#endif
  if (peer_id == t->root->peer)
    return NULL;

  for (n = t->disconnected_head; NULL != n; n = n->next)
  {
    if (n->peer == peer_id)
    {
      /* Was already pathless, waiting for reconnection */
      GNUNET_CONTAINER_DLL_remove (t->disconnected_head, t->disconnected_tail,
                                   n);
      return n;
    }
  }
  n = tree_find_peer (t, peer_id);
  if (NULL == n)
    return NULL;
  node = n;

  parent = n->parent;
  GNUNET_CONTAINER_DLL_remove (parent->children_head, parent->children_tail, n);
  n->parent = NULL;

  while (MESH_PEER_RELAY == parent->status && NULL == parent->children_head)
  {
#if MESH_TREE_DEBUG
    GNUNET_PEER_resolve (parent->peer, &id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tree:   Deleting node %s.\n",
                GNUNET_i2s (&id));
#endif
    n = parent->parent;
    tree_node_destroy (parent);
    parent = n;
  }
#if MESH_TREE_DEBUG
  GNUNET_PEER_resolve (parent->peer, &id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tree:   Not deleted peer %s.\n",
              GNUNET_i2s (&id));
#endif

  tree_mark_peers_disconnected (t, node, cb, cbcls);

  return node;
}


/**
 * Return a newly allocated individual path to reach a peer from the local peer,
 * according to the path tree of some tunnel.
 *
 * @param t Tunnel from which to read the path tree.
 * @param peer Short ID of the destination peer to whom we want a path.
 *
 * @return A newly allocated individual path to reach the destination peer.
 *         Path must be destroyed afterwards.
 */
struct MeshPeerPath *
tree_get_path_to_peer (struct MeshTunnelTree *t, GNUNET_PEER_Id peer)
{
  struct MeshTunnelTreeNode *n;
  struct MeshPeerPath *p;

  n = tree_find_peer (t, peer);
  if (NULL == n)
  {
    GNUNET_break (0);
    return NULL;
  }
  p = path_new (0);

  /* Building the path (inverted!) */
  while (n->peer != 1)
  {
    GNUNET_array_append (p->peers, p->length, n->peer);
    GNUNET_PEER_change_rc (n->peer, 1);
    n = n->parent;
    if (NULL == n)
    {
      GNUNET_break (0);
      path_destroy (p);
      return NULL;
    }
  }
  GNUNET_array_append (p->peers, p->length, 1);
  GNUNET_PEER_change_rc (1, 1);

  path_invert (p);

  return p;
}



/**
 * Integrate a stand alone path into the tunnel tree.
 * If the peer toward which the new path is already in the tree, the peer
 * and its children will be maked as disconnected and the callback
 * will be called on each one of them. They will be maked as online only after
 * receiving a PATH ACK for the new path for each one of them, so the caller
 * should take care of sending a new CREATE PATH message for each disconnected
 * peer.
 *
 * @param t Tunnel where to add the new path.
 * @param p Path to be integrated.
 * @param cb Callback to use to notify about peers temporarily disconnecting.
 * @param cbcls Closure for cb.
 *
 * @return GNUNET_OK in case of success.
 *         GNUNET_SYSERR in case of error.
 *
 * TODO: optimize
 * - go backwards on path looking for each peer in the present tree
 * - do not disconnect peers until new path is created & connected
 */
int
tree_add_path (struct MeshTunnelTree *t, const struct MeshPeerPath *p,
               MeshTreeCallback cb, void *cbcls)
{
  struct MeshTunnelTreeNode *parent;
  struct MeshTunnelTreeNode *oldnode;
  struct MeshTunnelTreeNode *n;
  struct MeshTunnelTreeNode *c;
  struct GNUNET_PeerIdentity id;
  int me;
  unsigned int i;

#if MESH_TREE_DEBUG
  GNUNET_PEER_resolve (p->peers[p->length - 1], &id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "tree:   Adding path [%u] towards peer %s.\n", p->length,
              GNUNET_i2s (&id));
#endif

  GNUNET_assert (0 != p->length);
  parent = n = t->root;
  if (n->peer != p->peers[0])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (1 == p->length)
    return GNUNET_OK;
  oldnode = tree_del_path (t, p->peers[p->length - 1], cb, cbcls);
  /* Look for the first node that is not already present in the tree
   *
   * Assuming that the tree is somewhat balanced, O(log n * log N).
   * - Length of the path is expected to be log N (size of whole network).
   * - Each level of the tree is expected to have log n children (size of tree).
   */
  me = t->root->peer == 1 ? 0 : -1;
  for (i = 1; i < p->length; i++)
  {
#if MESH_TREE_DEBUG
    GNUNET_PEER_resolve (p->peers[i], &id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tree:   Looking for peer %s.\n",
                GNUNET_i2s (&id));
#endif
    parent = n;
    if (p->peers[i] == 1)
      me = i;
    for (c = n->children_head; NULL != c; c = c->next)
    {
      if (c->peer == p->peers[i])
      {
#if MESH_TREE_DEBUG
        GNUNET_PEER_resolve (parent->peer, &id);
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "tree:   Found in children of %s.\n", GNUNET_i2s (&id));
#endif
        n = c;
        break;
      }
    }
    /*  If we couldn't find a child equal to path[i], we have reached the end
     * of the common path. */
    if (parent == n)
      break;
  }
#if MESH_TREE_DEBUG
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tree:   All childen visited.\n");
#endif
  /* Add the rest of the path as a branch from parent. */
  while (i < p->length)
  {
#if MESH_TREE_DEBUG
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tree:   Adding peer %u to %u.\n",
                p->peers[i], parent->peer);
    GNUNET_PEER_resolve (p->peers[i], &id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tree:   Adding peer %s.\n",
                GNUNET_i2s (&id));
    GNUNET_PEER_resolve (parent->peer, &id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tree:     to %s.\n",
                GNUNET_i2s (&id));
#endif

    if (i == p->length - 1 && NULL != oldnode)
    {
#if MESH_TREE_DEBUG
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "tree:   Putting old node into place.\n");
#endif
      oldnode->parent = parent;
      GNUNET_CONTAINER_DLL_insert (parent->children_head, parent->children_tail,
                                   oldnode);
      tree_node_update_first_hops (t, oldnode, NULL);
      n = oldnode;
    }
    else
    {
#if MESH_TREE_DEBUG
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tree:   Creating new node.\n");
#endif
      n = tree_node_new (parent, p->peers[i]);
      n->status = MESH_PEER_RELAY;
      if (n->peer == 1)
      {
        t->me = n;
        me = i;
      }
    }
    i++;
    parent = n;
  }
  n->status = MESH_PEER_SEARCHING;

  GNUNET_break (-1 != me);

  /* Add info about first hop into hashmap. */
  if (-1 != me && me < p->length - 1)
  {
#if MESH_TREE_DEBUG
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "MESH:   finding first hop (own pos %d/%u)\n", me,
                p->length - 1);
#endif
    GNUNET_PEER_resolve (p->peers[me + 1], &id);
    tree_update_first_hops (t, p->peers[me + 1], &id);
  }
#if MESH_TREE_DEBUG
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "MESH:   was last in path, not updating first hops (%d/%u)\n",
                me, p->length - 1);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tree:   New node added.\n");
#endif
  if (NULL == t->me)
    t->me = tree_find_peer (t, 1);
  return GNUNET_OK;
}


/**
 * Notifies a tree that a connection it might be using is broken.
 * Marks all peers down the paths as disconnected and notifies the client.
 *
 * @param t Tree to use.
 * @param p1 Short id of one of the peers (order unimportant)
 * @param p2 Short id of one of the peers (order unimportant)
 * @param cb Function to call for every peer that is marked as disconnected.
 * @param cbcls Closure for cb.
 *
 * @return Short ID of the first disconnected peer in the tree.
 */
GNUNET_PEER_Id
tree_notify_connection_broken (struct MeshTunnelTree *t, GNUNET_PEER_Id p1,
                               GNUNET_PEER_Id p2, MeshTreeCallback cb,
                               void *cbcls)
{
  struct MeshTunnelTreeNode *n;
  struct MeshTunnelTreeNode *c;

  n = tree_find_peer (t, p1);
  if (NULL == n)
    return 0;
  if (NULL != n->parent && n->parent->peer == p2)
  {
    tree_mark_peers_disconnected (t, n, cb, cbcls);
    GNUNET_CONTAINER_DLL_remove (n->parent->children_head,
                                 n->parent->children_tail, n);
    GNUNET_CONTAINER_DLL_insert (t->disconnected_head, t->disconnected_tail, n);
    return p1;
  }
  for (c = n->children_head; NULL != c; c = c->next)
  {
    if (c->peer == p2)
    {
      tree_mark_peers_disconnected (t, c, cb, cbcls);
      GNUNET_CONTAINER_DLL_remove (n->children_head, n->children_tail, c);
      GNUNET_CONTAINER_DLL_insert (t->disconnected_head, t->disconnected_tail,
                                   c);
      return p2;
    }
  }
  return 0;
}


/**
 * Deletes a peer from a tunnel, liberating all unused resources on the path to
 * it. It shouldn't have children, if it has they will be destroyed as well.
 * If the tree is not local and no longer has any paths, the root node will be
 * destroyed and marked as NULL.
 *
 * @param t Tunnel tree to use.
 * @param peer Short ID of the peer to remove from the tunnel tree.
 * @param cb Callback to notify client of disconnected peers.
 * @param cbcls Closure for cb.
 *
 * @return GNUNET_OK or GNUNET_SYSERR
 */
int
tree_del_peer (struct MeshTunnelTree *t, GNUNET_PEER_Id peer,
               MeshTreeCallback cb, void *cbcls)
{
  struct MeshTunnelTreeNode *n;

  n = tree_del_path (t, peer, cb, cbcls);
  if (NULL == n)
  {
    GNUNET_break (0);
    return GNUNET_YES;
  }
  GNUNET_break_op (NULL == n->children_head);
  tree_node_destroy (n);
  if (NULL == t->root->children_head && t->me != t->root)
  {
    tree_node_destroy (t->root);
    t->root = NULL;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}



/**
 * Get the cost of the path relative to the already built tunnel tree.
 *
 * @param t The tunnel tree to which compare.
 * @param path The individual path to reach a peer. It has to start at the
 *             root of the tree to be comparable.
 *
 * @return Number of hops to reach destination, UINT_MAX in case the peer is not
 *         in the path.
 *
 * TODO: adapt to allow any start / root combination
 * TODO: take in account state of the nodes
 */
unsigned int
tree_get_path_cost (struct MeshTunnelTree *t, struct MeshPeerPath *path)
{
  struct MeshTunnelTreeNode *n;
  struct MeshTunnelTreeNode *p;
  unsigned int i;
  unsigned int l;

  l = path_get_length (path);
  p = t->root;
  if (t->root->peer != path->peers[0])
  {
    GNUNET_break (0);
    return UINT_MAX;
  }
  for (i = 1; i < l; i++)
  {
    for (n = p->children_head; NULL != n; n = n->next)
    {
      if (path->peers[i] == n->peer)
      {
        break;
      }
    }
    if (NULL == n)
      return l - i;
    p = n;
  }
  return l - i;
}


/**
 * Print the tree on stderr
 *
 * @param t The tree
 */
void
tree_debug (struct MeshTunnelTree *t)
{
  tree_node_debug (t->root, 0);
}


/**
 * Iterator over hash map peer entries and frees all data in it.
 * Used prior to destroying a hashmap. Makes you miss anonymous functions in C.
 *
 * @param cls closure
 * @param key current key code (will no longer contain valid data!!)
 * @param value value in the hash map (treated as void *)
 * @return GNUNET_YES if we should continue to iterate, GNUNET_NO if not.
 */
static int
iterate_free (void *cls, const GNUNET_HashCode * key, void *value)
{
  GNUNET_free (value);
  return GNUNET_YES;
}


/**
 * Destroy the whole tree and free all used memory and Peer_Ids
 *
 * @param t Tree to be destroyed
 */
void
tree_destroy (struct MeshTunnelTree *t)
{
#if MESH_TREE_DEBUG
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tree: Destroying tree\n");
#endif
  tree_node_destroy (t->root);
  GNUNET_CONTAINER_multihashmap_iterate (t->first_hops, &iterate_free, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (t->first_hops);
  GNUNET_free (t);
}
