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


static void
debug_node(struct MeshTunnelTreeNode *n, uint16_t level)
{
  uint16_t i;

  for (i = 0; i < level; i++)
    fprintf(stderr, " ");
  fprintf(stderr, "%u\n", n->peer);
  for (i = 0; i < n->nchildren; i++)
    debug_node(&n->children[i], level + 1);
}



void
tree_debug(struct MeshTunnelTree *t)
{
  debug_node(t->root, 0);
}



/**
 * Invert the path
 *
 * @param p the path to invert
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
 * Destroy the path and free any allocated resources linked to it
 *
 * @param p the path to destroy
 *
 * @return GNUNET_OK on success
 */
int
path_destroy (struct MeshPeerPath *p)
{
  GNUNET_PEER_decrement_rcs (p->peers, p->length);
  GNUNET_free (p->peers);
  GNUNET_free (p);
  return GNUNET_OK;
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
path_get_first_hop (struct MeshTunnelTree *t, GNUNET_PEER_Id peer)
{
  struct GNUNET_PeerIdentity id;

  GNUNET_PEER_resolve (peer, &id);
  return GNUNET_CONTAINER_multihashmap_get (t->first_hops,
                                            &id.hashPubKey);
}


/**
 * Get the length of a path
 *
 * @param path The path to measure, with the local peer at any point of it
 *
 * @return Number of hops to reach destination
 *         UINT_MAX in case the peer is not in the path
 */
unsigned int
path_get_length (struct MeshPeerPath *path)
{
  if (NULL == path)
    return UINT_MAX;
  return path->length;
}


/**
 * Get the cost of the path relative to the already built tunnel tree
 *
 * @param t The tunnel tree to which compare
 * @param path The individual path to reach a peer
 *
 * @return Number of hops to reach destination, UINT_MAX in case the peer is not
 * in the path
 *
 * TODO: remove dummy implementation, look into the tunnel tree
 */
unsigned int
path_get_cost (struct MeshTunnelTree *t, struct MeshPeerPath *path)
{
  return path_get_length (path);
}


/**
 * Recursively find the given peer in the tree.
 *
 * @param t Tunnel where to look for the peer.
 * @param peer Peer to find
 *
 * @return Pointer to the node of the peer. NULL if not found.
 */
struct MeshTunnelTreeNode *
tree_find_peer (struct MeshTunnelTreeNode *root, GNUNET_PEER_Id peer_id)
{
  struct MeshTunnelTreeNode *n;
  unsigned int i;

  if (root->peer == peer_id)
    return root;
  for (i = 0; i < root->nchildren; i++)
  {
    n = tree_find_peer (&root->children[i], peer_id);
    if (NULL != n)
      return n;
  }
  return NULL;
}


/**
 * Recusively mark peer and children as disconnected, notify client
 *
 * @param tree Tree this node belongs to
 * @param parent Node to be clean, potentially with children
 * @param cb Callback to use to notify about disconnected peers.
 */
void
tree_mark_peers_disconnected (struct MeshTunnelTree *tree,
                              struct MeshTunnelTreeNode *parent,
                              MeshNodeDisconnectCB cb)
{
  struct GNUNET_PeerIdentity *pi;
  struct GNUNET_PeerIdentity id;
  unsigned int i;

  for (i = 0; i < parent->nchildren; i++)
  {
    tree_mark_peers_disconnected (tree, &parent->children[i], cb);
  }
  if (MESH_PEER_READY == parent->status)
  {
    cb (parent);
  }
  parent->status = MESH_PEER_RECONNECTING;
  
  /* Remove and free info about first hop */
  GNUNET_PEER_resolve(parent->peer, &id);
  pi = GNUNET_CONTAINER_multihashmap_get(tree->first_hops, &id.hashPubKey);
  GNUNET_CONTAINER_multihashmap_remove_all(tree->first_hops, &id.hashPubKey);
  if (NULL != pi)
    GNUNET_free(pi);
//   FIXME: add to service code on callback
//   struct GNUNET_MESH_PeerControl msg;
//   if (NULL == parent->t->client)
//     return;
//   msg.header.size = htons (sizeof (msg));
//   msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_DEL);
//   msg.tunnel_id = htonl (parent->t->local_tid);
//   GNUNET_PEER_resolve (parent->peer, &msg.peer);
//   if (NULL == nc)
//     return;
//   GNUNET_SERVER_notification_context_unicast (nc, parent->t->client->handle,
//                                               &msg.header, GNUNET_NO);
}


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
                        struct GNUNET_PeerIdentity *hop)
{
  struct GNUNET_PeerIdentity pi;
  struct GNUNET_PeerIdentity *copy;
  struct GNUNET_PeerIdentity id;
  unsigned int i;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "tree:   Finding first hop for %u.\n",
             parent->peer);
  if (NULL == hop)
  {
    struct MeshTunnelTreeNode *aux;
    struct MeshTunnelTreeNode *old;

    old = parent;
    aux = old->parent;
    while (aux != tree->me)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "tree:   ... its not %u.\n",
             old->peer);
      old = aux;
      aux = aux->parent;
      GNUNET_assert(NULL != aux);
    }
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "tree:   It's %u!!\n",
             old->peer);
    hop = &pi;
    GNUNET_PEER_resolve(old->peer, hop);
  }
  copy = GNUNET_malloc(sizeof(struct GNUNET_PeerIdentity));
  *copy = *hop;
  GNUNET_PEER_resolve(parent->peer, &id);
  GNUNET_CONTAINER_multihashmap_put(tree->first_hops, &id.hashPubKey, copy,
                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);

  for (i = 0; i < parent->nchildren; i++)
  {
    tree_update_first_hops (tree, &parent->children[i], hop);
  }
}


/**
 * Delete the current path to the peer, including all now unused relays.
 * The destination peer is NOT destroyed, it is returned in order to either set
 * a new path to it or destroy it explicitly, taking care of it's child nodes.
 *
 * @param t Tunnel tree where to delete the path from.
 * @param peer Destination peer whose path we want to remove.
 * @param cb Callback to use to notify about disconnected peers.
 *
 * @return pointer to the pathless node, NULL on error
 */
struct MeshTunnelTreeNode *
tree_del_path (struct MeshTunnelTree *t, GNUNET_PEER_Id peer_id,
                 MeshNodeDisconnectCB cb)
{
  struct MeshTunnelTreeNode *parent;
  struct MeshTunnelTreeNode *node;
  struct MeshTunnelTreeNode *n;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "tree:   Deleting path to %u.\n", peer_id);
  if (peer_id == t->root->peer)
    return NULL;
  n = tree_find_peer (t->me, peer_id);
  if (NULL == n)
    return NULL;
  node = GNUNET_malloc(sizeof(struct MeshTunnelTreeNode));
  *node = *n;
  parent = n->parent;
  parent->nchildren--;
  n->parent = NULL;
  *n = parent->children[parent->nchildren];
  parent->children = GNUNET_realloc(parent->children,
                                    parent->nchildren
                                    * sizeof(struct MeshTunnelTreeNode));
  while (t->root != parent && MESH_PEER_RELAY == parent->status &&
         0 == parent->nchildren)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "tree:   Deleting node %u.\n", parent->peer);
    n = parent->parent;
    tree_node_destroy(parent);
    parent = n;
  }

  tree_mark_peers_disconnected (t, node, cb);

  return node;
}


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
tree_get_path_to_peer(struct MeshTunnelTree *t, GNUNET_PEER_Id peer)
{
  struct MeshTunnelTreeNode *n;
  struct MeshPeerPath *p;
  GNUNET_PEER_Id myid = t->me->peer;

  n = tree_find_peer(t->me, peer);
  p = GNUNET_malloc(sizeof(struct MeshPeerPath));

  /* Building the path (inverted!) */
  while (n->peer != myid)
  {
    GNUNET_array_append(p->peers, p->length, n->peer);
    GNUNET_PEER_change_rc(n->peer, 1);
    n = n->parent;
    GNUNET_assert(NULL != n);
  }
  GNUNET_array_append(p->peers, p->length, myid);
  GNUNET_PEER_change_rc(myid, 1);

  path_invert(p);

  return p;
}


/**
 * Integrate a stand alone path into the tunnel tree.
 *
 * @param t Tunnel where to add the new path.
 * @param p Path to be integrated.
 * @param cb Callback to use to notify about peers temporarily disconnecting
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
                 MeshNodeDisconnectCB cb)
{
  struct MeshTunnelTreeNode *parent;
  struct MeshTunnelTreeNode *oldnode;
  struct MeshTunnelTreeNode *n;
  struct GNUNET_PeerIdentity id;
  struct GNUNET_PeerIdentity *hop;
  GNUNET_PEER_Id myid = t->me->peer;
  int me;
  unsigned int i;
  unsigned int j;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "tree:   Adding path [%u] towards peer %u to peer %u.\n",
             p->length,
             p->peers[p->length - 1],
             t->me->peer);
  GNUNET_assert(0 != p->length);
  parent = n = t->root;
  if (n->peer != p->peers[0])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (1 == p->length)
    return GNUNET_OK;
  oldnode = tree_del_path (t, p->peers[p->length - 1], cb);
  /* Look for the first node that is not already present in the tree
   *
   * Assuming that the tree is somewhat balanced, O(log n * log N).
   * - Length of the path is expected to be log N (size of whole network).
   * - Each level of the tree is expected to have log n children (size of tree).
   */
  me = t->root->peer == myid ? 0 : -1;
  for (i = 1; i < p->length; i++)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "tree:   Looking for peer %u.\n",
             p->peers[i]);
    parent = n;
    if (p->peers[i] == myid)
      me = i;
    for (j = 0; j < n->nchildren; j++)
    {
      if (n->children[j].peer == p->peers[i])
      {
        n = &n->children[j];
        break;
      }
    }
    /*  If we couldn't find a child equal to path[i], we have reached the end
     * of the common path. */
    if (parent == n)
      break;
  }
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "tree:   All childen visited.\n");
  if (-1 == me)
  {
    /* New path deviates from tree before reaching us. What happened? */
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  /* Add the rest of the path as a branch from parent. */
  while (i < p->length)
  {
    GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
               "tree:   Adding  peer %u, to %u.\n",
               p->peers[i],
               parent->peer);
    parent->nchildren++;
    parent->children = GNUNET_realloc (parent->children,
                                       parent->nchildren *
                                       sizeof(struct MeshTunnelTreeNode));
    n = &parent->children[parent->nchildren - 1];
    n->parent = parent;
    if (i == p->length - 1 && NULL != oldnode)
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "tree:   Putting old node into place.\n");
      /* Assignation and free can be misleading, using explicit mempcy */
      memcpy (n, oldnode, sizeof (struct MeshTunnelTreeNode));
      n->parent = parent;
      GNUNET_free (oldnode);
      for (j = 0; j < n->nchildren; j++)
      {
        n->children[j].parent = n;
        tree_update_first_hops (t, &n->children[j], NULL);
      }
    }
    else
    {
      GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "tree:   Creating new node.\n");
      n->t = t->t;
      n->status = MESH_PEER_RELAY;
      n->peer = p->peers[i];
      n->nchildren = 0;
      n->children = NULL;
    }
    i++;
    parent = n;
  }
  n->status = MESH_PEER_SEARCHING;

  /* Add info about first hop into hashmap. */
  if (me < p->length - 1)
  {
    GNUNET_PEER_resolve (p->peers[p->length - 1], &id);
    hop = GNUNET_CONTAINER_multihashmap_get(t->first_hops, &id.hashPubKey);
    if (NULL != hop)
      GNUNET_free(hop);
    hop = GNUNET_malloc(sizeof(struct GNUNET_PeerIdentity));
    GNUNET_PEER_resolve (p->peers[me + 1], hop);
    GNUNET_CONTAINER_multihashmap_put (t->first_hops, &id.hashPubKey,
                                       hop,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "tree:   New node added.\n");
  return GNUNET_OK;
}


/**
 * Destroy the node and all children
 * 
 * @param n Parent node to be destroyed
 */
void
tree_node_destroy (struct MeshTunnelTreeNode *n)
{
  struct MeshTunnelTreeNode *parent;
  unsigned int i;

  if (n->nchildren != 0)
  {
    for (i = 0; i < n->nchildren; i++)
    {
      tree_node_destroy(&n->children[i]);
    }
    if (n->children != NULL)
      GNUNET_free(n->children);
  }
  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "tree:   Destroying node %u.\n", n->peer);
  if (NULL == (parent = n->parent))
    return;
  i = (n - parent->children) / sizeof(struct MeshTunnelTreeNode);
  parent->children[i] = parent->children[parent->nchildren - 1];
  parent->nchildren--;
  parent->children = realloc(parent->children,
                             parent->nchildren
                             * sizeof(struct MeshTunnelTreeNode));

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG, "tree:   Destroyed.\n");
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
  GNUNET_free(value);
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
  tree_node_destroy(t->root);
  GNUNET_free(t->root);
  GNUNET_CONTAINER_multihashmap_iterate(t->first_hops, &iterate_free, NULL);
  GNUNET_CONTAINER_multihashmap_destroy(t->first_hops);
}