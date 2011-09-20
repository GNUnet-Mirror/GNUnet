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


extern GNUNET_PEER_Id myid;
extern struct GNUNET_PeerIdentity my_full_id;


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
 * @param t The tunnel to use
 * @param peer The peerinfo of the peer we are trying to reach
 *
 * @return peerinfo of the peer who is the first hop in the tunnel
 *         NULL on error
 */
struct GNUNET_PeerIdentity *
path_get_first_hop (struct MeshTunnel *t, struct MeshPeerInfo *peer)
{
  struct GNUNET_PeerIdentity id;

  GNUNET_PEER_resolve (peer->id, &id);
  return GNUNET_CONTAINER_multihashmap_get (t->tree->first_hops,
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
 * @param t The tunnel to which compare
 * @param path The individual path to reach a peer
 *
 * @return Number of hops to reach destination, UINT_MAX in case the peer is not
 * in the path
 *
 * TODO: remove dummy implementation, look into the tunnel tree
 */
unsigned int
path_get_cost (struct MeshTunnel *t, struct MeshPeerPath *path)
{
  return path_get_length (path);
}


/**
 * Add the path to the peer and update the path used to reach it in case this
 * is the shortest.
 *
 * @param peer_info Destination peer to add the path to.
 * @param path New path to add. Last peer must be the peer in arg 1.
 *             Path will be either used of freed if already known.
 *
 * TODO: trim the part from origin to us? Add it as path to origin?
 */
void
path_add_to_peer (struct MeshPeerInfo *peer_info, struct MeshPeerPath *path)
{
  struct MeshPeerPath *aux;
  unsigned int l;
  unsigned int l2;

  if (NULL == peer_info || NULL == path)
  {
    GNUNET_break (0);
    return;
  }

  l = path_get_length (path);

  for (aux = peer_info->path_head; aux != NULL; aux = aux->next)
  {
    l2 = path_get_length (aux);
    if (l2 > l)
    {
      GNUNET_CONTAINER_DLL_insert_before (peer_info->path_head,
                                          peer_info->path_tail, aux, path);
    }
    else
    {
      if (l2 == l && memcmp(path->peers, aux->peers, l) == 0)
      {
        path_destroy(path);
        return;
      }
    }
  }
  GNUNET_CONTAINER_DLL_insert_tail (peer_info->path_head, peer_info->path_tail,
                                    path);
  return;
}


/**
 * Send keepalive packets for a peer
 *
 * @param cls unused
 * @param tc unused
 *
 * FIXME path
 */
void
path_refresh (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshTunnel *t = cls;

//   struct GNUNET_PeerIdentity id;

  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
  {
    return;
  }
  /* FIXME implement multicast keepalive. Just an empty multicast packet? */
//   GNUNET_PEER_resolve (path_get_first_hop (path->t, path->peer)->id, &id);
//   GNUNET_CORE_notify_transmit_ready (core_handle, 0, 0,
//                                      GNUNET_TIME_UNIT_FOREVER_REL, &id,
//                                      sizeof (struct GNUNET_MESH_ManipulatePath)
//                                      +
//                                      (path->path->length *
//                                       sizeof (struct GNUNET_PeerIdentity)),
//                                      &send_core_create_path,
//                                      t);
  t->path_refresh_task =
      GNUNET_SCHEDULER_add_delayed (t->tree->refresh, &path_refresh, t);
  return;
}



/**
 * Recursively find the given peer in the tree.
 *
 * @param t Tunnel where to look for the peer.
 * @param peer Peer to find
 *
 * @return Pointer to the node of the peer. NULL if not found.
 */
struct MeshTunnelPathNode *
tunnel_find_peer (struct MeshTunnelPathNode *root, GNUNET_PEER_Id peer_id)
{
  struct MeshTunnelPathNode *n;
  unsigned int i;

  if (root->peer == peer_id)
    return root;
  for (i = 0; i < root->nchildren; i++)
  {
    n = tunnel_find_peer (&root->children[i], peer_id);
    if (NULL != n)
      return n;
  }
  return NULL;
}


/**
 * Recusively mark peer and children as disconnected, notify client
 *
 * @param parent Node to be clean, potentially with children
 * @param nc Notification context to use to alert the client
 */
void
tunnel_mark_peers_disconnected (struct MeshTunnelPathNode *parent,
                                struct GNUNET_SERVER_NotificationContext *nc)
{
  struct GNUNET_MESH_PeerControl msg;
  unsigned int i;

  parent->status = MESH_PEER_RECONNECTING;
  for (i = 0; i < parent->nchildren; i++)
  {
    tunnel_mark_peers_disconnected (&parent->children[i], nc);
  }
  if (NULL == parent->t->client)
    return;
  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_LOCAL_PEER_DEL);
  msg.tunnel_id = htonl (parent->t->local_tid);
  GNUNET_PEER_resolve (parent->peer, &msg.peer);
  if (NULL == nc)
    return;
  GNUNET_SERVER_notification_context_unicast (nc, parent->t->client->handle,
                                              &msg.header, GNUNET_NO);
}




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
                 struct GNUNET_SERVER_NotificationContext *nc)
{
  struct MeshTunnelPathNode *parent;
  struct MeshTunnelPathNode *node;
  struct MeshTunnelPathNode *n;

  if (peer_id == t->tree->root->peer)
    return NULL;
  node = n = tunnel_find_peer (t->tree->me, peer_id);
  if (NULL == n)
    return NULL;
  parent = n->parent;
  n->parent = NULL;
  while (NULL != parent && MESH_PEER_RELAY == parent->status &&
         1 == parent->nchildren)
  {
    n = parent;
    GNUNET_free (parent->children);
    parent = parent->parent;
  }
  if (NULL == parent)
    return node;
  *n = parent->children[parent->nchildren - 1];
  parent->nchildren--;
  parent->children = GNUNET_realloc (parent->children, parent->nchildren);

  tunnel_mark_peers_disconnected (node, nc);

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
tunnel_get_path_to_peer(struct MeshTunnel *t, struct MeshPeerInfo *peer_info)
{
  struct MeshTunnelPathNode *n;
  struct MeshPeerPath *p;
  GNUNET_PEER_Id myid = t->tree->me->peer;

  n = tunnel_find_peer(t->tree->me, peer_info->id);
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
 * @param nc Notification context to alert clients of peers
 *           temporarily disconnected
 *
 * @return GNUNET_OK in case of success.
 *         GNUNET_SYSERR in case of error.
 *
 * TODO: optimize
 * - go backwards on path looking for each peer in the present tree
 * - do not disconnect peers until new path is created & connected
 */
int
tunnel_add_path (struct MeshTunnel *t, const struct MeshPeerPath *p)
{
  struct MeshTunnelPathNode *parent;
  struct MeshTunnelPathNode *oldnode;
  struct MeshTunnelPathNode *n;
  struct GNUNET_PeerIdentity id;
  struct GNUNET_PeerIdentity *hop;
  GNUNET_PEER_Id myid = t->tree->me->peer;
  int me;
  unsigned int i;
  unsigned int j;

  GNUNET_assert(0 != p->length);
  n = t->tree->root;
  if (n->peer != p->peers[0])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (1 == p->length)
    return GNUNET_OK;
  oldnode = tunnel_del_path (t, p->peers[p->length - 1], NULL);
  /* Look for the first node that is not already present in the tree
   *
   * Assuming that the tree is somewhat balanced, O(log n * log N).
   * - Length of the path is expected to be log N (size of whole network).
   * - Each level of the tree is expected to have log n children (size of tree).
   */
  for (i = 0, me = -1; i < p->length; i++)
  {
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
  if (-1 == me)
  {
    /* New path deviates from tree before reaching us. What happened? */
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  /* Add the rest of the path as a branch from parent. */
  while (i < p->length)
  {
    parent->nchildren++;
    parent->children = GNUNET_realloc (parent->children,
                                       parent->nchildren *
                                       sizeof(struct MeshTunnelPathNode));
    n = &parent->children[parent->nchildren - 1];
    if (i == p->length - 1 && NULL != oldnode)
    {
      /* Assignation and free can be misleading, using explicit mempcy */
      memcpy (n, oldnode, sizeof (struct MeshTunnelPathNode));
      GNUNET_free (oldnode);
    }
    else
    {
      n->t = t;
      n->status = MESH_PEER_RELAY;
      n->peer = p->peers[i];
    }
    n->parent = parent;
    i++;
    parent = n;
  }

  /* Add info about first hop into hashmap. */
  if (me < p->length - 1)
  {
    GNUNET_PEER_resolve (p->peers[p->length - 1], &id);
    hop = GNUNET_malloc(sizeof(struct GNUNET_PeerIdentity));
    GNUNET_PEER_resolve (p->peers[me + 1], hop);
    GNUNET_CONTAINER_multihashmap_put (t->tree->first_hops, &id.hashPubKey,
                                       hop,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  }
  return GNUNET_OK;
}


/**
 * Add a peer to a tunnel, accomodating paths accordingly and initializing all
 * needed rescources.
 *
 * @param t Tunnel we want to add a new peer to
 * @param peer PeerInfo of the peer being added
 *
 */
void
tunnel_add_peer (struct MeshTunnel *t, struct MeshPeerInfo *peer)
{
  struct MeshPeerPath *p;
  struct MeshPeerPath *best_p;
  unsigned int best_cost;
  unsigned int cost;

  GNUNET_array_append (peer->tunnels, peer->ntunnels, t);
  if (NULL == (p = peer->path_head))
    return;

  best_p = p;
  best_cost = UINT_MAX;
  while (NULL != p)
  {
    if ((cost = path_get_cost (t, p)) < best_cost)
    {
      best_cost = cost;
      best_p = p;
    }
    p = p->next;
  }
  tunnel_add_path (t, best_p);
  if (GNUNET_SCHEDULER_NO_TASK == t->path_refresh_task)
    t->path_refresh_task =
        GNUNET_SCHEDULER_add_delayed (t->tree->refresh, &path_refresh, t);
}
