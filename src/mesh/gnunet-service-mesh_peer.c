/*
     This file is part of GNUnet.
     (C) 2013 Christian Grothoff (and other contributing authors)

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


#include "platform.h"
#include "gnunet_util_lib.h"

#include "gnunet-service-mesh_peer.h"
#include "gnunet-service-mesh_dht.h"
#include "mesh_path.h"

/******************************************************************************/
/********************************   STRUCTS  **********************************/
/******************************************************************************/

/**
 * Struct containing all information regarding a given peer
 */
struct MeshPeer
{
    /**
     * ID of the peer
     */
  GNUNET_PEER_Id id;

    /**
     * Last time we heard from this peer
     */
  struct GNUNET_TIME_Absolute last_contact;

    /**
     * Paths to reach the peer, ordered by ascending hop count
     */
  struct MeshPeerPath *path_head;

    /**
     * Paths to reach the peer, ordered by ascending hop count
     */
  struct MeshPeerPath *path_tail;

    /**
     * Handle to stop the DHT search for paths to this peer
     */
  struct GNUNET_DHT_GetHandle *dhtget;

    /**
     * Tunnel to this peer, if any.
     */
  struct MeshTunnel2 *tunnel;

    /**
     * Connections that go through this peer, indexed by tid;
     */
  struct GNUNET_CONTAINER_MultiHashMap *connections;

    /**
     * Handle for queued transmissions
     */
  struct GNUNET_CORE_TransmitHandle *core_transmit;

  /**
   * Transmission queue to core DLL head
   */
  struct MeshPeerQueue *queue_head;
  
  /**
   * Transmission queue to core DLL tail
   */
  struct MeshPeerQueue *queue_tail;

  /**
   * How many messages are in the queue to this peer.
   */
  unsigned int queue_n;
};


/******************************************************************************/
/*******************************   GLOBALS  ***********************************/
/******************************************************************************/

/**
 * Peers known, indexed by PeerIdentity (MeshPeer).
 */
static struct GNUNET_CONTAINER_MultiPeerMap *peers;

/**
 * How many peers do we want to remember?
 */
static unsigned long long max_peers;


/******************************************************************************/
/********************************   STATIC  ***********************************/
/******************************************************************************/

/**
 * Iterator over tunnel hash map entries to destroy the tunnel during shutdown.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to iterate,
 *         #GNUNET_NO if not.
 */
static int
shutdown_tunnel (void *cls, 
                 const struct GNUNET_PeerIdentity *key, 
                 void *value)
{
  struct MeshPeer *p = value;
  struct MeshTunnel2 *t = p->tunnel;

  if (NULL != t)
    GMT_destroy (t);
  return GNUNET_YES;
}



/**
 * Destroy the peer_info and free any allocated resources linked to it
 *
 * @param peer The peer_info to destroy.
 *
 * @return GNUNET_OK on success
 */
static int
peer_destroy (struct MeshPeer *peer)
{
  struct GNUNET_PeerIdentity id;
  struct MeshPeerPath *p;
  struct MeshPeerPath *nextp;
  
  GNUNET_PEER_resolve (peer->id, &id);
  GNUNET_PEER_change_rc (peer->id, -1);
  
  if (GNUNET_YES !=
    GNUNET_CONTAINER_multipeermap_remove (peers, &id, peer))
  {
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "removing peer %s, not in peermap\n", GNUNET_i2s (&id));
  }
    if (NULL != peer->dhtget)
    {
      GNUNET_DHT_get_stop (peer->dhtget);
    }
      p = peer->path_head;
      while (NULL != p)
      {
        nextp = p->next;
        GNUNET_CONTAINER_DLL_remove (peer->path_head, peer->path_tail, p);
        path_destroy (p);
        p = nextp;
      }
        tunnel_destroy_empty (peer->tunnel);
        GNUNET_free (peer);
        return GNUNET_OK;
}


/**
 * Returns if peer is used (has a tunnel, is neighbor).
 *
 * @peer Peer to check.
 *
 * @return GNUNET_YES if peer is in use.
 */
static int
peer_is_used (struct MeshPeer *peer)
{
  struct MeshPeerPath *p;
  
  if (NULL != peer->tunnel)
    return GNUNET_YES;
  
  for (p = peer->path_head; NULL != p; p = p->next)
  {
    if (p->length < 3)
      return GNUNET_YES;
  }
    return GNUNET_NO;
}


/**
 * Iterator over all the peers to get the oldest timestamp.
 *
 * @param cls Closure (unsued).
 * @param key ID of the peer.
 * @param value Peer_Info of the peer.
 */
static int
peer_get_oldest (void *cls,
                 const struct GNUNET_PeerIdentity *key,
                 void *value)
{
  struct MeshPeer *p = value;
  struct GNUNET_TIME_Absolute *abs = cls;
  
  /* Don't count active peers */
  if (GNUNET_YES == peer_is_used (p))
    return GNUNET_YES;
  
  if (abs->abs_value_us < p->last_contact.abs_value_us)
    abs->abs_value_us = p->last_contact.abs_value_us;
  
  return GNUNET_YES;
}


/**
 * Iterator over all the peers to remove the oldest entry.
 *
 * @param cls Closure (unsued).
 * @param key ID of the peer.
 * @param value Peer_Info of the peer.
 */
static int
peer_timeout (void *cls,
              const struct GNUNET_PeerIdentity *key,
              void *value)
{
  struct MeshPeer *p = value;
  struct GNUNET_TIME_Absolute *abs = cls;
  
  if (p->last_contact.abs_value_us == abs->abs_value_us &&
    GNUNET_NO == peer_is_used (p))
  {
    peer_destroy (p);
    return GNUNET_NO;
  }
    return GNUNET_YES;
}


/**
 * Delete oldest unused peer.
 */
static void
peer_delete_oldest (void)
{
  struct GNUNET_TIME_Absolute abs;
  
  abs = GNUNET_TIME_UNIT_FOREVER_ABS;
  
  GNUNET_CONTAINER_multipeermap_iterate (peers,
                                         &peer_get_oldest,
                                         &abs);
  GNUNET_CONTAINER_multipeermap_iterate (peers,
                                         &peer_timeout,
                                         &abs);
}


/**
 * Retrieve the MeshPeer stucture associated with the peer, create one
 * and insert it in the appropriate structures if the peer is not known yet.
 *
 * @param peer Full identity of the peer.
 *
 * @return Existing or newly created peer info.
 */
static struct MeshPeer *
peer_get (const struct GNUNET_PeerIdentity *peer_id)
{
  struct MeshPeer *peer;
  
  peer = GNUNET_CONTAINER_multipeermap_get (peers, peer_id);
  if (NULL == peer)
  {
    peer = GNUNET_new (struct MeshPeer);
    if (GNUNET_CONTAINER_multipeermap_size (peers) > max_peers)
    {
      peer_delete_oldest ();
    }
        GNUNET_CONTAINER_multipeermap_put (peers, peer_id, peer,
                                           GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
        peer->id = GNUNET_PEER_intern (peer_id);
  }
    peer->last_contact = GNUNET_TIME_absolute_get();
    
    return peer;
}


/**
 * Retrieve the MeshPeer stucture associated with the peer, create one
 * and insert it in the appropriate structures if the peer is not known yet.
 *
 * @param peer Short identity of the peer.
 *
 * @return Existing or newly created peer info.
 */
static struct MeshPeer *
peer_get_short (const GNUNET_PEER_Id peer)
{
  return peer_get (GNUNET_PEER_resolve2 (peer));
}


/**
 * Get a cost of a path for a peer considering existing tunnel connections.
 *
 * @param peer Peer towards which the path is considered.
 * @param path Candidate path.
 *
 * @return Cost of the path (path length + number of overlapping nodes)
 */
static unsigned int
peer_get_path_cost (const struct MeshPeer *peer,
                    const struct MeshPeerPath *path)
{
  struct MeshConnection *c;
  unsigned int overlap;
  unsigned int i;
  unsigned int j;
  
  if (NULL == path)
    return 0;
  
  overlap = 0;
  GNUNET_assert (NULL != peer->tunnel);
  
  for (i = 0; i < path->length; i++)
  {
    for (c = peer->tunnel->connection_head; NULL != c; c = c->next)
    {
      for (j = 0; j < c->path->length; j++)
      {
        if (path->peers[i] == c->path->peers[j])
        {
          overlap++;
          break;
        }
      }
    }
  }
    return (path->length + overlap) * (path->score * -1);
}


/**
 * Choose the best path towards a peer considering the tunnel properties.
 *
 * @param peer The destination peer.
 *
 * @return Best current known path towards the peer, if any.
 */
static struct MeshPeerPath *
peer_get_best_path (const struct MeshPeer *peer)
{
  struct MeshPeerPath *best_p;
  struct MeshPeerPath *p;
  struct MeshConnection *c;
  unsigned int best_cost;
  unsigned int cost;
  
  best_cost = UINT_MAX;
  best_p = NULL;
  for (p = peer->path_head; NULL != p; p = p->next)
  {
    for (c = peer->tunnel->connection_head; NULL != c; c = c->next)
      if (c->path == p)
        break;
      if (NULL != c)
        continue; /* If path is in use in a connection, skip it. */
        
            if ((cost = peer_get_path_cost (peer, p)) < best_cost)
            {
              best_cost = cost;
              best_p = p;
            }
  }
    return best_p;
}


/**
 * Add the path to the peer and update the path used to reach it in case this
 * is the shortest.
 *
 * @param peer_info Destination peer to add the path to.
 * @param path New path to add. Last peer must be the peer in arg 1.
 *             Path will be either used of freed if already known.
 * @param trusted Do we trust that this path is real?
 */
void
peer_add_path (struct MeshPeer *peer_info, struct MeshPeerPath *path,
               int trusted)
{
  struct MeshPeerPath *aux;
  unsigned int l;
  unsigned int l2;
  
  if ((NULL == peer_info) || (NULL == path))
  {
    GNUNET_break (0);
    path_destroy (path);
    return;
  }
    if (path->peers[path->length - 1] != peer_info->id)
    {
      GNUNET_break (0);
      path_destroy (path);
      return;
    }
      if (2 >= path->length && GNUNET_NO == trusted)
      {
        /* Only allow CORE to tell us about direct paths */
        path_destroy (path);
        return;
      }
        for (l = 1; l < path->length; l++)
        {
          if (path->peers[l] == myid)
          {
            GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "shortening path by %u\n", l);
            for (l2 = 0; l2 < path->length - l; l2++)
            {
              path->peers[l2] = path->peers[l + l2];
            }
                  path->length -= l;
                  l = 1;
                  path->peers =
                            GNUNET_realloc (path->peers, path->length * sizeof (GNUNET_PEER_Id));
          }
        }
        
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "adding path [%u] to peer %s\n",
                      path->length, peer2s (peer_info));
          
          l = path_get_length (path);
          if (0 == l)
          {
            path_destroy (path);
            return;
          }
          
            GNUNET_assert (peer_info->id == path->peers[path->length - 1]);
            for (aux = peer_info->path_head; aux != NULL; aux = aux->next)
            {
              l2 = path_get_length (aux);
              if (l2 > l)
              {
                GNUNET_CONTAINER_DLL_insert_before (peer_info->path_head,
                                                    peer_info->path_tail, aux, path);
                return;
              }
                  else
                  {
                    if (l2 == l && memcmp (path->peers, aux->peers, l) == 0)
                    {
                      path_destroy (path);
                      return;
                    }
                  }
            }
              GNUNET_CONTAINER_DLL_insert_tail (peer_info->path_head, peer_info->path_tail,
                                                path);
              return;
}


/**
 * Add the path to the origin peer and update the path used to reach it in case
 * this is the shortest.
 * The path is given in peer_info -> destination, therefore we turn the path
 * upside down first.
 *
 * @param peer_info Peer to add the path to, being the origin of the path.
 * @param path New path to add after being inversed.
 *             Path will be either used or freed.
 * @param trusted Do we trust that this path is real?
 */
static void
peer_add_path_to_origin (struct MeshPeer *peer_info,
                         struct MeshPeerPath *path, int trusted)
{
  if (NULL == path)
    return;
  path_invert (path);
  peer_add_path (peer_info, path, trusted);
}


/******************************************************************************/
/********************************    API    ***********************************/
/******************************************************************************/

/**
 * Initialize the peer subsystem.
 *
 * @param c Configuration.
 */
void
GMP_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  peers = GNUNET_CONTAINER_multipeermap_create (128, GNUNET_NO);
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "MESH", "MAX_PEERS",
                                             &max_peers))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_WARNING,
                               "MESH", "MAX_PEERS", "USING DEFAULT");
    max_peers = 1000;
  }
}

/**
 * Shut down the peer subsystem.
 */
void
GMP_shutdown (void)
{
  GNUNET_CONTAINER_multipeermap_iterate (peers, &shutdown_tunnel, NULL);
}


/**
 * Try to establish a new connection to this peer in the given tunnel.
 * If the peer doesn't have any path to it yet, try to get one.
 * If the peer already has some path, send a CREATE CONNECTION towards it.
 *
 * @param peer PeerInfo of the peer.
 */
void
GMP_connect (struct MeshPeer *peer)
{
  struct MeshTunnel2 *t;
  struct MeshPeerPath *p;
  struct MeshConnection *c;
  int rerun_dhtget;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "peer_connect towards %s\n",
              peer2s (peer));
  t = peer->tunnel;
  c = NULL;
  rerun_dhtget = GNUNET_NO;

  if (NULL != peer->path_head)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "path exists\n");
    p = peer_get_best_path (peer);
    if (NULL != p)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  %u hops\n", p->length);
      c = tunnel_use_path (t, p);
      if (NULL == c)
      {
        /* This case can happen when the path includes a first hop that is
         * not yet known to be connected.
         * 
         * This happens quite often during testing when running mesh
         * under valgrind: core connect notifications come very late and the
         * DHT result has already come and created a valid path.
         * In this case, the peer->connections hashmap will be NULL and
         * tunnel_use_path will not be able to create a connection from that
         * path.
         *
         * Re-running the DHT GET should give core time to callback.
         */
        GNUNET_break(0);
        rerun_dhtget = GNUNET_YES;
      }
      else
      {
        send_connection_create (c);
        return;
      }
    }
  }

  if (NULL != peer->dhtget && GNUNET_YES == rerun_dhtget)
  {
    GNUNET_DHT_get_stop (peer->dhtget);
    peer->dhtget = NULL;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  Stopping DHT GET for peer %s\n", peer2s (peer));
  }

  if (NULL == peer->dhtget)
  {
    const struct GNUNET_PeerIdentity *id;
    struct GNUNET_HashCode phash;

    id = GNUNET_PEER_resolve2 (peer->id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  Starting DHT GET for peer %s\n", peer2s (peer));
    GNUNET_CRYPTO_hash (&id, sizeof (struct GNUNET_PeerIdentity), &phash);
    peer->dhtget = GNUNET_DHT_get_start (dht_handle,    /* handle */
                                          GNUNET_BLOCK_TYPE_MESH_PEER, /* type */
                                          &phash,     /* key to search */
                                          dht_replication_level, /* replication level */
                                          GNUNET_DHT_RO_RECORD_ROUTE |
                                          GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
                                          NULL,       /* xquery */
                                          0,     /* xquery bits */
                                          &dht_get_id_handler, peer);
    if (MESH_TUNNEL_NEW == t->state)
      tunnel_change_state (t, MESH_TUNNEL_SEARCHING);
  }
}