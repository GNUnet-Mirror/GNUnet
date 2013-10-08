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
#include "gnunet-service-mesh_connection.h"
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
  struct GMD_search_handle *search_h;

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

/**
 * Percentage of messages that will be dropped (for test purposes only).
 */
static unsigned long long drop_percent;

/******************************************************************************/
/***************************** CORE CALLBACKS *********************************/
/******************************************************************************/


/**
  * Core callback to write a pre-constructed data packet to core buffer
  *
  * @param cls Closure (MeshTransmissionDescriptor with data in "data" member).
  * @param size Number of bytes available in buf.
  * @param buf Where the to write the message.
  *
  * @return number of bytes written to buf
  */
static size_t
send_core_data_raw (void *cls, size_t size, void *buf)
{
  struct GNUNET_MessageHeader *msg = cls;
  size_t total_size;

  GNUNET_assert (NULL != msg);
  total_size = ntohs (msg->size);

  if (total_size > size)
  {
    GNUNET_break (0);
    return 0;
  }
  memcpy (buf, msg, total_size);
  GNUNET_free (cls);
  return total_size;
}


/**
 * Function to send a create connection message to a peer.
 *
 * @param c Connection to create.
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
send_core_connection_create (struct MeshConnection *c, size_t size, void *buf)
{
  struct GNUNET_MESH_ConnectionCreate *msg;
  struct GNUNET_PeerIdentity *peer_ptr;
  struct MeshPeerPath *p = c->path;
  size_t size_needed;
  int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending CONNECTION CREATE...\n");
  size_needed =
      sizeof (struct GNUNET_MESH_ConnectionCreate) +
      p->length * sizeof (struct GNUNET_PeerIdentity);

  if (size < size_needed || NULL == buf)
  {
    GNUNET_break (0);
    return 0;
  }
  msg = (struct GNUNET_MESH_ConnectionCreate *) buf;
  msg->header.size = htons (size_needed);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_CONNECTION_CREATE);
  msg->cid = c->id;

  peer_ptr = (struct GNUNET_PeerIdentity *) &msg[1];
  for (i = 0; i < p->length; i++)
  {
    GNUNET_PEER_resolve (p->peers[i], peer_ptr++);
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "CONNECTION CREATE (%u bytes long) sent!\n", size_needed);
  return size_needed;
}


/**
 * Creates a path ack message in buf and frees all unused resources.
 *
 * @param c Connection to send an ACK on.
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 *
 * @return number of bytes written to buf
 */
static size_t
send_core_connection_ack (struct MeshConnection *c, size_t size, void *buf)
{
  struct GNUNET_MESH_ConnectionACK *msg = buf;
  struct MeshTunnel2 *t = c->t;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending CONNECTION ACK...\n");
  GNUNET_assert (NULL != t);
  if (sizeof (struct GNUNET_MESH_ConnectionACK) > size)
  {
    GNUNET_break (0);
    return 0;
  }
  msg->header.size = htons (sizeof (struct GNUNET_MESH_ConnectionACK));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_CONNECTION_ACK);
  msg->cid = c->id;
  msg->reserved = 0;

  /* TODO add signature */

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "CONNECTION ACK sent!\n");
  return sizeof (struct GNUNET_MESH_ConnectionACK);
}


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
    if (NULL != peer->search_h)
    {
      GMD_search_stop (peer->search_h);
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


/**
 * Adds a path to the peer_infos of all the peers in the path
 *
 * @param p Path to process.
 * @param confirmed Whether we know if the path works or not.
 */
static void
path_add_to_peers (struct MeshPeerPath *p, int confirmed)
{
  unsigned int i;

  /* TODO: invert and add */
  for (i = 0; i < p->length && p->peers[i] != myid; i++) /* skip'em */ ;
  for (i++; i < p->length; i++)
  {
    struct MeshPeer *aux;
    struct MeshPeerPath *copy;
    
    aux = peer_get_short (p->peers[i]);
    copy = path_duplicate (p);
    copy->length = i + 1;
    peer_add_path (aux, copy, p->length < 3 ? GNUNET_NO : confirmed);
  }
}


/**
 * Function to process paths received for a new peer addition. The recorded
 * paths form the initial tunnel, which can be optimized later.
 * Called on each result obtained for the DHT search.
 *
 * @param cls closure
 * @param path
 */
static void
search_handler (void *cls, struct MeshPeerPath *path)
{
  struct MeshPeer *peer = cls;
  unsigned int connection_count;

  path_add_to_peers (path, GNUNET_NO);

  /* Count connections */
  connection_count = GMC_count (peer->tunnel->connection_head);

  /* If we already have 3 (or more (?!)) connections, it's enough */
  if (3 <= connection_count)
    return;

  if (peer->tunnel->state == MESH_TUNNEL_SEARCHING)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " ... connect!\n");
    GMP_connect (peer);
  }
  return;
}


/**
 * Core callback to write a queued packet to core buffer
 *
 * @param cls Closure (peer info).
 * @param size Number of bytes available in buf.
 * @param buf Where the to write the message.
 *
 * @return number of bytes written to buf
 */
static size_t
queue_send (void *cls, size_t size, void *buf)
{
  struct MeshPeer *peer = cls;
  struct MeshFlowControl *fc;
  struct MeshConnection *c;
  struct GNUNET_MessageHeader *msg;
  struct MeshPeerQueue *queue;
  struct MeshTunnel2 *t;
  struct MeshChannel *ch;
  const struct GNUNET_PeerIdentity *dst_id;
  size_t data_size;
  uint32_t pid;
  uint16_t type;
  int fwd;

  peer->core_transmit = NULL;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "* Queue send (max %u)\n", size);

  if (NULL == buf || 0 == size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "* Buffer size 0.\n");
    return 0;
  }

  /* Initialize */
  queue = peer_get_first_message (peer);
  if (NULL == queue)
  {
    GNUNET_break (0); /* Core tmt_rdy should've been canceled */
    return 0;
  }
  c = queue->c;
  fwd = queue->fwd;
  fc = fwd ? &c->fwd_fc : &c->bck_fc;

  dst_id = GNUNET_PEER_resolve2 (peer->id);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   towards %s\n", GNUNET_i2s (dst_id));
  /* Check if buffer size is enough for the message */
  if (queue->size > size)
  {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   not enough room, reissue\n");
      peer->core_transmit =
          GNUNET_CORE_notify_transmit_ready (core_handle,
                                             GNUNET_NO,
                                             0,
                                             GNUNET_TIME_UNIT_FOREVER_REL,
                                             dst_id,
                                             queue->size,
                                             &queue_send,
                                             peer);
      return 0;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   size %u ok\n", queue->size);

  t = (NULL != c) ? c->t : NULL;
  type = 0;

  /* Fill buf */
  switch (queue->type)
  {
    case GNUNET_MESSAGE_TYPE_MESH_TUNNEL_DESTROY:
    case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_DESTROY:
    case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_BROKEN:
    case GNUNET_MESSAGE_TYPE_MESH_FWD:
    case GNUNET_MESSAGE_TYPE_MESH_BCK:
    case GNUNET_MESSAGE_TYPE_MESH_ACK:
    case GNUNET_MESSAGE_TYPE_MESH_POLL:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "*   raw: %s\n",
                  GNUNET_MESH_DEBUG_M2S (queue->type));
      data_size = send_core_data_raw (queue->cls, size, buf);
      msg = (struct GNUNET_MessageHeader *) buf;
      type = ntohs (msg->type);
      break;
    case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_CREATE:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   path create\n");
      if (GMC_is_origin (c, GNUNET_YES))
        data_size = send_core_connection_create (queue->c, size, buf);
      else
        data_size = send_core_data_raw (queue->cls, size, buf);
      break;
    case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_ACK:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   path ack\n");
      if (GMC_is_origin (c, GNUNET_NO) ||
          GMC_is_origin (c, GNUNET_YES))
        data_size = send_core_connection_ack (queue->c, size, buf);
      else
        data_size = send_core_data_raw (queue->cls, size, buf);
      break;
    case GNUNET_MESSAGE_TYPE_MESH_DATA:
    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_CREATE:
    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_DESTROY:
      /* This should be encapsulted */
      GNUNET_break (0);
      data_size = 0;
      break;
    default:
      GNUNET_break (0);
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, "*   type unknown: %u\n",
                  queue->type);
      data_size = 0;
  }

  if (0 < drop_percent &&
      GNUNET_CRYPTO_random_u32(GNUNET_CRYPTO_QUALITY_WEAK, 101) < drop_percent)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Dropping message of type %s\n",
                GNUNET_MESH_DEBUG_M2S (queue->type));
    data_size = 0;
  }

  /* Free queue, but cls was freed by send_core_* */
  ch = queue->ch;
  queue_destroy (queue, GNUNET_NO);

  /* Send ACK if needed, after accounting for sent ID in fc->queue_n */
  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_MESH_FWD:
    case GNUNET_MESSAGE_TYPE_MESH_BCK:
      pid = ntohl ( ((struct GNUNET_MESH_Encrypted *) buf)->pid );
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   accounting pid %u\n", pid);
      fc->last_pid_sent = pid;
      send_ack (c, ch, fwd);
      break;
    default:
      break;
  }

  /* If more data in queue, send next */
  queue = peer_get_first_message (peer);
  if (NULL != queue)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   more data!\n");
    if (NULL == peer->core_transmit) {
      peer->core_transmit =
          GNUNET_CORE_notify_transmit_ready(core_handle,
                                            0,
                                            0,
                                            GNUNET_TIME_UNIT_FOREVER_REL,
                                            dst_id,
                                            queue->size,
                                            &queue_send,
                                            peer);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "*   tmt rdy called somewhere else\n");
    }
    if (GNUNET_SCHEDULER_NO_TASK == fc->poll_task)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*   starting poll timeout\n");
      fc->poll_task =
          GNUNET_SCHEDULER_add_delayed (fc->poll_time, &connection_poll, fc);
    }
  }
  else
  {
    if (GNUNET_SCHEDULER_NO_TASK != fc->poll_task)
    {
      GNUNET_SCHEDULER_cancel (fc->poll_task);
      fc->poll_task = GNUNET_SCHEDULER_NO_TASK;
    }
  }
  if (NULL != c)
  {
    c->pending_messages--;
    if (GNUNET_YES == c->destroy && 0 == c->pending_messages)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*  destroying connection!\n");
      GMC_destroy (c);
    }
  }

  if (NULL != t)
  {
    t->pending_messages--;
    if (GNUNET_YES == t->destroy && 0 == t->pending_messages)
    {
//       GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*  destroying tunnel!\n");
      tunnel_destroy (t);
    }
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*  Return %d\n", data_size);
  return data_size;
}



/**
 * Get first sendable message.
 *
 * @param peer The destination peer.
 *
 * @return Best current known path towards the peer, if any.
 */
static struct MeshPeerQueue *
peer_get_first_message (const struct MeshPeer *peer)
{
  struct MeshPeerQueue *q;

  for (q = peer->queue_head; NULL != q; q = q->next)
  {
    if (queue_is_sendable (q))
      return q;
  }

  return NULL;
}


static int
queue_is_sendable (struct MeshPeerQueue *q)
{
  struct MeshFlowControl *fc;

  /* Is PID-independent? */
  switch (q->type)
  {
    case GNUNET_MESSAGE_TYPE_MESH_ACK:
    case GNUNET_MESSAGE_TYPE_MESH_POLL:
      return GNUNET_YES;
  }

  /* Is PID allowed? */
  fc = q->fwd ? &q->c->fwd_fc : &q->c->bck_fc;
  if (GMC_is_pid_bigger (fc->last_ack_recv, fc->last_pid_sent))
    return GNUNET_YES;

  return GNUNET_NO;
}


/******************************************************************************/
/********************************    API    ***********************************/
/******************************************************************************/


/**
 * Free a transmission that was already queued with all resources
 * associated to the request.
 *
 * @param queue Queue handler to cancel.
 * @param clear_cls Is it necessary to free associated cls?
 */
void
GMP_queue_destroy (struct MeshPeerQueue *queue, int clear_cls)
{
  struct MeshPeer *peer;
  struct MeshFlowControl *fc;
  int fwd;

  fwd = queue->fwd;
  peer = queue->peer;
  GNUNET_assert (NULL != queue->c);
  fc = fwd ? &queue->c->fwd_fc : &queue->c->bck_fc;

  if (GNUNET_YES == clear_cls)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   queue destroy type %s\n",
                GNUNET_MESH_DEBUG_M2S (queue->type));
    switch (queue->type)
    {
      case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_DESTROY:
      case GNUNET_MESSAGE_TYPE_MESH_TUNNEL_DESTROY:
        GNUNET_log (GNUNET_ERROR_TYPE_INFO, "destroying a DESTROY message\n");
        GNUNET_break (GNUNET_YES == queue->c->destroy);
        /* fall through */
      case GNUNET_MESSAGE_TYPE_MESH_FWD:
      case GNUNET_MESSAGE_TYPE_MESH_BCK:
      case GNUNET_MESSAGE_TYPE_MESH_ACK:
      case GNUNET_MESSAGE_TYPE_MESH_POLL:
      case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_ACK:
      case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_CREATE:
      case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_BROKEN:
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "   prebuilt message\n");;
        GNUNET_free_non_null (queue->cls);
        break;

      default:
        GNUNET_break (0);
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "   type %s unknown!\n",
                    GNUNET_MESH_DEBUG_M2S (queue->type));
    }

  }
  GNUNET_CONTAINER_DLL_remove (peer->queue_head, peer->queue_tail, queue);

  if (queue->type != GNUNET_MESSAGE_TYPE_MESH_ACK &&
      queue->type != GNUNET_MESSAGE_TYPE_MESH_POLL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Q_N- %p %u\n", fc, fc->queue_n);
    fc->queue_n--;
    peer->queue_n--;
  }
  if (NULL != queue->c)
  {
    queue->c->pending_messages--;
    if (NULL != queue->c->t)
    {
      queue->c->t->pending_messages--;
    }
  }

  GNUNET_free (queue);
}


/**
 * @brief Queue and pass message to core when possible.
 *
 * @param cls Closure (@c type dependant). It will be used by queue_send to
 *            build the message to be sent if not already prebuilt.
 * @param type Type of the message, 0 for a raw message.
 * @param size Size of the message.
 * @param c Connection this message belongs to (cannot be NULL).
 * @param ch Channel this message belongs to, if applicable (otherwise NULL).
 * @param fwd Is this a message going root->dest? (FWD ACK are NOT FWD!)
 */
void
GMP_queue_add (void *cls, uint16_t type, size_t size, 
               struct MeshConnection *c,
               struct MeshChannel *ch,
               int fwd)
{
  struct MeshPeerQueue *queue;
  struct MeshFlowControl *fc;
  struct MeshPeer *peer;
  int priority;
  int call_core;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "queue add %s %s (%u) on c %p, ch %p\n",
              fwd ? "FWD" : "BCK",  GNUNET_MESH_DEBUG_M2S (type), size, c, ch);
  GNUNET_assert (NULL != c);

  fc   = fwd ? &c->fwd_fc : &c->bck_fc;
  peer = fwd ? connection_get_next_hop (c) : connection_get_prev_hop (c);

  if (NULL == fc)
  {
    GNUNET_break (0);
    return;
  }

  if (NULL == peer->connections)
  {
    /* We are not connected to this peer, ignore request. */
    GNUNET_break_op (0);
    return;
  }

  priority = 0;

  if (GNUNET_MESSAGE_TYPE_MESH_POLL == type ||
      GNUNET_MESSAGE_TYPE_MESH_ACK == type)
  {
    priority = 100;
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "priority %d\n", priority);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "fc %p\n", fc);
  if (fc->queue_n >= fc->queue_max && 0 == priority)
  {
    GNUNET_STATISTICS_update (stats, "# messages dropped (buffer full)",
                              1, GNUNET_NO);
    GNUNET_break (0);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "queue full: %u/%u\n",
                fc->queue_n, fc->queue_max);
    return; /* Drop this message */
  }

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "last pid %u\n", fc->last_pid_sent);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "     ack %u\n", fc->last_ack_recv);
  if (GMC_is_pid_bigger (fc->last_pid_sent + 1, fc->last_ack_recv))
  {
    call_core = GNUNET_NO;
    if (GNUNET_SCHEDULER_NO_TASK == fc->poll_task &&
        GNUNET_MESSAGE_TYPE_MESH_POLL != type)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "no buffer space (%u > %u): starting poll\n",
                  fc->last_pid_sent + 1, fc->last_ack_recv);
      fc->poll_task = GNUNET_SCHEDULER_add_delayed (fc->poll_time,
                                                    &connection_poll,
                                                    fc);
    }
  }
  else
    call_core = GNUNET_YES;
  queue = GNUNET_malloc (sizeof (struct MeshPeerQueue));
  queue->cls = cls;
  queue->type = type;
  queue->size = size;
  queue->peer = peer;
  queue->c = c;
  queue->ch = ch;
  queue->fwd = fwd;
  if (100 <= priority)
  {
    struct MeshPeerQueue *copy;
    struct MeshPeerQueue *next;

    for (copy = peer->queue_head; NULL != copy; copy = next)
    {
      next = copy->next;
      if (copy->type == type && copy->c == c && copy->fwd == fwd)
      {
        /* Example: also a FWD ACK for connection XYZ */
        queue_destroy (copy, GNUNET_YES);
      }
    }
    GNUNET_CONTAINER_DLL_insert (peer->queue_head, peer->queue_tail, queue);
  }
  else
  {
    GNUNET_CONTAINER_DLL_insert_tail (peer->queue_head, peer->queue_tail, queue);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  Q_N+ %p %u\n", fc, fc->queue_n);
    fc->queue_n++;
    peer->queue_n++;
  }

  if (NULL == peer->core_transmit && GNUNET_YES == call_core)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "calling core tmt rdy towards %s for %u bytes\n",
                peer2s (peer), size);
    peer->core_transmit =
        GNUNET_CORE_notify_transmit_ready (core_handle,
                                           0,
                                           0,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_PEER_resolve2 (peer->id),
                                           size,
                                           &queue_send,
                                           peer);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "core tmt rdy towards %s already called\n",
                peer2s (peer));

  }
  c->pending_messages++;
  if (NULL != c->t)
    c->t->pending_messages++;
}



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

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "MESH", "DROP_PERCENT",
                                             &drop_percent))
  {
    drop_percent = 0;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "\n***************************************\n"
                "Mesh is running with drop mode enabled.\n"
                "This is NOT a good idea!\n"
                "Remove the DROP_PERCENT option from your configuration.\n"
                "***************************************\n");
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
  int rerun_search;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "peer_connect towards %s\n",
              peer2s (peer));
  t = peer->tunnel;
  c = NULL;
  rerun_search = GNUNET_NO;

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
                rerun_search = GNUNET_YES;
      }
      else
      {
        send_connection_create (c);
        return;
      }
    }
  }

  if (NULL != peer->search_h && GNUNET_YES == rerun_search)
  {
    GMD_search_stop (peer->search_h);
    peer->search_h = NULL;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  Stopping DHT GET for peer %s\n", peer2s (peer));
  }

  if (NULL == peer->search_h)
  {
    const struct GNUNET_PeerIdentity *id;

    id = GNUNET_PEER_resolve2 (peer->id);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  Starting DHT GET for peer %s\n", peer2s (peer));
    peer->search_h = GMD_search (id, &search_handler, peer);
    if (MESH_TUNNEL_NEW == t->state)
      tunnel_change_state (t, MESH_TUNNEL_SEARCHING);
  }
}