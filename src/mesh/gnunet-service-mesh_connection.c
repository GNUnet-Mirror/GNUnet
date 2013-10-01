/*
     This file is part of GNUnet.
     (C) 2001-2013 Christian Grothoff (and other contributing authors)

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
 * @file mesh/gnunet-service-mesh_connection.c
 * @brief GNUnet MESH service connection handling
 * @author Bartlomiej Polot
 */

#include "platform.h"
#include "gnunet_core_service.h"
#include "gnunet-service-mesh_connection.h"




/**
 * All the states a connection can be in.
 */
enum MeshConnectionState
{
  /**
   * Uninitialized status, should never appear in operation.
   */
  MESH_CONNECTION_NEW,

  /**
   * Connection create message sent, waiting for ACK.
   */
  MESH_CONNECTION_SENT,

  /**
   * Connection ACK sent, waiting for ACK.
   */
  MESH_CONNECTION_ACK,

  /**
   * Connection confirmed, ready to carry traffic.
   */
  MESH_CONNECTION_READY,
};



/**
 * Struct containing info about a queued transmission to this peer
 */
struct MeshPeerQueue
{
    /**
      * DLL next
      */
  struct MeshPeerQueue *next;

    /**
      * DLL previous
      */
  struct MeshPeerQueue *prev;

    /**
     * Peer this transmission is directed to.
     */
  struct MeshPeer *peer;

    /**
     * Connection this message belongs to.
     */
  struct MeshConnection *c;

    /**
     * Is FWD in c?
     */
  int fwd;

    /**
     * Channel this message belongs to, if known.
     */
  struct MeshChannel *ch;

    /**
     * Pointer to info stucture used as cls.
     */
  void *cls;

    /**
     * Type of message
     */
  uint16_t type;

    /**
     * Size of the message
     */
  size_t size;
};


/**
 * Struct to encapsulate all the Flow Control information to a peer to which
 * we are directly connected (on a core level).
 */
struct MeshFlowControl
{
  /**
   * Connection this controls.
   */
  struct MeshConnection *c;

  /**
   * How many messages are in the queue on this connection.
   */
  unsigned int queue_n;

  /**
   * How many messages do we accept in the queue.
   */
  unsigned int queue_max;

  /**
   * Next ID to use.
   */
  uint32_t next_pid;

  /**
   * ID of the last packet sent towards the peer.
   */
  uint32_t last_pid_sent;

  /**
   * ID of the last packet received from the peer.
   */
  uint32_t last_pid_recv;

  /**
   * Last ACK sent to the peer (peer can't send more than this PID).
   */
  uint32_t last_ack_sent;

  /**
   * Last ACK sent towards the origin (for traffic towards leaf node).
   */
  uint32_t last_ack_recv;

  /**
   * Task to poll the peer in case of a lost ACK causes stall.
   */
  GNUNET_SCHEDULER_TaskIdentifier poll_task;

  /**
   * How frequently to poll for ACKs.
   */
  struct GNUNET_TIME_Relative poll_time;
};


/**
 * Struct containing all information regarding a connection to a peer.
 */
struct MeshConnection
{
  /**
   * DLL
   */
  struct MeshConnection *next;
  struct MeshConnection *prev;

  /**
   * Tunnel this connection is part of.
   */
  struct MeshTunnel2 *t;

  /**
   * Flow control information for traffic fwd.
   */
  struct MeshFlowControl fwd_fc;

  /**
   * Flow control information for traffic bck.
   */
  struct MeshFlowControl bck_fc;

  /**
   * ID of the connection.
   */
  struct GNUNET_HashCode id;

  /**
   * State of the connection.
   */
  enum MeshConnectionState state;

  /**
   * Path being used for the tunnel.
   */
  struct MeshPeerPath *path;

  /**
   * Position of the local peer in the path.
   */
  unsigned int own_pos;

  /**
   * Task to keep the used paths alive at the owner,
   * time tunnel out on all the other peers.
   */
  GNUNET_SCHEDULER_TaskIdentifier fwd_maintenance_task;

  /**
   * Task to keep the used paths alive at the destination,
   * time tunnel out on all the other peers.
   */
  GNUNET_SCHEDULER_TaskIdentifier bck_maintenance_task;

  /**
   * Pending message count.
   */
  int pending_messages;

  /**
   * Destroy flag: if true, destroy on last message.
   */
  int destroy;
};






/**
 * Connections known, indexed by cid (MeshConnection).
 */
static struct GNUNET_CONTAINER_MultiHashMap *connections;

/**
 * How many connections are we willing to maintain.
 * Local connections are always allowed, even if there are more connections than max.
 */
static unsigned long long max_connections;

/**
 * How many messages *in total* are we willing to queue, divide by number of 
 * connections to get connection queue size.
 */
static unsigned long long max_msgs_queue;

/**
 * How often to send path keepalives. Paths timeout after 4 missed.
 */
static struct GNUNET_TIME_Relative refresh_connection_time;




/**
 * Initialize a Flow Control structure to the initial state.
 * 
 * @param fc Flow Control structure to initialize.
 */
static void
fc_init (struct MeshFlowControl *fc)
{
  fc->next_pid = 0;
  fc->last_pid_sent = (uint32_t) -1; /* Next (expected) = 0 */
  fc->last_pid_recv = (uint32_t) -1;
  fc->last_ack_sent = (uint32_t) 0;
  fc->last_ack_recv = (uint32_t) 0;
  fc->poll_task = GNUNET_SCHEDULER_NO_TASK;
  fc->poll_time = GNUNET_TIME_UNIT_SECONDS;
  fc->queue_n = 0;
  fc->queue_max = (max_msgs_queue / max_connections) + 1;
}


/**
 * Find a connection.
 *
 * @param cid Connection ID.
 */
static struct MeshConnection *
connection_get (const struct GNUNET_HashCode *cid)
{
  return GNUNET_CONTAINER_multihashmap_get (connections, cid);
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



/**
 * Free a transmission that was already queued with all resources
 * associated to the request.
 *
 * @param queue Queue handler to cancel.
 * @param clear_cls Is it necessary to free associated cls?
 */
static void
queue_destroy (struct MeshPeerQueue *queue, int clear_cls)
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



static void
queue_add (void *cls, uint16_t type, size_t size,
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
 * Sends an already built message on a connection, properly registering
 * all used resources.
 *
 * @param message Message to send. Function makes a copy of it.
 *                If message is not hop-by-hop, decrements TTL of copy.
 * @param c Connection on which this message is transmitted.
 * @param ch Channel on which this message is transmitted, or NULL.
 * @param fwd Is this a fwd message?
 */
static void
send_prebuilt_message_connection (const struct GNUNET_MessageHeader *message,
                                  struct MeshConnection *c,
                                  struct MeshChannel *ch,
                                  int fwd)
{
  void *data;
  size_t size;
  uint16_t type;

  size = ntohs (message->size);
  data = GNUNET_malloc (size);
  memcpy (data, message, size);
  type = ntohs (message->type);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Send %s (%u) on connection %s\n",
              GNUNET_MESH_DEBUG_M2S (type), size, GNUNET_h2s (&c->id));

  switch (type)
  {
    struct GNUNET_MESH_Encrypted *emsg;
    struct GNUNET_MESH_ACK       *amsg;
    struct GNUNET_MESH_Poll      *pmsg;
    struct GNUNET_MESH_ConnectionDestroy *dmsg;
    struct GNUNET_MESH_ConnectionBroken  *bmsg;
    uint32_t ttl;

    case GNUNET_MESSAGE_TYPE_MESH_FWD:
    case GNUNET_MESSAGE_TYPE_MESH_BCK:
      emsg = (struct GNUNET_MESH_Encrypted *) data;
      ttl = ntohl (emsg->ttl);
      if (0 == ttl)
      {
        GNUNET_break_op (0);
        return;
      }
      emsg->cid = c->id;
      emsg->ttl = htonl (ttl - 1);
      emsg->pid = htonl (fwd ? c->fwd_fc.next_pid++ : c->bck_fc.next_pid++);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " pid %u\n", ntohl (emsg->pid));
      break;

    case GNUNET_MESSAGE_TYPE_MESH_ACK:
      amsg = (struct GNUNET_MESH_ACK *) data;
      amsg->cid = c->id;
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " ack %u\n", ntohl (amsg->ack));
      break;

    case GNUNET_MESSAGE_TYPE_MESH_POLL:
      pmsg = (struct GNUNET_MESH_Poll *) data;
      pmsg->cid = c->id;
      pmsg->pid = htonl (fwd ? c->fwd_fc.last_pid_sent : c->bck_fc.last_pid_sent);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " poll %u\n", ntohl (pmsg->pid));
      break;

    case GNUNET_MESSAGE_TYPE_MESH_TUNNEL_DESTROY:
      dmsg = (struct GNUNET_MESH_ConnectionDestroy *) data;
      dmsg->cid = c->id;
      dmsg->reserved = 0;
      break;

    case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_BROKEN:
      bmsg = (struct GNUNET_MESH_ConnectionBroken *) data;
      bmsg->cid = c->id;
      bmsg->reserved = 0;
      break;

    case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_CREATE:
    case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_ACK:
      break;

    default:
      GNUNET_break (0);
  }

  queue_add (data,
             type,
             size,
             c,
             ch,
             fwd);
}




struct MeshConnection *
GMC_new (const struct GNUNET_HashCode *cid)
{
  struct MeshConnection *c;

  c = GNUNET_new (struct MeshConnection);
  c->id = *cid;
  GNUNET_CONTAINER_multihashmap_put (connections, &c->id, c,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  fc_init (&c->fwd_fc);
  fc_init (&c->bck_fc);
  c->fwd_fc.c = c;
  c->bck_fc.c = c;

  return c;
}


static void
GMC_destroy (struct MeshConnection *c)
{
  struct MeshPeer *peer;

  if (NULL == c)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "destroying connection %s[%X]\n",
              peer2s (c->t->peer),
              c->id);

  /* Cancel all traffic */
  connection_cancel_queues (c, GNUNET_YES);
  connection_cancel_queues (c, GNUNET_NO);

  /* Cancel maintainance task (keepalive/timeout) */
  if (GNUNET_SCHEDULER_NO_TASK != c->fwd_maintenance_task)
    GNUNET_SCHEDULER_cancel (c->fwd_maintenance_task);
  if (GNUNET_SCHEDULER_NO_TASK != c->bck_maintenance_task)
    GNUNET_SCHEDULER_cancel (c->bck_maintenance_task);

  /* Deregister from neighbors */
  peer = connection_get_next_hop (c);
  if (NULL != peer && NULL != peer->connections)
    GNUNET_CONTAINER_multihashmap_remove (peer->connections, &c->id, c);
  peer = connection_get_prev_hop (c);
  if (NULL != peer && NULL != peer->connections)
    GNUNET_CONTAINER_multihashmap_remove (peer->connections, &c->id, c);

  /* Delete */
  GNUNET_STATISTICS_update (stats, "# connections", -1, GNUNET_NO);
  GNUNET_CONTAINER_DLL_remove (c->t->connection_head, c->t->connection_tail, c);
  GNUNET_free (c);
}



/**
 * Send an ACK informing the predecessor about the available buffer space.
 *
 * Note that for fwd ack, the FWD mean forward *traffic* (root->dest),
 * the ACK itself goes "back" (dest->root).
 *
 * @param c Connection on which to send the ACK.
 * @param buffer How much space free to advertise?
 * @param fwd Is this FWD ACK? (Going dest->owner)
 */
static void
connection_send_ack (struct MeshConnection *c, unsigned int buffer, int fwd)
{
  struct MeshFlowControl *next_fc;
  struct MeshFlowControl *prev_fc;
  struct GNUNET_MESH_ACK msg;
  uint32_t ack;
  int delta;

  next_fc = fwd ? &c->fwd_fc : &c->bck_fc;
  prev_fc = fwd ? &c->bck_fc : &c->fwd_fc;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "connection send %s ack on %s\n",
              fwd ? "FWD" : "BCK", GNUNET_h2s (&c->id));

  /* Check if we need to transmit the ACK */
  if (prev_fc->last_ack_sent - prev_fc->last_pid_recv > 3)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Not sending ACK, buffer > 3\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "  last pid recv: %u, last ack sent: %u\n",
                prev_fc->last_pid_recv, prev_fc->last_ack_sent);
    return;
  }

  /* Ok, ACK might be necessary, what PID to ACK? */
  delta = next_fc->queue_max - next_fc->queue_n;
  ack = prev_fc->last_pid_recv + delta;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " ACK %u\n", ack);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              " last pid %u, last ack %u, qmax %u, q %u\n",
              prev_fc->last_pid_recv, prev_fc->last_ack_sent,
              next_fc->queue_max, next_fc->queue_n);
  if (ack == prev_fc->last_ack_sent)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Not sending FWD ACK, not needed\n");
    return;
  }

  prev_fc->last_ack_sent = ack;

  /* Build ACK message and send on connection */
  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_ACK);
  msg.ack = htonl (ack);
  msg.cid = c->id;

  send_prebuilt_message_connection (&msg.header, c, NULL, !fwd);
}


static void
connection_change_state (struct MeshConnection* c,
                         enum MeshConnectionState state)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connection %s state was %s\n",
              GNUNET_h2s (&c->id), GNUNET_MESH_DEBUG_CS2S (c->state));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connection %s state is now %s\n",
              GNUNET_h2s (&c->id), GNUNET_MESH_DEBUG_CS2S (state));
  c->state = state;
}



/**
 * Send keepalive packets for a connection.
 *
 * @param c Connection to keep alive..
 * @param fwd Is this a FWD keepalive? (owner -> dest).
 */
static void
connection_keepalive (struct MeshConnection *c, int fwd)
{
  struct GNUNET_MESH_ConnectionKeepAlive *msg;
  size_t size = sizeof (struct GNUNET_MESH_ConnectionKeepAlive);
  char cbuf[size];
  uint16_t type;

  type = fwd ? GNUNET_MESSAGE_TYPE_MESH_FWD_KEEPALIVE :
               GNUNET_MESSAGE_TYPE_MESH_BCK_KEEPALIVE;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "sending %s keepalive for connection %s[%d]\n",
              fwd ? "FWD" : "BCK",
              peer2s (c->t->peer),
              c->id);

  msg = (struct GNUNET_MESH_ConnectionKeepAlive *) cbuf;
  msg->header.size = htons (size);
  msg->header.type = htons (type);
  msg->cid = c->id;

  send_prebuilt_message_connection (&msg->header, c, NULL, fwd);
}


/**
 * Send CONNECTION_{CREATE/ACK} packets for a connection.
 *
 * @param c Connection for which to send the message.
 * @param fwd If GNUNET_YES, send CREATE, otherwise send ACK.
 */
static void
connection_recreate (struct MeshConnection *c, int fwd)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "sending connection recreate\n");
  if (fwd)
    send_connection_create (c);
  else
    send_connection_ack (c, GNUNET_NO);
}


/**
 * Generic connection timer management.
 * Depending on the role of the peer in the connection will send the
 * appropriate message (build or keepalive)
 *
 * @param c Conncetion to maintain.
 * @param fwd Is FWD?
 */
static void
connection_maintain (struct MeshConnection *c, int fwd)
{
  if (MESH_TUNNEL_SEARCHING == c->t->state)
  {
    /* TODO DHT GET with RO_BART */
    return;
  }
  switch (c->state)
  {
    case MESH_CONNECTION_NEW:
      GNUNET_break (0);
    case MESH_CONNECTION_SENT:
      connection_recreate (c, fwd);
      break;
    case MESH_CONNECTION_READY:
      connection_keepalive (c, fwd);
      break;
    default:
      break;
  }
}


static void
connection_fwd_keepalive (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshConnection *c = cls;

  c->fwd_maintenance_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  connection_maintain (c, GNUNET_YES);
  c->fwd_maintenance_task = GNUNET_SCHEDULER_add_delayed (refresh_connection_time,
                                                          &connection_fwd_keepalive,
                                                          c);
}


static void
connection_bck_keepalive (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshConnection *c = cls;

  c->bck_maintenance_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  connection_maintain (c, GNUNET_NO);
  c->bck_maintenance_task = GNUNET_SCHEDULER_add_delayed (refresh_connection_time,
                                                          &connection_bck_keepalive,
                                                          c);
}


/**
 * Send a message to all peers in this connection that the connection
 * is no longer valid.
 *
 * If some peer should not receive the message, it should be zero'ed out
 * before calling this function.
 *
 * @param c The connection whose peers to notify.
 */
static void
connection_send_destroy (struct MeshConnection *c)
{
  struct GNUNET_MESH_ConnectionDestroy msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_TUNNEL_DESTROY);;
  msg.cid = c->id;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  sending connection destroy for connection %s[%X]\n",
              peer2s (c->t->peer),
              c->id);

  if (GNUNET_NO == GMC_is_terminal (c, GNUNET_YES))
    send_prebuilt_message_connection (&msg.header, c, NULL, GNUNET_YES);
  if (GNUNET_NO == GMC_is_terminal (c, GNUNET_NO))
    send_prebuilt_message_connection (&msg.header, c, NULL, GNUNET_NO);
  c->destroy = GNUNET_YES;
}


/**
 * Get free buffer space in a connection.
 *
 * @param c Connection.
 * @param fwd Is query about FWD traffic?
 *
 * @return Free buffer space [0 - max_msgs_queue/max_connections]
 */
static unsigned int
connection_get_buffer (struct MeshConnection *c, int fwd)
{
  struct MeshFlowControl *fc;
  
  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  
  return (fc->queue_max - fc->queue_n);
}


/**
 * Get the first transmittable message for a connection.
 *
 * @param c Connection.
 * @param fwd Is this FWD?
 *
 * @return First transmittable message.
 */
static struct MeshPeerQueue *
connection_get_first_message (struct MeshConnection *c, int fwd)
{
  struct MeshPeerQueue *q;
  struct MeshPeer *p;

  p = connection_get_hop (c, fwd);

  for (q = p->queue_head; NULL != q; q = q->next)
  {
    if (q->c != c)
      continue;
    if (queue_is_sendable (q))
      return q;
  }

  return NULL;
}


/**
 * @brief Re-initiate traffic on this connection if necessary.
 *
 * Check if there is traffic queued towards this peer
 * and the core transmit handle is NULL (traffic was stalled).
 * If so, call core tmt rdy.
 *
 * @param c Connection on which initiate traffic.
 * @param fwd Is this about fwd traffic?
 */
static void
connection_unlock_queue (struct MeshConnection *c, int fwd)
{
  struct MeshPeer *peer;
  struct MeshPeerQueue *q;
  size_t size;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "connection_unlock_queue %s on %s\n",
              fwd ? "FWD" : "BCK", GNUNET_h2s (&c->id));

  if (GMC_is_terminal (c, fwd))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " is terminal!\n");
    return;
  }

  peer = connection_get_hop (c, fwd);

  if (NULL != peer->core_transmit)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  already unlocked!\n");
    return; /* Already unlocked */
  }

  q = connection_get_first_message (c, fwd);
  if (NULL == q)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  queue empty!\n");
    return; /* Nothing to transmit */
  }

  size = q->size;
  peer->core_transmit =
      GNUNET_CORE_notify_transmit_ready (core_handle,
                                         GNUNET_NO,
                                         0,
                                         GNUNET_TIME_UNIT_FOREVER_REL,
                                         GNUNET_PEER_resolve2 (peer->id),
                                         size,
                                         &queue_send,
                                         peer);
}


/**
 * Cancel all transmissions that belong to a certain connection.
 *
 * @param c Connection which to cancel.
 * @param fwd Cancel fwd traffic?
 */
static void
connection_cancel_queues (struct MeshConnection *c, int fwd)
{
  struct MeshPeerQueue *q;
  struct MeshPeerQueue *next;
  struct MeshFlowControl *fc;
  struct MeshPeer *peer;

  if (NULL == c)
  {
    GNUNET_break (0);
    return;
  }
  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  peer = connection_get_hop (c, fwd);

  for (q = peer->queue_head; NULL != q; q = next)
  {
    next = q->next;
    if (q->c == c)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "connection_cancel_queue %s\n",
                  GNUNET_MESH_DEBUG_M2S (q->type));
      queue_destroy (q, GNUNET_YES);
    }
  }
  if (NULL == peer->queue_head)
  {
    if (NULL != peer->core_transmit)
    {
      GNUNET_CORE_notify_transmit_ready_cancel (peer->core_transmit);
      peer->core_transmit = NULL;
    }
    if (GNUNET_SCHEDULER_NO_TASK != fc->poll_task)
    {
      GNUNET_SCHEDULER_cancel (fc->poll_task);
      fc->poll_task = GNUNET_SCHEDULER_NO_TASK;
    }
  }
}




/**
 * Function called if a connection has been stalled for a while,
 * possibly due to a missed ACK. Poll the neighbor about its ACK status.
 *
 * @param cls Closure (poll ctx).
 * @param tc TaskContext.
 */
static void
connection_poll (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshFlowControl *fc = cls;
  struct GNUNET_MESH_Poll msg;
  struct MeshConnection *c;

  fc->poll_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    return;
  }

  c = fc->c;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " *** Polling!\n");
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " *** connection [%X]\n",
              GNUNET_h2s (&c->id));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " ***   %s\n", 
              fc == &c->fwd_fc ? "FWD" : "BCK");

  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_POLL);
  msg.header.size = htons (sizeof (msg));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, " *** pid (%u)!\n", fc->last_pid_sent);
  send_prebuilt_message_connection (&msg.header, c, NULL, fc == &c->fwd_fc);
  fc->poll_time = GNUNET_TIME_STD_BACKOFF (fc->poll_time);
  fc->poll_task = GNUNET_SCHEDULER_add_delayed (fc->poll_time,
                                                &connection_poll, fc);
}




/**
 * Get the previous hop in a connection
 *
 * @param c Connection.
 *
 * @return Previous peer in the connection.
 */
static struct MeshPeer *
connection_get_prev_hop (struct MeshConnection *c)
{
  GNUNET_PEER_Id id;

  if (0 == c->own_pos || c->path->length < 2)
    id = c->path->peers[0];
  else
    id = c->path->peers[c->own_pos - 1];

  return peer_get_short (id);
}


/**
 * Get the next hop in a connection
 *
 * @param c Connection.
 *
 * @return Next peer in the connection. 
 */
static struct MeshPeer *
connection_get_next_hop (struct MeshConnection *c)
{
  GNUNET_PEER_Id id;

  if ((c->path->length - 1) == c->own_pos || c->path->length < 2)
    id = c->path->peers[c->path->length - 1];
  else
    id = c->path->peers[c->own_pos + 1];

  return peer_get_short (id);
}


/**
 * Get the hop in a connection.
 *
 * @param c Connection.
 * @param fwd Next hop?
 *
 * @return Next peer in the connection. 
 */
static struct MeshPeer *
connection_get_hop (struct MeshConnection *c, int fwd)
{
  if (fwd)
    return connection_get_next_hop (c);
  return connection_get_prev_hop (c);
}




/**
 * Timeout function due to lack of keepalive/traffic from the owner.
 * Destroys connection if called.
 *
 * @param cls Closure (connection to destroy).
 * @param tc TaskContext.
 */
static void
connection_fwd_timeout (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshConnection *c = cls;

  c->fwd_maintenance_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connection %s[%X] FWD timed out. Destroying.\n",
              peer2s (c->t->peer),
              c->id);

  if (GMC_is_origin (c, GNUNET_YES)) /* If local, leave. */
    return;

  GMC_destroy (c);
}


/**
 * Timeout function due to lack of keepalive/traffic from the destination.
 * Destroys connection if called.
 *
 * @param cls Closure (connection to destroy).
 * @param tc TaskContext
 */
static void
connection_bck_timeout (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshConnection *c = cls;

  c->bck_maintenance_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Connection %s[%X] FWD timed out. Destroying.\n",
              peer2s (c->t->peer),
              c->id);

  if (GMC_is_origin (c, GNUNET_NO)) /* If local, leave. */
    return;

  GMC_destroy (c);
}


/**
 * Resets the connection timeout task, some other message has done the
 * task's job.
 * - For the first peer on the direction this means to send
 *   a keepalive or a path confirmation message (either create or ACK).
 * - For all other peers, this means to destroy the connection,
 *   due to lack of activity.
 * Starts the tiemout if no timeout was running (connection just created).
 *
 * @param c Connection whose timeout to reset.
 * @param fwd Is this forward?
 *
 * TODO use heap to improve efficiency of scheduler.
 */
static void
connection_reset_timeout (struct MeshConnection *c, int fwd)
{
  GNUNET_SCHEDULER_TaskIdentifier *ti;
  GNUNET_SCHEDULER_Task f;

  ti = fwd ? &c->fwd_maintenance_task : &c->bck_maintenance_task;

  if (GNUNET_SCHEDULER_NO_TASK != *ti)
    GNUNET_SCHEDULER_cancel (*ti);

  if (GMC_is_origin (c, fwd)) /* Endpoint */
  {
    f  = fwd ? &connection_fwd_keepalive : &connection_bck_keepalive;
    *ti = GNUNET_SCHEDULER_add_delayed (refresh_connection_time, f, c);
  }
  else /* Relay */
  {
    struct GNUNET_TIME_Relative delay;

    delay = GNUNET_TIME_relative_multiply (refresh_connection_time, 4);
    f  = fwd ? &connection_fwd_timeout : &connection_bck_timeout;
    *ti = GNUNET_SCHEDULER_add_delayed (delay, f, c);
  }
}


/**
 * Iterator to notify all connections of a broken link. Mark connections
 * to destroy after all traffic has been sent.
 *
 * @param cls Closure (peer disconnected).
 * @param key Current key code (tid).
 * @param value Value in the hash map (connection).
 *
 * @return GNUNET_YES if we should continue to iterate,
 *         GNUNET_NO if not.
 */
int
GMC_notify_broken (void *cls,
                   const struct GNUNET_HashCode *key,
                   void *value)
{
  struct MeshPeer *peer = cls;
  struct MeshConnection *c = value;
  struct GNUNET_MESH_ConnectionBroken msg;
  int fwd;

  fwd = peer == connection_get_prev_hop (c);

  connection_cancel_queues (c, !fwd);
  if (GMC_is_terminal (c, fwd))
  {
    /* Local shutdown, no one to notify about this. */
    GMC_destroy (c);
    return GNUNET_YES;
  }

  msg.header.size = htons (sizeof (struct GNUNET_MESH_ConnectionBroken));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_CONNECTION_BROKEN);
  msg.cid = c->id;
  msg.peer1 = my_full_id;
  msg.peer2 = *GNUNET_PEER_resolve2 (peer->id);
  send_prebuilt_message_connection (&msg.header, c, NULL, fwd);
  c->destroy = GNUNET_YES;

  return GNUNET_YES;
}


/**
 * Initialize the connections subsystem
 *
 * @param c Configuration handle.
 */
void
GMC_init (struct GNUNET_CONFIGURATION_Handle *c)
{
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "MESH", "MAX_MSGS_QUEUE",
                                             &max_msgs_queue))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               "MESH", "MAX_MSGS_QUEUE", "MISSING");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "MESH", "MAX_CONNECTIONS",
                                             &max_connections))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               "MESH", "MAX_CONNECTIONS", "MISSING");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (c, "MESH", "REFRESH_CONNECTION_TIME",
                                           &refresh_connection_time))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               "MESH", "REFRESH_CONNECTION_TIME", "MISSING");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  connections = GNUNET_CONTAINER_multihashmap_create (1024, GNUNET_YES);
}


/**
 * Is this peer the first one on the connection?
 *
 * @param c Connection.
 * @param fwd Is this about fwd traffic?
 *
 * @return GNUNET_YES if origin, GNUNET_NO if relay/terminal.
 */
int
GMC_is_origin (struct MeshConnection *c, int fwd)
{
  if (!fwd && c->path->length - 1 == c->own_pos )
    return GNUNET_YES;
  if (fwd && 0 == c->own_pos)
    return GNUNET_YES;
  return GNUNET_NO;
}


/**
 * Is this peer the last one on the connection?
 *
 * @param c Connection.
 * @param fwd Is this about fwd traffic?
 *            Note that the ROOT is the terminal for BCK traffic!
 *
 * @return GNUNET_YES if terminal, GNUNET_NO if relay/origin.
 */
int
GMC_is_terminal (struct MeshConnection *c, int fwd)
{
  return GMC_is_origin (c, !fwd);
}