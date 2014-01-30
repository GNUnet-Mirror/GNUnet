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
#include "gnunet_util_lib.h"

#include "gnunet_statistics_service.h"

#include "mesh_path.h"
#include "mesh_protocol.h"
#include "mesh.h"
#include "gnunet-service-mesh_connection.h"
#include "gnunet-service-mesh_peer.h"
#include "gnunet-service-mesh_tunnel.h"


#define LOG(level, ...) GNUNET_log_from (level,"mesh-con",__VA_ARGS__)

#define MESH_MAX_POLL_TIME      GNUNET_TIME_relative_multiply (\
                                  GNUNET_TIME_UNIT_MINUTES,\
                                  10)
#define AVG_MSGS                32


/******************************************************************************/
/********************************   STRUCTS  **********************************/
/******************************************************************************/

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

  /**
   * Queued poll message, to cancel if not necessary anymore (got ACK).
   */
  struct MeshConnectionQueue *poll_msg;

  /**
   * Queued poll message, to cancel if not necessary anymore (got ACK).
   */
  struct MeshConnectionQueue *ack_msg;
};

/**
 * Keep a record of the last messages sent on this connection.
 */
struct MeshConnectionPerformance
{
  /**
   * Circular buffer for storing measurements.
   */
  double usecsperbyte[AVG_MSGS];

  /**
   * Running average of @c usecsperbyte.
   */
  double avg;

  /**
   * How many values of @c usecsperbyte are valid.
   */
  uint16_t size;

  /**
   * Index of the next "free" position in @c usecsperbyte.
   */
  uint16_t idx;
};


/**
 * Struct containing all information regarding a connection to a peer.
 */
struct MeshConnection
{
  /**
   * Tunnel this connection is part of.
   */
  struct MeshTunnel3 *t;

  /**
   * Flow control information for traffic fwd.
   */
  struct MeshFlowControl fwd_fc;

  /**
   * Flow control information for traffic bck.
   */
  struct MeshFlowControl bck_fc;

  /**
   * Measure connection performance on the endpoint.
   */
  struct MeshConnectionPerformance *perf;

  /**
   * ID of the connection.
   */
  struct GNUNET_HashCode id;

  /**
   * State of the connection.
   */
  enum MeshConnectionState state;

  /**
   * Path being used for the tunnel. At the origin of the connection
   * it's a pointer to the destination's path pool, otherwise just a copy.
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
   * Queue handle for maintainance traffic. One handle for FWD and BCK since
   * one peer never needs to maintain both directions (no loopback connections).
   */
  struct MeshPeerQueue *maintenance_q;

  /**
   * Counter to do exponential backoff when creating a connection (max 64).
   */
  unsigned short create_retry;

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
 * Handle for messages queued but not yet sent.
 */
struct MeshConnectionQueue
{
  /**
   * Peer queue handle, to cancel if necessary.
   */
  struct MeshPeerQueue *q;

  /**
   * Was this a forced message? (Do not account for it)
   */
  int forced;

  /**
   * Continuation to call once sent.
   */
  GMC_sent cont;

  /**
   * Closure for @c cont.
   */
  void *cont_cls;
};

/******************************************************************************/
/*******************************   GLOBALS  ***********************************/
/******************************************************************************/

/**
 * Global handle to the statistics service.
 */
extern struct GNUNET_STATISTICS_Handle *stats;

/**
 * Local peer own ID (memory efficient handle).
 */
extern GNUNET_PEER_Id myid;

/**
 * Local peer own ID (full value).
 */
extern struct GNUNET_PeerIdentity my_full_id;

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
 * How often to send path create / ACKs.
 */
static struct GNUNET_TIME_Relative create_connection_time;


/******************************************************************************/
/********************************   STATIC  ***********************************/
/******************************************************************************/

#if 0 // avoid compiler warning for unused static function
static void
fc_debug (struct MeshFlowControl *fc)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "    IN: %u/%u\n",
              fc->last_pid_recv, fc->last_ack_sent);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "    OUT: %u/%u\n",
              fc->last_pid_sent, fc->last_ack_recv);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "    QUEUE: %u/%u\n",
              fc->queue_n, fc->queue_max);
}

static void
connection_debug (struct MeshConnection *c)
{
  if (NULL == c)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "*** DEBUG NULL CONNECTION ***\n");
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Connection %s:%X\n",
              peer2s (c->t->peer), GMC_2s (c));
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  state: %u, pending msgs: %u\n",
              c->state, c->pending_messages);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  FWD FC\n");
  fc_debug (&c->fwd_fc);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  BCK FC\n");
  fc_debug (&c->bck_fc);
}
#endif


/**
 * Schedule next keepalive task, taking in consideration
 * the connection state and number of retries.
 *
 * @param c Connection for which to schedule the next keepalive.
 * @param fwd Direction for the next keepalive.
 */
static void
schedule_next_keepalive (struct MeshConnection *c, int fwd);


/**
 * Get string description for tunnel state.
 *
 * @param s Tunnel state.
 *
 * @return String representation.
 */
static const char *
GMC_state2s (enum MeshConnectionState s)
{
  switch (s)
  {
    case MESH_CONNECTION_NEW:
      return "MESH_CONNECTION_NEW";
    case MESH_CONNECTION_SENT:
      return "MESH_CONNECTION_SENT";
    case MESH_CONNECTION_ACK:
      return "MESH_CONNECTION_ACK";
    case MESH_CONNECTION_READY:
      return "MESH_CONNECTION_READY";
    case MESH_CONNECTION_DESTROYED:
      return "MESH_CONNECTION_DESTROYED";
    default:
      return "MESH_CONNECTION_STATE_ERROR";
  }
}


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


static void
connection_change_state (struct MeshConnection* c,
                         enum MeshConnectionState state)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "Connection %s state was %s\n",
              GMC_2s (c), GMC_state2s (c->state));
  if (MESH_CONNECTION_DESTROYED == c->state)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "state not changing anymore\n");
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "Connection %s state is now %s\n",
              GMC_2s (c), GMC_state2s (state));
  c->state = state;
  if (MESH_CONNECTION_READY == state)
    c->create_retry = 1;
}


/**
 * Callback called when a queued ACK message is sent.
 *
 * @param cls Closure (FC).
 * @param c Connection this message was on.
 * @param q Queue handler this call invalidates.
 * @param type Type of message sent.
 * @param fwd Was this a FWD going message?
 * @param size Size of the message.
 */
static void
ack_sent (void *cls,
          struct MeshConnection *c,
          struct MeshConnectionQueue *q,
          uint16_t type, int fwd, size_t size)
{
  struct MeshFlowControl *fc = cls;

  fc->ack_msg = NULL;
}


/**
 * Send an ACK on the connection, informing the predecessor about
 * the available buffer space. Should not be called in case the peer
 * is origin (no predecessor) in the @c fwd direction.
 *
 * Note that for fwd ack, the FWD mean forward *traffic* (root->dest),
 * the ACK itself goes "back" (dest->root).
 *
 * @param c Connection on which to send the ACK.
 * @param buffer How much space free to advertise?
 * @param fwd Is this FWD ACK? (Going dest -> root)
 * @param force Don't optimize out.
 */
static void
send_ack (struct MeshConnection *c, unsigned int buffer, int fwd, int force)
{
  struct MeshFlowControl *next_fc;
  struct MeshFlowControl *prev_fc;
  struct GNUNET_MESH_ACK msg;
  uint32_t ack;
  int delta;

  /* If origin, there is no connection to send ACKs. Wrong function! */
  if (GMC_is_origin (c, fwd))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "connection %s is origin in %s\n",
         GMC_2s (c), GM_f2s (fwd));
    GNUNET_break (0);
    return;
  }

  next_fc = fwd ? &c->fwd_fc : &c->bck_fc;
  prev_fc = fwd ? &c->bck_fc : &c->fwd_fc;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "connection send %s ack on %s\n",
       GM_f2s (fwd), GMC_2s (c));

  /* Check if we need to transmit the ACK. */
  delta = prev_fc->last_ack_sent - prev_fc->last_pid_recv;
  if (3 < delta && buffer < delta && GNUNET_NO == force)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Not sending ACK, buffer > 3\n");
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "  last pid recv: %u, last ack sent: %u\n",
         prev_fc->last_pid_recv, prev_fc->last_ack_sent);
    return;
  }

  /* Ok, ACK might be necessary, what PID to ACK? */
  ack = prev_fc->last_pid_recv + buffer;
  LOG (GNUNET_ERROR_TYPE_DEBUG, " ACK %u\n", ack);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       " last pid %u, last ack %u, qmax %u, q %u\n",
       prev_fc->last_pid_recv, prev_fc->last_ack_sent,
       next_fc->queue_max, next_fc->queue_n);
  if (ack == prev_fc->last_ack_sent && GNUNET_NO == force)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Not sending FWD ACK, not needed\n");
    return;
  }

  /* Check if message is already in queue */
  if (NULL != prev_fc->ack_msg)
  {
    if (GM_is_pid_bigger (ack, prev_fc->last_ack_sent))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, " canceling old ACK\n");
      GMC_cancel (prev_fc->ack_msg);
      /* GMC_cancel triggers ack_sent(), which clears fc->ack_msg */
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, " same ACK already in queue\n");
      return;
    }
  }

  prev_fc->last_ack_sent = ack;

  /* Build ACK message and send on connection */
  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_ACK);
  msg.ack = htonl (ack);
  msg.cid = c->id;

  prev_fc->ack_msg = GMC_send_prebuilt_message (&msg.header, c,
                                                !fwd, GNUNET_YES,
                                                &ack_sent, prev_fc);
}


/**
 * Callback called when a queued message is sent.
 *
 * Calculates the average time and connection packet tracking.
 *
 * @param cls Closure (ConnectionQueue Handle).
 * @param c Connection this message was on.
 * @param type Type of message sent.
 * @param fwd Was this a FWD going message?
 * @param size Size of the message.
 * @param wait Time spent waiting for core (only the time for THIS message)
 */
static void
message_sent (void *cls,
              struct MeshConnection *c, uint16_t type,
              int fwd, size_t size,
              struct GNUNET_TIME_Relative wait)
{
  struct MeshConnectionPerformance *p;
  struct MeshFlowControl *fc;
  struct MeshConnectionQueue *q = cls;
  double usecsperbyte;
  int forced;

  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "!  sent %s %s\n",
       GM_f2s (fwd),
       GM_m2s (type));
  LOG (GNUNET_ERROR_TYPE_DEBUG, "!  C_P- %p %u\n", c, c->pending_messages);
  if (NULL != q)
  {
    forced = q->forced;
    if (NULL != q->cont)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "!  calling cont\n");
      q->cont (q->cont_cls, c, q, type, fwd, size);
    }
    GNUNET_free (q);
  }
  else if (type == GNUNET_MESSAGE_TYPE_MESH_ENCRYPTED)
  {
    /* If NULL == q and ENCRYPTED == type, message must have been ch_mngmnt */
    forced = GNUNET_YES;
  }
  else
  {
    forced = GNUNET_NO;
  }
  c->pending_messages--;
  if (GNUNET_YES == c->destroy && 0 == c->pending_messages)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "!  destroying connection!\n");
    GMC_destroy (c);
    return;
  }
  /* Send ACK if needed, after accounting for sent ID in fc->queue_n */
  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_CREATE:
    case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_ACK:
      c->maintenance_q = NULL;
      /* Don't trigger a keepalive for sent ACKs, only SYN and SYNACKs */
      if (GNUNET_MESSAGE_TYPE_MESH_CONNECTION_CREATE == type || !fwd)
        schedule_next_keepalive (c, fwd);
      break;

    case GNUNET_MESSAGE_TYPE_MESH_ENCRYPTED:
      fc->last_pid_sent++;
      LOG (GNUNET_ERROR_TYPE_DEBUG, "!  Q_N- %p %u\n", fc, fc->queue_n);
      if (GNUNET_NO == forced)
      {
        fc->queue_n--;
        LOG (GNUNET_ERROR_TYPE_DEBUG,
            "!   accounting pid %u\n",
            fc->last_pid_sent);
      }
      else
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "!   forced, Q_N not accounting pid %u\n",
             fc->last_pid_sent);
      }
      GMC_send_ack (c, fwd, GNUNET_NO);
      break;

    case GNUNET_MESSAGE_TYPE_MESH_POLL:
      fc->poll_msg = NULL;
      break;

    case GNUNET_MESSAGE_TYPE_MESH_ACK:
      fc->ack_msg = NULL;
      break;

    default:
      break;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "!  message sent!\n");

  if (NULL == c->perf)
    return; /* Only endpoints are interested in timing. */

  p = c->perf;
  usecsperbyte = ((double) wait.rel_value_us) / size;
  if (p->size == AVG_MSGS)
  {
    /* Array is full. Substract oldest value, add new one and store. */
    p->avg -= (p->usecsperbyte[p->idx] / AVG_MSGS);
    p->usecsperbyte[p->idx] = usecsperbyte;
    p->avg += (p->usecsperbyte[p->idx] / AVG_MSGS);
  }
  else
  {
    /* Array not yet full. Add current value to avg and store. */
    p->usecsperbyte[p->idx] = usecsperbyte;
    p->avg *= p->size;
    p->avg += p->usecsperbyte[p->idx];
    p->size++;
    p->avg /= p->size;
  }
  p->idx = (p->idx + 1) % AVG_MSGS;
}


/**
 * Get the previous hop in a connection
 *
 * @param c Connection.
 *
 * @return Previous peer in the connection.
 */
static struct MeshPeer *
get_prev_hop (const struct MeshConnection *c)
{
  GNUNET_PEER_Id id;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  get prev hop %s [%u/%u]\n",
       GMC_2s (c), c->own_pos, c->path->length);
  if (0 == c->own_pos || c->path->length < 2)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  own pos is zero\n");
    id = c->path->peers[0];
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  own pos is NOT zero\n");
    id = c->path->peers[c->own_pos - 1];
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  id: %u\n", id);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  ID: %s\n", GNUNET_i2s (GNUNET_PEER_resolve2 (id)));
  return GMP_get_short (id);
}


/**
 * Get the next hop in a connection
 *
 * @param c Connection.
 *
 * @return Next peer in the connection.
 */
static struct MeshPeer *
get_next_hop (const struct MeshConnection *c)
{
  GNUNET_PEER_Id id;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  get next hop %s [%u/%u]\n",
       GMC_2s (c), c->own_pos, c->path->length);
  if ((c->path->length - 1) == c->own_pos || c->path->length < 2)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  own pos is end\n");
    id = c->path->peers[c->path->length - 1];
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  own pos is NOT end\n");
    id = c->path->peers[c->own_pos + 1];
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  id: %u\n", id);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  ID: %s\n", GNUNET_i2s (GNUNET_PEER_resolve2 (id)));

  return GMP_get_short (id);
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
get_hop (struct MeshConnection *c, int fwd)
{
  if (fwd)
    return get_next_hop (c);
  return get_prev_hop (c);
}


/**
 * Is traffic coming from this sender 'FWD' traffic?
 *
 * @param c Connection to check.
 * @param sender Peer identity of neighbor.
 *
 * @return #GNUNET_YES in case the sender is the 'prev' hop and therefore
 *         the traffic is 'FWD'.
 *         #GNUNET_NO for BCK.
 *         #GNUNET_SYSERR for errors.
 */
static int
is_fwd (const struct MeshConnection *c,
        const struct GNUNET_PeerIdentity *sender)
{
  GNUNET_PEER_Id id;

  id = GNUNET_PEER_search (sender);
  if (GMP_get_short_id (get_prev_hop (c)) == id)
    return GNUNET_YES;

  if (GMP_get_short_id (get_next_hop (c)) == id)
    return GNUNET_NO;

  GNUNET_break (0);
  return GNUNET_SYSERR;
}


/**
 * Sends a CONNECTION ACK message in reponse to a received CONNECTION_CREATE
 * or a first CONNECTION_ACK directed to us.
 *
 * @param connection Connection to confirm.
 * @param fwd Should we send it FWD? (root->dest)
 *            (First (~SYNACK) goes BCK, second (~ACK) goes FWD)
 */
static void
send_connection_ack (struct MeshConnection *connection, int fwd)
{
  struct MeshTunnel3 *t;

  t = connection->t;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Send connection %s ACK\n",
       GM_f2s (!fwd));
  GMP_queue_add (get_hop (connection, fwd), NULL,
                 GNUNET_MESSAGE_TYPE_MESH_CONNECTION_ACK,
                 sizeof (struct GNUNET_MESH_ConnectionACK),
                 connection, fwd, &message_sent, NULL);
  connection->pending_messages++;
  if (MESH_TUNNEL3_NEW == GMT_get_cstate (t))
    GMT_change_cstate (t, MESH_TUNNEL3_WAITING);
  if (MESH_CONNECTION_READY != connection->state)
    connection_change_state (connection, MESH_CONNECTION_SENT);
}


/**
 * Send a notification that a connection is broken.
 *
 * @param c Connection that is broken.
 * @param id1 Peer that has disconnected.
 * @param id2 Peer that has disconnected.
 * @param fwd Direction towards which to send it.
 */
static void
send_broken (struct MeshConnection *c,
             const struct GNUNET_PeerIdentity *id1,
             const struct GNUNET_PeerIdentity *id2,
             int fwd)
{
  struct GNUNET_MESH_ConnectionBroken msg;

  msg.header.size = htons (sizeof (struct GNUNET_MESH_ConnectionBroken));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_CONNECTION_BROKEN);
  msg.cid = c->id;
  msg.peer1 = *id1;
  msg.peer2 = *id2;
  GMC_send_prebuilt_message (&msg.header, c, fwd, GNUNET_YES, NULL, NULL);
}


/**
 * Send a notification that a connection is broken, when a connection
 * isn't even created.
 *
 * @param connection_id Connection ID.
 * @param id1 Peer that has disconnected.
 * @param id2 Peer that has disconnected.
 * @param peer Peer to notify (neighbor who sent the connection).
 */
static void
send_broken2 (struct GNUNET_HashCode *connection_id,
             const struct GNUNET_PeerIdentity *id1,
             const struct GNUNET_PeerIdentity *id2,
             GNUNET_PEER_Id peer_id)
{
  struct GNUNET_MESH_ConnectionBroken *msg;
  struct MeshPeer *neighbor;

  msg = GNUNET_new (struct GNUNET_MESH_ConnectionBroken);
  msg->header.size = htons (sizeof (struct GNUNET_MESH_ConnectionBroken));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_CONNECTION_BROKEN);
  msg->cid = *connection_id;
  msg->peer1 = *id1;
  msg->peer2 = *id2;
  neighbor = GMP_get_short (peer_id);
  GMP_queue_add (neighbor, msg,
                 GNUNET_MESSAGE_TYPE_MESH_ENCRYPTED,
                 sizeof (struct GNUNET_MESH_ConnectionBroken),
                 NULL, GNUNET_SYSERR, /* connection, fwd */
                 NULL, NULL); /* continuation */
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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "sending %s keepalive for connection %s]\n",
       GM_f2s (fwd), GMC_2s (c));

  msg = (struct GNUNET_MESH_ConnectionKeepAlive *) cbuf;
  msg->header.size = htons (size);
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_KEEPALIVE);
  msg->cid = c->id;
  msg->reserved = htonl (0);

  GMC_send_prebuilt_message (&msg->header, c, fwd, GNUNET_YES, NULL, NULL);
}


/**
 * Send CONNECTION_{CREATE/ACK} packets for a connection.
 *
 * @param c Connection for which to send the message.
 * @param fwd If #GNUNET_YES, send CREATE, otherwise send ACK.
 */
static void
connection_recreate (struct MeshConnection *c, int fwd)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "sending connection recreate\n");
  if (fwd)
    GMC_send_create (c);
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
  if (GNUNET_NO != c->destroy)
    return;

  if (MESH_TUNNEL3_SEARCHING == GMT_get_cstate (c->t))
  {
    /* TODO DHT GET with RO_BART */
    return;
  }
  switch (c->state)
  {
    case MESH_CONNECTION_NEW:
      GNUNET_break (0);
      /* fall-through */
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


/**
 * Keep the connection alive in the FWD direction.
 *
 * @param cls Closure (connection to keepalive).
 * @param tc TaskContext.
 */
static void
connection_fwd_keepalive (void *cls,
                          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshConnection *c = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "FWD keepalive for %s\n", GMC_2s (c));
  c->fwd_maintenance_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  connection_maintain (c, GNUNET_YES);

  /* Next execution will be scheduled by message_sent */
}


/**
 * Keep the connection alive in the BCK direction.
 *
 * TODO refactor and merge with connection_fwd_keepalive.
 *
 * @param cls Closure (connection to keepalive).
 * @param tc TaskContext.
 */
static void
connection_bck_keepalive (void *cls,
                          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshConnection *c = cls;

  c->bck_maintenance_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  connection_maintain (c, GNUNET_NO);

  /* Next execution will be scheduled by message_sent */
}


/**
 * Schedule next keepalive task, taking in consideration
 * the connection state and number of retries.
 *
 * If the peer is not the origin, do nothing.
 *
 * @param c Connection for which to schedule the next keepalive.
 * @param fwd Direction for the next keepalive.
 */
static void
schedule_next_keepalive (struct MeshConnection *c, int fwd)
{
  struct GNUNET_TIME_Relative delay;
  GNUNET_SCHEDULER_TaskIdentifier *task_id;
  GNUNET_SCHEDULER_Task keepalive_task;

  if (GNUNET_NO == GMC_is_origin (c, fwd))
    return;

  /* Calculate delay to use, depending on the state of the connection */
  if (MESH_CONNECTION_READY == c->state)
  {
    delay = refresh_connection_time;
  }
  else
  {
    if (1 > c->create_retry)
      c->create_retry = 1;
    delay = GNUNET_TIME_relative_multiply (create_connection_time,
                                           c->create_retry);
    if (c->create_retry < 64)
      c->create_retry *= 2;
  }

  /* Select direction-dependent parameters */
  if (GNUNET_YES == fwd)
  {
    task_id = &c->fwd_maintenance_task;
    keepalive_task = &connection_fwd_keepalive;
  }
  else
  {
    task_id = &c->bck_maintenance_task;
    keepalive_task = &connection_bck_keepalive;
  }

  /* Check that no one scheduled it before us (and alert in that case) */
  if (GNUNET_SCHEDULER_NO_TASK != *task_id)
  {
    GNUNET_break (0);
    GNUNET_SCHEDULER_cancel (*task_id);
  }

  /* Schedule the task */
  *task_id = GNUNET_SCHEDULER_add_delayed (delay, keepalive_task, c);
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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "connection_unlock_queue %s on %s\n",
              GM_f2s (fwd), GMC_2s (c));

  if (GMC_is_terminal (c, fwd))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " is terminal!\n");
    return;
  }

  peer = get_hop (c, fwd);
  GMP_queue_unlock (peer, c);
}


/**
 * Cancel all transmissions that belong to a certain connection.
 *
 * If the connection is scheduled for destruction and no more messages are left,
 * the connection will be destroyed by the continuation call.
 *
 * @param c Connection which to cancel. Might be destroyed during this call.
 * @param fwd Cancel fwd traffic?
 */
static void
connection_cancel_queues (struct MeshConnection *c, int fwd)
{
  struct MeshFlowControl *fc;
  struct MeshPeer *peer;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       " *** Cancel %s queues for connection %s\n",
       GM_f2s (fwd), GMC_2s (c));
  if (NULL == c)
  {
    GNUNET_break (0);
    return;
  }

  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  if (GNUNET_SCHEDULER_NO_TASK != fc->poll_task)
  {
    GNUNET_SCHEDULER_cancel (fc->poll_task);
    fc->poll_task = GNUNET_SCHEDULER_NO_TASK;
    LOG (GNUNET_ERROR_TYPE_DEBUG, " *** Cancel POLL in ccq for fc %p\n", fc);
  }
  peer = get_hop (c, fwd);
  GMP_queue_cancel (peer, c);
}


/**
 * Function called if a connection has been stalled for a while,
 * possibly due to a missed ACK. Poll the neighbor about its ACK status.
 *
 * @param cls Closure (poll ctx).
 * @param tc TaskContext.
 */
static void
connection_poll (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Callback called when a queued POLL message is sent.
 *
 * @param cls Closure (FC).
 * @param c Connection this message was on.
 * @param q Queue handler this call invalidates.
 * @param type Type of message sent.
 * @param fwd Was this a FWD going message?
 * @param size Size of the message.
 */
static void
poll_sent (void *cls,
           struct MeshConnection *c,
           struct MeshConnectionQueue *q,
           uint16_t type, int fwd, size_t size)
{
  struct MeshFlowControl *fc = cls;

  if (2 == c->destroy)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " *** POLL canceled on shutdown\n");
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       " *** POLL sent for , scheduling new one!\n");
  fc->poll_msg = NULL;
  fc->poll_time = GNUNET_TIME_STD_BACKOFF (fc->poll_time);
  fc->poll_task = GNUNET_SCHEDULER_add_delayed (fc->poll_time,
                                                &connection_poll, fc);
  LOG (GNUNET_ERROR_TYPE_DEBUG, " task %u\n", fc->poll_task);

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
  LOG (GNUNET_ERROR_TYPE_DEBUG, " *** Polling!\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, " *** connection [%s]\n", GMC_2s (c));
  LOG (GNUNET_ERROR_TYPE_DEBUG, " ***   %s\n",
       fc == &c->fwd_fc ? "FWD" : "BCK");

  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_POLL);
  msg.header.size = htons (sizeof (msg));
  msg.pid = htonl (fc->last_pid_sent);
  LOG (GNUNET_ERROR_TYPE_DEBUG, " *** last pid sent: %u!\n", fc->last_pid_sent);
  fc->poll_msg = GMC_send_prebuilt_message (&msg.header, c,
                                            fc == &c->fwd_fc, GNUNET_YES,
                                            &poll_sent, fc);
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

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Connection %s FWD timed out. Destroying.\n",
       GMC_2s (c));
  if (GMC_is_origin (c, GNUNET_YES)) /* If local, leave. */
  {
    GNUNET_break (0);
    return;
  }

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

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Connection %s BCK timed out. Destroying.\n",
       GMC_2s (c));

  if (GMC_is_origin (c, GNUNET_NO)) /* If local, leave. */
  {
    GNUNET_break (0);
    return;
  }

  GMC_destroy (c);
}


/**
 * Resets the connection timeout task, some other message has done the
 * task's job.
 * - For the first peer on the direction this means to send
 *   a keepalive or a path confirmation message (either create or ACK).
 * - For all other peers, this means to destroy the connection,
 *   due to lack of activity.
 * Starts the timeout if no timeout was running (connection just created).
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

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Connection %s reset timeout\n", GM_f2s (fwd));

  if (GNUNET_SCHEDULER_NO_TASK != *ti)
    GNUNET_SCHEDULER_cancel (*ti);

  if (GMC_is_origin (c, fwd)) /* Startpoint */
  {
    f = fwd ? &connection_fwd_keepalive : &connection_bck_keepalive;
    *ti = GNUNET_SCHEDULER_add_delayed (refresh_connection_time, f, c);
  }
  else /* Relay, endpoint. */
  {
    struct GNUNET_TIME_Relative delay;

    delay = GNUNET_TIME_relative_multiply (refresh_connection_time, 4);
    f = fwd ? &connection_fwd_timeout : &connection_bck_timeout;
    *ti = GNUNET_SCHEDULER_add_delayed (delay, f, c);
  }
}


/**
 * Add the connection to the list of both neighbors.
 *
 * @param c Connection.
 *
 * @return #GNUNET_OK if everything went fine
 *         #GNUNET_SYSERR if the was an error and @c c is malformed.
 */
static int
register_neighbors (struct MeshConnection *c)
{
  struct MeshPeer *next_peer;
  struct MeshPeer *prev_peer;

  next_peer = get_next_hop (c);
  prev_peer = get_prev_hop (c);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "register neighbors for connection %s\n",
       GMC_2s (c));
  path_debug (c->path);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "own pos %u\n", c->own_pos);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "putting connection %s to next peer %p\n",
       GMC_2s (c), next_peer);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "next peer %p %s\n", next_peer, GMP_2s (next_peer));
  LOG (GNUNET_ERROR_TYPE_DEBUG, "putting connection %s to prev peer %p\n",
       GMC_2s (c), prev_peer);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "prev peer %p %s\n", prev_peer, GMP_2s (prev_peer));

  if (GNUNET_NO == GMP_is_neighbor (next_peer)
      || GNUNET_NO == GMP_is_neighbor (prev_peer))
  {
    if (GMC_is_origin (c, GNUNET_YES))
      GNUNET_STATISTICS_update (stats, "# local bad paths", 1, GNUNET_NO);
    GNUNET_STATISTICS_update (stats, "# bad paths", 1, GNUNET_NO);

    LOG (GNUNET_ERROR_TYPE_DEBUG, "  register neighbors failed\n");
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  prev: %s, neighbor?: %d\n",
         GMP_2s (prev_peer), GMP_is_neighbor (prev_peer));
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  next: %s, neighbor?: %d\n",
         GMP_2s (next_peer), GMP_is_neighbor (next_peer));
    return GNUNET_SYSERR;
  }

  GMP_add_connection (next_peer, c);
  GMP_add_connection (prev_peer, c);

  return GNUNET_OK;
}


/**
 * Remove the connection from the list of both neighbors.
 *
 * @param c Connection.
 */
static void
unregister_neighbors (struct MeshConnection *c)
{
  struct MeshPeer *peer;

  peer = get_next_hop (c);
  if (GNUNET_OK != GMP_remove_connection (peer, c))
  {
    GNUNET_assert (MESH_CONNECTION_NEW == c->state
                  || MESH_CONNECTION_DESTROYED == c->state);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  cstate: %u\n", c->state);
    if (NULL != c->t) GMT_debug (c->t);
  }

  peer = get_prev_hop (c);
  if (GNUNET_OK != GMP_remove_connection (peer, c))
  {
    GNUNET_assert (MESH_CONNECTION_NEW == c->state
                  || MESH_CONNECTION_DESTROYED == c->state);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  cstate: %u\n", c->state);
    if (NULL != c->t) GMT_debug (c->t);
  }
}


/**
 * Bind the connection to the peer and the tunnel to that peer.
 *
 * If the peer has no tunnel, create one. Update tunnel and connection
 * data structres to reflect new status.
 *
 * @param c Connection.
 * @param peer Peer.
 */
static void
add_to_peer (struct MeshConnection *c, struct MeshPeer *peer)
{
  GMP_add_tunnel (peer);
  c->t = GMP_get_tunnel (peer);
  GMT_add_connection (c->t, c);
}


/**
 * Builds a path from a PeerIdentity array.
 *
 * @param peers PeerIdentity array.
 * @param size Size of the @c peers array.
 * @param own_pos Output parameter: own position in the path.
 *
 * @return Fixed and shortened path.
 */
static struct MeshPeerPath *
build_path_from_peer_ids (struct GNUNET_PeerIdentity *peers,
                          unsigned int size,
                          unsigned int *own_pos)
{
  struct MeshPeerPath *path;
  GNUNET_PEER_Id shortid;
  unsigned int i;
  unsigned int j;
  unsigned int offset;

  /* Create path */
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  Creating path...\n");
  path = path_new (size);
  *own_pos = 0;
  offset = 0;
  for (i = 0; i < size; i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  - %u: taking %s\n",
         i, GNUNET_i2s (&peers[i]));
    shortid = GNUNET_PEER_intern (&peers[i]);

    /* Check for loops / duplicates */
    for (j = 0; j < i - offset; j++)
    {
      if (path->peers[j] == shortid)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG, "    already exists at pos %u\n", j);
        offset += i - j;
        LOG (GNUNET_ERROR_TYPE_DEBUG, "    offset now\n", offset);
        GNUNET_PEER_change_rc (shortid, -1);
      }
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG, "    storing at %u\n", i - offset);
    path->peers[i - offset] = shortid;
    if (path->peers[i] == myid)
      *own_pos = i;
  }
  path->length -= offset;

  if (path->peers[*own_pos] != myid)
  {
    /* create path: self not found in path through self */
    GNUNET_break_op (0);
    path_destroy (path);
    return NULL;
  }

  return path;
}

/******************************************************************************/
/********************************    API    ***********************************/
/******************************************************************************/

/**
 * Core handler for connection creation.
 *
 * @param cls Closure (unused).
 * @param peer Sender (neighbor).
 * @param message Message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GMC_handle_create (void *cls, const struct GNUNET_PeerIdentity *peer,
                   const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_ConnectionCreate *msg;
  struct GNUNET_PeerIdentity *id;
  struct GNUNET_HashCode *cid;
  struct MeshPeerPath *path;
  struct MeshPeer *dest_peer;
  struct MeshPeer *orig_peer;
  struct MeshConnection *c;
  unsigned int own_pos;
  uint16_t size;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "\n\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received a connection create msg\n");

  /* Check size */
  size = ntohs (message->size);
  if (size < sizeof (struct GNUNET_MESH_ConnectionCreate))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  /* Calculate hops */
  size -= sizeof (struct GNUNET_MESH_ConnectionCreate);
  if (size % sizeof (struct GNUNET_PeerIdentity))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  size /= sizeof (struct GNUNET_PeerIdentity);
  if (1 > size)
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "    path has %u hops.\n", size);

  /* Get parameters */
  msg = (struct GNUNET_MESH_ConnectionCreate *) message;
  cid = &msg->cid;
  id = (struct GNUNET_PeerIdentity *) &msg[1];
  LOG (GNUNET_ERROR_TYPE_DEBUG, "    connection %s (%s->).\n",
       GNUNET_h2s (cid), GNUNET_i2s (id));

  /* Create connection */
  c = connection_get (cid);
  if (NULL == c)
  {
    path = build_path_from_peer_ids ((struct GNUNET_PeerIdentity *) &msg[1],
                                     size, &own_pos);
    if (NULL == path)
      return GNUNET_OK;
    if (0 == own_pos)
    {
      GNUNET_break_op (0);
      path_destroy (path);
      return GNUNET_OK;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  Own position: %u\n", own_pos);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  Creating connection\n");
    c = GMC_new (cid, NULL, path_duplicate (path), own_pos);
    if (NULL == c)
    {
      if (path->length - 1 == own_pos)
      {
        /* If we are destination, why did the creation fail? */
        GNUNET_break (0);
        return GNUNET_OK;
      }
      send_broken2 (cid, &my_full_id,
                    GNUNET_PEER_resolve2 (path->peers[own_pos + 1]),
                    path->peers[own_pos - 1]);
      path_destroy (path);
      return GNUNET_OK;
    }
    GMP_add_path_to_all (path, GNUNET_NO);
    connection_reset_timeout (c, GNUNET_YES);
  }
  else
  {
    path = path_duplicate (c->path);
  }
  if (MESH_CONNECTION_NEW == c->state)
    connection_change_state (c, MESH_CONNECTION_SENT);

  /* Remember peers */
  dest_peer = GMP_get (&id[size - 1]);
  orig_peer = GMP_get (&id[0]);

  /* Is it a connection to us? */
  if (c->own_pos == size - 1)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  It's for us!\n");
    GMP_add_path_to_origin (orig_peer, path_duplicate (path), GNUNET_YES);

    add_to_peer (c, orig_peer);
    if (MESH_TUNNEL3_NEW == GMT_get_cstate (c->t))
      GMT_change_cstate (c->t,  MESH_TUNNEL3_WAITING);

    send_connection_ack (c, GNUNET_NO);
    if (MESH_CONNECTION_SENT == c->state)
      connection_change_state (c, MESH_CONNECTION_ACK);
  }
  else
  {
    /* It's for somebody else! Retransmit. */
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  Retransmitting.\n");
    GMP_add_path (dest_peer, path_duplicate (path), GNUNET_NO);
    GMP_add_path_to_origin (orig_peer, path_duplicate (path), GNUNET_NO);
    GMC_send_prebuilt_message (message, c, GNUNET_YES, GNUNET_YES,
                               NULL, NULL);
  }
  path_destroy (path);
  return GNUNET_OK;
}


/**
 * Core handler for path confirmations.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GMC_handle_confirm (void *cls, const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_ConnectionACK *msg;
  struct MeshConnection *c;
  struct MeshPeerPath *p;
  struct MeshPeer *pi;
  enum MeshConnectionState oldstate;
  int fwd;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "\n\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Received a connection ACK msg\n");
  msg = (struct GNUNET_MESH_ConnectionACK *) message;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  on connection %s\n",
              GNUNET_h2s (&msg->cid));
  c = connection_get (&msg->cid);
  if (NULL == c)
  {
    GNUNET_STATISTICS_update (stats, "# control on unknown connection",
                              1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  don't know the connection!\n");
    return GNUNET_OK;
  }

  if (GNUNET_NO != c->destroy)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  connection being destroyed\n");
    return GNUNET_OK;
  }

  oldstate = c->state;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  via peer %s\n", GNUNET_i2s (peer));
  pi = GMP_get (peer);
  if (get_next_hop (c) == pi)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  SYNACK\n");
    fwd = GNUNET_NO;
    if (MESH_CONNECTION_SENT == oldstate)
      connection_change_state (c, MESH_CONNECTION_ACK);
  }
  else if (get_prev_hop (c) == pi)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  ACK\n");
    fwd = GNUNET_YES;
    connection_change_state (c, MESH_CONNECTION_READY);
  }
  else
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  connection_reset_timeout (c, fwd);

  /* Add path to peers? */
  p = c->path;
  if (NULL != p)
  {
    GMP_add_path_to_all (p, GNUNET_YES);
  }
  else
  {
    GNUNET_break (0);
  }

  /* Message for us as creator? */
  if (GMC_is_origin (c, GNUNET_YES))
  {
    if (GNUNET_NO != fwd)
    {
      GNUNET_break_op (0);
      return GNUNET_OK;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  Connection (SYN)ACK for us!\n");

    /* If just created, cancel the short timeout and start a long one */
    if (MESH_CONNECTION_SENT == oldstate)
      connection_reset_timeout (c, GNUNET_YES);

    /* Change connection state */
    connection_change_state (c, MESH_CONNECTION_READY);
    send_connection_ack (c, GNUNET_YES);

    /* Change tunnel state, trigger KX */
    if (MESH_TUNNEL3_WAITING == GMT_get_cstate (c->t))
      GMT_change_cstate (c->t, MESH_TUNNEL3_READY);

    return GNUNET_OK;
  }

  /* Message for us as destination? */
  if (GMC_is_terminal (c, GNUNET_YES))
  {
    if (GNUNET_YES != fwd)
    {
      GNUNET_break_op (0);
      return GNUNET_OK;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  Connection ACK for us!\n");

    /* If just created, cancel the short timeout and start a long one */
    if (MESH_CONNECTION_ACK == oldstate)
      connection_reset_timeout (c, GNUNET_NO);

    /* Change tunnel state */
    if (MESH_TUNNEL3_WAITING == GMT_get_cstate (c->t))
      GMT_change_cstate (c->t, MESH_TUNNEL3_READY);

    return GNUNET_OK;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  not for us, retransmitting...\n");
  GMC_send_prebuilt_message (message, c, fwd, GNUNET_YES, NULL, NULL);
  return GNUNET_OK;
}


/**
 * Core handler for notifications of broken paths
 *
 * @param cls Closure (unused).
 * @param id Peer identity of sending neighbor.
 * @param message Message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GMC_handle_broken (void* cls,
                   const struct GNUNET_PeerIdentity* id,
                   const struct GNUNET_MessageHeader* message)
{
  struct GNUNET_MESH_ConnectionBroken *msg;
  struct MeshConnection *c;
  int fwd;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "Received a CONNECTION BROKEN msg from %s\n", GNUNET_i2s (id));
  msg = (struct GNUNET_MESH_ConnectionBroken *) message;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  regarding %s\n",
              GNUNET_i2s (&msg->peer1));
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  regarding %s\n",
              GNUNET_i2s (&msg->peer2));
  c = connection_get (&msg->cid);
  if (NULL == c)
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  fwd = is_fwd (c, id);
  if (GMC_is_terminal (c, fwd))
  {
    path_invalidate (c->path);
    if (0 < c->pending_messages)
      c->destroy = GNUNET_YES;
    else
      GMC_destroy (c);
  }
  else
  {
    GMC_send_prebuilt_message (message, c, fwd, GNUNET_YES, NULL, NULL);
    c->destroy = GNUNET_YES;
    connection_cancel_queues (c, !fwd);
  }

  return GNUNET_OK;

}


/**
 * Core handler for tunnel destruction
 *
 * @param cls Closure (unused).
 * @param peer Peer identity of sending neighbor.
 * @param message Message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GMC_handle_destroy (void *cls, const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_ConnectionDestroy *msg;
  struct MeshConnection *c;
  int fwd;

  msg = (struct GNUNET_MESH_ConnectionDestroy *) message;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "Got a CONNECTION DESTROY message from %s\n",
              GNUNET_i2s (peer));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "  for connection %s\n",
              GNUNET_h2s (&msg->cid));
  c = connection_get (&msg->cid);
  if (NULL == c)
  {
    /* Probably already got the message from another path,
     * destroyed the tunnel and retransmitted to children.
     * Safe to ignore.
     */
    GNUNET_STATISTICS_update (stats, "# control on unknown connection",
                              1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  connection unknown: already destroyed?\n");
    return GNUNET_OK;
  }
  fwd = is_fwd (c, peer);
  if (GNUNET_SYSERR == fwd)
  {
    GNUNET_break_op (0); /* FIXME */
    return GNUNET_OK;
  }
  if (GNUNET_NO == GMC_is_terminal (c, fwd))
    GMC_send_prebuilt_message (message, c, fwd, GNUNET_YES, NULL, NULL);
  else if (0 == c->pending_messages)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "!  directly destroying connection!\n");
    GMC_destroy (c);
    return GNUNET_OK;
  }
  c->destroy = GNUNET_YES;
  c->state = MESH_CONNECTION_DESTROYED;
  if (NULL != c->t)
  {
    GMT_remove_connection (c->t, c);
    c->t = NULL;
  }

  return GNUNET_OK;
}

/**
 * Generic handler for mesh network encrypted traffic.
 *
 * @param peer Peer identity this notification is about.
 * @param msg Encrypted message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_encrypted (const struct GNUNET_PeerIdentity *peer,
                       const struct GNUNET_MESH_Encrypted *msg)
{
  struct MeshConnection *c;
  struct MeshPeer *neighbor;
  struct MeshFlowControl *fc;
  GNUNET_PEER_Id peer_id;
  uint32_t pid;
  uint32_t ttl;
  uint16_t type;
  size_t size;
  int fwd;

  /* Check size */
  size = ntohs (msg->header.size);
  if (size <
      sizeof (struct GNUNET_MESH_Encrypted) +
      sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  type = ntohs (msg->header.type);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "\n\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "got a %s message (#%u) from %s\n",
       GM_m2s (type), ntohl (msg->pid), GNUNET_i2s (peer));

  /* Check connection */
  c = connection_get (&msg->cid);
  if (NULL == c)
  {
    GNUNET_STATISTICS_update (stats, "# unknown connection", 1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "WARNING enc on unknown connection %s\n",
         GNUNET_h2s (&msg->cid));
    return GNUNET_OK;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  on connection %s\n", GMC_2s (c));

  /* Check if origin is as expected */
  neighbor = get_prev_hop (c);
  peer_id = GNUNET_PEER_search (peer);
  if (peer_id == GMP_get_short_id (neighbor))
  {
    fwd = GNUNET_YES;
  }
  else
  {
    neighbor = get_next_hop (c);
    if (peer_id == GMP_get_short_id (neighbor))
    {
      fwd = GNUNET_NO;
    }
    else
    {
      /* Unexpected peer sending traffic on a connection. */
      GNUNET_break_op (0);
      return GNUNET_OK;
    }
  }

  /* Check PID */
  fc = fwd ? &c->bck_fc : &c->fwd_fc;
  pid = ntohl (msg->pid);
  if (GM_is_pid_bigger (pid, fc->last_ack_sent))
  {
    GNUNET_STATISTICS_update (stats, "# unsolicited message", 1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
                "WARNING Received PID %u, (prev %u), ACK %u\n",
                pid, fc->last_pid_recv, fc->last_ack_sent);
    return GNUNET_OK;
  }
  if (GNUNET_NO == GM_is_pid_bigger (pid, fc->last_pid_recv))
  {
    GNUNET_STATISTICS_update (stats, "# duplicate PID", 1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
                " Pid %u not expected (%u+), dropping!\n",
                pid, fc->last_pid_recv + 1);
    return GNUNET_OK;
  }
  if (MESH_CONNECTION_SENT == c->state || MESH_CONNECTION_ACK == c->state)
    connection_change_state (c, MESH_CONNECTION_READY);
  connection_reset_timeout (c, fwd);
  fc->last_pid_recv = pid;

  /* Is this message for us? */
  if (GMC_is_terminal (c, fwd))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  message for us!\n");
    GNUNET_STATISTICS_update (stats, "# messages received", 1, GNUNET_NO);

    if (NULL == c->t)
    {
      GNUNET_break (GNUNET_NO != c->destroy);
      return GNUNET_OK;
    }
    fc->last_pid_recv = pid;
    GMT_handle_encrypted (c->t, msg);
    GMC_send_ack (c, fwd, GNUNET_NO);
    return GNUNET_OK;
  }

  /* Message not for us: forward to next hop */
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  not for us, retransmitting...\n");
  ttl = ntohl (msg->ttl);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "   ttl: %u\n", ttl);
  if (ttl == 0)
  {
    GNUNET_STATISTICS_update (stats, "# TTL drops", 1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_WARNING, " TTL is 0, DROPPING!\n");
    GMC_send_ack (c, fwd, GNUNET_NO);
    return GNUNET_OK;
  }

  GNUNET_STATISTICS_update (stats, "# messages forwarded", 1, GNUNET_NO);
  GMC_send_prebuilt_message (&msg->header, c, fwd, GNUNET_NO, NULL, NULL);

  return GNUNET_OK;
}

/**
 * Generic handler for mesh network encrypted traffic.
 *
 * @param peer Peer identity this notification is about.
 * @param msg Encrypted message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_kx (const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MESH_KX *msg)
{
  struct MeshConnection *c;
  struct MeshPeer *neighbor;
  GNUNET_PEER_Id peer_id;
  size_t size;
  uint16_t type;
  int fwd;

  /* Check size */
  size = ntohs (msg->header.size);
  if (size <
      sizeof (struct GNUNET_MESH_Encrypted) +
      sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  type = ntohs (msg->header.type);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "\n\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "got a %s message from %s\n",
       GM_m2s (type), GNUNET_i2s (peer));

  /* Check connection */
  c = connection_get (&msg->cid);
  if (NULL == c)
  {
    GNUNET_STATISTICS_update (stats, "# unknown connection", 1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "WARNING kx on unknown connection %s\n",
         GNUNET_h2s (&msg->cid));
    return GNUNET_OK;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, " on connection %s\n", GMC_2s (c));

  /* Check if origin is as expected */
  neighbor = get_prev_hop (c);
  peer_id = GNUNET_PEER_search (peer);
  if (peer_id == GMP_get_short_id (neighbor))
  {
    fwd = GNUNET_YES;
  }
  else
  {
    neighbor = get_next_hop (c);
    if (peer_id == GMP_get_short_id (neighbor))
    {
      fwd = GNUNET_NO;
    }
    else
    {
      /* Unexpected peer sending traffic on a connection. */
      GNUNET_break_op (0);
      return GNUNET_OK;
    }
  }

  /* Count as connection confirmation. */
  if (MESH_CONNECTION_SENT == c->state || MESH_CONNECTION_ACK == c->state)
  {
    connection_change_state (c, MESH_CONNECTION_READY);
    if (NULL != c->t)
    {
      if (MESH_TUNNEL3_WAITING == GMT_get_cstate (c->t))
        GMT_change_cstate (c->t, MESH_TUNNEL3_READY);
    }
  }
  connection_reset_timeout (c, fwd);

  /* Is this message for us? */
  if (GMC_is_terminal (c, fwd))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  message for us!\n");
    GNUNET_STATISTICS_update (stats, "# messages received", 1, GNUNET_NO);
    if (NULL == c->t)
    {
      GNUNET_break (0);
      return GNUNET_OK;
    }
    GMT_handle_kx (c->t, &msg[1].header);
    return GNUNET_OK;
  }

  /* Message not for us: forward to next hop */
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  not for us, retransmitting...\n");
  GNUNET_STATISTICS_update (stats, "# messages forwarded", 1, GNUNET_NO);
  GMC_send_prebuilt_message (&msg->header, c, fwd, GNUNET_NO, NULL, NULL);

  return GNUNET_OK;
}


/**
 * Core handler for encrypted mesh network traffic (channel mgmt, data).
 *
 * @param cls Closure (unused).
 * @param message Message received.
 * @param peer Peer who sent the message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GMC_handle_encrypted (void *cls, const struct GNUNET_PeerIdentity *peer,
                      const struct GNUNET_MessageHeader *message)
{
  return handle_mesh_encrypted (peer,
                                (struct GNUNET_MESH_Encrypted *)message);
}


/**
 * Core handler for key exchange traffic (ephemeral key, ping, pong).
 *
 * @param cls Closure (unused).
 * @param message Message received.
 * @param peer Peer who sent the message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GMC_handle_kx (void *cls, const struct GNUNET_PeerIdentity *peer,
               const struct GNUNET_MessageHeader *message)
{
  return handle_mesh_kx (peer,
                         (struct GNUNET_MESH_KX *) message);
}


/**
 * Core handler for mesh network traffic point-to-point acks.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GMC_handle_ack (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_ACK *msg;
  struct MeshConnection *c;
  struct MeshFlowControl *fc;
  GNUNET_PEER_Id id;
  uint32_t ack;
  int fwd;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "\n\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Got an ACK packet from %s!\n",
              GNUNET_i2s (peer));
  msg = (struct GNUNET_MESH_ACK *) message;

  c = connection_get (&msg->cid);

  if (NULL == c)
  {
    GNUNET_STATISTICS_update (stats, "# ack on unknown connection", 1,
                              GNUNET_NO);
    return GNUNET_OK;
  }

  /* Is this a forward or backward ACK? */
  id = GNUNET_PEER_search (peer);
  if (GMP_get_short_id (get_next_hop (c)) == id)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  FWD ACK\n");
    fc = &c->fwd_fc;
    fwd = GNUNET_YES;
  }
  else if (GMP_get_short_id (get_prev_hop (c)) == id)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  BCK ACK\n");
    fc = &c->bck_fc;
    fwd = GNUNET_NO;
  }
  else
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  ack = ntohl (msg->ack);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  ACK %u (was %u)\n",
              ack, fc->last_ack_recv);
  if (GM_is_pid_bigger (ack, fc->last_ack_recv))
    fc->last_ack_recv = ack;

  /* Cancel polling if the ACK is big enough. */
  if (GNUNET_SCHEDULER_NO_TASK != fc->poll_task &&
      GM_is_pid_bigger (fc->last_ack_recv, fc->last_pid_sent))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  Cancel poll\n");
    GNUNET_SCHEDULER_cancel (fc->poll_task);
    fc->poll_task = GNUNET_SCHEDULER_NO_TASK;
    fc->poll_time = GNUNET_TIME_UNIT_SECONDS;
  }

  connection_unlock_queue (c, fwd);

  return GNUNET_OK;
}


/**
 * Core handler for mesh network traffic point-to-point ack polls.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GMC_handle_poll (void *cls, const struct GNUNET_PeerIdentity *peer,
                 const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_Poll *msg;
  struct MeshConnection *c;
  struct MeshFlowControl *fc;
  GNUNET_PEER_Id id;
  uint32_t pid;
  int fwd;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "\n\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got a POLL message from %s!\n",
       GNUNET_i2s (peer));

  msg = (struct GNUNET_MESH_Poll *) message;

  c = connection_get (&msg->cid);

  if (NULL == c)
  {
    GNUNET_STATISTICS_update (stats, "# poll on unknown connection", 1,
                              GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "WARNING POLL message on unknown connection %s!\n",
         GNUNET_h2s (&msg->cid));
    return GNUNET_OK;
  }

  /* Is this a forward or backward ACK?
   * Note: a poll should never be needed in a loopback case,
   * since there is no possiblility of packet loss there, so
   * this way of discerining FWD/BCK should not be a problem.
   */
  id = GNUNET_PEER_search (peer);
  if (GMP_get_short_id (get_next_hop (c)) == id)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  FWD FC\n");
    fc = &c->fwd_fc;
  }
  else if (GMP_get_short_id (get_prev_hop (c)) == id)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  BCK FC\n");
    fc = &c->bck_fc;
  }
  else
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  pid = ntohl (msg->pid);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  PID %u, OLD %u\n", pid, fc->last_pid_recv);
  fc->last_pid_recv = pid;
  fwd = fc == &c->bck_fc;
  GMC_send_ack (c, fwd, GNUNET_YES);

  return GNUNET_OK;
}


/**
 * Core handler for mesh keepalives.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 *
 * TODO: Check who we got this from, to validate route.
 */
int
GMC_handle_keepalive (void *cls, const struct GNUNET_PeerIdentity *peer,
                      const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_ConnectionKeepAlive *msg;
  struct MeshConnection *c;
  struct MeshPeer *neighbor;
  GNUNET_PEER_Id peer_id;
  int fwd;

  msg = (struct GNUNET_MESH_ConnectionKeepAlive *) message;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "got a keepalive packet from %s\n",
              GNUNET_i2s (peer));

  c = connection_get (&msg->cid);
  if (NULL == c)
  {
    GNUNET_STATISTICS_update (stats, "# keepalive on unknown connection", 1,
                              GNUNET_NO);
    return GNUNET_OK;
  }

  /* Check if origin is as expected TODO refactor and reuse */
  peer_id = GNUNET_PEER_search (peer);
  neighbor = get_prev_hop (c);
  if (peer_id == GMP_get_short_id (neighbor))
  {
    fwd = GNUNET_YES;
  }
  else
  {
    neighbor = get_next_hop (c);
    if (peer_id == GMP_get_short_id (neighbor))
    {
      fwd = GNUNET_NO;
    }
    else
    {
      GNUNET_break_op (0);
      return GNUNET_OK;
    }
  }

  connection_change_state (c, MESH_CONNECTION_READY);
  connection_reset_timeout (c, fwd);

  if (GMC_is_terminal (c, fwd))
    return GNUNET_OK;

  GNUNET_STATISTICS_update (stats, "# keepalives forwarded", 1, GNUNET_NO);
  GMC_send_prebuilt_message (message, c, fwd, GNUNET_YES, NULL, NULL);

  return GNUNET_OK;
}


/**
 * Send an ACK on the appropriate connection/channel, depending on
 * the direction and the position of the peer.
 *
 * @param c Which connection to send the hop-by-hop ACK.
 * @param fwd Is this a fwd ACK? (will go dest->root).
 * @param force Send the ACK even if suboptimal (e.g. requested by POLL).
 */
void
GMC_send_ack (struct MeshConnection *c, int fwd, int force)
{
  unsigned int buffer;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "GMC send %s ACK on %s\n",
       GM_f2s (fwd), GMC_2s (c));

  if (NULL == c)
  {
    GNUNET_break (0);
    return;
  }

  if (GNUNET_NO != c->destroy)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  being destroyed, why bother...\n");
    return;
  }

  /* Get available buffer space */
  if (GMC_is_terminal (c, fwd))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  getting from all channels\n");
    buffer = GMT_get_channels_buffer (c->t);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  getting from one connection\n");
    buffer = GMC_get_buffer (c, fwd);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  buffer available: %u\n", buffer);
  if (0 == buffer && GNUNET_NO == force)
    return;

  /* Send available buffer space */
  if (GMC_is_origin (c, fwd))
  {
    GNUNET_assert (NULL != c->t);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  sending on channels...\n");
    GMT_unchoke_channels (c->t);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  sending on connection\n");
    send_ack (c, buffer, fwd, force);
  }
}


/**
 * Initialize the connections subsystem
 *
 * @param c Configuration handle.
 */
void
GMC_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "init\n");
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
  create_connection_time = GNUNET_TIME_UNIT_SECONDS;
  connections = GNUNET_CONTAINER_multihashmap_create (1024, GNUNET_YES);
}


/**
 * Destroy each connection on shutdown.
 *
 * @param cls Closure (unused).
 * @param key Current key code (CID, unused).
 * @param value Value in the hash map (connection)
 *
 * @return #GNUNET_YES, because we should continue to iterate,
 */
static int
shutdown_iterator (void *cls,
                   const struct GNUNET_HashCode *key,
                   void *value)
{
  struct MeshConnection *c = value;

  GMC_destroy (c);
  return GNUNET_YES;
}


/**
 * Shut down the connections subsystem.
 */
void
GMC_shutdown (void)
{
  GNUNET_CONTAINER_multihashmap_iterate (connections, &shutdown_iterator, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (connections);
  connections = NULL;
}


struct MeshConnection *
GMC_new (const struct GNUNET_HashCode *cid,
         struct MeshTunnel3 *t,
         struct MeshPeerPath *p,
         unsigned int own_pos)
{
  struct MeshConnection *c;

  c = GNUNET_new (struct MeshConnection);
  c->id = *cid;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (connections,
                                                    &c->id, c,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  fc_init (&c->fwd_fc);
  fc_init (&c->bck_fc);
  c->fwd_fc.c = c;
  c->bck_fc.c = c;

  c->t = t;
  GNUNET_assert (own_pos <= p->length - 1);
  c->own_pos = own_pos;
  c->path = p;

  if (GNUNET_OK != register_neighbors (c))
  {
    if (0 == own_pos)
    {
      path_invalidate (c->path);
      c->t = NULL;
      c->path = NULL;
    }
    GMC_destroy (c);
    return NULL;
  }

  return c;
}


void
GMC_destroy (struct MeshConnection *c)
{
  if (NULL == c)
  {
    GNUNET_break (0);
    return;
  }

  if (2 == c->destroy) /* cancel queues -> GMP_queue_cancel -> q_destroy -> */
    return;            /* -> message_sent -> GMC_destroy. Don't loop. */
  c->destroy = 2;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "destroying connection %s\n", GMC_2s (c));
  LOG (GNUNET_ERROR_TYPE_DEBUG, " fc's f: %p, b: %p\n",
       &c->fwd_fc, &c->bck_fc);
  LOG (GNUNET_ERROR_TYPE_DEBUG, " fc tasks f: %u, b: %u\n",
       c->fwd_fc.poll_task, c->bck_fc.poll_task);

  /* Cancel all traffic */
  if (NULL != c->path)
  {
    connection_cancel_queues (c, GNUNET_YES);
    connection_cancel_queues (c, GNUNET_NO);
    unregister_neighbors (c);
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG, " fc tasks f: %u, b: %u\n",
       c->fwd_fc.poll_task, c->bck_fc.poll_task);

  /* Cancel maintainance task (keepalive/timeout) */
  if (NULL != c->fwd_fc.poll_msg)
  {
    GMC_cancel (c->fwd_fc.poll_msg);
    LOG (GNUNET_ERROR_TYPE_DEBUG, " *** POLL msg FWD canceled\n");
  }
  if (NULL != c->bck_fc.poll_msg)
  {
    GMC_cancel (c->bck_fc.poll_msg);
    LOG (GNUNET_ERROR_TYPE_DEBUG, " *** POLL msg BCK canceled\n");
  }

  /* Delete from tunnel */
  if (NULL != c->t)
    GMT_remove_connection (c->t, c);

  if (GNUNET_NO == GMC_is_origin (c, GNUNET_YES) && NULL != c->path)
    path_destroy (c->path);
  if (GNUNET_SCHEDULER_NO_TASK != c->fwd_maintenance_task)
    GNUNET_SCHEDULER_cancel (c->fwd_maintenance_task);
  if (GNUNET_SCHEDULER_NO_TASK != c->bck_maintenance_task)
    GNUNET_SCHEDULER_cancel (c->bck_maintenance_task);
  if (GNUNET_SCHEDULER_NO_TASK != c->fwd_fc.poll_task)
  {
    GNUNET_SCHEDULER_cancel (c->fwd_fc.poll_task);
    LOG (GNUNET_ERROR_TYPE_DEBUG, " *** POLL FWD canceled\n");
  }
  if (GNUNET_SCHEDULER_NO_TASK != c->bck_fc.poll_task)
  {
    GNUNET_SCHEDULER_cancel (c->bck_fc.poll_task);
    LOG (GNUNET_ERROR_TYPE_DEBUG, " *** POLL BCK canceled\n");
  }

  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_multihashmap_remove (connections, &c->id, c));

  GNUNET_STATISTICS_update (stats, "# connections", -1, GNUNET_NO);
  GNUNET_free (c);
}

/**
 * Get the connection ID.
 *
 * @param c Connection to get the ID from.
 *
 * @return ID of the connection.
 */
const struct GNUNET_HashCode *
GMC_get_id (const struct MeshConnection *c)
{
  return &c->id;
}


/**
 * Get the connection path.
 *
 * @param c Connection to get the path from.
 *
 * @return path used by the connection.
 */
const struct MeshPeerPath *
GMC_get_path (const struct MeshConnection *c)
{
  if (GNUNET_NO == c->destroy)
    return c->path;
  return NULL;
}


/**
 * Get the connection state.
 *
 * @param c Connection to get the state from.
 *
 * @return state of the connection.
 */
enum MeshConnectionState
GMC_get_state (const struct MeshConnection *c)
{
  return c->state;
}

/**
 * Get the connection tunnel.
 *
 * @param c Connection to get the tunnel from.
 *
 * @return tunnel of the connection.
 */
struct MeshTunnel3 *
GMC_get_tunnel (const struct MeshConnection *c)
{
  return c->t;
}


/**
 * Get free buffer space in a connection.
 *
 * @param c Connection.
 * @param fwd Is query about FWD traffic?
 *
 * @return Free buffer space [0 - max_msgs_queue/max_connections]
 */
unsigned int
GMC_get_buffer (struct MeshConnection *c, int fwd)
{
  struct MeshFlowControl *fc;

  fc = fwd ? &c->fwd_fc : &c->bck_fc;

  return (fc->queue_max - fc->queue_n);
}

/**
 * Get how many messages have we allowed to send to us from a direction.
 *
 * @param c Connection.
 * @param fwd Are we asking about traffic from FWD (BCK messages)?
 *
 * @return last_ack_sent - last_pid_recv
 */
unsigned int
GMC_get_allowed (struct MeshConnection *c, int fwd)
{
  struct MeshFlowControl *fc;

  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  if (GM_is_pid_bigger(fc->last_pid_recv, fc->last_ack_sent))
  {
    return 0;
  }
  return (fc->last_ack_sent - fc->last_pid_recv);
}

/**
 * Get messages queued in a connection.
 *
 * @param c Connection.
 * @param fwd Is query about FWD traffic?
 *
 * @return Number of messages queued.
 */
unsigned int
GMC_get_qn (struct MeshConnection *c, int fwd)
{
  struct MeshFlowControl *fc;

  fc = fwd ? &c->fwd_fc : &c->bck_fc;

  return fc->queue_n;
}


/**
 * Allow the connection to advertise a buffer of the given size.
 *
 * The connection will send an @c fwd ACK message (so: in direction !fwd)
 * allowing up to last_pid_recv + buffer.
 *
 * @param c Connection.
 * @param buffer How many more messages the connection can accept.
 * @param fwd Is this about FWD traffic? (The ack will go dest->root).
 */
void
GMC_allow (struct MeshConnection *c, unsigned int buffer, int fwd)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  allowing %s %u messages %s\n",
       GMC_2s (c), buffer, GM_f2s (fwd));
  send_ack (c, buffer, fwd, GNUNET_NO);
}


/**
 * Notify other peers on a connection of a broken link. Mark connections
 * to destroy after all traffic has been sent.
 *
 * @param c Connection on which there has been a disconnection.
 * @param peer Peer that disconnected.
 */
void
GMC_notify_broken (struct MeshConnection *c,
                   struct MeshPeer *peer)
{
  int fwd;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       " notify broken on %s due to %s disconnect\n",
       GMC_2s (c), GMP_2s (peer));

  fwd = peer == get_prev_hop (c);

  if (GNUNET_YES == GMC_is_terminal (c, fwd))
  {
    /* Local shutdown, no one to notify about this. */
    GMC_destroy (c);
    return;
  }
  if (GNUNET_NO == c->destroy)
    send_broken (c, &my_full_id, GMP_get_id (peer), fwd);

  /* Connection will have at least one pending message
   * (the one we just scheduled), so no point in checking whether to
   * destroy immediately. */
  c->destroy = GNUNET_YES;
  c->state = MESH_CONNECTION_DESTROYED;

  /**
   * Cancel all queues, if no message is left, connection will be destroyed.
   */
  connection_cancel_queues (c, !fwd);

  return;
}


/**
 * Is this peer the first one on the connection?
 *
 * @param c Connection.
 * @param fwd Is this about fwd traffic?
 *
 * @return #GNUNET_YES if origin, #GNUNET_NO if relay/terminal.
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
 * @return #GNUNET_YES if terminal, #GNUNET_NO if relay/origin.
 */
int
GMC_is_terminal (struct MeshConnection *c, int fwd)
{
  return GMC_is_origin (c, !fwd);
}


/**
 * See if we are allowed to send by the next hop in the given direction.
 *
 * @param c Connection.
 * @param fwd Is this about fwd traffic?
 *
 * @return #GNUNET_YES in case it's OK to send.
 */
int
GMC_is_sendable (struct MeshConnection *c, int fwd)
{
  struct MeshFlowControl *fc;

  if (NULL == c)
  {
    GNUNET_break (0);
    return GNUNET_YES;
  }
  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  if (GM_is_pid_bigger (fc->last_ack_recv, fc->last_pid_sent))
    return GNUNET_YES;
  return GNUNET_NO;
}

/**
 * Sends an already built message on a connection, properly registering
 * all used resources.
 *
 * @param message Message to send. Function makes a copy of it.
 *                If message is not hop-by-hop, decrements TTL of copy.
 * @param c Connection on which this message is transmitted.
 * @param fwd Is this a fwd message?
 * @param force Force the connection to accept the message (buffer overfill).
 * @param cont Continuation called once message is sent. Can be NULL.
 * @param cont_cls Closure for @c cont.
 *
 * @return Handle to cancel the message before it's sent.
 *         NULL on error or if @c cont is NULL.
 *         Invalid on @c cont call.
 */
struct MeshConnectionQueue *
GMC_send_prebuilt_message (const struct GNUNET_MessageHeader *message,
                           struct MeshConnection *c, int fwd, int force,
                           GMC_sent cont, void *cont_cls)
{
  struct MeshFlowControl *fc;
  struct MeshConnectionQueue *q;
  void *data;
  size_t size;
  uint16_t type;
  int droppable;

  size = ntohs (message->size);
  data = GNUNET_malloc (size);
  memcpy (data, message, size);
  type = ntohs (message->type);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Send %s (%u bytes) on connection %s\n",
       GM_m2s (type), size, GMC_2s (c));

  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  droppable = GNUNET_NO == force;
  switch (type)
  {
    struct GNUNET_MESH_Encrypted *emsg;
    struct GNUNET_MESH_KX        *kmsg;
    struct GNUNET_MESH_ACK       *amsg;
    struct GNUNET_MESH_Poll      *pmsg;
    struct GNUNET_MESH_ConnectionDestroy *dmsg;
    struct GNUNET_MESH_ConnectionBroken  *bmsg;
    uint32_t ttl;

    case GNUNET_MESSAGE_TYPE_MESH_ENCRYPTED:
      emsg = (struct GNUNET_MESH_Encrypted *) data;
      ttl = ntohl (emsg->ttl);
      if (0 == ttl)
      {
        GNUNET_break_op (0);
        GNUNET_free (data);
        return NULL;
      }
      emsg->cid = c->id;
      emsg->ttl = htonl (ttl - 1);
      emsg->pid = htonl (fc->next_pid++);
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  Q_N+ %p %u\n", fc, fc->queue_n);
      if (GNUNET_YES == droppable)
      {
        fc->queue_n++;
        LOG (GNUNET_ERROR_TYPE_DEBUG, "pid %u\n", ntohl (emsg->pid));
        LOG (GNUNET_ERROR_TYPE_DEBUG, "last pid sent %u\n", fc->last_pid_sent);
        LOG (GNUNET_ERROR_TYPE_DEBUG, "     ack recv %u\n", fc->last_ack_recv);
      }
      else
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG, "  not droppable, Q_N stays the same\n");
      }
      if (GM_is_pid_bigger (fc->last_pid_sent + 1, fc->last_ack_recv))
      {
        GMC_start_poll (c, fwd);
      }
      break;

    case GNUNET_MESSAGE_TYPE_MESH_KX:
      kmsg = (struct GNUNET_MESH_KX *) data;
      kmsg->cid = c->id;
      break;

    case GNUNET_MESSAGE_TYPE_MESH_ACK:
      amsg = (struct GNUNET_MESH_ACK *) data;
      amsg->cid = c->id;
      LOG (GNUNET_ERROR_TYPE_DEBUG, " ack %u\n", ntohl (amsg->ack));
      droppable = GNUNET_NO;
      break;

    case GNUNET_MESSAGE_TYPE_MESH_POLL:
      pmsg = (struct GNUNET_MESH_Poll *) data;
      pmsg->cid = c->id;
      LOG (GNUNET_ERROR_TYPE_DEBUG, " poll %u\n", ntohl (pmsg->pid));
      droppable = GNUNET_NO;
      break;

    case GNUNET_MESSAGE_TYPE_MESH_CONNECTION_DESTROY:
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
    case GNUNET_MESSAGE_TYPE_MESH_KEEPALIVE:
      break;

    default:
      GNUNET_break (0);
      GNUNET_free (data);
      return NULL;
  }

  if (fc->queue_n > fc->queue_max && droppable)
  {
    GNUNET_STATISTICS_update (stats, "# messages dropped (buffer full)",
                              1, GNUNET_NO);
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
                "queue full: %u/%u\n",
                fc->queue_n, fc->queue_max);
    if (GNUNET_MESSAGE_TYPE_MESH_ENCRYPTED == type)
    {
      fc->queue_n--;
      fc->next_pid--;
    }
    GNUNET_free (data);
    return NULL; /* Drop this message */
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  C_P+ %p %u\n", c, c->pending_messages);
  c->pending_messages++;

  q = GNUNET_new (struct MeshConnectionQueue);
  q->forced = !droppable;
  q->q = GMP_queue_add (get_hop (c, fwd), data, type, size, c, fwd,
                        &message_sent, q);
  if (NULL == q->q)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "WARNING dropping msg on %s\n", GMC_2s (c));
    GNUNET_free (data);
    GNUNET_free (q);
    return NULL;
  }
  q->cont = cont;
  q->cont_cls = cont_cls;
  return q;
}


/**
 * Cancel a previously sent message while it's in the queue.
 *
 * ONLY can be called before the continuation given to the send function
 * is called. Once the continuation is called, the message is no longer in the
 * queue.
 *
 * @param q Handle to the queue.
 */
void
GMC_cancel (struct MeshConnectionQueue *q)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "!  GMC cancel message\n");

  /* queue destroy calls message_sent, which calls q->cont and frees q */
  GMP_queue_destroy (q->q, GNUNET_YES);
}


/**
 * Sends a CREATE CONNECTION message for a path to a peer.
 * Changes the connection and tunnel states if necessary.
 *
 * @param connection Connection to create.
 */
void
GMC_send_create (struct MeshConnection *connection)
{
  enum MeshTunnel3CState state;
  size_t size;

  size = sizeof (struct GNUNET_MESH_ConnectionCreate);
  size += connection->path->length * sizeof (struct GNUNET_PeerIdentity);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Send connection create\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  C_P+ %p %u (create)\n",
       connection, connection->pending_messages);
  connection->pending_messages++;

  connection->maintenance_q =
    GMP_queue_add (get_next_hop (connection), NULL,
                   GNUNET_MESSAGE_TYPE_MESH_CONNECTION_CREATE,
                   size, connection, GNUNET_YES, &message_sent, NULL);

  state = GMT_get_cstate (connection->t);
  if (MESH_TUNNEL3_SEARCHING == state || MESH_TUNNEL3_NEW == state)
    GMT_change_cstate (connection->t, MESH_TUNNEL3_WAITING);
  if (MESH_CONNECTION_NEW == connection->state)
    connection_change_state (connection, MESH_CONNECTION_SENT);
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
void
GMC_send_destroy (struct MeshConnection *c)
{
  struct GNUNET_MESH_ConnectionDestroy msg;

  if (GNUNET_YES == c->destroy)
    return;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_CONNECTION_DESTROY);;
  msg.cid = c->id;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "  sending connection destroy for connection %s\n",
              GMC_2s (c));

  if (GNUNET_NO == GMC_is_terminal (c, GNUNET_YES))
    GMC_send_prebuilt_message (&msg.header, c,
                               GNUNET_YES, GNUNET_YES, NULL, NULL);
  if (GNUNET_NO == GMC_is_terminal (c, GNUNET_NO))
    GMC_send_prebuilt_message (&msg.header, c,
                               GNUNET_NO, GNUNET_YES, NULL, NULL);
  c->destroy = GNUNET_YES;
  c->state = MESH_CONNECTION_DESTROYED;
}


/**
 * @brief Start a polling timer for the connection.
 *
 * When a neighbor does not accept more traffic on the connection it could be
 * caused by a simple congestion or by a lost ACK. Polling enables to check
 * for the lastest ACK status for a connection.
 *
 * @param c Connection.
 * @param fwd Should we poll in the FWD direction?
 */
void
GMC_start_poll (struct MeshConnection *c, int fwd)
{
  struct MeshFlowControl *fc;

  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  LOG (GNUNET_ERROR_TYPE_DEBUG, " *** POLL %s requested\n",
       GM_f2s (fwd));
  if (GNUNET_SCHEDULER_NO_TASK != fc->poll_task || NULL != fc->poll_msg)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " ***   not needed (%u, %p)\n",
         fc->poll_task, fc->poll_msg);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, " *** POLL started on request\n");
  fc->poll_task = GNUNET_SCHEDULER_add_delayed (fc->poll_time,
                                                &connection_poll,
                                                fc);
}


/**
 * @brief Stop polling a connection for ACKs.
 *
 * Once we have enough ACKs for future traffic, polls are no longer necessary.
 *
 * @param c Connection.
 * @param fwd Should we stop the poll in the FWD direction?
 */
void
GMC_stop_poll (struct MeshConnection *c, int fwd)
{
  struct MeshFlowControl *fc;

  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  if (GNUNET_SCHEDULER_NO_TASK != fc->poll_task)
  {
    GNUNET_SCHEDULER_cancel (fc->poll_task);
    fc->poll_task = GNUNET_SCHEDULER_NO_TASK;
  }
}

/**
 * Get a (static) string for a connection.
 *
 * @param c Connection.
 */
const char *
GMC_2s (const struct MeshConnection *c)
{
  if (NULL == c)
    return "NULL";

  if (NULL != c->t)
  {
    static char buf[128];

    sprintf (buf, "%s (->%s)", GNUNET_h2s (&c->id), GMT_2s (c->t));
    return buf;
  }
  return GNUNET_h2s (&c->id);
}
