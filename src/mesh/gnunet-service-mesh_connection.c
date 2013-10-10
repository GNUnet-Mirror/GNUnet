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
#include "mesh_protocol_enc.h"
#include "mesh_enc.h"
#include "gnunet-service-mesh_connection.h"
#include "gnunet-service-mesh_peer.h"
#include "gnunet-service-mesh_tunnel.h"
#include "gnunet-service-mesh_channel.h"


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
              peer2s (c->t->peer), GNUNET_h2s (&c->id));
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  state: %u, pending msgs: %u\n",
              c->state, c->pending_messages);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  FWD FC\n");
  fc_debug (&c->fwd_fc);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  BCK FC\n");
  fc_debug (&c->bck_fc);
}
#endif

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
              GNUNET_h2s (&c->id), GMC_state2s (c->state));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "Connection %s state is now %s\n",
              GNUNET_h2s (&c->id), GMC_state2s (state));
  c->state = state;
}


/**
 * Callback called when a queued message is sent.
 *
 * Calculates the average time 
 *
 * @param cls Closure.
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
  double usecsperbyte;

  if (NULL == c->perf)
    return; /* Only endpoints are interested in this. */

  LOG (GNUNET_ERROR_TYPE_DEBUG, "!  message sent!\n");
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

  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "!  Q_N- %p %u\n", fc, fc->queue_n);
  fc->queue_n--;
  c->pending_messages--;
  if (GNUNET_YES == c->destroy && 0 == c->pending_messages)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "!  destroying connection!\n");
    GMC_destroy (c);
  }
  /* Send ACK if needed, after accounting for sent ID in fc->queue_n */
  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_MESH_FWD:
    case GNUNET_MESSAGE_TYPE_MESH_BCK:
      fc->last_pid_sent++;
      LOG (GNUNET_ERROR_TYPE_DEBUG, "!   accounting pid %u\n", fc->last_pid_sent);
//       send_ack (c, ch, fwd);
      break;
    default:
      break;
  }
//   if (NULL != c->t)
//   {
//     c->t->pending_messages--;
//     if (GNUNET_YES == c->t->destroy && 0 == t->pending_messages)
//     {
//       LOG (GNUNET_ERROR_TYPE_DEBUG, "*  destroying tunnel!\n");
//       GMT_destroy (c->t);
//     }
//   }
}


/**
 * Get the previous hop in a connection
 *
 * @param c Connection.
 *
 * @return Previous peer in the connection.
 */
static struct MeshPeer *
get_prev_hop (struct MeshConnection *c)
{
  GNUNET_PEER_Id id;

  if (0 == c->own_pos || c->path->length < 2)
    id = c->path->peers[0];
  else
    id = c->path->peers[c->own_pos - 1];

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
get_next_hop (struct MeshConnection *c)
{
  GNUNET_PEER_Id id;

  if ((c->path->length - 1) == c->own_pos || c->path->length < 2)
    id = c->path->peers[c->path->length - 1];
  else
    id = c->path->peers[c->own_pos + 1];

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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "connection send %s ack on %s\n",
              fwd ? "FWD" : "BCK", GNUNET_h2s (&c->id));

  /* Check if we need to transmit the ACK */
  if (prev_fc->last_ack_sent - prev_fc->last_pid_recv > 3)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Not sending ACK, buffer > 3\n");
    LOG (GNUNET_ERROR_TYPE_DEBUG,
                "  last pid recv: %u, last ack sent: %u\n",
                prev_fc->last_pid_recv, prev_fc->last_ack_sent);
    return;
  }

  /* Ok, ACK might be necessary, what PID to ACK? */
  delta = next_fc->queue_max - next_fc->queue_n;
  ack = prev_fc->last_pid_recv + delta;
  LOG (GNUNET_ERROR_TYPE_DEBUG, " ACK %u\n", ack);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
              " last pid %u, last ack %u, qmax %u, q %u\n",
              prev_fc->last_pid_recv, prev_fc->last_ack_sent,
              next_fc->queue_max, next_fc->queue_n);
  if (ack == prev_fc->last_ack_sent)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Not sending FWD ACK, not needed\n");
    return;
  }

  prev_fc->last_ack_sent = ack;

  /* Build ACK message and send on connection */
  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_ACK);
  msg.ack = htonl (ack);
  msg.cid = c->id;

  GMC_send_prebuilt_message (&msg.header, c, NULL, !fwd);
}


/**
 * Sends a CONNECTION ACK message in reponse to a received CONNECTION_CREATE
 * or a first CONNECTION_ACK directed to us.
 *
 * @param connection Connection to confirm.
 * @param fwd Is this a fwd ACK? (First is bck (SYNACK), second is fwd (ACK))
 */
static void
send_connection_ack (struct MeshConnection *connection, int fwd)
{
  struct MeshTunnel3 *t;

  t = connection->t;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Send connection ack\n");
  GMP_queue_add (get_hop (connection, fwd), NULL,
                 GNUNET_MESSAGE_TYPE_MESH_CONNECTION_ACK,
                 sizeof (struct GNUNET_MESH_ConnectionACK),
                 connection, NULL, fwd,
                 &message_sent, NULL);
  if (MESH_TUNNEL3_NEW == GMT_get_state (t))
    GMT_change_state (t, MESH_TUNNEL3_WAITING);
  if (MESH_CONNECTION_READY != connection->state)
    GMC_change_state (connection, MESH_CONNECTION_SENT);
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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "sending %s keepalive for connection %s[%d]\n",
       fwd ? "FWD" : "BCK", GMT_2s (c->t), c->id);

  msg = (struct GNUNET_MESH_ConnectionKeepAlive *) cbuf;
  msg->header.size = htons (size);
  msg->header.type = htons (type);
  msg->cid = c->id;

  GMC_send_prebuilt_message (&msg->header, c, NULL, fwd);
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
  LOG (GNUNET_ERROR_TYPE_DEBUG, "sending connection recreate\n");
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
  if (MESH_TUNNEL3_SEARCHING == GMT_get_state (c->t))
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
              fwd ? "FWD" : "BCK", GNUNET_h2s (&c->id));

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
 * @param c Connection which to cancel.
 * @param fwd Cancel fwd traffic?
 */
static void
connection_cancel_queues (struct MeshConnection *c, int fwd)
{

  struct MeshFlowControl *fc;
  struct MeshPeer *peer;

  if (NULL == c)
  {
    GNUNET_break (0);
    return;
  }

  peer = get_hop (c, fwd);
  GMP_queue_cancel (peer, c);

  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  if (GNUNET_SCHEDULER_NO_TASK != fc->poll_task)
  {
    GNUNET_SCHEDULER_cancel (fc->poll_task);
    fc->poll_task = GNUNET_SCHEDULER_NO_TASK;
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
  LOG (GNUNET_ERROR_TYPE_DEBUG, " *** Polling!\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, " *** connection [%X]\n",
              GNUNET_h2s (&c->id));
  LOG (GNUNET_ERROR_TYPE_DEBUG, " ***   %s\n",
              fc == &c->fwd_fc ? "FWD" : "BCK");

  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_POLL);
  msg.header.size = htons (sizeof (msg));
  LOG (GNUNET_ERROR_TYPE_DEBUG, " *** pid (%u)!\n", fc->last_pid_sent);
  GMC_send_prebuilt_message (&msg.header, c, NULL, fc == &c->fwd_fc);
  fc->poll_time = GNUNET_TIME_STD_BACKOFF (fc->poll_time);
  fc->poll_task = GNUNET_SCHEDULER_add_delayed (fc->poll_time,
                                                &connection_poll, fc);
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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "Connection %s[%X] FWD timed out. Destroying.\n",
              GMT_2s (c->t),
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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "Connection %s[%X] FWD timed out. Destroying.\n",
              GMT_2s (c->t), c->id);

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
 * Add the connection to the list of both neighbors.
 *
 * @param c Connection.
 */
static void
register_neighbors (struct MeshConnection *c)
{
  struct MeshPeer *peer;

  peer = get_next_hop (c);
  if (GNUNET_NO == GMP_is_neighbor (peer))
  {
    GMC_destroy (c);
    return;
  }
  GMP_add_connection (peer, c);
  peer = get_prev_hop (c);
  if (GNUNET_NO == GMP_is_neighbor (peer))
  {
    GMC_destroy (c);
    return;
  }
  GMP_add_connection (peer, c);
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
  GMP_remove_connection (peer, c);

  peer = get_prev_hop (c);
  GMP_remove_connection (peer, c);

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
  uint16_t i;

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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "    connection %s (%s).\n",
              GNUNET_h2s (cid), GNUNET_i2s (id));

  /* Create connection */
  c = connection_get (cid);
  if (NULL == c)
  {
    /* Create path */
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  Creating path...\n");
    path = path_new (size);
    own_pos = 0;
    for (i = 0; i < size; i++)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  ... adding %s\n",
                  GNUNET_i2s (&id[i]));
      path->peers[i] = GNUNET_PEER_intern (&id[i]);
      if (path->peers[i] == myid)
        own_pos = i;
    }
    if (own_pos == 0 && path->peers[own_pos] != myid)
    {
      /* create path: self not found in path through self */
      GNUNET_break_op (0);
      path_destroy (path);
      GMC_destroy (c);
      return GNUNET_OK;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  Own position: %u\n", own_pos);
    GMP_add_path_to_all (path, GNUNET_NO);
        LOG (GNUNET_ERROR_TYPE_DEBUG, "  Creating connection\n");
    c = GMC_new (cid, NULL, path_duplicate (path), own_pos);
    if (NULL == c)
      return GNUNET_OK;
    connection_reset_timeout (c, GNUNET_YES);
  }
  else
  {
    path = NULL;
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
    GMP_add_path_to_origin (orig_peer, path, GNUNET_YES);

    GMP_add_tunnel (orig_peer);
    GMP_add_connection (orig_peer, c);
    if (MESH_TUNNEL3_NEW == GMT_get_state (c->t))
      GMT_change_state (c->t,  MESH_TUNNEL3_WAITING);

    send_connection_ack (c, GNUNET_NO);
    if (MESH_CONNECTION_SENT == c->state)
      connection_change_state (c, MESH_CONNECTION_ACK);

    /* Keep tunnel alive in direction dest->owner*/
    connection_reset_timeout (c, GNUNET_NO);
  }
  else
  {
    /* It's for somebody else! Retransmit. */
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  Retransmitting.\n");
    GMP_add_path (dest_peer, path_duplicate (path), GNUNET_NO);
    GMP_add_path_to_origin (orig_peer, path, GNUNET_NO);
    GMC_send_prebuilt_message (message, c, NULL, GNUNET_YES);
  }
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


  LOG (GNUNET_ERROR_TYPE_DEBUG, "  via peer %s\n",
              GNUNET_i2s (peer));
  pi = peer_get (peer);
  if (get_next_hop (c) == pi)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  SYNACK\n");
    fwd = GNUNET_NO;
    if (MESH_CONNECTION_SENT == c->state)
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
    path_add_to_peers (p, GNUNET_YES);
  }
  else
  {
    GNUNET_break (0);
  }

  /* Message for us as creator? */
  if (GMC_is_origin (c, GNUNET_YES))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  Connection (SYN)ACK for us!\n");
    connection_change_state (c, MESH_CONNECTION_READY);
    GMT_change_state (c->t, MESH_TUNNEL3_READY);
    send_connection_ack (c, GNUNET_YES);
    GMT_send_queued_data (c->t, GNUNET_YES);
    return GNUNET_OK;
  }

  /* Message for us as destination? */
  if (GMC_is_terminal (c, GNUNET_YES))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  Connection ACK for us!\n");
    GMC_change_state (c, MESH_CONNECTION_READY);
    GMT_change_state (c->t, MESH_TUNNEL3_READY);
    GMT_send_queued_data (c->t, GNUNET_NO);
    return GNUNET_OK;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  not for us, retransmitting...\n");
  GMC_send_prebuilt_message (message, c, NULL, fwd);
  return GNUNET_OK;
}


/**
 * Core handler for notifications of broken paths
 *
 * @param cls Closure (unused).
 * @param peer Peer identity of sending neighbor.
 * @param message Message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GMC_handle_broken (void *cls, const struct GNUNET_PeerIdentity *peer,
                   const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MESH_ConnectionBroken *msg;
  struct MeshConnection *c;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "Received a CONNECTION BROKEN msg from %s\n", GNUNET_i2s (peer));
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
  tunnel_notify_connection_broken (c->t, GNUNET_PEER_search (&msg->peer1),
                                   GNUNET_PEER_search (&msg->peer2));
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
  GNUNET_PEER_Id id;
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
    GNUNET_STATISTICS_update (stats, "# control on unknown tunnel",
                              1, GNUNET_NO);
    return GNUNET_OK;
  }
  id = GNUNET_PEER_search (peer);
  if (id == GMP_get_short_id (get_prev_hop (c)))
    fwd = GNUNET_YES;
  else if (id == GMP_get_short_id (get_next_hop (c)))
    fwd = GNUNET_NO;
  else
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  GMC_send_prebuilt_message (message, c, NULL, fwd);
  c->destroy = GNUNET_YES;

  return GNUNET_OK;
}

/**
 * Generic handler for mesh network encrypted traffic.
 *
 * @param peer Peer identity this notification is about.
 * @param message Encrypted message.
 * @param fwd Is this FWD traffic? GNUNET_YES : GNUNET_NO;
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_mesh_encrypted (const struct GNUNET_PeerIdentity *peer,
                       const struct GNUNET_MESH_Encrypted *msg,
                       int fwd)
{
  struct MeshConnection *c;
  struct MeshTunnel3 *t;
  struct MeshPeer *neighbor;
  struct MeshFlowControl *fc;
  uint32_t pid;
  uint32_t ttl;
  uint16_t type;
  size_t size;

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
              GNUNET_MESH_DEBUG_M2S (type), GNUNET_i2s (peer));

  /* Check connection */
  c = connection_get (&msg->cid);
  if (NULL == c)
  {
    GNUNET_STATISTICS_update (stats, "# unknown connection", 1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "WARNING connection unknown\n");
    return GNUNET_OK;
  }
  t = c->t;
  fc = fwd ? &c->bck_fc : &c->fwd_fc;

  /* Check if origin is as expected */
  neighbor = get_hop (c, !fwd);
  if (GNUNET_PEER_search (peer) != GMP_get_short_id (neighbor))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  /* Check PID */
  pid = ntohl (msg->pid);
  if (GMC_is_pid_bigger (pid, fc->last_ack_sent))
  {
    GNUNET_STATISTICS_update (stats, "# unsolicited message", 1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
                "WARNING Received PID %u, (prev %u), ACK %u\n",
                pid, fc->last_pid_recv, fc->last_ack_sent);
    return GNUNET_OK;
  }
  if (GNUNET_NO == GMC_is_pid_bigger (pid, fc->last_pid_recv))
  {
    GNUNET_STATISTICS_update (stats, "# duplicate PID", 1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
                " Pid %u not expected (%u+), dropping!\n",
                pid, fc->last_pid_recv + 1);
    return GNUNET_OK;
  }
  if (MESH_CONNECTION_SENT == c->state)
    connection_change_state (c, MESH_CONNECTION_READY);
  connection_reset_timeout (c, fwd);
  fc->last_pid_recv = pid;

  /* Is this message for us? */
  if (GMC_is_terminal (c, fwd))
  {
    size_t dsize = size - sizeof (struct GNUNET_MESH_Encrypted);
    char cbuf[dsize];
    struct GNUNET_MessageHeader *msgh;
    unsigned int off;

    /* TODO signature verification */
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  message for us!\n");
    GNUNET_STATISTICS_update (stats, "# messages received", 1, GNUNET_NO);

    fc->last_pid_recv = pid;
    tunnel_decrypt (t, cbuf, &msg[1], dsize, msg->iv, fwd);
    off = 0;
    while (off < dsize)
    {
      msgh = (struct GNUNET_MessageHeader *) &cbuf[off];
      handle_decrypted (t, msgh, fwd);
      off += ntohs (msgh->size);
    }
    send_ack (c, NULL, fwd);
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
    send_ack (c, NULL, fwd);
    return GNUNET_OK;
  }
  GNUNET_STATISTICS_update (stats, "# messages forwarded", 1, GNUNET_NO);

  send_prebuilt_message_connection (&msg->header, c, NULL, fwd);

  return GNUNET_OK;
}


/**
 * Core handler for mesh network traffic going orig->dest.
 *
 * @param cls Closure (unused).
 * @param message Message received.
 * @param peer Peer who sent the message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GMC_handle_fwd (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message)
{
  return handle_mesh_encrypted (peer,
                                (struct GNUNET_MESH_Encrypted *)message,
                                GNUNET_YES);
}

/**
 * Core handler for mesh network traffic going dest->orig.
 *
 * @param cls Closure (unused).
 * @param message Message received.
 * @param peer Peer who sent the message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GMC_handle_bck (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message)
{
  return handle_mesh_encrypted (peer,
                                (struct GNUNET_MESH_Encrypted *)message,
                                GNUNET_NO);
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
  if (GMC_is_pid_bigger (ack, fc->last_ack_recv))
    fc->last_ack_recv = ack;

  /* Cancel polling if the ACK is big enough. */
  if (GNUNET_SCHEDULER_NO_TASK != fc->poll_task &&
      GMC_is_pid_bigger (fc->last_ack_recv, fc->last_pid_sent))
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
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Got a POLL packet from %s!\n",
              GNUNET_i2s (peer));

  msg = (struct GNUNET_MESH_Poll *) message;

  c = connection_get (&msg->cid);

  if (NULL == c)
  {
    GNUNET_STATISTICS_update (stats, "# poll on unknown connection", 1,
                              GNUNET_NO);
    GNUNET_break_op (0);
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
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  FWD ACK\n");
    fc = &c->fwd_fc;
  }
  else if (GMP_get_short_id (get_prev_hop (c)) == id)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  BCK ACK\n");
    fc = &c->bck_fc;
  }
  else
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  pid = ntohl (msg->pid);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  PID %u, OLD %u\n",
              pid, fc->last_pid_recv);
  fc->last_pid_recv = pid;
  fwd = fc == &c->fwd_fc;
  send_ack (c, NULL, fwd);

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

  fwd = GNUNET_MESSAGE_TYPE_MESH_FWD_KEEPALIVE == ntohs (message->type) ?
        GNUNET_YES : GNUNET_NO;

  /* Check if origin is as expected */
  neighbor = get_hop (c, fwd);
  if (GNUNET_PEER_search (peer) != GMP_get_short_id (neighbor))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  connection_change_state (c, MESH_CONNECTION_READY);
  connection_reset_timeout (c, fwd);

  if (GMC_is_terminal (c, fwd))
    return GNUNET_OK;

  GNUNET_STATISTICS_update (stats, "# keepalives forwarded", 1, GNUNET_NO);
  GMC_send_prebuilt_message (message, c, NULL, fwd);

  return GNUNET_OK;
}


/**
 * Send an ACK on the appropriate connection/channel, depending on
 * the direction and the position of the peer.
 *
 * @param c Which connection to send the hop-by-hop ACK.
 * @param ch Channel, if any.
 * @param fwd Is this a fwd ACK? (will go dest->root)
 */
void
GMC_send_ack (struct MeshConnection *c, struct MeshChannel *ch, int fwd)
{
  unsigned int buffer;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "send ack %s on %p %p\n",
              fwd ? "FWD" : "BCK", c, ch);
  if (NULL == c || GMC_is_terminal (c, fwd))
  {
    struct MeshTunnel3 *t;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  getting from all connections\n");
    t = (NULL == c) ? GMCH_get_tunnel (ch) : GMC_get_tunnel (c);
    buffer = GMT_get_buffer (t, fwd);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  getting from one connection\n");
    buffer = GMC_get_buffer (c, fwd);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  buffer available: %u\n", buffer);

  if ( (NULL != ch && GMCH_is_origin (ch, fwd)) ||
       (NULL != c && GMC_is_origin (c, fwd)) )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  sending on channel...\n");
    if (0 < buffer)
    {
      GNUNET_assert (NULL != ch);
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  really sending!\n");
      send_local_ack (ch, fwd);
    }
  }
  else if (NULL == c)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  sending on all connections\n");
    GNUNET_assert (NULL != ch);
    channel_send_connections_ack (ch, buffer, fwd);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  sending on connection\n");
    connection_send_ack (c, buffer, fwd);
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
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "MESH", "MAX_MSGS_QUEUE",
                                             &max_msgs_queue))
  {
    LOG_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               "MESH", "MAX_MSGS_QUEUE", "MISSING");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "MESH", "MAX_CONNECTIONS",
                                             &max_connections))
  {
    LOG_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               "MESH", "MAX_CONNECTIONS", "MISSING");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (c, "MESH", "REFRESH_CONNECTION_TIME",
                                           &refresh_connection_time))
  {
    LOG_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               "MESH", "REFRESH_CONNECTION_TIME", "MISSING");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  connections = GNUNET_CONTAINER_multihashmap_create (1024, GNUNET_YES);
}

/**
 * Shut down the connections subsystem.
 */
void
GMC_shutdown (void)
{
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
  GNUNET_CONTAINER_multihashmap_put (connections, &c->id, c,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  fc_init (&c->fwd_fc);
  fc_init (&c->bck_fc);
  c->fwd_fc.c = c;
  c->bck_fc.c = c;

  c->t = t;
  if (own_pos > p->length - 1)
  {
    GNUNET_break (0);
    GMC_destroy (c);
    return NULL;
  }
  c->own_pos = own_pos;
  c->path = p;

  if (0 == own_pos)
  {
    c->fwd_maintenance_task =
            GNUNET_SCHEDULER_add_delayed (refresh_connection_time,
                                          &connection_fwd_keepalive, c);
  }
  register_neighbors (c);
  return c;
}


void
GMC_destroy (struct MeshConnection *c)
{
  if (NULL == c)
    return;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "destroying connection %s\n",
       GNUNET_h2s (&c->id));

  /* Cancel all traffic */
  connection_cancel_queues (c, GNUNET_YES);
  connection_cancel_queues (c, GNUNET_NO);

  /* Cancel maintainance task (keepalive/timeout) */
  if (GNUNET_SCHEDULER_NO_TASK != c->fwd_maintenance_task)
    GNUNET_SCHEDULER_cancel (c->fwd_maintenance_task);
  if (GNUNET_SCHEDULER_NO_TASK != c->bck_maintenance_task)
    GNUNET_SCHEDULER_cancel (c->bck_maintenance_task);

  /* Unregister from neighbors */
  unregister_neighbors (c);

  /* Delete */
  GNUNET_STATISTICS_update (stats, "# connections", -1, GNUNET_NO);
  GMT_remove_connection (c->t, c);
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
  return c->path;
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
 * Notify other peers on a connection of a broken link. Mark connections
 * to destroy after all traffic has been sent.
 *
 * @param c Connection on which there has been a disconnection.
 * @param peer Peer that disconnected.
 * @param my_full_id My ID (to send to other peers).
 */
void
GMC_notify_broken (struct MeshConnection *c,
                   struct MeshPeer *peer,
                   struct GNUNET_PeerIdentity *my_full_id)
{
  struct GNUNET_MESH_ConnectionBroken msg;
  int fwd;

  fwd = peer == get_prev_hop (c);

  connection_cancel_queues (c, !fwd);
  if (GMC_is_terminal (c, fwd))
  {
    /* Local shutdown, no one to notify about this. */
    GMC_destroy (c);
    return;
  }

  msg.header.size = htons (sizeof (struct GNUNET_MESH_ConnectionBroken));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_CONNECTION_BROKEN);
  msg.cid = c->id;
  msg.peer1 = *my_full_id;
  msg.peer2 = *GMP_get_id (peer);
  GMC_send_prebuilt_message (&msg.header, c, NULL, fwd);
  c->destroy = GNUNET_YES;

  return;
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


/**
 * See if we are allowed to send by the next hop in the given direction.
 *
 * @param c Connection.
 * @param fwd Is this about fwd traffic?
 *
 * @return GNUNET_YES in case it's OK.
 */
int
GMC_is_sendable (struct MeshConnection *c, int fwd)
{
  struct MeshFlowControl *fc;

  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  if (GMC_is_pid_bigger (fc->last_ack_recv, fc->last_pid_sent))
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
 * @param ch Channel on which this message is transmitted, or NULL.
 * @param fwd Is this a fwd message?
 */
void
GMC_send_prebuilt_message (const struct GNUNET_MessageHeader *message,
                           struct MeshConnection *c,
                           struct MeshChannel *ch,
                           int fwd)
{
  struct MeshFlowControl *fc;
  void *data;
  size_t size;
  uint16_t type;
  int droppable;

  size = ntohs (message->size);
  data = GNUNET_malloc (size);
  memcpy (data, message, size);
  type = ntohs (message->type);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Send %s (%u) on connection %s\n",
              GNUNET_MESH_DEBUG_M2S (type), size, GNUNET_h2s (&c->id));

  droppable = GNUNET_YES;
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
      LOG (GNUNET_ERROR_TYPE_DEBUG, " pid %u\n", ntohl (emsg->pid));
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
      pmsg->pid = htonl (fwd ? c->fwd_fc.last_pid_sent : c->bck_fc.last_pid_sent);
      LOG (GNUNET_ERROR_TYPE_DEBUG, " poll %u\n", ntohl (pmsg->pid));
      droppable = GNUNET_NO;
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

  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  if (fc->queue_n >= fc->queue_max && droppable)
  {
    GNUNET_STATISTICS_update (stats, "# messages dropped (buffer full)",
                              1, GNUNET_NO);
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
                "queue full: %u/%u\n",
                fc->queue_n, fc->queue_max);
    return; /* Drop this message */
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG, "last pid %u\n", fc->last_pid_sent);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "     ack %u\n", fc->last_ack_recv);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  Q_N+ %p %u\n", fc, fc->queue_n);
  if (GMC_is_pid_bigger (fc->last_pid_sent + 1, fc->last_ack_recv))
  {
    GMC_start_poll (c, fwd);
  }
  fc->queue_n++;
  c->pending_messages++;

  GMP_queue_add (get_hop (c, fwd), data, type, size, c, ch, fwd,
                 &message_sent, NULL);
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
enum MeshTunnel3State state;
  size_t size;

  size = sizeof (struct GNUNET_MESH_ConnectionCreate);
  size += connection->path->length * sizeof (struct GNUNET_PeerIdentity);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Send connection create\n");
  GMP_queue_add (get_next_hop (connection), NULL,
                 GNUNET_MESSAGE_TYPE_MESH_CONNECTION_CREATE,
                 size, connection, NULL,
                 GNUNET_YES, &message_sent, NULL);
  state = GMT_get_state (connection->t);
  if (MESH_TUNNEL3_SEARCHING == state || MESH_TUNNEL3_NEW == state)
    GMT_change_state (connection->t, MESH_TUNNEL3_WAITING);
  if (MESH_CONNECTION_NEW == connection->state)
    GMC_change_state (connection, MESH_CONNECTION_SENT);
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
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_TUNNEL_DESTROY);;
  msg.cid = c->id;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "  sending connection destroy for connection %s\n",
              GNUNET_h2s (&c->id));

  if (GNUNET_NO == GMC_is_terminal (c, GNUNET_YES))
    GMC_send_prebuilt_message (&msg.header, c, NULL, GNUNET_YES);
  if (GNUNET_NO == GMC_is_terminal (c, GNUNET_NO))
    GMC_send_prebuilt_message (&msg.header, c, NULL, GNUNET_NO);
  c->destroy = GNUNET_YES;
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
  if (GNUNET_SCHEDULER_NO_TASK != fc->poll_task)
  {
    return;
  }
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