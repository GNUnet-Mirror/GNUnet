/*
     This file is part of GNUnet.
     Copyright (C) 2001-2015 Christian Grothoff (and other contributing authors)

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
 * @file cadet/gnunet-service-cadet_connection.c
 * @brief GNUnet CADET service connection handling
 * @author Bartlomiej Polot
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "cadet_path.h"
#include "cadet_protocol.h"
#include "cadet.h"
#include "gnunet-service-cadet_connection.h"
#include "gnunet-service-cadet_peer.h"
#include "gnunet-service-cadet_tunnel.h"


#define LOG(level, ...) GNUNET_log_from (level,"cadet-con",__VA_ARGS__)
#define LOG2(level, ...) GNUNET_log_from_nocheck(level,"cadet-con",__VA_ARGS__)


#define CADET_MAX_POLL_TIME      GNUNET_TIME_relative_multiply (\
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
struct CadetFlowControl
{
  /**
   * Connection this controls.
   */
  struct CadetConnection *c;

  /**
   * How many messages are in the queue on this connection.
   */
  unsigned int queue_n;

  /**
   * How many messages do we accept in the queue.
   */
  unsigned int queue_max;

  /**
   * ID of the last packet sent towards the peer.
   */
  uint32_t last_pid_sent;

  /**
   * ID of the last packet received from the peer.
   */
  uint32_t last_pid_recv;

  /**
   * Bitmap of past 32 messages received:
   * - LSB being @c last_pid_recv.
   * - MSB being @c last_pid_recv - 31 (mod UINTMAX).
   */
  uint32_t recv_bitmap;

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
  struct GNUNET_SCHEDULER_Task *poll_task;

  /**
   * How frequently to poll for ACKs.
   */
  struct GNUNET_TIME_Relative poll_time;

  /**
   * Queued poll message, to cancel if not necessary anymore (got ACK).
   */
  struct CadetConnectionQueue *poll_msg;

  /**
   * Queued poll message, to cancel if not necessary anymore (got ACK).
   */
  struct CadetConnectionQueue *ack_msg;
};

/**
 * Keep a record of the last messages sent on this connection.
 */
struct CadetConnectionPerformance
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
struct CadetConnection
{
  /**
   * Tunnel this connection is part of.
   */
  struct CadetTunnel *t;

  /**
   * Flow control information for traffic fwd.
   */
  struct CadetFlowControl fwd_fc;

  /**
   * Flow control information for traffic bck.
   */
  struct CadetFlowControl bck_fc;

  /**
   * Measure connection performance on the endpoint.
   */
  struct CadetConnectionPerformance *perf;

  /**
   * ID of the connection.
   */
  struct GNUNET_CADET_Hash id;

  /**
   * Path being used for the tunnel. At the origin of the connection
   * it's a pointer to the destination's path pool, otherwise just a copy.
   */
  struct CadetPeerPath *path;

  /**
   * Task to keep the used paths alive at the owner,
   * time tunnel out on all the other peers.
   */
  struct GNUNET_SCHEDULER_Task *fwd_maintenance_task;

  /**
   * Task to keep the used paths alive at the destination,
   * time tunnel out on all the other peers.
   */
  struct GNUNET_SCHEDULER_Task *bck_maintenance_task;

  /**
   * Queue handle for maintainance traffic. One handle for FWD and BCK since
   * one peer never needs to maintain both directions (no loopback connections).
   */
  struct CadetPeerQueue *maintenance_q;

  /**
   * Should equal #get_next_hop().
   */
  struct CadetPeer *next_peer;

  /**
   * Should equal #get_prev_hop().
   */
  struct CadetPeer *prev_peer;

  /**
   * State of the connection.
   */
  enum CadetConnectionState state;

  /**
   * Position of the local peer in the path.
   */
  unsigned int own_pos;

  /**
   * Pending message count.
   */
  unsigned int pending_messages;

  /**
   * Destroy flag:
   * - if 0, connection in use.
   * - if 1, destroy on last message.
   * - if 2, connection is being destroyed don't re-enter.
   */
  int destroy;

  /**
   * Counter to do exponential backoff when creating a connection (max 64).
   */
  unsigned short create_retry;
};


/**
 * Handle for messages queued but not yet sent.
 */
struct CadetConnectionQueue
{
  /**
   * Peer queue handle, to cancel if necessary.
   */
  struct CadetPeerQueue *q;

  /**
   * Continuation to call once sent.
   */
  GCC_sent cont;

  /**
   * Closure for @e cont.
   */
  void *cont_cls;

  /**
   * Was this a forced message? (Do not account for it)
   */
  int forced;
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
 * Connections known, indexed by cid (CadetConnection).
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
fc_debug (struct CadetFlowControl *fc)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "    IN: %u/%u\n",
              fc->last_pid_recv, fc->last_ack_sent);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "    OUT: %u/%u\n",
              fc->last_pid_sent, fc->last_ack_recv);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "    QUEUE: %u/%u\n",
              fc->queue_n, fc->queue_max);
}

static void
connection_debug (struct CadetConnection *c)
{
  if (NULL == c)
  {
    LOG (GNUNET_ERROR_TYPE_INFO, "DEBUG NULL CONNECTION\n");
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Connection %s:%X\n",
              peer2s (c->t->peer), GCC_2s (c));
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
schedule_next_keepalive (struct CadetConnection *c, int fwd);


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
 */
static void
connection_reset_timeout (struct CadetConnection *c, int fwd);


/**
 * Get string description for tunnel state. Reentrant.
 *
 * @param s Tunnel state.
 *
 * @return String representation.
 */
static const char *
GCC_state2s (enum CadetConnectionState s)
{
  switch (s)
  {
    case CADET_CONNECTION_NEW:
      return "CADET_CONNECTION_NEW";
    case CADET_CONNECTION_SENT:
      return "CADET_CONNECTION_SENT";
    case CADET_CONNECTION_ACK:
      return "CADET_CONNECTION_ACK";
    case CADET_CONNECTION_READY:
      return "CADET_CONNECTION_READY";
    case CADET_CONNECTION_DESTROYED:
      return "CADET_CONNECTION_DESTROYED";
    case CADET_CONNECTION_BROKEN:
      return "CADET_CONNECTION_BROKEN";
    default:
      GNUNET_break (0);
      LOG (GNUNET_ERROR_TYPE_ERROR, " conn state %u unknown!\n", s);
      return "CADET_CONNECTION_STATE_ERROR";
  }
}


/**
 * Initialize a Flow Control structure to the initial state.
 *
 * @param fc Flow Control structure to initialize.
 */
static void
fc_init (struct CadetFlowControl *fc)
{
  fc->last_pid_sent = (uint32_t) -1; /* Next (expected) = 0 */
  fc->last_pid_recv = (uint32_t) -1;
  fc->last_ack_sent = (uint32_t) 0;
  fc->last_ack_recv = (uint32_t) 0;
  fc->poll_task = NULL;
  fc->poll_time = GNUNET_TIME_UNIT_SECONDS;
  fc->queue_n = 0;
  fc->queue_max = (max_msgs_queue / max_connections) + 1;
}


/**
 * Find a connection.
 *
 * @param cid Connection ID.
 */
static struct CadetConnection *
connection_get (const struct GNUNET_CADET_Hash *cid)
{
  return GNUNET_CONTAINER_multihashmap_get (connections, GC_h2hc (cid));
}


static void
connection_change_state (struct CadetConnection* c,
                         enum CadetConnectionState state)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connection %s state %s -> %s\n",
       GCC_2s (c), GCC_state2s (c->state), GCC_state2s (state));
  if (CADET_CONNECTION_DESTROYED <= c->state) /* Destroyed or broken. */
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "state not changing anymore\n");
    return;
  }
  c->state = state;
  if (CADET_CONNECTION_READY == state)
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
          struct CadetConnection *c,
          struct CadetConnectionQueue *q,
          uint16_t type, int fwd, size_t size)
{
  struct CadetFlowControl *fc = cls;

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
send_ack (struct CadetConnection *c, unsigned int buffer, int fwd, int force)
{
  struct CadetFlowControl *next_fc;
  struct CadetFlowControl *prev_fc;
  struct GNUNET_CADET_ACK msg;
  uint32_t ack;
  int delta;

  /* If origin, there is no connection to send ACKs. Wrong function! */
  if (GCC_is_origin (c, fwd))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "connection %s is origin in %s\n",
         GCC_2s (c), GC_f2s (fwd));
    GNUNET_break (0);
    return;
  }

  next_fc = fwd ? &c->fwd_fc : &c->bck_fc;
  prev_fc = fwd ? &c->bck_fc : &c->fwd_fc;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "connection send %s ack on %s\n",
       GC_f2s (fwd), GCC_2s (c));

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
    if (GC_is_pid_bigger (ack, prev_fc->last_ack_sent))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, " canceling old ACK\n");
      GCC_cancel (prev_fc->ack_msg);
      /* GCC_cancel triggers ack_sent(), which clears fc->ack_msg */
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
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_ACK);
  msg.ack = htonl (ack);
  msg.cid = c->id;

  prev_fc->ack_msg = GCC_send_prebuilt_message (&msg.header, 0, ack, c,
                                                !fwd, GNUNET_YES,
                                                &ack_sent, prev_fc);
  GNUNET_assert (NULL != prev_fc->ack_msg);
}


/**
 * Callback called when a connection queued message is sent.
 *
 * Calculates the average time and connection packet tracking.
 *
 * @param cls Closure (ConnectionQueue Handle).
 * @param c Connection this message was on.
 * @param sent Was it really sent? (Could have been canceled)
 * @param type Type of message sent.
 * @param pid Packet ID, or 0 if not applicable (create, destroy, etc).
 * @param fwd Was this a FWD going message?
 * @param size Size of the message.
 * @param wait Time spent waiting for core (only the time for THIS message)
 *
 * @return #GNUNET_YES if connection was destroyed, #GNUNET_NO otherwise.
 */
static int
conn_message_sent (void *cls,
                   struct CadetConnection *c, int sent,
                   uint16_t type, uint32_t pid, int fwd, size_t size,
                   struct GNUNET_TIME_Relative wait)
{
  struct CadetConnectionPerformance *p;
  struct CadetFlowControl *fc;
  struct CadetConnectionQueue *q = cls;
  double usecsperbyte;
  int forced;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "connection message_sent\n");

  GCC_debug (c, GNUNET_ERROR_TYPE_DEBUG);

  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  LOG (GNUNET_ERROR_TYPE_DEBUG, " %ssent %s %s pid %u\n",
       sent ? "" : "not ", GC_f2s (fwd), GC_m2s (type), pid);
  if (NULL != q)
  {
    forced = q->forced;
    if (NULL != q->cont)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, " calling cont\n");
      q->cont (q->cont_cls, c, q, type, fwd, size);
    }
    GNUNET_free (q);
  }
  else if (type == GNUNET_MESSAGE_TYPE_CADET_ENCRYPTED
           || type == GNUNET_MESSAGE_TYPE_CADET_AX)
  {
    /* If NULL == q and ENCRYPTED == type, message must have been ch_mngmnt */
    forced = GNUNET_YES;
  }
  else
  {
    forced = GNUNET_NO;
  }
  if (NULL == c)
  {
    if (type != GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN
        && type != GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR, "Message %s sent on NULL connection!\n",
           GC_m2s (type));
    }
    return GNUNET_NO;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, " C_P- %p %u\n", c, c->pending_messages);
  c->pending_messages--;
  if ( (GNUNET_YES == c->destroy) &&
       (0 == c->pending_messages) )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "!  destroying connection!\n");
    GCC_destroy (c);
    return GNUNET_YES;
  }
  /* Send ACK if needed, after accounting for sent ID in fc->queue_n */
  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE:
    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_ACK:
      c->maintenance_q = NULL;
      /* Don't trigger a keepalive for sent ACKs, only SYN and SYNACKs */
      if (GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE == type || !fwd)
        schedule_next_keepalive (c, fwd);
      break;

    case GNUNET_MESSAGE_TYPE_CADET_ENCRYPTED:
    case GNUNET_MESSAGE_TYPE_CADET_AX:
      if (GNUNET_YES == sent)
      {
        GNUNET_assert (NULL != q);
        fc->last_pid_sent = pid;
        if (GC_is_pid_bigger (fc->last_pid_sent + 1, fc->last_ack_recv))
          GCC_start_poll (c, fwd);
        GCC_send_ack (c, fwd, GNUNET_NO);
        connection_reset_timeout (c, fwd);
      }

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
      break;

    case GNUNET_MESSAGE_TYPE_CADET_KX:
      if (GNUNET_YES == sent)
        connection_reset_timeout (c, fwd);
      break;

    case GNUNET_MESSAGE_TYPE_CADET_POLL:
      fc->poll_msg = NULL;
      break;

    case GNUNET_MESSAGE_TYPE_CADET_ACK:
      fc->ack_msg = NULL;
      break;

    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN:
      break;

    default:
      LOG (GNUNET_ERROR_TYPE_ERROR, "%s unknown\n", GC_m2s (type));
      GNUNET_break (0);
      break;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "!  message sent!\n");

  if (NULL == c->perf)
    return GNUNET_NO; /* Only endpoints are interested in timing. */

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
  return GNUNET_NO;
}


/**
 * Get the previous hop in a connection
 *
 * @param c Connection.
 *
 * @return Previous peer in the connection.
 */
static struct CadetPeer *
get_prev_hop (const struct CadetConnection *c)
{
  GNUNET_PEER_Id id;

  if (NULL == c->path)
    return NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       " get prev hop %s [%u/%u]\n",
       GCC_2s (c), c->own_pos, c->path->length);
  if (0 == c->own_pos || c->path->length < 2)
    id = c->path->peers[0];
  else
    id = c->path->peers[c->own_pos - 1];

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  ID: %s (%u)\n",
       GNUNET_i2s (GNUNET_PEER_resolve2 (id)), id);

  return GCP_get_short (id);
}


/**
 * Get the next hop in a connection
 *
 * @param c Connection.
 *
 * @return Next peer in the connection.
 */
static struct CadetPeer *
get_next_hop (const struct CadetConnection *c)
{
  GNUNET_PEER_Id id;

  if (NULL == c->path)
    return NULL;

  LOG (GNUNET_ERROR_TYPE_DEBUG, " get next hop %s [%u/%u]\n",
       GCC_2s (c), c->own_pos, c->path->length);
  if ((c->path->length - 1) == c->own_pos || c->path->length < 2)
    id = c->path->peers[c->path->length - 1];
  else
    id = c->path->peers[c->own_pos + 1];

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  ID: %s (%u)\n",
       GNUNET_i2s (GNUNET_PEER_resolve2 (id)), id);

  return GCP_get_short (id);
}


/**
 * Get the hop in a connection.
 *
 * @param c Connection.
 * @param fwd Next in the FWD direction?
 *
 * @return Next peer in the connection.
 */
static struct CadetPeer *
get_hop (struct CadetConnection *c, int fwd)
{
  if (fwd)
    return get_next_hop (c);
  return get_prev_hop (c);
}


/**
 * Get a bit mask for a message received out-of-order.
 *
 * @param last_pid_recv Last PID we received prior to the out-of-order.
 * @param ooo_pid PID of the out-of-order message.
 */
static uint32_t
get_recv_bitmask (uint32_t last_pid_recv, uint32_t ooo_pid)
{
  return 1 << (last_pid_recv - ooo_pid);
}


/**
 * Check is an out-of-order message is ok:
 * - at most 31 messages behind.
 * - not duplicate.
 *
 * @param last_pid_recv Last in-order PID received.
 */
static int
is_ooo_ok (uint32_t last_pid_recv, uint32_t ooo_pid, uint32_t ooo_bitmap)
{
  uint32_t mask;

  if (GC_is_pid_bigger (last_pid_recv - 31, ooo_pid))
    return GNUNET_NO;

  mask = get_recv_bitmask (last_pid_recv, ooo_pid);
  if (0 != (ooo_bitmap & mask))
    return GNUNET_NO;

  return GNUNET_YES;
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
is_fwd (const struct CadetConnection *c,
        const struct GNUNET_PeerIdentity *sender)
{
  GNUNET_PEER_Id id;

  id = GNUNET_PEER_search (sender);
  if (GCP_get_short_id (get_prev_hop (c)) == id)
    return GNUNET_YES;

  if (GCP_get_short_id (get_next_hop (c)) == id)
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
send_connection_ack (struct CadetConnection *connection, int fwd)
{
  struct CadetTunnel *t;

  t = connection->t;
  LOG (GNUNET_ERROR_TYPE_INFO, "---> {%14s ACK} on connection %s\n",
       GC_f2s (!fwd), GCC_2s (connection));
  GCP_queue_add (get_hop (connection, fwd), NULL,
                 GNUNET_MESSAGE_TYPE_CADET_CONNECTION_ACK, 0, 0,
                 sizeof (struct GNUNET_CADET_ConnectionACK),
                 connection, fwd, &conn_message_sent, NULL);
  connection->pending_messages++;
  if (CADET_TUNNEL_NEW == GCT_get_cstate (t))
    GCT_change_cstate (t, CADET_TUNNEL_WAITING);
  if (CADET_CONNECTION_READY != connection->state)
    connection_change_state (connection, CADET_CONNECTION_SENT);
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
send_broken (struct CadetConnection *c,
             const struct GNUNET_PeerIdentity *id1,
             const struct GNUNET_PeerIdentity *id2,
             int fwd)
{
  struct GNUNET_CADET_ConnectionBroken msg;

  msg.header.size = htons (sizeof (struct GNUNET_CADET_ConnectionBroken));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN);
  msg.cid = c->id;
  msg.peer1 = *id1;
  msg.peer2 = *id2;
  GNUNET_assert (NULL == GCC_send_prebuilt_message (&msg.header, 0, 0, c, fwd,
                                                    GNUNET_YES, NULL, NULL));
}


/**
 * Send a notification that a connection is broken, when a connection
 * isn't even known to the local peer or soon to be destroyed.
 *
 * @param connection_id Connection ID.
 * @param id1 Peer that has disconnected, probably local peer.
 * @param id2 Peer that has disconnected can be NULL if unknown.
 * @param peer Peer to notify (neighbor who sent the connection).
 */
static void
send_broken_unknown (const struct GNUNET_CADET_Hash *connection_id,
                     const struct GNUNET_PeerIdentity *id1,
                     const struct GNUNET_PeerIdentity *id2,
                     const struct GNUNET_PeerIdentity *peer_id)
{
  struct GNUNET_CADET_ConnectionBroken *msg;
  struct CadetPeer *neighbor;

  LOG (GNUNET_ERROR_TYPE_INFO, "---> BROKEN on unknown connection %s\n",
       GNUNET_h2s (GC_h2hc (connection_id)));

  msg = GNUNET_new (struct GNUNET_CADET_ConnectionBroken);
  msg->header.size = htons (sizeof (struct GNUNET_CADET_ConnectionBroken));
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN);
  msg->cid = *connection_id;
  msg->peer1 = *id1;
  if (NULL != id2)
    msg->peer2 = *id2;
  else
    memset (&msg->peer2, 0, sizeof (msg->peer2));
  neighbor = GCP_get (peer_id);
  GCP_queue_add (neighbor, msg, GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN,
                 0, 2, sizeof (struct GNUNET_CADET_ConnectionBroken),
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
send_connection_keepalive (struct CadetConnection *c, int fwd)
{
  struct GNUNET_MessageHeader msg;
  struct CadetFlowControl *fc;

  LOG (GNUNET_ERROR_TYPE_INFO, "keepalive %s for connection %s\n",
       GC_f2s (fwd), GCC_2s (c));

  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  if (0 < fc->queue_n)
  {
    LOG (GNUNET_ERROR_TYPE_INFO, "not sending keepalive, traffic in queue\n");
    return;
  }

  GNUNET_STATISTICS_update (stats, "# keepalives sent", 1, GNUNET_NO);

  GNUNET_assert (NULL != c->t);
  msg.size = htons (sizeof (msg));
  msg.type = htons (GNUNET_MESSAGE_TYPE_CADET_KEEPALIVE);

  GNUNET_assert (NULL ==
                 GCT_send_prebuilt_message (&msg, c->t, c,
                                            GNUNET_NO, NULL, NULL));
}


/**
 * Send CONNECTION_{CREATE/ACK} packets for a connection.
 *
 * @param c Connection for which to send the message.
 * @param fwd If #GNUNET_YES, send CREATE, otherwise send ACK.
 */
static void
connection_recreate (struct CadetConnection *c, int fwd)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "sending connection recreate\n");
  if (fwd)
    GCC_send_create (c);
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
connection_maintain (struct CadetConnection *c, int fwd)
{
  if (GNUNET_NO != c->destroy)
  {
    LOG (GNUNET_ERROR_TYPE_INFO, "not sending keepalive, being destroyed\n");
    return;
  }

  if (NULL == c->t)
  {
    GNUNET_break (0);
    GCC_debug (c, GNUNET_ERROR_TYPE_ERROR);
    return;
  }

  if (CADET_TUNNEL_SEARCHING == GCT_get_cstate (c->t))
  {
    /* If status is SEARCHING, why is there a connection? Should be WAITING */
    GNUNET_break (0);
    GCT_debug (c->t, GNUNET_ERROR_TYPE_ERROR);
    LOG (GNUNET_ERROR_TYPE_INFO, "not sending keepalive, tunnel SEARCHING\n");
    schedule_next_keepalive (c, fwd);
    return;
  }
  switch (c->state)
  {
    case CADET_CONNECTION_NEW:
      GNUNET_break (0);
      /* fall-through */
    case CADET_CONNECTION_SENT:
      connection_recreate (c, fwd);
      break;
    case CADET_CONNECTION_READY:
      send_connection_keepalive (c, fwd);
      break;
    default:
      break;
  }
}



/**
 * Keep the connection alive.
 *
 * @param c Connection to keep alive.
 * @param fwd Direction.
 * @param shutdown Are we shutting down? (Don't send traffic)
 *                 Non-zero value for true, not necessarily GNUNET_YES.
 */
static void
connection_keepalive (struct CadetConnection *c, int fwd, int shutdown)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "%s keepalive for %s\n",
       GC_f2s (fwd), GCC_2s (c));

  if (fwd)
    c->fwd_maintenance_task = NULL;
  else
    c->bck_maintenance_task = NULL;

  if (GNUNET_NO != shutdown)
    return;

  connection_maintain (c, fwd);

  /* Next execution will be scheduled by message_sent or _maintain*/
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
  connection_keepalive ((struct CadetConnection *) cls,
                        GNUNET_YES,
                        tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN);
}


/**
 * Keep the connection alive in the BCK direction.
 *
 * @param cls Closure (connection to keepalive).
 * @param tc TaskContext.
 */
static void
connection_bck_keepalive (void *cls,
                          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  connection_keepalive ((struct CadetConnection *) cls,
                        GNUNET_NO,
                        tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN);
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
schedule_next_keepalive (struct CadetConnection *c, int fwd)
{
  struct GNUNET_TIME_Relative delay;
  struct GNUNET_SCHEDULER_Task * *task_id;
  GNUNET_SCHEDULER_TaskCallback keepalive_task;

  if (GNUNET_NO == GCC_is_origin (c, fwd))
    return;

  /* Calculate delay to use, depending on the state of the connection */
  if (CADET_CONNECTION_READY == c->state)
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

  /* Check that no one scheduled it before us */
  if (NULL != *task_id)
  {
    /* No need for a _break. It can happen for instance when sending a SYNACK
     * for a duplicate SYN: the first SYNACK scheduled the task. */
    GNUNET_SCHEDULER_cancel (*task_id);
  }

  /* Schedule the task */
  *task_id = GNUNET_SCHEDULER_add_delayed (delay, keepalive_task, c);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "next keepalive in %s\n",
       GNUNET_STRINGS_relative_time_to_string (delay, GNUNET_YES));
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
connection_unlock_queue (struct CadetConnection *c, int fwd)
{
  struct CadetPeer *peer;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "connection_unlock_queue %s on %s\n",
       GC_f2s (fwd), GCC_2s (c));

  if (GCC_is_terminal (c, fwd))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " is terminal, can unlock!\n");
    return;
  }

  peer = get_hop (c, fwd);
  GCP_queue_unlock (peer, c);
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
connection_cancel_queues (struct CadetConnection *c, int fwd)
{
  struct CadetFlowControl *fc;
  struct CadetPeer *peer;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Cancel %s queues for connection %s\n",
       GC_f2s (fwd), GCC_2s (c));
  if (NULL == c)
  {
    GNUNET_break (0);
    return;
  }

  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  if (NULL != fc->poll_task)
  {
    GNUNET_SCHEDULER_cancel (fc->poll_task);
    fc->poll_task = NULL;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Cancel POLL in ccq for fc %p\n", fc);
  }
  peer = get_hop (c, fwd);
  GCP_queue_cancel (peer, c);
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
           struct CadetConnection *c,
           struct CadetConnectionQueue *q,
           uint16_t type, int fwd, size_t size)
{
  struct CadetFlowControl *fc = cls;

  if (2 == c->destroy)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "POLL canceled on shutdown\n");
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "POLL sent for %s, scheduling new one!\n",
       GCC_2s (c));
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
  struct CadetFlowControl *fc = cls;
  struct GNUNET_CADET_Poll msg;
  struct CadetConnection *c;
  int fwd;

  fc->poll_task = NULL;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
  {
    return;
  }

  c = fc->c;
  fwd = fc == &c->fwd_fc;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Polling connection %s %s\n",
       GCC_2s (c),  GC_f2s (fwd));

  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_POLL);
  msg.header.size = htons (sizeof (msg));
  msg.pid = htonl (fc->last_pid_sent);
  LOG (GNUNET_ERROR_TYPE_DEBUG, " last pid sent: %u\n", fc->last_pid_sent);
  fc->poll_msg =
      GCC_send_prebuilt_message (&msg.header, 0, fc->last_pid_sent, c,
                                 fc == &c->fwd_fc, GNUNET_YES, &poll_sent, fc);
  GNUNET_assert (NULL != fc->poll_msg);
}


/**
 * Resend all queued messages for a connection on other connections of the
 * same tunnel, if possible. The connection WILL BE DESTROYED by this function.
 *
 * @param c Connection whose messages to resend.
 * @param fwd Resend fwd messages?
 */
static void
resend_messages_and_destroy (struct CadetConnection *c, int fwd)
{
  struct GNUNET_MessageHeader *out_msg;
  struct CadetTunnel *t = c->t;
  struct CadetPeer *neighbor;
  unsigned int pending;
  int destroyed;

  c->state = CADET_CONNECTION_DESTROYED;
  c->destroy = GNUNET_YES;

  destroyed = GNUNET_NO;
  neighbor = get_hop (c, fwd);
  pending = c->pending_messages;

  while (NULL != (out_msg = GCP_connection_pop (neighbor, c, &destroyed)))
  {
    if (NULL != t)
      GCT_resend_message (out_msg, t);
    GNUNET_free (out_msg);
  }

  /* All pending messages should have been popped,
   * and the connection destroyed by the continuation.
   */
  if (GNUNET_YES != destroyed)
  {
    if (0 != pending)
    {
      GNUNET_break (0);
      GCC_debug (c, GNUNET_ERROR_TYPE_ERROR);
      if (NULL != t) GCT_debug (t, GNUNET_ERROR_TYPE_ERROR);
    }
    GCC_destroy (c);
  }
}


/**
 * Generic connection timeout implementation.
 *
 * Timeout function due to lack of keepalive/traffic from an endpoint.
 * Destroys connection if called.
 *
 * @param c Connection to destroy.
 * @param fwd Was the timeout from the origin? (FWD timeout)
 */
static void
connection_timeout (struct CadetConnection *c, int fwd)
{
  struct CadetFlowControl *reverse_fc;

  reverse_fc = fwd ? &c->bck_fc : &c->fwd_fc;

  LOG (GNUNET_ERROR_TYPE_INFO,
       "Connection %s %s timed out. Destroying.\n",
       GCC_2s (c),
       GC_f2s (fwd));
  GCC_debug (c, GNUNET_ERROR_TYPE_DEBUG);

  if (GCC_is_origin (c, fwd)) /* Loopback? Something is wrong! */
  {
    GNUNET_break (0);
    return;
  }

  /* If dest, salvage queued traffic. */
  if (GCC_is_origin (c, !fwd))
  {
    const struct GNUNET_PeerIdentity *next_hop;

    next_hop = GCP_get_id (fwd ? get_prev_hop (c) : get_next_hop (c));
    send_broken_unknown (&c->id, &my_full_id, NULL, next_hop);
    if (0 < reverse_fc->queue_n)
      resend_messages_and_destroy (c, !fwd);
    return;
  }

  GCC_destroy (c);
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
  struct CadetConnection *c = cls;

  c->fwd_maintenance_task = NULL;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  connection_timeout (c, GNUNET_YES);
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
  struct CadetConnection *c = cls;

  c->bck_maintenance_task = NULL;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  connection_timeout (c, GNUNET_NO);
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
connection_reset_timeout (struct CadetConnection *c, int fwd)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Connection %s reset timeout\n", GC_f2s (fwd));

  if (GCC_is_origin (c, fwd)) /* Startpoint */
  {
    schedule_next_keepalive (c, fwd);
  }
  else /* Relay, endpoint. */
  {
    struct GNUNET_TIME_Relative delay;
    struct GNUNET_SCHEDULER_Task * *ti;
    GNUNET_SCHEDULER_TaskCallback f;

    ti = fwd ? &c->fwd_maintenance_task : &c->bck_maintenance_task;

    if (NULL != *ti)
      GNUNET_SCHEDULER_cancel (*ti);
    delay = GNUNET_TIME_relative_multiply (refresh_connection_time, 4);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  timing out in %s\n",
         GNUNET_STRINGS_relative_time_to_string (delay, GNUNET_NO));
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
register_neighbors (struct CadetConnection *c)
{
  c->next_peer = get_next_hop (c);
  c->prev_peer = get_prev_hop (c);
  GNUNET_break (c->next_peer != c->prev_peer);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "register neighbors for connection %s\n",
       GCC_2s (c));
  path_debug (c->path);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "own pos %u\n", c->own_pos);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "putting connection %s to next peer %p\n",
       GCC_2s (c),
       c->next_peer);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "next peer %p %s\n",
       c->next_peer,
       GCP_2s (c->next_peer));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "putting connection %s to prev peer %p\n",
       GCC_2s (c),
       c->prev_peer);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "prev peer %p %s\n",
       c->prev_peer,
       GCP_2s (c->prev_peer));

  if ( (GNUNET_NO == GCP_is_neighbor (c->next_peer)) ||
       (GNUNET_NO == GCP_is_neighbor (c->prev_peer)) )
  {
    if (GCC_is_origin (c, GNUNET_YES))
      GNUNET_STATISTICS_update (stats, "# local bad paths", 1, GNUNET_NO);
    GNUNET_STATISTICS_update (stats, "# bad paths", 1, GNUNET_NO);

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "  register neighbors failed\n");
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "  prev: %s, neighbor?: %d\n",
         GCP_2s (c->prev_peer),
         GCP_is_neighbor (c->prev_peer));
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "  next: %s, neighbor?: %d\n",
         GCP_2s (c->next_peer),
         GCP_is_neighbor (c->next_peer));
    return GNUNET_SYSERR;
  }
  GCP_add_connection (c->next_peer, c, GNUNET_NO);
  GCP_add_connection (c->prev_peer, c, GNUNET_YES);

  return GNUNET_OK;
}


/**
 * Remove the connection from the list of both neighbors.
 *
 * @param c Connection.
 */
static void
unregister_neighbors (struct CadetConnection *c)
{
  struct CadetPeer *peer;

  peer = get_next_hop (c);
  GNUNET_assert (c->next_peer == peer);
  GCP_remove_connection (peer, c);
  peer = get_prev_hop (c);
  GNUNET_assert (c->prev_peer == peer);
  GCP_remove_connection (peer, c);
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
add_to_peer (struct CadetConnection *c,
             struct CadetPeer *peer)
{
  GCP_add_tunnel (peer);
  c->t = GCP_get_tunnel (peer);
  GCT_add_connection (c->t, c);
}



/**
 * Iterator to compare each connection's path with the path of a new connection.
 *
 * If the connection conincides, the c member of path is set to the connection
 * and the destroy flag of the connection is set.
 *
 * @param cls Closure (new path).
 * @param c Connection in the tunnel to check.
 */
static void
check_path (void *cls, struct CadetConnection *c)
{
  struct CadetConnection *new_conn = cls;
  struct CadetPeerPath *path = new_conn->path;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  checking %s (%p), length %u\n",
       GCC_2s (c), c, c->path->length);

  if (c != new_conn
      && c->destroy == GNUNET_NO
      && c->state != CADET_CONNECTION_BROKEN
      && c->state != CADET_CONNECTION_DESTROYED
      && path_equivalent (path, c->path))
  {
    new_conn->destroy = GNUNET_YES;
    new_conn->path->c = c;
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  MATCH!\n");
  }
}

/**
 * Finds out if this path is already being used by and existing connection.
 *
 * Checks the tunnel towards the first peer in the path to see if it contains
 * any connection with the same path.
 *
 * If the existing connection is ready, it is kept.
 * Otherwise if the sender has a smaller ID that ours, we accept it (and
 * the peer will eventually reject our attempt).
 *
 * @param path Path to check.
 *
 * @return GNUNET_YES if the tunnel has a connection with the same path,
 *         GNUNET_NO otherwise.
 */
static int
does_connection_exist (struct CadetConnection *conn)
{
  struct CadetPeer *p;
  struct CadetTunnel *t;
  struct CadetConnection *c;

  p = GCP_get_short (conn->path->peers[0]);
  t = GCP_get_tunnel (p);
  if (NULL == t)
    return GNUNET_NO;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Checking for duplicates\n");

  GCT_iterate_connections (t, &check_path, conn);

  if (GNUNET_YES == conn->destroy)
  {
    c = conn->path->c;
    conn->destroy = GNUNET_NO;
    conn->path->c = conn;
    LOG (GNUNET_ERROR_TYPE_DEBUG, " found duplicate of %s\n", GCC_2s (conn));
    LOG (GNUNET_ERROR_TYPE_DEBUG, " duplicate: %s\n", GCC_2s (c));
    GCC_debug (c, GNUNET_ERROR_TYPE_DEBUG);
    if (CADET_CONNECTION_READY == c->state)
    {
      /* The other peer confirmed a live connection with this path,
       * why is it trying to duplicate it. */
      return GNUNET_YES;
    }

    if (GNUNET_CRYPTO_cmp_peer_identity (&my_full_id, GCP_get_id (p)) > 0)
    {
      struct CadetPeer *neighbor;

      LOG (GNUNET_ERROR_TYPE_DEBUG, " duplicate allowed (killing old)\n");
      if (GCC_is_origin (c, GNUNET_YES))
        neighbor = get_next_hop (c);
      else
        neighbor = get_prev_hop (c);
      send_broken_unknown (&c->id, &my_full_id, NULL,
                           GCP_get_id (neighbor));
      GCC_destroy (c);
      return GNUNET_NO;
    }
    else
      return GNUNET_YES;
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " %s has no duplicates\n", GCC_2s (conn));
    return GNUNET_NO;
  }
}


/**
 * Log receipt of message on stderr (INFO level).
 *
 * @param message Message received.
 * @param peer Peer who sent the message.
 * @param hash Connection ID.
 */
static void
log_message (const struct GNUNET_MessageHeader *message,
             const struct GNUNET_PeerIdentity *peer,
             const struct GNUNET_CADET_Hash *hash)
{
  uint16_t size;

  size = ntohs (message->size);
  LOG (GNUNET_ERROR_TYPE_INFO, "\n");
  LOG (GNUNET_ERROR_TYPE_INFO, "\n");
  LOG (GNUNET_ERROR_TYPE_INFO, "<-- %s on connection %s from %s, %6u bytes\n",
       GC_m2s (ntohs (message->type)), GNUNET_h2s (GC_h2hc (hash)),
       GNUNET_i2s (peer), (unsigned int) size);
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
GCC_handle_create (void *cls, const struct GNUNET_PeerIdentity *peer,
                   const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_CADET_ConnectionCreate *msg;
  struct GNUNET_PeerIdentity *id;
  struct GNUNET_CADET_Hash *cid;
  struct CadetPeerPath *path;
  struct CadetPeer *dest_peer;
  struct CadetPeer *orig_peer;
  struct CadetConnection *c;
  unsigned int own_pos;
  uint16_t size;

  /* Check size */
  size = ntohs (message->size);
  if (size < sizeof (struct GNUNET_CADET_ConnectionCreate))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  /* Calculate hops */
  size -= sizeof (struct GNUNET_CADET_ConnectionCreate);
  if (size % sizeof (struct GNUNET_PeerIdentity))
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }
  if (0 != size % sizeof (struct GNUNET_PeerIdentity))
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
  msg = (struct GNUNET_CADET_ConnectionCreate *) message;
  cid = &msg->cid;
  log_message (message, peer, cid);
  id = (struct GNUNET_PeerIdentity *) &msg[1];
  LOG (GNUNET_ERROR_TYPE_DEBUG, "    origin: %s\n", GNUNET_i2s (id));

  /* Create connection */
  c = connection_get (cid);
  if (NULL == c)
  {
    path = path_build_from_peer_ids ((struct GNUNET_PeerIdentity *) &msg[1],
                                     size, myid, &own_pos);
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
    c = GCC_new (cid, NULL, path, own_pos);
    if (NULL == c)
    {
      if (path->length - 1 == own_pos)
      {
        /* If we are destination, why did the creation fail? */
        GNUNET_break (0);
        path_destroy (path);
        return GNUNET_OK;
      }
      send_broken_unknown (cid, &my_full_id,
                           GNUNET_PEER_resolve2 (path->peers[own_pos + 1]),
                           peer);
      path_destroy (path);
      return GNUNET_OK;
    }
    GCP_add_path_to_all (path, GNUNET_NO);
    connection_reset_timeout (c, GNUNET_YES);
  }
  else
  {
    path = path_duplicate (c->path);
  }
  if (CADET_CONNECTION_NEW == c->state)
    connection_change_state (c, CADET_CONNECTION_SENT);

  /* Remember peers */
  dest_peer = GCP_get (&id[size - 1]);
  orig_peer = GCP_get (&id[0]);

  /* Is it a connection to us? */
  if (c->own_pos == path->length - 1)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  It's for us!\n");
    GCP_add_path_to_origin (orig_peer, path_duplicate (path), GNUNET_YES);

    add_to_peer (c, orig_peer);
    if (GNUNET_YES == does_connection_exist (c))
    {
      path_destroy (path);
      GCC_destroy (c);
      // FIXME Peer created a connection equal to one we think exists
      //       and is fine. What should we do?
      // Use explicit duplicate?
      // Accept new conn and destroy the old? (interruption in higher level)
      // Keep both and postpone disambiguation?
      // Keep the one created by peer with higher ID?
      // For now: reject new connection until current confirmed dead
      GNUNET_break_op (0);
      send_broken_unknown (cid, &my_full_id, NULL, peer);

      return GNUNET_OK;
    }

    if (CADET_TUNNEL_NEW == GCT_get_cstate (c->t))
      GCT_change_cstate (c->t,  CADET_TUNNEL_WAITING);

    send_connection_ack (c, GNUNET_NO);
    if (CADET_CONNECTION_SENT == c->state)
      connection_change_state (c, CADET_CONNECTION_ACK);
  }
  else
  {
    /* It's for somebody else! Retransmit. */
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  Retransmitting.\n");
    GCP_add_path (dest_peer, path_duplicate (path), GNUNET_NO);
    GCP_add_path_to_origin (orig_peer, path_duplicate (path), GNUNET_NO);
    GNUNET_assert (NULL == GCC_send_prebuilt_message (message, 0, 0, c,
                                                      GNUNET_YES, GNUNET_YES,
                                                      NULL, NULL));
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
GCC_handle_confirm (void *cls, const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_CADET_ConnectionACK *msg;
  struct CadetConnection *c;
  struct CadetPeerPath *p;
  struct CadetPeer *pi;
  enum CadetConnectionState oldstate;
  int fwd;

  msg = (struct GNUNET_CADET_ConnectionACK *) message;
  log_message (message, peer, &msg->cid);
  c = connection_get (&msg->cid);
  if (NULL == c)
  {
    GNUNET_STATISTICS_update (stats, "# control on unknown connection",
                              1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  don't know the connection!\n");
    send_broken_unknown (&msg->cid, &my_full_id, NULL, peer);
    return GNUNET_OK;
  }

  if (GNUNET_NO != c->destroy)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  connection being destroyed\n");
    return GNUNET_OK;
  }

  oldstate = c->state;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  via peer %s\n", GNUNET_i2s (peer));
  pi = GCP_get (peer);
  if (get_next_hop (c) == pi)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  SYNACK\n");
    fwd = GNUNET_NO;
    if (CADET_CONNECTION_SENT == oldstate)
      connection_change_state (c, CADET_CONNECTION_ACK);
  }
  else if (get_prev_hop (c) == pi)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  FINAL ACK\n");
    fwd = GNUNET_YES;
    connection_change_state (c, CADET_CONNECTION_READY);
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
    GCP_add_path_to_all (p, GNUNET_YES);
  }
  else
  {
    GNUNET_break (0);
  }

  /* Message for us as creator? */
  if (GCC_is_origin (c, GNUNET_YES))
  {
    if (GNUNET_NO != fwd)
    {
      GNUNET_break_op (0);
      return GNUNET_OK;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  Connection (SYN)ACK for us!\n");

    /* If just created, cancel the short timeout and start a long one */
    if (CADET_CONNECTION_SENT == oldstate)
      connection_reset_timeout (c, GNUNET_YES);

    /* Change connection state */
    connection_change_state (c, CADET_CONNECTION_READY);
    send_connection_ack (c, GNUNET_YES);

    /* Change tunnel state, trigger KX */
    if (CADET_TUNNEL_WAITING == GCT_get_cstate (c->t))
      GCT_change_cstate (c->t, CADET_TUNNEL_READY);

    return GNUNET_OK;
  }

  /* Message for us as destination? */
  if (GCC_is_terminal (c, GNUNET_YES))
  {
    if (GNUNET_YES != fwd)
    {
      GNUNET_break_op (0);
      return GNUNET_OK;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  Connection ACK for us!\n");

    /* If just created, cancel the short timeout and start a long one */
    if (CADET_CONNECTION_ACK == oldstate)
      connection_reset_timeout (c, GNUNET_NO);

    /* Change tunnel state */
    if (CADET_TUNNEL_WAITING == GCT_get_cstate (c->t))
      GCT_change_cstate (c->t, CADET_TUNNEL_READY);

    return GNUNET_OK;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  not for us, retransmitting...\n");
  GNUNET_assert (NULL == GCC_send_prebuilt_message (message, 0, 0, c, fwd,
                                                    GNUNET_YES, NULL, NULL));
  return GNUNET_OK;
}


/**
 * Core handler for notifications of broken connections.
 *
 * @param cls Closure (unused).
 * @param id Peer identity of sending neighbor.
 * @param message Message.
 *
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
int
GCC_handle_broken (void* cls,
                   const struct GNUNET_PeerIdentity* id,
                   const struct GNUNET_MessageHeader* message)
{
  struct GNUNET_CADET_ConnectionBroken *msg;
  struct CadetConnection *c;
  struct CadetTunnel *t;
  int pending;
  int fwd;

  msg = (struct GNUNET_CADET_ConnectionBroken *) message;
  log_message (message, id, &msg->cid);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  regarding %s\n",
              GNUNET_i2s (&msg->peer1));
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  regarding %s\n",
              GNUNET_i2s (&msg->peer2));
  c = connection_get (&msg->cid);
  if (NULL == c)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  duplicate CONNECTION_BROKEN\n");
    return GNUNET_OK;
  }

  t = c->t;

  fwd = is_fwd (c, id);
  c->destroy = GNUNET_YES;
  if (GCC_is_terminal (c, fwd))
  {
    struct CadetPeer *endpoint;

    if (NULL == t)
    {
      /* A terminal connection should not have 't' set to NULL. */
      GNUNET_break (0);
      GCC_debug (c, GNUNET_ERROR_TYPE_ERROR);
      return GNUNET_OK;
    }
    endpoint = GCP_get_short (c->path->peers[c->path->length - 1]);
    if (2 < c->path->length)
      path_invalidate (c->path);
    GCP_notify_broken_link (endpoint, &msg->peer1, &msg->peer2);

    c->state = CADET_CONNECTION_BROKEN;
    GCT_remove_connection (t, c);
    c->t = NULL;

    pending = c->pending_messages;
    if (0 < pending)
      resend_messages_and_destroy (c, !fwd);
    else
      GCC_destroy (c);
  }
  else
  {
    GNUNET_assert (NULL == GCC_send_prebuilt_message (message, 0, 0, c, fwd,
                                                      GNUNET_YES, NULL, NULL));
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
 * @return #GNUNET_OK to keep the connection open,
 *         #GNUNET_SYSERR to close it (signal serious error)
 */
int
GCC_handle_destroy (void *cls,
                    const struct GNUNET_PeerIdentity *peer,
                    const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_CADET_ConnectionDestroy *msg;
  struct CadetConnection *c;
  int fwd;

  msg = (const struct GNUNET_CADET_ConnectionDestroy *) message;
  log_message (message, peer, &msg->cid);
  c = connection_get (&msg->cid);
  if (NULL == c)
  {
    /* Probably already got the message from another path,
     * destroyed the tunnel and retransmitted to children.
     * Safe to ignore.
     */
    GNUNET_STATISTICS_update (stats, "# control on unknown connection",
                              1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "  connection unknown: already destroyed?\n");
    return GNUNET_OK;
  }
  fwd = is_fwd (c, peer);
  if (GNUNET_SYSERR == fwd)
  {
    GNUNET_break_op (0); /* FIXME */
    return GNUNET_OK;
  }
  if (GNUNET_NO == GCC_is_terminal (c, fwd))
    GNUNET_assert (NULL == GCC_send_prebuilt_message (message, 0, 0, c, fwd,
                                                      GNUNET_YES, NULL, NULL));
  else if (0 == c->pending_messages)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  directly destroying connection!\n");
    GCC_destroy (c);
    return GNUNET_OK;
  }
  c->destroy = GNUNET_YES;
  c->state = CADET_CONNECTION_DESTROYED;
  if (NULL != c->t)
  {
    GCT_remove_connection (c->t, c);
    c->t = NULL;
  }

  return GNUNET_OK;
}


/**
 * Check the message against internal state and test if it goes FWD or BCK.
 *
 * Updates the PID, state and timeout values for the connection.
 *
 * @param message Message to check. It must belong to an existing connection.
 * @param minimum_size The message cannot be smaller than this value.
 * @param cid Connection ID (even if @a c is NULL, the ID is still needed).
 * @param c Connection this message should belong. If NULL, check fails.
 * @param neighbor Neighbor that sent the message.
 */
static int
check_message (const struct GNUNET_MessageHeader *message,
               size_t minimum_size,
               const struct GNUNET_CADET_Hash* cid,
               struct CadetConnection *c,
               const struct GNUNET_PeerIdentity *neighbor,
               uint32_t pid)
{
  GNUNET_PEER_Id neighbor_id;
  struct CadetFlowControl *fc;
  struct CadetPeer *hop;
  int fwd;
  uint16_t type;

  /* Check size */
  if (ntohs (message->size) < minimum_size)
  {
    GNUNET_break_op (0);
    LOG (GNUNET_ERROR_TYPE_WARNING, "Size %u < %u\n",
         ntohs (message->size), minimum_size);
    return GNUNET_SYSERR;
  }

  /* Check connection */
  if (NULL == c)
  {
    GNUNET_STATISTICS_update (stats, "# unknown connection", 1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "%s on unknown connection %s\n",
         GC_m2s (ntohs (message->type)), GNUNET_h2s (GC_h2hc (cid)));
    send_broken_unknown (cid, &my_full_id, NULL, neighbor);
    return GNUNET_SYSERR;
  }

  /* Check if origin is as expected */
  neighbor_id = GNUNET_PEER_search (neighbor);
  hop = get_prev_hop (c);
  if (neighbor_id == GCP_get_short_id (hop))
  {
    fwd = GNUNET_YES;
  }
  else
  {
    hop = get_next_hop (c);
    GNUNET_break (hop == c->next_peer);
    if (neighbor_id == GCP_get_short_id (hop))
    {
      fwd = GNUNET_NO;
    }
    else
    {
      /* Unexpected peer sending traffic on a connection. */
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  }

  /* Check PID for payload messages */
  type = ntohs (message->type);
  if (GNUNET_MESSAGE_TYPE_CADET_ENCRYPTED == type
      || GNUNET_MESSAGE_TYPE_CADET_AX == type)
  {
    fc = fwd ? &c->bck_fc : &c->fwd_fc;
    LOG (GNUNET_ERROR_TYPE_DEBUG, " PID %u (expected %u - %u)\n",
         pid, fc->last_pid_recv + 1, fc->last_ack_sent);
    if (GC_is_pid_bigger (pid, fc->last_ack_sent))
    {
      GNUNET_break_op (0);
      GNUNET_STATISTICS_update (stats, "# unsolicited message", 1, GNUNET_NO);
      LOG (GNUNET_ERROR_TYPE_WARNING, "Received PID %u, (prev %u), ACK %u\n",
          pid, fc->last_pid_recv, fc->last_ack_sent);
      return GNUNET_SYSERR;
    }
    if (GC_is_pid_bigger (pid, fc->last_pid_recv))
    {
      unsigned int delta;

      delta = pid - fc->last_pid_recv;
      fc->last_pid_recv = pid;
      fc->recv_bitmap <<= delta;
      fc->recv_bitmap |= 1;
    }
    else
    {
      GNUNET_STATISTICS_update (stats, "# out of order PID", 1, GNUNET_NO);
      if (GNUNET_NO == is_ooo_ok (fc->last_pid_recv, pid, fc->recv_bitmap))
      {
        LOG (GNUNET_ERROR_TYPE_WARNING, "PID %u unexpected (%u+), dropping!\n",
             pid, fc->last_pid_recv - 31);
        return GNUNET_SYSERR;
      }
      fc->recv_bitmap |= get_recv_bitmask (fc->last_pid_recv, pid);
    }
  }

  /* Count as connection confirmation. */
  if (CADET_CONNECTION_SENT == c->state || CADET_CONNECTION_ACK == c->state)
  {
    connection_change_state (c, CADET_CONNECTION_READY);
    if (NULL != c->t)
    {
      if (CADET_TUNNEL_WAITING == GCT_get_cstate (c->t))
        GCT_change_cstate (c->t, CADET_TUNNEL_READY);
    }
  }
  connection_reset_timeout (c, fwd);

  return fwd;
}


/**
 * Generic handler for cadet network encrypted traffic.
 *
 * @param peer Peer identity this notification is about.
 * @param msg Encrypted message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_cadet_encrypted (const struct GNUNET_PeerIdentity *peer,
                        const struct GNUNET_MessageHeader *message)
{
  const struct GNUNET_CADET_Encrypted *otr_msg;
  const struct GNUNET_CADET_AX *ax_msg;
  const struct GNUNET_CADET_Hash* cid;
  struct CadetConnection *c;
  size_t minumum_size;
  size_t overhead;
  uint32_t pid;
  uint32_t ttl;
  int fwd;

  if (GNUNET_MESSAGE_TYPE_CADET_AX == ntohs (message->type))
  {
    overhead = sizeof (struct GNUNET_CADET_AX);
    ax_msg = (const struct GNUNET_CADET_AX *) message;
    cid = &ax_msg->cid;
    pid = ntohl (ax_msg->pid);
    otr_msg = NULL;
  }
  else
  {
    overhead = sizeof (struct GNUNET_CADET_Encrypted);
    otr_msg = (const struct GNUNET_CADET_Encrypted *) message;
    cid = &otr_msg->cid;
    pid = ntohl (otr_msg->pid);
  }

  log_message (message, peer, cid);

  minumum_size = sizeof (struct GNUNET_MessageHeader) + overhead;
  c = connection_get (cid);
  fwd = check_message (message, minumum_size, cid, c, peer, pid);

  /* If something went wrong, discard message. */
  if (GNUNET_SYSERR == fwd)
    return GNUNET_OK;

  /* Is this message for us? */
  if (GCC_is_terminal (c, fwd))
  {
    GNUNET_STATISTICS_update (stats, "# messages received", 1, GNUNET_NO);

    if (NULL == c->t)
    {
      GNUNET_break (GNUNET_NO != c->destroy);
      return GNUNET_OK;
    }
    GCT_handle_encrypted (c->t, message);
    GCC_send_ack (c, fwd, GNUNET_NO);
    return GNUNET_OK;
  }

  /* Message not for us: forward to next hop */
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  not for us, retransmitting...\n");
  if (NULL != otr_msg) /* only otr has ttl */
  {
    ttl = ntohl (otr_msg->ttl);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "   ttl: %u\n", ttl);
    if (ttl == 0)
    {
      GNUNET_STATISTICS_update (stats, "# TTL drops", 1, GNUNET_NO);
      LOG (GNUNET_ERROR_TYPE_WARNING, " TTL is 0, DROPPING!\n");
      GCC_send_ack (c, fwd, GNUNET_NO);
      return GNUNET_OK;
    }
  }

  GNUNET_STATISTICS_update (stats, "# messages forwarded", 1, GNUNET_NO);
  GNUNET_assert (NULL == GCC_send_prebuilt_message (message, 0, 0, c, fwd,
                                                    GNUNET_NO, NULL, NULL));

  return GNUNET_OK;
}

/**
 * Generic handler for cadet network encrypted traffic.
 *
 * @param peer Peer identity this notification is about.
 * @param msg Encrypted message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
static int
handle_cadet_kx (const struct GNUNET_PeerIdentity *peer,
                 const struct GNUNET_CADET_KX *msg)
{
  const struct GNUNET_CADET_Hash* cid;
  struct CadetConnection *c;
  size_t expected_size;
  int fwd;

  cid = &msg->cid;
  log_message (&msg->header, peer, cid);

  expected_size = sizeof (struct GNUNET_CADET_KX)
                  + sizeof (struct GNUNET_MessageHeader);
  c = connection_get (cid);
  fwd = check_message (&msg->header, expected_size, cid, c, peer, 0);

  /* If something went wrong, discard message. */
  if (GNUNET_SYSERR == fwd)
    return GNUNET_OK;

  /* Is this message for us? */
  if (GCC_is_terminal (c, fwd))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  message for us!\n");
    GNUNET_STATISTICS_update (stats, "# messages received", 1, GNUNET_NO);
    if (NULL == c->t)
    {
      GNUNET_break (0);
      return GNUNET_OK;
    }
    GCT_handle_kx (c->t, &msg[1].header);
    return GNUNET_OK;
  }

  /* Message not for us: forward to next hop */
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  not for us, retransmitting...\n");
  GNUNET_STATISTICS_update (stats, "# messages forwarded", 1, GNUNET_NO);
  GNUNET_assert (NULL == GCC_send_prebuilt_message (&msg->header, 0, 0, c, fwd,
                                                    GNUNET_NO, NULL, NULL));

  return GNUNET_OK;
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
GCC_handle_kx (void *cls, const struct GNUNET_PeerIdentity *peer,
               const struct GNUNET_MessageHeader *message)
{
  return handle_cadet_kx (peer, (struct GNUNET_CADET_KX *) message);
}


/**
 * Core handler for encrypted cadet network traffic (channel mgmt, data).
 *
 * @param cls Closure (unused).
 * @param message Message received.
 * @param peer Peer who sent the message.
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GCC_handle_encrypted (void *cls, const struct GNUNET_PeerIdentity *peer,
                      const struct GNUNET_MessageHeader *message)
{
  return handle_cadet_encrypted (peer, message);
}


/**
 * Core handler for cadet network traffic point-to-point acks.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GCC_handle_ack (void *cls, const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_CADET_ACK *msg;
  struct CadetConnection *c;
  struct CadetFlowControl *fc;
  GNUNET_PEER_Id id;
  uint32_t ack;
  int fwd;

  msg = (struct GNUNET_CADET_ACK *) message;
  log_message (message, peer, &msg->cid);
  c = connection_get (&msg->cid);
  if (NULL == c)
  {
    GNUNET_STATISTICS_update (stats, "# ack on unknown connection", 1,
                              GNUNET_NO);
    send_broken_unknown (&msg->cid, &my_full_id, NULL, peer);
    return GNUNET_OK;
  }

  /* Is this a forward or backward ACK? */
  id = GNUNET_PEER_search (peer);
  if (GCP_get_short_id (get_next_hop (c)) == id)
  {
    fc = &c->fwd_fc;
    fwd = GNUNET_YES;
  }
  else if (GCP_get_short_id (get_prev_hop (c)) == id)
  {
    fc = &c->bck_fc;
    fwd = GNUNET_NO;
  }
  else
  {
    GNUNET_break_op (0);
    return GNUNET_OK;
  }

  ack = ntohl (msg->ack);
  LOG (GNUNET_ERROR_TYPE_DEBUG, " %s ACK %u (was %u)\n",
       GC_f2s (fwd), ack, fc->last_ack_recv);
  if (GC_is_pid_bigger (ack, fc->last_ack_recv))
    fc->last_ack_recv = ack;

  /* Cancel polling if the ACK is big enough. */
  if (NULL != fc->poll_task &&
      GC_is_pid_bigger (fc->last_ack_recv, fc->last_pid_sent))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  Cancel poll\n");
    GNUNET_SCHEDULER_cancel (fc->poll_task);
    fc->poll_task = NULL;
    fc->poll_time = GNUNET_TIME_UNIT_SECONDS;
  }

  connection_unlock_queue (c, fwd);

  return GNUNET_OK;
}


/**
 * Core handler for cadet network traffic point-to-point ack polls.
 *
 * @param cls closure
 * @param message message
 * @param peer peer identity this notification is about
 *
 * @return GNUNET_OK to keep the connection open,
 *         GNUNET_SYSERR to close it (signal serious error)
 */
int
GCC_handle_poll (void *cls, const struct GNUNET_PeerIdentity *peer,
                 const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_CADET_Poll *msg;
  struct CadetConnection *c;
  struct CadetFlowControl *fc;
  GNUNET_PEER_Id id;
  uint32_t pid;
  int fwd;

  msg = (struct GNUNET_CADET_Poll *) message;
  log_message (message, peer, &msg->cid);
  c = connection_get (&msg->cid);
  if (NULL == c)
  {
    GNUNET_STATISTICS_update (stats, "# poll on unknown connection", 1,
                              GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "POLL message on unknown connection %s!\n",
         GNUNET_h2s (GC_h2hc (&msg->cid)));
    send_broken_unknown (&msg->cid, &my_full_id, NULL, peer);
    return GNUNET_OK;
  }

  /* Is this a forward or backward ACK?
   * Note: a poll should never be needed in a loopback case,
   * since there is no possiblility of packet loss there, so
   * this way of discerining FWD/BCK should not be a problem.
   */
  id = GNUNET_PEER_search (peer);
  if (GCP_get_short_id (get_next_hop (c)) == id)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  FWD FC\n");
    fc = &c->fwd_fc;
  }
  else if (GCP_get_short_id (get_prev_hop (c)) == id)
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
  GCC_send_ack (c, fwd, GNUNET_YES);

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
GCC_send_ack (struct CadetConnection *c, int fwd, int force)
{
  unsigned int buffer;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "GCC send %s ACK on %s\n",
       GC_f2s (fwd), GCC_2s (c));

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
  if (GCC_is_terminal (c, fwd))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  getting from all channels\n");
    buffer = GCT_get_channels_buffer (c->t);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  getting from one connection\n");
    buffer = GCC_get_buffer (c, fwd);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  buffer available: %u\n", buffer);
  if (0 == buffer && GNUNET_NO == force)
    return;

  /* Send available buffer space */
  if (GCC_is_origin (c, fwd))
  {
    GNUNET_assert (NULL != c->t);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  sending on channels...\n");
    GCT_unchoke_channels (c->t);
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
GCC_init (const struct GNUNET_CONFIGURATION_Handle *c)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "init\n");
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "CADET", "MAX_MSGS_QUEUE",
                                             &max_msgs_queue))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               "CADET", "MAX_MSGS_QUEUE", "MISSING");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "CADET", "MAX_CONNECTIONS",
                                             &max_connections))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               "CADET", "MAX_CONNECTIONS", "MISSING");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (c, "CADET", "REFRESH_CONNECTION_TIME",
                                           &refresh_connection_time))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               "CADET", "REFRESH_CONNECTION_TIME", "MISSING");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  create_connection_time = GNUNET_TIME_UNIT_SECONDS;
  connections = GNUNET_CONTAINER_multihashmap_create (1024, GNUNET_NO);
}


/**
 * Destroy each connection on shutdown.
 *
 * @param cls Closure (unused).
 * @param key Current key code (CID, unused).
 * @param value Value in the hash map (`struct CadetConnection`)
 *
 * @return #GNUNET_YES, because we should continue to iterate
 */
static int
shutdown_iterator (void *cls,
                   const struct GNUNET_HashCode *key,
                   void *value)
{
  struct CadetConnection *c = value;

  c->state = CADET_CONNECTION_DESTROYED;
  GCC_destroy (c);
  return GNUNET_YES;
}


/**
 * Shut down the connections subsystem.
 */
void
GCC_shutdown (void)
{
  GNUNET_CONTAINER_multihashmap_iterate (connections,
                                         &shutdown_iterator,
                                         NULL);
  GNUNET_CONTAINER_multihashmap_destroy (connections);
  connections = NULL;
}


/**
 * Create a connection.
 *
 * @param cid Connection ID (either created locally or imposed remotely).
 * @param t Tunnel this connection belongs to (or NULL);
 * @param path Path this connection has to use (copy is made).
 * @param own_pos Own position in the @c path path.
 *
 * @return Newly created connection, NULL in case of error (own id not in path).
 */
struct CadetConnection *
GCC_new (const struct GNUNET_CADET_Hash *cid,
         struct CadetTunnel *t,
         struct CadetPeerPath *path,
         unsigned int own_pos)
{
  struct CadetConnection *c;
  struct CadetPeerPath *p;

  p = path_duplicate (path);
  c = GNUNET_new (struct CadetConnection);
  c->id = *cid;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (connections,
                                                    GCC_get_h (c), c,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  fc_init (&c->fwd_fc);
  fc_init (&c->bck_fc);
  c->fwd_fc.c = c;
  c->bck_fc.c = c;

  c->t = t;
  GNUNET_assert (own_pos <= p->length - 1);
  c->own_pos = own_pos;
  c->path = p;
  p->c = c;
  GNUNET_assert (NULL != p);
  if (GNUNET_OK != register_neighbors (c))
  {
    if (0 == own_pos)
    {
      path_invalidate (c->path);
      c->t = NULL;
      c->path = NULL;
    }
    GCC_destroy (c);
    return NULL;
  }
  LOG (GNUNET_ERROR_TYPE_INFO, "New connection %s\n", GCC_2s (c));
  return c;
}


void
GCC_destroy (struct CadetConnection *c)
{
  if (NULL == c)
  {
    GNUNET_break (0);
    return;
  }

  if (2 == c->destroy) /* cancel queues -> GCP_queue_cancel -> q_destroy -> */
    return;            /* -> message_sent -> GCC_destroy. Don't loop. */
  c->destroy = 2;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "destroying connection %s\n",
       GCC_2s (c));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       " fc's f: %p, b: %p\n",
       &c->fwd_fc, &c->bck_fc);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       " fc tasks f: %u, b: %u\n",
       c->fwd_fc.poll_task,
       c->bck_fc.poll_task);

  /* Cancel all traffic */
  if (NULL != c->path)
  {
    connection_cancel_queues (c, GNUNET_YES);
    connection_cancel_queues (c, GNUNET_NO);
  }
  unregister_neighbors (c);
  path_destroy (c->path);
  c->path = NULL;

  /* Cancel maintainance task (keepalive/timeout) */
  if (NULL != c->fwd_fc.poll_msg)
  {
    GCC_cancel (c->fwd_fc.poll_msg);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 " POLL msg FWD canceled\n");
  }
  if (NULL != c->bck_fc.poll_msg)
  {
    GCC_cancel (c->bck_fc.poll_msg);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 " POLL msg BCK canceled\n");
  }

  /* Delete from tunnel */
  if (NULL != c->t)
    GCT_remove_connection (c->t, c);

  if (NULL != c->fwd_maintenance_task)
    GNUNET_SCHEDULER_cancel (c->fwd_maintenance_task);
  if (NULL != c->bck_maintenance_task)
    GNUNET_SCHEDULER_cancel (c->bck_maintenance_task);
  if (NULL != c->fwd_fc.poll_task)
  {
    GNUNET_SCHEDULER_cancel (c->fwd_fc.poll_task);
    LOG (GNUNET_ERROR_TYPE_DEBUG, " POLL task FWD canceled\n");
  }
  if (NULL != c->bck_fc.poll_task)
  {
    GNUNET_SCHEDULER_cancel (c->bck_fc.poll_task);
    LOG (GNUNET_ERROR_TYPE_DEBUG, " POLL task BCK canceled\n");
  }

  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_multihashmap_remove (connections,
                                                      GCC_get_h (c),
                                                      c));
  GNUNET_STATISTICS_update (stats,
                            "# connections",
                            -1,
                            GNUNET_NO);
  GNUNET_free (c);
}


/**
 * Get the connection ID.
 *
 * @param c Connection to get the ID from.
 *
 * @return ID of the connection.
 */
const struct GNUNET_CADET_Hash *
GCC_get_id (const struct CadetConnection *c)
{
  return &c->id;
}


/**
 * Get the connection ID.
 *
 * @param c Connection to get the ID from.
 *
 * @return ID of the connection.
 */
const struct GNUNET_HashCode *
GCC_get_h (const struct CadetConnection *c)
{
  return GC_h2hc (&c->id);
}


/**
 * Get the connection path.
 *
 * @param c Connection to get the path from.
 *
 * @return path used by the connection.
 */
const struct CadetPeerPath *
GCC_get_path (const struct CadetConnection *c)
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
enum CadetConnectionState
GCC_get_state (const struct CadetConnection *c)
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
struct CadetTunnel *
GCC_get_tunnel (const struct CadetConnection *c)
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
GCC_get_buffer (struct CadetConnection *c, int fwd)
{
  struct CadetFlowControl *fc;

  fc = fwd ? &c->fwd_fc : &c->bck_fc;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  Get %s buffer on %s: %u - %u\n",
       GC_f2s (fwd), GCC_2s (c), fc->queue_max, fc->queue_n);
  GCC_debug (c, GNUNET_ERROR_TYPE_DEBUG);

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
GCC_get_allowed (struct CadetConnection *c, int fwd)
{
  struct CadetFlowControl *fc;

  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  if (CADET_CONNECTION_READY != c->state
      || GC_is_pid_bigger (fc->last_pid_recv, fc->last_ack_sent))
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
GCC_get_qn (struct CadetConnection *c, int fwd)
{
  struct CadetFlowControl *fc;

  fc = fwd ? &c->fwd_fc : &c->bck_fc;

  return fc->queue_n;
}


/**
 * Get next PID to use.
 *
 * @param c Connection.
 * @param fwd Is query about FWD traffic?
 *
 * @return Last PID used + 1.
 */
unsigned int
GCC_get_pid (struct CadetConnection *c, int fwd)
{
  struct CadetFlowControl *fc;

  fc = fwd ? &c->fwd_fc : &c->bck_fc;

  return fc->last_pid_sent + 1;
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
GCC_allow (struct CadetConnection *c, unsigned int buffer, int fwd)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  allowing %s %u messages %s\n",
       GCC_2s (c), buffer, GC_f2s (fwd));
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
GCC_notify_broken (struct CadetConnection *c,
                   struct CadetPeer *peer)
{
  struct CadetPeer *hop;
  int fwd;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Notify broken on %s due to %s disconnect\n",
       GCC_2s (c),
       GCP_2s (peer));
  hop = get_prev_hop (c);
  if (NULL == hop)
  {
    /* Path was NULL, we should have deleted the connection. */
    GNUNET_break (0);
    return;
  }
  fwd = (peer == hop);
  if (GNUNET_YES == GCC_is_terminal (c, fwd))
  {
    /* Local shutdown, no one to notify about this. */
    GCC_destroy (c);
    return;
  }
  if (GNUNET_NO == c->destroy)
    send_broken (c, &my_full_id, GCP_get_id (peer), fwd);

  /* Connection will have at least one pending message
   * (the one we just scheduled), so no point in checking whether to
   * destroy immediately. */
  c->destroy = GNUNET_YES;
  c->state = CADET_CONNECTION_DESTROYED;

  /**
   * Cancel all queues, if no message is left, connection will be destroyed.
   */
  connection_cancel_queues (c, !fwd);
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
GCC_is_origin (struct CadetConnection *c, int fwd)
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
GCC_is_terminal (struct CadetConnection *c, int fwd)
{
  return GCC_is_origin (c, !fwd);
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
GCC_is_sendable (struct CadetConnection *c, int fwd)
{
  struct CadetFlowControl *fc;

  LOG (GNUNET_ERROR_TYPE_DEBUG, " checking sendability of %s traffic on %s\n",
       GC_f2s (fwd), GCC_2s (c));
  if (NULL == c)
  {
    GNUNET_break (0);
    return GNUNET_YES;
  }
  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       " last ack recv: %u, last pid sent: %u\n",
       fc->last_ack_recv, fc->last_pid_sent);
  if (GC_is_pid_bigger (fc->last_ack_recv, fc->last_pid_sent))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " sendable\n");
    return GNUNET_YES;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, " not sendable\n");
  return GNUNET_NO;
}


/**
 * Check if this connection is a direct one (never trim a direct connection).
 *
 * @param c Connection.
 *
 * @return #GNUNET_YES in case it's a direct connection, #GNUNET_NO otherwise.
 */
int
GCC_is_direct (struct CadetConnection *c)
{
  return (c->path->length == 2) ? GNUNET_YES : GNUNET_NO;
}

/**
 * Sends an already built message on a connection, properly registering
 * all used resources.
 *
 * @param message Message to send. Function makes a copy of it.
 *                If message is not hop-by-hop, decrements TTL of copy.
 * @param payload_type Type of payload, in case the message is encrypted.
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
struct CadetConnectionQueue *
GCC_send_prebuilt_message (const struct GNUNET_MessageHeader *message,
                           uint16_t payload_type, uint32_t payload_id,
                           struct CadetConnection *c, int fwd, int force,
                           GCC_sent cont, void *cont_cls)
{
  struct CadetFlowControl *fc;
  struct CadetConnectionQueue *q;
  void *data;
  size_t size;
  uint16_t type;
  int droppable;

  size = ntohs (message->size);
  data = GNUNET_malloc (size);
  memcpy (data, message, size);
  type = ntohs (message->type);
  LOG (GNUNET_ERROR_TYPE_INFO, "--> %s (%s %4u) on connection %s (%u bytes)\n",
       GC_m2s (type), GC_m2s (payload_type), payload_id, GCC_2s (c), size);

  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  droppable = GNUNET_NO == force;
  switch (type)
  {
    struct GNUNET_CADET_AX        *axmsg;
    struct GNUNET_CADET_Encrypted *emsg;
    struct GNUNET_CADET_KX        *kmsg;
    struct GNUNET_CADET_ACK       *amsg;
    struct GNUNET_CADET_Poll      *pmsg;
    struct GNUNET_CADET_ConnectionDestroy *dmsg;
    struct GNUNET_CADET_ConnectionBroken  *bmsg;
    uint32_t ttl;

    case GNUNET_MESSAGE_TYPE_CADET_AX:
    case GNUNET_MESSAGE_TYPE_CADET_ENCRYPTED:
      if (GNUNET_MESSAGE_TYPE_CADET_ENCRYPTED == type)
      {
        emsg = (struct GNUNET_CADET_Encrypted *) data;
        ttl = ntohl (emsg->ttl);
        if (0 == ttl)
        {
          GNUNET_break_op (0);
          GNUNET_free (data);
          return NULL;
        }
        emsg->cid = c->id;
        emsg->ttl = htonl (ttl - 1);
      }
      else
      {
        axmsg = (struct GNUNET_CADET_AX *) data;
        axmsg->cid = c->id;
      }
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  Q_N+ %p %u\n", fc, fc->queue_n);
      LOG (GNUNET_ERROR_TYPE_DEBUG, "last pid sent %u\n", fc->last_pid_sent);
      LOG (GNUNET_ERROR_TYPE_DEBUG, "     ack recv %u\n", fc->last_ack_recv);
      if (GNUNET_YES == droppable)
      {
        fc->queue_n++;
      }
      else
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG, "  not droppable, Q_N stays the same\n");
      }
      break;

    case GNUNET_MESSAGE_TYPE_CADET_KX:
      kmsg = (struct GNUNET_CADET_KX *) data;
      kmsg->cid = c->id;
      break;

    case GNUNET_MESSAGE_TYPE_CADET_ACK:
      amsg = (struct GNUNET_CADET_ACK *) data;
      amsg->cid = c->id;
      LOG (GNUNET_ERROR_TYPE_DEBUG, " ack %u\n", ntohl (amsg->ack));
      droppable = GNUNET_NO;
      break;

    case GNUNET_MESSAGE_TYPE_CADET_POLL:
      pmsg = (struct GNUNET_CADET_Poll *) data;
      pmsg->cid = c->id;
      LOG (GNUNET_ERROR_TYPE_DEBUG, " POLL %u\n", ntohl (pmsg->pid));
      droppable = GNUNET_NO;
      break;

    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY:
      dmsg = (struct GNUNET_CADET_ConnectionDestroy *) data;
      dmsg->cid = c->id;
      break;

    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_BROKEN:
      bmsg = (struct GNUNET_CADET_ConnectionBroken *) data;
      bmsg->cid = c->id;
      break;

    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE:
    case GNUNET_MESSAGE_TYPE_CADET_CONNECTION_ACK:
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
    LOG (GNUNET_ERROR_TYPE_DEBUG, "queue full: %u/%u\n",
         fc->queue_n, fc->queue_max);
    if (GNUNET_MESSAGE_TYPE_CADET_ENCRYPTED == type
        || GNUNET_MESSAGE_TYPE_CADET_AX == type)
    {
      fc->queue_n--;
    }
    GNUNET_free (data);
    return NULL; /* Drop this message */
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  C_P+ %s %u\n",
       GCC_2s (c), c->pending_messages);
  c->pending_messages++;

  q = GNUNET_new (struct CadetConnectionQueue);
  q->forced = !droppable;
  q->q = GCP_queue_add (get_hop (c, fwd), data, type, payload_type, payload_id,
                        size, c, fwd, &conn_message_sent, q);
  if (NULL == q->q)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "dropping msg on %s, NULL q\n", GCC_2s (c));
    GNUNET_free (data);
    GNUNET_free (q);
    return NULL;
  }
  q->cont = cont;
  q->cont_cls = cont_cls;
  return (NULL == cont) ? NULL : q;
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
GCC_cancel (struct CadetConnectionQueue *q)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "!  GCC cancel message\n");

  /* queue destroy calls message_sent, which calls q->cont and frees q */
  GCP_queue_destroy (q->q, GNUNET_YES, GNUNET_NO, 0);
}


/**
 * Sends a CREATE CONNECTION message for a path to a peer.
 * Changes the connection and tunnel states if necessary.
 *
 * @param connection Connection to create.
 */
void
GCC_send_create (struct CadetConnection *connection)
{
  enum CadetTunnelCState state;
  size_t size;

  size = sizeof (struct GNUNET_CADET_ConnectionCreate);
  size += connection->path->length * sizeof (struct GNUNET_PeerIdentity);

  LOG (GNUNET_ERROR_TYPE_INFO, "---> %s on connection %s  (%u bytes)\n",
       GC_m2s (GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE),
       GCC_2s (connection), size);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  C_P+ %p %u (create)\n",
       connection, connection->pending_messages);
  connection->pending_messages++;

  connection->maintenance_q =
    GCP_queue_add (get_next_hop (connection), NULL,
                   GNUNET_MESSAGE_TYPE_CADET_CONNECTION_CREATE, 0, 0,
                   size, connection, GNUNET_YES, &conn_message_sent, NULL);

  state = GCT_get_cstate (connection->t);
  if (CADET_TUNNEL_SEARCHING == state || CADET_TUNNEL_NEW == state)
    GCT_change_cstate (connection->t, CADET_TUNNEL_WAITING);
  if (CADET_CONNECTION_NEW == connection->state)
    connection_change_state (connection, CADET_CONNECTION_SENT);
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
GCC_send_destroy (struct CadetConnection *c)
{
  struct GNUNET_CADET_ConnectionDestroy msg;

  if (GNUNET_YES == c->destroy)
    return;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CONNECTION_DESTROY);
  msg.cid = c->id;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "  sending connection destroy for connection %s\n",
              GCC_2s (c));

  if (GNUNET_NO == GCC_is_terminal (c, GNUNET_YES))
    GNUNET_assert (NULL == GCC_send_prebuilt_message (&msg.header, 0, 0, c,
                                                      GNUNET_YES, GNUNET_YES,
                                                      NULL, NULL));
  if (GNUNET_NO == GCC_is_terminal (c, GNUNET_NO))
    GNUNET_assert (NULL == GCC_send_prebuilt_message (&msg.header, 0, 0, c,
                                                      GNUNET_NO, GNUNET_YES,
                                                      NULL, NULL));
  c->destroy = GNUNET_YES;
  c->state = CADET_CONNECTION_DESTROYED;
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
GCC_start_poll (struct CadetConnection *c, int fwd)
{
  struct CadetFlowControl *fc;

  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "POLL %s requested\n",
       GC_f2s (fwd));
  if (NULL != fc->poll_task || NULL != fc->poll_msg)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  POLL not needed (%p, %p)\n",
         fc->poll_task, fc->poll_msg);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "POLL started on request\n");
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
GCC_stop_poll (struct CadetConnection *c, int fwd)
{
  struct CadetFlowControl *fc;

  fc = fwd ? &c->fwd_fc : &c->bck_fc;
  if (NULL != fc->poll_task)
  {
    GNUNET_SCHEDULER_cancel (fc->poll_task);
    fc->poll_task = NULL;
  }
}

/**
 * Get a (static) string for a connection.
 *
 * @param c Connection.
 */
const char *
GCC_2s (const struct CadetConnection *c)
{
  if (NULL == c)
    return "NULL";

  if (NULL != c->t)
  {
    static char buf[128];

    SPRINTF (buf, "%s (->%s)",
             GNUNET_h2s (GC_h2hc (GCC_get_id (c))), GCT_2s (c->t));
    return buf;
  }
  return GNUNET_h2s (GC_h2hc (&c->id));
}


/**
 * Log all possible info about the connection state.
 *
 * @param c Connection to debug.
 * @param level Debug level to use.
 */
void
GCC_debug (const struct CadetConnection *c, enum GNUNET_ErrorType level)
{
  int do_log;
  char *s;

  do_log = GNUNET_get_log_call_status (level & (~GNUNET_ERROR_TYPE_BULK),
                                       "cadet-con",
                                       __FILE__, __FUNCTION__, __LINE__);
  if (0 == do_log)
    return;

  if (NULL == c)
  {
    LOG2 (level, "CCC DEBUG NULL CONNECTION\n");
    return;
  }

  LOG2 (level, "CCC DEBUG CONNECTION %s\n", GCC_2s (c));
  s = path_2s (c->path);
  LOG2 (level, "CCC  path %s, own pos: %u\n", s, c->own_pos);
  GNUNET_free (s);
  LOG2 (level, "CCC  state: %s, destroy: %u\n",
        GCC_state2s (c->state), c->destroy);
  LOG2 (level, "CCC  pending messages: %u\n", c->pending_messages);
  if (NULL != c->perf)
    LOG2 (level, "CCC  us/byte: %f\n", c->perf->avg);

  LOG2 (level, "CCC  FWD flow control:\n");
  LOG2 (level, "CCC   queue: %u/%u\n", c->fwd_fc.queue_n, c->fwd_fc.queue_max);
  LOG2 (level, "CCC   last PID sent: %5u, recv: %5u\n",
        c->fwd_fc.last_pid_sent, c->fwd_fc.last_pid_recv);
  LOG2 (level, "CCC   last ACK sent: %5u, recv: %5u\n",
        c->fwd_fc.last_ack_sent, c->fwd_fc.last_ack_recv);
  LOG2 (level, "CCC   recv PID bitmap: %X\n", c->fwd_fc.recv_bitmap);
  LOG2 (level, "CCC   poll: task %d, msg  %p, msg_ack %p)\n",
        c->fwd_fc.poll_task, c->fwd_fc.poll_msg, c->fwd_fc.ack_msg);

  LOG2 (level, "CCC  BCK flow control:\n");
  LOG2 (level, "CCC   queue: %u/%u\n", c->bck_fc.queue_n, c->bck_fc.queue_max);
  LOG2 (level, "CCC   last PID sent: %5u, recv: %5u\n",
        c->bck_fc.last_pid_sent, c->bck_fc.last_pid_recv);
  LOG2 (level, "CCC   last ACK sent: %5u, recv: %5u\n",
        c->bck_fc.last_ack_sent, c->bck_fc.last_ack_recv);
  LOG2 (level, "CCC   recv PID bitmap: %X\n", c->bck_fc.recv_bitmap);
  LOG2 (level, "CCC   poll: task %d, msg  %p, msg_ack %p)\n",
        c->bck_fc.poll_task, c->bck_fc.poll_msg, c->bck_fc.ack_msg);

  LOG2 (level, "CCC DEBUG CONNECTION END\n");
}
