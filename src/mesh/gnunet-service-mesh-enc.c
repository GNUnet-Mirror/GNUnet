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
 * @file mesh/gnunet-service-mesh-enc.c
 * @brief GNUnet MESH service with encryption
 * @author Bartlomiej Polot
 *
 *  FIXME in progress:
 * - when sending in-order buffered data, wait for client ACKs
 * - add signatures
 * - add encryption
 * - set connection IDs independently from tunnel, tunnel has no ID
 *
 * TODO:
 * - relay corking down to core
 * - set ttl relative to path length
 * TODO END
 *
 * Dictionary:
 * - peer: other mesh instance. If there is direct connection it's a neighbor.
 * - tunnel: encrypted connection to a peer, neighbor or not.
 * - channel: connection between two clients, on the same or different peers.
 *            have properties like reliability.
 * - path: series of directly connected peer from one peer to another.
 * - connection: path which is being used in a tunnel.
 */

#include "platform.h"
#include "gnunet_util_lib.h"
#include "mesh_enc.h"
#include "block_mesh.h"
#include "gnunet_statistics_service.h"

#include "gnunet-service-mesh_local.h"
#include "gnunet-service-mesh_channel.h"
#include "gnunet-service-mesh_connection.h"
#include "gnunet-service-mesh_dht.h"
#include "gnunet-service-mesh_peer.h"

#define MESH_BLOOM_SIZE         128


#define MESH_DEBUG_TIMING       __LINUX__ && GNUNET_NO


#if MESH_DEBUG_TIMING
#include <time.h>
double __sum;
uint64_t __count;
struct timespec __mesh_start;
struct timespec __mesh_end;
#define INTERVAL_START clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &(__mesh_start))
#define INTERVAL_END \
do {\
  clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &(__mesh_end));\
  double __diff = __mesh_end.tv_nsec - __mesh_start.tv_nsec;\
  if (__diff < 0) __diff += 1000000000;\
  __sum += __diff;\
  __count++;\
} while (0)
#define INTERVAL_SHOW \
if (0 < __count)\
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "AVG process time: %f ns\n", __sum/__count)
#else
#define INTERVAL_START
#define INTERVAL_END
#define INTERVAL_SHOW
#endif

/**
 * All the states a tunnel can be in.
 */
enum MeshTunnelState
{
    /**
     * Uninitialized status, should never appear in operation.
     */
  MESH_TUNNEL_NEW,

    /**
     * Path to the peer not known yet
     */
  MESH_TUNNEL_SEARCHING,

    /**
     * Request sent, not yet answered.
     */
  MESH_TUNNEL_WAITING,

    /**
     * Peer connected and ready to accept data
     */
  MESH_TUNNEL_READY,

    /**
     * Peer connected previosly but not responding
     */
  MESH_TUNNEL_RECONNECTING
};



/******************************************************************************/
/************************      DATA STRUCTURES     ****************************/
/******************************************************************************/

/** FWD declaration */
struct MeshTunnel2;


/**
 * Struct used to queue messages in a tunnel.
 */
struct MeshTunnelQueue
{
  /**
   * DLL
   */
  struct MeshTunnelQueue *next;
  struct MeshTunnelQueue *prev;

  /**
   * Channel.
   */
  struct MeshChannel *ch;

  /**
   * Message to send.
   */
  /* struct GNUNET_MessageHeader *msg; */
};


/**
 * Struct containing all information regarding a tunnel to a peer.
 */
struct MeshTunnel2
{
    /**
     * Endpoint of the tunnel.
     */
  struct MeshPeer *peer;

    /**
     * State of the tunnel.
     */
  enum MeshTunnelState state;

  /**
   * Local peer ephemeral private key
   */
  struct GNUNET_CRYPTO_EccPrivateKey *my_eph_key;

  /**
   * Local peer ephemeral public key
   */
  struct GNUNET_CRYPTO_EccPublicSignKey *my_eph;

  /**
   * Remote peer's public key.
   */
  struct GNUNET_CRYPTO_EccPublicSignKey *peers_eph;

  /**
   * Encryption ("our") key.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey e_key;

  /**
   * Decryption ("their") key.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey d_key;

  /**
   * Paths that are actively used to reach the destination peer.
   */
  struct MeshConnection *connection_head;
  struct MeshConnection *connection_tail;

  /**
   * Next connection number.
   */
  uint32_t next_cid;

  /**
   * Channels inside this tunnel.
   */
  struct MeshChannel *channel_head;
  struct MeshChannel *channel_tail;

  /**
   * Channel ID for the next created channel.
   */
  MESH_ChannelNumber next_chid;

  /**
   * Channel ID for the next incoming channel.
   */
  MESH_ChannelNumber next_local_chid;

  /**
   * Pending message count.
   */
  int pending_messages;

  /**
   * Destroy flag: if true, destroy on last message.
   */
  int destroy;

  /**
   * Queued messages, to transmit once tunnel gets connected.
   */
  struct MeshTunnelQueue *tq_head;
  struct MeshTunnelQueue *tq_tail;
};



/******************************************************************************/
/************************      DEBUG FUNCTIONS     ****************************/
/******************************************************************************/

#if MESH_DEBUG
/**
 * GNUNET_SCHEDULER_Task for printing a message after some operation is done
 * @param cls string to print
 * @param success  GNUNET_OK if the PUT was transmitted,
 *                GNUNET_NO on timeout,
 *                GNUNET_SYSERR on disconnect from service
 *                after the PUT message was transmitted
 *                (so we don't know if it was received or not)
 */

#if 0
static void
mesh_debug (void *cls, int success)
{
  char *s = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "%s (%d)\n", s, success);
}
#endif

#endif

/******************************************************************************/
/***********************      GLOBAL VARIABLES     ****************************/
/******************************************************************************/

/************************** Configuration parameters **************************/


/**
 * Maximum time allowed to connect to a peer found by string.
 */
static struct GNUNET_TIME_Relative connect_timeout;

/**
 * Default TTL for payload packets.
 */
static unsigned long long default_ttl;

/**
 * Percentage of messages that will be dropped (for test purposes only).
 */
static unsigned long long drop_percent;

/*************************** Static global variables **************************/

/**
 * Handle to the statistics service.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Local peer own ID (memory efficient handle).
 */
static GNUNET_PEER_Id myid;

/**
 * Local peer own ID (full value).
 */
static struct GNUNET_PeerIdentity my_full_id;

/**
 * Own private key.
 */
static struct GNUNET_CRYPTO_EccPrivateKey *my_private_key;


/******************************************************************************/
/***********************         DECLARATIONS        **************************/
/******************************************************************************/

/**
 * Adds a path to the data structs of all the peers in the path
 *
 * @param p Path to process.
 * @param confirmed Whether we know if the path works or not.
 */
static void
path_add_to_peers (struct MeshPeerPath *p, int confirmed);


/**
 * Change the tunnel state.
 *
 * @param t Tunnel whose state to change.
 * @param state New state.
 */
static void
tunnel_change_state (struct MeshTunnel2 *t, enum MeshTunnelState state);


/**
 * Notify a tunnel that a connection has broken that affects at least
 * some of its peers.
 *
 * @param t Tunnel affected.
 * @param p1 Peer that got disconnected from p2.
 * @param p2 Peer that got disconnected from p1.
 *
 * @return Short ID of the peer disconnected (either p1 or p2).
 *         0 if the tunnel remained unaffected.
 */
static GNUNET_PEER_Id
tunnel_notify_connection_broken (struct MeshTunnel2 *t,
                                 GNUNET_PEER_Id p1, GNUNET_PEER_Id p2);

/**
 * @brief Use the given path for the tunnel.
 * Update the next and prev hops (and RCs).
 * (Re)start the path refresh in case the tunnel is locally owned.
 *
 * @param t Tunnel to update.
 * @param p Path to use.
 *
 * @return Connection created.
 */
static struct MeshConnection *
tunnel_use_path (struct MeshTunnel2 *t, struct MeshPeerPath *p);

/**
 * Tunnel is empty: destroy it.
 *
 * Notifies all participants (peers, cleints) about the destruction.
 *
 * @param t Tunnel to destroy.
 */
static void
tunnel_destroy_empty (struct MeshTunnel2 *t);

/**
 * Destroy the tunnel.
 *
 * This function does not generate any warning traffic to clients or peers.
 *
 * Tasks:
 * Cancel messages belonging to this tunnel queued to neighbors.
 * Free any allocated resources linked to the tunnel.
 *
 * @param t The tunnel to destroy.
 */
static void
tunnel_destroy (struct MeshTunnel2 *t);


/**
 * Demultiplex by message type and call appropriate handler for a message
 * towards a channel of a local tunnel.
 *
 * @param t Tunnel this message came on.
 * @param msgh Message header.
 * @param fwd Is this message fwd?
 */
static void
handle_decrypted (struct MeshTunnel2 *t,
                  const struct GNUNET_MessageHeader *msgh,
                  int fwd);


/**
 * Dummy function to separate declarations from definitions in function list.
 */
void
__mesh_divider______________________________________________________________();


/**
 * Get string description for tunnel state.
 *
 * @param s Tunnel state.
 *
 * @return String representation.
 */
static const char *
GNUNET_MESH_DEBUG_TS2S (enum MeshTunnelState s)
{
  static char buf[128];

  switch (s)
  {
    case MESH_TUNNEL_NEW:
      return "MESH_TUNNEL_NEW";
    case MESH_TUNNEL_SEARCHING:
      return "MESH_TUNNEL_SEARCHING";
    case MESH_TUNNEL_WAITING:
      return "MESH_TUNNEL_WAITING";
    case MESH_TUNNEL_READY:
      return "MESH_TUNNEL_READY";
    case MESH_TUNNEL_RECONNECTING:
      return "MESH_TUNNEL_RECONNECTING";

    default:
      sprintf (buf, "%u (UNKNOWN STATE)", s);
      return buf;
  }
}




/******************************************************************************/
/******************      GENERAL HELPER FUNCTIONS      ************************/
/******************************************************************************/


/**
 * Get the static string for a peer ID.
 *
 * @param peer Peer.
 *
 * @return Static string for it's ID.
 */
static const char *
peer2s (const struct MeshPeer *peer)
{
  if (NULL == peer)
    return "(NULL)";
  return GNUNET_i2s (GNUNET_PEER_resolve2 (peer->id));
}



/**
 * Count established (ready) connections of a tunnel.
 *
 * @param t Tunnel on which to send the message.
 *
 * @return Number of connections.
 */
static unsigned int
tunnel_count_connections (struct MeshTunnel2 *t)
{
  struct MeshConnection *c;
  unsigned int i;

  for (c = t->connection_head, i = 0; NULL != c; c = c->next, i++);

  return i;
}


/**
 * Pick a connection on which send the next data message.
 *
 * @param t Tunnel on which to send the message.
 * @param fwd Is this a fwd message?
 *
 * @return The connection on which to send the next message.
 */
static struct MeshConnection *
tunnel_get_connection (struct MeshTunnel2 *t, int fwd)
{
  struct MeshConnection *c;
  struct MeshConnection *best;
  struct MeshFlowControl *fc;
  unsigned int lowest_q;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "tunnel_get_connection %s\n",
              peer2s (t->peer));
  best = NULL;
  lowest_q = UINT_MAX;
  for (c = t->connection_head; NULL != c; c = c->next)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  connection %s: %u\n",
                GNUNET_h2s (&c->id), c->state);
    if (MESH_CONNECTION_READY == c->state)
    {
      fc = fwd ? &c->fwd_fc : &c->bck_fc;
      if (NULL == fc)
      {
        GNUNET_break (0);
        continue;
      }
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "    q_n %u, \n", fc->queue_n);
      if (fc->queue_n < lowest_q)
      {
        best = c;
        lowest_q = fc->queue_n;
      }
    }
  }
  return best;
}




/**
 * Get the total buffer space for a tunnel.
 *
 * @param t Tunnel.
 * @param fwd Is this for FWD traffic?
 *
 * @return Buffer space offered by all connections in the tunnel.
 */
static unsigned int
tunnel_get_buffer (struct MeshTunnel2 *t, int fwd)
{
  struct MeshConnection *c;
  struct MeshFlowControl *fc;
  unsigned int buffer;

  c = t->connection_head;
  buffer = 0;

  /* If terminal, return biggest channel buffer */
  if (NULL == c || GMC_is_terminal (c, fwd))
  {
    struct MeshChannel *ch;
    unsigned int ch_buf;

    if (NULL == t->channel_head)
      return 64;

    for (ch = t->channel_head; NULL != ch; ch = ch->next)
    {
      ch_buf = channel_get_buffer (ch, fwd);
      if (ch_buf > buffer)
        buffer = ch_buf;
    }
    return buffer;
  }

  /* If not terminal, return sum of connection buffers */
  while (NULL != c)
  {
    if (c->state != MESH_CONNECTION_READY)
    {
      c = c->next;
      continue;
    }

    fc = fwd ? &c->fwd_fc : &c->bck_fc;
    buffer += fc->queue_max - fc->queue_n;
    c = c->next;
  }

  return buffer;
}


/**
 * FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME
 * Encrypt data with the tunnel key.
 *
 * @param t Tunnel whose key to use.
 * @param dst Destination for the encrypted data.
 * @param src Source of the plaintext.
 * @param size Size of the plaintext.
 * @param iv Initialization Vector to use.
 * @param fwd Is this a fwd message?
 */
static void
tunnel_encrypt (struct MeshTunnel2 *t,
                void *dst, const void *src,
                size_t size, uint64_t iv, int fwd)
{
  memcpy (dst, src, size);
}


/**
 * FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME
 * Decrypt data with the tunnel key.
 *
 * @param t Tunnel whose key to use.
 * @param dst Destination for the plaintext.
 * @param src Source of the encrypted data.
 * @param size Size of the encrypted data.
 * @param iv Initialization Vector to use.
 * @param fwd Is this a fwd message?
 */
static void
tunnel_decrypt (struct MeshTunnel2 *t,
                void *dst, const void *src,
                size_t size, uint64_t iv, int fwd)
{
  memcpy (dst, src, size);
}


/**
 * Sends an already built message on a tunnel, choosing the best connection.
 *
 * @param message Message to send. Function modifies it.
 * @param t Tunnel on which this message is transmitted.
 * @param ch Channel on which this message is transmitted.
 * @param fwd Is this a fwd message?
 */
static void
send_prebuilt_message_tunnel (struct GNUNET_MESH_Encrypted *msg,
                              struct MeshTunnel2 *t,
                              struct MeshChannel *ch,
                              int fwd)
{
  struct MeshConnection *c;
  uint16_t type;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Send on Tunnel %s\n",
              peer2s (t->peer));
  c = tunnel_get_connection (t, fwd);
  if (NULL == c)
  {
    GNUNET_break (GNUNET_YES == t->destroy);
    return;
  }
  type = ntohs (msg->header.type);
  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_MESH_FWD:
    case GNUNET_MESSAGE_TYPE_MESH_BCK:
    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_CREATE:
    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_DESTROY:
      msg->cid = c->id;
      msg->ttl = htonl (default_ttl);
      break;
    default:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "unkown type %s\n",
                  GNUNET_MESH_DEBUG_M2S (type));
      GNUNET_break (0);
  }
  msg->reserved = 0;

  send_prebuilt_message_connection (&msg->header, c, ch, fwd);
}



/**
 * Sends a CREATE CONNECTION message for a path to a peer.
 * Changes the connection and tunnel states if necessary.
 *
 * @param connection Connection to create.
 */
static void
send_connection_create (struct MeshConnection *connection)
{
  struct MeshTunnel2 *t;

  t = connection->t;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Send connection create\n");
  queue_add (NULL,
             GNUNET_MESSAGE_TYPE_MESH_CONNECTION_CREATE,
             sizeof (struct GNUNET_MESH_ConnectionCreate) +
                (connection->path->length *
                 sizeof (struct GNUNET_PeerIdentity)),
             connection,
             NULL,
             GNUNET_YES);
  if (NULL != t &&
      (MESH_TUNNEL_SEARCHING == t->state || MESH_TUNNEL_NEW == t->state))
    tunnel_change_state (t, MESH_TUNNEL_WAITING);
  if (MESH_CONNECTION_NEW == connection->state)
    connection_change_state (connection, MESH_CONNECTION_SENT);
}


/**
 * Sends a CONNECTION ACK message in reponse to a received CONNECTION_CREATE
 * directed to us.
 *
 * @param connection Connection to confirm.
 * @param fwd Is this a fwd ACK? (First is bck (SYNACK), second is fwd (ACK))
 */
static void
send_connection_ack (struct MeshConnection *connection, int fwd)
{
  struct MeshTunnel2 *t;

  t = connection->t;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Send connection ack\n");
  queue_add (NULL,
             GNUNET_MESSAGE_TYPE_MESH_CONNECTION_ACK,
             sizeof (struct GNUNET_MESH_ConnectionACK),
             connection,
             NULL,
             fwd);
  if (MESH_TUNNEL_NEW == t->state)
    tunnel_change_state (t, MESH_TUNNEL_WAITING);
  if (MESH_CONNECTION_READY != connection->state)
    connection_change_state (connection, MESH_CONNECTION_SENT);
}


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


#if 0
static void
fc_debug (struct MeshFlowControl *fc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "    IN: %u/%u\n",
              fc->last_pid_recv, fc->last_ack_sent);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "    OUT: %u/%u\n",
              fc->last_pid_sent, fc->last_ack_recv);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "    QUEUE: %u/%u\n",
              fc->queue_n, fc->queue_max);
}

static void
connection_debug (struct MeshConnection *c)
{
  if (NULL == c)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "*** DEBUG NULL CONNECTION ***\n");
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Connection %s:%X\n",
              peer2s (c->t->peer), GNUNET_h2s (&c->id));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  state: %u, pending msgs: %u\n",
              c->state, c->pending_messages);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  FWD FC\n");
  fc_debug (&c->fwd_fc);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  BCK FC\n");
  fc_debug (&c->bck_fc);
}

#endif


/**
 * Change the tunnel state.
 *
 * @param t Tunnel whose state to change.
 * @param state New state.
 */
static void
tunnel_change_state (struct MeshTunnel2* t, enum MeshTunnelState state)
{
  if (NULL == t)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Tunnel %s state was %s\n",
              peer2s (t->peer),
              GNUNET_MESH_DEBUG_TS2S (t->state));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Tunnel %s state is now %s\n",
              peer2s (t->peer),
              GNUNET_MESH_DEBUG_TS2S (state));
  t->state = state;
}


/**
 * Send all cached messages that we can, tunnel is online.
 *
 * @param t Tunnel that holds the messages.
 * @param fwd Is this fwd?
 */
static void
tunnel_send_queued_data (struct MeshTunnel2 *t, int fwd)
{
  struct MeshTunnelQueue *tq;
  struct MeshTunnelQueue *next;
  unsigned int room;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "tunnel_send_queued_data on tunnel %s\n",
              peer2s (t->peer));
  room = tunnel_get_buffer (t, fwd);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  buffer space: %u\n", room);
  for (tq = t->tq_head; NULL != tq && room > 0; tq = next)
  {
    next = tq->next;
    room--;
    GNUNET_CONTAINER_DLL_remove (t->tq_head, t->tq_tail, tq);
    send_prebuilt_message_channel ((struct GNUNET_MessageHeader *) &tq[1],
                                   tq->ch, fwd);

    GNUNET_free (tq);
  }
}


/**
 * Cache a message to be sent once tunnel is online.
 *
 * @param t Tunnel to hold the message.
 * @param ch Channel the message is about.
 * @param msg Message itself (copy will be made).
 * @param fwd Is this fwd?
 */
static void
tunnel_queue_data (struct MeshTunnel2 *t,
                   struct MeshChannel *ch,
                   struct GNUNET_MessageHeader *msg,
                   int fwd)
{
  struct MeshTunnelQueue *tq;
  uint16_t size = ntohs (msg->size);

  tq = GNUNET_malloc (sizeof (struct MeshTunnelQueue) + size);

  tq->ch = ch;
  memcpy (&tq[1], msg, size);
  GNUNET_CONTAINER_DLL_insert_tail (t->tq_head, t->tq_tail, tq);

  if (MESH_TUNNEL_READY == t->state)
    tunnel_send_queued_data (t, fwd);
}





static struct MeshConnection *
tunnel_use_path (struct MeshTunnel2 *t, struct MeshPeerPath *p)
{
  struct MeshConnection *c;
  struct GNUNET_HashCode cid;
  struct MeshPeer *peer;
  unsigned int own_pos;

  if (NULL == t || NULL == p)
  {
    GNUNET_break (0);
    return NULL;
  }

  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_NONCE, &cid);

  c = connection_new (&cid);
  c->t = t;
  GNUNET_CONTAINER_DLL_insert (t->connection_head, t->connection_tail, c);
  for (own_pos = 0; own_pos < p->length; own_pos++)
  {
    if (p->peers[own_pos] == myid)
      break;
  }
  if (own_pos > p->length - 1)
  {
    GNUNET_break (0);
    connection_destroy (c);
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

  peer = connection_get_next_hop (c);
  if (NULL == peer->connections)
  {
    connection_destroy (c);
    return NULL;
  }
  GNUNET_CONTAINER_multihashmap_put (peer->connections, &c->id, c,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  peer = connection_get_prev_hop (c);
  if (NULL == peer->connections)
  {
    connection_destroy (c);
    return NULL;
  }
  GNUNET_CONTAINER_multihashmap_put (peer->connections, &c->id, c,
                                     GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST);
  return c;
}


/**
 * Notifies a tunnel that a connection has broken that affects at least
 * some of its peers. Sends a notification towards the root of the tree.
 * In case the peer is the owner of the tree, notifies the client that owns
 * the tunnel and tries to reconnect.
 *
 * FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME FIXME
 *
 * @param t Tunnel affected.
 * @param p1 Peer that got disconnected from p2.
 * @param p2 Peer that got disconnected from p1.
 *
 * @return Short ID of the peer disconnected (either p1 or p2).
 *         0 if the tunnel remained unaffected.
 */
static GNUNET_PEER_Id
tunnel_notify_connection_broken (struct MeshTunnel2* t,
                                 GNUNET_PEER_Id p1, GNUNET_PEER_Id p2)
{
//   if (myid != p1 && myid != p2) FIXME
//   {
//     return;
//   }
//
//   if (tree_get_predecessor (t->tree) != 0)
//   {
//     /* We are the peer still connected, notify owner of the disconnection. */
//     struct GNUNET_MESH_PathBroken msg;
//     struct GNUNET_PeerIdentity neighbor;
//
//     msg.header.size = htons (sizeof (msg));
//     msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_PATH_BROKEN);
//     GNUNET_PEER_resolve (t->id.oid, &msg.oid);
//     msg.tid = htonl (t->id.tid);
//     msg.peer1 = my_full_id;
//     GNUNET_PEER_resolve (pid, &msg.peer2);
//     GNUNET_PEER_resolve (tree_get_predecessor (t->tree), &neighbor);
//     send_prebuilt_message (&msg.header, &neighbor, t);
//   }
  return 0;
}




/**
 * Send an ACK on the appropriate connection/channel, depending on
 * the direction and the position of the peer.
 *
 * @param c Which connection to send the hop-by-hop ACK.
 * @param ch Channel, if any.
 * @param fwd Is this a fwd ACK? (will go dest->root)
 */
static void
send_ack (struct MeshConnection *c, struct MeshChannel *ch, int fwd)
{
  unsigned int buffer;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "send ack %s on %p %p\n",
              fwd ? "FWD" : "BCK", c, ch);
  if (NULL == c || GMC_is_terminal (c, fwd))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  getting from all connections\n");
    buffer = tunnel_get_buffer (NULL == c ? ch->t : c->t, fwd);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  getting from one connection\n");
    buffer = connection_get_buffer (c, fwd);
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  buffer available: %u\n", buffer);

  if ( (NULL != ch && channel_is_origin (ch, fwd)) ||
       (NULL != c && connection_is_origin (c, fwd)) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  sending on channel...\n");
    if (0 < buffer)
    {
      GNUNET_assert (NULL != ch);
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  really sending!\n");
      send_local_ack (ch, fwd);
    }
  }
  else if (NULL == c)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  sending on all connections\n");
    GNUNET_assert (NULL != ch);
    channel_send_connections_ack (ch, buffer, fwd);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  sending on connection\n");
    connection_send_ack (c, buffer, fwd);
  }
}




/**
 * Confirm we got a channel create.
 *
 * @param ch The channel to confirm.
 * @param fwd Should we send the ACK fwd?
 */
static void
channel_send_ack (struct MeshChannel *ch, int fwd)
{
  struct GNUNET_MESH_ChannelManage msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_CHANNEL_ACK);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  sending channel %s ack for channel %s:%X\n",
              fwd ? "FWD" : "BCK", peer2s (ch->t->peer),
              ch->gid);

  msg.chid = htonl (ch->gid);
  send_prebuilt_message_channel (&msg.header, ch, !fwd);
}


/**
 * Send a message to all clients (local and remote) of this channel
 * notifying that the channel is no longer valid.
 *
 * If some peer or client should not receive the message,
 * should be zero'ed out before calling this function.
 *
 * @param ch The channel whose clients to notify.
 */
static void
channel_send_destroy (struct MeshChannel *ch)
{
  struct GNUNET_MESH_ChannelManage msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_CHANNEL_DESTROY);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "  sending channel destroy for channel %s:%X\n",
              peer2s (ch->t->peer),
              ch->gid);

  if (channel_is_terminal (ch, GNUNET_NO))
  {
    if (NULL != ch->root && GNUNET_NO == ch->root->shutting_down)
    {
      msg.chid = htonl (ch->lid_root);
      send_local_channel_destroy (ch, GNUNET_NO);
    }
  }
  else
  {
    msg.chid = htonl (ch->gid);
    send_prebuilt_message_channel (&msg.header, ch, GNUNET_NO);
  }

  if (channel_is_terminal (ch, GNUNET_YES))
  {
    if (NULL != ch->dest && GNUNET_NO == ch->dest->shutting_down)
    {
      msg.chid = htonl (ch->lid_dest);
      send_local_channel_destroy (ch, GNUNET_YES);
    }
  }
  else
  {
    msg.chid = htonl (ch->gid);
    send_prebuilt_message_channel (&msg.header, ch, GNUNET_YES);
  }
}


/**
 * Create a tunnel.
 */
static struct MeshTunnel2 *
tunnel_new (void)
{
  struct MeshTunnel2 *t;

  t = GNUNET_new (struct MeshTunnel2);
  t->next_chid = 0;
  t->next_local_chid = GNUNET_MESH_LOCAL_CHANNEL_ID_SERV;
//   if (GNUNET_OK !=
//       GNUNET_CONTAINER_multihashmap_put (tunnels, tid, t,
//                                          GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
//   {
//     GNUNET_break (0);
//     tunnel_destroy (t);
//     return NULL;
//   }

//   char salt[] = "salt";
//   GNUNET_CRYPTO_kdf (&t->e_key, sizeof (struct GNUNET_CRYPTO_SymmetricSessionKey),
//                      salt, sizeof (salt),
//                      &t->e_key, sizeof (struct GNUNET_CRYPTO_SymmetricSessionKey),
//                      &my_full_id, sizeof (struct GNUNET_PeerIdentity),
//                      GNUNET_PEER_resolve2 (t->peer->id), sizeof (struct GNUNET_PeerIdentity),
//                      NULL);
//   GNUNET_CRYPTO_kdf (&t->d_key, sizeof (struct GNUNET_CRYPTO_SymmetricSessionKey),
//                      salt, sizeof (salt),
//                      &t->d_key, sizeof (struct GNUNET_CRYPTO_SymmetricSessionKey),
//                      GNUNET_PEER_resolve2 (t->peer->id), sizeof (struct GNUNET_PeerIdentity),
//                      &my_full_id, sizeof (struct GNUNET_PeerIdentity),
//                      NULL);

  return t;
}


/**
 * Add a connection to a tunnel.
 *
 * @param t Tunnel.
 * @param c Connection.
 */
static void
tunnel_add_connection (struct MeshTunnel2 *t, struct MeshConnection *c)
{
  struct MeshConnection *aux;
  c->t = t;
  for (aux = t->connection_head; aux != NULL; aux = aux->next)
    if (aux == c)
      return;
  GNUNET_CONTAINER_DLL_insert_tail (t->connection_head, t->connection_tail, c);
}



static void
tunnel_destroy (struct MeshTunnel2 *t)
{
  struct MeshConnection *c;
  struct MeshConnection *next;

  if (NULL == t)
    return;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "destroying tunnel %s\n",
              peer2s (t->peer));

//   if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_remove (tunnels, &t->id, t))
//     GNUNET_break (0);

  for (c = t->connection_head; NULL != c; c = next)
  {
    next = c->next;
    connection_destroy (c);
  }

  GNUNET_STATISTICS_update (stats, "# tunnels", -1, GNUNET_NO);
  t->peer->tunnel = NULL;

  GNUNET_free (t);
}


/**
 * Tunnel is empty: destroy it.
 *
 * Notifies all connections about the destruction.
 *
 * @param t Tunnel to destroy.
 */
static void
tunnel_destroy_empty (struct MeshTunnel2 *t)
{
  struct MeshConnection *c;

  for (c = t->connection_head; NULL != c; c = c->next)
  {
    if (GNUNET_NO == c->destroy)
      connection_send_destroy (c);
  }

  if (0 == t->pending_messages)
    tunnel_destroy (t);
  else
    t->destroy = GNUNET_YES;
}


/**
 * Destroy tunnel if empty (no more channels).
 *
 * @param t Tunnel to destroy if empty.
 */
static void
tunnel_destroy_if_empty (struct MeshTunnel2 *t)
{
  if (NULL != t->channel_head)
    return;

  tunnel_destroy_empty (t);
}


/******************************************************************************/
/****************      MESH NETWORK HANDLER HELPERS     ***********************/
/******************************************************************************/






/******************************************************************************/
/********************      MESH NETWORK HANDLERS     **************************/
/******************************************************************************/

static void
handle_decrypted (struct MeshTunnel2 *t,
                  const struct GNUNET_MessageHeader *msgh,
                  int fwd)
{
  switch (ntohs (msgh->type))
  {
    case GNUNET_MESSAGE_TYPE_MESH_DATA:
      /* Don't send hop ACK, wait for client to ACK */
      handle_data (t, (struct GNUNET_MESH_Data *) msgh, fwd);
      break;

    case GNUNET_MESSAGE_TYPE_MESH_DATA_ACK:
      handle_data_ack (t, (struct GNUNET_MESH_DataACK *) msgh, fwd);
      break;

    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_CREATE:
      handle_channel_create (t,
                             (struct GNUNET_MESH_ChannelCreate *) msgh,
                             fwd);
      break;

    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_ACK:
      handle_channel_ack (t,
                          (struct GNUNET_MESH_ChannelManage *) msgh,
                          fwd);
      break;

    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_DESTROY:
      handle_channel_destroy (t,
                              (struct GNUNET_MESH_ChannelManage *) msgh,
                              fwd);
      break;

    default:
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "end-to-end message not known (%u)\n",
                  ntohs (msgh->type));
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
//   struct MeshConnection *c;
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
    peer_connect (peer);
  }
  return;
}


/******************************************************************************/
/************************      MAIN FUNCTIONS      ****************************/
/******************************************************************************/




/**
 * Task run during shutdown.
 *
 * @param cls unused
 * @param tc unused
 */
static void
shutdown_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "shutting down\n");

  GML_shutdown ();
  GMD_shutdown ();
  GMP_shutdown ();
  GMC_shutdown ();

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "shut down\n");
}


/**
 * Process mesh requests.
 *
 * @param cls closure
 * @param server the initialized server
 * @param c configuration to use
 */
static void
run (void *cls, struct GNUNET_SERVER_Handle *server,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  struct GNUNET_CRYPTO_EccPrivateKey *pk;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "starting to run\n");

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (c, "MESH", "CONNECT_TIMEOUT",
                                           &connect_timeout))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_ERROR,
                               "MESH", "CONNECT_TIMEOUT", "MISSING");
    GNUNET_SCHEDULER_shutdown ();
    return;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "MESH", "DEFAULT_TTL",
                                             &default_ttl))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_WARNING,
                               "MESH", "DEFAULT_TTL", "USING DEFAULT");
    default_ttl = 64;
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


  stats = GNUNET_STATISTICS_create ("mesh", c);

  /* Scheduled the task to clean up when shutdown is called */
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL, &shutdown_task,
                                NULL);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO, "reading key\n");
  pk = GNUNET_CRYPTO_ecc_key_create_from_configuration (c);
  GNUNET_assert (NULL != pk);
  my_private_key = pk;
  GNUNET_CRYPTO_ecc_key_get_public_for_signature (my_private_key,
                                                  &my_full_id.public_key);
  myid = GNUNET_PEER_intern (&my_full_id);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Mesh for peer [%s] starting\n",
              GNUNET_i2s(&my_full_id));

  GML_init (server);    /* Local clients */
  GMC_init (c);         /* Connections */
  GMP_init (c);         /* Peers */
  GMD_init (c, &my_full_id);         /* DHT */

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Mesh service running\n");
}


/**
 * The main function for the mesh service.
 *
 * @param argc number of arguments from the command line
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 */
int
main (int argc, char *const *argv)
{
  int ret;
  int r;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "main()\n");
  r = GNUNET_SERVICE_run (argc, argv, "mesh", GNUNET_SERVICE_OPTION_NONE, &run,
                          NULL);
  ret = (GNUNET_OK == r) ? 0 : 1;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "main() END\n");

  INTERVAL_SHOW;

  return ret;
}
