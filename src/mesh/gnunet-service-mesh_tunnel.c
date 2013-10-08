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

#include "gnunet_statistics_service.h"

#include "mesh_protocol_enc.h"

#include "gnunet-service-mesh_tunnel.h"
#include "gnunet-service-mesh_connection.h"
#include "gnunet-service-mesh_channel.h"
#include "gnunet-service-mesh_peer.h"
#include "mesh_path.h"

#define LOG(level, ...) GNUNET_log_from(level,"mesh-tun",__VA_ARGS__)

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
/********************************   STRUCTS  **********************************/
/******************************************************************************/

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

/******************************************************************************/
/*******************************   GLOBALS  ***********************************/
/******************************************************************************/

/**
 * Global handle to the statistics service.
 */
extern struct GNUNET_STATISTICS_Handle *stats;

/**
 * Default TTL for payload packets.
 */
static unsigned long long default_ttl;

/**
 * Local peer own ID (memory efficient handle).
 */
static GNUNET_PEER_Id my_short_id;

/**
 * Local peer own ID (full value).
 */
const static struct GNUNET_PeerIdentity *my_full_id;

/**
 * Own private key.
 */
const static struct GNUNET_CRYPTO_EccPrivateKey *my_private_key;


/******************************************************************************/
/********************************   STATIC  ***********************************/
/******************************************************************************/

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

  LOG (GNUNET_ERROR_TYPE_DEBUG, "tunnel_get_connection %s\n",
              peer2s (t->peer));
  best = NULL;
  lowest_q = UINT_MAX;
  for (c = t->connection_head; NULL != c; c = c->next)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  connection %s: %u\n",
                GNUNET_h2s (GMC_get_id (c)), c->state);
    if (MESH_CONNECTION_READY == c->state)
    {
      fc = fwd ? &c->fwd_fc : &c->bck_fc;
      if (NULL == fc)
      {
        GNUNET_break (0);
        continue;
      }
      LOG (GNUNET_ERROR_TYPE_DEBUG, "    q_n %u, \n", fc->queue_n);
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
      ch_buf = GMCH_get_buffer (ch, fwd);
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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "tunnel_send_queued_data on tunnel %s\n",
              peer2s (t->peer));
  room = tunnel_get_buffer (t, fwd);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  buffer space: %u\n", room);
  for (tq = t->tq_head; NULL != tq && room > 0; tq = next)
  {
    next = tq->next;
    room--;
    GNUNET_CONTAINER_DLL_remove (t->tq_head, t->tq_tail, tq);
    GMCH_send_prebuilt_message ((struct GNUNET_MessageHeader *) &tq[1],
                                tq->ch, fwd);

    GNUNET_free (tq);
  }
}


/******************************************************************************/
/********************************    API    ***********************************/
/******************************************************************************/

/**
 * Cache a message to be sent once tunnel is online.
 *
 * @param t Tunnel to hold the message.
 * @param ch Channel the message is about.
 * @param msg Message itself (copy will be made).
 * @param fwd Is this fwd?
 */
void
GMT_queue_data (struct MeshTunnel2 *t,
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


/**
 * Initialize the tunnel subsystem.
 *
 * @param c Configuration handle.
 * @param id Peer identity.
 * @param key ECC private key, to derive all other keys and do crypto.
 */
void
GMT_init (const struct GNUNET_CONFIGURATION_Handle *c,
          const struct GNUNET_PeerIdentity *id,
          const struct GNUNET_CRYPTO_EccPrivateKey *key)
{
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "MESH", "DEFAULT_TTL",
                                             &default_ttl))
  {
    LOG_config_invalid (GNUNET_ERROR_TYPE_WARNING,
                               "MESH", "DEFAULT_TTL", "USING DEFAULT");
    default_ttl = 64;
  }
  my_full_id = id;
  my_private_key = key;
  my_short_id = GNUNET_PEER_intern (my_full_id);
}


/**
 * Shut down the tunnel subsystem.
 */
void
GMT_shutdown (void)
{
  GNUNET_PEER_change_rc (my_short_id, -1);
}


/**
 * Create a tunnel.
 */
struct MeshTunnel2 *
GMT_new (void)
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
 * Change the tunnel state.
 *
 * @param t Tunnel whose state to change.
 * @param state New state.
 */
void
GMT_change_state (struct MeshTunnel2* t, enum MeshTunnelState state)
{
  if (NULL == t)
    return;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "Tunnel %s state was %s\n",
              peer2s (t->peer),
              GNUNET_MESH_DEBUG_TS2S (t->state));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "Tunnel %s state is now %s\n",
              peer2s (t->peer),
              GNUNET_MESH_DEBUG_TS2S (state));
  t->state = state;
}


/**
 * Add a connection to a tunnel.
 *
 * @param t Tunnel.
 * @param c Connection.
 */
void
GMT_add_connection (struct MeshTunnel2 *t, struct MeshConnection *c)
{
  struct MeshConnection *aux;
  c->t = t;
  for (aux = t->connection_head; aux != NULL; aux = aux->next)
    if (aux == c)
      return;
    GNUNET_CONTAINER_DLL_insert_tail (t->connection_head, t->connection_tail, c);
}




/**
 * Tunnel is empty: destroy it.
 *
 * Notifies all connections about the destruction.
 *
 * @param t Tunnel to destroy.
 */
void
GMT_destroy_empty (struct MeshTunnel2 *t)
{
  struct MeshConnection *c;

  for (c = t->connection_head; NULL != c; c = c->next)
  {
    if (GNUNET_NO == c->destroy)
      GMC_send_destroy (c);
  }

  if (0 == t->pending_messages)
    GMT_destroy (t);
  else
    t->destroy = GNUNET_YES;
}


/**
 * Destroy tunnel if empty (no more channels).
 *
 * @param t Tunnel to destroy if empty.
 */
void
GMT_destroy_if_empty (struct MeshTunnel2 *t)
{
  if (1 < GMCH_count (t->channel_head))
    return;

  GMT_destroy_empty (t);
}



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
void
GMT_destroy (struct MeshTunnel2 *t)
{
  struct MeshConnection *c;
  struct MeshConnection *next;

  if (NULL == t)
    return;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "destroying tunnel %s\n",
              peer2s (t->peer));

//   if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_remove (tunnels, &t->id, t))
//     GNUNET_break (0);

  for (c = t->connection_head; NULL != c; c = next)
  {
    next = c->next;
    GMC_destroy (c);
  }

  GNUNET_STATISTICS_update (stats, "# tunnels", -1, GNUNET_NO);
  GMP_set_tunnel (t->peer, NULL);

  GNUNET_free (t);
}

/**
 * Demultiplex by message type and call appropriate handler for a message
 * towards a channel of a local tunnel.
 *
 * @param t Tunnel this message came on.
 * @param msgh Message header.
 * @param fwd Is this message fwd?
 */
void
GMT_handle_decrypted (struct MeshTunnel2 *t,
                      const struct GNUNET_MessageHeader *msgh,
                      int fwd)
{
  switch (ntohs (msgh->type))
  {
    case GNUNET_MESSAGE_TYPE_MESH_DATA:
      /* Don't send hop ACK, wait for client to ACK */
      GMCH_handle_data (t, (struct GNUNET_MESH_Data *) msgh, fwd);
      break;

    case GNUNET_MESSAGE_TYPE_MESH_DATA_ACK:
      GMCH_handle_data_ack (t, (struct GNUNET_MESH_DataACK *) msgh, fwd);
      break;

    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_CREATE:
      GMCH_handle_create (t,
                          (struct GNUNET_MESH_ChannelCreate *) msgh,
                          fwd);
      break;

    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_ACK:
      GMCH_handle_ack (t,
                       (struct GNUNET_MESH_ChannelManage *) msgh,
                       fwd);
      break;

    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_DESTROY:
      GMCH_handle_destroy (t,
                           (struct GNUNET_MESH_ChannelManage *) msgh,
                           fwd);
      break;

    default:
      GNUNET_break_op (0);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "end-to-end message not known (%u)\n",
           ntohs (msgh->type));
  }
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
GNUNET_PEER_Id
GMT_notify_connection_broken (struct MeshTunnel2* t,
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
 * @brief Use the given path for the tunnel.
 * Update the next and prev hops (and RCs).
 * (Re)start the path refresh in case the tunnel is locally owned.
 *
 * @param t Tunnel to update.
 * @param p Path to use.
 *
 * @return Connection created.
 */
struct MeshConnection *
GMT_use_path (struct MeshTunnel2 *t, struct MeshPeerPath *p)
{
  struct MeshConnection *c;
  struct GNUNET_HashCode cid;
  unsigned int own_pos;

  if (NULL == t || NULL == p)
  {
    GNUNET_break (0);
    return NULL;
  }

  for (own_pos = 0; own_pos < p->length; own_pos++)
  {
    if (p->peers[own_pos] == my_short_id)
      break;
  }
  if (own_pos > p->length - 1)
  {
    GNUNET_break (0);
    return NULL;
  }

  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_NONCE, &cid);
  c = GMC_new (&cid, t, p, own_pos);
  GNUNET_CONTAINER_DLL_insert (t->connection_head, t->connection_tail, c);
  return c;
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
void
GMT_encrypt (struct MeshTunnel2 *t,
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
void
GMT_decrypt (struct MeshTunnel2 *t,
             void *dst, const void *src,
             size_t size, uint64_t iv, int fwd)
{
  memcpy (dst, src, size);
}


/**
 * Count established (ready) connections of a tunnel.
 *
 * @param t Tunnel on which to send the message.
 *
 * @return Number of connections.
 */
unsigned int
GMT_count_connections (struct MeshTunnel2 *t)
{
  return GMC_count (t->connection_head);
}


/**
 * Sends an already built message on a tunnel, choosing the best connection.
 *
 * @param message Message to send. Function modifies it.
 * @param t Tunnel on which this message is transmitted.
 * @param ch Channel on which this message is transmitted.
 * @param fwd Is this a fwd message?
 */
void
GMT_send_prebuilt_message (struct GNUNET_MESH_Encrypted *msg,
                           struct MeshTunnel2 *t,
                           struct MeshChannel *ch,
                           int fwd)
{
  struct MeshConnection *c;
  uint16_t type;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Send on Tunnel %s\n",
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
      msg->cid = *GMC_get_id (c);
      msg->ttl = htonl (default_ttl);
      break;
    default:
      LOG (GNUNET_ERROR_TYPE_DEBUG, "unkown type %s\n",
           GNUNET_MESH_DEBUG_M2S (type));
      GNUNET_break (0);
  }
  msg->reserved = 0;

  GMC_send_prebuilt_message (&msg->header, c, ch, fwd);
}
