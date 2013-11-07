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

#include "gnunet_signatures.h"
#include "gnunet_statistics_service.h"

#include "mesh_protocol_enc.h"
#include "mesh_path.h"

#include "gnunet-service-mesh_tunnel.h"
#include "gnunet-service-mesh_connection.h"
#include "gnunet-service-mesh_channel.h"
#include "gnunet-service-mesh_peer.h"

#define LOG(level, ...) GNUNET_log_from(level,"mesh-tun",__VA_ARGS__)

#define REKEY_WAIT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 30)

/******************************************************************************/
/********************************   STRUCTS  **********************************/
/******************************************************************************/

struct MeshTChannel
{
  struct MeshTChannel *next;
  struct MeshTChannel *prev;
  struct MeshChannel *ch;
};

struct MeshTConnection
{
  struct MeshTConnection *next;
  struct MeshTConnection *prev;
  struct MeshConnection *c;
};

/**
 * Structure used during a Key eXchange.
 */
struct MeshTunnelKXCtx
{
  /**
   * Decryption ("their") old key, for decrypting traffic sent by the
   * other end before the key exchange started.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey d_key_old;

  /**
   * Challenge to send in a ping and expect in the pong.
   */
  uint32_t challenge;
};

/**
 * Struct containing all information regarding a tunnel to a peer.
 */
struct MeshTunnel3
{
    /**
     * Endpoint of the tunnel.
     */
  struct MeshPeer *peer;

    /**
     * State of the tunnel.
     */
  enum MeshTunnel3State state;

  /**
   * Key eXchange context.
   */
  struct MeshTunnelKXCtx *kx_ctx;

  /**
   * Encryption ("our") key.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey e_key;

  /**
   * Decryption ("their") key.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey d_key;

  /**
   * Task to start the rekey process.
   */
  GNUNET_SCHEDULER_TaskIdentifier rekey_task;

  /**
   * Paths that are actively used to reach the destination peer.
   */
  struct MeshTConnection *connection_head;
  struct MeshTConnection *connection_tail;

  /**
   * Next connection number.
   */
  uint32_t next_cid;

  /**
   * Channels inside this tunnel.
   */
  struct MeshTChannel *channel_head;
  struct MeshTChannel *channel_tail;

  /**
   * Channel ID for the next created channel.
   */
  MESH_ChannelNumber next_chid;

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
 * Local peer own ID (memory efficient handle).
 */
extern GNUNET_PEER_Id myid;

/**
 * Local peer own ID (full value).
 */
extern struct GNUNET_PeerIdentity my_full_id;


/**
 * Set of all tunnels, in order to trigger a new exchange on rekey.
 * Indexed by peer's ID.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *tunnels;

/**
 * Default TTL for payload packets.
 */
static unsigned long long default_ttl;

/**
 * Own private key.
 */
const static struct GNUNET_CRYPTO_EddsaPrivateKey *my_private_key;

/**
 * Own ephemeral private key.
 */
static struct GNUNET_CRYPTO_EcdhePrivateKey *my_ephemeral_key;

/**
 * Cached message used to perform a key exchange.
 */
static struct GNUNET_MESH_KX_Ephemeral kx_msg;

/**
 * Task to generate a new ephemeral key.
 */
static GNUNET_SCHEDULER_TaskIdentifier rekey_task;

/**
 * Rekey period.
 */
static struct GNUNET_TIME_Relative rekey_period;

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
GMT_state2s (enum MeshTunnel3State s)
{
  static char buf[128];

  switch (s)
  {
    case MESH_TUNNEL3_NEW:
      return "MESH_TUNNEL3_NEW";
    case MESH_TUNNEL3_SEARCHING:
      return "MESH_TUNNEL3_SEARCHING";
    case MESH_TUNNEL3_WAITING:
      return "MESH_TUNNEL3_WAITING";
    case MESH_TUNNEL3_KEY_SENT:
      return "MESH_TUNNEL3_KEY_SENT";
    case MESH_TUNNEL3_PING_SENT:
      return "MESH_TUNNEL3_PING_SENT";
    case MESH_TUNNEL3_READY:
      return "MESH_TUNNEL3_READY";
    case MESH_TUNNEL3_RECONNECTING:
      return "MESH_TUNNEL3_RECONNECTING";
    case MESH_TUNNEL3_REKEY:
      return "MESH_TUNNEL3_REKEY";

    default:
      sprintf (buf, "%u (UNKNOWN STATE)", s);
      return buf;
  }
}


/**
 * Ephemeral key message purpose size.
 *
 * @return Size of the part of the ephemeral key message that must be signed.
 */
size_t
ephemeral_purpose_size (void)
{
  return sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
         sizeof (struct GNUNET_TIME_AbsoluteNBO) +
         sizeof (struct GNUNET_TIME_AbsoluteNBO) +
         sizeof (struct GNUNET_CRYPTO_EcdhePublicKey) +
         sizeof (struct GNUNET_PeerIdentity);
}


/**
 * Size of the encrypted part of a ping message.
 *
 * @return Size of the encrypted part of a ping message.
 */
size_t
ping_encryption_size (void)
{
  return sizeof (struct GNUNET_PeerIdentity) + sizeof (uint32_t);
}


/**
 * Get the channel's buffer. ONLY FOR NON-LOOPBACK CHANNELS!!
 *
 * @param tch Tunnel's channel handle.
 *
 * @return Amount of messages the channel can still buffer towards the client.
 */
static unsigned int
get_channel_buffer (const struct MeshTChannel *tch)
{
  int fwd;

  /* If channel is outgoing, is origin in the FWD direction and fwd is YES */
  fwd = GMCH_is_origin (tch->ch, GNUNET_YES);

  return GMCH_get_buffer (tch->ch, fwd);
}


/**
 * Get the channel's allowance status.
 *
 * @param tch Tunnel's channel handle.
 *
 * @return #GNUNET_YES if we allowed the client to send data to us.
 */
static int
get_channel_allowed (const struct MeshTChannel *tch)
{
  int fwd;

  /* If channel is outgoing, is origin in the FWD direction and fwd is YES */
  fwd = GMCH_is_origin (tch->ch, GNUNET_YES);

  return GMCH_get_allowed (tch->ch, fwd);
}


/**
 * Get the connection's buffer.
 *
 * @param tc Tunnel's connection handle.
 *
 * @return Amount of messages the connection can still buffer.
 */
static unsigned int
get_connection_buffer (const struct MeshTConnection *tc)
{
  int fwd;

  /* If connection is outgoing, is origin in the FWD direction and fwd is YES */
  fwd = GMC_is_origin (tc->c, GNUNET_YES);

  return GMC_get_buffer (tc->c, fwd);
}


/**
 * Get the connection's allowance.
 *
 * @param tc Tunnel's connection handle.
 *
 * @return Amount of messages we have allowed the next peer to send us.
 */
static unsigned int
get_connection_allowed (const struct MeshTConnection *tc)
{
  int fwd;

  /* If connection is outgoing, is origin in the FWD direction and fwd is YES */
  fwd = GMC_is_origin (tc->c, GNUNET_YES);

  return GMC_get_allowed (tc->c, fwd);
}


/**
 * Check that a ephemeral key message s well formed and correctly signed.
 *
 * @param t Tunnel on which the message came.
 * @param msg The ephemeral key message.
 *
 * @return GNUNET_OK if message is fine, GNUNET_SYSERR otherwise.
 */
int
check_ephemeral (struct MeshTunnel3 *t, 
                 const struct GNUNET_MESH_KX_Ephemeral *msg)
{
  /* Check message size */
  if (ntohs (msg->header.size) != sizeof (struct GNUNET_MESH_KX_Ephemeral))
    return GNUNET_SYSERR;

  /* Check signature size */
  if (ntohl (msg->purpose.size) != ephemeral_purpose_size ())
    return GNUNET_SYSERR;

  /* Check origin */
  if (0 != memcmp (&msg->origin_identity,
                   GMP_get_id (t->peer),
                   sizeof (struct GNUNET_PeerIdentity)))
    return GNUNET_SYSERR;

  /* Check signature */
  if (GNUNET_OK !=
      GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_PURPOSE_MESH_KX,
                                  &msg->purpose,
                                  &msg->signature,
                                  &msg->origin_identity.public_key))
    return GNUNET_SYSERR;

  return GNUNET_OK;
}


/**
 * Encrypt data with the tunnel key.
 *
 * @param t Tunnel whose key to use.
 * @param dst Destination for the encrypted data.
 * @param src Source of the plaintext. Can overlap with @c dst.
 * @param size Size of the plaintext.
 * @param iv Initialization Vector to use.
 */
static int
t_encrypt (struct MeshTunnel3 *t,
           void *dst, const void *src,
           size_t size, uint32_t iv)
{
  struct GNUNET_CRYPTO_SymmetricInitializationVector siv;

  GNUNET_CRYPTO_symmetric_derive_iv (&siv, &t->e_key, &iv, sizeof (uint32_t), NULL);
  return GNUNET_CRYPTO_symmetric_encrypt (src, size, &t->e_key, &siv, dst);
}


/**
 * Decrypt data with the tunnel key.
 *
 * @param t Tunnel whose key to use.
 * @param dst Destination for the plaintext.
 * @param src Source of the encrypted data. Can overlap with @c dst.
 * @param size Size of the encrypted data.
 * @param iv Initialization Vector to use.
 */
static int
t_decrypt (struct MeshTunnel3 *t,
           void *dst, const void *src,
           size_t size, uint32_t iv)
{
  struct GNUNET_CRYPTO_SymmetricInitializationVector siv;

  GNUNET_CRYPTO_symmetric_derive_iv (&siv, &t->e_key, &iv, sizeof (uint32_t), NULL);
  return GNUNET_CRYPTO_symmetric_decrypt (src, size, &t->d_key, &siv, dst);
}


/**
 * Create key material by doing ECDH on the local and remote ephemeral keys.
 *
 * @param key_material Where to store the key material.
 * @param ephemeral_key Peer's public ephemeral key.
 */
void
derive_key_material (struct GNUNET_HashCode *key_material,
                     const struct GNUNET_CRYPTO_EcdhePublicKey *ephemeral_key)
{
  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecc_ecdh (my_ephemeral_key,
                              ephemeral_key,
                              key_material))
  {
    GNUNET_break (0);
  }
}

/**
 * Create a symmetic key from the identities of both ends and the key material
 * from ECDH.
 *
 * @param key Destination for the generated key.
 * @param sender ID of the peer that will encrypt with @c key.
 * @param receiver ID of the peer that will decrypt with @c key.
 * @param key_material Hash created with ECDH with the ephemeral keys.
 */
void
derive_symmertic (struct GNUNET_CRYPTO_SymmetricSessionKey *key,
                  const struct GNUNET_PeerIdentity *sender,
                  const struct GNUNET_PeerIdentity *receiver,
                  const struct GNUNET_HashCode *key_material)
{
  const char salt[] = "MESH kx salt";

  GNUNET_CRYPTO_kdf (key, sizeof (struct GNUNET_CRYPTO_SymmetricSessionKey),
                     salt, sizeof (salt),
                     key_material, sizeof (struct GNUNET_HashCode),
                     sender, sizeof (struct GNUNET_PeerIdentity),
                     receiver, sizeof (struct GNUNET_PeerIdentity),
                     NULL);
}

/**
 * Pick a connection on which send the next data message.
 *
 * @param t Tunnel on which to send the message.
 *
 * @return The connection on which to send the next message.
 */
static struct MeshConnection *
tunnel_get_connection (struct MeshTunnel3 *t)
{
  struct MeshTConnection *iter;
  struct MeshConnection *best;
  unsigned int qn;
  unsigned int lowest_q;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "tunnel_get_connection %s\n", GMP_2s (t->peer));
  best = NULL;
  lowest_q = UINT_MAX;
  for (iter = t->connection_head; NULL != iter; iter = iter->next)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  connection %s: %u\n",
         GNUNET_h2s (GMC_get_id (iter->c)), GMC_get_state (iter->c));
    if (MESH_CONNECTION_READY == GMC_get_state (iter->c))
    {
      qn = GMC_get_qn (iter->c, GMC_is_origin (iter->c, GNUNET_YES));
      LOG (GNUNET_ERROR_TYPE_DEBUG, "    q_n %u, \n", qn);
      if (qn < lowest_q)
      {
        best = iter->c;
        lowest_q = qn;
      }
    }
  }
  return best;
}


/**
 * Send all cached messages that we can, tunnel is online.
 *
 * @param t Tunnel that holds the messages. Cannot be loopback.
 */
static void
send_queued_data (struct MeshTunnel3 *t)
{
  struct MeshTunnelQueue *tq;
  struct MeshTunnelQueue *next;
  unsigned int room;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "GMT_send_queued_data on tunnel %s\n",
              GMT_2s (t));

  if (GMT_is_loopback (t))
  {
    GNUNET_break (0);
    return;
  }

  room = GMT_get_connections_buffer (t);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  buffer space: %u\n", room);
  for (tq = t->tq_head; NULL != tq && room > 0; tq = next)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " data on channel %s\n", GMCH_2s (tq->ch));
    next = tq->next;
    room--;
    GNUNET_CONTAINER_DLL_remove (t->tq_head, t->tq_tail, tq);
    GMCH_send_prebuilt_message ((struct GNUNET_MessageHeader *) &tq[1],
                                tq->ch, GMCH_is_origin (tq->ch, GNUNET_YES));

    GNUNET_free (tq);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "GMT_send_queued_data end\n",
       GMP_2s (t->peer));
}




/**
 * Cache a message to be sent once tunnel is online.
 *
 * @param t Tunnel to hold the message.
 * @param ch Channel the message is about.
 * @param msg Message itself (copy will be made).
 */
static void
queue_data (struct MeshTunnel3 *t,
            struct MeshChannel *ch,
            const struct GNUNET_MessageHeader *msg)
{
  struct MeshTunnelQueue *tq;
  uint16_t size = ntohs (msg->size);

  if (MESH_TUNNEL3_READY == t->state)
  {
    GNUNET_break (0);
    return;
  }

  tq = GNUNET_malloc (sizeof (struct MeshTunnelQueue) + size);

  tq->ch = ch;
  memcpy (&tq[1], msg, size);
  GNUNET_CONTAINER_DLL_insert_tail (t->tq_head, t->tq_tail, tq);
}



/**
 * Sends key exchange message on a tunnel, choosing the best connection.
 * Should not be called on loopback tunnels.
 *
 * @param t Tunnel on which this message is transmitted.
 * @param message Message to send. Function modifies it.
 */
static void
send_kx (struct MeshTunnel3 *t,
         const struct GNUNET_MessageHeader *message)
{
  struct MeshConnection *c;
  struct GNUNET_MESH_KX *msg;
  size_t size = ntohs (message->size);
  char cbuf[sizeof (struct GNUNET_MESH_KX) + size];
  uint16_t type;
  int fwd;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "GMT KX on Tunnel %s\n", GMT_2s (t));

  /* Avoid loopback. */
  if (GMT_is_loopback (t))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  loopback!\n");
    GNUNET_break (0);
    return;
  }

  /* Must have a connection. */
  if (NULL == t->connection_head)
  {
    GNUNET_break (0);
    return;
  }

  msg = (struct GNUNET_MESH_KX *) cbuf;
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_KX);
  msg->header.size = htons (sizeof (struct GNUNET_MESH_KX) + size);
  c = tunnel_get_connection (t);
  if (NULL == c)
  {
    GNUNET_break (GNUNET_YES == t->destroy);
    return;
  }
  type = ntohs (message->type);
  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_MESH_KX_EPHEMERAL:
    case GNUNET_MESSAGE_TYPE_MESH_KX_PING:
    case GNUNET_MESSAGE_TYPE_MESH_KX_PONG:
      msg->cid = *GMC_get_id (c);
      msg->reserved = htonl (0);
      memcpy (&msg[1], message, size);
      break;
    default:
      LOG (GNUNET_ERROR_TYPE_DEBUG, "unkown type %s\n",
           GNUNET_MESH_DEBUG_M2S (type));
      GNUNET_break (0);
  }

  fwd = GMC_is_origin (t->connection_head->c, GNUNET_YES);
  GMC_send_prebuilt_message (&msg->header, c, fwd);
}


/**
 * Send the ephemeral key on a tunnel.
 *
 * @param t Tunnel on which to send the key.
 */
static void
send_ephemeral (struct MeshTunnel3 *t)
{
  kx_msg.sender_status = htonl (t->state);

  send_kx (t, &kx_msg.header);
}

/**
 * Send a ping message on a tunnel.
 *
 * @param t Tunnel on which to send the ping.
 */
static void
send_ping (struct MeshTunnel3 *t)
{
  struct GNUNET_MESH_KX_Ping msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_KX_PING);
  msg.iv = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX);
  msg.target = *GMP_get_id (t->peer);
  msg.nonce = t->kx_ctx->challenge;
  t_encrypt (t, &msg.target, &msg.target, ping_encryption_size(), msg.iv);

  send_kx (t, &msg.header);
}


/**
 * Send a pong message on a tunnel.
 *
 * @param t Tunnel on which to send the pong.
 * @param challenge Value sent in the ping that we have to send back.
 */
static void
send_pong (struct MeshTunnel3 *t, uint32_t challenge)
{
  struct GNUNET_MESH_KX_Pong msg;

  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_KX_PONG);
  msg.iv = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX);
  msg.nonce = challenge;
  t_encrypt (t, &msg.nonce, &msg.nonce, sizeof (msg.nonce), msg.iv);

  send_kx (t, &msg.header);
}


/**
 * Initiate a rekey with the remote peer.
 *
 * @param cls Closure (tunnel).
 * @param tc TaskContext.
 */
static void
rekey_tunnel (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MeshTunnel3 *t = cls;

  t->rekey_task = GNUNET_SCHEDULER_NO_TASK;

  if (NULL != tc && 0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;

  t->kx_ctx = GNUNET_new (struct MeshTunnelKXCtx);
  t->kx_ctx->challenge = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                                   UINT32_MAX);
  t->kx_ctx->d_key_old = t->d_key;
  send_ephemeral (t);
  if (MESH_TUNNEL3_READY == t->state)
  {
    send_ping (t);
    t->state = MESH_TUNNEL3_REKEY;
  }
  else if (MESH_TUNNEL3_WAITING == t->state)
  {
    t->state = MESH_TUNNEL3_KEY_SENT;
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Unexpected state %u\n", t->state);
  }

  t->rekey_task = GNUNET_SCHEDULER_add_delayed (REKEY_WAIT, &rekey_tunnel, t);
}


/**
 * Out ephemeral key has changed, create new session key on all tunnels.
 *
 * @param cls Closure (size of the hashmap).
 * @param key Current public key.
 * @param value Value in the hash map (tunnel).
 *
 * @return #GNUNET_YES, so we should continue to iterate,
 */
static int
rekey_iterator (void *cls,
                const struct GNUNET_PeerIdentity *key,
                void *value)
{
  struct MeshTunnel3 *t = value;
  struct GNUNET_TIME_Relative delay;
  long n = (long) cls;
  uint32_t r;

  if (GNUNET_SCHEDULER_NO_TASK != t->rekey_task)
    return GNUNET_YES;

  r = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, (uint32_t) n * 100);
  delay = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, r);
  t->rekey_task = GNUNET_SCHEDULER_add_delayed (delay, &rekey_tunnel, t);

  return GNUNET_YES;
}


/**
 * Create a new ephemeral key and key message, schedule next rekeying.
 *
 * @param cls Closure (unused).
 * @param tc TaskContext.
 */
static void
rekey (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TIME_Absolute time;
  long n;

  rekey_task = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;

  GNUNET_free_non_null (my_ephemeral_key);
  my_ephemeral_key = GNUNET_CRYPTO_ecdhe_key_create ();

  time = GNUNET_TIME_absolute_get ();
  kx_msg.creation_time = GNUNET_TIME_absolute_hton (time);
  time = GNUNET_TIME_absolute_add (time, rekey_period);
  time = GNUNET_TIME_absolute_add (time, GNUNET_TIME_UNIT_MINUTES);
  kx_msg.expiration_time = GNUNET_TIME_absolute_hton (time);
  GNUNET_CRYPTO_ecdhe_key_get_public (my_ephemeral_key, &kx_msg.ephemeral_key);

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_eddsa_sign (my_private_key,
                                           &kx_msg.purpose,
                                           &kx_msg.signature));

  n = (long) GNUNET_CONTAINER_multipeermap_size (tunnels);
  GNUNET_CONTAINER_multipeermap_iterate (tunnels, &rekey_iterator, (void *) n);

  rekey_task = GNUNET_SCHEDULER_add_delayed (rekey_period, &rekey, NULL);
}


/**
 * Demultiplex data per channel and call appropriate channel handler.
 *
 * @param t Tunnel on which the data came.
 * @param msg Data message.
 * @param fwd Is this message fwd? This only is meaningful in loopback channels.
 *            #GNUNET_YES if message is FWD on the respective channel (loopback)
 *            #GNUNET_NO if message is BCK on the respective channel (loopback)
 *            #GNUNET_SYSERR if message on a one-ended channel (remote)
 */
static void
handle_data (struct MeshTunnel3 *t,
             const struct GNUNET_MESH_Data *msg,
             int fwd)
{
  struct MeshChannel *ch;
  uint16_t type;
  size_t size;

  /* Check size */
  size = ntohs (msg->header.size);
  if (size <
      sizeof (struct GNUNET_MESH_Data) +
      sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    return;
  }
  type = ntohs (msg->header.type);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "got a %s message\n",
              GNUNET_MESH_DEBUG_M2S (type));
  LOG (GNUNET_ERROR_TYPE_DEBUG, " payload of type %s\n",
              GNUNET_MESH_DEBUG_M2S (ntohs (msg[1].header.type)));

  /* Check channel */
  ch = GMT_get_channel (t, ntohl (msg->chid));
  if (NULL == ch)
  {
    GNUNET_STATISTICS_update (stats, "# data on unknown channel",
                              1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "WARNING channel %u unknown\n",
         ntohl (msg->chid));
    return;
  }

  GMT_change_state (t, MESH_TUNNEL3_READY);
  GMCH_handle_data (ch, msg, fwd);
}


/**
 * Demultiplex data ACKs per channel and update appropriate channel buffer info.
 *
 * @param t Tunnel on which the DATA ACK came.
 * @param msg DATA ACK message.
 * @param fwd Is this message fwd? This only is meaningful in loopback channels.
 *            #GNUNET_YES if message is FWD on the respective channel (loopback)
 *            #GNUNET_NO if message is BCK on the respective channel (loopback)
 *            #GNUNET_SYSERR if message on a one-ended channel (remote)
 */
static void
handle_data_ack (struct MeshTunnel3 *t,
                 const struct GNUNET_MESH_DataACK *msg,
                 int fwd)
{
  struct MeshChannel *ch;
  size_t size;

  /* Check size */
  size = ntohs (msg->header.size);
  if (size != sizeof (struct GNUNET_MESH_DataACK))
  {
    GNUNET_break (0);
    return;
  }

  /* Check channel */
  ch = GMT_get_channel (t, ntohl (msg->chid));
  if (NULL == ch)
  {
    GNUNET_STATISTICS_update (stats, "# data ack on unknown channel",
                              1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "WARNING channel %u unknown\n",
         ntohl (msg->chid));
    return;
  }

  GMCH_handle_data_ack (ch, msg, fwd);
}


/**
 * Handle channel create.
 *
 * @param t Tunnel on which the data came.
 * @param msg Data message.
 */
static void
handle_ch_create (struct MeshTunnel3 *t,
                  const struct GNUNET_MESH_ChannelCreate *msg)
{
  struct MeshChannel *ch;
  size_t size;

  /* Check size */
  size = ntohs (msg->header.size);
  if (size != sizeof (struct GNUNET_MESH_ChannelCreate))
  {
    GNUNET_break (0);
    return;
  }

  /* Check channel */
  ch = GMT_get_channel (t, ntohl (msg->chid));
  if (NULL != ch && ! GMT_is_loopback (t))
  {
    /* Probably a retransmission, safe to ignore */
    LOG (GNUNET_ERROR_TYPE_DEBUG, "   already exists...\n");
  }
  else
  {
    ch = GMCH_handle_create (t, msg);
  }
  if (NULL != ch)
    GMT_add_channel (t, ch);
}



/**
 * Handle channel NACK.
 *
 * @param t Tunnel on which the data came.
 * @param msg Data message.
 */
static void
handle_ch_nack (struct MeshTunnel3 *t,
                const struct GNUNET_MESH_ChannelManage *msg)
{
  struct MeshChannel *ch;
  size_t size;

  /* Check size */
  size = ntohs (msg->header.size);
  if (size != sizeof (struct GNUNET_MESH_ChannelManage))
  {
    GNUNET_break (0);
    return;
  }

  /* Check channel */
  ch = GMT_get_channel (t, ntohl (msg->chid));
  if (NULL != ch && ! GMT_is_loopback (t))
  {
    GNUNET_STATISTICS_update (stats, "# channel NACK on unknown channel",
                              1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "WARNING channel %u unknown\n",
         ntohl (msg->chid));
    return;
  }

  GMCH_handle_nack (ch);
}


/**
 * Handle a CHANNEL ACK (SYNACK/ACK).
 *
 * @param t Tunnel on which the CHANNEL ACK came.
 * @param msg CHANNEL ACK message.
 * @param fwd Is this message fwd? This only is meaningful in loopback channels.
 *            #GNUNET_YES if message is FWD on the respective channel (loopback)
 *            #GNUNET_NO if message is BCK on the respective channel (loopback)
 *            #GNUNET_SYSERR if message on a one-ended channel (remote)
 */
static void
handle_ch_ack (struct MeshTunnel3 *t,
               const struct GNUNET_MESH_ChannelManage *msg,
               int fwd)
{
  struct MeshChannel *ch;
  size_t size;

  /* Check size */
  size = ntohs (msg->header.size);
  if (size != sizeof (struct GNUNET_MESH_ChannelManage))
  {
    GNUNET_break (0);
    return;
  }

  /* Check channel */
  ch = GMT_get_channel (t, ntohl (msg->chid));
  if (NULL == ch)
  {
    GNUNET_STATISTICS_update (stats, "# channel ack on unknown channel",
                              1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "WARNING channel %u unknown\n",
         ntohl (msg->chid));
    return;
  }

  GMCH_handle_ack (ch, msg, fwd);
}



/**
 * Handle a channel destruction message.
 *
 * @param t Tunnel on which the message came.
 * @param msg Channel destroy message.
 * @param fwd Is this message fwd? This only is meaningful in loopback channels.
 *            #GNUNET_YES if message is FWD on the respective channel (loopback)
 *            #GNUNET_NO if message is BCK on the respective channel (loopback)
 *            #GNUNET_SYSERR if message on a one-ended channel (remote)
 */
static void
handle_ch_destroy (struct MeshTunnel3 *t,
                   const struct GNUNET_MESH_ChannelManage *msg,
                   int fwd)
{
  struct MeshChannel *ch;
  size_t size;

  /* Check size */
  size = ntohs (msg->header.size);
  if (size != sizeof (struct GNUNET_MESH_ChannelManage))
  {
    GNUNET_break (0);
    return;
  }

  /* Check channel */
  ch = GMT_get_channel (t, ntohl (msg->chid));
  if (NULL == ch)
  {
    /* Probably a retransmission, safe to ignore */
    return;
  }

  GMCH_handle_destroy (ch, msg, fwd);
}


/**
 * The peer's ephemeral key has changed: update the symmetrical keys.
 *
 * @param t Tunnel this message came on.
 * @param msg Key eXchange message.
 */
static void
handle_ephemeral (struct MeshTunnel3 *t,
                  const struct GNUNET_MESH_KX_Ephemeral *msg)
{
  struct GNUNET_HashCode km;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  ephemeral key message\n");

  if (GNUNET_OK != check_ephemeral (t, msg))
  {
    GNUNET_break_op (0);
    return;
  }
  derive_key_material (&km, &msg->ephemeral_key);
  derive_symmertic (&t->e_key, &my_full_id, GMP_get_id (t->peer), &km);
  derive_symmertic (&t->d_key, GMP_get_id (t->peer), &my_full_id, &km);
  if (MESH_TUNNEL3_KEY_SENT == t->state)
  {
    send_ping (t);
    t->state = MESH_TUNNEL3_PING_SENT;
  }
}


/**
 * Peer wants to check our symmetrical keys by sending an encrypted challenge.
 * Answer with by retransmitting the challenge with the "opposite" key.
 *
 * @param t Tunnel this message came on.
 * @param msg Key eXchange Ping message.
 */
static void
handle_ping (struct MeshTunnel3 *t,
             const struct GNUNET_MESH_KX_Ping *msg)
{
  struct GNUNET_MESH_KX_Ping res;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  ping message\n");
  t_decrypt (t, &res.target, &msg->target, ping_encryption_size(), msg->iv);
  if (0 != memcmp (&my_full_id, &msg->target, sizeof (my_full_id)))
  {
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  at %s\n", GNUNET_i2s (&my_full_id));
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  for %s\n", GNUNET_i2s (&msg->target));
    return;
  }

  send_pong (t, res.iv);
}


/**
 * Peer has answer to our challenge.
 * If answer is successful, consider the key exchange finished and clean
 * up all related state.
 *
 * @param t Tunnel this message came on.
 * @param msg Key eXchange Pong message.
 */
static void
handle_pong (struct MeshTunnel3 *t,
             const struct GNUNET_MESH_KX_Pong *msg)
{
  uint32_t challenge;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "PONG received\n");
  if (GNUNET_SCHEDULER_NO_TASK == t->rekey_task)
  {
    GNUNET_break_op (0);
    return;
  }
  t_decrypt (t, &challenge, &msg->nonce, sizeof (uint32_t), msg->iv);

  if (challenge != t->kx_ctx->challenge)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Wrong PONG challenge: %u. Expected: %u.\n",
         challenge, t->kx_ctx->challenge);
    GNUNET_break_op (0);
    return;
  }
  GNUNET_SCHEDULER_cancel (t->rekey_task);
  t->rekey_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_free (t->kx_ctx);
  t->kx_ctx = NULL;
  t->state = MESH_TUNNEL3_READY;
  send_queued_data (t);
}


/**
 * Demultiplex by message type and call appropriate handler for a message
 * towards a channel of a local tunnel.
 *
 * @param t Tunnel this message came on.
 * @param msgh Message header.
 * @param fwd Is this message fwd? This only is meaningful in loopback channels.
 *            #GNUNET_YES if message is FWD on the respective channel (loopback)
 *            #GNUNET_NO if message is BCK on the respective channel (loopback)
 *            #GNUNET_SYSERR if message on a one-ended channel (remote)
 */
static void
handle_decrypted (struct MeshTunnel3 *t,
                  const struct GNUNET_MessageHeader *msgh,
                  int fwd)
{
  uint16_t type;

  type = ntohs (msgh->type);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Got a %s message!\n",
       GNUNET_MESH_DEBUG_M2S (type));

  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_MESH_DATA:
      /* Don't send hop ACK, wait for client to ACK */
      handle_data (t, (struct GNUNET_MESH_Data *) msgh, fwd);
      break;

    case GNUNET_MESSAGE_TYPE_MESH_DATA_ACK:
      handle_data_ack (t, (struct GNUNET_MESH_DataACK *) msgh, fwd);
      break;

    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_CREATE:
      handle_ch_create (t,
                        (struct GNUNET_MESH_ChannelCreate *) msgh);
      break;

    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_NACK:
      handle_ch_nack (t,
                      (struct GNUNET_MESH_ChannelManage *) msgh);
      break;

    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_ACK:
      handle_ch_ack (t,
                     (struct GNUNET_MESH_ChannelManage *) msgh,
                     fwd);
      break;

    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_DESTROY:
      handle_ch_destroy (t,
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

/******************************************************************************/
/********************************    API    ***********************************/
/******************************************************************************/

/**
 * Decrypt and demultiplex by message type. Call appropriate handler
 * for every message.
 *
 * @param t Tunnel this message came on.
 * @param msg Encrypted message.
 */
void
GMT_handle_encrypted (struct MeshTunnel3 *t,
                      const struct GNUNET_MESH_Encrypted *msg)
{
  size_t size = ntohs (msg->header.size);
  size_t payload_size = size - sizeof (struct GNUNET_MESH_Encrypted);
  size_t decrypted_size;
  char cbuf [payload_size];
  struct GNUNET_MessageHeader *msgh;
  unsigned int off;

  decrypted_size = t_decrypt (t, cbuf, &msg[1], payload_size, msg->iv);
  off = 0;
  while (off < decrypted_size)
  {
    msgh = (struct GNUNET_MessageHeader *) &cbuf[off];
    handle_decrypted (t, msgh, GNUNET_SYSERR);
    off += ntohs (msgh->size);
  }
}


/**
 * Demultiplex an encapsulated KX message by message type.
 *
 * @param t Tunnel on which the message came.
 * @param message Payload of KX message.
 */
void
GMT_handle_kx (struct MeshTunnel3 *t,
               const struct GNUNET_MessageHeader *message)
{
  uint16_t type;

  type = ntohs (message->type);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "kx message received\n", type);
  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_MESH_KX_EPHEMERAL:
      handle_ephemeral (t, (struct GNUNET_MESH_KX_Ephemeral *) message);
      break;

    case GNUNET_MESSAGE_TYPE_MESH_KX_PING:
      handle_ping (t, (struct GNUNET_MESH_KX_Ping *) message);
      break;

    case GNUNET_MESSAGE_TYPE_MESH_KX_PONG:
      handle_pong (t, (struct GNUNET_MESH_KX_Pong *) message);
      break;

    default:
      GNUNET_break_op (0);
      LOG (GNUNET_ERROR_TYPE_DEBUG, "kx message not known (%u)\n", type);
  }
}


/**
 * Initialize the tunnel subsystem.
 *
 * @param c Configuration handle.
 * @param key ECC private key, to derive all other keys and do crypto.
 */
void
GMT_init (const struct GNUNET_CONFIGURATION_Handle *c,
          const struct GNUNET_CRYPTO_EddsaPrivateKey *key)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "init\n");
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "MESH", "DEFAULT_TTL",
                                             &default_ttl))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_WARNING,
                               "MESH", "DEFAULT_TTL", "USING DEFAULT");
    default_ttl = 64;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (c, "MESH", "REKEY_PERIOD",
                                           &rekey_period))
  {
    rekey_period = GNUNET_TIME_UNIT_DAYS;
  }

  my_private_key = key;
  kx_msg.header.size = htons (sizeof (kx_msg));
  kx_msg.header.type = htons (GNUNET_MESSAGE_TYPE_MESH_KX_EPHEMERAL);
  kx_msg.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_MESH_KX);
  kx_msg.purpose.size = htonl (ephemeral_purpose_size ());
  kx_msg.origin_identity = my_full_id;
  rekey_task = GNUNET_SCHEDULER_add_now (&rekey, NULL);

  tunnels = GNUNET_CONTAINER_multipeermap_create (128, GNUNET_YES);
}


/**
 * Shut down the tunnel subsystem.
 */
void
GMT_shutdown (void)
{
  if (GNUNET_SCHEDULER_NO_TASK != rekey_task)
  {
    GNUNET_SCHEDULER_cancel (rekey_task);
    rekey_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_CONTAINER_multipeermap_destroy (tunnels);
}


/**
 * Create a tunnel.
 *
 * @param destination Peer this tunnel is towards.
 */
struct MeshTunnel3 *
GMT_new (struct MeshPeer *destination)
{
  struct MeshTunnel3 *t;

  t = GNUNET_new (struct MeshTunnel3);
  t->next_chid = 0;
  t->peer = destination;

  if (GNUNET_OK !=
      GNUNET_CONTAINER_multipeermap_put (tunnels, GMP_get_id (destination), t,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    GNUNET_break (0);
    GNUNET_free (t);
    return NULL;
  }
  return t;
}


/**
 * Change the tunnel state.
 *
 * @param t Tunnel whose state to change.
 * @param state New state.
 */
void
GMT_change_state (struct MeshTunnel3* t, enum MeshTunnel3State state)
{
  if (NULL == t)
    return;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "Tunnel %s state was %s\n",
              GMP_2s (t->peer),
              GMT_state2s (t->state));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
              "Tunnel %s state is now %s\n",
              GMP_2s (t->peer),
              GMT_state2s (state));
  if (myid != GMP_get_short_id (t->peer) &&
      MESH_TUNNEL3_WAITING == t->state && MESH_TUNNEL3_READY == state)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  triggered rekey\n");
    rekey_tunnel (t, NULL);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Tunnel %s state is now %s\n",
         GMP_2s (t->peer),
         GMT_state2s (t->state));
  }
  else
  {
    t->state = state;
  }
  if (MESH_TUNNEL3_READY == state && 3 <= GMT_count_connections (t))
  {
    GMP_stop_search (t->peer);
  }
}


/**
 * Add a connection to a tunnel.
 *
 * @param t Tunnel.
 * @param c Connection.
 */
void
GMT_add_connection (struct MeshTunnel3 *t, struct MeshConnection *c)
{
  struct MeshTConnection *aux;

  for (aux = t->connection_head; aux != NULL; aux = aux->next)
    if (aux->c == c)
      return;

  aux = GNUNET_new (struct MeshTConnection);
  aux->c = c;
  GNUNET_CONTAINER_DLL_insert_tail (t->connection_head, t->connection_tail, aux);
}


/**
 * Remove a connection from a tunnel.
 *
 * @param t Tunnel.
 * @param c Connection.
 */
void
GMT_remove_connection (struct MeshTunnel3 *t, struct MeshConnection *c)
{
  struct MeshTConnection *aux;

  for (aux = t->connection_head; aux != NULL; aux = aux->next)
    if (aux->c == c)
    {
      GNUNET_CONTAINER_DLL_remove (t->connection_head, t->connection_tail, aux);
      GNUNET_free (aux);
      return;
    }
}


/**
 * Add a channel to a tunnel.
 *
 * @param t Tunnel.
 * @param ch Channel.
 */
void
GMT_add_channel (struct MeshTunnel3 *t, struct MeshChannel *ch)
{
  struct MeshTChannel *aux;

  GNUNET_assert (NULL != ch);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Adding channel %p to tunnel %p\n", ch, t);

  for (aux = t->channel_head; aux != NULL; aux = aux->next)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  already there %p\n", aux->ch);
    if (aux->ch == ch)
      return;
  }

  aux = GNUNET_new (struct MeshTChannel);
  aux->ch = ch;
  LOG (GNUNET_ERROR_TYPE_DEBUG, " adding %p to %p\n", aux, t->channel_head);
  GNUNET_CONTAINER_DLL_insert_tail (t->channel_head, t->channel_tail, aux);
}


/**
 * Remove a channel from a tunnel.
 *
 * @param t Tunnel.
 * @param ch Channel.
 */
void
GMT_remove_channel (struct MeshTunnel3 *t, struct MeshChannel *ch)
{
  struct MeshTChannel *aux;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Removing channel %p from tunnel %p\n", ch, t);
  for (aux = t->channel_head; aux != NULL; aux = aux->next)
  {
    if (aux->ch == ch)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, " found! %s\n", GMCH_2s (ch));
      GNUNET_CONTAINER_DLL_remove (t->channel_head, t->channel_tail, aux);
      GNUNET_free (aux);
      return;
    }
  }
}


/**
 * Search for a channel by global ID.
 *
 * @param t Tunnel containing the channel.
 * @param chid Public channel number.
 *
 * @return channel handler, NULL if doesn't exist
 */
struct MeshChannel *
GMT_get_channel (struct MeshTunnel3 *t, MESH_ChannelNumber chid)
{
  struct MeshTChannel *iter;

  if (NULL == t)
    return NULL;

  for (iter = t->channel_head; NULL != iter; iter = iter->next)
  {
    if (GMCH_get_id (iter->ch) == chid)
      break;
  }

  return NULL == iter ? NULL : iter->ch;
}


/**
 * Tunnel is empty: destroy it.
 *
 * Notifies all connections about the destruction.
 *
 * @param t Tunnel to destroy.
 */
void
GMT_destroy_empty (struct MeshTunnel3 *t)
{
  struct MeshTConnection *iter;

  for (iter = t->connection_head; NULL != iter; iter = iter->next)
  {
    GMC_send_destroy (iter->c);
  }

  t->destroy = GNUNET_YES;
}


/**
 * Destroy tunnel if empty (no more channels).
 *
 * @param t Tunnel to destroy if empty.
 */
void
GMT_destroy_if_empty (struct MeshTunnel3 *t)
{
  if (1 < GMT_count_channels (t))
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
GMT_destroy (struct MeshTunnel3 *t)
{
  struct MeshTConnection *iter;
  struct MeshTConnection *next;

  if (NULL == t)
    return;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "destroying tunnel %s\n", GMP_2s (t->peer));

//   if (GNUNET_YES != GNUNET_CONTAINER_multihashmap_remove (tunnels, &t->id, t))
//     GNUNET_break (0);

  for (iter = t->connection_head; NULL != iter; iter = next)
  {
    next = iter->next;
    GMC_destroy (iter->c);
  }

  GNUNET_STATISTICS_update (stats, "# tunnels", -1, GNUNET_NO);
  GMP_set_tunnel (t->peer, NULL);

  if (GNUNET_SCHEDULER_NO_TASK != t->rekey_task)
    GNUNET_SCHEDULER_cancel (t->rekey_task);

  GNUNET_free (t);
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
GMT_use_path (struct MeshTunnel3 *t, struct MeshPeerPath *p)
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
    if (p->peers[own_pos] == myid)
      break;
  }
  if (own_pos > p->length - 1)
  {
    GNUNET_break (0);
    return NULL;
  }

  GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_NONCE, &cid);
  c = GMC_new (&cid, t, p, own_pos);
  GMT_add_connection (t, c);
  return c;
}


/**
 * Count established (ready) connections of a tunnel.
 *
 * @param t Tunnel on which to count.
 *
 * @return Number of connections.
 */
unsigned int
GMT_count_connections (struct MeshTunnel3 *t)
{
  struct MeshTConnection *iter;
  unsigned int count;

  for (count = 0, iter = t->connection_head;
       NULL != iter;
       iter = iter->next, count++);

  return count;
}

/**
 * Count channels of a tunnel.
 *
 * @param t Tunnel on which to count.
 *
 * @return Number of channels.
 */
unsigned int
GMT_count_channels (struct MeshTunnel3 *t)
{
  struct MeshTChannel *iter;
  unsigned int count;

  for (count = 0, iter = t->channel_head;
       NULL != iter;
       iter = iter->next, count++) /* skip */;

  return count;
}


/**
 * Get the state of a tunnel.
 *
 * @param t Tunnel.
 *
 * @return Tunnel's state.
 */
enum MeshTunnel3State
GMT_get_state (struct MeshTunnel3 *t)
{
  if (NULL == t)
  {
    GNUNET_break (0);
    return (enum MeshTunnel3State) -1;
  }
  return t->state;
}


/**
 * Get the maximum buffer space for a tunnel towards a local client.
 *
 * @param t Tunnel.
 *
 * @return Biggest buffer space offered by any channel in the tunnel.
 */
unsigned int
GMT_get_channels_buffer (struct MeshTunnel3 *t)
{
  struct MeshTChannel *iter;
  unsigned int buffer;
  unsigned int ch_buf;

  if (NULL == t->channel_head)
  {
    /* Probably getting buffer for a channel create/handshake. */
    return 64;
  }

  buffer = 0;
  for (iter = t->channel_head; NULL != iter; iter = iter->next)
  {
    ch_buf = get_channel_buffer (iter);
    if (ch_buf > buffer)
      buffer = ch_buf;
  }
  return buffer;
}


/**
 * Get the total buffer space for a tunnel for P2P traffic.
 *
 * @param t Tunnel.
 *
 * @return Buffer space offered by all connections in the tunnel.
 */
unsigned int
GMT_get_connections_buffer (struct MeshTunnel3 *t)
{
  struct MeshTConnection *iter;
  unsigned int buffer;

  iter = t->connection_head;
  buffer = 0;
  while (NULL != iter)
  {
    if (GMC_get_state (iter->c) != MESH_CONNECTION_READY)
    {
      iter = iter->next;
      continue;
    }

    buffer += get_connection_buffer (iter);
    iter = iter->next;
  }

  return buffer;
}


/**
 * Get the tunnel's destination.
 *
 * @param t Tunnel.
 *
 * @return ID of the destination peer.
 */
const struct GNUNET_PeerIdentity *
GMT_get_destination (struct MeshTunnel3 *t)
{
  return GMP_get_id (t->peer);
}


/**
 * Get the tunnel's next free global channel ID.
 *
 * @param t Tunnel.
 *
 * @return GID of a channel free to use.
 */
MESH_ChannelNumber
GMT_get_next_chid (struct MeshTunnel3 *t)
{
  MESH_ChannelNumber chid;

  while (NULL != GMT_get_channel (t, t->next_chid))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Channel %u exists...\n", t->next_chid);
    t->next_chid = (t->next_chid + 1) & ~GNUNET_MESH_LOCAL_CHANNEL_ID_CLI;
  }
  chid = t->next_chid;
  t->next_chid = (t->next_chid + 1) & ~GNUNET_MESH_LOCAL_CHANNEL_ID_CLI;

  return chid;
}


/**
 * Send ACK on one or more channels due to buffer in connections.
 *
 * @param t Channel which has some free buffer space.
 */
void
GMT_unchoke_channels (struct MeshTunnel3 *t)
{
  struct MeshTChannel *iter;
  unsigned int buffer;
  unsigned int channels = GMT_count_channels (t);
  unsigned int choked_n;
  struct MeshChannel *choked[channels];

  LOG (GNUNET_ERROR_TYPE_DEBUG, "GMT_unchoke_channels on %s\n", GMT_2s (t));
  LOG (GNUNET_ERROR_TYPE_DEBUG, " head: %p\n", t->channel_head);
  if (NULL != t->channel_head)
    LOG (GNUNET_ERROR_TYPE_DEBUG, " head ch: %p\n", t->channel_head->ch);

  if (NULL == t)
  {
    GNUNET_break (0);
    return;
  }

  /* Get buffer space */
  buffer = GMT_get_connections_buffer (t);
  if (0 == buffer)
  {
    return;
  }

  /* Count and remember choked channels */
  choked_n = 0;
  for (iter = t->channel_head; NULL != iter; iter = iter->next)
  {
    if (GNUNET_NO == get_channel_allowed (iter))
    {
      choked[choked_n++] = iter->ch;
    }
  }

  /* Unchoke random channels */
  while (0 < buffer && 0 < choked_n)
  {
    unsigned int r = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                               choked_n);
    GMCH_allow_client (choked[r], GMCH_is_origin (choked[r], GNUNET_YES));
    choked_n--;
    buffer--;
    choked[r] = choked[choked_n];
  }
}


/**
 * Send ACK on one or more connections due to buffer space to the client.
 *
 * Iterates all connections of the tunnel and sends ACKs appropriately.
 *
 * @param t Tunnel.
 */
void
GMT_send_connection_acks (struct MeshTunnel3 *t)
{
  struct MeshTConnection *iter;
  uint32_t allowed;
  uint32_t to_allow;
  uint32_t allow_per_connection;
  unsigned int cs;
  unsigned int buffer;

  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Tunnel send connection ACKs on %s\n",
       GMT_2s (t));

  if (NULL == t)
  {
    GNUNET_break (0);
    return;
  }

  buffer = GMT_get_channels_buffer (t);

  /* Count connections, how many messages are already allowed */
  cs = GMT_count_connections (t);
  for (allowed = 0, iter = t->connection_head; NULL != iter; iter = iter->next)
  {
    allowed += get_connection_allowed (iter);
  }

  /* Make sure there is no overflow */
  if (allowed > buffer)
  {
    return;
  }

  /* Authorize connections to send more data */
  to_allow = buffer; /* - allowed; */

  for (iter = t->connection_head; NULL != iter && to_allow > 0; iter = iter->next)
  {
    allow_per_connection = to_allow/cs;
    to_allow -= allow_per_connection;
    cs--;
    if (get_connection_allowed (iter) > 64 / 3)
    {
      continue;
    }
    GMC_allow (iter->c, buffer, GMC_is_origin (iter->c, GNUNET_YES));
  }

  GNUNET_break (to_allow == 0);
}


/**
 * Sends an already built message on a tunnel, encrypting it and
 * choosing the best connection.
 *
 * @param message Message to send. Function modifies it.
 * @param t Tunnel on which this message is transmitted.
 * @param ch Channel on which this message is transmitted.
 * @param fwd Is this a fwd message on @c ch?
 */
void
GMT_send_prebuilt_message (const struct GNUNET_MessageHeader *message,
                           struct MeshTunnel3 *t,
                           struct MeshChannel *ch,
                           int fwd)
{
  struct MeshConnection *c;
  struct GNUNET_MESH_Encrypted *msg;
  size_t size = ntohs (message->size);
  size_t encrypted_size;
  char cbuf[sizeof (struct GNUNET_MESH_Encrypted) + size];
  uint32_t iv;
  uint16_t type;

  if (MESH_TUNNEL3_READY != t->state)
  {
    queue_data (t, ch, message);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "GMT Send on Tunnel %s\n", GMT_2s (t));

  if (GMT_is_loopback (t))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  loopback!\n");
    handle_decrypted (t, message, fwd);
    return;
  }

  iv = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX);
  msg = (struct GNUNET_MESH_Encrypted *) cbuf;
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_MESH_ENCRYPTED);
  msg->iv = iv;
  encrypted_size = t_encrypt (t, &msg[1], message, size, iv);
  msg->header.size = htons (sizeof (struct GNUNET_MESH_Encrypted) + encrypted_size);
  c = tunnel_get_connection (t);
  if (NULL == c)
  {
    GNUNET_break (GNUNET_YES == t->destroy);
    return;
  }
  type = ntohs (message->type);
  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_MESH_DATA:
    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_CREATE:
    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_DESTROY:
    case GNUNET_MESSAGE_TYPE_MESH_CHANNEL_ACK:
      msg->cid = *GMC_get_id (c);
      msg->ttl = htonl (default_ttl);
      break;
    default:
      LOG (GNUNET_ERROR_TYPE_DEBUG, "unkown type %s\n",
           GNUNET_MESH_DEBUG_M2S (type));
      GNUNET_break (0);
  }

  fwd = GMC_is_origin (c, GNUNET_YES);
  GMC_send_prebuilt_message (&msg->header, c, fwd);
}

/**
 * Is the tunnel directed towards the local peer?
 *
 * @param t Tunnel.
 *
 * @return #GNUNET_YES if it is loopback.
 */
int
GMT_is_loopback (const struct MeshTunnel3 *t)
{
  return (myid == GMP_get_short_id (t->peer));
}


/**
 * Is the tunnel using this path already?
 *
 * @param t Tunnel.
 * @param p Path.
 *
 * @return #GNUNET_YES a connection uses this path.
 */
int
GMT_is_path_used (const struct MeshTunnel3 *t, const struct MeshPeerPath *p)
{
  struct MeshTConnection *iter;

  for (iter = t->connection_head; NULL != iter; iter = iter->next)
    if (GMC_get_path (iter->c) == p)
      return GNUNET_YES;

  return GNUNET_NO;
}


/**
 * Get a cost of a path for a tunnel considering existing connections.
 *
 * @param t Tunnel.
 * @param path Candidate path.
 *
 * @return Cost of the path (path length + number of overlapping nodes)
 */
unsigned int
GMT_get_path_cost (const struct MeshTunnel3 *t,
                   const struct MeshPeerPath *path)
{
  struct MeshTConnection *iter;
  unsigned int overlap;
  unsigned int i;
  unsigned int j;

  if (NULL == path)
    return 0;

  overlap = 0;
  GNUNET_assert (NULL != t);

  for (i = 0; i < path->length; i++)
  {
    for (iter = t->connection_head; NULL != iter; iter = iter->next)
    {
      for (j = 0; j < GMC_get_path (iter->c)->length; j++)
      {
        if (path->peers[i] == GMC_get_path (iter->c)->peers[j])
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
 * Get the static string for the peer this tunnel is directed.
 *
 * @param t Tunnel.
 *
 * @return Static string the destination peer's ID.
 */
const char *
GMT_2s (const struct MeshTunnel3 *t)
{
  if (NULL == t)
    return "(NULL)";

  return GMP_2s (t->peer);
}