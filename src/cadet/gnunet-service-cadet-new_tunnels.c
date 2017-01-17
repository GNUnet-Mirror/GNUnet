
/*
     This file is part of GNUnet.
     Copyright (C) 2013, 2017 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file cadet/gnunet-service-cadet-new_tunnels.c
 * @brief Information we track per tunnel.
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 *
 * FIXME:
 * - when managing connections, distinguish those that
 *   have (recently) had traffic from those that were
 *   never ready (or not recently)
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_signatures.h"
#include "cadet_protocol.h"
#include "cadet_path.h"
#include "gnunet-service-cadet-new.h"
#include "gnunet-service-cadet-new_channel.h"
#include "gnunet-service-cadet-new_connection.h"
#include "gnunet-service-cadet-new_tunnels.h"
#include "gnunet-service-cadet-new_peer.h"
#include "gnunet-service-cadet-new_paths.h"


/**
 * How long do we wait until tearing down an idle tunnel?
 */
#define IDLE_DESTROY_DELAY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 90)


/**
 * Struct to old keys for skipped messages while advancing the Axolotl ratchet.
 */
struct CadetTunnelSkippedKey
{
  /**
   * DLL next.
   */
  struct CadetTunnelSkippedKey *next;

  /**
   * DLL prev.
   */
  struct CadetTunnelSkippedKey *prev;

  /**
   * When was this key stored (for timeout).
   */
  struct GNUNET_TIME_Absolute timestamp;

  /**
   * Header key.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey HK;

  /**
   * Message key.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey MK;

  /**
   * Key number for a given HK.
   */
  unsigned int Kn;
};


/**
 * Axolotl data, according to https://github.com/trevp/axolotl/wiki .
 */
struct CadetTunnelAxolotl
{
  /**
   * A (double linked) list of stored message keys and associated header keys
   * for "skipped" messages, i.e. messages that have not been
   * received despite the reception of more recent messages, (head).
   */
  struct CadetTunnelSkippedKey *skipped_head;

  /**
   * Skipped messages' keys DLL, tail.
   */
  struct CadetTunnelSkippedKey *skipped_tail;

  /**
   * 32-byte root key which gets updated by DH ratchet.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey RK;

  /**
   * 32-byte header key (send).
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey HKs;

  /**
   * 32-byte header key (recv)
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey HKr;

  /**
   * 32-byte next header key (send).
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey NHKs;

  /**
   * 32-byte next header key (recv).
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey NHKr;

  /**
   * 32-byte chain keys (used for forward-secrecy updating, send).
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey CKs;

  /**
   * 32-byte chain keys (used for forward-secrecy updating, recv).
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey CKr;

  /**
   * ECDH for key exchange (A0 / B0).
   */
  struct GNUNET_CRYPTO_EcdhePrivateKey *kx_0;

  /**
   * ECDH Ratchet key (send).
   */
  struct GNUNET_CRYPTO_EcdhePrivateKey *DHRs;

  /**
   * ECDH Ratchet key (recv).
   */
  struct GNUNET_CRYPTO_EcdhePublicKey DHRr;

  /**
   * When does this ratchet expire and a new one is triggered.
   */
  struct GNUNET_TIME_Absolute ratchet_expiration;

  /**
   * Number of elements in @a skipped_head <-> @a skipped_tail.
   */
  unsigned int skipped;

  /**
   * Message number (reset to 0 with each new ratchet, next message to send).
   */
  uint32_t Ns;

  /**
   * Message number (reset to 0 with each new ratchet, next message to recv).
   */
  uint32_t Nr;

  /**
   * Previous message numbers (# of msgs sent under prev ratchet)
   */
  uint32_t PNs;

  /**
   * True (#GNUNET_YES) if we have to send a new ratchet key in next msg.
   */
  int ratchet_flag;

  /**
   * Number of messages recieved since our last ratchet advance.
   * - If this counter = 0, we cannot send a new ratchet key in next msg.
   * - If this counter > 0, we can (but don't yet have to) send a new key.
   */
  unsigned int ratchet_allowed;

  /**
   * Number of messages recieved since our last ratchet advance.
   * - If this counter = 0, we cannot send a new ratchet key in next msg.
   * - If this counter > 0, we can (but don't yet have to) send a new key.
   */
  unsigned int ratchet_counter;

};


/**
 * Entry in list of connections used by tunnel, with metadata.
 */
struct CadetTConnection
{
  /**
   * Next in DLL.
   */
  struct CadetTConnection *next;

  /**
   * Prev in DLL.
   */
  struct CadetTConnection *prev;

  /**
   * Connection handle.
   */
  struct CadetConnection *cc;

  /**
   * Tunnel this connection belongs to.
   */
  struct CadetTunnel *t;

  /**
   * Creation time, to keep oldest connection alive.
   */
  struct GNUNET_TIME_Absolute created;

  /**
   * Connection throughput, to keep fastest connection alive.
   */
  uint32_t throughput;
};


/**
 * Struct used to save messages in a non-ready tunnel to send once connected.
 */
struct CadetTunnelQueueEntry
{
  /**
   * We are entries in a DLL
   */
  struct CadetTunnelQueueEntry *next;

  /**
   * We are entries in a DLL
   */
  struct CadetTunnelQueueEntry *prev;

  /**
   * Tunnel these messages belong in.
   */
  struct CadetTunnel *t;

  /**
   * Continuation to call once sent (on the channel layer).
   */
  GNUNET_SCHEDULER_TaskCallback cont;

  /**
   * Closure for @c cont.
   */
  void *cont_cls;

  /**
   * Envelope of message to send follows.
   */
  struct GNUNET_MQ_Envelope *env;
};


/**
 * Struct containing all information regarding a tunnel to a peer.
 */
struct CadetTunnel
{
  /**
   * Destination of the tunnel.
   */
  struct CadetPeer *destination;

  /**
   * Peer's ephemeral key, to recreate @c e_key and @c d_key when own
   * ephemeral key changes.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey peers_ephemeral_key;

  /**
   * Encryption ("our") key. It is only "confirmed" if kx_ctx is NULL.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey e_key;

  /**
   * Decryption ("their") key. It is only "confirmed" if kx_ctx is NULL.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey d_key;

  /**
   * Axolotl info.
   */
  struct CadetTunnelAxolotl ax;

  /**
   * State of the tunnel connectivity.
   */
  enum CadetTunnelCState cstate;

  /**
   * State of the tunnel encryption.
   */
  enum CadetTunnelEState estate;

  /**
   * Task to start the rekey process.
   */
  struct GNUNET_SCHEDULER_Task *rekey_task;

  /**
   * DLL of connections that are actively used to reach the destination peer.
   */
  struct CadetTConnection *connection_head;

  /**
   * DLL of connections that are actively used to reach the destination peer.
   */
  struct CadetTConnection *connection_tail;

  /**
   * Channels inside this tunnel. Maps
   * `struct GCT_ChannelTunnelNumber` to a `struct CadetChannel`.
   */
  struct GNUNET_CONTAINER_MultiHashMap32 *channels;

  /**
   * Channel ID for the next created channel in this tunnel.
   */
  struct GCT_ChannelTunnelNumber next_chid;

  /**
   * Queued messages, to transmit once tunnel gets connected.
   */
  struct CadetTunnelQueueEntry *tq_head;

  /**
   * Queued messages, to transmit once tunnel gets connected.
   */
  struct CadetTunnelQueueEntry *tq_tail;

  /**
   * Task scheduled if there are no more channels using the tunnel.
   */
  struct GNUNET_SCHEDULER_Task *destroy_task;

  /**
   * Task to trim connections if too many are present.
   */
  struct GNUNET_SCHEDULER_Task *maintain_connections_task;

  /**
   * Ephemeral message in the queue (to avoid queueing more than one).
   */
  struct CadetConnectionQueue *ephm_hKILL;

  /**
   * Pong message in the queue.
   */
  struct CadetConnectionQueue *pong_hKILL;

  /**
   * Number of connections in the @e connection_head DLL.
   */
  unsigned int num_connections;

  /**
   * Number of entries in the @e tq_head DLL.
   */
  unsigned int tq_len;
};


/**
 * Get the static string for the peer this tunnel is directed.
 *
 * @param t Tunnel.
 *
 * @return Static string the destination peer's ID.
 */
const char *
GCT_2s (const struct CadetTunnel *t)
{
  static char buf[64];

  if (NULL == t)
    return "T(NULL)";

  GNUNET_snprintf (buf,
                   sizeof (buf),
                   "T(%s)",
                   GCP_2s (t->destination));
  return buf;
}


/**
 * Return the peer to which this tunnel goes.
 *
 * @param t a tunnel
 * @return the destination of the tunnel
 */
struct CadetPeer *
GCT_get_destination (struct CadetTunnel *t)
{
  return t->destination;
}


/**
 * Count channels of a tunnel.
 *
 * @param t Tunnel on which to count.
 *
 * @return Number of channels.
 */
unsigned int
GCT_count_channels (struct CadetTunnel *t)
{
  return GNUNET_CONTAINER_multihashmap32_size (t->channels);
}


/**
 * Count all created connections of a tunnel. Not necessarily ready connections!
 *
 * @param t Tunnel on which to count.
 *
 * @return Number of connections created, either being established or ready.
 */
unsigned int
GCT_count_any_connections (struct CadetTunnel *t)
{
  return t->num_connections;
}


/**
 * Get the connectivity state of a tunnel.
 *
 * @param t Tunnel.
 *
 * @return Tunnel's connectivity state.
 */
enum CadetTunnelCState
GCT_get_cstate (struct CadetTunnel *t)
{
  return t->cstate;
}


/**
 * Get the encryption state of a tunnel.
 *
 * @param t Tunnel.
 *
 * @return Tunnel's encryption state.
 */
enum CadetTunnelEState
GCT_get_estate (struct CadetTunnel *t)
{
  return t->estate;
}


/**
 * Add a channel to a tunnel.
 *
 * @param t Tunnel.
 * @param ch Channel
 * @return unique number identifying @a ch within @a t
 */
struct GCT_ChannelTunnelNumber
GCT_add_channel (struct CadetTunnel *t,
                 struct CadetChannel *ch)
{
  struct GCT_ChannelTunnelNumber ret;
  uint32_t chid;

  chid = ntohl (t->next_chid.channel_in_tunnel);
  while (NULL !=
         GNUNET_CONTAINER_multihashmap32_get (t->channels,
                                              chid))
    chid++;
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap32_put (t->channels,
                                                      chid,
                                                      ch,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  t->next_chid.channel_in_tunnel = htonl (chid + 1);
  ret.channel_in_tunnel = htonl (chid);
  return ret;
}


/**
 * This tunnel is no longer used, destroy it.
 *
 * @param cls the idle tunnel
 */
static void
destroy_tunnel (void *cls)
{
  struct CadetTunnel *t = cls;
  struct CadetTConnection *ct;
  struct CadetTunnelQueueEntry *tqe;

  t->destroy_task = NULL;
  GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap32_size (t->channels));
  while (NULL != (ct = t->connection_head))
  {
    GNUNET_assert (ct->t == t);
    GNUNET_CONTAINER_DLL_remove (t->connection_head,
                                 t->connection_tail,
                                 ct);
    GCC_destroy (ct->cc);
    GNUNET_free (ct);
  }
  while (NULL != (tqe = t->tq_head))
  {
    GNUNET_CONTAINER_DLL_remove (t->tq_head,
                                 t->tq_tail,
                                 tqe);
    GNUNET_MQ_discard (tqe->env);
    GNUNET_free (tqe);
  }
  GCP_drop_tunnel (t->destination,
                   t);
  GNUNET_CONTAINER_multihashmap32_destroy (t->channels);
  if (NULL != t->maintain_connections_task)
  {
    GNUNET_SCHEDULER_cancel (t->maintain_connections_task);
    t->maintain_connections_task = NULL;
  }
  GNUNET_free (t);
}


/**
 * A connection is ready for transmission.  Looks at our message queue
 * and if there is a message, sends it out via the connection.
 *
 * @param cls the `struct CadetTConnection` that is ready
 */
static void
connection_ready_cb (void *cls)
{
  struct CadetTConnection *ct = cls;
  struct CadetTunnel *t = ct->t;
  struct CadetTunnelQueueEntry *tq = t->tq_head;

  if (NULL == tq)
    return; /* no messages pending right now */

  /* ready to send message 'tq' on tunnel 'ct' */
  GNUNET_assert (t == tq->t);
  GNUNET_CONTAINER_DLL_remove (t->tq_head,
                               t->tq_tail,
                               tq);
  GCC_transmit (ct->cc,
                tq->env);
  tq->cont (tq->cont_cls);
  GNUNET_free (tq);
}


/**
 * Called when either we have a new connection, or a new message in the
 * queue, or some existing connection has transmission capacity.  Looks
 * at our message queue and if there is a message, picks a connection
 * to send it on.
 *
 * @param t tunnel to process messages on
 */
static void
trigger_transmissions (struct CadetTunnel *t)
{
  struct CadetTConnection *ct;

  if (NULL == t->tq_head)
    return; /* no messages pending right now */
  for (ct = t->connection_head;
       NULL != ct;
       ct = ct->next)
    if (GNUNET_YES == GCC_is_ready (ct->cc))
      break;
  if (NULL == ct)
    return; /* no connections ready */
  connection_ready_cb (ct);
}


/**
 * Function called to maintain the connections underlying our tunnel.
 * Tries to maintain (incl. tear down) connections for the tunnel, and
 * if there is a significant change, may trigger transmissions.
 *
 * Basically, needs to check if there are connections that perform
 * badly, and if so eventually kill them and trigger a replacement.
 * The strategy is to open one more connection than
 * #DESIRED_CONNECTIONS_PER_TUNNEL, and then periodically kick out the
 * least-performing one, and then inquire for new ones.
 *
 * @param cls the `struct CadetTunnel`
 */
static void
maintain_connections_cb (void *cls)
{
  struct CadetTunnel *t = cls;

  GNUNET_break (0); // FIXME: implement!
}


/**
 * Consider using the path @a p for the tunnel @a t.
 * The tunnel destination is at offset @a off in path @a p.
 *
 * @param cls our tunnel
 * @param path a path to our destination
 * @param off offset of the destination on path @a path
 * @return #GNUNET_YES (should keep iterating)
 */
static int
consider_path_cb (void *cls,
                  struct CadetPeerPath *path,
                  unsigned int off)
{
  struct CadetTunnel *t = cls;
  unsigned int min_length = UINT_MAX;
  GNUNET_CONTAINER_HeapCostType max_desire = 0;
  struct CadetTConnection *ct;

  /* Check if we care about the new path. */
  for (ct = t->connection_head;
       NULL != ct;
       ct = ct->next)
  {
    struct CadetPeerPath *ps;

    ps = GCC_get_path (ct->cc);
    if (ps == path)
      return GNUNET_YES; /* duplicate */
    min_length = GNUNET_MIN (min_length,
                             GCPP_get_length (ps));
    max_desire = GNUNET_MAX (max_desire,
                             GCPP_get_desirability (ps));
  }

  /* FIXME: not sure we should really just count
     'num_connections' here, as they may all have
     consistently failed to connect. */

  /* We iterate by increasing path length; if we have enough paths and
     this one is more than twice as long than what we are currently
     using, then ignore all of these super-long ones! */
  if ( (t->num_connections > DESIRED_CONNECTIONS_PER_TUNNEL) &&
       (min_length * 2 < off) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Ignoring paths of length %u, they are way too long.\n",
                min_length * 2);
    return GNUNET_NO;
  }
  /* If we have enough paths and this one looks no better, ignore it. */
  if ( (t->num_connections >= DESIRED_CONNECTIONS_PER_TUNNEL) &&
       (min_length < GCPP_get_length (path)) &&
       (max_desire > GCPP_get_desirability (path)) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Ignoring path (%u/%llu) to %s, got something better already.\n",
                GCPP_get_length (path),
                (unsigned long long) GCPP_get_desirability (path),
                GCP_2s (t->destination));
    return GNUNET_YES;
  }

  /* Path is interesting (better by some metric, or we don't have
     enough paths yet). */
  ct = GNUNET_new (struct CadetTConnection);
  ct->created = GNUNET_TIME_absolute_get ();
  ct->t = t;
  ct->cc = GCC_create (t->destination,
                       path,
                       &connection_ready_cb,
                       t);
  /* FIXME: schedule job to kill connection (and path?)  if it takes
     too long to get ready! (And track performance data on how long
     other connections took with the tunnel!)
     => Note: to be done within 'connection'-logic! */
  GNUNET_CONTAINER_DLL_insert (t->connection_head,
                               t->connection_tail,
                               ct);
  t->num_connections++;
  return GNUNET_YES;
}


/**
 * Consider using the path @a p for the tunnel @a t.
 * The tunnel destination is at offset @a off in path @a p.
 *
 * @param cls our tunnel
 * @param path a path to our destination
 * @param off offset of the destination on path @a path
 */
void
GCT_consider_path (struct CadetTunnel *t,
                   struct CadetPeerPath *p,
                   unsigned int off)
{
  (void) consider_path_cb (t,
                           p,
                           off);
}


/**
 * Create a tunnel to @a destionation.  Must only be called
 * from within #GCP_get_tunnel().
 *
 * @param destination where to create the tunnel to
 * @return new tunnel to @a destination
 */
struct CadetTunnel *
GCT_create_tunnel (struct CadetPeer *destination)
{
  struct CadetTunnel *t;

  t = GNUNET_new (struct CadetTunnel);
  t->destination = destination;
  t->channels = GNUNET_CONTAINER_multihashmap32_create (8);
  (void) GCP_iterate_paths (destination,
                            &consider_path_cb,
                            t);
  t->maintain_connections_task
    = GNUNET_SCHEDULER_add_now (&maintain_connections_cb,
                                t);
  return t;
}


/**
 * Remove a channel from a tunnel.
 *
 * @param t Tunnel.
 * @param ch Channel
 * @param gid unique number identifying @a ch within @a t
 */
void
GCT_remove_channel (struct CadetTunnel *t,
                    struct CadetChannel *ch,
                    struct GCT_ChannelTunnelNumber gid)
{
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap32_remove (t->channels,
                                                         ntohl (gid.channel_in_tunnel),
                                                         ch));
  if (0 ==
      GNUNET_CONTAINER_multihashmap32_size (t->channels))
  {
    t->destroy_task = GNUNET_SCHEDULER_add_delayed (IDLE_DESTROY_DELAY,
                                                    &destroy_tunnel,
                                                    t);
  }
}


/**
 * Sends an already built message on a tunnel, encrypting it and
 * choosing the best connection if not provided.
 *
 * @param message Message to send. Function modifies it.
 * @param t Tunnel on which this message is transmitted.
 * @param cont Continuation to call once message is really sent.
 * @param cont_cls Closure for @c cont.
 * @return Handle to cancel message. NULL if @c cont is NULL.
 */
struct CadetTunnelQueueEntry *
GCT_send (struct CadetTunnel *t,
          const struct GNUNET_MessageHeader *message,
          GNUNET_SCHEDULER_TaskCallback cont,
          void *cont_cls)
{
  struct CadetTunnelQueueEntry *q;
  uint16_t payload_size;

  payload_size = ntohs (message->size);

  q = GNUNET_malloc (sizeof (*q) +
                     payload_size);
  /* FIXME: encrypt 'message' to end of 'q' */
  q->t = t;
  q->cont = cont;
  q->cont_cls = cont_cls;
  GNUNET_CONTAINER_DLL_insert_tail (t->tq_head,
                                    t->tq_tail,
                                    q);
  /* FIXME: what about KX being ready? */
  trigger_transmissions (t);
  return q;
}


/**
 * Cancel a previously sent message while it's in the queue.
 *
 * ONLY can be called before the continuation given to the send
 * function is called. Once the continuation is called, the message is
 * no longer in the queue!
 *
 * @param q Handle to the queue entry to cancel.
 */
void
GCT_send_cancel (struct CadetTunnelQueueEntry *q)
{
  struct CadetTunnel *t = q->t;

  GNUNET_CONTAINER_DLL_remove (t->tq_head,
                               t->tq_tail,
                               q);
  GNUNET_free (q);
}


/**
 * Iterate over all connections of a tunnel.
 *
 * @param t Tunnel whose connections to iterate.
 * @param iter Iterator.
 * @param iter_cls Closure for @c iter.
 */
void
GCT_iterate_connections (struct CadetTunnel *t,
                         GCT_ConnectionIterator iter,
                         void *iter_cls)
{
  for (struct CadetTConnection *ct = t->connection_head;
       NULL != ct;
       ct = ct->next)
    iter (iter_cls,
          ct->cc);
}


/**
 * Closure for #iterate_channels_cb.
 */
struct ChanIterCls
{
  /**
   * Function to call.
   */
  GCT_ChannelIterator iter;

  /**
   * Closure for @e iter.
   */
  void *iter_cls;
};


/**
 * Helper function for #GCT_iterate_channels.
 *
 * @param cls the `struct ChanIterCls`
 * @param key unused
 * @param value a `struct CadetChannel`
 * @return #GNUNET_OK
 */
static int
iterate_channels_cb (void *cls,
                     uint32_t key,
                     void *value)
{
  struct ChanIterCls *ctx = cls;
  struct CadetChannel *ch = value;

  ctx->iter (ctx->iter_cls,
             ch);
  return GNUNET_OK;
}


/**
 * Iterate over all channels of a tunnel.
 *
 * @param t Tunnel whose channels to iterate.
 * @param iter Iterator.
 * @param iter_cls Closure for @c iter.
 */
void
GCT_iterate_channels (struct CadetTunnel *t,
                      GCT_ChannelIterator iter,
                      void *iter_cls)
{
  struct ChanIterCls ctx;

  ctx.iter = iter;
  ctx.iter_cls = iter_cls;
  GNUNET_CONTAINER_multihashmap32_iterate (t->channels,
                                           &iterate_channels_cb,
                                           &ctx);

}


/**
 * Call #GCCH_debug() on a channel.
 *
 * @param cls points to the log level to use
 * @param key unused
 * @param value the `struct CadetChannel` to dump
 * @return #GNUNET_OK (continue iteration)
 */
static int
debug_channel (void *cls,
               uint32_t key,
               void *value)
{
  const enum GNUNET_ErrorType *level = cls;
  struct CadetChannel *ch = value;

  GCCH_debug (ch, *level);
  return GNUNET_OK;
}


/**
 * Get string description for tunnel connectivity state.
 *
 * @param cs Tunnel state.
 *
 * @return String representation.
 */
static const char *
cstate2s (enum CadetTunnelCState cs)
{
  static char buf[32];

  switch (cs)
  {
    case CADET_TUNNEL_NEW:
      return "CADET_TUNNEL_NEW";
    case CADET_TUNNEL_SEARCHING:
      return "CADET_TUNNEL_SEARCHING";
    case CADET_TUNNEL_WAITING:
      return "CADET_TUNNEL_WAITING";
    case CADET_TUNNEL_READY:
      return "CADET_TUNNEL_READY";
    case CADET_TUNNEL_SHUTDOWN:
      return "CADET_TUNNEL_SHUTDOWN";
    default:
      SPRINTF (buf, "%u (UNKNOWN STATE)", cs);
      return buf;
  }
}


/**
 * Get string description for tunnel encryption state.
 *
 * @param es Tunnel state.
 *
 * @return String representation.
 */
static const char *
estate2s (enum CadetTunnelEState es)
{
  static char buf[32];

  switch (es)
  {
    case CADET_TUNNEL_KEY_UNINITIALIZED:
      return "CADET_TUNNEL_KEY_UNINITIALIZED";
    case CADET_TUNNEL_KEY_SENT:
      return "CADET_TUNNEL_KEY_SENT";
    case CADET_TUNNEL_KEY_PING:
      return "CADET_TUNNEL_KEY_PING";
    case CADET_TUNNEL_KEY_OK:
      return "CADET_TUNNEL_KEY_OK";
    case CADET_TUNNEL_KEY_REKEY:
      return "CADET_TUNNEL_KEY_REKEY";
    default:
      SPRINTF (buf, "%u (UNKNOWN STATE)", es);
      return buf;
  }
}


#define LOG2(level, ...) GNUNET_log_from_nocheck(level,"cadet-tun",__VA_ARGS__)


/**
 * Log all possible info about the tunnel state.
 *
 * @param t Tunnel to debug.
 * @param level Debug level to use.
 */
void
GCT_debug (const struct CadetTunnel *t,
           enum GNUNET_ErrorType level)
{
  struct CadetTConnection *iter_c;
  int do_log;

  do_log = GNUNET_get_log_call_status (level & (~GNUNET_ERROR_TYPE_BULK),
                                       "cadet-tun",
                                       __FILE__, __FUNCTION__, __LINE__);
  if (0 == do_log)
    return;

  LOG2 (level,
        "TTT TUNNEL TOWARDS %s in cstate %s, estate %s tq_len: %u #cons: %u\n",
        GCT_2s (t),
        cstate2s (t->cstate),
        estate2s (t->estate),
        t->tq_len,
        t->num_connections);
#if DUMP_KEYS_TO_STDERR
  ax_debug (t->ax, level);
#endif
  LOG2 (level,
        "TTT channels:\n");
  GNUNET_CONTAINER_multihashmap32_iterate (t->channels,
                                           &debug_channel,
                                           &level);
  LOG2 (level,
        "TTT connections:\n");
  for (iter_c = t->connection_head; NULL != iter_c; iter_c = iter_c->next)
    GCC_debug (iter_c->cc,
               level);

  LOG2 (level,
        "TTT TUNNEL END\n");
}


/* end of gnunet-service-cadet-new_tunnels.c */
