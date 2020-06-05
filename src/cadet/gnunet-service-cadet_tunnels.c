/*
     This file is part of GNUnet.
     Copyright (C) 2013, 2017, 2018 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */
/**
 * @file cadet/gnunet-service-cadet_tunnels.c
 * @brief Information we track per tunnel.
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 *
 * FIXME:
 * - proper connection evaluation during connection management:
 *   + consider quality (or quality spread?) of current connection set
 *     when deciding how often to do maintenance
 *   + interact with PEER to drive DHT GET/PUT operations based
 *     on how much we like our connections
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_signatures.h"
#include "cadet_protocol.h"
#include "gnunet-service-cadet_channel.h"
#include "gnunet-service-cadet_connection.h"
#include "gnunet-service-cadet_tunnels.h"
#include "gnunet-service-cadet_peer.h"
#include "gnunet-service-cadet_paths.h"


#define LOG(level, ...) GNUNET_log_from (level, "cadet-tun", __VA_ARGS__)

/**
 * How often do we try to decrypt payload with unverified key
 * material?  Used to limit CPU increase upon receiving bogus
 * KX.
 */
#define MAX_UNVERIFIED_ATTEMPTS 16

/**
 * How long do we wait until tearing down an idle tunnel?
 */
#define IDLE_DESTROY_DELAY GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_SECONDS, 90)

/**
 * How long do we wait initially before retransmitting the KX?
 * TODO: replace by 2 RTT if/once we have connection-level RTT data!
 */
#define INITIAL_KX_RETRY_DELAY GNUNET_TIME_relative_multiply ( \
    GNUNET_TIME_UNIT_MILLISECONDS, 250)

/**
 * Maximum number of skipped keys we keep in memory per tunnel.
 */
#define MAX_SKIPPED_KEYS 64

/**
 * Maximum number of keys (and thus ratchet steps) we are willing to
 * skip before we decide this is either a bogus packet or a DoS-attempt.
 */
#define MAX_KEY_GAP 256


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
   * 32-byte header key (currently used for sending).
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey HKs;

  /**
   * 32-byte header key (currently used for receiving)
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey HKr;

  /**
   * 32-byte next header key (for sending), used once the
   * ratchet advances.  We are sure that the sender has this
   * key as well only after @e ratchet_allowed is #GNUNET_YES.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey NHKs;

  /**
   * 32-byte next header key (for receiving).  To be tried
   * when decrypting with @e HKr fails and thus the sender
   * may have advanced the ratchet.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey NHKr;

  /**
   * 32-byte chain keys (used for forward-secrecy) for
   * sending messages. Updated for every message.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey CKs;

  /**
   * 32-byte chain keys (used for forward-secrecy) for
   * receiving messages. Updated for every message. If
   * messages are skipped, the respective derived MKs
   * (and the current @HKr) are kept in the @e skipped_head DLL.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey CKr;

  /**
   * ECDH for key exchange (A0 / B0).
   */
  struct GNUNET_CRYPTO_EcdhePrivateKey kx_0;

  /**
   * ECDH Ratchet key (our private key in the current DH).
   */
  struct GNUNET_CRYPTO_EcdhePrivateKey DHRs;

  /**
   * ECDH Ratchet key (other peer's public key in the current DH).
   */
  struct GNUNET_CRYPTO_EcdhePublicKey DHRr;

  /**
   * Last ephemeral public key received from the other peer,
   * for duplicate detection.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey last_ephemeral;

  /**
   * Time when the current ratchet expires and a new one is triggered
   * (if @e ratchet_allowed is #GNUNET_YES).
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
   * True (#GNUNET_YES) if we have received a message from the
   * other peer that uses the keys from our last ratchet step.
   * This implies that we are again allowed to advance the ratchet,
   * otherwise we have to wait until the other peer sees our current
   * ephemeral key and advances first.
   *
   * #GNUNET_NO if we have advanced the ratched but lack any evidence
   * that the other peer has noticed this.
   */
  int ratchet_allowed;

  /**
   * Number of messages recieved since our last ratchet advance.
   *
   * If this counter = 0, we cannot send a new ratchet key in the next
   * message.
   *
   * If this counter > 0, we could (but don't have to) send a new key.
   *
   * Once the @e ratchet_counter is larger than
   * #ratchet_messages (or @e ratchet_expiration time has past), and
   * @e ratchet_allowed is #GNUNET_YES, we advance the ratchet.
   */
  unsigned int ratchet_counter;
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
  GCT_SendContinuation cont;

  /**
   * Closure for @c cont.
   */
  void *cont_cls;

  /**
   * Envelope of message to send follows.
   */
  struct GNUNET_MQ_Envelope *env;

  /**
   * Where to put the connection identifier into the payload
   * of the message in @e env once we have it?
   */
  struct GNUNET_CADET_ConnectionTunnelIdentifier *cid;
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
   * Unverified Axolotl info, used only if we got a fresh KX (not a
   * KX_AUTH) while our end of the tunnel was still up.  In this case,
   * we keep the fresh KX around but do not put it into action until
   * we got encrypted payload that assures us of the authenticity of
   * the KX.
   */
  struct CadetTunnelAxolotl *unverified_ax;

  /**
   * Task scheduled if there are no more channels using the tunnel.
   */
  struct GNUNET_SCHEDULER_Task *destroy_task;

  /**
   * Task to trim connections if too many are present.
   */
  struct GNUNET_SCHEDULER_Task *maintain_connections_task;

  /**
   * Task to send messages from queue (if possible).
   */
  struct GNUNET_SCHEDULER_Task *send_task;

  /**
   * Task to trigger KX.
   */
  struct GNUNET_SCHEDULER_Task *kx_task;

  /**
   * Tokenizer for decrypted messages.
   */
  struct GNUNET_MessageStreamTokenizer *mst;

  /**
   * Dispatcher for decrypted messages only (do NOT use for sending!).
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * DLL of ready connections that are actively used to reach the destination peer.
   */
  struct CadetTConnection *connection_ready_head;

  /**
   * DLL of ready connections that are actively used to reach the destination peer.
   */
  struct CadetTConnection *connection_ready_tail;

  /**
   * DLL of connections that we maintain that might be used to reach the destination peer.
   */
  struct CadetTConnection *connection_busy_head;

  /**
   * DLL of connections that we maintain that might be used to reach the destination peer.
   */
  struct CadetTConnection *connection_busy_tail;

  /**
   * Channels inside this tunnel. Maps
   * `struct GNUNET_CADET_ChannelTunnelNumber` to a `struct CadetChannel`.
   */
  struct GNUNET_CONTAINER_MultiHashMap32 *channels;

  /**
   * Channel ID for the next created channel in this tunnel.
   */
  struct GNUNET_CADET_ChannelTunnelNumber next_ctn;

  /**
   * Queued messages, to transmit once tunnel gets connected.
   */
  struct CadetTunnelQueueEntry *tq_head;

  /**
   * Queued messages, to transmit once tunnel gets connected.
   */
  struct CadetTunnelQueueEntry *tq_tail;

  /**
   * Identification of the connection from which we are currently processing
   * a message. Only valid (non-NULL) during #handle_decrypted() and the
   * handle-*()-functions called from our @e mq during that function.
   */
  struct CadetTConnection *current_ct;

  /**
   * How long do we wait until we retry the KX?
   */
  struct GNUNET_TIME_Relative kx_retry_delay;

  /**
   * When do we try the next KX?
   */
  struct GNUNET_TIME_Absolute next_kx_attempt;

  /**
   * Number of connections in the @e connection_ready_head DLL.
   */
  unsigned int num_ready_connections;

  /**
   * Number of connections in the @e connection_busy_head DLL.
   */
  unsigned int num_busy_connections;

  /**
   * How often have we tried and failed to decrypt a message using
   * the unverified KX material from @e unverified_ax?  Used to
   * stop trying after #MAX_UNVERIFIED_ATTEMPTS.
   */
  unsigned int unverified_attempts;

  /**
   * Number of entries in the @e tq_head DLL.
   */
  unsigned int tq_len;

  /**
   * State of the tunnel encryption.
   */
  enum CadetTunnelEState estate;

  /**
   * Force triggering KX_AUTH independent of @e estate.
   */
  int kx_auth_requested;
};


/**
 * Am I Alice or Betty (some call her Bob), or talking to myself?
 *
 * @param other the other peer
 * @return #GNUNET_YES for Alice, #GNUNET_NO for Betty, #GNUNET_SYSERR if talking to myself
 */
int
GCT_alice_or_betty (const struct GNUNET_PeerIdentity *other)
{
  if (0 > GNUNET_memcmp (&my_full_id,
                         other))
    return GNUNET_YES;
  else if (0 < GNUNET_memcmp (&my_full_id,
                              other))
    return GNUNET_NO;
  else
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
}


/**
 * Connection @a ct is now unready, clear it's ready flag
 * and move it from the ready DLL to the busy DLL.
 *
 * @param ct connection to move to unready status
 */
static void
mark_connection_unready (struct CadetTConnection *ct)
{
  struct CadetTunnel *t = ct->t;

  GNUNET_assert (GNUNET_YES == ct->is_ready);
  GNUNET_CONTAINER_DLL_remove (t->connection_ready_head,
                               t->connection_ready_tail,
                               ct);
  GNUNET_assert (0 < t->num_ready_connections);
  t->num_ready_connections--;
  ct->is_ready = GNUNET_NO;
  GNUNET_CONTAINER_DLL_insert (t->connection_busy_head,
                               t->connection_busy_tail,
                               ct);
  t->num_busy_connections++;
}


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
    return "Tunnel(NULL)";
  GNUNET_snprintf (buf,
                   sizeof(buf),
                   "Tunnel %s",
                   GNUNET_i2s (GCP_get_id (t->destination)));
  return buf;
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
  case CADET_TUNNEL_KEY_AX_RECV:
    return "CADET_TUNNEL_KEY_AX_RECV";
  case CADET_TUNNEL_KEY_AX_SENT:
    return "CADET_TUNNEL_KEY_AX_SENT";
  case CADET_TUNNEL_KEY_AX_SENT_AND_RECV:
    return "CADET_TUNNEL_KEY_AX_SENT_AND_RECV";
  case CADET_TUNNEL_KEY_AX_AUTH_SENT:
    return "CADET_TUNNEL_KEY_AX_AUTH_SENT";
  case CADET_TUNNEL_KEY_OK:
    return "CADET_TUNNEL_KEY_OK";
  }
  GNUNET_snprintf (buf,
                   sizeof(buf),
                   "%u (UNKNOWN STATE)",
                   es);
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
 * Lookup a channel by its @a ctn.
 *
 * @param t tunnel to look in
 * @param ctn number of channel to find
 * @return NULL if channel does not exist
 */
struct CadetChannel *
lookup_channel (struct CadetTunnel *t,
                struct GNUNET_CADET_ChannelTunnelNumber ctn)
{
  return GNUNET_CONTAINER_multihashmap32_get (t->channels,
                                              ntohl (ctn.cn));
}


/**
 * Count all created connections of a tunnel. Not necessarily ready connections!
 *
 * @param t Tunnel on which to count.
 *
 * @return Number of connections created, either being established or ready.
 */
unsigned int
GCT_count_any_connections (const struct CadetTunnel *t)
{
  return t->num_ready_connections + t->num_busy_connections;
}


/**
 * Find first connection that is ready in the list of
 * our connections.  Picks ready connections round-robin.
 *
 * @param t tunnel to search
 * @return NULL if we have no connection that is ready
 */
static struct CadetTConnection *
get_ready_connection (struct CadetTunnel *t)
{
  struct CadetTConnection *hd = t->connection_ready_head;

  GNUNET_assert ((NULL == hd) ||
                 (GNUNET_YES == hd->is_ready));
  return hd;
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
 * Called when either we have a new connection, or a new message in the
 * queue, or some existing connection has transmission capacity.  Looks
 * at our message queue and if there is a message, picks a connection
 * to send it on.
 *
 * @param cls the `struct CadetTunnel` to process messages on
 */
static void
trigger_transmissions (void *cls);


/* ************************************** start core crypto ***************************** */


/**
 * Create a new Axolotl ephemeral (ratchet) key.
 *
 * @param ax key material to update
 */
static void
new_ephemeral (struct CadetTunnelAxolotl *ax)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Creating new ephemeral ratchet key (DHRs)\n");
  GNUNET_CRYPTO_ecdhe_key_create (&ax->DHRs);
}


/**
 * Calculate HMAC.
 *
 * @param plaintext Content to HMAC.
 * @param size Size of @c plaintext.
 * @param iv Initialization vector for the message.
 * @param key Key to use.
 * @param hmac[out] Destination to store the HMAC.
 */
static void
t_hmac (const void *plaintext,
        size_t size,
        uint32_t iv,
        const struct GNUNET_CRYPTO_SymmetricSessionKey *key,
        struct GNUNET_ShortHashCode *hmac)
{
  static const char ctx[] = "cadet authentication key";
  struct GNUNET_CRYPTO_AuthKey auth_key;
  struct GNUNET_HashCode hash;

  GNUNET_CRYPTO_hmac_derive_key (&auth_key,
                                 key,
                                 &iv, sizeof(iv),
                                 key, sizeof(*key),
                                 ctx, sizeof(ctx),
                                 NULL);
  /* Two step: GNUNET_ShortHash is only 256 bits,
     GNUNET_HashCode is 512, so we truncate. */
  GNUNET_CRYPTO_hmac (&auth_key,
                      plaintext,
                      size,
                      &hash);
  GNUNET_memcpy (hmac,
                 &hash,
                 sizeof(*hmac));
}


/**
 * Perform a HMAC.
 *
 * @param key Key to use.
 * @param[out] hash Resulting HMAC.
 * @param source Source key material (data to HMAC).
 * @param len Length of @a source.
 */
static void
t_ax_hmac_hash (const struct GNUNET_CRYPTO_SymmetricSessionKey *key,
                struct GNUNET_HashCode *hash,
                const void *source,
                unsigned int len)
{
  static const char ctx[] = "axolotl HMAC-HASH";
  struct GNUNET_CRYPTO_AuthKey auth_key;

  GNUNET_CRYPTO_hmac_derive_key (&auth_key,
                                 key,
                                 ctx, sizeof(ctx),
                                 NULL);
  GNUNET_CRYPTO_hmac (&auth_key,
                      source,
                      len,
                      hash);
}


/**
 * Derive a symmetric encryption key from an HMAC-HASH.
 *
 * @param key Key to use for the HMAC.
 * @param[out] out Key to generate.
 * @param source Source key material (data to HMAC).
 * @param len Length of @a source.
 */
static void
t_hmac_derive_key (const struct GNUNET_CRYPTO_SymmetricSessionKey *key,
                   struct GNUNET_CRYPTO_SymmetricSessionKey *out,
                   const void *source,
                   unsigned int len)
{
  static const char ctx[] = "axolotl derive key";
  struct GNUNET_HashCode h;

  t_ax_hmac_hash (key,
                  &h,
                  source,
                  len);
  GNUNET_CRYPTO_kdf (out, sizeof(*out),
                     ctx, sizeof(ctx),
                     &h, sizeof(h),
                     NULL);
}


/**
 * Encrypt data with the axolotl tunnel key.
 *
 * @param ax key material to use.
 * @param dst Destination with @a size bytes for the encrypted data.
 * @param src Source of the plaintext. Can overlap with @c dst, must contain @a size bytes
 * @param size Size of the buffers at @a src and @a dst
 */
static void
t_ax_encrypt (struct CadetTunnelAxolotl *ax,
              void *dst,
              const void *src,
              size_t size)
{
  struct GNUNET_CRYPTO_SymmetricSessionKey MK;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  size_t out_size;

  ax->ratchet_counter++;
  if ((GNUNET_YES == ax->ratchet_allowed) &&
      ((ratchet_messages <= ax->ratchet_counter) ||
       (0 == GNUNET_TIME_absolute_get_remaining (
          ax->ratchet_expiration).rel_value_us)))
  {
    ax->ratchet_flag = GNUNET_YES;
  }
  if (GNUNET_YES == ax->ratchet_flag)
  {
    /* Advance ratchet */
    struct GNUNET_CRYPTO_SymmetricSessionKey keys[3];
    struct GNUNET_HashCode dh;
    struct GNUNET_HashCode hmac;
    static const char ctx[] = "axolotl ratchet";

    new_ephemeral (ax);
    ax->HKs = ax->NHKs;

    /* RK, NHKs, CKs = KDF( HMAC-HASH(RK, DH(DHRs, DHRr)) ) */
    GNUNET_CRYPTO_ecc_ecdh (&ax->DHRs,
                            &ax->DHRr,
                            &dh);
    t_ax_hmac_hash (&ax->RK,
                    &hmac,
                    &dh,
                    sizeof(dh));
    GNUNET_CRYPTO_kdf (keys, sizeof(keys),
                       ctx, sizeof(ctx),
                       &hmac, sizeof(hmac),
                       NULL);
    ax->RK = keys[0];
    ax->NHKs = keys[1];
    ax->CKs = keys[2];

    ax->PNs = ax->Ns;
    ax->Ns = 0;
    ax->ratchet_flag = GNUNET_NO;
    ax->ratchet_allowed = GNUNET_NO;
    ax->ratchet_counter = 0;
    ax->ratchet_expiration
      = GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get (),
                                  ratchet_time);
  }

  t_hmac_derive_key (&ax->CKs,
                     &MK,
                     "0",
                     1);
  GNUNET_CRYPTO_symmetric_derive_iv (&iv,
                                     &MK,
                                     NULL, 0,
                                     NULL);

  out_size = GNUNET_CRYPTO_symmetric_encrypt (src,
                                              size,
                                              &MK,
                                              &iv,
                                              dst);
  GNUNET_assert (size == out_size);
  t_hmac_derive_key (&ax->CKs,
                     &ax->CKs,
                     "1",
                     1);
}


/**
 * Decrypt data with the axolotl tunnel key.
 *
 * @param ax key material to use.
 * @param dst Destination for the decrypted data, must contain @a size bytes.
 * @param src Source of the ciphertext. Can overlap with @c dst, must contain @a size bytes.
 * @param size Size of the @a src and @a dst buffers
 */
static void
t_ax_decrypt (struct CadetTunnelAxolotl *ax,
              void *dst,
              const void *src,
              size_t size)
{
  struct GNUNET_CRYPTO_SymmetricSessionKey MK;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  size_t out_size;

  t_hmac_derive_key (&ax->CKr,
                     &MK,
                     "0",
                     1);
  GNUNET_CRYPTO_symmetric_derive_iv (&iv,
                                     &MK,
                                     NULL, 0,
                                     NULL);
  GNUNET_assert (size >= sizeof(struct GNUNET_MessageHeader));
  out_size = GNUNET_CRYPTO_symmetric_decrypt (src,
                                              size,
                                              &MK,
                                              &iv,
                                              dst);
  GNUNET_assert (out_size == size);
  t_hmac_derive_key (&ax->CKr,
                     &ax->CKr,
                     "1",
                     1);
}


/**
 * Encrypt header with the axolotl header key.
 *
 * @param ax key material to use.
 * @param[in|out] msg Message whose header to encrypt.
 */
static void
t_h_encrypt (struct CadetTunnelAxolotl *ax,
             struct GNUNET_CADET_TunnelEncryptedMessage *msg)
{
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  size_t out_size;

  GNUNET_CRYPTO_symmetric_derive_iv (&iv,
                                     &ax->HKs,
                                     NULL, 0,
                                     NULL);
  out_size = GNUNET_CRYPTO_symmetric_encrypt (&msg->ax_header,
                                              sizeof(struct
                                                     GNUNET_CADET_AxHeader),
                                              &ax->HKs,
                                              &iv,
                                              &msg->ax_header);
  GNUNET_assert (sizeof(struct GNUNET_CADET_AxHeader) == out_size);
}


/**
 * Decrypt header with the current axolotl header key.
 *
 * @param ax key material to use.
 * @param src Message whose header to decrypt.
 * @param dst Where to decrypt header to.
 */
static void
t_h_decrypt (struct CadetTunnelAxolotl *ax,
             const struct GNUNET_CADET_TunnelEncryptedMessage *src,
             struct GNUNET_CADET_TunnelEncryptedMessage *dst)
{
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  size_t out_size;

  GNUNET_CRYPTO_symmetric_derive_iv (&iv,
                                     &ax->HKr,
                                     NULL, 0,
                                     NULL);
  out_size = GNUNET_CRYPTO_symmetric_decrypt (&src->ax_header.Ns,
                                              sizeof(struct
                                                     GNUNET_CADET_AxHeader),
                                              &ax->HKr,
                                              &iv,
                                              &dst->ax_header.Ns);
  GNUNET_assert (sizeof(struct GNUNET_CADET_AxHeader) == out_size);
}


/**
 * Delete a key from the list of skipped keys.
 *
 * @param ax key material to delete @a key from.
 * @param key Key to delete.
 */
static void
delete_skipped_key (struct CadetTunnelAxolotl *ax,
                    struct CadetTunnelSkippedKey *key)
{
  GNUNET_CONTAINER_DLL_remove (ax->skipped_head,
                               ax->skipped_tail,
                               key);
  GNUNET_free (key);
  ax->skipped--;
}


/**
 * Decrypt and verify data with the appropriate tunnel key and verify that the
 * data has not been altered since it was sent by the remote peer.
 *
 * @param ax key material to use.
 * @param dst Destination for the plaintext.
 * @param src Source of the message. Can overlap with @c dst.
 * @param size Size of the message.
 * @return Size of the decrypted data, -1 if an error was encountered.
 */
static ssize_t
try_old_ax_keys (struct CadetTunnelAxolotl *ax,
                 void *dst,
                 const struct GNUNET_CADET_TunnelEncryptedMessage *src,
                 size_t size)
{
  struct CadetTunnelSkippedKey *key;
  struct GNUNET_ShortHashCode *hmac;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  struct GNUNET_CADET_TunnelEncryptedMessage plaintext_header;
  struct GNUNET_CRYPTO_SymmetricSessionKey *valid_HK;
  size_t esize;
  size_t res;
  size_t len;
  unsigned int N;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Trying skipped keys\n");
  hmac = &plaintext_header.hmac;
  esize = size - sizeof(struct GNUNET_CADET_TunnelEncryptedMessage);

  /* Find a correct Header Key */
  valid_HK = NULL;
  for (key = ax->skipped_head; NULL != key; key = key->next)
  {
    t_hmac (&src->ax_header,
            sizeof(struct GNUNET_CADET_AxHeader) + esize,
            0,
            &key->HK,
            hmac);
    if (0 == GNUNET_memcmp (hmac,
                            &src->hmac))
    {
      valid_HK = &key->HK;
      break;
    }
  }
  if (NULL == key)
    return -1;

  /* Should've been checked in -cadet_connection.c handle_cadet_encrypted. */
  GNUNET_assert (size > sizeof(struct GNUNET_CADET_TunnelEncryptedMessage));
  len = size - sizeof(struct GNUNET_CADET_TunnelEncryptedMessage);
  GNUNET_assert (len >= sizeof(struct GNUNET_MessageHeader));

  /* Decrypt header */
  GNUNET_CRYPTO_symmetric_derive_iv (&iv,
                                     &key->HK,
                                     NULL, 0,
                                     NULL);
  res = GNUNET_CRYPTO_symmetric_decrypt (&src->ax_header.Ns,
                                         sizeof(struct GNUNET_CADET_AxHeader),
                                         &key->HK,
                                         &iv,
                                         &plaintext_header.ax_header.Ns);
  GNUNET_assert (sizeof(struct GNUNET_CADET_AxHeader) == res);

  /* Find the correct message key */
  N = ntohl (plaintext_header.ax_header.Ns);
  while ((NULL != key) &&
         (N != key->Kn))
    key = key->next;
  if ((NULL == key) ||
      (0 != GNUNET_memcmp (&key->HK,
                           valid_HK)))
    return -1;

  /* Decrypt payload */
  GNUNET_CRYPTO_symmetric_derive_iv (&iv,
                                     &key->MK,
                                     NULL,
                                     0,
                                     NULL);
  res = GNUNET_CRYPTO_symmetric_decrypt (&src[1],
                                         len,
                                         &key->MK,
                                         &iv,
                                         dst);
  delete_skipped_key (ax,
                      key);
  return res;
}


/**
 * Delete a key from the list of skipped keys.
 *
 * @param ax key material to delete from.
 * @param HKr Header Key to use.
 */
static void
store_skipped_key (struct CadetTunnelAxolotl *ax,
                   const struct GNUNET_CRYPTO_SymmetricSessionKey *HKr)
{
  struct CadetTunnelSkippedKey *key;

  key = GNUNET_new (struct CadetTunnelSkippedKey);
  key->timestamp = GNUNET_TIME_absolute_get ();
  key->Kn = ax->Nr;
  key->HK = ax->HKr;
  t_hmac_derive_key (&ax->CKr,
                     &key->MK,
                     "0",
                     1);
  t_hmac_derive_key (&ax->CKr,
                     &ax->CKr,
                     "1",
                     1);
  GNUNET_CONTAINER_DLL_insert (ax->skipped_head,
                               ax->skipped_tail,
                               key);
  ax->skipped++;
  ax->Nr++;
}


/**
 * Stage skipped AX keys and calculate the message key.
 * Stores each HK and MK for skipped messages.
 *
 * @param ax key material to use
 * @param HKr Header key.
 * @param Np Received meesage number.
 * @return #GNUNET_OK if keys were stored.
 *         #GNUNET_SYSERR if an error ocurred (@a Np not expected).
 */
static int
store_ax_keys (struct CadetTunnelAxolotl *ax,
               const struct GNUNET_CRYPTO_SymmetricSessionKey *HKr,
               uint32_t Np)
{
  int gap;

  gap = Np - ax->Nr;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Storing skipped keys [%u, %u)\n",
       ax->Nr,
       Np);
  if (MAX_KEY_GAP < gap)
  {
    /* Avoid DoS (forcing peer to do more than #MAX_KEY_GAP HMAC operations) */
    /* TODO: start new key exchange on return */
    GNUNET_break_op (0);
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Got message %u, expected %u+\n",
         Np,
         ax->Nr);
    return GNUNET_SYSERR;
  }
  if (0 > gap)
  {
    /* Delayed message: don't store keys, flag to try old keys. */
    return GNUNET_SYSERR;
  }

  while (ax->Nr < Np)
    store_skipped_key (ax,
                       HKr);

  while (ax->skipped > MAX_SKIPPED_KEYS)
    delete_skipped_key (ax,
                        ax->skipped_tail);
  return GNUNET_OK;
}


/**
 * Decrypt and verify data with the appropriate tunnel key and verify that the
 * data has not been altered since it was sent by the remote peer.
 *
 * @param ax key material to use
 * @param dst Destination for the plaintext.
 * @param src Source of the message. Can overlap with @c dst.
 * @param size Size of the message.
 * @return Size of the decrypted data, -1 if an error was encountered.
 */
static ssize_t
t_ax_decrypt_and_validate (struct CadetTunnelAxolotl *ax,
                           void *dst,
                           const struct
                           GNUNET_CADET_TunnelEncryptedMessage *src,
                           size_t size)
{
  struct GNUNET_ShortHashCode msg_hmac;
  struct GNUNET_HashCode hmac;
  struct GNUNET_CADET_TunnelEncryptedMessage plaintext_header;
  uint32_t Np;
  uint32_t PNp;
  size_t esize; /* Size of encryped payload */

  esize = size - sizeof(struct GNUNET_CADET_TunnelEncryptedMessage);

  /* Try current HK */
  t_hmac (&src->ax_header,
          sizeof(struct GNUNET_CADET_AxHeader) + esize,
          0, &ax->HKr,
          &msg_hmac);
  if (0 != GNUNET_memcmp (&msg_hmac,
                          &src->hmac))
  {
    static const char ctx[] = "axolotl ratchet";
    struct GNUNET_CRYPTO_SymmetricSessionKey keys[3];   /* RKp, NHKp, CKp */
    struct GNUNET_CRYPTO_SymmetricSessionKey HK;
    struct GNUNET_HashCode dh;
    struct GNUNET_CRYPTO_EcdhePublicKey *DHRp;

    /* Try Next HK */
    t_hmac (&src->ax_header,
            sizeof(struct GNUNET_CADET_AxHeader) + esize,
            0,
            &ax->NHKr,
            &msg_hmac);
    if (0 != GNUNET_memcmp (&msg_hmac,
                            &src->hmac))
    {
      /* Try the skipped keys, if that fails, we're out of luck. */
      return try_old_ax_keys (ax,
                              dst,
                              src,
                              size);
    }
    HK = ax->HKr;
    ax->HKr = ax->NHKr;
    t_h_decrypt (ax,
                 src,
                 &plaintext_header);
    Np = ntohl (plaintext_header.ax_header.Ns);
    PNp = ntohl (plaintext_header.ax_header.PNs);
    DHRp = &plaintext_header.ax_header.DHRs;
    store_ax_keys (ax,
                   &HK,
                   PNp);

    /* RKp, NHKp, CKp = KDF (HMAC-HASH (RK, DH (DHRp, DHRs))) */
    GNUNET_CRYPTO_ecc_ecdh (&ax->DHRs,
                            DHRp,
                            &dh);
    t_ax_hmac_hash (&ax->RK,
                    &hmac,
                    &dh, sizeof(dh));
    GNUNET_CRYPTO_kdf (keys, sizeof(keys),
                       ctx, sizeof(ctx),
                       &hmac, sizeof(hmac),
                       NULL);

    /* Commit "purported" keys */
    ax->RK = keys[0];
    ax->NHKr = keys[1];
    ax->CKr = keys[2];
    ax->DHRr = *DHRp;
    ax->Nr = 0;
    ax->ratchet_allowed = GNUNET_YES;
  }
  else
  {
    t_h_decrypt (ax,
                 src,
                 &plaintext_header);
    Np = ntohl (plaintext_header.ax_header.Ns);
    PNp = ntohl (plaintext_header.ax_header.PNs);
  }
  if ((Np != ax->Nr) &&
      (GNUNET_OK != store_ax_keys (ax,
                                   &ax->HKr,
                                   Np)))
  {
    /* Try the skipped keys, if that fails, we're out of luck. */
    return try_old_ax_keys (ax,
                            dst,
                            src,
                            size);
  }

  t_ax_decrypt (ax,
                dst,
                &src[1],
                esize);
  ax->Nr = Np + 1;
  return esize;
}


/**
 * Our tunnel became ready for the first time, notify channels
 * that have been waiting.
 *
 * @param cls our tunnel, not used
 * @param key unique ID of the channel, not used
 * @param value the `struct CadetChannel` to notify
 * @return #GNUNET_OK (continue to iterate)
 */
static int
notify_tunnel_up_cb (void *cls,
                     uint32_t key,
                     void *value)
{
  struct CadetChannel *ch = value;

  GCCH_tunnel_up (ch);
  return GNUNET_OK;
}


/**
 * Change the tunnel encryption state.
 * If the encryption state changes to OK, stop the rekey task.
 *
 * @param t Tunnel whose encryption state to change, or NULL.
 * @param state New encryption state.
 */
void
GCT_change_estate (struct CadetTunnel *t,
                   enum CadetTunnelEState state)
{
  enum CadetTunnelEState old = t->estate;

  t->estate = state;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s estate changed from %s to %s\n",
       GCT_2s (t),
       estate2s (old),
       estate2s (state));

  if ((CADET_TUNNEL_KEY_OK != old) &&
      (CADET_TUNNEL_KEY_OK == t->estate))
  {
    if (NULL != t->kx_task)
    {
      GNUNET_SCHEDULER_cancel (t->kx_task);
      t->kx_task = NULL;
    }
    /* notify all channels that have been waiting */
    GNUNET_CONTAINER_multihashmap32_iterate (t->channels,
                                             &notify_tunnel_up_cb,
                                             t);
    if (NULL != t->send_task)
      GNUNET_SCHEDULER_cancel (t->send_task);
    t->send_task = GNUNET_SCHEDULER_add_now (&trigger_transmissions,
                                             t);
  }
}


/**
 * Send a KX message.
 *
 * @param t tunnel on which to send the KX_AUTH
 * @param ct Tunnel and connection on which to send the KX_AUTH, NULL if
 *           we are to find one that is ready.
 * @param ax axolotl key context to use
 */
static void
send_kx (struct CadetTunnel *t,
         struct CadetTConnection *ct,
         struct CadetTunnelAxolotl *ax)
{
  struct CadetConnection *cc;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_TunnelKeyExchangeMessage *msg;
  enum GNUNET_CADET_KX_Flags flags;

  if (GNUNET_YES != GCT_alice_or_betty (GCP_get_id (t->destination)))
    return; /* only Alice may send KX */
  if ((NULL == ct) ||
      (GNUNET_NO == ct->is_ready))
    ct = get_ready_connection (t);
  if (NULL == ct)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Wanted to send %s in state %s, but no connection is ready, deferring\n",
         GCT_2s (t),
         estate2s (t->estate));
    t->next_kx_attempt = GNUNET_TIME_absolute_get ();
    return;
  }
  cc = ct->cc;
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_CADET_TUNNEL_KX);
  flags = GNUNET_CADET_KX_FLAG_FORCE_REPLY; /* always for KX */
  msg->flags = htonl (flags);
  msg->cid = *GCC_get_id (cc);
  GNUNET_CRYPTO_ecdhe_key_get_public (&ax->kx_0,
                                      &msg->ephemeral_key);
#if DEBUG_KX
  msg->ephemeral_key_XXX = ax->kx_0;
  msg->private_key_XXX = *my_private_key;
#endif
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending KX message to %s with ephemeral %s on CID %s\n",
       GCT_2s (t),
       GNUNET_e2s (&msg->ephemeral_key),
       GNUNET_sh2s (&msg->cid.connection_of_tunnel));
  GNUNET_CRYPTO_ecdhe_key_get_public (&ax->DHRs,
                                      &msg->ratchet_key);
  mark_connection_unready (ct);
  t->kx_retry_delay = GNUNET_TIME_STD_BACKOFF (t->kx_retry_delay);
  t->next_kx_attempt = GNUNET_TIME_relative_to_absolute (t->kx_retry_delay);
  if (CADET_TUNNEL_KEY_UNINITIALIZED == t->estate)
    GCT_change_estate (t,
                       CADET_TUNNEL_KEY_AX_SENT);
  else if (CADET_TUNNEL_KEY_AX_RECV == t->estate)
    GCT_change_estate (t,
                       CADET_TUNNEL_KEY_AX_SENT_AND_RECV);
  GCC_transmit (cc,
                env);
  GNUNET_STATISTICS_update (stats,
                            "# KX transmitted",
                            1,
                            GNUNET_NO);
}


/**
 * Send a KX_AUTH message.
 *
 * @param t tunnel on which to send the KX_AUTH
 * @param ct Tunnel and connection on which to send the KX_AUTH, NULL if
 *           we are to find one that is ready.
 * @param ax axolotl key context to use
 * @param force_reply Force the other peer to reply with a KX_AUTH message
 *         (set if we would like to transmit right now, but cannot)
 */
static void
send_kx_auth (struct CadetTunnel *t,
              struct CadetTConnection *ct,
              struct CadetTunnelAxolotl *ax,
              int force_reply)
{
  struct CadetConnection *cc;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_TunnelKeyExchangeAuthMessage *msg;
  enum GNUNET_CADET_KX_Flags flags;

  if ((NULL == ct) ||
      (GNUNET_NO == ct->is_ready))
    ct = get_ready_connection (t);
  if (NULL == ct)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Wanted to send KX_AUTH on %s, but no connection is ready, deferring\n",
         GCT_2s (t));
    t->next_kx_attempt = GNUNET_TIME_absolute_get ();
    t->kx_auth_requested = GNUNET_YES;   /* queue KX_AUTH independent of estate */
    return;
  }
  t->kx_auth_requested = GNUNET_NO; /* clear flag */
  cc = ct->cc;
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_CADET_TUNNEL_KX_AUTH);
  flags = GNUNET_CADET_KX_FLAG_NONE;
  if (GNUNET_YES == force_reply)
    flags |= GNUNET_CADET_KX_FLAG_FORCE_REPLY;
  msg->kx.flags = htonl (flags);
  msg->kx.cid = *GCC_get_id (cc);
  GNUNET_CRYPTO_ecdhe_key_get_public (&ax->kx_0,
                                      &msg->kx.ephemeral_key);
  GNUNET_CRYPTO_ecdhe_key_get_public (&ax->DHRs,
                                      &msg->kx.ratchet_key);
#if DEBUG_KX
  msg->kx.ephemeral_key_XXX = ax->kx_0;
  msg->kx.private_key_XXX = *my_private_key;
  msg->r_ephemeral_key_XXX = ax->last_ephemeral;
#endif
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending KX_AUTH message to %s with ephemeral %s on CID %s\n",
       GCT_2s (t),
       GNUNET_e2s (&msg->kx.ephemeral_key),
       GNUNET_sh2s (&msg->kx.cid.connection_of_tunnel));

  /* Compute authenticator (this is the main difference to #send_kx()) */
  GNUNET_CRYPTO_hash (&ax->RK,
                      sizeof(ax->RK),
                      &msg->auth);
  /* Compute when to be triggered again; actual job will
     be scheduled via #connection_ready_cb() */
  t->kx_retry_delay
    = GNUNET_TIME_STD_BACKOFF (t->kx_retry_delay);
  t->next_kx_attempt
    = GNUNET_TIME_relative_to_absolute (t->kx_retry_delay);

  /* Send via cc, mark it as unready */
  mark_connection_unready (ct);

  /* Update state machine, unless we are already OK */
  if (CADET_TUNNEL_KEY_OK != t->estate)
    GCT_change_estate (t,
                       CADET_TUNNEL_KEY_AX_AUTH_SENT);
  GCC_transmit (cc,
                env);
  GNUNET_STATISTICS_update (stats,
                            "# KX_AUTH transmitted",
                            1,
                            GNUNET_NO);
}


/**
 * Cleanup state used by @a ax.
 *
 * @param ax state to free, but not memory of @a ax itself
 */
static void
cleanup_ax (struct CadetTunnelAxolotl *ax)
{
  while (NULL != ax->skipped_head)
    delete_skipped_key (ax,
                        ax->skipped_head);
  GNUNET_assert (0 == ax->skipped);
  GNUNET_CRYPTO_ecdhe_key_clear (&ax->kx_0);
  GNUNET_CRYPTO_ecdhe_key_clear (&ax->DHRs);
}


/**
 * Update our Axolotl key state based on the KX data we received.
 * Computes the new chain keys, and root keys, etc, and also checks
 * whether this is a replay of the current chain.
 *
 * @param[in|out] axolotl chain key state to recompute
 * @param pid peer identity of the other peer
 * @param ephemeral_key ephemeral public key of the other peer
 * @param ratchet_key senders next ephemeral public key
 * @return #GNUNET_OK on success, #GNUNET_NO if the resulting
 *       root key is already in @a ax and thus the KX is useless;
 *       #GNUNET_SYSERR on hard errors (i.e. @a pid is #my_full_id)
 */
static int
update_ax_by_kx (struct CadetTunnelAxolotl *ax,
                 const struct GNUNET_PeerIdentity *pid,
                 const struct GNUNET_CRYPTO_EcdhePublicKey *ephemeral_key,
                 const struct GNUNET_CRYPTO_EcdhePublicKey *ratchet_key)
{
  struct GNUNET_HashCode key_material[3];
  struct GNUNET_CRYPTO_SymmetricSessionKey keys[5];
  const char salt[] = "CADET Axolotl salt";
  int am_I_alice;

  if (GNUNET_SYSERR == (am_I_alice = GCT_alice_or_betty (pid)))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (0 == GNUNET_memcmp (&ax->DHRr,
                          ratchet_key))
  {
    GNUNET_STATISTICS_update (stats,
                              "# Ratchet key already known",
                              1,
                              GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Ratchet key already known. Ignoring KX.\n");
    return GNUNET_NO;
  }

  ax->DHRr = *ratchet_key;
  ax->last_ephemeral = *ephemeral_key;
  /* ECDH A B0 */
  if (GNUNET_YES == am_I_alice)
  {
    GNUNET_CRYPTO_eddsa_ecdh (my_private_key,      /* a */
                              ephemeral_key,       /* B0 */
                              &key_material[0]);
  }
  else
  {
    GNUNET_CRYPTO_ecdh_eddsa (&ax->kx_0,            /* b0 */
                              &pid->public_key,     /* A */
                              &key_material[0]);
  }
  /* ECDH A0 B */
  if (GNUNET_YES == am_I_alice)
  {
    GNUNET_CRYPTO_ecdh_eddsa (&ax->kx_0,            /* a0 */
                              &pid->public_key,     /* B */
                              &key_material[1]);
  }
  else
  {
    GNUNET_CRYPTO_eddsa_ecdh (my_private_key,      /* b  */
                              ephemeral_key,       /* A0 */
                              &key_material[1]);
  }

  /* ECDH A0 B0 */
  GNUNET_CRYPTO_ecc_ecdh (&ax->kx_0,              /* a0 or b0 */
                          ephemeral_key,         /* B0 or A0 */
                          &key_material[2]);
  /* KDF */
  GNUNET_CRYPTO_kdf (keys, sizeof(keys),
                     salt, sizeof(salt),
                     &key_material, sizeof(key_material),
                     NULL);

  if (0 == memcmp (&ax->RK,
                   &keys[0],
                   sizeof(ax->RK)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Root key already known. Ignoring KX.\n");
    GNUNET_STATISTICS_update (stats,
                              "# Root key already known",
                              1,
                              GNUNET_NO);
    return GNUNET_NO;
  }

  ax->RK = keys[0];
  if (GNUNET_YES == am_I_alice)
  {
    ax->HKr = keys[1];
    ax->NHKs = keys[2];
    ax->NHKr = keys[3];
    ax->CKr = keys[4];
    ax->ratchet_flag = GNUNET_YES;
  }
  else
  {
    ax->HKs = keys[1];
    ax->NHKr = keys[2];
    ax->NHKs = keys[3];
    ax->CKs = keys[4];
    ax->ratchet_flag = GNUNET_NO;
    ax->ratchet_expiration
      = GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get (),
                                  ratchet_time);
  }
  return GNUNET_OK;
}


/**
 * Try to redo the KX or KX_AUTH handshake, if we can.
 *
 * @param cls the `struct CadetTunnel` to do KX for.
 */
static void
retry_kx (void *cls)
{
  struct CadetTunnel *t = cls;
  struct CadetTunnelAxolotl *ax;

  t->kx_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Trying to make KX progress on %s in state %s\n",
       GCT_2s (t),
       estate2s (t->estate));
  switch (t->estate)
  {
  case CADET_TUNNEL_KEY_UNINITIALIZED:   /* first attempt */
  case CADET_TUNNEL_KEY_AX_SENT:         /* trying again */
    send_kx (t,
             NULL,
             &t->ax);
    break;

  case CADET_TUNNEL_KEY_AX_RECV:
  case CADET_TUNNEL_KEY_AX_SENT_AND_RECV:
    /* We are responding, so only require reply
       if WE have a channel waiting. */
    if (NULL != t->unverified_ax)
    {
      /* Send AX_AUTH so we might get this one verified */
      ax = t->unverified_ax;
    }
    else
    {
      /* How can this be? */
      GNUNET_break (0);
      ax = &t->ax;
    }
    send_kx_auth (t,
                  NULL,
                  ax,
                  (0 == GCT_count_channels (t))
                  ? GNUNET_NO
                  : GNUNET_YES);
    break;

  case CADET_TUNNEL_KEY_AX_AUTH_SENT:
    /* We are responding, so only require reply
       if WE have a channel waiting. */
    if (NULL != t->unverified_ax)
    {
      /* Send AX_AUTH so we might get this one verified */
      ax = t->unverified_ax;
    }
    else
    {
      /* How can this be? */
      GNUNET_break (0);
      ax = &t->ax;
    }
    send_kx_auth (t,
                  NULL,
                  ax,
                  (0 == GCT_count_channels (t))
                  ? GNUNET_NO
                  : GNUNET_YES);
    break;

  case CADET_TUNNEL_KEY_OK:
    /* Must have been the *other* peer asking us to
       respond with a KX_AUTH. */
    if (NULL != t->unverified_ax)
    {
      /* Sending AX_AUTH in response to AX so we might get this one verified */
      ax = t->unverified_ax;
    }
    else
    {
      /* Sending AX_AUTH in response to AX_AUTH */
      ax = &t->ax;
    }
    send_kx_auth (t,
                  NULL,
                  ax,
                  GNUNET_NO);
    break;
  }
}


/**
 * Handle KX message that lacks authentication (and which will thus
 * only be considered authenticated after we respond with our own
 * KX_AUTH and finally successfully decrypt payload).
 *
 * @param ct connection/tunnel combo that received encrypted message
 * @param msg the key exchange message
 */
void
GCT_handle_kx (struct CadetTConnection *ct,
               const struct GNUNET_CADET_TunnelKeyExchangeMessage *msg)
{
  struct CadetTunnel *t = ct->t;
  int ret;

  GNUNET_STATISTICS_update (stats,
                            "# KX received",
                            1,
                            GNUNET_NO);
  if (GNUNET_YES ==
      GCT_alice_or_betty (GCP_get_id (t->destination)))
  {
    /* Betty/Bob is not allowed to send KX! */
    GNUNET_break_op (0);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received KX message from %s with ephemeral %s from %s on connection %s\n",
       GCT_2s (t),
       GNUNET_e2s (&msg->ephemeral_key),
       GNUNET_i2s (GCP_get_id (t->destination)),
       GCC_2s (ct->cc));
#if 1
  if ((0 ==
       memcmp (&t->ax.DHRr,
               &msg->ratchet_key,
               sizeof(msg->ratchet_key))) &&
      (0 ==
       memcmp (&t->ax.last_ephemeral,
               &msg->ephemeral_key,
               sizeof(msg->ephemeral_key))))

  {
    GNUNET_STATISTICS_update (stats,
                              "# Duplicate KX received",
                              1,
                              GNUNET_NO);
    send_kx_auth (t,
                  ct,
                  &t->ax,
                  GNUNET_NO);
    return;
  }
#endif
  /* We only keep ONE unverified KX around, so if there is an existing one,
     clean it up. */
  if (NULL != t->unverified_ax)
  {
    if ((0 ==
         memcmp (&t->unverified_ax->DHRr,
                 &msg->ratchet_key,
                 sizeof(msg->ratchet_key))) &&
        (0 ==
         memcmp (&t->unverified_ax->last_ephemeral,
                 &msg->ephemeral_key,
                 sizeof(msg->ephemeral_key))))
    {
      GNUNET_STATISTICS_update (stats,
                                "# Duplicate unverified KX received",
                                1,
                                GNUNET_NO);
#if 1
      send_kx_auth (t,
                    ct,
                    t->unverified_ax,
                    GNUNET_NO);
      return;
#endif
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Dropping old unverified KX state.\n");
    GNUNET_STATISTICS_update (stats,
                              "# Unverified KX dropped for fresh KX",
                              1,
                              GNUNET_NO);
    GNUNET_break (NULL == t->unverified_ax->skipped_head);
    memset (t->unverified_ax,
            0,
            sizeof(struct CadetTunnelAxolotl));
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Creating fresh unverified KX for %s\n",
         GCT_2s (t));
    GNUNET_STATISTICS_update (stats,
                              "# Fresh KX setup",
                              1,
                              GNUNET_NO);
    t->unverified_ax = GNUNET_new (struct CadetTunnelAxolotl);
  }
  /* Set as the 'current' RK/DHRr the one we are currently using,
     so that the duplicate-detection logic of
   #update_ax_by_kx can work. */
  t->unverified_ax->RK = t->ax.RK;
  t->unverified_ax->DHRr = t->ax.DHRr;
  t->unverified_ax->DHRs = t->ax.DHRs;
  t->unverified_ax->kx_0 = t->ax.kx_0;
  t->unverified_attempts = 0;

  /* Update 'ax' by the new key material */
  ret = update_ax_by_kx (t->unverified_ax,
                         GCP_get_id (t->destination),
                         &msg->ephemeral_key,
                         &msg->ratchet_key);
  GNUNET_break (GNUNET_SYSERR != ret);
  if (GNUNET_OK != ret)
  {
    GNUNET_STATISTICS_update (stats,
                              "# Useless KX",
                              1,
                              GNUNET_NO);
    return;   /* duplicate KX, nothing to do */
  }
  /* move ahead in our state machine */
  if (CADET_TUNNEL_KEY_UNINITIALIZED == t->estate)
    GCT_change_estate (t,
                       CADET_TUNNEL_KEY_AX_RECV);
  else if (CADET_TUNNEL_KEY_AX_SENT == t->estate)
    GCT_change_estate (t,
                       CADET_TUNNEL_KEY_AX_SENT_AND_RECV);

  /* KX is still not done, try again our end. */
  if (CADET_TUNNEL_KEY_OK != t->estate)
  {
    if (NULL != t->kx_task)
      GNUNET_SCHEDULER_cancel (t->kx_task);
    t->kx_task
      = GNUNET_SCHEDULER_add_now (&retry_kx,
                                  t);
  }
}


#if DEBUG_KX
static void
check_ee (const struct GNUNET_CRYPTO_EcdhePrivateKey *e1,
          const struct GNUNET_CRYPTO_EcdhePrivateKey *e2)
{
  struct GNUNET_CRYPTO_EcdhePublicKey p1;
  struct GNUNET_CRYPTO_EcdhePublicKey p2;
  struct GNUNET_HashCode hc1;
  struct GNUNET_HashCode hc2;

  GNUNET_CRYPTO_ecdhe_key_get_public (e1,
                                      &p1);
  GNUNET_CRYPTO_ecdhe_key_get_public (e2,
                                      &p2);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_ecc_ecdh (e1,
                                         &p2,
                                         &hc1));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_ecc_ecdh (e2,
                                         &p1,
                                         &hc2));
  GNUNET_break (0 == GNUNET_memcmp (&hc1,
                                    &hc2));
}


static void
check_ed (const struct GNUNET_CRYPTO_EcdhePrivateKey *e1,
          const struct GNUNET_CRYPTO_EddsaPrivateKey *e2)
{
  struct GNUNET_CRYPTO_EcdhePublicKey p1;
  struct GNUNET_CRYPTO_EddsaPublicKey p2;
  struct GNUNET_HashCode hc1;
  struct GNUNET_HashCode hc2;

  GNUNET_CRYPTO_ecdhe_key_get_public (e1,
                                      &p1);
  GNUNET_CRYPTO_eddsa_key_get_public (e2,
                                      &p2);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_ecdh_eddsa (e1,
                                           &p2,
                                           &hc1));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_eddsa_ecdh (e2,
                                           &p1,
                                           &hc2));
  GNUNET_break (0 == GNUNET_memcmp (&hc1,
                                    &hc2));
}


static void
test_crypto_bug (const struct GNUNET_CRYPTO_EcdhePrivateKey *e1,
                 const struct GNUNET_CRYPTO_EcdhePrivateKey *e2,
                 const struct GNUNET_CRYPTO_EddsaPrivateKey *d1,
                 const struct GNUNET_CRYPTO_EddsaPrivateKey *d2)
{
  check_ee (e1, e2);
  check_ed (e1, d2);
  check_ed (e2, d1);
}


#endif


/**
 * Handle KX_AUTH message.
 *
 * @param ct connection/tunnel combo that received encrypted message
 * @param msg the key exchange message
 */
void
GCT_handle_kx_auth (struct CadetTConnection *ct,
                    const struct GNUNET_CADET_TunnelKeyExchangeAuthMessage *msg)
{
  struct CadetTunnel *t = ct->t;
  struct CadetTunnelAxolotl ax_tmp;
  struct GNUNET_HashCode kx_auth;
  int ret;

  GNUNET_STATISTICS_update (stats,
                            "# KX_AUTH received",
                            1,
                            GNUNET_NO);
  if ((CADET_TUNNEL_KEY_UNINITIALIZED == t->estate) ||
      (CADET_TUNNEL_KEY_AX_RECV == t->estate))
  {
    /* Confusing, we got a KX_AUTH before we even send our own
       KX. This should not happen. We'll send our own KX ASAP anyway,
       so let's ignore this here. */
    GNUNET_break_op (0);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Handling KX_AUTH message from %s with ephemeral %s\n",
       GCT_2s (t),
       GNUNET_e2s (&msg->kx.ephemeral_key));
  /* We do everything in ax_tmp until we've checked the authentication
     so we don't clobber anything we care about by accident. */
  ax_tmp = t->ax;

  /* Update 'ax' by the new key material */
  ret = update_ax_by_kx (&ax_tmp,
                         GCP_get_id (t->destination),
                         &msg->kx.ephemeral_key,
                         &msg->kx.ratchet_key);
  if (GNUNET_OK != ret)
  {
    if (GNUNET_NO == ret)
      GNUNET_STATISTICS_update (stats,
                                "# redundant KX_AUTH received",
                                1,
                                GNUNET_NO);
    else
      GNUNET_break (0);  /* connect to self!? */
    return;
  }
  GNUNET_CRYPTO_hash (&ax_tmp.RK,
                      sizeof(ax_tmp.RK),
                      &kx_auth);
  if (0 != GNUNET_memcmp (&kx_auth,
                          &msg->auth))
  {
    /* This KX_AUTH is not using the latest KX/KX_AUTH data
       we transmitted to the sender, refuse it, try KX again. */
    GNUNET_STATISTICS_update (stats,
                              "# KX_AUTH not using our last KX received (auth failure)",
                              1,
                              GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "KX AUTH mismatch!\n");
#if DEBUG_KX
    {
      struct GNUNET_CRYPTO_EcdhePublicKey ephemeral_key;

      GNUNET_CRYPTO_ecdhe_key_get_public (&ax_tmp.kx_0,
                                          &ephemeral_key);
      if (0 != GNUNET_memcmp (&ephemeral_key,
                              &msg->r_ephemeral_key_XXX))
      {
        LOG (GNUNET_ERROR_TYPE_WARNING,
             "My ephemeral is %s!\n",
             GNUNET_e2s (&ephemeral_key));
        LOG (GNUNET_ERROR_TYPE_WARNING,
             "Response is for ephemeral %s!\n",
             GNUNET_e2s (&msg->r_ephemeral_key_XXX));
      }
      else
      {
        test_crypto_bug (&ax_tmp.kx_0,
                         &msg->kx.ephemeral_key_XXX,
                         my_private_key,
                         &msg->kx.private_key_XXX);
      }
    }
#endif
    if (NULL == t->kx_task)
      t->kx_task
        = GNUNET_SCHEDULER_add_at (t->next_kx_attempt,
                                   &retry_kx,
                                   t);
    return;
  }
  /* Yep, we're good. */
  t->ax = ax_tmp;
  if (NULL != t->unverified_ax)
  {
    /* We got some "stale" KX before, drop that. */
    cleanup_ax (t->unverified_ax);
    GNUNET_free (t->unverified_ax);
    t->unverified_ax = NULL;
  }

  /* move ahead in our state machine */
  switch (t->estate)
  {
  case CADET_TUNNEL_KEY_UNINITIALIZED:
  case CADET_TUNNEL_KEY_AX_RECV:
    /* Checked above, this is impossible. */
    GNUNET_assert (0);
    break;

  case CADET_TUNNEL_KEY_AX_SENT:      /* This is the normal case */
  case CADET_TUNNEL_KEY_AX_SENT_AND_RECV:   /* both peers started KX */
  case CADET_TUNNEL_KEY_AX_AUTH_SENT:   /* both peers now did KX_AUTH */
    GCT_change_estate (t,
                       CADET_TUNNEL_KEY_OK);
    break;

  case CADET_TUNNEL_KEY_OK:
    /* Did not expect another KX_AUTH, but so what, still acceptable.
       Nothing to do here. */
    break;
  }
  if (0 != (GNUNET_CADET_KX_FLAG_FORCE_REPLY & ntohl (msg->kx.flags)))
  {
    send_kx_auth (t,
                  NULL,
                  &t->ax,
                  GNUNET_NO);
  }
}


/* ************************************** end core crypto ***************************** */


/**
 * Compute the next free channel tunnel number for this tunnel.
 *
 * @param t the tunnel
 * @return unused number that can uniquely identify a channel in the tunnel
 */
static struct GNUNET_CADET_ChannelTunnelNumber
get_next_free_ctn (struct CadetTunnel *t)
{
#define HIGH_BIT 0x8000000
  struct GNUNET_CADET_ChannelTunnelNumber ret;
  uint32_t ctn;
  int cmp;
  uint32_t highbit;

  cmp = GNUNET_memcmp (&my_full_id,
                       GCP_get_id (GCT_get_destination (t)));
  if (0 < cmp)
    highbit = HIGH_BIT;
  else if (0 > cmp)
    highbit = 0;
  else
    GNUNET_assert (0); // loopback must never go here!
  ctn = ntohl (t->next_ctn.cn);
  while (NULL !=
         GNUNET_CONTAINER_multihashmap32_get (t->channels,
                                              ctn | highbit))
  {
    ctn = ((ctn + 1) & (~HIGH_BIT));
  }
  t->next_ctn.cn = htonl ((ctn + 1) & (~HIGH_BIT));
  ret.cn = htonl (ctn | highbit);
  return ret;
}


/**
 * Add a channel to a tunnel, and notify channel that we are ready
 * for transmission if we are already up.  Otherwise that notification
 * will be done later in #notify_tunnel_up_cb().
 *
 * @param t Tunnel.
 * @param ch Channel
 * @return unique number identifying @a ch within @a t
 */
struct GNUNET_CADET_ChannelTunnelNumber
GCT_add_channel (struct CadetTunnel *t,
                 struct CadetChannel *ch)
{
  struct GNUNET_CADET_ChannelTunnelNumber ctn;

  ctn = get_next_free_ctn (t);
  if (NULL != t->destroy_task)
  {
    GNUNET_SCHEDULER_cancel (t->destroy_task);
    t->destroy_task = NULL;
  }
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap32_put (t->channels,
                                                      ntohl (ctn.cn),
                                                      ch,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding %s to %s with state %d\n",
       GCCH_2s (ch),
       GCT_2s (t),
       t->estate);
  switch (t->estate)
  {
  case CADET_TUNNEL_KEY_UNINITIALIZED:
    /* waiting for connection to start KX */
    break;

  case CADET_TUNNEL_KEY_AX_RECV:
  case CADET_TUNNEL_KEY_AX_SENT:
  case CADET_TUNNEL_KEY_AX_SENT_AND_RECV:
    /* we're currently waiting for KX to complete */
    break;

  case CADET_TUNNEL_KEY_AX_AUTH_SENT:
    /* waiting for OTHER peer to send us data,
       we might need to prompt more aggressively! */
    if (NULL == t->kx_task)
      t->kx_task
        = GNUNET_SCHEDULER_add_at (t->next_kx_attempt,
                                   &retry_kx,
                                   t);
    break;

  case CADET_TUNNEL_KEY_OK:
    /* We are ready. Tell the new channel that we are up. */
    GCCH_tunnel_up (ch);
    break;
  }
  return ctn;
}


/**
 * We lost a connection, remove it from our list and clean up
 * the connection object itself.
 *
 * @param ct binding of connection to tunnel of the connection that was lost.
 */
void
GCT_connection_lost (struct CadetTConnection *ct)
{
  struct CadetTunnel *t = ct->t;

  if (GNUNET_YES == ct->is_ready)
  {
    GNUNET_CONTAINER_DLL_remove (t->connection_ready_head,
                                 t->connection_ready_tail,
                                 ct);
    t->num_ready_connections--;
  }
  else
  {
    GNUNET_CONTAINER_DLL_remove (t->connection_busy_head,
                                 t->connection_busy_tail,
                                 ct);
    t->num_busy_connections--;
  }
  GNUNET_free (ct);
}


/**
 * Clean up connection @a ct of a tunnel.
 *
 * @param cls the `struct CadetTunnel`
 * @param ct connection to clean up
 */
static void
destroy_t_connection (void *cls,
                      struct CadetTConnection *ct)
{
  struct CadetTunnel *t = cls;
  struct CadetConnection *cc = ct->cc;

  GNUNET_assert (ct->t == t);
  GCT_connection_lost (ct);
  GCC_destroy_without_tunnel (cc);
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
  struct CadetTunnelQueueEntry *tq;

  t->destroy_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Destroying idle %s\n",
       GCT_2s (t));
  GNUNET_assert (0 == GCT_count_channels (t));
  GCT_iterate_connections (t,
                           &destroy_t_connection,
                           t);
  GNUNET_assert (NULL == t->connection_ready_head);
  GNUNET_assert (NULL == t->connection_busy_head);
  while (NULL != (tq = t->tq_head))
  {
    if (NULL != tq->cont)
      tq->cont (tq->cont_cls,
                NULL);
    GCT_send_cancel (tq);
  }
  GCP_drop_tunnel (t->destination,
                   t);
  GNUNET_CONTAINER_multihashmap32_destroy (t->channels);
  if (NULL != t->maintain_connections_task)
  {
    GNUNET_SCHEDULER_cancel (t->maintain_connections_task);
    t->maintain_connections_task = NULL;
  }
  if (NULL != t->send_task)
  {
    GNUNET_SCHEDULER_cancel (t->send_task);
    t->send_task = NULL;
  }
  if (NULL != t->kx_task)
  {
    GNUNET_SCHEDULER_cancel (t->kx_task);
    t->kx_task = NULL;
  }
  GNUNET_MST_destroy (t->mst);
  GNUNET_MQ_destroy (t->mq);
  if (NULL != t->unverified_ax)
  {
    cleanup_ax (t->unverified_ax);
    GNUNET_free (t->unverified_ax);
  }
  cleanup_ax (&t->ax);
  GNUNET_assert (NULL == t->destroy_task);
  GNUNET_free (t);
}


/**
 * Remove a channel from a tunnel.
 *
 * @param t Tunnel.
 * @param ch Channel
 * @param ctn unique number identifying @a ch within @a t
 */
void
GCT_remove_channel (struct CadetTunnel *t,
                    struct CadetChannel *ch,
                    struct GNUNET_CADET_ChannelTunnelNumber ctn)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Removing %s from %s\n",
       GCCH_2s (ch),
       GCT_2s (t));
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap32_remove (t->channels,
                                                         ntohl (ctn.cn),
                                                         ch));
  if ((0 ==
       GCT_count_channels (t)) &&
      (NULL == t->destroy_task))
  {
    t->destroy_task
      = GNUNET_SCHEDULER_add_delayed (IDLE_DESTROY_DELAY,
                                      &destroy_tunnel,
                                      t);
  }
}


/**
 * Destroy remaining channels during shutdown.
 *
 * @param cls the `struct CadetTunnel` of the channel
 * @param key key of the channel
 * @param value the `struct CadetChannel`
 * @return #GNUNET_OK (continue to iterate)
 */
static int
destroy_remaining_channels (void *cls,
                            uint32_t key,
                            void *value)
{
  struct CadetChannel *ch = value;

  GCCH_handle_remote_destroy (ch,
                              NULL);
  return GNUNET_OK;
}


/**
 * Destroys the tunnel @a t now, without delay. Used during shutdown.
 *
 * @param t tunnel to destroy
 */
void
GCT_destroy_tunnel_now (struct CadetTunnel *t)
{
  GNUNET_assert (GNUNET_YES == shutting_down);
  GNUNET_CONTAINER_multihashmap32_iterate (t->channels,
                                           &destroy_remaining_channels,
                                           t);
  GNUNET_assert (0 ==
                 GCT_count_channels (t));
  if (NULL != t->destroy_task)
  {
    GNUNET_SCHEDULER_cancel (t->destroy_task);
    t->destroy_task = NULL;
  }
  destroy_tunnel (t);
}


/**
 * Send normal payload from queue in @a t via connection @a ct.
 * Does nothing if our payload queue is empty.
 *
 * @param t tunnel to send data from
 * @param ct connection to use for transmission (is ready)
 */
static void
try_send_normal_payload (struct CadetTunnel *t,
                         struct CadetTConnection *ct)
{
  struct CadetTunnelQueueEntry *tq;

  GNUNET_assert (GNUNET_YES == ct->is_ready);
  tq = t->tq_head;
  if (NULL == tq)
  {
    /* no messages pending right now */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Not sending payload of %s on ready %s (nothing pending)\n",
         GCT_2s (t),
         GCC_2s (ct->cc));
    return;
  }
  /* ready to send message 'tq' on tunnel 'ct' */
  GNUNET_assert (t == tq->t);
  GNUNET_CONTAINER_DLL_remove (t->tq_head,
                               t->tq_tail,
                               tq);
  if (NULL != tq->cid)
    *tq->cid = *GCC_get_id (ct->cc);
  mark_connection_unready (ct);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending payload of %s on %s\n",
       GCT_2s (t),
       GCC_2s (ct->cc));
  GCC_transmit (ct->cc,
                tq->env);
  if (NULL != tq->cont)
    tq->cont (tq->cont_cls,
              GCC_get_id (ct->cc));
  GNUNET_free (tq);
}


/**
 * A connection is @a is_ready for transmission.  Looks at our message
 * queue and if there is a message, sends it out via the connection.
 *
 * @param cls the `struct CadetTConnection` that is @a is_ready
 * @param is_ready #GNUNET_YES if connection are now ready,
 *                 #GNUNET_NO if connection are no longer ready
 */
static void
connection_ready_cb (void *cls,
                     int is_ready)
{
  struct CadetTConnection *ct = cls;
  struct CadetTunnel *t = ct->t;

  if (GNUNET_NO == is_ready)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s no longer ready for %s\n",
         GCC_2s (ct->cc),
         GCT_2s (t));
    mark_connection_unready (ct);
    return;
  }
  GNUNET_assert (GNUNET_NO == ct->is_ready);
  GNUNET_CONTAINER_DLL_remove (t->connection_busy_head,
                               t->connection_busy_tail,
                               ct);
  GNUNET_assert (0 < t->num_busy_connections);
  t->num_busy_connections--;
  ct->is_ready = GNUNET_YES;
  GNUNET_CONTAINER_DLL_insert_tail (t->connection_ready_head,
                                    t->connection_ready_tail,
                                    ct);
  t->num_ready_connections++;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s now ready for %s in state %s\n",
       GCC_2s (ct->cc),
       GCT_2s (t),
       estate2s (t->estate));
  switch (t->estate)
  {
  case CADET_TUNNEL_KEY_UNINITIALIZED:
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Do not begin KX for %s if WE have no channels waiting. Retrying after %d\n",
         GCT_2s (t),
         GNUNET_TIME_absolute_get_remaining (t->next_kx_attempt).rel_value_us);
    /* Do not begin KX if WE have no channels waiting! */
    if (0 != GNUNET_TIME_absolute_get_remaining (
          t->next_kx_attempt).rel_value_us)
      return;   /* wait for timeout before retrying */
    /* We are uninitialized, just transmit immediately,
       without undue delay. */

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Why for %s \n",
         GCT_2s (t));

    if (NULL != t->kx_task)
    {
      GNUNET_SCHEDULER_cancel (t->kx_task);
      t->kx_task = NULL;
    }
    send_kx (t,
             ct,
             &t->ax);
    if ((0 ==
         GCT_count_channels (t)) &&
        (NULL == t->destroy_task))
    {
      t->destroy_task
        = GNUNET_SCHEDULER_add_delayed (IDLE_DESTROY_DELAY,
                                        &destroy_tunnel,
                                        t);
    }
    break;

  case CADET_TUNNEL_KEY_AX_RECV:
  case CADET_TUNNEL_KEY_AX_SENT:
  case CADET_TUNNEL_KEY_AX_SENT_AND_RECV:
  case CADET_TUNNEL_KEY_AX_AUTH_SENT:
    /* we're currently waiting for KX to complete, schedule job */
    if (NULL == t->kx_task)
      t->kx_task
        = GNUNET_SCHEDULER_add_at (t->next_kx_attempt,
                                   &retry_kx,
                                   t);
    break;

  case CADET_TUNNEL_KEY_OK:
    if (GNUNET_YES == t->kx_auth_requested)
    {
      if (0 != GNUNET_TIME_absolute_get_remaining (
            t->next_kx_attempt).rel_value_us)
        return;     /* wait for timeout */
      if (NULL != t->kx_task)
      {
        GNUNET_SCHEDULER_cancel (t->kx_task);
        t->kx_task = NULL;
      }
      send_kx_auth (t,
                    ct,
                    &t->ax,
                    GNUNET_NO);
      return;
    }
    try_send_normal_payload (t,
                             ct);
    break;
  }
}


/**
 * Called when either we have a new connection, or a new message in the
 * queue, or some existing connection has transmission capacity.  Looks
 * at our message queue and if there is a message, picks a connection
 * to send it on.
 *
 * @param cls the `struct CadetTunnel` to process messages on
 */
static void
trigger_transmissions (void *cls)
{
  struct CadetTunnel *t = cls;
  struct CadetTConnection *ct;

  t->send_task = NULL;
  if (NULL == t->tq_head)
    return; /* no messages pending right now */
  ct = get_ready_connection (t);
  if (NULL == ct)
    return; /* no connections ready */
  try_send_normal_payload (t,
                           ct);
}


/**
 * Closure for #evaluate_connection. Used to assemble summary information
 * about the existing connections so we can evaluate a new path.
 */
struct EvaluationSummary
{
  /**
   * Minimum length of any of our connections, `UINT_MAX` if we have none.
   */
  unsigned int min_length;

  /**
   * Maximum length of any of our connections, 0 if we have none.
   */
  unsigned int max_length;

  /**
   * Minimum desirability of any of our connections, UINT64_MAX if we have none.
   */
  GNUNET_CONTAINER_HeapCostType min_desire;

  /**
   * Maximum desirability of any of our connections, 0 if we have none.
   */
  GNUNET_CONTAINER_HeapCostType max_desire;

  /**
   * Path we are comparing against for #evaluate_connection, can be NULL.
   */
  struct CadetPeerPath *path;

  /**
   * Connection deemed the "worst" so far encountered by #evaluate_connection,
   * NULL if we did not yet encounter any connections.
   */
  struct CadetTConnection *worst;

  /**
   * Numeric score of @e worst, only set if @e worst is non-NULL.
   */
  double worst_score;

  /**
   * Set to #GNUNET_YES if we have a connection over @e path already.
   */
  int duplicate;
};


/**
 * Evaluate a connection, updating our summary information in @a cls about
 * what kinds of connections we have.
 *
 * @param cls the `struct EvaluationSummary *` to update
 * @param ct a connection to include in the summary
 */
static void
evaluate_connection (void *cls,
                     struct CadetTConnection *ct)
{
  struct EvaluationSummary *es = cls;
  struct CadetConnection *cc = ct->cc;
  unsigned int ct_length;
  struct CadetPeerPath *ps;
  const struct CadetConnectionMetrics *metrics;
  GNUNET_CONTAINER_HeapCostType ct_desirability;
  struct GNUNET_TIME_Relative uptime;
  struct GNUNET_TIME_Relative last_use;
  double score;
  double success_rate;

  ps = GCC_get_path (cc,
                     &ct_length);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Evaluating path %s of existing %s\n",
       GCPP_2s (ps),
       GCC_2s (cc));
  if (ps == es->path)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Ignoring duplicate path %s.\n",
         GCPP_2s (es->path));
    es->duplicate = GNUNET_YES;
    return;
  }
  if (NULL != es->path)
  {
    int duplicate = GNUNET_YES;

    for (unsigned int i = 0; i < ct_length; i++)
    {
      GNUNET_assert (GCPP_get_length (es->path) > i);
      if (GCPP_get_peer_at_offset (es->path,
                                   i) !=
          GCPP_get_peer_at_offset (ps,
                                   i))
      {
        duplicate = GNUNET_NO;
        break;
      }
    }
    if (GNUNET_YES == duplicate)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Ignoring overlapping path %s.\n",
           GCPP_2s (es->path));
      es->duplicate = GNUNET_YES;
      return;
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Known path %s differs from proposed path\n",
           GCPP_2s (ps));
    }
  }

  ct_desirability = GCPP_get_desirability (ps);
  metrics = GCC_get_metrics (cc);
  uptime = GNUNET_TIME_absolute_get_duration (metrics->age);
  last_use = GNUNET_TIME_absolute_get_duration (metrics->last_use);
  /* We add 1.0 here to avoid division by zero. */
  success_rate = (metrics->num_acked_transmissions + 1.0)
                 / (metrics->num_successes + 1.0);
  score
    = ct_desirability
      + 100.0 / (1.0 + ct_length) /* longer paths = better */
      + sqrt (uptime.rel_value_us / 60000000LL) /* larger uptime = better */
      - last_use.rel_value_us / 1000L;        /* longer idle = worse */
  score *= success_rate;        /* weigh overall by success rate */

  if ((NULL == es->worst) ||
      (score < es->worst_score))
  {
    es->worst = ct;
    es->worst_score = score;
  }
  es->min_length = GNUNET_MIN (es->min_length,
                               ct_length);
  es->max_length = GNUNET_MAX (es->max_length,
                               ct_length);
  es->min_desire = GNUNET_MIN (es->min_desire,
                               ct_desirability);
  es->max_desire = GNUNET_MAX (es->max_desire,
                               ct_desirability);
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
  struct EvaluationSummary es;
  struct CadetTConnection *ct;

  GNUNET_assert (off < GCPP_get_length (path));
  GNUNET_assert (GCPP_get_peer_at_offset (path,
                                          off) == t->destination);
  es.min_length = UINT_MAX;
  es.max_length = 0;
  es.max_desire = 0;
  es.min_desire = UINT64_MAX;
  es.path = path;
  es.duplicate = GNUNET_NO;
  es.worst = NULL;

  /* Compute evaluation summary over existing connections. */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Evaluating proposed path %s for target %s\n",
       GCPP_2s (path),
       GCT_2s (t));
  /* FIXME: suspect this does not ACTUALLY iterate
     over all existing paths, otherwise dup detection
     should work!!! */
  GCT_iterate_connections (t,
                           &evaluate_connection,
                           &es);
  if (GNUNET_YES == es.duplicate)
    return GNUNET_YES;

  /* FIXME: not sure we should really just count
     'num_connections' here, as they may all have
     consistently failed to connect. */

  /* We iterate by increasing path length; if we have enough paths and
     this one is more than twice as long than what we are currently
     using, then ignore all of these super-long ones! */
  if ((GCT_count_any_connections (t) > DESIRED_CONNECTIONS_PER_TUNNEL) &&
      (es.min_length * 2 < off) &&
      (es.max_length < off))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Ignoring paths of length %u, they are way too long.\n",
         es.min_length * 2);
    return GNUNET_NO;
  }
  /* If we have enough paths and this one looks no better, ignore it. */
  if ((GCT_count_any_connections (t) >= DESIRED_CONNECTIONS_PER_TUNNEL) &&
      (es.min_length < GCPP_get_length (path)) &&
      (es.min_desire > GCPP_get_desirability (path)) &&
      (es.max_length < off))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
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
                       off,
                       ct,
                       &connection_ready_cb,
                       ct);

  /* FIXME: schedule job to kill connection (and path?)  if it takes
     too long to get ready! (And track performance data on how long
     other connections took with the tunnel!)
     => Note: to be done within 'connection'-logic! */
  GNUNET_CONTAINER_DLL_insert (t->connection_busy_head,
                               t->connection_busy_tail,
                               ct);
  t->num_busy_connections++;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Found interesting path %s for %s, created %s\n",
       GCPP_2s (path),
       GCT_2s (t),
       GCC_2s (ct->cc));
  return GNUNET_YES;
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
  struct GNUNET_TIME_Relative delay;
  struct EvaluationSummary es;

  t->maintain_connections_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Performing connection maintenance for %s.\n",
       GCT_2s (t));

  es.min_length = UINT_MAX;
  es.max_length = 0;
  es.max_desire = 0;
  es.min_desire = UINT64_MAX;
  es.path = NULL;
  es.worst = NULL;
  es.duplicate = GNUNET_NO;
  GCT_iterate_connections (t,
                           &evaluate_connection,
                           &es);
  if ((NULL != es.worst) &&
      (GCT_count_any_connections (t) > DESIRED_CONNECTIONS_PER_TUNNEL))
  {
    /* Clear out worst-performing connection 'es.worst'. */
    destroy_t_connection (t,
                          es.worst);
  }

  /* Consider additional paths */
  (void) GCP_iterate_paths (t->destination,
                            &consider_path_cb,
                            t);

  /* FIXME: calculate when to try again based on how well we are doing;
     in particular, if we have to few connections, we might be able
     to do without this (as PATHS should tell us whenever a new path
     is available instantly; however, need to make sure this job is
     restarted after that happens).
     Furthermore, if the paths we do know are in a reasonably narrow
     quality band and are plentyful, we might also consider us stabilized
     and then reduce the frequency accordingly.  */delay = GNUNET_TIME_UNIT_MINUTES;
  t->maintain_connections_task
    = GNUNET_SCHEDULER_add_delayed (delay,
                                    &maintain_connections_cb,
                                    t);
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
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Considering %s for %s (offset %u)\n",
       GCPP_2s (p),
       GCT_2s (t),
       off);
  (void) consider_path_cb (t,
                           p,
                           off);
}


/**
 * We got a keepalive. Track in statistics.
 *
 * @param cls the `struct CadetTunnel` for which we decrypted the message
 * @param msg  the message we received on the tunnel
 */
static void
handle_plaintext_keepalive (void *cls,
                            const struct GNUNET_MessageHeader *msg)
{
  struct CadetTunnel *t = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received KEEPALIVE on %s\n",
       GCT_2s (t));
  GNUNET_STATISTICS_update (stats,
                            "# keepalives received",
                            1,
                            GNUNET_NO);
}


/**
 * Check that @a msg is well-formed.
 *
 * @param cls the `struct CadetTunnel` for which we decrypted the message
 * @param msg  the message we received on the tunnel
 * @return #GNUNET_OK (any variable-size payload goes)
 */
static int
check_plaintext_data (void *cls,
                      const struct GNUNET_CADET_ChannelAppDataMessage *msg)
{
  return GNUNET_OK;
}


/**
 * We received payload data for a channel.  Locate the channel
 * and process the data, or return an error if the channel is unknown.
 *
 * @param cls the `struct CadetTunnel` for which we decrypted the message
 * @param msg the message we received on the tunnel
 */
static void
handle_plaintext_data (void *cls,
                       const struct GNUNET_CADET_ChannelAppDataMessage *msg)
{
  struct CadetTunnel *t = cls;
  struct CadetChannel *ch;

  ch = lookup_channel (t,
                       msg->ctn);
  if (NULL == ch)
  {
    /* We don't know about such a channel, might have been destroyed on our
       end in the meantime, or never existed. Send back a DESTROY. */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received %u bytes of application data for unknown channel %u, sending DESTROY\n",
         (unsigned int) (ntohs (msg->header.size) - sizeof(*msg)),
         ntohl (msg->ctn.cn));
    GCT_send_channel_destroy (t,
                              msg->ctn);
    return;
  }
  GCCH_handle_channel_plaintext_data (ch,
                                      GCC_get_id (t->current_ct->cc),
                                      msg);
}


/**
 * We received an acknowledgement for data we sent on a channel.
 * Locate the channel and process it, or return an error if the
 * channel is unknown.
 *
 * @param cls the `struct CadetTunnel` for which we decrypted the message
 * @param ack the message we received on the tunnel
 */
static void
handle_plaintext_data_ack (void *cls,
                           const struct GNUNET_CADET_ChannelDataAckMessage *ack)
{
  struct CadetTunnel *t = cls;
  struct CadetChannel *ch;

  ch = lookup_channel (t,
                       ack->ctn);
  if (NULL == ch)
  {
    /* We don't know about such a channel, might have been destroyed on our
       end in the meantime, or never existed. Send back a DESTROY. */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received DATA_ACK for unknown channel %u, sending DESTROY\n",
         ntohl (ack->ctn.cn));
    GCT_send_channel_destroy (t,
                              ack->ctn);
    return;
  }
  GCCH_handle_channel_plaintext_data_ack (ch,
                                          GCC_get_id (t->current_ct->cc),
                                          ack);
}


/**
 * We have received a request to open a channel to a port from
 * another peer.  Creates the incoming channel.
 *
 * @param cls the `struct CadetTunnel` for which we decrypted the message
 * @param copen the message we received on the tunnel
 */
static void
handle_plaintext_channel_open (void *cls,
                               const struct
                               GNUNET_CADET_ChannelOpenMessage *copen)
{
  struct CadetTunnel *t = cls;
  struct CadetChannel *ch;

  ch = GNUNET_CONTAINER_multihashmap32_get (t->channels,
                                            ntohl (copen->ctn.cn));
  if (NULL != ch)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received duplicate channel CHANNEL_OPEN on h_port %s from %s (%s), resending ACK\n",
         GNUNET_h2s (&copen->h_port),
         GCT_2s (t),
         GCCH_2s (ch));
    GCCH_handle_duplicate_open (ch,
                                GCC_get_id (t->current_ct->cc));
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received CHANNEL_OPEN on h_port %s from %s\n",
       GNUNET_h2s (&copen->h_port),
       GCT_2s (t));
  ch = GCCH_channel_incoming_new (t,
                                  copen->ctn,
                                  &copen->h_port,
                                  ntohl (copen->opt));
  if (NULL != t->destroy_task)
  {
    GNUNET_SCHEDULER_cancel (t->destroy_task);
    t->destroy_task = NULL;
  }
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap32_put (t->channels,
                                                      ntohl (copen->ctn.cn),
                                                      ch,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
}


/**
 * Send a DESTROY message via the tunnel.
 *
 * @param t the tunnel to transmit over
 * @param ctn ID of the channel to destroy
 */
void
GCT_send_channel_destroy (struct CadetTunnel *t,
                          struct GNUNET_CADET_ChannelTunnelNumber ctn)
{
  struct GNUNET_CADET_ChannelDestroyMessage msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending DESTORY message for channel ID %u\n",
       ntohl (ctn.cn));
  msg.header.size = htons (sizeof(msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY);
  msg.reserved = htonl (0);
  msg.ctn = ctn;
  GCT_send (t,
            &msg.header,
            NULL,
            NULL,
            &ctn);
}


/**
 * We have received confirmation from the target peer that the
 * given channel could be established (the port is open).
 * Tell the client.
 *
 * @param cls the `struct CadetTunnel` for which we decrypted the message
 * @param cm the message we received on the tunnel
 */
static void
handle_plaintext_channel_open_ack (void *cls,
                                   const struct
                                   GNUNET_CADET_ChannelOpenAckMessage *cm)
{
  struct CadetTunnel *t = cls;
  struct CadetChannel *ch;

  ch = lookup_channel (t,
                       cm->ctn);
  if (NULL == ch)
  {
    /* We don't know about such a channel, might have been destroyed on our
       end in the meantime, or never existed. Send back a DESTROY. */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received channel OPEN_ACK for unknown channel %u, sending DESTROY\n",
         ntohl (cm->ctn.cn));
    GCT_send_channel_destroy (t,
                              cm->ctn);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received channel OPEN_ACK on channel %s from %s\n",
       GCCH_2s (ch),
       GCT_2s (t));
  GCCH_handle_channel_open_ack (ch,
                                GCC_get_id (t->current_ct->cc),
                                &cm->port);
}


/**
 * We received a message saying that a channel should be destroyed.
 * Pass it on to the correct channel.
 *
 * @param cls the `struct CadetTunnel` for which we decrypted the message
 * @param cm the message we received on the tunnel
 */
static void
handle_plaintext_channel_destroy (void *cls,
                                  const struct
                                  GNUNET_CADET_ChannelDestroyMessage *cm)
{
  struct CadetTunnel *t = cls;
  struct CadetChannel *ch;

  ch = lookup_channel (t,
                       cm->ctn);
  if (NULL == ch)
  {
    /* We don't know about such a channel, might have been destroyed on our
       end in the meantime, or never existed. */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received channel DESTORY for unknown channel %u. Ignoring.\n",
         ntohl (cm->ctn.cn));
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received channel DESTROY on %s from %s\n",
       GCCH_2s (ch),
       GCT_2s (t));
  GCCH_handle_remote_destroy (ch,
                              GCC_get_id (t->current_ct->cc));
}


/**
 * Handles a message we decrypted, by injecting it into
 * our message queue (which will do the dispatching).
 *
 * @param cls the `struct CadetTunnel` that got the message
 * @param msg the message
 * @return #GNUNET_OK on success (always)
 *    #GNUNET_NO to stop further processing (no error)
 *    #GNUNET_SYSERR to stop further processing with error
 */
static int
handle_decrypted (void *cls,
                  const struct GNUNET_MessageHeader *msg)
{
  struct CadetTunnel *t = cls;

  GNUNET_assert (NULL != t->current_ct);
  GNUNET_MQ_inject_message (t->mq,
                            msg);
  return GNUNET_OK;
}


/**
 * Function called if we had an error processing
 * an incoming decrypted message.
 *
 * @param cls the `struct CadetTunnel`
 * @param error error code
 */
static void
decrypted_error_cb (void *cls,
                    enum GNUNET_MQ_Error error)
{
  GNUNET_break_op (0);
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
  struct CadetTunnel *t = GNUNET_new (struct CadetTunnel);
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (plaintext_keepalive,
                             GNUNET_MESSAGE_TYPE_CADET_CHANNEL_KEEPALIVE,
                             struct GNUNET_MessageHeader,
                             t),
    GNUNET_MQ_hd_var_size (plaintext_data,
                           GNUNET_MESSAGE_TYPE_CADET_CHANNEL_APP_DATA,
                           struct GNUNET_CADET_ChannelAppDataMessage,
                           t),
    GNUNET_MQ_hd_fixed_size (plaintext_data_ack,
                             GNUNET_MESSAGE_TYPE_CADET_CHANNEL_APP_DATA_ACK,
                             struct GNUNET_CADET_ChannelDataAckMessage,
                             t),
    GNUNET_MQ_hd_fixed_size (plaintext_channel_open,
                             GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN,
                             struct GNUNET_CADET_ChannelOpenMessage,
                             t),
    GNUNET_MQ_hd_fixed_size (plaintext_channel_open_ack,
                             GNUNET_MESSAGE_TYPE_CADET_CHANNEL_OPEN_ACK,
                             struct GNUNET_CADET_ChannelOpenAckMessage,
                             t),
    GNUNET_MQ_hd_fixed_size (plaintext_channel_destroy,
                             GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY,
                             struct GNUNET_CADET_ChannelDestroyMessage,
                             t),
    GNUNET_MQ_handler_end ()
  };

  t->kx_retry_delay = INITIAL_KX_RETRY_DELAY;
  new_ephemeral (&t->ax);
  GNUNET_CRYPTO_ecdhe_key_create (&t->ax.kx_0);
  t->destination = destination;
  t->channels = GNUNET_CONTAINER_multihashmap32_create (8);
  t->maintain_connections_task
    = GNUNET_SCHEDULER_add_now (&maintain_connections_cb,
                                t);
  t->mq = GNUNET_MQ_queue_for_callbacks (NULL,
                                         NULL,
                                         NULL,
                                         NULL,
                                         handlers,
                                         &decrypted_error_cb,
                                         t);
  t->mst = GNUNET_MST_create (&handle_decrypted,
                              t);
  return t;
}


/**
 * Add a @a connection to the @a tunnel.
 *
 * @param t a tunnel
 * @param cid connection identifer to use for the connection
 * @param options options for the connection
 * @param path path to use for the connection
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR on failure (duplicate connection)
 */
int
GCT_add_inbound_connection (struct CadetTunnel *t,
                            const struct
                            GNUNET_CADET_ConnectionTunnelIdentifier *cid,
                            struct CadetPeerPath *path)
{
  struct CadetTConnection *ct;

  ct = GNUNET_new (struct CadetTConnection);
  ct->created = GNUNET_TIME_absolute_get ();
  ct->t = t;
  ct->cc = GCC_create_inbound (t->destination,
                               path,
                               ct,
                               cid,
                               &connection_ready_cb,
                               ct);
  if (NULL == ct->cc)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "%s refused inbound %s (duplicate)\n",
         GCT_2s (t),
         GCC_2s (ct->cc));
    GNUNET_free (ct);
    return GNUNET_SYSERR;
  }
  /* FIXME: schedule job to kill connection (and path?)  if it takes
     too long to get ready! (And track performance data on how long
     other connections took with the tunnel!)
     => Note: to be done within 'connection'-logic! */
  GNUNET_CONTAINER_DLL_insert (t->connection_busy_head,
                               t->connection_busy_tail,
                               ct);
  t->num_busy_connections++;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s has new %s\n",
       GCT_2s (t),
       GCC_2s (ct->cc));
  return GNUNET_OK;
}


/**
 * Handle encrypted message.
 *
 * @param ct connection/tunnel combo that received encrypted message
 * @param msg the encrypted message to decrypt
 */
void
GCT_handle_encrypted (struct CadetTConnection *ct,
                      const struct GNUNET_CADET_TunnelEncryptedMessage *msg)
{
  struct CadetTunnel *t = ct->t;
  uint16_t size = ntohs (msg->header.size);
  char cbuf [size] GNUNET_ALIGN;
  ssize_t decrypted_size;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s received %u bytes of encrypted data in state %d\n",
       GCT_2s (t),
       (unsigned int) size,
       t->estate);

  switch (t->estate)
  {
  case CADET_TUNNEL_KEY_UNINITIALIZED:
  case CADET_TUNNEL_KEY_AX_RECV:
    /* We did not even SEND our KX, how can the other peer
       send us encrypted data? Must have been that we went
       down and the other peer still things we are up.
       Let's send it KX back. */
    GNUNET_STATISTICS_update (stats,
                              "# received encrypted without any KX",
                              1,
                              GNUNET_NO);
    if (NULL != t->kx_task)
    {
      GNUNET_SCHEDULER_cancel (t->kx_task);
      t->kx_task = NULL;
    }
    send_kx (t,
             ct,
             &t->ax);
    return;

  case CADET_TUNNEL_KEY_AX_SENT_AND_RECV:
    /* We send KX, and other peer send KX to us at the same time.
       Neither KX is AUTH'ed, so let's try KX_AUTH this time. */
    GNUNET_STATISTICS_update (stats,
                              "# received encrypted without KX_AUTH",
                              1,
                              GNUNET_NO);
    if (NULL != t->kx_task)
    {
      GNUNET_SCHEDULER_cancel (t->kx_task);
      t->kx_task = NULL;
    }
    send_kx_auth (t,
                  ct,
                  &t->ax,
                  GNUNET_YES);
    return;

  case CADET_TUNNEL_KEY_AX_SENT:
    /* We did not get the KX of the other peer, but that
       might have been lost.  Send our KX again immediately. */
    GNUNET_STATISTICS_update (stats,
                              "# received encrypted without KX",
                              1,
                              GNUNET_NO);
    if (NULL != t->kx_task)
    {
      GNUNET_SCHEDULER_cancel (t->kx_task);
      t->kx_task = NULL;
    }
    send_kx (t,
             ct,
             &t->ax);
    return;

  case CADET_TUNNEL_KEY_AX_AUTH_SENT:
  /* Great, first payload, we might graduate to OK! */
  case CADET_TUNNEL_KEY_OK:
    /* We are up and running, all good. */
    break;
  }

  decrypted_size = -1;
  if (CADET_TUNNEL_KEY_OK == t->estate)
  {
    /* We have well-established key material available,
       try that. (This is the common case.) */
    decrypted_size = t_ax_decrypt_and_validate (&t->ax,
                                                cbuf,
                                                msg,
                                                size);
  }

  if ((-1 == decrypted_size) &&
      (NULL != t->unverified_ax))
  {
    /* We have un-authenticated KX material available. We should try
       this as a back-up option, in case the sender crashed and
       switched keys. */
    decrypted_size = t_ax_decrypt_and_validate (t->unverified_ax,
                                                cbuf,
                                                msg,
                                                size);
    if (-1 != decrypted_size)
    {
      /* It worked! Treat this as authentication of the AX data! */
      cleanup_ax (&t->ax);
      t->ax = *t->unverified_ax;
      GNUNET_free (t->unverified_ax);
      t->unverified_ax = NULL;
    }
    if (CADET_TUNNEL_KEY_AX_AUTH_SENT == t->estate)
    {
      /* First time it worked, move tunnel into production! */
      GCT_change_estate (t,
                         CADET_TUNNEL_KEY_OK);
      if (NULL != t->send_task)
        GNUNET_SCHEDULER_cancel (t->send_task);
      t->send_task = GNUNET_SCHEDULER_add_now (&trigger_transmissions,
                                               t);
    }
  }
  if (NULL != t->unverified_ax)
  {
    /* We had unverified KX material that was useless; so increment
       counter and eventually move to ignore it.  Note that we even do
       this increment if we successfully decrypted with the old KX
       material and thus didn't even both with the new one.  This is
       the ideal case, as a malicious injection of bogus KX data
       basically only causes us to increment a counter a few times. */t->unverified_attempts++;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Failed to decrypt message with unverified KX data %u times\n",
         t->unverified_attempts);
    if (t->unverified_attempts > MAX_UNVERIFIED_ATTEMPTS)
    {
      cleanup_ax (t->unverified_ax);
      GNUNET_free (t->unverified_ax);
      t->unverified_ax = NULL;
    }
  }

  if (-1 == decrypted_size)
  {
    /* Decryption failed for good, complain. */
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "%s failed to decrypt and validate encrypted data, retrying KX\n",
         GCT_2s (t));
    GNUNET_STATISTICS_update (stats,
                              "# unable to decrypt",
                              1,
                              GNUNET_NO);
    if (NULL != t->kx_task)
    {
      GNUNET_SCHEDULER_cancel (t->kx_task);
      t->kx_task = NULL;
    }
    send_kx (t,
             ct,
             &t->ax);
    return;
  }
  GNUNET_STATISTICS_update (stats,
                            "# decrypted bytes",
                            decrypted_size,
                            GNUNET_NO);

  /* The MST will ultimately call #handle_decrypted() on each message. */
  t->current_ct = ct;
  GNUNET_break_op (GNUNET_OK ==
                   GNUNET_MST_from_buffer (t->mst,
                                           cbuf,
                                           decrypted_size,
                                           GNUNET_YES,
                                           GNUNET_NO));
  t->current_ct = NULL;
}


/**
 * Sends an already built message on a tunnel, encrypting it and
 * choosing the best connection if not provided.
 *
 * @param message Message to send. Function modifies it.
 * @param t Tunnel on which this message is transmitted.
 * @param cont Continuation to call once message is really sent.
 * @param cont_cls Closure for @c cont.
 * @param The ID of the channel we are using for sending.
 * @return Handle to cancel message
 */
struct CadetTunnelQueueEntry *
GCT_send (struct CadetTunnel *t,
          const struct GNUNET_MessageHeader *message,
          GCT_SendContinuation cont,
          void *cont_cls,
          struct GNUNET_CADET_ChannelTunnelNumber *ctn)
{
  struct CadetTunnelQueueEntry *tq;
  uint16_t payload_size;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_TunnelEncryptedMessage *ax_msg;
  struct CadetChannel *ch;

  if (NULL != ctn)
  {
    ch = lookup_channel (t,
                         *ctn);
    if ((NULL != ch)&& GCCH_is_type_to_drop (ch, message))
    {
      GNUNET_break (0);
      return NULL;
    }
  }

  if (CADET_TUNNEL_KEY_OK != t->estate)
  {
    GNUNET_break (0);
    return NULL;
  }
  payload_size = ntohs (message->size);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Encrypting %u bytes for %s\n",
       (unsigned int) payload_size,
       GCT_2s (t));
  env = GNUNET_MQ_msg_extra (ax_msg,
                             payload_size,
                             GNUNET_MESSAGE_TYPE_CADET_TUNNEL_ENCRYPTED);
  t_ax_encrypt (&t->ax,
                &ax_msg[1],
                message,
                payload_size);
  GNUNET_STATISTICS_update (stats,
                            "# encrypted bytes",
                            payload_size,
                            GNUNET_NO);
  ax_msg->ax_header.Ns = htonl (t->ax.Ns++);
  ax_msg->ax_header.PNs = htonl (t->ax.PNs);
  /* FIXME: we should do this once, not once per message;
     this is a point multiplication, and DHRs does not
     change all the time. */
  GNUNET_CRYPTO_ecdhe_key_get_public (&t->ax.DHRs,
                                      &ax_msg->ax_header.DHRs);
  t_h_encrypt (&t->ax,
               ax_msg);
  t_hmac (&ax_msg->ax_header,
          sizeof(struct GNUNET_CADET_AxHeader) + payload_size,
          0,
          &t->ax.HKs,
          &ax_msg->hmac);

  tq = GNUNET_malloc (sizeof(*tq));
  tq->t = t;
  tq->env = env;
  tq->cid = &ax_msg->cid; /* will initialize 'ax_msg->cid' once we know the connection */
  tq->cont = cont;
  tq->cont_cls = cont_cls;
  GNUNET_CONTAINER_DLL_insert_tail (t->tq_head,
                                    t->tq_tail,
                                    tq);
  if (NULL != t->send_task)
    GNUNET_SCHEDULER_cancel (t->send_task);
  t->send_task
    = GNUNET_SCHEDULER_add_now (&trigger_transmissions,
                                t);
  return tq;
}


/**
 * Cancel a previously sent message while it's in the queue.
 *
 * ONLY can be called before the continuation given to the send
 * function is called. Once the continuation is called, the message is
 * no longer in the queue!
 *
 * @param tq Handle to the queue entry to cancel.
 */
void
GCT_send_cancel (struct CadetTunnelQueueEntry *tq)
{
  struct CadetTunnel *t = tq->t;

  GNUNET_CONTAINER_DLL_remove (t->tq_head,
                               t->tq_tail,
                               tq);
  GNUNET_MQ_discard (tq->env);
  GNUNET_free (tq);
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
  struct CadetTConnection *n;

  for (struct CadetTConnection *ct = t->connection_ready_head;
       NULL != ct;
       ct = n)
  {
    n = ct->next;
    iter (iter_cls,
          ct);
  }
  for (struct CadetTConnection *ct = t->connection_busy_head;
       NULL != ct;
       ct = n)
  {
    n = ct->next;
    iter (iter_cls,
          ct);
  }
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


#define LOG2(level, ...) GNUNET_log_from_nocheck (level, "cadet-tun", \
                                                  __VA_ARGS__)


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
#if ! defined(GNUNET_CULL_LOGGING)
  struct CadetTConnection *iter_c;
  int do_log;

  do_log = GNUNET_get_log_call_status (level & (~GNUNET_ERROR_TYPE_BULK),
                                       "cadet-tun",
                                       __FILE__, __FUNCTION__, __LINE__);
  if (0 == do_log)
    return;

  LOG2 (level,
        "TTT TUNNEL TOWARDS %s in estate %s tq_len: %u #cons: %u\n",
        GCT_2s (t),
        estate2s (t->estate),
        t->tq_len,
        GCT_count_any_connections (t));
  LOG2 (level,
        "TTT channels:\n");
  GNUNET_CONTAINER_multihashmap32_iterate (t->channels,
                                           &debug_channel,
                                           &level);
  LOG2 (level,
        "TTT connections:\n");
  for (iter_c = t->connection_ready_head; NULL != iter_c; iter_c = iter_c->next)
    GCC_debug (iter_c->cc,
               level);
  for (iter_c = t->connection_busy_head; NULL != iter_c; iter_c = iter_c->next)
    GCC_debug (iter_c->cc,
               level);

  LOG2 (level,
        "TTT TUNNEL END\n");
#endif
}


/* end of gnunet-service-cadet_tunnels.c */
