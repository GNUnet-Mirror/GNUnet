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
 * - KX:
 *   + clean up KX logic, including adding sender authentication
 *   + implement rekeying
 *   + check KX estate machine -- make sure it is never stuck!
 * - connection management
 *   + properly (evaluate, kill old ones, search for new ones)
 *   + when managing connections, distinguish those that
 *     have (recently) had traffic from those that were
 *     never ready (or not recently)
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_signatures.h"
#include "gnunet-service-cadet-new.h"
#include "cadet_protocol.h"
#include "gnunet-service-cadet-new_channel.h"
#include "gnunet-service-cadet-new_connection.h"
#include "gnunet-service-cadet-new_tunnels.h"
#include "gnunet-service-cadet-new_peer.h"
#include "gnunet-service-cadet-new_paths.h"


#define LOG(level, ...) GNUNET_log_from(level,"cadet-tun",__VA_ARGS__)

/**
 * How often do we try to decrypt payload with unverified key
 * material?  Used to limit CPU increase upon receiving bogus
 * KX.
 */
#define MAX_UNVERIFIED_ATTEMPTS 16

/**
 * How long do we wait until tearing down an idle tunnel?
 */
#define IDLE_DESTROY_DELAY GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 90)

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
  struct GNUNET_CRYPTO_EcdhePrivateKey *kx_0;

  /**
   * ECDH Ratchet key (our private key in the current DH).
   */
  struct GNUNET_CRYPTO_EcdhePrivateKey *DHRs;

  /**
   * ECDH Ratchet key (other peer's public key in the current DH).
   */
  struct GNUNET_CRYPTO_EcdhePublicKey DHRr;

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
  GNUNET_SCHEDULER_TaskCallback cont;

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
   * DLL of connections that are actively used to reach the destination peer.
   */
  struct CadetTConnection *connection_head;

  /**
   * DLL of connections that are actively used to reach the destination peer.
   */
  struct CadetTConnection *connection_tail;

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
   * How long do we wait until we retry the KX?
   */
  struct GNUNET_TIME_Relative kx_retry_delay;

  /**
   * When do we try the next KX?
   */
  struct GNUNET_TIME_Absolute next_kx_attempt;

  /**
   * Number of connections in the @e connection_head DLL.
   */
  unsigned int num_connections;

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
    return "Tunnel(NULL)";
  GNUNET_snprintf (buf,
                   sizeof (buf),
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
    case CADET_TUNNEL_KEY_SENT:
      return "CADET_TUNNEL_KEY_SENT";
    case CADET_TUNNEL_KEY_PING:
      return "CADET_TUNNEL_KEY_PING";
    case CADET_TUNNEL_KEY_OK:
      return "CADET_TUNNEL_KEY_OK";
    default:
      SPRINTF (buf, "%u (UNKNOWN STATE)", es);
      return buf;
  }
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
GCT_count_any_connections (struct CadetTunnel *t)
{
  return t->num_connections;
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
  for (struct CadetTConnection *pos = t->connection_head;
       NULL != pos;
       pos = pos->next)
    if (GNUNET_YES == pos->is_ready)
    {
      if (pos != t->connection_tail)
      {
        /* move 'pos' to the end, so we try other ready connections
           first next time (round-robin, modulo availability) */
        GNUNET_CONTAINER_DLL_remove (t->connection_head,
                                     t->connection_tail,
                                     pos);
        GNUNET_CONTAINER_DLL_insert_tail (t->connection_head,
                                          t->connection_tail,
                                          pos);
      }
      return pos;
    }
  return NULL;
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
  GNUNET_free_non_null (ax->DHRs);
  ax->DHRs = GNUNET_CRYPTO_ecdhe_key_create ();
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
                                 &iv, sizeof (iv),
                                 key, sizeof (*key),
                                 ctx, sizeof (ctx),
                                 NULL);
  /* Two step: GNUNET_ShortHash is only 256 bits,
     GNUNET_HashCode is 512, so we truncate. */
  GNUNET_CRYPTO_hmac (&auth_key,
                      plaintext,
                      size,
                      &hash);
  GNUNET_memcpy (hmac,
                 &hash,
                 sizeof (*hmac));
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
                                 ctx, sizeof (ctx),
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
  GNUNET_CRYPTO_kdf (out, sizeof (*out),
                     ctx, sizeof (ctx),
                     &h, sizeof (h),
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
  if ( (GNUNET_YES == ax->ratchet_allowed) &&
       ( (ratchet_messages <= ax->ratchet_counter) ||
         (0 == GNUNET_TIME_absolute_get_remaining (ax->ratchet_expiration).rel_value_us)) )
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
    GNUNET_CRYPTO_ecc_ecdh (ax->DHRs,
                            &ax->DHRr,
                            &dh);
    t_ax_hmac_hash (&ax->RK,
                    &hmac,
                    &dh,
                    sizeof (dh));
    GNUNET_CRYPTO_kdf (keys, sizeof (keys),
                       ctx, sizeof (ctx),
                       &hmac, sizeof (hmac),
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
      = GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get(),
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
  GNUNET_assert (size >= sizeof (struct GNUNET_MessageHeader));
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
                                              sizeof (struct GNUNET_CADET_AxHeader),
                                              &ax->HKs,
                                              &iv,
                                              &msg->ax_header);
  GNUNET_assert (sizeof (struct GNUNET_CADET_AxHeader) == out_size);
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
                                              sizeof (struct GNUNET_CADET_AxHeader),
                                              &ax->HKr,
                                              &iv,
                                              &dst->ax_header.Ns);
  GNUNET_assert (sizeof (struct GNUNET_CADET_AxHeader) == out_size);
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
  esize = size - sizeof (struct GNUNET_CADET_TunnelEncryptedMessage);

  /* Find a correct Header Key */
  valid_HK = NULL;
  for (key = ax->skipped_head; NULL != key; key = key->next)
  {
    t_hmac (&src->ax_header,
            sizeof (struct GNUNET_CADET_AxHeader) + esize,
            0,
            &key->HK,
            hmac);
    if (0 == memcmp (hmac,
                     &src->hmac,
                     sizeof (*hmac)))
    {
      valid_HK = &key->HK;
      break;
    }
  }
  if (NULL == key)
    return -1;

  /* Should've been checked in -cadet_connection.c handle_cadet_encrypted. */
  GNUNET_assert (size > sizeof (struct GNUNET_CADET_TunnelEncryptedMessage));
  len = size - sizeof (struct GNUNET_CADET_TunnelEncryptedMessage);
  GNUNET_assert (len >= sizeof (struct GNUNET_MessageHeader));

  /* Decrypt header */
  GNUNET_CRYPTO_symmetric_derive_iv (&iv,
                                     &key->HK,
                                     NULL, 0,
                                     NULL);
  res = GNUNET_CRYPTO_symmetric_decrypt (&src->ax_header.Ns,
                                         sizeof (struct GNUNET_CADET_AxHeader),
                                         &key->HK,
                                         &iv,
                                         &plaintext_header.ax_header.Ns);
  GNUNET_assert (sizeof (struct GNUNET_CADET_AxHeader) == res);

  /* Find the correct message key */
  N = ntohl (plaintext_header.ax_header.Ns);
  while ( (NULL != key) &&
          (N != key->Kn) )
    key = key->next;
  if ( (NULL == key) ||
       (0 != memcmp (&key->HK,
                     valid_HK,
                     sizeof (*valid_HK))) )
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
                           const struct GNUNET_CADET_TunnelEncryptedMessage *src,
                           size_t size)
{
  struct GNUNET_ShortHashCode msg_hmac;
  struct GNUNET_HashCode hmac;
  struct GNUNET_CADET_TunnelEncryptedMessage plaintext_header;
  uint32_t Np;
  uint32_t PNp;
  size_t esize; /* Size of encryped payload */

  esize = size - sizeof (struct GNUNET_CADET_TunnelEncryptedMessage);

  /* Try current HK */
  t_hmac (&src->ax_header,
          sizeof (struct GNUNET_CADET_AxHeader) + esize,
          0, &ax->HKr,
          &msg_hmac);
  if (0 != memcmp (&msg_hmac,
                   &src->hmac,
                   sizeof (msg_hmac)))
  {
    static const char ctx[] = "axolotl ratchet";
    struct GNUNET_CRYPTO_SymmetricSessionKey keys[3]; /* RKp, NHKp, CKp */
    struct GNUNET_CRYPTO_SymmetricSessionKey HK;
    struct GNUNET_HashCode dh;
    struct GNUNET_CRYPTO_EcdhePublicKey *DHRp;

    /* Try Next HK */
    t_hmac (&src->ax_header,
            sizeof (struct GNUNET_CADET_AxHeader) + esize,
            0,
            &ax->NHKr,
            &msg_hmac);
    if (0 != memcmp (&msg_hmac,
                     &src->hmac,
                     sizeof (msg_hmac)))
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
    GNUNET_CRYPTO_ecc_ecdh (ax->DHRs,
                            DHRp,
                            &dh);
    t_ax_hmac_hash (&ax->RK,
                    &hmac,
                    &dh, sizeof (dh));
    GNUNET_CRYPTO_kdf (keys, sizeof (keys),
                       ctx, sizeof (ctx),
                       &hmac, sizeof (hmac),
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
  if ( (Np != ax->Nr) &&
       (GNUNET_OK != store_ax_keys (ax,
                                    &ax->HKr,
                                    Np)) )
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
       "Tunnel %s estate changed from %d to %d\n",
       GCT_2s (t),
       old,
       state);

  if ( (CADET_TUNNEL_KEY_OK != old) &&
       (CADET_TUNNEL_KEY_OK == t->estate) )
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
  }
}


/**
 * Send a KX message.
 *
 * FIXME: does not take care of sender-authentication yet!
 *
 * @param t Tunnel on which to send it.
 * @param ax axolotl key context to use
 * @param force_reply Force the other peer to reply with a KX message.
 */
static void
send_kx (struct CadetTunnel *t,
         struct CadetTunnelAxolotl *ax,
         int force_reply)
{
  struct CadetTConnection *ct;
  struct CadetConnection *cc;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_TunnelKeyExchangeMessage *msg;
  enum GNUNET_CADET_KX_Flags flags;

  ct = get_ready_connection (t);
  if (NULL == ct)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Wanted to send KX on tunnel %s, but no connection is ready, deferring\n",
         GCT_2s (t));
    return;
  }
  cc = ct->cc;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending KX on tunnel %s using connection %s\n",
       GCT_2s (t),
       GCC_2s (ct->cc));

  // GNUNET_assert (GNUNET_NO == GCT_is_loopback (t));
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_CADET_TUNNEL_KX);
  flags = GNUNET_CADET_KX_FLAG_NONE;
  if (GNUNET_YES == force_reply)
    flags |= GNUNET_CADET_KX_FLAG_FORCE_REPLY;
  msg->flags = htonl (flags);
  msg->cid = *GCC_get_id (cc);
  GNUNET_CRYPTO_ecdhe_key_get_public (ax->kx_0,
                                      &msg->ephemeral_key);
  GNUNET_CRYPTO_ecdhe_key_get_public (ax->DHRs,
                                      &msg->ratchet_key);
  ct->is_ready = GNUNET_NO;
  GCC_transmit (cc,
                env);
  t->kx_retry_delay = GNUNET_TIME_STD_BACKOFF (t->kx_retry_delay);
  t->next_kx_attempt = GNUNET_TIME_relative_to_absolute (t->kx_retry_delay);
  if (CADET_TUNNEL_KEY_UNINITIALIZED == t->estate)
    GCT_change_estate (t,
                       CADET_TUNNEL_KEY_SENT);
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
  GNUNET_free_non_null (ax->kx_0);
  GNUNET_free_non_null (ax->DHRs);
}


/**
 * Update our Axolotl key state based on the KX data we received.
 * Computes the new chain keys, and root keys, etc, and also checks
 * wether this is a replay of the current chain.
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

  if (0 > GNUNET_CRYPTO_cmp_peer_identity (&my_full_id,
                                           pid))
    am_I_alice = GNUNET_YES;
  else if (0 < GNUNET_CRYPTO_cmp_peer_identity (&my_full_id,
                                                pid))
    am_I_alice = GNUNET_NO;
  else
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }

  if (0 == memcmp (&ax->DHRr,
                   ratchet_key,
                   sizeof (*ratchet_key)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Ratchet key already known. Ignoring KX.\n");
    return GNUNET_NO;
  }

  ax->DHRr = *ratchet_key;

  /* ECDH A B0 */
  if (GNUNET_YES == am_I_alice)
  {
    GNUNET_CRYPTO_eddsa_ecdh (my_private_key,      /* A */
                              ephemeral_key, /* B0 */
                              &key_material[0]);
  }
  else
  {
    GNUNET_CRYPTO_ecdh_eddsa (ax->kx_0,            /* B0 */
                              &pid->public_key,    /* A */
                              &key_material[0]);
  }

  /* ECDH A0 B */
  if (GNUNET_YES == am_I_alice)
  {
    GNUNET_CRYPTO_ecdh_eddsa (ax->kx_0,            /* A0 */
                              &pid->public_key,    /* B */
                              &key_material[1]);
  }
  else
  {
    GNUNET_CRYPTO_eddsa_ecdh (my_private_key,      /* A */
                              ephemeral_key, /* B0 */
                              &key_material[1]);


  }

  /* ECDH A0 B0 */
  /* (This is the triple-DH, we could probably safely skip this,
     as A0/B0 are already in the key material.) */
  GNUNET_CRYPTO_ecc_ecdh (ax->kx_0,             /* A0 or B0 */
                          ephemeral_key,  /* B0 or A0 */
                          &key_material[2]);

  /* KDF */
  GNUNET_CRYPTO_kdf (keys, sizeof (keys),
                     salt, sizeof (salt),
                     &key_material, sizeof (key_material),
                     NULL);

  if (0 == memcmp (&ax->RK,
                   &keys[0],
                   sizeof (ax->RK)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Root key of handshake already known. Ignoring KX.\n");
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
      = GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get(),
                                  ratchet_time);
  }
  return GNUNET_OK;
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
  struct CadetTunnelAxolotl *ax;
  int ret;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Handling KX message for tunnel %s\n",
       GCT_2s (t));

  /* We only keep ONE unverified KX around, so if there is an existing one,
     clean it up. */
  if (NULL != t->unverified_ax)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Dropping old unverified KX state, got a fresh one.\n",
         t->unverified_attempts);
    cleanup_ax (t->unverified_ax);
    memset (t->unverified_ax,
            0,
            sizeof (struct CadetTunnelAxolotl));
    new_ephemeral (t->unverified_ax);
    t->unverified_ax->kx_0 = GNUNET_CRYPTO_ecdhe_key_create ();
  }
  else
  {
    t->unverified_ax = GNUNET_new (struct CadetTunnelAxolotl);
    new_ephemeral (t->unverified_ax);
    t->unverified_ax->kx_0 = GNUNET_CRYPTO_ecdhe_key_create ();
  }
  /* Set as the 'current' RK the one we are currently using,
     so that the duplicate-detection logic of
     #update_ax_by_kx can work. */
  t->unverified_ax->RK = t->ax.RK;
  t->unverified_attempts = 0;
  ax = t->unverified_ax;

  /* FIXME: why this? Investigate use of kx_task! */
  if (0 != (GNUNET_CADET_KX_FLAG_FORCE_REPLY & ntohl (msg->flags)))
  {
    if (NULL != t->kx_task)
    {
      GNUNET_SCHEDULER_cancel (t->kx_task);
      t->kx_task = NULL;
    }
    send_kx (t,
             ax,
             GNUNET_NO);
  }

  /* Update 'ax' by the new key material */
  ret = update_ax_by_kx (ax,
                         GCP_get_id (t->destination),
                         &msg->ephemeral_key,
                         &msg->ratchet_key);
  GNUNET_break (GNUNET_SYSERR != ret);
  if (GNUNET_OK != ret)
    return; /* duplicate KX, nothing to do */

  /* move ahead in our state machine */
  switch (t->estate)
  {
  case CADET_TUNNEL_KEY_UNINITIALIZED:
    GCT_change_estate (t,
                       CADET_TUNNEL_KEY_PING);
    break;
  case CADET_TUNNEL_KEY_SENT:
    /* Got a response to us sending our key; now
       we can start transmitting! */
    GCT_change_estate (t,
                       CADET_TUNNEL_KEY_OK);
    if (NULL != t->send_task)
      GNUNET_SCHEDULER_cancel (t->send_task);
    t->send_task = GNUNET_SCHEDULER_add_now (&trigger_transmissions,
                                             t);
    break;
  case CADET_TUNNEL_KEY_PING:
    /* Got a key yet again; need encrypted payload or KX_AUTH
       to advance to #CADET_TUNNEL_KEY_OK! */
    break;
  case CADET_TUNNEL_KEY_OK:
    /* Did not expect a key, but so what. */
    break;
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

  cmp = GNUNET_CRYPTO_cmp_peer_identity (&my_full_id,
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
                                              ctn))
  {
    ctn = ((ctn + 1) & (~ HIGH_BIT)) | highbit;
  }
  t->next_ctn.cn = htonl (((ctn + 1) & (~ HIGH_BIT)) | highbit);
  ret.cn = ntohl (ctn);
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
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap32_put (t->channels,
                                                      ntohl (ctn.cn),
                                                      ch,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding channel %s to tunnel %s\n",
       GCCH_2s (ch),
       GCT_2s (t));
  if (CADET_TUNNEL_KEY_OK == t->estate)
    GCCH_tunnel_up (ch);
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

  GNUNET_CONTAINER_DLL_remove (t->connection_head,
                               t->connection_tail,
                               ct);
  GNUNET_free (ct);
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
  struct CadetTunnelQueueEntry *tq;

  t->destroy_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Destroying idle tunnel %s\n",
       GCT_2s (t));
  GNUNET_assert (0 == GNUNET_CONTAINER_multihashmap32_size (t->channels));
  while (NULL != (ct = t->connection_head))
  {
    struct CadetConnection *cc;

    GNUNET_assert (ct->t == t);
    cc = ct->cc;
    GCT_connection_lost (ct);
    GCC_destroy_without_tunnel (cc);
  }
  while (NULL != (tq = t->tq_head))
  {
    if (NULL != tq->cont)
      tq->cont (tq->cont_cls);
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
  cleanup_ax (&t->ax);
  if (NULL != t->unverified_ax)
  {
    cleanup_ax (t->unverified_ax);
    GNUNET_free (t->unverified_ax);
  }
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
       "Removing channel %s from tunnel %s\n",
       GCCH_2s (ch),
       GCT_2s (t));
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap32_remove (t->channels,
                                                         ntohl (ctn.cn),
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

  GCCH_handle_remote_destroy (ch);
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
                 GNUNET_CONTAINER_multihashmap32_size (t->channels));
  if (NULL != t->destroy_task)
  {
    GNUNET_SCHEDULER_cancel (t->destroy_task);
    t->destroy_task = NULL;
  }
  destroy_tunnel (t);
}


/**
 * It's been a while, we should try to redo the KX, if we can.
 *
 * @param cls the `struct CadetTunnel` to do KX for.
 */
static void
retry_kx (void *cls)
{
  struct CadetTunnel *t = cls;

  t->kx_task = NULL;
  send_kx (t,
           &t->ax,
           ( (CADET_TUNNEL_KEY_UNINITIALIZED == t->estate) ||
             (CADET_TUNNEL_KEY_SENT == t->estate) )
           ? GNUNET_YES
           : GNUNET_NO);
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
  ct->is_ready = GNUNET_NO;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending payload of %s on %s\n",
       GCT_2s (t),
       GCC_2s (ct->cc));
  GCC_transmit (ct->cc,
                tq->env);
  if (NULL != tq->cont)
    tq->cont (tq->cont_cls);
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
         "Connection %s no longer ready for tunnel %s\n",
         GCC_2s (ct->cc),
         GCT_2s (t));
    ct->is_ready = GNUNET_NO;
    return;
  }
  ct->is_ready = GNUNET_YES;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connection %s now ready for tunnel %s in state %s\n",
       GCC_2s (ct->cc),
       GCT_2s (t),
       estate2s (t->estate));
  switch (t->estate)
  {
  case CADET_TUNNEL_KEY_UNINITIALIZED:
    send_kx (t,
             &t->ax,
             GNUNET_YES);
    break;
  case CADET_TUNNEL_KEY_SENT:
  case CADET_TUNNEL_KEY_PING:
    /* opportunity to #retry_kx() starts now, schedule job */
    if (NULL == t->kx_task)
    {
      t->kx_task
        = GNUNET_SCHEDULER_add_at (t->next_kx_attempt,
                                   &retry_kx,
                                   t);
    }
    break;
  case CADET_TUNNEL_KEY_OK:
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
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Ignoring duplicate path %s for tunnel %s.\n",
           GCPP_2s (path),
           GCT_2s (t));
      return GNUNET_YES; /* duplicate */
    }
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
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Ignoring paths of length %u, they are way too long.\n",
         min_length * 2);
    return GNUNET_NO;
  }
  /* If we have enough paths and this one looks no better, ignore it. */
  if ( (t->num_connections >= DESIRED_CONNECTIONS_PER_TUNNEL) &&
       (min_length < GCPP_get_length (path)) &&
       (max_desire > GCPP_get_desirability (path)) )
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
                       ct,
                       &connection_ready_cb,
                       ct);
  /* FIXME: schedule job to kill connection (and path?)  if it takes
     too long to get ready! (And track performance data on how long
     other connections took with the tunnel!)
     => Note: to be done within 'connection'-logic! */
  GNUNET_CONTAINER_DLL_insert (t->connection_head,
                               t->connection_tail,
                               ct);
  t->num_connections++;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Found interesting path %s for tunnel %s, created connection %s\n",
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

  t->maintain_connections_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Performing connection maintenance for tunnel %s.\n",
       GCT_2s (t));

  (void) GCP_iterate_paths (t->destination,
                            &consider_path_cb,
                            t);

  GNUNET_break (0); // FIXME: implement!
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
       "Received KEEPALIVE on tunnel %s\n",
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
         "Receicved %u bytes of application data for unknown channel %u, sending DESTROY\n",
         (unsigned int) (ntohs (msg->header.size) - sizeof (*msg)),
         ntohl (msg->ctn.cn));
    GCT_send_channel_destroy (t,
                              msg->ctn);
    return;
  }
  GCCH_handle_channel_plaintext_data (ch,
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
         "Receicved DATA_ACK for unknown channel %u, sending DESTROY\n",
         ntohl (ack->ctn.cn));
    GCT_send_channel_destroy (t,
                              ack->ctn);
    return;
  }
  GCCH_handle_channel_plaintext_data_ack (ch,
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
                               const struct GNUNET_CADET_ChannelOpenMessage *copen)
{
  struct CadetTunnel *t = cls;
  struct CadetChannel *ch;

  ch = GNUNET_CONTAINER_multihashmap32_get (t->channels,
                                            ntohl (copen->ctn.cn));
  if (NULL != ch)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Receicved duplicate channel OPEN on port %s from %s (%s), resending ACK\n",
         GNUNET_h2s (&copen->port),
         GCT_2s (t),
         GCCH_2s (ch));
    GCCH_handle_duplicate_open (ch);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Receicved channel OPEN on port %s from %s\n",
       GNUNET_h2s (&copen->port),
       GCT_2s (t));
  ch = GCCH_channel_incoming_new (t,
                                  copen->ctn,
                                  &copen->port,
                                  ntohl (copen->opt));
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
  struct GNUNET_CADET_ChannelManageMessage msg;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Sending DESTORY message for channel ID %u\n",
       ntohl (ctn.cn));
  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY);
  msg.reserved = htonl (0);
  msg.ctn = ctn;
  GCT_send (t,
            &msg.header,
            NULL,
            NULL);
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
                                   const struct GNUNET_CADET_ChannelManageMessage *cm)
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
  GCCH_handle_channel_open_ack (ch);
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
                                  const struct GNUNET_CADET_ChannelManageMessage *cm)
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
       "Receicved channel DESTROY on %s from %s\n",
       GCCH_2s (ch),
       GCT_2s (t));
  GCCH_handle_remote_destroy (ch);
}


/**
 * Handles a message we decrypted, by injecting it into
 * our message queue (which will do the dispatching).
 *
 * @param cls the `struct CadetTunnel` that got the message
 * @param msg the message
 * @return #GNUNET_OK (continue to process)
 */
static int
handle_decrypted (void *cls,
                  const struct GNUNET_MessageHeader *msg)
{
  struct CadetTunnel *t = cls;

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
                             struct GNUNET_CADET_ChannelManageMessage,
                             t),
    GNUNET_MQ_hd_fixed_size (plaintext_channel_destroy,
                             GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY,
                             struct GNUNET_CADET_ChannelManageMessage,
                             t),
    GNUNET_MQ_handler_end ()
  };

  new_ephemeral (&t->ax);
  t->ax.kx_0 = GNUNET_CRYPTO_ecdhe_key_create ();
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
 * @param path path to use for the connection
 * @return #GNUNET_OK on success,
 *         #GNUNET_SYSERR on failure (duplicate connection)
 */
int
GCT_add_inbound_connection (struct CadetTunnel *t,
                            const struct GNUNET_CADET_ConnectionTunnelIdentifier *cid,
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
         "Tunnel %s refused inbound connection %s (duplicate)\n",
         GCT_2s (t),
         GCC_2s (ct->cc));
    GNUNET_free (ct);
    return GNUNET_SYSERR;
  }
  /* FIXME: schedule job to kill connection (and path?)  if it takes
     too long to get ready! (And track performance data on how long
     other connections took with the tunnel!)
     => Note: to be done within 'connection'-logic! */
  GNUNET_CONTAINER_DLL_insert (t->connection_head,
                               t->connection_tail,
                               ct);
  t->num_connections++;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Tunnel %s has new connection %s\n",
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
       "Tunnel %s received %u bytes of encrypted data in state %d\n",
       GCT_2s (t),
       (unsigned int) size,
       t->estate);

  switch (t->estate)
  {
  case CADET_TUNNEL_KEY_UNINITIALIZED:
    /* We did not even SEND our KX, how can the other peer
       send us encrypted data? */
    GNUNET_break_op (0);
    return;
  case CADET_TUNNEL_KEY_SENT:
    /* We did not get the KX of the other peer, but that
       might have been lost.  Ask for KX again. */
    GNUNET_STATISTICS_update (stats,
                              "# received encrypted without KX",
                              1,
                              GNUNET_NO);
    if (NULL != t->kx_task)
      GNUNET_SCHEDULER_cancel (t->kx_task);
    t->kx_task = GNUNET_SCHEDULER_add_now (&retry_kx,
                                           t);
    return;
  case CADET_TUNNEL_KEY_PING:
    /* Great, first payload, we might graduate to OK */
  case CADET_TUNNEL_KEY_OK:
    break;
  }

  GNUNET_STATISTICS_update (stats,
                            "# received encrypted",
                            1,
                            GNUNET_NO);
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

  if ( (-1 == decrypted_size) &&
       (NULL != t->unverified_ax) )
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
    if (CADET_TUNNEL_KEY_PING == t->estate)
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
       basically only causes us to increment a counter a few times. */
    t->unverified_attempts++;
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
    GNUNET_break_op (0);
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Tunnel %s failed to decrypt and validate encrypted data\n",
         GCT_2s (t));
    GNUNET_STATISTICS_update (stats,
                              "# unable to decrypt",
                              1,
                              GNUNET_NO);
    return;
  }

  /* The MST will ultimately call #handle_decrypted() on each message. */
  GNUNET_break_op (GNUNET_OK ==
                   GNUNET_MST_from_buffer (t->mst,
                                           cbuf,
                                           decrypted_size,
                                           GNUNET_YES,
                                           GNUNET_NO));
}


/**
 * Sends an already built message on a tunnel, encrypting it and
 * choosing the best connection if not provided.
 *
 * @param message Message to send. Function modifies it.
 * @param t Tunnel on which this message is transmitted.
 * @param cont Continuation to call once message is really sent.
 * @param cont_cls Closure for @c cont.
 * @return Handle to cancel message
 */
struct CadetTunnelQueueEntry *
GCT_send (struct CadetTunnel *t,
          const struct GNUNET_MessageHeader *message,
          GNUNET_SCHEDULER_TaskCallback cont,
          void *cont_cls)
{
  struct CadetTunnelQueueEntry *tq;
  uint16_t payload_size;
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_CADET_TunnelEncryptedMessage *ax_msg;

  if (CADET_TUNNEL_KEY_OK != t->estate)
  {
    GNUNET_break (0);
    return NULL;
  }
  payload_size = ntohs (message->size);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Encrypting %u bytes for tunnel %s\n",
       (unsigned int) payload_size,
       GCT_2s (t));
  env = GNUNET_MQ_msg_extra (ax_msg,
                             payload_size,
                             GNUNET_MESSAGE_TYPE_CADET_TUNNEL_ENCRYPTED);
  t_ax_encrypt (&t->ax,
                &ax_msg[1],
                message,
                payload_size);
  ax_msg->ax_header.Ns = htonl (t->ax.Ns++);
  ax_msg->ax_header.PNs = htonl (t->ax.PNs);
  /* FIXME: we should do this once, not once per message;
     this is a point multiplication, and DHRs does not
     change all the time. */
  GNUNET_CRYPTO_ecdhe_key_get_public (t->ax.DHRs,
                                      &ax_msg->ax_header.DHRs);
  t_h_encrypt (&t->ax,
               ax_msg);
  t_hmac (&ax_msg->ax_header,
          sizeof (struct GNUNET_CADET_AxHeader) + payload_size,
          0,
          &t->ax.HKs,
          &ax_msg->hmac);

  tq = GNUNET_malloc (sizeof (*tq));
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
        "TTT TUNNEL TOWARDS %s in estate %s tq_len: %u #cons: %u\n",
        GCT_2s (t),
        estate2s (t->estate),
        t->tq_len,
        t->num_connections);
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
