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

#include "cadet_protocol.h"
#include "cadet_path.h"

#include "gnunet-service-cadet_tunnel.h"
#include "gnunet-service-cadet_connection.h"
#include "gnunet-service-cadet_channel.h"
#include "gnunet-service-cadet_peer.h"

#define LOG(level, ...) GNUNET_log_from(level,"cadet-tun",__VA_ARGS__)

#define REKEY_WAIT GNUNET_TIME_relative_multiply(GNUNET_TIME_UNIT_SECONDS, 5)

#define CONNECTIONS_PER_TUNNEL 3

#if !defined(GNUNET_CULL_LOGGING)
#define DUMP_KEYS_TO_STDERR GNUNET_YES
#else
#define DUMP_KEYS_TO_STDERR GNUNET_NO
#endif

/******************************************************************************/
/********************************   STRUCTS  **********************************/
/******************************************************************************/

struct CadetTChannel
{
  struct CadetTChannel *next;
  struct CadetTChannel *prev;
  struct CadetChannel *ch;
};


/**
 * Connection list and metadata.
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
  struct CadetConnection *c;

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
 * Structure used during a Key eXchange.
 */
struct CadetTunnelKXCtx
{
  /**
   * Encryption ("our") old key, for encrypting traffic sent by us
   * end before the key exchange is finished or times out.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey e_key_old;

  /**
   * Decryption ("their") old key, for decrypting traffic sent by the
   * other end before the key exchange started.
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey d_key_old;

  /**
   * Challenge to send in a ping and expect in the pong.
   */
  uint32_t challenge;

  /**
   * When the rekey started. One minute after this the new key will be used.
   */
  struct GNUNET_TIME_Absolute rekey_start_time;

  /**
   * Task for delayed destruction of the Key eXchange context, to allow delayed
   * messages with the old key to be decrypted successfully.
   */
  GNUNET_SCHEDULER_TaskIdentifier finish_task;
};

/**
 * Struct containing all information regarding a tunnel to a peer.
 */
struct CadetTunnel
{
    /**
     * Endpoint of the tunnel.
     */
  struct CadetPeer *peer;

    /**
     * State of the tunnel connectivity.
     */
  enum CadetTunnelCState cstate;

  /**
   * State of the tunnel encryption.
   */
  enum CadetTunnelEState estate;

  /**
   * Key eXchange context.
   */
  struct CadetTunnelKXCtx *kx_ctx;

  /**
   * Peer's ephemeral key, to recreate @c e_key and @c d_key when own ephemeral
   * key changes.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey peers_ephemeral_key;

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
  struct CadetTConnection *connection_head;
  struct CadetTConnection *connection_tail;

  /**
   * Next connection number.
   */
  uint32_t next_cid;

  /**
   * Channels inside this tunnel.
   */
  struct CadetTChannel *channel_head;
  struct CadetTChannel *channel_tail;

  /**
   * Channel ID for the next created channel.
   */
  CADET_ChannelNumber next_chid;

  /**
   * Destroy flag: if true, destroy on last message.
   */
  GNUNET_SCHEDULER_TaskIdentifier destroy_task;

  /**
   * Queued messages, to transmit once tunnel gets connected.
   */
  struct CadetTunnelDelayed *tq_head;
  struct CadetTunnelDelayed *tq_tail;
};


/**
 * Struct used to save messages in a non-ready tunnel to send once connected.
 */
struct CadetTunnelDelayed
{
  /**
   * DLL
   */
  struct CadetTunnelDelayed *next;
  struct CadetTunnelDelayed *prev;

  /**
   * Tunnel.
   */
  struct CadetTunnel *t;

  /**
   * Tunnel queue given to the channel to cancel request. Update on send_queued.
   */
  struct CadetTunnelQueue *tq;

  /**
   * Message to send.
   */
  /* struct GNUNET_MessageHeader *msg; */
};


/**
 * Handle for messages queued but not yet sent.
 */
struct CadetTunnelQueue
{
  /**
   * Connection queue handle, to cancel if necessary.
   */
  struct CadetConnectionQueue *cq;

  /**
   * Handle in case message hasn't been given to a connection yet.
   */
  struct CadetTunnelDelayed *tqd;

  /**
   * Continuation to call once sent.
   */
  GCT_sent cont;

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
 * Don't try to recover tunnels if shutting down.
 */
extern int shutting_down;


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
static struct GNUNET_CADET_KX_Ephemeral kx_msg;

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

    default:
      sprintf (buf, "%u (UNKNOWN STATE)", cs);
      return buf;
  }
  return "";
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
      sprintf (buf, "%u (UNKNOWN STATE)", es);
      return buf;
  }
  return "";
}


/**
 * @brief Check if tunnel is ready to send traffic.
 *
 * Tunnel must be connected and with encryption correctly set up.
 *
 * @param t Tunnel to check.
 *
 * @return #GNUNET_YES if ready, #GNUNET_NO otherwise
 */
static int
is_ready (struct CadetTunnel *t)
{
  int ready;

  GCT_debug (t, GNUNET_ERROR_TYPE_DEBUG);
  ready = CADET_TUNNEL_READY == t->cstate
          && (CADET_TUNNEL_KEY_OK == t->estate
              || CADET_TUNNEL_KEY_REKEY == t->estate);
  ready = ready || GCT_is_loopback (t);
  return ready;
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
get_channel_buffer (const struct CadetTChannel *tch)
{
  int fwd;

  /* If channel is outgoing, is origin in the FWD direction and fwd is YES */
  fwd = GCCH_is_origin (tch->ch, GNUNET_YES);

  return GCCH_get_buffer (tch->ch, fwd);
}


/**
 * Get the channel's allowance status.
 *
 * @param tch Tunnel's channel handle.
 *
 * @return #GNUNET_YES if we allowed the client to send data to us.
 */
static int
get_channel_allowed (const struct CadetTChannel *tch)
{
  int fwd;

  /* If channel is outgoing, is origin in the FWD direction and fwd is YES */
  fwd = GCCH_is_origin (tch->ch, GNUNET_YES);

  return GCCH_get_allowed (tch->ch, fwd);
}


/**
 * Get the connection's buffer.
 *
 * @param tc Tunnel's connection handle.
 *
 * @return Amount of messages the connection can still buffer.
 */
static unsigned int
get_connection_buffer (const struct CadetTConnection *tc)
{
  int fwd;

  /* If connection is outgoing, is origin in the FWD direction and fwd is YES */
  fwd = GCC_is_origin (tc->c, GNUNET_YES);

  return GCC_get_buffer (tc->c, fwd);
}


/**
 * Get the connection's allowance.
 *
 * @param tc Tunnel's connection handle.
 *
 * @return Amount of messages we have allowed the next peer to send us.
 */
static unsigned int
get_connection_allowed (const struct CadetTConnection *tc)
{
  int fwd;

  /* If connection is outgoing, is origin in the FWD direction and fwd is YES */
  fwd = GCC_is_origin (tc->c, GNUNET_YES);

  return GCC_get_allowed (tc->c, fwd);
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
check_ephemeral (struct CadetTunnel *t,
                 const struct GNUNET_CADET_KX_Ephemeral *msg)
{
  /* Check message size */
  if (ntohs (msg->header.size) != sizeof (struct GNUNET_CADET_KX_Ephemeral))
    return GNUNET_SYSERR;

  /* Check signature size */
  if (ntohl (msg->purpose.size) != ephemeral_purpose_size ())
    return GNUNET_SYSERR;

  /* Check origin */
  if (0 != memcmp (&msg->origin_identity,
                   GCP_get_id (t->peer),
                   sizeof (struct GNUNET_PeerIdentity)))
    return GNUNET_SYSERR;

  /* Check signature */
  if (GNUNET_OK !=
      GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_PURPOSE_CADET_KX,
                                  &msg->purpose,
                                  &msg->signature,
                                  &msg->origin_identity.public_key))
    return GNUNET_SYSERR;

  return GNUNET_OK;
}


/**
 * Select the best key to use for encryption (send), based on KX status.
 *
 * Normally, return the current key. If there is a KX in progress and the old
 * key is fresh enough, return the old key.
 *
 * @param t Tunnel to choose the key from.
 *
 * @return The optimal key to encrypt/hmac outgoing traffic.
 */
static const struct GNUNET_CRYPTO_SymmetricSessionKey *
select_key (const struct CadetTunnel *t)
{
  const struct GNUNET_CRYPTO_SymmetricSessionKey *key;

  if (NULL != t->kx_ctx
      && GNUNET_SCHEDULER_NO_TASK == t->kx_ctx->finish_task)
  {
    struct GNUNET_TIME_Relative age;

    age = GNUNET_TIME_absolute_get_duration (t->kx_ctx->rekey_start_time);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "  key exchange in progress, started %s ago\n",
         GNUNET_STRINGS_relative_time_to_string (age, GNUNET_YES));
    // FIXME make duration of old keys configurable
    if (age.rel_value_us < GNUNET_TIME_UNIT_MINUTES.rel_value_us)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  using old key\n");
      key = &t->kx_ctx->e_key_old;
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  using new key\n");
      key = &t->e_key;
    }
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  no KX: using current key\n");
    key = &t->e_key;
  }
  return key;
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
t_hmac (const void *plaintext, size_t size,
        uint32_t iv, const struct GNUNET_CRYPTO_SymmetricSessionKey *key,
        struct GNUNET_CADET_Hash *hmac)
{
  static const char ctx[] = "cadet authentication key";
  struct GNUNET_CRYPTO_AuthKey auth_key;
  struct GNUNET_HashCode hash;

#if DUMP_KEYS_TO_STDERR
  LOG (GNUNET_ERROR_TYPE_INFO, "  HMAC with key %s\n",
       GNUNET_h2s ((struct GNUNET_HashCode *) key));
#endif
  GNUNET_CRYPTO_hmac_derive_key (&auth_key, key,
                                 &iv, sizeof (iv),
                                 key, sizeof (*key),
                                 ctx, sizeof (ctx),
                                 NULL);
  /* Two step: CADET_Hash is only 256 bits, HashCode is 512. */
  GNUNET_CRYPTO_hmac (&auth_key, plaintext, size, &hash);
  memcpy (hmac, &hash, sizeof (*hmac));
}


/**
 * Encrypt daforce_newest_keyta with the tunnel key.
 *
 * @param t Tunnel whose key to use.
 * @param dst Destination for the encrypted data.
 * @param src Source of the plaintext. Can overlap with @c dst.
 * @param size Size of the plaintext.
 * @param iv Initialization Vector to use.
 * @param force_newest_key Force the use of the newest key, otherwise
 *                         CADET will use the old key when allowed.
 *                         This can happen in the case when a KX is going on
 *                         and the old one hasn't expired.
 */
static int
t_encrypt (struct CadetTunnel *t, void *dst, const void *src,
           size_t size, uint32_t iv, int force_newest_key)
{
  struct GNUNET_CRYPTO_SymmetricInitializationVector siv;
  const struct GNUNET_CRYPTO_SymmetricSessionKey *key;
  size_t out_size;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  t_encrypt start\n");

  key = GNUNET_YES == force_newest_key ? &t->e_key : select_key (t);
  #if DUMP_KEYS_TO_STDERR
  LOG (GNUNET_ERROR_TYPE_INFO, "  ENC with key %s\n",
       GNUNET_h2s ((struct GNUNET_HashCode *) key));
  #endif
  GNUNET_CRYPTO_symmetric_derive_iv (&siv, key, &iv, sizeof (iv), NULL);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  t_encrypt IV derived\n");
  out_size = GNUNET_CRYPTO_symmetric_encrypt (src, size, key, &siv, dst);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  t_encrypt end\n");

  return out_size;
}


/**
 * Decrypt and verify data with the appropriate tunnel key.
 *
 * @param key Key to use.
 * @param dst Destination for the plaintext.
 * @param src Source of the encrypted data. Can overlap with @c dst.
 * @param size Size of the encrypted data.
 * @param iv Initialization Vector to use.
 *
 * @return Size of the decrypted data, -1 if an error was encountered.
 */
static int
decrypt (const struct GNUNET_CRYPTO_SymmetricSessionKey *key,
         void *dst, const void *src, size_t size, uint32_t iv)
{
  struct GNUNET_CRYPTO_SymmetricInitializationVector siv;
  size_t out_size;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  decrypt start\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  decrypt iv\n");
  GNUNET_CRYPTO_symmetric_derive_iv (&siv, key, &iv, sizeof (iv), NULL);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  decrypt iv done\n");
  out_size = GNUNET_CRYPTO_symmetric_decrypt (src, size, key, &siv, dst);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  decrypt end\n");

  return out_size;
}


/**
 * Decrypt and verify data with the most recent tunnel key.
 *
 * @param t Tunnel whose key to use.
 * @param dst Destination for the plaintext.
 * @param src Source of the encrypted data. Can overlap with @c dst.
 * @param size Size of the encrypted data.
 * @param iv Initialization Vector to use.
 *
 * @return Size of the decrypted data, -1 if an error was encountered.
 */
static int
t_decrypt (struct CadetTunnel *t, void *dst, const void *src,
           size_t size, uint32_t iv)
{
  size_t out_size;

#if DUMP_KEYS_TO_STDERR
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  t_decrypt with %s\n",
       GNUNET_h2s ((struct GNUNET_HashCode *) &t->d_key));
#endif
  if (t->estate == CADET_TUNNEL_KEY_UNINITIALIZED)
  {
    GNUNET_STATISTICS_update (stats, "# non decryptable data", 1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "got data on %s without a valid key\n",
         GCT_2s (t));
    GCT_debug (t, GNUNET_ERROR_TYPE_WARNING);
    return -1;
  }

  out_size = decrypt (&t->d_key, dst, src, size, iv);

  return out_size;
}


/**
 * Decrypt and verify data with the appropriate tunnel key and verify that the
 * data has not been altered since it was sent by the remote peer.
 *
 * @param t Tunnel whose key to use.
 * @param dst Destination for the plaintext.
 * @param src Source of the encrypted data. Can overlap with @c dst.
 * @param size Size of the encrypted data.
 * @param iv Initialization Vector to use.
 * @param msg_hmac HMAC of the message, cannot be NULL.
 *
 * @return Size of the decrypted data, -1 if an error was encountered.
 */
static int
t_decrypt_and_validate (struct CadetTunnel *t,
                        void *dst, const void *src,
                        size_t size, uint32_t iv,
                        const struct GNUNET_CADET_Hash *msg_hmac)
{
  struct GNUNET_CRYPTO_SymmetricSessionKey *key;
  struct GNUNET_CADET_Hash hmac;
  int decrypted_size;

  /* Try primary (newest) key */
  key = &t->d_key;
  decrypted_size = decrypt (key, dst, src, size, iv);
  t_hmac (src, size, iv, key, &hmac);
  if (0 == memcmp (msg_hmac, &hmac, sizeof (hmac)))
    return decrypted_size;

  /* If no key exchange is going on, we just failed */
  if (NULL == t->kx_ctx)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                "Failed checksum validation on tunnel %s with no KX\n",
                GCT_2s (t));
    GNUNET_STATISTICS_update (stats, "# wrong HMAC", 1, GNUNET_NO);
    return -1;
  }

  /* Try secondary (from previous KX period) key */
  key = &t->kx_ctx->d_key_old;
  decrypted_size = decrypt (key, dst, src, size, iv);
  t_hmac (src, size, iv, key, &hmac);
  if (0 == memcmp (msg_hmac, &hmac, sizeof (hmac)))
    return decrypted_size;

  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
              "Failed checksum validation on tunnel %s with KX\n",
              GCT_2s (t));
  GNUNET_STATISTICS_update (stats, "# wrong HMAC", 1, GNUNET_NO);
  return -1;
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
  const char salt[] = "CADET kx salt";

  GNUNET_CRYPTO_kdf (key, sizeof (struct GNUNET_CRYPTO_SymmetricSessionKey),
                     salt, sizeof (salt),
                     key_material, sizeof (struct GNUNET_HashCode),
                     sender, sizeof (struct GNUNET_PeerIdentity),
                     receiver, sizeof (struct GNUNET_PeerIdentity),
                     NULL);
}


/**
 * Create a new Key eXchange context for the tunnel.
 *
 * Initializes the key copies, KX start timestamp and creates a new nonce.
 *
 * @param t Tunnel for which to create the KX ctx.
 */
static void
create_kx_ctx (struct CadetTunnel *t)
{
  if (NULL != t->kx_ctx)
  {
    if (GNUNET_SCHEDULER_NO_TASK != t->kx_ctx->finish_task)
    {
      GNUNET_SCHEDULER_cancel (t->kx_ctx->finish_task);
      t->kx_ctx->finish_task = GNUNET_SCHEDULER_NO_TASK;
    }
    return;
  }

  LOG (GNUNET_ERROR_TYPE_INFO, "  new kx ctx for %s\n", GCT_2s (t));
  t->kx_ctx = GNUNET_new (struct CadetTunnelKXCtx);
  t->kx_ctx->challenge = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE,
                                                   UINT32_MAX);
  t->kx_ctx->d_key_old = t->d_key;
  t->kx_ctx->e_key_old = t->e_key;
  t->kx_ctx->rekey_start_time = GNUNET_TIME_absolute_get ();
}


/**
 * Derive the tunnel's keys using our own and the peer's ephemeral keys.
 *
 * @param t Tunnel for which to create the keys.
 */
static void
create_keys (struct CadetTunnel *t)
{
  struct GNUNET_HashCode km;

  derive_key_material (&km, &t->peers_ephemeral_key);
  derive_symmertic (&t->e_key, &my_full_id, GCP_get_id (t->peer), &km);
  derive_symmertic (&t->d_key, GCP_get_id (t->peer), &my_full_id, &km);
#if DUMP_KEYS_TO_STDERR
  LOG (GNUNET_ERROR_TYPE_INFO, "ME: %s\n",
       GNUNET_h2s ((struct GNUNET_HashCode *) &kx_msg.ephemeral_key));
  LOG (GNUNET_ERROR_TYPE_INFO, "PE: %s\n",
       GNUNET_h2s ((struct GNUNET_HashCode *) &t->peers_ephemeral_key));
  LOG (GNUNET_ERROR_TYPE_INFO, "KM: %s\n", GNUNET_h2s (&km));
  LOG (GNUNET_ERROR_TYPE_INFO, "EK: %s\n",
       GNUNET_h2s ((struct GNUNET_HashCode *) &t->e_key));
  LOG (GNUNET_ERROR_TYPE_INFO, "DK: %s\n",
       GNUNET_h2s ((struct GNUNET_HashCode *) &t->d_key));
#endif
}


/**
 * Pick a connection on which send the next data message.
 *
 * @param t Tunnel on which to send the message.
 *
 * @return The connection on which to send the next message.
 */
static struct CadetConnection *
tunnel_get_connection (struct CadetTunnel *t)
{
  struct CadetTConnection *iter;
  struct CadetConnection *best;
  unsigned int qn;
  unsigned int lowest_q;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "tunnel_get_connection %s\n", GCT_2s (t));
  best = NULL;
  lowest_q = UINT_MAX;
  for (iter = t->connection_head; NULL != iter; iter = iter->next)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  connection %s: %u\n",
         GCC_2s (iter->c), GCC_get_state (iter->c));
    if (CADET_CONNECTION_READY == GCC_get_state (iter->c))
    {
      qn = GCC_get_qn (iter->c, GCC_is_origin (iter->c, GNUNET_YES));
      LOG (GNUNET_ERROR_TYPE_DEBUG, "    q_n %u, \n", qn);
      if (qn < lowest_q)
      {
        best = iter->c;
        lowest_q = qn;
      }
    }
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, " selected: connection %s\n", GCC_2s (best));
  return best;
}


/**
 * Callback called when a queued message is sent.
 *
 * Calculates the average time and connection packet tracking.
 *
 * @param cls Closure (TunnelQueue handle).
 * @param c Connection this message was on.
 * @param q Connection queue handle (unused).
 * @param type Type of message sent.
 * @param fwd Was this a FWD going message?
 * @param size Size of the message.
 */
static void
tun_message_sent (void *cls,
              struct CadetConnection *c,
              struct CadetConnectionQueue *q,
              uint16_t type, int fwd, size_t size)
{
  struct CadetTunnelQueue *qt = cls;
  struct CadetTunnel *t;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "tun_message_sent\n");

  GNUNET_assert (NULL != qt->cont);
  t = NULL == c ? NULL : GCC_get_tunnel (c);
  qt->cont (qt->cont_cls, t, qt, type, size);
  GNUNET_free (qt);
}


static unsigned int
count_queued_data (const struct CadetTunnel *t)
{
  struct CadetTunnelDelayed *iter;
  unsigned int count;

  for (count = 0, iter = t->tq_head; iter != NULL; iter = iter->next)
    count++;

  return count;
}

/**
 * Delete a queued message: either was sent or the channel was destroyed
 * before the tunnel's key exchange had a chance to finish.
 *
 * @param tqd Delayed queue handle.
 */
static void
unqueue_data (struct CadetTunnelDelayed *tqd)
{
  GNUNET_CONTAINER_DLL_remove (tqd->t->tq_head, tqd->t->tq_tail, tqd);
  GNUNET_free (tqd);
}


/**
 * Cache a message to be sent once tunnel is online.
 *
 * @param t Tunnel to hold the message.
 * @param msg Message itself (copy will be made).
 */
static struct CadetTunnelDelayed *
queue_data (struct CadetTunnel *t, const struct GNUNET_MessageHeader *msg)
{
  struct CadetTunnelDelayed *tqd;
  uint16_t size = ntohs (msg->size);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "queue data on Tunnel %s\n", GCT_2s (t));

  if (GNUNET_YES == is_ready (t))
  {
    GNUNET_break (0);
    return NULL;
  }

  tqd = GNUNET_malloc (sizeof (struct CadetTunnelDelayed) + size);

  tqd->t = t;
  memcpy (&tqd[1], msg, size);
  GNUNET_CONTAINER_DLL_insert_tail (t->tq_head, t->tq_tail, tqd);
  return tqd;
}


/**
 * Sends an already built message on a tunnel, encrypting it and
 * choosing the best connection.
 *
 * @param message Message to send. Function modifies it.
 * @param t Tunnel on which this message is transmitted.
 * @param c Connection to use (autoselect if NULL).
 * @param force Force the tunnel to take the message (buffer overfill).
 * @param cont Continuation to call once message is really sent.
 * @param cont_cls Closure for @c cont.
 * @param existing_q In case this a transmission of previously queued data,
 *                   this should be TunnelQueue given to the client.
 *                   Otherwise, NULL.
 *
 * @return Handle to cancel message.
 *         NULL if @c cont is NULL or an error happens and message is dropped.
 */
static struct CadetTunnelQueue *
send_prebuilt_message (const struct GNUNET_MessageHeader *message,
                       struct CadetTunnel *t, struct CadetConnection *c,
                       int force, GCT_sent cont, void *cont_cls,
                       struct CadetTunnelQueue *existing_q)
{
  struct CadetTunnelQueue *tq;
  struct GNUNET_CADET_Encrypted *msg;
  size_t size = ntohs (message->size);
  char cbuf[sizeof (struct GNUNET_CADET_Encrypted) + size];
  uint32_t mid;
  uint32_t iv;
  uint16_t type;
  int fwd;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "GMT Send on Tunnel %s\n", GCT_2s (t));

  if (GNUNET_NO == is_ready (t))
  {
    struct CadetTunnelDelayed *tqd;
    /* A non null existing_q indicates sending of queued data.
     * Should only happen after tunnel becomes ready.
     */
    GNUNET_assert (NULL == existing_q);
    tqd = queue_data (t, message);
    if (NULL == cont)
      return NULL;
    tq = GNUNET_new (struct CadetTunnelQueue);
    tq->tqd = tqd;
    tqd->tq = tq;
    tq->cont = cont;
    tq->cont_cls = cont_cls;
    return tq;
  }

  GNUNET_assert (GNUNET_NO == GCT_is_loopback (t));

  iv = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX);
  msg = (struct GNUNET_CADET_Encrypted *) cbuf;
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CADET_ENCRYPTED);
  msg->iv = iv;
  GNUNET_assert (t_encrypt (t, &msg[1], message, size, iv, GNUNET_NO) == size);
  t_hmac (&msg[1], size, iv, select_key (t), &msg->hmac);
  msg->header.size = htons (sizeof (struct GNUNET_CADET_Encrypted) + size);

  if (NULL == c)
    c = tunnel_get_connection (t);
  if (NULL == c)
  {
    /* Why is tunnel 'ready'? Should have been queued! */
    if (GNUNET_SCHEDULER_NO_TASK != t->destroy_task)
    {
      GNUNET_break (0);
      GCT_debug (t, GNUNET_ERROR_TYPE_WARNING);
    }
    return NULL; /* Drop... */
  }

  mid = 0;
  type = ntohs (message->type);
  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_CADET_DATA:
    case GNUNET_MESSAGE_TYPE_CADET_DATA_ACK:
      if (GNUNET_MESSAGE_TYPE_CADET_DATA == type)
        mid = ntohl (((struct GNUNET_CADET_Data *) message)->mid);
      else
        mid = ntohl (((struct GNUNET_CADET_DataACK *) message)->mid);
      /* Fall thru */
    case GNUNET_MESSAGE_TYPE_CADET_KEEPALIVE:
    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_CREATE:
    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY:
    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_ACK:
    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_NACK:
      msg->cid = *GCC_get_id (c);
      msg->ttl = htonl (default_ttl);
      break;
    default:
      GNUNET_break (0);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "type %s\n", GC_m2s (type));

  fwd = GCC_is_origin (c, GNUNET_YES);

  if (NULL == cont)
  {
    GNUNET_break (NULL == GCC_send_prebuilt_message (&msg->header, type, mid, c,
                                                     fwd, force, NULL, NULL));
    return NULL;
  }
  if (NULL == existing_q)
  {
    tq = GNUNET_new (struct CadetTunnelQueue); /* FIXME valgrind: leak*/
  }
  else
  {
    tq = existing_q;
    tq->tqd = NULL;
  }
  tq->cq = GCC_send_prebuilt_message (&msg->header, type, mid, c, fwd, force,
                                      &tun_message_sent, tq);
  GNUNET_assert (NULL != tq->cq);
  tq->cont = cont;
  tq->cont_cls = cont_cls;

  return tq;
}


/**
 * Send all cached messages that we can, tunnel is online.
 *
 * @param t Tunnel that holds the messages. Cannot be loopback.
 */
static void
send_queued_data (struct CadetTunnel *t)
{
  struct CadetTunnelDelayed *tqd;
  struct CadetTunnelDelayed *next;
  unsigned int room;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "GCT_send_queued_data on tunnel %s\n",
       GCT_2s (t));

  if (GCT_is_loopback (t))
  {
    GNUNET_break (0);
    return;
  }

  if (GNUNET_NO == is_ready (t))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  not ready yet: %s/%s\n",
         estate2s (t->estate), cstate2s (t->cstate));
    return;
  }

  room = GCT_get_connections_buffer (t);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  buffer space: %u\n", room);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  tq head: %p\n", t->tq_head);
  for (tqd = t->tq_head; NULL != tqd && room > 0; tqd = next)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, " sending queued data\n");
    next = tqd->next;
    room--;
    send_prebuilt_message ((struct GNUNET_MessageHeader *) &tqd[1],
                           tqd->t, NULL, GNUNET_YES,
                           NULL != tqd->tq ? tqd->tq->cont : NULL,
                           NULL != tqd->tq ? tqd->tq->cont_cls : NULL,
                           tqd->tq);
    unqueue_data (tqd);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "GCT_send_queued_data end\n", GCP_2s (t->peer));
}


/**
 * Sends key exchange message on a tunnel, choosing the best connection.
 * Should not be called on loopback tunnels.
 *
 * @param t Tunnel on which this message is transmitted.
 * @param message Message to send. Function modifies it.
 */
static void
send_kx (struct CadetTunnel *t,
         const struct GNUNET_MessageHeader *message)
{
  struct CadetConnection *c;
  struct GNUNET_CADET_KX *msg;
  size_t size = ntohs (message->size);
  char cbuf[sizeof (struct GNUNET_CADET_KX) + size];
  uint16_t type;
  int fwd;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "GMT KX on Tunnel %s\n", GCT_2s (t));

  /* Avoid loopback. */
  if (GCT_is_loopback (t))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  loopback!\n");
    GNUNET_break (0);
    return;
  }
  type = ntohs (message->type);

  /* Even if tunnel is being destroyed, send anyway.
   * Could be a response to a rekey initiated by remote peer,
   * who is trying to create a new channel!
   */

  /* Must have a connection. */
  if (NULL == t->connection_head && CADET_TUNNEL_SEARCHING != t->cstate)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "\n\n\n");
    GNUNET_break (0);
    LOG (GNUNET_ERROR_TYPE_WARNING, "sending %s\n", GC_m2s (type));
    GCT_debug (t, GNUNET_ERROR_TYPE_WARNING);
    GCP_debug (t->peer, GNUNET_ERROR_TYPE_WARNING);
    LOG (GNUNET_ERROR_TYPE_WARNING, "\n\n\n");
    return;
  }

  msg = (struct GNUNET_CADET_KX *) cbuf;
  msg->header.type = htons (GNUNET_MESSAGE_TYPE_CADET_KX);
  msg->header.size = htons (sizeof (struct GNUNET_CADET_KX) + size);
  c = tunnel_get_connection (t);
  if (NULL == c)
  {
    GNUNET_break (GNUNET_SCHEDULER_NO_TASK != t->destroy_task
                  || CADET_TUNNEL_READY != t->cstate);
    GCT_debug (t, GNUNET_ERROR_TYPE_WARNING);
    return;
  }
  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_CADET_KX_EPHEMERAL:
    case GNUNET_MESSAGE_TYPE_CADET_KX_PING:
    case GNUNET_MESSAGE_TYPE_CADET_KX_PONG:
      memcpy (&msg[1], message, size);
      break;
    default:
      LOG (GNUNET_ERROR_TYPE_DEBUG, "unkown type %s\n",
           GC_m2s (type));
      GNUNET_break (0);
  }

  fwd = GCC_is_origin (t->connection_head->c, GNUNET_YES);
  /* TODO save handle and cancel in case of a unneeded retransmission */
  GNUNET_assert (NULL == GCC_send_prebuilt_message (&msg->header, type, 0, c,
                                                    fwd, GNUNET_YES,
                                                    NULL, NULL));
}


/**
 * Send the ephemeral key on a tunnel.
 *
 * @param t Tunnel on which to send the key.
 */
static void
send_ephemeral (struct CadetTunnel *t)
{
  LOG (GNUNET_ERROR_TYPE_INFO, "===> EPHM for %s\n", GCT_2s (t));

  kx_msg.sender_status = htonl (t->estate);
  send_kx (t, &kx_msg.header);
}

/**
 * Send a ping message on a tunnel.
 *
 * @param t Tunnel on which to send the ping.
 */
static void
send_ping (struct CadetTunnel *t)
{
  struct GNUNET_CADET_KX_Ping msg;

  LOG (GNUNET_ERROR_TYPE_INFO, "===> PING for %s\n", GCT_2s (t));
  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_KX_PING);
  msg.iv = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX);
  msg.target = *GCP_get_id (t->peer);
  msg.nonce = t->kx_ctx->challenge;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "  sending %u\n", msg.nonce);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  towards %s\n", GNUNET_i2s (&msg.target));
  t_encrypt (t, &msg.target, &msg.target,
             ping_encryption_size(), msg.iv, GNUNET_YES);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  e sending %u\n", msg.nonce);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  e towards %s\n", GNUNET_i2s (&msg.target));

  send_kx (t, &msg.header);
}


/**
 * Send a pong message on a tunnel.
 *d_
 * @param t Tunnel on which to send the pong.
 * @param challenge Value sent in the ping that we have to send back.
 */
static void
send_pong (struct CadetTunnel *t, uint32_t challenge)
{
  struct GNUNET_CADET_KX_Pong msg;

  LOG (GNUNET_ERROR_TYPE_INFO, "===> PONG for %s\n", GCT_2s (t));
  msg.header.size = htons (sizeof (msg));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_KX_PONG);
  msg.iv = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX);
  msg.nonce = challenge;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  sending %u\n", msg.nonce);
  t_encrypt (t, &msg.nonce, &msg.nonce,
             sizeof (msg.nonce), msg.iv, GNUNET_YES);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  e sending %u\n", msg.nonce);

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
  struct CadetTunnel *t = cls;

  t->rekey_task = GNUNET_SCHEDULER_NO_TASK;

  LOG (GNUNET_ERROR_TYPE_INFO, "Re-key Tunnel %s\n", GCT_2s (t));
  if (NULL != tc && 0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
    return;

  if (NULL == t->kx_ctx)
  {
    create_kx_ctx (t);
    create_keys (t);
  }
  else
  {
    struct GNUNET_TIME_Relative duration;

    if (GNUNET_SCHEDULER_NO_TASK != t->kx_ctx->finish_task)
    {
      GNUNET_SCHEDULER_cancel (t->kx_ctx->finish_task);
      t->kx_ctx->finish_task = GNUNET_SCHEDULER_NO_TASK;
    }

    duration = GNUNET_TIME_absolute_get_duration (t->kx_ctx->rekey_start_time);
    LOG (GNUNET_ERROR_TYPE_DEBUG, " kx started %s ago\n",
         GNUNET_STRINGS_relative_time_to_string (duration, GNUNET_YES));

    // FIXME make duration of old keys configurable
    if (duration.rel_value_us >= GNUNET_TIME_UNIT_MINUTES.rel_value_us)
    {
      memset (&t->kx_ctx->d_key_old, 0, sizeof (t->kx_ctx->d_key_old));
      memset (&t->kx_ctx->e_key_old, 0, sizeof (t->kx_ctx->e_key_old));
    }
  }

  send_ephemeral (t);

  switch (t->estate)
  {
    case CADET_TUNNEL_KEY_UNINITIALIZED:
      t->estate = CADET_TUNNEL_KEY_SENT;
      break;
    case CADET_TUNNEL_KEY_SENT:
      break;
    case CADET_TUNNEL_KEY_OK:
      t->estate = CADET_TUNNEL_KEY_REKEY;
      /* fall-thru */
    case CADET_TUNNEL_KEY_PING:
    case CADET_TUNNEL_KEY_REKEY:
      send_ping (t);
      break;
    default:
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Unexpected state %u\n", t->estate);
  }

  // FIXME exponential backoff
  struct GNUNET_TIME_Relative delay;

  delay = GNUNET_TIME_relative_divide (rekey_period, 16);
  delay = GNUNET_TIME_relative_min (delay, REKEY_WAIT);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  next call in %s\n",
       GNUNET_STRINGS_relative_time_to_string (delay, GNUNET_YES));
  t->rekey_task = GNUNET_SCHEDULER_add_delayed (delay, &rekey_tunnel, t);
}


/**
 * Our ephemeral key has changed, create new session key on all tunnels.
 *
 * Each tunnel will start the Key Exchange with a random delay between
 * 0 and number_of_tunnels*100 milliseconds, so there are 10 key exchanges
 * per second, on average.
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
  struct CadetTunnel *t = value;
  struct GNUNET_TIME_Relative delay;
  long n = (long) cls;
  uint32_t r;

  if (GNUNET_SCHEDULER_NO_TASK != t->rekey_task)
    return GNUNET_YES;

  if (GNUNET_YES == GCT_is_loopback (t))
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
 * Called only on shutdown, destroy every tunnel.
 *
 * @param cls Closure (unused).
 * @param key Current public key.
 * @param value Value in the hash map (tunnel).
 *
 * @return #GNUNET_YES, so we should continue to iterate,
 */
static int
destroy_iterator (void *cls,
                const struct GNUNET_PeerIdentity *key,
                void *value)
{
  struct CadetTunnel *t = value;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "GCT_shutdown destroying tunnel at %p\n", t);
  GCT_destroy (t);
  return GNUNET_YES;
}


/**
 * Notify remote peer that we don't know a channel he is talking about,
 * probably CHANNEL_DESTROY was missed.
 *
 * @param t Tunnel on which to notify.
 * @param gid ID of the channel.
 */
static void
send_channel_destroy (struct CadetTunnel *t, unsigned int gid)
{
  struct GNUNET_CADET_ChannelManage msg;

  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY);
  msg.header.size = htons (sizeof (msg));
  msg.chid = htonl (gid);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "WARNING destroying unknown channel %u on tunnel %s\n",
       gid, GCT_2s (t));
  send_prebuilt_message (&msg.header, t, NULL, GNUNET_YES, NULL, NULL, NULL);
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
handle_data (struct CadetTunnel *t,
             const struct GNUNET_CADET_Data *msg,
             int fwd)
{
  struct CadetChannel *ch;
  size_t size;

  /* Check size */
  size = ntohs (msg->header.size);
  if (size <
      sizeof (struct GNUNET_CADET_Data) +
      sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break (0);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, " payload of type %s\n",
              GC_m2s (ntohs (msg[1].header.type)));

  /* Check channel */
  ch = GCT_get_channel (t, ntohl (msg->chid));
  if (NULL == ch)
  {
    GNUNET_STATISTICS_update (stats, "# data on unknown channel",
                              1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "WARNING channel 0x%X unknown\n",
         ntohl (msg->chid));
    send_channel_destroy (t, ntohl (msg->chid));
    return;
  }

  GCCH_handle_data (ch, msg, fwd);
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
handle_data_ack (struct CadetTunnel *t,
                 const struct GNUNET_CADET_DataACK *msg,
                 int fwd)
{
  struct CadetChannel *ch;
  size_t size;

  /* Check size */
  size = ntohs (msg->header.size);
  if (size != sizeof (struct GNUNET_CADET_DataACK))
  {
    GNUNET_break (0);
    return;
  }

  /* Check channel */
  ch = GCT_get_channel (t, ntohl (msg->chid));
  if (NULL == ch)
  {
    GNUNET_STATISTICS_update (stats, "# data ack on unknown channel",
                              1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "WARNING channel %u unknown\n",
         ntohl (msg->chid));
    return;
  }

  GCCH_handle_data_ack (ch, msg, fwd);
}


/**
 * Handle channel create.
 *
 * @param t Tunnel on which the data came.
 * @param msg Data message.
 */
static void
handle_ch_create (struct CadetTunnel *t,
                  const struct GNUNET_CADET_ChannelCreate *msg)
{
  struct CadetChannel *ch;
  size_t size;

  /* Check size */
  size = ntohs (msg->header.size);
  if (size != sizeof (struct GNUNET_CADET_ChannelCreate))
  {
    GNUNET_break (0);
    return;
  }

  /* Check channel */
  ch = GCT_get_channel (t, ntohl (msg->chid));
  if (NULL != ch && ! GCT_is_loopback (t))
  {
    /* Probably a retransmission, safe to ignore */
    LOG (GNUNET_ERROR_TYPE_DEBUG, "   already exists...\n");
  }
  ch = GCCH_handle_create (t, msg);
  if (NULL != ch)
    GCT_add_channel (t, ch);
}



/**
 * Handle channel NACK: check correctness and call channel handler for NACKs.
 *
 * @param t Tunnel on which the NACK came.
 * @param msg NACK message.
 */
static void
handle_ch_nack (struct CadetTunnel *t,
                const struct GNUNET_CADET_ChannelManage *msg)
{
  struct CadetChannel *ch;
  size_t size;

  /* Check size */
  size = ntohs (msg->header.size);
  if (size != sizeof (struct GNUNET_CADET_ChannelManage))
  {
    GNUNET_break (0);
    return;
  }

  /* Check channel */
  ch = GCT_get_channel (t, ntohl (msg->chid));
  if (NULL == ch)
  {
    GNUNET_STATISTICS_update (stats, "# channel NACK on unknown channel",
                              1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "WARNING channel %u unknown\n",
         ntohl (msg->chid));
    return;
  }

  GCCH_handle_nack (ch);
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
handle_ch_ack (struct CadetTunnel *t,
               const struct GNUNET_CADET_ChannelManage *msg,
               int fwd)
{
  struct CadetChannel *ch;
  size_t size;

  /* Check size */
  size = ntohs (msg->header.size);
  if (size != sizeof (struct GNUNET_CADET_ChannelManage))
  {
    GNUNET_break (0);
    return;
  }

  /* Check channel */
  ch = GCT_get_channel (t, ntohl (msg->chid));
  if (NULL == ch)
  {
    GNUNET_STATISTICS_update (stats, "# channel ack on unknown channel",
                              1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "WARNING channel %u unknown\n",
         ntohl (msg->chid));
    return;
  }

  GCCH_handle_ack (ch, msg, fwd);
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
handle_ch_destroy (struct CadetTunnel *t,
                   const struct GNUNET_CADET_ChannelManage *msg,
                   int fwd)
{
  struct CadetChannel *ch;
  size_t size;

  /* Check size */
  size = ntohs (msg->header.size);
  if (size != sizeof (struct GNUNET_CADET_ChannelManage))
  {
    GNUNET_break (0);
    return;
  }

  /* Check channel */
  ch = GCT_get_channel (t, ntohl (msg->chid));
  if (NULL == ch)
  {
    /* Probably a retransmission, safe to ignore */
    return;
  }

  GCCH_handle_destroy (ch, msg, fwd);
}


/**
 * The peer's ephemeral key has changed: update the symmetrical keys.
 *
 * @param t Tunnel this message came on.
 * @param msg Key eXchange message.
 */
static void
handle_ephemeral (struct CadetTunnel *t,
                  const struct GNUNET_CADET_KX_Ephemeral *msg)
{
  LOG (GNUNET_ERROR_TYPE_INFO, "<=== EPHM for %s\n", GCT_2s (t));

  if (GNUNET_OK != check_ephemeral (t, msg))
  {
    GNUNET_break_op (0);
    return;
  }

  create_kx_ctx (t);
  if (0 != memcmp (&t->peers_ephemeral_key, &msg->ephemeral_key,
                   sizeof (msg->ephemeral_key)))
  {
    t->peers_ephemeral_key = msg->ephemeral_key;
    create_keys (t);
    if (CADET_TUNNEL_KEY_OK == t->estate)
    {
      t->estate = CADET_TUNNEL_KEY_REKEY;
    }
  }
  if (CADET_TUNNEL_KEY_SENT == t->estate)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  our key was sent, sending ping\n");
    send_ping (t);
    t->estate = CADET_TUNNEL_KEY_PING;
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
handle_ping (struct CadetTunnel *t,
             const struct GNUNET_CADET_KX_Ping *msg)
{
  struct GNUNET_CADET_KX_Ping res;

  if (ntohs (msg->header.size) != sizeof (res))
  {
    GNUNET_break_op (0);
    return;
  }

  LOG (GNUNET_ERROR_TYPE_INFO, "<=== PING for %s\n", GCT_2s (t));
  t_decrypt (t, &res.target, &msg->target, ping_encryption_size (), msg->iv);
  if (0 != memcmp (&my_full_id, &res.target, sizeof (my_full_id)))
  {
    GNUNET_STATISTICS_update (stats, "# malformed PINGs", 1, GNUNET_NO);
    LOG (GNUNET_ERROR_TYPE_WARNING, "  malformed PING on %s\n", GCT_2s (t));
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  e got %u\n", msg->nonce);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  e towards %s\n", GNUNET_i2s (&msg->target));
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  got %u\n", res.nonce);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  towards %s\n", GNUNET_i2s (&res.target));
    create_kx_ctx (t);
    send_ephemeral (t);
    send_ping (t);
    return;
  }

  send_pong (t, res.nonce);
}


/**
 * @brief Finish the Key eXchange and destroy the old keys.
 *
 * @param cls Closure (Tunnel for which to finish the KX).
 * @param tc Task context.
 */
static void
finish_kx (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CadetTunnel *t = cls;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  LOG (GNUNET_ERROR_TYPE_INFO, "finish KX for %s\n", GCT_2s (t));

  GNUNET_free (t->kx_ctx);
  t->kx_ctx = NULL;
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
handle_pong (struct CadetTunnel *t,
             const struct GNUNET_CADET_KX_Pong *msg)
{
  uint32_t challenge;

  LOG (GNUNET_ERROR_TYPE_INFO, "<=== PONG for %s\n", GCT_2s (t));
  if (GNUNET_SCHEDULER_NO_TASK == t->rekey_task)
  {
    GNUNET_STATISTICS_update (stats, "# duplicate PONG messages", 1, GNUNET_NO);
    return;
  }
  t_decrypt (t, &challenge, &msg->nonce, sizeof (uint32_t), msg->iv);

  if (challenge != t->kx_ctx->challenge)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, "Wrong PONG challenge on %s\n", GCT_2s (t));
    LOG (GNUNET_ERROR_TYPE_DEBUG, "PONG: %u (e: %u). Expected: %u.\n",
         challenge, msg->nonce, t->kx_ctx->challenge);
    send_ephemeral (t);
    send_ping (t);
    return;
  }
  GNUNET_SCHEDULER_cancel (t->rekey_task);
  t->rekey_task = GNUNET_SCHEDULER_NO_TASK;

  /* Don't free the old keys right away, but after a delay.
   * Rationale: the KX could have happened over a very fast connection,
   * with payload traffic still signed with the old key stuck in a slower
   * connection.
   * Don't keep the keys longer than 1/4 the rekey period, and no longer than
   * one minute.
   */
  if (GNUNET_SCHEDULER_NO_TASK == t->kx_ctx->finish_task)
  {
    struct GNUNET_TIME_Relative delay;

    delay = GNUNET_TIME_relative_divide (rekey_period, 4);
    delay = GNUNET_TIME_relative_min (delay, GNUNET_TIME_UNIT_MINUTES);
    t->kx_ctx->finish_task = GNUNET_SCHEDULER_add_delayed (delay, finish_kx, t);
  }
  GCT_change_estate (t, CADET_TUNNEL_KEY_OK);
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
handle_decrypted (struct CadetTunnel *t,
                  const struct GNUNET_MessageHeader *msgh,
                  int fwd)
{
  uint16_t type;

  type = ntohs (msgh->type);
  LOG (GNUNET_ERROR_TYPE_INFO, "<=== %s on %s\n", GC_m2s (type), GCT_2s (t));

  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_CADET_KEEPALIVE:
      /* Do nothing, connection aleady got updated. */
      GNUNET_STATISTICS_update (stats, "# keepalives received", 1, GNUNET_NO);
      break;

    case GNUNET_MESSAGE_TYPE_CADET_DATA:
      /* Don't send hop ACK, wait for client to ACK */
      handle_data (t, (struct GNUNET_CADET_Data *) msgh, fwd);
      break;

    case GNUNET_MESSAGE_TYPE_CADET_DATA_ACK:
      handle_data_ack (t, (struct GNUNET_CADET_DataACK *) msgh, fwd);
      break;

    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_CREATE:
      handle_ch_create (t,
                        (struct GNUNET_CADET_ChannelCreate *) msgh);
      break;

    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_NACK:
      handle_ch_nack (t,
                      (struct GNUNET_CADET_ChannelManage *) msgh);
      break;

    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_ACK:
      handle_ch_ack (t,
                     (struct GNUNET_CADET_ChannelManage *) msgh,
                     fwd);
      break;

    case GNUNET_MESSAGE_TYPE_CADET_CHANNEL_DESTROY:
      handle_ch_destroy (t,
                         (struct GNUNET_CADET_ChannelManage *) msgh,
                         fwd);
      break;

    default:
      GNUNET_break_op (0);
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "end-to-end message not known (%u)\n",
           ntohs (msgh->type));
      GCT_debug (t, GNUNET_ERROR_TYPE_WARNING);
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
GCT_handle_encrypted (struct CadetTunnel *t,
                      const struct GNUNET_CADET_Encrypted *msg)
{
  size_t size = ntohs (msg->header.size);
  size_t payload_size = size - sizeof (struct GNUNET_CADET_Encrypted);
  int decrypted_size;
  char cbuf [payload_size];
  struct GNUNET_MessageHeader *msgh;
  unsigned int off;

  decrypted_size = t_decrypt_and_validate (t, cbuf, &msg[1], payload_size,
                                           msg->iv, &msg->hmac);

  if (-1 == decrypted_size)
  {
    GNUNET_break_op (0);
    return;
  }

  off = 0;
  while (off < decrypted_size)
  {
    uint16_t msize;

    msgh = (struct GNUNET_MessageHeader *) &cbuf[off];
    msize = ntohs (msgh->size);
    if (msize < sizeof (struct GNUNET_MessageHeader))
    {
      GNUNET_break_op (0);
      return;
    }
    handle_decrypted (t, msgh, GNUNET_SYSERR);
    off += msize;
  }
}


/**
 * Demultiplex an encapsulated KX message by message type.
 *
 * @param t Tunnel on which the message came.
 * @param message Payload of KX message.
 */
void
GCT_handle_kx (struct CadetTunnel *t,
               const struct GNUNET_MessageHeader *message)
{
  uint16_t type;

  type = ntohs (message->type);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "kx message received\n", type);
  switch (type)
  {
    case GNUNET_MESSAGE_TYPE_CADET_KX_EPHEMERAL:
      handle_ephemeral (t, (struct GNUNET_CADET_KX_Ephemeral *) message);
      break;

    case GNUNET_MESSAGE_TYPE_CADET_KX_PING:
      handle_ping (t, (struct GNUNET_CADET_KX_Ping *) message);
      break;

    case GNUNET_MESSAGE_TYPE_CADET_KX_PONG:
      handle_pong (t, (struct GNUNET_CADET_KX_Pong *) message);
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
GCT_init (const struct GNUNET_CONFIGURATION_Handle *c,
          const struct GNUNET_CRYPTO_EddsaPrivateKey *key)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "init\n");
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (c, "CADET", "DEFAULT_TTL",
                                             &default_ttl))
  {
    GNUNET_log_config_invalid (GNUNET_ERROR_TYPE_WARNING,
                               "CADET", "DEFAULT_TTL", "USING DEFAULT");
    default_ttl = 64;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_time (c, "CADET", "REKEY_PERIOD",
                                           &rekey_period))
  {
    rekey_period = GNUNET_TIME_UNIT_DAYS;
  }

  my_private_key = key;
  kx_msg.header.size = htons (sizeof (kx_msg));
  kx_msg.header.type = htons (GNUNET_MESSAGE_TYPE_CADET_KX_EPHEMERAL);
  kx_msg.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_CADET_KX);
  kx_msg.purpose.size = htonl (ephemeral_purpose_size ());
  kx_msg.origin_identity = my_full_id;
  rekey_task = GNUNET_SCHEDULER_add_now (&rekey, NULL);

  tunnels = GNUNET_CONTAINER_multipeermap_create (128, GNUNET_YES);
}


/**
 * Shut down the tunnel subsystem.
 */
void
GCT_shutdown (void)
{
  if (GNUNET_SCHEDULER_NO_TASK != rekey_task)
  {
    GNUNET_SCHEDULER_cancel (rekey_task);
    rekey_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_CONTAINER_multipeermap_iterate (tunnels, &destroy_iterator, NULL);
  GNUNET_CONTAINER_multipeermap_destroy (tunnels);
}


/**
 * Create a tunnel.
 *
 * @param destination Peer this tunnel is towards.
 */
struct CadetTunnel *
GCT_new (struct CadetPeer *destination)
{
  struct CadetTunnel *t;

  t = GNUNET_new (struct CadetTunnel);
  t->next_chid = 0;
  t->peer = destination;

  if (GNUNET_OK !=
      GNUNET_CONTAINER_multipeermap_put (tunnels, GCP_get_id (destination), t,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    GNUNET_break (0);
    GNUNET_free (t);
    return NULL;
  }
  return t;
}


/**
 * Change the tunnel's connection state.
 *
 * @param t Tunnel whose connection state to change.
 * @param cstate New connection state.
 */
void
GCT_change_cstate (struct CadetTunnel* t, enum CadetTunnelCState cstate)
{
  if (NULL == t)
    return;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Tunnel %s cstate %s => %s\n",
       GCP_2s (t->peer), cstate2s (t->cstate), cstate2s (cstate));
  if (myid != GCP_get_short_id (t->peer) &&
      CADET_TUNNEL_READY != t->cstate &&
      CADET_TUNNEL_READY == cstate)
  {
    t->cstate = cstate;
    if (CADET_TUNNEL_KEY_OK == t->estate)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  cstate triggered send queued data\n");
      send_queued_data (t);
    }
    else if (CADET_TUNNEL_KEY_UNINITIALIZED == t->estate)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  cstate triggered rekey\n");
      rekey_tunnel (t, NULL);
    }
  }
  t->cstate = cstate;

  if (CADET_TUNNEL_READY == cstate
      && CONNECTIONS_PER_TUNNEL <= GCT_count_connections (t))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  cstate triggered stop dht\n");
    GCP_stop_search (t->peer);
  }
}

/**
 * Change the tunnel encryption state.
 *
 * @param t Tunnel whose encryption state to change.
 * @param state New encryption state.
 */
void
GCT_change_estate (struct CadetTunnel* t, enum CadetTunnelEState state)
{
  if (NULL == t)
    return;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Tunnel %s estate was %s\n",
       GCP_2s (t->peer), estate2s (t->estate));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Tunnel %s estate is now %s\n",
       GCP_2s (t->peer), estate2s (state));
  if (myid != GCP_get_short_id (t->peer) &&
      CADET_TUNNEL_KEY_OK != t->estate && CADET_TUNNEL_KEY_OK == state)
  {
    t->estate = state;
    send_queued_data (t);
    return;
  }
  t->estate = state;
}


/**
 * @brief Check if tunnel has too many connections, and remove one if necessary.
 *
 * Currently this means the newest connection, unless it is a direct one.
 * Implemented as a task to avoid freeing a connection that is in the middle
 * of being created/processed.
 *
 * @param cls Closure (Tunnel to check).
 * @param tc Task context.
 */
static void
trim_connections (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CadetTunnel *t = cls;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  if (GCT_count_connections (t) > 2 * CONNECTIONS_PER_TUNNEL)
  {
    struct CadetTConnection *iter;
    struct CadetTConnection *c;

    for (c = iter = t->connection_head; NULL != iter; iter = iter->next)
    {
      if ((NULL == c || iter->created.abs_value_us > c->created.abs_value_us)
          && GNUNET_NO == GCC_is_direct (iter->c))
      {
        c = iter;
      }
    }
    if (NULL != c)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Too many connections on tunnel %s\n",
           GCT_2s (t));
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Destroying connection %s\n",
           GCC_2s (c->c));
      GCC_destroy (c->c);
    }
    else
    {
      GNUNET_break (0);
    }
  }
}


/**
 * Add a connection to a tunnel.
 *
 * @param t Tunnel.
 * @param c Connection.
 */
void
GCT_add_connection (struct CadetTunnel *t, struct CadetConnection *c)
{
  struct CadetTConnection *aux;

  GNUNET_assert (NULL != c);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "add connection %s\n", GCC_2s (c));
  LOG (GNUNET_ERROR_TYPE_DEBUG, " to tunnel %s\n", GCT_2s (t));
  for (aux = t->connection_head; aux != NULL; aux = aux->next)
    if (aux->c == c)
      return;

  aux = GNUNET_new (struct CadetTConnection);
  aux->c = c;
  aux->created = GNUNET_TIME_absolute_get ();

  GNUNET_CONTAINER_DLL_insert (t->connection_head, t->connection_tail, aux);

  GNUNET_SCHEDULER_add_now (&trim_connections, t);
}


/**
 * Mark a path as no longer valid for this tunnel: has been tried and failed.
 *
 * @param t Tunnel to update.
 * @param path Invalid path to remove. Is destroyed after removal.
 */
void
GCT_remove_path (struct CadetTunnel *t, struct CadetPeerPath *path)
{
  GCP_remove_path (t->peer, path);
}


/**
 * Remove a connection from a tunnel.
 *
 * @param t Tunnel.
 * @param c Connection.
 */
void
GCT_remove_connection (struct CadetTunnel *t,
                       struct CadetConnection *c)
{
  struct CadetTConnection *aux;
  struct CadetTConnection *next;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Removing connection %s from tunnel %s\n",
       GCC_2s (c), GCT_2s (t));
  for (aux = t->connection_head; aux != NULL; aux = next)
  {
    next = aux->next;
    if (aux->c == c)
    {
      GNUNET_CONTAINER_DLL_remove (t->connection_head, t->connection_tail, aux);
      GNUNET_free (aux);
    }
  }

  /* Start new connections if needed */
  if (CONNECTIONS_PER_TUNNEL > GCT_count_connections (t)
      && GNUNET_SCHEDULER_NO_TASK == t->destroy_task
      && CADET_TUNNEL_SHUTDOWN != t->cstate
      && GNUNET_NO == shutting_down)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  no more connections, getting new ones\n");
    GCT_change_cstate (t, CADET_TUNNEL_SEARCHING);
    GCP_connect (t->peer);
    return;
  }

  /* If not marked as ready, no change is needed */
  if (CADET_TUNNEL_READY != t->cstate)
    return;

  /* Check if any connection is ready to maintain cstate */
  for (aux = t->connection_head; aux != NULL; aux = aux->next)
    if (CADET_CONNECTION_READY == GCC_get_state (aux->c))
      return;

  GCT_change_cstate (t, CADET_TUNNEL_WAITING);
}


/**
 * Add a channel to a tunnel.
 *
 * @param t Tunnel.
 * @param ch Channel.
 */
void
GCT_add_channel (struct CadetTunnel *t, struct CadetChannel *ch)
{
  struct CadetTChannel *aux;

  GNUNET_assert (NULL != ch);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Adding channel %p to tunnel %p\n", ch, t);

  for (aux = t->channel_head; aux != NULL; aux = aux->next)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  already there %p\n", aux->ch);
    if (aux->ch == ch)
      return;
  }

  aux = GNUNET_new (struct CadetTChannel);
  aux->ch = ch;
  LOG (GNUNET_ERROR_TYPE_DEBUG, " adding %p to %p\n", aux, t->channel_head);
  GNUNET_CONTAINER_DLL_insert_tail (t->channel_head, t->channel_tail, aux);

  if (GNUNET_SCHEDULER_NO_TASK != t->destroy_task)
  {
    GNUNET_SCHEDULER_cancel (t->destroy_task);
    t->destroy_task = GNUNET_SCHEDULER_NO_TASK;
    LOG (GNUNET_ERROR_TYPE_DEBUG, " undo destroy!\n");
  }
}


/**
 * Remove a channel from a tunnel.
 *
 * @param t Tunnel.
 * @param ch Channel.
 */
void
GCT_remove_channel (struct CadetTunnel *t, struct CadetChannel *ch)
{
  struct CadetTChannel *aux;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Removing channel %p from tunnel %p\n", ch, t);
  for (aux = t->channel_head; aux != NULL; aux = aux->next)
  {
    if (aux->ch == ch)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, " found! %s\n", GCCH_2s (ch));
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
struct CadetChannel *
GCT_get_channel (struct CadetTunnel *t, CADET_ChannelNumber chid)
{
  struct CadetTChannel *iter;

  if (NULL == t)
    return NULL;

  for (iter = t->channel_head; NULL != iter; iter = iter->next)
  {
    if (GCCH_get_id (iter->ch) == chid)
      break;
  }

  return NULL == iter ? NULL : iter->ch;
}


/**
 * @brief Destroy a tunnel and free all resources.
 *
 * Should only be called a while after the tunnel has been marked as destroyed,
 * in case there is a new channel added to the same peer shortly after marking
 * the tunnel. This way we avoid a new public key handshake.
 *
 * @param cls Closure (tunnel to destroy).
 * @param tc Task context.
 */
static void
delayed_destroy (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CadetTunnel *t = cls;
  struct CadetTConnection *iter;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "delayed destroying tunnel %p\n", t);
  if (0 != (GNUNET_SCHEDULER_REASON_SHUTDOWN & tc->reason))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Not destroying tunnel, due to shutdown. "
         "Tunnel at %p should have been freed by GCT_shutdown\n", t);
    return;
  }
  t->destroy_task = GNUNET_SCHEDULER_NO_TASK;
  t->cstate = CADET_TUNNEL_SHUTDOWN;

  for (iter = t->connection_head; NULL != iter; iter = iter->next)
  {
    GCC_send_destroy (iter->c);
  }
  GCT_destroy (t);
}


/**
 * Tunnel is empty: destroy it.
 *
 * Notifies all connections about the destruction.
 *
 * @param t Tunnel to destroy.
 */
void
GCT_destroy_empty (struct CadetTunnel *t)
{
  if (GNUNET_YES == shutting_down)
    return; /* Will be destroyed immediately anyway */

  if (GNUNET_SCHEDULER_NO_TASK != t->destroy_task)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Tunnel %s is already scheduled for destruction. Tunnel debug dump:\n",
         GCT_2s (t));
    GCT_debug (t, GNUNET_ERROR_TYPE_WARNING);
    GNUNET_break (0);
    /* should never happen, tunnel can only become empty once, and the
     * task identifier should be NO_TASK (cleaned when the tunnel was created
     * or became un-empty)
     */
    return;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Tunnel %s empty: destroying scheduled\n",
       GCT_2s (t));

  // FIXME make delay a config option
  t->destroy_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES,
                                                  &delayed_destroy, t);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Scheduled destroy of %p as %llX\n",
       t, t->destroy_task);
}


/**
 * Destroy tunnel if empty (no more channels).
 *
 * @param t Tunnel to destroy if empty.
 */
void
GCT_destroy_if_empty (struct CadetTunnel *t)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Tunnel %s destroy if empty\n", GCT_2s (t));
  if (1 < GCT_count_channels (t))
    return;

  GCT_destroy_empty (t);
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
GCT_destroy (struct CadetTunnel *t)
{
  struct CadetTConnection *iter_c;
  struct CadetTConnection *next_c;
  struct CadetTChannel *iter_ch;
  struct CadetTChannel *next_ch;

  if (NULL == t)
    return;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "destroying tunnel %s\n", GCP_2s (t->peer));

  GNUNET_break (GNUNET_YES ==
                GNUNET_CONTAINER_multipeermap_remove (tunnels,
                                                      GCP_get_id (t->peer), t));

  for (iter_c = t->connection_head; NULL != iter_c; iter_c = next_c)
  {
    next_c = iter_c->next;
    GCC_destroy (iter_c->c);
  }
  for (iter_ch = t->channel_head; NULL != iter_ch; iter_ch = next_ch)
  {
    next_ch = iter_ch->next;
    GCCH_destroy (iter_ch->ch);
    /* Should only happen on shutdown, but it's ok. */
  }

  if (GNUNET_SCHEDULER_NO_TASK != t->destroy_task)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "cancelling %llX\n", t->destroy_task);
    GNUNET_SCHEDULER_cancel (t->destroy_task);
    t->destroy_task = GNUNET_SCHEDULER_NO_TASK;
  }

  GNUNET_STATISTICS_update (stats, "# tunnels", -1, GNUNET_NO);
  GCP_set_tunnel (t->peer, NULL);

  if (GNUNET_SCHEDULER_NO_TASK != t->rekey_task)
  {
    GNUNET_SCHEDULER_cancel (t->rekey_task);
    t->rekey_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != t->kx_ctx)
  {
    if (GNUNET_SCHEDULER_NO_TASK != t->kx_ctx->finish_task)
      GNUNET_SCHEDULER_cancel (t->kx_ctx->finish_task);
    GNUNET_free (t->kx_ctx);
  }
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
struct CadetConnection *
GCT_use_path (struct CadetTunnel *t, struct CadetPeerPath *p)
{
  struct CadetConnection *c;
  struct GNUNET_CADET_Hash cid;
  unsigned int own_pos;

  if (NULL == t || NULL == p)
  {
    GNUNET_break (0);
    return NULL;
  }

  if (CADET_TUNNEL_SHUTDOWN == t->cstate)
  {
    GNUNET_break (0);
    return NULL;
  }

  for (own_pos = 0; own_pos < p->length; own_pos++)
  {
    if (p->peers[own_pos] == myid)
      break;
  }
  if (own_pos >= p->length)
  {
    GNUNET_break_op (0);
    return NULL;
  }

  GNUNET_CRYPTO_random_block (GNUNET_CRYPTO_QUALITY_NONCE, &cid, sizeof (cid));
  c = GCC_new (&cid, t, p, own_pos);
  if (NULL == c)
  {
    /* Path was flawed */
    return NULL;
  }
  GCT_add_connection (t, c);
  return c;
}


/**
 * Count created connections of a tunnel. Not necessarily ready connections!
 *
 * @param t Tunnel on which to count.
 *
 * @return Number of connections created, either being established or ready.
 */
unsigned int
GCT_count_connections (struct CadetTunnel *t)
{
  struct CadetTConnection *iter;
  unsigned int count;

  if (NULL == t)
    return 0;

  for (count = 0, iter = t->connection_head; NULL != iter; iter = iter->next)
    if (CADET_CONNECTION_DESTROYED != GCC_get_state (iter->c))
      count++;

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
GCT_count_channels (struct CadetTunnel *t)
{
  struct CadetTChannel *iter;
  unsigned int count;

  for (count = 0, iter = t->channel_head;
       NULL != iter;
       iter = iter->next, count++) /* skip */;

  return count;
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
  if (NULL == t)
  {
    GNUNET_assert (0);
    return (enum CadetTunnelCState) -1;
  }
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
  if (NULL == t)
  {
    GNUNET_assert (0);
    return (enum CadetTunnelEState) -1;
  }
  return t->estate;
}

/**
 * Get the maximum buffer space for a tunnel towards a local client.
 *
 * @param t Tunnel.
 *
 * @return Biggest buffer space offered by any channel in the tunnel.
 */
unsigned int
GCT_get_channels_buffer (struct CadetTunnel *t)
{
  struct CadetTChannel *iter;
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
GCT_get_connections_buffer (struct CadetTunnel *t)
{
  struct CadetTConnection *iter;
  unsigned int buffer;

  if (GNUNET_NO == is_ready (t))
  {
    if (count_queued_data (t) > 3)
      return 0;
    else
      return 1;
  }

  buffer = 0;
  for (iter = t->connection_head; NULL != iter; iter = iter->next)
  {
    if (GCC_get_state (iter->c) != CADET_CONNECTION_READY)
    {
      continue;
    }
    buffer += get_connection_buffer (iter);
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
GCT_get_destination (struct CadetTunnel *t)
{
  return GCP_get_id (t->peer);
}


/**
 * Get the tunnel's next free global channel ID.
 *
 * @param t Tunnel.
 *
 * @return GID of a channel free to use.
 */
CADET_ChannelNumber
GCT_get_next_chid (struct CadetTunnel *t)
{
  CADET_ChannelNumber chid;
  CADET_ChannelNumber mask;
  int result;

  /* Set bit 30 depending on the ID relationship. Bit 31 is always 0 for GID.
   * If our ID is bigger or loopback tunnel, start at 0, bit 30 = 0
   * If peer's ID is bigger, start at 0x4... bit 30 = 1
   */
  result = GNUNET_CRYPTO_cmp_peer_identity (&my_full_id, GCP_get_id (t->peer));
  if (0 > result)
    mask = 0x40000000;
  else
    mask = 0x0;
  t->next_chid |= mask;

  while (NULL != GCT_get_channel (t, t->next_chid))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Channel %u exists...\n", t->next_chid);
    t->next_chid = (t->next_chid + 1) & ~GNUNET_CADET_LOCAL_CHANNEL_ID_CLI;
    t->next_chid |= mask;
  }
  chid = t->next_chid;
  t->next_chid = (t->next_chid + 1) & ~GNUNET_CADET_LOCAL_CHANNEL_ID_CLI;
  t->next_chid |= mask;

  return chid;
}


/**
 * Send ACK on one or more channels due to buffer in connections.
 *
 * @param t Channel which has some free buffer space.
 */
void
GCT_unchoke_channels (struct CadetTunnel *t)
{
  struct CadetTChannel *iter;
  unsigned int buffer;
  unsigned int channels = GCT_count_channels (t);
  unsigned int choked_n;
  struct CadetChannel *choked[channels];

  LOG (GNUNET_ERROR_TYPE_DEBUG, "GCT_unchoke_channels on %s\n", GCT_2s (t));
  LOG (GNUNET_ERROR_TYPE_DEBUG, " head: %p\n", t->channel_head);
  if (NULL != t->channel_head)
    LOG (GNUNET_ERROR_TYPE_DEBUG, " head ch: %p\n", t->channel_head->ch);

  /* Get buffer space */
  buffer = GCT_get_connections_buffer (t);
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
    GCCH_allow_client (choked[r], GCCH_is_origin (choked[r], GNUNET_YES));
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
GCT_send_connection_acks (struct CadetTunnel *t)
{
  struct CadetTConnection *iter;
  uint32_t allowed;
  uint32_t to_allow;
  uint32_t allow_per_connection;
  unsigned int cs;
  unsigned int buffer;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Tunnel send connection ACKs on %s\n",
       GCT_2s (t));

  if (NULL == t)
  {
    GNUNET_break (0);
    return;
  }

  buffer = GCT_get_channels_buffer (t);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  buffer %u\n", buffer);

  /* Count connections, how many messages are already allowed */
  cs = GCT_count_connections (t);
  for (allowed = 0, iter = t->connection_head; NULL != iter; iter = iter->next)
  {
    allowed += get_connection_allowed (iter);
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  allowed %u\n", allowed);

  /* Make sure there is no overflow */
  if (allowed > buffer)
  {
    return;
  }

  /* Authorize connections to send more data */
  to_allow = buffer; /* - allowed; */

  for (iter = t->connection_head;
       NULL != iter && to_allow > 0;
       iter = iter->next)
  {
    allow_per_connection = to_allow/cs;
    to_allow -= allow_per_connection;
    cs--;
    if (get_connection_allowed (iter) > 64 / 3)
    {
      continue;
    }
    GCC_allow (iter->c, allow_per_connection,
               GCC_is_origin (iter->c, GNUNET_NO));
  }

  GNUNET_break (to_allow == 0);
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
GCT_cancel (struct CadetTunnelQueue *q)
{
  if (NULL != q->cq)
  {
    GCC_cancel (q->cq);
    /* tun_message_sent() will be called and free q */
  }
  else if (NULL != q->tqd)
  {
    unqueue_data (q->tqd);
    q->tqd = NULL;
    if (NULL != q->cont)
      q->cont (q->cont_cls, NULL, q, 0, 0);
    GNUNET_free (q);
  }
  else
  {
    GNUNET_break (0);
  }
}


/**
 * Sends an already built message on a tunnel, encrypting it and
 * choosing the best connection if not provided.
 *
 * @param message Message to send. Function modifies it.
 * @param t Tunnel on which this message is transmitted.
 * @param c Connection to use (autoselect if NULL).
 * @param force Force the tunnel to take the message (buffer overfill).
 * @param cont Continuation to call once message is really sent.
 * @param cont_cls Closure for @c cont.
 *
 * @return Handle to cancel message. NULL if @c cont is NULL.
 */
struct CadetTunnelQueue *
GCT_send_prebuilt_message (const struct GNUNET_MessageHeader *message,
                           struct CadetTunnel *t, struct CadetConnection *c,
                           int force, GCT_sent cont, void *cont_cls)
{
  return send_prebuilt_message (message, t, c, force, cont, cont_cls, NULL);
}


/**
 * Is the tunnel directed towards the local peer?
 *
 * @param t Tunnel.
 *
 * @return #GNUNET_YES if it is loopback.
 */
int
GCT_is_loopback (const struct CadetTunnel *t)
{
  return (myid == GCP_get_short_id (t->peer));
}


/**
 * Is the tunnel this path already?
 *
 * @param t Tunnel.
 * @param p Path.
 *
 * @return #GNUNET_YES a connection uses this path.
 */
int
GCT_is_path_used (const struct CadetTunnel *t, const struct CadetPeerPath *p)
{
  struct CadetTConnection *iter;

  for (iter = t->connection_head; NULL != iter; iter = iter->next)
    if (GCC_get_path (iter->c) == p)
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
GCT_get_path_cost (const struct CadetTunnel *t,
                   const struct CadetPeerPath *path)
{
  struct CadetTConnection *iter;
  const struct CadetPeerPath *aux;
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
      aux = GCC_get_path (iter->c);
      if (NULL == aux)
        continue;

      for (j = 0; j < aux->length; j++)
      {
        if (path->peers[i] == aux->peers[j])
        {
          overlap++;
          break;
        }
      }
    }
  }
  return path->length + overlap;
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
  if (NULL == t)
    return "(NULL)";

  return GCP_2s (t->peer);
}


/******************************************************************************/
/*****************************    INFO/DEBUG    *******************************/
/******************************************************************************/

/**
 * Log all possible info about the tunnel state.
 *
 * @param t Tunnel to debug.
 * @param level Debug level to use.
 */
void
GCT_debug (const struct CadetTunnel *t, enum GNUNET_ErrorType level)
{
  struct CadetTChannel *iterch;
  struct CadetTConnection *iterc;

  LOG (level, "TTT DEBUG TUNNEL TOWARDS %s\n", GCT_2s (t));
  LOG (level, "TTT  cstate %s, estate %s\n",
       cstate2s (t->cstate), estate2s (t->estate));
  LOG (level, "TTT  kx_ctx %p, rekey_task %u\n", t->kx_ctx, t->rekey_task);
  LOG (level, "TTT  tq_head %p, tq_tail %p\n", t->tq_head, t->tq_tail);
  LOG (level, "TTT  destroy %u\n", t->destroy_task);

  LOG (level, "TTT  channels:\n");
  for (iterch = t->channel_head; NULL != iterch; iterch = iterch->next)
  {
    LOG (level, "TTT  - %s\n", GCCH_2s (iterch->ch));
  }

  LOG (level, "TTT  connections:\n");
  for (iterc = t->connection_head; NULL != iterc; iterc = iterc->next)
  {
    LOG (level, "TTT  - %s [%u] buf: %u/%u (qn %u/%u)\n",
         GCC_2s (iterc->c), GCC_get_state (iterc->c),
         GCC_get_buffer (iterc->c, GNUNET_YES),
         GCC_get_buffer (iterc->c, GNUNET_NO),
         GCC_get_qn (iterc->c, GNUNET_YES),
         GCC_get_qn (iterc->c, GNUNET_NO));
  }

  LOG (level, "TTT DEBUG TUNNEL END\n");
}


/**
 * Iterate all tunnels.
 *
 * @param iter Iterator.
 * @param cls Closure for @c iter.
 */
void
GCT_iterate_all (GNUNET_CONTAINER_PeerMapIterator iter, void *cls)
{
  GNUNET_CONTAINER_multipeermap_iterate (tunnels, iter, cls);
}


/**
 * Count all tunnels.
 *
 * @return Number of tunnels to remote peers kept by this peer.
 */
unsigned int
GCT_count_all (void)
{
  return GNUNET_CONTAINER_multipeermap_size (tunnels);
}


/**
 * Iterate all connections of a tunnel.
 *
 * @param t Tunnel whose connections to iterate.
 * @param iter Iterator.
 * @param cls Closure for @c iter.
 */
void
GCT_iterate_connections (struct CadetTunnel *t, GCT_conn_iter iter, void *cls)
{
  struct CadetTConnection *ct;

  for (ct = t->connection_head; NULL != ct; ct = ct->next)
    iter (cls, ct->c);
}


/**
 * Iterate all channels of a tunnel.
 *
 * @param t Tunnel whose channels to iterate.
 * @param iter Iterator.
 * @param cls Closure for @c iter.
 */
void
GCT_iterate_channels (struct CadetTunnel *t, GCT_chan_iter iter, void *cls)
{
  struct CadetTChannel *cht;

  for (cht = t->channel_head; NULL != cht; cht = cht->next)
    iter (cls, cht->ch);
}
