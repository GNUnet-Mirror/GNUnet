/*
     This file is part of GNUnet.
     (C) 2009-2013 Christian Grothoff (and other contributing authors)

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
 * @file core/gnunet-service-core_kx.c
 * @brief code for managing the key exchange (SET_KEY, PING, PONG) with other peers
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-core_kx.h"
#include "gnunet-service-core.h"
#include "gnunet-service-core_clients.h"
#include "gnunet-service-core_neighbours.h"
#include "gnunet-service-core_sessions.h"
#include "gnunet_statistics_service.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_protocols.h"
#include "core.h"


/**
 * How long do we wait for SET_KEY confirmation initially?
 */
#define INITIAL_SET_KEY_RETRY_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)

/**
 * What is the minimum frequency for a PING message?
 */
#define MIN_PING_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * How often do we rekey?
 */
#define REKEY_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 12)

/**
 * What time difference do we tolerate?
 */
#define REKEY_TOLERANCE GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)

/**
 * What is the maximum age of a message for us to consider processing
 * it?  Note that this looks at the timestamp used by the other peer,
 * so clock skew between machines does come into play here.  So this
 * should be picked high enough so that a little bit of clock skew
 * does not prevent peers from connecting to us.
 */
#define MAX_MESSAGE_AGE GNUNET_TIME_UNIT_DAYS



GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message transmitted with the signed ephemeral key of a peer.  The
 * session key is then derived from the two ephemeral keys (ECDHE).
 */
struct EphemeralKeyMessage
{

  /**
   * Message type is #GNUNET_MESSAGE_TYPE_CORE_EPHEMERAL_KEY.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Status of the sender (should be in `enum PeerStateMachine`), nbo.
   */
  int32_t sender_status GNUNET_PACKED;

  /**
   * An ECC signature of the @e origin_identity asserting the validity of
   * the given ephemeral key.
   */
  struct GNUNET_CRYPTO_EddsaSignature signature;

  /**
   * Information about what is being signed.
   */
  struct GNUNET_CRYPTO_EccSignaturePurpose purpose;

  /**
   * At what time was this key created (beginning of validity).
   */
  struct GNUNET_TIME_AbsoluteNBO creation_time;

  /**
   * When does the given ephemeral key expire (end of validity).
   */
  struct GNUNET_TIME_AbsoluteNBO expiration_time;

  /**
   * Ephemeral public ECC key.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey ephemeral_key;

  /**
   * Public key of the signing peer (persistent version, not the ephemeral public key).
   */
  struct GNUNET_PeerIdentity origin_identity;

};


/**
 * We're sending an (encrypted) PING to the other peer to check if he
 * can decrypt.  The other peer should respond with a PONG with the
 * same content, except this time encrypted with the receiver's key.
 */
struct PingMessage
{
  /**
   * Message type is #GNUNET_MESSAGE_TYPE_CORE_PING.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Seed for the IV
   */
  uint32_t iv_seed GNUNET_PACKED;

  /**
   * Intended target of the PING, used primarily to check
   * that decryption actually worked.
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Random number chosen to make reply harder.
   */
  uint32_t challenge GNUNET_PACKED;
};


/**
 * Response to a PING.  Includes data from the original PING.
 */
struct PongMessage
{
  /**
   * Message type is #GNUNET_MESSAGE_TYPE_CORE_PONG.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Seed for the IV
   */
  uint32_t iv_seed GNUNET_PACKED;

  /**
   * Random number to make faking the reply harder.  Must be
   * first field after header (this is where we start to encrypt!).
   */
  uint32_t challenge GNUNET_PACKED;

  /**
   * Reserved, always zero.
   */
  uint32_t reserved;

  /**
   * Intended target of the PING, used primarily to check
   * that decryption actually worked.
   */
  struct GNUNET_PeerIdentity target;
};


/**
 * Encapsulation for encrypted messages exchanged between
 * peers.  Followed by the actual encrypted data.
 */
struct EncryptedMessage
{
  /**
   * Message type is either #GNUNET_MESSAGE_TYPE_CORE_ENCRYPTED_MESSAGE.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Random value used for IV generation.
   */
  uint32_t iv_seed GNUNET_PACKED;

  /**
   * MAC of the encrypted message (starting at 'sequence_number'),
   * used to verify message integrity. Everything after this value
   * (excluding this value itself) will be encrypted and authenticated.
   * ENCRYPTED_HEADER_SIZE must be set to the offset of the *next* field.
   */
  struct GNUNET_HashCode hmac;

  /**
   * Sequence number, in network byte order.  This field
   * must be the first encrypted/decrypted field
   */
  uint32_t sequence_number GNUNET_PACKED;

  /**
   * Reserved, always zero.
   */
  uint32_t reserved;

  /**
   * Timestamp.  Used to prevent reply of ancient messages
   * (recent messages are caught with the sequence number).
   */
  struct GNUNET_TIME_AbsoluteNBO timestamp;

};
GNUNET_NETWORK_STRUCT_END


/**
 * Number of bytes (at the beginning) of `struct EncryptedMessage`
 * that are NOT encrypted.
 */
#define ENCRYPTED_HEADER_SIZE (offsetof(struct EncryptedMessage, sequence_number))


/**
 * Information about the status of a key exchange with another peer.
 */
struct GSC_KeyExchangeInfo
{

  /**
   * DLL.
   */
  struct GSC_KeyExchangeInfo *next;

  /**
   * DLL.
   */
  struct GSC_KeyExchangeInfo *prev;

  /**
   * Identity of the peer.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * PING message we transmit to the other peer.
   */
  struct PingMessage ping;

  /**
   * Ephemeral public ECC key of the other peer.
   */
  struct GNUNET_CRYPTO_EcdhePublicKey other_ephemeral_key;

  /**
   * Key we use to encrypt our messages for the other peer
   * (initialized by us when we do the handshake).
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey encrypt_key;

  /**
   * Key we use to decrypt messages from the other peer
   * (given to us by the other peer during the handshake).
   */
  struct GNUNET_CRYPTO_SymmetricSessionKey decrypt_key;

  /**
   * At what time did the other peer generate the decryption key?
   */
  struct GNUNET_TIME_Absolute foreign_key_expires;

  /**
   * When should the session time out (if there are no PONGs)?
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * What was the last timeout we informed our monitors about?
   */
  struct GNUNET_TIME_Absolute last_notify_timeout;

  /**
   * At what frequency are we currently re-trying SET_KEY messages?
   */
  struct GNUNET_TIME_Relative set_key_retry_frequency;

  /**
   * ID of task used for re-trying SET_KEY and PING message.
   */
  GNUNET_SCHEDULER_TaskIdentifier retry_set_key_task;

  /**
   * ID of task used for sending keep-alive pings.
   */
  GNUNET_SCHEDULER_TaskIdentifier keep_alive_task;

  /**
   * Bit map indicating which of the 32 sequence numbers before the last
   * were received (good for accepting out-of-order packets and
   * estimating reliability of the connection)
   */
  unsigned int last_packets_bitmap;

  /**
   * last sequence number received on this connection (highest)
   */
  uint32_t last_sequence_number_received;

  /**
   * last sequence number transmitted
   */
  uint32_t last_sequence_number_sent;

  /**
   * What was our PING challenge number (for this peer)?
   */
  uint32_t ping_challenge;

  /**
   * What is our connection status?
   */
  enum GNUNET_CORE_KxState status;

};


/**
 * Our private key.
 */
static struct GNUNET_CRYPTO_EddsaPrivateKey *my_private_key;

/**
 * Our ephemeral private key.
 */
static struct GNUNET_CRYPTO_EcdhePrivateKey *my_ephemeral_key;

/**
 * Current message we send for a key exchange.
 */
static struct EphemeralKeyMessage current_ekm;

/**
 * Our message stream tokenizer (for encrypted payload).
 */
static struct GNUNET_SERVER_MessageStreamTokenizer *mst;

/**
 * DLL head.
 */
static struct GSC_KeyExchangeInfo *kx_head;

/**
 * DLL tail.
 */
static struct GSC_KeyExchangeInfo *kx_tail;

/**
 * Task scheduled for periodic re-generation (and thus rekeying) of our
 * ephemeral key.
 */
static GNUNET_SCHEDULER_TaskIdentifier rekey_task;

/**
 * Notification context for all monitors.
 */
static struct GNUNET_SERVER_NotificationContext *nc;


/**
 * Inform the given monitor about the KX state of
 * the given peer.
 *
 * @param client client to inform
 * @param kx key exchange state to inform about
 */
static void
monitor_notify (struct GNUNET_SERVER_Client *client,
                struct GSC_KeyExchangeInfo *kx)
{
  struct MonitorNotifyMessage msg;

  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_MONITOR_NOTIFY);
  msg.header.size = htons (sizeof (msg));
  msg.state = htonl ((uint32_t) kx->status);
  msg.peer = kx->peer;
  msg.timeout = GNUNET_TIME_absolute_hton (kx->timeout);
  GNUNET_SERVER_notification_context_unicast (nc,
                                              client,
                                              &msg.header,
                                              GNUNET_NO);
}


/**
 * Calculate seed value we should use for a message.
 *
 * @param kx key exchange context
 */
static uint32_t
calculate_seed (struct GSC_KeyExchangeInfo *kx)
{
  /* Note: may want to make this non-random and instead
     derive from key material to avoid having an undetectable
     side-channel */
  return htonl (GNUNET_CRYPTO_random_u32
		(GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX));
}


/**
 * Inform all monitors about the KX state of the given peer.
 *
 * @param kx key exchange state to inform about
 */
static void
monitor_notify_all (struct GSC_KeyExchangeInfo *kx)
{
  struct MonitorNotifyMessage msg;

  msg.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_MONITOR_NOTIFY);
  msg.header.size = htons (sizeof (msg));
  msg.state = htonl ((uint32_t) kx->status);
  msg.peer = kx->peer;
  msg.timeout = GNUNET_TIME_absolute_hton (kx->timeout);
  GNUNET_SERVER_notification_context_broadcast (nc,
                                                &msg.header,
                                                GNUNET_NO);
  kx->last_notify_timeout = kx->timeout;
}


/**
 * Derive an authentication key from "set key" information
 *
 * @param akey authentication key to derive
 * @param skey session key to use
 * @param seed seed to use
 */
static void
derive_auth_key (struct GNUNET_CRYPTO_AuthKey *akey,
                 const struct GNUNET_CRYPTO_SymmetricSessionKey *skey,
                 uint32_t seed)
{
  static const char ctx[] = "authentication key";

  GNUNET_CRYPTO_hmac_derive_key (akey, skey,
                                 &seed, sizeof (seed),
                                 skey, sizeof (struct GNUNET_CRYPTO_SymmetricSessionKey),
                                 ctx, sizeof (ctx),
                                 NULL);
}


/**
 * Derive an IV from packet information
 *
 * @param iv initialization vector to initialize
 * @param skey session key to use
 * @param seed seed to use
 * @param identity identity of the other peer to use
 */
static void
derive_iv (struct GNUNET_CRYPTO_SymmetricInitializationVector *iv,
           const struct GNUNET_CRYPTO_SymmetricSessionKey *skey, uint32_t seed,
           const struct GNUNET_PeerIdentity *identity)
{
  static const char ctx[] = "initialization vector";

  GNUNET_CRYPTO_symmetric_derive_iv (iv, skey, &seed, sizeof (seed),
				     identity,
				     sizeof (struct GNUNET_PeerIdentity), ctx,
				     sizeof (ctx), NULL);
}


/**
 * Derive an IV from pong packet information
 *
 * @param iv initialization vector to initialize
 * @param skey session key to use
 * @param seed seed to use
 * @param challenge nonce to use
 * @param identity identity of the other peer to use
 */
static void
derive_pong_iv (struct GNUNET_CRYPTO_SymmetricInitializationVector *iv,
                const struct GNUNET_CRYPTO_SymmetricSessionKey *skey, uint32_t seed,
                uint32_t challenge, const struct GNUNET_PeerIdentity *identity)
{
  static const char ctx[] = "pong initialization vector";

  GNUNET_CRYPTO_symmetric_derive_iv (iv, skey, &seed, sizeof (seed),
				     identity,
				     sizeof (struct GNUNET_PeerIdentity),
				     &challenge, sizeof (challenge),
				     ctx, sizeof (ctx),
				     NULL);
}


/**
 * Derive an AES key from key material
 *
 * @param sender peer identity of the sender
 * @param receiver peer identity of the sender
 * @param key_material high entropy key material to use
 * @param skey set to derived session key
 */
static void
derive_aes_key (const struct GNUNET_PeerIdentity *sender,
		const struct GNUNET_PeerIdentity *receiver,
		const struct GNUNET_HashCode *key_material,
		struct GNUNET_CRYPTO_SymmetricSessionKey *skey)
{
  static const char ctx[] = "aes key generation vector";

  GNUNET_CRYPTO_kdf (skey, sizeof (struct GNUNET_CRYPTO_SymmetricSessionKey),
		     ctx, sizeof (ctx),
		     key_material, sizeof (struct GNUNET_HashCode),
		     sender, sizeof (struct GNUNET_PeerIdentity),
		     receiver, sizeof (struct GNUNET_PeerIdentity),
		     NULL);
}


/**
 * Encrypt size bytes from @a in and write the result to @a out.  Use the
 * @a kx key for outbound traffic of the given neighbour.
 *
 * @param kx key information context
 * @param iv initialization vector to use
 * @param in ciphertext
 * @param out plaintext
 * @param size size of @a in/@a out
 * @return #GNUNET_OK on success
 */
static int
do_encrypt (struct GSC_KeyExchangeInfo *kx,
            const struct GNUNET_CRYPTO_SymmetricInitializationVector *iv,
            const void *in, void *out, size_t size)
{
  if (size != (uint16_t) size)
  {
    GNUNET_break (0);
    return GNUNET_NO;
  }
  GNUNET_assert (size ==
                 GNUNET_CRYPTO_symmetric_encrypt (in, (uint16_t) size,
                                            &kx->encrypt_key, iv, out));
  GNUNET_STATISTICS_update (GSC_stats, gettext_noop ("# bytes encrypted"), size,
                            GNUNET_NO);
  /* the following is too sensitive to write to log files by accident,
     so we require manual intervention to get this one... */
#if 0
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypted %u bytes for `%4s' using key %u, IV %u\n",
              (unsigned int) size, GNUNET_i2s (&kx->peer),
              (unsigned int) kx->encrypt_key.crc32, GNUNET_CRYPTO_crc32_n (iv,
                                                                           sizeof
                                                                           (iv)));
#endif
  return GNUNET_OK;
}


/**
 * Decrypt size bytes from @a in and write the result to @a out.  Use the
 * @a kx key for inbound traffic of the given neighbour.  This function does
 * NOT do any integrity-checks on the result.
 *
 * @param kx key information context
 * @param iv initialization vector to use
 * @param in ciphertext
 * @param out plaintext
 * @param size size of @a in / @a out
 * @return #GNUNET_OK on success
 */
static int
do_decrypt (struct GSC_KeyExchangeInfo *kx,
            const struct GNUNET_CRYPTO_SymmetricInitializationVector *iv,
            const void *in, void *out, size_t size)
{
  if (size != (uint16_t) size)
  {
    GNUNET_break (0);
    return GNUNET_NO;
  }
  if ( (kx->status != GNUNET_CORE_KX_STATE_KEY_RECEIVED) &&
       (kx->status != GNUNET_CORE_KX_STATE_UP) &&
       (kx->status != GNUNET_CORE_KX_STATE_REKEY_SENT) )
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (size !=
      GNUNET_CRYPTO_symmetric_decrypt (in, (uint16_t) size, &kx->decrypt_key, iv,
                                 out))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_STATISTICS_update (GSC_stats, gettext_noop ("# bytes decrypted"), size,
                            GNUNET_NO);
  /* the following is too sensitive to write to log files by accident,
     so we require manual intervention to get this one... */
#if 0
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Decrypted %u bytes from `%4s' using key %u, IV %u\n",
              (unsigned int) size, GNUNET_i2s (&kx->peer),
              (unsigned int) kx->decrypt_key.crc32, GNUNET_CRYPTO_crc32_n (iv,
                                                                           sizeof
                                                                           (*iv)));
#endif
  return GNUNET_OK;
}


/**
 * Send our key (and encrypted PING) to the other peer.
 *
 * @param kx key exchange context
 */
static void
send_key (struct GSC_KeyExchangeInfo *kx);


/**
 * Task that will retry #send_key() if our previous attempt failed.
 *
 * @param cls our `struct GSC_KeyExchangeInfo`
 * @param tc scheduler context
 */
static void
set_key_retry_task (void *cls,
                    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GSC_KeyExchangeInfo *kx = cls;

  kx->retry_set_key_task = GNUNET_SCHEDULER_NO_TASK;
  kx->set_key_retry_frequency = GNUNET_TIME_STD_BACKOFF (kx->set_key_retry_frequency);
  GNUNET_assert (GNUNET_CORE_KX_STATE_DOWN != kx->status);
  send_key (kx);
}


/**
 * Create a fresh PING message for transmission to the other peer.
 *
 * @param kx key exchange context to create PING for
 */
static void
setup_fresh_ping (struct GSC_KeyExchangeInfo *kx)
{
  struct PingMessage pp;
  struct PingMessage *pm;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;

  pm = &kx->ping;
  pm->header.size = htons (sizeof (struct PingMessage));
  pm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_PING);
  pm->iv_seed = calculate_seed (kx);
  derive_iv (&iv, &kx->encrypt_key, pm->iv_seed, &kx->peer);
  pp.challenge = kx->ping_challenge;
  pp.target = kx->peer;
  do_encrypt (kx, &iv, &pp.target, &pm->target,
              sizeof (struct PingMessage) - ((void *) &pm->target -
                                             (void *) pm));
}


/**
 * Start the key exchange with the given peer.
 *
 * @param pid identity of the peer to do a key exchange with
 * @return key exchange information context
 */
struct GSC_KeyExchangeInfo *
GSC_KX_start (const struct GNUNET_PeerIdentity *pid)
{
  struct GSC_KeyExchangeInfo *kx;
  struct GNUNET_HashCode h1;
  struct GNUNET_HashCode h2;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Initiating key exchange with `%s'\n",
              GNUNET_i2s (pid));
  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop ("# key exchanges initiated"), 1,
                            GNUNET_NO);
  kx = GNUNET_new (struct GSC_KeyExchangeInfo);
  kx->peer = *pid;
  kx->set_key_retry_frequency = INITIAL_SET_KEY_RETRY_FREQUENCY;
  GNUNET_CONTAINER_DLL_insert (kx_head,
			       kx_tail,
			       kx);
  kx->status = GNUNET_CORE_KX_STATE_KEY_SENT;
  monitor_notify_all (kx);
  GNUNET_CRYPTO_hash (pid,
                      sizeof (struct GNUNET_PeerIdentity),
                      &h1);
  GNUNET_CRYPTO_hash (&GSC_my_identity,
                      sizeof (struct GNUNET_PeerIdentity),
                      &h2);
  if (0 < GNUNET_CRYPTO_hash_cmp (&h1,
				  &h2))
  {
    /* peer with "lower" identity starts KX, otherwise we typically end up
       with both peers starting the exchange and transmit the 'set key'
       message twice */
    send_key (kx);
  }
  else
  {
    /* peer with "higher" identity starts a delayed  KX, if the "lower" peer
     * does not start a KX since he sees no reasons to do so  */
    kx->retry_set_key_task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
                                                           &set_key_retry_task, kx);
  }
  return kx;
}


/**
 * Stop key exchange with the given peer.  Clean up key material.
 *
 * @param kx key exchange to stop
 */
void
GSC_KX_stop (struct GSC_KeyExchangeInfo *kx)
{
  GSC_SESSIONS_end (&kx->peer);
  GNUNET_STATISTICS_update (GSC_stats, gettext_noop ("# key exchanges stopped"),
                            1, GNUNET_NO);
  if (kx->retry_set_key_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (kx->retry_set_key_task);
    kx->retry_set_key_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (kx->keep_alive_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (kx->keep_alive_task);
    kx->keep_alive_task = GNUNET_SCHEDULER_NO_TASK;
  }
  kx->status = GNUNET_CORE_KX_PEER_DISCONNECT;
  monitor_notify_all (kx);
  GNUNET_CONTAINER_DLL_remove (kx_head,
			       kx_tail,
			       kx);
  GNUNET_free (kx);
}


/**
 * Send our PING to the other peer.
 *
 * @param kx key exchange context
 */
static void
send_ping (struct GSC_KeyExchangeInfo *kx)
{
  GSC_NEIGHBOURS_transmit (&kx->peer,
                           &kx->ping.header,
                           MIN_PING_FREQUENCY);
}


/**
 * Derive fresh session keys from the current ephemeral keys.
 *
 * @param kx session to derive keys for
 */
static void
derive_session_keys (struct GSC_KeyExchangeInfo *kx)
{
  struct GNUNET_HashCode key_material;

  if (GNUNET_OK !=
      GNUNET_CRYPTO_ecc_ecdh (my_ephemeral_key,
			      &kx->other_ephemeral_key,
			      &key_material))
  {
    GNUNET_break (0);
    return;
  }
  derive_aes_key (&GSC_my_identity,
		  &kx->peer,
		  &key_material,
		  &kx->encrypt_key);
  derive_aes_key (&kx->peer,
		  &GSC_my_identity,
		  &key_material,
		  &kx->decrypt_key);
  memset (&key_material, 0, sizeof (key_material));
  /* fresh key, reset sequence numbers */
  kx->last_sequence_number_received = 0;
  kx->last_packets_bitmap = 0;
  setup_fresh_ping (kx);
}


/**
 * We received a SET_KEY message.  Validate and update
 * our key material and status.
 *
 * @param kx key exchange status for the corresponding peer
 * @param msg the set key message we received
 */
void
GSC_KX_handle_ephemeral_key (struct GSC_KeyExchangeInfo *kx,
			     const struct GNUNET_MessageHeader *msg)
{
  const struct EphemeralKeyMessage *m;
  struct GNUNET_TIME_Absolute start_t;
  struct GNUNET_TIME_Absolute end_t;
  struct GNUNET_TIME_Absolute now;
  enum GNUNET_CORE_KxState sender_status;
  uint16_t size;

  size = ntohs (msg->size);
  if (sizeof (struct EphemeralKeyMessage) != size)
  {
    GNUNET_break_op (0);
    return;
  }
  m = (const struct EphemeralKeyMessage *) msg;
  end_t = GNUNET_TIME_absolute_ntoh (m->expiration_time);
  if ( ( (GNUNET_CORE_KX_STATE_KEY_RECEIVED == kx->status) ||
	 (GNUNET_CORE_KX_STATE_UP == kx->status) ||
	 (GNUNET_CORE_KX_STATE_REKEY_SENT == kx->status) ) &&
       (end_t.abs_value_us <= kx->foreign_key_expires.abs_value_us) )
  {
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop ("# old ephemeral keys ignored"),
			      1, GNUNET_NO);
    return;
  }
  start_t = GNUNET_TIME_absolute_ntoh (m->creation_time);

  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop ("# ephemeral keys received"),
                            1, GNUNET_NO);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service receives `%s' request from `%4s'.\n", "EPHEMERAL_KEY",
              GNUNET_i2s (&kx->peer));
  if (0 !=
      memcmp (&m->origin_identity,
	      &kx->peer.public_key,
              sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break_op (0);
    return;
  }
  if ((ntohl (m->purpose.size) !=
       sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
       sizeof (struct GNUNET_TIME_AbsoluteNBO) +
       sizeof (struct GNUNET_TIME_AbsoluteNBO) +
       sizeof (struct GNUNET_CRYPTO_EddsaPublicKey) +
       sizeof (struct GNUNET_CRYPTO_EddsaPublicKey)) ||
      (GNUNET_OK !=
       GNUNET_CRYPTO_eddsa_verify (GNUNET_SIGNATURE_PURPOSE_SET_ECC_KEY,
				 &m->purpose,
                                 &m->signature, &m->origin_identity.public_key)))
  {
    /* invalid signature */
    GNUNET_break_op (0);
    return;
  }
  now = GNUNET_TIME_absolute_get ();
  if ( (end_t.abs_value_us < GNUNET_TIME_absolute_subtract (now, REKEY_TOLERANCE).abs_value_us) ||
       (start_t.abs_value_us > GNUNET_TIME_absolute_add (now, REKEY_TOLERANCE).abs_value_us) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Ephemeral key message from peer `%s' rejected as its validity range does not match our system time (%llu not in [%llu,%llu]).\n"),
		GNUNET_i2s (&kx->peer),
		now.abs_value_us,
		start_t.abs_value_us,
		end_t.abs_value_us);
    return;
  }
  kx->other_ephemeral_key = m->ephemeral_key;
  kx->foreign_key_expires = end_t;
  derive_session_keys (kx);
  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop ("# EPHEMERAL_KEY messages received"), 1,
                            GNUNET_NO);

  /* check if we still need to send the sender our key */
  sender_status = (enum GNUNET_CORE_KxState) ntohl (m->sender_status);
  switch (sender_status)
  {
  case GNUNET_CORE_KX_STATE_DOWN:
    GNUNET_break_op (0);
    break;
  case GNUNET_CORE_KX_STATE_KEY_SENT:
    /* fine, need to send our key after updating our status, see below */
    GSC_SESSIONS_reinit (&kx->peer);
    break;
  case GNUNET_CORE_KX_STATE_KEY_RECEIVED:
    /* other peer already got our key, but typemap did go down */
    GSC_SESSIONS_reinit (&kx->peer);
    break;
  case GNUNET_CORE_KX_STATE_UP:
    /* other peer already got our key, typemap NOT down */
    break;
  case GNUNET_CORE_KX_STATE_REKEY_SENT:
    /* other peer already got our key, typemap NOT down */
    break;
  default:
    GNUNET_break (0);
    break;
  }
  /* check if we need to confirm everything is fine via PING + PONG */
  switch (kx->status)
  {
  case GNUNET_CORE_KX_STATE_DOWN:
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == kx->keep_alive_task);
    kx->status = GNUNET_CORE_KX_STATE_KEY_RECEIVED;
    monitor_notify_all (kx);
    if (GNUNET_CORE_KX_STATE_KEY_SENT == sender_status)
      send_key (kx);
    send_ping (kx);
    break;
  case GNUNET_CORE_KX_STATE_KEY_SENT:
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == kx->keep_alive_task);
    kx->status = GNUNET_CORE_KX_STATE_KEY_RECEIVED;
    monitor_notify_all (kx);
    if (GNUNET_CORE_KX_STATE_KEY_SENT == sender_status)
      send_key (kx);
    send_ping (kx);
    break;
  case GNUNET_CORE_KX_STATE_KEY_RECEIVED:
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == kx->keep_alive_task);
    if (GNUNET_CORE_KX_STATE_KEY_SENT == sender_status)
      send_key (kx);
    send_ping (kx);
    break;
  case GNUNET_CORE_KX_STATE_UP:
    kx->status = GNUNET_CORE_KX_STATE_REKEY_SENT;
    monitor_notify_all (kx);
    if (GNUNET_CORE_KX_STATE_KEY_SENT == sender_status)
      send_key (kx);
    /* we got a new key, need to reconfirm! */
    send_ping (kx);
    break;
  case GNUNET_CORE_KX_STATE_REKEY_SENT:
    if (GNUNET_CORE_KX_STATE_KEY_SENT == sender_status)
      send_key (kx);
    /* we got a new key, need to reconfirm! */
    send_ping (kx);
    break;
  default:
    GNUNET_break (0);
    break;
  }
}


/**
 * We received a PING message.  Validate and transmit
 * a PONG message.
 *
 * @param kx key exchange status for the corresponding peer
 * @param msg the encrypted PING message itself
 */
void
GSC_KX_handle_ping (struct GSC_KeyExchangeInfo *kx,
                    const struct GNUNET_MessageHeader *msg)
{
  const struct PingMessage *m;
  struct PingMessage t;
  struct PongMessage tx;
  struct PongMessage tp;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  uint16_t msize;

  msize = ntohs (msg->size);
  if (msize != sizeof (struct PingMessage))
  {
    GNUNET_break_op (0);
    return;
  }
  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop ("# PING messages received"), 1,
                            GNUNET_NO);
  if ( (kx->status != GNUNET_CORE_KX_STATE_KEY_RECEIVED) &&
       (kx->status != GNUNET_CORE_KX_STATE_UP) &&
       (kx->status != GNUNET_CORE_KX_STATE_REKEY_SENT))
  {
    /* ignore */
    GNUNET_STATISTICS_update (GSC_stats,
			      gettext_noop ("# PING messages dropped (out of order)"), 1,
			      GNUNET_NO);
    return;
  }
  m = (const struct PingMessage *) msg;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service receives `%s' request from `%4s'.\n", "PING",
              GNUNET_i2s (&kx->peer));
  derive_iv (&iv, &kx->decrypt_key, m->iv_seed, &GSC_my_identity);
  if (GNUNET_OK !=
      do_decrypt (kx, &iv, &m->target, &t.target,
                  sizeof (struct PingMessage) - ((void *) &m->target -
                                                 (void *) m)))
  {
    GNUNET_break_op (0);
    return;
  }
  if (0 !=
      memcmp (&t.target, &GSC_my_identity, sizeof (struct GNUNET_PeerIdentity)))
  {
    char sender[9];
    char peer[9];

    GNUNET_snprintf (sender, sizeof (sender), "%8s", GNUNET_i2s (&kx->peer));
    GNUNET_snprintf (peer, sizeof (peer), "%8s", GNUNET_i2s (&t.target));
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("Received PING from `%s' for different identity: I am `%s', PONG identity: `%s'\n"),
                sender, GNUNET_i2s (&GSC_my_identity), peer);
    GNUNET_break_op (0);
    return;
  }
  /* construct PONG */
  tx.reserved = 0;
  tx.challenge = t.challenge;
  tx.target = t.target;
  tp.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_PONG);
  tp.header.size = htons (sizeof (struct PongMessage));
  tp.iv_seed = calculate_seed (kx);
  derive_pong_iv (&iv, &kx->encrypt_key, tp.iv_seed, t.challenge, &kx->peer);
  do_encrypt (kx, &iv, &tx.challenge, &tp.challenge,
              sizeof (struct PongMessage) - ((void *) &tp.challenge -
                                             (void *) &tp));
  GNUNET_STATISTICS_update (GSC_stats, gettext_noop ("# PONG messages created"),
                            1, GNUNET_NO);
  GSC_NEIGHBOURS_transmit (&kx->peer,
                           &tp.header,
                           GNUNET_TIME_UNIT_FOREVER_REL /* FIXME: timeout */ );
}


/**
 * Task triggered when a neighbour entry is about to time out
 * (and we should prevent this by sending a PING).
 *
 * @param cls the 'struct GSC_KeyExchangeInfo'
 * @param tc scheduler context (not used)
 */
static void
send_keep_alive (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GSC_KeyExchangeInfo *kx = cls;
  struct GNUNET_TIME_Relative retry;
  struct GNUNET_TIME_Relative left;

  kx->keep_alive_task = GNUNET_SCHEDULER_NO_TASK;
  left = GNUNET_TIME_absolute_get_remaining (kx->timeout);
  if (0 == left.rel_value_us)
  {
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop ("# sessions terminated by timeout"),
                              1, GNUNET_NO);
    GSC_SESSIONS_end (&kx->peer);
    kx->status = GNUNET_CORE_KX_STATE_KEY_SENT;
    monitor_notify_all (kx);
    send_key (kx);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending KEEPALIVE to `%s'\n",
              GNUNET_i2s (&kx->peer));
  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop ("# keepalive messages sent"), 1,
                            GNUNET_NO);
  setup_fresh_ping (kx);
  GSC_NEIGHBOURS_transmit (&kx->peer,
                           &kx->ping.header,
                           kx->set_key_retry_frequency);
  retry =
      GNUNET_TIME_relative_max (GNUNET_TIME_relative_divide (left, 2),
                                MIN_PING_FREQUENCY);
  kx->keep_alive_task =
      GNUNET_SCHEDULER_add_delayed (retry, &send_keep_alive, kx);
}


/**
 * We've seen a valid message from the other peer.
 * Update the time when the session would time out
 * and delay sending our keep alive message further.
 *
 * @param kx key exchange where we saw activity
 */
static void
update_timeout (struct GSC_KeyExchangeInfo *kx)
{
  struct GNUNET_TIME_Relative delta;

  kx->timeout =
      GNUNET_TIME_relative_to_absolute
      (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  delta = GNUNET_TIME_absolute_get_difference (kx->last_notify_timeout,
                                               kx->timeout);
  if (delta.rel_value_us > 5LL * 1000LL * 1000LL)
  {
    /* we only notify monitors about timeout changes if those
       are bigger than the threshold (5s) */
    monitor_notify_all (kx);
  }
  if (kx->keep_alive_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (kx->keep_alive_task);
  kx->keep_alive_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_divide
                                    (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                     2), &send_keep_alive, kx);
}


/**
 * We received a PONG message.  Validate and update our status.
 *
 * @param kx key exchange context for the the PONG
 * @param msg the encrypted PONG message itself
 */
void
GSC_KX_handle_pong (struct GSC_KeyExchangeInfo *kx,
                    const struct GNUNET_MessageHeader *msg)
{
  const struct PongMessage *m;
  struct PongMessage t;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  uint16_t msize;

  msize = ntohs (msg->size);
  if (sizeof (struct PongMessage) != msize)
  {
    GNUNET_break_op (0);
    return;
  }
  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop ("# PONG messages received"), 1,
                            GNUNET_NO);
  switch (kx->status)
  {
  case GNUNET_CORE_KX_STATE_DOWN:
    GNUNET_STATISTICS_update (GSC_stats,
			      gettext_noop ("# PONG messages dropped (connection down)"), 1,
			      GNUNET_NO);
    return;
  case GNUNET_CORE_KX_STATE_KEY_SENT:
    GNUNET_STATISTICS_update (GSC_stats,
			      gettext_noop ("# PONG messages dropped (out of order)"), 1,
			      GNUNET_NO);
    return;
  case GNUNET_CORE_KX_STATE_KEY_RECEIVED:
    break;
  case GNUNET_CORE_KX_STATE_UP:
    break;
  case GNUNET_CORE_KX_STATE_REKEY_SENT:
    break;
  default:
    GNUNET_break (0);
    return;
  }
  m = (const struct PongMessage *) msg;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service receives `%s' response from `%4s'.\n", "PONG",
              GNUNET_i2s (&kx->peer));
  /* mark as garbage, just to be sure */
  memset (&t, 255, sizeof (t));
  derive_pong_iv (&iv, &kx->decrypt_key, m->iv_seed, kx->ping_challenge,
                  &GSC_my_identity);
  if (GNUNET_OK !=
      do_decrypt (kx, &iv, &m->challenge, &t.challenge,
                  sizeof (struct PongMessage) - ((void *) &m->challenge -
                                                 (void *) m)))
  {
    GNUNET_break_op (0);
    return;
  }
  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop ("# PONG messages decrypted"), 1,
                            GNUNET_NO);
  if ((0 != memcmp (&t.target, &kx->peer, sizeof (struct GNUNET_PeerIdentity)))
      || (kx->ping_challenge != t.challenge))
  {
    /* PONG malformed */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received malformed `%s' wanted sender `%4s' with challenge %u\n",
                "PONG", GNUNET_i2s (&kx->peer),
                (unsigned int) kx->ping_challenge);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received malformed `%s' received from `%4s' with challenge %u\n",
                "PONG", GNUNET_i2s (&t.target), (unsigned int) t.challenge);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received PONG from `%s'\n",
              GNUNET_i2s (&kx->peer));
  /* no need to resend key any longer */
  if (GNUNET_SCHEDULER_NO_TASK != kx->retry_set_key_task)
  {
    GNUNET_SCHEDULER_cancel (kx->retry_set_key_task);
    kx->retry_set_key_task = GNUNET_SCHEDULER_NO_TASK;
  }
  switch (kx->status)
  {
  case GNUNET_CORE_KX_STATE_DOWN:
    GNUNET_assert (0);           /* should be impossible */
    return;
  case GNUNET_CORE_KX_STATE_KEY_SENT:
    GNUNET_assert (0);           /* should be impossible */
    return;
  case GNUNET_CORE_KX_STATE_KEY_RECEIVED:
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop
                              ("# session keys confirmed via PONG"), 1,
                              GNUNET_NO);
    kx->status = GNUNET_CORE_KX_STATE_UP;
    monitor_notify_all (kx);
    GSC_SESSIONS_create (&kx->peer, kx);
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == kx->keep_alive_task);
    update_timeout (kx);
    break;
  case GNUNET_CORE_KX_STATE_UP:
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop
                              ("# timeouts prevented via PONG"), 1,
                              GNUNET_NO);
    update_timeout (kx);
    break;
  case GNUNET_CORE_KX_STATE_REKEY_SENT:
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop
                              ("# rekey operations confirmed via PONG"), 1,
                              GNUNET_NO);
    kx->status = GNUNET_CORE_KX_STATE_UP;
    monitor_notify_all (kx);
    update_timeout (kx);
    break;
  default:
    GNUNET_break (0);
    break;
  }
}


/**
 * Send our key to the other peer.
 *
 * @param kx key exchange context
 */
static void
send_key (struct GSC_KeyExchangeInfo *kx)
{
  GNUNET_assert (GNUNET_CORE_KX_STATE_DOWN != kx->status);
  if (GNUNET_SCHEDULER_NO_TASK != kx->retry_set_key_task)
  {
     GNUNET_SCHEDULER_cancel (kx->retry_set_key_task);
     kx->retry_set_key_task = GNUNET_SCHEDULER_NO_TASK;
  }
  /* always update sender status in SET KEY message */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Sending key to `%s' (my status: %d)\n",
              GNUNET_i2s (&kx->peer),
	      kx->status);
  current_ekm.sender_status = htonl ((int32_t) (kx->status));
  GSC_NEIGHBOURS_transmit (&kx->peer,
                           &current_ekm.header,
                           kx->set_key_retry_frequency);
  kx->retry_set_key_task =
      GNUNET_SCHEDULER_add_delayed (kx->set_key_retry_frequency,
                                    &set_key_retry_task, kx);
}


/**
 * Encrypt and transmit a message with the given payload.
 *
 * @param kx key exchange context
 * @param payload payload of the message
 * @param payload_size number of bytes in @a payload
 */
void
GSC_KX_encrypt_and_transmit (struct GSC_KeyExchangeInfo *kx,
                             const void *payload,
                             size_t payload_size)
{
  size_t used = payload_size + sizeof (struct EncryptedMessage);
  char pbuf[used];              /* plaintext */
  char cbuf[used];              /* ciphertext */
  struct EncryptedMessage *em;  /* encrypted message */
  struct EncryptedMessage *ph;  /* plaintext header */
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  struct GNUNET_CRYPTO_AuthKey auth_key;

  ph = (struct EncryptedMessage *) pbuf;
  ph->sequence_number = htonl (++kx->last_sequence_number_sent);
  ph->iv_seed = calculate_seed (kx);
  ph->reserved = 0;
  ph->timestamp = GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get ());
  memcpy (&ph[1], payload, payload_size);

  em = (struct EncryptedMessage *) cbuf;
  em->header.size = htons (used);
  em->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_ENCRYPTED_MESSAGE);
  em->iv_seed = ph->iv_seed;
  derive_iv (&iv, &kx->encrypt_key, ph->iv_seed, &kx->peer);
  GNUNET_assert (GNUNET_OK ==
                 do_encrypt (kx, &iv, &ph->sequence_number,
                             &em->sequence_number,
                             used - ENCRYPTED_HEADER_SIZE));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Encrypted %u bytes for %s\n",
              used - ENCRYPTED_HEADER_SIZE, GNUNET_i2s (&kx->peer));
  derive_auth_key (&auth_key,
		   &kx->encrypt_key,
		   ph->iv_seed);
  GNUNET_CRYPTO_hmac (&auth_key, &em->sequence_number,
                      used - ENCRYPTED_HEADER_SIZE, &em->hmac);
  GSC_NEIGHBOURS_transmit (&kx->peer,
                           &em->header,
                           GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Closure for #deliver_message()
 */
struct DeliverMessageContext
{

  /**
   * Key exchange context.
   */
  struct GSC_KeyExchangeInfo *kx;

  /**
   * Sender of the message.
   */
  const struct GNUNET_PeerIdentity *peer;
};


/**
 * We received an encrypted message.  Decrypt, validate and
 * pass on to the appropriate clients.
 *
 * @param kx key exchange context for encrypting the message
 * @param msg encrypted message
 */
void
GSC_KX_handle_encrypted_message (struct GSC_KeyExchangeInfo *kx,
                                 const struct GNUNET_MessageHeader *msg)
{
  const struct EncryptedMessage *m;
  struct EncryptedMessage *pt;  /* plaintext */
  struct GNUNET_HashCode ph;
  uint32_t snum;
  struct GNUNET_TIME_Absolute t;
  struct GNUNET_CRYPTO_SymmetricInitializationVector iv;
  struct GNUNET_CRYPTO_AuthKey auth_key;
  struct DeliverMessageContext dmc;
  uint16_t size = ntohs (msg->size);
  char buf[size] GNUNET_ALIGN;

  if (size <
      sizeof (struct EncryptedMessage) + sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return;
  }
  m = (const struct EncryptedMessage *) msg;
  if (GNUNET_CORE_KX_STATE_UP != kx->status)
  {
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop
                              ("# DATA message dropped (out of order)"),
                              1, GNUNET_NO);
    return;
  }
  if (0 == GNUNET_TIME_absolute_get_remaining (kx->foreign_key_expires).rel_value_us)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		_("Session to peer `%s' went down due to key expiration (should not happen)\n"),
		GNUNET_i2s (&kx->peer));
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop ("# sessions terminated by key expiration"),
                              1, GNUNET_NO);
    GSC_SESSIONS_end (&kx->peer);
    if (GNUNET_SCHEDULER_NO_TASK != kx->keep_alive_task)
    {
      GNUNET_SCHEDULER_cancel (kx->keep_alive_task);
      kx->keep_alive_task = GNUNET_SCHEDULER_NO_TASK;
    }
    kx->status = GNUNET_CORE_KX_STATE_KEY_SENT;
    monitor_notify_all (kx);
    send_key (kx);
    return;
  }

  /* validate hash */
  derive_auth_key (&auth_key, &kx->decrypt_key, m->iv_seed);
  GNUNET_CRYPTO_hmac (&auth_key, &m->sequence_number,
                      size - ENCRYPTED_HEADER_SIZE, &ph);
  if (0 != memcmp (&ph, &m->hmac, sizeof (struct GNUNET_HashCode)))
  {
    /* checksum failed */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Failed checksum validation for a message from `%s'\n",
		GNUNET_i2s (&kx->peer));
    return;
  }
  derive_iv (&iv, &kx->decrypt_key, m->iv_seed, &GSC_my_identity);
  /* decrypt */
  if (GNUNET_OK !=
      do_decrypt (kx, &iv, &m->sequence_number, &buf[ENCRYPTED_HEADER_SIZE],
                  size - ENCRYPTED_HEADER_SIZE))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Decrypted %u bytes from %s\n",
              size - ENCRYPTED_HEADER_SIZE,
              GNUNET_i2s (&kx->peer));
  pt = (struct EncryptedMessage *) buf;

  /* validate sequence number */
  snum = ntohl (pt->sequence_number);
  if (kx->last_sequence_number_received == snum)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received duplicate message, ignoring.\n");
    /* duplicate, ignore */
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop ("# bytes dropped (duplicates)"),
                              size, GNUNET_NO);
    return;
  }
  if ((kx->last_sequence_number_received > snum) &&
      (kx->last_sequence_number_received - snum > 32))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received ancient out of sequence message, ignoring.\n");
    /* ancient out of sequence, ignore */
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop
                              ("# bytes dropped (out of sequence)"), size,
                              GNUNET_NO);
    return;
  }
  if (kx->last_sequence_number_received > snum)
  {
    unsigned int rotbit = 1 << (kx->last_sequence_number_received - snum - 1);

    if ((kx->last_packets_bitmap & rotbit) != 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received duplicate message, ignoring.\n");
      GNUNET_STATISTICS_update (GSC_stats,
                                gettext_noop ("# bytes dropped (duplicates)"),
                                size, GNUNET_NO);
      /* duplicate, ignore */
      return;
    }
    kx->last_packets_bitmap |= rotbit;
  }
  if (kx->last_sequence_number_received < snum)
  {
    unsigned int shift = (snum - kx->last_sequence_number_received);

    if (shift >= 8 * sizeof (kx->last_packets_bitmap))
      kx->last_packets_bitmap = 0;
    else
      kx->last_packets_bitmap <<= shift;
    kx->last_sequence_number_received = snum;
  }

  /* check timestamp */
  t = GNUNET_TIME_absolute_ntoh (pt->timestamp);
  if (GNUNET_TIME_absolute_get_duration (t).rel_value_us >
      MAX_MESSAGE_AGE.rel_value_us)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Message received far too old (%s). Content ignored.\n",
                GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_duration (t),
                                                        GNUNET_YES));
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop
                              ("# bytes dropped (ancient message)"), size,
                              GNUNET_NO);
    return;
  }

  /* process decrypted message(s) */
  update_timeout (kx);
  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop ("# bytes of payload decrypted"),
                            size - sizeof (struct EncryptedMessage),
                            GNUNET_NO);
  dmc.kx = kx;
  dmc.peer = &kx->peer;
  if (GNUNET_OK !=
      GNUNET_SERVER_mst_receive (mst, &dmc,
                                 &buf[sizeof (struct EncryptedMessage)],
                                 size - sizeof (struct EncryptedMessage),
                                 GNUNET_YES,
                                 GNUNET_NO))
    GNUNET_break_op (0);
}


/**
 * Deliver P2P message to interested clients.
 * Invokes send twice, once for clients that want the full message, and once
 * for clients that only want the header
 *
 * @param cls always NULL
 * @param client who sent us the message (struct GSC_KeyExchangeInfo)
 * @param m the message
 */
static int
deliver_message (void *cls,
                 void *client,
                 const struct GNUNET_MessageHeader *m)
{
  struct DeliverMessageContext *dmc = client;

  if (GNUNET_CORE_KX_STATE_UP != dmc->kx->status)
  {
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop
                              ("# PAYLOAD dropped (out of order)"),
                              1, GNUNET_NO);
    return GNUNET_OK;
  }
  switch (ntohs (m->type))
  {
  case GNUNET_MESSAGE_TYPE_CORE_BINARY_TYPE_MAP:
  case GNUNET_MESSAGE_TYPE_CORE_COMPRESSED_TYPE_MAP:
    GSC_SESSIONS_set_typemap (dmc->peer, m);
    return GNUNET_OK;
  case GNUNET_MESSAGE_TYPE_CORE_CONFIRM_TYPE_MAP:
    GSC_SESSIONS_confirm_typemap (dmc->peer, m);
    return GNUNET_OK;
  default:
    GSC_CLIENTS_deliver_message (dmc->peer, m,
                                 ntohs (m->size),
                                 GNUNET_CORE_OPTION_SEND_FULL_INBOUND);
    GSC_CLIENTS_deliver_message (dmc->peer, m,
                                 sizeof (struct GNUNET_MessageHeader),
                                 GNUNET_CORE_OPTION_SEND_HDR_INBOUND);
  }
  return GNUNET_OK;
}


/**
 * Setup the message that links the ephemeral key to our persistent
 * public key and generate the appropriate signature.
 */
static void
sign_ephemeral_key ()
{
  current_ekm.header.size = htons (sizeof (struct EphemeralKeyMessage));
  current_ekm.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_EPHEMERAL_KEY);
  current_ekm.sender_status = 0; /* to be set later */
  current_ekm.purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_SET_ECC_KEY);
  current_ekm.purpose.size = htonl (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
				    sizeof (struct GNUNET_TIME_AbsoluteNBO) +
				    sizeof (struct GNUNET_TIME_AbsoluteNBO) +
				    sizeof (struct GNUNET_CRYPTO_EcdhePublicKey) +
				    sizeof (struct GNUNET_PeerIdentity));
  current_ekm.creation_time = GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get ());
  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (GSC_cfg,
					    "core",
					    "USE_EPHEMERAL_KEYS"))
  {
    current_ekm.expiration_time = GNUNET_TIME_absolute_hton (GNUNET_TIME_relative_to_absolute (GNUNET_TIME_relative_add (REKEY_FREQUENCY,
															 REKEY_TOLERANCE)));
  }
  else
  {
    current_ekm.expiration_time = GNUNET_TIME_absolute_hton (GNUNET_TIME_UNIT_FOREVER_ABS);
  }
  GNUNET_CRYPTO_ecdhe_key_get_public (my_ephemeral_key,
                                      &current_ekm.ephemeral_key);
  current_ekm.origin_identity = GSC_my_identity;
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CRYPTO_eddsa_sign (my_private_key,
					 &current_ekm.purpose,
					 &current_ekm.signature));
}


/**
 * Task run to trigger rekeying.
 *
 * @param cls closure, NULL
 * @param tc scheduler context
 */
static void
do_rekey (void *cls,
	  const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GSC_KeyExchangeInfo *pos;

  rekey_task = GNUNET_SCHEDULER_add_delayed (REKEY_FREQUENCY,
					     &do_rekey,
					     NULL);
  if (NULL != my_ephemeral_key)
    GNUNET_free (my_ephemeral_key);
  my_ephemeral_key = GNUNET_CRYPTO_ecdhe_key_create ();
  GNUNET_assert (NULL != my_ephemeral_key);
  sign_ephemeral_key ();
  for (pos = kx_head; NULL != pos; pos = pos->next)
  {
    if (GNUNET_CORE_KX_STATE_UP == pos->status)
    {
      pos->status = GNUNET_CORE_KX_STATE_REKEY_SENT;
      monitor_notify_all (pos);
      derive_session_keys (pos);
    }
    if (GNUNET_CORE_KX_STATE_DOWN == pos->status)
    {
      pos->status = GNUNET_CORE_KX_STATE_KEY_SENT;
      monitor_notify_all (pos);
    }
    monitor_notify_all (pos);
    send_key (pos);
  }
}


/**
 * Initialize KX subsystem.
 *
 * @param pk private key to use for the peer
 * @param server the server of the CORE service
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
int
GSC_KX_init (struct GNUNET_CRYPTO_EddsaPrivateKey *pk,
             struct GNUNET_SERVER_Handle *server)
{
  nc = GNUNET_SERVER_notification_context_create (server,
                                                  1);
  my_private_key = pk;
  GNUNET_CRYPTO_eddsa_key_get_public (my_private_key,
						  &GSC_my_identity.public_key);
  my_ephemeral_key = GNUNET_CRYPTO_ecdhe_key_create ();
  if (NULL == my_ephemeral_key)
  {
    GNUNET_break (0);
    GNUNET_free (my_private_key);
    my_private_key = NULL;
    return GNUNET_SYSERR;
  }
  sign_ephemeral_key ();
  rekey_task = GNUNET_SCHEDULER_add_delayed (REKEY_FREQUENCY,
                                             &do_rekey,
                                             NULL);
  mst = GNUNET_SERVER_mst_create (&deliver_message, NULL);
  return GNUNET_OK;
}


/**
 * Shutdown KX subsystem.
 */
void
GSC_KX_done ()
{
  if (GNUNET_SCHEDULER_NO_TASK != rekey_task)
  {
    GNUNET_SCHEDULER_cancel (rekey_task);
    rekey_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != my_ephemeral_key)
  {
    GNUNET_free (my_ephemeral_key);
    my_ephemeral_key = NULL;
  }
  if (NULL != my_private_key)
  {
    GNUNET_free (my_private_key);
    my_private_key = NULL;
  }
  if (NULL != mst)
  {
    GNUNET_SERVER_mst_destroy (mst);
    mst = NULL;
  }
  if (NULL != nc)
  {
    GNUNET_SERVER_notification_context_destroy (nc);
    nc = NULL;
  }
}


/**
 * Handle #GNUNET_MESSAGE_TYPE_CORE_MONITOR_PEERS request.  For this
 * request type, the client does not have to have transmitted an INIT
 * request.  All current peers are returned, regardless of which
 * message types they accept.
 *
 * @param cls unused
 * @param client client sending the iteration request
 * @param message iteration request message
 */
void
GSC_KX_handle_client_monitor_peers (void *cls,
                                    struct GNUNET_SERVER_Client *client,
                                    const struct GNUNET_MessageHeader *message)
{
  struct MonitorNotifyMessage done_msg;
  struct GSC_KeyExchangeInfo *kx;

  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  GNUNET_SERVER_notification_context_add (nc,
                                          client);
  for (kx = kx_head; NULL != kx; kx = kx->next)
    monitor_notify (client, kx);
  done_msg.header.size = htons (sizeof (struct MonitorNotifyMessage));
  done_msg.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_MONITOR_NOTIFY);
  done_msg.state = htonl ((uint32_t) GNUNET_CORE_KX_ITERATION_FINISHED);
  memset (&done_msg.peer, 0, sizeof (struct GNUNET_PeerIdentity));
  done_msg.timeout = GNUNET_TIME_absolute_hton (GNUNET_TIME_UNIT_FOREVER_ABS);
  GNUNET_SERVER_notification_context_unicast (nc,
                                              client,
                                              &done_msg.header,
                                              GNUNET_NO);
}


/* end of gnunet-service-core_kx.c */
