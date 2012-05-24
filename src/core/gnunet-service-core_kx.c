/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011, 2012 Christian Grothoff (and other contributing authors)

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
#include "gnunet_peerinfo_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"
#include "gnunet_protocols.h"
#include "core.h"


/**
 * Set to GNUNET_YES to perform some slightly expensive internal invariant checks.
 */
#define EXTRA_CHECKS GNUNET_YES

/**
 * How long do we wait for SET_KEY confirmation initially?
 */
#define INITIAL_SET_KEY_RETRY_FREQUENCY GNUNET_TIME_relative_multiply (MAX_SET_KEY_DELAY, 1)

/**
 * What is the minimum frequency for a PING message?
 */
#define MIN_PING_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

/**
 * How often do we rekey?
 */
#define REKEY_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 90)


/**
 * What is the maximum age of a message for us to consider processing
 * it?  Note that this looks at the timestamp used by the other peer,
 * so clock skew between machines does come into play here.  So this
 * should be picked high enough so that a little bit of clock skew
 * does not prevent peers from connecting to us.
 */
#define MAX_MESSAGE_AGE GNUNET_TIME_UNIT_DAYS

/**
 * What is the maximum delay for a SET_KEY message?
 */
#define MAX_SET_KEY_DELAY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * We're sending an (encrypted) PING to the other peer to check if he
 * can decrypt.  The other peer should respond with a PONG with the
 * same content, except this time encrypted with the receiver's key.
 */
struct PingMessage
{
  /**
   * Message type is CORE_PING.
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
   * Message type is CORE_PONG.
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
   * Reserved, always 'GNUNET_BANDWIDTH_VALUE_MAX'.
   */
  struct GNUNET_BANDWIDTH_Value32NBO reserved;

  /**
   * Intended target of the PING, used primarily to check
   * that decryption actually worked.
   */
  struct GNUNET_PeerIdentity target;
};


/**
 * Message transmitted to set (or update) a session key.
 */
struct SetKeyMessage
{

  /**
   * Message type is either CORE_SET_KEY.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Status of the sender (should be in "enum PeerStateMachine"), nbo.
   */
  int32_t sender_status GNUNET_PACKED;

  /**
   * Purpose of the signature, will be
   * GNUNET_SIGNATURE_PURPOSE_SET_KEY.
   */
  struct GNUNET_CRYPTO_RsaSignaturePurpose purpose;

  /**
   * At what time was this key created?
   */
  struct GNUNET_TIME_AbsoluteNBO creation_time;

  /**
   * The encrypted session key.
   */
  struct GNUNET_CRYPTO_RsaEncryptedData encrypted_key;

  /**
   * Who is the intended recipient?
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Signature of the stuff above (starting at purpose).
   */
  struct GNUNET_CRYPTO_RsaSignature signature;

};


/**
 * Encapsulation for encrypted messages exchanged between
 * peers.  Followed by the actual encrypted data.
 */
struct EncryptedMessage
{
  /**
   * Message type is either CORE_ENCRYPTED_MESSAGE.
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
  GNUNET_HashCode hmac;

  /**
   * Sequence number, in network byte order.  This field
   * must be the first encrypted/decrypted field
   */
  uint32_t sequence_number GNUNET_PACKED;

  /**
   * Reserved, always 'GNUNET_BANDWIDTH_VALUE_MAX'.
   */
  struct GNUNET_BANDWIDTH_Value32NBO reserved;

  /**
   * Timestamp.  Used to prevent reply of ancient messages
   * (recent messages are caught with the sequence number).
   */
  struct GNUNET_TIME_AbsoluteNBO timestamp;

};
GNUNET_NETWORK_STRUCT_END


/**
 * Number of bytes (at the beginning) of "struct EncryptedMessage"
 * that are NOT encrypted.
 */
#define ENCRYPTED_HEADER_SIZE (offsetof(struct EncryptedMessage, sequence_number))


/**
 * State machine for our P2P encryption handshake.  Everyone starts in
 * "DOWN", if we receive the other peer's key (other peer initiated)
 * we start in state RECEIVED (since we will immediately send our
 * own); otherwise we start in SENT.  If we get back a PONG from
 * within either state, we move up to CONFIRMED (the PONG will always
 * be sent back encrypted with the key we sent to the other peer).
 */
enum KxStateMachine
{
  /**
   * No handshake yet.
   */
  KX_STATE_DOWN,

  /**
   * We've sent our session key.
   */
  KX_STATE_KEY_SENT,

  /**
   * We've received the other peers session key.
   */
  KX_STATE_KEY_RECEIVED,

  /**
   * The other peer has confirmed our session key with a message
   * encrypted with his session key (which we got).  Key exchange
   * is done.
   */
  KX_STATE_UP,

  /**
   * We're rekeying, so we have received the other peer's session
   * key, but he didn't get ours yet.
   */
  KX_STATE_REKEY,

  /**
   * We're rekeying but have not yet received confirmation for our new
   * key from the other peer.
   */
  KX_STATE_REKEY_SENT
};


/**
 * Information about the status of a key exchange with another peer.
 */
struct GSC_KeyExchangeInfo
{
  /**
   * Identity of the peer.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * SetKeyMessage to transmit (initialized the first
   * time our status goes past 'KX_STATE_KEY_SENT').
   */
  struct SetKeyMessage skm;

  /**
   * PING message we transmit to the other peer.
   */
  struct PingMessage ping;

  /**
   * SetKeyMessage we received and did not process yet.
   */
  struct SetKeyMessage *skm_received;

  /**
   * PING message we received from the other peer and
   * did not process yet (or NULL).
   */
  struct PingMessage *ping_received;

  /**
   * PONG message we received from the other peer and
   * did not process yet (or NULL).
   */
  struct PongMessage *pong_received;

  /**
   * Encrypted message we received from the other peer and
   * did not process yet (or NULL).
   */
  struct EncryptedMessage *emsg_received;

  /**
   * Non-NULL if we are currently looking up HELLOs for this peer.
   * for this peer.
   */
  struct GNUNET_PEERINFO_IteratorContext *pitr;

  /**
   * Public key of the neighbour, NULL if we don't have it yet.
   */
  struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded *public_key;

  /**
   * We received a PONG message before we got the "public_key"
   * (or the SET_KEY).  We keep it here until we have a key
   * to decrypt it.  NULL if no PONG is pending.
   */
  struct PongMessage *pending_pong;

  /**
   * Key we use to encrypt our messages for the other peer
   * (initialized by us when we do the handshake).
   */
  struct GNUNET_CRYPTO_AesSessionKey encrypt_key;

  /**
   * Key we use to decrypt messages from the other peer
   * (given to us by the other peer during the handshake).
   */
  struct GNUNET_CRYPTO_AesSessionKey decrypt_key;

  /**
   * At what time did we generate our encryption key?
   */
  struct GNUNET_TIME_Absolute encrypt_key_created;

  /**
   * At what time did the other peer generate the decryption key?
   */
  struct GNUNET_TIME_Absolute decrypt_key_created;

  /**
   * When should the session time out (if there are no PONGs)?
   */
  struct GNUNET_TIME_Absolute timeout;

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
  enum KxStateMachine status;

};


/**
 * Handle to peerinfo service.
 */
static struct GNUNET_PEERINFO_Handle *peerinfo;

/**
 * Our private key.
 */
static struct GNUNET_CRYPTO_RsaPrivateKey *my_private_key;

/**
 * Our public key.
 */
static struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded my_public_key;

/**
 * Our message stream tokenizer (for encrypted payload).
 */
static struct GNUNET_SERVER_MessageStreamTokenizer *mst;


#if EXTRA_CHECKS
/**
 * Check internal invariants of the given KX record.
 *
 * @param kx record to check
 * @param file filename for error reporting
 * @param line line number for error reporting
 */ 
static void
check_kx_record (struct GSC_KeyExchangeInfo *kx,
		 const char *file,
		 int line)
{
  struct GNUNET_HashCode hc;

  if (NULL == kx->public_key)
    return;
  GNUNET_CRYPTO_hash (kx->public_key, sizeof (*kx->public_key), &hc);
  GNUNET_assert_at (0 == memcmp (&hc, &kx->peer, sizeof (struct GNUNET_HashCode)), file, line);
}


/**
 * Check internal invariants of the given KX record.
 *
 * @param kx record to check
 */
#define CHECK_KX(kx) check_kx_record(kx, __FILE__, __LINE__)
#else
#define CHECK_KX(kx) 
#endif

/**
 * Derive an authentication key from "set key" information
 *
 * @param akey authentication key to derive
 * @param skey session key to use
 * @param seed seed to use
 * @param creation_time creation time to use
 */
static void
derive_auth_key (struct GNUNET_CRYPTO_AuthKey *akey,
                 const struct GNUNET_CRYPTO_AesSessionKey *skey, uint32_t seed,
                 struct GNUNET_TIME_Absolute creation_time)
{
  static const char ctx[] = "authentication key";
  struct GNUNET_TIME_AbsoluteNBO ctbe;

  ctbe = GNUNET_TIME_absolute_hton (creation_time);
  GNUNET_CRYPTO_hmac_derive_key (akey, skey, &seed, sizeof (seed), &skey->key,
                                 sizeof (skey->key), &ctbe, sizeof (ctbe), ctx,
                                 sizeof (ctx), NULL);
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
derive_iv (struct GNUNET_CRYPTO_AesInitializationVector *iv,
           const struct GNUNET_CRYPTO_AesSessionKey *skey, uint32_t seed,
           const struct GNUNET_PeerIdentity *identity)
{
  static const char ctx[] = "initialization vector";

  GNUNET_CRYPTO_aes_derive_iv (iv, skey, &seed, sizeof (seed),
                               &identity->hashPubKey.bits,
                               sizeof (identity->hashPubKey.bits), ctx,
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
derive_pong_iv (struct GNUNET_CRYPTO_AesInitializationVector *iv,
                const struct GNUNET_CRYPTO_AesSessionKey *skey, uint32_t seed,
                uint32_t challenge, const struct GNUNET_PeerIdentity *identity)
{
  static const char ctx[] = "pong initialization vector";

  GNUNET_CRYPTO_aes_derive_iv (iv, skey, &seed, sizeof (seed),
                               &identity->hashPubKey.bits,
                               sizeof (identity->hashPubKey.bits), &challenge,
                               sizeof (challenge), ctx, sizeof (ctx), NULL);
}


/**
 * Encrypt size bytes from in and write the result to out.  Use the
 * key for outbound traffic of the given neighbour.
 *
 * @param kx key information context
 * @param iv initialization vector to use
 * @param in ciphertext
 * @param out plaintext
 * @param size size of in/out
 * @return GNUNET_OK on success
 */
static int
do_encrypt (struct GSC_KeyExchangeInfo *kx,
            const struct GNUNET_CRYPTO_AesInitializationVector *iv,
            const void *in, void *out, size_t size)
{
  if (size != (uint16_t) size)
  {
    GNUNET_break (0);
    return GNUNET_NO;
  }
  GNUNET_assert (size ==
                 GNUNET_CRYPTO_aes_encrypt (in, (uint16_t) size,
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
 * Decrypt size bytes from in and write the result to out.  Use the
 * key for inbound traffic of the given neighbour.  This function does
 * NOT do any integrity-checks on the result.
 *
 * @param kx key information context
 * @param iv initialization vector to use
 * @param in ciphertext
 * @param out plaintext
 * @param size size of in/out
 * @return GNUNET_OK on success
 */
static int
do_decrypt (struct GSC_KeyExchangeInfo *kx,
            const struct GNUNET_CRYPTO_AesInitializationVector *iv,
            const void *in, void *out, size_t size)
{
  if (size != (uint16_t) size)
  {
    GNUNET_break (0);
    return GNUNET_NO;
  }
  if ( (kx->status != KX_STATE_KEY_RECEIVED) && (kx->status != KX_STATE_UP) &&
       (kx->status != KX_STATE_REKEY_SENT) &&
       (kx->status != KX_STATE_REKEY) )
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (size !=
      GNUNET_CRYPTO_aes_decrypt (in, (uint16_t) size, &kx->decrypt_key, iv,
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
 * Task that will retry "send_key" if our previous attempt failed.
 *
 * @param cls our 'struct GSC_KeyExchangeInfo'
 * @param tc scheduler context
 */
static void
set_key_retry_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GSC_KeyExchangeInfo *kx = cls;

  kx->retry_set_key_task = GNUNET_SCHEDULER_NO_TASK;
  kx->set_key_retry_frequency =
      GNUNET_TIME_relative_multiply (kx->set_key_retry_frequency, 2);
  send_key (kx);
}


/**
 * PEERINFO is giving us a HELLO for a peer.  Add the public key to
 * the neighbour's struct and continue with the key exchange.  Or, if
 * we did not get a HELLO, just do nothing.
 *
 * @param cls the 'struct GSC_KeyExchangeInfo' to retry sending the key for
 * @param peer the peer for which this is the HELLO
 * @param hello HELLO message of that peer
 * @param err_msg NULL if successful, otherwise contains error message
 */
static void
process_hello (void *cls, const struct GNUNET_PeerIdentity *peer,
               const struct GNUNET_HELLO_Message *hello, const char *err_msg)
{
  struct GSC_KeyExchangeInfo *kx = cls;
  struct SetKeyMessage *skm;

  CHECK_KX (kx);
  if (NULL != err_msg)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                _("Error in communication with PEERINFO service\n"));
    kx->pitr = NULL;
    if (GNUNET_SCHEDULER_NO_TASK != kx->retry_set_key_task)
      GNUNET_SCHEDULER_cancel (kx->retry_set_key_task);
    kx->retry_set_key_task =
        GNUNET_SCHEDULER_add_delayed (kx->set_key_retry_frequency,
                                      &set_key_retry_task, kx);
    return;
  }
  if (NULL == peer)
  {
    kx->pitr = NULL;
    if (NULL != kx->public_key)
      return;                   /* done here */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Failed to obtain public key for peer `%4s', delaying processing of SET_KEY\n",
                GNUNET_i2s (&kx->peer));
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop
                              ("# Delayed connecting due to lack of public key"),
                              1, GNUNET_NO);
    if (GNUNET_SCHEDULER_NO_TASK != kx->retry_set_key_task)
      GNUNET_SCHEDULER_cancel (kx->retry_set_key_task);
    kx->retry_set_key_task =
        GNUNET_SCHEDULER_add_delayed (kx->set_key_retry_frequency,
                                      &set_key_retry_task, kx);
    return;
  }
  GNUNET_break (0 == memcmp (peer, &kx->peer, sizeof (struct GNUNET_PeerIdentity)));
  if (NULL != kx->public_key)
  {
    /* already have public key, why are we here? */
    GNUNET_break (0);
    return;
  }
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == kx->retry_set_key_task);
  kx->public_key =
      GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
  if (GNUNET_OK != GNUNET_HELLO_get_key (hello, kx->public_key))
  {
    GNUNET_break (0);
    GNUNET_free (kx->public_key);
    kx->public_key = NULL;
    CHECK_KX (kx);
    return;
  }
  CHECK_KX (kx);
  send_key (kx);
  if (NULL != kx->skm_received)
  {
    skm = kx->skm_received;
    kx->skm_received = NULL;
    GSC_KX_handle_set_key (kx, &skm->header);
    GNUNET_free (skm);
  }
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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Initiating key exchange with `%s'\n",
              GNUNET_i2s (pid));
  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop ("# key exchanges initiated"), 1,
                            GNUNET_NO);
  kx = GNUNET_malloc (sizeof (struct GSC_KeyExchangeInfo));
  kx->peer = *pid;
  kx->set_key_retry_frequency = INITIAL_SET_KEY_RETRY_FREQUENCY;
  kx->pitr =
      GNUNET_PEERINFO_iterate (peerinfo, pid,
                               GNUNET_TIME_UNIT_FOREVER_REL /* timeout? */ ,
                               &process_hello, kx);
  CHECK_KX (kx);
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
  GNUNET_STATISTICS_update (GSC_stats, gettext_noop ("# key exchanges stopped"),
                            1, GNUNET_NO);
  if (NULL != kx->pitr)
  {
    GNUNET_PEERINFO_iterate_cancel (kx->pitr);
    kx->pitr = NULL;
  }
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
  GNUNET_free_non_null (kx->skm_received);
  GNUNET_free_non_null (kx->ping_received);
  GNUNET_free_non_null (kx->pong_received);
  GNUNET_free_non_null (kx->emsg_received);
  GNUNET_free_non_null (kx->public_key);
  GNUNET_free (kx);
}


/**
 * We received a SET_KEY message.  Validate and update
 * our key material and status.
 *
 * @param kx key exchange status for the corresponding peer
 * @param msg the set key message we received
 */
void
GSC_KX_handle_set_key (struct GSC_KeyExchangeInfo *kx,
                       const struct GNUNET_MessageHeader *msg)
{
  const struct SetKeyMessage *m;
  struct GNUNET_TIME_Absolute t;
  struct GNUNET_CRYPTO_AesSessionKey k;
  struct PingMessage *ping;
  struct PongMessage *pong;
  enum KxStateMachine sender_status;
  uint16_t size;
  
  CHECK_KX (kx);
  size = ntohs (msg->size);
  if (size != sizeof (struct SetKeyMessage))
  {
    GNUNET_break_op (0);
    return;
  }
  m = (const struct SetKeyMessage *) msg;
  GNUNET_STATISTICS_update (GSC_stats, gettext_noop ("# session keys received"),
                            1, GNUNET_NO);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service receives `%s' request from `%4s'.\n", "SET_KEY",
              GNUNET_i2s (&kx->peer));
  if (NULL == kx->public_key)
  {
    GNUNET_free_non_null (kx->skm_received);
    kx->skm_received = (struct SetKeyMessage *) GNUNET_copy_message (msg);
    return;
  }
  if (0 !=
      memcmp (&m->target, &GSC_my_identity,
              sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                _("`%s' is for `%s', not for me.  Ignoring.\n"), "SET_KEY",
                GNUNET_i2s (&m->target));
    return;
  }
  if ((ntohl (m->purpose.size) !=
       sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) +
       sizeof (struct GNUNET_TIME_AbsoluteNBO) +
       sizeof (struct GNUNET_CRYPTO_RsaEncryptedData) +
       sizeof (struct GNUNET_PeerIdentity)) ||
      (GNUNET_OK !=
       GNUNET_CRYPTO_rsa_verify (GNUNET_SIGNATURE_PURPOSE_SET_KEY, &m->purpose,
                                 &m->signature, kx->public_key)))
  {
    /* invalid signature */
    CHECK_KX (kx);
    GNUNET_break_op (0);
    return;
  }
  t = GNUNET_TIME_absolute_ntoh (m->creation_time);
  if (((kx->status == KX_STATE_KEY_RECEIVED) || (kx->status == KX_STATE_UP)) &&
      (t.abs_value < kx->decrypt_key_created.abs_value))
  {
    /* this could rarely happen due to massive re-ordering of
     * messages on the network level, but is most likely either
     * a bug or some adversary messing with us.  Report. */
    GNUNET_break_op (0);
    return;
  }
  if ((GNUNET_CRYPTO_rsa_decrypt
       (my_private_key, &m->encrypted_key, &k,
        sizeof (struct GNUNET_CRYPTO_AesSessionKey)) !=
       sizeof (struct GNUNET_CRYPTO_AesSessionKey)) ||
      (GNUNET_OK != GNUNET_CRYPTO_aes_check_session_key (&k)))
  {
    /* failed to decrypt !? */
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		"Invalid key %x decrypted by %s from message %u (origin: %s)\n",
		(unsigned int) GNUNET_CRYPTO_crc32_n (&k, sizeof (struct GNUNET_CRYPTO_AesSessionKey)),
		GNUNET_i2s (&GSC_my_identity),
		(unsigned int) GNUNET_CRYPTO_crc32_n (&m->encrypted_key, sizeof (struct GNUNET_CRYPTO_RsaEncryptedData)),
		GNUNET_h2s (&kx->peer.hashPubKey));
    GNUNET_break_op (0);
    return;
  }
  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop ("# SET_KEY messages decrypted"), 1,
                            GNUNET_NO);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received SET_KEY from `%s'\n",
              GNUNET_i2s (&kx->peer));
  kx->decrypt_key = k;
  if (kx->decrypt_key_created.abs_value != t.abs_value)
  {
    /* fresh key, reset sequence numbers */
    kx->last_sequence_number_received = 0;
    kx->last_packets_bitmap = 0;
    kx->decrypt_key_created = t;
  }
  sender_status = (enum KxStateMachine) ntohl (m->sender_status);
  switch (kx->status)
  {
  case KX_STATE_DOWN:
    kx->status = KX_STATE_KEY_RECEIVED;
    /* we're not up, so we are already doing 'send_key' */
    break;
  case KX_STATE_KEY_SENT:
    kx->status = KX_STATE_KEY_RECEIVED;
    /* we're not up, so we are already doing 'send_key' */
    break;
  case KX_STATE_KEY_RECEIVED:
    /* we're not up, so we are already doing 'send_key' */
    break;
  case KX_STATE_UP: 
    if ((sender_status == KX_STATE_DOWN) ||
        (sender_status == KX_STATE_KEY_SENT))
      send_key (kx);            /* we are up, but other peer is not! */
    break;
  case KX_STATE_REKEY:
    if ((sender_status == KX_STATE_DOWN) ||
        (sender_status == KX_STATE_KEY_SENT))
      send_key (kx);            /* we are up, but other peer is not! */
    break;
  case KX_STATE_REKEY_SENT:
    if ((sender_status == KX_STATE_DOWN) ||
        (sender_status == KX_STATE_KEY_SENT))
      send_key (kx);            /* we are up, but other peer is not! */
    break;
  default:
    GNUNET_break (0);
    break;
  }
  if (NULL != kx->ping_received)
  {
    ping = kx->ping_received;
    kx->ping_received = NULL;
    GSC_KX_handle_ping (kx, &ping->header);
    GNUNET_free (ping);
  }
  if (NULL != kx->pong_received)
  {
    pong = kx->pong_received;
    kx->pong_received = NULL;
    GSC_KX_handle_pong (kx, &pong->header);
    GNUNET_free (pong);
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
  struct GNUNET_CRYPTO_AesInitializationVector iv;
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
  if ((kx->status != KX_STATE_KEY_RECEIVED) && (kx->status != KX_STATE_UP) &&
      (kx->status != KX_STATE_REKEY_SENT))
  {
    /* defer */
    GNUNET_free_non_null (kx->ping_received);
    kx->ping_received = (struct PingMessage *) GNUNET_copy_message (msg);
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received PING from `%s'\n",
              GNUNET_i2s (&kx->peer));
  /* construct PONG */
  tx.reserved = GNUNET_BANDWIDTH_VALUE_MAX;
  tx.challenge = t.challenge;
  tx.target = t.target;
  tp.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_PONG);
  tp.header.size = htons (sizeof (struct PongMessage));
  tp.iv_seed =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX);
  derive_pong_iv (&iv, &kx->encrypt_key, tp.iv_seed, t.challenge, &kx->peer);
  do_encrypt (kx, &iv, &tx.challenge, &tp.challenge,
              sizeof (struct PongMessage) - ((void *) &tp.challenge -
                                             (void *) &tp));
  GNUNET_STATISTICS_update (GSC_stats, gettext_noop ("# PONG messages created"),
                            1, GNUNET_NO);
  GSC_NEIGHBOURS_transmit (&kx->peer, &tp.header,
                           GNUNET_TIME_UNIT_FOREVER_REL /* FIXME: timeout */ );
}


/**
 * Create a fresh SET KEY message for transmission to the other peer.
 * Also creates a new key.
 *
 * @param kx key exchange context to create SET KEY message for
 */
static void
setup_fresh_setkey (struct GSC_KeyExchangeInfo *kx)
{
  struct SetKeyMessage *skm;

  GNUNET_CRYPTO_aes_create_session_key (&kx->encrypt_key);
  kx->encrypt_key_created = GNUNET_TIME_absolute_get ();
  skm = &kx->skm;
  skm->header.size = htons (sizeof (struct SetKeyMessage));
  skm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_SET_KEY);
  skm->purpose.size =
      htonl (sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) +
             sizeof (struct GNUNET_TIME_AbsoluteNBO) +
             sizeof (struct GNUNET_CRYPTO_RsaEncryptedData) +
             sizeof (struct GNUNET_PeerIdentity));
  skm->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_SET_KEY);
  skm->creation_time = GNUNET_TIME_absolute_hton (kx->encrypt_key_created);
  skm->target = kx->peer;
  CHECK_KX (kx);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_rsa_encrypt (&kx->encrypt_key,
                                            sizeof (struct
                                                    GNUNET_CRYPTO_AesSessionKey),
                                            kx->public_key,
                                            &skm->encrypted_key));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Encrypting key %x for %s resulting in message %u (origin: %s)\n",
	      (unsigned int) GNUNET_CRYPTO_crc32_n (&kx->encrypt_key, sizeof (struct GNUNET_CRYPTO_AesSessionKey)),
	      GNUNET_i2s (&kx->peer),
	      (unsigned int) GNUNET_CRYPTO_crc32_n (&skm->encrypted_key, sizeof (struct GNUNET_CRYPTO_RsaEncryptedData)),
	      GNUNET_h2s (&GSC_my_identity.hashPubKey));

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_rsa_sign (my_private_key, &skm->purpose,
                                         &skm->signature));
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
  struct GNUNET_CRYPTO_AesInitializationVector iv;

  pm = &kx->ping;
  pm->header.size = htons (sizeof (struct PingMessage));
  pm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_PING);
  pm->iv_seed =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX);
  derive_iv (&iv, &kx->encrypt_key, pm->iv_seed, &kx->peer);
  pp.challenge = kx->ping_challenge;
  pp.target = kx->peer;
  do_encrypt (kx, &iv, &pp.target, &pm->target,
              sizeof (struct PingMessage) - ((void *) &pm->target -
                                             (void *) pm));
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
  if (0 == left.rel_value)
  {
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop ("# sessions terminated by timeout"),
                              1, GNUNET_NO);
    GSC_SESSIONS_end (&kx->peer);
    kx->status = KX_STATE_DOWN;
    send_key (kx);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending KEEPALIVE to `%s'\n",
              GNUNET_i2s (&kx->peer));
  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop ("# keepalive messages sent"), 1,
                            GNUNET_NO);
  setup_fresh_ping (kx);
  GSC_NEIGHBOURS_transmit (&kx->peer, &kx->ping.header,
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
  kx->timeout =
      GNUNET_TIME_relative_to_absolute
      (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  if (kx->keep_alive_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (kx->keep_alive_task);
  kx->keep_alive_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_divide
                                    (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                     2), &send_keep_alive, kx);
}


/**
 * Trigger rekeying event.
 * 
 * @param cls the 'struct GSC_KeyExchangeInfo'
 * @param tc schedule context (unused)
 */
static void
trigger_rekey (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GSC_KeyExchangeInfo *kx = cls;
  
  GNUNET_break (KX_STATE_UP == kx->status);
  kx->status = KX_STATE_REKEY;
  kx->set_key_retry_frequency = INITIAL_SET_KEY_RETRY_FREQUENCY;
  kx->retry_set_key_task =
    GNUNET_SCHEDULER_add_delayed (kx->set_key_retry_frequency,
				  &set_key_retry_task, kx);
}


/**
 * Schedule rekey operation.
 *
 * @param kx key exchange to schedule rekey for
 */
static void
schedule_rekey (struct GSC_KeyExchangeInfo *kx)
{
  struct GNUNET_TIME_Relative rdelay;

  if (GNUNET_SCHEDULER_NO_TASK != kx->retry_set_key_task)  
    GNUNET_SCHEDULER_cancel (kx->retry_set_key_task);
  rdelay = REKEY_FREQUENCY;
  /* randomize rekey frequency by one minute to avoid synchronization */
  rdelay.rel_value += GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
						60 * 1000);
  kx->retry_set_key_task = GNUNET_SCHEDULER_add_delayed (REKEY_FREQUENCY,
							 &trigger_rekey,
							 kx);   
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
  struct EncryptedMessage *emsg;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
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
  case KX_STATE_DOWN:
    return;
  case KX_STATE_KEY_SENT:
    GNUNET_free_non_null (kx->pong_received);
    kx->pong_received = (struct PongMessage *) GNUNET_copy_message (msg);    
    return;
  case KX_STATE_KEY_RECEIVED:
    break;
  case KX_STATE_UP:
    break;
  case KX_STATE_REKEY:
    break;
  case KX_STATE_REKEY_SENT:
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Received PONG from `%s'\n",
              GNUNET_i2s (&kx->peer));
  switch (kx->status)
  {
  case KX_STATE_DOWN:
    GNUNET_break (0);           /* should be impossible */
    return;
  case KX_STATE_KEY_SENT:
    GNUNET_break (0);           /* should be impossible */
    return;
  case KX_STATE_KEY_RECEIVED:
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop
                              ("# session keys confirmed via PONG"), 1,
                              GNUNET_NO);
    kx->status = KX_STATE_UP;
    GSC_SESSIONS_create (&kx->peer, kx);
    CHECK_KX (kx);
    schedule_rekey (kx);
    GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == kx->keep_alive_task);
    if (NULL != kx->emsg_received)
    {
      emsg = kx->emsg_received;
      kx->emsg_received = NULL;
      GSC_KX_handle_encrypted_message (kx, &emsg->header, NULL,
                                       0 /* FIXME: ATSI */ );
      GNUNET_free (emsg);
    }
    update_timeout (kx);
    break;
  case KX_STATE_UP:
    update_timeout (kx);
    break;
  case KX_STATE_REKEY:
    update_timeout (kx);
    break;
  case KX_STATE_REKEY_SENT:
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop
                              ("# rekey operations confirmed via PONG"), 1,
                              GNUNET_NO);
    kx->status = KX_STATE_UP;
    schedule_rekey (kx);
    update_timeout (kx);
    break;
  default:
    GNUNET_break (0);
    break;
  }
}


/**
 * Send our key (and encrypted PING) to the other peer.
 *
 * @param kx key exchange context
 */
static void
send_key (struct GSC_KeyExchangeInfo *kx)
{
  CHECK_KX (kx);
  if (GNUNET_SCHEDULER_NO_TASK != kx->retry_set_key_task)
  {
     GNUNET_SCHEDULER_cancel (kx->retry_set_key_task);
     kx->retry_set_key_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (KX_STATE_UP == kx->status)
    return;                     /* nothing to do */
  if (NULL == kx->public_key)
  {
    /* lookup public key, then try again */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Trying to obtain public key for `%s'\n",
                GNUNET_i2s (&kx->peer));
    kx->pitr =
        GNUNET_PEERINFO_iterate (peerinfo, &kx->peer,
                                 GNUNET_TIME_UNIT_FOREVER_REL /* timeout? */ ,
                                 &process_hello, kx);
    return;
  }

  /* update status */
  switch (kx->status)
  {
  case KX_STATE_DOWN:
    kx->status = KX_STATE_KEY_SENT;
    /* setup SET KEY message */
    setup_fresh_setkey (kx);
    setup_fresh_ping (kx);
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop
                              ("# SET_KEY and PING messages created"), 1,
                              GNUNET_NO);
    break;
  case KX_STATE_KEY_SENT:
    break;
  case KX_STATE_KEY_RECEIVED:
    break;
  case KX_STATE_UP:
    GNUNET_break (0);
    return;
  case KX_STATE_REKEY:
    kx->status = KX_STATE_REKEY_SENT;
    /* setup fresh SET KEY message */
    setup_fresh_setkey (kx);
    setup_fresh_ping (kx);
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop
                              ("# SET_KEY and PING messages created"), 1,
                              GNUNET_NO);
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop
                              ("# REKEY operations performed"), 1,
                              GNUNET_NO);
    break;
  case KX_STATE_REKEY_SENT:
    break;
  default:
    GNUNET_break (0);
    return;
  }

  /* always update sender status in SET KEY message */
  /* Not sending rekey sent state to be compatible with GNUnet 0.9.2 */
  kx->skm.sender_status = htonl ((int32_t) ((kx->status == KX_STATE_REKEY_SENT) ? 
					    KX_STATE_KEY_RECEIVED : kx->status));  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending SET_KEY and PING to `%s'\n",
              GNUNET_i2s (&kx->peer));
  GSC_NEIGHBOURS_transmit (&kx->peer, &kx->skm.header,
                           kx->set_key_retry_frequency);
  GSC_NEIGHBOURS_transmit (&kx->peer, &kx->ping.header,
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
 * @param payload_size number of bytes in 'payload'
 */
void
GSC_KX_encrypt_and_transmit (struct GSC_KeyExchangeInfo *kx,
                             const void *payload, size_t payload_size)
{
  size_t used = payload_size + sizeof (struct EncryptedMessage);
  char pbuf[used];              /* plaintext */
  char cbuf[used];              /* ciphertext */
  struct EncryptedMessage *em;  /* encrypted message */
  struct EncryptedMessage *ph;  /* plaintext header */
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  struct GNUNET_CRYPTO_AuthKey auth_key;

  ph = (struct EncryptedMessage *) pbuf;
  ph->iv_seed =
      htonl (GNUNET_CRYPTO_random_u32
             (GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX));
  ph->sequence_number = htonl (++kx->last_sequence_number_sent);
  ph->reserved = GNUNET_BANDWIDTH_VALUE_MAX;
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
  derive_auth_key (&auth_key, &kx->encrypt_key, ph->iv_seed,
                   kx->encrypt_key_created);
  GNUNET_CRYPTO_hmac (&auth_key, &em->sequence_number,
                      used - ENCRYPTED_HEADER_SIZE, &em->hmac);
  GSC_NEIGHBOURS_transmit (&kx->peer, &em->header,
                           GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Closure for 'deliver_message'
 */
struct DeliverMessageContext
{

  /**
   * Performance information for the connection.
   */
  const struct GNUNET_ATS_Information *atsi;

  /**
   * Sender of the message.
   */
  const struct GNUNET_PeerIdentity *peer;

  /**
   * Number of entries in 'atsi' array.
   */
  uint32_t atsi_count;
};


/**
 * We received an encrypted message.  Decrypt, validate and
 * pass on to the appropriate clients.
 *
 * @param kx key exchange context for encrypting the message
 * @param msg encrypted message
 * @param atsi performance data
 * @param atsi_count number of entries in ats (excluding 0-termination)
 */
void
GSC_KX_handle_encrypted_message (struct GSC_KeyExchangeInfo *kx,
                                 const struct GNUNET_MessageHeader *msg,
                                 const struct GNUNET_ATS_Information *atsi,
                                 uint32_t atsi_count)
{
  const struct EncryptedMessage *m;
  struct EncryptedMessage *pt;  /* plaintext */
  GNUNET_HashCode ph;
  uint32_t snum;
  struct GNUNET_TIME_Absolute t;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
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
  if ((kx->status != KX_STATE_KEY_RECEIVED) && (kx->status != KX_STATE_UP) &&
      (kx->status != KX_STATE_REKEY_SENT) )
  {
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop
                              ("# failed to decrypt message (no session key)"),
                              1, GNUNET_NO);
    return;
  }
  if (KX_STATE_KEY_RECEIVED == kx->status)
  {
    /* defer */
    GNUNET_free_non_null (kx->emsg_received);
    kx->emsg_received = (struct EncryptedMessage *) GNUNET_copy_message (msg);
    return;
  }
  /* validate hash */
  derive_auth_key (&auth_key, &kx->decrypt_key, m->iv_seed,
                   kx->decrypt_key_created);
  GNUNET_CRYPTO_hmac (&auth_key, &m->sequence_number,
                      size - ENCRYPTED_HEADER_SIZE, &ph);
  if (0 != memcmp (&ph, &m->hmac, sizeof (GNUNET_HashCode)))
  {
    /* checksum failed */
    GNUNET_break_op (0);
    return;
  }
  derive_iv (&iv, &kx->decrypt_key, m->iv_seed, &GSC_my_identity);
  /* decrypt */
  if (GNUNET_OK !=
      do_decrypt (kx, &iv, &m->sequence_number, &buf[ENCRYPTED_HEADER_SIZE],
                  size - ENCRYPTED_HEADER_SIZE))
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Decrypted %u bytes from %s\n",
              size - ENCRYPTED_HEADER_SIZE, GNUNET_i2s (&kx->peer));
  pt = (struct EncryptedMessage *) buf;

  /* validate sequence number */
  snum = ntohl (pt->sequence_number);
  if (kx->last_sequence_number_received == snum)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
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
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
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
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
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
  if (GNUNET_TIME_absolute_get_duration (t).rel_value >
      MAX_MESSAGE_AGE.rel_value)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _("Message received far too old (%llu ms). Content ignored.\n"),
                GNUNET_TIME_absolute_get_duration (t).rel_value);
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
                            size - sizeof (struct EncryptedMessage), GNUNET_NO);
  dmc.atsi = atsi;
  dmc.atsi_count = atsi_count;
  dmc.peer = &kx->peer;
  if (GNUNET_OK !=
      GNUNET_SERVER_mst_receive (mst, &dmc,
                                 &buf[sizeof (struct EncryptedMessage)],
                                 size - sizeof (struct EncryptedMessage),
                                 GNUNET_YES, GNUNET_NO))
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
deliver_message (void *cls, void *client, const struct GNUNET_MessageHeader *m)
{
  struct DeliverMessageContext *dmc = client;

  switch (ntohs (m->type))
  {
  case GNUNET_MESSAGE_TYPE_CORE_BINARY_TYPE_MAP:
  case GNUNET_MESSAGE_TYPE_CORE_COMPRESSED_TYPE_MAP:
    GSC_SESSIONS_set_typemap (dmc->peer, m);
    return GNUNET_OK;
  default:
    GSC_CLIENTS_deliver_message (dmc->peer, dmc->atsi, dmc->atsi_count, m,
                                 ntohs (m->size),
                                 GNUNET_CORE_OPTION_SEND_FULL_INBOUND);
    GSC_CLIENTS_deliver_message (dmc->peer, dmc->atsi, dmc->atsi_count, m,
                                 sizeof (struct GNUNET_MessageHeader),
                                 GNUNET_CORE_OPTION_SEND_HDR_INBOUND);
  }
  return GNUNET_OK;
}


/**
 * Initialize KX subsystem.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
int
GSC_KX_init ()
{
  char *keyfile;

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (GSC_cfg, "GNUNETD", "HOSTKEY",
                                               &keyfile))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("Core service is lacking HOSTKEY configuration setting.  Exiting.\n"));
    return GNUNET_SYSERR;
  }
  my_private_key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  GNUNET_free (keyfile);
  if (NULL == my_private_key)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Core service could not access hostkey.  Exiting.\n"));
    return GNUNET_SYSERR;
  }
  GNUNET_CRYPTO_rsa_key_get_public (my_private_key, &my_public_key);
  GNUNET_CRYPTO_hash (&my_public_key, sizeof (my_public_key),
                      &GSC_my_identity.hashPubKey);
  peerinfo = GNUNET_PEERINFO_connect (GSC_cfg);
  if (NULL == peerinfo)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Could not access PEERINFO service.  Exiting.\n"));
    GNUNET_CRYPTO_rsa_key_free (my_private_key);
    my_private_key = NULL;
    return GNUNET_SYSERR;
  }
  mst = GNUNET_SERVER_mst_create (&deliver_message, NULL);
  return GNUNET_OK;
}


/**
 * Shutdown KX subsystem.
 */
void
GSC_KX_done ()
{
  if (NULL != my_private_key)
  {
    GNUNET_CRYPTO_rsa_key_free (my_private_key);
    my_private_key = NULL;
  }
  if (NULL != peerinfo)
  {
    GNUNET_PEERINFO_disconnect (peerinfo);
    peerinfo = NULL;
  }
  if (NULL != mst)
  {
    GNUNET_SERVER_mst_destroy (mst);
    mst = NULL;
  }
}

/* end of gnunet-service-core_kx.c */
