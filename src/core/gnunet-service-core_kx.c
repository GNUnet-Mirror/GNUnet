/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
#include "gnunet-service-core_neighbours.h"


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
 * Response to a PING.  Includes data from the original PING
 * plus initial bandwidth quota information.
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
   * Desired bandwidth (how much we should send to this
   * peer / how much is the sender willing to receive).
   */
  struct GNUNET_BANDWIDTH_Value32NBO inbound_bw_limit;

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
   * Desired bandwidth (how much we should send to this peer / how
   * much is the sender willing to receive)?
   */
  struct GNUNET_BANDWIDTH_Value32NBO inbound_bw_limit;

  /**
   * Timestamp.  Used to prevent reply of ancient messages
   * (recent messages are caught with the sequence number).
   */
  struct GNUNET_TIME_AbsoluteNBO timestamp;

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



/**
 * Derive an authentication key from "set key" information
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
  GNUNET_STATISTICS_update (stats, gettext_noop ("# bytes encrypted"), size,
                            GNUNET_NO);
#if DEBUG_CORE > 2
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
  if ((kx->status != KX_STATE_KEY_RECEIVED) &&
      (kx->status != KX_STATE_UP))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (size !=
      GNUNET_CRYPTO_aes_decrypt (in, (uint16_t) size, &kx->decrypt_key, iv, out))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_STATISTICS_update (stats, gettext_noop ("# bytes decrypted"), size,
                            GNUNET_NO);
#if DEBUG_CORE > 1
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
  kx->set_key_retry_frequency = GNUNET_TIME_relative_multiply (kx->set_key_retry_frequency, 2);
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
	       const struct GNUNET_HELLO_Message *hello,
	       const char *err_msg)
{
  struct GSC_KeyExchangeInfo *kx = cls;
  struct SetKeyMessage *skm;

  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == n->retry_set_key_task);
  if (err_msg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                _("Error in communication with PEERINFO service\n"));
    kx->pitr = NULL;
    return;
  }
  if (peer == NULL)
  {
    kx->pitr = NULL;
    if (kx->public_key != NULL)
      return; /* done here */
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		"Failed to obtain public key for peer `%4s', delaying processing of SET_KEY\n",
		GNUNET_i2s (&kx->peer));
#endif
    GNUNET_STATISTICS_update (stats,
			      gettext_noop
			      ("# Delayed connecting due to lack of public key"),
			      1, GNUNET_NO);
    kx->retry_set_key_task =
      GNUNET_SCHEDULER_add_delayed (kx->set_key_retry_frequency,
				    &set_key_retry_task, kx);
    return;
  }
  if (kx->public_key != NULL)
  {
    /* already have public key, why are we here? */
    GNUNET_break (0);
    return;
  }
  kx->public_key =
      GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
  if (GNUNET_OK != GNUNET_HELLO_get_key (hello, n->public_key))
  {
    GNUNET_break (0);
    GNUNET_free (kx->public_key);
    kx->public_key = NULL;
    return;
  }
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
 * Send our key (and encrypted PING) to the other peer.
 *
 * @param kx key exchange context
 */
static void
send_key (struct GSC_KeyExchangeInfo *kx);


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

  kx = GNUNET_malloc (sizeof (struct GSC_KeyExchangeInfo));
  kx->peer = *pid;
  n->set_key_retry_frequency = INITIAL_SET_KEY_RETRY_FREQUENCY;
  kx->pitr = GNUNET_PEERINFO_iterate (peerinfo,
				      pid,
				      GNUNET_TIME_UNIT_FOREVER_REL /* timeout? */,
				      &process_hello,
				      kx);  
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
  if (kx->pitr != NULL)
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
    GNUNET_SCHEDULER_cancel (n->keep_alive_task);
    kx->keep_alive_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_free_non_null (kx->skm_received);
  GNUNET_free_non_null (kx->ping_received);
  GNUNET_free_non_null (kx->pong_received);
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
		       const struct GNUNET_MessageHandler *msg)
{
  const struct SetKeyMessage *m;
  struct SetKeyMessage *m_cpy;
  struct GNUNET_TIME_Absolute t;
  struct GNUNET_CRYPTO_AesSessionKey k;
  struct PingMessage *ping;
  struct PongMessage *pong;
  enum PeerStateMachine sender_status;
  uint16_t size;
  
  size = ntohs (msg->header);
  if (size != sizeof (struct SetKeyMessage))
    {
      GNUNET_break_op (0);
      return;
    }
  m = (const struct SetKeyMessage*) msg;
  GNUNET_STATISTICS_update (stats, gettext_noop ("# session keys received"),
			    1, GNUNET_NO);

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service receives `%s' request from `%4s'.\n", "SET_KEY",
              GNUNET_i2s (&kx->peer));
#endif
  if (kx->public_key == NULL)
  {
    GNUNET_free_non_null (kx->skm_received);
    kx->skm_received = GNUNET_copy_message (msg);
    return;
  }
  if (0 !=
      memcmp (&m->target, &GSC_my_identity, sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                _("`%s' is for `%s', not for me.  Ignoring.\n"),
                "SET_KEY", GNUNET_i2s (&m->target));
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
    GNUNET_break_op (0);
    return;
  }
  t = GNUNET_TIME_absolute_ntoh (m->creation_time);
  if (((kx->status == KX_STATE_KEY_RECEIVED) ||
       (kx->status == KX_STATE_UP)) &&
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
    GNUNET_break_op (0);
    return;
  }
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# SET_KEY messages decrypted"), 1,
                            GNUNET_NO);
  kx->decrypt_key = k;
  if (kx->decrypt_key_created.abs_value != t.abs_value)
  {
    /* fresh key, reset sequence numbers */
    kx->last_sequence_number_received = 0;
    kx->last_packets_bitmap = 0;
    kx->decrypt_key_created = t;
  }
  sender_status = (enum PeerStateMachine) ntohl (m->sender_status);

  switch (kx->status)
  {
  case KX_STATE_DOWN:
    kx->status = PEER_STATE_KEY_RECEIVED;
    /* we're not up, so we are already doing 'send_key' */
    break;
  case KX_STATE_KEY_SENT:
    n->status = PEER_STATE_KEY_RECEIVED;
    /* we're not up, so we are already doing 'send_key' */
    break;
  case KX_STATE_KEY_RECEIVED:
    /* we're not up, so we are already doing 'send_key' */
    break;
  case KX_STATE_UP:
    if ( (sender_status == KX_STATE_DOWN) ||
	 (sender_status == KX_PEER_STATE_KEY_SENT) )
      send_key (kx); /* we are up, but other peer is not! */
    break;
  default:
    GNUNET_break (0);
    break;
  }
  if (kx->ping_received != NULL)
  {
    ping = kx->ping_received;
    kx->ping_received = NULL;
    GSC_KX_handle_ping (kx, &ping->header);
    GNUNET_free (ping);
  }
  if (kx->pong_received != NULL)
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
GSC_KX_handle_ping (struct GSC_KeyExchangeInfo *n, const struct GNUNET_MessageHeader *msg)
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
			    gettext_noop ("# PING messages received"),
			    1, GNUNET_NO);
  if ( (kx->status != KX_STATE_KEY_RECEIVED) &&
       (kx->status != KX_STATE_UP) )
    {
      /* defer */
      GNUNET_free_non_null (n->pending_ping);
      n->pending_ping = GNUNET_copy_message (msg);
      return;
    }
  m = (const struct PingMessage*) msg;
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service receives `%s' request from `%4s'.\n", "PING",
              GNUNET_i2s (&n->peer));
#endif
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

    GNUNET_snprintf (sender, sizeof (sender), "%8s", GNUNET_i2s (&n->peer));
    GNUNET_snprintf (peer, sizeof (peer), "%8s", GNUNET_i2s (&t.target));
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Received PING from `%s' for different identity: I am `%s', PONG identity: `%s'\n"),
                sender, GNUNET_i2s (&my_identity), peer);
    GNUNET_break_op (0);
    return;
  }
  /* construct PONG */
  tx.inbound_bw_limit = n->bw_in;
  tx.challenge = t.challenge;
  tx.target = t.target;
  tp.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_PONG);
  tp.header.size = htons (sizeof (struct PongMessage));
  tp.iv_seed =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX);
  derive_pong_iv (&iv, &n->encrypt_key, tp.iv_seed, t.challenge, &kx->peer);
  do_encrypt (n, &iv, &tx.challenge, &tp.challenge,
              sizeof (struct PongMessage) - ((void *) &tp.challenge -
                                             (void *) tp));
  GNUNET_STATISTICS_update (GSC_stats, 
			    gettext_noop ("# PONG messages created"), 1,
                            GNUNET_NO);
  GSC_NEIGHBOURS_transmit (&kx->peer,
			   &tp.header,
			   GNUNET_TIME_UNIT_FOREVER_REL /* FIXME: timeout */);
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
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CRYPTO_rsa_encrypt (&kx->encrypt_key,
					    sizeof (struct
						    GNUNET_CRYPTO_AesSessionKey),
					    kx->public_key, &skm->encrypted_key));
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
  if (left.rel_value == 0)
  {    
    GSC_SESSIONS_end (&kx->peer);
    kx->status = KX_STATE_DOWN;
    return;
  }
  setup_fresh_ping (kx);
  GDS_NEIGHBOURS_transmit (&kx->peer,
			   &kx->ping.header,
			   kx->set_key_retry_frequency);
  retry =
      GNUNET_TIME_relative_max (GNUNET_TIME_relative_divide (left, 2),
                                MIN_PING_FREQUENCY);
  kx->keep_alive_task =
    GNUNET_SCHEDULER_add_delayed (retry, &send_keep_alive, kx);

}


/**
 * We received a PONG message.  Validate and update our status.
 *
 * @param kx key exchange context for the the PONG
 * @param m the encrypted PONG message itself
 */
void
GSC_KX_handle_pong (struct GSC_KeyExchangeInfo *kx, const struct GNUNET_MessageHeader *msg)
{
  const struct PongMessage *m;
  struct PongMessage t;
  struct ConnectNotifyMessage *cnm;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];
  struct GNUNET_TRANSPORT_ATS_Information *mats;
  uint16_t msize;
  size_t size;

  msize = ntohs (msg->size);
  if (msize != sizeof (struct PongMessage))
  {
    GNUNET_break_op (0);
    return;
  }
  GNUNET_STATISTICS_update (GSC_stats, gettext_noop ("# PONG messages received"),
			    1, GNUNET_NO);

  if ( (kx->status != KX_STATE_KEY_RECEIVED) &&
       (kx->status != KX_STATE_UP) )
  {
    if (kx->status == KX_STATE_KEY_SENT)
    {
      GNUNET_free_non_null (n->pending_pong);
      n->pending_pong = GNUNET_copy_message (msg);
    }
    return;
  }
  m = (const struct PongMessage*) msg;
#if DEBUG_HANDSHAKE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service receives `%s' response from `%4s'.\n", "PONG",
              GNUNET_i2s (&kx->peer));
#endif
  /* mark as garbage, just to be sure */
  memset (&t, 255, sizeof (t));
  derive_pong_iv (&iv, &kx->decrypt_key, m->iv_seed, kx->ping_challenge,
                  &my_identity);
  if (GNUNET_OK !=
      do_decrypt (kx, &iv, &m->challenge, &t.challenge,
                  sizeof (struct PongMessage) - ((void *) &m->challenge -
                                                 (void *) m)))
  {
    GNUNET_break_op (0);
    return;
  }
  GNUNET_STATISTICS_update (stats, gettext_noop ("# PONG messages decrypted"),
                            1, GNUNET_NO);
  if ((0 != memcmp (&t.target, &kx->peer, sizeof (struct GNUNET_PeerIdentity)))
      || (kx->ping_challenge != t.challenge))
  {
    /* PONG malformed */
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received malformed `%s' wanted sender `%4s' with challenge %u\n",
                "PONG", GNUNET_i2s (&n->peer),
                (unsigned int) n->ping_challenge);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received malformed `%s' received from `%4s' with challenge %u\n",
                "PONG", GNUNET_i2s (&t.target), (unsigned int) t.challenge);
#endif
    return;
  }
  switch (kx->status)
  {
  case KX_STATE_DOWN:
    GNUNET_break (0);           /* should be impossible */
    return;
  case KX_STATE_KEY_SENT:
    GNUNET_break (0);           /* should be impossible */
    return;
  case KX_STATE_KEY_RECEIVED:
    GNUNET_STATISTICS_update (stats,
                              gettext_noop
                              ("# Session keys confirmed via PONG"), 1,
                              GNUNET_NO);
    kx->status = KX_STATE_UP;
    GSC_SESSIONS_create (&kx->peer);
    GNUNET_assert (kx->retry_set_key_task != GNUNET_SCHEDULER_NO_TASK);
    GNUNET_SCHEDULER_cancel (kx->retry_set_key_task);
    kx->retry_set_key_task = GNUNET_SCHEDULER_NO_TASK;
    GNUNET_assert (kx->keep_alive_task == GNUNET_SCHEDULER_NO_TASK);
    update_timeout (kx);
    break;
  case PEER_STATE_KEY_CONFIRMED:
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
  struct GNUNET_CRYPTO_AesInitializationVector iv;

  GNUNET_assert (kx->retry_set_key_task == GNUNET_SCHEDULER_NO_TASK);
  if (KX_STATE_UP == kx->status) 
    return; /* nothing to do */
  if (kx->public_key == NULL)
  {
    /* lookup public key, then try again */
    kx->pitr =
      GNUNET_PEERINFO_iterate (peerinfo, &kx->peer,
			       GNUNET_TIME_UNIT_FOREVER_REL /* timeout? */,
			       &process_hello, kx);
    return;
  }

  /* update status */
  switch (n->status)
  {
  case KX_STATE_DOWN:
    n->status = PEER_STATE_KEY_SENT;    
    /* setup SET KEY message */
    setup_fresh_set_key (kx);
    setup_fresh_ping (kx);
    GNUNET_STATISTICS_update (stats,
			      gettext_noop
			      ("# SET_KEY and PING messages created"), 1,
			      GNUNET_NO);
    break;
  case KX_STATE_KEY_SENT:
    break;
  case KX_STATE_KEY_RECEIVED:
    break;
  case KX_STATE_KEY_CONFIRMED:
    GNUNET_break (0);
    return;
  default:
    GNUNET_break (0);
    return;
  }

  /* always update sender status in SET KEY message */
  kx->skm.sender_status = htonl ((int32_t) kx->status);

  GDS_NEIGHBOURS_transmit (&kx->peer,
			   &kx->skm.header,
			   kx->set_key_retry_frequency);
  GDS_NEIGHBOURS_transmit (&kx->peer,
			   &kx->ping.header,
			   kx->set_key_retry_frequency);
  kx->retry_set_key_task =
    GNUNET_SCHEDULER_add_delayed (kx->set_key_retry_frequency,
				  &set_key_retry_task, kx);
}


/**
 * Encrypt and transmit a message with the given payload.
 *
 * @param kx key exchange context
 * @param bw_in bandwidth limit to transmit to the other peer;
 *              the other peer shall not send us more than the
 *              given rate
 * @param payload payload of the message
 * @param payload_size number of bytes in 'payload'
 */
void
GSC_KX_encrypt_and_transmit (struct GSC_KeyExchangeInfo *kx,
			     struct GNUNET_BANDWIDTH_Value32NBO bw_in,
			     const void *payload,
			     size_t payload_size)
{
  size_t used = payload_size + sizeof (struct EncryptedMessage);
  char pbuf[used]; /* plaintext */
  char cbuf[used]; /* ciphertext */
  struct EncryptedMessage *em;  /* encrypted message */
  struct EncryptedMessage *ph;  /* plaintext header */
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  struct GNUNET_CRYPTO_AuthKey auth_key;

#if DEBUG_CORE_QUOTA
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending %u b/s as new limit to peer `%4s'\n",
              (unsigned int) ntohl (bw_in.value__),
	      GNUNET_i2s (&kx->peer));
#endif
  ph = (struct EncryptedMessage*) pbuf;
  ph->iv_seed =
      htonl (GNUNET_CRYPTO_random_u32
             (GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX));
  ph->sequence_number = htonl (++kx->last_sequence_number_sent);
  ph->inbound_bw_limit = bw_in;
  ph->timestamp = GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get ());
  memcpy (&ph[1], payload, payload_size);

  em = (struct EncryptedMessage *) cbuf;
  em->header.size = htons (used);
  em->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_ENCRYPTED_MESSAGE);
  em->iv_seed = ph->iv_seed;
  derive_iv (&iv, &kx->encrypt_key, ph->iv_seed, &kx->peer);
  GNUNET_assert (GNUNET_OK ==
                 do_encrypt (kx, &iv, &ph->sequence_number, &em->sequence_number,
                             used - ENCRYPTED_HEADER_SIZE));
  derive_auth_key (&auth_key, &kx->encrypt_key, ph->iv_seed,
                   kx->encrypt_key_created);
  GNUNET_CRYPTO_hmac (&auth_key, &em->sequence_number,
                      used - ENCRYPTED_HEADER_SIZE, &em->hmac);
  GDS_NEIGHBOURS_transmit (&kx->peer,
			   &em->header,
			   GNUNET_TIME_UNIT_FOREVER_REL);
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
  kx->timeout = GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
  if (kx->keep_alive_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (n->keep_alive_task);
  kx->keep_alive_task =
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_divide
				  (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
				   2), &send_keep_alive, kx);
}


/**
 * We received an encrypted message.  Decrypt, validate and
 * pass on to the appropriate clients.
 *
 * @param n target of the message
 * @param m encrypted message
 * @param atsi performance data
 * @param atsi_count number of entries in ats (excluding 0-termination)
 */
void
GSC_KX_handle_encrypted_message (struct GSC_KeyExchangeInfo *n, 
				 const struct GNUNET_MessageHeader *msg,
				 const struct GNUNET_TRANSPORT_ATS_Information *atsi,
				 uint32_t atsi_count)
{
  const struct EncryptedMessage *m;
  char buf[size];
  struct EncryptedMessage *pt;  /* plaintext */
  GNUNET_HashCode ph;
  uint32_t snum;
  struct GNUNET_TIME_Absolute t;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  struct GNUNET_CRYPTO_AuthKey auth_key;
  uint16_t size = ntohs (msg->size);

  if (size <
      sizeof (struct EncryptedMessage) + sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_break_op (0);
    return;
  }
  m = (const struct EncryptedMessage*) msg;
  if ( (kx->status != KX_STATE_KEY_RECEIVED) &&
       (kx->status != KX_STATE_UP) )
  {
    GNUNET_STATISTICS_update (stats,
			      gettext_noop
			      ("# failed to decrypt message (no session key)"),
			      1, GNUNET_NO);
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
      GNUNET_STATISTICS_update (stats,
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
    GNUNET_STATISTICS_update (stats,
                              gettext_noop
                              ("# bytes dropped (ancient message)"), size,
                              GNUNET_NO);
    return;
  }

  /* process decrypted message(s) */
  update_timeout (kx);
  GSC_SESSIONS_update (&kx->peer,
		       pt->inbound_bw_limit,
		       atsi, atsi_count); // FIXME: does 'SESSIONS' need atsi!?
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# bytes of payload decrypted"),
                            size - sizeof (struct EncryptedMessage), GNUNET_NO);
  if (GNUNET_OK !=
      GNUNET_SERVER_mst_receive (mst, kx, &buf[sizeof (struct EncryptedMessage)],
                                 size - sizeof (struct EncryptedMessage),
                                 GNUNET_YES, GNUNET_NO))
    GNUNET_break_op (0);
}




/**
 * Deliver P2P message to interested clients.
 *
 * @param cls always NULL
 * @param client who sent us the message (struct GSC_KeyExchangeInfo)
 * @param m the message
 */
static void
deliver_message (void *cls, void *client, const struct GNUNET_MessageHeader *m)
{
  struct GSC_KeyExchangeInfo *kx = client;

  // FIXME (need to check stuff, need ATSI, etc.)
  // FIXME: does clients work properly if never called with option 'NOTHING'!?
  GSC_CLIENTS_deliver_message (&kx->peer,
			       NULL, 0, // kx->atsi...
			       m,
			       ntohs (m->size),
			       GNUNET_CORE_OPTION_SEND_FULL_INBOUND);
  GSC_CLIENTS_deliver_message (&kx->peer,
			       NULL, 0, // kx->atsi...
			       m,
			       sizeof (struct GNUNET_MessageHeader),
			       GNUNET_CORE_OPTION_SEND_HDR_INBOUND);
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
                _("Core service is lacking HOSTKEY configuration setting.  Exiting.\n"));
    return GNUNET_SYSERR;
  }
  my_private_key = GNUNET_CRYPTO_rsa_key_create_from_file (keyfile);
  GNUNET_free (keyfile);
  if (my_private_key == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Core service could not access hostkey.  Exiting.\n"));
    return GNUNET_SYSERR;
  }
  GNUNET_CRYPTO_rsa_key_get_public (my_private_key, &my_public_key);
  GNUNET_CRYPTO_hash (&my_public_key, sizeof (my_public_key),
                      &my_identity.hashPubKey);
  peerinfo = GNUNET_PEERINFO_connect (cfg);
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
  if (my_private_key != NULL)
  {
    GNUNET_CRYPTO_rsa_key_free (my_private_key);
    my_private_key = NULL;
  }
  if (peerinfo != NULL)
  {
    GNUNET_PEERINFO_disconnect (peerinfo);
    peerinfo = NULL;
  }
  if (mst != NULL)
  {
    GNUNET_SERVER_mst_destroy (mst);
    mst = NULL;
  }
}

/* end of gnunet-service-core_kx.c */
