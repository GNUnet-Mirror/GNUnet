
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
 * Handle to peerinfo service.
 */
static struct GNUNET_PEERINFO_Handle *peerinfo;



/**
 * We received a PING message.  Validate and transmit
 * PONG.
 *
 * @param n sender of the PING
 * @param m the encrypted PING message itself
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
static void
handle_ping (struct Neighbour *n, const struct PingMessage *m,
             const struct GNUNET_TRANSPORT_ATS_Information *ats,
             uint32_t ats_count)
{
  struct PingMessage t;
  struct PongMessage tx;
  struct PongMessage *tp;
  struct MessageEntry *me;
  struct GNUNET_CRYPTO_AesInitializationVector iv;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service receives `%s' request from `%4s'.\n", "PING",
              GNUNET_i2s (&n->peer));
#endif
  derive_iv (&iv, &n->decrypt_key, m->iv_seed, &my_identity);
  if (GNUNET_OK !=
      do_decrypt (n, &iv, &m->target, &t.target,
                  sizeof (struct PingMessage) - ((void *) &m->target -
                                                 (void *) m)))
    return;
#if DEBUG_HANDSHAKE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Decrypted `%s' to `%4s' with challenge %u decrypted using key %u, IV %u (salt %u)\n",
              "PING", GNUNET_i2s (&t.target), (unsigned int) t.challenge,
              (unsigned int) n->decrypt_key.crc32, GNUNET_CRYPTO_crc32_n (&iv,
                                                                          sizeof
                                                                          (iv)),
              m->iv_seed);
#endif
  GNUNET_STATISTICS_update (stats, gettext_noop ("# PING messages decrypted"),
                            1, GNUNET_NO);
  if (0 !=
      memcmp (&t.target, &my_identity, sizeof (struct GNUNET_PeerIdentity)))
  {
    char sender[9];
    char peer[9];

    GNUNET_snprintf (sender, sizeof (sender), "%8s", GNUNET_i2s (&n->peer));
    GNUNET_snprintf (peer, sizeof (peer), "%8s", GNUNET_i2s (&t.target));
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _
                ("Received PING from `%s' for different identity: I am `%s', PONG identity: `%s'\n"),
                sender, GNUNET_i2s (&my_identity), peer);
    GNUNET_break_op (0);
    return;
  }
  update_neighbour_performance (n, ats, ats_count);
  me = GNUNET_malloc (sizeof (struct MessageEntry) +
                      sizeof (struct PongMessage));
  GNUNET_CONTAINER_DLL_insert_after (n->encrypted_head, n->encrypted_tail,
                                     n->encrypted_tail, me);
  me->deadline = GNUNET_TIME_relative_to_absolute (MAX_PONG_DELAY);
  me->priority = PONG_PRIORITY;
  me->size = sizeof (struct PongMessage);
  tx.inbound_bw_limit = n->bw_in;
  tx.challenge = t.challenge;
  tx.target = t.target;
  tp = (struct PongMessage *) &me[1];
  tp->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_PONG);
  tp->header.size = htons (sizeof (struct PongMessage));
  tp->iv_seed =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX);
  derive_pong_iv (&iv, &n->encrypt_key, tp->iv_seed, t.challenge, &n->peer);
  do_encrypt (n, &iv, &tx.challenge, &tp->challenge,
              sizeof (struct PongMessage) - ((void *) &tp->challenge -
                                             (void *) tp));
  GNUNET_STATISTICS_update (stats, gettext_noop ("# PONG messages created"), 1,
                            GNUNET_NO);
#if DEBUG_HANDSHAKE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypting `%s' with challenge %u using key %u, IV %u (salt %u)\n",
              "PONG", (unsigned int) t.challenge,
              (unsigned int) n->encrypt_key.crc32, GNUNET_CRYPTO_crc32_n (&iv,
                                                                          sizeof
                                                                          (iv)),
              tp->iv_seed);
#endif
  /* trigger queue processing */
  process_encrypted_neighbour_queue (n);
}


/**
 * We received a PONG message.  Validate and update our status.
 *
 * @param n sender of the PONG
 * @param m the encrypted PONG message itself
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
static void
handle_pong (struct Neighbour *n, const struct PongMessage *m,
             const struct GNUNET_TRANSPORT_ATS_Information *ats,
             uint32_t ats_count)
{
  struct PongMessage t;
  struct ConnectNotifyMessage *cnm;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];
  struct GNUNET_TRANSPORT_ATS_Information *mats;
  size_t size;

#if DEBUG_HANDSHAKE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service receives `%s' response from `%4s'.\n", "PONG",
              GNUNET_i2s (&n->peer));
#endif
  /* mark as garbage, just to be sure */
  memset (&t, 255, sizeof (t));
  derive_pong_iv (&iv, &n->decrypt_key, m->iv_seed, n->ping_challenge,
                  &my_identity);
  if (GNUNET_OK !=
      do_decrypt (n, &iv, &m->challenge, &t.challenge,
                  sizeof (struct PongMessage) - ((void *) &m->challenge -
                                                 (void *) m)))
  {
    GNUNET_break_op (0);
    return;
  }
  GNUNET_STATISTICS_update (stats, gettext_noop ("# PONG messages decrypted"),
                            1, GNUNET_NO);
#if DEBUG_HANDSHAKE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Decrypted `%s' from `%4s' with challenge %u using key %u, IV %u (salt %u)\n",
              "PONG", GNUNET_i2s (&t.target), (unsigned int) t.challenge,
              (unsigned int) n->decrypt_key.crc32, GNUNET_CRYPTO_crc32_n (&iv,
                                                                          sizeof
                                                                          (iv)),
              m->iv_seed);
#endif
  if ((0 != memcmp (&t.target, &n->peer, sizeof (struct GNUNET_PeerIdentity)))
      || (n->ping_challenge != t.challenge))
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
    GNUNET_break_op (n->ping_challenge != t.challenge);
    return;
  }
  switch (n->status)
  {
  case PEER_STATE_DOWN:
    GNUNET_break (0);           /* should be impossible */
    return;
  case PEER_STATE_KEY_SENT:
    GNUNET_break (0);           /* should be impossible, how did we decrypt? */
    return;
  case PEER_STATE_KEY_RECEIVED:
    GNUNET_STATISTICS_update (stats,
                              gettext_noop
                              ("# Session keys confirmed via PONG"), 1,
                              GNUNET_NO);
    n->status = PEER_STATE_KEY_CONFIRMED;
    {
      struct GNUNET_MessageHeader *hdr;

      hdr = compute_type_map_message ();
      send_type_map_to_neighbour (hdr, &n->peer.hashPubKey, n);
      GNUNET_free (hdr);
    }
    if (n->bw_out_external_limit.value__ != t.inbound_bw_limit.value__)
    {
      n->bw_out_external_limit = t.inbound_bw_limit;
      n->bw_out =
          GNUNET_BANDWIDTH_value_min (n->bw_out_external_limit,
                                      n->bw_out_internal_limit);
      GNUNET_BANDWIDTH_tracker_update_quota (&n->available_send_window,
                                             n->bw_out);
      GNUNET_TRANSPORT_set_quota (transport, &n->peer, n->bw_in, n->bw_out);
    }
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Confirmed key via `%s' message for peer `%4s'\n", "PONG",
                GNUNET_i2s (&n->peer));
#endif
    if (n->retry_set_key_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (n->retry_set_key_task);
      n->retry_set_key_task = GNUNET_SCHEDULER_NO_TASK;
    }
    update_neighbour_performance (n, ats, ats_count);
    size =
        sizeof (struct ConnectNotifyMessage) +
        (n->ats_count) * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
    if (size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
    {
      GNUNET_break (0);
      /* recovery strategy: throw away performance data */
      GNUNET_array_grow (n->ats, n->ats_count, 0);
      size =
          sizeof (struct PeerStatusNotifyMessage) +
          n->ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
    }
    cnm = (struct ConnectNotifyMessage *) buf;
    cnm->header.size = htons (size);
    cnm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_CONNECT);
    cnm->ats_count = htonl (n->ats_count);
    cnm->peer = n->peer;
    mats = &cnm->ats;
    memcpy (mats, n->ats,
            n->ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information));
    mats[n->ats_count].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
    mats[n->ats_count].value = htonl (0);
    send_to_all_clients (&cnm->header, GNUNET_NO,
                         GNUNET_CORE_OPTION_SEND_CONNECT);
    process_encrypted_neighbour_queue (n);
    /* fall-through! */
  case PEER_STATE_KEY_CONFIRMED:
    n->last_activity = GNUNET_TIME_absolute_get ();
    if (n->keep_alive_task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (n->keep_alive_task);
    n->keep_alive_task =
        GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_divide
                                      (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                       2), &send_keep_alive, n);
    handle_peer_status_change (n);
    break;
  default:
    GNUNET_break (0);
    break;
  }
}


/**
 * We received a SET_KEY message.  Validate and update
 * our key material and status.
 *
 * @param n the neighbour from which we received message m
 * @param m the set key message we received
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
static void
handle_set_key (struct Neighbour *n, const struct SetKeyMessage *m,
                const struct GNUNET_TRANSPORT_ATS_Information *ats,
                uint32_t ats_count)
{
  struct SetKeyMessage *m_cpy;
  struct GNUNET_TIME_Absolute t;
  struct GNUNET_CRYPTO_AesSessionKey k;
  struct PingMessage *ping;
  struct PongMessage *pong;
  enum PeerStateMachine sender_status;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service receives `%s' request from `%4s'.\n", "SET_KEY",
              GNUNET_i2s (&n->peer));
#endif
  if (n->public_key == NULL)
  {
    if (n->pitr != NULL)
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Ignoring `%s' message due to lack of public key for peer (still trying to obtain one).\n",
                  "SET_KEY");
#endif
      return;
    }
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Lacking public key for peer, trying to obtain one (handle_set_key).\n");
#endif
    m_cpy = GNUNET_malloc (sizeof (struct SetKeyMessage));
    memcpy (m_cpy, m, sizeof (struct SetKeyMessage));
    /* lookup n's public key, then try again */
    GNUNET_assert (n->skm == NULL);
    n->skm = m_cpy;
    n->pitr =
        GNUNET_PEERINFO_iterate (peerinfo, &n->peer, GNUNET_TIME_UNIT_MINUTES,
                                 &process_hello_retry_handle_set_key, n);
    GNUNET_STATISTICS_update (stats,
                              gettext_noop
                              ("# SET_KEY messages deferred (need public key)"),
                              1, GNUNET_NO);
    return;
  }
  if (0 !=
      memcmp (&m->target, &my_identity, sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                _
                ("Received `%s' message that was for `%s', not for me.  Ignoring.\n"),
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
                                 &m->signature, n->public_key)))
  {
    /* invalid signature */
    GNUNET_break_op (0);
    return;
  }
  t = GNUNET_TIME_absolute_ntoh (m->creation_time);
  if (((n->status == PEER_STATE_KEY_RECEIVED) ||
       (n->status == PEER_STATE_KEY_CONFIRMED)) &&
      (t.abs_value < n->decrypt_key_created.abs_value))
  {
    /* this could rarely happen due to massive re-ordering of
     * messages on the network level, but is most likely either
     * a bug or some adversary messing with us.  Report. */
    GNUNET_break_op (0);
    return;
  }
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Decrypting key material.\n");
#endif
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
  n->decrypt_key = k;
  if (n->decrypt_key_created.abs_value != t.abs_value)
  {
    /* fresh key, reset sequence numbers */
    n->last_sequence_number_received = 0;
    n->last_packets_bitmap = 0;
    n->decrypt_key_created = t;
  }
  update_neighbour_performance (n, ats, ats_count);
  sender_status = (enum PeerStateMachine) ntohl (m->sender_status);
  switch (n->status)
  {
  case PEER_STATE_DOWN:
    n->status = PEER_STATE_KEY_RECEIVED;
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Responding to `%s' with my own key.\n", "SET_KEY");
#endif
    send_key (n);
    break;
  case PEER_STATE_KEY_SENT:
  case PEER_STATE_KEY_RECEIVED:
    n->status = PEER_STATE_KEY_RECEIVED;
    if ((sender_status != PEER_STATE_KEY_RECEIVED) &&
        (sender_status != PEER_STATE_KEY_CONFIRMED))
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Responding to `%s' with my own key (other peer has status %u).\n",
                  "SET_KEY", (unsigned int) sender_status);
#endif
      send_key (n);
    }
    break;
  case PEER_STATE_KEY_CONFIRMED:
    if ((sender_status != PEER_STATE_KEY_RECEIVED) &&
        (sender_status != PEER_STATE_KEY_CONFIRMED))
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Responding to `%s' with my own key (other peer has status %u), I was already fully up.\n",
                  "SET_KEY", (unsigned int) sender_status);
#endif
      send_key (n);
    }
    break;
  default:
    GNUNET_break (0);
    break;
  }
  if (n->pending_ping != NULL)
  {
    ping = n->pending_ping;
    n->pending_ping = NULL;
    handle_ping (n, ping, NULL, 0);
    GNUNET_free (ping);
  }
  if (n->pending_pong != NULL)
  {
    pong = n->pending_pong;
    n->pending_pong = NULL;
    handle_pong (n, pong, NULL, 0);
    GNUNET_free (pong);
  }
}



/**
 * PEERINFO is giving us a HELLO for a peer.  Add the public key to
 * the neighbour's struct and retry send_key.  Or, if we did not get a
 * HELLO, just do nothing.
 *
 * @param cls the 'struct Neighbour' to retry sending the key for
 * @param peer the peer for which this is the HELLO
 * @param hello HELLO message of that peer
 * @param err_msg NULL if successful, otherwise contains error message
 */
static void
process_hello_retry_send_key (void *cls, const struct GNUNET_PeerIdentity *peer,
                              const struct GNUNET_HELLO_Message *hello,
                              const char *err_msg)
{
  struct Neighbour *n = cls;

  if (err_msg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                _("Error in communication with PEERINFO service\n"));
    /* return; */
  }

  if (peer == NULL)
  {
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Entered `%s' and `%s' is NULL!\n",
                "process_hello_retry_send_key", "peer");
#endif
    n->pitr = NULL;
    if (n->public_key != NULL)
    {
      if (n->retry_set_key_task != GNUNET_SCHEDULER_NO_TASK)
      {
        GNUNET_SCHEDULER_cancel (n->retry_set_key_task);
        n->retry_set_key_task = GNUNET_SCHEDULER_NO_TASK;
      }
      GNUNET_STATISTICS_update (stats,
                                gettext_noop
                                ("# SET_KEY messages deferred (need public key)"),
                                -1, GNUNET_NO);
      send_key (n);
    }
    else
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Failed to obtain public key for peer `%4s', delaying processing of SET_KEY\n",
                  GNUNET_i2s (&n->peer));
#endif
      GNUNET_STATISTICS_update (stats,
                                gettext_noop
                                ("# Delayed connecting due to lack of public key"),
                                1, GNUNET_NO);
      if (GNUNET_SCHEDULER_NO_TASK == n->retry_set_key_task)
        n->retry_set_key_task =
            GNUNET_SCHEDULER_add_delayed (n->set_key_retry_frequency,
                                          &set_key_retry_task, n);
    }
    return;
  }

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Entered `%s' for peer `%4s'\n",
              "process_hello_retry_send_key", GNUNET_i2s (peer));
#endif
  if (n->public_key != NULL)
  {
    /* already have public key, why are we here? */
    GNUNET_break (0);
    return;
  }

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received new `%s' message for `%4s', initiating key exchange.\n",
              "HELLO", GNUNET_i2s (peer));
#endif
  n->public_key =
      GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
  if (GNUNET_OK != GNUNET_HELLO_get_key (hello, n->public_key))
  {
    GNUNET_STATISTICS_update (stats,
                              gettext_noop
                              ("# Error extracting public key from HELLO"), 1,
                              GNUNET_NO);
    GNUNET_free (n->public_key);
    n->public_key = NULL;
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "GNUNET_HELLO_get_key returned awfully\n");
#endif
    return;
  }
}


/**
 * Send our key (and encrypted PING) to the other peer.
 *
 * @param n the other peer
 */
static void
send_key (struct Neighbour *n)
{
  struct MessageEntry *pos;
  struct SetKeyMessage *sm;
  struct MessageEntry *me;
  struct PingMessage pp;
  struct PingMessage *pm;
  struct GNUNET_CRYPTO_AesInitializationVector iv;

  if (n->retry_set_key_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (n->retry_set_key_task);
    n->retry_set_key_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (n->pitr != NULL)
  {
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Key exchange in progress with `%4s'.\n",
                GNUNET_i2s (&n->peer));
#endif
    return;                     /* already in progress */
  }
  if (GNUNET_YES != n->is_connected)
  {
    GNUNET_STATISTICS_update (stats,
                              gettext_noop
                              ("# Asking transport to connect (for SET_KEY)"),
                              1, GNUNET_NO);
    GNUNET_TRANSPORT_try_connect (transport, &n->peer);
    return;
  }
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asked to perform key exchange with `%4s'.\n",
              GNUNET_i2s (&n->peer));
#endif
  if (n->public_key == NULL)
  {
    /* lookup n's public key, then try again */
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Lacking public key for `%4s', trying to obtain one (send_key).\n",
                GNUNET_i2s (&n->peer));
#endif
    GNUNET_assert (n->pitr == NULL);
    n->pitr =
        GNUNET_PEERINFO_iterate (peerinfo, &n->peer,
                                 GNUNET_TIME_relative_multiply
                                 (GNUNET_TIME_UNIT_SECONDS, 20),
                                 &process_hello_retry_send_key, n);
    return;
  }
  pos = n->encrypted_head;
  while (pos != NULL)
  {
    if (GNUNET_YES == pos->is_setkey)
    {
      if (pos->sender_status == n->status)
      {
#if DEBUG_CORE
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "`%s' message for `%4s' queued already\n", "SET_KEY",
                    GNUNET_i2s (&n->peer));
#endif
        goto trigger_processing;
      }
      GNUNET_CONTAINER_DLL_remove (n->encrypted_head, n->encrypted_tail, pos);
      GNUNET_free (pos);
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Removing queued `%s' message for `%4s', will create a new one\n",
                  "SET_KEY", GNUNET_i2s (&n->peer));
#endif
      break;
    }
    pos = pos->next;
  }

  /* update status */
  switch (n->status)
  {
  case PEER_STATE_DOWN:
    n->status = PEER_STATE_KEY_SENT;
    break;
  case PEER_STATE_KEY_SENT:
    break;
  case PEER_STATE_KEY_RECEIVED:
    break;
  case PEER_STATE_KEY_CONFIRMED:
    break;
  default:
    GNUNET_break (0);
    break;
  }


  /* first, set key message */
  me = GNUNET_malloc (sizeof (struct MessageEntry) +
                      sizeof (struct SetKeyMessage) +
                      sizeof (struct PingMessage));
  me->deadline = GNUNET_TIME_relative_to_absolute (MAX_SET_KEY_DELAY);
  me->priority = SET_KEY_PRIORITY;
  me->size = sizeof (struct SetKeyMessage) + sizeof (struct PingMessage);
  me->is_setkey = GNUNET_YES;
  me->got_slack = GNUNET_YES;   /* do not defer this one! */
  me->sender_status = n->status;
  GNUNET_CONTAINER_DLL_insert_after (n->encrypted_head, n->encrypted_tail,
                                     n->encrypted_tail, me);
  sm = (struct SetKeyMessage *) &me[1];
  sm->header.size = htons (sizeof (struct SetKeyMessage));
  sm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_SET_KEY);
  sm->sender_status =
      htonl ((int32_t)
             ((n->status ==
               PEER_STATE_DOWN) ? PEER_STATE_KEY_SENT : n->status));
  sm->purpose.size =
      htonl (sizeof (struct GNUNET_CRYPTO_RsaSignaturePurpose) +
             sizeof (struct GNUNET_TIME_AbsoluteNBO) +
             sizeof (struct GNUNET_CRYPTO_RsaEncryptedData) +
             sizeof (struct GNUNET_PeerIdentity));
  sm->purpose.purpose = htonl (GNUNET_SIGNATURE_PURPOSE_SET_KEY);
  sm->creation_time = GNUNET_TIME_absolute_hton (n->encrypt_key_created);
  sm->target = n->peer;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_rsa_encrypt (&n->encrypt_key,
                                            sizeof (struct
                                                    GNUNET_CRYPTO_AesSessionKey),
                                            n->public_key, &sm->encrypted_key));
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CRYPTO_rsa_sign (my_private_key, &sm->purpose,
                                         &sm->signature));
  pm = (struct PingMessage *) &sm[1];
  pm->header.size = htons (sizeof (struct PingMessage));
  pm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_PING);
  pm->iv_seed =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX);
  derive_iv (&iv, &n->encrypt_key, pm->iv_seed, &n->peer);
  pp.challenge = n->ping_challenge;
  pp.target = n->peer;
#if DEBUG_HANDSHAKE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypting `%s' and `%s' messages with challenge %u for `%4s' using key %u, IV %u (salt %u).\n",
              "SET_KEY", "PING", (unsigned int) n->ping_challenge,
              GNUNET_i2s (&n->peer), (unsigned int) n->encrypt_key.crc32,
              GNUNET_CRYPTO_crc32_n (&iv, sizeof (iv)), pm->iv_seed);
#endif
  do_encrypt (n, &iv, &pp.target, &pm->target,
              sizeof (struct PingMessage) - ((void *) &pm->target -
                                             (void *) pm));
  GNUNET_STATISTICS_update (stats,
                            gettext_noop
                            ("# SET_KEY and PING messages created"), 1,
                            GNUNET_NO);
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Have %llu ms left for `%s' transmission.\n",
              (unsigned long long)
              GNUNET_TIME_absolute_get_remaining (me->deadline).rel_value,
              "SET_KEY");
#endif
trigger_processing:
  /* trigger queue processing */
  process_encrypted_neighbour_queue (n);
  if ((n->status != PEER_STATE_KEY_CONFIRMED) &&
      (GNUNET_SCHEDULER_NO_TASK == n->retry_set_key_task))
    n->retry_set_key_task =
        GNUNET_SCHEDULER_add_delayed (n->set_key_retry_frequency,
                                      &set_key_retry_task, n);
}


/**
 * We received a SET_KEY message.  Validate and update
 * our key material and status.
 *
 * @param n the neighbour from which we received message m
 * @param m the set key message we received
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
static void
handle_set_key (struct Neighbour *n, const struct SetKeyMessage *m,
                const struct GNUNET_TRANSPORT_ATS_Information *ats,
                uint32_t ats_count);



/**
 * PEERINFO is giving us a HELLO for a peer.  Add the public key to
 * the neighbour's struct and retry handling the set_key message.  Or,
 * if we did not get a HELLO, just free the set key message.
 *
 * @param cls pointer to the set key message
 * @param peer the peer for which this is the HELLO
 * @param hello HELLO message of that peer
 * @param err_msg NULL if successful, otherwise contains error message
 */
static void
process_hello_retry_handle_set_key (void *cls,
                                    const struct GNUNET_PeerIdentity *peer,
                                    const struct GNUNET_HELLO_Message *hello,
                                    const char *err_msg)
{
  struct Neighbour *n = cls;
  struct SetKeyMessage *sm = n->skm;

  if (err_msg != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                _("Error in communication with PEERINFO service\n"));
    /* return; */
  }

  if (peer == NULL)
  {
    n->skm = NULL;
    n->pitr = NULL;
    if (n->public_key != NULL)
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Received `%s' for `%4s', continuing processing of `%s' message.\n",
                  "HELLO", GNUNET_i2s (&n->peer), "SET_KEY");
#endif
      handle_set_key (n, sm, NULL, 0);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  _
                  ("Ignoring `%s' message due to lack of public key for peer `%4s' (failed to obtain one).\n"),
                  "SET_KEY", GNUNET_i2s (&n->peer));
    }
    GNUNET_free (sm);
    return;
  }
  if (n->public_key != NULL)
    return;                     /* multiple HELLOs match!? */
  n->public_key =
      GNUNET_malloc (sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
  if (GNUNET_OK != GNUNET_HELLO_get_key (hello, n->public_key))
  {
    GNUNET_break_op (0);
    GNUNET_free (n->public_key);
    n->public_key = NULL;
  }
}



/**
 * Task that will retry "send_key" if our previous attempt failed
 * to yield a PONG.
 */
static void
set_key_retry_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Neighbour *n = cls;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Retrying key transmission to `%4s'\n",
              GNUNET_i2s (&n->peer));
#endif
  n->retry_set_key_task = GNUNET_SCHEDULER_NO_TASK;
  n->set_key_retry_frequency =
      GNUNET_TIME_relative_multiply (n->set_key_retry_frequency, 2);
  send_key (n);
}


struct GSC_KeyExchangeInfo *
GSC_KX_start (const struct GNUNET_PeerIdentity *pid)
{
  struct GSC_KeyExchangeInfo *kx;

  kx = NULL;
  return kx;
}


void
GSC_KX_stop (struct GSC_KeyExchangeInfo *kx)
{
  if (kx->pitr != NULL)
  {
    GNUNET_PEERINFO_iterate_cancel (kx->pitr);
    kx->pitr = NULL;
  }
  if (kx->retry_set_key_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (kx->retry_set_key_task);
  GNUNET_free_non_null (kx->public_key);
  GNUNET_free (kx);
}


int 
GSC_KX_init ()
{
  peerinfo = GNUNET_PEERINFO_connect (cfg);
  if (NULL == peerinfo)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Could not access PEERINFO service.  Exiting.\n"));
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


void 
GSC_KX_done ()
{
  if (peerinfo != NULL)
    {
      GNUNET_PEERINFO_disconnect (peerinfo);
      peerinfo = NULL;
    }

}
