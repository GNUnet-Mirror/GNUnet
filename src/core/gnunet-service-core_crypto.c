
/**
 * Our private key.
 */
static struct GNUNET_CRYPTO_RsaPrivateKey *my_private_key;

/**
 * Our public key.
 */
static struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded my_public_key;


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
 * @param n neighbour we are sending to
 * @param iv initialization vector to use
 * @param in ciphertext
 * @param out plaintext
 * @param size size of in/out
 * @return GNUNET_OK on success
 */
static int
do_encrypt (struct Neighbour *n,
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
                                            &n->encrypt_key, iv, out));
  GNUNET_STATISTICS_update (stats, gettext_noop ("# bytes encrypted"), size,
                            GNUNET_NO);
#if DEBUG_CORE > 2
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypted %u bytes for `%4s' using key %u, IV %u\n",
              (unsigned int) size, GNUNET_i2s (&n->peer),
              (unsigned int) n->encrypt_key.crc32, GNUNET_CRYPTO_crc32_n (iv,
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
 * @param n neighbour we are receiving from
 * @param iv initialization vector to use
 * @param in ciphertext
 * @param out plaintext
 * @param size size of in/out
 * @return GNUNET_OK on success
 */
static int
do_decrypt (struct Neighbour *n,
            const struct GNUNET_CRYPTO_AesInitializationVector *iv,
            const void *in, void *out, size_t size)
{
  if (size != (uint16_t) size)
  {
    GNUNET_break (0);
    return GNUNET_NO;
  }
  if ((n->status != PEER_STATE_KEY_RECEIVED) &&
      (n->status != PEER_STATE_KEY_CONFIRMED))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (size !=
      GNUNET_CRYPTO_aes_decrypt (in, (uint16_t) size, &n->decrypt_key, iv, out))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  GNUNET_STATISTICS_update (stats, gettext_noop ("# bytes decrypted"), size,
                            GNUNET_NO);
#if DEBUG_CORE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Decrypted %u bytes from `%4s' using key %u, IV %u\n",
              (unsigned int) size, GNUNET_i2s (&n->peer),
              (unsigned int) n->decrypt_key.crc32, GNUNET_CRYPTO_crc32_n (iv,
                                                                          sizeof
                                                                          (*iv)));
#endif
  return GNUNET_OK;
}



/**
 * We received an encrypted message.  Decrypt, validate and
 * pass on to the appropriate clients.
 *
 * @param n target of the message
 * @param m encrypted message
 * @param ats performance data
 * @param ats_count number of entries in ats (excluding 0-termination)
 */
static void
handle_encrypted_message (struct Neighbour *n, const struct EncryptedMessage *m,
                          const struct GNUNET_TRANSPORT_ATS_Information *ats,
                          uint32_t ats_count)
{
  size_t size = ntohs (m->header.size);
  char buf[size];
  struct EncryptedMessage *pt;  /* plaintext */
  GNUNET_HashCode ph;
  uint32_t snum;
  struct GNUNET_TIME_Absolute t;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  struct GNUNET_CRYPTO_AuthKey auth_key;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service receives `%s' request from `%4s'.\n",
              "ENCRYPTED_MESSAGE", GNUNET_i2s (&n->peer));
#endif
  /* validate hash */
  derive_auth_key (&auth_key, &n->decrypt_key, m->iv_seed,
                   n->decrypt_key_created);
  GNUNET_CRYPTO_hmac (&auth_key, &m->sequence_number,
                      size - ENCRYPTED_HEADER_SIZE, &ph);
#if DEBUG_HANDSHAKE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Re-Authenticated %u bytes of ciphertext (`%u'): `%s'\n",
              (unsigned int) size - ENCRYPTED_HEADER_SIZE,
              GNUNET_CRYPTO_crc32_n (&m->sequence_number,
                                     size - ENCRYPTED_HEADER_SIZE),
              GNUNET_h2s (&ph));
#endif

  if (0 != memcmp (&ph, &m->hmac, sizeof (GNUNET_HashCode)))
  {
    /* checksum failed */
    GNUNET_break_op (0);
    return;
  }
  derive_iv (&iv, &n->decrypt_key, m->iv_seed, &my_identity);
  /* decrypt */
  if (GNUNET_OK !=
      do_decrypt (n, &iv, &m->sequence_number, &buf[ENCRYPTED_HEADER_SIZE],
                  size - ENCRYPTED_HEADER_SIZE))
    return;
  pt = (struct EncryptedMessage *) buf;

  /* validate sequence number */
  snum = ntohl (pt->sequence_number);
  if (n->last_sequence_number_received == snum)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Received duplicate message, ignoring.\n");
    /* duplicate, ignore */
    GNUNET_STATISTICS_update (stats,
                              gettext_noop ("# bytes dropped (duplicates)"),
                              size, GNUNET_NO);
    return;
  }
  if ((n->last_sequence_number_received > snum) &&
      (n->last_sequence_number_received - snum > 32))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Received ancient out of sequence message, ignoring.\n");
    /* ancient out of sequence, ignore */
    GNUNET_STATISTICS_update (stats,
                              gettext_noop
                              ("# bytes dropped (out of sequence)"), size,
                              GNUNET_NO);
    return;
  }
  if (n->last_sequence_number_received > snum)
  {
    unsigned int rotbit = 1 << (n->last_sequence_number_received - snum - 1);

    if ((n->last_packets_bitmap & rotbit) != 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Received duplicate message, ignoring.\n");
      GNUNET_STATISTICS_update (stats,
                                gettext_noop ("# bytes dropped (duplicates)"),
                                size, GNUNET_NO);
      /* duplicate, ignore */
      return;
    }
    n->last_packets_bitmap |= rotbit;
  }
  if (n->last_sequence_number_received < snum)
  {
    int shift = (snum - n->last_sequence_number_received);

    if (shift >= 8 * sizeof (n->last_packets_bitmap))
      n->last_packets_bitmap = 0;
    else
      n->last_packets_bitmap <<= shift;
    n->last_sequence_number_received = snum;
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
  if (n->bw_out_external_limit.value__ != pt->inbound_bw_limit.value__)
  {
#if DEBUG_CORE_SET_QUOTA
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received %u b/s as new inbound limit for peer `%4s'\n",
                (unsigned int) ntohl (pt->inbound_bw_limit.value__),
                GNUNET_i2s (&n->peer));
#endif
    n->bw_out_external_limit = pt->inbound_bw_limit;
    n->bw_out =
        GNUNET_BANDWIDTH_value_min (n->bw_out_external_limit,
                                    n->bw_out_internal_limit);
    GNUNET_BANDWIDTH_tracker_update_quota (&n->available_send_window,
                                           n->bw_out);
    GNUNET_TRANSPORT_set_quota (transport, &n->peer, n->bw_in, n->bw_out);
  }
  n->last_activity = GNUNET_TIME_absolute_get ();
  if (n->keep_alive_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (n->keep_alive_task);
  n->keep_alive_task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_relative_divide
                                    (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                     2), &send_keep_alive, n);
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# bytes of payload decrypted"),
                            size - sizeof (struct EncryptedMessage), GNUNET_NO);
  handle_peer_status_change (n);
  update_neighbour_performance (n, ats, ats_count);
  if (GNUNET_OK !=
      GNUNET_SERVER_mst_receive (mst, n, &buf[sizeof (struct EncryptedMessage)],
                                 size - sizeof (struct EncryptedMessage),
                                 GNUNET_YES, GNUNET_NO))
    GNUNET_break_op (0);
}


/**
 * Wrapper around 'free_neighbour'; helper for 'cleaning_task'.
 */
static int
free_neighbour_helper (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct Neighbour *n = value;

  free_neighbour (n);
  return GNUNET_OK;
}


int 
GSC_CRYPTO_init ()
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
  if (my_private_key == NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Core service could not access hostkey.  Exiting.\n"));
    return GNUNET_SYSERR;
  }
  GNUNET_CRYPTO_rsa_key_get_public (my_private_key, &my_public_key);
  GNUNET_CRYPTO_hash (&my_public_key, sizeof (my_public_key),
                      &my_identity.hashPubKey);

  return GNUNET_OK;
}


void
GSC_CRYPTO_done ()
{
  if (my_private_key != NULL)
    GNUNET_CRYPTO_rsa_key_free (my_private_key);
}
