struct GSC_KeyExchangeInfo
{

  /**
   * SetKeyMessage to transmit, NULL if we are not currently trying
   * to send one.
   */
  struct SetKeyMessage *skm;

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
   * We received a PING message before we got the "public_key"
   * (or the SET_KEY).  We keep it here until we have a key
   * to decrypt it.  NULL if no PING is pending.
   */
  struct PingMessage *pending_ping;

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
   * At what frequency are we currently re-trying SET_KEY messages?
   */
  struct GNUNET_TIME_Relative set_key_retry_frequency;

  /**
   * ID of task used for re-trying SET_KEY and PING message.
   */
  GNUNET_SCHEDULER_TaskIdentifier retry_set_key_task;

  /**
   * What was our PING challenge number (for this peer)?
   */
  uint32_t ping_challenge;

  /**
   * What is our connection status?
   */
  enum PeerStateMachine status;

};
