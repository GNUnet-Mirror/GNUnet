/* code for managing of 'encrypted' sessions (key exchange done) */


/**
 * Record kept for each request for transmission issued by a
 * client that is still pending.
 */
struct ClientActiveRequest;

/**
 * Data kept per session.
 */
struct Session
{
  /**
   * Identity of the other peer.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Head of list of requests from clients for transmission to
   * this peer.
   */
  struct ClientActiveRequest *active_client_request_head;

  /**
   * Tail of list of requests from clients for transmission to
   * this peer.
   */
  struct ClientActiveRequest *active_client_request_tail;

  /**
   * Performance data for the peer.
   */
  struct GNUNET_TRANSPORT_ATS_Information *ats;

  /**
   * Information about the key exchange with the other peer.
   */
  struct GSC_KeyExchangeInfo *kxinfo;

  /**
   * ID of task used for sending keep-alive pings.
   */
  GNUNET_SCHEDULER_TaskIdentifier keep_alive_task;

  /**
   * ID of task used for cleaning up dead neighbour entries.
   */
  GNUNET_SCHEDULER_TaskIdentifier dead_clean_task;

  /**
   * ID of task used for updating bandwidth quota for this neighbour.
   */
  GNUNET_SCHEDULER_TaskIdentifier quota_update_task;

  /**
   * At what time did we initially establish (as in, complete session
   * key handshake) this connection?  Should be zero if status != KEY_CONFIRMED.
   */
  struct GNUNET_TIME_Absolute time_established;

  /**
   * At what time did we last receive an encrypted message from the
   * other peer?  Should be zero if status != KEY_CONFIRMED.
   */
  struct GNUNET_TIME_Absolute last_activity;

  /**
   * How valueable were the messages of this peer recently?
   */
  unsigned long long current_preference;

  /**
   * Number of entries in 'ats'.
   */
  unsigned int ats_count;

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
   * Available bandwidth in for this peer (current target).
   */
  struct GNUNET_BANDWIDTH_Value32NBO bw_in;

  /**
   * Available bandwidth out for this peer (current target).
   */
  struct GNUNET_BANDWIDTH_Value32NBO bw_out;

  /**
   * Internal bandwidth limit set for this peer (initially typically
   * set to "-1").  Actual "bw_out" is MIN of
   * "bpm_out_internal_limit" and "bw_out_external_limit".
   */
  struct GNUNET_BANDWIDTH_Value32NBO bw_out_internal_limit;

  /**
   * External bandwidth limit set for this peer by the
   * peer that we are communicating with.  "bw_out" is MIN of
   * "bw_out_internal_limit" and "bw_out_external_limit".
   */
  struct GNUNET_BANDWIDTH_Value32NBO bw_out_external_limit;

};


/**
 * Map of peer identities to 'struct Session'.
 */
static struct GNUNET_CONTAINER_MultiHashMap *sessions;


/**
 * Session entry for "this" peer.
 */
static struct Session self;

/**
 * Sum of all preferences among all neighbours.
 */
static unsigned long long preference_sum;


// FIXME.........

/**
 * At what time should the connection to the given neighbour
 * time out (given no further activity?)
 *
 * @param n neighbour in question
 * @return absolute timeout
 */
static struct GNUNET_TIME_Absolute
get_neighbour_timeout (struct Neighbour *n)
{
  return GNUNET_TIME_absolute_add (n->last_activity,
                                   GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
}


/**
 * Helper function for update_preference_sum.
 */
static int
update_preference (void *cls, const GNUNET_HashCode * key, void *value)
{
  unsigned long long *ps = cls;
  struct Neighbour *n = value;

  n->current_preference /= 2;
  *ps += n->current_preference;
  return GNUNET_OK;
}


/**
 * A preference value for a neighbour was update.  Update
 * the preference sum accordingly.
 *
 * @param inc how much was a preference value increased?
 */
static void
update_preference_sum (unsigned long long inc)
{
  unsigned long long os;

  os = preference_sum;
  preference_sum += inc;
  if (preference_sum >= os)
    return;                     /* done! */
  /* overflow! compensate by cutting all values in half! */
  preference_sum = 0;
  GNUNET_CONTAINER_multihashmap_iterate (neighbours, &update_preference,
                                         &preference_sum);
  GNUNET_STATISTICS_set (stats, gettext_noop ("# total peer preference"),
                         preference_sum, GNUNET_NO);
}


/**
 * Find the entry for the given neighbour.
 *
 * @param peer identity of the neighbour
 * @return NULL if we are not connected, otherwise the
 *         neighbour's entry.
 */
static struct Neighbour *
find_neighbour (const struct GNUNET_PeerIdentity *peer)
{
  return GNUNET_CONTAINER_multihashmap_get (neighbours, &peer->hashPubKey);
}


/**
 * Function called by transport telling us that a peer
 * changed status.
 *
 * @param n the peer that changed status
 */
static void
handle_peer_status_change (struct Neighbour *n)
{
  struct PeerStatusNotifyMessage *psnm;
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];
  struct GNUNET_TRANSPORT_ATS_Information *ats;
  size_t size;

  if ((!n->is_connected) || (n->status != PEER_STATE_KEY_CONFIRMED))
    return;
#if DEBUG_CORE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Peer `%4s' changed status\n",
              GNUNET_i2s (&n->peer));
#endif
  size =
      sizeof (struct PeerStatusNotifyMessage) +
      n->ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
  if (size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    /* recovery strategy: throw away performance data */
    GNUNET_array_grow (n->ats, n->ats_count, 0);
    size =
        sizeof (struct PeerStatusNotifyMessage) +
        n->ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
  }
  psnm = (struct PeerStatusNotifyMessage *) buf;
  psnm->header.size = htons (size);
  psnm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_STATUS_CHANGE);
  psnm->timeout = GNUNET_TIME_absolute_hton (get_neighbour_timeout (n));
  psnm->bandwidth_in = n->bw_in;
  psnm->bandwidth_out = n->bw_out;
  psnm->peer = n->peer;
  psnm->ats_count = htonl (n->ats_count);
  ats = &psnm->ats;
  memcpy (ats, n->ats,
          n->ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information));
  ats[n->ats_count].type = htonl (0);
  ats[n->ats_count].value = htonl (0);
  send_to_all_clients (&psnm->header, GNUNET_YES,
                       GNUNET_CORE_OPTION_SEND_STATUS_CHANGE);
  GNUNET_STATISTICS_update (stats, gettext_noop ("# peer status changes"), 1,
                            GNUNET_NO);
}



/**
 * Go over our message queue and if it is not too long, go
 * over the pending requests from clients for this
 * neighbour and send some clients a 'READY' notification.
 *
 * @param n which peer to process
 */
static void
schedule_peer_messages (struct Neighbour *n)
{
  struct SendMessageReady smr;
  struct ClientActiveRequest *car;
  struct ClientActiveRequest *pos;
  struct Client *c;
  struct MessageEntry *mqe;
  unsigned int queue_size;

  /* check if neighbour queue is empty enough! */
  if (n != &self)
  {
    queue_size = 0;
    mqe = n->messages;
    while (mqe != NULL)
    {
      queue_size++;
      mqe = mqe->next;
    }
    if (queue_size >= MAX_PEER_QUEUE_SIZE)
    {
#if DEBUG_CORE_CLIENT
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Not considering client transmission requests: queue full\n");
#endif
      return;                   /* queue still full */
    }
    /* find highest priority request */
    pos = n->active_client_request_head;
    car = NULL;
    while (pos != NULL)
    {
      if ((car == NULL) || (pos->priority > car->priority))
        car = pos;
      pos = pos->next;
    }
  }
  else
  {
    car = n->active_client_request_head;
  }
  if (car == NULL)
    return;                     /* no pending requests */
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Permitting client transmission request to `%s'\n",
              GNUNET_i2s (&n->peer));
#endif
  c = car->client;
  GNUNET_CONTAINER_DLL_remove (n->active_client_request_head,
                               n->active_client_request_tail, car);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (c->requests,
                                                       &n->peer.hashPubKey,
                                                       car));
  smr.header.size = htons (sizeof (struct SendMessageReady));
  smr.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_SEND_READY);
  smr.size = htons (car->msize);
  smr.smr_id = car->smr_id;
  smr.peer = n->peer;
  send_to_client (c, &smr.header, GNUNET_NO);
  GNUNET_free (car);
}



/**
 * Free the given entry for the neighbour (it has
 * already been removed from the list at this point).
 *
 * @param n neighbour to free
 */
static void
free_neighbour (struct Neighbour *n)
{
  struct MessageEntry *m;
  struct ClientActiveRequest *car;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Destroying neighbour entry for peer `%4s'\n",
              GNUNET_i2s (&n->peer));
#endif
  if (n->skm != NULL)
  {
    GNUNET_free (n->skm);
    n->skm = NULL;
  }
  while (NULL != (m = n->messages))
  {
    n->messages = m->next;
    GNUNET_free (m);
  }
  while (NULL != (m = n->encrypted_head))
  {
    GNUNET_CONTAINER_DLL_remove (n->encrypted_head, n->encrypted_tail, m);
    GNUNET_free (m);
  }
  while (NULL != (car = n->active_client_request_head))
  {
    GNUNET_CONTAINER_DLL_remove (n->active_client_request_head,
                                 n->active_client_request_tail, car);
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multihashmap_remove (car->client->requests,
                                                         &n->peer.hashPubKey,
                                                         car));
    GNUNET_free (car);
  }
  if (NULL != n->th)
  {
    GNUNET_TRANSPORT_notify_transmit_ready_cancel (n->th);
    n->th = NULL;
  }
  if (n->retry_plaintext_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (n->retry_plaintext_task);
  if (n->quota_update_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (n->quota_update_task);
  if (n->dead_clean_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (n->dead_clean_task);
  if (n->keep_alive_task != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_SCHEDULER_cancel (n->keep_alive_task);
  if (n->status == PEER_STATE_KEY_CONFIRMED)
    GNUNET_STATISTICS_update (stats, gettext_noop ("# established sessions"),
                              -1, GNUNET_NO);
  GNUNET_array_grow (n->ats, n->ats_count, 0);
  GNUNET_free_non_null (n->pending_ping);
  GNUNET_free_non_null (n->pending_pong);
  GNUNET_free (n);
}



/**
 * Task triggered when a neighbour entry is about to time out
 * (and we should prevent this by sending a PING).
 *
 * @param cls the 'struct Neighbour'
 * @param tc scheduler context (not used)
 */
static void
send_keep_alive (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Neighbour *n = cls;
  struct GNUNET_TIME_Relative retry;
  struct GNUNET_TIME_Relative left;
  struct MessageEntry *me;
  struct PingMessage pp;
  struct PingMessage *pm;
  struct GNUNET_CRYPTO_AesInitializationVector iv;

  n->keep_alive_task = GNUNET_SCHEDULER_NO_TASK;
  /* send PING */
  me = GNUNET_malloc (sizeof (struct MessageEntry) +
                      sizeof (struct PingMessage));
  me->deadline = GNUNET_TIME_relative_to_absolute (MAX_PING_DELAY);
  me->priority = PING_PRIORITY;
  me->size = sizeof (struct PingMessage);
  GNUNET_CONTAINER_DLL_insert_after (n->encrypted_head, n->encrypted_tail,
                                     n->encrypted_tail, me);
  pm = (struct PingMessage *) &me[1];
  pm->header.size = htons (sizeof (struct PingMessage));
  pm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_PING);
  pm->iv_seed =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX);
  derive_iv (&iv, &n->encrypt_key, pm->iv_seed, &n->peer);
  pp.challenge = n->ping_challenge;
  pp.target = n->peer;
#if DEBUG_HANDSHAKE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypting `%s' message with challenge %u for `%4s' using key %u, IV %u (salt %u).\n",
              "PING", (unsigned int) n->ping_challenge, GNUNET_i2s (&n->peer),
              (unsigned int) n->encrypt_key.crc32, GNUNET_CRYPTO_crc32_n (&iv,
                                                                          sizeof
                                                                          (iv)),
              pm->iv_seed);
#endif
  do_encrypt (n, &iv, &pp.target, &pm->target,
              sizeof (struct PingMessage) - ((void *) &pm->target -
                                             (void *) pm));
  process_encrypted_neighbour_queue (n);
  /* reschedule PING job */
  left = GNUNET_TIME_absolute_get_remaining (get_neighbour_timeout (n));
  retry =
      GNUNET_TIME_relative_max (GNUNET_TIME_relative_divide (left, 2),
                                MIN_PING_FREQUENCY);
  n->keep_alive_task =
      GNUNET_SCHEDULER_add_delayed (retry, &send_keep_alive, n);

}

/**
 * Consider freeing the given neighbour since we may not need
 * to keep it around anymore.
 *
 * @param n neighbour to consider discarding
 */
static void
consider_free_neighbour (struct Neighbour *n);


/**
 * Task triggered when a neighbour entry might have gotten stale.
 *
 * @param cls the 'struct Neighbour'
 * @param tc scheduler context (not used)
 */
static void
consider_free_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Neighbour *n = cls;

  n->dead_clean_task = GNUNET_SCHEDULER_NO_TASK;
  consider_free_neighbour (n);
}


/**
 * Consider freeing the given neighbour since we may not need
 * to keep it around anymore.
 *
 * @param n neighbour to consider discarding
 */
static void
consider_free_neighbour (struct Neighbour *n)
{
  struct GNUNET_TIME_Relative left;

  if ((n->th != NULL) || (n->pitr != NULL) || (GNUNET_YES == n->is_connected))
    return;                     /* no chance */

  left = GNUNET_TIME_absolute_get_remaining (get_neighbour_timeout (n));
  if (left.rel_value > 0)
  {
    if (n->dead_clean_task != GNUNET_SCHEDULER_NO_TASK)
      GNUNET_SCHEDULER_cancel (n->dead_clean_task);
    n->dead_clean_task =
        GNUNET_SCHEDULER_add_delayed (left, &consider_free_task, n);
    return;
  }
  /* actually free the neighbour... */
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (neighbours,
                                                       &n->peer.hashPubKey, n));
  GNUNET_STATISTICS_set (stats, gettext_noop ("# neighbour entries allocated"),
                         GNUNET_CONTAINER_multihashmap_size (neighbours),
                         GNUNET_NO);
  free_neighbour (n);
}


/**
 * Function called when the transport service is ready to
 * receive an encrypted message for the respective peer
 *
 * @param cls neighbour to use message from
 * @param size number of bytes we can transmit
 * @param buf where to copy the message
 * @return number of bytes transmitted
 */
static size_t
notify_encrypted_transmit_ready (void *cls, size_t size, void *buf)
{
  struct Neighbour *n = cls;
  struct MessageEntry *m;
  size_t ret;
  char *cbuf;

  n->th = NULL;
  m = n->encrypted_head;
  if (m == NULL)
  {
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Encrypted message queue empty, no messages added to buffer for `%4s'\n",
                GNUNET_i2s (&n->peer));
#endif
    return 0;
  }
  GNUNET_CONTAINER_DLL_remove (n->encrypted_head, n->encrypted_tail, m);
  ret = 0;
  cbuf = buf;
  if (buf != NULL)
  {
    GNUNET_assert (size >= m->size);
    memcpy (cbuf, &m[1], m->size);
    ret = m->size;
    GNUNET_BANDWIDTH_tracker_consume (&n->available_send_window, m->size);
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Copied message of type %u and size %u into transport buffer for `%4s'\n",
                (unsigned int)
                ntohs (((struct GNUNET_MessageHeader *) &m[1])->type),
                (unsigned int) ret, GNUNET_i2s (&n->peer));
#endif
    process_encrypted_neighbour_queue (n);
  }
  else
  {
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Transmission of message of type %u and size %u failed\n",
                (unsigned int)
                ntohs (((struct GNUNET_MessageHeader *) &m[1])->type),
                (unsigned int) m->size);
#endif
  }
  GNUNET_free (m);
  consider_free_neighbour (n);
  GNUNET_STATISTICS_update (stats,
                            gettext_noop
                            ("# encrypted bytes given to transport"), ret,
                            GNUNET_NO);
  return ret;
}


/**
 * Check if we have encrypted messages for the specified neighbour
 * pending, and if so, check with the transport about sending them
 * out.
 *
 * @param n neighbour to check.
 */
static void
process_encrypted_neighbour_queue (struct Neighbour *n)
{
  struct MessageEntry *m;

  if (n->th != NULL)
    return;                     /* request already pending */
  if (GNUNET_YES != n->is_connected)
  {
    GNUNET_break (0);
    return;
  }
  m = n->encrypted_head;
  if (m == NULL)
  {
    /* encrypted queue empty, try plaintext instead */
    process_plaintext_neighbour_queue (n);
    return;
  }
#if DEBUG_CORE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Asking transport for transmission of %u bytes to `%4s' in next %llu ms\n",
              (unsigned int) m->size, GNUNET_i2s (&n->peer),
              (unsigned long long)
              GNUNET_TIME_absolute_get_remaining (m->deadline).rel_value);
#endif
  n->th =
       GNUNET_TRANSPORT_notify_transmit_ready (transport, &n->peer, m->size,
                                              m->priority,
                                              GNUNET_TIME_absolute_get_remaining
                                              (m->deadline),
                                              &notify_encrypted_transmit_ready,
                                              n);
  if (n->th == NULL)
  {
    /* message request too large or duplicate request */
    GNUNET_break (0);
    /* discard encrypted message */
    GNUNET_CONTAINER_DLL_remove (n->encrypted_head, n->encrypted_tail, m);
    GNUNET_free (m);
    process_encrypted_neighbour_queue (n);
  }
}


/**
 * Initialize a new 'struct Neighbour'.
 *
 * @param pid ID of the new neighbour
 * @return handle for the new neighbour
 */
static struct Neighbour *
create_neighbour (const struct GNUNET_PeerIdentity *pid)
{
  struct Neighbour *n;
  struct GNUNET_TIME_Absolute now;

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Creating neighbour entry for peer `%4s'\n", GNUNET_i2s (pid));
#endif
  n = GNUNET_malloc (sizeof (struct Neighbour));
  n->peer = *pid;
  GNUNET_CRYPTO_aes_create_session_key (&n->encrypt_key);
  now = GNUNET_TIME_absolute_get ();
  n->encrypt_key_created = now;
  n->last_activity = now;
  n->set_key_retry_frequency = INITIAL_SET_KEY_RETRY_FREQUENCY;
  n->bw_in = GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT;
  n->bw_out = GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT;
  n->bw_out_internal_limit = GNUNET_BANDWIDTH_value_init (UINT32_MAX);
  n->bw_out_external_limit = GNUNET_CONSTANTS_DEFAULT_BW_IN_OUT;
  n->ping_challenge =
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (neighbours,
                                                    &n->peer.hashPubKey, n,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  GNUNET_STATISTICS_set (stats, gettext_noop ("# neighbour entries allocated"),
                         GNUNET_CONTAINER_multihashmap_size (neighbours),
                         GNUNET_NO);
  neighbour_quota_update (n, NULL);
  consider_free_neighbour (n);
  return n;
}


int
GSC_NEIGHBOURS_init ()
{
  neighbours = GNUNET_CONTAINER_multihashmap_create (128);
  self.public_key = &my_public_key;
  self.peer = my_identity;
  self.last_activity = GNUNET_TIME_UNIT_FOREVER_ABS;
  self.status = PEER_STATE_KEY_CONFIRMED;
  self.is_connected = GNUNET_YES;
  return GNUNET_OK;
}


void
GSC_NEIGHBOURS_done ()
{
  GNUNET_CONTAINER_multihashmap_iterate (neighbours, &free_neighbour_helper,
                                         NULL);
  GNUNET_CONTAINER_multihashmap_destroy (neighbours);
  neighbours = NULL;
  GNUNET_STATISTICS_set (stats, gettext_noop ("# neighbour entries allocated"),
                         0, GNUNET_NO);
}
