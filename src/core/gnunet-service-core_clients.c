
/**
 * Data structure for each client connected to the core service.
 */
struct Client
{
  /**
   * Clients are kept in a linked list.
   */
  struct Client *next;

  /**
   * Handle for the client with the server API.
   */
  struct GNUNET_SERVER_Client *client_handle;

  /**
   * Array of the types of messages this peer cares
   * about (with "tcnt" entries).  Allocated as part
   * of this client struct, do not free!
   */
  const uint16_t *types;

  /**
   * Map of peer identities to active transmission requests of this
   * client to the peer (of type 'struct ClientActiveRequest').
   */
  struct GNUNET_CONTAINER_MultiHashMap *requests;

  /**
   * Options for messages this client cares about,
   * see GNUNET_CORE_OPTION_ values.
   */
  uint32_t options;

  /**
   * Number of types of incoming messages this client
   * specifically cares about.  Size of the "types" array.
   */
  unsigned int tcnt;

};


/**
 * Record kept for each request for transmission issued by a
 * client that is still pending.
 */
struct ClientActiveRequest
{

  /**
   * Active requests are kept in a doubly-linked list of
   * the respective target peer.
   */
  struct ClientActiveRequest *next;

  /**
   * Active requests are kept in a doubly-linked list of
   * the respective target peer.
   */
  struct ClientActiveRequest *prev;

  /**
   * Handle to the client.
   */
  struct Client *client;

  /**
   * By what time would the client want to see this message out?
   */
  struct GNUNET_TIME_Absolute deadline;

  /**
   * How important is this request.
   */
  uint32_t priority;

  /**
   * How many more requests does this client have?
   */
  uint32_t queue_size;

  /**
   * How many bytes does the client intend to send?
   */
  uint16_t msize;

  /**
   * Unique request ID (in big endian).
   */
  uint16_t smr_id;

};



/**
 * Linked list of our clients.
 */
static struct Client *clients;

/**
 * Context for notifications we need to send to our clients.
 */
static struct GNUNET_SERVER_NotificationContext *notifier;


/**
 * Our message stream tokenizer (for encrypted payload).
 */
static struct GNUNET_SERVER_MessageStreamTokenizer *mst;



/**
 * Send a message to one of our clients.
 *
 * @param client target for the message
 * @param msg message to transmit
 * @param can_drop could this message be dropped if the
 *        client's queue is getting too large?
 */
static void
send_to_client (struct Client *client, const struct GNUNET_MessageHeader *msg,
                int can_drop)
{
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Preparing to send %u bytes of message of type %u to client.\n",
              (unsigned int) ntohs (msg->size),
              (unsigned int) ntohs (msg->type));
#endif
  GNUNET_SERVER_notification_context_unicast (notifier, client->client_handle,
                                              msg, can_drop);
}





/**
 * Send a message to all of our current clients that have
 * the right options set.
 *
 * @param msg message to multicast
 * @param can_drop can this message be discarded if the queue is too long
 * @param options mask to use
 */
static void
send_to_all_clients (const struct GNUNET_MessageHeader *msg, int can_drop,
                     int options)
{
  struct Client *c;

  c = clients;
  while (c != NULL)
  {
    if (0 != (c->options & options))
    {
#if DEBUG_CORE_CLIENT > 1
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Sending message of type %u to client.\n",
                  (unsigned int) ntohs (msg->type));
#endif
      send_to_client (c, msg, can_drop);
    }
    c = c->next;
  }
}



/**
 * Handle CORE_SEND_REQUEST message.
 */
static void
handle_client_send_request (void *cls, struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message)
{
  const struct SendMessageRequest *req;
  struct Neighbour *n;
  struct Client *c;
  struct ClientActiveRequest *car;

  req = (const struct SendMessageRequest *) message;
  if (0 ==
      memcmp (&req->peer, &my_identity, sizeof (struct GNUNET_PeerIdentity)))
    n = &self;
  else
    n = find_neighbour (&req->peer);
  if ((n == NULL) || (GNUNET_YES != n->is_connected) ||
      (n->status != PEER_STATE_KEY_CONFIRMED))
  {
    /* neighbour must have disconnected since request was issued,
     * ignore (client will realize it once it processes the
     * disconnect notification) */
#if DEBUG_CORE_CLIENT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Dropped client request for transmission (am disconnected)\n");
#endif
    GNUNET_STATISTICS_update (stats,
                              gettext_noop
                              ("# send requests dropped (disconnected)"), 1,
                              GNUNET_NO);
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  c = clients;
  while ((c != NULL) && (c->client_handle != client))
    c = c->next;
  if (c == NULL)
  {
    /* client did not send INIT first! */
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  if (c->requests == NULL)
    c->requests = GNUNET_CONTAINER_multihashmap_create (16);
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received client transmission request. queueing\n");
#endif
  car = GNUNET_CONTAINER_multihashmap_get (c->requests, &req->peer.hashPubKey);
  if (car == NULL)
  {
    /* create new entry */
    car = GNUNET_malloc (sizeof (struct ClientActiveRequest));
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CONTAINER_multihashmap_put (c->requests,
                                                      &req->peer.hashPubKey,
                                                      car,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST));
    GNUNET_CONTAINER_DLL_insert (n->active_client_request_head,
                                 n->active_client_request_tail, car);
    car->client = c;
  }
  car->deadline = GNUNET_TIME_absolute_ntoh (req->deadline);
  car->priority = ntohl (req->priority);
  car->queue_size = ntohl (req->queue_size);
  car->msize = ntohs (req->size);
  car->smr_id = req->smr_id;
  schedule_peer_messages (n);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Notify client about an existing connection to one of our neighbours.
 */
static int
notify_client_about_neighbour (void *cls, const GNUNET_HashCode * key,
                               void *value)
{
  struct Client *c = cls;
  struct Neighbour *n = value;
  size_t size;
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];
  struct GNUNET_TRANSPORT_ATS_Information *ats;
  struct ConnectNotifyMessage *cnm;

  size =
      sizeof (struct ConnectNotifyMessage) +
      (n->ats_count) * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
  if (size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    /* recovery strategy: throw away performance data */
    GNUNET_array_grow (n->ats, n->ats_count, 0);
    size =
        sizeof (struct ConnectNotifyMessage) +
        (n->ats_count) * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
  }
  cnm = (struct ConnectNotifyMessage *) buf;
  cnm->header.size = htons (size);
  cnm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_CONNECT);
  cnm->ats_count = htonl (n->ats_count);
  ats = &cnm->ats;
  memcpy (ats, n->ats,
          sizeof (struct GNUNET_TRANSPORT_ATS_Information) * n->ats_count);
  ats[n->ats_count].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
  ats[n->ats_count].value = htonl (0);
  if (n->status == PEER_STATE_KEY_CONFIRMED)
  {
#if DEBUG_CORE_CLIENT
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message to client.\n",
                "NOTIFY_CONNECT");
#endif
    cnm->peer = n->peer;
    send_to_client (c, &cnm->header, GNUNET_NO);
  }
  return GNUNET_OK;
}



/**
 * Handle CORE_INIT request.
 */
static void
handle_client_init (void *cls, struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *message)
{
  const struct InitMessage *im;
  struct InitReplyMessage irm;
  struct Client *c;
  uint16_t msize;
  const uint16_t *types;
  uint16_t *wtypes;
  unsigned int i;

#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client connecting to core service with `%s' message\n", "INIT");
#endif
  /* check that we don't have an entry already */
  c = clients;
  while (c != NULL)
  {
    if (client == c->client_handle)
    {
      GNUNET_break (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
    c = c->next;
  }
  msize = ntohs (message->size);
  if (msize < sizeof (struct InitMessage))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  GNUNET_SERVER_notification_context_add (notifier, client);
  im = (const struct InitMessage *) message;
  types = (const uint16_t *) &im[1];
  msize -= sizeof (struct InitMessage);
  c = GNUNET_malloc (sizeof (struct Client) + msize);
  c->client_handle = client;
  c->next = clients;
  clients = c;
  c->tcnt = msize / sizeof (uint16_t);
  c->types = (const uint16_t *) &c[1];
  wtypes = (uint16_t *) & c[1];
  for (i = 0; i < c->tcnt; i++)
  {
    wtypes[i] = ntohs (types[i]);
    my_type_map[wtypes[i] / 32] |= (1 << (wtypes[i] % 32));
  }
  if (c->tcnt > 0)
    broadcast_my_type_map ();
  c->options = ntohl (im->options);
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p is interested in %u message types\n", c,
              (unsigned int) c->tcnt);
#endif
  /* send init reply message */
  irm.header.size = htons (sizeof (struct InitReplyMessage));
  irm.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_INIT_REPLY);
  irm.reserved = htonl (0);
  memcpy (&irm.publicKey, &my_public_key,
          sizeof (struct GNUNET_CRYPTO_RsaPublicKeyBinaryEncoded));
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message to client.\n",
              "INIT_REPLY");
#endif
  send_to_client (c, &irm.header, GNUNET_NO);
  if (0 != (c->options & GNUNET_CORE_OPTION_SEND_CONNECT))
  {
    /* notify new client about existing neighbours */
    GNUNET_CONTAINER_multihashmap_iterate (neighbours,
                                           &notify_client_about_neighbour, c);
  }
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Free client request records.
 *
 * @param cls NULL
 * @param key identity of peer for which this is an active request
 * @param value the 'struct ClientActiveRequest' to free
 * @return GNUNET_YES (continue iteration)
 */
static int
destroy_active_client_request (void *cls, const GNUNET_HashCode * key,
                               void *value)
{
  struct ClientActiveRequest *car = value;
  struct Neighbour *n;
  struct GNUNET_PeerIdentity peer;

  peer.hashPubKey = *key;
  n = find_neighbour (&peer);
  GNUNET_assert (NULL != n);
  GNUNET_CONTAINER_DLL_remove (n->active_client_request_head,
                               n->active_client_request_tail, car);
  GNUNET_free (car);
  return GNUNET_YES;
}


/**
 * A client disconnected, clean up.
 *
 * @param cls closure
 * @param client identification of the client
 */
static void
handle_client_disconnect (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct Client *pos;
  struct Client *prev;
  unsigned int i;
  const uint16_t *wtypes;

  if (client == NULL)
    return;
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Client %p has disconnected from core service.\n", client);
#endif
  prev = NULL;
  pos = clients;
  while (pos != NULL)
  {
    if (client == pos->client_handle)
      break;
    prev = pos;
    pos = pos->next;
  }
  if (pos == NULL)
  {
    /* client never sent INIT */
    return;
  }
  if (prev == NULL)
    clients = pos->next;
  else
    prev->next = pos->next;
  if (pos->requests != NULL)
  {
    GNUNET_CONTAINER_multihashmap_iterate (pos->requests,
                                           &destroy_active_client_request,
                                           NULL);
    GNUNET_CONTAINER_multihashmap_destroy (pos->requests);
  }
  GNUNET_free (pos);

  /* rebuild my_type_map */
  memset (my_type_map, 0, sizeof (my_type_map));
  for (pos = clients; NULL != pos; pos = pos->next)
  {
    wtypes = (const uint16_t *) &pos[1];
    for (i = 0; i < pos->tcnt; i++)
      my_type_map[wtypes[i] / 32] |= (1 << (wtypes[i] % 32));
  }
  broadcast_my_type_map ();
}





/**
 * Handle CORE_SEND request.
 *
 * @param cls unused
 * @param client the client issuing the request
 * @param message the "struct SendMessage"
 */
static void
handle_client_send (void *cls, struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *message)
{
  const struct SendMessage *sm;
  struct Neighbour *n;
  struct MessageEntry *prev;
  struct MessageEntry *pos;
  struct MessageEntry *e;
  struct MessageEntry *min_prio_entry;
  struct MessageEntry *min_prio_prev;
  unsigned int min_prio;
  unsigned int queue_size;
  uint16_t msize;

  msize = ntohs (message->size);
  if (msize <
      sizeof (struct SendMessage) + sizeof (struct GNUNET_MessageHeader))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "msize is %u, should be at least %u (in %s:%d)\n", msize,
                sizeof (struct SendMessage) +
                sizeof (struct GNUNET_MessageHeader), __FILE__, __LINE__);
    GNUNET_break (0);
    if (client != NULL)
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  sm = (const struct SendMessage *) message;
  msize -= sizeof (struct SendMessage);
  if (0 ==
      memcmp (&sm->peer, &my_identity, sizeof (struct GNUNET_PeerIdentity)))
  {
    /* loopback */
    GNUNET_SERVER_mst_receive (mst, &self, (const char *) &sm[1], msize,
                               GNUNET_YES, GNUNET_NO);
    if (client != NULL)
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  n = find_neighbour (&sm->peer);
  if ((n == NULL) || (GNUNET_YES != n->is_connected) ||
      (n->status != PEER_STATE_KEY_CONFIRMED))
  {
    /* attempt to send message to peer that is not connected anymore
     * (can happen due to asynchrony) */
    GNUNET_STATISTICS_update (stats,
                              gettext_noop
                              ("# messages discarded (disconnected)"), 1,
                              GNUNET_NO);
    if (client != NULL)
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core received `%s' request, queueing %u bytes of plaintext data for transmission to `%4s'.\n",
              "SEND", (unsigned int) msize, GNUNET_i2s (&sm->peer));
#endif
  discard_expired_messages (n);
  /* bound queue size */
  /* NOTE: this entire block to bound the queue size should be
   * obsolete with the new client-request code and the
   * 'schedule_peer_messages' mechanism; we still have this code in
   * here for now as a sanity check for the new mechanmism;
   * ultimately, we should probably simply reject SEND messages that
   * are not 'approved' (or provide a new core API for very unreliable
   * delivery that always sends with priority 0).  Food for thought. */
  min_prio = UINT32_MAX;
  min_prio_entry = NULL;
  min_prio_prev = NULL;
  queue_size = 0;
  prev = NULL;
  pos = n->messages;
  while (pos != NULL)
  {
    if (pos->priority <= min_prio)
    {
      min_prio_entry = pos;
      min_prio_prev = prev;
      min_prio = pos->priority;
    }
    queue_size++;
    prev = pos;
    pos = pos->next;
  }
  if (queue_size >= MAX_PEER_QUEUE_SIZE)
  {
    /* queue full */
    if (ntohl (sm->priority) <= min_prio)
    {
      /* discard new entry; this should no longer happen! */
      GNUNET_break (0);
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Queue full (%u/%u), discarding new request (%u bytes of type %u)\n",
                  queue_size, (unsigned int) MAX_PEER_QUEUE_SIZE,
                  (unsigned int) msize, (unsigned int) ntohs (message->type));
#endif
      GNUNET_STATISTICS_update (stats,
                                gettext_noop ("# discarded CORE_SEND requests"),
                                1, GNUNET_NO);

      if (client != NULL)
        GNUNET_SERVER_receive_done (client, GNUNET_OK);
      return;
    }
    GNUNET_assert (min_prio_entry != NULL);
    /* discard "min_prio_entry" */
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Queue full, discarding existing older request\n");
#endif
    GNUNET_STATISTICS_update (stats,
                              gettext_noop
                              ("# discarded lower priority CORE_SEND requests"),
                              1, GNUNET_NO);
    if (min_prio_prev == NULL)
      n->messages = min_prio_entry->next;
    else
      min_prio_prev->next = min_prio_entry->next;
    GNUNET_free (min_prio_entry);
  }

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding transmission request for `%4s' of size %u to queue\n",
              GNUNET_i2s (&sm->peer), (unsigned int) msize);
#endif
  GNUNET_break (0 == ntohl (sm->reserved));
  e = GNUNET_malloc (sizeof (struct MessageEntry) + msize);
  e->deadline = GNUNET_TIME_absolute_ntoh (sm->deadline);
  e->priority = ntohl (sm->priority);
  e->size = msize;
  if (GNUNET_YES != (int) ntohl (sm->cork))
    e->got_slack = GNUNET_YES;
  memcpy (&e[1], &sm[1], msize);

  /* insert, keep list sorted by deadline */
  prev = NULL;
  pos = n->messages;
  while ((pos != NULL) && (pos->deadline.abs_value < e->deadline.abs_value))
  {
    prev = pos;
    pos = pos->next;
  }
  if (prev == NULL)
    n->messages = e;
  else
    prev->next = e;
  e->next = pos;

  /* consider scheduling now */
  process_plaintext_neighbour_queue (n);
  if (client != NULL)
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle CORE_REQUEST_CONNECT request.
 *
 * @param cls unused
 * @param client the client issuing the request
 * @param message the "struct ConnectMessage"
 */
static void
handle_client_request_connect (void *cls, struct GNUNET_SERVER_Client *client,
                               const struct GNUNET_MessageHeader *message)
{
  const struct ConnectMessage *cm = (const struct ConnectMessage *) message;
  struct Neighbour *n;

  if (0 ==
      memcmp (&cm->peer, &my_identity, sizeof (struct GNUNET_PeerIdentity)))
  {
    /* In this case a client has asked us to connect to ourselves, not really an error! */
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  GNUNET_break (ntohl (cm->reserved) == 0);
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core received `%s' request for `%4s', will try to establish connection\n",
              "REQUEST_CONNECT", GNUNET_i2s (&cm->peer));
#endif
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# connection requests received"), 1,
                            GNUNET_NO);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
  n = find_neighbour (&cm->peer);
  if ((n == NULL) || (GNUNET_YES != n->is_connected))
  {
    GNUNET_TRANSPORT_try_connect (transport, &cm->peer);
  }
  else
  {
    GNUNET_STATISTICS_update (stats,
                              gettext_noop
                              ("# connection requests ignored (already connected)"),
                              1, GNUNET_NO);
  }
}



/**
 * Helper function for handle_client_iterate_peers.
 *
 * @param cls the 'struct GNUNET_SERVER_TransmitContext' to queue replies
 * @param key identity of the connected peer
 * @param value the 'struct Neighbour' for the peer
 * @return GNUNET_OK (continue to iterate)
 */
static int
queue_connect_message (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GNUNET_SERVER_TransmitContext *tc = cls;
  struct Neighbour *n = value;
  char buf[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];
  struct GNUNET_TRANSPORT_ATS_Information *ats;
  size_t size;
  struct ConnectNotifyMessage *cnm;

  cnm = (struct ConnectNotifyMessage *) buf;
  if (n->status != PEER_STATE_KEY_CONFIRMED)
    return GNUNET_OK;
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
  ats = &cnm->ats;
  memcpy (ats, n->ats,
          n->ats_count * sizeof (struct GNUNET_TRANSPORT_ATS_Information));
  ats[n->ats_count].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
  ats[n->ats_count].value = htonl (0);
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message to client.\n",
              "NOTIFY_CONNECT");
#endif
  cnm->peer = n->peer;
  GNUNET_SERVER_transmit_context_append_message (tc, &cnm->header);
  return GNUNET_OK;
}


/**
 * Handle CORE_ITERATE_PEERS request.
 *
 * @param cls unused
 * @param client client sending the iteration request
 * @param message iteration request message
 */
static void
handle_client_iterate_peers (void *cls, struct GNUNET_SERVER_Client *client,
                             const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MessageHeader done_msg;
  struct GNUNET_SERVER_TransmitContext *tc;
  int msize;

  /* notify new client about existing neighbours */

  msize = ntohs (message->size);
  tc = GNUNET_SERVER_transmit_context_create (client);
  if (msize == sizeof (struct GNUNET_MessageHeader))
    GNUNET_CONTAINER_multihashmap_iterate (neighbours, &queue_connect_message,
                                           tc);
  else
    GNUNET_break (0);

  done_msg.size = htons (sizeof (struct GNUNET_MessageHeader));
  done_msg.type = htons (GNUNET_MESSAGE_TYPE_CORE_ITERATE_PEERS_END);
  GNUNET_SERVER_transmit_context_append_message (tc, &done_msg);
  GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Handle CORE_PEER_CONNECTED request.  Notify client about existing neighbours.
 *
 * @param cls unused
 * @param client client sending the iteration request
 * @param message iteration request message
 */
static void
handle_client_have_peer (void *cls, struct GNUNET_SERVER_Client *client,
                         const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MessageHeader done_msg;
  struct GNUNET_SERVER_TransmitContext *tc;
  struct GNUNET_PeerIdentity *peer;

  tc = GNUNET_SERVER_transmit_context_create (client);
  peer = (struct GNUNET_PeerIdentity *) &message[1];
  GNUNET_CONTAINER_multihashmap_get_multiple (neighbours, &peer->hashPubKey,
                                              &queue_connect_message, tc);
  done_msg.size = htons (sizeof (struct GNUNET_MessageHeader));
  done_msg.type = htons (GNUNET_MESSAGE_TYPE_CORE_ITERATE_PEERS_END);
  GNUNET_SERVER_transmit_context_append_message (tc, &done_msg);
  GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Handle REQUEST_INFO request.
 *
 * @param cls unused
 * @param client client sending the request
 * @param message iteration request message
 */
static void
handle_client_request_info (void *cls, struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message)
{
  const struct RequestInfoMessage *rcm;
  struct Client *pos;
  struct Neighbour *n;
  struct ConfigurationInfoMessage cim;
  int32_t want_reserv;
  int32_t got_reserv;
  unsigned long long old_preference;
  struct GNUNET_TIME_Relative rdelay;

  rdelay = GNUNET_TIME_relative_get_zero ();
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Core service receives `%s' request.\n",
              "REQUEST_INFO");
#endif
  pos = clients;
  while (pos != NULL)
  {
    if (client == pos->client_handle)
      break;
    pos = pos->next;
  }
  if (pos == NULL)
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  rcm = (const struct RequestInfoMessage *) message;
  n = find_neighbour (&rcm->peer);
  memset (&cim, 0, sizeof (cim));
  if ((n != NULL) && (GNUNET_YES == n->is_connected))
  {
    want_reserv = ntohl (rcm->reserve_inbound);
    if (n->bw_out_internal_limit.value__ != rcm->limit_outbound.value__)
    {
      n->bw_out_internal_limit = rcm->limit_outbound;
      if (n->bw_out.value__ !=
          GNUNET_BANDWIDTH_value_min (n->bw_out_internal_limit,
                                      n->bw_out_external_limit).value__)
      {
        n->bw_out =
            GNUNET_BANDWIDTH_value_min (n->bw_out_internal_limit,
                                        n->bw_out_external_limit);
        GNUNET_BANDWIDTH_tracker_update_quota (&n->available_recv_window,
                                               n->bw_out);
        GNUNET_TRANSPORT_set_quota (transport, &n->peer, n->bw_in, n->bw_out);
        handle_peer_status_change (n);
      }
    }
    if (want_reserv < 0)
    {
      got_reserv = want_reserv;
    }
    else if (want_reserv > 0)
    {
      rdelay =
          GNUNET_BANDWIDTH_tracker_get_delay (&n->available_recv_window,
                                              want_reserv);
      if (rdelay.rel_value == 0)
        got_reserv = want_reserv;
      else
        got_reserv = 0;         /* all or nothing */
    }
    else
      got_reserv = 0;
    GNUNET_BANDWIDTH_tracker_consume (&n->available_recv_window, got_reserv);
    old_preference = n->current_preference;
    n->current_preference += GNUNET_ntohll (rcm->preference_change);
    if (old_preference > n->current_preference)
    {
      /* overflow; cap at maximum value */
      n->current_preference = ULLONG_MAX;
    }
    update_preference_sum (n->current_preference - old_preference);
#if DEBUG_CORE_QUOTA
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Received reservation request for %d bytes for peer `%4s', reserved %d bytes, suggesting delay of %llu ms\n",
                (int) want_reserv, GNUNET_i2s (&rcm->peer), (int) got_reserv,
                (unsigned long long) rdelay.rel_value);
#endif
    cim.reserved_amount = htonl (got_reserv);
    cim.reserve_delay = GNUNET_TIME_relative_hton (rdelay);
    cim.bw_out = n->bw_out;
    cim.preference = n->current_preference;
  }
  else
  {
    /* Technically, this COULD happen (due to asynchronous behavior),
     * but it should be rare, so we should generate an info event
     * to help diagnosis of serious errors that might be masked by this */
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _
                ("Client asked for preference change with peer `%s', which is not connected!\n"),
                GNUNET_i2s (&rcm->peer));
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  cim.header.size = htons (sizeof (struct ConfigurationInfoMessage));
  cim.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_CONFIGURATION_INFO);
  cim.peer = rcm->peer;
  cim.rim_id = rcm->rim_id;
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Sending `%s' message to client.\n",
              "CONFIGURATION_INFO");
#endif
  send_to_client (pos, &cim.header, GNUNET_NO);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}




/**
 * Send a P2P message to a client.
 *
 * @param sender who sent us the message?
 * @param client who should we give the message to?
 * @param m contains the message to transmit
 * @param msize number of bytes in buf to transmit
 */
static void
send_p2p_message_to_client (struct Neighbour *sender, struct Client *client,
                            const void *m, size_t msize)
{
  size_t size =
      msize + sizeof (struct NotifyTrafficMessage) +
      (sender->ats_count) * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
  char buf[size];
  struct NotifyTrafficMessage *ntm;
  struct GNUNET_TRANSPORT_ATS_Information *ats;

  GNUNET_assert (GNUNET_YES == sender->is_connected);
  GNUNET_break (sender->status == PEER_STATE_KEY_CONFIRMED);
  if (size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    /* recovery strategy: throw performance data away... */
    GNUNET_array_grow (sender->ats, sender->ats_count, 0);
    size =
        msize + sizeof (struct NotifyTrafficMessage) +
        (sender->ats_count) * sizeof (struct GNUNET_TRANSPORT_ATS_Information);
  }
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Core service passes message from `%4s' of type %u to client.\n",
              GNUNET_i2s (&sender->peer),
              (unsigned int)
              ntohs (((const struct GNUNET_MessageHeader *) m)->type));
#endif
  ntm = (struct NotifyTrafficMessage *) buf;
  ntm->header.size = htons (size);
  ntm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_INBOUND);
  ntm->ats_count = htonl (sender->ats_count);
  ntm->peer = sender->peer;
  ats = &ntm->ats;
  memcpy (ats, sender->ats,
          sizeof (struct GNUNET_TRANSPORT_ATS_Information) * sender->ats_count);
  ats[sender->ats_count].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
  ats[sender->ats_count].value = htonl (0);
  memcpy (&ats[sender->ats_count + 1], m, msize);
  send_to_client (client, &ntm->header, GNUNET_YES);
}




/**
 * Deliver P2P message to interested clients.
 *
 * @param cls always NULL
 * @param client who sent us the message (struct Neighbour)
 * @param m the message
 */
static void
deliver_message (void *cls, void *client, const struct GNUNET_MessageHeader *m)
{
  struct Neighbour *sender = client;
  size_t msize = ntohs (m->size);
  char buf[256];
  struct Client *cpos;
  uint16_t type;
  unsigned int tpos;
  int deliver_full;
  int dropped;

  GNUNET_break (sender->status == PEER_STATE_KEY_CONFIRMED);
  type = ntohs (m->type);
#if DEBUG_CORE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received encapsulated message of type %u and size %u from `%4s'\n",
              (unsigned int) type, ntohs (m->size), GNUNET_i2s (&sender->peer));
#endif
  GNUNET_snprintf (buf, sizeof (buf),
                   gettext_noop ("# bytes of messages of type %u received"),
                   (unsigned int) type);
  GNUNET_STATISTICS_update (stats, buf, msize, GNUNET_NO);
  if ((GNUNET_MESSAGE_TYPE_CORE_BINARY_TYPE_MAP == type) ||
      (GNUNET_MESSAGE_TYPE_CORE_COMPRESSED_TYPE_MAP == type))
  {
    /* FIXME: update message type map for 'Neighbour' */
    return;
  }
  dropped = GNUNET_YES;
  cpos = clients;
  while (cpos != NULL)
  {
    deliver_full = GNUNET_NO;
    if (0 != (cpos->options & GNUNET_CORE_OPTION_SEND_FULL_INBOUND))
      deliver_full = GNUNET_YES;
    else
    {
      for (tpos = 0; tpos < cpos->tcnt; tpos++)
      {
        if (type != cpos->types[tpos])
          continue;
        deliver_full = GNUNET_YES;
        break;
      }
    }
    if (GNUNET_YES == deliver_full)
    {
      send_p2p_message_to_client (sender, cpos, m, msize);
      dropped = GNUNET_NO;
    }
    else if (cpos->options & GNUNET_CORE_OPTION_SEND_HDR_INBOUND)
    {
      send_p2p_message_to_client (sender, cpos, m,
                                  sizeof (struct GNUNET_MessageHeader));
    }
    cpos = cpos->next;
  }
  if (dropped == GNUNET_YES)
  {
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Message of type %u from `%4s' not delivered to any client.\n",
                (unsigned int) type, GNUNET_i2s (&sender->peer));
#endif
    GNUNET_STATISTICS_update (stats,
                              gettext_noop
                              ("# messages not delivered to any client"), 1,
                              GNUNET_NO);
  }
}



void
GSC_CLIENTS_init (struct GNUNET_SERVER_Handle *server)
{
  static const struct GNUNET_SERVER_MessageHandler handlers[] = {
    {&handle_client_init, NULL,
     GNUNET_MESSAGE_TYPE_CORE_INIT, 0},
    {&handle_client_iterate_peers, NULL,
     GNUNET_MESSAGE_TYPE_CORE_ITERATE_PEERS,
     sizeof (struct GNUNET_MessageHeader)},
    {&handle_client_have_peer, NULL,
     GNUNET_MESSAGE_TYPE_CORE_PEER_CONNECTED,
     sizeof (struct GNUNET_MessageHeader) +
     sizeof (struct GNUNET_PeerIdentity)},
    {&handle_client_request_info, NULL,
     GNUNET_MESSAGE_TYPE_CORE_REQUEST_INFO,
     sizeof (struct RequestInfoMessage)},
    {&handle_client_send_request, NULL,
     GNUNET_MESSAGE_TYPE_CORE_SEND_REQUEST,
     sizeof (struct SendMessageRequest)},
    {&handle_client_send, NULL,
     GNUNET_MESSAGE_TYPE_CORE_SEND, 0},
    {&handle_client_request_connect, NULL,
     GNUNET_MESSAGE_TYPE_CORE_REQUEST_CONNECT,
     sizeof (struct ConnectMessage)},
    {NULL, NULL, 0, 0}
  };

  /* setup notification */
  notifier =
      GNUNET_SERVER_notification_context_create (server, MAX_NOTIFY_QUEUE);
  GNUNET_SERVER_disconnect_notify (server, &handle_client_disconnect, NULL);
  GNUNET_SERVER_add_handlers (server, handlers);
  mst = GNUNET_SERVER_mst_create (&deliver_message, NULL);
}


void
GSC_CLIENTS_done ()
{
  struct Client *c;

  while (NULL != (c = clients))
    handle_client_disconnect (NULL, c->client_handle);
  GNUNET_SERVER_notification_context_destroy (notifier);
  notifier = NULL;
  if (mst != NULL)
    {
      GNUNET_SERVER_mst_destroy (mst);
      mst = NULL;
    }

}
