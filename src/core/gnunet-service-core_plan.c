


/**
 * Select messages for transmission.  This heuristic uses a combination
 * of earliest deadline first (EDF) scheduling (with bounded horizon)
 * and priority-based discard (in case no feasible schedule exist) and
 * speculative optimization (defer any kind of transmission until
 * we either create a batch of significant size, 25% of max, or until
 * we are close to a deadline).  Furthermore, when scheduling the
 * heuristic also packs as many messages into the batch as possible,
 * starting with those with the earliest deadline.  Yes, this is fun.
 *
 * @param n neighbour to select messages from
 * @param size number of bytes to select for transmission
 * @param retry_time set to the time when we should try again
 *        (only valid if this function returns zero)
 * @return number of bytes selected, or 0 if we decided to
 *         defer scheduling overall; in that case, retry_time is set.
 */
static size_t
select_messages (struct Neighbour *n, size_t size,
                 struct GNUNET_TIME_Relative *retry_time)
{
  struct MessageEntry *pos;
  struct MessageEntry *min;
  struct MessageEntry *last;
  unsigned int min_prio;
  struct GNUNET_TIME_Absolute t;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Relative delta;
  uint64_t avail;
  struct GNUNET_TIME_Relative slack;    /* how long could we wait before missing deadlines? */
  size_t off;
  uint64_t tsize;
  unsigned int queue_size;
  int discard_low_prio;

  GNUNET_assert (NULL != n->messages);
  now = GNUNET_TIME_absolute_get ();
  /* last entry in linked list of messages processed */
  last = NULL;
  /* should we remove the entry with the lowest
   * priority from consideration for scheduling at the
   * end of the loop? */
  queue_size = 0;
  tsize = 0;
  pos = n->messages;
  while (pos != NULL)
  {
    queue_size++;
    tsize += pos->size;
    pos = pos->next;
  }
  discard_low_prio = GNUNET_YES;
  while (GNUNET_YES == discard_low_prio)
  {
    min = NULL;
    min_prio = UINT_MAX;
    discard_low_prio = GNUNET_NO;
    /* calculate number of bytes available for transmission at time "t" */
    avail = GNUNET_BANDWIDTH_tracker_get_available (&n->available_send_window);
    t = now;
    /* how many bytes have we (hypothetically) scheduled so far */
    off = 0;
    /* maximum time we can wait before transmitting anything
     * and still make all of our deadlines */
    slack = GNUNET_TIME_UNIT_FOREVER_REL;
    pos = n->messages;
    /* note that we use "*2" here because we want to look
     * a bit further into the future; much more makes no
     * sense since new message might be scheduled in the
     * meantime... */
    while ((pos != NULL) && (off < size * 2))
    {
      if (pos->do_transmit == GNUNET_YES)
      {
        /* already removed from consideration */
        pos = pos->next;
        continue;
      }
      if (discard_low_prio == GNUNET_NO)
      {
        delta = GNUNET_TIME_absolute_get_difference (t, pos->deadline);
        if (delta.rel_value > 0)
        {
          // FIXME: HUH? Check!
          t = pos->deadline;
          avail +=
              GNUNET_BANDWIDTH_value_get_available_until (n->bw_out, delta);
        }
        if (avail < pos->size)
        {
          // FIXME: HUH? Check!
          discard_low_prio = GNUNET_YES;        /* we could not schedule this one! */
        }
        else
        {
          avail -= pos->size;
          /* update slack, considering both its absolute deadline
           * and relative deadlines caused by other messages
           * with their respective load */
          slack =
              GNUNET_TIME_relative_min (slack,
                                        GNUNET_BANDWIDTH_value_get_delay_for
                                        (n->bw_out, avail));
          if (pos->deadline.abs_value <= now.abs_value)
          {
            /* now or never */
            slack = GNUNET_TIME_UNIT_ZERO;
          }
          else if (GNUNET_YES == pos->got_slack)
          {
            /* should be soon now! */
            slack =
                GNUNET_TIME_relative_min (slack,
                                          GNUNET_TIME_absolute_get_remaining
                                          (pos->slack_deadline));
          }
          else
          {
            slack =
                GNUNET_TIME_relative_min (slack,
                                          GNUNET_TIME_absolute_get_difference
                                          (now, pos->deadline));
            pos->got_slack = GNUNET_YES;
            pos->slack_deadline =
                GNUNET_TIME_absolute_min (pos->deadline,
                                          GNUNET_TIME_relative_to_absolute
                                          (GNUNET_CONSTANTS_MAX_CORK_DELAY));
          }
        }
      }
      off += pos->size;
      t = GNUNET_TIME_absolute_max (pos->deadline, t);  // HUH? Check!
      if (pos->priority <= min_prio)
      {
        /* update min for discard */
        min_prio = pos->priority;
        min = pos;
      }
      pos = pos->next;
    }
    if (discard_low_prio)
    {
      GNUNET_assert (min != NULL);
      /* remove lowest-priority entry from consideration */
      min->do_transmit = GNUNET_YES;    /* means: discard (for now) */
    }
    last = pos;
  }
  /* guard against sending "tiny" messages with large headers without
   * urgent deadlines */
  if ((slack.rel_value > GNUNET_CONSTANTS_MAX_CORK_DELAY.rel_value) &&
      (size > 4 * off) && (queue_size <= MAX_PEER_QUEUE_SIZE - 2))
  {
    /* less than 25% of message would be filled with deadlines still
     * being met if we delay by one second or more; so just wait for
     * more data; but do not wait longer than 1s (since we don't want
     * to delay messages for a really long time either). */
    *retry_time = GNUNET_CONSTANTS_MAX_CORK_DELAY;
    /* reset do_transmit values for next time */
    while (pos != last)
    {
      pos->do_transmit = GNUNET_NO;
      pos = pos->next;
    }
    GNUNET_STATISTICS_update (stats,
                              gettext_noop
                              ("# transmissions delayed due to corking"), 1,
                              GNUNET_NO);
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Deferring transmission for %llums due to underfull message buffer size (%u/%u)\n",
                (unsigned long long) retry_time->rel_value, (unsigned int) off,
                (unsigned int) size);
#endif
    return 0;
  }
  /* select marked messages (up to size) for transmission */
  off = 0;
  pos = n->messages;
  while (pos != last)
  {
    if ((pos->size <= size) && (pos->do_transmit == GNUNET_NO))
    {
      pos->do_transmit = GNUNET_YES;    /* mark for transmission */
      off += pos->size;
      size -= pos->size;
#if DEBUG_CORE > 1
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Selecting message of size %u for transmission\n",
                  (unsigned int) pos->size);
#endif
    }
    else
    {
#if DEBUG_CORE > 1
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Not selecting message of size %u for transmission at this time (maximum is %u)\n",
                  (unsigned int) pos->size, size);
#endif
      pos->do_transmit = GNUNET_NO;     /* mark for not transmitting! */
    }
    pos = pos->next;
  }
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Selected %llu/%llu bytes of %u/%u plaintext messages for transmission to `%4s'.\n",
              (unsigned long long) off, (unsigned long long) tsize, queue_size,
              (unsigned int) MAX_PEER_QUEUE_SIZE, GNUNET_i2s (&n->peer));
#endif
  return off;
}


/**
 * Batch multiple messages into a larger buffer.
 *
 * @param n neighbour to take messages from
 * @param buf target buffer
 * @param size size of buf
 * @param deadline set to transmission deadline for the result
 * @param retry_time set to the time when we should try again
 *        (only valid if this function returns zero)
 * @param priority set to the priority of the batch
 * @return number of bytes written to buf (can be zero)
 */
static size_t
batch_message (struct Neighbour *n, char *buf, size_t size,
               struct GNUNET_TIME_Absolute *deadline,
               struct GNUNET_TIME_Relative *retry_time, unsigned int *priority)
{
  char ntmb[GNUNET_SERVER_MAX_MESSAGE_SIZE - 1];
  struct NotifyTrafficMessage *ntm = (struct NotifyTrafficMessage *) ntmb;
  struct MessageEntry *pos;
  struct MessageEntry *prev;
  struct MessageEntry *next;
  size_t ret;

  ret = 0;
  *priority = 0;
  *deadline = GNUNET_TIME_UNIT_FOREVER_ABS;
  *retry_time = GNUNET_TIME_UNIT_FOREVER_REL;
  if (0 == select_messages (n, size, retry_time))
  {
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No messages selected, will try again in %llu ms\n",
                retry_time->rel_value);
#endif
    return 0;
  }
  ntm->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_OUTBOUND);
  ntm->ats_count = htonl (0);
  ntm->ats.type = htonl (0);
  ntm->ats.value = htonl (0);
  ntm->peer = n->peer;
  pos = n->messages;
  prev = NULL;
  while ((pos != NULL) && (size >= sizeof (struct GNUNET_MessageHeader)))
  {
    next = pos->next;
    if (GNUNET_YES == pos->do_transmit)
    {
      GNUNET_assert (pos->size <= size);
      /* do notifications */
      /* FIXME: track if we have *any* client that wants
       * full notifications and only do this if that is
       * actually true */
      if (pos->size <
          GNUNET_SERVER_MAX_MESSAGE_SIZE - sizeof (struct NotifyTrafficMessage))
      {
        memcpy (&ntm[1], &pos[1], pos->size);
        ntm->header.size =
            htons (sizeof (struct NotifyTrafficMessage) +
                   sizeof (struct GNUNET_MessageHeader));
        send_to_all_clients (&ntm->header, GNUNET_YES,
                             GNUNET_CORE_OPTION_SEND_HDR_OUTBOUND);
      }
      else
      {
        /* message too large for 'full' notifications, we do at
         * least the 'hdr' type */
        memcpy (&ntm[1], &pos[1], sizeof (struct GNUNET_MessageHeader));
      }
      ntm->header.size =
          htons (sizeof (struct NotifyTrafficMessage) + pos->size);
      send_to_all_clients (&ntm->header, GNUNET_YES,
                           GNUNET_CORE_OPTION_SEND_FULL_OUTBOUND);
#if DEBUG_HANDSHAKE
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Encrypting %u bytes with message of type %u and size %u\n",
                  pos->size,
                  (unsigned int)
                  ntohs (((const struct GNUNET_MessageHeader *) &pos[1])->type),
                  (unsigned int)
                  ntohs (((const struct GNUNET_MessageHeader *)
                          &pos[1])->size));
#endif
      /* copy for encrypted transmission */
      memcpy (&buf[ret], &pos[1], pos->size);
      ret += pos->size;
      size -= pos->size;
      *priority += pos->priority;
#if DEBUG_CORE > 1
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Adding plaintext message of size %u with deadline %llu ms to batch\n",
                  (unsigned int) pos->size,
                  (unsigned long long)
                  GNUNET_TIME_absolute_get_remaining (pos->deadline).rel_value);
#endif
      deadline->abs_value =
          GNUNET_MIN (deadline->abs_value, pos->deadline.abs_value);
      GNUNET_free (pos);
      if (prev == NULL)
        n->messages = next;
      else
        prev->next = next;
    }
    else
    {
      prev = pos;
    }
    pos = next;
  }
#if DEBUG_CORE > 1
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Deadline for message batch is %llu ms\n",
              GNUNET_TIME_absolute_get_remaining (*deadline).rel_value);
#endif
  return ret;
}


/**
 * Remove messages with deadlines that have long expired from
 * the queue.
 *
 * @param n neighbour to inspect
 */
static void
discard_expired_messages (struct Neighbour *n)
{
  struct MessageEntry *prev;
  struct MessageEntry *next;
  struct MessageEntry *pos;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Relative delta;
  int disc;
  unsigned int queue_length;

  disc = GNUNET_NO;
  now = GNUNET_TIME_absolute_get ();
  prev = NULL;
  queue_length = 0;
  pos = n->messages;
  while (pos != NULL)
  {
    queue_length++;
    next = pos->next;
    delta = GNUNET_TIME_absolute_get_difference (pos->deadline, now);
    if (delta.rel_value > PAST_EXPIRATION_DISCARD_TIME.rel_value)
    {
#if DEBUG_CORE
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  "Message is %llu ms past due, discarding.\n",
                  delta.rel_value);
#endif
      if (prev == NULL)
        n->messages = next;
      else
        prev->next = next;
      GNUNET_STATISTICS_update (stats,
                                gettext_noop
                                ("# messages discarded (expired prior to transmission)"),
                                1, GNUNET_NO);
      disc = GNUNET_YES;
      GNUNET_free (pos);
    }
    else
      prev = pos;
    pos = next;
  }
  if ( (GNUNET_YES == disc) &&
       (queue_length == MAX_PEER_QUEUE_SIZE) )
    schedule_peer_messages (n);
}


/**
 * Signature of the main function of a task.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
static void
retry_plaintext_processing (void *cls,
                            const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Neighbour *n = cls;

  n->retry_plaintext_task = GNUNET_SCHEDULER_NO_TASK;
  process_plaintext_neighbour_queue (n);
}


/**
 * Check if we have plaintext messages for the specified neighbour
 * pending, and if so, consider batching and encrypting them (and
 * then trigger processing of the encrypted queue if needed).
 *
 * @param n neighbour to check.
 */
static void
process_plaintext_neighbour_queue (struct Neighbour *n)
{
  char pbuf[GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE + sizeof (struct EncryptedMessage)];    /* plaintext */
  size_t used;
  struct EncryptedMessage *em;  /* encrypted message */
  struct EncryptedMessage *ph;  /* plaintext header */
  struct MessageEntry *me;
  unsigned int priority;
  struct GNUNET_TIME_Absolute deadline;
  struct GNUNET_TIME_Relative retry_time;
  struct GNUNET_CRYPTO_AesInitializationVector iv;
  struct GNUNET_CRYPTO_AuthKey auth_key;

  if (n->retry_plaintext_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (n->retry_plaintext_task);
    n->retry_plaintext_task = GNUNET_SCHEDULER_NO_TASK;
  }
  switch (n->status)
  {
  case PEER_STATE_DOWN:
    send_key (n);
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Not yet connected to `%4s', deferring processing of plaintext messages.\n",
                GNUNET_i2s (&n->peer));
#endif
    return;
  case PEER_STATE_KEY_SENT:
    if (n->retry_set_key_task == GNUNET_SCHEDULER_NO_TASK)
      n->retry_set_key_task =
          GNUNET_SCHEDULER_add_delayed (n->set_key_retry_frequency,
                                        &set_key_retry_task, n);
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Not yet connected to `%4s', deferring processing of plaintext messages.\n",
                GNUNET_i2s (&n->peer));
#endif
    return;
  case PEER_STATE_KEY_RECEIVED:
    if (n->retry_set_key_task == GNUNET_SCHEDULER_NO_TASK)
      n->retry_set_key_task =
          GNUNET_SCHEDULER_add_delayed (n->set_key_retry_frequency,
                                        &set_key_retry_task, n);
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Not yet connected to `%4s', deferring processing of plaintext messages.\n",
                GNUNET_i2s (&n->peer));
#endif
    return;
  case PEER_STATE_KEY_CONFIRMED:
    /* ready to continue */
    break;
  }
  discard_expired_messages (n);
  if (n->messages == NULL)
  {
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Plaintext message queue for `%4s' is empty.\n",
                GNUNET_i2s (&n->peer));
#endif
    return;                     /* no pending messages */
  }
  if (n->encrypted_head != NULL)
  {
#if DEBUG_CORE > 2
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Encrypted message queue for `%4s' is still full, delaying plaintext processing.\n",
                GNUNET_i2s (&n->peer));
#endif
    return;                     /* wait for messages already encrypted to be
                                 * processed first! */
  }
  ph = (struct EncryptedMessage *) pbuf;
  deadline = GNUNET_TIME_UNIT_FOREVER_ABS;
  priority = 0;
  used = sizeof (struct EncryptedMessage);
  used +=
      batch_message (n, &pbuf[used],
                     GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE, &deadline,
                     &retry_time, &priority);
  if (used == sizeof (struct EncryptedMessage))
  {
#if DEBUG_CORE > 1
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No messages selected for transmission to `%4s' at this time, will try again later.\n",
                GNUNET_i2s (&n->peer));
#endif
    /* no messages selected for sending, try again later... */
    n->retry_plaintext_task =
        GNUNET_SCHEDULER_add_delayed (retry_time, &retry_plaintext_processing,
                                      n);
    return;
  }
#if DEBUG_CORE_QUOTA
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sending %u b/s as new limit to peer `%4s'\n",
              (unsigned int) ntohl (n->bw_in.value__), GNUNET_i2s (&n->peer));
#endif
  ph->iv_seed =
      htonl (GNUNET_CRYPTO_random_u32
             (GNUNET_CRYPTO_QUALITY_NONCE, UINT32_MAX));
  ph->sequence_number = htonl (++n->last_sequence_number_sent);
  ph->inbound_bw_limit = n->bw_in;
  ph->timestamp = GNUNET_TIME_absolute_hton (GNUNET_TIME_absolute_get ());

  /* setup encryption message header */
  me = GNUNET_malloc (sizeof (struct MessageEntry) + used);
  me->deadline = deadline;
  me->priority = priority;
  me->size = used;
  em = (struct EncryptedMessage *) &me[1];
  em->header.size = htons (used);
  em->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_ENCRYPTED_MESSAGE);
  em->iv_seed = ph->iv_seed;
  derive_iv (&iv, &n->encrypt_key, ph->iv_seed, &n->peer);
  /* encrypt */
#if DEBUG_HANDSHAKE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Encrypting %u bytes of plaintext messages for `%4s' for transmission in %llums.\n",
              (unsigned int) used - ENCRYPTED_HEADER_SIZE,
              GNUNET_i2s (&n->peer),
              (unsigned long long)
              GNUNET_TIME_absolute_get_remaining (deadline).rel_value);
#endif
  GNUNET_assert (GNUNET_OK ==
                 do_encrypt (n, &iv, &ph->sequence_number, &em->sequence_number,
                             used - ENCRYPTED_HEADER_SIZE));
  derive_auth_key (&auth_key, &n->encrypt_key, ph->iv_seed,
                   n->encrypt_key_created);
  GNUNET_CRYPTO_hmac (&auth_key, &em->sequence_number,
                      used - ENCRYPTED_HEADER_SIZE, &em->hmac);
#if DEBUG_HANDSHAKE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Authenticated %u bytes of ciphertext %u: `%s'\n",
              used - ENCRYPTED_HEADER_SIZE,
              GNUNET_CRYPTO_crc32_n (&em->sequence_number,
                                     used - ENCRYPTED_HEADER_SIZE),
              GNUNET_h2s (&em->hmac));
#endif
  /* append to transmission list */
  GNUNET_CONTAINER_DLL_insert_after (n->encrypted_head, n->encrypted_tail,
                                     n->encrypted_tail, me);
  process_encrypted_neighbour_queue (n);
  schedule_peer_messages (n);
}

