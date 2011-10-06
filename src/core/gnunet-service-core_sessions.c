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
 * @file core/gnunet-service-core_neighbours.c
 * @brief code for managing of 'encrypted' sessions (key exchange done) 
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_service_core.h"
#include "gnunet_service_core_neighbours.h"
#include "gnunet_service_core_kx.h"
#include "gnunet_service_core_sessions.h"

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
  GSC_CLIENTS_solicite_request (car);
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
  GSC_KX_encrypt_and_transmit (n->kx,
			       &pbuf[struct EncryptedMessage],
			       used - sizeof (struct EncryptedMessage));
  schedule_peer_messages (n);
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



/**
 * We have a new client, notify it about all current sessions.
 *
 * @param client the new client
 */
void
GSC_SESSIONS_notify_client_about_sessions (struct GSC_Client *client)
{
  /* notify new client about existing neighbours */
  GNUNET_CONTAINER_multihashmap_iterate (neighbours,
					 &notify_client_about_neighbour, client);
}


/**
 * Queue a request from a client for transmission to a particular peer.
 *
 * @param car request to queue; this handle is then shared between
 *         the caller (CLIENTS subsystem) and SESSIONS and must not
 *         be released by either until either 'GNUNET_SESSIONS_dequeue',
 *         'GNUNET_SESSIONS_transmit' or 'GNUNET_CLIENTS_failed'
 *         have been invoked on it
 */
void
GSC_SESSIONS_queue_request (struct GSC_ClientActiveRequest *car)
{
  struct Neighbour *n; // FIXME: session...

  n = find_neighbour (&car->peer);
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
    GSC_CLIENTS_reject_requests (car);
    return;
  }
#if DEBUG_CORE_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received client transmission request. queueing\n");
#endif
    GNUNET_CONTAINER_DLL_insert (n->active_client_request_head,
                                 n->active_client_request_tail, car);

  // schedule_peer_messages (n);
}


/**
 * Dequeue a request from a client from transmission to a particular peer.
 *
 * @param car request to dequeue; this handle will then be 'owned' by
 *        the caller (CLIENTS sysbsystem)
 */
void
GSC_SESSIONS_dequeue_request (struct GSC_ClientActiveRequest *car)
{
  struct Session *s;

  s = find_session (&car->peer);
  GNUNET_CONTAINER_DLL_remove (s->active_client_request_head,
                               s->active_client_request_tail, car);
}



/**
 * Transmit a message to a particular peer.
 *
 * @param car original request that was queued and then solicited;
 *            this handle will now be 'owned' by the SESSIONS subsystem
 * @param msg message to transmit
 */
void
GSC_SESSIONS_transmit (struct GSC_ClientActiveRequest *car,
		       const struct GNUNET_MessageHeader *msg)
{
  struct MessageEntry *prev;
  struct MessageEntry *pos;
  struct MessageEntry *e;
  struct MessageEntry *min_prio_entry;
  struct MessageEntry *min_prio_prev;
  unsigned int min_prio;
  unsigned int queue_size;

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

}




/**
 * Helper function for GSC_SESSIONS_handle_client_iterate_peers.
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
void
GSC_SESSIONS_handle_client_iterate_peers (void *cls, struct GNUNET_SERVER_Client *client,
					  const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MessageHeader done_msg;
  struct GNUNET_SERVER_TransmitContext *tc;

  tc = GNUNET_SERVER_transmit_context_create (client);
  GNUNET_CONTAINER_multihashmap_iterate (neighbours, &queue_connect_message,
					 tc);
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
void
GSC_SESSIONS_handle_client_have_peer (void *cls, struct GNUNET_SERVER_Client *client,
				      const struct GNUNET_MessageHeader *message)
{
  struct GNUNET_MessageHeader done_msg;
  struct GNUNET_SERVER_TransmitContext *tc;
  const struct GNUNET_PeerIdentity *peer;

  peer = (const struct GNUNET_PeerIdentity *) &message[1]; // YUCK!
  tc = GNUNET_SERVER_transmit_context_create (client);
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
void
GSC_SESSIONS_handle_client_request_info (void *cls, struct GNUNET_SERVER_Client *client,
					 const struct GNUNET_MessageHeader *message)
{
  const struct RequestInfoMessage *rcm;
  struct GSC_Client *pos;
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
  GSC_CLIENTS_send_to_client (client, &cim.header, GNUNET_NO);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
