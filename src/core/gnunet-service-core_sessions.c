/*
     This file is part of GNUnet.
     Copyright (C) 2009-2014 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file core/gnunet-service-core_sessions.c
 * @brief code for managing of 'encrypted' sessions (key exchange done)
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-core.h"
#include "gnunet-service-core_neighbours.h"
#include "gnunet-service-core_kx.h"
#include "gnunet-service-core_typemap.h"
#include "gnunet-service-core_sessions.h"
#include "gnunet-service-core_clients.h"
#include "gnunet_constants.h"
#include "core.h"


/**
 * How many encrypted messages do we queue at most?
 * Needed to bound memory consumption.
 */
#define MAX_ENCRYPTED_MESSAGE_QUEUE_SIZE 4


/**
 * Message ready for encryption.  This struct is followed by the
 * actual content of the message.
 */
struct SessionMessageEntry
{

  /**
   * We keep messages in a doubly linked list.
   */
  struct SessionMessageEntry *next;

  /**
   * We keep messages in a doubly linked list.
   */
  struct SessionMessageEntry *prev;

  /**
   * Deadline for transmission, 1s after we received it (if we
   * are not corking), otherwise "now".  Note that this message
   * does NOT expire past its deadline.
   */
  struct GNUNET_TIME_Absolute deadline;

  /**
   * How long is the message? (number of bytes following the `struct
   * MessageEntry`, but not including the size of `struct
   * MessageEntry` itself!)
   */
  size_t size;

  /**
   * How important is this message.
   */
  enum GNUNET_CORE_Priority priority;

};


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
  struct GSC_ClientActiveRequest *active_client_request_head;

  /**
   * Tail of list of requests from clients for transmission to
   * this peer.
   */
  struct GSC_ClientActiveRequest *active_client_request_tail;

  /**
   * Head of list of messages ready for encryption.
   */
  struct SessionMessageEntry *sme_head;

  /**
   * Tail of list of messages ready for encryption.
   */
  struct SessionMessageEntry *sme_tail;

  /**
   * Information about the key exchange with the other peer.
   */
  struct GSC_KeyExchangeInfo *kxinfo;

  /**
   * Current type map for this peer.
   */
  struct GSC_TypeMap *tmap;

  /**
   * Task to transmit corked messages with a delay.
   */
  struct GNUNET_SCHEDULER_Task *cork_task;

  /**
   * Task to transmit our type map.
   */
  struct GNUNET_SCHEDULER_Task *typemap_task;

  /**
   * Retransmission delay we currently use for the typemap
   * transmissions (if not confirmed).
   */
  struct GNUNET_TIME_Relative typemap_delay;

  /**
   * Is the neighbour queue empty and thus ready for us
   * to transmit an encrypted message?
   */
  int ready_to_transmit;

  /**
   * Is this the first time we're sending the typemap? If so,
   * we want to send it a bit faster the second time.  0 if
   * we are sending for the first time, 1 if not.
   */
  int first_typemap;
};


GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Message sent to confirm that a typemap was received.
 */
struct TypeMapConfirmationMessage
{

  /**
   * Header with type #GNUNET_MESSAGE_TYPE_CORE_CONFIRM_TYPE_MAP.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Reserved, always zero.
   */
  uint32_t reserved GNUNET_PACKED;

  /**
   * Hash of the (decompressed) type map that was received.
   */
  struct GNUNET_HashCode tm_hash;

};

GNUNET_NETWORK_STRUCT_END


/**
 * Map of peer identities to `struct Session`.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *sessions;


/**
 * Find the session for the given peer.
 *
 * @param peer identity of the peer
 * @return NULL if we are not connected, otherwise the
 *         session handle
 */
static struct Session *
find_session (const struct GNUNET_PeerIdentity *peer)
{
  return GNUNET_CONTAINER_multipeermap_get (sessions, peer);
}


/**
 * End the session with the given peer (we are no longer
 * connected).
 *
 * @param pid identity of peer to kill session with
 */
void
GSC_SESSIONS_end (const struct GNUNET_PeerIdentity *pid)
{
  struct Session *session;
  struct GSC_ClientActiveRequest *car;
  struct SessionMessageEntry *sme;

  session = find_session (pid);
  if (NULL == session)
    return;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Destroying session for peer `%4s'\n",
              GNUNET_i2s (&session->peer));
  if (NULL != session->cork_task)
  {
    GNUNET_SCHEDULER_cancel (session->cork_task);
    session->cork_task = NULL;
  }
  while (NULL != (car = session->active_client_request_head))
  {
    GNUNET_CONTAINER_DLL_remove (session->active_client_request_head,
                                 session->active_client_request_tail, car);
    GSC_CLIENTS_reject_request (car,
                                GNUNET_NO);
  }
  while (NULL != (sme = session->sme_head))
  {
    GNUNET_CONTAINER_DLL_remove (session->sme_head,
                                 session->sme_tail,
                                 sme);
    GNUNET_free (sme);
  }
  if (NULL != session->typemap_task)
  {
    GNUNET_SCHEDULER_cancel (session->typemap_task);
    session->typemap_task = NULL;
  }
  GSC_CLIENTS_notify_clients_about_neighbour (&session->peer,
                                              session->tmap, NULL);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multipeermap_remove (sessions,
                                                       &session->peer,
                                                       session));
  GNUNET_STATISTICS_set (GSC_stats, gettext_noop ("# peers connected"),
                         GNUNET_CONTAINER_multipeermap_size (sessions),
                         GNUNET_NO);
  GSC_TYPEMAP_destroy (session->tmap);
  session->tmap = NULL;
  GNUNET_free (session);
}


/**
 * Transmit our current typemap message to the other peer.
 * (Done periodically until the typemap is confirmed).
 *
 * @param cls the `struct Session *`
 * @param tc unused
 */
static void
transmit_typemap_task (void *cls,
                       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Session *session = cls;
  struct GNUNET_MessageHeader *hdr;
  struct GNUNET_TIME_Relative delay;

  session->typemap_delay = GNUNET_TIME_STD_BACKOFF (session->typemap_delay);
  delay = session->typemap_delay;
  /* randomize a bit to avoid spont. sync */
  delay.rel_value_us +=
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 1000 * 1000);
  session->typemap_task =
      GNUNET_SCHEDULER_add_delayed (delay,
                                    &transmit_typemap_task, session);
  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop ("# type map refreshes sent"),
                            1,
                            GNUNET_NO);
  hdr = GSC_TYPEMAP_compute_type_map_message ();
  GSC_KX_encrypt_and_transmit (session->kxinfo,
                               hdr,
                               ntohs (hdr->size));
  GNUNET_free (hdr);
}


/**
 * Restart the typemap task for the given session.
 *
 * @param session session to restart typemap transmission for
 */
static void
start_typemap_task (struct Session *session)
{
  if (NULL != session->typemap_task)
    GNUNET_SCHEDULER_cancel (session->typemap_task);
  session->typemap_delay = GNUNET_TIME_UNIT_SECONDS;
  session->typemap_task =
    GNUNET_SCHEDULER_add_delayed (session->typemap_delay,
                                  &transmit_typemap_task,
                                  session);
}


/**
 * Create a session, a key exchange was just completed.
 *
 * @param peer peer that is now connected
 * @param kx key exchange that completed
 */
void
GSC_SESSIONS_create (const struct GNUNET_PeerIdentity *peer,
                     struct GSC_KeyExchangeInfo *kx)
{
  struct Session *session;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Creating session for peer `%4s'\n",
              GNUNET_i2s (peer));
  session = GNUNET_new (struct Session);
  session->tmap = GSC_TYPEMAP_create ();
  session->peer = *peer;
  session->kxinfo = kx;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_put (sessions,
                                                    &session->peer,
                                                    session,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  GNUNET_STATISTICS_set (GSC_stats, gettext_noop ("# peers connected"),
                         GNUNET_CONTAINER_multipeermap_size (sessions),
                         GNUNET_NO);
  GSC_CLIENTS_notify_clients_about_neighbour (peer,
                                              NULL,
                                              session->tmap);
  start_typemap_task (session);
}


/**
 * The other peer has indicated that he 'lost' the session
 * (KX down), reinitialize the session on our end, in particular
 * this means to restart the typemap transmission.
 *
 * @param peer peer that is now connected
 */
void
GSC_SESSIONS_reinit (const struct GNUNET_PeerIdentity *peer)
{
  struct Session *session;

  session = find_session (peer);
  if (NULL == session)
  {
    /* KX/session is new for both sides; thus no need to restart what
       has not yet begun */
    return;
  }
  start_typemap_task (session);
}


/**
 * The other peer has confirmed receiving our type map,
 * check if it is current and if so, stop retransmitting it.
 *
 * @param peer peer that confirmed the type map
 * @param msg confirmation message we received
 */
void
GSC_SESSIONS_confirm_typemap (const struct GNUNET_PeerIdentity *peer,
                              const struct GNUNET_MessageHeader *msg)
{
  const struct TypeMapConfirmationMessage *cmsg;
  struct Session *session;

  session = find_session (peer);
  if (NULL == session)
  {
    GNUNET_break (0);
    return;
  }
  if (ntohs (msg->size) != sizeof (struct TypeMapConfirmationMessage))
  {
    GNUNET_break_op (0);
    return;
  }
  cmsg = (const struct TypeMapConfirmationMessage *) msg;
  if (GNUNET_YES !=
      GSC_TYPEMAP_check_hash (&cmsg->tm_hash))
  {
    /* our typemap has changed in the meantime, do not
       accept confirmation */
    GNUNET_STATISTICS_update (GSC_stats,
                              gettext_noop
                              ("# outdated typemap confirmations received"),
                              1, GNUNET_NO);
    return;
  }
  if (NULL != session->typemap_task)
  {
    GNUNET_SCHEDULER_cancel (session->typemap_task);
    session->typemap_task = NULL;
  }
  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop
                            ("# valid typemap confirmations received"),
                            1, GNUNET_NO);
}


/**
 * Notify the given client about the session (client is new).
 *
 * @param cls the `struct GSC_Client`
 * @param key peer identity
 * @param value the `struct Session`
 * @return #GNUNET_OK (continue to iterate)
 */
static int
notify_client_about_session (void *cls,
                             const struct GNUNET_PeerIdentity *key,
                             void *value)
{
  struct GSC_Client *client = cls;
  struct Session *session = value;

  GSC_CLIENTS_notify_client_about_neighbour (client,
                                             &session->peer,
                                             NULL,      /* old TMAP: none */
                                             session->tmap);
  return GNUNET_OK;
}


/**
 * We have a new client, notify it about all current sessions.
 *
 * @param client the new client
 */
void
GSC_SESSIONS_notify_client_about_sessions (struct GSC_Client *client)
{
  /* notify new client about existing sessions */
  GNUNET_CONTAINER_multipeermap_iterate (sessions,
                                         &notify_client_about_session,
                                         client);
}


/**
 * Try to perform a transmission on the given session.  Will solicit
 * additional messages if the 'sme' queue is not full enough.
 *
 * @param session session to transmit messages from
 */
static void
try_transmission (struct Session *session);


/**
 * Queue a request from a client for transmission to a particular peer.
 *
 * @param car request to queue; this handle is then shared between
 *         the caller (CLIENTS subsystem) and SESSIONS and must not
 *         be released by either until either #GSC_SESSIONS_dequeue(),
 *         #GSC_SESSIONS_transmit() or #GSC_CLIENTS_failed()
 *         have been invoked on it
 */
void
GSC_SESSIONS_queue_request (struct GSC_ClientActiveRequest *car)
{
  struct Session *session;

  session = find_session (&car->target);
  if (NULL == session)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Dropped client request for transmission (am disconnected)\n");
    GNUNET_break (0);           /* should have been rejected earlier */
    GSC_CLIENTS_reject_request (car,
                                GNUNET_NO);
    return;
  }
  if (car->msize > GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    GSC_CLIENTS_reject_request (car,
                                GNUNET_YES);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received client transmission request. queueing\n");
  GNUNET_CONTAINER_DLL_insert (session->active_client_request_head,
                               session->active_client_request_tail,
                               car);
  try_transmission (session);
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
  struct Session *session;

  if (0 ==
      memcmp (&car->target,
              &GSC_my_identity,
              sizeof (struct GNUNET_PeerIdentity)))
    return;
  session = find_session (&car->target);
  GNUNET_assert (NULL != session);
  GNUNET_CONTAINER_DLL_remove (session->active_client_request_head,
                               session->active_client_request_tail,
                               car);
  /* dequeueing of 'high' priority messages may unblock
     transmission for lower-priority messages, so we also
     need to try in this case. */
  try_transmission (session);
}


/**
 * Solicit messages for transmission, starting with those of the highest
 * priority.
 *
 * @param session session to solict messages for
 * @param msize how many bytes do we have already
 */
static void
solicit_messages (struct Session *session,
                  size_t msize)
{
  struct GSC_ClientActiveRequest *car;
  struct GSC_ClientActiveRequest *nxt;
  size_t so_size;
  enum GNUNET_CORE_Priority pmax;

  so_size = msize;
  pmax = GNUNET_CORE_PRIO_BACKGROUND;
  for (car = session->active_client_request_head; NULL != car; car = car->next)
  {
    if (GNUNET_YES == car->was_solicited)
      continue;
    pmax = GNUNET_MAX (pmax, car->priority);
  }
  nxt = session->active_client_request_head;
  while (NULL != (car = nxt))
  {
    nxt = car->next;
    if (car->priority < pmax)
      continue;
    if (so_size + car->msize > GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
      break;
    so_size += car->msize;
    if (GNUNET_YES == car->was_solicited)
      continue;
    car->was_solicited = GNUNET_YES;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Soliciting message with priority %u\n",
                car->priority);
    GSC_CLIENTS_solicit_request (car);
  }
}


/**
 * Some messages were delayed (corked), but the timeout has now expired.
 * Send them now.
 *
 * @param cls `struct Session` with the messages to transmit now
 * @param tc scheduler context (unused)
 */
static void
pop_cork_task (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Session *session = cls;

  session->cork_task = NULL;
  try_transmission (session);
}


/**
 * Try to perform a transmission on the given session. Will solicit
 * additional messages if the 'sme' queue is not full enough or has
 * only low-priority messages.
 *
 * @param session session to transmit messages from
 */
static void
try_transmission (struct Session *session)
{
  struct SessionMessageEntry *pos;
  size_t msize;
  struct GNUNET_TIME_Absolute now;
  struct GNUNET_TIME_Absolute min_deadline;
  enum GNUNET_CORE_Priority maxp;
  enum GNUNET_CORE_Priority maxpc;
  struct GSC_ClientActiveRequest *car;
  int excess;

  if (GNUNET_YES != session->ready_to_transmit)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Already ready to transmit, not evaluating queue\n");
    return;
  }
  msize = 0;
  min_deadline = GNUNET_TIME_UNIT_FOREVER_ABS;
  /* if the peer has excess bandwidth, background traffic is allowed,
     otherwise not */
  if (MAX_ENCRYPTED_MESSAGE_QUEUE_SIZE <=
      GSC_NEIGHBOURS_get_queue_size (&session->peer))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Transmission queue already very long, waiting...\n");
    return; /* queue already too long */
  }
  excess = GSC_NEIGHBOURS_check_excess_bandwidth (&session->peer);
  if (GNUNET_YES == excess)
    maxp = GNUNET_CORE_PRIO_BACKGROUND;
  else
    maxp = GNUNET_CORE_PRIO_BEST_EFFORT;
  /* determine highest priority of 'ready' messages we already solicited from clients */
  pos = session->sme_head;
  while ((NULL != pos) &&
         (msize + pos->size <= GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE))
  {
    GNUNET_assert (pos->size < GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE);
    msize += pos->size;
    maxp = GNUNET_MAX (maxp, pos->priority);
    min_deadline = GNUNET_TIME_absolute_min (min_deadline,
                                             pos->deadline);
    pos = pos->next;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Calculating transmission set with %u priority (%s) and %s earliest deadline\n",
              maxp,
              (GNUNET_YES == excess) ? "excess bandwidth" : "limited bandwidth",
              GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_remaining (min_deadline),
                                                      GNUNET_YES));

  if (maxp < GNUNET_CORE_PRIO_CRITICAL_CONTROL)
  {
    /* if highest already solicited priority from clients is not critical,
       check if there are higher-priority messages to be solicited from clients */
    if (GNUNET_YES == excess)
      maxpc = GNUNET_CORE_PRIO_BACKGROUND;
    else
      maxpc = GNUNET_CORE_PRIO_BEST_EFFORT;
    for (car = session->active_client_request_head; NULL != car; car = car->next)
    {
      if (GNUNET_YES == car->was_solicited)
        continue;
      maxpc = GNUNET_MAX (maxpc, car->priority);
    }
    if (maxpc > maxp)
    {
      /* we have messages waiting for solicitation that have a higher
         priority than those that we already accepted; solicit the
         high-priority messages first */
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Soliciting messages based on priority (%u > %u)\n",
                  maxpc,
                  maxp);
      solicit_messages (session, 0);
      return;
    }
  }
  else
  {
    /* never solicit more, we have critical messages to process */
    excess = GNUNET_NO;
    maxpc = GNUNET_CORE_PRIO_BACKGROUND;
  }
  now = GNUNET_TIME_absolute_get ();
  if ( ( (GNUNET_YES == excess) ||
         (maxpc >= GNUNET_CORE_PRIO_BEST_EFFORT) ) &&
       ( (0 == msize) ||
         ( (msize < GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE / 2) &&
           (min_deadline.abs_value_us > now.abs_value_us))) )
  {
    /* not enough ready yet (tiny message & cork possible), or no messages at all,
       and either excess bandwidth or best-effort or higher message waiting at
       client; in this case, we try to solicit more */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Soliciting messages (excess %d, maxpc %d, message size %u, deadline %s)\n",
                excess,
                maxpc,
                msize,
                GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_remaining (min_deadline),
                                                        GNUNET_YES));
    solicit_messages (session,
                      msize);
    if (msize > 0)
    {
      /* if there is data to send, just not yet, make sure we do transmit
       * it once the deadline is reached */
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Corking until %s\n",
                  GNUNET_STRINGS_relative_time_to_string (GNUNET_TIME_absolute_get_remaining (min_deadline),
                                                          GNUNET_YES));
      if (NULL != session->cork_task)
        GNUNET_SCHEDULER_cancel (session->cork_task);
      session->cork_task =
          GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining (min_deadline),
                                        &pop_cork_task,
                                        session);
    }
    else
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                  "Queue empty, waiting for solicitations\n");
    }
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Building combined plaintext buffer to transmit message!\n");
  /* create plaintext buffer of all messages (that fit), encrypt and
     transmit */
  {
    static unsigned long long total_bytes;
    static unsigned int total_msgs;
    char pbuf[msize];           /* plaintext */
    size_t used;

    used = 0;
    while ( (NULL != (pos = session->sme_head)) &&
            (used + pos->size <= msize) )
    {
      memcpy (&pbuf[used], &pos[1], pos->size);
      used += pos->size;
      GNUNET_CONTAINER_DLL_remove (session->sme_head,
                                   session->sme_tail,
                                   pos);
      GNUNET_free (pos);
    }
    /* compute average payload size */
    total_bytes += used;
    total_msgs++;
    if (0 == total_msgs)
    {
      /* 2^32 messages, wrap around... */
      total_msgs = 1;
      total_bytes = used;
    }
    GNUNET_STATISTICS_set (GSC_stats,
                           "# avg payload per encrypted message",
                           total_bytes / total_msgs,
                           GNUNET_NO);
    /* now actually transmit... */
    session->ready_to_transmit = GNUNET_NO;
    GSC_KX_encrypt_and_transmit (session->kxinfo,
                                 pbuf,
                                 used);
  }
}


/**
 * Send an updated typemap message to the neighbour now,
 * and restart typemap transmissions.
 *
 * @param cls the message
 * @param key neighbour's identity
 * @param value `struct Neighbour` of the target
 * @return always #GNUNET_OK
 */
static int
do_restart_typemap_message (void *cls,
                            const struct GNUNET_PeerIdentity *key,
                            void *value)
{
  const struct GNUNET_MessageHeader *hdr = cls;
  struct Session *session = value;
  struct SessionMessageEntry *sme;
  uint16_t size;

  size = ntohs (hdr->size);
  sme = GNUNET_malloc (sizeof (struct SessionMessageEntry) + size);
  memcpy (&sme[1], hdr, size);
  sme->size = size;
  sme->priority = GNUNET_CORE_PRIO_CRITICAL_CONTROL;
  GNUNET_CONTAINER_DLL_insert (session->sme_head,
                               session->sme_tail,
                               sme);
  try_transmission (session);
  start_typemap_task (session);
  return GNUNET_OK;
}


/**
 * Broadcast an updated typemap message to all neighbours.
 * Restarts the retransmissions until the typemaps are confirmed.
 *
 * @param msg message to transmit
 */
void
GSC_SESSIONS_broadcast_typemap (const struct GNUNET_MessageHeader *msg)
{
  if (NULL == sessions)
    return;
  GNUNET_CONTAINER_multipeermap_iterate (sessions,
                                         &do_restart_typemap_message,
                                         (void *) msg);
}


/**
 * Traffic is being solicited for the given peer.  This means that the
 * message queue on the transport-level (NEIGHBOURS subsystem) is now
 * empty and it is now OK to transmit another (non-control) message.
 *
 * @param pid identity of peer ready to receive data
 */
void
GSC_SESSIONS_solicit (const struct GNUNET_PeerIdentity *pid)
{
  struct Session *session;

  session = find_session (pid);
  if (NULL == session)
    return;
  session->ready_to_transmit = GNUNET_YES;
  try_transmission (session);
}


/**
 * Transmit a message to a particular peer.
 *
 * @param car original request that was queued and then solicited;
 *            this handle will now be 'owned' by the SESSIONS subsystem
 * @param msg message to transmit
 * @param cork is corking allowed?
 * @param priority how important is this message
 */
void
GSC_SESSIONS_transmit (struct GSC_ClientActiveRequest *car,
                       const struct GNUNET_MessageHeader *msg,
                       int cork,
                       enum GNUNET_CORE_Priority priority)
{
  struct Session *session;
  struct SessionMessageEntry *sme;
  struct SessionMessageEntry *pos;
  size_t msize;

  session = find_session (&car->target);
  if (NULL == session)
    return;
  msize = ntohs (msg->size);
  sme = GNUNET_malloc (sizeof (struct SessionMessageEntry) + msize);
  memcpy (&sme[1], msg, msize);
  sme->size = msize;
  sme->priority = priority;
  if (GNUNET_YES == cork)
    sme->deadline =
        GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_MAX_CORK_DELAY);
  pos = session->sme_head;
  while ( (NULL != pos) &&
          (pos->priority >= sme->priority) )
    pos = pos->next;
  if (NULL == pos)
    GNUNET_CONTAINER_DLL_insert_tail (session->sme_head,
                                      session->sme_tail,
                                      sme);
  else
    GNUNET_CONTAINER_DLL_insert_after (session->sme_head,
                                       session->sme_tail,
                                       pos->prev,
                                       sme);
  try_transmission (session);
}


/**
 * We have received a typemap message from a peer, update ours.
 * Notifies clients about the session.
 *
 * @param peer peer this is about
 * @param msg typemap update message
 */
void
GSC_SESSIONS_set_typemap (const struct GNUNET_PeerIdentity *peer,
                          const struct GNUNET_MessageHeader *msg)
{
  struct Session *session;
  struct GSC_TypeMap *nmap;
  struct SessionMessageEntry *sme;
  struct TypeMapConfirmationMessage *tmc;

  nmap = GSC_TYPEMAP_get_from_message (msg);
  if (NULL == nmap)
    return;                     /* malformed */
  session = find_session (peer);
  if (NULL == session)
  {
    GNUNET_break (0);
    return;
  }
  sme = GNUNET_malloc (sizeof (struct SessionMessageEntry) +
                       sizeof (struct TypeMapConfirmationMessage));
  sme->deadline = GNUNET_TIME_absolute_get ();
  sme->size = sizeof (struct TypeMapConfirmationMessage);
  sme->priority = GNUNET_CORE_PRIO_CRITICAL_CONTROL;
  tmc = (struct TypeMapConfirmationMessage *) &sme[1];
  tmc->header.size = htons (sizeof (struct TypeMapConfirmationMessage));
  tmc->header.type = htons (GNUNET_MESSAGE_TYPE_CORE_CONFIRM_TYPE_MAP);
  tmc->reserved = htonl (0);
  GSC_TYPEMAP_hash (nmap,
                    &tmc->tm_hash);
  GNUNET_CONTAINER_DLL_insert (session->sme_head,
                               session->sme_tail,
                               sme);
  try_transmission (session);
  GSC_CLIENTS_notify_clients_about_neighbour (peer,
                                              session->tmap,
                                              nmap);
  GSC_TYPEMAP_destroy (session->tmap);
  session->tmap = nmap;
}


/**
 * The given peer send a message of the specified type.  Make sure the
 * respective bit is set in its type-map and that clients are notified
 * about the session.
 *
 * @param peer peer this is about
 * @param type type of the message
 */
void
GSC_SESSIONS_add_to_typemap (const struct GNUNET_PeerIdentity *peer,
                             uint16_t type)
{
  struct Session *session;
  struct GSC_TypeMap *nmap;

  if (0 == memcmp (peer,
                   &GSC_my_identity,
                   sizeof (struct GNUNET_PeerIdentity)))
    return;
  session = find_session (peer);
  GNUNET_assert (NULL != session);
  if (GNUNET_YES == GSC_TYPEMAP_test_match (session->tmap, &type, 1))
    return;                     /* already in it */
  nmap = GSC_TYPEMAP_extend (session->tmap, &type, 1);
  GSC_CLIENTS_notify_clients_about_neighbour (peer,
                                              session->tmap, nmap);
  GSC_TYPEMAP_destroy (session->tmap);
  session->tmap = nmap;
}


/**
 * Initialize sessions subsystem.
 */
void
GSC_SESSIONS_init ()
{
  sessions = GNUNET_CONTAINER_multipeermap_create (128,
                                                   GNUNET_YES);
}


/**
 * Helper function for #GSC_SESSIONS_done() to free all
 * active sessions.
 *
 * @param cls NULL
 * @param key identity of the connected peer
 * @param value the `struct Session` for the peer
 * @return #GNUNET_OK (continue to iterate)
 */
static int
free_session_helper (void *cls,
                     const struct GNUNET_PeerIdentity *key,
                     void *value)
{
  struct Session *session = value;

  GSC_SESSIONS_end (&session->peer);
  return GNUNET_OK;
}


/**
 * Shutdown sessions subsystem.
 */
void
GSC_SESSIONS_done ()
{
  if (NULL != sessions)
  {
    GNUNET_CONTAINER_multipeermap_iterate (sessions,
                                           &free_session_helper, NULL);
    GNUNET_CONTAINER_multipeermap_destroy (sessions);
    sessions = NULL;
  }
}

/* end of gnunet-service-core_sessions.c */
