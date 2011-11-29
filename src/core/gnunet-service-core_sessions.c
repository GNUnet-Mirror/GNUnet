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

/**
 * How often do we transmit our typemap?
 */
#define TYPEMAP_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)


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
   * How long is the message? (number of bytes following the "struct
   * MessageEntry", but not including the size of "struct
   * MessageEntry" itself!)
   */
  size_t size;

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
   * At what time did we initially establish this session?
   * (currently unused, should be integrated with ATS in the
   * future...).
   */
  struct GNUNET_TIME_Absolute time_established;

  /**
   * Task to transmit corked messages with a delay.
   */
  GNUNET_SCHEDULER_TaskIdentifier cork_task;

  /**
   * Task to transmit our type map.
   */
  GNUNET_SCHEDULER_TaskIdentifier typemap_task;

  /**
   * Is the neighbour queue empty and thus ready for us
   * to transmit an encrypted message?
   */
  int ready_to_transmit;

};


/**
 * Map of peer identities to 'struct Session'.
 */
static struct GNUNET_CONTAINER_MultiHashMap *sessions;


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
  return GNUNET_CONTAINER_multihashmap_get (sessions, &peer->hashPubKey);
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
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Destroying session for peer `%4s'\n",
              GNUNET_i2s (&session->peer));
#endif
  if (GNUNET_SCHEDULER_NO_TASK != session->cork_task)
  {
    GNUNET_SCHEDULER_cancel (session->cork_task);
    session->cork_task = GNUNET_SCHEDULER_NO_TASK;
  }
  while (NULL != (car = session->active_client_request_head))
  {
    GNUNET_CONTAINER_DLL_remove (session->active_client_request_head,
                                 session->active_client_request_tail, car);
    GSC_CLIENTS_reject_request (car);
  }
  while (NULL != (sme = session->sme_head))
  {
    GNUNET_CONTAINER_DLL_remove (session->sme_head, session->sme_tail, sme);
    GNUNET_free (sme);
  }
  GNUNET_SCHEDULER_cancel (session->typemap_task);
  GSC_CLIENTS_notify_clients_about_neighbour (&session->peer, NULL,
                                              0 /* FIXME: ATSI */ ,
                                              session->tmap, NULL);
  GNUNET_assert (GNUNET_YES ==
                 GNUNET_CONTAINER_multihashmap_remove (sessions,
                                                       &session->
                                                       peer.hashPubKey,
                                                       session));
  GNUNET_STATISTICS_set (GSC_stats, gettext_noop ("# entries in session map"),
                         GNUNET_CONTAINER_multihashmap_size (sessions),
                         GNUNET_NO);
  GSC_TYPEMAP_destroy (session->tmap);
  session->tmap = NULL;
  GNUNET_free (session);
}


/**
 * Transmit our current typemap message to the other peer.
 * (Done periodically in case an update got lost).
 *
 * @param cls the 'struct Session*'
 * @param tc unused
 */
static void
transmit_typemap_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Session *session = cls;
  struct GNUNET_MessageHeader *hdr;
  struct GNUNET_TIME_Relative delay;

  delay = TYPEMAP_FREQUENCY;
  /* randomize a bit to avoid spont. sync */
  delay.rel_value +=
      GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK, 1000);
  session->typemap_task =
      GNUNET_SCHEDULER_add_delayed (delay, &transmit_typemap_task, session);
  GNUNET_STATISTICS_update (GSC_stats,
                            gettext_noop ("# type map refreshes sent"), 1,
                            GNUNET_NO);
  hdr = GSC_TYPEMAP_compute_type_map_message ();
  GSC_KX_encrypt_and_transmit (session->kxinfo, hdr, ntohs (hdr->size));
  GNUNET_free (hdr);
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

#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Creating session for peer `%4s'\n",
              GNUNET_i2s (peer));
#endif
  session = GNUNET_malloc (sizeof (struct Session));
  session->tmap = GSC_TYPEMAP_create ();
  session->peer = *peer;
  session->kxinfo = kx;
  session->time_established = GNUNET_TIME_absolute_get ();
  session->typemap_task =
      GNUNET_SCHEDULER_add_now (&transmit_typemap_task, session);
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multihashmap_put (sessions, &peer->hashPubKey,
                                                    session,
                                                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY));
  GNUNET_STATISTICS_set (GSC_stats, gettext_noop ("# entries in session map"),
                         GNUNET_CONTAINER_multihashmap_size (sessions),
                         GNUNET_NO);
  GSC_CLIENTS_notify_clients_about_neighbour (peer, NULL, 0 /* FIXME: ATSI */ ,
                                              NULL, session->tmap);
}


/**
 * Notify the given client about the session (client is new).
 *
 * @param cls the 'struct GSC_Client'
 * @param key peer identity
 * @param value the 'struct Session'
 * @return GNUNET_OK (continue to iterate)
 */
static int
notify_client_about_session (void *cls, const GNUNET_HashCode * key,
                             void *value)
{
  struct GSC_Client *client = cls;
  struct Session *session = value;

  GSC_CLIENTS_notify_client_about_neighbour (client, &session->peer, NULL, 0,   /* FIXME: ATS!? */
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
  GNUNET_CONTAINER_multihashmap_iterate (sessions, &notify_client_about_session,
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
 *         be released by either until either 'GNUNET_SESSIONS_dequeue',
 *         'GNUNET_SESSIONS_transmit' or 'GNUNET_CLIENTS_failed'
 *         have been invoked on it
 */
void
GSC_SESSIONS_queue_request (struct GSC_ClientActiveRequest *car)
{
  struct Session *session;

  session = find_session (&car->target);
  if (session == NULL)
  {
#if DEBUG_CORE
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Dropped client request for transmission (am disconnected)\n");
#endif
    GNUNET_break (0);           /* should have been rejected earlier */
    GSC_CLIENTS_reject_request (car);
    return;
  }
  if (car->msize > GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    GSC_CLIENTS_reject_request (car);
    return;
  }
#if DEBUG_CORE
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received client transmission request. queueing\n");
#endif
  GNUNET_CONTAINER_DLL_insert (session->active_client_request_head,
                               session->active_client_request_tail, car);
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
  struct Session *s;

  if (0 ==
      memcmp (&car->target, &GSC_my_identity,
              sizeof (struct GNUNET_PeerIdentity)))
    return;
  s = find_session (&car->target);
  GNUNET_assert (NULL != s);
  GNUNET_CONTAINER_DLL_remove (s->active_client_request_head,
                               s->active_client_request_tail, car);
}


/**
 * Discard all expired active transmission requests from clients.
 *
 * @param session session to clean up
 */
static void
discard_expired_requests (struct Session *session)
{
  struct GSC_ClientActiveRequest *pos;
  struct GSC_ClientActiveRequest *nxt;
  struct GNUNET_TIME_Absolute now;

  now = GNUNET_TIME_absolute_get ();
  pos = NULL;
  nxt = session->active_client_request_head;
  while (NULL != nxt)
  {
    pos = nxt;
    nxt = pos->next;
    if ((pos->deadline.abs_value < now.abs_value) &&
        (GNUNET_YES != pos->was_solicited))
    {
      GNUNET_STATISTICS_update (GSC_stats,
                                gettext_noop
                                ("# messages discarded (expired prior to transmission)"),
                                1, GNUNET_NO);
      GNUNET_CONTAINER_DLL_remove (session->active_client_request_head,
                                   session->active_client_request_tail, pos);
      GSC_CLIENTS_reject_request (pos);
    }
  }
}


/**
 * Solicit messages for transmission.
 *
 * @param session session to solict messages for
 */
static void
solicit_messages (struct Session *session)
{
  struct GSC_ClientActiveRequest *car;
  struct GSC_ClientActiveRequest *nxt;
  size_t so_size;

  discard_expired_requests (session);
  so_size = 0;
  nxt = session->active_client_request_head;
  while (NULL != (car = nxt))
  {
    nxt = car->next;
    if (so_size + car->msize > GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE)
      break;
    so_size += car->msize;
    if (car->was_solicited == GNUNET_YES)
      continue;
    car->was_solicited = GNUNET_YES;
    GSC_CLIENTS_solicit_request (car);
  }
}


/**
 * Some messages were delayed (corked), but the timeout has now expired.
 * Send them now.
 *
 * @param cls 'struct Session' with the messages to transmit now
 * @param tc scheduler context (unused)
 */
static void
pop_cork_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Session *session = cls;

  session->cork_task = GNUNET_SCHEDULER_NO_TASK;
  try_transmission (session);
}


/**
 * Try to perform a transmission on the given session. Will solicit
 * additional messages if the 'sme' queue is not full enough.
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

  if (GNUNET_YES != session->ready_to_transmit)
    return;
  msize = 0;
  min_deadline = GNUNET_TIME_UNIT_FOREVER_ABS;
  /* check 'ready' messages */
  pos = session->sme_head;
  while ((NULL != pos) &&
         (msize + pos->size <= GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE))
  {
    GNUNET_assert (pos->size < GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE);
    msize += pos->size;
    min_deadline = GNUNET_TIME_absolute_min (min_deadline, pos->deadline);
    pos = pos->next;
  }
  now = GNUNET_TIME_absolute_get ();
  if ((msize == 0) ||
      ((msize < GNUNET_CONSTANTS_MAX_ENCRYPTED_MESSAGE_SIZE / 2) &&
       (min_deadline.abs_value > now.abs_value)))
  {
    /* not enough ready yet, try to solicit more */
    solicit_messages (session);
    if (msize > 0)
    {
      /* if there is data to send, just not yet, make sure we do transmit
       * it once the deadline is reached */
      if (session->cork_task != GNUNET_SCHEDULER_NO_TASK)
        GNUNET_SCHEDULER_cancel (session->cork_task);
      session->cork_task =
          GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining
                                        (min_deadline), &pop_cork_task,
                                        session);
    }
    return;
  }
  /* create plaintext buffer of all messages, encrypt and transmit */
  {
    static unsigned long long total_bytes;
    static unsigned int total_msgs;
    char pbuf[msize];           /* plaintext */
    size_t used;

    used = 0;
    while ((NULL != (pos = session->sme_head)) && (used + pos->size <= msize))
    {
      memcpy (&pbuf[used], &pos[1], pos->size);
      used += pos->size;
      GNUNET_CONTAINER_DLL_remove (session->sme_head, session->sme_tail, pos);
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
    GNUNET_STATISTICS_set (GSC_stats, "# avg payload per encrypted message",
                           total_bytes / total_msgs, GNUNET_NO);
    /* now actually transmit... */
    session->ready_to_transmit = GNUNET_NO;
    GSC_KX_encrypt_and_transmit (session->kxinfo, pbuf, used);
  }
}


/**
 * Send a message to the neighbour now.
 *
 * @param cls the message
 * @param key neighbour's identity
 * @param value 'struct Neighbour' of the target
 * @return always GNUNET_OK
 */
static int
do_send_message (void *cls, const GNUNET_HashCode * key, void *value)
{
  const struct GNUNET_MessageHeader *hdr = cls;
  struct Session *session = value;
  struct SessionMessageEntry *m;
  uint16_t size;

  size = ntohs (hdr->size);
  m = GNUNET_malloc (sizeof (struct SessionMessageEntry) + size);
  memcpy (&m[1], hdr, size);
  m->size = size;
  GNUNET_CONTAINER_DLL_insert (session->sme_head, session->sme_tail, m);
  try_transmission (session);
  return GNUNET_OK;
}


/**
 * Broadcast a message to all neighbours.
 *
 * @param msg message to transmit
 */
void
GSC_SESSIONS_broadcast (const struct GNUNET_MessageHeader *msg)
{
  if (NULL == sessions)
    return;
  GNUNET_CONTAINER_multihashmap_iterate (sessions, &do_send_message,
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
 */
void
GSC_SESSIONS_transmit (struct GSC_ClientActiveRequest *car,
                       const struct GNUNET_MessageHeader *msg, int cork)
{
  struct Session *session;
  struct SessionMessageEntry *sme;
  size_t msize;

  session = find_session (&car->target);
  if (NULL == session)
    return;
  msize = ntohs (msg->size);
  sme = GNUNET_malloc (sizeof (struct SessionMessageEntry) + msize);
  memcpy (&sme[1], msg, msize);
  sme->size = msize;
  if (GNUNET_YES == cork)
    sme->deadline =
        GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_MAX_CORK_DELAY);
  GNUNET_CONTAINER_DLL_insert_tail (session->sme_head, session->sme_tail, sme);
  try_transmission (session);
}


/**
 * Helper function for GSC_SESSIONS_handle_client_iterate_peers.
 *
 * @param cls the 'struct GNUNET_SERVER_TransmitContext' to queue replies
 * @param key identity of the connected peer
 * @param value the 'struct Neighbour' for the peer
 * @return GNUNET_OK (continue to iterate)
 */
#include "core.h"
static int
queue_connect_message (void *cls, const GNUNET_HashCode * key, void *value)
{
  struct GNUNET_SERVER_TransmitContext *tc = cls;
  struct Session *session = value;
  struct ConnectNotifyMessage cnm;

  /* FIXME: code duplication with clients... */
  cnm.header.size = htons (sizeof (struct ConnectNotifyMessage));
  cnm.header.type = htons (GNUNET_MESSAGE_TYPE_CORE_NOTIFY_CONNECT);
  // FIXME: full ats...
  cnm.ats_count = htonl (0);
  cnm.peer = session->peer;
  GNUNET_SERVER_transmit_context_append_message (tc, &cnm.header);
  return GNUNET_OK;
}


/**
 * Handle CORE_ITERATE_PEERS request. For this request type, the client
 * does not have to have transmitted an INIT request.  All current peers
 * are returned, regardless of which message types they accept.
 *
 * @param cls unused
 * @param client client sending the iteration request
 * @param message iteration request message
 */
void
GSC_SESSIONS_handle_client_iterate_peers (void *cls,
                                          struct GNUNET_SERVER_Client *client,
                                          const struct GNUNET_MessageHeader
                                          *message)
{
  struct GNUNET_MessageHeader done_msg;
  struct GNUNET_SERVER_TransmitContext *tc;

  tc = GNUNET_SERVER_transmit_context_create (client);
  GNUNET_CONTAINER_multihashmap_iterate (sessions, &queue_connect_message, tc);
  done_msg.size = htons (sizeof (struct GNUNET_MessageHeader));
  done_msg.type = htons (GNUNET_MESSAGE_TYPE_CORE_ITERATE_PEERS_END);
  GNUNET_SERVER_transmit_context_append_message (tc, &done_msg);
  GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Handle CORE_PEER_CONNECTED request.   Notify client about connection
 * to the given neighbour.  For this request type, the client does not
 * have to have transmitted an INIT request.  All current peers are
 * returned, regardless of which message types they accept.
 *
 * @param cls unused
 * @param client client sending the iteration request
 * @param message iteration request message
 */
void
GSC_SESSIONS_handle_client_have_peer (void *cls,
                                      struct GNUNET_SERVER_Client *client,
                                      const struct GNUNET_MessageHeader
                                      *message)
{
  struct GNUNET_MessageHeader done_msg;
  struct GNUNET_SERVER_TransmitContext *tc;
  const struct GNUNET_PeerIdentity *peer;

  peer = (const struct GNUNET_PeerIdentity *) &message[1];      // YUCK!
  tc = GNUNET_SERVER_transmit_context_create (client);
  GNUNET_CONTAINER_multihashmap_get_multiple (sessions, &peer->hashPubKey,
                                              &queue_connect_message, tc);
  done_msg.size = htons (sizeof (struct GNUNET_MessageHeader));
  done_msg.type = htons (GNUNET_MESSAGE_TYPE_CORE_ITERATE_PEERS_END);
  GNUNET_SERVER_transmit_context_append_message (tc, &done_msg);
  GNUNET_SERVER_transmit_context_run (tc, GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * We've received a typemap message from a peer, update ours.
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

  nmap = GSC_TYPEMAP_get_from_message (msg);
  if (NULL == nmap)
    return;                     /* malformed */
  session = find_session (peer);
  if (NULL == session)
  {
    GNUNET_break (0);
    return;
  }
  GSC_CLIENTS_notify_clients_about_neighbour (peer, NULL, 0,    /* FIXME: ATS */
                                              session->tmap, nmap);
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

  if (0 == memcmp (peer, &GSC_my_identity, sizeof (struct GNUNET_PeerIdentity)))
    return;
  session = find_session (peer);
  GNUNET_assert (NULL != session);
  if (GNUNET_YES == GSC_TYPEMAP_test_match (session->tmap, &type, 1))
    return;                     /* already in it */
  nmap = GSC_TYPEMAP_extend (session->tmap, &type, 1);
  GSC_CLIENTS_notify_clients_about_neighbour (peer, NULL, 0,    /* FIXME: ATS */
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
  sessions = GNUNET_CONTAINER_multihashmap_create (128);
}


/**
 * Helper function for GSC_SESSIONS_handle_client_iterate_peers.
 *
 * @param cls NULL
 * @param key identity of the connected peer
 * @param value the 'struct Session' for the peer
 * @return GNUNET_OK (continue to iterate)
 */
static int
free_session_helper (void *cls, const GNUNET_HashCode * key, void *value)
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
  GNUNET_CONTAINER_multihashmap_iterate (sessions, &free_session_helper, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (sessions);
  sessions = NULL;
}

/* end of gnunet-service-core_sessions.c */
