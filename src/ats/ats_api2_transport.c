/*
     This file is part of GNUnet.
     Copyright (C) 2010-2015, 2018 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/
/**
 * @file ats/ats_api2_transport.c
 * @brief address suggestions and bandwidth allocation
 * @author Christian Grothoff
 * @author Matthias Wachs
 */
#include "platform.h"
#include "gnunet_ats_transport_service.h"
#include "ats2.h"

#define LOG(kind,...) GNUNET_log_from(kind, "ats-transport-api", __VA_ARGS__)


/**
 * Information we track per session, incoming or outgoing.  It also
 * doesn't matter if we have a session, any session that ATS is
 * allowed to suggest right now should be tracked.
 */
struct GNUNET_ATS_SessionRecord
{

  /**
   * Transport handle this session record belongs to.
   */
  struct GNUNET_ATS_TransportHandle *ath;

  /**
   * Address data.
   */
  const char *address;

  /**
   * Session handle, NULL if inbound-only (also implies we cannot
   * actually control inbound traffic via transport!).  So if
   * @e session is NULL, the @e properties are informative for
   * ATS (connection exists, utilization) but ATS cannot directly
   * influence it (and should thus not call the
   * #GNUNET_ATS_AllocationCallback for this @e session, which is
   * obvious as NULL is not a meaningful session to allocation
   * resources to).
   */
  struct GNUNET_ATS_Session *session;

  /**
   * Identity of the peer reached at @e address.
   */
  struct GNUNET_PeerIdentity pid;

  /**
   * Performance data about the @e session.
   */
  struct GNUNET_ATS_Properties properties;

  /**
   * Unique ID to identify this session at this @a pid in IPC
   * messages.
   */
  uint32_t slot;

};


/**
 * Handle to the ATS subsystem for bandwidth/transport transport information.
 */
struct GNUNET_ATS_TransportHandle
{

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Callback to invoke on suggestions.
   */
  GNUNET_ATS_SuggestionCallback suggest_cb;

  /**
   * Closure for @e suggest_cb.
   */
  void *suggest_cb_cls;

  /**
   * Callback to invoke on allocations.
   */
  GNUNET_ATS_AllocationCallback alloc_cb;

  /**
   * Closure for @e alloc_cb.
   */
  void *alloc_cb_cls;

  /**
   * Message queue for sending requests to the ATS service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Task to trigger reconnect.
   */
  struct GNUNET_SCHEDULER_Task *task;

  /**
   * Hash map mapping PIDs to session records.
   */
  struct GNUNET_CONTAINER_MultiPeerMap *records;

  /**
   * Reconnect backoff delay.
   */
  struct GNUNET_TIME_Relative backoff;

};



/**
 * Convert ATS properties from host to network byte order.
 *
 * @param nbo[OUT] value written
 * @param hbo value read
 */
static void
properties_hton (struct PropertiesNBO *nbo,
                 const struct GNUNET_ATS_Properties *hbo)
{
  nbo->delay = GNUNET_TIME_relative_hton (hbo->delay);
  nbo->goodput_out = htonl (hbo->goodput_out);
  nbo->goodput_in = htonl (hbo->goodput_in);
  nbo->utilization_out = htonl (hbo->utilization_out);
  nbo->utilization_in = htonl (hbo->utilization_in);
  nbo->distance = htonl (hbo->distance);
  nbo->mtu = htonl (hbo->mtu);
  nbo->nt = htonl ((uint32_t) hbo->nt);
  nbo->cc = htonl ((uint32_t) hbo->cc);
}


/**
 * Re-establish the connection to the ATS service.
 *
 * @param sh handle to use to re-connect.
 */
static void
reconnect (struct GNUNET_ATS_TransportHandle *ath);


/**
 * Re-establish the connection to the ATS service.
 *
 * @param cls handle to use to re-connect.
 */
static void
reconnect_task (void *cls)
{
  struct GNUNET_ATS_TransportHandle *ath = cls;

  ath->task = NULL;
  reconnect (ath);
}


/**
 * Disconnect from ATS and then reconnect.
 *
 * @param ath our handle
 */
static void
force_reconnect (struct GNUNET_ATS_TransportHandle *ath)
{
  if (NULL != ath->mq)
  {
    GNUNET_MQ_destroy (ath->mq);
    ath->mq = NULL;
  }
  /* FIXME: do we tell transport service about disconnect events? CON:
     initially ATS will have a really screwed picture of the world and
     the rapid change would be bad.  PRO: if we don't, ATS and
     transport may disagree about the allocation for a while...
     For now: lazy: do nothing. */
  ath->backoff = GNUNET_TIME_STD_BACKOFF (ath->backoff);
  ath->task = GNUNET_SCHEDULER_add_delayed (ath->backoff,
                                           &reconnect_task,
                                           ath);
}


/**
 * Check format of address suggestion message from the service.
 *
 * @param cls the `struct GNUNET_ATS_TransportHandle`
 * @param m message received
 */
static int
check_ats_address_suggestion (void *cls,
                              const struct AddressSuggestionMessage *m)
{
  (void) cls;
  GNUNET_MQ_check_zero_termination (m);
  return GNUNET_SYSERR;
}


/**
 * We received an address suggestion message from the service.
 *
 * @param cls the `struct GNUNET_ATS_TransportHandle`
 * @param m message received
 */
static void
handle_ats_address_suggestion (void *cls,
			       const struct AddressSuggestionMessage *m)
{
  struct GNUNET_ATS_TransportHandle *ath = cls;
  const char *address = (const char *) &m[1];

  ath->suggest_cb (ath->suggest_cb_cls,
                  &m->peer,
                  address);
}


/**
 * Closure for #match_session_cb.
 */
struct FindContext
{
  /**
   * Key to look for.
   */
  uint32_t session_id;

  /**
   * Where to store the result.
   */
  struct GNUNET_ATS_SessionRecord *sr;
};


/**
 * Finds matching session record.
 *
 * @param cls a `struct FindContext`
 * @param pid peer identity (unused)
 * @param value a `struct GNUNET_ATS_SessionRecord`
 * @return #GNUNET_NO if match found, #GNUNET_YES to continue searching
 */
static int
match_session_cb (void *cls,
                  const struct GNUNET_PeerIdentity *pid,
                  void *value)
{
  struct FindContext *fc = cls;
  struct GNUNET_ATS_SessionRecord *sr = value;

  (void) pid;
  if (fc->session_id == sr->slot)
  {
    fc->sr = sr;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}



/**
 * Find session record for peer @a pid and session @a session_id
 *
 * @param ath transport handle to search
 * @param session_id session ID to match
 * @param pid peer to search under
 * @return NULL if no such record exists
 */
static struct GNUNET_ATS_SessionRecord *
find_session (struct GNUNET_ATS_TransportHandle *ath,
              uint32_t session_id,
              const struct GNUNET_PeerIdentity *pid)
{
  struct FindContext fc = {
    .session_id = session_id,
    .sr = NULL
  };
  GNUNET_CONTAINER_multipeermap_get_multiple (ath->records,
                                              pid,
                                              &match_session_cb,
                                              &fc);
  return fc.sr;
}


/**
 * We received a session allocation message from the service.
 *
 * @param cls the `struct GNUNET_ATS_TransportHandle`
 * @param m message received
 */
static void
handle_ats_session_allocation (void *cls,
			       const struct SessionAllocationMessage *m)
{
  struct GNUNET_ATS_TransportHandle *ath = cls;
  struct GNUNET_ATS_SessionRecord *ar;
  uint32_t session_id;

  session_id = ntohl (m->session_id);
  ar = find_session (ath,
                     session_id,
                     &m->peer);
  if (NULL == ar)
  {
    /* this can (rarely) happen if ATS changes an sessiones allocation
       just when the transport service deleted it */
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                "Allocation ignored, session unknown\n");
    return;
  }
  ath->backoff = GNUNET_TIME_UNIT_ZERO;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "ATS allocates bandwidth for peer `%s' using address %s\n",
       GNUNET_i2s (&ar->pid),
       ar->address);
  ath->alloc_cb (ath->alloc_cb_cls,
                 ar->session,
                 m->bandwidth_out,
                 m->bandwidth_in);
}


/**
 * We encountered an error handling the MQ to the ATS service.
 * Reconnect.
 *
 * @param cls the `struct GNUNET_ATS_TransportHandle`
 * @param error details about the error
 */
static void
error_handler (void *cls,
               enum GNUNET_MQ_Error error)
{
  struct GNUNET_ATS_TransportHandle *ath = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "ATS connection died (code %d), reconnecting\n",
       (int) error);
  force_reconnect (ath);
}


/**
 * Generate and transmit the `struct SessionAddMessage` for the given
 * session record.
 *
 * @param ar the session to inform the ATS service about
 */
static void
send_add_session_message (const struct GNUNET_ATS_SessionRecord *ar)
{
  struct GNUNET_ATS_TransportHandle *ath = ar->ath;
  struct GNUNET_MQ_Envelope *ev;
  struct SessionAddMessage *m;
  size_t alen;

  if (NULL == ath->mq)
    return; /* disconnected, skip for now */
  alen = strlen (ar->address) + 1;
  ev = GNUNET_MQ_msg_extra (m,
                            alen,
                            (NULL == ar->session)
                            ? GNUNET_MESSAGE_TYPE_ATS_SESSION_ADD_INBOUND_ONLY
                            : GNUNET_MESSAGE_TYPE_ATS_SESSION_ADD);
  m->peer = ar->pid;
  m->session_id = htonl (ar->slot);
  properties_hton (&m->properties,
                   &ar->properties);
  GNUNET_memcpy (&m[1],
                 ar->address,
                 alen);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding address `%s' for peer `%s'\n",
       ar->address,
       GNUNET_i2s (&ar->pid));
  GNUNET_MQ_send (ath->mq,
                  ev);
}


/**
 * Send ATS information about the session record.
 *
 * @param cls our `struct GNUNET_ATS_TransportHandle *`, unused
 * @param pid unused
 * @param value the `struct GNUNET_ATS_SessionRecord *` to add
 * @return #GNUNET_OK
 */
static int
send_add_session_cb (void *cls,
                     const struct GNUNET_PeerIdentity *pid,
                     void *value)
{
  struct GNUNET_ATS_SessionRecord *ar = value;

  (void) cls;
  (void) pid;
  send_add_session_message (ar);
  return GNUNET_OK;
}


/**
 * Re-establish the connection to the ATS service.
 *
 * @param ath handle to use to re-connect.
 */
static void
reconnect (struct GNUNET_ATS_TransportHandle *ath)
{
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_var_size (ats_address_suggestion,
                           GNUNET_MESSAGE_TYPE_ATS_ADDRESS_SUGGESTION,
                           struct AddressSuggestionMessage,
                           ath),
    GNUNET_MQ_hd_fixed_size (ats_session_allocation,
                             GNUNET_MESSAGE_TYPE_ATS_SESSION_ALLOCATION,
                             struct SessionAllocationMessage,
                             ath),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *ev;
  struct GNUNET_MessageHeader *init;

  GNUNET_assert (NULL == ath->mq);
  ath->mq = GNUNET_CLIENT_connect (ath->cfg,
                                  "ats",
                                  handlers,
                                  &error_handler,
                                  ath);
  if (NULL == ath->mq)
  {
    GNUNET_break (0);
    force_reconnect (ath);
    return;
  }
  ev = GNUNET_MQ_msg (init,
                      GNUNET_MESSAGE_TYPE_ATS_START);
  GNUNET_MQ_send (ath->mq,
                  ev);
  if (NULL == ath->mq)
    return;
  GNUNET_CONTAINER_multipeermap_iterate (ath->records,
                                         &send_add_session_cb,
                                         ath);
}


/**
 * Initialize the ATS subsystem.
 *
 * @param cfg configuration to use
 * @param alloc_cb notification to call whenever the allocation changed
 * @param alloc_cb_cls closure for @a alloc_cb
 * @param suggest_cb notification to call whenever the suggestation is made
 * @param suggest_cb_cls closure for @a suggest_cb
 * @return ats context
 */
struct GNUNET_ATS_TransportHandle *
GNUNET_ATS_transport_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
                           GNUNET_ATS_AllocationCallback alloc_cb,
                           void *alloc_cb_cls,
                           GNUNET_ATS_SuggestionCallback suggest_cb,
                           void *suggest_cb_cls)
{
  struct GNUNET_ATS_TransportHandle *ath;

  ath = GNUNET_new (struct GNUNET_ATS_TransportHandle);
  ath->cfg = cfg;
  ath->suggest_cb = suggest_cb;
  ath->suggest_cb_cls = suggest_cb_cls;
  ath->alloc_cb = alloc_cb;
  ath->alloc_cb_cls = alloc_cb_cls;
  ath->records = GNUNET_CONTAINER_multipeermap_create (128,
                                                      GNUNET_YES);
  reconnect (ath);
  return ath;
}


/**
 * Release memory associated with the session record.
 *
 * @param cls NULL
 * @param pid unused
 * @param value a `struct GNUNET_ATS_SessionRecord`
 * @return #GNUNET_OK
 */
static int
free_record (void *cls,
             const struct GNUNET_PeerIdentity *pid,
             void *value)
{
  struct GNUNET_ATS_SessionRecord *ar = value;

  (void) cls;
  (void) pid;
  GNUNET_free (ar);
  return GNUNET_OK;
}


/**
 * Client is done with ATS transport, release resources.
 *
 * @param ath handle to release
 */
void
GNUNET_ATS_transport_done (struct GNUNET_ATS_TransportHandle *ath)
{
  if (NULL != ath->mq)
  {
    GNUNET_MQ_destroy (ath->mq);
    ath->mq = NULL;
  }
  if (NULL != ath->task)
  {
    GNUNET_SCHEDULER_cancel (ath->task);
    ath->task = NULL;
  }
  GNUNET_CONTAINER_multipeermap_iterate (ath->records,
                                         &free_record,
                                         NULL);
  GNUNET_CONTAINER_multipeermap_destroy (ath->records);
  GNUNET_free (ath);
}


/**
 * We have a new session ATS should know. Sessiones have to be added
 * with this function before they can be: updated, set in use and
 * destroyed.
 *
 * @param ath handle
 * @param pid peer we connected to
 * @param address the address (human readable version)
 * @param session transport-internal handle for the session/queue, NULL if
 *        the session is inbound-only
 * @param prop performance data for the session
 * @return handle to the session representation inside ATS, NULL
 *         on error (i.e. ATS knows this exact session already)
 */
struct GNUNET_ATS_SessionRecord *
GNUNET_ATS_session_add (struct GNUNET_ATS_TransportHandle *ath,
                        const struct GNUNET_PeerIdentity *pid,
                        const char *address,
                        struct GNUNET_ATS_Session *session,
                        const struct GNUNET_ATS_Properties *prop)
{
  struct GNUNET_ATS_SessionRecord *ar;
  uint32_t s;
  size_t alen;

  if (NULL == address)
  {
    /* we need a valid address */
    GNUNET_break (0);
    return NULL;
  }
  alen = strlen (address) + 1;
  if ( (alen + sizeof (struct SessionAddMessage) >= GNUNET_MAX_MESSAGE_SIZE) ||
       (alen >= GNUNET_MAX_MESSAGE_SIZE) )
  {
    /* address too large for us, this should not happen */
    GNUNET_break (0);
    return NULL;
  }

  /* Spin 's' until we find an unused session ID for this pid */
  for (s = GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                     UINT32_MAX);
       NULL != find_session (ath,
                             s,
                             pid);
       s++) ;

  alen = strlen (address) + 1;
  ar = GNUNET_malloc (sizeof (struct GNUNET_ATS_SessionRecord) + alen);
  ar->ath = ath;
  ar->slot = s;
  ar->session = session;
  ar->address = (const char *) &ar[1];
  ar->pid = *pid;
  ar->properties = *prop;
  memcpy (&ar[1],
          address,
          alen);
  (void) GNUNET_CONTAINER_multipeermap_put (ath->records,
                                            &ar->pid,
                                            ar,
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  send_add_session_message (ar);
  return ar;
}


/**
 * We have updated performance statistics for a given session.  Note
 * that this function can be called for sessiones that are currently
 * in use as well as sessiones that are valid but not actively in use.
 * Furthermore, the peer may not even be connected to us right now (in
 * which case the call may be ignored or the information may be stored
 * for later use).  Update bandwidth assignments.
 *
 * @param ar session record to update information for
 * @param prop performance data for the session
 */
void
GNUNET_ATS_session_update (struct GNUNET_ATS_SessionRecord *ar,
                           const struct GNUNET_ATS_Properties *prop)
{
  struct GNUNET_ATS_TransportHandle *ath = ar->ath;
  struct GNUNET_MQ_Envelope *ev;
  struct SessionUpdateMessage *m;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Updating address `%s' for peer `%s'\n",
       ar->address,
       GNUNET_i2s (&ar->pid));
  ar->properties = *prop;
  if (NULL == ath->mq)
    return; /* disconnected, skip for now */
  ev = GNUNET_MQ_msg (m,
                      GNUNET_MESSAGE_TYPE_ATS_SESSION_UPDATE);
  m->session_id = htonl (ar->slot);
  m->peer = ar->pid;
  properties_hton (&m->properties,
                   &ar->properties);
  GNUNET_MQ_send (ath->mq,
                  ev);
}


/**
 * A session was destroyed, ATS should now schedule and
 * allocate under the assumption that this @a ar is no
 * longer in use.
 *
 * @param ar session record to drop
 */
void
GNUNET_ATS_session_del (struct GNUNET_ATS_SessionRecord *ar)
{
  struct GNUNET_ATS_TransportHandle *ath = ar->ath;
  struct GNUNET_MQ_Envelope *ev;
  struct SessionDelMessage *m;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Deleting address `%s' for peer `%s'\n",
       ar->address,
       GNUNET_i2s (&ar->pid));
  if (NULL == ath->mq)
    return;
  ev = GNUNET_MQ_msg (m,
                      GNUNET_MESSAGE_TYPE_ATS_SESSION_DEL);
  m->session_id = htonl (ar->slot);
  m->peer = ar->pid;
  GNUNET_MQ_send (ath->mq,
                  ev);
}


/* end of ats_api2_transport.c */
