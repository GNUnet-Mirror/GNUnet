/*
     This file is part of GNUnet.
     Copyright (C) 2010-2015 Christian Grothoff (and other contributing authors)

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
 * @file ats/ats_api_scheduling.c
 * @brief automatic transport selection and outbound bandwidth determination
 * @author Christian Grothoff
 * @author Matthias Wachs
 *
 * TODO:
 * - we could avoid a linear scan over the
 *   active addresses in some cases, so if
 *   there is need, we can still optimize here
 * - we might want to split off the logic to
 *   determine LAN vs. WAN, as it has nothing
 *   to do with accessing the ATS service.
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "ats.h"

/**
 * How frequently do we scan the interfaces for changes to the addresses?
 */
#define INTERFACE_PROCESSING_INTERVAL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 2)

#define LOG(kind,...) GNUNET_log_from(kind, "ats-scheduling-api", __VA_ARGS__)

/**
 * Session ID we use if there is no session / slot.
 */
#define NOT_FOUND 0


/**
 * Information we track per address, incoming or outgoing.  It also
 * doesn't matter if we have a session, any address that ATS is
 * allowed to suggest right now should be tracked.
 */
struct GNUNET_ATS_AddressRecord
{

  /**
   * Scheduling handle this address record belongs to.
   */
  struct GNUNET_ATS_SchedulingHandle *sh;

  /**
   * Address data.
   */
  struct GNUNET_HELLO_Address *address;

  /**
   * Session handle.  NULL if we have an address but no
   * active session for this address.
   */
  struct Session *session;

  /**
   * Array with performance data about the address.
   */
  struct GNUNET_ATS_Information *ats;

  /**
   * Number of entries in @e ats.
   */
  uint32_t ats_count;

  /**
   * Which slot (index) in the session array does
   * this record correspond to?  FIXME:
   * FIXME: a linear search on this is really crappy!
   * Maybe switch to a 64-bit global counter and be
   * done with it?  Or does that then cause too much
   * trouble on the ATS-service side?
   */
  uint32_t slot;

  /**
   * We're about to destroy this address record, just ATS does
   * not know this yet.  Once ATS confirms its destruction,
   * we can clean up.
   */
  int in_destroy;
};


/**
 * Handle to the ATS subsystem for bandwidth/transport scheduling information.
 */
struct GNUNET_ATS_SchedulingHandle
{

  /**
   * Our configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Callback to invoke on suggestions.
   */
  GNUNET_ATS_AddressSuggestionCallback suggest_cb;

  /**
   * Closure for @e suggest_cb.
   */
  void *suggest_cb_cls;

  /**
   * Connection to ATS service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Message queue for sending requests to the ATS service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Array of session objects (we need to translate them to numbers and back
   * for the protocol; the offset in the array is the session number on the
   * network).  Index 0 is always NULL and reserved to represent the NULL pointer.
   * Unused entries are also NULL.
   */
  struct GNUNET_ATS_AddressRecord **session_array;

  /**
   * Task to trigger reconnect.
   */
  struct GNUNET_SCHEDULER_Task *task;

  /**
   * Reconnect backoff delay.
   */
  struct GNUNET_TIME_Relative backoff;

  /**
   * Size of the @e session_array.
   */
  unsigned int session_array_size;

};


/**
 * Re-establish the connection to the ATS service.
 *
 * @param sh handle to use to re-connect.
 */
static void
reconnect (struct GNUNET_ATS_SchedulingHandle *sh);


/**
 * Re-establish the connection to the ATS service.
 *
 * @param cls handle to use to re-connect.
 * @param tc scheduler context
 */
static void
reconnect_task (void *cls,
                const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_ATS_SchedulingHandle *sh = cls;

  sh->task = NULL;
  reconnect (sh);
}


/**
 * Disconnect from ATS and then reconnect.
 *
 * @param sh our handle
 */
static void
force_reconnect (struct GNUNET_ATS_SchedulingHandle *sh)
{
  if (NULL != sh->mq)
  {
    GNUNET_MQ_destroy (sh->mq);
    sh->mq = NULL;
  }
  if (NULL != sh->client)
  {
    GNUNET_CLIENT_disconnect (sh->client);
    sh->client = NULL;
  }
  sh->suggest_cb (sh->suggest_cb_cls,
                  NULL, NULL, NULL,
                  GNUNET_BANDWIDTH_ZERO,
                  GNUNET_BANDWIDTH_ZERO);
  sh->backoff = GNUNET_TIME_STD_BACKOFF (sh->backoff);
  sh->task = GNUNET_SCHEDULER_add_delayed (sh->backoff,
                                           &reconnect_task,
                                           sh);
}


/**
 * Find the session object corresponding to the given session ID.
 *
 * @param sh our handle
 * @param session_id current session ID
 * @param peer peer the session belongs to
 * @return the session object (or NULL)
 */
static struct GNUNET_ATS_AddressRecord *
find_session (struct GNUNET_ATS_SchedulingHandle *sh,
              uint32_t session_id,
              const struct GNUNET_PeerIdentity *peer)
{
  struct GNUNET_ATS_AddressRecord *ar;

  if (session_id >= sh->session_array_size)
  {
    GNUNET_break (0);
    return NULL;
  }
  if (0 == session_id)
    return NULL;
  ar = sh->session_array[session_id];
  if (NULL == ar)
  {
    GNUNET_break (0);
    return NULL;
  }
  if (NULL == ar->address)
  {
    /* address was destroyed in the meantime, this can happen
       as we communicate asynchronously with the ATS service. */
    return NULL;
  }
  if (0 != memcmp (peer,
                   &ar->address->peer,
                   sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break (0);
    force_reconnect (sh);
    return NULL;
  }
  return ar;
}


/**
 * Get an available session ID.
 *
 * @param sh our handle
 * @return an unused slot, but never NOT_FOUND (0)
 */
static uint32_t
find_empty_session_slot (struct GNUNET_ATS_SchedulingHandle *sh)
{
  static uint32_t off;
  uint32_t i;

  i = 0;
  while ( ( (NOT_FOUND == off) ||
            (NULL != sh->session_array[off % sh->session_array_size]) ) &&
          (i < sh->session_array_size) )
  {
    off++;
    i++;
  }
  if ( (NOT_FOUND != off % sh->session_array_size) &&
       (NULL == sh->session_array[off % sh->session_array_size]) )
    return off;
  i = sh->session_array_size;
  GNUNET_array_grow (sh->session_array,
                     sh->session_array_size,
                     sh->session_array_size * 2);
  return i;
}


/**
 * Get the ID for the given session object.
 *
 * @param sh our handle
 * @param session session object
 * @param address the address we are looking for
 * @return the session id or NOT_FOUND for error
 */
static uint32_t
find_session_id (struct GNUNET_ATS_SchedulingHandle *sh,
                 struct Session *session,
                 const struct GNUNET_HELLO_Address *address)
{
  uint32_t i;

  if (NULL == address)
  {
    GNUNET_break (0);
    return NOT_FOUND;
  }
  for (i = 1; i < sh->session_array_size; i++)
    if ( (NULL != sh->session_array[i]) &&
         ( (session == sh->session_array[i]->session) ||
           (NULL == sh->session_array[i]->session) ) &&
         (0 == GNUNET_HELLO_address_cmp (address,
                                         sh->session_array[i]->address)) )
      return i;
  return NOT_FOUND;
}


/**
 * Release the session slot from the session table (ATS service is
 * also done using it).
 *
 * @param sh our handle
 * @param session_id identifies session that is no longer valid
 */
static void
release_session (struct GNUNET_ATS_SchedulingHandle *sh,
                 uint32_t session_id)
{
  struct GNUNET_ATS_AddressRecord *ar;

  if (NOT_FOUND == session_id)
    return;
  if (session_id >= sh->session_array_size)
  {
    GNUNET_break (0);
    force_reconnect (sh);
    return;
  }
  /* this slot should have been removed from remove_session before */
  ar = sh->session_array[session_id];
  if (NULL != ar->session)
  {
    GNUNET_break (0);
    force_reconnect (sh);
    return;
  }
  GNUNET_HELLO_address_free (ar->address);
  GNUNET_free (ar);
  sh->session_array[session_id] = NULL;
}


/**
 * Type of a function to call when we receive a session release
 * message from the service.
 *
 * @param cls the `struct GNUNET_ATS_SchedulingHandle`
 * @param msg message received, NULL on timeout or fatal error
 */
static void
process_ats_session_release_message (void *cls,
                                     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_ATS_SchedulingHandle *sh = cls;
  const struct SessionReleaseMessage *srm;

  srm = (const struct SessionReleaseMessage *) msg;
  /* Note: peer field in srm not necessary right now,
     but might be good to have in the future */
  release_session (sh,
                   ntohl (srm->session_id));
}


/**
 * Type of a function to call when we receive a address suggestion
 * message from the service.
 *
 * @param cls the `struct GNUNET_ATS_SchedulingHandle`
 * @param msg message received, NULL on timeout or fatal error
 */
static void
process_ats_address_suggestion_message (void *cls,
                                        const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_ATS_SchedulingHandle *sh = cls;
  const struct AddressSuggestionMessage *m;
  struct GNUNET_ATS_AddressRecord *ar;
  uint32_t session_id;

  m = (const struct AddressSuggestionMessage *) msg;
  session_id = ntohl (m->session_id);
  if (0 == session_id)
  {
    GNUNET_break (0);
    force_reconnect (sh);
    return;
  }
  ar = find_session (sh, session_id, &m->peer);
  if (NULL == ar)
  {
    GNUNET_break (0);
    force_reconnect (sh);
    return;
  }
  if (NULL == sh->suggest_cb)
    return;
  if (GNUNET_YES == ar->in_destroy)
  {
    /* ignore suggestion, as this address is dying, unless BW is 0,
       in that case signal 'disconnect' via BW 0 */
    if ( (0 == ntohl (m->bandwidth_out.value__)) &&
         (0 == ntohl (m->bandwidth_in.value__)) )
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "ATS suggests disconnect from peer `%s' with BW %u/%u\n",
           GNUNET_i2s (&ar->address->peer),
           (unsigned int) ntohl (m->bandwidth_out.value__),
           (unsigned int) ntohl (m->bandwidth_in.value__));
      sh->suggest_cb (sh->suggest_cb_cls,
                      &m->peer,
                      NULL,
                      NULL,
                      m->bandwidth_out,
                      m->bandwidth_in);
    }
    return;
  }
  if ( (NULL == ar->session) &&
       (GNUNET_HELLO_address_check_option (ar->address,
                                           GNUNET_HELLO_ADDRESS_INFO_INBOUND)) )
  {
    GNUNET_break (0);
    return;
  }
  sh->backoff = GNUNET_TIME_UNIT_ZERO;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "ATS suggests address slot %u for peer `%s' using plugin %s\n",
       ar->slot,
       GNUNET_i2s (&ar->address->peer),
       ar->address->transport_name);
  sh->suggest_cb (sh->suggest_cb_cls,
                  &m->peer,
                  ar->address,
                  ar->session,
                  m->bandwidth_out,
                  m->bandwidth_in);
}


/**
 * We encountered an error handling the MQ to the
 * ATS service.  Reconnect.
 *
 * @param cls the `struct GNUNET_ATS_SchedulingHandle`
 * @param error details about the error
 */
static void
error_handler (void *cls,
               enum GNUNET_MQ_Error error)
{
  struct GNUNET_ATS_SchedulingHandle *sh = cls;

  LOG (GNUNET_ERROR_TYPE_WARNING,
       "ATS connection died (code %d), reconnecting\n",
       (int) error);
  force_reconnect (sh);
}


/**
 * Generate and transmit the `struct AddressAddMessage` for the given
 * address record.
 *
 * @param sh the scheduling handle to use for transmission
 * @param ar the address to inform the ATS service about
 */
static void
send_add_address_message (struct GNUNET_ATS_SchedulingHandle *sh,
                          const struct GNUNET_ATS_AddressRecord *ar)
{
  struct GNUNET_MQ_Envelope *ev;
  struct AddressAddMessage *m;
  struct GNUNET_ATS_Information *am;
  char *pm;
  size_t namelen;
  size_t msize;

  if (NULL == sh->mq)
    return; /* disconnected, skip for now */
  namelen = (NULL == ar->address->transport_name)
    ? 0
    : strlen (ar->address->transport_name) + 1;
  msize = ar->address->address_length +
    ar->ats_count * sizeof (struct GNUNET_ATS_Information) + namelen;

  ev = GNUNET_MQ_msg_extra (m, msize, GNUNET_MESSAGE_TYPE_ATS_ADDRESS_ADD);
  m->ats_count = htonl (ar->ats_count);
  m->peer = ar->address->peer;
  m->address_length = htons (ar->address->address_length);
  m->address_local_info = htonl ((uint32_t) ar->address->local_info);
  m->plugin_name_length = htons (namelen);
  m->session_id = htonl (ar->slot);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding address for peer `%s', plugin `%s', session %p slot %u\n",
       GNUNET_i2s (&ar->address->peer),
       ar->address->transport_name,
       ar->session,
       ar->slot);
  am = (struct GNUNET_ATS_Information *) &m[1];
  memcpy (am,
          ar->ats,
          ar->ats_count * sizeof (struct GNUNET_ATS_Information));
  pm = (char *) &am[ar->ats_count];
  memcpy (pm,
          ar->address->address,
          ar->address->address_length);
  if (NULL != ar->address->transport_name)
    memcpy (&pm[ar->address->address_length],
            ar->address->transport_name,
            namelen);
  GNUNET_MQ_send (sh->mq, ev);
}


/**
 * Re-establish the connection to the ATS service.
 *
 * @param sh handle to use to re-connect.
 */
static void
reconnect (struct GNUNET_ATS_SchedulingHandle *sh)
{
  static const struct GNUNET_MQ_MessageHandler handlers[] =
    { { &process_ats_session_release_message,
        GNUNET_MESSAGE_TYPE_ATS_SESSION_RELEASE,
        sizeof (struct SessionReleaseMessage) },
      { &process_ats_address_suggestion_message,
        GNUNET_MESSAGE_TYPE_ATS_ADDRESS_SUGGESTION,
        sizeof (struct AddressSuggestionMessage) },
      { NULL, 0, 0 } };
  struct GNUNET_MQ_Envelope *ev;
  struct ClientStartMessage *init;
  unsigned int i;
  struct GNUNET_ATS_AddressRecord *ar;

  GNUNET_assert (NULL == sh->client);
  sh->client = GNUNET_CLIENT_connect ("ats", sh->cfg);
  if (NULL == sh->client)
  {
    force_reconnect (sh);
    return;
  }
  sh->mq = GNUNET_MQ_queue_for_connection_client (sh->client,
                                                  handlers,
                                                  &error_handler,
                                                  sh);
  ev = GNUNET_MQ_msg (init,
                      GNUNET_MESSAGE_TYPE_ATS_START);
  init->start_flag = htonl (START_FLAG_SCHEDULING);
  GNUNET_MQ_send (sh->mq, ev);
  if (NULL == sh->mq)
    return;
  for (i=0;i<sh->session_array_size;i++)
  {
    ar = sh->session_array[i];
    if (NULL == ar)
      continue;
    send_add_address_message (sh, ar);
    if (NULL == sh->mq)
      return;
  }
}


/**
 * Initialize the ATS subsystem.
 *
 * @param cfg configuration to use
 * @param suggest_cb notification to call whenever the suggestation changed
 * @param suggest_cb_cls closure for @a suggest_cb
 * @return ats context
 */
struct GNUNET_ATS_SchedulingHandle *
GNUNET_ATS_scheduling_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
                            GNUNET_ATS_AddressSuggestionCallback suggest_cb,
                            void *suggest_cb_cls)
{
  struct GNUNET_ATS_SchedulingHandle *sh;

  sh = GNUNET_new (struct GNUNET_ATS_SchedulingHandle);
  sh->cfg = cfg;
  sh->suggest_cb = suggest_cb;
  sh->suggest_cb_cls = suggest_cb_cls;
  GNUNET_array_grow (sh->session_array,
                     sh->session_array_size,
                     4);
  reconnect (sh);
  return sh;
}


/**
 * Client is done with ATS scheduling, release resources.
 *
 * @param sh handle to release
 */
void
GNUNET_ATS_scheduling_done (struct GNUNET_ATS_SchedulingHandle *sh)
{
  unsigned int i;

  if (NULL != sh->mq)
  {
    GNUNET_MQ_destroy (sh->mq);
    sh->mq = NULL;
  }
  if (NULL != sh->client)
  {
    GNUNET_CLIENT_disconnect (sh->client);
    sh->client = NULL;
  }
  if (NULL != sh->task)
  {
    GNUNET_SCHEDULER_cancel (sh->task);
    sh->task = NULL;
  }
  for (i=0;i<sh->session_array_size;i++)
  {
    GNUNET_free_non_null (sh->session_array[i]);
    sh->session_array[i] = NULL;
  }
  GNUNET_array_grow (sh->session_array,
                     sh->session_array_size,
                     0);
  GNUNET_free (sh);
}


/**
 * Test if a address and a session is known to ATS
 *
 * @param sh the scheduling handle
 * @param address the address
 * @param session the session
 * @return #GNUNET_YES or #GNUNET_NO
 */
int
GNUNET_ATS_session_known (struct GNUNET_ATS_SchedulingHandle *sh,
                          const struct GNUNET_HELLO_Address *address,
                          struct Session *session)
{
  if (NULL == session)
    return GNUNET_NO;
  if (NOT_FOUND != find_session_id (sh,
                                    session,
                                    address))
    return GNUNET_YES;  /* Exists */
  return GNUNET_NO;
}


/**
 * We have a new address ATS should know. Addresses have to be added
 * with this function before they can be: updated, set in use and
 * destroyed.
 *
 * @param sh handle
 * @param address the address
 * @param session session handle, can be NULL
 * @param ats performance data for the address
 * @param ats_count number of performance records in @a ats
 * @return handle to the address representation inside ATS, NULL
 *         on error (i.e. ATS knows this exact address already)
 */
struct GNUNET_ATS_AddressRecord *
GNUNET_ATS_address_add (struct GNUNET_ATS_SchedulingHandle *sh,
                        const struct GNUNET_HELLO_Address *address,
                        struct Session *session,
                        const struct GNUNET_ATS_Information *ats,
                        uint32_t ats_count)
{
  struct GNUNET_ATS_AddressRecord *ar;
  size_t namelen;
  size_t msize;
  uint32_t s;

  if (NULL == address)
  {
    /* we need a valid address */
    GNUNET_break (0);
    return NULL;
  }
  namelen = (NULL == address->transport_name)
    ? 0
    : strlen (address->transport_name) + 1;
  msize = address->address_length +
    ats_count * sizeof (struct GNUNET_ATS_Information) + namelen;
  if ((msize + sizeof (struct AddressUpdateMessage) >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
      (address->address_length >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
      (namelen >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
      (ats_count >=
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_ATS_Information)))
  {
    /* address too large for us, this should not happen */
    GNUNET_break (0);
    return NULL;
  }

  if (NOT_FOUND !=
      find_session_id (sh,
                       session,
                       address))
  {
    /* Already existing, nothing todo, but this should not happen */
    GNUNET_break (0);
    return NULL;
  }
  s = find_empty_session_slot (sh);
  ar = GNUNET_new (struct GNUNET_ATS_AddressRecord);
  ar->sh = sh;
  ar->slot = s;
  ar->session = session;
  ar->address = GNUNET_HELLO_address_copy (address);
  GNUNET_array_grow (ar->ats,
                     ar->ats_count,
                     ats_count);
  memcpy (ar->ats,
          ats,
          ats_count * sizeof (struct GNUNET_ATS_Information));
  sh->session_array[s] = ar;
  send_add_address_message (sh, ar);
  return ar;
}


/**
 * An address was used to initiate a session.
 *
 * @param ar address record to update information for
 * @param session session handle
 */
void
GNUNET_ATS_address_add_session (struct GNUNET_ATS_AddressRecord *ar,
                                struct Session *session)
{
  GNUNET_break (NULL == ar->session);
  ar->session = session;
}


/**
 * A session was destroyed, disassociate it from the
 * given address record.  If this was an incoming
 * addess, destroy the address as well.
 *
 * @param ar address record to update information for
 * @param session session handle
 * @return #GNUNET_YES if the @a ar was destroyed because
 *                     it was an incoming address,
 *         #GNUNET_NO if the @ar was kept because we can
 *                    use it still to establish a new session
 */
int
GNUNET_ATS_address_del_session (struct GNUNET_ATS_AddressRecord *ar,
                                struct Session *session)
{
  GNUNET_break (session == ar->session);
  ar->session = NULL;
  if (GNUNET_HELLO_address_check_option (ar->address,
                                         GNUNET_HELLO_ADDRESS_INFO_INBOUND))
  {
    GNUNET_ATS_address_destroy (ar);
    return GNUNET_YES;
  }
  return GNUNET_NO;
}


/**
 * We have updated performance statistics for a given address.  Note
 * that this function can be called for addresses that are currently
 * in use as well as addresses that are valid but not actively in use.
 * Furthermore, the peer may not even be connected to us right now (in
 * which case the call may be ignored or the information may be stored
 * for later use).  Update bandwidth assignments.
 *
 * @param ar address record to update information for
 * @param ats performance data for the address
 * @param ats_count number of performance records in @a ats
 */
void
GNUNET_ATS_address_update (struct GNUNET_ATS_AddressRecord *ar,
                           const struct GNUNET_ATS_Information *ats,
                           uint32_t ats_count)
{
  struct GNUNET_ATS_SchedulingHandle *sh = ar->sh;
  struct GNUNET_MQ_Envelope *ev;
  struct AddressUpdateMessage *m;
  struct GNUNET_ATS_Information *am;
  size_t msize;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Updating address for peer `%s', plugin `%s', session %p slot %u\n",
       GNUNET_i2s (&ar->address->peer),
       ar->address->transport_name,
       ar->session,
       ar->slot);
  GNUNET_array_grow (ar->ats,
                     ar->ats_count,
                     ats_count);
  memcpy (ar->ats,
          ats,
          ats_count * sizeof (struct GNUNET_ATS_Information));

  if (NULL == sh->mq)
    return; /* disconnected, skip for now */
  msize = ar->ats_count * sizeof (struct GNUNET_ATS_Information);
  ev = GNUNET_MQ_msg_extra (m, msize, GNUNET_MESSAGE_TYPE_ATS_ADDRESS_UPDATE);
  m->ats_count = htonl (ar->ats_count);
  m->peer = ar->address->peer;
  m->session_id = htonl (ar->slot);
  am = (struct GNUNET_ATS_Information *) &m[1];
  memcpy (am,
          ar->ats,
          ar->ats_count * sizeof (struct GNUNET_ATS_Information));
  GNUNET_MQ_send (sh->mq, ev);
}



/**
 * An address got destroyed, stop using it as a valid address.
 *
 * @param ar address to destroy
 */
void
GNUNET_ATS_address_destroy (struct GNUNET_ATS_AddressRecord *ar)
{
  struct GNUNET_ATS_SchedulingHandle *sh = ar->sh;
  struct GNUNET_MQ_Envelope *ev;
  struct AddressDestroyedMessage *m;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Deleting address for peer `%s', plugin `%s', slot %u session %p\n",
       GNUNET_i2s (&ar->address->peer),
       ar->address->transport_name,
       ar->slot,
       ar->session);
  GNUNET_break (NULL == ar->session);
  ar->session = NULL;
  ar->in_destroy = GNUNET_YES;
  GNUNET_array_grow (ar->ats,
                     ar->ats_count,
                     0);
  if (NULL == sh->mq)
    return;
  ev = GNUNET_MQ_msg (m, GNUNET_MESSAGE_TYPE_ATS_ADDRESS_DESTROYED);
  m->session_id = htonl (ar->slot);
  m->peer = ar->address->peer;
  GNUNET_MQ_send (sh->mq, ev);
}


/* end of ats_api_scheduling.c */
