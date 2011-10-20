/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 */
#include "platform.h"
#include "gnunet_ats_service.h"
#include "ats.h"


/**
 * Message in linked list we should send to the ATS service.  The
 * actual binary message follows this struct.
 */
struct PendingMessage
{

  /**
   * Kept in a DLL.
   */ 
  struct PendingMessage *next;

  /**
   * Kept in a DLL.
   */ 
  struct PendingMessage *prev;

  /**
   * Size of the message.
   */
  size_t size;

  /**
   * Is this the 'ATS_START' message?
   */ 
  int is_init;
};


/**
 * Information we track per session.
 */
struct SessionRecord
{
  /**
   * Identity of the peer (just needed for error checking).
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Session handle.
   */
  struct Session *session;

  /**
   * Set to GNUNET_YES if the slot is used.
   */
  int slot_used;
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
   * Closure for 'suggest_cb'.
   */
  void *suggest_cb_cls;

  /**
   * Connection to ATS service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Head of list of messages for the ATS service.
   */
  struct PendingMessage *pending_head;

  /**
   * Tail of list of messages for the ATS service
   */
  struct PendingMessage *pending_tail;

  /**
   * Current request for transmission to ATS.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Array of session objects (we need to translate them to numbers and back
   * for the protocol; the offset in the array is the session number on the
   * network).  Index 0 is always NULL and reserved to represent the NULL pointer.
   * Unused entries are also NULL.
   */
  struct SessionRecord *session_array;

  /**
   * Task to trigger reconnect.
   */ 
  GNUNET_SCHEDULER_TaskIdentifier task;
  
  /**
   * Size of the session array.
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

  sh->task = GNUNET_SCHEDULER_NO_TASK;
  reconnect (sh);
}


/**
 * Transmit messages from the message queue to the service
 * (if there are any, and if we are not already trying).
 *
 * @param sh handle to use
 */
static void
do_transmit (struct GNUNET_ATS_SchedulingHandle *sh);


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls the 'struct GNUNET_ATS_SchedulingHandle'
 * @param msg message received, NULL on timeout or fatal error
 */
static void
process_ats_message (void *cls,
		     const struct GNUNET_MessageHeader *msg);


/**
 * We can now transmit a message to ATS. Do it.
 *
 * @param cls the 'struct GNUNET_ATS_SchedulingHandle'
 * @param size number of bytes we can transmit to ATS
 * @param buf where to copy the messages
 * @return number of bytes copied into buf
 */
static size_t
transmit_message_to_ats (void *cls,
			 size_t size,
			 void *buf)
{
  struct GNUNET_ATS_SchedulingHandle *sh = cls;
  struct PendingMessage *p;
  size_t ret;
  char *cbuf;

  sh->th = NULL;
  ret = 0;
  cbuf = buf;
  while ( (NULL != (p = sh->pending_head)) &&
	  (p->size <= size) )
  {
    memcpy (&cbuf[ret], &p[1], p->size);    
    ret += p->size;
    size -= p->size;
    GNUNET_CONTAINER_DLL_remove (sh->pending_head,
				 sh->pending_tail,
				 p);
    if (GNUNET_YES == p->is_init)
      GNUNET_CLIENT_receive (sh->client,
			     &process_ats_message, sh,
			     GNUNET_TIME_UNIT_FOREVER_REL);
    GNUNET_free (p);
  }
  do_transmit (sh);
  return ret;
}


/**
 * Transmit messages from the message queue to the service
 * (if there are any, and if we are not already trying).
 *
 * @param sh handle to use
 */
static void
do_transmit (struct GNUNET_ATS_SchedulingHandle *sh)
{
  struct PendingMessage *p;

  if (NULL != sh->th)
    return;
  if (NULL == (p = sh->pending_head))
    return;
  if (NULL == sh->client)
    return; /* currently reconnecting */
  sh->th = GNUNET_CLIENT_notify_transmit_ready (sh->client,
						p->size,
						GNUNET_TIME_UNIT_FOREVER_REL,
						GNUNET_YES,
						&transmit_message_to_ats, sh);
}


/**
 * Find the session object corresponding to the given session ID.
 *
 * @param sh our handle
 * @param session_id current session ID
 * @param peer peer the session belongs to
 * @return the session object (or NULL)
 */
static struct Session*
find_session (struct GNUNET_ATS_SchedulingHandle *sh,
	      uint32_t session_id,
	      const struct GNUNET_PeerIdentity *peer)
{
  if (session_id >= sh->session_array_size)
  {
    GNUNET_break (0);
    return NULL;
  }
  if (session_id == 0)
    return NULL;
  GNUNET_assert (0 == memcmp (peer,
			      &sh->session_array[session_id].peer,
			      sizeof (struct GNUNET_PeerIdentity)));
  return sh->session_array[session_id].session;
}


/**
 * Get the ID for the given session object.  If we do not have an ID for
 * the given session object, allocate one.
 *
 * @param sh our handle
 * @param session session object
 * @param peer peer the session belongs to
 * @return the session id
 */
static uint32_t 
get_session_id (struct GNUNET_ATS_SchedulingHandle *sh,
		struct Session *session,
		const struct GNUNET_PeerIdentity *peer)
{
  unsigned int i;
  unsigned int f;
  
  if (NULL == session)
    return 0;
  f = 0;
  for (i=1;i<sh->session_array_size;i++)
  {
    if (session == sh->session_array[i].session)
    {
      GNUNET_assert (0 == memcmp (peer,
				  &sh->session_array[i].peer,
				  sizeof (struct GNUNET_PeerIdentity)));
      return i;
    }
    if ( (f == 0) &&
	 (sh->session_array[i].slot_used == GNUNET_NO) )
      f = i;
  }
  if (f == 0)
  {    
    f = sh->session_array_size;
    GNUNET_array_grow (sh->session_array,
		       sh->session_array_size,
		       sh->session_array_size * 2);
  }
  GNUNET_assert (f > 0);
  sh->session_array[f].session = session;
  sh->session_array[f].peer = *peer;
  sh->session_array[f].slot_used = GNUNET_YES;
  return f;
}


/**
 * Remove the session of the given session ID from the session
 * table (it is no longer valid).
 *
 * @param sh our handle
 * @param session_id identifies session that is no longer valid
 * @param peer peer the session belongs to
 */
static void
remove_session (struct GNUNET_ATS_SchedulingHandle *sh,
		uint32_t session_id,
		const struct GNUNET_PeerIdentity *peer)
{
  if (0 == session_id)
    return;
  GNUNET_assert (session_id < sh->session_array_size);
  GNUNET_assert (GNUNET_YES == sh->session_array[session_id].slot_used);
  GNUNET_assert (0 == memcmp (peer,
			      &sh->session_array[session_id].peer,
			      sizeof (struct GNUNET_PeerIdentity)));
  sh->session_array[session_id].session = NULL;
}


/**
 * Release the session slot from the session table (ATS service is
 * also done using it).
 *
 * @param sh our handle
 * @param session_id identifies session that is no longer valid
 * @param peer peer the session belongs to
 */
static void
release_session (struct GNUNET_ATS_SchedulingHandle *sh,
		 uint32_t session_id,
		 const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_assert (session_id < sh->session_array_size);
  GNUNET_assert (0 == memcmp (peer,
			      &sh->session_array[session_id].peer,
			      sizeof (struct GNUNET_PeerIdentity)));
  sh->session_array[session_id].slot_used = GNUNET_NO;
  memset (&sh->session_array[session_id].peer,
	  0, 
	  sizeof (struct GNUNET_PeerIdentity));
}


static void
process_release_message (struct GNUNET_ATS_SchedulingHandle *sh,
			 const struct SessionReleaseMessage *srm)
{
  release_session (sh,
		   ntohl (srm->session_id),
		   &srm->peer);
}


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls the 'struct GNUNET_ATS_SchedulingHandle'
 * @param msg message received, NULL on timeout or fatal error
 */
static void
process_ats_message (void *cls,
		     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_ATS_SchedulingHandle *sh = cls;
  const struct AddressSuggestionMessage *m;
  const struct GNUNET_ATS_Information *atsi;
  const char *address;
  const char *plugin_name;
  uint16_t address_length;
  uint16_t plugin_name_length;
  uint32_t ats_count;

  if (NULL == msg) 
  {
    GNUNET_CLIENT_disconnect (sh->client, GNUNET_NO);
    sh->client = NULL;
    sh->task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
					     &reconnect_task, sh);
    return;
  }
  if ( (ntohs (msg->type) == GNUNET_MESSAGE_TYPE_ATS_SESSION_RELEASE) &&
       (ntohs (msg->size) == sizeof (struct SessionReleaseMessage)) )
  {
    process_release_message (sh,
			     (const struct SessionReleaseMessage*) msg);
    GNUNET_CLIENT_receive (sh->client,
			   &process_ats_message, sh,
			   GNUNET_TIME_UNIT_FOREVER_REL);
    return;
  }
  if ( (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_ATS_ADDRESS_SUGGESTION) ||
       (ntohs (msg->size) <= sizeof (struct AddressSuggestionMessage)) )
  {
    GNUNET_break (0);
    GNUNET_CLIENT_disconnect (sh->client, GNUNET_NO);
    sh->client = NULL;
    sh->task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
					     &reconnect_task, sh);
    return;
  }
  m = (const struct AddressSuggestionMessage*) msg;
  ats_count = ntohl (m->ats_count);
  address_length = ntohs (m->address_length);
  atsi = (const struct GNUNET_ATS_Information*) &m[1];
  address = (const char*) &atsi[ats_count];
  plugin_name = &address[address_length];
  plugin_name_length = ntohs (m->plugin_name_length);
  if ( (address_length +
	plugin_name_length +
	ats_count * sizeof (struct GNUNET_ATS_Information) +
	sizeof (struct AddressSuggestionMessage) != ntohs (msg->size))  ||
       (ats_count > GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_ATS_Information)) ||
       (plugin_name[plugin_name_length - 1] != '\0') )
  {
    GNUNET_break (0);
    GNUNET_CLIENT_disconnect (sh->client, GNUNET_NO);
    sh->client = NULL;
    sh->task = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS,
					     &reconnect_task, sh);
    return;
  }
  sh->suggest_cb (sh->suggest_cb_cls,
		  &m->peer,
		  plugin_name,
		  address, address_length,
		  find_session (sh, ntohl (m->session_id), &m->peer),
		  m->bandwidth_out,
		  m->bandwidth_in,
		  atsi,
		  ats_count);
  GNUNET_CLIENT_receive (sh->client,
			 &process_ats_message, sh,
			 GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Re-establish the connection to the ATS service.
 *
 * @param sh handle to use to re-connect.
 */
static void
reconnect (struct GNUNET_ATS_SchedulingHandle *sh)
{
  struct PendingMessage *p;
  struct ClientStartMessage *init;

  GNUNET_assert (NULL == sh->client);
  sh->client = GNUNET_CLIENT_connect ("ats", sh->cfg);
  GNUNET_assert (NULL != sh->client);
  if ( (NULL == (p = sh->pending_head)) ||
       (GNUNET_YES != p->is_init) )
  {
    p = GNUNET_malloc (sizeof (struct PendingMessage) +
		       sizeof (struct ClientStartMessage));
    p->size = sizeof (struct ClientStartMessage);
    p->is_init = GNUNET_YES;
    init = (struct ClientStartMessage *) &p[1];
    init->header.type = htons (GNUNET_MESSAGE_TYPE_ATS_START);
    init->header.size = htons (sizeof (struct ClientStartMessage));
    init->start_flag = htonl (START_FLAG_SCHEDULING);
    GNUNET_CONTAINER_DLL_insert (sh->pending_head,
				 sh->pending_tail,
				 p);
  }
  do_transmit (sh);
}


/**
 * Initialize the ATS subsystem.
 *
 * @param cfg configuration to use
 * @param suggest_cb notification to call whenever the suggestation changed
 * @param suggest_cb_cls closure for 'suggest_cb'
 * @return ats context
 */
struct GNUNET_ATS_SchedulingHandle *
GNUNET_ATS_scheduling_init (const struct GNUNET_CONFIGURATION_Handle *cfg,
			    GNUNET_ATS_AddressSuggestionCallback suggest_cb,
			    void *suggest_cb_cls)
{
  struct GNUNET_ATS_SchedulingHandle *sh;

  sh = GNUNET_malloc (sizeof (struct GNUNET_ATS_SchedulingHandle));
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
  struct PendingMessage *p;

  while (NULL != (p = sh->pending_head))
  {
    GNUNET_CONTAINER_DLL_remove (sh->pending_head,
				 sh->pending_tail,
				 p);
    GNUNET_free (p);
  }
  if (NULL != sh->client)
  {
    GNUNET_CLIENT_disconnect (sh->client, GNUNET_NO);
    sh->client = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != sh->task)
  {
    GNUNET_SCHEDULER_cancel (sh->task);
    sh->task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_array_grow (sh->session_array,
		     sh->session_array_size,
		     0);
  GNUNET_free (sh);
}


/**
 * We would like to establish a new connection with a peer.  ATS
 * should suggest a good address to begin with.
 *
 * @param sh handle
 * @param peer identity of the peer we need an address for
 */
void
GNUNET_ATS_suggest_address (struct GNUNET_ATS_SchedulingHandle *sh,
                            const struct GNUNET_PeerIdentity *peer)
{
  struct PendingMessage *p;
  struct RequestAddressMessage *m;

  p = GNUNET_malloc (sizeof (struct PendingMessage) +
		     sizeof (struct RequestAddressMessage));
  p->size = sizeof (struct RequestAddressMessage);
  p->is_init = GNUNET_NO;
  m = (struct RequestAddressMessage*) &p[1];
  m->header.type = htons (GNUNET_MESSAGE_TYPE_ATS_REQUEST_ADDRESS);
  m->header.size = htons (sizeof (struct RequestAddressMessage));
  m->reserved = htonl (0);
  m->peer = *peer;
  GNUNET_CONTAINER_DLL_insert_tail (sh->pending_head,
				    sh->pending_tail,
				    p);
  do_transmit (sh);
}


/**
 * We have updated performance statistics for a given address.  Note
 * that this function can be called for addresses that are currently
 * in use as well as addresses that are valid but not actively in use.
 * Furthermore, the peer may not even be connected to us right now (in
 * which case the call may be ignored or the information may be stored
 * for later use).  Update bandwidth assignments.
 *
 * @param sh handle
 * @param peer identity of the new peer
 * @param plugin_name name of the transport plugin
 * @param plugin_addr address  (if available)
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param session session handle (if available)
 * @param ats performance data for the address
 * @param ats_count number of performance records in 'ats'
 */
void
GNUNET_ATS_address_update (struct GNUNET_ATS_SchedulingHandle *sh,
                           const struct GNUNET_PeerIdentity *peer,
                           const char *plugin_name,
                           const void *plugin_addr, size_t plugin_addr_len,
			   struct Session *session,
                           const struct GNUNET_ATS_Information *ats,
                           uint32_t ats_count)
{
  struct PendingMessage *p;
  struct AddressUpdateMessage *m;
  struct GNUNET_ATS_Information *am;
  char *pm;
  size_t namelen;
  size_t msize;

  namelen = (plugin_name == NULL) ? 0 : strlen (plugin_name) + 1;						
  msize = sizeof (struct AddressUpdateMessage) + plugin_addr_len + 
    ats_count * sizeof (struct GNUNET_ATS_Information) + namelen;
  if ( (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
       (plugin_addr_len  >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
       (namelen  >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
       (ats_count >= GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_ATS_Information)) )
  {
    GNUNET_break (0);
    return;
  }
  p = GNUNET_malloc (sizeof (struct PendingMessage) +  msize);
  p->size = msize;
  p->is_init = GNUNET_NO;
  m = (struct AddressUpdateMessage*) &p[1];
  m->header.type = htons (GNUNET_MESSAGE_TYPE_ATS_ADDRESS_UPDATE);
  m->header.size = htons (msize);
  m->ats_count = htonl (ats_count);
  m->peer = *peer;
  m->address_length = htons (plugin_addr_len);
  m->plugin_name_length = htons (namelen);
  m->session_id = htonl (get_session_id (sh, session, peer));
  am = (struct GNUNET_ATS_Information*) &m[1];
  memcpy (am, ats, ats_count * sizeof (struct GNUNET_ATS_Information));
  pm = (char *) &am[ats_count];
  memcpy (pm, plugin_addr, plugin_addr_len);
  memcpy (&pm[plugin_addr_len], plugin_name, namelen);
  GNUNET_CONTAINER_DLL_insert_tail (sh->pending_head,
				    sh->pending_tail,
				    p);
  do_transmit (sh);
}


/**
 * A session got destroyed, stop including it as a valid address.
 *
 * @param sh handle
 * @param peer identity of the peer
 * @param plugin_name name of the transport plugin
 * @param plugin_addr address  (if available)
 * @param plugin_addr_len number of bytes in plugin_addr
 * @param session session handle that is no longer valid
 */
void
GNUNET_ATS_address_destroyed (struct GNUNET_ATS_SchedulingHandle *sh,
                              const struct GNUNET_PeerIdentity *peer,
			      const char *plugin_name,
			      const void *plugin_addr, 
			      size_t plugin_addr_len,
			      struct Session *session)
{
  struct PendingMessage *p;
  struct AddressDestroyedMessage *m;
  char *pm;
  size_t namelen;
  size_t msize;
  uint32_t session_id;

  namelen = (plugin_name == NULL) ? 0 : strlen (plugin_name) + 1;						
  msize = sizeof (struct AddressDestroyedMessage) + plugin_addr_len + 
    namelen;
  if ( (msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
       (plugin_addr_len  >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
       (namelen  >= GNUNET_SERVER_MAX_MESSAGE_SIZE) )
  {
    GNUNET_break (0);
    return;
  }
  p = GNUNET_malloc (sizeof (struct PendingMessage) +  msize);
  p->size = msize;
  p->is_init = GNUNET_NO;
  m = (struct AddressDestroyedMessage*) &p[1];
  m->header.type = htons (GNUNET_MESSAGE_TYPE_ATS_ADDRESS_DESTROYED);
  m->header.size = htons (msize);
  m->reserved = htonl (0);
  m->peer = *peer;
  m->address_length = htons (plugin_addr_len);
  m->plugin_name_length = htons (namelen);
  m->session_id = htonl (session_id = get_session_id (sh, session, peer));
  pm = (char *) &m[1];
  memcpy (pm, plugin_addr, plugin_addr_len);
  memcpy (&pm[plugin_addr_len], plugin_name, namelen);
  GNUNET_CONTAINER_DLL_insert_tail (sh->pending_head,
				    sh->pending_tail,
				    p);
  do_transmit (sh);
  remove_session (sh, session_id, peer);
}

/* end of ats_api_scheduling.c */
