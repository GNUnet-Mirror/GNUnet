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


#define INTERFACE_PROCESSING_INTERVALL GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

#define NOT_FOUND 0

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
   * Set to #GNUNET_YES if the slot is used.
   */
  int slot_used;
};


struct ATS_Network
{
  struct ATS_Network * next;

  struct ATS_Network * prev;

  struct sockaddr *network;
  struct sockaddr *netmask;
  socklen_t length;
};

/**
 * Handle for address suggestions
 */
struct GNUNET_ATS_SuggestHandle
{
  struct GNUNET_ATS_SuggestHandle *prev;
  struct GNUNET_ATS_SuggestHandle *next;
  struct GNUNET_PeerIdentity id;
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
   * DLL for suggestions head
   */
  struct GNUNET_ATS_SuggestHandle *sug_head;

  /**
   * DLL for suggestions tail
   */
  struct GNUNET_ATS_SuggestHandle *sug_tail;

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
   * Head of network list
   */
  struct ATS_Network * net_head;

  /**
   * Tail of network list
   */
  struct ATS_Network * net_tail;

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
  struct GNUNET_SCHEDULER_Task * task;

  /**
   * Task retrieving interfaces from the system
   */
  struct GNUNET_SCHEDULER_Task * interface_task;


  /**
   * Size of the session array.
   */
  unsigned int session_array_size;

  /**
   * Should we reconnect to ATS due to some serious error?
   */
  int reconnect;
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
reconnect_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
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
  sh->reconnect = GNUNET_NO;
  GNUNET_CLIENT_disconnect (sh->client);
  sh->client = NULL;
  sh->task =
      GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_SECONDS, &reconnect_task,
                                    sh);
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
process_ats_message (void *cls, const struct GNUNET_MessageHeader *msg);


/**
 * We can now transmit a message to ATS. Do it.
 *
 * @param cls the 'struct GNUNET_ATS_SchedulingHandle'
 * @param size number of bytes we can transmit to ATS
 * @param buf where to copy the messages
 * @return number of bytes copied into buf
 */
static size_t
transmit_message_to_ats (void *cls, size_t size, void *buf)
{
  struct GNUNET_ATS_SchedulingHandle *sh = cls;
  struct PendingMessage *p;
  size_t ret;
  char *cbuf;

  sh->th = NULL;
  if ((size == 0) || (buf == NULL))
  {
    force_reconnect (sh);
    return 0;
  }
  ret = 0;
  cbuf = buf;
  while ((NULL != (p = sh->pending_head)) && (p->size <= size))
  {
    memcpy (&cbuf[ret], &p[1], p->size);
    ret += p->size;
    size -= p->size;
    GNUNET_CONTAINER_DLL_remove (sh->pending_head, sh->pending_tail, p);
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
    return;                     /* currently reconnecting */
  sh->th =
      GNUNET_CLIENT_notify_transmit_ready (sh->client, p->size,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_NO, &transmit_message_to_ats,
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
static struct Session *
find_session (struct GNUNET_ATS_SchedulingHandle *sh, uint32_t session_id,
              const struct GNUNET_PeerIdentity *peer)
{

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "ats-scheduling-api",
              "Find session %u from peer %s in %p\n",
              (unsigned int) session_id, GNUNET_i2s (peer), sh);

  if (session_id >= sh->session_array_size)
  {
    GNUNET_break (0);
    return NULL;
  }
  if (0 == session_id)
    return NULL;
  if (sh->session_array[session_id].session == NULL)
  {
    GNUNET_break (0 ==
                  memcmp (peer, &sh->session_array[session_id].peer,
                          sizeof (struct GNUNET_PeerIdentity)));
    return NULL;
  }

  if (0 !=
      memcmp (peer, &sh->session_array[session_id].peer,
              sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break (0);
    sh->reconnect = GNUNET_YES;
    return NULL;
  }
  /* This check exploits the fact that first field of a session object
   * is peer identity.
   */
  if (0 !=
      memcmp (peer, sh->session_array[session_id].session,
              sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "ats-scheduling-api",
              "Session %p belongs to peer `%s'\n",
              sh->session_array[session_id].session, GNUNET_i2s_full ((struct GNUNET_PeerIdentity *) &sh->session_array[session_id].peer));
/*
    GNUNET_break (0);
    sh->reconnect = GNUNET_YES;
    return NULL;
*/
  }
  return sh->session_array[session_id].session;
}


/**
 * Get an available session ID for the given session object.
 *
 * @param sh our handle
 * @param session session object
 * @param peer peer the session belongs to
 * @return the session id
 */
static uint32_t
find_empty_session_slot (struct GNUNET_ATS_SchedulingHandle *sh, struct Session *session,
                const struct GNUNET_PeerIdentity *peer)
{
  unsigned int i;
  unsigned int f;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "ats-scheduling-api",
              "Get session ID for session %p from peer %s in %p\n", session,
              GNUNET_i2s (peer), sh);

  if (NULL == session)
    return NOT_FOUND;
  f = 0;
  for (i = 1; i < sh->session_array_size; i++)
  {
    if ((f == 0) && (sh->session_array[i].slot_used == GNUNET_NO))
      f = i;
  }
  if (f == 0)
  {
    f = sh->session_array_size;
    GNUNET_array_grow (sh->session_array, sh->session_array_size,
                       sh->session_array_size * 2);
  }
  GNUNET_assert (f > 0);
  sh->session_array[f].session = session;
  sh->session_array[f].peer = *peer;
  sh->session_array[f].slot_used = GNUNET_YES;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "ats-scheduling-api",
              "Assigning session ID %u for session %p of peer %s in %p\n", f,
              session, GNUNET_i2s (peer), sh);

  return f;
}


/**
 * Get the ID for the given session object.
 *
 * @param sh our handle
 * @param session session object
 * @param peer peer the session belongs to
 * @return the session id or NOT_FOUND for error
 */
static uint32_t
find_session_id (struct GNUNET_ATS_SchedulingHandle *sh, struct Session *session,
                const struct GNUNET_PeerIdentity *peer)
{
  unsigned int i;
  char * p2;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "ats-scheduling-api",
              "Get session ID for session %p from peer %s in %p\n", session,
              GNUNET_i2s (peer), sh);

  if (NULL == session)
    return NOT_FOUND;
  for (i = 1; i < sh->session_array_size; i++)
  {
    if (session == sh->session_array[i].session)
    {
      if (0 != memcmp (peer, &sh->session_array[i].peer,
                       sizeof (struct GNUNET_PeerIdentity)))
      {
        p2 = strdup (GNUNET_i2s (&sh->session_array[i].peer));
        GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, "ats-scheduling-api",
                    "Session %p did not match: old session was for peer `%s' new session is for `%s'\n",
                    session, GNUNET_i2s (peer), p2);
        GNUNET_free (p2);
        return NOT_FOUND;
      }
      return i;
    }
  }
  return NOT_FOUND;
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
remove_session (struct GNUNET_ATS_SchedulingHandle *sh, uint32_t session_id,
                const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_assert (peer != NULL);
  GNUNET_assert (sh != NULL);

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "ats-scheduling-api",
              "Release sessionID %u from peer %s in %p\n",
              (unsigned int) session_id, GNUNET_i2s (peer), sh);

  if (0 == session_id)
    return;

  GNUNET_assert (session_id < sh->session_array_size);
  GNUNET_assert (GNUNET_YES == sh->session_array[session_id].slot_used);
  GNUNET_assert (0 == memcmp (peer,
                              &sh->session_array[session_id].peer,
                              sizeof (struct GNUNET_PeerIdentity)));
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "ats-scheduling-api",
              "Session %p for peer `%s' removed from slot %u \n",
              sh->session_array[session_id].session,
              GNUNET_i2s (peer),
              session_id);
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
release_session (struct GNUNET_ATS_SchedulingHandle *sh, uint32_t session_id,
                 const struct GNUNET_PeerIdentity *peer)
{

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "ats-scheduling-api",
              "Release sessionID %u from peer %s in %p\n",
              (unsigned int) session_id, GNUNET_i2s (peer), sh);

  if (session_id >= sh->session_array_size)
  {
    GNUNET_break (0);
    sh->reconnect = GNUNET_YES;
    return;
  }

  /* this slot should have been removed from remove_session before */
  GNUNET_assert (sh->session_array[session_id].session == NULL);

  if (0 !=
      memcmp (peer, &sh->session_array[session_id].peer,
              sizeof (struct GNUNET_PeerIdentity)))
  {
    GNUNET_break (0);
    sh->reconnect = GNUNET_YES;
    return;
  }
  sh->session_array[session_id].slot_used = GNUNET_NO;
  memset (&sh->session_array[session_id].peer, 0,
          sizeof (struct GNUNET_PeerIdentity));
}


static void
process_release_message (struct GNUNET_ATS_SchedulingHandle *sh,
                         const struct SessionReleaseMessage *srm)
{
  release_session (sh, ntohl (srm->session_id), &srm->peer);
}


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls the 'struct GNUNET_ATS_SchedulingHandle'
 * @param msg message received, NULL on timeout or fatal error
 */
static void
process_ats_message (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_ATS_SchedulingHandle *sh = cls;
  const struct AddressSuggestionMessage *m;
  const struct GNUNET_ATS_Information *atsi;
  const char *plugin_address;
  const char *plugin_name;
  uint16_t plugin_address_length;
  uint16_t plugin_name_length;
  uint32_t ats_count;
  struct GNUNET_HELLO_Address address;
  struct Session *s;

  if (NULL == msg)
  {
    force_reconnect (sh);
    return;
  }
  if ((ntohs (msg->type) == GNUNET_MESSAGE_TYPE_ATS_SESSION_RELEASE) &&
      (ntohs (msg->size) == sizeof (struct SessionReleaseMessage)))
  {
    process_release_message (sh, (const struct SessionReleaseMessage *) msg);
    GNUNET_CLIENT_receive (sh->client, &process_ats_message, sh,
                           GNUNET_TIME_UNIT_FOREVER_REL);
    if (GNUNET_YES == sh->reconnect)
      force_reconnect (sh);
    return;
  }
  if ((ntohs (msg->type) != GNUNET_MESSAGE_TYPE_ATS_ADDRESS_SUGGESTION) ||
      (ntohs (msg->size) <= sizeof (struct AddressSuggestionMessage)))
  {
    GNUNET_break (0);
    force_reconnect (sh);
    return;
  }
  m = (const struct AddressSuggestionMessage *) msg;
  ats_count = ntohl (m->ats_count);
  plugin_address_length = ntohs (m->address_length);
  atsi = (const struct GNUNET_ATS_Information *) &m[1];
  plugin_address = (const char *) &atsi[ats_count];
  plugin_name = &plugin_address[plugin_address_length];
  plugin_name_length = ntohs (m->plugin_name_length);
  if ((plugin_address_length + plugin_name_length +
       ats_count * sizeof (struct GNUNET_ATS_Information) +
       sizeof (struct AddressSuggestionMessage) != ntohs (msg->size)) ||
      (ats_count >
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_ATS_Information))
      || (plugin_name[plugin_name_length - 1] != '\0'))
  {
    GNUNET_break (0);
    force_reconnect (sh);
    return;
  }
  uint32_t session_id = ntohl (m->session_id);

  if (session_id == 0)
    s = NULL;
  else
  {
    s = find_session (sh, session_id, &m->peer);
    if (s == NULL)
    {

      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "ats-scheduling-api",
                  "ATS tries to use outdated session `%s'\n",
                  GNUNET_i2s (&m->peer));
      GNUNET_CLIENT_receive (sh->client, &process_ats_message, sh,
                             GNUNET_TIME_UNIT_FOREVER_REL);
      return;
    }
  }

  if (NULL == sh->suggest_cb)
  	return;

  address.peer = m->peer;
  address.address = plugin_address;
  address.address_length = plugin_address_length;
  address.transport_name = plugin_name;
  address.local_info = ntohl(m->address_local_info);

  if ((s == NULL) && (0 == address.address_length))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "ATS returned invalid address for peer `%s' transport `%s' address length %i, session_id %i\n",
                GNUNET_i2s (&address.peer), address.transport_name,
                plugin_address_length, session_id);
    GNUNET_break_op (0);
    GNUNET_CLIENT_receive (sh->client, &process_ats_message, sh,
                           GNUNET_TIME_UNIT_FOREVER_REL);
    return;
  }

  sh->suggest_cb (sh->suggest_cb_cls,
                  (const struct GNUNET_PeerIdentity *) &m->peer,
                  &address, s, m->bandwidth_out,
                  m->bandwidth_in, atsi, ats_count);

  GNUNET_CLIENT_receive (sh->client, &process_ats_message, sh,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  if (GNUNET_YES == sh->reconnect)
    force_reconnect (sh);
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
  GNUNET_CLIENT_receive (sh->client, &process_ats_message, sh,
                           GNUNET_TIME_UNIT_FOREVER_REL);
  if ((NULL == (p = sh->pending_head)) || (GNUNET_YES != p->is_init))
  {
    p = GNUNET_malloc (sizeof (struct PendingMessage) +
                       sizeof (struct ClientStartMessage));
    p->size = sizeof (struct ClientStartMessage);
    p->is_init = GNUNET_YES;
    init = (struct ClientStartMessage *) &p[1];
    init->header.type = htons (GNUNET_MESSAGE_TYPE_ATS_START);
    init->header.size = htons (sizeof (struct ClientStartMessage));
    init->start_flag = htonl (START_FLAG_SCHEDULING);
    GNUNET_CONTAINER_DLL_insert (sh->pending_head, sh->pending_tail, p);
  }
  do_transmit (sh);
}


/**
 * delete the current network list
 */
static void
delete_networks (struct GNUNET_ATS_SchedulingHandle *sh)
{
  struct ATS_Network * cur = sh->net_head;
  while (cur != NULL)
  {
    GNUNET_CONTAINER_DLL_remove(sh->net_head, sh->net_tail, cur);
    GNUNET_free (cur);
    cur = sh->net_head;
  }
}


static int
interface_proc (void *cls, const char *name,
                int isDefault,
                const struct sockaddr *
                addr,
                const struct sockaddr *
                broadcast_addr,
                const struct sockaddr *
                netmask, socklen_t addrlen)
{
  struct GNUNET_ATS_SchedulingHandle * sh = cls;
  /* Calculate network */
  struct ATS_Network *net = NULL;

  /* Skipping IPv4 loopback addresses since we have special check  */
  if  (addr->sa_family == AF_INET)
  {
    struct sockaddr_in * a4 = (struct sockaddr_in *) addr;

    if ((a4->sin_addr.s_addr & htonl(0xff000000)) == htonl (0x7f000000))
       return GNUNET_OK;
  }
  /* Skipping IPv6 loopback addresses since we have special check  */
  if  (addr->sa_family == AF_INET6)
  {
    struct sockaddr_in6 * a6 = (struct sockaddr_in6 *) addr;
    if (IN6_IS_ADDR_LOOPBACK (&a6->sin6_addr))
      return GNUNET_OK;
  }

  if (addr->sa_family == AF_INET)
  {
    struct sockaddr_in *addr4 = (struct sockaddr_in *) addr;
    struct sockaddr_in *netmask4 = (struct sockaddr_in *) netmask;
    struct sockaddr_in *tmp = NULL;
    struct sockaddr_in network4;

    net = GNUNET_malloc(sizeof (struct ATS_Network) + 2 * sizeof (struct sockaddr_in));
    tmp = (struct sockaddr_in *) &net[1];
    net->network = (struct sockaddr *) &tmp[0];
    net->netmask = (struct sockaddr *) &tmp[1];
    net->length = addrlen;

    memset (&network4, 0, sizeof (network4));
    network4.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
    network4.sin_len = sizeof (network4);
#endif
    network4.sin_addr.s_addr = (addr4->sin_addr.s_addr & netmask4->sin_addr.s_addr);

    memcpy (net->netmask, netmask4, sizeof (struct sockaddr_in));
    memcpy (net->network, &network4, sizeof (struct sockaddr_in));
  }

  if (addr->sa_family == AF_INET6)
  {
    struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *) addr;
    struct sockaddr_in6 *netmask6 = (struct sockaddr_in6 *) netmask;
    struct sockaddr_in6 * tmp = NULL;
    struct sockaddr_in6 network6;

    net = GNUNET_malloc(sizeof (struct ATS_Network) + 2 * sizeof (struct sockaddr_in6));
    tmp = (struct sockaddr_in6 *) &net[1];
    net->network = (struct sockaddr *) &tmp[0];
    net->netmask = (struct sockaddr *) &tmp[1];
    net->length = addrlen;

    memset (&network6, 0, sizeof (network6));
    network6.sin6_family = AF_INET6;
#if HAVE_SOCKADDR_IN_SIN_LEN
    network6.sin6_len = sizeof (network6);
#endif
    int c = 0;
    uint32_t *addr_elem = (uint32_t *) &addr6->sin6_addr;
    uint32_t *mask_elem = (uint32_t *) &netmask6->sin6_addr;
    uint32_t *net_elem = (uint32_t *) &network6.sin6_addr;
    for (c = 0; c < 4; c++)
      net_elem[c] = addr_elem[c] & mask_elem[c];

    memcpy (net->netmask, netmask6, sizeof (struct sockaddr_in6));
    memcpy (net->network, &network6, sizeof (struct sockaddr_in6));
  }

  /* Store in list */
  if (net != NULL)
  {
#if VERBOSE_ATS
    char * netmask = GNUNET_strdup (GNUNET_a2s((struct sockaddr *) net->netmask, addrlen));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Adding network `%s', netmask `%s'\n",
        GNUNET_a2s((struct sockaddr *) net->network, addrlen),
        netmask);
    GNUNET_free (netmask);
# endif
    GNUNET_CONTAINER_DLL_insert(sh->net_head, sh->net_tail, net);
  }
  return GNUNET_OK;
}


/**
 * Periodically get list of addresses
 * @param cls closure
 * @param tc Task context
 */
static void
get_addresses (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_ATS_SchedulingHandle * sh = cls;
  sh->interface_task = NULL;
  delete_networks (sh);
  GNUNET_OS_network_interfaces_list(interface_proc, sh);
  sh->interface_task = GNUNET_SCHEDULER_add_delayed (INTERFACE_PROCESSING_INTERVALL,
                                                     get_addresses,
                                                     sh);
}


/**
 * Convert a `enum GNUNET_ATS_Network_Type` to a string
 *
 * @param net the network type
 * @return a string or NULL if invalid
 */
const char *
GNUNET_ATS_print_network_type (enum GNUNET_ATS_Network_Type net)
{
  switch (net)
    {
    case GNUNET_ATS_NET_UNSPECIFIED:
      return "UNSPECIFIED";
    case GNUNET_ATS_NET_LOOPBACK:
      return "LOOPBACK";
    case GNUNET_ATS_NET_LAN:
      return "LAN";
    case GNUNET_ATS_NET_WAN:
      return "WAN";
    case GNUNET_ATS_NET_WLAN:
      return "WLAN";
    case GNUNET_ATS_NET_BT:
      return "BLUETOOTH";
    default:
      return NULL;
    }
}


/**
 * Convert a ATS property to a string
 *
 * @param type the property type
 * @return a string or NULL if invalid
 */
const char *
GNUNET_ATS_print_property_type (enum GNUNET_ATS_Property type)
{
  switch (type)
  {
  case GNUNET_ATS_ARRAY_TERMINATOR:
    return "TERMINATOR";
  case GNUNET_ATS_UTILIZATION_OUT:
    return "UTILIZATION_UP";
  case GNUNET_ATS_UTILIZATION_IN:
    return "UTILIZATION_DOWN";
  case GNUNET_ATS_UTILIZATION_PAYLOAD_OUT:
    return "UTILIZATION_PAYLOAD_UP";
  case GNUNET_ATS_UTILIZATION_PAYLOAD_IN:
    return "UTILIZATION_PAYLOAD_DOWN";
  case GNUNET_ATS_NETWORK_TYPE:
    return "NETWORK_TYPE";
  case GNUNET_ATS_QUALITY_NET_DELAY:
    return "DELAY";
  case GNUNET_ATS_QUALITY_NET_DISTANCE:
    return "DISTANCE";
  case GNUNET_ATS_COST_WAN:
    return "COST_WAN";
  case GNUNET_ATS_COST_LAN:
    return "COST_LAN";
  case GNUNET_ATS_COST_WLAN:
    return "COST_WLAN";
  default:
    return NULL;
  }
}


/**
 * Returns where the address is located: LAN or WAN or ...
 *
 * @param sh the scheduling handle
 * @param addr address
 * @param addrlen address length
 * @return location as GNUNET_ATS_Information
 */
struct GNUNET_ATS_Information
GNUNET_ATS_address_get_type (struct GNUNET_ATS_SchedulingHandle * sh, const struct sockaddr * addr, socklen_t addrlen)
{
  GNUNET_assert (sh != NULL);
  struct ATS_Network * cur = sh->net_head;

  int type = GNUNET_ATS_NET_UNSPECIFIED;
  struct GNUNET_ATS_Information ats;

  if  (addr->sa_family == AF_UNIX)
  {
    type = GNUNET_ATS_NET_LOOPBACK;
  }

  /* IPv4 loopback check */
  if  (addr->sa_family == AF_INET)
  {
    struct sockaddr_in * a4 = (struct sockaddr_in *) addr;

    if ((a4->sin_addr.s_addr & htonl(0xff000000)) == htonl (0x7f000000))
      type = GNUNET_ATS_NET_LOOPBACK;
  }
  /* IPv6 loopback check */
  if  (addr->sa_family == AF_INET6)
  {
    struct sockaddr_in6 * a6 = (struct sockaddr_in6 *) addr;
    if (IN6_IS_ADDR_LOOPBACK (&a6->sin6_addr))
      type = GNUNET_ATS_NET_LOOPBACK;
  }

  /* Check local networks */
  while ((cur != NULL) && (type == GNUNET_ATS_NET_UNSPECIFIED))
  {
    if (addrlen != cur->length)
    {
      cur = cur->next;
      continue;
    }

    if (addr->sa_family == AF_INET)
    {
      struct sockaddr_in * a4 = (struct sockaddr_in *) addr;
      struct sockaddr_in * net4 = (struct sockaddr_in *) cur->network;
      struct sockaddr_in * mask4 = (struct sockaddr_in *) cur->netmask;

      if (((a4->sin_addr.s_addr & mask4->sin_addr.s_addr)) == net4->sin_addr.s_addr)
        type = GNUNET_ATS_NET_LAN;
    }
    if (addr->sa_family == AF_INET6)
    {
      struct sockaddr_in6 * a6 = (struct sockaddr_in6 *) addr;
      struct sockaddr_in6 * net6 = (struct sockaddr_in6 *) cur->network;
      struct sockaddr_in6 * mask6 = (struct sockaddr_in6 *) cur->netmask;

      int res = GNUNET_YES;
      int c = 0;
      uint32_t *addr_elem = (uint32_t *) &a6->sin6_addr;
      uint32_t *mask_elem = (uint32_t *) &mask6->sin6_addr;
      uint32_t *net_elem = (uint32_t *) &net6->sin6_addr;
      for (c = 0; c < 4; c++)
        if ((addr_elem[c] & mask_elem[c]) != net_elem[c])
          res = GNUNET_NO;

      if (res == GNUNET_YES)
        type = GNUNET_ATS_NET_LAN;
    }
    cur = cur->next;
  }

  /* no local network found for this address, default: WAN */
  if (type == GNUNET_ATS_NET_UNSPECIFIED)
    type = GNUNET_ATS_NET_WAN;
  ats.type = htonl (GNUNET_ATS_NETWORK_TYPE);
  ats.value = htonl (type);

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "ats-scheduling-api",
                   "`%s' is in network `%s'\n",
                   GNUNET_a2s ((const struct sockaddr *) addr, addrlen),
                   GNUNET_ATS_print_network_type(type));
  return ats;
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

  sh = GNUNET_new (struct GNUNET_ATS_SchedulingHandle);
  sh->cfg = cfg;
  sh->suggest_cb = suggest_cb;
  sh->suggest_cb_cls = suggest_cb_cls;
  GNUNET_array_grow (sh->session_array, sh->session_array_size, 4);
  GNUNET_OS_network_interfaces_list(interface_proc, sh);
  sh->interface_task = GNUNET_SCHEDULER_add_delayed (INTERFACE_PROCESSING_INTERVALL,
      get_addresses,
      sh);
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
  struct GNUNET_ATS_SuggestHandle *cur;
  struct GNUNET_ATS_SuggestHandle *next;
  while (NULL != (p = sh->pending_head))
  {
    GNUNET_CONTAINER_DLL_remove (sh->pending_head, sh->pending_tail, p);
    GNUNET_free (p);
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

  next = sh->sug_head;
  while (NULL != (cur = next))
  {
  		next = cur->next;
  		GNUNET_CONTAINER_DLL_remove (sh->sug_head, sh->sug_tail, cur);
  		GNUNET_free (cur);
  }

  delete_networks (sh);
  if (sh->interface_task != NULL)
  {
    GNUNET_SCHEDULER_cancel(sh->interface_task);
    sh->interface_task = NULL;
  }
  GNUNET_array_grow (sh->session_array, sh->session_array_size, 0);
  GNUNET_free (sh);
  sh = NULL;
}

/**
 * We would like to reset the address suggestion block time for this
 * peer
 *
 * @param sh handle
 * @param peer identity of the peer we want to reset
 */
void
GNUNET_ATS_reset_backoff (struct GNUNET_ATS_SchedulingHandle *sh,
                          const struct GNUNET_PeerIdentity *peer)
{
  struct PendingMessage *p;
  struct ResetBackoffMessage *m;

  p = GNUNET_malloc (sizeof (struct PendingMessage) +
                     sizeof (struct ResetBackoffMessage));
  p->size = sizeof (struct ResetBackoffMessage);
  p->is_init = GNUNET_NO;
  m = (struct ResetBackoffMessage *) &p[1];
  m->header.type = htons (GNUNET_MESSAGE_TYPE_ATS_RESET_BACKOFF);
  m->header.size = htons (sizeof (struct ResetBackoffMessage));
  m->reserved = htonl (0);
  m->peer = *peer;
  GNUNET_CONTAINER_DLL_insert_tail (sh->pending_head, sh->pending_tail, p);
  do_transmit (sh);
}


/**
 * We would like to receive address suggestions for a peer. ATS will
 * respond with a call to the continuation immediately containing an address or
 * no address if none is available. ATS can suggest more addresses until we call
 * #GNUNET_ATS_suggest_address_cancel().
 *
 * @param sh handle
 * @param peer identity of the peer we need an address for
 * @param cont the continuation to call with the address
 * @param cont_cls the cls for the @a cont
 * @return suggest handle
 */
struct GNUNET_ATS_SuggestHandle *
GNUNET_ATS_suggest_address (struct GNUNET_ATS_SchedulingHandle *sh,
                            const struct GNUNET_PeerIdentity *peer,
                            GNUNET_ATS_AddressSuggestionCallback cont,
                            void *cont_cls)
{
  struct PendingMessage *p;
  struct RequestAddressMessage *m;
  struct GNUNET_ATS_SuggestHandle *s;

  // FIXME: ATS needs to remember this in case of
  // a disconnect!
  p = GNUNET_malloc (sizeof (struct PendingMessage) +
                     sizeof (struct RequestAddressMessage));
  p->size = sizeof (struct RequestAddressMessage);
  p->is_init = GNUNET_NO;
  m = (struct RequestAddressMessage *) &p[1];
  m->header.type = htons (GNUNET_MESSAGE_TYPE_ATS_REQUEST_ADDRESS);
  m->header.size = htons (sizeof (struct RequestAddressMessage));
  m->reserved = htonl (0);
  m->peer = *peer;
  GNUNET_CONTAINER_DLL_insert_tail (sh->pending_head, sh->pending_tail, p);
  do_transmit (sh);
  s = GNUNET_new (struct GNUNET_ATS_SuggestHandle);
  s->id = (*peer);
  GNUNET_CONTAINER_DLL_insert_tail (sh->sug_head, sh->sug_tail, s);
  return s;
}


/**
 * We would like to stop receiving address updates for this peer
 *
 * @param sh handle
 * @param peer identity of the peer
 */
void
GNUNET_ATS_suggest_address_cancel (struct GNUNET_ATS_SchedulingHandle *sh,
                                   const struct GNUNET_PeerIdentity *peer)
{
  struct PendingMessage *p;
  struct RequestAddressMessage *m;
  struct GNUNET_ATS_SuggestHandle *s;

  for (s = sh->sug_head; NULL != s; s = s->next)
  	if (0 == memcmp(peer, &s->id, sizeof (s->id)))
  		break;
  if (NULL == s)
  {
  	GNUNET_break (0);
  	return;
  }
  else
  {
  	GNUNET_CONTAINER_DLL_remove (sh->sug_head, sh->sug_tail, s);
  	GNUNET_free (s);
  }

  p = GNUNET_malloc (sizeof (struct PendingMessage) +
                     sizeof (struct RequestAddressMessage));
  p->size = sizeof (struct RequestAddressMessage);
  p->is_init = GNUNET_NO;
  m = (struct RequestAddressMessage *) &p[1];
  m->header.type = htons (GNUNET_MESSAGE_TYPE_ATS_REQUEST_ADDRESS_CANCEL);
  m->header.size = htons (sizeof (struct RequestAddressMessage));
  m->reserved = htonl (0);
  m->peer = *peer;
  GNUNET_CONTAINER_DLL_insert_tail (sh->pending_head, sh->pending_tail, p);
  do_transmit (sh);
}


/**
 * Test if a address and a session is known to ATS
 *
 * @param sh the scheduling handle
 * @param address the address
 * @param session the session
 * @return GNUNET_YES or GNUNET_NO
 */
int
GNUNET_ATS_session_known (struct GNUNET_ATS_SchedulingHandle *sh,
    											const struct GNUNET_HELLO_Address *address,
    											struct Session *session)
{
	int s;
  if (NULL != session)
  {
    if (NOT_FOUND != (s = find_session_id (sh, session, &address->peer)))
    {
      /* Existing */
      return GNUNET_YES;
    }
    return GNUNET_NO;
  }
  return GNUNET_NO;
}

/**
 * We have a new address ATS should know. Addresses have to be added with this
 * function before they can be: updated, set in use and destroyed
 *
 * @param sh handle
 * @param address the address
 * @param session session handle, can be NULL
 * @param ats performance data for the address
 * @param ats_count number of performance records in 'ats'
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GNUNET_ATS_address_add (struct GNUNET_ATS_SchedulingHandle *sh,
                        const struct GNUNET_HELLO_Address *address,
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
  uint32_t s = 0;

  if (address == NULL)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  namelen = (address->transport_name == NULL) ? 0 : strlen (address->transport_name) + 1;

  msize = sizeof (struct AddressUpdateMessage) + address->address_length +
      ats_count * sizeof (struct GNUNET_ATS_Information) + namelen;
  if ((msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
      (address->address_length >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
      (namelen >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
      (ats_count >=
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_ATS_Information)))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  if (NULL != session)
  {
    if (NOT_FOUND != (s = find_session_id (sh, session, &address->peer)))
    {
      /* Already existing, nothing todo */
      return GNUNET_SYSERR;
    }
    s = find_empty_session_slot (sh, session, &address->peer);
    GNUNET_break (NOT_FOUND != s);
  }

  p = GNUNET_malloc (sizeof (struct PendingMessage) + msize);
  p->size = msize;
  p->is_init = GNUNET_NO;
  m = (struct AddressUpdateMessage *) &p[1];
  m->header.type = htons (GNUNET_MESSAGE_TYPE_ATS_ADDRESS_ADD);
  m->header.size = htons (msize);
  m->ats_count = htonl (ats_count);
  m->peer = address->peer;
  m->address_length = htons (address->address_length);
  m->address_local_info = htonl ((uint32_t) address->local_info);
  m->plugin_name_length = htons (namelen);
  m->session_id = htonl (s);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Adding address for peer `%s', plugin `%s', session %p id %u\n",
              GNUNET_i2s (&address->peer),
              address->transport_name, session, s);

  am = (struct GNUNET_ATS_Information *) &m[1];
  memcpy (am, ats, ats_count * sizeof (struct GNUNET_ATS_Information));
  pm = (char *) &am[ats_count];
  memcpy (pm, address->address, address->address_length);
  if (NULL != address->transport_name)
	memcpy (&pm[address->address_length], address->transport_name, namelen);
  GNUNET_CONTAINER_DLL_insert_tail (sh->pending_head, sh->pending_tail, p);
  do_transmit (sh);
  return GNUNET_OK;

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
 * @param address the address
 * @param session session handle, can be NULL
 * @param ats performance data for the address
 * @param ats_count number of performance records in @a ats
 * @return #GNUNET_YES on success, #GNUNET_NO if address or session are unknown,
 * #GNUNET_SYSERR on hard failure
 */
int
GNUNET_ATS_address_update (struct GNUNET_ATS_SchedulingHandle *sh,
                           const struct GNUNET_HELLO_Address *address,
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
  uint32_t s = 0;

  if (NULL == address)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (NULL == sh)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  namelen = (address->transport_name ==
       NULL) ? 0 : strlen (address->transport_name) + 1;
  msize =
      sizeof (struct AddressUpdateMessage) + address->address_length +
      ats_count * sizeof (struct GNUNET_ATS_Information) + namelen;
  if ((msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
      (address->address_length >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
      (namelen >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
      (ats_count >=
       GNUNET_SERVER_MAX_MESSAGE_SIZE / sizeof (struct GNUNET_ATS_Information)))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  if (NULL != session)
  {
    s = find_session_id (sh, session, &address->peer);
    if (NOT_FOUND == s)
      return GNUNET_NO;
  }

  p = GNUNET_malloc (sizeof (struct PendingMessage) + msize);
  p->size = msize;
  p->is_init = GNUNET_NO;
  m = (struct AddressUpdateMessage *) &p[1];
  m->header.type = htons (GNUNET_MESSAGE_TYPE_ATS_ADDRESS_UPDATE);
  m->header.size = htons (msize);
  m->ats_count = htonl (ats_count);
  m->peer = address->peer;
  m->address_length = htons (address->address_length);
  m->address_local_info = htonl ((uint32_t) address->local_info);
  m->plugin_name_length = htons (namelen);

  m->session_id = htonl (s);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Updating address for peer `%s', plugin `%s', session %p id %u\n",
              GNUNET_i2s (&address->peer),
              address->transport_name, session, s);

  am = (struct GNUNET_ATS_Information *) &m[1];
  memcpy (am, ats, ats_count * sizeof (struct GNUNET_ATS_Information));
  pm = (char *) &am[ats_count];
  memcpy (pm, address->address, address->address_length);
  memcpy (&pm[address->address_length], address->transport_name, namelen);
  GNUNET_CONTAINER_DLL_insert_tail (sh->pending_head, sh->pending_tail, p);
  do_transmit (sh);
  return GNUNET_YES;
}


/**
 * An address is now in use or not used any more.
 *
 * @param sh handle
 * @param address the address
 * @param session session handle, can be NULL
 * @param in_use #GNUNET_YES if this address is now used, #GNUNET_NO
 * if address is not used any more
 */
void
GNUNET_ATS_address_in_use (struct GNUNET_ATS_SchedulingHandle *sh,
                           const struct GNUNET_HELLO_Address *address,
                           struct Session *session, int in_use)
{
  struct PendingMessage *p;
  struct AddressUseMessage *m;
  char *pm;
  size_t namelen;
  size_t msize;
  uint32_t s = 0;

  GNUNET_assert (NULL != address);
  namelen =
      (address->transport_name ==
       NULL) ? 0 : strlen (address->transport_name) + 1;
  msize = sizeof (struct AddressUseMessage) + address->address_length + namelen;
  if ((msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
      (address->address_length >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
      (namelen >= GNUNET_SERVER_MAX_MESSAGE_SIZE))
  {
    GNUNET_break (0);
    return;
  }

  if (session != NULL)
  {
    s = find_session_id (sh, session, &address->peer);
    if ((s == NOT_FOUND) && (GNUNET_NO == in_use))
    {
      /* trying to set unknown address to NO */
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Trying to set unknown address to unused for peer `%s', plugin `%s', session %p\n",
                  GNUNET_i2s (&address->peer), address->transport_name, session);
      GNUNET_break (0);
      return;
    }
    if ((s == NOT_FOUND) && (GNUNET_YES == in_use))
    {
      /* trying to set new address to YES */
      s = find_empty_session_slot (sh, session, &address->peer);
      GNUNET_assert (NOT_FOUND != s);
    }
  }

  p = GNUNET_malloc (sizeof (struct PendingMessage) + msize);
  p->size = msize;
  p->is_init = GNUNET_NO;
  m = (struct AddressUseMessage *) &p[1];
  m->header.type = htons (GNUNET_MESSAGE_TYPE_ATS_ADDRESS_IN_USE);
  m->header.size = htons (msize);
  m->peer = address->peer;
  m->in_use = htons (in_use);
  m->address_length = htons (address->address_length);
  m->address_local_info = htonl ((uint32_t) address->local_info);
  m->plugin_name_length = htons (namelen);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Setting address used to %s for peer `%s', plugin `%s', session %p\n",
              (GNUNET_YES == in_use) ? "YES" : "NO",
              GNUNET_i2s (&address->peer), address->transport_name, session);

  m->session_id = htonl (s);
  pm = (char *) &m[1];
  memcpy (pm, address->address, address->address_length);
  memcpy (&pm[address->address_length], address->transport_name, namelen);
  GNUNET_CONTAINER_DLL_insert_tail (sh->pending_head, sh->pending_tail, p);
  do_transmit (sh);
  return;
}


/**
 * An address got destroyed, stop including it as a valid address.
 *
 * If a session is given, only the session will be removed, if no session is
 * given the full address will be deleted.
 *
 * @param sh handle
 * @param address the address
 * @param session session handle that is no longer valid, can be NULL
 */
void
GNUNET_ATS_address_destroyed (struct GNUNET_ATS_SchedulingHandle *sh,
                              const struct GNUNET_HELLO_Address *address,
                              struct Session *session)
{
  struct PendingMessage *p;
  struct AddressDestroyedMessage *m;
  char *pm;
  size_t namelen;
  size_t msize;
  uint32_t s = 0;

  if (address == NULL)
  {
    GNUNET_break (0);
    return;
  }

  GNUNET_assert (address->transport_name != NULL);
  namelen = strlen (address->transport_name) + 1;
  GNUNET_assert (namelen > 1);
  msize =
      sizeof (struct AddressDestroyedMessage) + address->address_length +
      namelen;
  if ((msize >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
      (address->address_length >= GNUNET_SERVER_MAX_MESSAGE_SIZE) ||
      (namelen >= GNUNET_SERVER_MAX_MESSAGE_SIZE))
  {
    GNUNET_break (0);
    return;
  }

  s = find_session_id (sh, session, &address->peer);
  if ((NULL != session) && (NOT_FOUND == s))
  {
    /* trying to delete unknown address */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Trying to delete unknown address for peer `%s', plugin `%s', session %p\n",
                GNUNET_i2s (&address->peer), address->transport_name, session);
    return;
  }

  p = GNUNET_malloc (sizeof (struct PendingMessage) + msize);
  p->size = msize;
  p->is_init = GNUNET_NO;
  m = (struct AddressDestroyedMessage *) &p[1];
  m->header.type = htons (GNUNET_MESSAGE_TYPE_ATS_ADDRESS_DESTROYED);
  m->header.size = htons (msize);
  m->reserved = htonl (0);
  m->peer = address->peer;
  m->address_length = htons (address->address_length);
  m->address_local_info = htonl ((uint32_t) address->local_info);
  m->plugin_name_length = htons (namelen);

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Deleting address for peer `%s', plugin `%s', session %p\n",
              GNUNET_i2s (&address->peer), address->transport_name, session);

  m->session_id = htonl (s);
  pm = (char *) &m[1];
  memcpy (pm, address->address, address->address_length);
  memcpy (&pm[address->address_length], address->transport_name, namelen);
  GNUNET_CONTAINER_DLL_insert_tail (sh->pending_head, sh->pending_tail, p);
  do_transmit (sh);
  remove_session (sh, s, &address->peer);
}

/* end of ats_api_scheduling.c */
