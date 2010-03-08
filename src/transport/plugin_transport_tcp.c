/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file transport/plugin_transport_tcp.c
 * @brief Implementation of the TCP transport service
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_hello_lib.h"
#include "gnunet_connection_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_resolver_service.h"
#include "gnunet_server_lib.h"
#include "gnunet_service_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "plugin_transport.h"
#include "transport.h"

#define DEBUG_TCP GNUNET_NO

/**
 * How long until we give up on transmitting the welcome message?
 */
#define HOSTNAME_RESOLVE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)


/**
 * Initial handshake message for a session.
 */
struct WelcomeMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_WELCOME.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Identity of the node connecting (TCP client)
   */
  struct GNUNET_PeerIdentity clientIdentity;

};


/**
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin;


/**
 * Information kept for each message that is yet to
 * be transmitted.
 */
struct PendingMessage
{

  /**
   * This is a doubly-linked list.
   */
  struct PendingMessage *next;

  /**
   * This is a doubly-linked list.
   */
  struct PendingMessage *prev;

  /**
   * The pending message
   */
  const char *msg;

  /**
   * Continuation function to call once the message
   * has been sent.  Can be NULL if there is no
   * continuation to call.
   */
  GNUNET_TRANSPORT_TransmitContinuation transmit_cont;

  /**
   * Closure for transmit_cont.
   */
  void *transmit_cont_cls;

  /**
   * Timeout value for the pending message.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * So that the gnunet-service-transport can group messages together,
   * these pending messages need to accept a message buffer and size
   * instead of just a GNUNET_MessageHeader.
   */
  size_t message_size;

};


/**
 * Session handle for TCP connections.
 */
struct Session
{

  /**
   * Stored in a linked list.
   */
  struct Session *next;

  /**
   * Pointer to the global plugin struct.
   */
  struct Plugin *plugin;

  /**
   * The client (used to identify this connection)
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Messages currently pending for transmission
   * to this peer, if any.
   */
  struct PendingMessage *pending_messages_head;

  /**
   * Messages currently pending for transmission
   * to this peer, if any.
   */
  struct PendingMessage *pending_messages_tail;

  /**
   * Handle for pending transmission request.
   */
  struct GNUNET_CONNECTION_TransmitHandle *transmit_handle;

  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  struct GNUNET_PeerIdentity target;

  /**
   * ID of task used to delay receiving more to throttle sender.
   */
  GNUNET_SCHEDULER_TaskIdentifier receive_delay_task;

  /**
   * Address of the other peer (either based on our 'connect'
   * call or on our 'accept' call).
   */
  void *connect_addr;

  /**
   * Length of connect_addr.
   */
  size_t connect_alen;

  /**
   * Are we still expecting the welcome message? (GNUNET_YES/GNUNET_NO)
   */
  int expecting_welcome;

};


/**
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin
{
  /**
   * Our environment.
   */
  struct GNUNET_TRANSPORT_PluginEnvironment *env;

  /**
   * The listen socket.
   */
  struct GNUNET_CONNECTION_Handle *lsock;

  /**
   * List of open TCP sessions.
   */
  struct Session *sessions;

  /**
   * Handle for the statistics service.
   */
  struct GNUNET_STATISTICS_Handle *statistics;

  /**
   * Handle to the network service.
   */
  struct GNUNET_SERVICE_Context *service;

  /**
   * Handle to the server for this service.
   */
  struct GNUNET_SERVER_Handle *server;

  /**
   * Copy of the handler array where the closures are
   * set to this struct's instance.
   */
  struct GNUNET_SERVER_MessageHandler *handlers;

  /**
   * Handle for request of hostname resolution, non-NULL if pending.
   */
  struct GNUNET_RESOLVER_RequestHandle *hostname_dns;

  /**
   * ID of task used to update our addresses when one expires.
   */
  GNUNET_SCHEDULER_TaskIdentifier address_update_task;

  /**
   * Port that we are actually listening on.
   */
  uint16_t open_port;

  /**
   * Port that the user said we would have visible to the
   * rest of the world.
   */
  uint16_t adv_port;

};


/**
 * Find the session handle for the given client.
 *
 * @return NULL if no matching session exists
 */
static struct Session *
find_session_by_client (struct Plugin *plugin,
                        const struct GNUNET_SERVER_Client *client)
{
  struct Session *ret;

  ret = plugin->sessions;
  while ((ret != NULL) && (client != ret->client))
    ret = ret->next;
  return ret;
}


/**
 * Create a new session.  Also queues a welcome message.
 *
 * @param plugin us
 * @param target peer to connect to
 * @param client client to use
 * @return new session object
 */
static struct Session *
create_session (struct Plugin *plugin,
                const struct GNUNET_PeerIdentity *target,
                struct GNUNET_SERVER_Client *client)
{
  struct Session *ret;
  struct PendingMessage *pm;
  struct WelcomeMessage welcome;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "tcp",
		   "Creating new session for peer `%4s'\n",
		   GNUNET_i2s (target));
  ret = GNUNET_malloc (sizeof (struct Session));
  ret->plugin = plugin;
  ret->next = plugin->sessions;
  plugin->sessions = ret;
  ret->client = client;
  ret->target = *target;
  ret->expecting_welcome = GNUNET_YES;
  pm = GNUNET_malloc (sizeof (struct PendingMessage) + sizeof (struct WelcomeMessage));
  pm->msg = (const char*) &pm[1];
  pm->message_size = sizeof (struct WelcomeMessage);
  welcome.header.size = htons (sizeof (struct WelcomeMessage));
  welcome.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_WELCOME);
  welcome.clientIdentity = *plugin->env->my_identity;
  memcpy (&pm[1], &welcome, sizeof (welcome));
  pm->timeout = GNUNET_TIME_UNIT_FOREVER_ABS;
  GNUNET_CONTAINER_DLL_insert (ret->pending_messages_head,
			       ret->pending_messages_tail,
			       pm);
  return ret;
}


/**
 * If we have pending messages, ask the server to
 * transmit them (schedule the respective tasks, etc.)
 *
 * @param session for which session should we do this
 */
static void process_pending_messages (struct Session *session);


/**
 * Function called to notify a client about the socket
 * being ready to queue more data.  "buf" will be
 * NULL and "size" zero if the socket was closed for
 * writing in the meantime.
 *
 * @param cls closure
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
do_transmit (void *cls, size_t size, void *buf)
{
  struct Session *session = cls;
  struct PendingMessage *pm;
  char *cbuf;

  size_t ret;

  session->transmit_handle = NULL;
  if (buf == NULL)
    {
#if DEBUG_TCP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "tcp",
                       "Timeout trying to transmit to peer `%4s', discarding message queue.\n",
                       GNUNET_i2s (&session->target));
#endif
      /* timeout */
      while (NULL != (pm = session->pending_messages_head))
        {
	  GNUNET_CONTAINER_DLL_remove (session->pending_messages_head,
				       session->pending_messages_tail,
				       pm);
#if DEBUG_TCP
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                           "tcp",
                           "Failed to transmit %u byte message to `%4s'.\n",
			   pm->message_size,
                           GNUNET_i2s (&session->target));
#endif
          if (pm->transmit_cont != NULL)
            pm->transmit_cont (pm->transmit_cont_cls,
                               &session->target, GNUNET_SYSERR);
          GNUNET_free (pm);
        }
      return 0;
    }
  ret = 0;
  cbuf = buf;
  while (NULL != (pm = session->pending_messages_head))
    {
      if (size < pm->message_size)
	break;
      memcpy (cbuf, pm->msg, pm->message_size);
      cbuf += pm->message_size;
      ret += pm->message_size;
      size -= pm->message_size;
      GNUNET_CONTAINER_DLL_remove (session->pending_messages_head,
				   session->pending_messages_tail,
				   pm);
      if (pm->transmit_cont != NULL)
        pm->transmit_cont (pm->transmit_cont_cls,
                           &session->target, GNUNET_OK);
      GNUNET_free (pm);
    }
  if (session->client != NULL)
    process_pending_messages (session);
#if DEBUG_TCP > 1
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "tcp", "Transmitting %u bytes\n", ret);
#endif
  return ret;
}


/**
 * If we have pending messages, ask the server to
 * transmit them (schedule the respective tasks, etc.)
 *
 * @param session for which session should we do this
 */
static void
process_pending_messages (struct Session *session)
{
  struct PendingMessage *pm;
  GNUNET_assert (session->client != NULL);
  if (session->transmit_handle != NULL)
    return;
  if (NULL == (pm = session->pending_messages_head))
    return;
  session->transmit_handle
    = GNUNET_SERVER_notify_transmit_ready (session->client,
                                           pm->message_size,
                                           GNUNET_TIME_absolute_get_remaining
                                           (pm->timeout),
                                           &do_transmit, session);
}


/**
 * Functions with this signature are called whenever we need
 * to close a session due to a disconnect or failure to
 * establish a connection.
 *
 * @param session session to close down
 */
static void
disconnect_session (struct Session *session)
{
  struct Session *prev;
  struct Session *pos;
  struct PendingMessage *pm;

#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "tcp",
                   "Disconnecting from `%4s' at %s (session %p).\n",
                   GNUNET_i2s (&session->target),
                   (session->connect_addr != NULL) ?
                   GNUNET_a2s (session->connect_addr,
                               session->connect_alen) : "*", session);
#endif
  /* remove from session list */
  prev = NULL;
  pos = session->plugin->sessions;
  while (pos != session)
    {
      prev = pos;
      pos = pos->next;
    }
  if (prev == NULL)
    session->plugin->sessions = session->next;
  else
    prev->next = session->next;
  /* clean up state */
  if (session->transmit_handle != NULL)
    {
      GNUNET_CONNECTION_notify_transmit_ready_cancel
        (session->transmit_handle);
      session->transmit_handle = NULL;
    }
  while (NULL != (pm = session->pending_messages_head))
    {
#if DEBUG_TCP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "tcp",
                       pm->transmit_cont != NULL
                       ? "Could not deliver message to `%4s'.\n"
                       :
                       "Could not deliver message to `%4s', notifying.\n",
                       GNUNET_i2s (&session->target));
#endif
      GNUNET_CONTAINER_DLL_remove (session->pending_messages_head,
				   session->pending_messages_tail,
				   pm);
      if (NULL != pm->transmit_cont)
        pm->transmit_cont (pm->transmit_cont_cls,
                           &session->target, GNUNET_SYSERR);
      GNUNET_free (pm);
    }
  if (GNUNET_NO == session->expecting_welcome)
    {
#if DEBUG_TCP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "tcp",
                       "Notifying transport service about loss of connection with `%4s'.\n",
                       GNUNET_i2s (&session->target));
#endif
      /* Data session that actually went past the initial handshake;
         transport service may know about this one, so we need to
         notify transport service about disconnect */
      // FIXME: we should have a very clear connect-disconnect
      // protocol with gnunet-service-transport! 
      // FIXME: but this is not possible for all plugins, so what gives?
    }
  if (session->receive_delay_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (session->plugin->env->sched,
			       session->receive_delay_task);
      if (session->client != NULL)
	{
	  GNUNET_SERVER_receive_done (session->client, 
				      GNUNET_SYSERR);
	}
    }
  if (session->client != NULL)
    {
      GNUNET_SERVER_client_drop (session->client);
      session->client = NULL;
    } 
  GNUNET_free_non_null (session->connect_addr);
  GNUNET_free (session);
}


/**
 * Function that can be used by the transport service to transmit
 * a message using the plugin.   Note that in the case of a
 * peer disconnecting, the continuation MUST be called
 * prior to the disconnect notification itself.  This function
 * will be called with this peer's HELLO message to initiate
 * a fresh connection to another peer.
 *
 * @param cls closure
 * @param target who should receive this message
 * @param msg the message to transmit
 * @param msgbuf_size number of bytes in 'msg'
 * @param priority how important is the message (most plugins will
 *                 ignore message priority and just FIFO)
 * @param timeout how long to wait at most for the transmission (does not
 *                require plugins to discard the message after the timeout,
 *                just advisory for the desired delay; most plugins will ignore
 *                this as well)
 * @param addr the address to use (can be NULL if the plugin
 *                is "on its own" (i.e. re-use existing TCP connection))
 * @param addrlen length of the address in bytes
 * @param force_address GNUNET_YES if the plugin MUST use the given address,
 *                otherwise the plugin may use other addresses or
 *                existing connections (if available)
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...); can be NULL
 * @param cont_cls closure for cont
 * @return number of bytes used (on the physical network, with overheads);
 *         -1 on hard errors (i.e. address invalid); 0 is a legal value
 *         and does NOT mean that the message was not transmitted (DV)
 */
static ssize_t
tcp_plugin_send (void *cls,
                 const struct GNUNET_PeerIdentity *target,
                 const char *msg,
                 size_t msgbuf_size,
                 uint32_t priority,
                 struct GNUNET_TIME_Relative timeout,
		 const void *addr,
		 size_t addrlen,
		 int force_address,
                 GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct Session *session;
  struct PendingMessage *pm;
  struct GNUNET_CONNECTION_Handle *sa;
  int af;

  session = plugin->sessions;
  /* FIXME: we could do this a cheaper with a hash table
     where we could restrict the iteration to entries that match
     the target peer... */
  while ( (session != NULL) &&
	  ( (0 != memcmp (target,
			  &session->target, 
			  sizeof (struct GNUNET_PeerIdentity))) ||
	    ( (GNUNET_YES == force_address) &&
	      (addr != NULL) &&
	      ( (addrlen != session->connect_alen) ||
		(0 != memcmp (session->connect_addr,
			      addr,
			      addrlen)) ) ) ) )
    session = session->next;
  if ( (session == NULL) &&
       (addr == NULL) )
    {
#if DEBUG_TCP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "tcp",
                       "Asked to transmit to `%4s' without address and I have no existing connection (failing).\n",
                       GNUNET_i2s (target));
#endif
      return -1;
    }
  if (session == NULL)
    {
      if (sizeof (struct sockaddr_in) == addrlen)
	af = AF_INET;
      else if (sizeof (struct sockaddr_in6) == addrlen)
	af = AF_INET6;
      else
	{
	  GNUNET_break_op (0);
	  return -1;
	}
      sa = GNUNET_CONNECTION_create_from_sockaddr (plugin->env->sched,
						   af, addr, addrlen,
						   GNUNET_SERVER_MAX_MESSAGE_SIZE);
      if (sa == NULL)
	{
#if DEBUG_TCP
	  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
			   "tcp",
			   "Failed to create connection to `%4s' at `%s'\n",
			   GNUNET_i2s (target),
			   GNUNET_a2s (addr, addrlen));
#endif
	  return -1;
	}

#if DEBUG_TCP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "tcp",
                       "Asked to transmit to `%4s', creating fresh session using address `%s'.\n",
		       GNUNET_i2s (target),
		       GNUNET_a2s (addr, addrlen));
#endif
      session = create_session (plugin,
				target,
				GNUNET_SERVER_connect_socket (plugin->server,
							      sa));
      session->connect_addr = GNUNET_malloc (addrlen);
      memcpy (session->connect_addr,
	      addr,
	      addrlen);
      session->connect_alen = addrlen;
    }
  GNUNET_assert (session != NULL);
  GNUNET_assert (session->client != NULL);

  /* create new message entry */
  pm = GNUNET_malloc (sizeof (struct PendingMessage) + msgbuf_size);
  pm->msg = (const char*) &pm[1];
  memcpy (&pm[1], msg, msgbuf_size);
  pm->message_size = msgbuf_size;
  pm->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  pm->transmit_cont = cont;
  pm->transmit_cont_cls = cont_cls;

  /* append pm to pending_messages list */
  GNUNET_CONTAINER_DLL_insert_after (session->pending_messages_head,
				     session->pending_messages_tail,
				     session->pending_messages_tail,
				     pm);
#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "tcp",
		   "Asked to transmit %u bytes to `%s', added message to list.\n",
		   msgbuf_size,
		   GNUNET_i2s (target));
#endif
  process_pending_messages (session);
  return msgbuf_size;
}


/**
 * Function that can be called to force a disconnect from the
 * specified neighbour.  This should also cancel all previously
 * scheduled transmissions.  Obviously the transmission may have been
 * partially completed already, which is OK.  The plugin is supposed
 * to close the connection (if applicable) and no longer call the
 * transmit continuation(s).
 *
 * Finally, plugin MUST NOT call the services's receive function to
 * notify the service that the connection to the specified target was
 * closed after a getting this call.
 *
 * @param cls closure
 * @param target peer for which the last transmission is
 *        to be cancelled
 */
static void
tcp_plugin_disconnect (void *cls, const struct GNUNET_PeerIdentity *target)
{
  struct Plugin *plugin = cls;
  struct Session *session;
  struct PendingMessage *pm;

#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "tcp",
                   "Asked to cancel session with `%4s'\n",
                   GNUNET_i2s (target));
#endif
  session = plugin->sessions;
  while (NULL != session)
    {
      if (0 == memcmp (target,
		       &session->target,
		       sizeof (struct GNUNET_PeerIdentity)))
	{
	  pm = session->pending_messages_head;
	  while (pm != NULL)
	    {
	      pm->transmit_cont = NULL;
	      pm->transmit_cont_cls = NULL;
	      pm = pm->next;
	    }
	  if (session->client != NULL)
	    {
	      GNUNET_SERVER_client_drop (session->client);
	      session->client = NULL;
	    }
	  /* rest of the clean-up of the session will be done as part of
	     disconnect_notify which should be triggered any time now
	     (or which may be triggering this call in the first place) */
	}
      session = session->next;
    }
}


struct PrettyPrinterContext
{
  GNUNET_TRANSPORT_AddressStringCallback asc;
  void *asc_cls;
  uint16_t port;
};


/**
 * Append our port and forward the result.
 */
static void
append_port (void *cls, const char *hostname)
{
  struct PrettyPrinterContext *ppc = cls;
  char *ret;

  if (hostname == NULL)
    {
      ppc->asc (ppc->asc_cls, NULL);
      GNUNET_free (ppc);
      return;
    }
  GNUNET_asprintf (&ret, "%s:%d", hostname, ppc->port);
  ppc->asc (ppc->asc_cls, ret);
  GNUNET_free (ret);
}


/**
 * Convert the transports address to a nice, human-readable
 * format.
 *
 * @param cls closure
 * @param type name of the transport that generated the address
 * @param addr one of the addresses of the host, NULL for the last address
 *        the specific address format depends on the transport
 * @param addrlen length of the address
 * @param numeric should (IP) addresses be displayed in numeric form?
 * @param timeout after how long should we give up?
 * @param asc function to call on each string
 * @param asc_cls closure for asc
 */
static void
tcp_plugin_address_pretty_printer (void *cls,
                                   const char *type,
                                   const void *addr,
                                   size_t addrlen,
                                   int numeric,
                                   struct GNUNET_TIME_Relative timeout,
                                   GNUNET_TRANSPORT_AddressStringCallback asc,
                                   void *asc_cls)
{
  struct Plugin *plugin = cls;
  const struct sockaddr_in *v4;
  const struct sockaddr_in6 *v6;
  struct PrettyPrinterContext *ppc;

  if ((addrlen != sizeof (struct sockaddr_in)) &&
      (addrlen != sizeof (struct sockaddr_in6)))
    {
      /* invalid address */
      GNUNET_break_op (0);
      asc (asc_cls, NULL);
      return;
    }
  ppc = GNUNET_malloc (sizeof (struct PrettyPrinterContext));
  ppc->asc = asc;
  ppc->asc_cls = asc_cls;
  if (addrlen == sizeof (struct sockaddr_in))
    {
      v4 = (const struct sockaddr_in *) addr;
      ppc->port = ntohs (v4->sin_port);
    }
  else
    {
      v6 = (const struct sockaddr_in6 *) addr;
      ppc->port = ntohs (v6->sin6_port);

    }
  GNUNET_RESOLVER_hostname_get (plugin->env->sched,
                                plugin->env->cfg,
                                addr,
                                addrlen,
                                !numeric, timeout, &append_port, ppc);
}


/**
 * Check if the given port is plausible (must be either
 * our listen port or our advertised port).  If it is
 * neither, we return one of these two ports at random.
 *
 * @return either in_port or a more plausible port
 */
static uint16_t
check_port (struct Plugin *plugin, uint16_t in_port)
{
  if ((in_port == plugin->adv_port) || (in_port == plugin->open_port))
    return in_port;
  return (GNUNET_CRYPTO_random_u32 (GNUNET_CRYPTO_QUALITY_WEAK,
                                    2) == 0)
    ? plugin->open_port : plugin->adv_port;
}


/**
 * Another peer has suggested an address for this peer and transport
 * plugin.  Check that this could be a valid address.
 *
 * @param cls closure
 * @param addr pointer to the address
 * @param addrlen length of addr
 * @return GNUNET_OK if this is a plausible address for this peer
 *         and transport
 */
static int
tcp_plugin_check_address (void *cls, void *addr, size_t addrlen)
{
  struct Plugin *plugin = cls;
  char buf[sizeof (struct sockaddr_in6)];
  struct sockaddr_in *v4;
  struct sockaddr_in6 *v6;

  if ((addrlen != sizeof (struct sockaddr_in)) &&
      (addrlen != sizeof (struct sockaddr_in6)))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  memcpy (buf, addr, sizeof (struct sockaddr_in6));
  if (addrlen == sizeof (struct sockaddr_in))
    {
      v4 = (struct sockaddr_in *) buf;
      v4->sin_port = htons (check_port (plugin, ntohs (v4->sin_port)));
    }
  else
    {
      v6 = (struct sockaddr_in6 *) buf;
      v6->sin6_port = htons (check_port (plugin, ntohs (v6->sin6_port)));
    }
#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "tcp",
                   "Informing transport service about my address `%s'.\n",
                   GNUNET_a2s (addr, addrlen));
#endif
  return GNUNET_OK;
}


/**
 * We've received a welcome from this peer via TCP.  Possibly create a
 * fresh client record and send back our welcome.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_tcp_welcome (void *cls,
                    struct GNUNET_SERVER_Client *client,
                    const struct GNUNET_MessageHeader *message)
{
  struct Plugin *plugin = cls;
  const struct WelcomeMessage *wm = (const struct WelcomeMessage *) message;
  struct Session *session;
  size_t alen;
  void *vaddr;

#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "tcp",
                   "Received %s message from a `%4s/%p'.\n", 
		   "WELCOME",
                   GNUNET_i2s (&wm->clientIdentity), client);
#endif
  session = find_session_by_client (plugin, client);
  if (session == NULL)
    {
      GNUNET_SERVER_client_keep (client);
      session = create_session (plugin,
				&wm->clientIdentity, client);
      if (GNUNET_OK ==
	  GNUNET_SERVER_client_get_address (client, &vaddr, &alen))
	{
#if DEBUG_TCP
	  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
			   "tcp",
			   "Found address `%s' for incoming connection %p\n",
			   GNUNET_a2s (vaddr, alen),
			   client);
#endif
	  session->connect_addr = vaddr;
	  session->connect_alen = alen;
	}
      else
        {
#if DEBUG_TCP
	  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
			   "tcp",
			   "Did not obtain TCP socket address for incoming connection\n");
#endif
        }
#if DEBUG_TCP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "tcp",
                       "Creating new session %p for connection %p\n",
                       session, client);
#endif
      process_pending_messages (session);
    }
  if (session->expecting_welcome != GNUNET_YES)
    {
      GNUNET_break_op (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  session->expecting_welcome = GNUNET_NO;
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Task to signal the server that we can continue
 * receiving from the TCP client now.
 */
static void
delayed_done (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Session *session = cls;
  struct GNUNET_TIME_Relative delay;

  session->receive_delay_task = GNUNET_SCHEDULER_NO_TASK;
  delay = session->plugin->env->receive (session->plugin->env->cls,
					 &session->target,
					 NULL, 0, NULL, 0);
  if (delay.value == 0)
    GNUNET_SERVER_receive_done (session->client, GNUNET_OK);
  else
    session->receive_delay_task = 
      GNUNET_SCHEDULER_add_delayed (session->plugin->env->sched,
				    delay, &delayed_done, session);
}


/**
 * We've received data for this peer via TCP.  Unbox,
 * compute latency and forward.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_tcp_data (void *cls,
                 struct GNUNET_SERVER_Client *client,
                 const struct GNUNET_MessageHeader *message)
{
  struct Plugin *plugin = cls;
  struct Session *session;
  struct GNUNET_TIME_Relative delay;

  session = find_session_by_client (plugin, client);
  if (GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_WELCOME == ntohs(message->type))
    {
      /* We don't want to propagate WELCOME messages up! */
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
      return; 
    }    
  if ( (NULL == session) || (GNUNET_NO != session->expecting_welcome))
    {
      GNUNET_break_op (0);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "tcp", 
		   "Passing %u bytes of type %u from `%4s' to transport service.\n",
                   (unsigned int) ntohs (message->size), 
		   (unsigned int) ntohs (message->type),
		   GNUNET_i2s (&session->target));
#endif
  delay = plugin->env->receive (plugin->env->cls, &session->target, message, 1,
				session->connect_addr,
				session->connect_alen);

  if (delay.value == 0)
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
  else
    session->receive_delay_task = 
      GNUNET_SCHEDULER_add_delayed (session->plugin->env->sched,
				    delay, &delayed_done, session);
}


/**
 * Handlers for the various TCP messages.
 */
static struct GNUNET_SERVER_MessageHandler my_handlers[] = {
  {&handle_tcp_welcome, NULL, GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_WELCOME,
   sizeof (struct WelcomeMessage)},
  {&handle_tcp_data, NULL, GNUNET_MESSAGE_TYPE_ALL, 0},
  {NULL, NULL, 0, 0}
};


/**
 * Functions with this signature are called whenever a peer
 * is disconnected on the network level.
 *
 * @param cls closure
 * @param client identification of the client
 */
static void
disconnect_notify (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct Plugin *plugin = cls;
  struct Session *session;

  if (client == NULL)
    return;
  session = find_session_by_client (plugin, client);
  if (session == NULL)
    return;                     /* unknown, nothing to do */
#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "tcp",
                   "Destroying session of `%4s' with %s (%p) due to network-level disconnect.\n",
                   GNUNET_i2s (&session->target),
                   (session->connect_addr != NULL) ?
                   GNUNET_a2s (session->connect_addr,
                               session->connect_alen) : "*", client);
#endif
  disconnect_session (session);
}


/**
 * Add the IP of our network interface to the list of
 * our external IP addresses.
 */
static int
process_interfaces (void *cls,
                    const char *name,
                    int isDefault,
                    const struct sockaddr *addr, socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  int af;
  struct sockaddr_in *v4;
  struct sockaddr_in6 *v6;

  af = addr->sa_family;
  if (af == AF_INET)
    {
      v4 = (struct sockaddr_in *) addr;
      v4->sin_port = htons (plugin->adv_port);
    }
  else
    {
      GNUNET_assert (af == AF_INET6);
      v6 = (struct sockaddr_in6 *) addr;
      v6->sin6_port = htons (plugin->adv_port);
    }
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO |
                   GNUNET_ERROR_TYPE_BULK,
                   "tcp", _("Found address `%s' (%s)\n"),
                   GNUNET_a2s (addr, addrlen), name);
  plugin->env->notify_address (plugin->env->cls,
                               "tcp",
                               addr, addrlen, GNUNET_TIME_UNIT_FOREVER_REL);
  return GNUNET_OK;
}


/**
 * Function called by the resolver for each address obtained from DNS
 * for our own hostname.  Add the addresses to the list of our
 * external IP addresses.
 *
 * @param cls closure
 * @param addr one of the addresses of the host, NULL for the last address
 * @param addrlen length of the address
 */
static void
process_hostname_ips (void *cls,
                      const struct sockaddr *addr, socklen_t addrlen)
{
  struct Plugin *plugin = cls;

  if (addr == NULL)
    {
      plugin->hostname_dns = NULL;
      return;
    }
  process_interfaces (plugin, "<hostname>", GNUNET_YES, addr, addrlen);
}


/**
 * Entry point for the plugin.
 */
void *
libgnunet_plugin_transport_tcp_init (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;
  struct GNUNET_SERVICE_Context *service;
  unsigned long long aport;
  unsigned long long bport;
  unsigned int i;

  service = GNUNET_SERVICE_start ("transport-tcp", env->sched, env->cfg);
  if (service == NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
                       "tcp",
                       _
                       ("Failed to start service for `%s' transport plugin.\n"),
                       "tcp");
      return NULL;
    }
  aport = 0;
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (env->cfg,
                                              "transport-tcp",
                                              "PORT",
                                              &bport)) ||
      (bport > 65535) ||
      ((GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_number (env->cfg,
                                               "transport-tcp",
                                               "ADVERTISED-PORT",
                                               &aport)) && (aport > 65535)))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                       "tcp",
                       _
                       ("Require valid port number for service `%s' in configuration!\n"),
                       "transport-tcp");
      GNUNET_SERVICE_stop (service);
      return NULL;
    }
  if (aport == 0)
    aport = bport;
  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->open_port = bport;
  plugin->adv_port = aport;
  plugin->env = env;
  plugin->lsock = NULL;
  plugin->statistics = NULL;
  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;
  api->send = &tcp_plugin_send;
  api->disconnect = &tcp_plugin_disconnect;
  api->address_pretty_printer = &tcp_plugin_address_pretty_printer;
  api->check_address = &tcp_plugin_check_address;
  plugin->service = service;
  plugin->server = GNUNET_SERVICE_get_server (service);
  plugin->handlers = GNUNET_malloc (sizeof (my_handlers));
  memcpy (plugin->handlers, my_handlers, sizeof (my_handlers));
  for (i = 0;
       i <
       sizeof (my_handlers) / sizeof (struct GNUNET_SERVER_MessageHandler);
       i++)
    plugin->handlers[i].callback_cls = plugin;
  GNUNET_SERVER_add_handlers (plugin->server, plugin->handlers);

  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
                   "tcp", _("TCP transport listening on port %llu\n"), bport);
  if (aport != bport)
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
                     "tcp",
                     _
                     ("TCP transport advertises itself as being on port %llu\n"),
                     aport);
  GNUNET_SERVER_disconnect_notify (plugin->server, &disconnect_notify,
                                   plugin);
  /* FIXME: do the two calls below periodically again and
     not just once (since the info we get might change...) */
  GNUNET_OS_network_interfaces_list (&process_interfaces, plugin);
  plugin->hostname_dns = GNUNET_RESOLVER_hostname_resolve (env->sched,
                                                           env->cfg,
                                                           AF_UNSPEC,
                                                           HOSTNAME_RESOLVE_TIMEOUT,
                                                           &process_hostname_ips,
                                                           plugin);
  return api;
}


/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_transport_tcp_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;
  struct Session *session;

  while (NULL != (session = plugin->sessions))
    disconnect_session (session);
  if (NULL != plugin->hostname_dns)
    {
      GNUNET_RESOLVER_request_cancel (plugin->hostname_dns);
      plugin->hostname_dns = NULL;
    }
  GNUNET_SERVICE_stop (plugin->service);
  GNUNET_free (plugin->handlers);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_tcp.c */
