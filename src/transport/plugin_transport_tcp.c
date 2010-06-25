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
#define DEBUG_TCP_NAT GNUNET_NO

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
 * Basically a WELCOME message, but with the purpose
 * of giving the waiting peer a client handle to use
 */
struct TCP_NAT_ProbeMessage
{
  /**
   * Type is GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_NAT_PROBE.
   */
  struct GNUNET_MessageHeader header;

  /**
   * Identity of the sender of the message.
   */
  struct GNUNET_PeerIdentity clientIdentity;

};

/**
 * Context for sending a NAT probe via TCP.
 */
struct TCPProbeContext
{
  /**
   * Probe connection.
   */
  struct GNUNET_CONNECTION_Handle *sock;

  /**
   * Message to be sent.
   */
  struct TCP_NAT_ProbeMessage message;

  /**
   * Handle to the transmission.
   */
  struct GNUNET_CONNECTION_TransmitHandle *transmit_handle;

  /**
   * Transport plugin handle.
   */
  struct Plugin *plugin;
};


/**
 * Network format for IPv4 addresses.
 */
struct IPv4TcpAddress
{
  /**
   * IPv4 address, in network byte order.
   */
  uint32_t ipv4_addr;

  /**
   * Port number, in network byte order.
   */
  uint16_t t_port;

};


/**
 * Network format for IPv6 addresses.
 */
struct IPv6TcpAddress
{
  /**
   * IPv6 address.
   */
  struct in6_addr ipv6_addr;

  /**
   * Port number, in network byte order.
   */
  uint16_t t6_port;

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
   * API requirement.
   */
  struct SessionHeader header;

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
   * Last activity on this connection.  Used to select preferred
   * connection.
   */
  struct GNUNET_TIME_Absolute last_activity;

  /**
   * Length of connect_addr.
   */
  size_t connect_alen;

  /**
   * Are we still expecting the welcome message? (GNUNET_YES/GNUNET_NO)
   */
  int expecting_welcome;

  /**
   * Was this a connection that was inbound (we accepted)? (GNUNET_YES/GNUNET_NO)
   */
  int inbound;

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

  /*
   * stdout pipe handle for the gnunet-nat-server process
   */
  struct GNUNET_DISK_PipeHandle *server_stdout;

  /*
   * stdout file handle (for reading) for the gnunet-nat-server process
   */
  const struct GNUNET_DISK_FileHandle *server_stdout_handle;

  /**
   * ID of select gnunet-nat-server stdout read task
   */
  GNUNET_SCHEDULER_TaskIdentifier server_read_task;

  /**
   * The process id of the server process (if behind NAT)
   */
  pid_t server_pid;

  /**
   * List of open TCP sessions.
   */
  struct Session *sessions;

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
   * Map of peers we have tried to contact behind a NAT
   */
  struct GNUNET_CONTAINER_MultiHashMap *nat_wait_conns;

  /**
   * The external address given to us by the user.  Must be actual
   * outside visible address for NAT punching to work.
   */
  char *external_address;

  /**
   * The internal address given to us by the user (or discovered).
   */
  char *internal_address;

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

  /**
   * Is this transport configured to be behind a NAT?
   */
  int behind_nat;

  /**
   * Is this transport configured to allow connections to NAT'd peers?
   */
  int allow_nat;

  /**
   * Should this transport advertise only NAT addresses (port set to 0)?
   * If not, all addresses will be duplicated for NAT punching and regular
   * ports.
   */
  int only_nat_addresses;

};




/**
 * Function called for a quick conversion of the binary address to
 * a numeric address.  Note that the caller must not free the 
 * address and that the next call to this function is allowed
 * to override the address again.
 *
 * @param cls closure ('struct Plugin*')
 * @param addr binary address
 * @param addrlen length of the address
 * @return string representing the same address 
 */
static const char* 
tcp_address_to_string (void *cls,
		       const void *addr,
		       size_t addrlen)
{
  static char rbuf[INET6_ADDRSTRLEN + 12];
  char buf[INET6_ADDRSTRLEN];
  const void *sb;
  struct in_addr a4;
  struct in6_addr a6;
  const struct IPv4TcpAddress *t4;
  const struct IPv6TcpAddress *t6;
  int af;
  uint16_t port;

  if (addrlen == sizeof (struct IPv6TcpAddress))
    {
      t6 = addr;
      af = AF_INET6;
      port = ntohs (t6->t6_port);
      memcpy (&a6, &t6->ipv6_addr, sizeof (a6));
      sb = &a6;
    }
  else if (addrlen == sizeof (struct IPv4TcpAddress))
    {
      t4 = addr;
      af = AF_INET;
      port = ntohs (t4->t_port);
      memcpy (&a4, &t4->ipv4_addr, sizeof (a4));
      sb = &a4;
    }
  else
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
		       "tcp",
		       _("Unexpected address length: %u\n"),
		       addrlen);
      GNUNET_break (0);
      return NULL;
    }
  if (NULL == inet_ntop (af, sb, buf, INET6_ADDRSTRLEN))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "inet_ntop");
      return NULL;
    }
  GNUNET_snprintf (rbuf,
		   sizeof (rbuf),
		   (af == AF_INET6) ? "[%s]:%u" : "%s:%u",
		   buf,
		   port);
  return rbuf;
}


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
 * @param is_nat this a NAT session, we should wait for a client to
 *               connect to us from an address, then assign that to
 *               the session
 * @return new session object
 */
static struct Session *
create_session (struct Plugin *plugin,
                const struct GNUNET_PeerIdentity *target,
                struct GNUNET_SERVER_Client *client, int is_nat)
{
  struct Session *ret;
  struct PendingMessage *pm;
  struct WelcomeMessage welcome;

  if (is_nat != GNUNET_YES)
    GNUNET_assert (client != NULL);
  else
    GNUNET_assert (client == NULL);

#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "tcp",
		   "Creating new session for peer `%4s'\n",
		   GNUNET_i2s (target));
#endif
  ret = GNUNET_malloc (sizeof (struct Session));
  ret->last_activity = GNUNET_TIME_absolute_get ();
  ret->plugin = plugin;
  if (is_nat != GNUNET_YES) /* If not a NAT WAIT conn, add it to global list */
    {
      ret->next = plugin->sessions;
      plugin->sessions = ret;
    }
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
  GNUNET_STATISTICS_update (plugin->env->stats,
			    gettext_noop ("# bytes currently in TCP buffers"),
			    pm->message_size,
			    GNUNET_NO);      
  GNUNET_CONTAINER_DLL_insert (ret->pending_messages_head,
			       ret->pending_messages_tail,
			       pm);
  if (is_nat != GNUNET_YES)
    GNUNET_STATISTICS_update (plugin->env->stats,
                              gettext_noop ("# TCP sessions active"),
                              1,
                              GNUNET_NO);
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
  struct GNUNET_PeerIdentity pid;
  struct Plugin *plugin;
  struct PendingMessage *pos;
  struct PendingMessage *hd;
  struct PendingMessage *tl;
  struct GNUNET_TIME_Absolute now;
  char *cbuf;
  size_t ret;

  session->transmit_handle = NULL;
  plugin = session->plugin;
  if (buf == NULL)
    {
#if DEBUG_TCP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "tcp",
                       "Timeout trying to transmit to peer `%4s', discarding message queue.\n",
                       GNUNET_i2s (&session->target));
#endif
      /* timeout; cancel all messages that have already expired */
      hd = NULL;
      tl = NULL;
      ret = 0;
      now = GNUNET_TIME_absolute_get ();
      while ( (NULL != (pos = session->pending_messages_head)) &&
	      (pos->timeout.value <= now.value) )
	{
	  GNUNET_CONTAINER_DLL_remove (session->pending_messages_head,
				       session->pending_messages_tail,
				       pos);
#if DEBUG_TCP
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                           "tcp",
                           "Failed to transmit %u byte message to `%4s'.\n",
			   pos->message_size,
                           GNUNET_i2s (&session->target));
#endif
	  ret += pos->message_size;
	  GNUNET_CONTAINER_DLL_insert_after (hd, tl, tl, pos);
        }
      /* do this call before callbacks (so that if callbacks destroy
	 session, they have a chance to cancel actions done by this
	 call) */
      process_pending_messages (session);  
      pid = session->target;
      /* no do callbacks and do not use session again since
	 the callbacks may abort the session */
      while (NULL != (pos = hd))
	{
	  GNUNET_CONTAINER_DLL_remove (hd, tl, pos);
	  if (pos->transmit_cont != NULL)
	    pos->transmit_cont (pos->transmit_cont_cls,
				&pid, GNUNET_SYSERR);
	  GNUNET_free (pos);
	}
      GNUNET_STATISTICS_update (plugin->env->stats,
				gettext_noop ("# bytes currently in TCP buffers"),
				- (int64_t) ret,
				GNUNET_NO); 
      GNUNET_STATISTICS_update (plugin->env->stats,
				gettext_noop ("# bytes discarded by TCP (timeout)"),
				ret,
				GNUNET_NO);      
      return 0;
    }
  /* copy all pending messages that would fit */
  ret = 0;
  cbuf = buf;
  hd = NULL;
  tl = NULL;
  while (NULL != (pos = session->pending_messages_head)) 
    {
      if (ret + pos->message_size > size) 
	break;
      GNUNET_CONTAINER_DLL_remove (session->pending_messages_head,
				   session->pending_messages_tail,
				   pos);
      GNUNET_assert (size >= pos->message_size);
      /* FIXME: this memcpy can be up to 7% of our total runtime */
      memcpy (cbuf, pos->msg, pos->message_size);
      cbuf += pos->message_size;
      ret += pos->message_size;
      size -= pos->message_size;
      GNUNET_CONTAINER_DLL_insert_after (hd, tl, tl, pos);
    }
  /* schedule 'continuation' before callbacks so that callbacks that
     cancel everything don't cause us to use a session that no longer
     exists... */
  process_pending_messages (session);  
  session->last_activity = GNUNET_TIME_absolute_get ();
  pid = session->target;
  /* we'll now call callbacks that may cancel the session; hence
     we should not use 'session' after this point */
  while (NULL != (pos = hd))
    {
      GNUNET_CONTAINER_DLL_remove (hd, tl, pos);
      if (pos->transmit_cont != NULL)
        pos->transmit_cont (pos->transmit_cont_cls,
			    &pid, GNUNET_OK);
      GNUNET_free (pos);
    }
  GNUNET_assert (hd == NULL);
  GNUNET_assert (tl == NULL);
#if DEBUG_TCP > 1
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "tcp", "Transmitting %u bytes\n", ret);
#endif
  GNUNET_STATISTICS_update (plugin->env->stats,
			    gettext_noop ("# bytes currently in TCP buffers"),
			    - (int64_t) ret,
			    GNUNET_NO);       
  GNUNET_STATISTICS_update (plugin->env->stats,
			    gettext_noop ("# bytes transmitted via TCP"),
			    ret,
			    GNUNET_NO);      
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
                   tcp_address_to_string (session->plugin,
					  session->connect_addr,
					  session->connect_alen) : "*", 
		   session);
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
  session->plugin->env->session_end (session->plugin->env->cls,
			    &session->target,
			    session);
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
      GNUNET_STATISTICS_update (session->plugin->env->stats,
				gettext_noop ("# bytes currently in TCP buffers"),
				- (int64_t) pm->message_size,
				GNUNET_NO);      
      GNUNET_STATISTICS_update (session->plugin->env->stats,
				gettext_noop ("# bytes discarded by TCP (disconnect)"),
				pm->message_size,
				GNUNET_NO);      
      GNUNET_CONTAINER_DLL_remove (session->pending_messages_head,
				   session->pending_messages_tail,
				   pm);
      if (NULL != pm->transmit_cont)
        pm->transmit_cont (pm->transmit_cont_cls,
                           &session->target, GNUNET_SYSERR);
      GNUNET_free (pm);
    }
  GNUNET_break (session->client != NULL);
  if (session->receive_delay_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (session->plugin->env->sched,
			       session->receive_delay_task);
      if (session->client != NULL)
	GNUNET_SERVER_receive_done (session->client, 
				    GNUNET_SYSERR);	
    }
  if (session->client != NULL)	     
    GNUNET_SERVER_client_drop (session->client);
  GNUNET_STATISTICS_update (session->plugin->env->stats,
			    gettext_noop ("# TCP sessions active"),
			    -1,
			    GNUNET_NO);      
  GNUNET_free_non_null (session->connect_addr);
  GNUNET_free (session);
}


/**
 * Given two otherwise equivalent sessions, pick the better one.
 * 
 * @param s1 one session (also default)
 * @param s2 other session
 * @return "better" session (more active)
 */
static struct Session *
select_better_session (struct Session *s1,
		       struct Session *s2)
{
  if (s1 == NULL)
    return s2;
  if (s2 == NULL)
    return s1;
  if ( (s1->expecting_welcome == GNUNET_NO) &&
       (s2->expecting_welcome == GNUNET_YES) )
    return s1;
  if ( (s1->expecting_welcome == GNUNET_YES) &&
       (s2->expecting_welcome == GNUNET_NO) )
    return s2;
  if (s1->last_activity.value < s2->last_activity.value)
    return s2;
  if (s1->last_activity.value > s2->last_activity.value)
    return s1;
  if ( (GNUNET_YES == s1->inbound) &&
       (GNUNET_NO  == s2->inbound) )
    return s1;
  if ( (GNUNET_NO  == s1->inbound) &&
       (GNUNET_YES == s2->inbound) )
    return s2;
  return s1;
}


/**
 * We learned about a peer (possibly behind NAT) so run the
 * gnunet-nat-client to send dummy ICMP responses
 *
 * @param plugin the plugin for this transport
 * @param addr the address of the peer
 * @param addrlen the length of the address
 */
void
run_gnunet_nat_client (struct Plugin *plugin, const char *addr, size_t addrlen)
{
  char inet4[INET_ADDRSTRLEN];
  char *address_as_string;
  char *port_as_string;
  pid_t pid;
  const struct sockaddr *sa = (const struct sockaddr *)addr;
#if DEBUG_TCP_NAT
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "tcp",
                  _("called run_gnunet_nat_client addrlen %d others are %d and %d\n"), addrlen, sizeof (struct sockaddr), sizeof (struct sockaddr_in));
#endif

  if (addrlen < sizeof (struct sockaddr))
    return;

  switch (sa->sa_family)
    {
    case AF_INET:
      if (addrlen != sizeof (struct sockaddr_in))
        return;
      if (NULL == inet_ntop (AF_INET,
			     &((struct sockaddr_in *) sa)->sin_addr,
			     inet4, INET_ADDRSTRLEN))
	{
	  GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "inet_ntop");
	  return;
	}
      address_as_string = GNUNET_strdup (inet4);
      break;
    case AF_INET6:
    default:
      return;
    }

  GNUNET_asprintf(&port_as_string, "%d", plugin->adv_port);
#if DEBUG_TCP_NAT
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "tcp",
                  _("Running gnunet-nat-client with arguments: %s %s %d\n"), plugin->external_address, address_as_string, plugin->adv_port);
#endif

  /* Start the client process */
  pid = GNUNET_OS_start_process(NULL, NULL, "gnunet-nat-client", "gnunet-nat-client", plugin->external_address, address_as_string, port_as_string, NULL);
  GNUNET_free(address_as_string);
  GNUNET_free(port_as_string);
  GNUNET_OS_process_wait (pid);
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
 * @param session which session must be used (or NULL for "any")
 * @param addr the address to use (can be NULL if the plugin
 *                is "on its own" (i.e. re-use existing TCP connection))
 * @param addrlen length of the address in bytes
 * @param force_address GNUNET_YES if the plugin MUST use the given address,
 *                GNUNET_NO means the plugin may use any other address and
 *                GNUNET_SYSERR means that only reliable existing
 *                bi-directional connections should be used (regardless
 *                of address)
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...); can be NULL
 * @param cont_cls closure for cont
 * @return number of bytes used (on the physical network, with overheads);
 *         -1 on hard errors (i.e. address invalid); 0 is a legal value
 *         and does NOT mean that the message was not transmitted (DV and NAT)
 */
static ssize_t
tcp_plugin_send (void *cls,
                 const struct GNUNET_PeerIdentity *target,
                 const char *msg,
                 size_t msgbuf_size,
                 uint32_t priority,
                 struct GNUNET_TIME_Relative timeout,
		 struct Session *session,
		 const void *addr,
		 size_t addrlen,
		 int force_address,
                 GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Plugin *plugin = cls;
  struct Session *cand_session;
  struct Session *next;
  struct PendingMessage *pm;
  struct GNUNET_CONNECTION_Handle *sa;
  int af;
  const void *sb;
  size_t sbs;
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
  const struct IPv4TcpAddress *t4;
  const struct IPv6TcpAddress *t6;
  unsigned int is_natd;

  GNUNET_STATISTICS_update (plugin->env->stats,
			    gettext_noop ("# bytes TCP was asked to transmit"),
			    msgbuf_size,
			    GNUNET_NO);      
  /* FIXME: we could do this cheaper with a hash table
     where we could restrict the iteration to entries that match
     the target peer... */
  is_natd = GNUNET_NO;
  if (session == NULL)
    {
      cand_session = NULL;
      next = plugin->sessions;
      while (NULL != (session = next)) 
	{
	  next = session->next;
	  GNUNET_assert (session->client != NULL);
	  if (0 != memcmp (target,
			   &session->target, 
			   sizeof (struct GNUNET_PeerIdentity)))
	    continue;
	  if ( ( (GNUNET_SYSERR == force_address) &&
		 (session->expecting_welcome == GNUNET_NO) ) ||
	       (GNUNET_NO == force_address) )   
	    {
	      cand_session = select_better_session (cand_session,
						    session);
	      continue;
	    }
	  if (GNUNET_SYSERR == force_address)
	    continue;
	  GNUNET_break (GNUNET_YES == force_address);
	  if (addr == NULL)
	    {
	      GNUNET_break (0);
	      break;
	    }
	  if (session->inbound == GNUNET_YES) 
	    continue;
	  if (addrlen != session->connect_alen)
	    continue;
	  if (0 != memcmp (session->connect_addr,
			   addr,
			   addrlen))
	    continue;
	  cand_session = select_better_session (cand_session,
						session);	      
	}
      session = cand_session;
    }
  if ( (session == NULL) &&
       (addr == NULL) )
    {
#if DEBUG_TCP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "tcp",
                       "Asked to transmit to `%4s' without address and I have no existing connection (failing).\n",
                       GNUNET_i2s (target));
#endif
      GNUNET_STATISTICS_update (plugin->env->stats,
				gettext_noop ("# bytes discarded by TCP (no address and no connection)"),
				msgbuf_size,
				GNUNET_NO);      
      return -1;
    }
  if (session == NULL)
    {
      if (addrlen == sizeof (struct IPv6TcpAddress))
	{
	  t6 = addr;
	  af = AF_INET6;
	  memset (&a6, 0, sizeof (a6));
#if HAVE_SOCKADDR_IN_SIN_LEN
          a6.sin6_len = sizeof (a6);
#endif
	  a6.sin6_family = AF_INET6;
	  a6.sin6_port = t6->t6_port;
	  if (t6->t6_port == 0)
	    is_natd = GNUNET_YES;
	  memcpy (&a6.sin6_addr,
		  &t6->ipv6_addr,
		  sizeof (struct in6_addr));      
	  sb = &a6;
	  sbs = sizeof (a6);
	}
      else if (addrlen == sizeof (struct IPv4TcpAddress))
	{
	  t4 = addr;
	  af = AF_INET;
	  memset (&a4, 0, sizeof (a4));
#if HAVE_SOCKADDR_IN_SIN_LEN
          a4.sin_len = sizeof (a4);
#endif
	  a4.sin_family = AF_INET;
	  a4.sin_port = t4->t_port;
	  if (t4->t_port == 0)
	    is_natd = GNUNET_YES;
	  a4.sin_addr.s_addr = t4->ipv4_addr;
	  sb = &a4;
	  sbs = sizeof (a4);
	}
      else
	{
	  GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
			   "tcp",
			   _("Address of unexpected length: %u\n"),
			   addrlen);
	  GNUNET_break (0);
	  return -1;
	}

      if ((is_natd == GNUNET_YES) && (addrlen == sizeof (struct IPv6TcpAddress)))
        return -1; /* NAT client only works with IPv4 addresses */


      if ( (plugin->allow_nat == GNUNET_YES) && (is_natd == GNUNET_YES) &&
           (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains(plugin->nat_wait_conns, &target->hashPubKey)))
        {
#if DEBUG_TCP_NAT
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                           "tcp",
                           _("Found valid IPv4 NAT address!\n"));
#endif
          session = create_session (plugin,
                                    target,
                                    NULL, is_natd);

          /* create new message entry */
          pm = GNUNET_malloc (sizeof (struct PendingMessage) + msgbuf_size);
	  /* FIXME: the memset of this malloc can be up to 2% of our total runtime */
          pm->msg = (const char*) &pm[1];
          memcpy (&pm[1], msg, msgbuf_size); 
	  /* FIXME: this memcpy can be up to 7% of our total run-time 
	     (for transport service) */
          pm->message_size = msgbuf_size;
          pm->timeout = GNUNET_TIME_relative_to_absolute (timeout);
          pm->transmit_cont = cont;
          pm->transmit_cont_cls = cont_cls;

          /* append pm to pending_messages list */
          GNUNET_CONTAINER_DLL_insert_after (session->pending_messages_head,
                                             session->pending_messages_tail,
                                             session->pending_messages_tail,
                                             pm);

          GNUNET_assert(GNUNET_CONTAINER_multihashmap_put(plugin->nat_wait_conns, &target->hashPubKey, session, GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY) == GNUNET_OK);
#if DEBUG_TCP_NAT
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                           "tcp",
                           "Created NAT WAIT connection to `%4s' at `%s'\n",
                           GNUNET_i2s (target),
                           GNUNET_a2s (sb, sbs));
#endif
          run_gnunet_nat_client(plugin, sb, sbs);
          return 0;
        }
      else if ((plugin->allow_nat == GNUNET_YES) && (is_natd == GNUNET_YES) && (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains(plugin->nat_wait_conns, &target->hashPubKey)))
        {
          /* Only do one NAT punch attempt per peer identity */
          return -1;
        }
      sa = GNUNET_CONNECTION_create_from_sockaddr (plugin->env->sched,
						   af, sb, sbs,
						   GNUNET_SERVER_MAX_MESSAGE_SIZE - 1);
      if (sa == NULL)
	{
#if DEBUG_TCP
	  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
			   "tcp",
			   "Failed to create connection to `%4s' at `%s'\n",
			   GNUNET_i2s (target),
			   GNUNET_a2s (sb, sbs));
#endif
	  GNUNET_STATISTICS_update (plugin->env->stats,
				    gettext_noop ("# bytes discarded by TCP (failed to connect)"),
				    msgbuf_size,
				    GNUNET_NO);      
	  return -1;
	}
#if DEBUG_TCP
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "tcp",
                       "Asked to transmit to `%4s', creating fresh session using address `%s'.\n",
		       GNUNET_i2s (target),
		       GNUNET_a2s (sb, sbs));
#endif
      session = create_session (plugin,
				target,
				GNUNET_SERVER_connect_socket (plugin->server,
							      sa), is_natd);
      session->connect_addr = GNUNET_malloc (addrlen);
      memcpy (session->connect_addr,
	      addr,
	      addrlen);
      session->connect_alen = addrlen;
    }
  GNUNET_assert (session != NULL);
  GNUNET_assert (session->client != NULL);
  GNUNET_STATISTICS_update (plugin->env->stats,
			    gettext_noop ("# bytes currently in TCP buffers"),
			    msgbuf_size,
			    GNUNET_NO);      
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
tcp_plugin_disconnect (void *cls,
		       const struct GNUNET_PeerIdentity *target)
{
  struct Plugin *plugin = cls;
  struct Session *session;
  struct Session *next;
  struct PendingMessage *pm;

#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "tcp",
                   "Asked to cancel session with `%4s'\n",
                   GNUNET_i2s (target));
#endif
  next = plugin->sessions;
  while (NULL != (session = next))
    {
      next = session->next;
      if (0 != memcmp (target,
		       &session->target,
		       sizeof (struct GNUNET_PeerIdentity)))
	continue;
      pm = session->pending_messages_head;
      while (pm != NULL)
	{
	  pm->transmit_cont = NULL;
	  pm->transmit_cont_cls = NULL;
	  pm = pm->next;
	}
      disconnect_session (session);
    }
}


/**
 * Context for address to string conversion.
 */
struct PrettyPrinterContext
{
  /**
   * Function to call with the result.
   */
  GNUNET_TRANSPORT_AddressStringCallback asc;

  /**
   * Clsoure for 'asc'.
   */
  void *asc_cls;

  /**
   * Port to add after the IP address.
   */
  uint16_t port;
};


/**
 * Append our port and forward the result.
 *
 * @param cls the 'struct PrettyPrinterContext*'
 * @param hostname hostname part of the address
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
  struct PrettyPrinterContext *ppc;
  const void *sb;
  size_t sbs;
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
  const struct IPv4TcpAddress *t4;
  const struct IPv6TcpAddress *t6;
  uint16_t port;

  if (addrlen == sizeof (struct IPv6TcpAddress))
    {
      t6 = addr;
      memset (&a6, 0, sizeof (a6));
      a6.sin6_family = AF_INET6;
      a6.sin6_port = t6->t6_port;
      memcpy (&a6.sin6_addr,
	      &t6->ipv6_addr,
	      sizeof (struct in6_addr));      
      port = ntohs (t6->t6_port);
      sb = &a6;
      sbs = sizeof (a6);
    }
  else if (addrlen == sizeof (struct IPv4TcpAddress))
    {
      t4 = addr;
      memset (&a4, 0, sizeof (a4));
      a4.sin_family = AF_INET;
      a4.sin_port = t4->t_port;
      a4.sin_addr.s_addr = t4->ipv4_addr;
      port = ntohs (t4->t_port);
      sb = &a4;
      sbs = sizeof (a4);
    }
  else
    {
      /* invalid address */
      GNUNET_break_op (0);
      asc (asc_cls, NULL);
      return;
    }
  ppc = GNUNET_malloc (sizeof (struct PrettyPrinterContext));
  ppc->asc = asc;
  ppc->asc_cls = asc_cls;
  ppc->port = port;
  GNUNET_RESOLVER_hostname_get (plugin->env->sched,
                                plugin->env->cfg,
                                sb,
                                sbs,
                                !numeric, timeout, &append_port, ppc);
}


/**
 * Check if the given port is plausible (must be either
 * our listen port or our advertised port).  If it is
 * neither, we return one of these two ports at random.
 *
 * @param plugin global variables
 * @param in_port port number to check
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
 * plugin.  Check that this could be a valid address. This function
 * is not expected to 'validate' the address in the sense of trying to
 * connect to it but simply to see if the binary format is technically
 * legal for establishing a connection.
 *
 * @param cls closure, our 'struct Plugin*'
 * @param addr pointer to the address
 * @param addrlen length of addr
 * @return GNUNET_OK if this is a plausible address for this peer
 *         and transport, GNUNET_SYSERR if not
 */
static int
tcp_plugin_check_address (void *cls, void *addr, size_t addrlen)
{
  struct Plugin *plugin = cls;
  struct IPv4TcpAddress *v4;
  struct IPv6TcpAddress *v6;

  if ((addrlen != sizeof (struct IPv4TcpAddress)) &&
      (addrlen != sizeof (struct IPv6TcpAddress)))
    {
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
  if (addrlen == sizeof (struct IPv4TcpAddress))
    {
      v4 = (struct IPv4TcpAddress *) addr;
      v4->t_port = htons (check_port (plugin, ntohs (v4->t_port)));
    }
  else
    {
      v6 = (struct IPv6TcpAddress *) addr;
      if (IN6_IS_ADDR_LINKLOCAL (&v6->ipv6_addr))
	{
	  GNUNET_break_op (0);
	  return GNUNET_SYSERR;
	}
      v6->t6_port = htons (check_port (plugin, ntohs (v6->t6_port)));
    }
  return GNUNET_OK;
}

/**
 * We've received a nat probe from this peer via TCP.  Finish
 * creating the client session and resume sending of queued
 * messages.
 *
 * @param cls closure
 * @param client identification of the client
 * @param message the actual message
 */
static void
handle_tcp_nat_probe (void *cls,
                     struct GNUNET_SERVER_Client *client,
                     const struct GNUNET_MessageHeader *message)
{
  struct Plugin *plugin = cls;
  struct Session *session;
  struct TCP_NAT_ProbeMessage *tcp_nat_probe;
  size_t alen;
  void *vaddr;
  struct IPv4TcpAddress *t4;
  struct IPv6TcpAddress *t6;
  const struct sockaddr_in *s4;
  const struct sockaddr_in6 *s6;

#if DEBUG_TCP_NAT
  GNUNET_log_from(GNUNET_ERROR_TYPE_DEBUG, "tcp", "received tcp NAT probe\n");
#endif
  /* We have received a TCP NAT probe, meaning we (hopefully) initiated
   * a connection to this peer by running gnunet-nat-client.  This peer
   * received the punch message and now wants us to use the new connection
   * as the default for that peer.  Do so and then send a WELCOME message
   * so we can really be connected!
   */
  if (ntohs(message->size) != sizeof(struct TCP_NAT_ProbeMessage))
    {
#if DEBUG_TCP_NAT
      GNUNET_log_from(GNUNET_ERROR_TYPE_DEBUG, "tcp", "Bad size fo tcp NAT probe, expected %d got %d.\n", sizeof(struct TCP_NAT_ProbeMessage), ntohs(message->size));
#endif
      GNUNET_break_op(0);
      return;
    }
  tcp_nat_probe = (struct TCP_NAT_ProbeMessage *)message;

  if (GNUNET_CONTAINER_multihashmap_contains(plugin->nat_wait_conns, &tcp_nat_probe->clientIdentity.hashPubKey) == GNUNET_YES)
    {
#if DEBUG_TCP_NAT
      GNUNET_log_from(GNUNET_ERROR_TYPE_DEBUG, "tcp", "Found session for NAT probe!\n");
#endif
      session = GNUNET_CONTAINER_multihashmap_get(plugin->nat_wait_conns, &tcp_nat_probe->clientIdentity.hashPubKey);
      GNUNET_assert(session != NULL);
      GNUNET_assert(GNUNET_CONTAINER_multihashmap_remove(plugin->nat_wait_conns, &tcp_nat_probe->clientIdentity.hashPubKey, session) == GNUNET_YES);
      GNUNET_SERVER_client_keep (client);
      session->client = client;
      session->last_activity = GNUNET_TIME_absolute_get ();

      if (GNUNET_OK ==
          GNUNET_SERVER_client_get_address (client, &vaddr, &alen))
        {
#if DEBUG_TCP_NAT
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                           "tcp",
                           "Found address `%s' for incoming connection %p\n",
                           GNUNET_a2s (vaddr, alen),
                           client);
#endif
          if (alen == sizeof (struct sockaddr_in))
            {
              s4 = vaddr;
              t4 = GNUNET_malloc (sizeof (struct IPv4TcpAddress));
              t4->t_port = s4->sin_port;
              t4->ipv4_addr = s4->sin_addr.s_addr;
              session->connect_addr = t4;
              session->connect_alen = sizeof (struct IPv4TcpAddress);
            }
          else if (alen == sizeof (struct sockaddr_in6))
            {
              s6 = vaddr;
              t6 = GNUNET_malloc (sizeof (struct IPv6TcpAddress));
              t6->t6_port = s6->sin6_port;
              memcpy (&t6->ipv6_addr,
                      &s6->sin6_addr,
                      sizeof (struct in6_addr));
              session->connect_addr = t6;
              session->connect_alen = sizeof (struct IPv6TcpAddress);
            }

          session->connect_addr = GNUNET_malloc (alen);
          memcpy (session->connect_addr,
                  vaddr,
                  alen);
          session->connect_alen = alen;
          GNUNET_free (vaddr);
        }

      session->next = plugin->sessions;
      plugin->sessions = session;
      GNUNET_STATISTICS_update (plugin->env->stats,
                                gettext_noop ("# TCP sessions active"),
                                1,
                                GNUNET_NO);
      process_pending_messages (session);
    }
  else
    {
#if DEBUG_TCP_NAT
      GNUNET_log_from(GNUNET_ERROR_TYPE_DEBUG, "tcp", "Did NOT find session for NAT probe!\n");
#endif
    }
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
  struct IPv4TcpAddress *t4;
  struct IPv6TcpAddress *t6;
  const struct sockaddr_in *s4;
  const struct sockaddr_in6 *s6;


#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "tcp",
                   "Received %s message from a `%4s/%p'.\n", 
		   "WELCOME",
                   GNUNET_i2s (&wm->clientIdentity), client);
#endif
  GNUNET_STATISTICS_update (plugin->env->stats,
			    gettext_noop ("# TCP WELCOME messages received"),
			    1,
			    GNUNET_NO);      
  session = find_session_by_client (plugin, client);
  if (session == NULL)
    {
      GNUNET_SERVER_client_keep (client);
      session = create_session (plugin,
				&wm->clientIdentity, client, GNUNET_NO);
      session->inbound = GNUNET_YES;
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
	  if (alen == sizeof (struct sockaddr_in))
	    {
	      s4 = vaddr;
	      t4 = GNUNET_malloc (sizeof (struct IPv4TcpAddress));
	      t4->t_port = s4->sin_port;
	      t4->ipv4_addr = s4->sin_addr.s_addr;
	      session->connect_addr = t4;
	      session->connect_alen = sizeof (struct IPv4TcpAddress);
	    }
	  else if (alen == sizeof (struct sockaddr_in6))
	    {
	      s6 = vaddr;
	      t6 = GNUNET_malloc (sizeof (struct IPv6TcpAddress));
	      t6->t6_port = s6->sin6_port;
	      memcpy (&t6->ipv6_addr,
		      &s6->sin6_addr,
		      sizeof (struct in6_addr));
	      session->connect_addr = t6;
	      session->connect_alen = sizeof (struct IPv6TcpAddress);
	    }
	  GNUNET_free (vaddr);
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
  session->last_activity = GNUNET_TIME_absolute_get ();
  session->expecting_welcome = GNUNET_NO;
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Task to signal the server that we can continue
 * receiving from the TCP client now.
 *
 * @param cls the 'struct Session*'
 * @param tc task context (unused)
 */
static void
delayed_done (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Session *session = cls;
  struct GNUNET_TIME_Relative delay;

  session->receive_delay_task = GNUNET_SCHEDULER_NO_TASK;
  delay = session->plugin->env->receive (session->plugin->env->cls,
					 &session->target,
					 NULL, 0, 
					 session,
					 NULL, 0);
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

  if ((GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_WELCOME == ntohs(message->type)) || (ntohs(message->type) == GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_NAT_PROBE))
    {
      /* We don't want to propagate WELCOME and NAT Probe messages up! */
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
      return; 
    }    
  session = find_session_by_client (plugin, client);
  if ( (NULL == session) || (GNUNET_YES == session->expecting_welcome))
    {
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  session->last_activity = GNUNET_TIME_absolute_get ();
#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "tcp", 
		   "Passing %u bytes of type %u from `%4s' to transport service.\n",
                   (unsigned int) ntohs (message->size), 
		   (unsigned int) ntohs (message->type),
		   GNUNET_i2s (&session->target));
#endif
  GNUNET_STATISTICS_update (plugin->env->stats,
			    gettext_noop ("# bytes received via TCP"),
			    ntohs (message->size),
			    GNUNET_NO); 
  delay = plugin->env->receive (plugin->env->cls, &session->target, message, 1,
				session, 
				(GNUNET_YES == session->inbound) ? NULL : session->connect_addr,
				(GNUNET_YES == session->inbound) ? 0 : session->connect_alen);
  if (delay.value == 0)
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
  else
    session->receive_delay_task = 
      GNUNET_SCHEDULER_add_delayed (session->plugin->env->sched,
				    delay, &delayed_done, session);
}


/**
 * Functions with this signature are called whenever a peer
 * is disconnected on the network level.
 *
 * @param cls closure
 * @param client identification of the client
 */
static void
disconnect_notify (void *cls, 
		   struct GNUNET_SERVER_Client *client)
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
                   tcp_address_to_string (session->plugin,
					  session->connect_addr,
					  session->connect_alen) : "*",
		   client);
#endif
  disconnect_session (session);
}


/**
 * Add the IP of our network interface to the list of
 * our external IP addresses.
 *
 * @param cls the 'struct Plugin*'
 * @param name name of the interface
 * @param isDefault do we think this may be our default interface
 * @param addr address of the interface
 * @param addrlen number of bytes in addr
 * @return GNUNET_OK to continue iterating
 */
static int
process_interfaces (void *cls,
                    const char *name,
                    int isDefault,
                    const struct sockaddr *addr, socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  int af;
  struct IPv4TcpAddress t4;
  struct IPv6TcpAddress t6;
  struct IPv4TcpAddress t4_nat;
  struct IPv6TcpAddress t6_nat;
  void *arg;
  uint16_t args;
  void *arg_nat;

  af = addr->sa_family;
  arg_nat = NULL;
  if (af == AF_INET)
    {
      t4.ipv4_addr = ((struct sockaddr_in *) addr)->sin_addr.s_addr;
      if ((plugin->behind_nat == GNUNET_YES) && (plugin->only_nat_addresses == GNUNET_YES))
        t4.t_port = htons(0);
      else if (plugin->behind_nat == GNUNET_YES) /* We are behind NAT, but will advertise NAT and normal addresses */
        {
          t4_nat.ipv4_addr = ((struct sockaddr_in *) addr)->sin_addr.s_addr;
          t4_nat.t_port = htons(plugin->adv_port);
          arg_nat = &t4_nat;
        }
      else
        t4.t_port = htons (plugin->adv_port);
      arg = &t4;
      args = sizeof (t4);
    }
  else if (af == AF_INET6)
    {
      if (IN6_IS_ADDR_LINKLOCAL (&((struct sockaddr_in6 *) addr)->sin6_addr))
	{
	  /* skip link local addresses */
	  return GNUNET_OK;
	}
      memcpy (&t6.ipv6_addr,
	      &((struct sockaddr_in6 *) addr)->sin6_addr,
	      sizeof (struct in6_addr));
      if ((plugin->behind_nat == GNUNET_YES) && (plugin->only_nat_addresses == GNUNET_YES))
        t6.t6_port = htons(0);
      else if (plugin->behind_nat == GNUNET_YES) /* We are behind NAT, but will advertise NAT and normal addresses */
        {
          memcpy (&t6_nat.ipv6_addr,
                  &((struct sockaddr_in6 *) addr)->sin6_addr,
                  sizeof (struct in6_addr));
          t6_nat.t6_port = htons(plugin->adv_port);
          arg_nat = &t6;
        }
      else
        t6.t6_port = htons (plugin->adv_port);
      arg = &t6;
      args = sizeof (t6);
    }
  else
    {
      GNUNET_break (0);
      return GNUNET_OK;
    }
  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO |
                   GNUNET_ERROR_TYPE_BULK,
                   "tcp", 
		   _("Found address `%s' (%s)\n"),
                   GNUNET_a2s (addr, addrlen), name);

  plugin->env->notify_address (plugin->env->cls,
                               "tcp",
                               arg, args, GNUNET_TIME_UNIT_FOREVER_REL);

  if (arg_nat != NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_INFO |
                       GNUNET_ERROR_TYPE_BULK,
                      "tcp",
                      _("Found address `%s' (%s)\n"),
                      GNUNET_a2s (addr, addrlen), name);
      plugin->env->notify_address (plugin->env->cls,
                                   "tcp",
                                   arg_nat, args, GNUNET_TIME_UNIT_FOREVER_REL);
    }

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
  /* FIXME: Can we figure out our external address here so it doesn't need to be user specified? */
  process_interfaces (plugin, "<hostname>", GNUNET_YES, addr, addrlen);
}

/**
 * We can now send a probe message, copy into buffer to really send.
 *
 * @param cls closure, a struct TCPProbeContext
 * @param size max size to copy
 * @param buf buffer to copy message to
 */
static size_t notify_send_probe (void *cls,
                                 size_t size, void *buf)
{
  struct TCPProbeContext *tcp_probe_ctx = cls;

  if (buf == NULL)
    {
      return 0;
    }

  GNUNET_assert(size >= sizeof(tcp_probe_ctx->message));
  memcpy(buf, &tcp_probe_ctx->message, sizeof(tcp_probe_ctx->message));
  GNUNET_SERVER_connect_socket (tcp_probe_ctx->plugin->server,
                                tcp_probe_ctx->sock);

  GNUNET_free(tcp_probe_ctx);
  return sizeof(tcp_probe_ctx->message);
}

/*
 * @param cls the plugin handle
 * @param tc the scheduling context (for rescheduling this function again)
 *
 * We have been notified that gnunet-nat-server has written something to stdout.
 * Handle the output, then reschedule this function to be called again once
 * more is available.
 *
 */
static void
tcp_plugin_server_read (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  char mybuf[40];
  ssize_t bytes;
  memset(&mybuf, 0, sizeof(mybuf));
  int i;
  int port;
  char *port_start;
  struct sockaddr_in in_addr;
  struct TCPProbeContext *tcp_probe_ctx;
  struct GNUNET_CONNECTION_Handle *sock;

  if (tc->reason == GNUNET_SCHEDULER_REASON_SHUTDOWN)
    return;

  bytes = GNUNET_DISK_file_read(plugin->server_stdout_handle, &mybuf, sizeof(mybuf));

  if (bytes < 1)
    {
#if DEBUG_TCP_NAT
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "tcp",
                      _("Finished reading from server stdout with code: %d\n"), bytes);
#endif
      return;
    }

  port = 0;
  port_start = NULL;
  for (i = 0; i < sizeof(mybuf); i++)
    {
      if (mybuf[i] == '\n')
        mybuf[i] = '\0';

      if ((mybuf[i] == ':') && (i + 1 < sizeof(mybuf)))
        {
          mybuf[i] = '\0';
          port_start = &mybuf[i + 1];
        }
    }

  if (port_start != NULL)
    port = atoi(port_start);
  else
    {
      plugin->server_read_task =
           GNUNET_SCHEDULER_add_read_file (plugin->env->sched,
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           plugin->server_stdout_handle, &tcp_plugin_server_read, plugin);
      return;
    }

#if DEBUG_UDP_NAT
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "tcp",
                  _("nat-server-read read: %s port %d\n"), &mybuf, port);
#endif


  if (inet_pton(AF_INET, &mybuf[0], &in_addr.sin_addr) != 1)
    {

      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, "tcp",
                  _("nat-server-read malformed address\n"), &mybuf, port);

      plugin->server_read_task =
          GNUNET_SCHEDULER_add_read_file (plugin->env->sched,
                                          GNUNET_TIME_UNIT_FOREVER_REL,
                                          plugin->server_stdout_handle, &tcp_plugin_server_read, plugin);
      return;
    }

  in_addr.sin_family = AF_INET;
  in_addr.sin_port = htons(port);
  /**
   * We have received an ICMP response, ostensibly from a non-NAT'd peer
   *  that wants to connect to us! Send a message to establish a connection.
   */
  sock = GNUNET_CONNECTION_create_from_sockaddr (plugin->env->sched, AF_INET, (struct sockaddr *)&in_addr,
                                                 sizeof(in_addr), GNUNET_SERVER_MAX_MESSAGE_SIZE - 1);
  if (sock == NULL)
    {
      plugin->server_read_task =
          GNUNET_SCHEDULER_add_read_file (plugin->env->sched,
                                          GNUNET_TIME_UNIT_FOREVER_REL,
                                          plugin->server_stdout_handle, &tcp_plugin_server_read, plugin);
      return;
    }
  else
    {
      tcp_probe_ctx = GNUNET_malloc(sizeof(struct TCPProbeContext));

      tcp_probe_ctx->message.header.size = htons(sizeof(struct TCP_NAT_ProbeMessage));
      tcp_probe_ctx->message.header.type = htons(GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_NAT_PROBE);
      memcpy(&tcp_probe_ctx->message.clientIdentity, plugin->env->my_identity, sizeof(struct GNUNET_PeerIdentity));
      tcp_probe_ctx->plugin = plugin;
      tcp_probe_ctx->sock = sock;
      tcp_probe_ctx->transmit_handle = GNUNET_CONNECTION_notify_transmit_ready (sock,
                                                                 ntohs(tcp_probe_ctx->message.header.size),
                                                                 GNUNET_TIME_UNIT_FOREVER_REL,
                                                                 &notify_send_probe, tcp_probe_ctx);

    }

  plugin->server_read_task =
      GNUNET_SCHEDULER_add_read_file (plugin->env->sched,
                                      GNUNET_TIME_UNIT_FOREVER_REL,
                                      plugin->server_stdout_handle, &tcp_plugin_server_read, plugin);
}

/**
 * Start the gnunet-nat-server process for users behind NAT.
 *
 * @param plugin the transport plugin
 *
 * @return GNUNET_YES if process was started, GNUNET_SYSERR on error
 */
static int
tcp_transport_start_nat_server(struct Plugin *plugin)
{

  plugin->server_stdout = GNUNET_DISK_pipe(GNUNET_YES);
  if (plugin->server_stdout == NULL)
    return GNUNET_SYSERR;

#if DEBUG_TCP_NAT
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                   "tcp",
                   "Starting gnunet-nat-server process cmd: %s %s\n", "gnunet-nat-server", plugin->internal_address);
#endif
  /* Start the server process */
  plugin->server_pid = GNUNET_OS_start_process(NULL, plugin->server_stdout, "gnunet-nat-server", "gnunet-nat-server", plugin->internal_address, NULL);
  if (plugin->server_pid == GNUNET_SYSERR)
    {
#if DEBUG_TCP_NAT
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                     "tcp",
                     "Failed to start gnunet-nat-server process\n");
#endif
      return GNUNET_SYSERR;
    }
  /* Close the write end of the read pipe */
  GNUNET_DISK_pipe_close_end(plugin->server_stdout, GNUNET_DISK_PIPE_END_WRITE);

  plugin->server_stdout_handle = GNUNET_DISK_pipe_handle(plugin->server_stdout, GNUNET_DISK_PIPE_END_READ);
  plugin->server_read_task =
      GNUNET_SCHEDULER_add_read_file (plugin->env->sched,
                                      GNUNET_TIME_UNIT_FOREVER_REL,
                                      plugin->server_stdout_handle, &tcp_plugin_server_read, plugin);
  return GNUNET_YES;
}

/**
 * Return the actual path to a file found in the current
 * PATH environment variable.
 *
 * @param binary the name of the file to find
 */
static char *
get_path_from_PATH (char *binary)
{
  char *path;
  char *pos;
  char *end;
  char *buf;
  const char *p;

  p = getenv ("PATH");
  if (p == NULL)
    return NULL;
  path = GNUNET_strdup (p);     /* because we write on it */
  buf = GNUNET_malloc (strlen (path) + 20);
  pos = path;

  while (NULL != (end = strchr (pos, ':')))
    {
      *end = '\0';
      sprintf (buf, "%s/%s", pos, binary);
      if (GNUNET_DISK_file_test (buf) == GNUNET_YES)
        {
          GNUNET_free (path);
          return buf;
        }
      pos = end + 1;
    }
  sprintf (buf, "%s/%s", pos, binary);
  if (GNUNET_DISK_file_test (buf) == GNUNET_YES)
    {
      GNUNET_free (path);
      return buf;
    }
  GNUNET_free (buf);
  GNUNET_free (path);
  return NULL;
}

/**
 * Check whether the suid bit is set on a file.
 * Attempts to find the file using the current
 * PATH environment variable as a search path.
 *
 * @param binary the name of the file to check
 */
static int
check_gnunet_nat_binary(char *binary)
{
  struct stat statbuf;
  char *p;

  p = get_path_from_PATH (binary);
  if (p == NULL)
    return GNUNET_NO;
  if (0 != STAT (p, &statbuf))
    {
      GNUNET_free (p);
      return GNUNET_SYSERR;
    }
  GNUNET_free (p);
  if ( (0 != (statbuf.st_mode & S_ISUID)) &&
       (statbuf.st_uid == 0) )
    return GNUNET_YES;
  return GNUNET_NO;
}

/**
 * Entry point for the plugin.
 *
 * @param cls closure, the 'struct GNUNET_TRANSPORT_PluginEnvironment*'
 * @return the 'struct GNUNET_TRANSPORT_PluginFunctions*' or NULL on error
 */
void *
libgnunet_plugin_transport_tcp_init (void *cls)
{
  static const struct GNUNET_SERVER_MessageHandler my_handlers[] = {
    {&handle_tcp_welcome, NULL, GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_WELCOME,
     sizeof (struct WelcomeMessage)},
    {&handle_tcp_nat_probe, NULL, GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_NAT_PROBE, sizeof (struct TCP_NAT_ProbeMessage)},
    {&handle_tcp_data, NULL, GNUNET_MESSAGE_TYPE_ALL, 0},
    {NULL, NULL, 0, 0}
  };
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;
  struct GNUNET_SERVICE_Context *service;
  unsigned long long aport;
  unsigned long long bport;
  unsigned int i;
  int behind_nat;
  int allow_nat;
  int only_nat_addresses;
  char *internal_address;
  char *external_address;
  struct sockaddr_in in_addr;
  struct IPv4TcpAddress t4;

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

  if (GNUNET_YES == GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
                                                           "transport-tcp",
                                                           "BEHIND_NAT"))
    {
      /* We are behind nat (according to the user) */
      if (check_gnunet_nat_binary("gnunet-nat-server") == GNUNET_YES)
        {
          behind_nat = GNUNET_YES;
        }
      else
        {
          behind_nat = GNUNET_NO;
          GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, "tcp", "Configuration specified you are behind a NAT, but gnunet-nat-server is not installed properly (suid bit not set)!\n");
        }
    }
  else
    behind_nat = GNUNET_NO; /* We are not behind nat! */

  if (GNUNET_YES == GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
                                                           "transport-tcp",
                                                           "ALLOW_NAT"))
    {
      if (check_gnunet_nat_binary("gnunet-nat-client") == GNUNET_YES)
        allow_nat = GNUNET_YES; /* We will try to connect to NAT'd peers */
      else
      {
        allow_nat = GNUNET_NO;
        GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, "tcp", "Configuration specified you want to connect to NAT'd peers, but gnunet-nat-client is not installed properly (suid bit not set)!\n");
      }
    }
  else
    allow_nat = GNUNET_NO; /* We don't want to try to help NAT'd peers */


  if (GNUNET_YES == GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
                                                           "transport-tcp",
                                                           "ONLY_NAT_ADDRESSES"))
    only_nat_addresses = GNUNET_YES; /* We will only report our addresses as NAT'd */
  else
    only_nat_addresses = GNUNET_NO; /* We will report our addresses as NAT'd and non-NAT'd */

  external_address = NULL;
  if (((GNUNET_YES == behind_nat) || (GNUNET_YES == allow_nat)) && (GNUNET_OK !=
         GNUNET_CONFIGURATION_get_value_string (env->cfg,
                                                "transport-tcp",
                                                "EXTERNAL_ADDRESS",
                                                &external_address)))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                       "tcp",
                       _
                       ("Require EXTERNAL_ADDRESS for service `%s' in configuration (either BEHIND_NAT or ALLOW_NAT set to YES)!\n"),
                       "transport-tcp");
      GNUNET_SERVICE_stop (service);
      return NULL;
    }

  if ((external_address != NULL) && (inet_pton(AF_INET, external_address, &in_addr.sin_addr) != 1))
    {
      GNUNET_log_from(GNUNET_ERROR_TYPE_WARNING, "udp", "Malformed EXTERNAL_ADDRESS %s given in configuration!\n", external_address);
    }

  internal_address = NULL;
  if ((GNUNET_YES == behind_nat) && (GNUNET_OK !=
         GNUNET_CONFIGURATION_get_value_string (env->cfg,
                                                "transport-tcp",
                                                "INTERNAL_ADDRESS",
                                                &internal_address)))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                       "tcp",
                       _
                       ("Require INTERNAL_ADDRESS for service `%s' in configuration!\n"),
                       "transport-tcp");
      GNUNET_SERVICE_stop (service);
      GNUNET_free_non_null(external_address);
      return NULL;
    }

  if ((internal_address != NULL) && (inet_pton(AF_INET, internal_address, &in_addr.sin_addr) != 1))
    {
      GNUNET_log_from(GNUNET_ERROR_TYPE_WARNING, "udp", "Malformed INTERNAL_ADDRESS %s given in configuration!\n", internal_address);
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
      GNUNET_free_non_null(external_address);
      GNUNET_free_non_null(internal_address);
      GNUNET_SERVICE_stop (service);
      return NULL;
    }

  if (aport == 0)
    aport = bport;
  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->open_port = bport;
  plugin->adv_port = aport;
  plugin->external_address = external_address;
  plugin->internal_address = internal_address;
  plugin->behind_nat = behind_nat;
  plugin->allow_nat = allow_nat;
  plugin->only_nat_addresses = only_nat_addresses;
  plugin->env = env;
  plugin->lsock = NULL;
  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;
  api->send = &tcp_plugin_send;
  api->disconnect = &tcp_plugin_disconnect;
  api->address_pretty_printer = &tcp_plugin_address_pretty_printer;
  api->check_address = &tcp_plugin_check_address;
  api->address_to_string = &tcp_address_to_string;
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

  if (behind_nat == GNUNET_YES)
    {
      if (GNUNET_YES != tcp_transport_start_nat_server(plugin))
        {
          GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                           "tcp",
                           _
                           ("Failed to start %s required for NAT in %s!\n"),
                           "gnunet-nat-server"
                           "transport-tcp");
          GNUNET_free_non_null(external_address);
          GNUNET_free_non_null(internal_address);
          GNUNET_SERVICE_stop (service);
          return NULL;
        }
    }

  if (allow_nat == GNUNET_YES)
    {
      plugin->nat_wait_conns = GNUNET_CONTAINER_multihashmap_create(100);
      GNUNET_assert(plugin->nat_wait_conns != NULL);
    }

  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
                   "tcp", _("TCP transport listening on port %llu\n"), bport);
  if (aport != bport)
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
                     "tcp",
                     _("TCP transport advertises itself as being on port %llu\n"),
                     aport);
  GNUNET_SERVER_disconnect_notify (plugin->server, 
				   &disconnect_notify,
                                   plugin);
  if (plugin->behind_nat == GNUNET_NO)
    {
      GNUNET_OS_network_interfaces_list (&process_interfaces, plugin);
    }

  plugin->hostname_dns = GNUNET_RESOLVER_hostname_resolve (env->sched,
                                                           env->cfg,
                                                           AF_UNSPEC,
                                                           HOSTNAME_RESOLVE_TIMEOUT,
                                                           &process_hostname_ips,
                                                           plugin);

  if ((plugin->behind_nat == GNUNET_YES) && (inet_pton(AF_INET, plugin->external_address, &t4.ipv4_addr) == 1))
    {
      t4.t_port = htons(0);
      plugin->env->notify_address (plugin->env->cls,
                                  "tcp",
                                  &t4, sizeof(t4), GNUNET_TIME_UNIT_FOREVER_REL);
    }
  else if ((plugin->external_address != NULL) && (inet_pton(AF_INET, plugin->external_address, &t4.ipv4_addr) == 1))
    {
      t4.t_port = htons(plugin->adv_port);
      plugin->env->notify_address (plugin->env->cls,
                                   "tcp",
                                   &t4, sizeof(t4), GNUNET_TIME_UNIT_FOREVER_REL);
    }

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
