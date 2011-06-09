/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file transport/plugin_transport_tcp.c
 * @brief Implementation of the TCP transport service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_hello_lib.h"
#include "gnunet_connection_lib.h"
#include "gnunet_container_lib.h"
#include "gnunet_nat_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_resolver_service.h"
#include "gnunet_server_lib.h"
#include "gnunet_service_lib.h"
#include "gnunet_signatures.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_plugin.h"
#include "transport.h"

#define DEBUG_TCP GNUNET_NO

#define DEBUG_TCP_NAT GNUNET_YES

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
   * Active probes are kept in a DLL.
   */
  struct TCPProbeContext *next;

  /**
   * Active probes are kept in a DLL.
   */
  struct TCPProbeContext *prev;

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
  uint32_t ipv4_addr GNUNET_PACKED;

  /**
   * Port number, in network byte order.
   */
  uint16_t t_port GNUNET_PACKED;

};


/**
 * Network format for IPv6 addresses.
 */
struct IPv6TcpAddress
{
  /**
   * IPv6 address.
   */
  struct in6_addr ipv6_addr GNUNET_PACKED;

  /**
   * Port number, in network byte order.
   */
  uint16_t t6_port GNUNET_PACKED;

};


/**
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin;


/**
 * Local network addresses (actual IP address follows this struct).
 * PORT is NOT included!
 */
struct LocalAddrList
{

  /**
   * This is a doubly linked list.
   */
  struct LocalAddrList *next;

  /**
   * This is a doubly linked list.
   */
  struct LocalAddrList *prev;

  /**
   * Link to plugin.
   */
  struct Plugin *plugin;

  /**
   * Handle to NAT holes we've tried to punch for this address.
   */
  struct GNUNET_NAT_Handle *nat;

  /**
   * Pointer to a 'struct IPv4/V6TcpAddress' describing our external IP and port
   * as obtained from the NAT by automatic port mapping.
   */
  void *external_nat_address;

  /**
   * Number of bytes in 'external_nat_address'
   */
  size_t ena_size;

  /**
   * Number of bytes of the address that follow
   */
  size_t size;

};


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

  /**
   * Was this session created using NAT traversal?
   */
  int is_nat;

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
   * stdout pipe handle for the gnunet-nat-server process
   */
  struct GNUNET_DISK_PipeHandle *server_stdout;

  /**
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
  struct GNUNET_OS_Process *server_proc;

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
   * The external address given to us by the user.  Used for HELLOs
   * and address validation.
   */
  char *external_address;

  /**
   * The internal address given to us by the user (or discovered).
   * Used for NAT traversal (ICMP method), but not as a 'validateable'
   * address in HELLOs.
   */
  char *internal_address;

  /**
   * Address given for us to bind to (ONLY).
   */
  char *bind_address;

  /**
   * use local addresses?
   */
  int use_localaddresses;

  /**
   * List of our IP addresses.
   */
  struct LocalAddrList *lal_head;

  /**
   * Tail of our IP address list.
   */
  struct LocalAddrList *lal_tail;

  /**
   * List of active TCP probes.
   */
  struct TCPProbeContext *probe_head;

  /**
   * List of active TCP probes.
   */
  struct TCPProbeContext *probe_tail;

  /**
   * Handle for (DYN)DNS lookup of our external IP.
   */
  struct GNUNET_RESOLVER_RequestHandle *ext_dns;

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
   * Has the NAT been punched?
   */
  int nat_punched;

  /**
   * Is this transport configured to allow connections to NAT'd peers?
   */
  int enable_nat_client;

  /**
   * Should we run the gnunet-nat-server?
   */
  int enable_nat_server;

  /**
   * Are we allowed to try UPnP/PMP for NAT traversal?
   */
  int enable_upnp;

};


/**
 * Our external IP address/port mapping has changed.
 *
 * @param cls closure, the 'struct LocalAddrList'
 * @param add_remove GNUNET_YES to mean the new public IP address, GNUNET_NO to mean
 *     the previous (now invalid) one
 * @param addr either the previous or the new public IP address
 * @param addrlen actual lenght of the address
 */
static void
nat_port_map_callback (void *cls,
		       int add_remove,
		       const struct sockaddr *addr,
		       socklen_t addrlen)
{
  struct LocalAddrList *lal = cls;
  struct Plugin *plugin = lal->plugin;
  int af;
  struct IPv4TcpAddress t4;
  struct IPv6TcpAddress t6;
  void *arg;
  uint16_t args;

  /* convert 'addr' to our internal format */
  af = addr->sa_family;
  switch (af)
    {
    case AF_INET:
      t4.ipv4_addr = ((struct sockaddr_in *) addr)->sin_addr.s_addr;
      t6.t6_port = ((struct sockaddr_in *) addr)->sin_port;
      arg = &t4;
      args = sizeof (t4);
      break;
    case AF_INET6:
      memcpy (&t6.ipv6_addr,
	      &((struct sockaddr_in6 *) addr)->sin6_addr,
	      sizeof (struct in6_addr));
      t6.t6_port = ((struct sockaddr_in6 *) addr)->sin6_port;
      arg = &t6;
      args = sizeof (t6);    
      break;
    default:
      GNUNET_break (0);
      return;
    } 

  /* modify our published address list */
  if (GNUNET_YES == add_remove)
    {
      plugin->env->notify_address (plugin->env->cls,
                                   "tcp",
                                   arg, args, GNUNET_TIME_UNIT_FOREVER_REL);
      GNUNET_free_non_null (lal->external_nat_address);
      lal->external_nat_address = GNUNET_memdup (arg, args);
      lal->ena_size = args;
    }
  else
    {
      plugin->env->notify_address (plugin->env->cls,
                                   "tcp",
                                   arg, args, GNUNET_TIME_UNIT_ZERO);
      GNUNET_free_non_null (lal->external_nat_address);
      lal->ena_size = 0;
    }
}


/**
 * Add the given address to the list of 'local' addresses, thereby
 * making it a 'legal' address for this peer to have.  
 * 
 * @param plugin the plugin
 * @param arg the address, either an IPv4 or an IPv6 IP address
 * @param arg_size number of bytes in arg
 */
static void
add_to_address_list (struct Plugin *plugin,
		     const void *arg,
		     size_t arg_size)
{
  struct LocalAddrList *lal;
  struct sockaddr_in v4;
  struct sockaddr_in6 v6;
  const struct sockaddr *sa;
  socklen_t salen;

  lal = plugin->lal_head;
  while (NULL != lal)
    {
      if ( (lal->size == arg_size) &&
	   (0 == memcmp (&lal[1], arg, arg_size)) )
	return;
      lal = lal->next;
    }
  lal = GNUNET_malloc (sizeof (struct LocalAddrList) + arg_size);
  lal->plugin = plugin;
  lal->size = arg_size;
  memcpy (&lal[1], arg, arg_size);
  GNUNET_CONTAINER_DLL_insert (plugin->lal_head,
			       plugin->lal_tail,
			       lal);
  if (plugin->open_port == 0)
    return; /* we're not listening at all... */
  if (arg_size == sizeof (struct in_addr))
    {
      memset (&v4, 0, sizeof (v4));
      v4.sin_family = AF_INET;
      v4.sin_port = htons (plugin->open_port);
      memcpy (&v4.sin_addr, arg, arg_size);
#if HAVE_SOCKADDR_IN_SIN_LEN
      v4.sin_len = sizeof (struct sockaddr_in);
#endif
      sa = (const struct sockaddr*) &v4;
      salen = sizeof (v4);
    }
  else if (arg_size == sizeof (struct in6_addr))
    {     
      memset (&v6, 0, sizeof (v6));
      v6.sin6_family = AF_INET6;
      v6.sin6_port = htons (plugin->open_port);
      memcpy (&v6.sin6_addr, arg, arg_size);
#if HAVE_SOCKADDR_IN_SIN_LEN
      v6.sin6_len = sizeof (struct sockaddr_in6);
#endif
      sa = (const struct sockaddr*) &v6;
      salen = sizeof (v6);
    }
  else
    {
      GNUNET_break (0);
      return;
    }
  if ( (plugin->behind_nat == GNUNET_YES) &&
       (plugin->enable_upnp == GNUNET_YES) )
    lal->nat = GNUNET_NAT_register (sa, salen,
				    &nat_port_map_callback,
				    lal);
}


/**
 * Check if the given address is in the list of 'local' addresses.
 * 
 * @param plugin the plugin
 * @param arg the address, either an IPv4 or an IPv6 IP address
 * @param arg_size number of bytes in arg
 * @return GNUNET_OK if this is one of our IPs, GNUNET_SYSERR if not
 */
static int
check_local_addr (struct Plugin *plugin,
		  const void *arg,
		  size_t arg_size)
{
  struct LocalAddrList *lal;

  lal = plugin->lal_head;
  while (NULL != lal)
    {
      if ( (lal->size == arg_size) &&
	   (0 == memcmp (&lal[1], arg, arg_size)) )
	return GNUNET_OK;
      lal = lal->next;
    }
  return GNUNET_SYSERR;
}


/**
 * Check if the given address is in the list of 'mapped' addresses.
 * 
 * @param plugin the plugin
 * @param arg the address, either a 'struct IPv4TcpAddress' or a 'struct IPv6TcpAddress'
 * @param arg_size number of bytes in arg
 * @return GNUNET_OK if this is one of our IPs, GNUNET_SYSERR if not
 */
static int
check_mapped_addr (struct Plugin *plugin,
		   const void *arg,
		   size_t arg_size)
{
  struct LocalAddrList *lal;

  lal = plugin->lal_head;
  while (NULL != lal)
    {
      if ( (lal->ena_size == arg_size) &&
	   (0 == memcmp (lal->external_nat_address, arg, arg_size)) )
	return GNUNET_OK;
      lal = lal->next;
    }
  return GNUNET_SYSERR;
}


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
		       _("Unexpected address length: %u bytes\n"),
		       (unsigned int) addrlen);
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
 * @param plugin the plugin
 * @param client which client to find the session handle for
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
 * @param plugin the plugin
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
                struct GNUNET_SERVER_Client *client, 
		int is_nat)
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
  ret->is_nat = is_nat;
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
	      (pos->timeout.abs_value <= now.abs_value) )
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
		   "tcp",
		   "Transmitting %u bytes\n", 
		   ret);
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
                   "Disconnecting from `%4s' at %s.\n",
                   GNUNET_i2s (&session->target),
                   (session->connect_addr != NULL) ?
                   tcp_address_to_string (session->plugin,
					  session->connect_addr,
					  session->connect_alen) : "*");
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
                       : "Could not deliver message to `%4s', notifying.\n",
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
      GNUNET_SCHEDULER_cancel (session->receive_delay_task);
      if (session->client != NULL)
	GNUNET_SERVER_receive_done (session->client,
				    GNUNET_SYSERR);	
    }
  else if (session->client != NULL)
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
  if (s1->last_activity.abs_value < s2->last_activity.abs_value)
    return s2;
  if (s1->last_activity.abs_value > s2->last_activity.abs_value)
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
 * gnunet-nat-client to send dummy ICMP responses.
 *
 * @param plugin the plugin for this transport
 * @param sa the address of the peer (IPv4-only)
 */
static void
run_gnunet_nat_client (struct Plugin *plugin, 
		       const struct sockaddr_in *sa)
{
  char inet4[INET_ADDRSTRLEN];
  char port_as_string[6];
  struct GNUNET_OS_Process *proc;

  if (plugin->internal_address == NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
		       "tcp",
		       _("Internal IP address not known, cannot use ICMP NAT traversal method\n"));
      return;
    }
  GNUNET_assert (sa->sin_family == AF_INET);
  if (NULL == inet_ntop (AF_INET,
			 &sa->sin_addr,
			 inet4, INET_ADDRSTRLEN))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "inet_ntop");
      return;
    }
  GNUNET_snprintf(port_as_string, 
		  sizeof (port_as_string),
		  "%d", 
		  plugin->adv_port);
#if DEBUG_TCP_NAT
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "tcp",
		   _("Running gnunet-nat-client %s %s %u\n"), 
		   plugin->internal_address,
		   inet4,
		   (unsigned int) plugin->adv_port);
#endif
  proc = GNUNET_OS_start_process (NULL, 
				  NULL, 
				  "gnunet-nat-client",
				  "gnunet-nat-client",
				  plugin->internal_address, 
				  inet4,
				  port_as_string, 
				  NULL);
  if (NULL == proc)
    return;
  /* we know that the gnunet-nat-client will terminate virtually
     instantly */
  GNUNET_OS_process_wait (proc);
  GNUNET_OS_process_close (proc);
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
	  if ( (addrlen != session->connect_alen) && 
	       (session->is_nat == GNUNET_NO) )
	    continue;
	  if ((0 != memcmp (session->connect_addr,
			   addr,
			   addrlen)) && (session->is_nat == GNUNET_NO))
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


      if ( (plugin->enable_nat_client == GNUNET_YES) && 
	   (is_natd == GNUNET_YES) &&
           (GNUNET_NO == GNUNET_CONTAINER_multihashmap_contains(plugin->nat_wait_conns,
								&target->hashPubKey)) )
        {
#if DEBUG_TCP_NAT
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
			   "tcp",
                           _("Found valid IPv4 NAT address (creating session)!\n"));
#endif
          session = create_session (plugin,
                                    target,
                                    NULL, 
				    GNUNET_YES);

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

          GNUNET_assert(GNUNET_CONTAINER_multihashmap_put(plugin->nat_wait_conns,
							  &target->hashPubKey,
							  session, 
							  GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY) == GNUNET_OK);
#if DEBUG_TCP_NAT
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
			   "tcp",
                           "Created NAT WAIT connection to `%4s' at `%s'\n",
                           GNUNET_i2s (target),
                           GNUNET_a2s (sb, sbs));
#endif
          run_gnunet_nat_client (plugin, &a4);
          return 0;
        }
      if ( (plugin->enable_nat_client == GNUNET_YES) && 
	   (is_natd == GNUNET_YES) && 
	   (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains(plugin->nat_wait_conns, 
								 &target->hashPubKey)) )
        {
          /* Only do one NAT punch attempt per peer identity */
          return -1;
        }
      sa = GNUNET_CONNECTION_create_from_sockaddr (af, sb, sbs);
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
#if DEBUG_TCP_NAT
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		       "tcp",
                       "Asked to transmit to `%4s', creating fresh session using address `%s'.\n",
		       GNUNET_i2s (target),
		       GNUNET_a2s (sb, sbs));
#endif
      session = create_session (plugin,
				target,
				GNUNET_SERVER_connect_socket (plugin->server,
							      sa), 
				GNUNET_NO);
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
      GNUNET_STATISTICS_update (session->plugin->env->stats,
				gettext_noop ("# transport-service disconnect requests for TCP"),
				1,
				GNUNET_NO);
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
  GNUNET_RESOLVER_hostname_get (plugin->env->cfg,
                                sb,
                                sbs,
                                !numeric, timeout, &append_port, ppc);
}


/**
 * Check if the given port is plausible (must be either our listen
 * port or our advertised port), or any port if we are behind NAT
 * and do not have a port open.  If it is neither, we return
 * GNUNET_SYSERR.
 *
 * @param plugin global variables
 * @param in_port port number to check
 * @return GNUNET_OK if port is either open_port or adv_port
 */
static int
check_port (struct Plugin *plugin, 
	    uint16_t in_port)
{
  if ((in_port == plugin->adv_port) || (in_port == plugin->open_port))
    return GNUNET_OK;
  return GNUNET_SYSERR;
}


/**
 * Function that will be called to check if a binary address for this
 * plugin is well-formed and corresponds to an address for THIS peer
 * (as per our configuration).  Naturally, if absolutely necessary,
 * plugins can be a bit conservative in their answer, but in general
 * plugins should make sure that the address does not redirect
 * traffic to a 3rd party that might try to man-in-the-middle our
 * traffic.
 *
 * @param cls closure, our 'struct Plugin*'
 * @param addr pointer to the address
 * @param addrlen length of addr
 * @return GNUNET_OK if this is a plausible address for this peer
 *         and transport, GNUNET_SYSERR if not
 */
static int
tcp_plugin_check_address (void *cls,
			  const void *addr,
			  size_t addrlen)
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
      if (GNUNET_OK ==
	  check_mapped_addr (plugin, v4, sizeof (struct IPv4TcpAddress)))
	return GNUNET_OK;
      if (GNUNET_OK !=
	  check_port (plugin, ntohs (v4->t_port)))
	return GNUNET_SYSERR;
      if (GNUNET_OK !=
	  check_local_addr (plugin, &v4->ipv4_addr, sizeof (struct in_addr)))
	return GNUNET_SYSERR;	
    }
  else
    {
      v6 = (struct IPv6TcpAddress *) addr;
      if (IN6_IS_ADDR_LINKLOCAL (&v6->ipv6_addr))
	{
	  GNUNET_break_op (0);
	  return GNUNET_SYSERR;
	}
      if (GNUNET_OK ==
	  check_mapped_addr (plugin, v6, sizeof (struct IPv6TcpAddress)))
	return GNUNET_OK;
      if (GNUNET_OK !=
	  check_port (plugin, ntohs (v6->t6_port)))
	return GNUNET_SYSERR;
      if (GNUNET_OK !=
	  check_local_addr (plugin, &v6->ipv6_addr, sizeof (struct in6_addr)))
	return GNUNET_SYSERR;
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
  const struct TCP_NAT_ProbeMessage *tcp_nat_probe;
  size_t alen;
  void *vaddr;
  struct IPv4TcpAddress *t4;
  struct IPv6TcpAddress *t6;
  const struct sockaddr_in *s4;
  const struct sockaddr_in6 *s6;

#if DEBUG_TCP_NAT
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, 
		   "tcp",
		   "received tcp NAT probe\n");
#endif
  /* We have received a TCP NAT probe, meaning we (hopefully) initiated
   * a connection to this peer by running gnunet-nat-client.  This peer
   * received the punch message and now wants us to use the new connection
   * as the default for that peer.  Do so and then send a WELCOME message
   * so we can really be connected!
   */
  if (ntohs(message->size) != sizeof(struct TCP_NAT_ProbeMessage))
    {
      GNUNET_break_op(0);
      return;
    }
  tcp_nat_probe = (const struct TCP_NAT_ProbeMessage *)message;
  session = GNUNET_CONTAINER_multihashmap_get(plugin->nat_wait_conns, 
					      &tcp_nat_probe->clientIdentity.hashPubKey);
  if (session == NULL)
    {
#if DEBUG_TCP_NAT
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		       "tcp",
		       "Did NOT find session for NAT probe!\n");
#endif
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
      return;
    }
#if DEBUG_TCP_NAT
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, 
		   "tcp",
		   "Found session for NAT probe!\n");
#endif
  GNUNET_assert(GNUNET_CONTAINER_multihashmap_remove(plugin->nat_wait_conns, 
						     &tcp_nat_probe->clientIdentity.hashPubKey,
						     session) == GNUNET_YES);
  if (GNUNET_OK !=
      GNUNET_SERVER_client_get_address (client, &vaddr, &alen))
    {
      GNUNET_break (0);
      GNUNET_free (session);
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
      return;
    }

  GNUNET_SERVER_client_keep (client);
  session->client = client;
  session->last_activity = GNUNET_TIME_absolute_get ();
  session->inbound = GNUNET_NO;

#if DEBUG_TCP_NAT
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "tcp",
		   "Found address `%s' for incoming connection\n",
		   GNUNET_a2s (vaddr, alen));
#endif
  switch (((const struct sockaddr *)vaddr)->sa_family)
    {
    case AF_INET:
      s4 = vaddr;
      t4 = GNUNET_malloc (sizeof (struct IPv4TcpAddress));
      t4->t_port = s4->sin_port;
      t4->ipv4_addr = s4->sin_addr.s_addr;
      session->connect_addr = t4;
      session->connect_alen = sizeof (struct IPv4TcpAddress);
      break;
    case AF_INET6:    
      s6 = vaddr;
      t6 = GNUNET_malloc (sizeof (struct IPv6TcpAddress));
      t6->t6_port = s6->sin6_port;
      memcpy (&t6->ipv6_addr,
	      &s6->sin6_addr,
	      sizeof (struct in6_addr));
      session->connect_addr = t6;
      session->connect_alen = sizeof (struct IPv6TcpAddress);
      break;
    default:
      GNUNET_break_op (0);
#if DEBUG_TCP_NAT
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		       "tcp",
		       "Bad address for incoming connection!\n");
#endif
      GNUNET_free (vaddr);
      GNUNET_SERVER_client_drop (client);
      GNUNET_free (session);
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  GNUNET_free (vaddr);
  
  session->next = plugin->sessions;
  plugin->sessions = session;
  GNUNET_STATISTICS_update (plugin->env->stats,
			    gettext_noop ("# TCP sessions active"),
			    1,
			    GNUNET_NO);
  process_pending_messages (session);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
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
                   "Received %s message from `%4s'.\n",
		   "WELCOME",
                   GNUNET_i2s (&wm->clientIdentity));
#endif
  GNUNET_STATISTICS_update (plugin->env->stats,
			    gettext_noop ("# TCP WELCOME messages received"),
			    1,
			    GNUNET_NO);
  session = find_session_by_client (plugin, client);

  if (session == NULL)
    {
#if DEBUG_TCP_NAT
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		       "tcp",
                       "Received %s message from a `%4s', creating new session\n",
                       "WELCOME",
                       GNUNET_i2s (&wm->clientIdentity));
#endif
      GNUNET_SERVER_client_keep (client);
      session = create_session (plugin,
				&wm->clientIdentity,
				client,
				GNUNET_NO);
      session->inbound = GNUNET_YES;
      if (GNUNET_OK ==
	  GNUNET_SERVER_client_get_address (client, &vaddr, &alen))
	{
#if DEBUG_TCP_NAT
	  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
			   "tcp",
			   "Found address `%s' for incoming connection\n",
			   GNUNET_a2s (vaddr, alen));
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
      process_pending_messages (session);
    }
  else
    {
#if DEBUG_TCP_NAT
    if (GNUNET_OK ==
        GNUNET_SERVER_client_get_address (client, &vaddr, &alen))
      {
        GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
			 "tcp",
			 "Found address `%s' (already have session)\n",
			 GNUNET_a2s (vaddr, alen));
	GNUNET_free (vaddr);
      }
#endif
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
delayed_done (void *cls, 
	      const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Session *session = cls;
  struct GNUNET_TIME_Relative delay;

  session->receive_delay_task = GNUNET_SCHEDULER_NO_TASK;
  delay = session->plugin->env->receive (session->plugin->env->cls,
					 &session->target,
					 NULL,
					 NULL, 0,
					 session,
					 NULL, 0);
  if (delay.rel_value == 0)
    GNUNET_SERVER_receive_done (session->client, GNUNET_OK);
  else
    session->receive_delay_task =
      GNUNET_SCHEDULER_add_delayed (delay, &delayed_done, session);
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
  uint16_t type;

  type = ntohs (message->type);
  if ( (GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_WELCOME == type) || 
       (GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_NAT_PROBE == type) )
    {
      /* We don't want to propagate WELCOME and NAT Probe messages up! */
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
      return;
    }
  session = find_session_by_client (plugin, client);
  if ( (NULL == session) || (GNUNET_YES == session->expecting_welcome) )
    {
      GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
      return;
    }
  session->last_activity = GNUNET_TIME_absolute_get ();
#if DEBUG_TCP > 1
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
  struct GNUNET_TRANSPORT_ATS_Information distance[2];
  distance[0].type = htonl (GNUNET_TRANSPORT_ATS_QUALITY_NET_DISTANCE);
  distance[0].value = htonl (1);
  distance[1].type = htonl (GNUNET_TRANSPORT_ATS_ARRAY_TERMINATOR);
  distance[1].value = htonl (0);
  delay = plugin->env->receive (plugin->env->cls, &session->target, message,
				(const struct GNUNET_TRANSPORT_ATS_Information *) &distance,
				2,
				session,
				(GNUNET_YES == session->inbound) ? NULL : session->connect_addr,
				(GNUNET_YES == session->inbound) ? 0 : session->connect_alen);
  if (delay.rel_value == 0)
    {
      GNUNET_SERVER_receive_done (client, GNUNET_OK);
    }
  else
    {
#if DEBUG_TCP 
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		       "tcp",
		       "Throttling receiving from `%s' for %llu ms\n",
		       GNUNET_i2s (&session->target),
		       (unsigned long long) delay.rel_value);
#endif
      GNUNET_SERVER_disable_receive_done_warning (client);
      session->receive_delay_task =
	GNUNET_SCHEDULER_add_delayed (delay, &delayed_done, session);
    }
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
                   "Destroying session of `%4s' with %s due to network-level disconnect.\n",
                   GNUNET_i2s (&session->target),
                   (session->connect_addr != NULL) ?
                   tcp_address_to_string (session->plugin,
					  session->connect_addr,
					  session->connect_alen) : "*");
#endif
  GNUNET_STATISTICS_update (session->plugin->env->stats,
			    gettext_noop ("# network-level TCP disconnect events"),
			    1,
			    GNUNET_NO);
  disconnect_session (session);
}


static int check_localaddress (const struct sockaddr *addr, socklen_t addrlen)
{
	uint32_t res = 0;
	int local = GNUNET_NO;
	int af = addr->sa_family;
    switch (af)
    {
      case AF_INET:
      {
    	  uint32_t netmask = 0x7F000000;
    	  uint32_t address = ntohl (((struct sockaddr_in *) addr)->sin_addr.s_addr);
    	  res = (address >> 24) ^ (netmask >> 24);
    	  if (res != 0)
    		  local = GNUNET_NO;
    	  else
    		  local = GNUNET_YES;
#if DEBUG_TCP
    	    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
    			  "Checking IPv4 address `%s': %s\n", GNUNET_a2s (addr, addrlen), (local==GNUNET_YES) ? "local" : "global");
#endif
    	    break;
      }
      case AF_INET6:
      {
    	   if (IN6_IS_ADDR_LOOPBACK  (&((struct sockaddr_in6 *) addr)->sin6_addr) ||
    		   IN6_IS_ADDR_LINKLOCAL (&((struct sockaddr_in6 *) addr)->sin6_addr))
    		   local = GNUNET_YES;
    	   else
    		   local = GNUNET_NO;
#if DEBUG_TCP
    	   GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
    			  "Checking IPv6 address `%s' : %s\n", GNUNET_a2s (addr, addrlen), (local==GNUNET_YES) ? "local" : "global");
#endif
    	   break;
      }
    }
	return local;
}

/**
 * Add the IP of our network interface to the list of
 * our internal IP addresses.
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
  char buf[INET6_ADDRSTRLEN];

  af = addr->sa_family;
  arg_nat = NULL;

  if (plugin->use_localaddresses == GNUNET_NO)
  {
	  if (GNUNET_YES == check_localaddress (addr, addrlen))
	  {
#if DEBUG_TCP
          GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
        	   "tcp",
			   "Not notifying transport of address `%s' (local address)\n",
			   GNUNET_a2s (addr, addrlen));
#endif
		  return GNUNET_OK;
	  }
  }

  switch (af)
    {
    case AF_INET:
      t4.ipv4_addr = ((struct sockaddr_in *) addr)->sin_addr.s_addr;
      GNUNET_assert (NULL != inet_ntop(AF_INET, 
				       &t4.ipv4_addr, 
				       buf, 
				       sizeof (buf)));
      if ( (plugin->bind_address != NULL) && 
	   (0 != strcmp(buf, plugin->bind_address)) )
        {
#if DEBUG_TCP
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, 
			   "tcp",
			   "Not notifying transport of address `%s' (does not match bind address)\n",
			   GNUNET_a2s (addr, addrlen));
#endif
          return GNUNET_OK;
        }
      if ( (plugin->internal_address == NULL) &&
	   (isDefault) )	
	plugin->internal_address = GNUNET_strdup (buf);	
      add_to_address_list (plugin, &t4.ipv4_addr, sizeof (struct in_addr));
      if (plugin->behind_nat == GNUNET_YES) 
        {
	  /* Also advertise as NAT (with port 0) */
          t4_nat.ipv4_addr = ((struct sockaddr_in *) addr)->sin_addr.s_addr;
          t4_nat.t_port = htons(0);
          arg_nat = &t4_nat;
        }	
      t4.t_port = htons (plugin->adv_port);	
      arg = &t4;
      args = sizeof (t4);
      break;
    case AF_INET6:      
      if ( (IN6_IS_ADDR_LINKLOCAL (&((struct sockaddr_in6 *) addr)->sin6_addr)) || 
	   (GNUNET_YES == GNUNET_CONFIGURATION_get_value_yesno(plugin->env->cfg, 
							       "nat", 
							       "DISABLEV6")) )
	{
	  /* skip link local addresses */
	  return GNUNET_OK;
	}
      memcpy (&t6.ipv6_addr,
	      &((struct sockaddr_in6 *) addr)->sin6_addr,
	      sizeof (struct in6_addr));

      /* check bind address */
      GNUNET_assert (NULL != inet_ntop(AF_INET6,
				       &t6.ipv6_addr,
				       buf,
				       sizeof (buf)));

      if ( (plugin->bind_address != NULL) &&
	   (0 != strcmp(buf, plugin->bind_address)) )
        {
#if DEBUG_TCP
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
			   "tcp",
			   "Not notifying transport of address `%s' (does not match bind address)\n",
			   GNUNET_a2s (addr, addrlen));
#endif
          return GNUNET_OK;
        }

      add_to_address_list (plugin, 
			   &t6.ipv6_addr, 
			   sizeof (struct in6_addr));
      if (plugin->behind_nat == GNUNET_YES)
        {
	  /* Also advertise as NAT (with port 0) */
          memcpy (&t6_nat.ipv6_addr,
                  &((struct sockaddr_in6 *) addr)->sin6_addr,
                  sizeof (struct in6_addr));
          t6_nat.t6_port = htons(0);
          arg_nat = &t6;
        }
      t6.t6_port = htons (plugin->adv_port);
      arg = &t6;
      args = sizeof (t6);
      break;
    default:
      GNUNET_break (0);
      return GNUNET_OK;
    }
  if (plugin->adv_port != 0)
  {
#if DEBUG_TCP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "tcp",
		   "Found address `%s' (%s) len %d\n",
                   GNUNET_a2s (addr, addrlen), name, args);
#endif
  plugin->env->notify_address (plugin->env->cls,
                               "tcp",
                               arg, args, GNUNET_TIME_UNIT_FOREVER_REL);
  }

  if (arg_nat != NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		       "tcp",
		       _("Found address `%s' (%s) len %d\n"),
		       GNUNET_a2s (addr, addrlen), name, args);
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
 * @return number of bytes copied into buf
 */
static size_t
notify_send_probe (void *cls,
		   size_t size,
		   void *buf)
{
  struct TCPProbeContext *tcp_probe_ctx = cls;
  struct Plugin *plugin = tcp_probe_ctx->plugin;
  size_t ret;

  tcp_probe_ctx->transmit_handle = NULL;
  GNUNET_CONTAINER_DLL_remove (plugin->probe_head,
			       plugin->probe_tail,
			       tcp_probe_ctx);
  if (buf == NULL)
    {
      GNUNET_CONNECTION_destroy (tcp_probe_ctx->sock, GNUNET_NO);
      GNUNET_free(tcp_probe_ctx);
      return 0;    
    }
  GNUNET_assert(size >= sizeof(tcp_probe_ctx->message));
  memcpy(buf, &tcp_probe_ctx->message, sizeof(tcp_probe_ctx->message));
  GNUNET_SERVER_connect_socket (tcp_probe_ctx->plugin->server,
                                tcp_probe_ctx->sock);
  ret = sizeof(tcp_probe_ctx->message);
  GNUNET_free(tcp_probe_ctx);
  return ret;
}


/**
 * We have been notified that gnunet-nat-server has written something to stdout.
 * Handle the output, then reschedule this function to be called again once
 * more is available.
 *
 * @param cls the plugin handle
 * @param tc the scheduling context
 */
static void
tcp_plugin_server_read (void *cls, 
			const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  char mybuf[40];
  ssize_t bytes;
  size_t i;
  int port;
  const char *port_start;
  struct sockaddr_in sin_addr;
  struct TCPProbeContext *tcp_probe_ctx;
  struct GNUNET_CONNECTION_Handle *sock;

  if ( (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN) != 0)
    return;
  memset (mybuf, 0, sizeof(mybuf));
  bytes = GNUNET_DISK_file_read(plugin->server_stdout_handle, 
				mybuf,
				sizeof(mybuf));
  if (bytes < 1)
    {
#if DEBUG_TCP_NAT
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		       "tcp",
		       "Finished reading from server stdout with code: %d\n", 
		       bytes);
#endif
      /* FIXME: consider process_wait here? */
      return;
    }

  port_start = NULL;
  for (i = 0; i < sizeof(mybuf); i++)
    {
      if (mybuf[i] == '\n')
	{
	  mybuf[i] = '\0';
	  break;
	}
      if ( (mybuf[i] == ':') && (i + 1 < sizeof(mybuf)) )
        {
          mybuf[i] = '\0';
          port_start = &mybuf[i + 1];
        }
    }

  /* construct socket address of sender */
  memset (&sin_addr, 0, sizeof (sin_addr));
  sin_addr.sin_family = AF_INET;
#if HAVE_SOCKADDR_IN_SIN_LEN
  sin_addr.sin_len = sizeof (sin_addr);
#endif
  if ( (NULL == port_start) ||
       (1 != sscanf (port_start, "%d", &port)) ||
       (-1 == inet_pton(AF_INET, mybuf, &sin_addr.sin_addr)) )
    {
      /* should we restart gnunet-nat-server? */
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
		       "tcp",
		       _("gnunet-nat-server generated malformed address `%s'\n"),
		       mybuf);
      plugin->server_read_task 
	= GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
					  plugin->server_stdout_handle,
					  &tcp_plugin_server_read, 
					  plugin);
      return;
    }
  sin_addr.sin_port = htons((uint16_t) port);
#if DEBUG_TCP_NAT
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "tcp",
		   "gnunet-nat-server read: %s:%d\n", 
		   mybuf, port);
#endif

  /**
   * We have received an ICMP response, ostensibly from a peer
   * that wants to connect to us! Send a message to establish a connection.
   */
  sock = GNUNET_CONNECTION_create_from_sockaddr (AF_INET, 
						 (const struct sockaddr *)&sin_addr,
                                                 sizeof (sin_addr));
  if (sock == NULL)
    {
      /* failed for some odd reason (out of sockets?); ignore attempt */
      plugin->server_read_task =
          GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                          plugin->server_stdout_handle, 
					  &tcp_plugin_server_read, 
					  plugin);
      return;
    }

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "Sending TCP probe message to `%s:%u'!\n", 
		   mybuf,
		   (unsigned int) port);  
  /* FIXME: do we need to track these probe context objects so that
     we can clean them up on plugin unload? */
  tcp_probe_ctx
    = GNUNET_malloc(sizeof(struct TCPProbeContext));
  tcp_probe_ctx->message.header.size
    = htons(sizeof(struct TCP_NAT_ProbeMessage));
  tcp_probe_ctx->message.header.type
    = htons(GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_NAT_PROBE);
  memcpy (&tcp_probe_ctx->message.clientIdentity,
	  plugin->env->my_identity,
	  sizeof(struct GNUNET_PeerIdentity));
  tcp_probe_ctx->plugin = plugin;
  tcp_probe_ctx->sock = sock;
  GNUNET_CONTAINER_DLL_insert (plugin->probe_head,
			       plugin->probe_tail,
			       tcp_probe_ctx);
  tcp_probe_ctx->transmit_handle 
    = GNUNET_CONNECTION_notify_transmit_ready (sock,
					       ntohs (tcp_probe_ctx->message.header.size),
					       GNUNET_TIME_UNIT_FOREVER_REL,
					       &notify_send_probe, tcp_probe_ctx);
  
  plugin->server_read_task =
      GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                      plugin->server_stdout_handle,
				      &tcp_plugin_server_read,
				      plugin);
}


/**
 * Start the gnunet-nat-server process for users behind NAT.
 *
 * @param plugin the transport plugin
 * @return GNUNET_YES if process was started, GNUNET_SYSERR on error
 */
static int
tcp_transport_start_nat_server (struct Plugin *plugin)
{
  if (plugin->internal_address == NULL)
    return GNUNET_SYSERR;
  plugin->server_stdout = GNUNET_DISK_pipe (GNUNET_YES,
					    GNUNET_NO,
					    GNUNET_YES);
  if (plugin->server_stdout == NULL)
    return GNUNET_SYSERR;
#if DEBUG_TCP_NAT
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
		   "tcp"
                   "Starting %s %s\n", "gnunet-nat-server", plugin->internal_address);
#endif
  /* Start the server process */
  plugin->server_proc = GNUNET_OS_start_process (NULL,
						 plugin->server_stdout,
						 "gnunet-nat-server", 
						 "gnunet-nat-server", 
						 plugin->internal_address, 
						 NULL);
  if (plugin->server_proc == NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
		       "tcp",
		       _("Failed to start %s\n"),
		       "gnunet-nat-server");
      GNUNET_DISK_pipe_close (plugin->server_stdout);
      plugin->server_stdout = NULL;    
      return GNUNET_SYSERR;
    }
  /* Close the write end of the read pipe */
  GNUNET_DISK_pipe_close_end(plugin->server_stdout, 
			     GNUNET_DISK_PIPE_END_WRITE);
  plugin->server_stdout_handle 
    = GNUNET_DISK_pipe_handle (plugin->server_stdout, 
			       GNUNET_DISK_PIPE_END_READ);
  plugin->server_read_task 
    = GNUNET_SCHEDULER_add_read_file (GNUNET_TIME_UNIT_FOREVER_REL,
                                      plugin->server_stdout_handle,
				      &tcp_plugin_server_read, 
				      plugin);
  return GNUNET_YES;
}


/**
 * Return the actual path to a file found in the current
 * PATH environment variable.
 *
 * @param binary the name of the file to find
 * @return path to binary, NULL if not found
 */
static char *
get_path_from_PATH (const char *binary)
{
  char *path;
  char *pos;
  char *end;
  char *buf;
  const char *p;

  p = getenv ("PATH");
  if (p == NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
		       "tcp",
		       _("PATH environment variable is unset.\n"));
      return NULL;
    }
  path = GNUNET_strdup (p);     /* because we write on it */
  buf = GNUNET_malloc (strlen (path) + 20);
  pos = path;

  while (NULL != (end = strchr (pos, PATH_SEPARATOR)))
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
 * @return GNUNET_YES if the file is SUID, 
 *         GNUNET_NO if not, 
 *         GNUNET_SYSERR on error
 */
static int
check_gnunet_nat_binary (const char *binary)
{
  struct stat statbuf;
  char *p;
#ifdef MINGW
  SOCKET rawsock;
  char *binaryexe;

  GNUNET_asprintf (&binaryexe, "%s.exe", binary);
  p = get_path_from_PATH (binaryexe);
  free (binaryexe);
#else
  p = get_path_from_PATH (binary);
#endif
  if (p == NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
		       "tcp",
		       _("Could not find binary `%s' in PATH!\n"),
		       binary);
      return GNUNET_NO;
    }
  if (0 != STAT (p, &statbuf))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING, 
		  _("stat (%s) failed: %s\n"), 
		  p,
		  STRERROR (errno));
      GNUNET_free (p);
      return GNUNET_SYSERR;
    }
  GNUNET_free (p);
#ifndef MINGW
  if ( (0 != (statbuf.st_mode & S_ISUID)) &&
       (statbuf.st_uid == 0) )
    return GNUNET_YES;
  return GNUNET_NO;
#else
  rawsock = socket (AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (INVALID_SOCKET == rawsock)
    {
      DWORD err = GetLastError ();
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, 
		       "tcp",
		       "socket (AF_INET, SOCK_RAW, IPPROTO_ICMP) failed! GLE = %d\n", err);
      return GNUNET_NO; /* not running as administrator */
    }
  closesocket (rawsock);
  return GNUNET_YES;
#endif
}


/**
 * Our (external) hostname was resolved.
 *
 * @param cls the 'struct Plugin'
 * @param addr NULL on error, otherwise result of DNS lookup
 * @param addrlen number of bytes in addr
 */
static void
process_external_ip (void *cls,
		     const struct sockaddr *addr,
		     socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  const struct sockaddr_in *s;
  struct IPv4TcpAddress t4;
  char buf[INET_ADDRSTRLEN];

  plugin->ext_dns = NULL;
  if (addr == NULL)
    return;
  GNUNET_assert (addrlen == sizeof (struct sockaddr_in));
  s = (const struct sockaddr_in *) addr;
  t4.ipv4_addr = s->sin_addr.s_addr;
  if ( (plugin->behind_nat == GNUNET_YES) &&
       (plugin->enable_nat_server == GNUNET_YES) )
    {
      t4.t_port = htons(0);
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, 
		       "tcp",
		       "Notifying transport of address %s:%d\n",
		       plugin->external_address,
		       0);
    }
  else
    {
      t4.t_port = htons(plugin->adv_port);
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, 
		       "tcp",
		       "Notifying transport of address %s:%d\n",
		       plugin->external_address, 
		       (int) plugin->adv_port);
    }

  if ((plugin->bind_address != NULL) && (plugin->behind_nat == GNUNET_NO))
  {
      GNUNET_assert (NULL != inet_ntop(AF_INET,
				       &t4.ipv4_addr,
				       buf,
				       sizeof (buf)));
      if (0 != strcmp (plugin->bind_address, buf))
      {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
		       "tcp",
		       "NAT is not enabled and specific bind address `%s' differs from external address `%s'! Not notifying about external address `%s'\n",
		       plugin->bind_address,
		       plugin->external_address,
		       plugin->external_address);
      return;
      }
  }

  add_to_address_list (plugin, 
		       &t4.ipv4_addr, 
		       sizeof (struct in_addr));

  plugin->env->notify_address (plugin->env->cls,
			       "tcp",
			       &t4, sizeof(t4),
			       GNUNET_TIME_UNIT_FOREVER_REL);
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
  int nat_punched;
  int enable_nat_client;
  int enable_nat_server;
  int enable_upnp;
  int use_localaddresses;
  char *internal_address;
  char *external_address;
  char *bind_address;
  struct sockaddr_in in_addr;
  struct GNUNET_TIME_Relative idle_timeout;

  behind_nat = GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
						     "nat",
						     "BEHIND_NAT");
  nat_punched = GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
						      "nat",
						      "NAT_PUNCHED");
  enable_nat_client = GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
							    "nat",
							    "ENABLE_NAT_CLIENT");
  enable_nat_server = GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
							    "nat",
							    "ENABLE_NAT_SERVER");
  enable_upnp = GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
						      "nat",
						      "ENABLE_UPNP");
  
  if ( (GNUNET_YES == enable_nat_server) &&
       (GNUNET_YES != check_gnunet_nat_binary("gnunet-nat-server")) )
    {
      enable_nat_server = GNUNET_NO;
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Configuration requires `%s', but binary is not installed properly (SUID bit not set).  Option disabled.\n"),
		  "gnunet-nat-server");        
    }

  if ( (GNUNET_YES == enable_nat_client) &&
       (GNUNET_YES != check_gnunet_nat_binary("gnunet-nat-client")) )
    {
      enable_nat_client = GNUNET_NO;
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Configuration requires `%s', but binary is not installed properly (SUID bit not set).  Option disabled.\n"),
		  "gnunet-nat-client");	
    }
  
  external_address = NULL;
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_have_value (env->cfg,
				       "nat",
				       "EXTERNAL_ADDRESS"))
    {
      (void) GNUNET_CONFIGURATION_get_value_string (env->cfg,
						    "nat",
						    "EXTERNAL_ADDRESS",
						    &external_address);
    }

  if ( (external_address != NULL) && 
       (inet_pton(AF_INET, external_address, &in_addr.sin_addr) != 1) ) 
    {
      
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
		       "tcp",
		       _("Malformed %s `%s' given in configuration!\n"), 
		       "EXTERNAL_ADDRESS",
		       external_address);
      return NULL;   
    }
  if ( (external_address == NULL) &&
       (nat_punched == GNUNET_YES) )
    {
      nat_punched = GNUNET_NO;
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Configuration says NAT was punched, but `%s' is not given.  Option ignored.\n"),
		  "EXTERNAL_ADDRESS");	
    }

  if (GNUNET_YES == nat_punched)
    {
      enable_nat_server = GNUNET_NO;
      enable_upnp = GNUNET_NO;
    }

  bind_address = NULL;
  if (GNUNET_YES == GNUNET_CONFIGURATION_get_value_string (env->cfg,
							   "nat",
							   "BINDTO",
							   &bind_address))
	{
	  GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
			   "tcp",
			   _("Binding TCP plugin to specific address: `%s'\n"),
			   bind_address);
	}

  internal_address = NULL;
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_have_value (env->cfg,
				       "nat",
				       "INTERNAL_ADDRESS"))
    {
      (void) GNUNET_CONFIGURATION_get_value_string (env->cfg,
						    "nat",
						    "INTERNAL_ADDRESS",
						    &internal_address);
    }

  if ( (internal_address != NULL) && 
       (inet_pton(AF_INET, internal_address, &in_addr.sin_addr) != 1) )
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
		       "tcp",
		       _("Malformed %s `%s' given in configuration!\n"), 
		       "INTERNAL_ADDRESS",
		       internal_address);      
      GNUNET_free_non_null(internal_address);
      GNUNET_free_non_null(external_address);
      return NULL;
    }

  if ((bind_address != NULL) && (internal_address != NULL))
    {
      if (0 != strcmp(internal_address, bind_address ))
	{
	  GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
			   "tcp",
			   "Specific bind address `%s' and internal address `%s' must not differ, forcing internal address to bind address!\n", 
			   bind_address, internal_address);
	  GNUNET_free (internal_address);
	  internal_address = bind_address;
	  GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
			   "tcp","New internal address `%s'\n", internal_address);
	}
    }
  
  aport = 0;
  if ( (GNUNET_OK !=
	GNUNET_CONFIGURATION_get_value_number (env->cfg,
					       "transport-tcp",
					       "PORT",
					       &bport)) ||
       (bport > 65535) ||
       ((GNUNET_OK ==
	 GNUNET_CONFIGURATION_get_value_number (env->cfg,
						"transport-tcp",
						"ADVERTISED-PORT",
						&aport)) && 
	(aport > 65535)) )
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
		       "tcp",
                       _("Require valid port number for service `%s' in configuration!\n"),
                       "transport-tcp");
      GNUNET_free_non_null(external_address);
      GNUNET_free_non_null(internal_address);
      return NULL;
    }

  use_localaddresses = GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
							     "transport-tcp",
							     "USE_LOCALADDR");
  if (use_localaddresses == GNUNET_SYSERR)
    use_localaddresses = GNUNET_NO;
  
  if (aport == 0)
    aport = bport;
  if (bport == 0)
    aport = 0;

  if (bport != 0)
    {
      service = GNUNET_SERVICE_start ("transport-tcp", env->cfg);
      if (service == NULL)
	{
	  GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING,
			   "tcp",
			   _("Failed to start service.\n"));
	  return NULL;
	}
    }
  else
    service = NULL;

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->open_port = bport;
  plugin->adv_port = aport;
  plugin->bind_address = bind_address;
  plugin->external_address = external_address;
  plugin->internal_address = internal_address;
  plugin->behind_nat = behind_nat;
  plugin->nat_punched = nat_punched;
  plugin->enable_nat_client = enable_nat_client;
  plugin->enable_nat_server = enable_nat_server;
  plugin->enable_upnp = enable_upnp;
  plugin->use_localaddresses = use_localaddresses;
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
  if (service != NULL)   
    {
      plugin->server = GNUNET_SERVICE_get_server (service);
    }
  else
    {
      if (GNUNET_OK !=
	  GNUNET_CONFIGURATION_get_value_time (env->cfg,
					       "transport-tcp",
					       "TIMEOUT",
					       &idle_timeout))
	{
	  GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
			   "tcp",
			   _("Failed to find option %s in section %s!\n"),
			   "TIMEOUT",
			   "transport-tcp");
	  GNUNET_free_non_null(external_address);
	  GNUNET_free_non_null(internal_address);
	  GNUNET_free (api);
	  return NULL;
	}
      plugin->server = GNUNET_SERVER_create_with_sockets (NULL, NULL, NULL,
							  idle_timeout, GNUNET_YES);
    }
  plugin->handlers = GNUNET_malloc (sizeof (my_handlers));
  memcpy (plugin->handlers, my_handlers, sizeof (my_handlers));
  for (i = 0;
       i < sizeof (my_handlers) / sizeof (struct GNUNET_SERVER_MessageHandler);
       i++)
    plugin->handlers[i].callback_cls = plugin;
  GNUNET_SERVER_add_handlers (plugin->server, plugin->handlers);
  GNUNET_SERVER_disconnect_notify (plugin->server,
				   &disconnect_notify,
				   plugin);    
  GNUNET_OS_network_interfaces_list (&process_interfaces, plugin);

  if ( (plugin->behind_nat == GNUNET_YES) &&
       (plugin->enable_nat_server == GNUNET_YES) &&
       (GNUNET_YES != tcp_transport_start_nat_server(plugin)) )
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
		       "tcp",
		       _("Failed to start %s required for NAT in %s!\n"),
		       "gnunet-nat-server"
		       "transport-tcp");
      GNUNET_free_non_null(external_address);
      GNUNET_free_non_null(internal_address);
      if (service != NULL)
	GNUNET_SERVICE_stop (service);
      else
	GNUNET_SERVER_destroy (plugin->server);
      GNUNET_free (api);
      return NULL;
    }

  if (enable_nat_client == GNUNET_YES)
    {
      plugin->nat_wait_conns = GNUNET_CONTAINER_multihashmap_create(16);
      GNUNET_assert (plugin->nat_wait_conns != NULL);
    }

  if (bport != 0)
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, 
		     "tcp",
		     _("TCP transport listening on port %llu\n"), 
		     bport);
  else
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, 
		     "tcp",
		     _("TCP transport not listening on any port (client only)\n"));
  if (aport != bport)
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO,
		     "tcp",
                     _("TCP transport advertises itself as being on port %llu\n"),
                     aport);

  plugin->hostname_dns = GNUNET_RESOLVER_hostname_resolve (env->cfg,
                                                           AF_UNSPEC,
                                                           HOSTNAME_RESOLVE_TIMEOUT,
                                                           &process_hostname_ips,
                                                           plugin);

  if (plugin->external_address != NULL) 
    {
      plugin->ext_dns = GNUNET_RESOLVER_ip_get (env->cfg,
						plugin->external_address,
						AF_INET,
						GNUNET_TIME_UNIT_MINUTES,
						&process_external_ip,
						plugin);
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
  struct LocalAddrList *lal;
  struct TCPProbeContext *tcp_probe;

  if (plugin->ext_dns != NULL)
    {
      GNUNET_RESOLVER_request_cancel (plugin->ext_dns);
      plugin->ext_dns = NULL;
    }
  while (NULL != (session = plugin->sessions))
    disconnect_session (session);
  if (NULL != plugin->hostname_dns)
    {
      GNUNET_RESOLVER_request_cancel (plugin->hostname_dns);
      plugin->hostname_dns = NULL;
    }
  if (plugin->service != NULL)
    GNUNET_SERVICE_stop (plugin->service);
  else
    GNUNET_SERVER_destroy (plugin->server);
  GNUNET_free (plugin->handlers);
  while (NULL != (lal = plugin->lal_head))
    {
      GNUNET_CONTAINER_DLL_remove (plugin->lal_head,
				   plugin->lal_tail,
				   lal);
      if (lal->nat != NULL)
	GNUNET_NAT_unregister (lal->nat);
      GNUNET_free_non_null (lal->external_nat_address);
      GNUNET_free (lal);
    }
  while (NULL != (tcp_probe = plugin->probe_head))
    {
      GNUNET_CONTAINER_DLL_remove (plugin->probe_head,
				   plugin->probe_tail,
				   tcp_probe);
      GNUNET_CONNECTION_destroy (tcp_probe->sock, GNUNET_NO);
      GNUNET_free (tcp_probe);
    }

  if ((plugin->behind_nat == GNUNET_YES) &&
      (plugin->enable_nat_server == GNUNET_YES))
    {
      if (0 != GNUNET_OS_process_kill (plugin->server_proc, SIGTERM))
        GNUNET_log_strerror (GNUNET_ERROR_TYPE_WARNING, "kill");
      GNUNET_OS_process_wait (plugin->server_proc);
      GNUNET_OS_process_close (plugin->server_proc);
      plugin->server_proc = NULL;
    }
  GNUNET_free_non_null(plugin->bind_address);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_tcp.c */
