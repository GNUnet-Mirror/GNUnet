/*
     This file is part of GNUnet
     (C) 2002--2012 Christian Grothoff (and other contributing authors)

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
#include "gnunet_constants.h"
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

#define LOG(kind,...) GNUNET_log_from (kind, "transport-tcp",__VA_ARGS__)

/**
 * How long until we give up on establishing an NAT connection?
 * Must be > 4 RTT
 */
#define NAT_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 10)


GNUNET_NETWORK_STRUCT_BEGIN

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
GNUNET_NETWORK_STRUCT_END

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


GNUNET_NETWORK_STRUCT_BEGIN

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
  uint16_t t4_port GNUNET_PACKED;

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
GNUNET_NETWORK_STRUCT_END

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
   * Pointer to the global plugin struct.
   */
  struct Plugin *plugin;

  /**
   * The client (used to identify this connection)
   */
  struct GNUNET_SERVER_Client *client;

  /**
   * Task cleaning up a NAT client connection establishment attempt;
   */
  GNUNET_SCHEDULER_TaskIdentifier nat_connection_timeout;

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
  struct GNUNET_SERVER_TransmitHandle *transmit_handle;

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
   * Session timeout task
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * Address of the other peer (either based on our 'connect'
   * call or on our 'accept' call).
   *
   * struct IPv4TcpAddress or struct IPv6TcpAddress
   *
   */
  void *addr;

  /**
   * Length of connect_addr.
   */
  size_t addrlen;

  /**
   * Last activity on this connection.  Used to select preferred
   * connection.
   */
  struct GNUNET_TIME_Absolute last_activity;

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

  /**
   * ATS network type in NBO
   */
  uint32_t ats_address_network_type;
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
   * Our handle to the NAT module.
   */
  struct GNUNET_NAT_Handle *nat;

  /**
   * Map from peer identities to sessions for the given peer.
   */
  struct GNUNET_CONTAINER_MultiHashMap *sessionmap;

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
   * Map of peers we have tried to contact behind a NAT
   */
  struct GNUNET_CONTAINER_MultiHashMap *nat_wait_conns;

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
   * How many more TCP sessions are we allowed to open right now?
   */
  unsigned long long max_connections;

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
 * Start session timeout
 */
static void
start_session_timeout (struct Session *s);


/**
 * Increment session timeout due to activity
 */
static void
reschedule_session_timeout (struct Session *s);


/**
 * Cancel timeout
 */
static void
stop_session_timeout (struct Session *s);


/* DEBUG CODE */
static const char *
tcp_address_to_string (void *cls, const void *addr, size_t addrlen);


static unsigned int sessions;


static void 
inc_sessions (struct Plugin *plugin, struct Session *session, int line)
{
  sessions++;
  unsigned int size = GNUNET_CONTAINER_multihashmap_size(plugin->sessionmap);
  if (sessions != size)
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Inconsistent sessions %u <-> session map size: %u\n",
        sessions, size);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "%4i Session increased to %u (session map size: %u): `%s' `%s'\n",
      line,
      sessions,
      size,
      GNUNET_i2s (&session->target),
      tcp_address_to_string (NULL, session->addr, session->addrlen));
}


static void 
dec_sessions (struct Plugin *plugin, struct Session *session, int line)
{
  GNUNET_assert (sessions > 0);
  unsigned int size = GNUNET_CONTAINER_multihashmap_size(plugin->sessionmap);
  sessions--;
  if (sessions != size)
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Inconsistent sessions %u <-> session map size: %u\n",
      sessions, size);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "%4i Session decreased to %u (session map size: %u): `%s' `%s'\n",
      line,
      sessions,
      size,
      GNUNET_i2s (&session->target),
      tcp_address_to_string (NULL, session->addr, session->addrlen));
}
/* DEBUG CODE */


/**
 * Function to check if an inbound connection is acceptable.
 * Mostly used to limit the total number of open connections
 * we can have.
 *
 * @param cls the 'struct Plugin'
 * @param ucred credentials, if available, otherwise NULL
 * @param addr address
 * @param addrlen length of address
 * @return GNUNET_YES to allow, GNUNET_NO to deny, GNUNET_SYSERR
 *   for unknown address family (will be denied).
 */
static int
plugin_tcp_access_check (void *cls,
                         const struct GNUNET_CONNECTION_Credentials *ucred,
                         const struct sockaddr *addr, socklen_t addrlen)
{
  struct Plugin *plugin = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Accepting new incoming TCP connection\n");
  if (0 == plugin->max_connections)
    return GNUNET_NO;
  plugin->max_connections--;
  return GNUNET_YES;
}


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
tcp_nat_port_map_callback (void *cls, int add_remove,
                           const struct sockaddr *addr, socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  struct IPv4TcpAddress t4;
  struct IPv6TcpAddress t6;
  void *arg;
  size_t args;

  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "NPMC called with %d for address `%s'\n", add_remove,
       GNUNET_a2s (addr, addrlen));
  /* convert 'addr' to our internal format */
  switch (addr->sa_family)
  {
  case AF_INET:
    GNUNET_assert (addrlen == sizeof (struct sockaddr_in));
    t4.ipv4_addr = ((struct sockaddr_in *) addr)->sin_addr.s_addr;
    t4.t4_port = ((struct sockaddr_in *) addr)->sin_port;
    arg = &t4;
    args = sizeof (t4);
    break;
  case AF_INET6:
    GNUNET_assert (addrlen == sizeof (struct sockaddr_in6));
    memcpy (&t6.ipv6_addr, &((struct sockaddr_in6 *) addr)->sin6_addr,
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
  plugin->env->notify_address (plugin->env->cls, add_remove, arg, args);
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
static const char *
tcp_address_to_string (void *cls, const void *addr, size_t addrlen)
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

  switch (addrlen)
  {
  case sizeof (struct IPv6TcpAddress):
    t6 = addr;
    af = AF_INET6;
    port = ntohs (t6->t6_port);
    memcpy (&a6, &t6->ipv6_addr, sizeof (a6));
    sb = &a6;
    break;
  case sizeof (struct IPv4TcpAddress): 
    t4 = addr;
    af = AF_INET;
    port = ntohs (t4->t4_port);
    memcpy (&a4, &t4->ipv4_addr, sizeof (a4));
    sb = &a4;
    break;
  default:
    LOG (GNUNET_ERROR_TYPE_ERROR, 
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
  GNUNET_snprintf (rbuf, sizeof (rbuf), (af == AF_INET6) ? "[%s]:%u" : "%s:%u",
                   buf, port);
  return rbuf;
}


/**
 * Function called to convert a string address to
 * a binary address.
 *
 * @param cls closure ('struct Plugin*')
 * @param addr string address
 * @param addrlen length of the address
 * @param buf location to store the buffer
 * @param added location to store the number of bytes in the buffer.
 *        If the function returns GNUNET_SYSERR, its contents are undefined.
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
static int
tcp_string_to_address (void *cls, const char *addr, uint16_t addrlen,
    void **buf, size_t *added)
{
  struct sockaddr_storage socket_address;

  if ((NULL == addr) || (addrlen == 0))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if ('\0' != addr[addrlen - 1])
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (strlen (addr) != addrlen - 1)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_STRINGS_to_address_ip (addr, strlen (addr),
				    &socket_address))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  switch (socket_address.ss_family)
  {
  case AF_INET:
    {
      struct IPv4TcpAddress *t4;
      struct sockaddr_in *in4 = (struct sockaddr_in *) &socket_address;

      t4 = GNUNET_malloc (sizeof (struct IPv4TcpAddress));
      t4->ipv4_addr = in4->sin_addr.s_addr;
      t4->t4_port = in4->sin_port;
      *buf = t4;
      *added = sizeof (struct IPv4TcpAddress);
      return GNUNET_OK;
    }
  case AF_INET6:  
    {
      struct IPv6TcpAddress *t6;
      struct sockaddr_in6 *in6 = (struct sockaddr_in6 *) &socket_address;
      t6 = GNUNET_malloc (sizeof (struct IPv6TcpAddress));
      t6->ipv6_addr = in6->sin6_addr;
      t6->t6_port = in6->sin6_port;
      *buf = t6;
      *added = sizeof (struct IPv6TcpAddress);
      return GNUNET_OK;
    }
  default:
    return GNUNET_SYSERR;
  }
}


struct SessionClientCtx
{
  const struct GNUNET_SERVER_Client *client;
  struct Session *ret;
};


static int 
session_lookup_by_client_it (void *cls,
			     const GNUNET_HashCode * key,
			     void *value)
{
  struct SessionClientCtx *sc_ctx = cls;
  struct Session *s = value;

  if (s->client == sc_ctx->client)
  {
    sc_ctx->ret = s;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Find the session handle for the given client.
 *
 * @param plugin the plugin
 * @param client which client to find the session handle for
 * @return NULL if no matching session exists
 */
static struct Session *
lookup_session_by_client (struct Plugin *plugin,
			  const struct GNUNET_SERVER_Client *client)
{
  struct SessionClientCtx sc_ctx;

  sc_ctx.client = client;
  sc_ctx.ret = NULL;
  GNUNET_CONTAINER_multihashmap_iterate (plugin->sessionmap, &session_lookup_by_client_it, &sc_ctx);
  return sc_ctx.ret;
}


/**
 * Create a new session.  Also queues a welcome message.
 *
 * @param plugin the plugin
 * @param target peer to connect to
 * @param client client to use, reference counter must have already been increased
 * @param is_nat this a NAT session, we should wait for a client to
 *               connect to us from an address, then assign that to
 *               the session
 * @return new session object
 */
static struct Session *
create_session (struct Plugin *plugin, const struct GNUNET_PeerIdentity *target,
                struct GNUNET_SERVER_Client *client, int is_nat)
{
  struct Session *ret;
  struct PendingMessage *pm;
  struct WelcomeMessage welcome;

  if (GNUNET_YES != is_nat)
    GNUNET_assert (NULL != client);
  else
    GNUNET_assert (NULL == client);

  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Creating new session for peer `%4s'\n",
       GNUNET_i2s (target));
  ret = GNUNET_malloc (sizeof (struct Session));
  ret->last_activity = GNUNET_TIME_absolute_get ();
  ret->plugin = plugin;
  ret->is_nat = is_nat;
  ret->client = client;
  ret->target = *target;
  ret->expecting_welcome = GNUNET_YES;
  ret->ats_address_network_type = htonl (GNUNET_ATS_NET_UNSPECIFIED);
  pm = GNUNET_malloc (sizeof (struct PendingMessage) +
                      sizeof (struct WelcomeMessage));
  pm->msg = (const char *) &pm[1];
  pm->message_size = sizeof (struct WelcomeMessage);
  welcome.header.size = htons (sizeof (struct WelcomeMessage));
  welcome.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_WELCOME);
  welcome.clientIdentity = *plugin->env->my_identity;
  memcpy (&pm[1], &welcome, sizeof (welcome));
  pm->timeout = GNUNET_TIME_UNIT_FOREVER_ABS;
  GNUNET_STATISTICS_update (plugin->env->stats,
                            gettext_noop ("# bytes currently in TCP buffers"),
                            pm->message_size, GNUNET_NO);
  GNUNET_CONTAINER_DLL_insert (ret->pending_messages_head,
                               ret->pending_messages_tail, pm);
  if (GNUNET_YES != is_nat)
  {
    GNUNET_STATISTICS_update (plugin->env->stats,
                              gettext_noop ("# TCP sessions active"), 1,
                              GNUNET_NO);
  }
  start_session_timeout (ret);

  return ret;
}


/**
 * If we have pending messages, ask the server to
 * transmit them (schedule the respective tasks, etc.)
 *
 * @param session for which session should we do this
 */
static void
process_pending_messages (struct Session *session);


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

  GNUNET_assert (NULL != session);
  session->transmit_handle = NULL;
  plugin = session->plugin;
  if (NULL == buf)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Timeout trying to transmit to peer `%4s', discarding message queue.\n",
	 GNUNET_i2s (&session->target));
    /* timeout; cancel all messages that have already expired */
    hd = NULL;
    tl = NULL;
    ret = 0;
    now = GNUNET_TIME_absolute_get ();
    while ((NULL != (pos = session->pending_messages_head)) &&
           (pos->timeout.abs_value <= now.abs_value))
    {
      GNUNET_CONTAINER_DLL_remove (session->pending_messages_head,
                                   session->pending_messages_tail, pos);
      LOG (GNUNET_ERROR_TYPE_DEBUG,
	   "Failed to transmit %u byte message to `%4s'.\n",
	   pos->message_size, GNUNET_i2s (&session->target));
      ret += pos->message_size;
      GNUNET_CONTAINER_DLL_insert_after (hd, tl, tl, pos);
    }
    /* do this call before callbacks (so that if callbacks destroy
     * session, they have a chance to cancel actions done by this
     * call) */
    process_pending_messages (session);
    pid = session->target;
    /* no do callbacks and do not use session again since
     * the callbacks may abort the session */
    while (NULL != (pos = hd))
    {
      GNUNET_CONTAINER_DLL_remove (hd, tl, pos);
      if (pos->transmit_cont != NULL)
        pos->transmit_cont (pos->transmit_cont_cls, &pid, GNUNET_SYSERR);
      GNUNET_free (pos);
    }
    GNUNET_STATISTICS_update (plugin->env->stats,
                              gettext_noop ("# bytes currently in TCP buffers"),
                              -(int64_t) ret, GNUNET_NO);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              gettext_noop
                              ("# bytes discarded by TCP (timeout)"), ret,
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
                                 session->pending_messages_tail, pos);
    GNUNET_assert (size >= pos->message_size);
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Transmitting message of type %u\n",
	 ntohs (((struct GNUNET_MessageHeader *) pos->msg)->type));
    /* FIXME: this memcpy can be up to 7% of our total runtime */
    memcpy (cbuf, pos->msg, pos->message_size);
    cbuf += pos->message_size;
    ret += pos->message_size;
    size -= pos->message_size;
    GNUNET_CONTAINER_DLL_insert_tail (hd, tl, pos);
  }
  /* schedule 'continuation' before callbacks so that callbacks that
   * cancel everything don't cause us to use a session that no longer
   * exists... */
  process_pending_messages (session);
  session->last_activity = GNUNET_TIME_absolute_get ();
  pid = session->target;
  /* we'll now call callbacks that may cancel the session; hence
   * we should not use 'session' after this point */
  while (NULL != (pos = hd))
  {
    GNUNET_CONTAINER_DLL_remove (hd, tl, pos);
    if (pos->transmit_cont != NULL)
      pos->transmit_cont (pos->transmit_cont_cls, &pid, GNUNET_OK);
    GNUNET_free (pos);
  }
  GNUNET_assert (hd == NULL);
  GNUNET_assert (tl == NULL);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Transmitting %u bytes\n",
                   ret);
  GNUNET_STATISTICS_update (plugin->env->stats,
                            gettext_noop ("# bytes currently in TCP buffers"),
                            -(int64_t) ret, GNUNET_NO);
  GNUNET_STATISTICS_update (plugin->env->stats,
                            gettext_noop ("# bytes transmitted via TCP"), ret,
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

  session->transmit_handle =
      GNUNET_SERVER_notify_transmit_ready (session->client, pm->message_size,
                                           GNUNET_TIME_absolute_get_remaining
                                           (pm->timeout), &do_transmit,
                                           session);
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
  struct PendingMessage *pm;
  struct Plugin * plugin = session->plugin;

  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Disconnecting session of peer `%s' address `%s'\n",
       GNUNET_i2s (&session->target),
       tcp_address_to_string (NULL, session->addr, session->addrlen));

  stop_session_timeout (session);

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove (plugin->sessionmap, &session->target.hashPubKey, session))
  {
    GNUNET_STATISTICS_update (session->plugin->env->stats,
			      gettext_noop ("# TCP sessions active"), -1,
			      GNUNET_NO);
    dec_sessions (plugin, session, __LINE__);
  }
  else GNUNET_assert (GNUNET_YES == GNUNET_CONTAINER_multihashmap_remove (plugin->nat_wait_conns, &session->target.hashPubKey, session));

  /* clean up state */
  if (session->transmit_handle != NULL)
  {
    GNUNET_SERVER_notify_transmit_ready_cancel (session->transmit_handle);
    session->transmit_handle = NULL;
  }
  session->plugin->env->session_end (session->plugin->env->cls,
                                     &session->target, session);

  if (GNUNET_SCHEDULER_NO_TASK != session->nat_connection_timeout)
  {
    GNUNET_SCHEDULER_cancel (session->nat_connection_timeout);
    session->nat_connection_timeout = GNUNET_SCHEDULER_NO_TASK;
  }

  while (NULL != (pm = session->pending_messages_head))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 pm->transmit_cont !=
	 NULL ? "Could not deliver message to `%4s'.\n" :
	 "Could not deliver message to `%4s', notifying.\n",
	 GNUNET_i2s (&session->target));
    GNUNET_STATISTICS_update (session->plugin->env->stats,
                              gettext_noop ("# bytes currently in TCP buffers"),
                              -(int64_t) pm->message_size, GNUNET_NO);
    GNUNET_STATISTICS_update (session->plugin->env->stats,
                              gettext_noop
                              ("# bytes discarded by TCP (disconnect)"),
                              pm->message_size, GNUNET_NO);
    GNUNET_CONTAINER_DLL_remove (session->pending_messages_head,
                                 session->pending_messages_tail, pm);
    if (NULL != pm->transmit_cont)
      pm->transmit_cont (pm->transmit_cont_cls, &session->target,
                         GNUNET_SYSERR);
    GNUNET_free (pm);
  }
  if (session->receive_delay_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (session->receive_delay_task);
    if (NULL != session->client)
      GNUNET_SERVER_receive_done (session->client, GNUNET_SYSERR);
  }
  if (NULL != session->client)
  {
    GNUNET_SERVER_client_disconnect (session->client);
    GNUNET_SERVER_client_drop (session->client);
    session->client = NULL;
  }
  GNUNET_free_non_null (session->addr);
  GNUNET_assert (NULL == session->transmit_handle);
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
 * @param session which session must be used
 * @param msgbuf the message to transmit
 * @param msgbuf_size number of bytes in 'msgbuf'
 * @param priority how important is the message (most plugins will
 *                 ignore message priority and just FIFO)
 * @param to how long to wait at most for the transmission (does not
 *                require plugins to discard the message after the timeout,
 *                just advisory for the desired delay; most plugins will ignore
 *                this as well)
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
    struct Session *session,
    const char *msgbuf, size_t msgbuf_size,
    unsigned int priority,
    struct GNUNET_TIME_Relative to,
    GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct Plugin * plugin = cls;
  struct PendingMessage *pm;

  GNUNET_assert (NULL != plugin);
  GNUNET_assert (NULL != session);

  /* create new message entry */
  pm = GNUNET_malloc (sizeof (struct PendingMessage) + msgbuf_size);
  pm->msg = (const char *) &pm[1];
  memcpy (&pm[1], msgbuf, msgbuf_size);
  pm->message_size = msgbuf_size;
  pm->timeout = GNUNET_TIME_relative_to_absolute (to);
  pm->transmit_cont = cont;
  pm->transmit_cont_cls = cont_cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Asked to transmit %u bytes to `%s', added message to list.\n",
       msgbuf_size, GNUNET_i2s (&session->target));

  reschedule_session_timeout (session);

  if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains_value(plugin->sessionmap, &session->target.hashPubKey, session))
  {
    GNUNET_assert (session->client != NULL);

    GNUNET_SERVER_client_set_timeout (session->client,
                                      GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
    GNUNET_STATISTICS_update (plugin->env->stats,
                              gettext_noop ("# bytes currently in TCP buffers"),
                              msgbuf_size, GNUNET_NO);

    /* append pm to pending_messages list */
    GNUNET_CONTAINER_DLL_insert_tail (session->pending_messages_head,
                                      session->pending_messages_tail, pm);

    process_pending_messages (session);
    return msgbuf_size;
  }
  else if (GNUNET_YES == GNUNET_CONTAINER_multihashmap_contains_value(plugin->nat_wait_conns, &session->target.hashPubKey, session))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "This NAT WAIT session for peer `%s' is not yet ready!\n",
	 GNUNET_i2s (&session->target));

    GNUNET_STATISTICS_update (plugin->env->stats,
                              gettext_noop ("# bytes currently in TCP buffers"),
                              msgbuf_size, GNUNET_NO);

    /* append pm to pending_messages list */
    GNUNET_CONTAINER_DLL_insert_tail (session->pending_messages_head,
                                      session->pending_messages_tail, pm);
    return msgbuf_size;
  }
  else
  {
    if (NULL != cont)
      cont (cont_cls, &session->target, GNUNET_SYSERR);
    GNUNET_break (0);
    GNUNET_free (pm);
    return GNUNET_SYSERR; /* session does not exist here */
  }
}


struct SessionItCtx
{
  void *addr;
  size_t addrlen;
  struct Session *result;
};


static int 
session_lookup_it (void *cls,
		   const GNUNET_HashCode *key,
		   void *value)
{
  struct SessionItCtx * si_ctx = cls;
  struct Session * session = value;
#if 0
  char * a1 = strdup (tcp_address_to_string(NULL, session->addr, session->addrlen));
  char * a2 = strdup (tcp_address_to_string(NULL, si_ctx->addr, si_ctx->addrlen));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Comparing: %s %u <-> %s %u\n",
       a1,
       session->addrlen,
       a2,
       si_ctx->addrlen);
  GNUNET_free (a1);
  GNUNET_free (a2);
#endif
  if (session->addrlen != si_ctx->addrlen)
  {
    return GNUNET_YES;
  }
  if (0 != memcmp (session->addr, si_ctx->addr, si_ctx->addrlen))
  {
    return GNUNET_YES;
  }
#if 0
  a1 = strdup (tcp_address_to_string(NULL, session->addr, session->addrlen));
  a2 = strdup (tcp_address_to_string(NULL, si_ctx->addr, si_ctx->addrlen));
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Comparing: %s %u <-> %s %u , OK!\n",
       a1,
       session->addrlen,
       a2,
       si_ctx->addrlen);
  GNUNET_free (a1);
  GNUNET_free (a2);
#endif
  /* Found existing session */
  si_ctx->result = session;
  return GNUNET_NO;
}


/**
 * Task cleaning up a NAT connection attempt after timeout
 */
static void
nat_connect_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Session *session = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "NAT WAIT connection to `%4s' at `%s' could not be established, removing session\n",
       GNUNET_i2s (&session->target), tcp_address_to_string(NULL, session->addr, session->addrlen));
  disconnect_session (session);
}


/**
 * Create a new session to transmit data to the target
 * This session will used to send data to this peer and the plugin will
 * notify us by calling the env->session_end function
 *
 * @param cls closure
 * @param address pointer to the GNUNET_HELLO_Address
 * @return the session if the address is valid, NULL otherwise
 */
static struct Session *
tcp_plugin_get_session (void *cls,
			const struct GNUNET_HELLO_Address *address)
{
  struct Plugin * plugin = cls;
  struct Session * session = NULL;
  int af;
  const void *sb;
  size_t sbs;
  struct GNUNET_CONNECTION_Handle *sa;
  struct sockaddr_in a4;
  struct sockaddr_in6 a6;
  const struct IPv4TcpAddress *t4;
  const struct IPv6TcpAddress *t6;
  struct GNUNET_ATS_Information ats;
  unsigned int is_natd = GNUNET_NO;
  size_t addrlen;

  GNUNET_assert (plugin != NULL);
  GNUNET_assert (address != NULL);
  addrlen = address->address_length;
  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Trying to get session for `%s' address of peer `%s'\n",
       tcp_address_to_string(NULL, address->address, address->address_length),
       GNUNET_i2s (&address->peer));

  /* look for existing session */
  if (GNUNET_YES == 
      GNUNET_CONTAINER_multihashmap_contains(plugin->sessionmap, &address->peer.hashPubKey))
  {
    struct SessionItCtx si_ctx;

    si_ctx.addr = (void *) address->address;
    si_ctx.addrlen = address->address_length;

    si_ctx.result = NULL;

    GNUNET_CONTAINER_multihashmap_get_multiple(plugin->sessionmap, &address->peer.hashPubKey, &session_lookup_it, &si_ctx);
    if (si_ctx.result != NULL)
    {
      session = si_ctx.result;
      LOG (GNUNET_ERROR_TYPE_DEBUG, 
	   "Found exisiting session for `%s' address `%s' session %p\n",
	   GNUNET_i2s (&address->peer),
	   tcp_address_to_string(NULL, address->address, address->address_length),
	   session);
      return session;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Existing sessions did not match address `%s' or peer `%s'\n",
	 tcp_address_to_string(NULL, address->address, address->address_length),
	 GNUNET_i2s (&address->peer));
  }

  if (addrlen == sizeof (struct IPv6TcpAddress))
  {
    GNUNET_assert (NULL != address->address);     /* make static analysis happy */
    t6 = address->address;
    af = AF_INET6;
    memset (&a6, 0, sizeof (a6));
#if HAVE_SOCKADDR_IN_SIN_LEN
    a6.sin6_len = sizeof (a6);
#endif
    a6.sin6_family = AF_INET6;
    a6.sin6_port = t6->t6_port;
    if (t6->t6_port == 0)
      is_natd = GNUNET_YES;
    memcpy (&a6.sin6_addr, &t6->ipv6_addr, sizeof (struct in6_addr));
    sb = &a6;
    sbs = sizeof (a6);
  }
  else if (addrlen == sizeof (struct IPv4TcpAddress))
  {
    GNUNET_assert (NULL != address->address);     /* make static analysis happy */
    t4 = address->address;
    af = AF_INET;
    memset (&a4, 0, sizeof (a4));
#if HAVE_SOCKADDR_IN_SIN_LEN
    a4.sin_len = sizeof (a4);
#endif
    a4.sin_family = AF_INET;
    a4.sin_port = t4->t4_port;
    if (t4->t4_port == 0)
      is_natd = GNUNET_YES;
    a4.sin_addr.s_addr = t4->ipv4_addr;
    sb = &a4;
    sbs = sizeof (a4);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, 
	 _("Address of unexpected length: %u\n"), addrlen);
    GNUNET_break (0);
    return NULL;
  }

  ats = plugin->env->get_address_type (plugin->env->cls, sb ,sbs);

  if ((is_natd == GNUNET_YES) && (addrlen == sizeof (struct IPv6TcpAddress)))
  {
    /* NAT client only works with IPv4 addresses */
    return NULL;
  }

  if (0 == plugin->max_connections)
  {
    /* saturated */
    return NULL;
  }

  if ((is_natd == GNUNET_YES) &&
      (GNUNET_YES ==
       GNUNET_CONTAINER_multihashmap_contains (plugin->nat_wait_conns,
                                               &address->peer.hashPubKey)))
  {
    /* Only do one NAT punch attempt per peer identity */
     return NULL;
  }

  if ((is_natd == GNUNET_YES) && (NULL != plugin->nat) &&
      (GNUNET_NO ==
       GNUNET_CONTAINER_multihashmap_contains (plugin->nat_wait_conns,
                                               &address->peer.hashPubKey)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Found valid IPv4 NAT address (creating session)!\n") ;
    session = create_session (plugin, &address->peer, NULL, GNUNET_YES);
    session->addrlen = 0;
    session->addr = NULL;
    session->ats_address_network_type = ats.value;
    session->nat_connection_timeout = GNUNET_SCHEDULER_add_delayed(NAT_TIMEOUT,
        &nat_connect_timeout,
        session);
    GNUNET_assert (session != NULL);
    GNUNET_assert (GNUNET_CONTAINER_multihashmap_put
                   (plugin->nat_wait_conns, &address->peer.hashPubKey, session,
                    GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY) == GNUNET_OK);

    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Created NAT WAIT connection to `%4s' at `%s'\n",
	 GNUNET_i2s (&session->target), GNUNET_a2s (sb, sbs));

    if (GNUNET_OK == GNUNET_NAT_run_client (plugin->nat, &a4))
      return session;
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, 
	   "Running NAT client for `%4s' at `%s' failed\n",
	   GNUNET_i2s (&session->target), GNUNET_a2s (sb, sbs));
      disconnect_session (session);
      return NULL;
    }
  }

  /* create new outbound session */
  GNUNET_assert (0 != plugin->max_connections);
  sa = GNUNET_CONNECTION_create_from_sockaddr (af, sb, sbs);
  if (sa == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Failed to create connection to `%4s' at `%s'\n",
	 GNUNET_i2s (&session->target), GNUNET_a2s (sb, sbs));
    return NULL;
  }
  plugin->max_connections--;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Asked to transmit to `%4s', creating fresh session using address `%s'.\n",
       GNUNET_i2s (&address->peer), GNUNET_a2s (sb, sbs));

  session = create_session (plugin,
                            &address->peer,
                            GNUNET_SERVER_connect_socket (plugin->server, sa),
                            GNUNET_NO);
  session->addr = GNUNET_malloc (addrlen);
  memcpy (session->addr, address->address, addrlen);
  session->addrlen = addrlen;
  session->ats_address_network_type = ats.value;

  GNUNET_CONTAINER_multihashmap_put(plugin->sessionmap, &address->peer.hashPubKey, session, GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  inc_sessions (plugin, session, __LINE__);
  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Creating new session for `%s' address `%s' session %p\n",
       GNUNET_i2s (&address->peer),
       tcp_address_to_string(NULL, address->address, address->address_length),
       session);
  /* Send TCP Welcome */
  process_pending_messages (session);

  return session;
}


static int 
session_disconnect_it (void *cls,
		       const GNUNET_HashCode * key,
		       void *value)
{
  struct Session *session = value;

  GNUNET_STATISTICS_update (session->plugin->env->stats,
                            gettext_noop
                            ("# transport-service disconnect requests for TCP"),
                            1, GNUNET_NO);
  disconnect_session (session);
  return GNUNET_YES;
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

  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Disconnecting peer `%4s'\n", GNUNET_i2s (target));
  GNUNET_CONTAINER_multihashmap_get_multiple (plugin->sessionmap, &target->hashPubKey, &session_disconnect_it, plugin);
  GNUNET_CONTAINER_multihashmap_get_multiple (plugin->nat_wait_conns, &target->hashPubKey, &session_disconnect_it, plugin);
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

  int ipv6;
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
  if (GNUNET_YES == ppc->ipv6)
    GNUNET_asprintf (&ret, "[%s]:%d", hostname, ppc->port);
  else
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
tcp_plugin_address_pretty_printer (void *cls, const char *type,
                                   const void *addr, size_t addrlen,
                                   int numeric,
                                   struct GNUNET_TIME_Relative timeout,
                                   GNUNET_TRANSPORT_AddressStringCallback asc,
                                   void *asc_cls)
{
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
    memcpy (&a6.sin6_addr, &t6->ipv6_addr, sizeof (struct in6_addr));
    port = ntohs (t6->t6_port);
    sb = &a6;
    sbs = sizeof (a6);
  }
  else if (addrlen == sizeof (struct IPv4TcpAddress))
  {
    t4 = addr;
    memset (&a4, 0, sizeof (a4));
    a4.sin_family = AF_INET;
    a4.sin_port = t4->t4_port;
    a4.sin_addr.s_addr = t4->ipv4_addr;
    port = ntohs (t4->t4_port);
    sb = &a4;
    sbs = sizeof (a4);
  }
  else if (0 == addrlen)
  {
    asc (asc_cls, "<inbound connection>");
    asc (asc_cls, NULL);
    return;
  }
  else
  {
    /* invalid address */
    GNUNET_break_op (0);
    asc (asc_cls, NULL);
    return;
  }
  ppc = GNUNET_malloc (sizeof (struct PrettyPrinterContext));
  if (addrlen == sizeof (struct IPv6TcpAddress))
    ppc->ipv6 = GNUNET_YES;
  else
    ppc->ipv6 = GNUNET_NO;
  ppc->asc = asc;
  ppc->asc_cls = asc_cls;
  ppc->port = port;
  GNUNET_RESOLVER_hostname_get (sb, sbs, !numeric, timeout, &append_port, ppc);
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
check_port (struct Plugin *plugin, uint16_t in_port)
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
tcp_plugin_check_address (void *cls, const void *addr, size_t addrlen)
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
    if (GNUNET_OK != check_port (plugin, ntohs (v4->t4_port)))
      return GNUNET_SYSERR;
    if (GNUNET_OK !=
        GNUNET_NAT_test_address (plugin->nat, &v4->ipv4_addr,
                                 sizeof (struct in_addr)))
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
    if (GNUNET_OK != check_port (plugin, ntohs (v6->t6_port)))
      return GNUNET_SYSERR;
    if (GNUNET_OK !=
        GNUNET_NAT_test_address (plugin->nat, &v6->ipv6_addr,
                                 sizeof (struct in6_addr)))
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
handle_tcp_nat_probe (void *cls, struct GNUNET_SERVER_Client *client,
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

  LOG (GNUNET_ERROR_TYPE_DEBUG, "received NAT probe\n");

  /* We have received a TCP NAT probe, meaning we (hopefully) initiated
   * a connection to this peer by running gnunet-nat-client.  This peer
   * received the punch message and now wants us to use the new connection
   * as the default for that peer.  Do so and then send a WELCOME message
   * so we can really be connected!
   */
  if (ntohs (message->size) != sizeof (struct TCP_NAT_ProbeMessage))
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  tcp_nat_probe = (const struct TCP_NAT_ProbeMessage *) message;
  if (0 ==
      memcmp (&tcp_nat_probe->clientIdentity, plugin->env->my_identity,
              sizeof (struct GNUNET_PeerIdentity)))
  {
    /* refuse connections from ourselves */
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }

  session =
      GNUNET_CONTAINER_multihashmap_get (plugin->nat_wait_conns,
                                         &tcp_nat_probe->
                                         clientIdentity.hashPubKey);
  if (session == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Did NOT find session for NAT probe!\n");
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Found session for NAT probe!\n");

  if (session->nat_connection_timeout != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (session->nat_connection_timeout);
    session->nat_connection_timeout = GNUNET_SCHEDULER_NO_TASK;
  }

  if (GNUNET_OK != GNUNET_SERVER_client_get_address (client, &vaddr, &alen))
  {
    GNUNET_break (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    disconnect_session (session);
    return;
  }
  GNUNET_assert (GNUNET_CONTAINER_multihashmap_remove
                 (plugin->nat_wait_conns,
                  &tcp_nat_probe->clientIdentity.hashPubKey,
                  session) == GNUNET_YES);
  GNUNET_CONTAINER_multihashmap_put(plugin->sessionmap,
				    &session->target.hashPubKey, session, 
				    GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);  
  session->last_activity = GNUNET_TIME_absolute_get ();
  session->inbound = GNUNET_NO;
  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Found address `%s' for incoming connection\n",
       GNUNET_a2s (vaddr, alen));
  switch (((const struct sockaddr *) vaddr)->sa_family)
  {
  case AF_INET:
    s4 = vaddr;
    t4 = GNUNET_malloc (sizeof (struct IPv4TcpAddress));
    t4->t4_port = s4->sin_port;
    t4->ipv4_addr = s4->sin_addr.s_addr;
    session->addr = t4;
    session->addrlen = sizeof (struct IPv4TcpAddress);
    break;
  case AF_INET6:
    s6 = vaddr;
    t6 = GNUNET_malloc (sizeof (struct IPv6TcpAddress));
    t6->t6_port = s6->sin6_port;
    memcpy (&t6->ipv6_addr, &s6->sin6_addr, sizeof (struct in6_addr));
    session->addr = t6;
    session->addrlen = sizeof (struct IPv6TcpAddress);
    break;
  default:
    GNUNET_break_op (0);
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Bad address for incoming connection!\n");
    GNUNET_free (vaddr);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    disconnect_session (session);
    return;
  }
  GNUNET_free (vaddr);
  GNUNET_break (NULL == session->client);
  GNUNET_SERVER_client_keep (client);
  session->client = client;
  inc_sessions (plugin, session, __LINE__);
  GNUNET_STATISTICS_update (plugin->env->stats,
                            gettext_noop ("# TCP sessions active"), 1,
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
handle_tcp_welcome (void *cls, struct GNUNET_SERVER_Client *client,
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

  if (0 ==
      memcmp (&wm->clientIdentity, plugin->env->my_identity,
              sizeof (struct GNUNET_PeerIdentity)))
  {
    /* refuse connections from ourselves */
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Received %s message from `%4s'\n", "WELCOME",
       GNUNET_i2s (&wm->clientIdentity));
  GNUNET_STATISTICS_update (plugin->env->stats,
                            gettext_noop ("# TCP WELCOME messages received"), 1,
                            GNUNET_NO);
  session = lookup_session_by_client (plugin, client);
  if (session != NULL)
  {
    if (GNUNET_OK == GNUNET_SERVER_client_get_address (client, &vaddr, &alen))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, 
	   "Found existing session %p for peer `%s'\n",
	   session,
	   GNUNET_a2s (vaddr, alen));
      GNUNET_free (vaddr);
    }
  }
  else
  {
    GNUNET_SERVER_client_keep (client);
    session = create_session (plugin, &wm->clientIdentity, client, GNUNET_NO);
    session->inbound = GNUNET_YES;
    if (GNUNET_OK == GNUNET_SERVER_client_get_address (client, &vaddr, &alen))
    {
      if (alen == sizeof (struct sockaddr_in))
      {
        s4 = vaddr;
        t4 = GNUNET_malloc (sizeof (struct IPv4TcpAddress));
        t4->t4_port = s4->sin_port;
        t4->ipv4_addr = s4->sin_addr.s_addr;
        session->addr = t4;
        session->addrlen = sizeof (struct IPv4TcpAddress);
      }
      else if (alen == sizeof (struct sockaddr_in6))
      {
        s6 = vaddr;
        t6 = GNUNET_malloc (sizeof (struct IPv6TcpAddress));
        t6->t6_port = s6->sin6_port;
        memcpy (&t6->ipv6_addr, &s6->sin6_addr, sizeof (struct in6_addr));
        session->addr = t6;
        session->addrlen = sizeof (struct IPv6TcpAddress);
      }

      struct GNUNET_ATS_Information ats;
      ats = plugin->env->get_address_type (plugin->env->cls, vaddr ,alen);
      session->ats_address_network_type = ats.value;

      GNUNET_free (vaddr);
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, 
	   "Did not obtain TCP socket address for incoming connection\n");
    }
    GNUNET_CONTAINER_multihashmap_put(plugin->sessionmap, &wm->clientIdentity.hashPubKey, session, GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    inc_sessions (plugin, session, __LINE__);
  }

  if (session->expecting_welcome != GNUNET_YES)
  {
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    return;
  }
  session->last_activity = GNUNET_TIME_absolute_get ();
  session->expecting_welcome = GNUNET_NO;


  process_pending_messages (session);

  GNUNET_SERVER_client_set_timeout (client,
                                    GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
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
  struct GNUNET_ATS_Information ats;

  session->receive_delay_task = GNUNET_SCHEDULER_NO_TASK;
  delay =
      session->plugin->env->receive (session->plugin->env->cls,
                                     &session->target, NULL, &ats, 0, session,
                                     NULL, 0);
  reschedule_session_timeout (session);

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
handle_tcp_data (void *cls, struct GNUNET_SERVER_Client *client,
                 const struct GNUNET_MessageHeader *message)
{
  struct Plugin *plugin = cls;
  struct Session *session;
  struct GNUNET_TIME_Relative delay;
  uint16_t type;

  type = ntohs (message->type);
  if ((GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_WELCOME == type) ||
      (GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_NAT_PROBE == type))
  {
    /* We don't want to propagate WELCOME and NAT Probe messages up! */
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
    return;
  }
  session = lookup_session_by_client (plugin, client);
  if (NULL == session)
  {
    /* No inbound session found */
    void *vaddr;
    size_t alen;
    
    GNUNET_SERVER_client_get_address (client, &vaddr, &alen);
    LOG (GNUNET_ERROR_TYPE_ERROR, 
	 "Received unexpected %u bytes of type %u from `%s'\n",
	 (unsigned int) ntohs (message->size),
	 (unsigned int) ntohs (message->type),
	 GNUNET_a2s(vaddr, alen));
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    GNUNET_free_non_null(vaddr);
    return;
  }
  else if (GNUNET_YES == session->expecting_welcome)
  {
    /* Session is expecting WELCOME message */
    void *vaddr;
    size_t alen;

    GNUNET_SERVER_client_get_address (client, &vaddr, &alen);
    LOG (GNUNET_ERROR_TYPE_ERROR, 
	 "Received unexpected %u bytes of type %u from `%s'\n",
	 (unsigned int) ntohs (message->size),
	 (unsigned int) ntohs (message->type),
	 GNUNET_a2s(vaddr, alen));
    GNUNET_break_op (0);
    GNUNET_SERVER_receive_done (client, GNUNET_SYSERR);
    GNUNET_free_non_null(vaddr);
    return;
  }

  session->last_activity = GNUNET_TIME_absolute_get ();
  LOG (GNUNET_ERROR_TYPE_DEBUG, 
                   "Passing %u bytes of type %u from `%4s' to transport service.\n",
                   (unsigned int) ntohs (message->size),
                   (unsigned int) ntohs (message->type),
                   GNUNET_i2s (&session->target));

  GNUNET_STATISTICS_update (plugin->env->stats,
                            gettext_noop ("# bytes received via TCP"),
                            ntohs (message->size), GNUNET_NO);
  struct GNUNET_ATS_Information distance[2];

  distance[0].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
  distance[0].value = htonl (1);
  distance[1].type = htonl (GNUNET_ATS_NETWORK_TYPE);
  distance[1].value = session->ats_address_network_type;
  GNUNET_break (ntohl(session->ats_address_network_type) != GNUNET_ATS_NET_UNSPECIFIED);

  GNUNET_assert (GNUNET_CONTAINER_multihashmap_contains_value (plugin->sessionmap,
      &session->target.hashPubKey,
      session));

  delay = plugin->env->receive (plugin->env->cls,
                                &session->target,
                                message,
                                (const struct GNUNET_ATS_Information *) &distance,
                                1, session,
                                (GNUNET_YES == session->inbound) ? NULL : session->addr,
                                (GNUNET_YES == session->inbound) ? 0 : session->addrlen);

  reschedule_session_timeout (session);

  if (delay.rel_value == 0)
  {
    GNUNET_SERVER_receive_done (client, GNUNET_OK);
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
	 "Throttling receiving from `%s' for %llu ms\n",
	 GNUNET_i2s (&session->target),
	 (unsigned long long) delay.rel_value);
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
disconnect_notify (void *cls, struct GNUNET_SERVER_Client *client)
{
  struct Plugin *plugin = cls;
  struct Session *session;

  if (client == NULL)
    return;
  plugin->max_connections++;
  session = lookup_session_by_client (plugin, client);
  if (session == NULL)
    return;                     /* unknown, nothing to do */
  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Destroying session of `%4s' with %s due to network-level disconnect.\n",
       GNUNET_i2s (&session->target),
       (session->addr !=
	NULL) ? tcp_address_to_string (session->plugin,
				       session->addr,
				       session->addrlen) :
       "*");
  GNUNET_STATISTICS_update (session->plugin->env->stats,
                            gettext_noop
                            ("# network-level TCP disconnect events"), 1,
                            GNUNET_NO);
  disconnect_session (session);
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
notify_send_probe (void *cls, size_t size, void *buf)
{
  struct TCPProbeContext *tcp_probe_ctx = cls;
  struct Plugin *plugin = tcp_probe_ctx->plugin;
  size_t ret;

  tcp_probe_ctx->transmit_handle = NULL;
  GNUNET_CONTAINER_DLL_remove (plugin->probe_head, plugin->probe_tail,
                               tcp_probe_ctx);
  if (buf == NULL)
  {
    GNUNET_CONNECTION_destroy (tcp_probe_ctx->sock);
    GNUNET_free (tcp_probe_ctx);
    return 0;
  }
  GNUNET_assert (size >= sizeof (tcp_probe_ctx->message));
  memcpy (buf, &tcp_probe_ctx->message, sizeof (tcp_probe_ctx->message));
  GNUNET_SERVER_connect_socket (tcp_probe_ctx->plugin->server,
                                tcp_probe_ctx->sock);
  ret = sizeof (tcp_probe_ctx->message);
  GNUNET_free (tcp_probe_ctx);
  return ret;
}


/**
 * Function called by the NAT subsystem suggesting another peer wants
 * to connect to us via connection reversal.  Try to connect back to the
 * given IP.
 *
 * @param cls closure
 * @param addr address to try
 * @param addrlen number of bytes in addr
 */
static void
try_connection_reversal (void *cls, const struct sockaddr *addr,
                         socklen_t addrlen)
{
  struct Plugin *plugin = cls;
  struct GNUNET_CONNECTION_Handle *sock;
  struct TCPProbeContext *tcp_probe_ctx;

  /**
   * We have received an ICMP response, ostensibly from a peer
   * that wants to connect to us! Send a message to establish a connection.
   */
  sock = GNUNET_CONNECTION_create_from_sockaddr (AF_INET, addr, addrlen);
  if (sock == NULL)
  {
    /* failed for some odd reason (out of sockets?); ignore attempt */
    return;
  }

  /* FIXME: do we need to track these probe context objects so that
   * we can clean them up on plugin unload? */
  tcp_probe_ctx = GNUNET_malloc (sizeof (struct TCPProbeContext));
  tcp_probe_ctx->message.header.size =
      htons (sizeof (struct TCP_NAT_ProbeMessage));
  tcp_probe_ctx->message.header.type =
      htons (GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_NAT_PROBE);
  memcpy (&tcp_probe_ctx->message.clientIdentity, plugin->env->my_identity,
          sizeof (struct GNUNET_PeerIdentity));
  tcp_probe_ctx->plugin = plugin;
  tcp_probe_ctx->sock = sock;
  GNUNET_CONTAINER_DLL_insert (plugin->probe_head, plugin->probe_tail,
                               tcp_probe_ctx);
  tcp_probe_ctx->transmit_handle =
      GNUNET_CONNECTION_notify_transmit_ready (sock,
                                               ntohs (tcp_probe_ctx->
                                                      message.header.size),
                                               GNUNET_TIME_UNIT_FOREVER_REL,
                                               &notify_send_probe,
                                               tcp_probe_ctx);

}


/**
 * Session was idle, so disconnect it
 */
static void
session_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_assert (NULL != cls);
  struct Session *s = cls;

  s->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Session %p was idle for %llu, disconnecting\n",
	      s, GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value);
  /* call session destroy function */
  disconnect_session(s);
}


/**
 * Start session timeout
 */
static void
start_session_timeout (struct Session *s)
{
  GNUNET_assert (NULL != s);
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == s->timeout_task);
  s->timeout_task =  GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                                   &session_timeout,
                                                   s);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "Timeout for session %p set to %llu\n",
	      s, 
	      GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value);
}


/**
 * Increment session timeout due to activity
 */
static void
reschedule_session_timeout (struct Session *s)
{
  GNUNET_assert (NULL != s);
  if (GNUNET_SCHEDULER_NO_TASK == s->timeout_task)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, 
		"Timeout for peer `%s' %s not scheduled\n",
		GNUNET_i2s (&s->target), 
		tcp_address_to_string(NULL, s->addr, s->addrlen));
    return;
  }
  GNUNET_SCHEDULER_cancel (s->timeout_task);
  s->timeout_task =  GNUNET_SCHEDULER_add_delayed (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT,
                                                   &session_timeout,
                                                   s);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Timeout rescheduled for session %p set to %llu\n",
	      s,
	      (unsigned long long) GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value);
}


/**
 * Cancel timeout
 */
static void
stop_session_timeout (struct Session *s)
{
  GNUNET_assert (NULL != s);
  if (GNUNET_SCHEDULER_NO_TASK != s->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (s->timeout_task);
    s->timeout_task = GNUNET_SCHEDULER_NO_TASK;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Timeout rescheduled for session %p canceled\n",
		s, GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value);
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
		"Timeout for session %p was not active\n",
		s);
  }
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
    {&handle_tcp_nat_probe, NULL, GNUNET_MESSAGE_TYPE_TRANSPORT_TCP_NAT_PROBE,
     sizeof (struct TCP_NAT_ProbeMessage)},
    {&handle_tcp_data, NULL, GNUNET_MESSAGE_TYPE_ALL, 0},
    {NULL, NULL, 0, 0}
  };
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct Plugin *plugin;
  struct GNUNET_SERVICE_Context *service;
  unsigned long long aport;
  unsigned long long bport;
  unsigned long long max_connections;
  unsigned int i;
  struct GNUNET_TIME_Relative idle_timeout;
  int ret;
  struct sockaddr **addrs;
  socklen_t *addrlens;

  if (NULL == env->receive)
  {
    /* run in 'stub' mode (i.e. as part of gnunet-peerinfo), don't fully
       initialze the plugin or the API */
    api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
    api->cls = NULL;
    api->address_pretty_printer = &tcp_plugin_address_pretty_printer;
    api->address_to_string = &tcp_address_to_string;
    api->string_to_address = &tcp_string_to_address;
    return api;
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (env->cfg, "transport-tcp",
                                             "MAX_CONNECTIONS",
                                             &max_connections))
    max_connections = 128;

  aport = 0;
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (env->cfg, "transport-tcp", "PORT",
                                              &bport)) || (bport > 65535) ||
      ((GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_number (env->cfg, "transport-tcp",
                                               "ADVERTISED-PORT", &aport)) &&
       (aport > 65535)))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, 
	 _
	 ("Require valid port number for service `%s' in configuration!\n"),
	 "transport-tcp");
    return NULL;
  }
  if (aport == 0)
    aport = bport;
  if (bport == 0)
    aport = 0;
  if (bport != 0)
  {
    service = GNUNET_SERVICE_start ("transport-tcp", env->cfg, GNUNET_SERVICE_OPTION_NONE);
    if (service == NULL)
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
	   _("Failed to start service.\n"));
      return NULL;
    }
  }
  else
    service = NULL;

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->sessionmap = GNUNET_CONTAINER_multihashmap_create(max_connections);
  plugin->max_connections = max_connections;
  plugin->open_port = bport;
  plugin->adv_port = aport;
  plugin->env = env;
  plugin->lsock = NULL;
  if ((service != NULL) &&
      (GNUNET_SYSERR !=
       (ret =
        GNUNET_SERVICE_get_server_addresses ("transport-tcp", env->cfg, &addrs,
                                             &addrlens))))
  {
    plugin->nat =
        GNUNET_NAT_register (env->cfg, GNUNET_YES, aport, (unsigned int) ret,
                             (const struct sockaddr **) addrs, addrlens,
                             &tcp_nat_port_map_callback,
                             &try_connection_reversal, plugin);
    while (ret > 0)
    {
      ret--;
      GNUNET_assert (addrs[ret] != NULL);
      GNUNET_free (addrs[ret]);
    }
    GNUNET_free_non_null (addrs);
    GNUNET_free_non_null (addrlens);
  }
  else
  {
    plugin->nat =
        GNUNET_NAT_register (env->cfg, GNUNET_YES, 0, 0, NULL, NULL, NULL,
                             &try_connection_reversal, plugin);
  }
  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;
  api->send = &tcp_plugin_send;
  api->get_session = &tcp_plugin_get_session;

  api->disconnect = &tcp_plugin_disconnect;
  api->address_pretty_printer = &tcp_plugin_address_pretty_printer;
  api->check_address = &tcp_plugin_check_address;
  api->address_to_string = &tcp_address_to_string;
  api->string_to_address = &tcp_string_to_address;
  plugin->service = service;
  if (service != NULL)
  {
    plugin->server = GNUNET_SERVICE_get_server (service);
  }
  else
  {
    if (GNUNET_OK !=
        GNUNET_CONFIGURATION_get_value_time (env->cfg, "transport-tcp",
                                             "TIMEOUT", &idle_timeout))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
	   _("Failed to find option %s in section %s!\n"),
	   "TIMEOUT", "transport-tcp");
      if (plugin->nat != NULL)
        GNUNET_NAT_unregister (plugin->nat);
      GNUNET_free (plugin);
      GNUNET_free (api);
      return NULL;
    }
    plugin->server =
        GNUNET_SERVER_create_with_sockets (&plugin_tcp_access_check, plugin,
                                           NULL, idle_timeout, GNUNET_YES);
  }
  plugin->handlers = GNUNET_malloc (sizeof (my_handlers));
  memcpy (plugin->handlers, my_handlers, sizeof (my_handlers));
  for (i = 0;
       i < sizeof (my_handlers) / sizeof (struct GNUNET_SERVER_MessageHandler);
       i++)
    plugin->handlers[i].callback_cls = plugin;
  GNUNET_SERVER_add_handlers (plugin->server, plugin->handlers);
  GNUNET_SERVER_disconnect_notify (plugin->server, &disconnect_notify, plugin);
  plugin->nat_wait_conns = GNUNET_CONTAINER_multihashmap_create (16);
  if (bport != 0)
    LOG (GNUNET_ERROR_TYPE_INFO, 
	 _("TCP transport listening on port %llu\n"), bport);
  else
    LOG (GNUNET_ERROR_TYPE_INFO, 
	 _
	 ("TCP transport not listening on any port (client only)\n"));
  if (aport != bport)
    LOG (GNUNET_ERROR_TYPE_INFO, 
                     _
                     ("TCP transport advertises itself as being on port %llu\n"),
                     aport);
  /* Initially set connections to 0 */
  GNUNET_STATISTICS_set(plugin->env->stats,
                        gettext_noop ("# TCP sessions active"), 0,
                        GNUNET_NO);
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
  struct TCPProbeContext *tcp_probe;

  if (NULL == plugin)
  {
    GNUNET_free (api);
    return NULL;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Shutting down TCP plugin\n");

  /* Removing leftover sessions */
  GNUNET_CONTAINER_multihashmap_iterate(plugin->sessionmap, &session_disconnect_it, NULL);
  /* Removing leftover NAT sessions */
  GNUNET_CONTAINER_multihashmap_iterate(plugin->nat_wait_conns, &session_disconnect_it, NULL);

  if (plugin->service != NULL)
    GNUNET_SERVICE_stop (plugin->service);
  else
    GNUNET_SERVER_destroy (plugin->server);
  GNUNET_free (plugin->handlers);
  if (plugin->nat != NULL)
    GNUNET_NAT_unregister (plugin->nat);
  while (NULL != (tcp_probe = plugin->probe_head))
  {
    GNUNET_CONTAINER_DLL_remove (plugin->probe_head, plugin->probe_tail,
                                 tcp_probe);
    GNUNET_CONNECTION_destroy (tcp_probe->sock);
    GNUNET_free (tcp_probe);
  }
  GNUNET_CONTAINER_multihashmap_destroy (plugin->nat_wait_conns);
  GNUNET_CONTAINER_multihashmap_destroy (plugin->sessionmap);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_tcp.c */
