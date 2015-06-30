/*
     This file is part of GNUnet
     Copyright (C) 2002-2014 Christian Grothoff (and other contributing authors)

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
 * @file transport/plugin_transport_http_server.c
 * @brief HTTP/S server transport plugin
 * @author Matthias Wachs
 * @author David Barksdale
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_plugin.h"
#include "gnunet_nat_lib.h"
#include "plugin_transport_http_common.h"
#include <microhttpd.h>
#include <regex.h>



#if BUILD_HTTPS
#define PLUGIN_NAME "https_server"
#define LIBGNUNET_PLUGIN_TRANSPORT_INIT libgnunet_plugin_transport_https_server_init
#define LIBGNUNET_PLUGIN_TRANSPORT_DONE libgnunet_plugin_transport_https_server_done
#else
#define PLUGIN_NAME "http_server"
#define LIBGNUNET_PLUGIN_TRANSPORT_INIT libgnunet_plugin_transport_http_server_init
#define LIBGNUNET_PLUGIN_TRANSPORT_DONE libgnunet_plugin_transport_http_server_done
#endif

#define HTTP_ERROR_RESPONSE "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\"><HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD><BODY><H1>Not Found</H1>The requested URL was not found on this server.<P><HR><ADDRESS></ADDRESS></BODY></HTML>"
#define _RECEIVE 0
#define _SEND 1


#define LOG(kind,...) GNUNET_log_from (kind, "transport-" PLUGIN_NAME,__VA_ARGS__)


/**
 * Information we keep with MHD for an HTTP request.
 */
struct ServerRequest
{
  /**
   * The session this server request belongs to
   * Can be NULL, when session was disconnected and freed
   */
  struct Session *session;

  /**
   * The MHD connection
   */
  struct MHD_Connection *mhd_conn;

  /**
   * The MHD daemon
   */
  struct MHD_Daemon *mhd_daemon;

  /**
   * Options requested by peer
   */
  uint32_t options;
#define OPTION_LONG_POLL 1 /* GET request wants long-poll semantics */

  /**
   * _RECV or _SEND
   */
  int direction;

  /**
   * For PUT requests: Is this the first or last callback with size 0
   * For GET requests: Have we sent a message
   */
  int connected;

};


/**
 * Wrapper to manage addresses
 */
struct HttpAddressWrapper
{
  /**
   * Linked list next
   */
  struct HttpAddressWrapper *next;

  /**
   * Linked list previous
   */
  struct HttpAddressWrapper *prev;

  /**
   * An address we are using.
   */
  struct HttpAddress *address;

  /**
   * Length of the address.
   */
  size_t addrlen;
};


/**
 *  Message to send using http
 */
struct HTTP_Message
{
  /**
   * next pointer for double linked list
   */
  struct HTTP_Message *next;

  /**
   * previous pointer for double linked list
   */
  struct HTTP_Message *prev;

  /**
   * buffer containing data to send
   */
  char *buf;

  /**
   * amount of data already sent
   */
  size_t pos;

  /**
   * buffer length
   */
  size_t size;

  /**
   * HTTP/S specific overhead
   */
  size_t overhead;

  /**
   * Continuation function to call once the transmission buffer
   * has again space available.  NULL if there is no
   * continuation to call.
   */
  GNUNET_TRANSPORT_TransmitContinuation transmit_cont;

  /**
   * Closure for transmit_cont.
   */
  void *transmit_cont_cls;
};


/**
 * Session handle for connections.
 */
struct Session
{

  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  struct GNUNET_PeerIdentity target;

  /**
   * Pointer to the global plugin struct.
   */
  struct HTTP_Server_Plugin *plugin;

  /**
   * next pointer for double linked list
   */
  struct HTTP_Message *msg_head;

  /**
   * previous pointer for double linked list
   */
  struct HTTP_Message *msg_tail;

  /**
   * Message stream tokenizer for incoming data
   */
  struct GNUNET_SERVER_MessageStreamTokenizer *msg_tk;

  /**
   * Client recv handle
   */
  struct ServerRequest *server_recv;

  /**
   * Client send handle
   */
  struct ServerRequest *server_send;

  /**
   * Address
   */
  struct GNUNET_HELLO_Address *address;

  /**
   * Absolute time when to receive data again
   * Used for receive throttling
   */
  struct GNUNET_TIME_Absolute next_receive;

  /**
   * Absolute time when this connection will time out.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Session timeout task
   */
  struct GNUNET_SCHEDULER_Task * timeout_task;

  /**
   * Task to resume MHD handling when receiving is allowed again
   */
  struct GNUNET_SCHEDULER_Task * recv_wakeup_task;

  /**
   * Number of bytes waiting for transmission to this peer.
   */
  unsigned long long bytes_in_queue;

  /**
   * Number of messages waiting for transmission to this peer.
   */
  unsigned int msgs_in_queue;

  /**
   * Unique HTTP/S connection tag for this connection
   */
  uint32_t tag;

  /**
   * ATS network type.
   */
  enum GNUNET_ATS_Network_Type scope;

  /**
   * #GNUNET_YES if this session is known to the service.
   */
  int known_to_service;

};


/**
 * Encapsulation of all of the state of the plugin.
 */
struct HTTP_Server_Plugin
{
  /**
   * Our environment.
   */
  struct GNUNET_TRANSPORT_PluginEnvironment *env;

  /**
   * Hash map of open sessions.
   */
  struct GNUNET_CONTAINER_MultiPeerMap *sessions;

  /**
   * Function to call about session status changes.
   */
  GNUNET_TRANSPORT_SessionInfoCallback sic;

  /**
   * Closure for @e sic.
   */
  void *sic_cls;

  /**
   * Plugin name
   */
  char *name;

  /**
   * Protocol
   */
  char *protocol;

  /**
   * External address
   */
  char *external_hostname;

  /**
   * External hostname the plugin can be connected to, can be different to
   * the host's FQDN, used e.g. for reverse proxying
   */
  struct GNUNET_HELLO_Address *ext_addr;

  /**
   * NAT handle & address management
   */
  struct GNUNET_NAT_Handle *nat;

  /**
   * IPv4 addresses DLL head
   */
  struct HttpAddressWrapper *addr_head;

  /**
   * IPv4 addresses DLL tail
   */
  struct HttpAddressWrapper *addr_tail;

  /**
   * IPv4 server socket to bind to
   */
  struct sockaddr_in *server_addr_v4;

  /**
   * IPv6 server socket to bind to
   */
  struct sockaddr_in6 *server_addr_v6;

  /**
   * MHD IPv4 daemon
   */
  struct MHD_Daemon *server_v4;

  /**
   * MHD IPv4 daemon
   */
  struct MHD_Daemon *server_v6;

#if BUILD_HTTPS
  /**
   * Crypto related
   *
   * Example:
   *
   * Use RC4-128 instead of AES:
   * NONE:+VERS-TLS1.0:+ARCFOUR-128:+SHA1:+RSA:+COMP-NULL
   *
   */
  char *crypto_init;

  /**
   * TLS key
   */
  char *key;

  /**
   * TLS certificate
   */
  char *cert;
#endif

  /**
   * MHD IPv4 task
   */
  struct GNUNET_SCHEDULER_Task * server_v4_task;

  /**
   * MHD IPv6 task
   */
  struct GNUNET_SCHEDULER_Task * server_v6_task;

  /**
   * Task calling transport service about external address
   */
  struct GNUNET_SCHEDULER_Task * notify_ext_task;

  /**
   * Notify transport only about external address
   */
  unsigned int external_only;

  /**
   * The IPv4 server is scheduled to run asap
   */
  int server_v4_immediately;

  /**
   * The IPv6 server is scheduled to run asap
   */
  int server_v6_immediately;

  /**
   * Verify external address
   */
  int verify_external_hostname;

  /**
   * Maximum number of sockets the plugin can use
   * Each http request /request connections are two connections
   */
  unsigned int max_request;

  /**
   * Current number of sockets the plugin can use
   * Each http connection are two requests
   */
  unsigned int cur_request;

  /**
   * Did we immediately end the session in disconnect_cb
   */
  int in_shutdown;

  /**
   * Length of peer id
   */
  int peer_id_length;

  /**
   * My options to be included in the address
   */
  uint32_t options;

  /**
   * use IPv6
   */
  uint16_t use_ipv6;

  /**
   * use IPv4
   */
  uint16_t use_ipv4;

  /**
   * Port used
   */
  uint16_t port;

  /**
   * Regex for parsing URLs. FIXME: this seems overkill.
   */
  regex_t url_regex;

};


/**
 * If a session monitor is attached, notify it about the new
 * session state.
 *
 * @param plugin our plugin
 * @param session session that changed state
 * @param state new state of the session
 */
static void
notify_session_monitor (struct HTTP_Server_Plugin *plugin,
                        struct Session *session,
                        enum GNUNET_TRANSPORT_SessionState state)
{
  struct GNUNET_TRANSPORT_SessionInfo info;

  if (NULL == plugin->sic)
    return;
  memset (&info, 0, sizeof (info));
  info.state = state;
  info.is_inbound = GNUNET_YES;
  info.num_msg_pending = session->msgs_in_queue;
  info.num_bytes_pending = session->bytes_in_queue;
  info.receive_delay = session->next_receive;
  info.session_timeout = session->timeout;
  info.address = session->address;
  plugin->sic (plugin->sic_cls,
               session,
               &info);
}


/**
 * Wake up an MHD connection which was suspended
 *
 * @param cls the session
 * @param tc task context
 */
static void
server_wake_up (void *cls,
                const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Session *s = cls;

  s->recv_wakeup_task = NULL;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Session %p: Waking up PUT handle\n",
       s);
  MHD_resume_connection (s->server_recv->mhd_conn);
}


/**
 * Reschedule the execution of both IPv4 and IPv6 server.
 *
 * @param plugin the plugin
 * @param server which server to schedule v4 or v6?
 * @param now #GNUNET_YES to schedule execution immediately, #GNUNET_NO to wait
 * until timeout
 */
static void
server_reschedule (struct HTTP_Server_Plugin *plugin,
                   struct MHD_Daemon *server,
                   int now);


/**
 * Deletes the session.  Must not be used afterwards.
 *
 * @param s the session to delete
 */
static void
server_delete_session (struct Session *s)
{
  struct HTTP_Server_Plugin *plugin = s->plugin;
  struct HTTP_Message *msg;

  if (NULL != s->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (s->timeout_task);
    s->timeout_task = NULL;
    s->timeout = GNUNET_TIME_UNIT_ZERO_ABS;
  }
  if (NULL != s->recv_wakeup_task)
  {
    GNUNET_SCHEDULER_cancel (s->recv_wakeup_task);
    s->recv_wakeup_task = NULL;
    if (NULL != s->server_recv)
      MHD_resume_connection (s->server_recv->mhd_conn);
  }
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_remove (plugin->sessions,
                                                       &s->target,
                                                       s));
  while (NULL != (msg = s->msg_head))
  {
    GNUNET_CONTAINER_DLL_remove (s->msg_head,
                                 s->msg_tail,
                                 msg);
    if (NULL != msg->transmit_cont)
      msg->transmit_cont (msg->transmit_cont_cls,
                          &s->target,
                          GNUNET_SYSERR,
                          msg->size,
                          msg->pos + msg->overhead);
    GNUNET_assert (s->msgs_in_queue > 0);
    s->msgs_in_queue--;
    GNUNET_assert (s->bytes_in_queue >= msg->size);
    s->bytes_in_queue -= msg->size;
    GNUNET_free (msg);
  }

  GNUNET_assert (0 == s->msgs_in_queue);
  GNUNET_assert (0 == s->bytes_in_queue);

  if (NULL != s->server_send)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Server: %p / %p Terminating inbound PUT session to peer `%s'\n",
         s, s->server_send,
         GNUNET_i2s (&s->target));
    s->server_send->session = NULL;
    MHD_set_connection_option (s->server_send->mhd_conn,
                               MHD_CONNECTION_OPTION_TIMEOUT,
                               1 /* 0 = no timeout, so this is MIN */);
    server_reschedule (plugin, s->server_send->mhd_daemon, GNUNET_YES);
  }

  if (NULL != s->server_recv)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Server: %p / %p Terminating inbound GET session to peer `%s'\n",
         s, s->server_recv, GNUNET_i2s (&s->target));
    s->server_recv->session = NULL;
    MHD_set_connection_option (s->server_recv->mhd_conn,
                               MHD_CONNECTION_OPTION_TIMEOUT,
                               1 /* 0 = no timeout, so this is MIN */);
    server_reschedule (plugin, s->server_recv->mhd_daemon, GNUNET_YES);
  }
  notify_session_monitor (plugin,
                          s,
                          GNUNET_TRANSPORT_SS_DONE);
  if (GNUNET_YES == s->known_to_service)
  {
    plugin->env->session_end (plugin->env->cls,
                              s->address,
                              s);
    s->known_to_service = GNUNET_NO;
  }
  if (NULL != s->msg_tk)
  {
    GNUNET_SERVER_mst_destroy (s->msg_tk);
    s->msg_tk = NULL;
  }
  GNUNET_HELLO_address_free (s->address);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Session %p destroyed\n",
       s);

  GNUNET_free (s);
}


/**
 * Disconnect session @a s by telling MHD to close the
 * connections (reducing timeout, etc.).
 *
 * @param cls closure with the `struct HTTP_Server_Plugin`
 * @param s the session
 * @return #GNUNET_OK on success
 */
static int
http_server_plugin_disconnect_session (void *cls,
                                       struct Session *s)
{
  server_delete_session (s);
  return GNUNET_OK;
}


/**
 * Session was idle, so disconnect it
 *
 * @param cls the session
 * @param tc task context
 */
static void
server_session_timeout (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Session *s = cls;
  struct GNUNET_TIME_Relative left;

  s->timeout_task = NULL;
  left = GNUNET_TIME_absolute_get_remaining (s->timeout);
  if (0 != left.rel_value_us)
  {
    /* not actually our turn yet, but let's at least update
       the monitor, it may think we're about to die ... */
    notify_session_monitor (s->plugin,
                            s,
                            GNUNET_TRANSPORT_SS_UP);
    s->timeout_task = GNUNET_SCHEDULER_add_delayed (left,
                                                    &server_session_timeout,
                                                    s);
    return;
  }
  GNUNET_log (TIMEOUT_LOG,
              "Session %p was idle for %s, disconnecting\n",
              s,
	      GNUNET_STRINGS_relative_time_to_string (HTTP_SERVER_SESSION_TIMEOUT,
						      GNUNET_YES));
  server_delete_session (s);
}


/**
 * Increment session timeout due to activity session @a s
 *
 * @param s the session
 */
static void
server_reschedule_session_timeout (struct Session *s)
{
 GNUNET_assert (NULL != s->timeout_task);
  s->timeout = GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
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
 * @param msgbuf_size number of bytes in @a msgbuf
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
 * @param cont_cls closure for @a cont
 * @return number of bytes used (on the physical network, with overheads);
 *         -1 on hard errors (i.e. address invalid); 0 is a legal value
 *         and does NOT mean that the message was not transmitted (DV)
 */
static ssize_t
http_server_plugin_send (void *cls,
                         struct Session *session,
                         const char *msgbuf,
                         size_t msgbuf_size,
                         unsigned int priority,
                         struct GNUNET_TIME_Relative to,
                         GNUNET_TRANSPORT_TransmitContinuation cont,
                         void *cont_cls)
{
  struct HTTP_Server_Plugin *plugin = cls;
  struct HTTP_Message *msg;
  ssize_t bytes_sent = 0;
  char *stat_txt;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Session %p/request %p: Sending message with %u to peer `%s'\n",
       session,
       session->server_send,
       msgbuf_size,
       GNUNET_i2s (&session->target));

  /* create new message and schedule */
  bytes_sent = sizeof (struct HTTP_Message) + msgbuf_size;
  msg = GNUNET_malloc (bytes_sent);
  msg->next = NULL;
  msg->size = msgbuf_size;
  msg->pos = 0;
  msg->buf = (char *) &msg[1];
  msg->transmit_cont = cont;
  msg->transmit_cont_cls = cont_cls;
  memcpy (msg->buf,
          msgbuf,
          msgbuf_size);
  GNUNET_CONTAINER_DLL_insert_tail (session->msg_head,
                                    session->msg_tail,
                                    msg);
  session->msgs_in_queue++;
  session->bytes_in_queue += msg->size;
  notify_session_monitor (plugin,
                          session,
                          GNUNET_TRANSPORT_SS_UP);
  GNUNET_asprintf (&stat_txt,
                   "# bytes currently in %s_server buffers",
                   plugin->protocol);
  GNUNET_STATISTICS_update (plugin->env->stats,
                            stat_txt, msgbuf_size, GNUNET_NO);
  GNUNET_free (stat_txt);

  if (NULL != session->server_send)
    server_reschedule (session->plugin,
                       session->server_send->mhd_daemon,
                       GNUNET_YES);
  return bytes_sent;
}


/**
 * Terminate session during shutdown.
 *
 * @param cls the `struct HTTP_Server_Plugin *`
 * @param peer for which this is a session
 * @param value the `struct Session` to clean up
 * @return #GNUNET_OK (continue to iterate)
 */
static int
destroy_session_shutdown_cb (void *cls,
                    const struct GNUNET_PeerIdentity *peer,
                    void *value)
{
  struct Session *s = value;
  struct ServerRequest *sc_send;
  struct ServerRequest *sc_recv;

  sc_send = s->server_send;
  sc_recv = s->server_recv;
  server_delete_session (s);

  GNUNET_free_non_null (sc_send);
  GNUNET_free_non_null (sc_recv);

  return GNUNET_OK;
}

/**
 * Terminate session.
 *
 * @param cls the `struct HTTP_Server_Plugin *`
 * @param peer for which this is a session
 * @param value the `struct Session` to clean up
 * @return #GNUNET_OK (continue to iterate)
 */
static int
destroy_session_cb (void *cls,
                    const struct GNUNET_PeerIdentity *peer,
                    void *value)
{
  struct Session *s = value;

  server_delete_session (s);
  return GNUNET_OK;
}

/**
 * Function that can be used to force the plugin to disconnect
 * from the given peer and cancel all previous transmissions
 * (and their continuationc).
 *
 * @param cls closure
 * @param target peer from which to disconnect
 */
static void
http_server_plugin_disconnect_peer (void *cls,
                                    const struct GNUNET_PeerIdentity *target)
{
  struct HTTP_Server_Plugin *plugin = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transport tells me to disconnect `%s'\n",
       GNUNET_i2s (target));
  GNUNET_CONTAINER_multipeermap_get_multiple (plugin->sessions,
                                              target,
                                              &destroy_session_cb,
                                              plugin);
}


/**
 * Another peer has suggested an address for this
 * peer and transport plugin.  Check that this could be a valid
 * address.  If so, consider adding it to the list
 * of addresses.
 *
 * @param cls closure
 * @param addr pointer to the address
 * @param addrlen length of @a addr
 * @return #GNUNET_OK if this is a plausible address for this peer
 *         and transport
 */
static int
http_server_plugin_address_suggested (void *cls,
                                      const void *addr,
                                      size_t addrlen)
{
  struct HTTP_Server_Plugin *plugin = cls;
  struct HttpAddressWrapper *next;
  struct HttpAddressWrapper *pos;
  const struct HttpAddress *haddr = addr;

  if ((NULL != plugin->ext_addr) &&
      GNUNET_YES == (http_common_cmp_addresses (addr, addrlen,
                                                plugin->ext_addr->address,
                                                plugin->ext_addr->address_length)))
  {
    /* Checking HTTP_OPTIONS_VERIFY_CERTIFICATE option for external hostname */
    if ((ntohl (haddr->options) & HTTP_OPTIONS_VERIFY_CERTIFICATE) !=
        (plugin->options & HTTP_OPTIONS_VERIFY_CERTIFICATE))
      return GNUNET_NO; /* VERIFY option not set as required! */
    return GNUNET_OK;
  }
  next  = plugin->addr_head;
  while (NULL != (pos = next))
  {
    next = pos->next;
    if (GNUNET_YES == (http_common_cmp_addresses(addr,
                                                 addrlen,
                                                 pos->address,
                                                 pos->addrlen)))
      return GNUNET_OK;
  }
  return GNUNET_NO;
}


/**
 * Creates a new outbound session the transport
 * service will use to send data to the peer.
 *
 * Since HTTP/S server cannot create sessions, always returns NULL.
 *
 * @param cls the plugin
 * @param address the address
 * @return always NULL
 */
static struct Session *
http_server_plugin_get_session (void *cls,
                                const struct GNUNET_HELLO_Address *address)
{
  return NULL;
}


/**
 * Call MHD IPv4 to process pending requests and then go back
 * and schedule the next run.
 *
 * @param cls plugin as closure
 * @param tc task context
 */
static void
server_v4_run (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct HTTP_Server_Plugin *plugin = cls;

  plugin->server_v4_task = NULL;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  plugin->server_v4_immediately = GNUNET_NO;
  GNUNET_assert (MHD_YES == MHD_run (plugin->server_v4));
  server_reschedule (plugin, plugin->server_v4, GNUNET_NO);
}


/**
 * Call MHD IPv6 to process pending requests and then go back
 * and schedule the next run.
 *
 * @param cls plugin as closure
 * @param tc task context
 */
static void
server_v6_run (void *cls,
               const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct HTTP_Server_Plugin *plugin = cls;

  plugin->server_v6_task = NULL;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  plugin->server_v6_immediately = GNUNET_NO;
  GNUNET_assert (MHD_YES == MHD_run (plugin->server_v6));
  server_reschedule (plugin, plugin->server_v6, GNUNET_NO);
}


/**
 * Function that queries MHD's select sets and
 * starts the task waiting for them.
 *
 * @param plugin plugin
 * @param daemon_handle the MHD daemon handle
 * @param now schedule now
 * @return gnunet task identifier
 */
static struct GNUNET_SCHEDULER_Task *
server_schedule (struct HTTP_Server_Plugin *plugin,
                 struct MHD_Daemon *daemon_handle,
                 int now)
{
  struct GNUNET_SCHEDULER_Task * ret;
  fd_set rs;
  fd_set ws;
  fd_set es;
  struct GNUNET_NETWORK_FDSet *wrs;
  struct GNUNET_NETWORK_FDSet *wws;
  int max;
  MHD_UNSIGNED_LONG_LONG timeout;
  static unsigned long long last_timeout = 0;
  int haveto;
  struct GNUNET_TIME_Relative tv;

  if (GNUNET_YES == plugin->in_shutdown)
    return NULL;

  ret = NULL;
  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  wrs = GNUNET_NETWORK_fdset_create ();
  wws = GNUNET_NETWORK_fdset_create ();
  max = -1;
  GNUNET_assert (MHD_YES ==
                 MHD_get_fdset (daemon_handle,
                                &rs,
                                &ws,
                                &es,
                                &max));
  haveto = MHD_get_timeout (daemon_handle, &timeout);
  if (haveto == MHD_YES)
  {
    if (timeout != last_timeout)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "SELECT Timeout changed from %llu to %llu (ms)\n",
           last_timeout, timeout);
      last_timeout = timeout;
    }
    if (timeout <= GNUNET_TIME_UNIT_SECONDS.rel_value_us / 1000LL)
      tv.rel_value_us = (uint64_t) timeout * 1000LL;
    else
      tv = GNUNET_TIME_UNIT_SECONDS;
  }
  else
    tv = GNUNET_TIME_UNIT_SECONDS;
  /* Force immediate run, since we have outbound data to send */
  if (now == GNUNET_YES)
    tv = GNUNET_TIME_UNIT_MILLISECONDS;
  GNUNET_NETWORK_fdset_copy_native (wrs, &rs, max + 1);
  GNUNET_NETWORK_fdset_copy_native (wws, &ws, max + 1);

  if (daemon_handle == plugin->server_v4)
  {
    if (plugin->server_v4_task != NULL)
    {
      GNUNET_SCHEDULER_cancel (plugin->server_v4_task);
      plugin->server_v4_task = NULL;
    }
#if 0
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Scheduling IPv4 server task in %llu ms\n",
         tv);
#endif
    ret =
        GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                     tv, wrs, wws,
                                     &server_v4_run, plugin);
  }
  if (daemon_handle == plugin->server_v6)
  {
    if (plugin->server_v6_task != NULL)
    {
      GNUNET_SCHEDULER_cancel (plugin->server_v6_task);
      plugin->server_v6_task = NULL;
    }
#if 0
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Scheduling IPv6 server task in %llu ms\n", tv);
#endif
    ret =
        GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                     tv, wrs, wws,
                                     &server_v6_run, plugin);
  }
  GNUNET_NETWORK_fdset_destroy (wrs);
  GNUNET_NETWORK_fdset_destroy (wws);
  return ret;
}


/**
 * Reschedule the execution of both IPv4 and IPv6 server
 *
 * @param plugin the plugin
 * @param server which server to schedule v4 or v6?
 * @param now #GNUNET_YES to schedule execution immediately, #GNUNET_NO to wait
 * until timeout
 */
static void
server_reschedule (struct HTTP_Server_Plugin *plugin,
                   struct MHD_Daemon *server,
                   int now)
{
  if ((server == plugin->server_v4) && (plugin->server_v4 != NULL))
  {
    if (GNUNET_YES == plugin->server_v4_immediately)
      return; /* No rescheduling, server will run asap */

    if (GNUNET_YES == now)
      plugin->server_v4_immediately = GNUNET_YES;

    if (plugin->server_v4_task != NULL)
    {
      GNUNET_SCHEDULER_cancel (plugin->server_v4_task);
      plugin->server_v4_task = NULL;
    }
    plugin->server_v4_task = server_schedule (plugin, plugin->server_v4, now);
  }

  if ((server == plugin->server_v6) && (plugin->server_v6 != NULL))
  {
    if (GNUNET_YES == plugin->server_v6_immediately)
      return; /* No rescheduling, server will run asap */

    if (GNUNET_YES == now)
      plugin->server_v6_immediately = GNUNET_YES;

    if (plugin->server_v6_task != NULL)
    {
      GNUNET_SCHEDULER_cancel (plugin->server_v6_task);
      plugin->server_v6_task = NULL;
    }
    plugin->server_v6_task = server_schedule (plugin, plugin->server_v6, now);
  }
}


/**
 * Function that is called to get the keepalive factor.
 * GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT is divided by this number to
 * calculate the interval between keepalive packets.
 *
 * @param cls closure with the `struct HTTP_Server_Plugin`
 * @return keepalive factor
 */
static unsigned int
http_server_query_keepalive_factor (void *cls)
{
  return 3;
}


/**
 * Function that will be called whenever the transport service wants to
 * notify the plugin that a session is still active and in use and
 * therefore the session timeout for this session has to be updated
 *
 * @param cls closure
 * @param peer which peer was the session for
 * @param session which session is being updated
 */
static void
http_server_plugin_update_session_timeout (void *cls,
                                           const struct GNUNET_PeerIdentity *peer,
                                           struct Session *session)
{
  server_reschedule_session_timeout (session);
}


/**
 * Tell MHD that the connection should timeout after @a to seconds.
 *
 * @param plugin our plugin
 * @param s session for which the timeout changes
 * @param to timeout in seconds
 */
static void
server_mhd_connection_timeout (struct HTTP_Server_Plugin *plugin,
			       struct Session *s,
			       unsigned int to)
{
  /* Setting timeouts for other connections */
  if (NULL != s->server_recv)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Setting timeout for %p to %u sec.\n",
         s->server_recv, to);
    MHD_set_connection_option (s->server_recv->mhd_conn,
			       MHD_CONNECTION_OPTION_TIMEOUT,
			       to);
    server_reschedule (plugin, s->server_recv->mhd_daemon, GNUNET_NO);
  }
  if (NULL != s->server_send)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Setting timeout for %p to %u sec.\n",
         s->server_send, to);
    MHD_set_connection_option (s->server_send->mhd_conn,
			       MHD_CONNECTION_OPTION_TIMEOUT,
			       to);
    server_reschedule (plugin, s->server_send->mhd_daemon, GNUNET_NO);
  }
}


/**
 * Parse incoming URL for tag and target
 *
 * @param plugin plugin
 * @param url incoming url
 * @param target where to store the target
 * @param tag where to store the tag
 * @param options where to store the options
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
server_parse_url (struct HTTP_Server_Plugin *plugin,
		  const char *url,
		  struct GNUNET_PeerIdentity *target,
		  uint32_t *tag,
		  uint32_t *options)
{
  regmatch_t matches[4];
  const char *tag_start;
  const char *target_start;
  char *tag_end;
  char *options_end;
  size_t hash_length;
  unsigned long int rc;

  /* URL parsing */
#define URL_REGEX \
  ("^.*/([0-9A-Z]+);([0-9]+)(,[0-9]+)?$")

  if (NULL == url)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  if (regexec(&plugin->url_regex, url, 4, matches, 0))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "URL `%s' did not match regex\n", url);
    return GNUNET_SYSERR;
  }

  target_start = &url[matches[1].rm_so];
  tag_start = &url[matches[2].rm_so];

  /* convert tag */
  rc = strtoul (tag_start, &tag_end, 10);
  if (&url[matches[2].rm_eo] != tag_end)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "URL tag did not line up with submatch\n");
    return GNUNET_SYSERR;
  }
  if (rc == 0)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "URL tag is zero\n");
    return GNUNET_SYSERR;
  }
  if ((rc == ULONG_MAX) && (ERANGE == errno))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "URL tag > ULONG_MAX\n");
    return GNUNET_SYSERR;
  }
  if (rc > UINT32_MAX)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "URL tag > UINT32_MAX\n");
    return GNUNET_SYSERR;
  }
  (*tag) = (uint32_t)rc;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Found tag `%u' in url\n",
       *tag);

  /* convert peer id */
  hash_length = matches[1].rm_eo - matches[1].rm_so;
  if (hash_length != plugin->peer_id_length)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "URL target is %u bytes, expecting %u\n",
         hash_length, plugin->peer_id_length);
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_CRYPTO_eddsa_public_key_from_string (target_start,
						     hash_length,
						     &target->public_key))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "URL target conversion failed\n");
    return GNUNET_SYSERR;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Found target `%s' in URL\n",
       GNUNET_i2s_full (target));

  /* convert options */
  if (-1 == matches[3].rm_so)
  {
    *options = 0;
  }
  else
  {
    rc = strtoul (&url[matches[3].rm_so + 1], &options_end, 10);
    if (&url[matches[3].rm_eo] != options_end)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "URL options did not line up with submatch\n");
      return GNUNET_SYSERR;
    }
    if ((rc == ULONG_MAX) && (ERANGE == errno))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "URL options > ULONG_MAX\n");
      return GNUNET_SYSERR;
    }
    if (rc > UINT32_MAX)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "URL options > UINT32_MAX\n");
      return GNUNET_SYSERR;
    }
    (*options) = (uint32_t) rc;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Found options `%u' in url\n",
         *options);
  }
  return GNUNET_OK;
}


/**
 * Closure for #session_tag_it().
 */
struct SessionTagContext
{
  /**
   * Set to session matching the tag.
   */
  struct Session *res;

  /**
   * Tag we are looking for.
   */
  uint32_t tag;
};


/**
 * Find a session with a matching tag.
 *
 * @param cls the `struct SessionTagContext *`
 * @param key peer identity (unused)
 * @param value the `struct Session *`
 * @return #GNUNET_NO if we found the session, #GNUNET_OK if not
 */
static int
session_tag_it (void *cls,
                const struct GNUNET_PeerIdentity *key,
                void *value)
{
  struct SessionTagContext *stc = cls;
  struct Session *s = value;

  if (s->tag == stc->tag)
  {
    stc->res = s;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Lookup a mhd connection and create one if none is found
 *
 * @param plugin the plugin handle
 * @param mhd_connection the incoming mhd_connection
 * @param url incoming requested URL
 * @param method PUT or GET
 * @return the server connecetion
 */
static struct ServerRequest *
server_lookup_connection (struct HTTP_Server_Plugin *plugin,
                          struct MHD_Connection *mhd_connection,
                          const char *url,
                          const char *method)
{
  struct Session *s = NULL;
  struct ServerRequest *sc = NULL;
  const union MHD_ConnectionInfo *conn_info;
  struct HttpAddress *addr;
  struct GNUNET_PeerIdentity target;
  size_t addr_len;
  struct SessionTagContext stc;
  uint32_t options;
  int direction = GNUNET_SYSERR;
  unsigned int to;
  enum GNUNET_ATS_Network_Type scope;

  conn_info = MHD_get_connection_info (mhd_connection,
                                       MHD_CONNECTION_INFO_CLIENT_ADDRESS);
  if ((conn_info->client_addr->sa_family != AF_INET) &&
      (conn_info->client_addr->sa_family != AF_INET6))
    return NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "New %s request from %s\n",
       method,
       url);
  stc.tag = 0;
  if (GNUNET_SYSERR ==
      server_parse_url (plugin, url, &target, &stc.tag, &options))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Invalid url %s\n", url);
    return NULL;
  }
  if (0 == strcmp (MHD_HTTP_METHOD_PUT, method))
    direction = _RECEIVE;
  else if (0 == strcmp (MHD_HTTP_METHOD_GET, method))
    direction = _SEND;
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Invalid method %s for request from %s\n",
         method, url);
    return NULL;
  }

  plugin->cur_request++;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "New %s request from %s with tag %u (%u of %u)\n",
       method,
       GNUNET_i2s (&target),
       stc.tag,
       plugin->cur_request, plugin->max_request);
  /* find existing session */
  stc.res = NULL;
  GNUNET_CONTAINER_multipeermap_get_multiple (plugin->sessions,
                                              &target,
                                              &session_tag_it,
                                              &stc);
  if (NULL == (s = stc.res))
  {
    /* create new session */
    addr = NULL;
    switch (conn_info->client_addr->sa_family)
    {
    case (AF_INET):
      addr = http_common_address_from_socket (plugin->protocol,
                                              conn_info->client_addr,
                                              sizeof (struct sockaddr_in));
      addr_len = http_common_address_get_size (addr);
      scope = plugin->env->get_address_type (plugin->env->cls,
                                             conn_info->client_addr,
                                             sizeof (struct sockaddr_in));
      break;
    case (AF_INET6):
      addr = http_common_address_from_socket (plugin->protocol,
                                              conn_info->client_addr,
                                              sizeof (struct sockaddr_in6));
      addr_len = http_common_address_get_size (addr);
      scope = plugin->env->get_address_type (plugin->env->cls,
                                             conn_info->client_addr,
                                             sizeof (struct sockaddr_in6));
      break;
    default:
      /* external host name */
      return NULL;
    }
    s = GNUNET_new (struct Session);
    s->target = target;
    s->plugin = plugin;
    s->scope = scope;
    s->address = GNUNET_HELLO_address_allocate (&s->target,
                                                PLUGIN_NAME,
                                                addr,
                                                addr_len,
                                                GNUNET_HELLO_ADDRESS_INFO_INBOUND);
    s->next_receive = GNUNET_TIME_UNIT_ZERO_ABS;
    s->tag = stc.tag;
    s->timeout = GNUNET_TIME_relative_to_absolute (HTTP_SERVER_SESSION_TIMEOUT);
    s->timeout_task = GNUNET_SCHEDULER_add_delayed (HTTP_SERVER_SESSION_TIMEOUT,
                                                    &server_session_timeout,
                                                    s);
    (void) GNUNET_CONTAINER_multipeermap_put (plugin->sessions,
                                              &s->target,
                                              s,
                                              GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
    notify_session_monitor (plugin,
                            s,
                            GNUNET_TRANSPORT_SS_INIT);
    notify_session_monitor (plugin,
                            s,
                            GNUNET_TRANSPORT_SS_HANDSHAKE);
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Creating new session %p for peer `%s' connecting from `%s'\n",
         s, GNUNET_i2s (&target),
         http_common_plugin_address_to_string (plugin->protocol,
                                               addr,
                                               addr_len));
    GNUNET_free_non_null (addr);
  }

  if ( (_RECEIVE == direction) &&
       (NULL != s->server_recv) )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Duplicate PUT request from `%s' tag %u, dismissing new request\n",
         GNUNET_i2s (&target),
         stc.tag);
    return NULL;
  }
  if ((_SEND == direction) && (NULL != s->server_send))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Duplicate GET request from `%s' tag %u, dismissing new request\n",
         GNUNET_i2s (&target),
         stc.tag);
    return NULL;
  }
  sc = GNUNET_new (struct ServerRequest);
  if (conn_info->client_addr->sa_family == AF_INET)
    sc->mhd_daemon = plugin->server_v4;
  if (conn_info->client_addr->sa_family == AF_INET6)
    sc->mhd_daemon = plugin->server_v6;
  sc->mhd_conn = mhd_connection;
  sc->direction = direction;
  sc->connected = GNUNET_NO;
  sc->session = s;
  sc->options = options;
  if (direction == _SEND)
  {
    s->server_send = sc;
  }
  if (direction == _RECEIVE)
  {
    s->server_recv = sc;
  }

  if ((GNUNET_NO == s->known_to_service) &&
      (NULL != s->server_send) &&
      (NULL != s->server_recv) )
  {
    s->known_to_service = GNUNET_YES;
    notify_session_monitor (plugin,
                            s,
                            GNUNET_TRANSPORT_SS_UP);
    plugin->env->session_start (plugin->env->cls,
                                s->address,
                                s,
                                s->scope);
  }

  to = (HTTP_SERVER_SESSION_TIMEOUT.rel_value_us / 1000LL / 1000LL);
  server_mhd_connection_timeout (plugin, s, to);
  return sc;
}


/**
 * Callback called by MHD when it needs data to send
 *
 * @param cls current session
 * @param pos position in buffer
 * @param buf the buffer to write data to
 * @param max max number of bytes available in @a buf
 * @return bytes written to @a buf
 */
static ssize_t
server_send_callback (void *cls,
                      uint64_t pos,
                      char *buf,
                      size_t max)
{
  struct ServerRequest *sc = cls;
  struct Session *s = sc->session;
  ssize_t bytes_read = 0;
  struct HTTP_Message *msg;
  char *stat_txt;

  if (NULL == s)
  {
    /* session is disconnecting */
    return 0;
  }

  sc = s->server_send;
  if (NULL == sc)
    return 0;
  msg = s->msg_head;
  if (NULL != msg)
  {
    /* sending */
    bytes_read = GNUNET_MIN (msg->size - msg->pos,
                             max);
    memcpy (buf, &msg->buf[msg->pos], bytes_read);
    msg->pos += bytes_read;

    /* removing message */
    if (msg->pos == msg->size)
    {
      GNUNET_CONTAINER_DLL_remove (s->msg_head,
                                   s->msg_tail,
                                   msg);
      if (NULL != msg->transmit_cont)
        msg->transmit_cont (msg->transmit_cont_cls, &s->target, GNUNET_OK,
                            msg->size, msg->size + msg->overhead);
      GNUNET_assert (s->msgs_in_queue > 0);
      s->msgs_in_queue--;
      GNUNET_assert (s->bytes_in_queue >= msg->size);
      s->bytes_in_queue -= msg->size;
      GNUNET_free (msg);
      notify_session_monitor (s->plugin,
                              s,
                              GNUNET_TRANSPORT_SS_UPDATE);
    }
  }
  if (0 < bytes_read)
  {
    sc->connected = GNUNET_YES;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Sent %u bytes to peer `%s' with session %p \n",
         bytes_read,
         GNUNET_i2s (&s->target),
         s);
    GNUNET_asprintf (&stat_txt,
                     "# bytes currently in %s_server buffers",
                     s->plugin->protocol);
    GNUNET_STATISTICS_update (s->plugin->env->stats,
                              stat_txt,
                              - bytes_read,
                              GNUNET_NO);
    GNUNET_free (stat_txt);
    GNUNET_asprintf (&stat_txt,
                     "# bytes transmitted via %s_server",
                     s->plugin->protocol);
    GNUNET_STATISTICS_update (s->plugin->env->stats,
                              stat_txt, bytes_read, GNUNET_NO);
    GNUNET_free (stat_txt);
  }
  else if ((sc->options & OPTION_LONG_POLL) && sc->connected)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Completing GET response to peer `%s' with session %p\n",
         GNUNET_i2s (&s->target),
         s);
    return MHD_CONTENT_READER_END_OF_STREAM;
  }
  return bytes_read;
}


/**
 * Callback called by MessageStreamTokenizer when a message has arrived
 *
 * @param cls current session as closure
 * @param client client
 * @param message the message to be forwarded to transport service
 * @return #GNUNET_OK
 */
static int
server_receive_mst_cb (void *cls,
                       void *client,
                       const struct GNUNET_MessageHeader *message)
{
  struct Session *s = cls;
  struct HTTP_Server_Plugin *plugin = s->plugin;
  struct GNUNET_TIME_Relative delay;
  char *stat_txt;

  if (GNUNET_NO == s->known_to_service)
  {
    s->known_to_service = GNUNET_YES;
    plugin->env->session_start (plugin->env->cls,
                                s->address,
                                s,
                                s->scope);
    notify_session_monitor (plugin,
                            s,
                            GNUNET_TRANSPORT_SS_UP);
  }
  delay = plugin->env->receive (plugin->env->cls,
                                s->address,
                                s,
                                message);
  GNUNET_asprintf (&stat_txt,
                   "# bytes received via %s_server",
                   plugin->protocol);
  GNUNET_STATISTICS_update (plugin->env->stats,
                            stat_txt, ntohs (message->size), GNUNET_NO);
  GNUNET_free (stat_txt);
  s->next_receive = GNUNET_TIME_relative_to_absolute (delay);
  if (delay.rel_value_us > 0)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Peer `%s' address `%s' next read delayed for %s\n",
         GNUNET_i2s (&s->target),
         http_common_plugin_address_to_string (plugin->protocol,
                                               s->address->address,
                                               s->address->address_length),
         GNUNET_STRINGS_relative_time_to_string (delay,
                                                 GNUNET_YES));
  }
  server_reschedule_session_timeout (s);
  return GNUNET_OK;
}


/**
 * Add headers to a request indicating that we allow Cross-Origin Resource
 * Sharing.
 *
 * @param response response object to modify
 */
static void
add_cors_headers(struct MHD_Response *response)
{
  MHD_add_response_header (response,
                           "Access-Control-Allow-Origin",
                           "*");
  MHD_add_response_header (response,
                           "Access-Control-Allow-Methods",
                           "GET, PUT, OPTIONS");
  MHD_add_response_header (response,
                           "Access-Control-Max-Age",
                           "86400");
}


/**
 * MHD callback for a new incoming connection
 *
 * @param cls the plugin handle
 * @param mhd_connection the mhd connection
 * @param url the requested URL
 * @param method GET or PUT
 * @param version HTTP version
 * @param upload_data upload data
 * @param upload_data_size size of @a upload_data
 * @param httpSessionCache the session cache to remember the connection
 * @return MHD_YES if connection is accepted, MHD_NO on reject
 */
static int
server_access_cb (void *cls,
                  struct MHD_Connection *mhd_connection,
                  const char *url,
                  const char *method,
                  const char *version,
                  const char *upload_data,
                  size_t *upload_data_size,
                  void **httpSessionCache)
{
  struct HTTP_Server_Plugin *plugin = cls;
  struct ServerRequest *sc = *httpSessionCache;
  struct Session *s;
  struct MHD_Response *response;
  int res = MHD_YES;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       _("Access from connection %p (%u of %u) for `%s' `%s' url `%s' with upload data size %u\n"),
       sc,
       plugin->cur_request,
       plugin->max_request,
       method,
       version,
       url,
       (*upload_data_size));
  if (NULL == sc)
  {
    /* CORS pre-flight request */
    if (0 == strcmp (MHD_HTTP_METHOD_OPTIONS, method))
    {
      response = MHD_create_response_from_buffer (0, NULL,
          MHD_RESPMEM_PERSISTENT);
      add_cors_headers(response);
      res = MHD_queue_response (mhd_connection, MHD_HTTP_OK, response);
      MHD_destroy_response (response);
      return res;
    }
    /* new connection */
    sc = server_lookup_connection (plugin, mhd_connection, url, method);
    if (NULL != sc)
    {
      /* attach to new / existing session */
      (*httpSessionCache) = sc;
    }
    else
    {
      /* existing session already has matching connection, refuse */
      response = MHD_create_response_from_buffer (strlen (HTTP_ERROR_RESPONSE),
                                                  HTTP_ERROR_RESPONSE,
                                                  MHD_RESPMEM_PERSISTENT);
      MHD_add_response_header (response,
			       MHD_HTTP_HEADER_CONTENT_TYPE,
			       "text/html");
      add_cors_headers(response);
      res = MHD_queue_response (mhd_connection, MHD_HTTP_NOT_FOUND, response);
      MHD_destroy_response (response);
      return res;
    }
  }
  /* 'old' connection */
  if (NULL == (s = sc->session))
  {
    /* Session was already disconnected;
       sent HTTP/1.1: 200 OK as response */
    response = MHD_create_response_from_buffer (strlen ("Thank you!"),
                                                "Thank you!",
                                                MHD_RESPMEM_PERSISTENT);
    add_cors_headers(response);
    MHD_queue_response (mhd_connection, MHD_HTTP_OK, response);
    MHD_destroy_response (response);
    return MHD_YES;
  }

  if (sc->direction == _SEND)
  {
    response = MHD_create_response_from_callback (MHD_SIZE_UNKNOWN, 32 * 1024,
        &server_send_callback, sc, NULL);
    add_cors_headers(response);
    MHD_queue_response (mhd_connection, MHD_HTTP_OK, response);
    MHD_destroy_response (response);
    return MHD_YES;
  }
  if (sc->direction == _RECEIVE)
  {
    if ((*upload_data_size == 0) && (sc->connected == GNUNET_NO))
    {
      /* (*upload_data_size == 0) first callback when header are passed */
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Session %p / Connection %p: Peer `%s' PUT on address `%s' connected\n",
           s, sc,
           GNUNET_i2s (&s->target),
           http_common_plugin_address_to_string (plugin->protocol,
                                                 s->address->address,
                                                 s->address->address_length));
      sc->connected = GNUNET_YES;
      return MHD_YES;
    }
    else if ((*upload_data_size == 0) && (sc->connected == GNUNET_YES))
    {
      /* (*upload_data_size == 0) when upload is complete */
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Session %p / Connection %p: Peer `%s' PUT on address `%s' finished upload\n",
           s, sc,
           GNUNET_i2s (&s->target),
           http_common_plugin_address_to_string (plugin->protocol,
                                                 s->address->address,
                                                 s->address->address_length));
      sc->connected = GNUNET_NO;
      /* Sent HTTP/1.1: 200 OK as PUT Response\ */
      response = MHD_create_response_from_buffer (strlen ("Thank you!"),
                                                  "Thank you!",
                                                  MHD_RESPMEM_PERSISTENT);
      add_cors_headers(response);
      MHD_queue_response (mhd_connection, MHD_HTTP_OK, response);
      MHD_destroy_response (response);
      return MHD_YES;
    }
    else if ((*upload_data_size > 0) && (sc->connected == GNUNET_YES))
    {
      struct GNUNET_TIME_Relative delay;

      /* (*upload_data_size > 0) for every segment received */
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Session %p / Connection %p: Peer `%s' PUT on address `%s' received %u bytes\n",
           s, sc,
           GNUNET_i2s (&s->target),
           http_common_plugin_address_to_string (plugin->protocol,
                                                 s->address->address,
                                                 s->address->address_length),
           *upload_data_size);
      delay = GNUNET_TIME_absolute_get_remaining (s->next_receive);
      if (0 == delay.rel_value_us)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "PUT with %u bytes forwarded to MST\n",
             *upload_data_size);
        if (s->msg_tk == NULL)
        {
          s->msg_tk = GNUNET_SERVER_mst_create (&server_receive_mst_cb, s);
        }
        GNUNET_SERVER_mst_receive (s->msg_tk, s, upload_data, *upload_data_size,
            GNUNET_NO, GNUNET_NO);
        server_mhd_connection_timeout (plugin, s,
            GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value_us / 1000LL
                / 1000LL);
        (*upload_data_size) = 0;
      }
      else
      {
        /* delay processing */
        GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
            "Session %p / Connection %p: no inbound bandwidth available! Next read was delayed by %s\n",
            s, sc, GNUNET_STRINGS_relative_time_to_string (delay, GNUNET_YES));
        GNUNET_assert(s->server_recv->mhd_conn == mhd_connection);
        MHD_suspend_connection (s->server_recv->mhd_conn);
        if (NULL == s->recv_wakeup_task)
          s->recv_wakeup_task = GNUNET_SCHEDULER_add_delayed (delay,
              &server_wake_up, s);
      }
      return MHD_YES;
    }
    else
    {
      GNUNET_break (0);
      return MHD_NO;
    }
  }
  return res;
}


/**
 * Callback from MHD when a connection disconnects
 *
 * @param cls closure with the `struct HTTP_Server_Plugin *`
 * @param connection the disconnected MHD connection
 * @param httpSessionCache the pointer to distinguish
 */
static void
server_disconnect_cb (void *cls,
                      struct MHD_Connection *connection,
                      void **httpSessionCache)
{
  struct HTTP_Server_Plugin *plugin = cls;
  struct ServerRequest *sc = *httpSessionCache;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Disconnect for connection %p\n",
       sc);
  if (NULL == sc)
  {
    /* CORS pre-flight request finished */
    return;
  }

  if (NULL != sc->session)
  {
    if (sc->direction == _SEND)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Peer `%s' connection  %p, GET on address `%s' disconnected\n",
           GNUNET_i2s (&sc->session->target),
           sc->session->server_send,
           http_common_plugin_address_to_string (plugin->protocol,
               sc->session->address->address,
               sc->session->address->address_length));

      sc->session->server_send = NULL;
    }
    else if (sc->direction == _RECEIVE)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Peer `%s' connection %p PUT on address `%s' disconnected\n",
           GNUNET_i2s (&sc->session->target),
           sc->session->server_recv,
           http_common_plugin_address_to_string (plugin->protocol,
               sc->session->address->address,
               sc->session->address->address_length));
      sc->session->server_recv = NULL;
      if (NULL != sc->session->msg_tk)
      {
        GNUNET_SERVER_mst_destroy (sc->session->msg_tk);
        sc->session->msg_tk = NULL;
      }
    }
  }
  GNUNET_free (sc);
  plugin->cur_request--;
}


/**
 * Check if incoming connection is accepted.
 *
 * @param cls plugin as closure
 * @param addr address of incoming connection
 * @param addr_len number of bytes in @a addr
 * @return MHD_YES if connection is accepted, MHD_NO if connection is rejected
 */
static int
server_accept_cb (void *cls,
                  const struct sockaddr *addr,
                  socklen_t addr_len)
{
  struct HTTP_Server_Plugin *plugin = cls;

  if (plugin->cur_request <= plugin->max_request)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         _("Accepting connection (%u of %u) from `%s'\n"),
         plugin->cur_request, plugin->max_request,
         GNUNET_a2s (addr, addr_len));
    return MHD_YES;
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Server reached maximum number connections (%u), rejecting new connection\n"),
         plugin->max_request);
    return MHD_NO;
  }
}


/**
 * Log function called by MHD.
 *
 * @param arg NULL
 * @param fmt format string
 * @param ap arguments for the format string (va_start() and va_end()
 *           will be called by MHD)
 */
static void
server_log (void *arg,
            const char *fmt,
            va_list ap)
{
  char text[1024];

  vsnprintf (text,
             sizeof (text),
             fmt,
             ap);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Server: %s\n",
              text);
}


#if BUILD_HTTPS
/**
 * Load ssl certificate from file
 *
 * @param file filename
 * @return content of the file
 */
static char *
server_load_file (const char *file)
{
  struct GNUNET_DISK_FileHandle *gn_file;
  uint64_t fsize;
  char *text = NULL;

  if (GNUNET_OK != GNUNET_DISK_file_size (file,
      &fsize, GNUNET_NO, GNUNET_YES))
    return NULL;
  text = GNUNET_malloc (fsize + 1);
  gn_file =
      GNUNET_DISK_file_open (file, GNUNET_DISK_OPEN_READ,
                             GNUNET_DISK_PERM_USER_READ);
  if (NULL == gn_file)
  {
    GNUNET_free (text);
    return NULL;
  }
  if (GNUNET_SYSERR == GNUNET_DISK_file_read (gn_file, text, fsize))
  {
    GNUNET_free (text);
    GNUNET_DISK_file_close (gn_file);
    return NULL;
  }
  text[fsize] = '\0';
  GNUNET_DISK_file_close (gn_file);
  return text;
}
#endif


#if BUILD_HTTPS
/**
 * Load ssl certificate
 *
 * @param plugin the plugin
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static int
server_load_certificate (struct HTTP_Server_Plugin *plugin)
{
  int res = GNUNET_OK;
  char *key_file;
  char *cert_file;


  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (plugin->env->cfg,
                                               plugin->name,
                                               "KEY_FILE", &key_file))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               plugin->name, "CERT_FILE");
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (plugin->env->cfg,
                                               plugin->name,
                                               "CERT_FILE", &cert_file))
  {
    GNUNET_log_config_missing (GNUNET_ERROR_TYPE_ERROR,
                               plugin->name, "CERT_FILE");
    GNUNET_free (key_file);
    return GNUNET_SYSERR;
  }
  /* Get crypto init string from config. If not present, use
   * default values */
  if (GNUNET_OK ==
      GNUNET_CONFIGURATION_get_value_string (plugin->env->cfg,
                                             plugin->name,
                                             "CRYPTO_INIT",
                                             &plugin->crypto_init))
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Using crypto init string `%s'\n",
         plugin->crypto_init);
  else
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Using default crypto init string \n");

  /* read key & certificates from file */
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Trying to loading TLS certificate from key-file `%s' cert-file`%s'\n",
              key_file, cert_file);

  plugin->key = server_load_file (key_file);
  plugin->cert = server_load_file (cert_file);

  if ((plugin->key == NULL) || (plugin->cert == NULL))
  {
    struct GNUNET_OS_Process *cert_creation;

    GNUNET_free_non_null (plugin->key);
    plugin->key = NULL;
    GNUNET_free_non_null (plugin->cert);
    plugin->cert = NULL;

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No usable TLS certificate found, creating certificate\n");
    errno = 0;
    cert_creation =
        GNUNET_OS_start_process (GNUNET_NO, GNUNET_OS_INHERIT_STD_OUT_AND_ERR,
                                 NULL, NULL, NULL,
                                 "gnunet-transport-certificate-creation",
                                 "gnunet-transport-certificate-creation",
                                 key_file,
                                 cert_file,
                                 NULL);
    if (NULL == cert_creation)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Could not create a new TLS certificate, program `gnunet-transport-certificate-creation' could not be started!\n"));
      GNUNET_free (key_file);
      GNUNET_free (cert_file);

      GNUNET_free_non_null (plugin->key);
      plugin->key = NULL;
      GNUNET_free_non_null (plugin->cert);
      plugin->cert = NULL;
      GNUNET_free_non_null (plugin->crypto_init);
      plugin->crypto_init = NULL;

      return GNUNET_SYSERR;
    }
    GNUNET_assert (GNUNET_OK == GNUNET_OS_process_wait (cert_creation));
    GNUNET_OS_process_destroy (cert_creation);

    plugin->key = server_load_file (key_file);
    plugin->cert = server_load_file (cert_file);
  }

  if ((plugin->key == NULL) || (plugin->cert == NULL))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("No usable TLS certificate found and creating one at `%s/%s' failed!\n"),
         key_file, cert_file);
    GNUNET_free (key_file);
    GNUNET_free (cert_file);

    GNUNET_free_non_null (plugin->key);
    plugin->key = NULL;
    GNUNET_free_non_null (plugin->cert);
    plugin->cert = NULL;
    GNUNET_free_non_null (plugin->crypto_init);
    plugin->crypto_init = NULL;

    return GNUNET_SYSERR;
  }
  GNUNET_free (key_file);
  GNUNET_free (cert_file);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "TLS certificate loaded\n");
  return res;
}
#endif


/**
 * Invoke `MHD_start_daemon` with the various options we need to
 * setup the HTTP server with the given listen address.
 *
 * @param plugin our plugin
 * @param addr listen address to use
 * @param v6 MHD_NO_FLAG or MHD_USE_IPv6, depending on context
 * @return NULL on error
 */
static struct MHD_Daemon *
run_mhd_start_daemon (struct HTTP_Server_Plugin *plugin,
                      const struct sockaddr_in *addr,
                      int v6)
{
  struct MHD_Daemon *server;
  unsigned int timeout;

#if MHD_VERSION >= 0x00090E00
  timeout = HTTP_SERVER_NOT_VALIDATED_TIMEOUT.rel_value_us / 1000LL / 1000LL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "MHD can set timeout per connection! Default time out %u sec.\n",
       timeout);
#else
  timeout = HTTP_SERVER_SESSION_TIMEOUT.rel_value_us / 1000LL / 1000LL;
  LOG (GNUNET_ERROR_TYPE_WARNING,
       "MHD cannot set timeout per connection! Default time out %u sec.\n",
       timeout);
#endif
  server = MHD_start_daemon (
#if VERBOSE_SERVER
                             MHD_USE_DEBUG |
#endif
#if BUILD_HTTPS
                             MHD_USE_SSL |
#endif
                             MHD_USE_SUSPEND_RESUME |
                             v6,
                             plugin->port,
                             &server_accept_cb, plugin,
                             &server_access_cb, plugin,
                             MHD_OPTION_SOCK_ADDR,
                             addr,
                             MHD_OPTION_CONNECTION_LIMIT,
                             (unsigned int) plugin->max_request,
#if BUILD_HTTPS
                             MHD_OPTION_HTTPS_PRIORITIES,
                             plugin->crypto_init,
                             MHD_OPTION_HTTPS_MEM_KEY,
                             plugin->key,
                             MHD_OPTION_HTTPS_MEM_CERT,
                             plugin->cert,
#endif
                             MHD_OPTION_CONNECTION_TIMEOUT,
                             timeout,
                             MHD_OPTION_CONNECTION_MEMORY_LIMIT,
                             (size_t) (2 *
                                       GNUNET_SERVER_MAX_MESSAGE_SIZE),
                             MHD_OPTION_NOTIFY_COMPLETED,
                             &server_disconnect_cb, plugin,
                             MHD_OPTION_EXTERNAL_LOGGER,
                             &server_log, NULL,
                             MHD_OPTION_END);
#ifdef TCP_STEALTH
  if ( (NULL != server) &&
       (0 != (plugin->options & HTTP_OPTIONS_TCP_STEALTH)) )
  {
    const union MHD_DaemonInfo *di;

    di = MHD_get_daemon_info (server,
                              MHD_DAEMON_INFO_LISTEN_FD,
                              NULL);
    if ( (0 != setsockopt ((int) di->listen_fd,
                           IPPROTO_TCP,
                           TCP_STEALTH,
                           plugin->env->my_identity,
                           sizeof (struct GNUNET_PeerIdentity))) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("TCP_STEALTH not supported on this platform.\n"));
      MHD_stop_daemon (server);
      server = NULL;
    }
  }
#endif
  return server;
}


/**
 * Start the HTTP server
 *
 * @param plugin the plugin handle
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static int
server_start (struct HTTP_Server_Plugin *plugin)
{
  const char *msg;

  GNUNET_assert (NULL != plugin);
#if BUILD_HTTPS
  if (GNUNET_SYSERR == server_load_certificate (plugin))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Could not load or create server certificate! Loading plugin failed!\n"));
    return GNUNET_SYSERR;
  }
#endif



  plugin->server_v4 = NULL;
  if (GNUNET_YES == plugin->use_ipv4)
  {
    plugin->server_v4
      = run_mhd_start_daemon (plugin,
                              (const struct sockaddr_in *) plugin->server_addr_v4,
                              MHD_NO_FLAG);

    if (NULL == plugin->server_v4)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Failed to start %s IPv4 server component on port %u\n",
           plugin->name,
           plugin->port);
    }
    else
      server_reschedule (plugin,
                         plugin->server_v4,
                         GNUNET_NO);
  }


  plugin->server_v6 = NULL;
  if (GNUNET_YES == plugin->use_ipv6)
  {
    plugin->server_v6
      = run_mhd_start_daemon (plugin,
                              (const struct sockaddr_in *) plugin->server_addr_v6,
                              MHD_USE_IPv6);
    if (NULL == plugin->server_v6)
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           "Failed to start %s IPv6 server component on port %u\n",
           plugin->name,
           plugin->port);
    }
    else
    {
      server_reschedule (plugin,
                         plugin->server_v6,
                         GNUNET_NO);
    }
  }
  msg = "No";
  if ( (NULL == plugin->server_v6) &&
       (NULL == plugin->server_v4) )
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "%s %s server component started on port %u\n",
         msg,
         plugin->name,
         plugin->port);
    return GNUNET_SYSERR;
  }
  if ((NULL != plugin->server_v6) &&
      (NULL != plugin->server_v4))
    msg = "IPv4 and IPv6";
  else if (NULL != plugin->server_v6)
    msg = "IPv6";
  else if (NULL != plugin->server_v4)
    msg = "IPv4";
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "%s %s server component started on port %u\n",
       msg,
       plugin->name,
       plugin->port);
  return GNUNET_OK;
}


/**
 * Add an address to the server's set of addresses and notify transport
 *
 * @param cls the plugin handle
 * @param add_remove #GNUNET_YES on add, #GNUNET_NO on remove
 * @param addr the address
 * @param addrlen address length
 */
static void
server_add_address (void *cls,
                    int add_remove,
                    const struct sockaddr *addr,
                    socklen_t addrlen)
{
  struct HTTP_Server_Plugin *plugin = cls;
  struct GNUNET_HELLO_Address *address;
  struct HttpAddressWrapper *w = NULL;

  w = GNUNET_new (struct HttpAddressWrapper);
  w->address = http_common_address_from_socket (plugin->protocol,
                                                addr,
                                                addrlen);
  if (NULL == w->address)
  {
    GNUNET_free (w);
    return;
  }
  w->addrlen = http_common_address_get_size (w->address);

  GNUNET_CONTAINER_DLL_insert (plugin->addr_head,
                               plugin->addr_tail,
                               w);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Notifying transport to add address `%s'\n",
       http_common_plugin_address_to_string (plugin->protocol,
                                             w->address,
                                             w->addrlen));
  /* modify our published address list */
#if BUILD_HTTPS
  address = GNUNET_HELLO_address_allocate (plugin->env->my_identity,
      "https_client", w->address, w->addrlen, GNUNET_HELLO_ADDRESS_INFO_NONE);
#else
  address = GNUNET_HELLO_address_allocate (plugin->env->my_identity,
      "http_client", w->address, w->addrlen, GNUNET_HELLO_ADDRESS_INFO_NONE);
#endif

  plugin->env->notify_address (plugin->env->cls,
                               add_remove,
                               address);
  GNUNET_HELLO_address_free (address);
}


/**
 * Remove an address from the server's set of addresses and notify transport
 *
 * @param cls the plugin handle
 * @param add_remove #GNUNET_YES on add, #GNUNET_NO on remove
 * @param addr the address
 * @param addrlen address length
 */
static void
server_remove_address (void *cls,
                       int add_remove,
                       const struct sockaddr *addr,
                       socklen_t addrlen)
{
  struct HTTP_Server_Plugin *plugin = cls;
  struct GNUNET_HELLO_Address *address;
  struct HttpAddressWrapper *w = plugin->addr_head;
  size_t saddr_len;
  void * saddr;

  saddr = http_common_address_from_socket (plugin->protocol,
                                           addr,
                                           addrlen);
  if (NULL == saddr)
    return;
  saddr_len = http_common_address_get_size (saddr);

  while (NULL != w)
  {
    if (GNUNET_YES ==
        http_common_cmp_addresses (w->address,
                                   w->addrlen,
                                   saddr,
                                   saddr_len))
      break;
    w = w->next;
  }
  GNUNET_free (saddr);

  if (NULL == w)
    return;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Notifying transport to remove address `%s'\n",
       http_common_plugin_address_to_string (plugin->protocol,
                                             w->address,
                                             w->addrlen));
  GNUNET_CONTAINER_DLL_remove (plugin->addr_head,
                               plugin->addr_tail,
                               w);
  /* modify our published address list */
#if BUILD_HTTPS
  address = GNUNET_HELLO_address_allocate (plugin->env->my_identity,
      "https_client", w->address, w->addrlen, GNUNET_HELLO_ADDRESS_INFO_NONE);
#else
  address = GNUNET_HELLO_address_allocate (plugin->env->my_identity,
      "http_client", w->address, w->addrlen, GNUNET_HELLO_ADDRESS_INFO_NONE);
#endif
  plugin->env->notify_address (plugin->env->cls, add_remove, address);
  GNUNET_HELLO_address_free (address);
  GNUNET_free (w->address);
  GNUNET_free (w);
}



/**
 * Our external IP address/port mapping has changed.
 *
 * @param cls closure, the 'struct LocalAddrList'
 * @param add_remove #GNUNET_YES to mean the new public IP address, #GNUNET_NO to mean
 *     the previous (now invalid) one
 * @param addr either the previous or the new public IP address
 * @param addrlen actual lenght of the address
 */
static void
server_nat_port_map_callback (void *cls,
                              int add_remove,
                              const struct sockaddr *addr,
                              socklen_t addrlen)
{
  struct HTTP_Server_Plugin *plugin = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "NAT called to %s address `%s'\n",
       (add_remove == GNUNET_NO) ? "remove" : "add",
       GNUNET_a2s (addr, addrlen));

  if (AF_INET == addr->sa_family)
  {
    struct sockaddr_in *s4 = (struct sockaddr_in *) addr;

    if (GNUNET_NO == plugin->use_ipv4)
      return;

    if ((NULL != plugin->server_addr_v4) &&
        (0 != memcmp (&plugin->server_addr_v4->sin_addr,
                      &s4->sin_addr, sizeof (struct in_addr))))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Skipping address `%s' (not bindto address)\n",
           GNUNET_a2s (addr, addrlen));
      return;
    }
  }

  if (AF_INET6 == addr->sa_family)
  {
    struct sockaddr_in6 *s6 = (struct sockaddr_in6 *) addr;
    if (GNUNET_NO == plugin->use_ipv6)
      return;

    if ((NULL != plugin->server_addr_v6) &&
        (0 != memcmp (&plugin->server_addr_v6->sin6_addr,
                      &s6->sin6_addr, sizeof (struct in6_addr))))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Skipping address `%s' (not bindto address)\n",
           GNUNET_a2s (addr, addrlen));
      return;
    }
  }

  switch (add_remove)
  {
  case GNUNET_YES:
    server_add_address (cls, add_remove, addr, addrlen);
    break;
  case GNUNET_NO:
    server_remove_address (cls, add_remove, addr, addrlen);
    break;
  }
}


/**
 * Get valid server addresses
 *
 * @param plugin the plugin handle
 * @param service_name the servicename
 * @param cfg configuration handle
 * @param addrs addresses
 * @param addr_lens address length
 * @return number of addresses
 */
static int
server_get_addresses (struct HTTP_Server_Plugin *plugin,
                      const char *service_name,
                      const struct GNUNET_CONFIGURATION_Handle *cfg,
                      struct sockaddr ***addrs,
                      socklen_t ** addr_lens)
{
  int disablev6;
  unsigned long long port;
  struct addrinfo hints;
  struct addrinfo *res;
  struct addrinfo *pos;
  struct addrinfo *next;
  unsigned int i;
  int resi;
  int ret;
  struct sockaddr **saddrs;
  socklen_t *saddrlens;
  char *hostname;

  *addrs = NULL;
  *addr_lens = NULL;

  disablev6 = !plugin->use_ipv6;

  port = 0;
  if (GNUNET_CONFIGURATION_have_value (cfg, service_name, "PORT"))
  {
    GNUNET_break (GNUNET_OK ==
                  GNUNET_CONFIGURATION_get_value_number (cfg, service_name,
                                                         "PORT", &port));
    if (port > 65535)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Require valid port number for service in configuration!\n"));
      return GNUNET_SYSERR;
    }
  }
  if (0 == port)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "Starting in listen only mode\n");
    return -1; /* listen only */
  }


  if (GNUNET_CONFIGURATION_have_value (cfg, service_name,
                                       "BINDTO"))
  {
    GNUNET_break (GNUNET_OK ==
                  GNUNET_CONFIGURATION_get_value_string (cfg, service_name,
                                                         "BINDTO", &hostname));
  }
  else
    hostname = NULL;

  if (NULL != hostname)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Resolving `%s' since that is where `%s' will bind to.\n",
         hostname, service_name);
    memset (&hints, 0, sizeof (struct addrinfo));
    if (disablev6)
      hints.ai_family = AF_INET;
    if ((0 != (ret = getaddrinfo (hostname, NULL, &hints, &res))) ||
        (NULL == res))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Failed to resolve `%s': %s\n"),
                  hostname,
                  gai_strerror (ret));
      GNUNET_free (hostname);
      return GNUNET_SYSERR;
    }
    next = res;
    i = 0;
    while (NULL != (pos = next))
    {
      next = pos->ai_next;
      if ((disablev6) && (pos->ai_family == AF_INET6))
        continue;
      i++;
    }
    if (0 == i)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("Failed to find %saddress for `%s'.\n"),
                  disablev6 ? "IPv4 " : "", hostname);
      freeaddrinfo (res);
      GNUNET_free (hostname);
      return GNUNET_SYSERR;
    }
    resi = i;
    saddrs = GNUNET_malloc ((resi + 1) * sizeof (struct sockaddr *));
    saddrlens = GNUNET_malloc ((resi + 1) * sizeof (socklen_t));
    i = 0;
    next = res;
    while (NULL != (pos = next))
    {
      next = pos->ai_next;
      if ((disablev6) && (pos->ai_family == AF_INET6))
        continue;
      if ((pos->ai_protocol != IPPROTO_TCP) && (0 != pos->ai_protocol))
        continue;               /* not TCP */
      if ((pos->ai_socktype != SOCK_STREAM) && (0 != pos->ai_socktype))
        continue;               /* huh? */
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Service will bind to `%s'\n",
           GNUNET_a2s (pos->ai_addr,
                       pos->ai_addrlen));
      if (pos->ai_family == AF_INET)
      {
        GNUNET_assert (pos->ai_addrlen == sizeof (struct sockaddr_in));
        saddrlens[i] = pos->ai_addrlen;
        saddrs[i] = GNUNET_malloc (saddrlens[i]);
        memcpy (saddrs[i], pos->ai_addr, saddrlens[i]);
        ((struct sockaddr_in *) saddrs[i])->sin_port = htons (port);
      }
      else
      {
        GNUNET_assert (pos->ai_family == AF_INET6);
        GNUNET_assert (pos->ai_addrlen == sizeof (struct sockaddr_in6));
        saddrlens[i] = pos->ai_addrlen;
        saddrs[i] = GNUNET_malloc (saddrlens[i]);
        memcpy (saddrs[i], pos->ai_addr, saddrlens[i]);
        ((struct sockaddr_in6 *) saddrs[i])->sin6_port = htons (port);
      }
      i++;
    }
    GNUNET_free (hostname);
    freeaddrinfo (res);
    resi = i;
  }
  else
  {
    /* will bind against everything, just set port */
    if (disablev6)
    {
      /* V4-only */
      resi = 1;
      i = 0;
      saddrs = GNUNET_malloc ((resi + 1) * sizeof (struct sockaddr *));
      saddrlens = GNUNET_malloc ((resi + 1) * sizeof (socklen_t));

      saddrlens[i] = sizeof (struct sockaddr_in);
      saddrs[i] = GNUNET_malloc (saddrlens[i]);
#if HAVE_SOCKADDR_IN_SIN_LEN
      ((struct sockaddr_in *) saddrs[i])->sin_len = saddrlens[i];
#endif
      ((struct sockaddr_in *) saddrs[i])->sin_family = AF_INET;
      ((struct sockaddr_in *) saddrs[i])->sin_port = htons (port);
    }
    else
    {
      /* dual stack */
      resi = 2;
      saddrs = GNUNET_malloc ((resi + 1) * sizeof (struct sockaddr *));
      saddrlens = GNUNET_malloc ((resi + 1) * sizeof (socklen_t));
      i = 0;
      saddrlens[i] = sizeof (struct sockaddr_in6);
      saddrs[i] = GNUNET_malloc (saddrlens[i]);
#if HAVE_SOCKADDR_IN_SIN_LEN
      ((struct sockaddr_in6 *) saddrs[i])->sin6_len = saddrlens[0];
#endif
      ((struct sockaddr_in6 *) saddrs[i])->sin6_family = AF_INET6;
      ((struct sockaddr_in6 *) saddrs[i])->sin6_port = htons (port);
      i++;
      saddrlens[i] = sizeof (struct sockaddr_in);
      saddrs[i] = GNUNET_malloc (saddrlens[i]);
#if HAVE_SOCKADDR_IN_SIN_LEN
      ((struct sockaddr_in *) saddrs[i])->sin_len = saddrlens[1];
#endif
      ((struct sockaddr_in *) saddrs[i])->sin_family = AF_INET;
      ((struct sockaddr_in *) saddrs[i])->sin_port = htons (port);
    }
  }
  *addrs = saddrs;
  *addr_lens = saddrlens;
  return resi;
}


/**
 * Ask NAT for addresses
 *
 * @param plugin the plugin handle
 */
static void
server_start_report_addresses (struct HTTP_Server_Plugin *plugin)
{
  int res = GNUNET_OK;
  struct sockaddr **addrs;
  socklen_t *addrlens;

  res = server_get_addresses (plugin,
                              plugin->name,
                              plugin->env->cfg,
                              &addrs, &addrlens);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       _("Found %u addresses to report to NAT service\n"),
       res);

  if (GNUNET_SYSERR == res)
  {
    plugin->nat = NULL;
    return;
  }

  plugin->nat =
      GNUNET_NAT_register (plugin->env->cfg,
                           GNUNET_YES,
                           plugin->port,
                           (unsigned int) res,
                           (const struct sockaddr **) addrs, addrlens,
                           &server_nat_port_map_callback, NULL, plugin);
  while (res > 0)
  {
    res--;
    GNUNET_assert (NULL != addrs[res]);
    GNUNET_free (addrs[res]);
  }
  GNUNET_free_non_null (addrs);
  GNUNET_free_non_null (addrlens);
}


/**
 * Stop NAT for addresses
 *
 * @param plugin the plugin handle
 */
static void
server_stop_report_addresses (struct HTTP_Server_Plugin *plugin)
{
  struct HttpAddressWrapper *w;

  /* Stop NAT handle */
  if (NULL != plugin->nat)
  {
    GNUNET_NAT_unregister (plugin->nat);
    plugin->nat = NULL;
  }
  /* Clean up addresses */
  while (NULL != plugin->addr_head)
  {
    w = plugin->addr_head;
    GNUNET_CONTAINER_DLL_remove (plugin->addr_head,
                                 plugin->addr_tail,
                                 w);
    GNUNET_free (w->address);
    GNUNET_free (w);
  }
}


/**
 * Check if IPv6 supported on this system
 *
 * @param plugin the plugin handle
 * @return #GNUNET_YES on success, else #GNUNET_NO
 */
static int
server_check_ipv6_support (struct HTTP_Server_Plugin *plugin)
{
  struct GNUNET_NETWORK_Handle *desc = NULL;
  int res = GNUNET_NO;

  /* Probe IPv6 support */
  desc = GNUNET_NETWORK_socket_create (PF_INET6, SOCK_STREAM, 0);
  if (NULL == desc)
  {
    if ((errno == ENOBUFS) || (errno == ENOMEM) || (errno == ENFILE) ||
        (errno == EACCES))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "socket");
    }
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Disabling IPv6 since it is not supported on this system!\n"));
    res = GNUNET_NO;
  }
  else
  {
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (desc));
    desc = NULL;
    res = GNUNET_YES;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Testing IPv6 on this system: %s\n",
       (res == GNUNET_YES) ? "successful" : "failed");
  return res;
}


/**
 * Notify server about our external hostname
 *
 * @param cls plugin
 * @param tc task context (unused)
 */
static void
server_notify_external_hostname (void *cls,
                                 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct HTTP_Server_Plugin *plugin = cls;
  struct HttpAddress *ext_addr;
  size_t ext_addr_len;
  unsigned int urlen;
  char *url;

  plugin->notify_ext_task = NULL;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  GNUNET_asprintf(&url,
                  "%s://%s",
                  plugin->protocol,
                  plugin->external_hostname);

  urlen = strlen (url) + 1;
  ext_addr = GNUNET_malloc (sizeof (struct HttpAddress) + urlen);
  ext_addr->options = htonl (plugin->options);
  ext_addr->urlen = htonl (urlen);
  ext_addr_len = sizeof (struct HttpAddress) + urlen;
  memcpy (&ext_addr[1], url, urlen);
  GNUNET_free (url);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Notifying transport about external hostname address `%s'\n",
       plugin->external_hostname);

#if BUILD_HTTPS
  if (GNUNET_YES == plugin->verify_external_hostname)
    LOG (GNUNET_ERROR_TYPE_INFO,
         "Enabling SSL verification for external hostname address `%s'\n",
         plugin->external_hostname);
  plugin->ext_addr = GNUNET_HELLO_address_allocate (plugin->env->my_identity,
      "https_client", ext_addr, ext_addr_len, GNUNET_HELLO_ADDRESS_INFO_NONE );
  plugin->env->notify_address (plugin->env->cls, GNUNET_YES, plugin->ext_addr);
  GNUNET_free (ext_addr);
#else
  plugin->ext_addr = GNUNET_HELLO_address_allocate (plugin->env->my_identity,
      "http_client", ext_addr, ext_addr_len, GNUNET_HELLO_ADDRESS_INFO_NONE );
  plugin->env->notify_address (plugin->env->cls, GNUNET_YES, plugin->ext_addr);
  GNUNET_free (ext_addr);
#endif
}


/**
 * Configure the plugin
 *
 * @param plugin plugin handle
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static int
server_configure_plugin (struct HTTP_Server_Plugin *plugin)
{
  unsigned long long port;
  unsigned long long max_connections;
  char *bind4_address = NULL;
  char *bind6_address = NULL;
  char *eh_tmp = NULL;
  int external_hostname_use_port;

  /* Use IPv4? */
  if (GNUNET_CONFIGURATION_have_value
      (plugin->env->cfg, plugin->name, "USE_IPv4"))
  {
    plugin->use_ipv4 =
        GNUNET_CONFIGURATION_get_value_yesno (plugin->env->cfg,
                                              plugin->name,
                                              "USE_IPv4");
  }
  else
    plugin->use_ipv4 = GNUNET_YES;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       _("IPv4 support is %s\n"),
       (plugin->use_ipv4 == GNUNET_YES) ? "enabled" : "disabled");

  /* Use IPv6? */
  if (GNUNET_CONFIGURATION_have_value
      (plugin->env->cfg, plugin->name, "USE_IPv6"))
  {
    plugin->use_ipv6 =
        GNUNET_CONFIGURATION_get_value_yesno (plugin->env->cfg,
                                              plugin->name,
                                              "USE_IPv6");
  }
  else
    plugin->use_ipv6 = GNUNET_YES;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       _("IPv6 support is %s\n"),
       (plugin->use_ipv6 == GNUNET_YES) ? "enabled" : "disabled");

  if ((plugin->use_ipv4 == GNUNET_NO) && (plugin->use_ipv6 == GNUNET_NO))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Neither IPv4 nor IPv6 are enabled! Fix in configuration\n"));
    return GNUNET_SYSERR;
  }

  /* Reading port number from config file */
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (plugin->env->cfg,
                                              plugin->name,
                                              "PORT", &port)) || (port > 65535))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Port is required! Fix in configuration\n"));
    return GNUNET_SYSERR;
  }
  plugin->port = port;

  LOG (GNUNET_ERROR_TYPE_INFO,
       _("Using port %u\n"), plugin->port);

  if ((plugin->use_ipv4 == GNUNET_YES) &&
      (GNUNET_YES == GNUNET_CONFIGURATION_get_value_string (plugin->env->cfg,
                          plugin->name, "BINDTO", &bind4_address)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Binding %s plugin to specific IPv4 address: `%s'\n",
         plugin->protocol, bind4_address);
    plugin->server_addr_v4 = GNUNET_new (struct sockaddr_in);
    if (1 != inet_pton (AF_INET, bind4_address,
                        &plugin->server_addr_v4->sin_addr))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Specific IPv4 address `%s' in configuration file is invalid!\n"),
           bind4_address);
      GNUNET_free (bind4_address);
      GNUNET_free (plugin->server_addr_v4);
      plugin->server_addr_v4 = NULL;
      return GNUNET_SYSERR;
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           _("Binding to IPv4 address %s\n"),
           bind4_address);
      plugin->server_addr_v4->sin_family = AF_INET;
      plugin->server_addr_v4->sin_port = htons (plugin->port);
    }
    GNUNET_free (bind4_address);
  }

  if ((plugin->use_ipv6 == GNUNET_YES) &&
      (GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_string (plugin->env->cfg,
                                              plugin->name,
                                              "BINDTO6", &bind6_address)))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Binding %s plugin to specific IPv6 address: `%s'\n",
         plugin->protocol, bind6_address);
    plugin->server_addr_v6 = GNUNET_new (struct sockaddr_in6);
    if (1 !=
        inet_pton (AF_INET6, bind6_address, &plugin->server_addr_v6->sin6_addr))
    {
      LOG (GNUNET_ERROR_TYPE_ERROR,
           _("Specific IPv6 address `%s' in configuration file is invalid!\n"),
           bind6_address);
      GNUNET_free (bind6_address);
      GNUNET_free (plugin->server_addr_v6);
      plugin->server_addr_v6 = NULL;
      return GNUNET_SYSERR;
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           _("Binding to IPv6 address %s\n"),
           bind6_address);
      plugin->server_addr_v6->sin6_family = AF_INET6;
      plugin->server_addr_v6->sin6_port = htons (plugin->port);
    }
    GNUNET_free (bind6_address);
  }

  plugin->verify_external_hostname = GNUNET_NO;
#if BUILD_HTTPS
  plugin->verify_external_hostname = GNUNET_CONFIGURATION_get_value_yesno (plugin->env->cfg,
                                                                           plugin->name,
                                                                           "VERIFY_EXTERNAL_HOSTNAME");
  if (GNUNET_SYSERR == plugin->verify_external_hostname)
  	plugin->verify_external_hostname = GNUNET_NO;
  if (GNUNET_YES == plugin->verify_external_hostname)
  	plugin->options |= HTTP_OPTIONS_VERIFY_CERTIFICATE;
#endif
  external_hostname_use_port = GNUNET_CONFIGURATION_get_value_yesno (plugin->env->cfg,
                                                                     plugin->name,
                                                                     "EXTERNAL_HOSTNAME_USE_PORT");
  if (GNUNET_SYSERR == external_hostname_use_port)
  	external_hostname_use_port = GNUNET_NO;


  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_string (plugin->env->cfg,
                                             plugin->name,
                                             "EXTERNAL_HOSTNAME",
                                             &eh_tmp))
  {
    char *tmp;
    char *pos = NULL;
    char *pos_url = NULL;

    if (NULL != strstr(eh_tmp, "://"))
      tmp = &strstr(eh_tmp, "://")[3];
    else
      tmp = eh_tmp;

    if (GNUNET_YES == external_hostname_use_port)
    {
      if ( (strlen (tmp) > 1) && (NULL != (pos = strchr(tmp, '/'))) )
      {
        pos_url = pos + 1;
        pos[0] = '\0';
        GNUNET_asprintf (&plugin->external_hostname,
                         "%s:%u/%s",
                         tmp,
                         (uint16_t) port,
                         (NULL == pos_url) ? "" : pos_url);
      }
      else
        GNUNET_asprintf (&plugin->external_hostname,
                         "%s:%u",
                         tmp,
                         (uint16_t) port);
    }
    else
      plugin->external_hostname = GNUNET_strdup (tmp);
    GNUNET_free (eh_tmp);

    LOG (GNUNET_ERROR_TYPE_INFO,
         _("Using external hostname `%s'\n"),
         plugin->external_hostname);
    plugin->notify_ext_task = GNUNET_SCHEDULER_add_now (&server_notify_external_hostname,
                                                        plugin);

    /* Use only configured external hostname */
    if (GNUNET_CONFIGURATION_have_value
        (plugin->env->cfg,
         plugin->name,
         "EXTERNAL_HOSTNAME_ONLY"))
    {
      plugin->external_only =
        GNUNET_CONFIGURATION_get_value_yesno (plugin->env->cfg,
                                              plugin->name,
                                              "EXTERNAL_HOSTNAME_ONLY");
    }
    else
      plugin->external_only = GNUNET_NO;

    if (GNUNET_YES == plugin->external_only)
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           _("Notifying transport only about hostname `%s'\n"),
           plugin->external_hostname);
  }
  else
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "No external hostname configured\n");

  /* Optional parameters */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (plugin->env->cfg,
                                             plugin->name,
                                             "MAX_CONNECTIONS",
                                             &max_connections))
    max_connections = 128;
  plugin->max_request = max_connections;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       _("Maximum number of connections is %u\n"),
       plugin->max_request);

  plugin->peer_id_length = strlen (GNUNET_i2s_full (plugin->env->my_identity));

  return GNUNET_OK;
}


/**
 * Exit point from the plugin.
 *
 * @param cls api
 * @return NULL
 */
void *
LIBGNUNET_PLUGIN_TRANSPORT_DONE (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct HTTP_Server_Plugin *plugin = api->cls;

  if (NULL == api->cls)
  {
    /* Free for stub mode */
    GNUNET_free (api);
    return NULL;
  }
  plugin->in_shutdown = GNUNET_YES;
  LOG (GNUNET_ERROR_TYPE_INFO,
       _("Shutting down plugin `%s'\n"),
       plugin->name);

  if (NULL != plugin->notify_ext_task)
  {
    GNUNET_SCHEDULER_cancel (plugin->notify_ext_task);
    plugin->notify_ext_task = NULL;
  }

  if (NULL != plugin->ext_addr)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Notifying transport to remove address `%s'\n",
         http_common_plugin_address_to_string (plugin->protocol,
                                               plugin->ext_addr->address,
                                               plugin->ext_addr->address_length));
#if BUILD_HTTPS
    plugin->env->notify_address (plugin->env->cls,
                                 GNUNET_NO,
                                 plugin->ext_addr);
#else
  plugin->env->notify_address (plugin->env->cls,
                               GNUNET_NO,
                               plugin->ext_addr);
#endif
    GNUNET_HELLO_address_free (plugin->ext_addr);
    plugin->ext_addr = NULL;
  }

  /* Stop to report addresses to transport service */
  server_stop_report_addresses (plugin);
  if (NULL != plugin->server_v4)
  {
    MHD_stop_daemon (plugin->server_v4);
    plugin->server_v4 = NULL;
  }
  if (NULL != plugin->server_v6)
  {
    MHD_stop_daemon (plugin->server_v6);
    plugin->server_v6 = NULL;
  }
  if (NULL != plugin->server_v4_task)
  {
    GNUNET_SCHEDULER_cancel (plugin->server_v4_task);
    plugin->server_v4_task = NULL;
  }

  if (NULL != plugin->server_v6_task)
  {
    GNUNET_SCHEDULER_cancel (plugin->server_v6_task);
    plugin->server_v6_task = NULL;
  }
#if BUILD_HTTPS
  GNUNET_free_non_null (plugin->crypto_init);
  GNUNET_free_non_null (plugin->cert);
  GNUNET_free_non_null (plugin->key);
#endif
  GNUNET_CONTAINER_multipeermap_iterate (plugin->sessions,
                                         &destroy_session_shutdown_cb,
                                         plugin);
  GNUNET_CONTAINER_multipeermap_destroy (plugin->sessions);
  plugin->sessions = NULL;
  /* Clean up */
  GNUNET_free_non_null (plugin->external_hostname);
  GNUNET_free_non_null (plugin->ext_addr);
  GNUNET_free_non_null (plugin->server_addr_v4);
  GNUNET_free_non_null (plugin->server_addr_v6);
  regfree (&plugin->url_regex);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       _("Shutdown for plugin `%s' complete\n"),
       plugin->name);

  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}


/**
 * Function called for a quick conversion of the binary address to
 * a numeric address.  Note that the caller must not free the
 * address and that the next call to this function is allowed
 * to override the address again.
 *
 * @param cls unused
 * @param addr binary address
 * @param addrlen length of the address
 * @return string representing the same address
 */
static const char *
http_server_plugin_address_to_string (void *cls,
                                      const void *addr,
                                      size_t addrlen)
{
  return http_common_plugin_address_to_string (PLUGIN_NAME,
                                               addr,
                                               addrlen);
}


/**
 * Function obtain the network type for a session
 *
 * @param cls closure ('struct HTTP_Server_Plugin*')
 * @param session the session
 * @return the network type in HBO or #GNUNET_SYSERR
 */
static enum GNUNET_ATS_Network_Type
http_server_plugin_get_network (void *cls,
                                struct Session *session)
{
  return session->scope;
}


/**
 * Function that will be called whenever the transport service wants to
 * notify the plugin that the inbound quota changed and that the plugin
 * should update it's delay for the next receive value
 *
 * @param cls closure
 * @param peer which peer was the session for
 * @param session which session is being updated
 * @param delay new delay to use for receiving
 */
static void
http_server_plugin_update_inbound_delay (void *cls,
                                         const struct GNUNET_PeerIdentity *peer,
                                         struct Session *session,
                                         struct GNUNET_TIME_Relative delay)
{
  session->next_receive = GNUNET_TIME_relative_to_absolute (delay);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "New inbound delay %s\n",
       GNUNET_STRINGS_relative_time_to_string (delay,
                                               GNUNET_NO));
  if (NULL != session->recv_wakeup_task)
  {
    GNUNET_SCHEDULER_cancel (session->recv_wakeup_task);
    session->recv_wakeup_task
      = GNUNET_SCHEDULER_add_delayed (delay,
                                      &server_wake_up,
                                      session);
  }
}


/**
 * Return information about the given session to the
 * monitor callback.
 *
 * @param cls the `struct Plugin` with the monitor callback (`sic`)
 * @param peer peer we send information about
 * @param value our `struct Session` to send information about
 * @return #GNUNET_OK (continue to iterate)
 */
static int
send_session_info_iter (void *cls,
                        const struct GNUNET_PeerIdentity *peer,
                        void *value)
{
  struct HTTP_Server_Plugin *plugin = cls;
  struct Session *session = value;

  notify_session_monitor (plugin,
                          session,
                          GNUNET_TRANSPORT_SS_INIT);
  return GNUNET_OK;
}


/**
 * Begin monitoring sessions of a plugin.  There can only
 * be one active monitor per plugin (i.e. if there are
 * multiple monitors, the transport service needs to
 * multiplex the generated events over all of them).
 *
 * @param cls closure of the plugin
 * @param sic callback to invoke, NULL to disable monitor;
 *            plugin will being by iterating over all active
 *            sessions immediately and then enter monitor mode
 * @param sic_cls closure for @a sic
 */
static void
http_server_plugin_setup_monitor (void *cls,
                                  GNUNET_TRANSPORT_SessionInfoCallback sic,
                                  void *sic_cls)
{
  struct HTTP_Server_Plugin *plugin = cls;

  plugin->sic = sic;
  plugin->sic_cls = sic_cls;
  if (NULL != sic)
  {
    GNUNET_CONTAINER_multipeermap_iterate (plugin->sessions,
                                           &send_session_info_iter,
                                           plugin);
    /* signal end of first iteration */
    sic (sic_cls, NULL, NULL);
  }
}


/**
 * Entry point for the plugin.
 *
 * @param cls env
 * @return api
 */
void *
LIBGNUNET_PLUGIN_TRANSPORT_INIT (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct HTTP_Server_Plugin *plugin;

  if (NULL == env->receive)
  {
    /* run in 'stub' mode (i.e. as part of gnunet-peerinfo), don't fully
       initialze the plugin or the API */
    api = GNUNET_new (struct GNUNET_TRANSPORT_PluginFunctions);
    api->cls = NULL;
    api->address_to_string = &http_server_plugin_address_to_string;
    api->string_to_address = &http_common_plugin_string_to_address;
    api->address_pretty_printer = &http_common_plugin_address_pretty_printer;
    return api;
  }
  plugin = GNUNET_new (struct HTTP_Server_Plugin);
  plugin->env = env;
  plugin->sessions = GNUNET_CONTAINER_multipeermap_create (128,
                                                           GNUNET_YES);

  api = GNUNET_new (struct GNUNET_TRANSPORT_PluginFunctions);
  api->cls = plugin;
  api->send = &http_server_plugin_send;
  api->disconnect_peer = &http_server_plugin_disconnect_peer;
  api->disconnect_session = &http_server_plugin_disconnect_session;
  api->query_keepalive_factor = &http_server_query_keepalive_factor;
  api->check_address = &http_server_plugin_address_suggested;
  api->get_session = &http_server_plugin_get_session;

  api->address_to_string = &http_server_plugin_address_to_string;
  api->string_to_address = &http_common_plugin_string_to_address;
  api->address_pretty_printer = &http_common_plugin_address_pretty_printer;
  api->get_network = &http_server_plugin_get_network;
  api->update_session_timeout = &http_server_plugin_update_session_timeout;
  api->update_inbound_delay = &http_server_plugin_update_inbound_delay;
  api->setup_monitor = &http_server_plugin_setup_monitor;
#if BUILD_HTTPS
  plugin->name = "transport-https_server";
  plugin->protocol = "https";
#else
  plugin->name = "transport-http_server";
  plugin->protocol = "http";
#endif

  if (GNUNET_YES ==
      GNUNET_CONFIGURATION_get_value_yesno (env->cfg,
                                            plugin->name,
                                            "TCP_STEALTH"))
  {
#ifdef TCP_STEALTH
    plugin->options |= HTTP_OPTIONS_TCP_STEALTH;
#else
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("TCP_STEALTH not supported on this platform.\n"));
    LIBGNUNET_PLUGIN_TRANSPORT_DONE (api);
    return NULL;
#endif
  }

  /* Compile URL regex */
  if (regcomp(&plugin->url_regex,
              URL_REGEX,
              REG_EXTENDED))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
                     _("Unable to compile URL regex\n"));
    LIBGNUNET_PLUGIN_TRANSPORT_DONE (api);
    return NULL;
  }

  /* Configure plugin */
  if (GNUNET_SYSERR == server_configure_plugin (plugin))
  {
    LIBGNUNET_PLUGIN_TRANSPORT_DONE (api);
    return NULL;
  }

  /* Check IPv6 support */
  if (GNUNET_YES == plugin->use_ipv6)
    plugin->use_ipv6 = server_check_ipv6_support (plugin);

  /* Report addresses to transport service */
  if (GNUNET_NO == plugin->external_only)
    server_start_report_addresses (plugin);

  if (GNUNET_SYSERR == server_start (plugin))
  {
    LIBGNUNET_PLUGIN_TRANSPORT_DONE (api);
    return NULL;
  }
  return api;
}

/* end of plugin_transport_http_server.c */
