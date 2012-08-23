/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

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
 * @file transport/plugin_transport_http_server.c
 * @brief HTTP/S server transport plugin
 * @author Matthias Wachs
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_connection_lib.h"
#include "gnunet_server_lib.h"
#include "gnunet_service_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_transport_plugin.h"

#include "gnunet_container_lib.h"
#include "gnunet_nat_lib.h"
#include "plugin_transport_http_common.h"
#include "microhttpd.h"

#if BUILD_HTTPS
#define LIBGNUNET_PLUGIN_TRANSPORT_INIT libgnunet_plugin_transport_https_server_init
#define LIBGNUNET_PLUGIN_TRANSPORT_DONE libgnunet_plugin_transport_https_server_done
#else
#define LIBGNUNET_PLUGIN_TRANSPORT_INIT libgnunet_plugin_transport_http_server_init
#define LIBGNUNET_PLUGIN_TRANSPORT_DONE libgnunet_plugin_transport_http_server_done
#endif

#define HTTP_NOT_VALIDATED_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 15)

#define TESTING GNUNET_NO

#if TESTING
#define TIMEOUT_LOG GNUNET_ERROR_TYPE_ERROR
#define TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)
#else
#define TIMEOUT_LOG GNUNET_ERROR_TYPE_DEBUG
#define TIMEOUT GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT
#endif


/**
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin;


/**
 * Session handle for connections.
 */
struct HttpServerSession
{
  /**
   * Stored in a linked list.
   */
  struct HttpServerSession *next;

  /**
   * Stored in a linked list.
   */
  struct HttpServerSession *prev;

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
   * Client send handle
   */
  struct ServerConnection *server_recv;

  /**
   * Client send handle
   */
  struct ServerConnection *server_send;

  /**
   * Address
   */
  void *addr;

  /**
   * Session timeout task
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;
};

struct ServerConnection
{
  /* _RECV or _SEND */
  int direction;

  /* Should this connection get disconnected? GNUNET_YES/NO  */
  int disconnect;

  /* The session this server connection belongs to */
  struct Session *session;

  /* The MHD connection */
  struct MHD_Connection *mhd_conn;
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
   * Linked list head of open sessions.
   */

  struct HttpServerSession *head;

  /**
   * Linked list tail of open sessions.
   */
  struct HttpServerSession *tail;

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
   * Maximum number of sockets the plugin can use
   * Each http inbound /outbound connections are two connections
   */
  unsigned int max_connections;

  /**
   * Current number of sockets the plugin can use
   * Each http inbound /outbound connections are two connections
   */
  unsigned int cur_connections;

  /**
   * External hostname the plugin can be connected to, can be different to
   * the host's FQDN, used e.g. for reverse proxying
   */
  char *ext_addr;

  /**
   * External address length
   */
  size_t ext_addr_len;

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
   * Task calling transport service about external address
   */
  GNUNET_SCHEDULER_TaskIdentifier notify_ext_task;

  /**
   * NAT handle & address management
   */
  struct GNUNET_NAT_Handle *nat;

  /**
   * Server semi connections
   * A full session consists of 2 semi-connections: send and receive
   * If not both directions are established the server keeps this sessions here
   */
  struct HttpServerSession *server_semi_head;

  struct HttpServerSession *server_semi_tail;

  /**
   * List of own addresses
   */

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
   * MHD IPv4 task
   */
  GNUNET_SCHEDULER_TaskIdentifier server_v4_task;

  /**
   * MHD IPv6 task
   */
  GNUNET_SCHEDULER_TaskIdentifier server_v6_task;

  /**
   * The IPv4 server is scheduled to run asap
   */
  int server_v4_immediately;

  /**
   * The IPv6 server is scheduled to run asap
   */
  int server_v6_immediately;

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

  void *addr;

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


static struct Plugin * p;

#if 0
/**
 * Start session timeout
 */
static void
server_start_session_timeout (struct HttpServerSession *s);

/**
 * Increment session timeout due to activity
 */
static void
server_reschedule_session_timeout (struct HttpServerSession *s);
#endif
/**
 * Cancel timeout
 */
static void
server_stop_session_timeout (struct HttpServerSession *s);

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
http_server_plugin_send (void *cls,
                  struct Session *session,
                  const char *msgbuf, size_t msgbuf_size,
                  unsigned int priority,
                  struct GNUNET_TIME_Relative to,
                  GNUNET_TRANSPORT_TransmitContinuation cont, void *cont_cls)
{
  struct HTTP_Server_Plugin *plugin = cls;
  int bytes_sent = 0;

  GNUNET_assert (plugin != NULL);
  GNUNET_assert (session != NULL);

  GNUNET_break (0);

  /*  struct Plugin *plugin = cls; */
  return bytes_sent;
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
http_server_plugin_disconnect (void *cls, const struct GNUNET_PeerIdentity *target)
{
  // struct Plugin *plugin = cls;
  GNUNET_break (0);
}


/**
 * Another peer has suggested an address for this
 * peer and transport plugin.  Check that this could be a valid
 * address.  If so, consider adding it to the list
 * of addresses.
 *
 * @param cls closure
 * @param addr pointer to the address
 * @param addrlen length of addr
 * @return GNUNET_OK if this is a plausible address for this peer
 *         and transport
 */
static int
http_server_plugin_address_suggested (void *cls, const void *addr, size_t addrlen)
{
  struct HTTP_Server_Plugin *plugin = cls;
  struct HttpAddressWrapper *w = plugin->addr_head;

  if ((NULL != plugin->ext_addr) && GNUNET_YES == (http_common_cmp_addresses (addr, addrlen, plugin->ext_addr, plugin->ext_addr_len)))
    return GNUNET_OK;

  while (NULL != w)
  {
    if (GNUNET_YES == (http_common_cmp_addresses(addr,
                                                 addrlen,
                                                 w->addr,
                                                 w->addrlen)))
      return GNUNET_OK;
  }

  return GNUNET_NO;
}

/**
 * Creates a new outbound session the transport
 * service will use to send data to the peer
 *
 * Since HTTP/S server cannot create sessions, always return NULL
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
 * Deleting the session
 * Must not be used afterwards
 */

void
server_delete_session (struct HttpServerSession *s)
{
  struct HTTP_Server_Plugin *plugin = s->plugin;
  server_stop_session_timeout(s);

  GNUNET_CONTAINER_DLL_remove (plugin->head, plugin->tail, s);
  struct HTTP_Message *msg = s->msg_head;
  struct HTTP_Message *tmp = NULL;

  while (msg != NULL)
  {
    tmp = msg->next;

    GNUNET_CONTAINER_DLL_remove (s->msg_head, s->msg_tail, msg);
    if (msg->transmit_cont != NULL)
    {
      msg->transmit_cont (msg->transmit_cont_cls, &s->target, GNUNET_SYSERR);
    }
    GNUNET_free (msg);
    msg = tmp;
  }

  if (s->msg_tk != NULL)
  {
    GNUNET_SERVER_mst_destroy (s->msg_tk);
    s->msg_tk = NULL;
  }
  GNUNET_free (s->addr);
  GNUNET_free_non_null (s->server_recv);
  GNUNET_free_non_null (s->server_send);
  GNUNET_free (s);
}

int
server_disconnect (struct HttpServerSession *s)
{
  struct ServerConnection * send;
  struct ServerConnection * recv;

  send = (struct ServerConnection *) s->server_send;
  if (s->server_send != NULL)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, s->plugin->name,
                     "Server: %p / %p Terminating inbound PUT session to peer `%s'\n",
                     s, s->server_send, GNUNET_i2s (&s->target));

    send->disconnect = GNUNET_YES;
#if MHD_VERSION >= 0x00090E00
      MHD_set_connection_option (send->mhd_conn, MHD_CONNECTION_OPTION_TIMEOUT,
                                 1);
#endif
  }

  recv = (struct ServerConnection *) s->server_recv;
  if (recv != NULL)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, s->plugin->name,
                     "Server: %p / %p Terminating inbound GET session to peer `%s'\n",
                     s, s->server_recv, GNUNET_i2s (&s->target));

    recv->disconnect = GNUNET_YES;
#if MHD_VERSION >= 0x00090E00
      MHD_set_connection_option (recv->mhd_conn, MHD_CONNECTION_OPTION_TIMEOUT,
                                 1);
#endif
  }

  /* Schedule connection immediately */
#if 0
  if (s->addrlen == sizeof (struct IPv4HttpAddress))
  {
    server_reschedule (s->plugin, s->plugin->server_v4, GNUNET_YES);
  }
  else if (s->addrlen == sizeof (struct IPv6HttpAddress))
  {
    server_reschedule (s->plugin, s->plugin->server_v6, GNUNET_YES);
  }
#endif
  return GNUNET_OK;

}


/**
* Cancel timeout
*/
static void
server_stop_session_timeout (struct HttpServerSession *s)
{
 GNUNET_assert (NULL != s);

 if (GNUNET_SCHEDULER_NO_TASK != s->timeout_task)
 {
   GNUNET_SCHEDULER_cancel (s->timeout_task);
   s->timeout_task = GNUNET_SCHEDULER_NO_TASK;
   GNUNET_log (TIMEOUT_LOG, "Timeout stopped for session %p\n", s);
 }
}

static int
server_access_cb (void *cls, struct MHD_Connection *mhd_connection,
                  const char *url, const char *method, const char *version,
                  const char *upload_data, size_t * upload_data_size,
                  void **httpSessionCache)
{
  /* FIXME SPLIT */
  return MHD_NO;
}

static void
server_disconnect_cb (void *cls, struct MHD_Connection *connection,
                      void **httpSessionCache)
{
  /* FIXME SPLIT */
  GNUNET_break (0);
}

/**
 * Check if incoming connection is accepted.
 * NOTE: Here every connection is accepted
 * @param cls plugin as closure
 * @param addr address of incoming connection
 * @param addr_len address length of incoming connection
 * @return MHD_YES if connection is accepted, MHD_NO if connection is rejected
 *
 */
static int
server_accept_cb (void *cls, const struct sockaddr *addr, socklen_t addr_len)
{
  struct HTTP_Server_Plugin *plugin = cls;
  GNUNET_break (0);
  if (plugin->cur_connections <= plugin->max_connections)
    return MHD_YES;
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Server: Cannot accept new connections\n");
    return MHD_NO;
  }
}

static void
server_log (void *arg, const char *fmt, va_list ap)
{
  char text[1024];

  vsnprintf (text, sizeof (text), fmt, ap);
  va_end (ap);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Server: %s\n", text);
}

/**
 * Function that queries MHD's select sets and
 * starts the task waiting for them.
 * @param plugin plugin
 * @param daemon_handle the MHD daemon handle
 * @return gnunet task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier
server_schedule (struct HTTP_Server_Plugin *plugin, struct MHD_Daemon *daemon_handle,
                 int now);

/**
 * Reschedule the execution of both IPv4 and IPv6 server
 * @param plugin the plugin
 * @param server which server to schedule v4 or v6?
 * @param now GNUNET_YES to schedule execution immediately, GNUNET_NO to wait
 * until timeout
 */
static void
server_reschedule (struct HTTP_Server_Plugin *plugin, struct MHD_Daemon *server, int now)
{
  if ((server == plugin->server_v4) && (plugin->server_v4 != NULL))
  {
    if (GNUNET_YES == plugin->server_v4_immediately)
      return; /* No rescheduling, server will run asap */

    if (GNUNET_YES == now)
      plugin->server_v4_immediately = GNUNET_YES;

    if (plugin->server_v4_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (plugin->server_v4_task);
      plugin->server_v4_task = GNUNET_SCHEDULER_NO_TASK;
    }
    plugin->server_v4_task = server_schedule (plugin, plugin->server_v4, now);
  }

  if ((server == plugin->server_v6) && (plugin->server_v6 != NULL))
  {
    if (GNUNET_YES == plugin->server_v6_immediately)
      return; /* No rescheduling, server will run asap */

    if (GNUNET_YES == now)
      plugin->server_v6_immediately = GNUNET_YES;

    if (plugin->server_v6_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (plugin->server_v6_task);
      plugin->server_v6_task = GNUNET_SCHEDULER_NO_TASK;
    }
    plugin->server_v6_task = server_schedule (plugin, plugin->server_v6, now);
  }
}

/**
 * Call MHD IPv4 to process pending requests and then go back
 * and schedule the next run.
 * @param cls plugin as closure
 * @param tc task context
 */
static void
server_v4_run (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct HTTP_Server_Plugin *plugin = cls;

  GNUNET_assert (cls != NULL);

  plugin->server_v4_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
#if 0
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Running IPv4 server\n");
#endif
  plugin->server_v4_immediately = GNUNET_NO;
  GNUNET_assert (MHD_YES == MHD_run (plugin->server_v4));
  server_reschedule (plugin, plugin->server_v4, GNUNET_NO);
}


/**
 * Call MHD IPv6 to process pending requests and then go back
 * and schedule the next run.
 * @param cls plugin as closure
 * @param tc task context
 */
static void
server_v6_run (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct HTTP_Server_Plugin *plugin = cls;

  GNUNET_assert (cls != NULL);
  plugin->server_v6_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
#if 0
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Running IPv6 server\n");
#endif
  plugin->server_v6_immediately = GNUNET_NO;
  GNUNET_assert (MHD_YES == MHD_run (plugin->server_v6));
  server_reschedule (plugin, plugin->server_v6, GNUNET_NO);
}


/**
 * Function that queries MHD's select sets and
 * starts the task waiting for them.
 * @param plugin plugin
 * @param daemon_handle the MHD daemon handle
 * @return gnunet task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier
server_schedule (struct HTTP_Server_Plugin *plugin, struct MHD_Daemon *daemon_handle,
                 int now)
{
  GNUNET_SCHEDULER_TaskIdentifier ret;
  fd_set rs;
  fd_set ws;
  fd_set es;
  struct GNUNET_NETWORK_FDSet *wrs;
  struct GNUNET_NETWORK_FDSet *wws;
  struct GNUNET_NETWORK_FDSet *wes;
  int max;
  unsigned MHD_LONG_LONG timeout;
  static unsigned long long last_timeout = 0;
  int haveto;

  struct GNUNET_TIME_Relative tv;

  ret = GNUNET_SCHEDULER_NO_TASK;
  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  wrs = GNUNET_NETWORK_fdset_create ();
  wes = GNUNET_NETWORK_fdset_create ();
  wws = GNUNET_NETWORK_fdset_create ();
  max = -1;
  GNUNET_assert (MHD_YES == MHD_get_fdset (daemon_handle, &rs, &ws, &es, &max));
  haveto = MHD_get_timeout (daemon_handle, &timeout);
  if (haveto == MHD_YES)
  {
    if (timeout != last_timeout)
    {
#if VERBOSE_SERVER
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                       "SELECT Timeout changed from %llu to %llu\n",
                       last_timeout, timeout);
#endif
      last_timeout = timeout;
    }
    tv.rel_value = (uint64_t) timeout;
  }
  else
    tv = GNUNET_TIME_UNIT_SECONDS;
  /* Force immediate run, since we have outbound data to send */
  if (now == GNUNET_YES)
    tv = GNUNET_TIME_UNIT_MILLISECONDS;
  GNUNET_NETWORK_fdset_copy_native (wrs, &rs, max + 1);
  GNUNET_NETWORK_fdset_copy_native (wws, &ws, max + 1);
  GNUNET_NETWORK_fdset_copy_native (wes, &es, max + 1);

  if (daemon_handle == plugin->server_v4)
  {
    if (plugin->server_v4_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (plugin->server_v4_task);
      plugin->server_v4_task = GNUNET_SCHEDULER_NO_TASK;
    }
#if 0
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Scheduling IPv4 server task in %llu ms\n", tv);
#endif
    ret =
        GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                     tv, wrs, wws,
                                     &server_v4_run, plugin);
  }
  if (daemon_handle == plugin->server_v6)
  {
    if (plugin->server_v6_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (plugin->server_v6_task);
      plugin->server_v6_task = GNUNET_SCHEDULER_NO_TASK;
    }
#if 0
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Scheduling IPv6 server task in %llu ms\n", tv);
#endif
    ret =
        GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                     tv, wrs, wws,
                                     &server_v6_run, plugin);
  }
  GNUNET_NETWORK_fdset_destroy (wrs);
  GNUNET_NETWORK_fdset_destroy (wws);
  GNUNET_NETWORK_fdset_destroy (wes);
  return ret;
}


#if BUILD_HTTPS
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
  if (gn_file == NULL)
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

static int
server_load_certificate (struct HTTP_Server_Plugin *plugin)
{
  int res = GNUNET_OK;

  char *key_file;
  char *cert_file;

  /* Get crypto init string from config
   * If not present just use default values */

  if (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_string (plugin->env->cfg,
                                                        plugin->name,
                                                        "CRYPTO_INIT",
                                                        &plugin->crypto_init))
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                       "Using crypto init string `%s'\n",
                       plugin->crypto_init);
  else
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Using default crypto init string \n");

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (plugin->env->cfg, plugin->name,
                                               "KEY_FILE", &key_file))
  {
    key_file = GNUNET_strdup ("https_key.key");
  }

  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (plugin->env->cfg, plugin->name,
                                               "CERT_FILE", &cert_file))
  {
    GNUNET_asprintf (&cert_file, "%s", "https_cert.crt");
  }

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
        GNUNET_OS_start_process (GNUNET_NO, GNUNET_OS_INHERIT_STD_OUT_AND_ERR, NULL, NULL,
                                 "gnunet-transport-certificate-creation",
                                 "gnunet-transport-certificate-creation",
                                 key_file, cert_file, NULL);
    if (cert_creation == NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                       _
                       ("Could not create a new TLS certificate, program `gnunet-transport-certificate-creation' could not be started!\n"));
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
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                     _
                     ("No usable TLS certificate found and creating one failed!\n"),
                     "transport-https");
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "TLS certificate loaded\n");
  return res;
}
#endif

int
server_start (struct HTTP_Server_Plugin *plugin)
{
  unsigned int timeout;
  GNUNET_assert (NULL != plugin);

#if BUILD_HTTPS
  if (GNUNET_SYSERR == server_load_certificate (plugin))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                     "Could not load or create server certificate! Loading plugin failed!\n");
    return GNUNET_SYSERR;
  }
#endif


#if MHD_VERSION >= 0x00090E00
  timeout = HTTP_NOT_VALIDATED_TIMEOUT.rel_value / 1000;
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "MHD can set timeout per connection! Default time out %u sec.\n",
                   timeout);
#else
  timeout = GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value / 1000;
  GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, plugin->name,
                   "MHD cannot set timeout per connection! Default time out %u sec.\n",
                   timeout);
#endif
  plugin->server_v4 = NULL;
  if (plugin->use_ipv4 == GNUNET_YES)
  {
    plugin->server_v4 = MHD_start_daemon (
#if VERBOSE_SERVER
                                           MHD_USE_DEBUG |
#endif
#if BUILD_HTTPS
                                           MHD_USE_SSL |
#endif
                                           MHD_NO_FLAG, plugin->port,
                                           &server_accept_cb, plugin,
                                           &server_access_cb, plugin,
                                           MHD_OPTION_SOCK_ADDR,
                                           (struct sockaddr_in *)
                                           plugin->server_addr_v4,
                                           MHD_OPTION_CONNECTION_LIMIT,
                                           (unsigned int)
                                           plugin->max_connections,
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
                                           server_log, NULL, MHD_OPTION_END);
  }
  plugin->server_v6 = NULL;
  if (plugin->use_ipv6 == GNUNET_YES)
  {
    plugin->server_v6 = MHD_start_daemon (
#if VERBOSE_SERVER
                                           MHD_USE_DEBUG |
#endif
#if BUILD_HTTPS
                                           MHD_USE_SSL |
#endif
                                           MHD_USE_IPv6, plugin->port,
                                           &server_accept_cb, plugin,
                                           &server_access_cb, plugin,
                                           MHD_OPTION_SOCK_ADDR,
                                           (struct sockaddr_in6 *)
                                           plugin->server_addr_v6,
                                           MHD_OPTION_CONNECTION_LIMIT,
                                           (unsigned int)
                                           plugin->max_connections,
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
                                           server_log, NULL, MHD_OPTION_END);

  }

  if ((plugin->use_ipv4 == GNUNET_YES) && (plugin->server_v4 == NULL))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                     "Failed to start %s IPv4 server component on port %u\n",
                     plugin->name, plugin->port);
    return GNUNET_SYSERR;
  }
  server_reschedule (plugin, plugin->server_v4, GNUNET_NO);

  if ((plugin->use_ipv6 == GNUNET_YES) && (plugin->server_v6 == NULL))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                     "Failed to start %s IPv6 server component on port %u\n",
                     plugin->name, plugin->port);
    return GNUNET_SYSERR;
  }
  server_reschedule (plugin, plugin->server_v6, GNUNET_NO);
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "%s server component started on port %u\n", plugin->name,
                   plugin->port);
  return GNUNET_OK;
}


void
server_stop (struct HTTP_Server_Plugin *plugin)
{
  struct HttpServerSession *s = NULL;
  struct HttpServerSession *t = NULL;

  struct MHD_Daemon *server_v4_tmp = plugin->server_v4;
  plugin->server_v4 = NULL;

  struct MHD_Daemon *server_v6_tmp = plugin->server_v6;
  plugin->server_v6 = NULL;

  if (plugin->server_v4_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (plugin->server_v4_task);
    plugin->server_v4_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (plugin->server_v6_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (plugin->server_v6_task);
    plugin->server_v6_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (server_v6_tmp != NULL)
  {
    MHD_stop_daemon (server_v4_tmp);
  }
  if (server_v6_tmp != NULL)
  {
    MHD_stop_daemon (server_v6_tmp);
  }

  /* cleaning up semi-sessions never propagated */
  s = plugin->server_semi_head;
  while (s != NULL)
  {
#if VERBOSE_SERVER
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Deleting semi-sessions %p\n", s);
#endif
    t = s->next;
    struct HTTP_Message *msg = s->msg_head;
    struct HTTP_Message *tmp = NULL;

    while (msg != NULL)
    {
      tmp = msg->next;

      GNUNET_CONTAINER_DLL_remove (s->msg_head, s->msg_tail, msg);
      if (msg->transmit_cont != NULL)
      {
        msg->transmit_cont (msg->transmit_cont_cls, &s->target, GNUNET_SYSERR);
      }
      GNUNET_free (msg);
      msg = tmp;
    }

    server_delete_session (s);
    s = t;
  }

  p = NULL;

#if BUILD_HTTPS
  GNUNET_free_non_null (plugin->crypto_init);
  GNUNET_free_non_null (plugin->cert);
  GNUNET_free_non_null (plugin->key);
#endif

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "%s server component stopped\n", plugin->name);
}

static void
server_add_address (void *cls, int add_remove, const struct sockaddr *addr,
                 socklen_t addrlen)
{
  struct HTTP_Server_Plugin *plugin = cls;
  struct HttpAddressWrapper *w = NULL;

  if ((AF_INET == addr->sa_family) && (GNUNET_NO == plugin->use_ipv4))
    return;

  if ((AF_INET6 == addr->sa_family) && (GNUNET_NO == plugin->use_ipv6))
    return;

  w = GNUNET_malloc (sizeof (struct HttpAddressWrapper));
  w->addr = http_common_address_from_socket (plugin->protocol, addr, addrlen);
  if (NULL == w->addr)
  {
    GNUNET_free (w);
    return;
  }
  w->addrlen = http_common_address_get_size (w->addr);

  GNUNET_CONTAINER_DLL_insert(plugin->addr_head, plugin->addr_tail, w);
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Notifying transport to add address `%s'\n",
                   http_common_plugin_address_to_string(NULL, w->addr, w->addrlen));

  plugin->env->notify_address (plugin->env->cls, add_remove, w->addr, w->addrlen);
}


static void
server_remove_address (void *cls, int add_remove, const struct sockaddr *addr,
                    socklen_t addrlen)
{
  struct HTTP_Server_Plugin *plugin = cls;
  struct HttpAddressWrapper *w = plugin->addr_head;
  size_t saddr_len;
  void * saddr = http_common_address_from_socket (plugin->protocol, addr, addrlen);
  if (NULL == saddr)
    return;
  saddr_len =  http_common_address_get_size (saddr);

  while (NULL != w)
  {
      if (GNUNET_YES == http_common_cmp_addresses(w->addr, w->addrlen, saddr, saddr_len))
        break;
      w = w->next;
  }
  GNUNET_free (saddr);

  if (NULL == w)
    return;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Notifying transport to remove address `%s'\n",
                   http_common_plugin_address_to_string (NULL, w->addr, w->addrlen));
  GNUNET_CONTAINER_DLL_remove (plugin->addr_head, plugin->addr_tail, w);
  plugin->env->notify_address (plugin->env->cls, add_remove, w->addr, w->addrlen);
  GNUNET_free (w->addr);
  GNUNET_free (w);
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
server_nat_port_map_callback (void *cls, int add_remove, const struct sockaddr *addr,
                       socklen_t addrlen)
{
  GNUNET_assert (cls != NULL);
  struct HTTP_Server_Plugin *plugin = cls;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "NPMC called %s to address `%s'\n",
                   (add_remove == GNUNET_NO) ? "remove" : "add",
                   GNUNET_a2s (addr, addrlen));

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


static int
server_get_addresses (struct HTTP_Server_Plugin *plugin,
                      const char *serviceName,
                      const struct GNUNET_CONFIGURATION_Handle *cfg,
                      struct sockaddr ***addrs, socklen_t ** addr_lens)
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
  if (GNUNET_CONFIGURATION_have_value (cfg, serviceName, "PORT"))
  {
    GNUNET_break (GNUNET_OK ==
                  GNUNET_CONFIGURATION_get_value_number (cfg, serviceName,
                                                         "PORT", &port));
    if (port > 65535)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _
                  ("Require valid port number for service in configuration!\n"));
      return GNUNET_SYSERR;
    }
  }
  if (0 == port)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, plugin->name,
                     "Starting in listen only mode\n");
    return -1; /* listen only */
  }


  if (GNUNET_CONFIGURATION_have_value (cfg, serviceName, "BINDTO"))
  {
    GNUNET_break (GNUNET_OK ==
                  GNUNET_CONFIGURATION_get_value_string (cfg, serviceName,
                                                         "BINDTO", &hostname));
  }
  else
    hostname = NULL;

  if (hostname != NULL)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Resolving `%s' since that is where `%s' will bind to.\n",
                     hostname, serviceName);
    memset (&hints, 0, sizeof (struct addrinfo));
    if (disablev6)
      hints.ai_family = AF_INET;
    if ((0 != (ret = getaddrinfo (hostname, NULL, &hints, &res))) ||
        (res == NULL))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("Failed to resolve `%s': %s\n"),
                  hostname, gai_strerror (ret));
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
      if ((pos->ai_protocol != IPPROTO_TCP) && (pos->ai_protocol != 0))
        continue;               /* not TCP */
      if ((pos->ai_socktype != SOCK_STREAM) && (pos->ai_socktype != 0))
        continue;               /* huh? */
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                       "Service will bind to `%s'\n", GNUNET_a2s (pos->ai_addr,
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

static void
server_start_report_addresses (struct HTTP_Server_Plugin *plugin)
{
  int res = GNUNET_OK;
  struct sockaddr **addrs;
  socklen_t *addrlens;

  res = server_get_addresses (plugin,
                              plugin->name, plugin->env->cfg,
                              &addrs, &addrlens);
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   _("Found %u addresses to report to NAT service\n"), res);

  if (GNUNET_SYSERR == res)
  {
    plugin->nat = NULL;
    return;
  }

  plugin->nat =
      GNUNET_NAT_register (plugin->env->cfg, GNUNET_YES, plugin->port,
                           (unsigned int) res,
                           (const struct sockaddr **) addrs, addrlens,
                           &server_nat_port_map_callback, NULL, plugin);
  while (res > 0)
  {
    res--;
    GNUNET_assert (addrs[res] != NULL);
    GNUNET_free (addrs[res]);
  }
  GNUNET_free_non_null (addrs);
  GNUNET_free_non_null (addrlens);
}


static void
server_stop_report_addresses (struct HTTP_Server_Plugin *plugin)
{
  /* Stop NAT handle */
  if (NULL != plugin->nat)
    GNUNET_NAT_unregister (plugin->nat);

  /* Clean up addresses */
  struct HttpAddressWrapper *w;

  while (plugin->addr_head != NULL)
  {
    w = plugin->addr_head;
    GNUNET_CONTAINER_DLL_remove (plugin->addr_head, plugin->addr_tail, w);
    GNUNET_free (w->addr);
    GNUNET_free (w);
  }
}


/**
 * Check if IPv6 supported on this system
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
    GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, plugin->name,
                     _
                     ("Disabling IPv6 since it is not supported on this system!\n"));
    res = GNUNET_NO;
  }
  else
  {
    GNUNET_break (GNUNET_OK == GNUNET_NETWORK_socket_close (desc));
    desc = NULL;
    res = GNUNET_YES;
  }
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Testing IPv6 on this system: %s\n",
                   (res == GNUNET_YES) ? "successful" : "failed");
  return res;
}


/**
 * Function called when the service shuts down.  Unloads our plugins
 * and cancels pending validations.
 *
 * @param cls closure, unused
 * @param tc task context (unused)
 */
static void
server_notify_external_hostname (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct HTTP_Server_Plugin *plugin = cls;

  plugin->notify_ext_task = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  GNUNET_asprintf(&plugin->ext_addr, "%s://%s", plugin->protocol, plugin->external_hostname);
  plugin->ext_addr_len = strlen (plugin->ext_addr) + 1;
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Notifying transport about external hostname address `%s'\n", plugin->ext_addr);
  plugin->env->notify_address (plugin->env->cls, GNUNET_YES, plugin->ext_addr, plugin->ext_addr_len );
}


static int
server_configure_plugin (struct HTTP_Server_Plugin *plugin)
{
  unsigned long long port;
  unsigned long long max_connections;
  char *bind4_address = NULL;
  char *bind6_address = NULL;

  /* Use IPv4? */
  if (GNUNET_CONFIGURATION_have_value
      (plugin->env->cfg, plugin->name, "USE_IPv4"))
  {
    plugin->use_ipv4 =
        GNUNET_CONFIGURATION_get_value_yesno (plugin->env->cfg, plugin->name,
                                              "USE_IPv4");
  }
  else
    plugin->use_ipv4 = GNUNET_YES;
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   _("IPv4 support is %s\n"),
                   (plugin->use_ipv4 == GNUNET_YES) ? "enabled" : "disabled");

  /* Use IPv6? */
  if (GNUNET_CONFIGURATION_have_value
      (plugin->env->cfg, plugin->name, "USE_IPv6"))
  {
    plugin->use_ipv6 =
        GNUNET_CONFIGURATION_get_value_yesno (plugin->env->cfg, plugin->name,
                                              "USE_IPv6");
  }
  else
    plugin->use_ipv6 = GNUNET_YES;
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   _("IPv6 support is %s\n"),
                   (plugin->use_ipv6 == GNUNET_YES) ? "enabled" : "disabled");

  if ((plugin->use_ipv4 == GNUNET_NO) && (plugin->use_ipv6 == GNUNET_NO))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                     _
                     ("Neither IPv4 nor IPv6 are enabled! Fix in configuration\n"),
                     plugin->name);
    return GNUNET_SYSERR;
  }

  /* Reading port number from config file */
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (plugin->env->cfg, plugin->name,
                                              "PORT", &port)) || (port > 65535))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                     _("Port is required! Fix in configuration\n"),
                     plugin->name);
    return GNUNET_SYSERR;
  }
  plugin->port = port;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   _("Using port %u\n"), plugin->port);

  if ((plugin->use_ipv4 == GNUNET_YES) &&
      (GNUNET_YES == GNUNET_CONFIGURATION_get_value_string (plugin->env->cfg,
                          plugin->name, "BINDTO", &bind4_address)))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Binding %s plugin to specific IPv4 address: `%s'\n",
                     plugin->protocol, bind4_address);
    plugin->server_addr_v4 = GNUNET_malloc (sizeof (struct sockaddr_in));
    if (1 != inet_pton (AF_INET, bind4_address,
                        &plugin->server_addr_v4->sin_addr))
    {
        GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                         _
                         ("Specific IPv4 address `%s' in configuration file is invalid!\n"),
                         bind4_address);
      GNUNET_free (bind4_address);
      GNUNET_free (plugin->server_addr_v4);
      plugin->server_addr_v4 = NULL;
      return GNUNET_SYSERR;
    }
    else
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                         _("Binding to IPv4 address %s\n"), bind4_address);
      plugin->server_addr_v4->sin_family = AF_INET;
      plugin->server_addr_v4->sin_port = htons (plugin->port);
    }
    GNUNET_free (bind4_address);
  }

  if ((plugin->use_ipv6 == GNUNET_YES) &&
      (GNUNET_YES ==
       GNUNET_CONFIGURATION_get_value_string (plugin->env->cfg, plugin->name,
                                              "BINDTO6", &bind6_address)))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Binding %s plugin to specific IPv6 address: `%s'\n",
                     plugin->protocol, bind6_address);
    plugin->server_addr_v6 = GNUNET_malloc (sizeof (struct sockaddr_in6));
    if (1 !=
        inet_pton (AF_INET6, bind6_address, &plugin->server_addr_v6->sin6_addr))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                       _
                       ("Specific IPv6 address `%s' in configuration file is invalid!\n"),
                       bind6_address);
      GNUNET_free (bind6_address);
      GNUNET_free (plugin->server_addr_v6);
      plugin->server_addr_v6 = NULL;
      return GNUNET_SYSERR;
    }
    else
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                         _("Binding to IPv6 address %s\n"), bind6_address);
      plugin->server_addr_v6->sin6_family = AF_INET6;
      plugin->server_addr_v6->sin6_port = htons (plugin->port);
    }
    GNUNET_free (bind6_address);
  }

  if (GNUNET_YES == GNUNET_CONFIGURATION_get_value_string (plugin->env->cfg, plugin->name,
                                              "EXTERNAL_HOSTNAME", &plugin->external_hostname))
  {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                       _("Using external hostname `%s'\n"), plugin->external_hostname);
      plugin->notify_ext_task = GNUNET_SCHEDULER_add_now (&server_notify_external_hostname, plugin);
  }
  else
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "No external hostname configured\n");


  /* Optional parameters */
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (plugin->env->cfg,
                      plugin->name,
                      "MAX_CONNECTIONS", &max_connections))
    max_connections = 128;
  plugin->max_connections = max_connections;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   _("Maximum number of connections is %u\n"),
                   plugin->max_connections);
  return GNUNET_OK;
}

#if 0
/**
 * Session was idle, so disconnect it
 */
static void
server_session_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_assert (NULL != cls);
  struct HttpServerSession *s = cls;

  s->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (TIMEOUT_LOG,
              "Session %p was idle for %llu ms, disconnecting\n",
              s, (unsigned long long) TIMEOUT.rel_value);

  /* call session destroy function */
 GNUNET_assert (GNUNET_OK == server_disconnect (s));
}


/**
* Start session timeout
*/
static void
server_start_session_timeout (struct HttpServerSession *s)
{
 GNUNET_assert (NULL != s);
 GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == s->timeout_task);
 s->timeout_task =  GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                                  &session_timeout,
                                                  s);
 GNUNET_log (TIMEOUT_LOG,
             "Timeout for session %p set to %llu ms\n",
             s,  (unsigned long long) TIMEOUT.rel_value);
}


/**
* Increment session timeout due to activity
*/
static void
server_reschedule_session_timeout (struct HttpServerSession *s)
{
 GNUNET_assert (NULL != s);
 GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != s->timeout_task);

 GNUNET_SCHEDULER_cancel (s->timeout_task);
 s->timeout_task =  GNUNET_SCHEDULER_add_delayed (TIMEOUT,
                                                  &session_timeout,
                                                  s);
 GNUNET_log (TIMEOUT_LOG,
             "Timeout rescheduled for session %p set to %llu ms\n",
             s, (unsigned long long) TIMEOUT.rel_value);
}
#endif

/**
 * Exit point from the plugin.
 */
void *
LIBGNUNET_PLUGIN_TRANSPORT_DONE (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct HTTP_Server_Plugin *plugin = api->cls;

  if (GNUNET_SCHEDULER_NO_TASK != plugin->notify_ext_task)
  {
      GNUNET_SCHEDULER_cancel (plugin->notify_ext_task);
      plugin->notify_ext_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (NULL != plugin->ext_addr)
  {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                       "Notifying transport to remove address `%s'\n",
                       http_common_plugin_address_to_string (NULL,
                           plugin->ext_addr,
                           plugin->ext_addr_len));
      plugin->env->notify_address (plugin->env->cls,
                                   GNUNET_NO,
                                   plugin->ext_addr,
                                   plugin->ext_addr_len);
  }

  /* Stop to report addresses to transport service */
  server_stop_report_addresses (plugin);

  server_stop (plugin);

  /* Clean up */
  GNUNET_free_non_null (plugin->external_hostname);
  GNUNET_free_non_null (plugin->ext_addr);
  GNUNET_free_non_null (plugin->server_addr_v4);
  GNUNET_free_non_null (plugin->server_addr_v6);

  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}


/**
 * Entry point for the plugin.
 */
void *
LIBGNUNET_PLUGIN_TRANSPORT_INIT (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct HTTP_Server_Plugin *plugin;

  plugin = GNUNET_malloc (sizeof (struct HTTP_Server_Plugin));
  plugin->env = env;
  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;
  api->send = &http_server_plugin_send;
  api->disconnect = &http_server_plugin_disconnect;
  api->check_address = &http_server_plugin_address_suggested;
  api->get_session = &http_server_plugin_get_session;

  api->address_to_string = &http_common_plugin_address_to_string;
  api->string_to_address = &http_common_plugin_string_to_address;
  api->address_pretty_printer = &http_common_plugin_address_pretty_printer;

#if BUILD_HTTPS
  plugin->name = "transport-https_server";
  plugin->protocol = "https";
#else
  plugin->name = "transport-http_server";
  plugin->protocol = "http";
#endif

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
  server_start_report_addresses (plugin);

  if (GNUNET_SYSERR == server_start (plugin))
  {
      LIBGNUNET_PLUGIN_TRANSPORT_DONE (api);
      return NULL;
  }

  return api;
}




/* end of plugin_transport_http_server.c */
