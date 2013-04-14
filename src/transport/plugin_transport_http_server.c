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
#include "gnunet_common.h"
#include "gnunet_server_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_plugin.h"
#include "gnunet_nat_lib.h"
#include "plugin_transport_http_common.h"
#include <microhttpd.h>

#if BUILD_HTTPS
#define LIBGNUNET_PLUGIN_TRANSPORT_INIT libgnunet_plugin_transport_https_server_init
#define LIBGNUNET_PLUGIN_TRANSPORT_DONE libgnunet_plugin_transport_https_server_done
#else
#define LIBGNUNET_PLUGIN_TRANSPORT_INIT libgnunet_plugin_transport_http_server_init
#define LIBGNUNET_PLUGIN_TRANSPORT_DONE libgnunet_plugin_transport_http_server_done
#endif

#define HTTP_ERROR_RESPONSE "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\"><HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD><BODY><H1>Not Found</H1>The requested URL was not found on this server.<P><HR><ADDRESS></ADDRESS></BODY></HTML>"
#define _RECEIVE 0
#define _SEND 1


/* Enable output for debbuging URL's of incoming requests */
#define DEBUG_URL_PARSE GNUNET_NO


/**
 * Encapsulation of all of the state of the plugin.
 */
struct Plugin;


/**
 * Session handle for connections.
 */
struct Session
{
  /**
   * Stored in a linked list.
   */
  struct Session *next;

  /**
   * Stored in a linked list.
   */
  struct Session *prev;

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
   * Address length
   */
  size_t addrlen;

  /**
   * Unique HTTP/S connection tag for this connection
   */
  uint32_t tag;

  /**
   * ATS network type in NBO
   */
  uint32_t ats_address_network_type;

  /**
   * Was session given to transport service?
   */
  int session_passed;

  /**
   * Did we immediately end the session in disconnect_cb
   */
  int session_ended;

  /**
   * Are incoming connection established at the moment
   */
  int connect_in_progress;

  /**
   * Absolute time when to receive data again
   * Used for receive throttling
   */
  struct GNUNET_TIME_Absolute next_receive;

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

  /* For PUT connections: Is this the first or last callback with size 0 */
  int connected;

  /* The session this server connection belongs to */
  struct Session *session;

  /* The MHD connection */
  struct MHD_Connection *mhd_conn;

  /* The MHD daemon */
  struct MHD_Daemon *mhd_daemon;
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

  struct Session *head;

  /**
   * Linked list tail of open sessions.
   */
  struct Session *tail;

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
   * Verify external address
   */
  int verify_external_hostname;


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
   * Did we immediately end the session in disconnect_cb
   */
  int in_shutdown;

  /**
   * Length of peer id
   */
  int peer_id_length;

  /**
   * External hostname the plugin can be connected to, can be different to
   * the host's FQDN, used e.g. for reverse proxying
   */
  char *ext_addr;

  /**
   * Notify transport only about external address
   */
  unsigned int external_only;

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
 * The http_server plugin handle
 */
static struct HTTP_Server_Plugin * p;


/**
 * Start session timeout for session s
 * @param s the session
 */
static void
server_start_session_timeout (struct Session *s);


/**
 * Increment session timeout due to activity for session s
 * @param s the session
 */
static void
server_reschedule_session_timeout (struct Session *s);


/**
 * Cancel timeout for session s
 * @param s the session
 */
static void
server_stop_session_timeout (struct Session *s);


/**
 * Disconnect a session  s
 * @param s the session
 */
static int
server_disconnect (struct Session *s);


/**
 * Does session s exist?
 *
 * @param plugin the plugin handle
 * @param s the session
 * @return GNUNET_YES on success, GNUNET_NO on error
 */
static int
server_exist_session (struct HTTP_Server_Plugin *plugin, struct Session *s);


/**
 * Reschedule the execution of both IPv4 and IPv6 server
 * @param plugin the plugin
 * @param server which server to schedule v4 or v6?
 * @param now GNUNET_YES to schedule execution immediately, GNUNET_NO to wait
 * until timeout
 */
static void
server_reschedule (struct HTTP_Server_Plugin *plugin, struct MHD_Daemon *server,
				   int now);


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
  struct HTTP_Message *msg;
  int bytes_sent = 0;
  char *stat_txt;

  GNUNET_assert (plugin != NULL);
  GNUNET_assert (session != NULL);

  if (GNUNET_NO == server_exist_session (plugin, session))
  {
      GNUNET_break (0);
      return GNUNET_SYSERR;
  }
  if (NULL == session->server_send)
  {
     if (GNUNET_NO == session->connect_in_progress)
     {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, session->plugin->name,
                       "Session %p/connection %p: Sending message with %u bytes to peer `%s' with FAILED\n",
                       session, session->server_send,
                       msgbuf_size, GNUNET_i2s (&session->target));
      GNUNET_break (0);
      return GNUNET_SYSERR;
     }
  }
  else
  {
      if (GNUNET_YES == session->server_send->disconnect)
        return GNUNET_SYSERR;
  }


  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, session->plugin->name,
                   "Session %p/connection %p: Sending message with %u to peer `%s' with \n",
                   session, session->server_send,
                   msgbuf_size, GNUNET_i2s (&session->target));

  /* create new message and schedule */
  bytes_sent = sizeof (struct HTTP_Message) + msgbuf_size;
  msg = GNUNET_malloc (bytes_sent);
  msg->next = NULL;
  msg->size = msgbuf_size;
  msg->pos = 0;
  msg->buf = (char *) &msg[1];
  msg->transmit_cont = cont;
  msg->transmit_cont_cls = cont_cls;
  memcpy (msg->buf, msgbuf, msgbuf_size);

  GNUNET_CONTAINER_DLL_insert_tail (session->msg_head, session->msg_tail, msg);

  GNUNET_asprintf (&stat_txt, "# bytes currently in %s_server buffers", plugin->protocol);
  GNUNET_STATISTICS_update (plugin->env->stats,
                            stat_txt, msgbuf_size, GNUNET_NO);
  GNUNET_free (stat_txt);

  if (NULL != session->server_send)
  {
      server_reschedule (session->plugin,
                         session->server_send->mhd_daemon,
                         GNUNET_YES);
      server_reschedule_session_timeout (session);
  }
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
  struct HTTP_Server_Plugin *plugin = cls;
  struct Session *next = NULL;
  struct Session *pos = NULL;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Transport tells me to disconnect `%s'\n",
                   GNUNET_i2s (target));

  next = plugin->head;
  while (NULL != (pos = next))
  {
    next = pos->next;
    if (0 == memcmp (target, &pos->target, sizeof (struct GNUNET_PeerIdentity)))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                       "Disconnecting session %p to `%s'\n",
                       pos, GNUNET_i2s (target));
      server_disconnect (pos);
    }
  }

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
http_server_plugin_address_suggested (void *cls, const void *addr,
		size_t addrlen)
{
  struct HTTP_Server_Plugin *plugin = cls;
  struct HttpAddressWrapper *next;
  struct HttpAddressWrapper *pos;


  if ((NULL != plugin->ext_addr) &&
	   GNUNET_YES == (http_common_cmp_addresses (addr, addrlen,
			   	   	   plugin->ext_addr, plugin->ext_addr_len)))
    return GNUNET_OK;

  next  = plugin->addr_head;
  while (NULL != (pos = next))
  {
    next = pos->next;
    if (GNUNET_YES == (http_common_cmp_addresses(addr,
                                                 addrlen,
                                                 pos->addr,
                                                 pos->addrlen)))
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
 *
 * @param s the session to delete
 */
static void
server_delete_session (struct Session *s)
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
      msg->transmit_cont (msg->transmit_cont_cls, &s->target, GNUNET_SYSERR,
                          msg->size, msg->pos + msg->overhead);
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

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Session %p destroyed\n", s);
}


/**
* Cancel timeout for session s
*
* @param s the session
*/
static void
server_stop_session_timeout (struct Session *s)
{
 GNUNET_assert (NULL != s);

 if (GNUNET_SCHEDULER_NO_TASK != s->timeout_task)
 {
   GNUNET_SCHEDULER_cancel (s->timeout_task);
   s->timeout_task = GNUNET_SCHEDULER_NO_TASK;
   GNUNET_log (TIMEOUT_LOG, "Timeout stopped for session %p\n", s);
 }
}


/**
 * Function that queries MHD's select sets and
 * starts the task waiting for them.
 * @param plugin plugin
 * @param daemon_handle the MHD daemon handle
 * @param now schedule immediately
 * @return gnunet task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier
server_schedule (struct HTTP_Server_Plugin *plugin,
				 struct MHD_Daemon *daemon_handle,
                 int now);


/**
 * Reschedule the execution of both IPv4 and IPv6 server
 * @param plugin the plugin
 * @param server which server to schedule v4 or v6?
 * @param now GNUNET_YES to schedule execution immediately, GNUNET_NO to wait
 * until timeout
 */
static void
server_reschedule (struct HTTP_Server_Plugin *plugin, struct MHD_Daemon *server,
				   int now)
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
 * Disconnect session s
 *
 * @param s the session
 * @return GNUNET_OK on success
 */
static int
server_disconnect (struct Session *s)
{
  struct ServerConnection * send = NULL;
  struct ServerConnection * recv = NULL;

  if (GNUNET_NO == server_exist_session (p, s))
  {
      GNUNET_break (0);
      return GNUNET_SYSERR;
  }

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
    server_reschedule (s->plugin, send->mhd_daemon, GNUNET_YES);
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
    server_reschedule (s->plugin, recv->mhd_daemon, GNUNET_YES);
  }
  return GNUNET_OK;
}

static void
server_mhd_connection_timeout (struct HTTP_Server_Plugin *plugin, struct Session *s, int to)
{
#if MHD_VERSION >= 0x00090E00
    /* Setting timeouts for other connections */
    if (s->server_recv != NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                       "Setting timeout for %p to %u sec.\n", s->server_recv, to);
      MHD_set_connection_option (s->server_recv->mhd_conn,
                                 MHD_CONNECTION_OPTION_TIMEOUT,
                                 to);
      server_reschedule (plugin, s->server_recv->mhd_daemon, GNUNET_NO);
    }
    if (s->server_send != NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                       "Setting timeout for %p to %u sec.\n", s->server_send, to);
      MHD_set_connection_option (s->server_send->mhd_conn,
                                 MHD_CONNECTION_OPTION_TIMEOUT,
                                 to);
      server_reschedule (plugin, s->server_send->mhd_daemon, GNUNET_NO);
    }
#endif
}

/**
 * Parse incoming URL for tag and target
 *
 * @param plugin plugin
 * @param url incoming url
 * @param target where to store the target
 * @param tag where to store the tag
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */

static int
server_parse_url (struct HTTP_Server_Plugin *plugin, const char * url, struct GNUNET_PeerIdentity * target, uint32_t *tag)
{
  char * tag_start = NULL;
  char * tag_end = NULL;
  char * target_start = NULL;
  char * separator = NULL;
  char hash[plugin->peer_id_length+1];
  int hash_length;
  unsigned long int ctag;

  /* URL parsing
   * URL is valid if it is in the form [prefix with (multiple) '/'][peerid[103];tag]*/

  if (NULL == url)
  {
      GNUNET_break (0);
      return GNUNET_SYSERR;
  }
  /* convert tag */

  /* find separator */
  separator = strrchr (url, ';');

  if (NULL == separator)
  {
      if (DEBUG_URL_PARSE) GNUNET_break (0);
      return GNUNET_SYSERR;
  }
  tag_start = separator + 1;

  if (strlen (tag_start) == 0)
  {
    /* No tag after separator */
    if (DEBUG_URL_PARSE) GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  ctag = strtoul (tag_start, &tag_end, 10);
  if (ctag == 0)
  {
    /* tag == 0 , invalid */
    if (DEBUG_URL_PARSE) GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if ((ctag == ULONG_MAX) && (ERANGE == errno))
  {
    /* out of range: > ULONG_MAX */
    if (DEBUG_URL_PARSE) GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if (ctag > UINT32_MAX)
  {
    /* out of range: > UINT32_MAX */
    if (DEBUG_URL_PARSE) GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  (*tag) = (uint32_t) ctag;
  if (NULL == tag_end)
  {
      /* no char after tag */
      if (DEBUG_URL_PARSE) GNUNET_break (0);
      return GNUNET_SYSERR;
  }
  if (url[strlen(url)] != tag_end[0])
  {
      /* there are more not converted chars after tag */
      if (DEBUG_URL_PARSE) GNUNET_break (0);
      return GNUNET_SYSERR;
  }
  if (DEBUG_URL_PARSE)
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
       "Found tag `%u' in url\n", (*tag));

  /* convert peer id */
  target_start = strrchr (url, '/');
  if (NULL == target_start)
  {
      /* no leading '/' */
      target_start = (char *) url;
  }
  target_start++;
  hash_length = separator - target_start;
  if (hash_length != plugin->peer_id_length)
  {
      /* no char after tag */
      if (DEBUG_URL_PARSE) GNUNET_break (0);
      return GNUNET_SYSERR;
  }
  memcpy (hash, target_start, hash_length);
  hash[hash_length] = '\0';

  if (GNUNET_OK != GNUNET_CRYPTO_hash_from_string ((const char *) hash, &(target->hashPubKey)))
  {
      /* hash conversion failed */
      if (DEBUG_URL_PARSE) GNUNET_break (0);
      return GNUNET_SYSERR;
  }

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
     "Found target `%s' in url\n", GNUNET_h2s_full(&target->hashPubKey));
  return GNUNET_OK;
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
static struct ServerConnection *
server_lookup_connection (struct HTTP_Server_Plugin *plugin,
                       struct MHD_Connection *mhd_connection, const char *url,
                       const char *method)
{
  struct Session *s = NULL;
  struct ServerConnection *sc = NULL;
  const union MHD_ConnectionInfo *conn_info;
  struct GNUNET_ATS_Information ats;

  char *addr;
  size_t addr_len;

  struct GNUNET_PeerIdentity target;
  uint32_t tag = 0;
  int direction = GNUNET_SYSERR;
  int to;

  conn_info = MHD_get_connection_info (mhd_connection,
                                       MHD_CONNECTION_INFO_CLIENT_ADDRESS);
  if ((conn_info->client_addr->sa_family != AF_INET) &&
      (conn_info->client_addr->sa_family != AF_INET6))
    return NULL;
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "New %s connection from %s\n", method, url);

  if (GNUNET_SYSERR == server_parse_url (plugin, url, &target, &tag))
  {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                       "Invalid url %s\n", url);
      return NULL;
  }
  if (0 == strcmp (MHD_HTTP_METHOD_PUT, method))
    direction = _RECEIVE;
  else if (0 == strcmp (MHD_HTTP_METHOD_GET, method))
    direction = _SEND;
  else
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Invalid method %s connection from %s\n", method, url);
    return NULL;
  }

  plugin->cur_connections++;
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "New %s connection from %s with tag %u (%u of %u)\n",
                   method,
                   GNUNET_i2s (&target), tag,
                   plugin->cur_connections, plugin->max_connections);
  /* find duplicate session */
  s = plugin->head;
  while (s != NULL)
  {
    if ((0 == memcmp (&s->target, &target, sizeof (struct GNUNET_PeerIdentity))) &&
        (s->tag == tag))
      break;
    s = s->next;
  }
  if (s != NULL)
  {
    if ((_RECEIVE == direction) && (NULL != s->server_recv))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                       "Duplicate PUT connection from `%s' tag %u, dismissing new connection\n",
                       GNUNET_i2s (&target),
                       tag);
      return NULL;

    }
    if ((_SEND == direction) && (NULL != s->server_send))
    {
        GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                         "Duplicate GET connection from `%s' tag %u, dismissing new connection\n",
                         GNUNET_i2s (&target),
                         tag);
        return NULL;
    }
  }
  else
  {
    /* create new session */
    switch (conn_info->client_addr->sa_family)
    {
    case (AF_INET):
      addr = http_common_address_from_socket (plugin->protocol, conn_info->client_addr, sizeof (struct sockaddr_in));
      addr_len = http_common_address_get_size (addr);
      ats = plugin->env->get_address_type (plugin->env->cls, conn_info->client_addr, sizeof (struct sockaddr_in));
      break;
    case (AF_INET6):
      addr = http_common_address_from_socket (plugin->protocol, conn_info->client_addr, sizeof (struct sockaddr_in6));
      addr_len = http_common_address_get_size (addr);
      ats = plugin->env->get_address_type (plugin->env->cls, conn_info->client_addr, sizeof (struct sockaddr_in6));
      break;
    default:
      GNUNET_break (0);
      return NULL;
    }
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Creating new session for peer `%s' connecting from `%s'\n",
                     GNUNET_i2s (&target),
                     http_common_plugin_address_to_string (NULL, addr, addr_len));

    s = GNUNET_malloc (sizeof (struct Session));
    memcpy (&s->target, &target, sizeof (struct GNUNET_PeerIdentity));
    s->plugin = plugin;
    s->addr = addr;
    s->addrlen = addr_len;
    s->ats_address_network_type = ats.value;
    s->next_receive = GNUNET_TIME_UNIT_ZERO_ABS;
    s->tag = tag;
    s->server_recv = NULL;
    s->server_send = NULL;
    s->session_passed = GNUNET_NO;
    s->session_ended = GNUNET_NO;
    s->connect_in_progress = GNUNET_YES;
    server_start_session_timeout(s);
    GNUNET_CONTAINER_DLL_insert (plugin->head, plugin->tail, s);
  }
  sc = GNUNET_malloc (sizeof (struct ServerConnection));
  if (conn_info->client_addr->sa_family == AF_INET)
    sc->mhd_daemon = plugin->server_v4;
  if (conn_info->client_addr->sa_family == AF_INET6)
    sc->mhd_daemon = plugin->server_v6;
  sc->mhd_conn = mhd_connection;
  sc->direction = direction;
  sc->connected = GNUNET_NO;
  sc->session = s;
  if (direction == _SEND)
    s->server_send = sc;
  if (direction == _RECEIVE)
    s->server_recv = sc;

  if ((NULL != s->server_send) && (NULL != s->server_recv))
    s->connect_in_progress = GNUNET_NO; /* PUT and GET are connected */

#if MHD_VERSION >= 0x00090E00
  if ((NULL == s->server_recv) || (NULL == s->server_send))
  {
    to = (HTTP_SERVER_NOT_VALIDATED_TIMEOUT.rel_value / 1000);
    MHD_set_connection_option (mhd_connection, MHD_CONNECTION_OPTION_TIMEOUT, to);
    server_reschedule (plugin, sc->mhd_daemon, GNUNET_NO);
  }
  else
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Session %p for peer `%s' fully connected\n",
                     s, GNUNET_i2s (&target));
    to = (SERVER_SESSION_TIMEOUT.rel_value / 1000);
    server_mhd_connection_timeout (plugin, s, to);
  }

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Setting timeout for %p to %u sec.\n", sc, to);
#endif
  return sc;
}


/**
 * Lookup a session for a server connection
 *
 * @param plugin the plugin
 * @param sc the server connection
 * @return the session found or NULL
 */
static struct Session *
server_lookup_session (struct HTTP_Server_Plugin *plugin,
                       struct ServerConnection * sc)
{
  struct Session *s;

  for (s = plugin->head; NULL != s; s = s->next)
    if ((s->server_recv == sc) || (s->server_send == sc))
      return s;
  return NULL;
}

int
server_exist_session (struct HTTP_Server_Plugin *plugin, struct Session *s)
{
  struct Session * head;

  GNUNET_assert (NULL != plugin);
  GNUNET_assert (NULL != s);

  for (head = plugin->head; head != NULL; head = head->next)
  {
    if (head == s)
      return GNUNET_YES;
  }
  return GNUNET_NO;
}


/**
 * Callback called by MHD when it needs data to send
 *
 * @param cls current session
 * @param pos position in buffer
 * @param buf the buffer to write data to
 * @param max max number of bytes available in buffer
 * @return bytes written to buffer
 */
static ssize_t
server_send_callback (void *cls, uint64_t pos, char *buf, size_t max)
{
  struct Session *s = cls;
  ssize_t bytes_read = 0;
  struct HTTP_Message *msg;
  char *stat_txt;

  GNUNET_assert (NULL != p);
  if (GNUNET_NO == server_exist_session (p, s))
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
      GNUNET_CONTAINER_DLL_remove (s->msg_head, s->msg_tail, msg);
      if (NULL != msg->transmit_cont)
        msg->transmit_cont (msg->transmit_cont_cls, &s->target, GNUNET_OK,
                            msg->size, msg->size + msg->overhead);
      GNUNET_free (msg);
    }
  }
  if (0 < bytes_read)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, s->plugin->name,
                   "Sent %u bytes to peer `%s' with session %p \n", bytes_read, GNUNET_i2s (&s->target), s);
    GNUNET_asprintf (&stat_txt, "# bytes currently in %s_server buffers", p->protocol);
    GNUNET_STATISTICS_update (p->env->stats,
                              stat_txt, -bytes_read, GNUNET_NO);
    GNUNET_free (stat_txt);
    GNUNET_asprintf (&stat_txt, "# bytes transmitted via %s_server", p->protocol);
    GNUNET_STATISTICS_update (p->env->stats,
                              stat_txt, bytes_read, GNUNET_NO);
    GNUNET_free (stat_txt);
  }
  return bytes_read;
}


/**
 * Callback called by MessageStreamTokenizer when a message has arrived
 *
 * @param cls current session as closure
 * @param client client
 * @param message the message to be forwarded to transport service
 * @return GNUNET_OK
 */
static int
server_receive_mst_cb (void *cls, void *client,
                       const struct GNUNET_MessageHeader *message)
{
  struct Session *s = cls;
  struct HTTP_Server_Plugin *plugin = s->plugin;
  struct GNUNET_ATS_Information atsi;
  struct GNUNET_TIME_Relative delay;
  char *stat_txt;

  GNUNET_assert (NULL != p);
  if (GNUNET_NO == server_exist_session(p, s))
    return GNUNET_OK;


  atsi.type = htonl (GNUNET_ATS_NETWORK_TYPE);
  atsi.value = s->ats_address_network_type;
  GNUNET_break (s->ats_address_network_type != ntohl (GNUNET_ATS_NET_UNSPECIFIED));


  delay = plugin->env->receive (plugin->env->cls,
                                &s->target,
                                message,
                                s, s->addr, s->addrlen);

  plugin->env->update_address_metrics (plugin->env->cls,
				       &s->target,
				       s->addr,
				       s->addrlen,
				       s,
				       &atsi, 1);

  GNUNET_asprintf (&stat_txt, "# bytes received via %s_server", plugin->protocol);
  GNUNET_STATISTICS_update (plugin->env->stats,
                            stat_txt, ntohs (message->size), GNUNET_NO);
  GNUNET_free (stat_txt);

  s->session_passed = GNUNET_YES;
  s->next_receive = GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get (), delay);
  if (delay.rel_value > 0)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Peer `%s' address `%s' next read delayed for %llu ms\n",
                     GNUNET_i2s (&s->target),
                     http_common_plugin_address_to_string (NULL, s->addr, s->addrlen),
                     delay);
  }
  server_reschedule_session_timeout (s);
  return GNUNET_OK;
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
 * @param upload_data_size sizeof upload data
 * @param httpSessionCache the session cache to remember the connection
 * @return MHD_YES if connection is accepted, MHD_NO on reject
 */
static int
server_access_cb (void *cls, struct MHD_Connection *mhd_connection,
                  const char *url, const char *method, const char *version,
                  const char *upload_data, size_t * upload_data_size,
                  void **httpSessionCache)
{
  struct HTTP_Server_Plugin *plugin = cls;
  int res = MHD_YES;

  struct ServerConnection *sc = *httpSessionCache;
  struct Session *s;
  struct MHD_Response *response;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   _("Access from connection %p (%u of %u) for `%s' `%s' url `%s' with upload data size %u\n"),
                   sc,
                   plugin->cur_connections, plugin->max_connections,
                   method, version, url, (*upload_data_size));

  GNUNET_assert (cls != NULL);
  if (sc == NULL)
  {
    /* new connection */
    sc = server_lookup_connection (plugin, mhd_connection, url, method);
    if (sc != NULL)
    {
      (*httpSessionCache) = sc;
    }
    else
    {
      response = MHD_create_response_from_data (strlen (HTTP_ERROR_RESPONSE), HTTP_ERROR_RESPONSE, MHD_NO, MHD_NO);
      MHD_add_response_header (response,
			       MHD_HTTP_HEADER_CONTENT_TYPE,
			       "text/html");
      res = MHD_queue_response (mhd_connection, MHD_HTTP_NOT_FOUND, response);
      MHD_destroy_response (response);
      return res;
    }
  }
  else
  {
    /* 'old' connection */
    if (NULL == server_lookup_session (plugin, sc))
    {
      /* Session was already disconnected */
      return MHD_NO;
    }
  }

  /* existing connection */
  sc = (*httpSessionCache);
  s = sc->session;
  GNUNET_assert (NULL != s);
  /* connection is to be disconnected */
  if (sc->disconnect == GNUNET_YES)
  {
    /* Sent HTTP/1.1: 200 OK as response */
    response = MHD_create_response_from_data (strlen ("Thank you!"),
                                       "Thank you!",
                                       MHD_NO, MHD_NO);
    res = MHD_queue_response (mhd_connection, MHD_HTTP_OK, response);
    MHD_destroy_response (response);
    return MHD_YES;
  }
  GNUNET_assert (s != NULL);

  if (sc->direction == _SEND)
  {
    response = MHD_create_response_from_callback (MHD_SIZE_UNKNOWN,
                                                  32 * 1024,
                                                  &server_send_callback, s,
                                                  NULL);
    MHD_queue_response (mhd_connection, MHD_HTTP_OK, response);
    MHD_destroy_response (response);
    return MHD_YES;
  }
  if (sc->direction == _RECEIVE)
  {
    if ((*upload_data_size == 0) && (sc->connected == GNUNET_NO))
    {
      /* (*upload_data_size == 0) first callback when header are passed */
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                       "Session %p / Connection %p: Peer `%s' PUT on address `%s' connected\n",
                       s, sc,
                       GNUNET_i2s (&s->target),
                       http_common_plugin_address_to_string (NULL,
                                                             s->addr,
                                                             s->addrlen));
      sc->connected = GNUNET_YES;
      return MHD_YES;
    }
    else if ((*upload_data_size == 0) && (sc->connected == GNUNET_YES))
    {
      /* (*upload_data_size == 0) when upload is complete */
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                       "Session %p / Connection %p: Peer `%s' PUT on address `%s' finished upload\n",
                       s, sc,
                       GNUNET_i2s (&s->target),
                       http_common_plugin_address_to_string (NULL,
                                                             s->addr,
                                                             s->addrlen));
      sc->connected = GNUNET_NO;
      /* Sent HTTP/1.1: 200 OK as PUT Response\ */
      response = MHD_create_response_from_data (strlen ("Thank you!"),
                                         "Thank you!",
                                         MHD_NO, MHD_NO);
      res = MHD_queue_response (mhd_connection, MHD_HTTP_OK, response);
      MHD_destroy_response (response);
      return MHD_YES;
    }
    else if ((*upload_data_size > 0) && (sc->connected == GNUNET_YES))
    {
      /* (*upload_data_size > 0) for every segment received */
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                       "Session %p / Connection %p: Peer `%s' PUT on address `%s' received %u bytes\n",
                       s, sc,
                       GNUNET_i2s (&s->target),
                       http_common_plugin_address_to_string (NULL,
                                                             s->addr,
                                                             s->addrlen),
                       *upload_data_size);
      struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();

      if ((s->next_receive.abs_value <= now.abs_value))
      {
        GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                         "PUT with %u bytes forwarded to MST\n",
                         *upload_data_size);
        if (s->msg_tk == NULL)
        {
          s->msg_tk = GNUNET_SERVER_mst_create (&server_receive_mst_cb, s);
        }
            GNUNET_SERVER_mst_receive (s->msg_tk, s, upload_data,
                                       *upload_data_size, GNUNET_NO, GNUNET_NO);
#if MHD_VERSION >= 0x00090E00
        server_mhd_connection_timeout (plugin, s, GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value / 1000);
#endif
        (*upload_data_size) = 0;
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Session %p / Connection %p: no inbound bandwidth available! Next read was delayed by %llu ms\n",
                    s, sc, now.abs_value - s->next_receive.abs_value);
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
 * @param cls closure
 * @param connection the disconnected MHD connection
 * @param httpSessionCache the pointer to distinguish
 */
static void
server_disconnect_cb (void *cls, struct MHD_Connection *connection,
                      void **httpSessionCache)
{
  struct ServerConnection *sc = *httpSessionCache;
  struct Session *s = NULL;
  struct Session *t = NULL;
  struct HTTP_Server_Plugin *plugin = NULL;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, p->name,
                   "Disconnect for connection %p \n", sc);

  if (sc == NULL)
    return;

  if (NULL == (s = server_lookup_session (p, sc)))
    return;

  GNUNET_assert (NULL != p);
  for (t = p->head; t != NULL; t = t->next)
  {
    if (t == s)
      break;
  }
  if (NULL == t)
    return;

  plugin = s->plugin;
  if (sc->direction == _SEND)
  {

    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Peer `%s' connection  %p, GET on address `%s' disconnected\n",
                     GNUNET_i2s (&s->target), s->server_send,
                     http_common_plugin_address_to_string (NULL, s->addr, s->addrlen));
    s->server_send = NULL;
    if (NULL != (s->server_recv))
    {
      s->server_recv->disconnect = GNUNET_YES;
      GNUNET_assert (NULL != s->server_recv->mhd_conn);
#if MHD_VERSION >= 0x00090E00
      MHD_set_connection_option (s->server_recv->mhd_conn, MHD_CONNECTION_OPTION_TIMEOUT,
                                 1);
#endif
      server_reschedule (plugin, s->server_recv->mhd_daemon, GNUNET_NO);
    }
  }
  if (sc->direction == _RECEIVE)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Peer `%s' connection %p PUT on address `%s' disconnected\n",
                     GNUNET_i2s (&s->target), s->server_recv,
                     http_common_plugin_address_to_string (NULL, s->addr, s->addrlen));
    s->server_recv = NULL;
    /* Do not terminate session when PUT disconnects
    if (NULL != (s->server_send))
    {
        s->server_send->disconnect = GNUNET_YES;
      GNUNET_assert (NULL != s->server_send->mhd_conn);
#if MHD_VERSION >= 0x00090E00
      MHD_set_connection_option (s->server_send->mhd_conn, MHD_CONNECTION_OPTION_TIMEOUT,
                                 1);
#endif
      server_reschedule (plugin, s->server_send->mhd_daemon, GNUNET_NO);
    }*/
    if (s->msg_tk != NULL)
    {
      GNUNET_SERVER_mst_destroy (s->msg_tk);
      s->msg_tk = NULL;
    }
  }

  GNUNET_free (sc);
  plugin->cur_connections--;

  if ((s->server_send == NULL) && (s->server_recv == NULL))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Peer `%s' on address `%s' disconnected\n",
                     GNUNET_i2s (&s->target),
                     http_common_plugin_address_to_string (NULL, s->addr, s->addrlen));

    if ((GNUNET_YES == s->session_passed) && (GNUNET_NO == s->session_ended))
    {
        /* Notify transport immediately that this session is invalid */
        s->session_ended = GNUNET_YES;
        plugin->env->session_end (plugin->env->cls, &s->target, s);
    }
    server_delete_session (s);
  }

}


/**
 * Check if incoming connection is accepted.

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

  if (plugin->cur_connections <= plugin->max_connections)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     _("Accepting connection (%u of %u) from `%s'\n"),
                     plugin->cur_connections, plugin->max_connections,
                     GNUNET_a2s (addr, addr_len));
    return MHD_YES;
  }
  else
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, plugin->name,
                     _("Server reached maximum number connections (%u), rejecting new connection\n"),
                     plugin->max_connections);
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


#define UNSIGNED_MHD_LONG_LONG unsigned MHD_LONG_LONG

/**
 * Function that queries MHD's select sets and
 * starts the task waiting for them.
 *
 * @param plugin plugin
 * @param daemon_handle the MHD daemon handle
 * @return gnunet task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier
server_schedule (struct HTTP_Server_Plugin *plugin,
                 struct MHD_Daemon *daemon_handle,
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
  UNSIGNED_MHD_LONG_LONG timeout;
  static unsigned long long last_timeout = 0;
  int haveto;

  struct GNUNET_TIME_Relative tv;

  if (GNUNET_YES == plugin->in_shutdown)
    return GNUNET_SCHEDULER_NO_TASK;

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

      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                       "SELECT Timeout changed from %llu to %llu\n",
                       last_timeout, timeout);
      last_timeout = timeout;
    }
    if (timeout <= GNUNET_TIME_UNIT_SECONDS.rel_value)
      tv.rel_value = (uint64_t) timeout;
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
/**
 * Load ssl certificate
 *
 * @param plugin the plugin
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
static int
server_load_certificate (struct HTTP_Server_Plugin *plugin)
{
  int res = GNUNET_OK;

  char *sh;
  char *key_file;
  char *cert_file;

  /* Get crypto init string from config
   * If not present just use default values */

  if (GNUNET_OK !=
                 GNUNET_CONFIGURATION_get_value_string (plugin->env->cfg,
                                                        "PATHS",
                                                        "SERVICEHOME",
                                                        &sh))
  {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                       "Failed to get servicehome!\n");
      return GNUNET_SYSERR;
  }


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
    GNUNET_break (0);
    GNUNET_asprintf (&key_file, "%s/%s", sh, "https_key.key");
  }


  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (plugin->env->cfg, plugin->name,
                                               "CERT_FILE", &cert_file))
  {
      GNUNET_break (0);
    GNUNET_asprintf (&cert_file, "%s/%s", sh, "https_cert.crt");
  }
  GNUNET_free (sh);
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


/**
 * Start the HTTP server
 *
 * @param plugin the plugin handle
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
static int
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
  timeout = HTTP_SERVER_NOT_VALIDATED_TIMEOUT.rel_value / 1000;
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "MHD can set timeout per connection! Default time out %u sec.\n",
                   timeout);
#else
  timeout = SERVER_SESSION_TIMEOUT.rel_value / 1000;
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
  if (plugin->server_v4 != NULL)
  {
    MHD_stop_daemon (plugin->server_v4);
    plugin->server_v4 = NULL;
  }
  if ( plugin->server_v6 != NULL)
  {
    MHD_stop_daemon (plugin->server_v6);
    plugin->server_v6 = NULL;
  }


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
  p = NULL;

#if BUILD_HTTPS
  GNUNET_free_non_null (plugin->crypto_init);
  GNUNET_free_non_null (plugin->cert);
  GNUNET_free_non_null (plugin->key);
#endif

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "%s server component stopped\n", plugin->name);
}


/**
 * Add an address to the server's set of addresses and notify transport
 *
 * @param cls the plugin handle
 * @param add_remove GNUNET_YES on add, GNUNET_NO on remove
 * @param addr the address
 * @param addrlen address length
 */
static void
server_add_address (void *cls, int add_remove, const struct sockaddr *addr,
                 socklen_t addrlen)
{
  struct HTTP_Server_Plugin *plugin = cls;
  struct HttpAddressWrapper *w = NULL;

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
#if BUILD_HTTPS
  plugin->env->notify_address (plugin->env->cls, add_remove, w->addr, w->addrlen, "https_client");
#else
  plugin->env->notify_address (plugin->env->cls, add_remove, w->addr, w->addrlen, "http_client");
#endif
}


/**
 * Remove an address from the server's set of addresses and notify transport
 *
 * @param cls the plugin handle
 * @param add_remove GNUNET_YES on add, GNUNET_NO on remove
 * @param addr the address
 * @param addrlen address length
 */
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
#if BUILD_HTTPS
  plugin->env->notify_address (plugin->env->cls, add_remove, w->addr, w->addrlen, "https_client");
#else
  plugin->env->notify_address (plugin->env->cls, add_remove, w->addr, w->addrlen, "http_client");
#endif
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
        GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
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
        GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
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
 * @param serviceName the servicename
 * @param cfg configuration handle
 * @param addrs addresses
 * @param addr_lens address length
 * @return number of addresses
 */
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


/**
 * Stop NAT for addresses
 *
 * @param plugin the plugin handle
 */
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
 *
 * @param plugin the plugin handle
 * @return GNUNET_YES on success, else GNUNET_NO
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
 * Notify server about our external hostname
 *
 * @param cls plugin
 * @param tc task context (unused)
 */
static void
server_notify_external_hostname (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct HTTP_Server_Plugin *plugin = cls;

  plugin->notify_ext_task = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;


#if BUILD_HTTPS
  GNUNET_asprintf(&plugin->ext_addr, "%s%s://%s", plugin->protocol,
  		(GNUNET_YES == plugin->verify_external_hostname) ? "+" : "",
  		plugin->external_hostname);
#else
  GNUNET_asprintf(&plugin->ext_addr, "%s://%s", plugin->protocol,
  		plugin->external_hostname);
#endif

  plugin->ext_addr_len = strlen (plugin->ext_addr) + 1;
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Notifying transport about external hostname address `%s'\n", plugin->ext_addr);

#if BUILD_HTTPS
  if (GNUNET_YES == plugin->verify_external_hostname)
    GNUNET_log_from (GNUNET_ERROR_TYPE_INFO, plugin->name,
                     "Enabling SSL verification for external hostname address `%s'\n", plugin->ext_addr);
  plugin->env->notify_address (plugin->env->cls, GNUNET_YES,
                               plugin->ext_addr, plugin->ext_addr_len,
                               "https_client");
#else
  plugin->env->notify_address (plugin->env->cls, GNUNET_YES,
                               plugin->ext_addr, plugin->ext_addr_len,
                               "http_client");
#endif
}


/**
 * Configure the plugin
 *
 * @param plugin plugin handle
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
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

  plugin->verify_external_hostname = GNUNET_NO;
#if BUILD_HTTPS
  plugin->verify_external_hostname = GNUNET_CONFIGURATION_get_value_yesno (plugin->env->cfg, plugin->name,
																				"VERIFY_EXTERNAL_HOSTNAME");
  if (GNUNET_SYSERR == plugin->verify_external_hostname)
  	plugin->verify_external_hostname = GNUNET_NO;
#endif

  if (GNUNET_YES == GNUNET_CONFIGURATION_get_value_string (plugin->env->cfg, plugin->name,
                                              "EXTERNAL_HOSTNAME", &plugin->external_hostname))
  {
      char * tmp = NULL;
      if (NULL != strstr(plugin->external_hostname, "://"))
      {
          tmp = strdup(&strstr(plugin->external_hostname, "://")[3]);
          GNUNET_free (plugin->external_hostname);
          plugin->external_hostname = tmp;

      }
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                       _("Using external hostname `%s'\n"), plugin->external_hostname);
      plugin->notify_ext_task = GNUNET_SCHEDULER_add_now (&server_notify_external_hostname, plugin);

      /* Use only configured external hostname */
      if (GNUNET_CONFIGURATION_have_value
          (plugin->env->cfg, plugin->name, "EXTERNAL_HOSTNAME_ONLY"))
      {
        plugin->external_only =
            GNUNET_CONFIGURATION_get_value_yesno (plugin->env->cfg, plugin->name,
                                                  "EXTERNAL_HOSTNAME_ONLY");
      }
      else
        plugin->external_only = GNUNET_NO;

      if (GNUNET_YES == plugin->external_only)
        GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                         _("Notifying transport only about hostname `%s'\n"), plugin->external_hostname);
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


  plugin->peer_id_length = strlen (GNUNET_h2s_full (&plugin->env->my_identity->hashPubKey));

  return GNUNET_OK;
}


/**
 * Session was idle, so disconnect it
 *
 * @param cls the session
 * @param tc task context
 */
static void
server_session_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_assert (NULL != cls);
  struct Session *s = cls;

  s->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (TIMEOUT_LOG,
              "Session %p was idle for %llu ms, disconnecting\n",
              s, (unsigned long long) SERVER_SESSION_TIMEOUT.rel_value);

  /* call session destroy function */
 GNUNET_assert (GNUNET_OK == server_disconnect (s));
}


/**
* Start session timeout for session s
*
* @param s the session
*/
static void
server_start_session_timeout (struct Session *s)
{
 GNUNET_assert (NULL != s);
 GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == s->timeout_task);
 s->timeout_task =  GNUNET_SCHEDULER_add_delayed (SERVER_SESSION_TIMEOUT,
                                                  &server_session_timeout,
                                                  s);
 GNUNET_log (TIMEOUT_LOG,
             "Timeout for session %p set to %llu ms\n",
             s,  (unsigned long long) SERVER_SESSION_TIMEOUT.rel_value);
}


/**
* Increment session timeout due to activity session s
*
* @param s the session
*/
static void
server_reschedule_session_timeout (struct Session *s)
{
 GNUNET_assert (NULL != s);
 GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != s->timeout_task);

 GNUNET_SCHEDULER_cancel (s->timeout_task);
 s->timeout_task =  GNUNET_SCHEDULER_add_delayed (SERVER_SESSION_TIMEOUT,
                                                  &server_session_timeout,
                                                  s);
 GNUNET_log (TIMEOUT_LOG,
             "Timeout rescheduled for session %p set to %llu ms\n",
             s, (unsigned long long) SERVER_SESSION_TIMEOUT.rel_value);
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
  struct Session *pos;
  struct Session *next;

  if (NULL == api->cls)
  {
    /* Free for stub mode */
    GNUNET_free (api);
    return NULL;
  }
  plugin->in_shutdown = GNUNET_YES;
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   _("Shutting down plugin `%s'\n"),
                   plugin->name);

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
#if BUILD_HTTPS
      plugin->env->notify_address (plugin->env->cls,
                                   GNUNET_NO,
                                   plugin->ext_addr,
                                   plugin->ext_addr_len,
                                   "https_client");
#else
  plugin->env->notify_address (plugin->env->cls,
                               GNUNET_NO,
                               plugin->ext_addr,
                               plugin->ext_addr_len,
                               "http_client");
#endif

  }

  /* Stop to report addresses to transport service */
  server_stop_report_addresses (plugin);
  server_stop (plugin);
  next = plugin->head;
  while (NULL != (pos = next))
  {
      next = pos->next;
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                       "Removing left over session %p\n", pos);

      if ((GNUNET_YES == pos->session_passed) && (GNUNET_NO == pos->session_ended))
      {
        /* Notify transport immediately that this session is invalid */
        pos->session_ended = GNUNET_YES;
        plugin->env->session_end (plugin->env->cls, &pos->target, pos);
      }

      server_delete_session (pos);
  }

  /* Clean up */
  GNUNET_free_non_null (plugin->external_hostname);
  GNUNET_free_non_null (plugin->ext_addr);
  GNUNET_free_non_null (plugin->server_addr_v4);
  GNUNET_free_non_null (plugin->server_addr_v6);

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   _("Shutdown for plugin `%s' complete\n"),
                   plugin->name);

  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
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

  plugin = GNUNET_malloc (sizeof (struct HTTP_Server_Plugin));
  plugin->env = env;
  p = plugin;

  if (NULL == env->receive)
  {
    /* run in 'stub' mode (i.e. as part of gnunet-peerinfo), don't fully
       initialze the plugin or the API */
    api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
    api->cls = NULL;
    api->address_to_string = &http_common_plugin_address_to_string;
    api->string_to_address = &http_common_plugin_string_to_address;
    api->address_pretty_printer = &http_common_plugin_address_pretty_printer;
    return api;
  }

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
