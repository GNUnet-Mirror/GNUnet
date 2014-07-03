/*
     This file is part of GNUnet
     (C) 2002-2014 Christian Grothoff (and other contributing authors)

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
 * @file transport/plugin_transport_http_client.c
 * @brief HTTP/S client transport plugin
 * @author Matthias Wachs
 * @author Christian Grothoff
 */

#if BUILD_HTTPS
#define PLUGIN_NAME "https_client"
#define HTTP_STAT_STR_CONNECTIONS "# HTTPS client connections"
#define LIBGNUNET_PLUGIN_TRANSPORT_INIT libgnunet_plugin_transport_https_client_init
#define LIBGNUNET_PLUGIN_TRANSPORT_DONE libgnunet_plugin_transport_https_client_done
#else
#define PLUGIN_NAME "http_client"
#define HTTP_STAT_STR_CONNECTIONS "# HTTP client connections"
#define LIBGNUNET_PLUGIN_TRANSPORT_INIT libgnunet_plugin_transport_http_client_init
#define LIBGNUNET_PLUGIN_TRANSPORT_DONE libgnunet_plugin_transport_http_client_done
#endif

#define VERBOSE_CURL GNUNET_NO

#define PUT_DISCONNECT_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

#define ENABLE_PUT GNUNET_YES
#define ENABLE_GET GNUNET_YES

#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_plugin.h"
#include "plugin_transport_http_common.h"
#include <curl/curl.h>


#define LOG(kind,...) GNUNET_log_from(kind, PLUGIN_NAME, __VA_ARGS__)

/**
 * Encapsulation of all of the state of the plugin.
 */
struct HTTP_Client_Plugin;

/**
 * State of a HTTP PUT request
 */
enum HTTP_PUT_REQUEST_STATE
{
  /**
   *  Just created, not yet connected
   */
  H_NOT_CONNECTED,

  /**
   *  Connected
   */
  H_CONNECTED,

  /**
   *  Paused, nothing to send
   */
  H_PAUSED,

  /**
   * Temporary disconnect in progress due to inactivity
   */
  H_TMP_DISCONNECTING,

  /**
   * Send request while temporary disconnect, reconnect
   */
  H_TMP_RECONNECT_REQUIRED,

  /**
   * Temporarily disconnected
   */
  H_TMP_DISCONNECTED,

  /**
   * Disconnected
   */
  H_DISCONNECTED
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
   * Continuation function to call once the transmission buffer
   * has again space available.  NULL if there is no
   * continuation to call.
   */
  GNUNET_TRANSPORT_TransmitContinuation transmit_cont;

  /**
   * Closure for @e transmit_cont.
   */
  void *transmit_cont_cls;

  /**
   * amount of data already sent
   */
  size_t pos;

  /**
   * buffer length
   */
  size_t size;

};


/**
 * Session handle for HTTP(S) connections.
 */
struct Session;


/**
 * A request handle
 *
 */
struct RequestHandle
{
  /**
   * Current state of this request
   */
  enum HTTP_PUT_REQUEST_STATE state;

  /**
   * The curl easy handle
   */
  CURL *easyhandle;

  /**
   * The related session
   */
  struct Session *s;
};


/**
 * Session handle for connections.
 */
struct Session
{
  /**
   * The URL to connect to
   */
  char *url;

  /**
   * Address
   */
  struct GNUNET_HELLO_Address *address;

  /**
   * Pointer to the global plugin struct.
   */
  struct HTTP_Client_Plugin *plugin;

  /**
   * Handle for the HTTP PUT request.
   */
  struct RequestHandle put;

  /**
   * Handle for the HTTP GET request.
   */
  struct RequestHandle get;

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
   * Session timeout task
   */
  GNUNET_SCHEDULER_TaskIdentifier put_disconnect_task;

  /**
   * Session timeout task
   */
  GNUNET_SCHEDULER_TaskIdentifier timeout_task;

  /**
   * Task to wake up client receive handle when receiving is allowed again
   */
  GNUNET_SCHEDULER_TaskIdentifier recv_wakeup_task;

  /**
   * Absolute time when to receive data again.
   * Used for receive throttling.
   */
  struct GNUNET_TIME_Absolute next_receive;

  /**
   * When does this session time out.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Number of bytes waiting for transmission to this peer.
   */
  unsigned long long bytes_in_queue;

  /**
   * Outbound overhead due to HTTP connection
   * Add to next message of this session when calling callback
   */
  size_t overhead;

  /**
   * Number of messages waiting for transmission to this peer.
   */
  unsigned int msgs_in_queue;

  /**
   * ATS network type in NBO
   */
  uint32_t ats_address_network_type;
};


/**
 * Encapsulation of all of the state of the plugin.
 */
struct HTTP_Client_Plugin
{
  /**
   * Our environment.
   */
  struct GNUNET_TRANSPORT_PluginEnvironment *env;

  /**
   * Open sessions.
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
   * Proxy configuration: hostname or ip of the proxy server
   */
  char *proxy_hostname;

  /**
   * Username for the proxy server
   */
  char *proxy_username;

  /**
   * Password for the proxy server
   */
  char *proxy_password;

  /**
   * cURL Multihandle
   */
  CURLM *curl_multi_handle;

  /**
   * curl perform task
   */
  GNUNET_SCHEDULER_TaskIdentifier client_perform_task;

  /**
   * Type of proxy server:
   *
   * Valid values as supported by curl:
   * CURLPROXY_HTTP, CURLPROXY_HTTP_1_0 CURLPROXY_SOCKS4, CURLPROXY_SOCKS5,
   * CURLPROXY_SOCKS4A, CURLPROXY_SOCKS5_HOSTNAME
   */
  curl_proxytype proxytype;

  /**
   * Use proxy tunneling:
   * Tunnel all operations through a given HTTP instead of have the proxy
   * evaluate the HTTP request
   *
   * Default: #GNUNET_NO, #GNUNET_YES experimental
   */
  int proxy_use_httpproxytunnel;

  /**
   * My options to be included in the address
   */
  uint32_t options;

  /**
   * Maximum number of sockets the plugin can use
   * Each http connections are two requests
   */
  unsigned int max_requests;

  /**
   * Current number of sockets the plugin can use
   * Each http connections are two requests
   */
  unsigned int cur_requests;

  /**
   * Last used unique HTTP connection tag
   */
  uint32_t last_tag;

  /**
   * use IPv6
   */
  uint16_t use_ipv6;

  /**
   * use IPv4
   */
  uint16_t use_ipv4;

  /**
   * Should we emulate an XHR client for testing?
   */
  int emulate_xhr;
};

/**
 * Disconnect a session
 *
 * @param cls the `struct HTTP_Client_Plugin *`
 * @param s session
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
http_client_plugin_session_disconnect (void *cls, struct Session *s);

/**
 * If a session monitor is attached, notify it about the new
 * session state.
 *
 * @param plugin our plugin
 * @param session session that changed state
 * @param state new state of the session
 */
static void
notify_session_monitor (struct HTTP_Client_Plugin *plugin,
                        struct Session *session,
                        enum GNUNET_TRANSPORT_SessionState state)
{
  struct GNUNET_TRANSPORT_SessionInfo info;

  if (NULL == plugin->sic)
    return;
  memset (&info, 0, sizeof (info));
  info.state = state;
  info.is_inbound = GNUNET_NO;
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
 * Delete session @a s.
 *
 * @param s the session to delete
 */
static void
client_delete_session (struct Session *s)
{
  struct HTTP_Client_Plugin *plugin = s->plugin;
  struct HTTP_Message *pos;
  struct HTTP_Message *next;
  CURLMcode mret;

  if (GNUNET_SCHEDULER_NO_TASK != s->timeout_task)
  {
    GNUNET_SCHEDULER_cancel (s->timeout_task);
    s->timeout_task = GNUNET_SCHEDULER_NO_TASK;
    s->timeout = GNUNET_TIME_UNIT_ZERO_ABS;
  }
  if (GNUNET_SCHEDULER_NO_TASK != s->put_disconnect_task)
  {
    GNUNET_SCHEDULER_cancel (s->put_disconnect_task);
    s->put_disconnect_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (GNUNET_SCHEDULER_NO_TASK != s->recv_wakeup_task)
  {
    GNUNET_SCHEDULER_cancel (s->recv_wakeup_task);
    s->recv_wakeup_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONTAINER_multipeermap_remove (plugin->sessions,
                                                       &s->address->peer,
                                                       s));
  if (NULL != s->put.easyhandle)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Session %p/request %p: disconnecting PUT request to peer `%s'\n",
         s,
         s->put.easyhandle,
         GNUNET_i2s (&s->address->peer));

    /* remove curl handle from multi handle */
    mret = curl_multi_remove_handle (plugin->curl_multi_handle,
                                     s->put.easyhandle);
    GNUNET_break (CURLM_OK == mret);
    curl_easy_cleanup (s->put.easyhandle);
    s->put.easyhandle = NULL;
  }
  if (NULL != s->get.easyhandle)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Session %p/request %p: disconnecting GET request to peer `%s'\n",
         s, s->get.easyhandle,
         GNUNET_i2s (&s->address->peer));
    /* remove curl handle from multi handle */
    mret = curl_multi_remove_handle (plugin->curl_multi_handle,
                                     s->get.easyhandle);
    GNUNET_break (CURLM_OK == mret);
    curl_easy_cleanup (s->get.easyhandle);
    GNUNET_assert (plugin->cur_requests > 0);
    plugin->cur_requests--;
    s->get.easyhandle = NULL;
  }
  GNUNET_STATISTICS_set (plugin->env->stats,
                         HTTP_STAT_STR_CONNECTIONS,
                         plugin->cur_requests,
                         GNUNET_NO);
  next = s->msg_head;
  while (NULL != (pos = next))
  {
    next = pos->next;
    GNUNET_CONTAINER_DLL_remove (s->msg_head,
                                 s->msg_tail,
                                 pos);
    GNUNET_assert (0 < s->msgs_in_queue);
    s->msgs_in_queue--;
    GNUNET_assert (pos->size <= s->bytes_in_queue);
    s->bytes_in_queue -= pos->size;
    if (NULL != pos->transmit_cont)
      pos->transmit_cont (pos->transmit_cont_cls,
                          &s->address->peer,
                          GNUNET_SYSERR,
                          pos->size,
                          pos->pos + s->overhead);
    s->overhead = 0;
    GNUNET_free (pos);
  }
  GNUNET_assert (0 == s->msgs_in_queue);
  GNUNET_assert (0 == s->bytes_in_queue);
  notify_session_monitor (plugin,
                          s,
                          GNUNET_TRANSPORT_SS_DOWN);
  if (NULL != s->msg_tk)
  {
    GNUNET_SERVER_mst_destroy (s->msg_tk);
    s->msg_tk = NULL;
  }
  GNUNET_HELLO_address_free (s->address);
  GNUNET_free (s->url);
  GNUNET_free (s);
}


/**
 * Increment session timeout due to activity for session @a s.
 *
 * @param s the session
 */
static void
client_reschedule_session_timeout (struct Session *s)
{
  GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != s->timeout_task);
  s->timeout = GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT);
}


/**
 * Task performing curl operations
 *
 * @param cls plugin as closure
 * @param tc gnunet scheduler task context
 */
static void
client_run (void *cls,
            const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Function setting up file descriptors and scheduling task to run
 *
 * @param plugin the plugin as closure
 * @param now schedule task in 1ms, regardless of what curl may say
 * @return #GNUNET_SYSERR for hard failure, #GNUNET_OK for ok
 */
static int
client_schedule (struct HTTP_Client_Plugin *plugin,
                 int now)
{
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  struct GNUNET_NETWORK_FDSet *grs;
  struct GNUNET_NETWORK_FDSet *gws;
  long to;
  CURLMcode mret;
  struct GNUNET_TIME_Relative timeout;

  /* Cancel previous scheduled task */
  if (plugin->client_perform_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (plugin->client_perform_task);
    plugin->client_perform_task = GNUNET_SCHEDULER_NO_TASK;
  }
  max = -1;
  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  mret = curl_multi_fdset (plugin->curl_multi_handle, &rs, &ws, &es, &max);
  if (mret != CURLM_OK)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR, _("%s failed at %s:%d: `%s'\n"),
                "curl_multi_fdset", __FILE__, __LINE__,
                curl_multi_strerror (mret));
    return GNUNET_SYSERR;
  }
  mret = curl_multi_timeout (plugin->curl_multi_handle, &to);
  if (to == -1)
    timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1);
  else
    timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, to);
  if (now == GNUNET_YES)
    timeout = GNUNET_TIME_UNIT_MILLISECONDS;

  if (mret != CURLM_OK)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
                _("%s failed at %s:%d: `%s'\n"),
                "curl_multi_timeout", __FILE__, __LINE__,
                curl_multi_strerror (mret));
    return GNUNET_SYSERR;
  }

  grs = GNUNET_NETWORK_fdset_create ();
  gws = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_copy_native (grs, &rs, max + 1);
  GNUNET_NETWORK_fdset_copy_native (gws, &ws, max + 1);

  /* Schedule task to run when select is ready to read or write */
  plugin->client_perform_task =
      GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                   timeout, grs, gws,
                                   &client_run, plugin);
  GNUNET_NETWORK_fdset_destroy (gws);
  GNUNET_NETWORK_fdset_destroy (grs);
  return GNUNET_OK;
}

#if VERBOSE_CURL
/**
 * Loggging function
 *
 * @param curl the curl easy handle
 * @param type message type
 * @param data data to log, NOT a 0-terminated string
 * @param size data length
 * @param cls the closure
 * @return always 0
 */
static int
client_log (CURL *curl,
            curl_infotype type,
	    const char *data,
            size_t size,
            void *cls)
{
  struct RequestHandle *ch = cls;
  const char *ttype = "UNSPECIFIED";
  char text[size + 2];

  if (! ((type == CURLINFO_TEXT) || (type == CURLINFO_HEADER_IN) || (type == CURLINFO_HEADER_OUT)))
    return 0;
  switch (type)
  {
  case CURLINFO_TEXT:
    ttype = "TEXT";
    break;
  case CURLINFO_HEADER_IN:
    ttype = "HEADER_IN";
    break;
  case CURLINFO_HEADER_OUT:
    ttype = "HEADER_OUT";
    /* Overhead*/
    GNUNET_assert (NULL != ch);
    GNUNET_assert (NULL != ch->easyhandle);
    GNUNET_assert (NULL != ch->s);
    ch->s->overhead += size;
    break;
  default:
    ttype = "UNSPECIFIED";
    break;
  }
  memcpy (text, data, size);
  if (text[size - 1] == '\n')
  {
    text[size] = '\0';
  }
  else
  {
    text[size] = '\n';
    text[size + 1] = '\0';
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Request %p %s: %s",
       ch->easyhandle,
       ttype,
       text);
  return 0;
}
#endif

/**
 * Connect GET request
 *
 * @param s the session to connect
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
static int
client_connect_get (struct Session *s);


/**
 * Connect a HTTP put request
 *
 * @param s the session to connect
 * @return #GNUNET_SYSERR for hard failure, #GNUNET_OK for success
 */
static int
client_connect_put (struct Session *s);


/**
 * Function that can be used by the transport service to transmit
 * a message using the plugin.   Note that in the case of a
 * peer disconnecting, the continuation MUST be called
 * prior to the disconnect notification itself.  This function
 * will be called with this peer's HELLO message to initiate
 * a fresh connection to another peer.
 *
 * @param cls closure
 * @param s which session must be used
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
 * @param cont_cls closure for cont
 * @return number of bytes used (on the physical network, with overheads);
 *         -1 on hard errors (i.e. address invalid); 0 is a legal value
 *         and does NOT mean that the message was not transmitted (DV)
 */
static ssize_t
http_client_plugin_send (void *cls,
                         struct Session *s,
                         const char *msgbuf,
                         size_t msgbuf_size,
                         unsigned int priority,
                         struct GNUNET_TIME_Relative to,
                         GNUNET_TRANSPORT_TransmitContinuation cont,
                         void *cont_cls)
{
  struct HTTP_Client_Plugin *plugin = cls;
  struct HTTP_Message *msg;
  char *stat_txt;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Session %p/request %p: Sending message with %u to peer `%s' \n",
       s, s->put.easyhandle,
       msgbuf_size, GNUNET_i2s (&s->address->peer));

  /* create new message and schedule */
  msg = GNUNET_malloc (sizeof (struct HTTP_Message) + msgbuf_size);
  msg->next = NULL;
  msg->size = msgbuf_size;
  msg->pos = 0;
  msg->buf = (char *) &msg[1];
  msg->transmit_cont = cont;
  msg->transmit_cont_cls = cont_cls;
  memcpy (msg->buf, msgbuf, msgbuf_size);
  GNUNET_CONTAINER_DLL_insert_tail (s->msg_head,
                                    s->msg_tail,
                                    msg);
  s->msgs_in_queue++;
  s->bytes_in_queue += msg->size;

  GNUNET_asprintf (&stat_txt,
                   "# bytes currently in %s_client buffers",
                   plugin->protocol);
  GNUNET_STATISTICS_update (plugin->env->stats,
                            stat_txt, msgbuf_size, GNUNET_NO);
  GNUNET_free (stat_txt);
  notify_session_monitor (plugin,
                          s,
                          GNUNET_TRANSPORT_SS_UP);
  if (H_TMP_DISCONNECTING == s->put.state)
  {
    /* PUT request is currently getting disconnected */
    s->put.state = H_TMP_RECONNECT_REQUIRED;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Session %p/request %p: currently disconnecting, reconnecting immediately\n",
         s,
         s->put.easyhandle);
    return msgbuf_size;
  }
  if (H_PAUSED == s->put.state)
  {
    /* PUT request was paused, unpause */
    GNUNET_assert (s->put_disconnect_task != GNUNET_SCHEDULER_NO_TASK);
    GNUNET_SCHEDULER_cancel (s->put_disconnect_task);
    s->put_disconnect_task = GNUNET_SCHEDULER_NO_TASK;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Session %p/request %p: unpausing request\n",
         s, s->put.easyhandle);
    s->put.state = H_CONNECTED;
    if (NULL != s->put.easyhandle)
      curl_easy_pause (s->put.easyhandle, CURLPAUSE_CONT);
  }
  else if (H_TMP_DISCONNECTED == s->put.state)
  {
    /* PUT request was disconnected, reconnect */
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Session %p: Reconnecting PUT request\n", s);
    GNUNET_break (NULL == s->put.easyhandle);
    if (GNUNET_SYSERR == client_connect_put (s))
    {
      /* Could not reconnect */
      http_client_plugin_session_disconnect (plugin, s);
      return GNUNET_SYSERR;
    }
  }
  client_schedule (s->plugin, GNUNET_YES);
  return msgbuf_size;
}


/**
 * Disconnect a session
 *
 * @param cls the `struct HTTP_Client_Plugin *`
 * @param s session
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
http_client_plugin_session_disconnect (void *cls,
                                       struct Session *s)
{
  struct HTTP_Client_Plugin *plugin = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Session %p: notifying transport about ending session\n",s);
  plugin->env->session_end (plugin->env->cls, s->address, s);
  client_delete_session (s);

  /* Re-schedule since handles have changed */
  if (plugin->client_perform_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (plugin->client_perform_task);
    plugin->client_perform_task = GNUNET_SCHEDULER_NO_TASK;
  }
  client_schedule (plugin, GNUNET_YES);

  return GNUNET_OK;
}


/**
 * Function that is called to get the keepalive factor.
 * #GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT is divided by this number to
 * calculate the interval between keepalive packets.
 *
 * @param cls closure with the `struct Plugin`
 * @return keepalive factor
 */
static unsigned int
http_client_query_keepalive_factor (void *cls)
{
  return 3;
}


/**
 * Callback to destroys all sessions on exit.
 *
 * @param cls the `struct HTTP_Client_Plugin *`
 * @param peer identity of the peer
 * @param value the `struct Session *`
 * @return #GNUNET_OK (continue iterating)
 */
static int
destroy_session_cb (void *cls,
                    const struct GNUNET_PeerIdentity *peer,
                    void *value)
{
  struct HTTP_Client_Plugin *plugin = cls;
  struct Session *session = value;

  http_client_plugin_session_disconnect (plugin, session);
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
http_client_plugin_peer_disconnect (void *cls,
                                    const struct GNUNET_PeerIdentity *target)
{
  struct HTTP_Client_Plugin *plugin = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transport tells me to disconnect `%s'\n",
       GNUNET_i2s (target));
  GNUNET_CONTAINER_multipeermap_get_multiple (plugin->sessions, target,
      &destroy_session_cb, plugin);
}


/**
 * Closure for #session_lookup_client_by_address().
 */
struct SessionClientCtx
{
  /**
   * Address we are looking for.
   */
  const struct GNUNET_HELLO_Address *address;

  /**
   * Session that was found.
   */
  struct Session *ret;
};


/**
 * Locate the seession object for a given address.
 *
 * @param cls the `struct SessionClientCtx *`
 * @param key peer identity
 * @param value the `struct Session` to check
 * @return #GNUNET_NO if found, #GNUNET_OK if not
 */
static int
session_lookup_client_by_address (void *cls,
                                  const struct GNUNET_PeerIdentity *key,
                                  void *value)
{
  struct SessionClientCtx *sc_ctx = cls;
  struct Session *s = value;

  if (0 == GNUNET_HELLO_address_cmp (sc_ctx->address,
                                     s->address))
  {
    sc_ctx->ret = s;
    return GNUNET_NO;
  }
  return GNUNET_YES;
}


/**
 * Check if a sessions exists for an specific address
 *
 * @param plugin the plugin
 * @param address the address
 * @return the session or NULL
 */
static struct Session *
client_lookup_session (struct HTTP_Client_Plugin *plugin,
                       const struct GNUNET_HELLO_Address *address)
{
  struct SessionClientCtx sc_ctx;

  sc_ctx.address = address;
  sc_ctx.ret = NULL;
  GNUNET_CONTAINER_multipeermap_iterate (plugin->sessions,
                                         &session_lookup_client_by_address,
                                         &sc_ctx);
  return sc_ctx.ret;
}


/**
 * When we have nothing to transmit, we pause the HTTP PUT
 * after a while (so that gnurl stops asking).  This task
 * is the delayed task that actually disconnects the PUT.
 *
 * @param cls the `struct Session *` with the put
 * @param tc scheduler context
 */
static void
client_put_disconnect (void *cls,
                       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Session *s = cls;

  s->put_disconnect_task = GNUNET_SCHEDULER_NO_TASK;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Session %p/request %p: will be disconnected due to no activity\n",
       s, s->put.easyhandle);
  s->put.state = H_TMP_DISCONNECTING;
  if (NULL != s->put.easyhandle)
    curl_easy_pause (s->put.easyhandle, CURLPAUSE_CONT);
  client_schedule (s->plugin, GNUNET_YES);
}


/**
 * Callback method used with libcurl
 * Method is called when libcurl needs to read data during sending
 *
 * @param stream pointer where to write data
 * @param size size of an individual element
 * @param nmemb count of elements that can be written to the buffer
 * @param cls our `struct Session`
 * @return bytes written to stream, returning 0 will terminate request!
 */
static size_t
client_send_cb (void *stream,
                size_t size,
                size_t nmemb,
                void *cls)
{
  struct Session *s = cls;
  struct HTTP_Client_Plugin *plugin = s->plugin;
  struct HTTP_Message *msg = s->msg_head;
  size_t len;
  char *stat_txt;

  if (H_TMP_DISCONNECTING == s->put.state)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Session %p/request %p: disconnect due to inactivity\n",
         s, s->put.easyhandle);
    return 0;
  }

  if (NULL == msg)
  {
    if (GNUNET_YES == plugin->emulate_xhr)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Session %p/request %p: PUT request finished\n",
           s, s->put.easyhandle);
      s->put.state = H_TMP_DISCONNECTING;
      return 0;
    }

    /* We have nothing to send, so pause PUT request */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Session %p/request %p: nothing to send, suspending\n",
         s, s->put.easyhandle);
    s->put_disconnect_task = GNUNET_SCHEDULER_add_delayed (PUT_DISCONNECT_TIMEOUT,
        &client_put_disconnect, s);
    s->put.state = H_PAUSED;
    return CURL_READFUNC_PAUSE;
  }
  /* data to send */
  GNUNET_assert (msg->pos < msg->size);
  /* calculate how much fits in buffer */
  len = GNUNET_MIN (msg->size - msg->pos,
                    size * nmemb);
  memcpy (stream, &msg->buf[msg->pos], len);
  msg->pos += len;
  if (msg->pos == msg->size)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Session %p/request %p: sent message with %u bytes sent, removing message from queue\n",
         s, s->put.easyhandle, msg->size, msg->pos);
    /* Calling transmit continuation  */
    GNUNET_CONTAINER_DLL_remove (s->msg_head,
                                 s->msg_tail,
                                 msg);
    GNUNET_assert (0 < s->msgs_in_queue);
    s->msgs_in_queue--;
    GNUNET_assert (msg->size <= s->bytes_in_queue);
    s->bytes_in_queue -= msg->size;
    if (NULL != msg->transmit_cont)
      msg->transmit_cont (msg->transmit_cont_cls,
                          &s->address->peer,
                          GNUNET_OK,
                          msg->size,
                          msg->size + s->overhead);
    s->overhead = 0;
    GNUNET_free (msg);
  }
  notify_session_monitor (plugin,
                          s,
                          GNUNET_TRANSPORT_SS_UP);
  GNUNET_asprintf (&stat_txt,
                   "# bytes currently in %s_client buffers",
                   plugin->protocol);
  GNUNET_STATISTICS_update (plugin->env->stats,
                            stat_txt,
                            - len,
                            GNUNET_NO);
  GNUNET_free (stat_txt);
  GNUNET_asprintf (&stat_txt,
                   "# bytes transmitted via %s_client",
                   plugin->protocol);
  GNUNET_STATISTICS_update (plugin->env->stats,
                            stat_txt,
                            len,
                            GNUNET_NO);
  GNUNET_free (stat_txt);
  return len;
}


/**
 * Wake up a curl handle which was suspended
 *
 * @param cls the session
 * @param tc task context
 */
static void
client_wake_up (void *cls,
                const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Session *s = cls;

  s->recv_wakeup_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Session %p/request %p: Waking up GET handle\n",
       s, s->get.easyhandle);
  if (H_PAUSED == s->put.state)
  {
    /* PUT request was paused, unpause */
    GNUNET_assert (s->put_disconnect_task != GNUNET_SCHEDULER_NO_TASK);
    GNUNET_SCHEDULER_cancel (s->put_disconnect_task);
    s->put_disconnect_task = GNUNET_SCHEDULER_NO_TASK;
    s->put.state = H_CONNECTED;
    if (NULL != s->put.easyhandle)
      curl_easy_pause (s->put.easyhandle, CURLPAUSE_CONT);
  }
  if (NULL != s->get.easyhandle)
    curl_easy_pause (s->get.easyhandle, CURLPAUSE_CONT);
}


/**
 * Callback for message stream tokenizer
 *
 * @param cls the session
 * @param client not used
 * @param message the message received
 * @return always #GNUNET_OK
 */
static int
client_receive_mst_cb (void *cls,
                       void *client,
                       const struct GNUNET_MessageHeader *message)
{
  struct Session *s = cls;
  struct HTTP_Client_Plugin *plugin;
  struct GNUNET_TIME_Relative delay;
  struct GNUNET_ATS_Information atsi;
  char *stat_txt;

  plugin = s->plugin;
  atsi.type = htonl (GNUNET_ATS_NETWORK_TYPE);
  atsi.value = s->ats_address_network_type;
  GNUNET_break (s->ats_address_network_type != ntohl (GNUNET_ATS_NET_UNSPECIFIED));

  delay = s->plugin->env->receive (plugin->env->cls,
                                   s->address,
                                   s,
                                   message);
  plugin->env->update_address_metrics (plugin->env->cls,
				       s->address, s,
				       &atsi, 1);

  GNUNET_asprintf (&stat_txt,
                   "# bytes received via %s_client",
                   plugin->protocol);
  GNUNET_STATISTICS_update (plugin->env->stats,
                            stat_txt,
                            ntohs (message->size),
                            GNUNET_NO);
  GNUNET_free (stat_txt);

  s->next_receive = GNUNET_TIME_relative_to_absolute (delay);
  if (GNUNET_TIME_absolute_get ().abs_value_us < s->next_receive.abs_value_us)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Client: peer `%s' address `%s' next read delayed for %s\n",
         GNUNET_i2s (&s->address->peer),
         http_common_plugin_address_to_string (s->plugin->protocol,
                                               s->address->address,
                                               s->address->address_length),
         GNUNET_STRINGS_relative_time_to_string (delay,
                                                 GNUNET_YES));
  }
  client_reschedule_session_timeout (s);
  return GNUNET_OK;
}


/**
 * Callback method used with libcurl when data for a PUT request are
 * received.  We do not expect data here, so we just discard it.
 *
 * @param stream pointer where to write data
 * @param size size of an individual element
 * @param nmemb count of elements that can be written to the buffer
 * @param cls destination pointer, passed to the libcurl handle
 * @return bytes read from stream
 */
static size_t
client_receive_put (void *stream,
                    size_t size,
                    size_t nmemb,
                    void *cls)
{
  return size * nmemb;
}


/**
 * Callback method used with libcurl when data for a GET request are
 * received. Forward to MST
 *
 * @param stream pointer where to write data
 * @param size size of an individual element
 * @param nmemb count of elements that can be written to the buffer
 * @param cls destination pointer, passed to the libcurl handle
 * @return bytes read from stream
 */
static size_t
client_receive (void *stream,
                size_t size,
                size_t nmemb,
                void *cls)
{
  struct Session *s = cls;
  struct GNUNET_TIME_Absolute now;
  size_t len = size * nmemb;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Session %p / request %p: Received %u bytes from peer `%s'\n",
       s, s->get.easyhandle,
       len, GNUNET_i2s (&s->address->peer));
  now = GNUNET_TIME_absolute_get ();
  if (now.abs_value_us < s->next_receive.abs_value_us)
  {
    struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
    struct GNUNET_TIME_Relative delta
      = GNUNET_TIME_absolute_get_difference (now, s->next_receive);

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Session %p / request %p: No inbound bandwidth available! Next read was delayed for %s\n",
         s,
         s->get.easyhandle,
         GNUNET_STRINGS_relative_time_to_string (delta,
                                                 GNUNET_YES));
    if (s->recv_wakeup_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (s->recv_wakeup_task);
      s->recv_wakeup_task = GNUNET_SCHEDULER_NO_TASK;
    }
    s->recv_wakeup_task
      = GNUNET_SCHEDULER_add_delayed (delta,
                                      &client_wake_up,
                                      s);
    return CURL_WRITEFUNC_PAUSE;
  }
  if (NULL == s->msg_tk)
    s->msg_tk = GNUNET_SERVER_mst_create (&client_receive_mst_cb,
                                          s);
  GNUNET_SERVER_mst_receive (s->msg_tk,
                             s,
                             stream,
                             len,
                             GNUNET_NO,
                             GNUNET_NO);
  return len;
}


/**
 * Task performing curl operations
 *
 * @param cls plugin as closure
 * @param tc scheduler task context
 */
static void
client_run (void *cls,
            const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct HTTP_Client_Plugin *plugin = cls;
  int running;
  long http_statuscode;
  CURLMcode mret;
  CURLMsg *msg;
  int put_request; /* GNUNET_YES if easy handle is put, GNUNET_NO for get */
  int msgs_left;

  plugin->client_perform_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  /* While data are available or timeouts occured */
  do
  {
    running = 0;
    /* Perform operations for all handles */
    mret = curl_multi_perform (plugin->curl_multi_handle, &running);

    /* Get additional information for all handles */
    while (NULL != (msg = curl_multi_info_read (plugin->curl_multi_handle, &msgs_left)))
    {
      CURL *easy_h = msg->easy_handle;
      struct Session *s = NULL;
      char *d = NULL; /* curl requires 'd' to be a 'char *' */

      GNUNET_assert (NULL != easy_h);

      /* Obtain session from easy handle */
      GNUNET_assert (CURLE_OK == curl_easy_getinfo (easy_h, CURLINFO_PRIVATE, &d));
      s = (struct Session *) d;
      GNUNET_assert (NULL != s);

      if (msg->msg != CURLMSG_DONE)
        continue; /* This should not happen */

      /* Get HTTP response code */
      GNUNET_break (CURLE_OK == curl_easy_getinfo (easy_h,
          CURLINFO_RESPONSE_CODE, &http_statuscode));


      if (easy_h == s->put.easyhandle)
        put_request = GNUNET_YES;
      else
        put_request = GNUNET_NO;

      /* Log status of terminated request */
      if  ((0 != msg->data.result) || (http_statuscode != 200))
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Session %p/request %p: %s request to `%s' ended with status %i reason %i: `%s'\n",
             s, msg->easy_handle,
             (GNUNET_YES == put_request) ? "PUT" : "GET",
             GNUNET_i2s (&s->address->peer),
             http_statuscode,
             msg->data.result,
             curl_easy_strerror (msg->data.result));
      else
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Session %p/request %p: %s request to `%s' ended normal\n",
             s, msg->easy_handle,
             (GNUNET_YES == put_request) ? "PUT" : "GET",
             GNUNET_i2s (&s->address->peer));

      /* Remove easy handle from multi handle */
      curl_multi_remove_handle (plugin->curl_multi_handle, easy_h);

      /* Clean up easy handle */
      curl_easy_cleanup (easy_h);

      /* Remove information */
      GNUNET_assert (plugin->cur_requests > 0);
      plugin->cur_requests--;
      LOG  (GNUNET_ERROR_TYPE_INFO,
          "%s request done, number of requests decreased to %u\n",
          (GNUNET_YES == put_request) ? "PUT" : "GET",
          plugin->cur_requests);

      if (GNUNET_YES == put_request)
      {
        /* Clean up a PUT request */
        s->put.easyhandle = NULL;
        s->put.s = NULL;

        switch (s->put.state) {
          case H_NOT_CONNECTED:
          case H_DISCONNECTED:
          case H_TMP_DISCONNECTED:
            /* This must not happen */
            GNUNET_break (0);
            break;
          case H_TMP_RECONNECT_REQUIRED:
            /* Transport called send while disconnect in progess, reconnect */
            if (GNUNET_SYSERR == client_connect_put (s))
            {
              /* Reconnect failed, disconnect session */
              http_client_plugin_session_disconnect (plugin, s);
            }
            break;
          case H_TMP_DISCONNECTING:
            /* PUT gets temporarily disconnected */
            s->put.state = H_TMP_DISCONNECTED;
            break;
          case H_PAUSED:
          case H_CONNECTED:
            /* PUT gets permanently disconnected */
            s->put.state = H_DISCONNECTED;
            http_client_plugin_session_disconnect (plugin, s);
            break;
          default:
            GNUNET_break (0);
            break;
        }
      }
      else if (GNUNET_NO == put_request)
      {
        /* Clean up a GET request */
        s->get.easyhandle = NULL;
        s->get.s = NULL;

        /* If we are emulating an XHR client we need to make another GET
         * request.
         */
        if (GNUNET_YES == plugin->emulate_xhr)
        {
          if (GNUNET_SYSERR == client_connect_get (s))
            http_client_plugin_session_disconnect (plugin, s);
        }
        else
        {
          /* GET request was terminated, so disconnect session */
          http_client_plugin_session_disconnect (plugin, s);
        }
      }
      else
        GNUNET_break (0); /* Must not happen */
    }
  }
  while (mret == CURLM_CALL_MULTI_PERFORM);
  client_schedule (plugin, GNUNET_NO);
}


/**
 * Connect GET request for a session
 *
 * @param s the session to connect
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
static int
client_connect_get (struct Session *s)
{
  CURLMcode mret;

  /* create get request */
  s->get.easyhandle = curl_easy_init ();
  s->get.s = s;
#if VERBOSE_CURL
  curl_easy_setopt (s->get.easyhandle, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt (s->get.easyhandle, CURLOPT_DEBUGFUNCTION, &client_log);
  curl_easy_setopt (s->get.easyhandle, CURLOPT_DEBUGDATA, &s->get);
#endif
#if BUILD_HTTPS
  curl_easy_setopt (s->get.easyhandle, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
  {
    struct HttpAddress *ha;

    ha = (struct HttpAddress *) s->address->address;

    if (HTTP_OPTIONS_VERIFY_CERTIFICATE ==
        (ntohl (ha->options) & HTTP_OPTIONS_VERIFY_CERTIFICATE))
    {
      curl_easy_setopt (s->get.easyhandle, CURLOPT_SSL_VERIFYPEER, 1L);
      curl_easy_setopt (s->get.easyhandle, CURLOPT_SSL_VERIFYHOST, 2L);
    }
    else
    {
      curl_easy_setopt (s->get.easyhandle, CURLOPT_SSL_VERIFYPEER, 0);
      curl_easy_setopt (s->get.easyhandle, CURLOPT_SSL_VERIFYHOST, 0);
    }
  }
  curl_easy_setopt (s->get.easyhandle, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
  curl_easy_setopt (s->get.easyhandle, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
#else
  curl_easy_setopt (s->get.easyhandle, CURLOPT_PROTOCOLS, CURLPROTO_HTTP);
  curl_easy_setopt (s->get.easyhandle, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP);
#endif

  if (NULL != s->plugin->proxy_hostname)
  {
    curl_easy_setopt (s->get.easyhandle, CURLOPT_PROXY, s->plugin->proxy_hostname);
    curl_easy_setopt (s->get.easyhandle, CURLOPT_PROXYTYPE, s->plugin->proxytype);
    if (NULL != s->plugin->proxy_username)
      curl_easy_setopt (s->get.easyhandle, CURLOPT_PROXYUSERNAME,
          s->plugin->proxy_username);
    if (NULL != s->plugin->proxy_password)
      curl_easy_setopt (s->get.easyhandle, CURLOPT_PROXYPASSWORD,
          s->plugin->proxy_password);
    if (GNUNET_YES == s->plugin->proxy_use_httpproxytunnel)
      curl_easy_setopt (s->get.easyhandle, CURLOPT_HTTPPROXYTUNNEL,
          s->plugin->proxy_use_httpproxytunnel);
  }

  if (GNUNET_YES == s->plugin->emulate_xhr)
  {
    char *url;

    GNUNET_asprintf(&url, "%s,1", s->url);
    curl_easy_setopt (s->get.easyhandle, CURLOPT_URL, url);
    GNUNET_free(url);
  } else
    curl_easy_setopt (s->get.easyhandle, CURLOPT_URL, s->url);
  //curl_easy_setopt (s->get.easyhandle, CURLOPT_HEADERFUNCTION, &curl_get_header_cb);
  //curl_easy_setopt (s->get.easyhandle, CURLOPT_WRITEHEADER, ps);
  curl_easy_setopt (s->get.easyhandle, CURLOPT_READFUNCTION, client_send_cb);
  curl_easy_setopt (s->get.easyhandle, CURLOPT_READDATA, s);
  curl_easy_setopt (s->get.easyhandle, CURLOPT_WRITEFUNCTION, client_receive);
  curl_easy_setopt (s->get.easyhandle, CURLOPT_WRITEDATA, s);
  /* No timeout by default, timeout done with session timeout */
  curl_easy_setopt (s->get.easyhandle, CURLOPT_TIMEOUT, 0);
  curl_easy_setopt (s->get.easyhandle, CURLOPT_PRIVATE, s);
  curl_easy_setopt (s->get.easyhandle, CURLOPT_CONNECTTIMEOUT_MS,
                    (long) (HTTP_CLIENT_NOT_VALIDATED_TIMEOUT.rel_value_us / 1000LL));
  curl_easy_setopt (s->get.easyhandle, CURLOPT_BUFFERSIZE,
                    2 * GNUNET_SERVER_MAX_MESSAGE_SIZE);
#if CURL_TCP_NODELAY
  curl_easy_setopt (ps->recv_endpoint, CURLOPT_TCP_NODELAY, 1);
#endif
  curl_easy_setopt (s->get.easyhandle, CURLOPT_FOLLOWLOCATION, 0);

  mret = curl_multi_add_handle (s->plugin->curl_multi_handle,
                                s->get.easyhandle);
  if (CURLM_OK != mret)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Session %p : Failed to add GET handle to multihandle: `%s'\n",
         s,
         curl_multi_strerror (mret));
    curl_easy_cleanup (s->get.easyhandle);
    s->get.easyhandle = NULL;
    s->get.s = NULL;
    s->get.easyhandle = NULL;
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  s->plugin->cur_requests++;
  LOG  (GNUNET_ERROR_TYPE_INFO,
      "GET request `%s' established, number of requests increased to %u\n",
      s->url, s->plugin->cur_requests);
  return GNUNET_OK;
}


/**
 * Connect a HTTP put request
 *
 * @param s the session to connect
 * @return #GNUNET_SYSERR for hard failure, #GNUNET_OK for ok
 */
static int
client_connect_put (struct Session *s)
{
  CURLMcode mret;

  /* create put request */
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Session %p: Init PUT handle\n", s);
  s->put.easyhandle = curl_easy_init ();
  s->put.s = s;
#if VERBOSE_CURL
  curl_easy_setopt (s->put.easyhandle, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt (s->put.easyhandle, CURLOPT_DEBUGFUNCTION, &client_log);
  curl_easy_setopt (s->put.easyhandle, CURLOPT_DEBUGDATA, &s->put);
#endif
#if BUILD_HTTPS
  curl_easy_setopt (s->put.easyhandle, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
  {
    struct HttpAddress *ha;
    ha = (struct HttpAddress *) s->address->address;

    if (HTTP_OPTIONS_VERIFY_CERTIFICATE ==
        (ntohl (ha->options) & HTTP_OPTIONS_VERIFY_CERTIFICATE))
    {
      curl_easy_setopt (s->put.easyhandle, CURLOPT_SSL_VERIFYPEER, 1L);
      curl_easy_setopt (s->put.easyhandle, CURLOPT_SSL_VERIFYHOST, 2L);
    }
    else
    {
      curl_easy_setopt (s->put.easyhandle, CURLOPT_SSL_VERIFYPEER, 0);
      curl_easy_setopt (s->put.easyhandle, CURLOPT_SSL_VERIFYHOST, 0);
    }
  }
  curl_easy_setopt (s->put.easyhandle, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS);
  curl_easy_setopt (s->put.easyhandle, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);
#else
  curl_easy_setopt (s->put.easyhandle, CURLOPT_PROTOCOLS, CURLPROTO_HTTP);
  curl_easy_setopt (s->put.easyhandle, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP);
#endif
  if (s->plugin->proxy_hostname != NULL)
  {
    curl_easy_setopt (s->put.easyhandle, CURLOPT_PROXY, s->plugin->proxy_hostname);
    curl_easy_setopt (s->put.easyhandle, CURLOPT_PROXYTYPE, s->plugin->proxytype);
    if (NULL != s->plugin->proxy_username)
      curl_easy_setopt (s->put.easyhandle, CURLOPT_PROXYUSERNAME,
          s->plugin->proxy_username);
    if (NULL != s->plugin->proxy_password)
      curl_easy_setopt (s->put.easyhandle, CURLOPT_PROXYPASSWORD,
          s->plugin->proxy_password);
    if (GNUNET_YES == s->plugin->proxy_use_httpproxytunnel)
      curl_easy_setopt (s->put.easyhandle, CURLOPT_HTTPPROXYTUNNEL,
          s->plugin->proxy_use_httpproxytunnel);
  }

  curl_easy_setopt (s->put.easyhandle, CURLOPT_URL, s->url);
  curl_easy_setopt (s->put.easyhandle, CURLOPT_UPLOAD, 1L);
  //curl_easy_setopt (s->put.easyhandle, CURLOPT_HEADERFUNCTION, &client_curl_header);
  //curl_easy_setopt (s->put.easyhandle, CURLOPT_WRITEHEADER, ps);
  curl_easy_setopt (s->put.easyhandle, CURLOPT_READFUNCTION, client_send_cb);
  curl_easy_setopt (s->put.easyhandle, CURLOPT_READDATA, s);
  curl_easy_setopt (s->put.easyhandle, CURLOPT_WRITEFUNCTION, client_receive_put);
  curl_easy_setopt (s->put.easyhandle, CURLOPT_WRITEDATA, s);
  /* No timeout by default, timeout done with session timeout */
  curl_easy_setopt (s->put.easyhandle, CURLOPT_TIMEOUT, 0);
  curl_easy_setopt (s->put.easyhandle, CURLOPT_PRIVATE, s);
  curl_easy_setopt (s->put.easyhandle, CURLOPT_CONNECTTIMEOUT_MS,
                    (long) (HTTP_CLIENT_NOT_VALIDATED_TIMEOUT.rel_value_us / 1000LL));
  curl_easy_setopt (s->put.easyhandle, CURLOPT_BUFFERSIZE,
                    2 * GNUNET_SERVER_MAX_MESSAGE_SIZE);
#if CURL_TCP_NODELAY
  curl_easy_setopt (s->put.easyhandle, CURLOPT_TCP_NODELAY, 1);
#endif
  mret = curl_multi_add_handle (s->plugin->curl_multi_handle,
                                s->put.easyhandle);
  if (CURLM_OK != mret)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Session %p : Failed to add PUT handle to multihandle: `%s'\n",
         s, curl_multi_strerror (mret));
    curl_easy_cleanup (s->put.easyhandle);
    s->put.easyhandle = NULL;
    s->put.easyhandle = NULL;
    s->put.s = NULL;
    s->put.state = H_DISCONNECTED;
    return GNUNET_SYSERR;
  }
  s->put.state = H_CONNECTED;
  s->plugin->cur_requests++;

  LOG  (GNUNET_ERROR_TYPE_INFO,
      "PUT request `%s' established, number of requests increased to %u\n",
      s->url, s->plugin->cur_requests);

  return GNUNET_OK;
}


/**
 * Connect both PUT and GET request for a session
 *
 * @param s the session to connect
 * @return #GNUNET_OK on success, #GNUNET_SYSERR otherwise
 */
static int
client_connect (struct Session *s)
{
  struct HTTP_Client_Plugin *plugin = s->plugin;
  int res = GNUNET_OK;

  /* create url */
  if (NULL == http_common_plugin_address_to_string(plugin->protocol,
          s->address->address, s->address->address_length))
    {
      LOG(GNUNET_ERROR_TYPE_DEBUG, "Invalid address peer `%s'\n",
          GNUNET_i2s(&s->address->peer));
      return GNUNET_SYSERR;
    }

  GNUNET_asprintf(&s->url, "%s/%s;%u",
      http_common_plugin_address_to_url(NULL, s->address->address,
          s->address->address_length),
      GNUNET_i2s_full(plugin->env->my_identity), plugin->last_tag);

  plugin->last_tag++;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Initiating outbound session peer `%s' using address `%s'\n",
       GNUNET_i2s (&s->address->peer), s->url);

  if (GNUNET_SYSERR == client_connect_get (s))
    return GNUNET_SYSERR;
  /* If we are emulating an XHR client then delay sending a PUT request until
   * there is something to send.
   */
  if (GNUNET_YES == plugin->emulate_xhr)
  {
    s->put.state = H_TMP_DISCONNECTED;
  }
  else if (GNUNET_SYSERR == client_connect_put (s))
    return GNUNET_SYSERR;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Session %p: connected with GET %p and PUT %p\n",
       s, s->get.easyhandle, s->put.easyhandle);
  /* Perform connect */
  GNUNET_STATISTICS_set (plugin->env->stats,
                         HTTP_STAT_STR_CONNECTIONS,
                         plugin->cur_requests,
                         GNUNET_NO);
  /* Re-schedule since handles have changed */
  if (plugin->client_perform_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (plugin->client_perform_task);
    plugin->client_perform_task = GNUNET_SCHEDULER_NO_TASK;
  }

  /* Schedule task to run immediately */
  plugin->client_perform_task = GNUNET_SCHEDULER_add_now (client_run, plugin);
  return res;
}


/**
 * Function obtain the network type for a session
 *
 * @param cls closure (`struct Plugin*`)
 * @param session the session
 * @return the network type
 */
static enum GNUNET_ATS_Network_Type
http_client_plugin_get_network (void *cls,
                                struct Session *session)
{
  return ntohl (session->ats_address_network_type);
}


/**
 * Session was idle, so disconnect it
 *
 * @param cls the `struct Session` of the idle session
 * @param tc scheduler context
 */
static void
client_session_timeout (void *cls,
                        const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Session *s = cls;
  struct GNUNET_TIME_Relative left;

  s->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  left = GNUNET_TIME_absolute_get_remaining (s->timeout);
  if (0 != left.rel_value_us)
  {
    /* not actually our turn yet, but let's at least update
       the monitor, it may think we're about to die ... */
    notify_session_monitor (s->plugin,
                            s,
                            GNUNET_TRANSPORT_SS_UP);
    s->timeout_task = GNUNET_SCHEDULER_add_delayed (left,
                                                    &client_session_timeout,
                                                    s);
    return;
  }
  LOG (TIMEOUT_LOG,
       "Session %p was idle for %s, disconnecting\n",
       s,
       GNUNET_STRINGS_relative_time_to_string (HTTP_CLIENT_SESSION_TIMEOUT,
                                               GNUNET_YES));
  GNUNET_assert (GNUNET_OK ==
                 http_client_plugin_session_disconnect (s->plugin,
                                                 s));
}


/**
 * Creates a new outbound session the transport service will use to
 * send data to the peer
 *
 * @param cls the plugin
 * @param address the address
 * @return the session or NULL of max connections exceeded
 */
static struct Session *
http_client_plugin_get_session (void *cls,
                                const struct GNUNET_HELLO_Address *address)
{
  struct HTTP_Client_Plugin *plugin = cls;
  struct Session *s;
  struct sockaddr *sa;
  struct GNUNET_ATS_Information ats;
  size_t salen = 0;
  int res;

  GNUNET_assert (NULL != address->address);

  /* find existing session */
  s = client_lookup_session (plugin, address);
  if (NULL != s)
    return s;

  /* create a new session */
  if (plugin->max_requests <= plugin->cur_requests)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "Maximum number of requests (%u) reached: "
         "cannot connect to peer `%s'\n",
         plugin->max_requests,
         GNUNET_i2s (&address->peer));
    return NULL;
  }

  /* Determine network location */
  ats.type = htonl (GNUNET_ATS_NETWORK_TYPE);
  ats.value = htonl (GNUNET_ATS_NET_UNSPECIFIED);
  sa = http_common_socket_from_address (address->address, address->address_length, &res);
  if (GNUNET_SYSERR == res)
    return NULL;
  if (GNUNET_YES == res)
  {
    GNUNET_assert (NULL != sa);
    if (AF_INET == sa->sa_family)
    {
      salen = sizeof (struct sockaddr_in);
    }
    else if (AF_INET6 == sa->sa_family)
    {
      salen = sizeof (struct sockaddr_in6);
    }
    ats = plugin->env->get_address_type (plugin->env->cls, sa, salen);
    GNUNET_free (sa);
  }
  else if (GNUNET_NO == res)
  {
    /* Cannot convert to sockaddr -> is external hostname */
    ats.value = htonl (GNUNET_ATS_NET_WAN);
  }
  if (GNUNET_ATS_NET_UNSPECIFIED == ntohl (ats.value))
  {
    GNUNET_break (0);
    return NULL;
  }

  s = GNUNET_new (struct Session);
  s->plugin = plugin;
  s->address = GNUNET_HELLO_address_copy (address);
  s->ats_address_network_type = ats.value;

  s->put.state = H_NOT_CONNECTED;
  s->timeout = GNUNET_TIME_relative_to_absolute (HTTP_CLIENT_SESSION_TIMEOUT);
  s->timeout_task =  GNUNET_SCHEDULER_add_delayed (HTTP_CLIENT_SESSION_TIMEOUT,
                                                   &client_session_timeout,
                                                   s);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Created new session %p for `%s' address `%s''\n",
       s,
       http_common_plugin_address_to_string (plugin->protocol,
                                             s->address->address,
                                             s->address->address_length),
       GNUNET_i2s (&s->address->peer));

  /* add new session */
  (void) GNUNET_CONTAINER_multipeermap_put (plugin->sessions,
                                            &s->address->peer,
                                            s,
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  /* initiate new connection */
  if (GNUNET_SYSERR == client_connect (s))
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         "Cannot connect to peer `%s' address `%s''\n",
         http_common_plugin_address_to_string (plugin->protocol,
             s->address->address, s->address->address_length),
             GNUNET_i2s (&s->address->peer));
    client_delete_session (s);
    return NULL;
  }
  notify_session_monitor (plugin, s, GNUNET_TRANSPORT_SS_UP); /* or handshake? */
  return s;
}


/**
 * Setup http_client plugin
 *
 * @param plugin the plugin handle
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
static int
client_start (struct HTTP_Client_Plugin *plugin)
{
  curl_global_init (CURL_GLOBAL_ALL);
  plugin->curl_multi_handle = curl_multi_init ();

  if (NULL == plugin->curl_multi_handle)
  {
    LOG (GNUNET_ERROR_TYPE_ERROR,
         _("Could not initialize curl multi handle, failed to start %s plugin!\n"),
         plugin->name);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Another peer has suggested an address for this
 * peer and transport plugin.  Check that this could be a valid
 * address.  If so, consider adding it to the list
 * of addresses.
 *
 * @param cls closure with the `struct Plugin`
 * @param addr pointer to the address
 * @param addrlen length of @a addr
 * @return #GNUNET_OK if this is a plausible address for this peer
 *         and transport; always returns #GNUNET_NO (this is the client!)
 */
static int
http_client_plugin_address_suggested (void *cls,
                                      const void *addr,
                                      size_t addrlen)
{
  /* A HTTP/S client does not have any valid address so:*/
  return GNUNET_NO;
}


/**
 * Exit point from the plugin.
 *
 * @param cls api as closure
 * @return NULL
 */
void *
LIBGNUNET_PLUGIN_TRANSPORT_DONE (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct HTTP_Client_Plugin *plugin = api->cls;

  if (NULL == api->cls)
  {
    /* Stub shutdown */
    GNUNET_free (api);
    return NULL;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       _("Shutting down plugin `%s'\n"),
       plugin->name);
  GNUNET_CONTAINER_multipeermap_iterate (plugin->sessions,
                                         &destroy_session_cb,
                                         plugin);
  if (GNUNET_SCHEDULER_NO_TASK != plugin->client_perform_task)
  {
    GNUNET_SCHEDULER_cancel (plugin->client_perform_task);
    plugin->client_perform_task = GNUNET_SCHEDULER_NO_TASK;
  }
  if (NULL != plugin->curl_multi_handle)
  {
    curl_multi_cleanup (plugin->curl_multi_handle);
    plugin->curl_multi_handle = NULL;
  }
  curl_global_cleanup ();
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       _("Shutdown for plugin `%s' complete\n"),
       plugin->name);
  GNUNET_CONTAINER_multipeermap_destroy (plugin->sessions);
  GNUNET_free_non_null (plugin->proxy_hostname);
  GNUNET_free_non_null (plugin->proxy_username);
  GNUNET_free_non_null (plugin->proxy_password);
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}


/**
 * Configure plugin
 *
 * @param plugin the plugin handle
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on failure
 */
static int
client_configure_plugin (struct HTTP_Client_Plugin *plugin)
{
  unsigned long long max_requests;
  char *proxy_type;


  /* Optional parameters */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_number (plugin->env->cfg,
                                             plugin->name,
                                             "MAX_CONNECTIONS",
                                             &max_requests))
    max_requests = 128;
  plugin->max_requests = max_requests;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       _("Maximum number of requests is %u\n"),
       plugin->max_requests);

  /* Read proxy configuration */
  if (GNUNET_OK == GNUNET_CONFIGURATION_get_value_string (plugin->env->cfg,
      plugin->name, "PROXY", &plugin->proxy_hostname))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Found proxy host: `%s'\n",
         plugin->proxy_hostname);
    /* proxy username */
    if (GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_string (plugin->env->cfg,
                                               plugin->name,
                                               "PROXY_USERNAME",
                                               &plugin->proxy_username))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Found proxy username name: `%s'\n",
           plugin->proxy_username);
    }

    /* proxy password */
    if (GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_string (plugin->env->cfg,
                                               plugin->name,
                                               "PROXY_PASSWORD",
                                               &plugin->proxy_password))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Found proxy password name: `%s'\n",
           plugin->proxy_password);
    }

    /* proxy type */
    if (GNUNET_OK ==
        GNUNET_CONFIGURATION_get_value_string (plugin->env->cfg,
                                               plugin->name,
                                               "PROXY_TYPE",
                                               &proxy_type))
    {
      GNUNET_STRINGS_utf8_toupper (proxy_type, proxy_type);

      if (0 == strcmp(proxy_type, "HTTP"))
        plugin->proxytype = CURLPROXY_HTTP;
      else if (0 == strcmp(proxy_type, "SOCKS4"))
        plugin->proxytype = CURLPROXY_SOCKS4;
      else if (0 == strcmp(proxy_type, "SOCKS5"))
        plugin->proxytype = CURLPROXY_SOCKS5;
      else if (0 == strcmp(proxy_type, "SOCKS4A"))
        plugin->proxytype = CURLPROXY_SOCKS4A;
      else if (0 == strcmp(proxy_type, "SOCKS5_HOSTNAME "))
        plugin->proxytype = CURLPROXY_SOCKS5_HOSTNAME ;
      else
      {
        LOG (GNUNET_ERROR_TYPE_ERROR,
             _("Invalid proxy type: `%s', disabling proxy! Check configuration!\n"),
             proxy_type);

        GNUNET_free (proxy_type);
        GNUNET_free (plugin->proxy_hostname);
        plugin->proxy_hostname = NULL;
        GNUNET_free_non_null (plugin->proxy_username);
        plugin->proxy_username = NULL;
        GNUNET_free_non_null (plugin->proxy_password);
        plugin->proxy_password = NULL;

        return GNUNET_SYSERR;
      }

      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Found proxy type: `%s'\n",
           proxy_type);
    }

    /* proxy http tunneling */
    plugin->proxy_use_httpproxytunnel
      = GNUNET_CONFIGURATION_get_value_yesno (plugin->env->cfg,
                                              plugin->name,
                                              "PROXY_HTTP_TUNNELING");
    if (GNUNET_SYSERR == plugin->proxy_use_httpproxytunnel)
      plugin->proxy_use_httpproxytunnel = GNUNET_NO;

    GNUNET_free_non_null (proxy_type);
  }

  /* Should we emulate an XHR client for testing? */
  plugin->emulate_xhr
    = GNUNET_CONFIGURATION_get_value_yesno (plugin->env->cfg,
                                            plugin->name,
                                            "EMULATE_XHR");
  return GNUNET_OK;
}


/**
 * Function called by the pretty printer for the resolved address for
 * each human-readable address obtained.  The callback can be called
 * several times. The last invocation must be with a @a address of
 * NULL and a @a res of #GNUNET_OK.  Thus, to indicate conversion
 * errors, the callback might be called first with @a address NULL and
 * @a res being #GNUNET_SYSERR.  In that case, there must still be a
 * subsequent call later with @a address NULL and @a res #GNUNET_OK.
 *
 * @param cls closure
 * @param address one of the names for the host, NULL on last callback
 * @param res #GNUNET_OK if conversion was successful, #GNUNET_SYSERR on failure,
 *      #GNUNET_OK on last callback
 */
static const char *
http_client_plugin_address_to_string (void *cls,
                                      const void *addr,
                                      size_t addrlen)
{
  return http_common_plugin_address_to_string (PLUGIN_NAME,
                                               addr,
                                               addrlen);
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
http_client_plugin_update_session_timeout (void *cls,
                                           const struct GNUNET_PeerIdentity *peer,
                                           struct Session *session)
{
  client_reschedule_session_timeout (session);
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
http_client_plugin_update_inbound_delay (void *cls,
                                         const struct GNUNET_PeerIdentity *peer,
                                         struct Session *s,
                                         struct GNUNET_TIME_Relative delay)
{
  s->next_receive = GNUNET_TIME_relative_to_absolute (delay);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "New inbound delay %s\n",
       GNUNET_STRINGS_relative_time_to_string (delay,
                                               GNUNET_NO));
  if (s->recv_wakeup_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (s->recv_wakeup_task);
    s->recv_wakeup_task = GNUNET_SCHEDULER_add_delayed (delay,
        &client_wake_up, s);
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
  struct HTTP_Client_Plugin *plugin = cls;
  struct Session *session = value;

  notify_session_monitor (plugin,
                          session,
                          GNUNET_TRANSPORT_SS_UP);
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
http_client_plugin_setup_monitor (void *cls,
                                  GNUNET_TRANSPORT_SessionInfoCallback sic,
                                  void *sic_cls)
{
  struct HTTP_Client_Plugin *plugin = cls;

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
 */
void *
LIBGNUNET_PLUGIN_TRANSPORT_INIT (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  struct HTTP_Client_Plugin *plugin;

  if (NULL == env->receive)
  {
    /* run in 'stub' mode (i.e. as part of gnunet-peerinfo), don't fully
       initialze the plugin or the API */
    api = GNUNET_new (struct GNUNET_TRANSPORT_PluginFunctions);
    api->cls = NULL;
    api->address_to_string = &http_client_plugin_address_to_string;
    api->string_to_address = &http_common_plugin_string_to_address;
    api->address_pretty_printer = &http_common_plugin_address_pretty_printer;
    return api;
  }

  plugin = GNUNET_new (struct HTTP_Client_Plugin);
  plugin->env = env;
  plugin->sessions = GNUNET_CONTAINER_multipeermap_create (128,
                                                           GNUNET_YES);
  api = GNUNET_new (struct GNUNET_TRANSPORT_PluginFunctions);
  api->cls = plugin;
  api->send = &http_client_plugin_send;
  api->disconnect_session = &http_client_plugin_session_disconnect;
  api->query_keepalive_factor = &http_client_query_keepalive_factor;
  api->disconnect_peer = &http_client_plugin_peer_disconnect;
  api->check_address = &http_client_plugin_address_suggested;
  api->get_session = &http_client_plugin_get_session;
  api->address_to_string = &http_client_plugin_address_to_string;
  api->string_to_address = &http_common_plugin_string_to_address;
  api->address_pretty_printer = &http_common_plugin_address_pretty_printer;
  api->get_network = &http_client_plugin_get_network;
  api->update_session_timeout = &http_client_plugin_update_session_timeout;
  api->update_inbound_delay = &http_client_plugin_update_inbound_delay;
  api->setup_monitor = &http_client_plugin_setup_monitor;
#if BUILD_HTTPS
  plugin->name = "transport-https_client";
  plugin->protocol = "https";
#else
  plugin->name = "transport-http_client";
  plugin->protocol = "http";
#endif
  plugin->last_tag = 1;

  if (GNUNET_SYSERR == client_configure_plugin (plugin))
  {
    LIBGNUNET_PLUGIN_TRANSPORT_DONE (api);
    return NULL;
  }

  /* Start client */
  if (GNUNET_SYSERR == client_start (plugin))
  {
    LIBGNUNET_PLUGIN_TRANSPORT_DONE (api);
    return NULL;
  }
  return api;
}

/* end of plugin_transport_http_client.c */
