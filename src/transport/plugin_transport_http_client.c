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
 * @file transport/plugin_transport_http_client.c
 * @brief HTTP/S client transport plugin
 * @author Matthias Wachs
 */

#if BUILD_HTTPS
#define LIBGNUNET_PLUGIN_TRANSPORT_INIT libgnunet_plugin_transport_https_client_init
#define LIBGNUNET_PLUGIN_TRANSPORT_DONE libgnunet_plugin_transport_https_client_done
#else
#define LIBGNUNET_PLUGIN_TRANSPORT_INIT libgnunet_plugin_transport_http_client_init
#define LIBGNUNET_PLUGIN_TRANSPORT_DONE libgnunet_plugin_transport_http_client_done
#endif

#define VERBOSE_CURL GNUNET_YES

#define PUT_DISCONNECT_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 1)

#define ENABLE_PUT GNUNET_YES
#define ENABLE_GET GNUNET_YES

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_common.h"
#include "gnunet_server_lib.h"
#include "gnunet_transport_plugin.h"
#include "plugin_transport_http_common.h"
#include <curl/curl.h>



/**
 * Encapsulation of all of the state of the plugin.
 */
struct HTTP_Client_Plugin;


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


/**
 * Session handle for connections.
 */
struct Session;

struct ConnectionHandle
{
  CURL *easyhandle;
  struct Session *s;
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
   * Stored in a linked list.
   */
  struct Session *next;

  /**
   * Stored in a linked list.
   */
  struct Session *prev;

  /**
   * The URL to connect to
   */
  char *url;

  /**
   * Address
   */
  void *addr;

  /**
   * Address length
   */
  size_t addrlen;

  /**
   * ATS network type in NBO
   */
  uint32_t ats_address_network_type;

  /**
   * Pointer to the global plugin struct.
   */
  struct HTTP_Client_Plugin *plugin;

  /**
   * Client send handle
   */
  void *client_put;

  struct ConnectionHandle put;
  struct ConnectionHandle get;

  /**
   * Is the client PUT handle currently paused
   */
  int put_paused;

  /**
   * Is the client PUT handle disconnect in progress?
   */
  int put_tmp_disconnecting;

  /**
   * Is the client PUT handle temporarily disconnected?
   */
  int put_tmp_disconnected;

  /**
   * We received data to send while disconnecting, reconnect immediately
   */
  int put_reconnect_required;

  /**
   * Client receive handle
   */
  void *client_get;

  /**
   * Outbound overhead due to HTTP connection
   * Add to next message of this session when calling callback
   */
  size_t overhead;

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
  * Absolute time when to receive data again
  * Used for receive throttling
  */
  struct GNUNET_TIME_Absolute next_receive;
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
   * cURL Multihandle
   */
  CURLM *curl_multi_handle;

  /**
   * curl perform task
   */
  GNUNET_SCHEDULER_TaskIdentifier client_perform_task;
};


/**
 * Encapsulation of all of the state of the plugin.
 */
struct HTTP_Client_Plugin *p;


/**
 * Start session timeout for a session
 * @param s the session
 */
static void
client_start_session_timeout (struct Session *s);


/**
 * Increment session timeout due to activity for a session
 * @param s the session
 */
static void
client_reschedule_session_timeout (struct Session *s);


/**
 * Cancel timeout for a session
 * @param s the session
 */
static void
client_stop_session_timeout (struct Session *s);


/**
 * Function setting up file descriptors and scheduling task to run
 *
 * @param  plugin plugin as closure
 * @param now schedule task in 1ms, regardless of what curl may say
 * @return GNUNET_SYSERR for hard failure, GNUNET_OK for ok
 */
static int
client_schedule (struct HTTP_Client_Plugin *plugin, int now);

static int
client_connect_put (struct Session *s);

/**
 * Does a session s exists?
 *
 * @param plugin the plugin
 * @param s desired session
 * @return GNUNET_YES or GNUNET_NO
 */
static int
client_exist_session (struct HTTP_Client_Plugin *plugin, struct Session *s)
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
 * Loggging function
 *
 * @param curl the curl easy handle
 * @param type message type
 * @param data data as a not \0-terminated string
 * @param size data length
 * @param cls the closure
 * @return always 0
 */
static int
client_log (CURL *curl, curl_infotype type, char *data, size_t size, void *cls)
{
  struct ConnectionHandle *ch = cls;
  char *ttype = "UNSPECIFIED";
  if ((type == CURLINFO_TEXT) || (type == CURLINFO_HEADER_IN) || (type == CURLINFO_HEADER_OUT))
  {
    char text[size + 2];

    switch (type) {
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

#if VERBOSE_CURL
    memcpy (text, data, size);
    if (text[size - 1] == '\n')
      text[size] = '\0';
    else
    {
      text[size] = '\n';
      text[size + 1] = '\0';
    }
#if BUILD_HTTPS
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "transport-https_client",
                     "Connection %p %s: %s", ch->easyhandle, ttype, text);
#else
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "transport-http_client",
                     "Connection %p %s: %s", ch->easyhandle, ttype, text);
#endif
  }
#endif
  return 0;
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
 * @param s which session must be used
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
http_client_plugin_send (void *cls,
                         struct Session *s,
                         const char *msgbuf, size_t msgbuf_size,
                         unsigned int priority,
                         struct GNUNET_TIME_Relative to,
                         GNUNET_TRANSPORT_TransmitContinuation cont,
                         void *cont_cls)
{
  struct HTTP_Client_Plugin *plugin = cls;
  struct HTTP_Message *msg;
  char *stat_txt;

  GNUNET_assert (plugin != NULL);
  GNUNET_assert (s != NULL);

  /* lookup if session is really existing */
  if (GNUNET_YES != client_exist_session (plugin, s))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, s->plugin->name,
                   "Session %p/connection %p: Sending message with %u to peer `%s' \n",
                   s, s->client_put,
                   msgbuf_size, GNUNET_i2s (&s->target));

  /* create new message and schedule */
  msg = GNUNET_malloc (sizeof (struct HTTP_Message) + msgbuf_size);
  msg->next = NULL;
  msg->size = msgbuf_size;
  msg->pos = 0;
  msg->buf = (char *) &msg[1];
  msg->transmit_cont = cont;
  msg->transmit_cont_cls = cont_cls;
  memcpy (msg->buf, msgbuf, msgbuf_size);
  GNUNET_CONTAINER_DLL_insert_tail (s->msg_head, s->msg_tail, msg);

  GNUNET_asprintf (&stat_txt, "# bytes currently in %s_client buffers", plugin->protocol);
  GNUNET_STATISTICS_update (plugin->env->stats,
                            stat_txt, msgbuf_size, GNUNET_NO);

  GNUNET_free (stat_txt);

  if (GNUNET_YES == s->put_tmp_disconnecting)
  {
    /* PUT connection is currently getting disconnected */
    s->put_reconnect_required = GNUNET_YES;
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, s->plugin->name,
                     "Session %p/connection %jp: currently disconnecting, reconnecting immediately\n",
                     s, s->client_put);
    return msgbuf_size;
  }
  else if (GNUNET_YES == s->put_paused)
  {
    /* PUT connection was paused, unpause */
    GNUNET_assert (s->put_disconnect_task != GNUNET_SCHEDULER_NO_TASK);
    GNUNET_SCHEDULER_cancel (s->put_disconnect_task);
    s->put_disconnect_task = GNUNET_SCHEDULER_NO_TASK;
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, s->plugin->name,
                     "Session %p/connection %p: unpausing connection\n",
                     s, s->client_put);
    s->put_paused = GNUNET_NO;
    curl_easy_pause (s->client_put, CURLPAUSE_CONT);
  }
  else if (GNUNET_YES == s->put_tmp_disconnected)
  {
    /* PUT connection was disconnected, reconnect */
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, s->plugin->name,
                     "Session %p: Reconnecting PUT connection\n",
                     s);
    s->put_tmp_disconnected = GNUNET_NO;
    GNUNET_break (s->client_put == NULL);
    if (GNUNET_SYSERR == client_connect_put (s))
    {
      return GNUNET_SYSERR;
    }
  }

  client_schedule (s->plugin, GNUNET_YES);
  client_reschedule_session_timeout (s);
  return msgbuf_size;
}


/**
 * Delete session s
 *
 * @param s the session to delete
 */
static void
client_delete_session (struct Session *s)
{
  struct HTTP_Client_Plugin *plugin = s->plugin;
  struct HTTP_Message *pos;
  struct HTTP_Message *next;

  client_stop_session_timeout (s);

  if (GNUNET_SCHEDULER_NO_TASK != s->put_disconnect_task)
  {
      GNUNET_SCHEDULER_cancel (s->put_disconnect_task);
      s->put_disconnect_task = GNUNET_SCHEDULER_NO_TASK;
  }

  GNUNET_CONTAINER_DLL_remove (plugin->head, plugin->tail, s);

  next = s->msg_head;
  while (NULL != (pos = next))
  {
    next = pos->next;
    GNUNET_CONTAINER_DLL_remove (s->msg_head, s->msg_tail, pos);
    if (pos->transmit_cont != NULL)
      pos->transmit_cont (pos->transmit_cont_cls, &s->target, GNUNET_SYSERR,
                          pos->size, pos->pos + s->overhead);
    s->overhead = 0;
    GNUNET_free (pos);
  }

  if (s->msg_tk != NULL)
  {
    GNUNET_SERVER_mst_destroy (s->msg_tk);
    s->msg_tk = NULL;
  }
  GNUNET_free (s->addr);
  GNUNET_free (s->url);
  GNUNET_free (s);
}



/**
 * Disconnect a session
 *
 * @param s session
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
client_disconnect (struct Session *s)
{
  struct HTTP_Client_Plugin *plugin = s->plugin;
  struct HTTP_Message *msg;
  struct HTTP_Message *t;
  int res = GNUNET_OK;
  CURLMcode mret;

  if (GNUNET_YES != client_exist_session (plugin, s))
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  if (s->client_put != NULL)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Session %p/connection %p: disconnecting PUT connection to peer `%s'\n",
                     s, s->client_put, GNUNET_i2s (&s->target));

    /* remove curl handle from multi handle */
    mret = curl_multi_remove_handle (plugin->curl_multi_handle, s->client_put);
    if (mret != CURLM_OK)
    {
      /* clean up easy handle, handle is now invalid and free'd */
      res = GNUNET_SYSERR;
      GNUNET_break (0);
    }
    curl_easy_cleanup (s->client_put);
    s->client_put = NULL;
  }


  if (s->recv_wakeup_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (s->recv_wakeup_task);
    s->recv_wakeup_task = GNUNET_SCHEDULER_NO_TASK;
  }

  if (s->client_get != NULL)
  {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                       "Session %p/connection %p: disconnecting GET connection to peer `%s'\n",
                       s, s->client_get, GNUNET_i2s (&s->target));

    /* remove curl handle from multi handle */
    mret = curl_multi_remove_handle (plugin->curl_multi_handle, s->client_get);
    if (mret != CURLM_OK)
    {
      /* clean up easy handle, handle is now invalid and free'd */
      res = GNUNET_SYSERR;
      GNUNET_break (0);
    }
    curl_easy_cleanup (s->client_get);
    s->client_get = NULL;
  }

  msg = s->msg_head;
  while (msg != NULL)
  {
    t = msg->next;
    if (NULL != msg->transmit_cont)
      msg->transmit_cont (msg->transmit_cont_cls, &s->target, GNUNET_SYSERR,
                          msg->size, msg->pos + s->overhead);
    s->overhead = 0;
    GNUNET_CONTAINER_DLL_remove (s->msg_head, s->msg_tail, msg);
    GNUNET_free (msg);
    msg = t;
  }

  GNUNET_assert (plugin->cur_connections >= 2);
  plugin->cur_connections -= 2;
  GNUNET_STATISTICS_set (plugin->env->stats,
      "# HTTP client sessions",
      plugin->cur_connections,
      GNUNET_NO);

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Session %p: notifying transport about ending session\n",s);

  plugin->env->session_end (plugin->env->cls, &s->target, s);
  client_delete_session (s);

  /* Re-schedule since handles have changed */
  if (plugin->client_perform_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (plugin->client_perform_task);
    plugin->client_perform_task = GNUNET_SCHEDULER_NO_TASK;
  }
  client_schedule (plugin, GNUNET_YES);

  return res;
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
http_client_plugin_disconnect (void *cls, const struct GNUNET_PeerIdentity *target)
{
  struct HTTP_Client_Plugin *plugin = cls;
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
                       "Disconnecting session %p to `%pos'\n",
                       pos, GNUNET_i2s (target));
      GNUNET_assert (GNUNET_OK == client_disconnect (pos));
    }
  }

}


static struct Session *
client_lookup_session (struct HTTP_Client_Plugin *plugin,
                       const struct GNUNET_HELLO_Address *address)
{
  struct Session *pos;

  for (pos = plugin->head; NULL != pos; pos = pos->next)
    if ((0 == memcmp (&address->peer, &pos->target, sizeof (struct GNUNET_PeerIdentity))) &&
        (address->address_length == pos->addrlen) &&
        (0 == memcmp (address->address, pos->addr, pos->addrlen)))
      return pos;
  return NULL;
}

static void
client_put_disconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Session *s = cls;
  s->put_disconnect_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, s->plugin->name,
                   "Session %p/connection %p: will be disconnected due to no activity\n",
                   s, s->client_put);
  s->put_paused = GNUNET_NO;
  s->put_tmp_disconnecting = GNUNET_YES;
  curl_easy_pause (s->client_put, CURLPAUSE_CONT);
  client_schedule (s->plugin, GNUNET_YES);
}



/**
 * Callback method used with libcurl
 * Method is called when libcurl needs to read data during sending
 *
 * @param stream pointer where to write data
 * @param size size of an individual element
 * @param nmemb count of elements that can be written to the buffer
 * @param cls source pointer, passed to the libcurl handle
 * @return bytes written to stream, returning 0 will terminate connection!
 */
static size_t
client_send_cb (void *stream, size_t size, size_t nmemb, void *cls)
{
  struct Session *s = cls;
  struct HTTP_Client_Plugin *plugin = s->plugin;
  struct HTTP_Message *msg = s->msg_head;
  size_t len;
  char *stat_txt;

  if (GNUNET_YES != client_exist_session (plugin, s))
  {
    GNUNET_break (0);
    return 0;
  }
  if (GNUNET_YES == s->put_tmp_disconnecting)
  {

      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, s->plugin->name,
                       "Session %p/connection %p: disconnect due to inactivity\n",
                       s, s->client_put);
      return 0;
  }

  if (NULL == msg)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Session %p/connection %p: nothing to send, suspending\n",
                     s, s->client_put);
    s->put_disconnect_task = GNUNET_SCHEDULER_add_delayed (PUT_DISCONNECT_TIMEOUT, &client_put_disconnect, s);
    s->put_paused = GNUNET_YES;
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
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Session %p/connection %p: sent message with %u bytes sent, removing message from queue\n",
                     s, s->client_put, msg->size, msg->pos);
    /* Calling transmit continuation  */
    GNUNET_CONTAINER_DLL_remove (s->msg_head, s->msg_tail, msg);
    if (NULL != msg->transmit_cont)
      msg->transmit_cont (msg->transmit_cont_cls, &s->target, GNUNET_OK,
                          msg->size, msg->size + s->overhead);
    s->overhead = 0;
    GNUNET_free (msg);
  }

  GNUNET_asprintf (&stat_txt, "# bytes currently in %s_client buffers", plugin->protocol);
  GNUNET_STATISTICS_update (plugin->env->stats,
                            stat_txt, -len, GNUNET_NO);
  GNUNET_free (stat_txt);

  GNUNET_asprintf (&stat_txt, "# bytes transmitted via %s_client", plugin->protocol);
  GNUNET_STATISTICS_update (plugin->env->stats,
                            stat_txt, len, GNUNET_NO);
  GNUNET_free (stat_txt);

  client_reschedule_session_timeout (s);
  return len;
}


/**
 * Wake up a curl handle which was suspended
 *
 * @param cls the session
 * @param tc task context
 */
static void
client_wake_up (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Session *s = cls;

  if (GNUNET_YES != client_exist_session(p, s))
  {
    GNUNET_break (0);
    return;
  }
  s->recv_wakeup_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, s->plugin->name,
                   "Session %p/connection %p: Waking up GET handle\n", s, s->client_get);
  if (s->client_get != NULL)
    curl_easy_pause (s->client_get, CURLPAUSE_CONT);
}


/**
 * Callback for message stream tokenizer
 *
 * @param cls the session
 * @param client not used
 * @param message the message received
 * @return always GNUNET_OK
 */
static int
client_receive_mst_cb (void *cls, void *client,
                       const struct GNUNET_MessageHeader *message)
{
  struct Session *s = cls;
  struct HTTP_Client_Plugin *plugin;
  struct GNUNET_TIME_Relative delay;
  struct GNUNET_ATS_Information atsi[2];
  char *stat_txt;
  if (GNUNET_YES != client_exist_session(p, s))
  {
    GNUNET_break (0);
    return GNUNET_OK;
  }
  plugin = s->plugin;

  atsi[0].type = htonl (GNUNET_ATS_QUALITY_NET_DISTANCE);
  atsi[0].value = htonl (1);
  atsi[1].type = htonl (GNUNET_ATS_NETWORK_TYPE);
  atsi[1].value = s->ats_address_network_type;
  GNUNET_break (s->ats_address_network_type != ntohl (GNUNET_ATS_NET_UNSPECIFIED));

  delay = s->plugin->env->receive (plugin->env->cls, &s->target, message,
                                   (const struct GNUNET_ATS_Information *) &atsi, 2,
                                   s, s->addr, s->addrlen);

  GNUNET_asprintf (&stat_txt, "# bytes received via %s_client", plugin->protocol);
  GNUNET_STATISTICS_update (plugin->env->stats,
                            stat_txt, ntohs(message->size), GNUNET_NO);
  GNUNET_free (stat_txt);

  s->next_receive =
      GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get (), delay);

  if (GNUNET_TIME_absolute_get ().abs_value < s->next_receive.abs_value)
  {

    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Client: peer `%s' address `%s' next read delayed for %llu ms\n",
                     GNUNET_i2s (&s->target), GNUNET_a2s (s->addr, s->addrlen),
                     delay);
  }
  client_reschedule_session_timeout (s);
  return GNUNET_OK;
}


/**
 * Callback method used with libcurl when data for a PUT connection are
 * received. We do not expect data here, so we just dismiss it
 *
 * @param stream pointer where to write data
 * @param size size of an individual element
 * @param nmemb count of elements that can be written to the buffer
 * @param cls destination pointer, passed to the libcurl handle
 * @return bytes read from stream
 */
static size_t
client_receive_put (void *stream, size_t size, size_t nmemb, void *cls)
{
  return size * nmemb;
}


/**
 * Callback method used with libcurl when data for a GET connection are
 * received. Forward to MST
 *
 * @param stream pointer where to write data
 * @param size size of an individual element
 * @param nmemb count of elements that can be written to the buffer
 * @param cls destination pointer, passed to the libcurl handle
 * @return bytes read from stream
 */
static size_t
client_receive (void *stream, size_t size, size_t nmemb, void *cls)
{
  struct Session *s = cls;
  struct GNUNET_TIME_Absolute now;
  size_t len = size * nmemb;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, s->plugin->name,
                   "Session %p / connection %p: Received %u bytes from peer `%s'\n",
                   s, s->client_get,
                   len, GNUNET_i2s (&s->target));
  now = GNUNET_TIME_absolute_get ();
  if (now.abs_value < s->next_receive.abs_value)
  {
    struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
    struct GNUNET_TIME_Relative delta =
        GNUNET_TIME_absolute_get_difference (now, s->next_receive);
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, s->plugin->name,
                     "Session %p / connection %p: No inbound bandwidth available! Next read was delayed for %llu ms\n",
                     s, s->client_get, delta.rel_value);
    if (s->recv_wakeup_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (s->recv_wakeup_task);
      s->recv_wakeup_task = GNUNET_SCHEDULER_NO_TASK;
    }
    s->recv_wakeup_task =
        GNUNET_SCHEDULER_add_delayed (delta, &client_wake_up, s);
    return CURL_WRITEFUNC_PAUSE;
  }
  if (NULL == s->msg_tk)
    s->msg_tk = GNUNET_SERVER_mst_create (&client_receive_mst_cb, s);
  GNUNET_SERVER_mst_receive (s->msg_tk, s, stream, len, GNUNET_NO, GNUNET_NO);
  return len;
}


/**
 * Task performing curl operations
 *
 * @param cls plugin as closure
 * @param tc gnunet scheduler task context
 */
static void
client_run (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Function setting up file descriptors and scheduling task to run
 *
 * @param  plugin plugin as closure
 * @param now schedule task in 1ms, regardless of what curl may say
 * @return GNUNET_SYSERR for hard failure, GNUNET_OK for ok
 */
static int
client_schedule (struct HTTP_Client_Plugin *plugin, int now)
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
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("%s failed at %s:%d: `%s'\n"),
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
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("%s failed at %s:%d: `%s'\n"),
                "curl_multi_timeout", __FILE__, __LINE__,
                curl_multi_strerror (mret));
    return GNUNET_SYSERR;
  }

  grs = GNUNET_NETWORK_fdset_create ();
  gws = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_copy_native (grs, &rs, max + 1);
  GNUNET_NETWORK_fdset_copy_native (gws, &ws, max + 1);

  plugin->client_perform_task =
      GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                   timeout, grs, gws,
                                   &client_run, plugin);
  GNUNET_NETWORK_fdset_destroy (gws);
  GNUNET_NETWORK_fdset_destroy (grs);
  return GNUNET_OK;
}


/**
 * Task performing curl operations
 *
 * @param cls plugin as closure
 * @param tc gnunet scheduler task context
 */
static void
client_run (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct HTTP_Client_Plugin *plugin = cls;
  int running;
  long http_statuscode;
  CURLMcode mret;

  GNUNET_assert (cls != NULL);

  plugin->client_perform_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  do
  {
    running = 0;
    mret = curl_multi_perform (plugin->curl_multi_handle, &running);

    CURLMsg *msg;
    int msgs_left;

    while ((msg = curl_multi_info_read (plugin->curl_multi_handle, &msgs_left)))
    {
      CURL *easy_h = msg->easy_handle;
      struct Session *s = NULL;
      char *d = (char *) s;

      if (easy_h == NULL)
      {
        GNUNET_break (0);
        GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                         "Client: connection to ended with reason %i: `%s', %i handles running\n",
                         msg->data.result,
                         curl_easy_strerror (msg->data.result), running);
        continue;
      }

      GNUNET_assert (CURLE_OK ==
                     curl_easy_getinfo (easy_h, CURLINFO_PRIVATE, &d));
      s = (struct Session *) d;

      if (GNUNET_YES != client_exist_session(plugin, s))
      {
        GNUNET_break (0);
        return;
      }

      GNUNET_assert (s != NULL);
      if (msg->msg == CURLMSG_DONE)
      {
        curl_easy_getinfo (easy_h, CURLINFO_RESPONSE_CODE, &http_statuscode);
        if (easy_h == s->client_put)
        {
            if  ((0 != msg->data.result) || (http_statuscode != 200))
            {
                GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                  "Session %p/connection %p: PUT connection to `%s' ended with status %i reason %i: `%s'\n",
                  s, msg->easy_handle, GNUNET_i2s (&s->target),
                  http_statuscode,
                  msg->data.result,
                  curl_easy_strerror (msg->data.result));
            }
            else
              GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                "Session %p/connection %p: PUT connection to `%s' ended normal\n",
                s, msg->easy_handle, GNUNET_i2s (&s->target));
            if (s->client_get == NULL)
            {
              /* Disconnect other transmission direction and tell transport */
            }
            curl_multi_remove_handle (plugin->curl_multi_handle, easy_h);
            curl_easy_cleanup (easy_h);
            s->put_tmp_disconnecting = GNUNET_NO;
            s->put_tmp_disconnected = GNUNET_YES;
            s->client_put = NULL;
            s->put.easyhandle = NULL;
            s->put.s = NULL;

            /*
             * Handling a rare case:
             * plugin_send was called during temporary put disconnect,
             * reconnect required after connection was disconnected
             */
            if (GNUNET_YES == s->put_reconnect_required)
            {
                s->put_reconnect_required = GNUNET_NO;
                client_connect_put(s);
            }
        }
        if (easy_h == s->client_get)
        {
            if  ((0 != msg->data.result) || (http_statuscode != 200))
            {
              GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                "Session %p/connection %p: GET connection to `%s' ended with status %i reason %i: `%s'\n",
                s, msg->easy_handle, GNUNET_i2s (&s->target),
                http_statuscode,
                msg->data.result,
                curl_easy_strerror (msg->data.result));

            }
            else
              GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                "Session %p/connection %p: GET connection to `%s' ended normal\n",
                s, msg->easy_handle, GNUNET_i2s (&s->target));
            /* Disconnect other transmission direction and tell transport */
            s->get.easyhandle = NULL;
            s->get.s = NULL;
            client_disconnect (s);
        }
      }
    }
  }
  while (mret == CURLM_CALL_MULTI_PERFORM);
  client_schedule (plugin, GNUNET_NO);
}

static int
client_connect_get (struct Session *s)
{
  CURLMcode mret;
  /* create get connection */
  s->client_get = curl_easy_init ();
  s->get.s = s;
  s->get.easyhandle = s->client_get;
#if VERBOSE_CURL
  curl_easy_setopt (s->client_get, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt (s->client_get, CURLOPT_DEBUGFUNCTION, &client_log);
  curl_easy_setopt (s->client_get, CURLOPT_DEBUGDATA, &s->get);
#endif
#if BUILD_HTTPS
  curl_easy_setopt (s->client_get, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
  curl_easy_setopt (s->client_get, CURLOPT_SSL_VERIFYPEER, 0);
  curl_easy_setopt (s->client_get, CURLOPT_SSL_VERIFYHOST, 0);
#endif
  curl_easy_setopt (s->client_get, CURLOPT_URL, s->url);
  //curl_easy_setopt (s->client_get, CURLOPT_HEADERFUNCTION, &curl_get_header_cb);
  //curl_easy_setopt (s->client_get, CURLOPT_WRITEHEADER, ps);
  curl_easy_setopt (s->client_get, CURLOPT_READFUNCTION, client_send_cb);
  curl_easy_setopt (s->client_get, CURLOPT_READDATA, s);
  curl_easy_setopt (s->client_get, CURLOPT_WRITEFUNCTION, client_receive);
  curl_easy_setopt (s->client_get, CURLOPT_WRITEDATA, s);
  /* No timeout by default, timeout done with session timeout */
  curl_easy_setopt (s->client_get, CURLOPT_TIMEOUT, 0);
  curl_easy_setopt (s->client_get, CURLOPT_PRIVATE, s);
  curl_easy_setopt (s->client_get, CURLOPT_CONNECTTIMEOUT_MS,
                    (long) HTTP_CLIENT_NOT_VALIDATED_TIMEOUT.rel_value);
  curl_easy_setopt (s->client_get, CURLOPT_BUFFERSIZE,
                    2 * GNUNET_SERVER_MAX_MESSAGE_SIZE);
#if CURL_TCP_NODELAY
  curl_easy_setopt (ps->recv_endpoint, CURLOPT_TCP_NODELAY, 1);
#endif
  mret = curl_multi_add_handle (s->plugin->curl_multi_handle, s->client_get);
  if (mret != CURLM_OK)
  {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, s->plugin->name,
                       "Session %p : Failed to add GET handle to multihandle: `%s'\n",
                       s, curl_multi_strerror (mret));
    curl_easy_cleanup (s->client_get);
    s->client_get = NULL;
    s->get.s = NULL;
    s->get.easyhandle = NULL;
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }

  return GNUNET_OK;
}

static int
client_connect_put (struct Session *s)
{
  CURLMcode mret;
  /* create put connection */
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, s->plugin->name,
                       "Session %p : Init PUT handle \n", s);
  s->client_put = curl_easy_init ();
  s->put.s = s;
  s->put.easyhandle = s->client_put;
#if VERBOSE_CURL
  curl_easy_setopt (s->client_put, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt (s->client_put, CURLOPT_DEBUGFUNCTION, &client_log);
  curl_easy_setopt (s->client_put, CURLOPT_DEBUGDATA, &s->put);
#endif
#if BUILD_HTTPS
  curl_easy_setopt (s->client_put, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
  curl_easy_setopt (s->client_put, CURLOPT_SSL_VERIFYPEER, 0);
  curl_easy_setopt (s->client_put, CURLOPT_SSL_VERIFYHOST, 0);
#endif
  curl_easy_setopt (s->client_put, CURLOPT_URL, s->url);
  curl_easy_setopt (s->client_put, CURLOPT_UPLOAD, 1L);
  //curl_easy_setopt (s->client_put, CURLOPT_HEADERFUNCTION, &client_curl_header);
  //curl_easy_setopt (s->client_put, CURLOPT_WRITEHEADER, ps);
  curl_easy_setopt (s->client_put, CURLOPT_READFUNCTION, client_send_cb);
  curl_easy_setopt (s->client_put, CURLOPT_READDATA, s);
  curl_easy_setopt (s->client_put, CURLOPT_WRITEFUNCTION, client_receive_put);
  curl_easy_setopt (s->client_put, CURLOPT_WRITEDATA, s);
  /* No timeout by default, timeout done with session timeout */
  curl_easy_setopt (s->client_put, CURLOPT_TIMEOUT, 0);
  curl_easy_setopt (s->client_put, CURLOPT_PRIVATE, s);
  curl_easy_setopt (s->client_put, CURLOPT_CONNECTTIMEOUT_MS,
                    (long) HTTP_CLIENT_NOT_VALIDATED_TIMEOUT.rel_value);
  curl_easy_setopt (s->client_put, CURLOPT_BUFFERSIZE,
                    2 * GNUNET_SERVER_MAX_MESSAGE_SIZE);
#if CURL_TCP_NODELAY
  curl_easy_setopt (s->client_put, CURLOPT_TCP_NODELAY, 1);
#endif
  mret = curl_multi_add_handle (s->plugin->curl_multi_handle, s->client_put);
  if (mret != CURLM_OK)
  {
   GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, s->plugin->name,
                    "Session %p : Failed to add PUT handle to multihandle: `%s'\n",
                    s, curl_multi_strerror (mret));
    curl_easy_cleanup (s->client_put);
    s->client_put = NULL;
    s->put.easyhandle = NULL;
    s->put.s = NULL;
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

static int
client_connect (struct Session *s)
{

  struct HTTP_Client_Plugin *plugin = s->plugin;
  int res = GNUNET_OK;


  /* create url */
  if (NULL == http_common_plugin_address_to_string (NULL, s->addr, s->addrlen))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Invalid address peer `%s'\n",
                     GNUNET_i2s (&s->target));
    return GNUNET_SYSERR;
  }

  GNUNET_asprintf (&s->url, "%s/%s;%u",
      http_common_plugin_address_to_string (plugin, s->addr, s->addrlen),
                   GNUNET_h2s_full (&plugin->env->my_identity->hashPubKey),
                   plugin->last_tag);

  plugin->last_tag++;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Initiating outbound session peer `%s' using address `%s'\n",
                   GNUNET_i2s (&s->target), s->url);

  if ((GNUNET_SYSERR == client_connect_get (s)) ||
      (GNUNET_SYSERR == client_connect_put (s)))
  {
      GNUNET_break (0);
      return GNUNET_SYSERR;
  }

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
               "Session %p: connected with connections GET %p and PUT %p\n",
               s, s->client_get, s->client_put);

  /* Perform connect */
  plugin->cur_connections += 2;
  GNUNET_STATISTICS_set (plugin->env->stats,
      "# HTTP client connections",
      plugin->cur_connections,
      GNUNET_NO);

  /* Re-schedule since handles have changed */
  if (plugin->client_perform_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (plugin->client_perform_task);
    plugin->client_perform_task = GNUNET_SCHEDULER_NO_TASK;
  }
  plugin->client_perform_task = GNUNET_SCHEDULER_add_now (client_run, plugin);
  return res;
}


/**
 * Creates a new outbound session the transport service will use to send data to the
 * peer
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
  struct Session * s = NULL;
  struct sockaddr *sa;
  struct GNUNET_ATS_Information ats;
  size_t salen = 0;
  int res;

  GNUNET_assert (plugin != NULL);
  GNUNET_assert (address != NULL);
  GNUNET_assert (address->address != NULL);

  /* find existing session */
  s = client_lookup_session (plugin, address);
  if (s != NULL)
    return s;

  if (plugin->max_connections <= plugin->cur_connections)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_WARNING, plugin->name,
                     "Maximum number of connections (%u) reached: "
                     "cannot connect to peer `%s'\n",
                     plugin->max_connections,
                     GNUNET_i2s (&address->peer));
    return NULL;
  }

  ats.type = htonl (GNUNET_ATS_NETWORK_TYPE);
  ats.value = htonl (GNUNET_ATS_NET_UNSPECIFIED);
  sa = http_common_socket_from_address (address->address, address->address_length, &res);

  if (GNUNET_SYSERR == res)
  {
      return NULL;
  }
  else if (GNUNET_YES == res)
  {
      GNUNET_assert (NULL != sa);
      if (AF_INET == sa->sa_family)
      {
          salen = sizeof (struct sockaddr_in);
      }
      else if (AF_INET == sa->sa_family)
      {
          salen = sizeof (struct sockaddr_in6);
      }
      ats = plugin->env->get_address_type (plugin->env->cls, sa, salen);
      GNUNET_free (sa);
  }
  else if (GNUNET_NO == res)
  {
      ats.value = htonl (GNUNET_ATS_COST_WAN);
  }

  if (GNUNET_ATS_NET_UNSPECIFIED == ntohl(ats.value))
  {
      GNUNET_break (0);
      return NULL;
  }

  s = GNUNET_malloc (sizeof (struct Session));
  memcpy (&s->target, &address->peer, sizeof (struct GNUNET_PeerIdentity));
  s->plugin = plugin;
  s->addr = GNUNET_malloc (address->address_length);
  memcpy (s->addr, address->address, address->address_length);
  s->addrlen = address->address_length;
  s->ats_address_network_type = ats.value;
  s->put_paused = GNUNET_NO;
  s->put_tmp_disconnecting = GNUNET_NO;
  s->put_tmp_disconnected = GNUNET_NO;
  client_start_session_timeout (s);

  /* add new session */
  GNUNET_CONTAINER_DLL_insert (plugin->head, plugin->tail, s);

  /* initiate new connection */
  if (GNUNET_SYSERR == client_connect (s))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                     "Cannot connect to peer `%s' address `%s''\n",
                     http_common_plugin_address_to_string (NULL, s->addr, s->addrlen),
                     GNUNET_i2s (&s->target));
    client_delete_session (s);
    return NULL;
  }
  return s;
}


/**
 * Setup http_client plugin
 *
 * @param plugin the plugin handle
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
static int
client_start (struct HTTP_Client_Plugin *plugin)
{
  curl_global_init (CURL_GLOBAL_ALL);
  plugin->curl_multi_handle = curl_multi_init ();

  if (NULL == plugin->curl_multi_handle)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                     _("Could not initialize curl multi handle, failed to start %s plugin!\n"),
                     plugin->name);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}

/**
 * Session was idle, so disconnect it
 */
static void
client_session_timeout (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_assert (NULL != cls);
  struct Session *s = cls;

  s->timeout_task = GNUNET_SCHEDULER_NO_TASK;
  GNUNET_log (TIMEOUT_LOG,
              "Session %p was idle for %llu ms, disconnecting\n",
              s, (unsigned long long) CLIENT_SESSION_TIMEOUT.rel_value);

  /* call session destroy function */
  GNUNET_assert (GNUNET_OK == client_disconnect (s));
}


/**
 * Start session timeout for session s
 *
 * @param s the session
 */
static void
client_start_session_timeout (struct Session *s)
{

 GNUNET_assert (NULL != s);
 GNUNET_assert (GNUNET_SCHEDULER_NO_TASK == s->timeout_task);
 s->timeout_task =  GNUNET_SCHEDULER_add_delayed (CLIENT_SESSION_TIMEOUT,
                                                  &client_session_timeout,
                                                  s);
 GNUNET_log (TIMEOUT_LOG,
             "Timeout for session %p set to %llu ms\n",
             s,  (unsigned long long) CLIENT_SESSION_TIMEOUT.rel_value);
}


/**
 * Increment session timeout due to activity for session s
 *
 * param s the session
 */
static void
client_reschedule_session_timeout (struct Session *s)
{

 GNUNET_assert (NULL != s);
 GNUNET_assert (GNUNET_SCHEDULER_NO_TASK != s->timeout_task);

 GNUNET_SCHEDULER_cancel (s->timeout_task);
 s->timeout_task =  GNUNET_SCHEDULER_add_delayed (CLIENT_SESSION_TIMEOUT,
                                                  &client_session_timeout,
                                                  s);
 GNUNET_log (TIMEOUT_LOG,
             "Timeout rescheduled for session %p set to %llu ms\n",
             s, (unsigned long long) CLIENT_SESSION_TIMEOUT.rel_value);
}


/**
 * Cancel timeout due to activity for session s
 *
 * param s the session
 */
static void
client_stop_session_timeout (struct Session *s)
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
http_client_plugin_address_suggested (void *cls, const void *addr, size_t addrlen)
{
  /* struct Plugin *plugin = cls; */

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
  struct Session *pos;
  struct Session *next;

  if (NULL == api->cls)
  {
    /* Stub shutdown */
    GNUNET_free (api);
    return NULL;
  }

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   _("Shutting down plugin `%s'\n"),
                   plugin->name);


  next = plugin->head;
  while (NULL != (pos = next))
  {
      next = pos->next;
      client_disconnect (pos);
  }
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

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   _("Shutdown for plugin `%s' complete\n"),
                   plugin->name);

  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}


/**
 * Configure plugin
 *
 * @param plugin the plugin handle
 * @return GNUNET_OK on success, GNUNET_SYSERR on failure
 */
static int
client_configure_plugin (struct HTTP_Client_Plugin *plugin)
{
  unsigned long long max_connections;

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
    api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
    api->cls = NULL;
    api->address_to_string = &http_common_plugin_address_to_string;
    api->string_to_address = &http_common_plugin_string_to_address;
    api->address_pretty_printer = &http_common_plugin_address_pretty_printer;
    return api;
  }

  plugin = GNUNET_malloc (sizeof (struct HTTP_Client_Plugin));
  p = plugin;
  plugin->env = env;
  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;
  api->send = &http_client_plugin_send;
  api->disconnect = &http_client_plugin_disconnect;
  api->check_address = &http_client_plugin_address_suggested;
  api->get_session = &http_client_plugin_get_session;
  api->address_to_string = &http_common_plugin_address_to_string;
  api->string_to_address = &http_common_plugin_string_to_address;
  api->address_pretty_printer = &http_common_plugin_address_pretty_printer;


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
