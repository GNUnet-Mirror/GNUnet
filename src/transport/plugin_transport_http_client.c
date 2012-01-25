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
 * @brief http transport service plugin
 * @author Matthias Wachs
 */

#include "plugin_transport_http.h"

#if VERBOSE_CURL
/**
 * Function to log curl debug messages with GNUNET_log
 * @param curl handle
 * @param type curl_infotype
 * @param data data
 * @param size size
 * @param cls  closure
 * @return 0
 */
static int
client_log (CURL * curl, curl_infotype type, char *data, size_t size, void *cls)
{
  if (type == CURLINFO_TEXT)
  {
    char text[size + 2];

    memcpy (text, data, size);
    if (text[size - 1] == '\n')
      text[size] = '\0';
    else
    {
      text[size] = '\n';
      text[size + 1] = '\0';
    }
#if BUILD_HTTPS
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "transport-https",
                     "Client: %X - %s", cls, text);
#else
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, "transport-http",
                     "Client: %X - %s", cls, text);
#endif
  }
  return 0;
}
#endif

/**
 * Task performing curl operations
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
client_schedule (struct Plugin *plugin, int now)
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
  mret = curl_multi_fdset (plugin->client_mh, &rs, &ws, &es, &max);
  if (mret != CURLM_OK)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, _("%s failed at %s:%d: `%s'\n"),
                "curl_multi_fdset", __FILE__, __LINE__,
                curl_multi_strerror (mret));
    return GNUNET_SYSERR;
  }
  mret = curl_multi_timeout (plugin->client_mh, &to);
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
                                   GNUNET_SCHEDULER_NO_TASK, timeout, grs, gws,
                                   &client_run, plugin);
  GNUNET_NETWORK_fdset_destroy (gws);
  GNUNET_NETWORK_fdset_destroy (grs);
  return GNUNET_OK;
}


int
client_send (struct Session *s, struct HTTP_Message *msg)
{
  GNUNET_assert (s != NULL);
  GNUNET_CONTAINER_DLL_insert (s->msg_head, s->msg_tail, msg);

  if (s->client_put_paused == GNUNET_YES)
  {
#if VERBOSE_CLIENT
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, s->plugin->name,
                     "Client: %X was suspended, unpausing\n", s->client_put);
#endif
    s->client_put_paused = GNUNET_NO;
    curl_easy_pause (s->client_put, CURLPAUSE_CONT);
  }

  client_schedule (s->plugin, GNUNET_YES);

  return GNUNET_OK;
}



/**
 * Task performing curl operations
 * @param cls plugin as closure
 * @param tc gnunet scheduler task context
 */
static void
client_run (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Plugin *plugin = cls;
  int running;
  CURLMcode mret;

  GNUNET_assert (cls != NULL);

  plugin->client_perform_task = GNUNET_SCHEDULER_NO_TASK;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  do
  {
    running = 0;
    mret = curl_multi_perform (plugin->client_mh, &running);

    CURLMsg *msg;
    int msgs_left;

    while ((msg = curl_multi_info_read (plugin->client_mh, &msgs_left)))
    {
      CURL *easy_h = msg->easy_handle;
      struct Session *s = NULL;
      char *d = (char *) s;


      //GNUNET_assert (easy_h != NULL);
      if (easy_h == NULL)
      {
        GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                         "Client: connection to ended with reason %i: `%s', %i handles running\n",
                         msg->data.result,
                         curl_easy_strerror (msg->data.result), running);
        continue;
      }

      GNUNET_assert (CURLE_OK ==
                     curl_easy_getinfo (easy_h, CURLINFO_PRIVATE, &d));
      s = (struct Session *) d;
      GNUNET_assert (s != NULL);

      if (msg->msg == CURLMSG_DONE)
      {
        GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                         "Client: %X connection to '%s'  %s ended with reason %i: `%s'\n",
                         msg->easy_handle, GNUNET_i2s (&s->target),
                         http_plugin_address_to_string (NULL, s->addr,
                                                        s->addrlen),
                         msg->data.result,
                         curl_easy_strerror (msg->data.result));

        client_disconnect (s);
        //GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,"Notifying about ended session to peer `%s' `%s'\n", GNUNET_i2s (&s->target), http_plugin_address_to_string (plugin, s->addr, s->addrlen));
        notify_session_end (plugin, &s->target, s);
      }
    }
  }
  while (mret == CURLM_CALL_MULTI_PERFORM);
  client_schedule (plugin, GNUNET_NO);
}

int
client_disconnect (struct Session *s)
{
  int res = GNUNET_OK;
  CURLMcode mret;
  struct Plugin *plugin = s->plugin;
  struct HTTP_Message *msg;
  struct HTTP_Message *t;



  if (s->client_put != NULL)
  {
#if DEBUG_HTTP
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Client: %X Deleting outbound PUT session to peer `%s'\n",
                     s->client_put, GNUNET_i2s (&s->target));
#endif

    mret = curl_multi_remove_handle (plugin->client_mh, s->client_put);
    if (mret != CURLM_OK)
    {
      curl_easy_cleanup (s->client_put);
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
#if DEBUG_HTTP
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Client: %X Deleting outbound GET session to peer `%s'\n",
                     s->client_get, GNUNET_i2s (&s->target));
#endif

    mret = curl_multi_remove_handle (plugin->client_mh, s->client_get);
    if (mret != CURLM_OK)
    {
      curl_easy_cleanup (s->client_get);
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
      msg->transmit_cont (msg->transmit_cont_cls, &s->target, GNUNET_SYSERR);
    GNUNET_CONTAINER_DLL_remove (s->msg_head, s->msg_tail, msg);
    GNUNET_free (msg);
    msg = t;
  }

  plugin->cur_connections -= 2;
  /* Re-schedule since handles have changed */
  if (plugin->client_perform_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (plugin->client_perform_task);
    plugin->client_perform_task = GNUNET_SCHEDULER_NO_TASK;
  }

  client_schedule (plugin, GNUNET_YES);

  return res;
}

static void
client_receive_mst_cb (void *cls, void *client,
                       const struct GNUNET_MessageHeader *message)
{
  struct Session *s = cls;
  struct GNUNET_TIME_Relative delay;

  delay = http_plugin_receive (s, &s->target, message, s, s->addr, s->addrlen);
  s->next_receive =
      GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get (), delay);

  if (GNUNET_TIME_absolute_get ().abs_value < s->next_receive.abs_value)
  {
#if VERBOSE_CLIENT
    struct Plugin *plugin = s->plugin;

    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Client: peer `%s' address `%s' next read delayed for %llu ms\n",
                     GNUNET_i2s (&s->target), GNUNET_a2s (s->addr, s->addrlen),
                     delay);
#endif
  }
}

static void
client_wake_up (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct Session *s = cls;

  s->recv_wakeup_task = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, s->plugin->name,
                   "Client: %X Waking up receive handle\n", s->client_get);

  if (s->client_get != NULL)
    curl_easy_pause (s->client_get, CURLPAUSE_CONT);

}

/**
* Callback method used with libcurl
* Method is called when libcurl needs to write data during sending
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


#if VERBOSE_CLIENT
  struct Plugin *plugin = s->plugin;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Client: Received %Zu bytes from peer `%s'\n", len,
                   GNUNET_i2s (&s->target));
#endif

  now = GNUNET_TIME_absolute_get ();
  if (now.abs_value < s->next_receive.abs_value)
  {
    struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();
    struct GNUNET_TIME_Relative delta =
        GNUNET_TIME_absolute_get_difference (now, s->next_receive);
#if DEBUG_CLIENT
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Client: %X No inbound bandwidth available! Next read was delayed for %llu ms\n",
                     s->client_get, delta.rel_value);
#endif
    if (s->recv_wakeup_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (s->recv_wakeup_task);
      s->recv_wakeup_task = GNUNET_SCHEDULER_NO_TASK;
    }
    s->recv_wakeup_task =
        GNUNET_SCHEDULER_add_delayed (delta, &client_wake_up, s);
    return CURLPAUSE_ALL;
  }


  if (s->msg_tk == NULL)
    s->msg_tk = GNUNET_SERVER_mst_create (&client_receive_mst_cb, s);

  GNUNET_SERVER_mst_receive (s->msg_tk, s, stream, len, GNUNET_NO, GNUNET_NO);

  return len;
}

/**
 * Callback method used with libcurl
 * Method is called when libcurl needs to read data during sending
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

#if VERBOSE_CLIENT
  struct Plugin *plugin = s->plugin;
#endif
  size_t bytes_sent = 0;
  size_t len;

  struct HTTP_Message *msg = s->msg_head;

  if (msg == NULL)
  {
#if VERBOSE_CLIENT
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Client: %X Nothing to send! Suspending PUT handle!\n",
                     s->client_put);
#endif
    s->client_put_paused = GNUNET_YES;
    return CURL_READFUNC_PAUSE;
  }

  GNUNET_assert (msg != NULL);
  /* data to send */
  if (msg->pos < msg->size)
  {
    /* data fit in buffer */
    if ((msg->size - msg->pos) <= (size * nmemb))
    {
      len = (msg->size - msg->pos);
      memcpy (stream, &msg->buf[msg->pos], len);
      msg->pos += len;
      bytes_sent = len;
    }
    else
    {
      len = size * nmemb;
      memcpy (stream, &msg->buf[msg->pos], len);
      msg->pos += len;
      bytes_sent = len;
    }
  }
  /* no data to send */
  else
  {
    GNUNET_assert (0);
    bytes_sent = 0;
  }

  if (msg->pos == msg->size)
  {
#if VERBOSE_CLIENT
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Client: %X Message with %u bytes sent, removing message from queue\n",
                     s->client_put, msg->size, msg->pos);
#endif
    /* Calling transmit continuation  */
    if (NULL != msg->transmit_cont)
      msg->transmit_cont (msg->transmit_cont_cls, &s->target, GNUNET_OK);
    GNUNET_CONTAINER_DLL_remove (s->msg_head, s->msg_tail, msg);
    GNUNET_free (msg);
  }
  return bytes_sent;
}

int
client_connect (struct Session *s)
{
  struct Plugin *plugin = s->plugin;
  int res = GNUNET_OK;
  char *url;
  CURLMcode mret;

#if VERBOSE_CLIENT
#endif
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Initiating outbound session peer `%s'\n",
                   GNUNET_i2s (&s->target));


  s->inbound = GNUNET_NO;

  plugin->last_tag++;
  /* create url */
  GNUNET_asprintf (&url, "%s%s;%u",
                   http_plugin_address_to_string (plugin, s->addr, s->addrlen),
                   GNUNET_h2s_full (&plugin->env->my_identity->hashPubKey),
                   plugin->last_tag);
#if 0
  GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name, "URL `%s'\n", url);
#endif
  /* create get connection */
  s->client_get = curl_easy_init ();
#if VERBOSE_CURL
  curl_easy_setopt (s->client_get, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt (s->client_get, CURLOPT_DEBUGFUNCTION, &client_log);
  curl_easy_setopt (s->client_get, CURLOPT_DEBUGDATA, s->client_get);
#endif
#if BUILD_HTTPS
  curl_easy_setopt (s->client_get, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
  curl_easy_setopt (s->client_get, CURLOPT_SSL_VERIFYPEER, 0);
  curl_easy_setopt (s->client_get, CURLOPT_SSL_VERIFYHOST, 0);
#endif
  curl_easy_setopt (s->client_get, CURLOPT_URL, url);
  //curl_easy_setopt (s->client_get, CURLOPT_HEADERFUNCTION, &curl_get_header_cb);
  //curl_easy_setopt (s->client_get, CURLOPT_WRITEHEADER, ps);
  curl_easy_setopt (s->client_get, CURLOPT_READFUNCTION, client_send_cb);
  curl_easy_setopt (s->client_get, CURLOPT_READDATA, s);
  curl_easy_setopt (s->client_get, CURLOPT_WRITEFUNCTION, client_receive);
  curl_easy_setopt (s->client_get, CURLOPT_WRITEDATA, s);
  curl_easy_setopt (s->client_get, CURLOPT_TIMEOUT_MS,
                    (long) GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value);
  curl_easy_setopt (s->client_get, CURLOPT_PRIVATE, s);
  curl_easy_setopt (s->client_get, CURLOPT_CONNECTTIMEOUT_MS,
                    (long) HTTP_NOT_VALIDATED_TIMEOUT.rel_value);
  curl_easy_setopt (s->client_get, CURLOPT_BUFFERSIZE,
                    2 * GNUNET_SERVER_MAX_MESSAGE_SIZE);
#if CURL_TCP_NODELAY
  curl_easy_setopt (ps->recv_endpoint, CURLOPT_TCP_NODELAY, 1);
#endif

  /* create put connection */
  s->client_put = curl_easy_init ();
#if VERBOSE_CURL
  curl_easy_setopt (s->client_put, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt (s->client_put, CURLOPT_DEBUGFUNCTION, &client_log);
  curl_easy_setopt (s->client_put, CURLOPT_DEBUGDATA, s->client_put);
#endif
#if BUILD_HTTPS
  curl_easy_setopt (s->client_put, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1);
  curl_easy_setopt (s->client_put, CURLOPT_SSL_VERIFYPEER, 0);
  curl_easy_setopt (s->client_put, CURLOPT_SSL_VERIFYHOST, 0);
#endif
  curl_easy_setopt (s->client_put, CURLOPT_URL, url);
  curl_easy_setopt (s->client_put, CURLOPT_PUT, 1L);
  //curl_easy_setopt (s->client_put, CURLOPT_HEADERFUNCTION, &curl_put_header_cb);
  //curl_easy_setopt (s->client_put, CURLOPT_WRITEHEADER, ps);
  curl_easy_setopt (s->client_put, CURLOPT_READFUNCTION, client_send_cb);
  curl_easy_setopt (s->client_put, CURLOPT_READDATA, s);
  curl_easy_setopt (s->client_put, CURLOPT_WRITEFUNCTION, client_receive);
  curl_easy_setopt (s->client_put, CURLOPT_WRITEDATA, s);
  curl_easy_setopt (s->client_put, CURLOPT_TIMEOUT_MS,
                    (long) GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value);
  curl_easy_setopt (s->client_put, CURLOPT_PRIVATE, s);
  curl_easy_setopt (s->client_put, CURLOPT_CONNECTTIMEOUT_MS,
                    (long) HTTP_NOT_VALIDATED_TIMEOUT.rel_value);
  curl_easy_setopt (s->client_put, CURLOPT_BUFFERSIZE,
                    2 * GNUNET_SERVER_MAX_MESSAGE_SIZE);
#if CURL_TCP_NODELAY
  curl_easy_setopt (s->client_put, CURLOPT_TCP_NODELAY, 1);
#endif

  GNUNET_free (url);

  mret = curl_multi_add_handle (plugin->client_mh, s->client_get);
  if (mret != CURLM_OK)
  {
    curl_easy_cleanup (s->client_get);
    res = GNUNET_SYSERR;
    GNUNET_break (0);
  }

  mret = curl_multi_add_handle (plugin->client_mh, s->client_put);
  if (mret != CURLM_OK)
  {
    curl_multi_remove_handle (plugin->client_mh, s->client_get);
    curl_easy_cleanup (s->client_get);
    curl_easy_cleanup (s->client_put);
    res = GNUNET_SYSERR;
    GNUNET_break (0);
  }

  /* Perform connect */
  plugin->cur_connections += 2;

  /* Re-schedule since handles have changed */
  if (plugin->client_perform_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (plugin->client_perform_task);
    plugin->client_perform_task = GNUNET_SCHEDULER_NO_TASK;
  }
  plugin->client_perform_task = GNUNET_SCHEDULER_add_now (client_run, plugin);

  return res;
}

int
client_start (struct Plugin *plugin)
{
  int res = GNUNET_OK;

  curl_global_init (CURL_GLOBAL_ALL);
  plugin->client_mh = curl_multi_init ();

  if (NULL == plugin->client_mh)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                     _
                     ("Could not initialize curl multi handle, failed to start %s plugin!\n"),
                     plugin->name);
    res = GNUNET_SYSERR;
  }
  return res;
}

void
client_stop (struct Plugin *plugin)
{
  if (plugin->client_perform_task != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel (plugin->client_perform_task);
    plugin->client_perform_task = GNUNET_SCHEDULER_NO_TASK;
  }

  curl_multi_cleanup (plugin->client_mh);
  curl_global_cleanup ();
}



/* end of plugin_transport_http_client.c */
