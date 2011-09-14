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

#if VERBOSE_CLIENT
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Client: %X - %s", cls, text);
  }
  return 0;
}
#endif

int
client_disconnect (struct Session *s)
{
  int res = GNUNET_OK;
  CURLMcode mret;

#if DEBUG_HTTP
  GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, s->plugin->name,
                   "Deleting outbound session peer `%s'\n",
                   GNUNET_i2s (&s->target));
#endif

  mret = curl_multi_remove_handle (s->plugin->client_mh, s->client_put);
  if (mret != CURLM_OK)
  {
    curl_easy_cleanup (s->client_put);
    res = GNUNET_SYSERR;
    GNUNET_break (0);
  }
  curl_easy_cleanup (s->client_put);

  mret = curl_multi_remove_handle (s->plugin->client_mh, s->client_get);
  if (mret != CURLM_OK)
  {
    curl_easy_cleanup (s->client_get);
    res = GNUNET_SYSERR;
    GNUNET_break (0);
  }
  curl_easy_cleanup (s->client_get);

  return res;
}

int
client_send (struct Session *s, const char *msgbuf, size_t msgbuf_size)
{
  return GNUNET_OK;
}

int
client_connect (struct Session *s)
{
  int res = GNUNET_OK;
  char *url;
  CURLMcode mret;

#if DEBUG_HTTP
  GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, s->plugin->name,
                   "Initiating outbound session peer `%s'\n",
                   GNUNET_i2s (&s->target));
#endif

  s->inbound = GNUNET_NO;

  /* create url */
  GNUNET_asprintf (&url, "%s://%s/", s->plugin->protocol,
                   http_plugin_address_to_string (NULL, s->addr, s->addrlen));

#if DEBUG_HTTP
  GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, s->plugin->name, "URL `%s'\n", url);
#endif

  /* create get connection */
  s->client_get = curl_easy_init ();
#if VERBOSE_CLIENT
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
  //curl_easy_setopt (s->client_get, CURLOPT_READFUNCTION, curl_send_cb);
  //curl_easy_setopt (s->client_get, CURLOPT_READDATA, ps);
  //curl_easy_setopt (s->client_get, CURLOPT_WRITEFUNCTION, curl_receive_cb);
  //curl_easy_setopt (s->client_get, CURLOPT_WRITEDATA, ps);
  curl_easy_setopt (s->client_get, CURLOPT_TIMEOUT,
                    (long) GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value);
  //curl_easy_setopt (s->client_get, CURLOPT_PRIVATE, ps);
  curl_easy_setopt (s->client_get, CURLOPT_CONNECTTIMEOUT,
                    (long) HTTP_NOT_VALIDATED_TIMEOUT.rel_value);
  curl_easy_setopt (s->client_get, CURLOPT_BUFFERSIZE,
                    2 * GNUNET_SERVER_MAX_MESSAGE_SIZE);
#if CURL_TCP_NODELAY
  curl_easy_setopt (ps->recv_endpoint, CURLOPT_TCP_NODELAY, 1);
#endif

  /* create put connection */
  s->client_put = curl_easy_init ();
#if VERBOSE_CLIENT
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
  //curl_easy_setopt (s->client_put, CURLOPT_READFUNCTION, curl_send_cb);
  //curl_easy_setopt (s->client_put, CURLOPT_READDATA, ps);
  //curl_easy_setopt (s->client_put, CURLOPT_WRITEFUNCTION, curl_receive_cb);
  //curl_easy_setopt (s->client_put, CURLOPT_WRITEDATA, ps);
  curl_easy_setopt (s->client_put, CURLOPT_TIMEOUT,
                    (long) GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value);
  //curl_easy_setopt (s->client_put, CURLOPT_PRIVATE, ps);
  curl_easy_setopt (s->client_put, CURLOPT_CONNECTTIMEOUT,
                    (long) HTTP_NOT_VALIDATED_TIMEOUT.rel_value);
  curl_easy_setopt (s->client_put, CURLOPT_BUFFERSIZE,
                    2 * GNUNET_SERVER_MAX_MESSAGE_SIZE);
#if CURL_TCP_NODELAY
  curl_easy_setopt (s->client_put, CURLOPT_TCP_NODELAY, 1);
#endif

  GNUNET_free (url);

  mret = curl_multi_add_handle (s->plugin->client_mh, s->client_get);
  if (mret != CURLM_OK)
  {
    curl_easy_cleanup (s->client_get);
    res = GNUNET_SYSERR;
    GNUNET_break (0);
  }

  mret = curl_multi_add_handle (s->plugin->client_mh, s->client_put);
  if (mret != CURLM_OK)
  {
    curl_multi_remove_handle (s->plugin->client_mh, s->client_get);
    curl_easy_cleanup (s->client_get);
    curl_easy_cleanup (s->client_put);
    res = GNUNET_SYSERR;
    GNUNET_break (0);
  }

  /* Perform connect */

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
  curl_multi_cleanup (plugin->client_mh);
  curl_global_cleanup ();
}



/* end of plugin_transport_http_client.c */
