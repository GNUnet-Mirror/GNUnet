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
 * @file transport/plugin_transport_http.c
 * @brief http transport service plugin
 * @author Matthias Wachs
 */

#include "plugin_transport_http.h"

#define HTTP_ERROR_RESPONSE "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\"><HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD><BODY><H1>Not Found</H1>The requested URL was not found on this server.<P><HR><ADDRESS></ADDRESS></BODY></HTML>"
#define _RECEIVE 0
#define _SEND 1

struct ServerConnection
{
  /* _RECV or _SEND */
  int direction;

  /* should this connection get disconnected? GNUNET_YES/NO  */
  int disconnect;

  struct Session *session;
  struct MHD_Connection *mhd_conn;
};

/**
 * Function that queries MHD's select sets and
 * starts the task waiting for them.
 * @param plugin plugin
 * @param daemon_handle the MHD daemon handle
 * @param now schedule now or with MHD delay
 * @return gnunet task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier
server_schedule (struct Plugin *plugin,
                 struct MHD_Daemon *daemon_handle,
                 int now);

static void
server_log (void *arg, const char *fmt, va_list ap)
{
  char text[1024];

  vsnprintf (text, sizeof (text), fmt, ap);
  va_end (ap);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Server: %s\n", text);
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
  struct Plugin *plugin = cls;

  if (plugin->cur_connections <= plugin->max_connections)
    return MHD_YES;
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Server: Cannot accept new connections\n");
    return MHD_NO;
  }
}


#if BUILD_HTTPS
static char *
server_load_file (const char *file)
{
  struct GNUNET_DISK_FileHandle *gn_file;
  struct stat fstat;
  char *text = NULL;

  if (0 != STAT (file, &fstat))
    return NULL;
  text = GNUNET_malloc (fstat.st_size + 1);
  gn_file =
      GNUNET_DISK_file_open (file, GNUNET_DISK_OPEN_READ,
                             GNUNET_DISK_PERM_USER_READ);
  if (gn_file == NULL)
  {
    GNUNET_free (text);
    return NULL;
  }
  if (GNUNET_SYSERR == GNUNET_DISK_file_read (gn_file, text, fstat.st_size))
  {
    GNUNET_free (text);
    GNUNET_DISK_file_close (gn_file);
    return NULL;
  }
  text[fstat.st_size] = '\0';
  GNUNET_DISK_file_close (gn_file);
  return text;
}
#endif


#if BUILD_HTTPS

static int
server_load_certificate (struct Plugin *plugin)
{
  int res = GNUNET_OK;

  char *key_file;
  char *cert_file;

  /* Get crypto init string from config
   * If not present just use default values */

  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CONFIGURATION_get_value_string (plugin->env->cfg,
                                                        plugin->name,
                                                        "CRYPTO_INIT",
                                                        &plugin->crypto_init));

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
              "Loading TLS certificate from key-file `%s' cert-file`%s'\n",
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

#if VERBOSE_SERVER
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No usable TLS certificate found, creating certificate\n");
#endif
    errno = 0;
    cert_creation =
        GNUNET_OS_start_process (GNUNET_NO, NULL, NULL,
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
    GNUNET_OS_process_close (cert_creation);

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
#if DEBUG_HTTP
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "TLS certificate loaded\n");
#endif

  return res;
}
#endif


/**
 * Reschedule the execution of both IPv4 and IPv6 server
 * @param plugin the plugin
 * @param server which server to schedule v4 or v6?
 * @param now GNUNET_YES to schedule execution immediately, GNUNET_NO to wait
 * until timeout
 */

static void
server_reschedule (struct Plugin *plugin, struct MHD_Daemon *server, int now)
{
  if ((server == plugin->server_v4) && (plugin->server_v4 != NULL))
  {
    if (plugin->server_v4_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (plugin->server_v4_task);
      plugin->server_v4_task = GNUNET_SCHEDULER_NO_TASK;
    }
    plugin->server_v4_task = server_schedule (plugin, plugin->server_v4, now);
  }

  if ((server == plugin->server_v6) && (plugin->server_v6 != NULL))
  {
    if (plugin->server_v6_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (plugin->server_v6_task);
      plugin->server_v6_task = GNUNET_SCHEDULER_NO_TASK;
    }
    plugin->server_v6_task = server_schedule (plugin, plugin->server_v6, now);
  }
}

/**
 * Callback called by MessageStreamTokenizer when a message has arrived
 * @param cls current session as closure
 * @param client clien
 * @param message the message to be forwarded to transport service
 */
static void
server_receive_mst_cb (void *cls, void *client,
                       const struct GNUNET_MessageHeader *message)
{
  struct Session *s = cls;
  struct Plugin *plugin = s->plugin;
  struct GNUNET_TIME_Relative delay;

  delay = http_plugin_receive (s, &s->target, message, s, s->addr, s->addrlen);

  s->next_receive =
      GNUNET_TIME_absolute_add (GNUNET_TIME_absolute_get (), delay);

  if (delay.rel_value > 0)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Server: peer `%s' address `%s' next read delayed for %llu ms\n",
                     GNUNET_i2s (&s->target),
                     http_plugin_address_to_string (NULL, s->addr, s->addrlen),
                     delay);
  }
}

/**
 * Callback called by MHD when it needs data to send
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

  struct HTTP_Message *msg;
  int bytes_read = 0;

  //static int c = 0;
  msg = s->msg_head;
  if (msg != NULL)
  {
    /* sending */
    if ((msg->size - msg->pos) <= max)
    {
      memcpy (buf, &msg->buf[msg->pos], (msg->size - msg->pos));
      bytes_read = msg->size - msg->pos;
      msg->pos += (msg->size - msg->pos);
    }
    else
    {
      memcpy (buf, &msg->buf[msg->pos], max);
      msg->pos += max;
      bytes_read = max;
    }

    /* removing message */
    if (msg->pos == msg->size)
    {
      if (NULL != msg->transmit_cont)
        msg->transmit_cont (msg->transmit_cont_cls, &s->target, GNUNET_OK);
      GNUNET_CONTAINER_DLL_remove (s->msg_head, s->msg_tail, msg);
      GNUNET_free (msg);
    }
  }

  struct Plugin *plugin = s->plugin;
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Server: %X: sent %u bytes\n", s, bytes_read);

  return bytes_read;
}

static struct ServerConnection *
server_lookup_session (struct Plugin *plugin,
                       struct MHD_Connection *mhd_connection, const char *url,
                       const char *method)
{
  struct Session *s = NULL;
  struct Session *t;
  struct ServerConnection *sc = NULL;
  const union MHD_ConnectionInfo *conn_info;
  struct GNUNET_ATS_Information ats;
  struct IPv4HttpAddress a4;
  struct IPv6HttpAddress a6;
  struct sockaddr_in *s4;
  struct sockaddr_in6 *s6;
  void *a;
  size_t a_len;
  struct GNUNET_PeerIdentity target;
  int check = GNUNET_NO;
  uint32_t tag = 0;
  int direction = GNUNET_SYSERR;

  conn_info =
      MHD_get_connection_info (mhd_connection,
                               MHD_CONNECTION_INFO_CLIENT_ADDRESS);
  if ((conn_info->client_addr->sa_family != AF_INET) &&
      (conn_info->client_addr->sa_family != AF_INET6))
    return MHD_NO;

  if ((strlen (&url[1]) >= 105) && (url[104] == ';'))
  {
    char hash[104];
    char *tagc = (char *) &url[105];

    memcpy (&hash, &url[1], 103);
    hash[103] = '\0';
    if (GNUNET_OK ==
        GNUNET_CRYPTO_hash_from_string ((const char *) &hash,
                                        &(target.hashPubKey)))
    {
      tag = strtoul (tagc, NULL, 10);
      if (tagc > 0)
        check = GNUNET_YES;
    }
  }

  if (0 == strcmp (MHD_HTTP_METHOD_PUT, method))
    direction = _RECEIVE;
  else if (0 == strcmp (MHD_HTTP_METHOD_GET, method))
    direction = _SEND;
  else
  {
    GNUNET_break_op (0);
    goto error;
  }


  if (check == GNUNET_NO)
    goto error;

  plugin->cur_connections++;
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Server: New inbound connection from %s with tag %u\n",
                   GNUNET_i2s (&target), tag);
  /* find duplicate session */

  t = plugin->head;

  while (t != NULL)
  {
    if ((t->inbound) &&
        (0 == memcmp (&t->target, &target, sizeof (struct GNUNET_PeerIdentity)))
        &&
        /* FIXME add source address comparison */
        (t->tag == tag))
      break;
    t = t->next;
  }
  if (t != NULL)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Server: Duplicate session, dismissing new connection from peer `%s'\n",
                     GNUNET_i2s (&target));
    goto error;
  }

  /* find semi-session */
  t = plugin->server_semi_head;

  while (t != NULL)
  {
    /* FIXME add source address comparison */
    if ((0 == memcmp (&t->target, &target, sizeof (struct GNUNET_PeerIdentity)))
        && (t->tag == tag))
    {
      break;
    }
    t = t->next;
  }

  if (t == NULL)
    goto create;
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Server: Found existing semi-session for `%s'\n",
                   GNUNET_i2s (&target));

  if ((direction == _SEND) && (t->server_send != NULL))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Server: Duplicate GET session, dismissing new connection from peer `%s'\n",
                     GNUNET_i2s (&target));
    goto error;
  }
  else
  {
    s = t;
    GNUNET_CONTAINER_DLL_remove (plugin->server_semi_head,
                                 plugin->server_semi_tail, s);
    GNUNET_CONTAINER_DLL_insert (plugin->head, plugin->tail, s);
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Server: Found matching semi-session, merging session for peer `%s'\n",
                     GNUNET_i2s (&target));

    goto found;
  }
  if ((direction == _RECEIVE) && (t->server_recv != NULL))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Server: Duplicate PUT session, dismissing new connection from peer `%s'\n",
                     GNUNET_i2s (&target));
    goto error;
  }
  else
  {
    s = t;
    GNUNET_CONTAINER_DLL_remove (plugin->server_semi_head,
                                 plugin->server_semi_tail, s);
    GNUNET_CONTAINER_DLL_insert (plugin->head, plugin->tail, s);
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Server: Found matching semi-session, merging session for peer `%s'\n",
                     GNUNET_i2s (&target));
    goto found;
  }

create:
/* create new session */
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Server: Creating new session for peer `%s' \n",
                   GNUNET_i2s (&target));
  switch (conn_info->client_addr->sa_family)
  {
  case (AF_INET):
    s4 = ((struct sockaddr_in *) conn_info->client_addr);
    a4.u4_port = s4->sin_port;
    memcpy (&a4.ipv4_addr, &s4->sin_addr, sizeof (struct in_addr));
    a = &a4;
    a_len = sizeof (struct IPv4HttpAddress);
    ats = plugin->env->get_address_type (plugin->env->cls, (const struct sockaddr *) s4, sizeof (struct sockaddr_in));
    break;
  case (AF_INET6):
    s6 = ((struct sockaddr_in6 *) conn_info->client_addr);
    a6.u6_port = s6->sin6_port;
    memcpy (&a6.ipv6_addr, &s6->sin6_addr, sizeof (struct in6_addr));
    a = &a6;
    a_len = sizeof (struct IPv6HttpAddress);
    ats = plugin->env->get_address_type (plugin->env->cls, (const struct sockaddr *) s6, sizeof (struct sockaddr_in6));
    break;
  default:
    GNUNET_break (0);
    goto error;
  }
  s = create_session (plugin, &target, a, a_len, NULL, NULL);
  s->ats_address_network_type = ats.value;

  s->inbound = GNUNET_YES;
  s->next_receive = GNUNET_TIME_absolute_get_zero ();
  s->tag = tag;
  if (0 == strcmp (MHD_HTTP_METHOD_PUT, method))
    s->server_recv = s;
  if (0 == strcmp (MHD_HTTP_METHOD_GET, method))
    s->server_send = s;
  GNUNET_CONTAINER_DLL_insert (plugin->server_semi_head,
                               plugin->server_semi_tail, s);
  goto found;

error:
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Server: Invalid connection request\n");
  return NULL;

found:
  sc = GNUNET_malloc (sizeof (struct ServerConnection));
  sc->mhd_conn = mhd_connection;
  sc->direction = direction;
  sc->session = s;
  if (direction == _SEND)
    s->server_send = sc;
  if (direction == _RECEIVE)
    s->server_recv = sc;

#if MHD_VERSION >= 0x00090E00
  int to = (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value / 1000);

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Server: Setting timeout for %X to %u sec.\n", sc, to);
  MHD_set_connection_option (mhd_connection, MHD_CONNECTION_OPTION_TIMEOUT, to);

  struct MHD_Daemon *d = NULL;

  if (s->addrlen == sizeof (struct IPv6HttpAddress))
    d = plugin->server_v6;
  if (s->addrlen == sizeof (struct IPv4HttpAddress))
    d = plugin->server_v4;

  server_reschedule (plugin, d, GNUNET_NO);
#endif
  return sc;
}

/**
 * Process GET or PUT request received via MHD.  For
 * GET, queue response that will send back our pending
 * messages.  For PUT, process incoming data and send
 * to GNUnet core.  In either case, check if a session
 * already exists and create a new one if not.
 */
static int
server_access_cb (void *cls, struct MHD_Connection *mhd_connection,
                  const char *url, const char *method, const char *version,
                  const char *upload_data, size_t * upload_data_size,
                  void **httpSessionCache)
{

  struct Plugin *plugin = cls;
  struct ServerConnection *sc = *httpSessionCache;
  struct Session *s = NULL;

  int res = MHD_YES;
  struct MHD_Response *response;

  GNUNET_assert (cls != NULL);
  /* new connection */
  if (sc == NULL)
  {
    sc = server_lookup_session (plugin, mhd_connection, url, method);
    if (sc != NULL)
      (*httpSessionCache) = sc;
    else
    {
      response =
          MHD_create_response_from_data (strlen (HTTP_ERROR_RESPONSE),
                                         HTTP_ERROR_RESPONSE, MHD_NO, MHD_NO);
      res = MHD_queue_response (mhd_connection, MHD_HTTP_NOT_FOUND, response);
      MHD_destroy_response (response);
      return res;
    }
  }

  /* existing connection */
  sc = (*httpSessionCache);
  s = sc->session;

  /* connection is to be disconnected */
  if (sc->disconnect == GNUNET_YES)
  {
    /* Sent HTTP/1.1: 200 OK as PUT Response\ */
    response =
        MHD_create_response_from_data (strlen ("Thank you!"), "Thank you!",
                                       MHD_NO, MHD_NO);
    res = MHD_queue_response (mhd_connection, MHD_HTTP_OK, response);
    MHD_destroy_response (response);
    return MHD_YES;
  }

  GNUNET_assert (s != NULL);
  /* Check if both directions are connected */
  if ((sc->session->server_recv == NULL) || (sc->session->server_send == NULL))
  {
    /* Delayed read from since not both semi-connections are connected */
    return MHD_YES;
  }

  if (sc->direction == _SEND)
  {
    response =
        MHD_create_response_from_callback (-1, 32 * 1024, &server_send_callback,
                                           s, NULL);
    MHD_queue_response (mhd_connection, MHD_HTTP_OK, response);
    MHD_destroy_response (response);
    return MHD_YES;
  }
  if (sc->direction == _RECEIVE)
  {
    if (*upload_data_size == 0)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                       "Server: Peer `%s' PUT on address `%s' connected\n",
                       GNUNET_i2s (&s->target),
                       http_plugin_address_to_string (NULL, s->addr,
                                                      s->addrlen));
      return MHD_YES;
    }

    /* Receiving data */
    if ((*upload_data_size > 0))
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                       "Server: peer `%s' PUT on address `%s' received %u bytes\n",
                       GNUNET_i2s (&s->target),
                       http_plugin_address_to_string (NULL, s->addr,
                                                      s->addrlen),
                       *upload_data_size);
      struct GNUNET_TIME_Absolute now = GNUNET_TIME_absolute_get ();

      if ((s->next_receive.abs_value <= now.abs_value))
      {
        GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                         "Server: %X: PUT with %u bytes forwarded to MST\n", s,
                         *upload_data_size);
        if (s->msg_tk == NULL)
        {
          s->msg_tk = GNUNET_SERVER_mst_create (&server_receive_mst_cb, s);
        }
            GNUNET_SERVER_mst_receive (s->msg_tk, s, upload_data,
                                       *upload_data_size, GNUNET_NO, GNUNET_NO);

#if MHD_VERSION >= 0x00090E00
        int to = (GNUNET_CONSTANTS_IDLE_CONNECTION_TIMEOUT.rel_value / 1000);
        struct ServerConnection *t = NULL;

        GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                         "Server: Received %u bytes\n", *upload_data_size);
        /* Setting timeouts for other connections */
        if (s->server_recv != NULL)
        {
          t = s->server_recv;
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                           "Server: Setting timeout for %X to %u sec.\n", t,
                           to);
          MHD_set_connection_option (t->mhd_conn, MHD_CONNECTION_OPTION_TIMEOUT,
                                     to);
        }
        if (s->server_send != NULL)
        {
          t = s->server_send;
          GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                           "Server: Setting timeout for %X to %u sec.\n", t,
                           to);
          MHD_set_connection_option (t->mhd_conn, MHD_CONNECTION_OPTION_TIMEOUT,
                                     to);
        }
        struct MHD_Daemon *d = NULL;

        if (s->addrlen == sizeof (struct IPv6HttpAddress))
          d = plugin->server_v6;
        if (s->addrlen == sizeof (struct IPv4HttpAddress))
          d = plugin->server_v4;
        server_reschedule (plugin, d, GNUNET_NO);
#endif
        (*upload_data_size) = 0;
      }
      else
      {
        GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                    "Server: %X no inbound bandwidth available! Next read was delayed by %llu ms\n",
                    s, now.abs_value - s->next_receive.abs_value);
      }
      return MHD_YES;
    }
    else
      return MHD_NO;
  }
  return res;
}

static void
server_disconnect_cb (void *cls, struct MHD_Connection *connection,
                      void **httpSessionCache)
{
  struct ServerConnection *sc = *httpSessionCache;
  struct ServerConnection *tc = NULL;
  struct Session *s = NULL;
  struct Session *t = NULL;
  struct Plugin *plugin = NULL;

  if (sc == NULL)
    return;

  s = sc->session;
  plugin = s->plugin;
  if (sc->direction == _SEND)
  {

    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Server: %X peer `%s' GET on address `%s' disconnected\n",
                     s->server_send, GNUNET_i2s (&s->target),
                     http_plugin_address_to_string (NULL, s->addr, s->addrlen));

    s->server_send = NULL;

    if (s->server_recv != NULL)
    {
      tc = s->server_recv;
      tc->disconnect = GNUNET_YES;
#if MHD_VERSION >= 0x00090E00
      MHD_set_connection_option (sc->mhd_conn, MHD_CONNECTION_OPTION_TIMEOUT,
                                 1);
#endif
    }
  }
  if (sc->direction == _RECEIVE)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Server: %X peer `%s' PUT on address `%s' disconnected\n",
                     s->server_recv, GNUNET_i2s (&s->target),
                     http_plugin_address_to_string (NULL, s->addr, s->addrlen));
    s->server_recv = NULL;
    if (s->server_send != NULL)
    {
      tc = s->server_send;
      tc->disconnect = GNUNET_YES;
#if MHD_VERSION >= 0x00090E00
      MHD_set_connection_option (sc->mhd_conn, MHD_CONNECTION_OPTION_TIMEOUT,
                                 1);
#endif
    }
    if (s->msg_tk != NULL)
    {
      GNUNET_SERVER_mst_destroy (s->msg_tk);
      s->msg_tk = NULL;
    }
  }
  GNUNET_free (sc);

  t = plugin->server_semi_head;
  while (t != NULL)
  {
    if (t == s)
    {
      GNUNET_CONTAINER_DLL_remove (plugin->server_semi_head,
                                   plugin->server_semi_tail, s);
      GNUNET_CONTAINER_DLL_insert (plugin->head, plugin->tail, s);
      break;
    }
    t = t->next;
  }
  plugin->cur_connections--;

  struct MHD_Daemon *d = NULL;

  if (s->addrlen == sizeof (struct IPv6HttpAddress))
    d = plugin->server_v6;
  if (s->addrlen == sizeof (struct IPv4HttpAddress))
    d = plugin->server_v4;
  server_reschedule (plugin, d, GNUNET_NO);

  if ((s->server_send == NULL) && (s->server_recv == NULL))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Server: peer `%s' on address `%s' disconnected\n",
                     GNUNET_i2s (&s->target),
                     http_plugin_address_to_string (NULL, s->addr, s->addrlen));
    if (s->msg_tk != NULL)
    {
      GNUNET_SERVER_mst_destroy (s->msg_tk);
      s->msg_tk = NULL;
    }

    notify_session_end (s->plugin, &s->target, s);
  }
}

int
server_disconnect (struct Session *s)
{
  struct Plugin *plugin = s->plugin;
  struct Session *t = plugin->head;

  while (t != NULL)
  {
    if (t->inbound == GNUNET_YES)
    {
      if (t->server_send != NULL)
      {
        ((struct ServerConnection *) t->server_send)->disconnect = GNUNET_YES;
      }
      if (t->server_send != NULL)
      {
        ((struct ServerConnection *) t->server_send)->disconnect = GNUNET_YES;
      }
    }
    t = t->next;
  }
  return GNUNET_OK;
}

int
server_send (struct Session *s, struct HTTP_Message *msg)
{
  GNUNET_CONTAINER_DLL_insert (s->msg_head, s->msg_tail, msg);

  if (s->addrlen == sizeof (struct IPv4HttpAddress))
  {
    server_reschedule (s->plugin, s->plugin->server_v4, GNUNET_YES);
  }
  else if (s->addrlen == sizeof (struct IPv6HttpAddress))
  {
    server_reschedule (s->plugin, s->plugin->server_v6, GNUNET_YES);
  }
  else
    return GNUNET_SYSERR;
  return GNUNET_OK;
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
  struct Plugin *plugin = cls;

  GNUNET_assert (cls != NULL);

  plugin->server_v4_task = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Running IPv4 server\n");

  GNUNET_assert (MHD_YES == MHD_run (plugin->server_v4));
  if (plugin->server_v4 != NULL)
    plugin->server_v4_task =
        server_schedule (plugin, plugin->server_v4, GNUNET_NO);
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
  struct Plugin *plugin = cls;

  GNUNET_assert (cls != NULL);

  plugin->server_v6_task = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;

  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "Running IPv6 server\n");

  GNUNET_assert (MHD_YES == MHD_run (plugin->server_v6));
  if (plugin->server_v6 != NULL)
    plugin->server_v6_task =
        server_schedule (plugin, plugin->server_v6, GNUNET_NO);
}

/**
 * Function that queries MHD's select sets and
 * starts the task waiting for them.
 * @param plugin plugin
 * @param daemon_handle the MHD daemon handle
 * @return gnunet task identifier
 */
static GNUNET_SCHEDULER_TaskIdentifier
server_schedule (struct Plugin *plugin, struct MHD_Daemon *daemon_handle,
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
  unsigned long long timeout;
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
#if VERBOSE_SERVER
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Scheduling IPv4 server task in %llu ms\n", tv);
#endif
    ret =
        GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                     GNUNET_SCHEDULER_NO_TASK, tv, wrs, wws,
                                     &server_v4_run, plugin);
  }
  if (daemon_handle == plugin->server_v6)
  {
    if (plugin->server_v6_task != GNUNET_SCHEDULER_NO_TASK)
    {
      GNUNET_SCHEDULER_cancel (plugin->server_v6_task);
      plugin->server_v6_task = GNUNET_SCHEDULER_NO_TASK;
    }
#if VERBOSE_SERVER
    GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                     "Scheduling IPv6 server task in %llu ms\n", tv);
#endif
    ret =
        GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                     GNUNET_SCHEDULER_NO_TASK, tv, wrs, wws,
                                     &server_v6_run, plugin);
  }
  GNUNET_NETWORK_fdset_destroy (wrs);
  GNUNET_NETWORK_fdset_destroy (wws);
  GNUNET_NETWORK_fdset_destroy (wes);
  return ret;
}

int
server_start (struct Plugin *plugin)
{
  int res = GNUNET_OK;
  unsigned int timeout;

#if BUILD_HTTPS
  res = server_load_certificate (plugin);
  if (res == GNUNET_SYSERR)
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                     "Could not load or create server certificate! Loading plugin failed!\n");
    return res;
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
  if (plugin->ipv4 == GNUNET_YES)
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
  if (plugin->ipv6 == GNUNET_YES)
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

  if ((plugin->ipv4 == GNUNET_YES) && (plugin->server_v4 == NULL))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                     "Failed to start %s IPv4 server component on port %u\n",
                     plugin->name, plugin->port);
    return GNUNET_SYSERR;
  }
  server_reschedule (plugin, plugin->server_v4, GNUNET_NO);

  if ((plugin->ipv6 == GNUNET_YES) && (plugin->server_v6 == NULL))
  {
    GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR, plugin->name,
                     "Failed to start %s IPv6 server component on port %u\n",
                     plugin->name, plugin->port);
    return GNUNET_SYSERR;
  }
  server_reschedule (plugin, plugin->server_v6, GNUNET_NO);


#if DEBUG_HTTP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "%s server component started on port %u\n", plugin->name,
                   plugin->port);
#endif
  return res;
}

void
server_stop (struct Plugin *plugin)
{
  struct Session *s = NULL;
  struct Session *t = NULL;

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

    delete_session (s);
    s = t;
  }

#if BUILD_HTTPS
  GNUNET_free_non_null (plugin->crypto_init);
  GNUNET_free_non_null (plugin->cert);
  GNUNET_free_non_null (plugin->key);
#endif

#if DEBUG_HTTP
  GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG, plugin->name,
                   "%s server component stopped\n", plugin->name);
#endif
}



/* end of plugin_transport_http.c */
