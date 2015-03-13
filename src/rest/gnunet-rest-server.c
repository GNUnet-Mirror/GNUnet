/*
   This file is part of GNUnet.
   Copyright (C) 2012-2015 Christian Grothoff (and other contributing authors)

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
 * @author Martin Schanzenbach
 * @file src/rest/gnunet-rest-server.c
 * @brief REST service for GNUnet services
 *
 */
#include "platform.h"
#include <microhttpd.h>
#include "gnunet_util_lib.h"
#include "gnunet_rest_plugin.h"


/**
 * Default Socks5 listen port.
 */
#define GNUNET_REST_SERVICE_PORT 7776

/**
 * Maximum supported length for a URI.
 * Should die. @deprecated
 */
#define MAX_HTTP_URI_LENGTH 2048

/**
 * Port for plaintext HTTP.
 */
#define HTTP_PORT 80

/**
 * Port for HTTPS.
 */
#define HTTPS_PORT 443

/**
 * After how long do we clean up unused MHD SSL/TLS instances?
 */
#define MHD_CACHE_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)

#define GN_REST_STATE_INIT 0
#define GN_REST_STATE_PROCESSING 1

/**
 * The task ID
 */
struct GNUNET_SCHEDULER_Task * httpd_task;

/**
 * is this an ssl daemon? //TODO
 */
int is_ssl;

/**
 * The port the service is running on (default 7776)
 */
static unsigned long port = GNUNET_REST_SERVICE_PORT;

/**
 * The listen socket of the service for IPv4
 */
static struct GNUNET_NETWORK_Handle *lsock4;

/**
 * The listen socket of the service for IPv6
 */
static struct GNUNET_NETWORK_Handle *lsock6;

/**
 * The listen task ID for IPv4
 */
static struct GNUNET_SCHEDULER_Task * ltask4;

/**
 * The listen task ID for IPv6
 */
static struct GNUNET_SCHEDULER_Task * ltask6;

/**
 * Daemon for HTTP
 */
static struct MHD_Daemon *httpd;

/**
 * Response we return on failures.
 */
static struct MHD_Response *failure_response;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Map of loaded plugins.
 */
struct GNUNET_CONTAINER_MultiHashMap *plugin_map;

/**
 * MHD Connection handle 
 */
struct MhdConnectionHandle
{
  struct MHD_Connection *con;

  struct MHD_Response *response;

  struct GNUNET_REST_Plugin *plugin;

  struct RestConnectionDataHandle *data_handle;

  int status;

  int state;
};

/* ************************* Global helpers ********************* */


/**
 * Task run whenever HTTP server operations are pending.
 *
 * @param cls NULL
 * @param tc sched context
 */
static void
do_httpd (void *cls,
          const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Run MHD now, we have extra data ready for the callback.
 */
static void
run_mhd_now ()
{
  if (NULL !=
      httpd_task)
    GNUNET_SCHEDULER_cancel (httpd_task);
  httpd_task = GNUNET_SCHEDULER_add_now (&do_httpd,
                                         NULL);
}

/**
 * Plugin result callback
 *
 * @param cls closure (MHD connection handle)
 * @param data the data to return to the caller
 * @param len length of the data
 * @param status GNUNET_OK if successful
 */
void
plugin_callback (void *cls,
                 struct MHD_Response *resp,
                 int status)
{
  struct MhdConnectionHandle *handle = cls;
  handle->status = status;
  handle->response = resp;
  run_mhd_now(); 
}

int
cleanup_url_map (void *cls,
                 const struct GNUNET_HashCode *key,
                 void *value)
{
  GNUNET_free_non_null (value);
  return GNUNET_YES;
}

void
cleanup_handle (struct MhdConnectionHandle *handle)
{
  if (NULL != handle->response)
    MHD_destroy_response (handle->response);
  if (NULL != handle->data_handle)
  {
    if (NULL != handle->data_handle->url_param_map)
    {
      GNUNET_CONTAINER_multihashmap_iterate (handle->data_handle->url_param_map,
                                             &cleanup_url_map,
                                             NULL);
      GNUNET_CONTAINER_multihashmap_destroy (handle->data_handle->url_param_map);
    }
    GNUNET_free (handle->data_handle);
  }
  GNUNET_free (handle);

}

int
url_iterator (void *cls,
              enum MHD_ValueKind kind,
              const char *key,
              const char *value)
{
  struct RestConnectionDataHandle *handle = cls;
  struct GNUNET_HashCode hkey;
  char *val;
  
  GNUNET_CRYPTO_hash (key, strlen (key), &hkey);
  GNUNET_asprintf (&val, "%s", value);
  if (GNUNET_OK !=
      GNUNET_CONTAINER_multihashmap_put (handle->url_param_map,
                                         &hkey,
                                         val,
                                         GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not load add url param `%s'=%s\n",
                key, value);
  }
  return MHD_YES;
}

/* ********************************* MHD response generation ******************* */

/**
 * Main MHD callback for handling requests.
 *
 * @param cls unused
 * @param con MHD connection handle
 * @param url the url in the request
 * @param meth the HTTP method used ("GET", "PUT", etc.)
 * @param ver the HTTP version string (i.e. "HTTP/1.1")
 * @param upload_data the data being uploaded (excluding HEADERS,
 *        for a POST that fits into memory and that is encoded
 *        with a supported encoding, the POST data will NOT be
 *        given in upload_data and is instead available as
 *        part of MHD_get_connection_values; very large POST
 *        data *will* be made available incrementally in
 *        upload_data)
 * @param upload_data_size set initially to the size of the
 *        @a upload_data provided; the method must update this
 *        value to the number of bytes NOT processed;
 * @param con_cls pointer to location where we store the 'struct Request'
 * @return MHD_YES if the connection was handled successfully,
 *         MHD_NO if the socket must be closed due to a serious
 *         error while handling the request
 */
static int
create_response (void *cls,
                 struct MHD_Connection *con,
                 const char *url,
                 const char *meth,
                 const char *ver,
                 const char *upload_data,
                 size_t *upload_data_size,
                 void **con_cls)
{
  char *plugin_name;
  struct GNUNET_HashCode key;
  struct MhdConnectionHandle *con_handle;
  struct RestConnectionDataHandle *rest_conndata_handle;

  con_handle = *con_cls;

  if (NULL == *con_cls)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "New connection %s\n", url);
    char tmp_url[strlen(url)+1];
    strcpy (tmp_url, url);
    con_handle = GNUNET_new (struct MhdConnectionHandle);
    con_handle->con = con;
    con_handle->state = GN_REST_STATE_INIT;
    *con_cls = con_handle;

    plugin_name = strtok(tmp_url, "/");

    if (NULL != plugin_name)
    {
      GNUNET_CRYPTO_hash (plugin_name, strlen (plugin_name), &key);

      con_handle->plugin = GNUNET_CONTAINER_multihashmap_get (plugin_map,
                                                              &key);
    }
    else
      con_handle->plugin = NULL;

    if (NULL == con_handle->plugin)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  "Queueing response with MHD\n");
      GNUNET_free (con_handle);
      MHD_queue_response (con,
                          MHD_HTTP_INTERNAL_SERVER_ERROR,
                          failure_response);
    }
    return MHD_YES;
  }
  if (GN_REST_STATE_INIT == con_handle->state)
  {
    rest_conndata_handle = GNUNET_new (struct RestConnectionDataHandle);
    rest_conndata_handle->method = meth;
    rest_conndata_handle->url = url;
    rest_conndata_handle->data = upload_data;
    rest_conndata_handle->data_size = *upload_data_size;
    rest_conndata_handle->url_param_map = GNUNET_CONTAINER_multihashmap_create (16,
                                                                                GNUNET_NO);
    con_handle->data_handle = rest_conndata_handle;
    MHD_get_connection_values (con,
                               MHD_GET_ARGUMENT_KIND,
                               &url_iterator,
                               rest_conndata_handle);
    con_handle->state = GN_REST_STATE_PROCESSING;
    con_handle->plugin->process_request (rest_conndata_handle,
                                         &plugin_callback,
                                         con_handle);
    *upload_data_size = 0;

  }
  if (NULL != con_handle->response)
  {

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Queueing response from plugin with MHD\n");
    if (GNUNET_OK == con_handle->status) {
      return MHD_queue_response (con,
                                 MHD_HTTP_OK,
                                 con_handle->response);
    } else {
      return MHD_queue_response (con,
                                 MHD_HTTP_BAD_REQUEST,
                                 con_handle->response);
    }
    cleanup_handle (con_handle);
  }
  return MHD_YES;
}

/* ******************** MHD HTTP setup and event loop ******************** */

/**
 * Function called when MHD decides that we are done with a connection.
 *
 * @param cls NULL
 * @param connection connection handle
 * @param con_cls value as set by the last call to
 *        the MHD_AccessHandlerCallback, should be our handle
 * @param toe reason for request termination (ignored)
 */
static void
mhd_completed_cb (void *cls,
                  struct MHD_Connection *connection,
                  void **con_cls,
                  enum MHD_RequestTerminationCode toe)
{

  if (MHD_REQUEST_TERMINATED_COMPLETED_OK != toe)
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "MHD encountered error handling request: %d\n",
                toe);
  *con_cls = NULL;
}

/**
 * Kill the MHD daemon.
 */
static void
kill_httpd ()
{
  if (NULL != httpd)
  {
    MHD_stop_daemon (httpd);
    httpd = NULL;
  }
  if (NULL != httpd_task)
  { 
    GNUNET_SCHEDULER_cancel (httpd_task);
    httpd_task = NULL;
  }
}

/**
 * Task run whenever HTTP server is idle for too long. Kill it.
 *
 * @param cls NULL
 * @param tc sched context
 */
static void
kill_httpd_task (void *cls,
                 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  httpd_task = NULL;
  kill_httpd ();
}
/**
 * Schedule MHD.  This function should be called initially when an
 * MHD is first getting its client socket, and will then automatically
 * always be called later whenever there is work to be done.
 *
 * @param hd the daemon to schedule
 */
static void
schedule_httpd ()
{
  fd_set rs;
  fd_set ws;
  fd_set es;
  struct GNUNET_NETWORK_FDSet *wrs;
  struct GNUNET_NETWORK_FDSet *wws;
  int max;
  int haveto;
  MHD_UNSIGNED_LONG_LONG timeout;
  struct GNUNET_TIME_Relative tv;

  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  max = -1;
  if (MHD_YES != MHD_get_fdset (httpd, &rs, &ws, &es, &max))
  {
    kill_httpd ();
    return;
  }
  haveto = MHD_get_timeout (httpd, &timeout);
  if (MHD_YES == haveto)
    tv.rel_value_us = (uint64_t) timeout * 1000LL;
  else
    tv = GNUNET_TIME_UNIT_FOREVER_REL;
  if (-1 != max)
  {
    wrs = GNUNET_NETWORK_fdset_create ();
    wws = GNUNET_NETWORK_fdset_create ();
    GNUNET_NETWORK_fdset_copy_native (wrs, &rs, max + 1);
    GNUNET_NETWORK_fdset_copy_native (wws, &ws, max + 1);
  }
  else
  {
    wrs = NULL;
    wws = NULL;
  }
  if (NULL != httpd_task)
    GNUNET_SCHEDULER_cancel (httpd_task);
  if ( (MHD_YES != haveto) &&
       (-1 == max))
  {
    /* daemon is idle, kill after timeout */
    httpd_task = GNUNET_SCHEDULER_add_delayed (MHD_CACHE_TIMEOUT,
                                               &kill_httpd_task,
                                               NULL);
  }
  else
  {
    httpd_task =
      GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                   tv, wrs, wws,
                                   &do_httpd, NULL);
  }
  if (NULL != wrs)
    GNUNET_NETWORK_fdset_destroy (wrs);
  if (NULL != wws)
    GNUNET_NETWORK_fdset_destroy (wws);
}

/**
 * Task run whenever HTTP server operations are pending.
 *
 * @param cls NULL
 * @param tc scheduler context
 */
static void
do_httpd (void *cls,
          const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  httpd_task = NULL;
  MHD_run (httpd);
  schedule_httpd ();
}

/**
 * Accept new incoming connections
 *
 * @param cls the closure with the lsock4 or lsock6
 * @param tc the scheduler context
 */
static void
do_accept (void *cls,
           const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NETWORK_Handle *lsock = cls;
  struct GNUNET_NETWORK_Handle *s;
  int fd;
  const struct sockaddr *addr;
  socklen_t len;

  if (lsock == lsock4)
    ltask4 = NULL;
  else
    ltask6 = NULL;
  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return; 
  if (lsock == lsock4)
    ltask4 = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                            lsock,
                                            &do_accept, lsock);
  else
    ltask6 = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                            lsock,
                                            &do_accept, lsock);
  s = GNUNET_NETWORK_socket_accept (lsock, NULL, NULL);
  if (NULL == s)
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "accept");
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Got an inbound connection, waiting for data\n");
  fd = GNUNET_NETWORK_get_fd (s);
  addr = GNUNET_NETWORK_get_addr (s);
  len = GNUNET_NETWORK_get_addrlen (s);
  if (MHD_YES != MHD_add_connection (httpd, fd, addr, len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Failed to pass client to MHD\n"));
    return;
  }

  schedule_httpd ();
}

/**
 * Task run on shutdown
 *
 * @param cls closure
 * @param tc task context
 */
static void
do_shutdown (void *cls,
             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Shutting down...\n");
  kill_httpd ();
}

/**
 * Create an IPv4 listen socket bound to our port.
 *
 * @return NULL on error
 */
static struct GNUNET_NETWORK_Handle *
bind_v4 ()
{
  struct GNUNET_NETWORK_Handle *ls;
  struct sockaddr_in sa4;
  int eno;

  memset (&sa4, 0, sizeof (sa4));
  sa4.sin_family = AF_INET;
  sa4.sin_port = htons (port);
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa4.sin_len = sizeof (sa4);
#endif 
  ls = GNUNET_NETWORK_socket_create (AF_INET,
                                     SOCK_STREAM,
                                     0);
  if (NULL == ls)
    return NULL;
  if (GNUNET_OK !=
      GNUNET_NETWORK_socket_bind (ls, (const struct sockaddr *) &sa4,
                                  sizeof (sa4)))
  {
    eno = errno;
    GNUNET_NETWORK_socket_close (ls);
    errno = eno;
    return NULL;
  }
  return ls;
}

/**
 * Create an IPv6 listen socket bound to our port.
 *
 * @return NULL on error
 */
static struct GNUNET_NETWORK_Handle *
bind_v6 ()
{
  struct GNUNET_NETWORK_Handle *ls;
  struct sockaddr_in6 sa6;
  int eno;

  memset (&sa6, 0, sizeof (sa6));
  sa6.sin6_family = AF_INET6;
  sa6.sin6_port = htons (port);
#if HAVE_SOCKADDR_IN_SIN_LEN
  sa6.sin6_len = sizeof (sa6);
#endif 
  ls = GNUNET_NETWORK_socket_create (AF_INET6,
                                     SOCK_STREAM,
                                     0);
  if (NULL == ls)
    return NULL;
  if (GNUNET_OK !=
      GNUNET_NETWORK_socket_bind (ls, (const struct sockaddr *) &sa6,
                                  sizeof (sa6)))
  {
    eno = errno;
    GNUNET_NETWORK_socket_close (ls);
    errno = eno;
    return NULL;
  }
  return ls;
}

/**
 * Callback for plugin load
 *
 * @param cls NULL
 * @param libname the name of the library loaded
 * @param lib_ret the object returned by the plugin initializer
 */
void
load_plugin (void *cls,
             const char *libname,
             void *lib_ret)
{
  struct GNUNET_REST_Plugin *plugin = lib_ret;
  struct GNUNET_HashCode key;
  if (NULL == lib_ret)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not load plugin `%s'\n",
                libname);
    return;
  }
  GNUNET_assert (1 < strlen (plugin->name));
  GNUNET_assert ('/' == *plugin->name);
  GNUNET_CRYPTO_hash (plugin->name+1, strlen (plugin->name+1), &key);
  if (GNUNET_OK != GNUNET_CONTAINER_multihashmap_put (plugin_map,
                                                      &key,
                                                      plugin,
                                                      GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_ONLY))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Could not load add plugin `%s'\n",
                libname);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Loaded plugin `%s'\n",
              libname);
}

/**
 * Main function that will be run
 *
 * @param cls closure
 * @param args remaining command-line arguments
 * @param cfgfile name of the configuration file used (for saving, can be NULL)
 * @param c configuration
 */
static void
run (void *cls, char *const *args, const char *cfgfile,
     const struct GNUNET_CONFIGURATION_Handle *c)
{
  cfg = c;
  plugin_map = GNUNET_CONTAINER_multihashmap_create (10, GNUNET_NO);

  /* Open listen socket proxy */
  lsock6 = bind_v6 ();
  if (NULL == lsock6)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "bind");
  else
  {
    if (GNUNET_OK != GNUNET_NETWORK_socket_listen (lsock6, 5))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "listen");
      GNUNET_NETWORK_socket_close (lsock6);
      lsock6 = NULL;
    }
    else
    {
      ltask6 = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                              lsock6, &do_accept, lsock6);
    }
  }
  lsock4 = bind_v4 ();
  if (NULL == lsock4)
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "bind");
  else
  {
    if (GNUNET_OK != GNUNET_NETWORK_socket_listen (lsock4, 5))
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR, "listen");
      GNUNET_NETWORK_socket_close (lsock4);
      lsock4 = NULL;
    }
    else
    {
      ltask4 = GNUNET_SCHEDULER_add_read_net (GNUNET_TIME_UNIT_FOREVER_REL,
                                              lsock4, &do_accept, lsock4);
    }
  }
  if ( (NULL == lsock4) &&
       (NULL == lsock6) )
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  } 
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Service listens on port %u\n",
              port);
  httpd = MHD_start_daemon (MHD_USE_DEBUG | MHD_USE_NO_LISTEN_SOCKET,
                            0,
                            NULL, NULL,
                            &create_response, NULL,
                            MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 16,
                            MHD_OPTION_NOTIFY_COMPLETED, &mhd_completed_cb, NULL,
                            MHD_OPTION_END);
  if (NULL == httpd)
  {
    GNUNET_SCHEDULER_shutdown ();
    return;
  }
  /* Load plugins */
  GNUNET_PLUGIN_load_all ("libgnunet_plugin_rest",
                          (void *) cfg,
                          &load_plugin,
                          NULL);
  GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_FOREVER_REL,
                                &do_shutdown, NULL);
}

/**
 *
 * The main function for gnunet-rest-service
 *
 * @param argc number of arguments from the cli
 * @param argv command line arguments
 * @return 0 ok, 1 on error
 *
 */
int
main (int argc, char *const *argv)
{
  static const struct GNUNET_GETOPT_CommandLineOption options[] = {
    {'p', "port", NULL,
      gettext_noop ("listen on specified port (default: 7776)"), 1,
      &GNUNET_GETOPT_set_ulong, &port},
    GNUNET_GETOPT_OPTION_END
  };
  static const char* err_page =
    "{}";
  int ret;

  if (GNUNET_OK != GNUNET_STRINGS_get_utf8_args (argc, argv, &argc, &argv))
    return 2;
  GNUNET_log_setup ("gnunet-rest-service", "WARNING", NULL);
  failure_response = MHD_create_response_from_buffer (strlen(err_page),
                                                      (void*)err_page,
                                                      MHD_RESPMEM_PERSISTENT);
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Start\n");
  ret =
    (GNUNET_OK ==
     GNUNET_PROGRAM_run (argc, argv, "gnunet-rest-server",
                         _("GNUnet REST server"),
                         options,
                         &run, NULL)) ? 0: 1;
  MHD_destroy_response (failure_response);
  GNUNET_free_non_null ((char *) argv);
  return ret;
}

/* end of gnunet-rest-server.c */
