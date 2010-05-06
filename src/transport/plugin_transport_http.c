/*
     This file is part of GNUnet
     (C) 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2009 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @brief Implementation of the HTTP transport service
 * @author Matthias Wachs
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_connection_lib.h"
#include "gnunet_server_lib.h"
#include "gnunet_service_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "plugin_transport.h"
#include "microhttpd.h"
#include <curl/curl.h>

#define VERBOSE GNUNET_YES
#define DEBUG GNUNET_YES

/**
 * After how long do we expire an address that we
 * learned from another peer if it is not reconfirmed
 * by anyone?
 */
#define LEARNED_ADDRESS_EXPIRATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 6)

#define HTTP_TIMEOUT 600

#define CURL_EASY_SETOPT(c, a, b) do { ret = curl_easy_setopt(c, a, b); if (ret != CURLE_OK) GNUNET_log(GNUNET_ERROR_TYPE_WARNING, _("%s failed at %s:%d: `%s'\n"), "curl_easy_setopt", __FILE__, __LINE__, curl_easy_strerror(ret)); } while (0);

/**
 * Text of the response sent back after the last bytes of a PUT
 * request have been received (just to formally obey the HTTP
 * protocol).
 */
#define HTTP_PUT_RESPONSE "Thank you!"

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
   * Pointer to the global plugin struct.
   */
  struct Plugin *plugin;

  /**
   * The client (used to identify this connection)
   */
  /* void *client; */

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

  /**
   * To whom are we talking to (set to our identity
   * if we are still waiting for the welcome message)
   */
  struct GNUNET_PeerIdentity sender;

  /**
   * At what time did we reset last_received last?
   */
  struct GNUNET_TIME_Absolute last_quota_update;

  /**
   * How many bytes have we received since the "last_quota_update"
   * timestamp?
   */
  uint64_t last_received;

  /**
   * Number of bytes per ms that this peer is allowed
   * to send to us.
   */
  uint32_t quota;

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
   * Handle to the network service.
   */
  struct GNUNET_SERVICE_Context *service;

  /**
   * List of open sessions.
   */
  struct Session *sessions;
};

static struct Plugin *plugin;

/**
 * Daemon for listening for new IPv4 connections.
 */
static struct MHD_Daemon *http_daemon_v4;

/**
 * Daemon for listening for new IPv6connections.
 */
static struct MHD_Daemon *http_daemon_v6;

/**
 * Our primary task for http daemon handling IPv4 connections
 */
static GNUNET_SCHEDULER_TaskIdentifier http_task_v4;

/**
 * Our primary task for http daemon handling IPv6 connections
 */
static GNUNET_SCHEDULER_TaskIdentifier http_task_v6;

/**
 * ID of the task downloading the hostlist
 */
static GNUNET_SCHEDULER_TaskIdentifier ti_download;



/**
 * Curl multi for managing client operations.
 */
static CURLM *curl_multi;

static char * get_url( const struct GNUNET_PeerIdentity * target)
{
  return strdup("http://localhost:12389");
}

static size_t curl_read_function( void *ptr, size_t size, size_t nmemb, void *stream)
{
  // strcpy ("Testmessa")
  return 0;
}

/**
 * Task that is run when we are ready to receive more data from the hostlist
 * server.
 *
 * @param cls closure, unused
 * @param tc task context, unused
 */
static void
task_download (void *cls,
             const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Download!!!");
}

/**
 * Function that can be used by the transport service to transmit
 * a message using the plugin.
 *
 * @param cls closure
 * @param target who should receive this message
 * @param priority how important is the message
 * @param msgbuf the message to transmit
 * @param msgbuf_size number of bytes in 'msgbuf'
 * @param timeout when should we time out 
 * @param session which session must be used (or NULL for "any")
 * @param addr the address to use (can be NULL if the plugin
 *                is "on its own" (i.e. re-use existing TCP connection))
 * @param addrlen length of the address in bytes
 * @param force_address GNUNET_YES if the plugin MUST use the given address,
 *                otherwise the plugin may use other addresses or
 *                existing connections (if available)
 * @param cont continuation to call once the message has
 *        been transmitted (or if the transport is ready
 *        for the next transmission call; or if the
 *        peer disconnected...)
 * @param cont_cls closure for cont
 * @return number of bytes used (on the physical network, with overheads);
 *         -1 on hard errors (i.e. address invalid); 0 is a legal value
 *         and does NOT mean that the message was not transmitted (DV)
 */
static ssize_t
http_plugin_send (void *cls,
                  const struct GNUNET_PeerIdentity * target,
                  const char *msgbuf,
                  size_t msgbuf_size,
                  unsigned int priority,
                  struct GNUNET_TIME_Relative timeout,
                  struct Session *session,
                  const void *addr,
                  size_t addrlen,
                  int force_address,
                  GNUNET_TRANSPORT_TransmitContinuation cont,
                  void *cont_cls)
{
  char * peer_url = get_url( target );
  CURL *curl;
  CURLMcode mret;
  CURLcode ret;

  int bytes_sent = 0;
  /*  struct Plugin *plugin = cls; */

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Sending %u bytes (`%s') to `%s'\n",msgbuf_size, msgbuf,GNUNET_i2s(target));
  /* Insert code to send using cURL */
  curl = curl_easy_init ();

  CURL_EASY_SETOPT (curl, CURLOPT_FOLLOWLOCATION, 1);
  CURL_EASY_SETOPT (curl, CURLOPT_MAXREDIRS, 4);

   /* setting put options */
  CURL_EASY_SETOPT (curl, CURLOPT_UPLOAD, 1L);
  CURL_EASY_SETOPT (curl, CURLOPT_PUT, 1L);
  CURL_EASY_SETOPT (curl, CURLOPT_READDATA, msgbuf);


  /* no need to abort if the above failed */
  CURL_EASY_SETOPT (curl,
                    CURLOPT_URL,
                    peer_url);
  if (ret != CURLE_OK)
    {
      /* clean_up (); */
      return 0;
    }
  CURL_EASY_SETOPT (curl,
                    CURLOPT_FAILONERROR,
                    1);
#if 0
  CURL_EASY_SETOPT (curl,
                    CURLOPT_VERBOSE,
                    1);
#endif
  CURL_EASY_SETOPT (curl,
                    CURLOPT_BUFFERSIZE,
                    GNUNET_SERVER_MAX_MESSAGE_SIZE);
  if (0 == strncmp (peer_url, "http", 4))
    CURL_EASY_SETOPT (curl, CURLOPT_USERAGENT, "GNUnet");
  CURL_EASY_SETOPT (curl,
                    CURLOPT_CONNECTTIMEOUT,
                    60L);
  CURL_EASY_SETOPT (curl,
                    CURLOPT_TIMEOUT,
                    60L);

  curl_multi = curl_multi_init ();
  if (curl_multi == NULL)
    {
      GNUNET_break (0);
      /* clean_up (); */
      return 0;
    }
  mret = curl_multi_add_handle (curl_multi, curl);
  if (mret != CURLM_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("%s failed at %s:%d: `%s'\n"),
                  "curl_multi_add_handle", __FILE__, __LINE__,
                  curl_multi_strerror (mret));
      mret = curl_multi_cleanup (curl_multi);
      if (mret != CURLM_OK)
        GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                    _("%s failed at %s:%d: `%s'\n"),
                    "curl_multi_cleanup", __FILE__, __LINE__,
                    curl_multi_strerror (mret));
      curl_multi = NULL;
      /* clean_up (); */
      return 0;
    }


  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  struct GNUNET_NETWORK_FDSet *grs;
  struct GNUNET_NETWORK_FDSet *gws;
  struct GNUNET_TIME_Relative rtime;
  long timeout_curl;
  max = -1;
  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  mret = curl_multi_fdset (curl_multi, &rs, &ws, &es, &max);
  if (mret != CURLM_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("%s failed at %s:%d: `%s'\n"),
                  "curl_multi_fdset", __FILE__, __LINE__,
                  curl_multi_strerror (mret));
      /* clean_up (); */
      return 0;
    }
  mret = curl_multi_timeout (curl_multi, &timeout_curl);
  if (mret != CURLM_OK)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                  _("%s failed at %s:%d: `%s'\n"),
                  "curl_multi_timeout", __FILE__, __LINE__,
                  curl_multi_strerror (mret));
      /* clean_up (); */
      return 0;
    }
  /*rtime = GNUNET_TIME_relative_min (GNUNET_TIME_absolute_get_remaining (end_time),
                                    GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS,
                                                                   timeout));*/
  grs = GNUNET_NETWORK_fdset_create ();
  gws = GNUNET_NETWORK_fdset_create ();
  GNUNET_NETWORK_fdset_copy_native (grs, &rs, max + 1);
  GNUNET_NETWORK_fdset_copy_native (gws, &ws, max + 1);
#if DEBUG_HOSTLIST_CLIENT
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Scheduling task for hostlist download using cURL\n");
#endif

  ti_download = GNUNET_SCHEDULER_add_select (plugin->env->sched,
                                   GNUNET_SCHEDULER_PRIORITY_DEFAULT,
                                   GNUNET_SCHEDULER_NO_TASK,
                                   GNUNET_TIME_UNIT_FOREVER_REL,
                                   grs,
                                   gws,
                                   &task_download,
                                   curl_multi);
  GNUNET_NETWORK_fdset_destroy (gws);
  GNUNET_NETWORK_fdset_destroy (grs);

  GNUNET_free(peer_url);
  /* FIXME: */
  bytes_sent = msgbuf_size;

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
void
http_plugin_disconnect (void *cls,
                            const struct GNUNET_PeerIdentity *target)
{
  // struct Plugin *plugin = cls;
  // FIXME
  return;
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
http_plugin_address_pretty_printer (void *cls,
                                    const char *type,
                                    const void *addr,
                                    size_t addrlen,
                                    int numeric,
                                    struct GNUNET_TIME_Relative timeout,
                                    GNUNET_TRANSPORT_AddressStringCallback
                                    asc, void *asc_cls)
{
  asc (asc_cls, NULL);
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
http_plugin_address_suggested (void *cls,
                                  void *addr, size_t addrlen)
{
  /* struct Plugin *plugin = cls; */

  /* check if the address is plausible; if so,
     add it to our list! */
  return GNUNET_OK;
}

/**
 * Check if we are allowed to connect to the given IP.
 */
static int
acceptPolicyCallback (void *cls,
                      const struct sockaddr *addr, socklen_t addr_len)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Incoming connection \n");
  /* Currently all incoming connections are accepted, so nothing to do here */
  return MHD_YES;
}

/**
 * Process GET or PUT request received via MHD.  For
 * GET, queue response that will send back our pending
 * messages.  For PUT, process incoming data and send
 * to GNUnet core.  In either case, check if a session
 * already exists and create a new one if not.
 */
static int
accessHandlerCallback (void *cls,
                       struct MHD_Connection *session,
                       const char *url,
                       const char *method,
                       const char *version,
                       const char *upload_data,
                       size_t * upload_data_size, void **httpSessionCache)
{
  struct MHD_Response *response;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"HTTP Daemon has an incoming `%s' request from \n",method);

  /* Find out if session exists, otherwise create one */

  /* Is it a PUT or a GET request */
  if ( 0 == strcmp (MHD_HTTP_METHOD_PUT, method) )
  {
    /* PUT method here */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Got PUT Request with size %u \n",upload_data_size);
    GNUNET_STATISTICS_update( plugin->env->stats , gettext_noop("# PUT requests"), 1, GNUNET_NO);
  }
  if ( 0 == strcmp (MHD_HTTP_METHOD_GET, method) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Got GET Request with size\n");
    GNUNET_STATISTICS_update( plugin->env->stats , gettext_noop("# GET requests"), 1, GNUNET_NO);
  }

  response = MHD_create_response_from_data (strlen (HTTP_PUT_RESPONSE),
                                   HTTP_PUT_RESPONSE, MHD_NO, MHD_NO);
  MHD_queue_response (session, MHD_HTTP_OK, response);
  MHD_destroy_response (response);

  return MHD_YES;
}

/**
 * Function that queries MHD's select sets and
 * starts the task waiting for them.
 */
static GNUNET_SCHEDULER_TaskIdentifier prepare_daemon (struct MHD_Daemon *daemon_handle);
/**
 * Call MHD to process pending requests and then go back
 * and schedule the next run.
 */
static void
run_daemon (void *cls,
            const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MHD_Daemon *daemon_handle = cls;

  if (daemon_handle == http_daemon_v4)
    http_task_v4 = GNUNET_SCHEDULER_NO_TASK;

  if (daemon_handle == http_daemon_v6)
    http_task_v6 = GNUNET_SCHEDULER_NO_TASK;


  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_assert (MHD_YES == MHD_run (daemon_handle));
  if (daemon_handle == http_daemon_v4)
    http_task_v4 = prepare_daemon (daemon_handle);
  if (daemon_handle == http_daemon_v6)
    http_task_v6 = prepare_daemon (daemon_handle);
}

/**
 * Function that queries MHD's select sets and
 * starts the task waiting for them.
 */
static GNUNET_SCHEDULER_TaskIdentifier
prepare_daemon (struct MHD_Daemon *daemon_handle)
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
  int haveto;
  struct GNUNET_TIME_Relative tv;

  FD_ZERO(&rs);
  FD_ZERO(&ws);
  FD_ZERO(&es);
  wrs = GNUNET_NETWORK_fdset_create ();
  wes = GNUNET_NETWORK_fdset_create ();
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
    tv.value = (uint64_t) timeout;
  else
    tv = GNUNET_TIME_UNIT_FOREVER_REL;
  GNUNET_NETWORK_fdset_copy_native (wrs, &rs, max);
  GNUNET_NETWORK_fdset_copy_native (wws, &ws, max);
  GNUNET_NETWORK_fdset_copy_native (wes, &es, max);
  ret = GNUNET_SCHEDULER_add_select (plugin->env->sched,
                                     GNUNET_SCHEDULER_PRIORITY_HIGH,
                                     GNUNET_SCHEDULER_NO_TASK,
                                     tv,
                                     wrs,
                                     wws,
                                     &run_daemon,
                                     daemon_handle);
  GNUNET_NETWORK_fdset_destroy (wrs);
  GNUNET_NETWORK_fdset_destroy (wws);
  GNUNET_NETWORK_fdset_destroy (wes);
  return ret;
}

/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_transport_http_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Shutting down http plugin...\n");

  if ( ti_download != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(plugin->env->sched, ti_download);
    http_task_v4 = GNUNET_SCHEDULER_NO_TASK;
  }

  if ( http_task_v4 != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(plugin->env->sched, http_task_v4);
    http_task_v4 = GNUNET_SCHEDULER_NO_TASK;
  }

  if ( http_task_v6 != GNUNET_SCHEDULER_NO_TASK)
  {
    GNUNET_SCHEDULER_cancel(plugin->env->sched, http_task_v6);
    http_task_v6 = GNUNET_SCHEDULER_NO_TASK;
  }

  if (http_daemon_v4 != NULL)
  {
    MHD_stop_daemon (http_daemon_v4);
    http_daemon_v4 = NULL;
  }
  if (http_daemon_v6 != NULL)
  {
    MHD_stop_daemon (http_daemon_v6);
    http_daemon_v6 = NULL;
  }


  if ( NULL != curl_multi)
  {
    curl_multi_cleanup (curl_multi);
    curl_multi = NULL;
  }
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/**
 * Entry point for the plugin.
 */
void *
libgnunet_plugin_transport_http_init (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  long long unsigned int port;

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->env = env;

  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;
  api->send = &http_plugin_send;
  api->disconnect = &http_plugin_disconnect;
  api->address_pretty_printer = &http_plugin_address_pretty_printer;
  api->check_address = &http_plugin_address_suggested;


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Starting http plugin...\n");
  /* Reading port number from config file */
  if ((GNUNET_OK !=
       GNUNET_CONFIGURATION_get_value_number (env->cfg,
                                              "transport-http",
                                              "PORT",
                                              &port)) ||
      (port > 65535) )
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_ERROR,
                       "http",
                       _
                       ("Require valid port number for service `%s' in configuration!\n"),
                       "transport-http");
      libgnunet_plugin_transport_http_done (api);
      return NULL;
    }
  if ((http_daemon_v4 == NULL) && (http_daemon_v6 == NULL) && (port != 0))
    {
      http_daemon_v6 = MHD_start_daemon (MHD_USE_IPv6,
                                         port,
                                         &acceptPolicyCallback,
                                         NULL, &accessHandlerCallback, NULL,
                                         MHD_OPTION_CONNECTION_LIMIT, (unsigned int) 16,
                                         MHD_OPTION_PER_IP_CONNECTION_LIMIT, (unsigned int) 1,
                                         MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 16,
                                         MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t) (16 * 1024),
                                         MHD_OPTION_END);
      http_daemon_v4 = MHD_start_daemon (MHD_NO_FLAG,
                                         port,
                                         &acceptPolicyCallback,
                                         NULL, &accessHandlerCallback, NULL,
                                         MHD_OPTION_CONNECTION_LIMIT, (unsigned int) 16,
                                         MHD_OPTION_PER_IP_CONNECTION_LIMIT, (unsigned int) 1,
                                         MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 16,
                                         MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t) (16 * 1024),
                                         MHD_OPTION_END);
    }

  curl_multi = curl_multi_init ();

  if (http_daemon_v4 != NULL)
    http_task_v4 = prepare_daemon (http_daemon_v4);
  if (http_daemon_v6 != NULL)
    http_task_v6 = prepare_daemon (http_daemon_v6);

  if ((http_daemon_v4 == NULL) || (http_daemon_v6 != NULL))
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Starting MHD on port %u\n",port);


  if (NULL == plugin->env->stats)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to retrieve statistics handle\n"));
    libgnunet_plugin_transport_http_done (api);
    return NULL;
  }

  GNUNET_STATISTICS_set ( env->stats, "# PUT requests", 0, GNUNET_NO);
  GNUNET_STATISTICS_set ( env->stats, "# GET requests", 0, GNUNET_NO);

  if ( ((NULL == http_daemon_v4) && (NULL == http_daemon_v6)) || (NULL == curl_multi))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Initializing http plugin failed\n");
    libgnunet_plugin_transport_http_done (api);
    return NULL;
  }
  else
    return api;
}

/* end of plugin_transport_http.c */
