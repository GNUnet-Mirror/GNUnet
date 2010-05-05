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
 * Daemon for listening for new connections.
 */
static struct MHD_Daemon *http_daemon;

/**
 * Our primary task for http
 */
static GNUNET_SCHEDULER_TaskIdentifier http_task;

/**
 * Curl multi for managing client operations.
 */
static CURLM *curl_multi;

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
                      const struct GNUNET_PeerIdentity *
                      target,
                      const char *msgbuf,
                      size_t msgbuf_size,
                      unsigned int priority,
                      struct GNUNET_TIME_Relative timeout,
		      struct Session *session,
                      const void *addr,
                      size_t addrlen,
                      int force_address,
                      GNUNET_TRANSPORT_TransmitContinuation
                      cont, void *cont_cls)
{
  int bytes_sent = 0;
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
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG," Incoming connection \n");
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
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Got GET Request with size %u \n",upload_data_size);
    GNUNET_STATISTICS_update( plugin->env->stats , gettext_noop("# GET requests"), 1, GNUNET_NO);
  }

  return MHD_YES;
}

/**
 * MHD is done handling a request.  Cleanup
 * the respective transport state.
 */
static void
requestCompletedCallback (void *unused,
                          struct MHD_Connection *session,
                          void **httpSessionCache)
{

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

  if (daemon_handle == http_daemon)
    http_task = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;
  GNUNET_assert (MHD_YES == MHD_run (daemon_handle));
  if (daemon_handle == http_daemon)
    http_task = prepare_daemon (daemon_handle);

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
 * Entry point for the plugin.
 */
void *
libgnunet_plugin_transport_http_init (void *cls)
{
  struct GNUNET_TRANSPORT_PluginEnvironment *env = cls;
  struct GNUNET_TRANSPORT_PluginFunctions *api;
  long long unsigned int port;
  struct GNUNET_SERVICE_Context *service;
  int use_ipv6;

  plugin = GNUNET_malloc (sizeof (struct Plugin));
  plugin->env = env;

  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;
  api->send = &http_plugin_send;
  api->disconnect = &http_plugin_disconnect;
  api->address_pretty_printer = &http_plugin_address_pretty_printer;
  api->check_address = &http_plugin_address_suggested;

  /*
  service = GNUNET_SERVICE_start ("transport-http", env->sched, env->cfg);
  if (service == NULL)
    {
      GNUNET_log_from (GNUNET_ERROR_TYPE_DEBUG,
                       "http",
                       _("Failed to start service for `%s' transport plugin.\n"),
                       "http");
      return NULL;
    }
  plugin->service = service;
  */
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
      GNUNET_free (api);
      return NULL;
    }
  use_ipv6 = GNUNET_YES;
  use_ipv6 = GNUNET_CONFIGURATION_get_value_yesno  (env->cfg, "transport-http","USE_IPV6");
  if ((http_daemon == NULL) && (port != 0))
    {
      if ( use_ipv6 == GNUNET_YES)
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Starting MHD on port %u with IPv6 enabled\n",port);
          http_daemon = MHD_start_daemon (MHD_USE_IPv6,
                                         port,
                                         &acceptPolicyCallback,
                                         NULL, &accessHandlerCallback, NULL,
                                         MHD_OPTION_CONNECTION_TIMEOUT,
                                         (unsigned int) HTTP_TIMEOUT,
                                         MHD_OPTION_CONNECTION_MEMORY_LIMIT,
                                         (unsigned int) GNUNET_SERVER_MAX_MESSAGE_SIZE,
                                         MHD_OPTION_CONNECTION_LIMIT,
                                         (unsigned int) 128,
                                         MHD_OPTION_PER_IP_CONNECTION_LIMIT,
                                         (unsigned int) 8,
                                         MHD_OPTION_NOTIFY_COMPLETED,
                                         &requestCompletedCallback, NULL,
                                         MHD_OPTION_END);
        }
      else
        {
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Starting MHD on port %u with IPv6 disabled\n",port);
          http_daemon = MHD_start_daemon (MHD_NO_FLAG,
                                         port,
                                         &acceptPolicyCallback,
                                         NULL, &accessHandlerCallback, NULL,
                                         MHD_OPTION_CONNECTION_TIMEOUT,
                                         (unsigned int) HTTP_TIMEOUT,
                                         MHD_OPTION_CONNECTION_MEMORY_LIMIT,
                                         (unsigned int) GNUNET_SERVER_MAX_MESSAGE_SIZE,
                                         MHD_OPTION_CONNECTION_LIMIT,
                                         (unsigned int) 128,
                                         MHD_OPTION_PER_IP_CONNECTION_LIMIT,
                                         (unsigned int) 8,
                                         MHD_OPTION_NOTIFY_COMPLETED,
                                         &requestCompletedCallback, NULL,
                                         MHD_OPTION_END);
        }
    }

  curl_multi = curl_multi_init ();

  if (http_daemon != NULL)
    http_task = prepare_daemon (http_daemon);

  if (NULL == plugin->env->stats)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _("Failed to retrieve statistics handle\n"));
    GNUNET_free (api);
    return NULL;
  }

  GNUNET_STATISTICS_set ( env->stats, "# PUT requests", 0, GNUNET_NO);
  GNUNET_STATISTICS_set ( env->stats, "# GET requests", 0, GNUNET_NO);

  if ( (NULL == http_daemon) || (NULL == curl_multi))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Initializing http plugin failed\n");
    GNUNET_free (api);
    return NULL;
  }
  else
    return api;
}


/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_transport_http_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;

  if (http_daemon != NULL)
  {
    MHD_stop_daemon (http_daemon);
    http_daemon = NULL;
  }

  curl_multi_cleanup (curl_multi);
  curl_multi = NULL;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Shutting down http plugin...\n");
  /* GNUNET_SERVICE_stop (plugin->service); */
  GNUNET_free (plugin);
  GNUNET_free (api);
  return NULL;
}

/* end of plugin_transport_http.c */
