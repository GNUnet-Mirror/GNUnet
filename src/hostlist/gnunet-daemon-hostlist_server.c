/*
     This file is part of GNUnet.
     Copyright (C) 2008, 2009, 2010, 2014, 2016 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file hostlist/gnunet-daemon-hostlist_server.c
 * @author Christian Grothoff
 * @author Matthias Wachs
 * @author David Barksdale
 * @brief application to provide an integrated hostlist HTTP server
 */
#include "platform.h"
#include <microhttpd.h>
#include "gnunet-daemon-hostlist_server.h"
#include "gnunet_hello_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet-daemon-hostlist.h"
#include "gnunet_resolver_service.h"


/**
 * How long until our hostlist advertisment transmission via CORE should
 * time out?
 */
#define GNUNET_ADV_TIMEOUT \
  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)


/**
 * Handle to the HTTP server as provided by libmicrohttpd for IPv6.
 */
static struct MHD_Daemon *daemon_handle_v6;

/**
 * Handle to the HTTP server as provided by libmicrohttpd for IPv4.
 */
static struct MHD_Daemon *daemon_handle_v4;

/**
 * Our configuration.
 */
static const struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * For keeping statistics.
 */
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Handle to the core service (NULL until we've connected to it).
 */
static struct GNUNET_CORE_Handle *core;

/**
 * Handle to the peerinfo notify service (NULL until we've connected to it).
 */
static struct GNUNET_PEERINFO_NotifyContext *notify;

/**
 * Our primary task for IPv4.
 */
static struct GNUNET_SCHEDULER_Task *hostlist_task_v4;

/**
 * Our primary task for IPv6.
 */
static struct GNUNET_SCHEDULER_Task *hostlist_task_v6;

/**
 * Our canonical response.
 */
static struct MHD_Response *response;

/**
 * Handle for accessing peerinfo service.
 */
static struct GNUNET_PEERINFO_Handle *peerinfo;

/**
 * Set if we are allowed to advertise our hostlist to others.
 */
static int advertising;

/**
 * Buffer for the hostlist address
 */
static char *hostlist_uri;


/**
 * Context for #host_processor().
 */
struct HostSet
{
  /**
   * Iterator used to build @e data (NULL when done).
   */
  struct GNUNET_PEERINFO_IteratorContext *pitr;

  /**
   * Place where we accumulate all of the HELLO messages.
   */
  char *data;

  /**
   * Number of bytes in @e data.
   */
  unsigned int size;
};


/**
 * NULL if we are not currenlty iterating over peer information.
 */
static struct HostSet *builder;


/**
 * Add headers to a request indicating that we allow Cross-Origin Resource
 * Sharing.
 *
 * @param response response to add headers to
 */
static void
add_cors_headers (struct MHD_Response *response)
{
  MHD_add_response_header (response, "Access-Control-Allow-Origin", "*");
  MHD_add_response_header (response,
                           "Access-Control-Allow-Methods",
                           "GET, OPTIONS");
  MHD_add_response_header (response, "Access-Control-Max-Age", "86400");
}


/**
 * Function that assembles our response.
 */
static void
finish_response ()
{
  if (NULL != response)
    MHD_destroy_response (response);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Creating hostlist response with %u bytes\n",
              (unsigned int) builder->size);
  response = MHD_create_response_from_buffer (builder->size,
                                              builder->data,
                                              MHD_RESPMEM_MUST_FREE);
  add_cors_headers (response);
  if ((NULL == daemon_handle_v4) && (NULL == daemon_handle_v6))
  {
    MHD_destroy_response (response);
    response = NULL;
  }
  GNUNET_STATISTICS_set (stats,
                         gettext_noop ("bytes in hostlist"),
                         builder->size,
                         GNUNET_YES);
  GNUNET_free (builder);
  builder = NULL;
}


/**
 * Set @a cls to #GNUNET_YES (we have an address!).
 *
 * @param cls closure, an `int *`
 * @param address the address (ignored)
 * @param expiration expiration time (call is ignored if this is in the past)
 * @return  #GNUNET_SYSERR to stop iterating (unless expiration has occured)
 */
static int
check_has_addr (void *cls,
                const struct GNUNET_HELLO_Address *address,
                struct GNUNET_TIME_Absolute expiration)
{
  int *arg = cls;

  if (0 == GNUNET_TIME_absolute_get_remaining (expiration).rel_value_us)
  {
    GNUNET_STATISTICS_update (stats,
                              gettext_noop ("expired addresses encountered"),
                              1,
                              GNUNET_YES);
    return GNUNET_YES;   /* ignore this address */
  }
  *arg = GNUNET_YES;
  return GNUNET_SYSERR;
}


/**
 * Callback that processes each of the known HELLOs for the
 * hostlist response construction.
 *
 * @param cls closure, NULL
 * @param peer id of the peer, NULL for last call
 * @param hello hello message for the peer (can be NULL)
 * @param err_msg message
 */
static void
host_processor (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_HELLO_Message *hello,
                const char *err_msg)
{
  size_t old;
  size_t s;
  int has_addr;

  if (NULL != err_msg)
  {
    GNUNET_assert (NULL == peer);
    builder->pitr = NULL;
    GNUNET_free_non_null (builder->data);
    GNUNET_free (builder);
    builder = NULL;
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ ("Error in communication with PEERINFO service: %s\n"),
                err_msg);
    return;
  }
  if (NULL == peer)
  {
    builder->pitr = NULL;
    finish_response ();
    return;
  }
  if (NULL == hello)
    return;
  has_addr = GNUNET_NO;
  GNUNET_HELLO_iterate_addresses (hello, GNUNET_NO, &check_has_addr, &has_addr);
  if (GNUNET_NO == has_addr)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "HELLO for peer `%4s' has no address, not suitable for hostlist!\n",
                GNUNET_i2s (peer));
    GNUNET_STATISTICS_update (stats,
                              gettext_noop (
                                "HELLOs without addresses encountered (ignored)"),
                              1,
                              GNUNET_NO);
    return;
  }
  old = builder->size;
  s = GNUNET_HELLO_size (hello);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received %u bytes of `%s' from peer `%s' for hostlist.\n",
              (unsigned int) s,
              "HELLO",
              GNUNET_i2s (peer));
  if ((old + s >= GNUNET_MAX_MALLOC_CHECKED) ||
      (old + s >= MAX_BYTES_PER_HOSTLISTS))
  {
    /* too large, skip! */
    GNUNET_STATISTICS_update (stats,
                              gettext_noop (
                                "bytes not included in hostlist (size limit)"),
                              s,
                              GNUNET_NO);
    return;
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              "Adding peer `%s' to hostlist (%u bytes)\n",
              GNUNET_i2s (peer),
              (unsigned int) s);
  GNUNET_array_grow (builder->data, builder->size, old + s);
  GNUNET_memcpy (&builder->data[old], hello, s);
}


/**
 * Hostlist access policy (very permissive, allows everything).
 * Returns #MHD_NO only if we are not yet ready to serve.
 *
 * @param cls closure
 * @param addr address information from the client
 * @param addrlen length of @a addr
 * @return #MHD_YES if connection is allowed, #MHD_NO if not (we are not ready)
 */
static int
accept_policy_callback (void *cls,
                        const struct sockaddr *addr,
                        socklen_t addrlen)
{
  if (NULL == response)
  {
    GNUNET_log (
      GNUNET_ERROR_TYPE_DEBUG,
      "Received request for hostlist, but I am not yet ready; rejecting!\n");
    return MHD_NO;
  }
  return MHD_YES; /* accept all */
}


/**
 * Main request handler.
 *
 * @param cls argument given together with the function
 *        pointer when the handler was registered with MHD
 * @param connection
 * @param url the requested url
 * @param method the HTTP method used (#MHD_HTTP_METHOD_GET,
 *        #MHD_HTTP_METHOD_PUT, etc.)
 * @param version the HTTP version string (i.e.
 *        #MHD_HTTP_VERSION_1_1)
 * @param upload_data the data being uploaded (excluding HEADERS,
 *        for a POST that fits into memory and that is encoded
 *        with a supported encoding, the POST data will NOT be
 *        given in upload_data and is instead available as
 *        part of #MHD_get_connection_values; very large POST
 *        data *will* be made available incrementally in
 *        @a upload_data)
 * @param upload_data_size set initially to the size of the
 *        @a upload_data provided; the method must update this
 *        value to the number of bytes NOT processed;
 * @param con_cls pointer that the callback can set to some
 *        address and that will be preserved by MHD for future
 *        calls for this request; since the access handler may
 *        be called many times (i.e., for a PUT/POST operation
 *        with plenty of upload data) this allows the application
 *        to easily associate some request-specific state.
 *        If necessary, this state can be cleaned up in the
 *        global #MHD_RequestCompletedCallback (which
 *        can be set with the #MHD_OPTION_NOTIFY_COMPLETED).
 *        Initially, `*con_cls` will be NULL.
 * @return #MHD_YES if the connection was handled successfully,
 *         #MHD_NO if the socket must be closed due to a serios
 *         error while handling the request
 */
static int
access_handler_callback (void *cls,
                         struct MHD_Connection *connection,
                         const char *url,
                         const char *method,
                         const char *version,
                         const char *upload_data,
                         size_t *upload_data_size,
                         void **con_cls)
{
  static int dummy;

  /* CORS pre-flight request */
  if (0 == strcmp (MHD_HTTP_METHOD_OPTIONS, method))
  {
    struct MHD_Response *options_response;
    int rc;

    options_response =
      MHD_create_response_from_buffer (0, NULL, MHD_RESPMEM_PERSISTENT);
    add_cors_headers (options_response);
    rc = MHD_queue_response (connection, MHD_HTTP_OK, options_response);
    MHD_destroy_response (options_response);
    return rc;
  }
  if (0 != strcmp (method, MHD_HTTP_METHOD_GET))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Refusing `%s' request to hostlist server\n"),
                method);
    GNUNET_STATISTICS_update (stats,
                              gettext_noop (
                                "hostlist requests refused (not HTTP GET)"),
                              1,
                              GNUNET_YES);
    return MHD_NO;
  }
  if (NULL == *con_cls)
  {
    (*con_cls) = &dummy;
    return MHD_YES;
  }
  if (0 != *upload_data_size)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _ ("Refusing `%s' request with %llu bytes of upload data\n"),
                method,
                (unsigned long long) *upload_data_size);
    GNUNET_STATISTICS_update (stats,
                              gettext_noop (
                                "hostlist requests refused (upload data)"),
                              1,
                              GNUNET_YES);
    return MHD_NO;   /* do not support upload data */
  }
  if (NULL == response)
  {
    GNUNET_log (
      GNUNET_ERROR_TYPE_WARNING,
      _ (
        "Could not handle hostlist request since I do not have a response yet\n"));
    GNUNET_STATISTICS_update (stats,
                              gettext_noop (
                                "hostlist requests refused (not ready)"),
                              1,
                              GNUNET_YES);
    return MHD_NO;   /* internal error, no response yet */
  }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _ ("Received request for our hostlist\n"));
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("hostlist requests processed"),
                            1,
                            GNUNET_YES);
  return MHD_queue_response (connection, MHD_HTTP_OK, response);
}


/**
 * Handler called by CORE when CORE is ready to transmit message
 *
 * @param cls closure with the `const struct GNUNET_PeerIdentity *` of
 *            the peer we are sending to
 * @param size size of buffer to copy message to
 * @param buf buffer to copy message to
 * @return number of bytes copied to @a buf
 */
static void
adv_transmit (struct GNUNET_MQ_Handle *mq)
{
  static uint64_t hostlist_adv_count;
  size_t uri_size; /* Including \0 termination! */
  struct GNUNET_MessageHeader *header;
  struct GNUNET_MQ_Envelope *env;

  uri_size = strlen (hostlist_uri) + 1;
  env = GNUNET_MQ_msg_extra (header,
                             uri_size,
                             GNUNET_MESSAGE_TYPE_HOSTLIST_ADVERTISEMENT);
  GNUNET_memcpy (&header[1], hostlist_uri, uri_size);
  GNUNET_MQ_env_set_options (env,
                             GNUNET_MQ_PREF_CORK_ALLOWED
                             | GNUNET_MQ_PREF_UNRELIABLE);
  GNUNET_MQ_send (mq, env);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Sent advertisement message: Copied %u bytes into buffer!\n",
              (unsigned int) uri_size);
  hostlist_adv_count++;
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              " # Sent advertisement message: %llu\n",
              (unsigned long long) hostlist_adv_count);
  GNUNET_STATISTICS_update (stats,
                            gettext_noop ("# hostlist advertisements send"),
                            1,
                            GNUNET_NO);
}


/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param mq queue for transmission to @a peer
 * @return NULL (must!)
 */
static void *
connect_handler (void *cls,
                 const struct GNUNET_PeerIdentity *peer,
                 struct GNUNET_MQ_Handle *mq)
{
  size_t size;

  if (! advertising)
    return NULL;
  if (NULL == hostlist_uri)
    return NULL;
  size = strlen (hostlist_uri) + 1;
  if (size + sizeof(struct GNUNET_MessageHeader) >= GNUNET_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return NULL;
  }
  size += sizeof(struct GNUNET_MessageHeader);
  if (NULL == core)
  {
    GNUNET_break (0);
    return NULL;
  }
  GNUNET_log (
    GNUNET_ERROR_TYPE_DEBUG,
    "Asked CORE to transmit advertisement message with a size of %u bytes to peer `%s'\n",
    (unsigned int) size,
    GNUNET_i2s (peer));
  adv_transmit (mq);
  return NULL;
}


/**
 * PEERINFO calls this function to let us know about a possible peer
 * that we might want to connect to.
 *
 * @param cls closure (not used)
 * @param peer potential peer to connect to
 * @param hello HELLO for this peer (or NULL)
 * @param err_msg NULL if successful, otherwise contains error message
 */
static void
process_notify (void *cls,
                const struct GNUNET_PeerIdentity *peer,
                const struct GNUNET_HELLO_Message *hello,
                const char *err_msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Peerinfo is notifying us to rebuild our hostlist\n");
  if (NULL != err_msg)
    GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                _ ("Error in communication with PEERINFO service: %s\n"),
                err_msg);
  if (NULL != builder)
  {
    /* restart re-build already in progress ... */
    if (NULL != builder->pitr)
    {
      GNUNET_PEERINFO_iterate_cancel (builder->pitr);
      builder->pitr = NULL;
    }
    GNUNET_free_non_null (builder->data);
    builder->size = 0;
    builder->data = NULL;
  }
  else
  {
    builder = GNUNET_new (struct HostSet);
  }
  GNUNET_assert (NULL != peerinfo);
  builder->pitr =
    GNUNET_PEERINFO_iterate (peerinfo, GNUNET_NO, NULL, &host_processor, NULL);
}


/**
 * Function that queries MHD's select sets and
 * starts the task waiting for them.
 */
static struct GNUNET_SCHEDULER_Task *
prepare_daemon (struct MHD_Daemon *daemon_handle);


/**
 * Call MHD to process pending requests and then go back
 * and schedule the next run.
 *
 * @param cls the `struct MHD_Daemon` of the HTTP server to run
 */
static void
run_daemon (void *cls)
{
  struct MHD_Daemon *daemon_handle = cls;

  if (daemon_handle == daemon_handle_v4)
    hostlist_task_v4 = NULL;
  else
    hostlist_task_v6 = NULL;
  GNUNET_assert (MHD_YES == MHD_run (daemon_handle));
  if (daemon_handle == daemon_handle_v4)
    hostlist_task_v4 = prepare_daemon (daemon_handle);
  else
    hostlist_task_v6 = prepare_daemon (daemon_handle);
}


/**
 * Function that queries MHD's select sets and
 * starts the task waiting for them.
 *
 * @param daemon_handle HTTP server to prepare to run
 */
static struct GNUNET_SCHEDULER_Task *
prepare_daemon (struct MHD_Daemon *daemon_handle)
{
  struct GNUNET_SCHEDULER_Task *ret;
  fd_set rs;
  fd_set ws;
  fd_set es;
  struct GNUNET_NETWORK_FDSet *wrs;
  struct GNUNET_NETWORK_FDSet *wws;
  int max;
  MHD_UNSIGNED_LONG_LONG timeout;
  int haveto;
  struct GNUNET_TIME_Relative tv;

  FD_ZERO (&rs);
  FD_ZERO (&ws);
  FD_ZERO (&es);
  wrs = GNUNET_NETWORK_fdset_create ();
  wws = GNUNET_NETWORK_fdset_create ();
  max = -1;
  GNUNET_assert (MHD_YES == MHD_get_fdset (daemon_handle, &rs, &ws, &es, &max));
  haveto = MHD_get_timeout (daemon_handle, &timeout);
  if (haveto == MHD_YES)
    tv.rel_value_us = (uint64_t) timeout * 1000LL;
  else
    tv = GNUNET_TIME_UNIT_FOREVER_REL;
  GNUNET_NETWORK_fdset_copy_native (wrs, &rs, max + 1);
  GNUNET_NETWORK_fdset_copy_native (wws, &ws, max + 1);
  ret = GNUNET_SCHEDULER_add_select (GNUNET_SCHEDULER_PRIORITY_HIGH,
                                     tv,
                                     wrs,
                                     wws,
                                     &run_daemon,
                                     daemon_handle);
  GNUNET_NETWORK_fdset_destroy (wrs);
  GNUNET_NETWORK_fdset_destroy (wws);
  return ret;
}


/**
 * Start server offering our hostlist.
 *
 * @param c configuration to use
 * @param st statistics handle to use
 * @param co core handle to use
 * @param[out] server_ch set to handler for CORE connect events
 * @param advertise #GNUNET_YES if we should advertise our hostlist
 * @return #GNUNET_OK on success
 */
int
GNUNET_HOSTLIST_server_start (const struct GNUNET_CONFIGURATION_Handle *c,
                              struct GNUNET_STATISTICS_Handle *st,
                              struct GNUNET_CORE_Handle *co,
                              GNUNET_CORE_ConnectEventHandler *server_ch,
                              int advertise)
{
  unsigned long long port;
  char *hostname;
  char *ipv4;
  char *ipv6;
  size_t size;
  struct in_addr i4;
  struct in6_addr i6;
  struct sockaddr_in v4;
  struct sockaddr_in6 v6;
  const struct sockaddr *sa4;
  const struct sockaddr *sa6;

  advertising = advertise;
  if (! advertising)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Advertising not enabled on this hostlist server\n");
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Advertising enabled on this hostlist server\n");
  }
  cfg = c;
  stats = st;
  peerinfo = GNUNET_PEERINFO_connect (cfg);
  if (NULL == peerinfo)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Could not access PEERINFO service.  Exiting.\n"));
    return GNUNET_SYSERR;
  }
  if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_number (cfg,
                                                          "HOSTLIST",
                                                          "HTTPPORT",
                                                          &port))
    return GNUNET_SYSERR;
  if ((0 == port) || (port > UINT16_MAX))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Invalid port number %llu.  Exiting.\n"),
                port);
    return GNUNET_SYSERR;
  }

  if (GNUNET_SYSERR ==
      GNUNET_CONFIGURATION_get_value_string (cfg,
                                             "HOSTLIST",
                                             "EXTERNAL_DNS_NAME",
                                             &hostname))
    hostname = GNUNET_RESOLVER_local_fqdn_get ();
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _ ("Hostlist service starts on %s:%llu\n"),
              hostname,
              port);
  if (NULL != hostname)
  {
    size = strlen (hostname);
    if (size + 15 > MAX_URL_LEN)
    {
      GNUNET_break (0);
    }
    else
    {
      GNUNET_asprintf (&hostlist_uri,
                       "http://%s:%u/",
                       hostname,
                       (unsigned int) port);
      GNUNET_log (GNUNET_ERROR_TYPE_INFO,
                  _ ("Address to obtain hostlist: `%s'\n"),
                  hostlist_uri);
    }
    GNUNET_free (hostname);
  }

  if (GNUNET_CONFIGURATION_have_value (cfg, "HOSTLIST", "BINDTOIPV4"))
  {
    if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (cfg,
                                                            "HOSTLIST",
                                                            "BINDTOIP",
                                                            &ipv4))
    {
      GNUNET_log (
        GNUNET_ERROR_TYPE_WARNING,
        _ ("BINDTOIP does not a valid IPv4 address! Ignoring BINDTOIPV4.\n"));
    }
  }
  else
    ipv4 = NULL;
  if (GNUNET_CONFIGURATION_have_value (cfg, "HOSTLIST", "BINDTOIPV6"))
  {
    if (GNUNET_OK != GNUNET_CONFIGURATION_get_value_string (cfg,
                                                            "HOSTLIST",
                                                            "BINDTOIP",
                                                            &ipv6))
    {
      GNUNET_log (
        GNUNET_ERROR_TYPE_WARNING,
        _ ("BINDTOIP does not a valid IPv4 address! Ignoring BINDTOIPV6.\n"));
    }
  }
  else
    ipv6 = NULL;
  sa4 = NULL;
  if (NULL != ipv4)
  {
    if (1 == inet_pton (AF_INET, ipv4, &i4))
    {
      memset (&v4, 0, sizeof(v4));
      v4.sin_family = AF_INET;
      v4.sin_addr = i4;
      v4.sin_port = htons (port);
#if HAVE_SOCKADDR_IN_SIN_LEN
      v4.sin_len = sizeof(v4);
#endif
      sa4 = (const struct sockaddr *) &v4;
    }
    else
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _ (
                    "`%s' is not a valid IPv4 address! Ignoring BINDTOIPV4.\n"),
                  ipv4);
    GNUNET_free (ipv4);
  }
  sa6 = NULL;
  if (NULL != ipv6)
  {
    if (1 == inet_pton (AF_INET6, ipv6, &i6))
    {
      memset (&v6, 0, sizeof(v6));
      v6.sin6_family = AF_INET6;
      v6.sin6_addr = i6;
      v6.sin6_port = htons (port);
#if HAVE_SOCKADDR_IN_SIN_LEN
      v6.sin6_len = sizeof(v6);
#endif
      sa6 = (const struct sockaddr *) &v6;
    }
    else
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _ (
                    "`%s' is not a valid IPv6 address! Ignoring BINDTOIPV6.\n"),
                  ipv6);
    GNUNET_free (ipv6);
  }

  daemon_handle_v6 = MHD_start_daemon (MHD_USE_IPv6 | MHD_USE_DEBUG,
                                       (uint16_t) port,
                                       &accept_policy_callback,
                                       NULL,
                                       &access_handler_callback,
                                       NULL,
                                       MHD_OPTION_CONNECTION_LIMIT,
                                       (unsigned int) 128,
                                       MHD_OPTION_PER_IP_CONNECTION_LIMIT,
                                       (unsigned int) 32,
                                       MHD_OPTION_CONNECTION_TIMEOUT,
                                       (unsigned int) 16,
                                       MHD_OPTION_CONNECTION_MEMORY_LIMIT,
                                       (size_t) (16 * 1024),
                                       MHD_OPTION_SOCK_ADDR,
                                       sa6,
                                       MHD_OPTION_END);
  daemon_handle_v4 = MHD_start_daemon (MHD_NO_FLAG | MHD_USE_DEBUG,
                                       (uint16_t) port,
                                       &accept_policy_callback,
                                       NULL,
                                       &access_handler_callback,
                                       NULL,
                                       MHD_OPTION_CONNECTION_LIMIT,
                                       (unsigned int) 128,
                                       MHD_OPTION_PER_IP_CONNECTION_LIMIT,
                                       (unsigned int) 32,
                                       MHD_OPTION_CONNECTION_TIMEOUT,
                                       (unsigned int) 16,
                                       MHD_OPTION_CONNECTION_MEMORY_LIMIT,
                                       (size_t) (16 * 1024),
                                       MHD_OPTION_SOCK_ADDR,
                                       sa4,
                                       MHD_OPTION_END);

  if ((NULL == daemon_handle_v6) && (NULL == daemon_handle_v4))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                _ ("Could not start hostlist HTTP server on port %u\n"),
                (unsigned short) port);
    return GNUNET_SYSERR;
  }

  core = co;
  *server_ch = &connect_handler;
  if (NULL != daemon_handle_v4)
    hostlist_task_v4 = prepare_daemon (daemon_handle_v4);
  if (NULL != daemon_handle_v6)
    hostlist_task_v6 = prepare_daemon (daemon_handle_v6);
  notify = GNUNET_PEERINFO_notify (cfg, GNUNET_NO, &process_notify, NULL);
  return GNUNET_OK;
}


/**
 * Stop server offering our hostlist.
 */
void
GNUNET_HOSTLIST_server_stop ()
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Hostlist server shutdown\n");
  if (NULL != hostlist_task_v6)
  {
    GNUNET_SCHEDULER_cancel (hostlist_task_v6);
    hostlist_task_v6 = NULL;
  }
  if (NULL != hostlist_task_v4)
  {
    GNUNET_SCHEDULER_cancel (hostlist_task_v4);
    hostlist_task_v4 = NULL;
  }
  if (NULL != daemon_handle_v4)
  {
    MHD_stop_daemon (daemon_handle_v4);
    daemon_handle_v4 = NULL;
  }
  if (NULL != daemon_handle_v6)
  {
    MHD_stop_daemon (daemon_handle_v6);
    daemon_handle_v6 = NULL;
  }
  if (NULL != response)
  {
    MHD_destroy_response (response);
    response = NULL;
  }
  if (NULL != notify)
  {
    GNUNET_PEERINFO_notify_cancel (notify);
    notify = NULL;
  }
  if (NULL != builder)
  {
    if (NULL != builder->pitr)
    {
      GNUNET_PEERINFO_iterate_cancel (builder->pitr);
      builder->pitr = NULL;
    }
    GNUNET_free_non_null (builder->data);
    GNUNET_free (builder);
    builder = NULL;
  }
  if (NULL != peerinfo)
  {
    GNUNET_PEERINFO_disconnect (peerinfo);
    peerinfo = NULL;
  }
  cfg = NULL;
  stats = NULL;
  core = NULL;
}

/* end of gnunet-daemon-hostlist_server.c */
