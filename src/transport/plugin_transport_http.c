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
 * @file transport/plugin_transport_template.c
 * @brief template for a new transport service
 * @author Christian Grothoff
 */

#include "platform.h"
#include "gnunet_protocols.h"
#include "gnunet_connection_lib.h"
#include "gnunet_server_lib.h"
#include "gnunet_service_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_resolver_service.h"
#include "plugin_transport.h"
#include "microhttpd.h"
#include <curl/curl.h>

#define DEBUG_HTTP GNUNET_NO

/**
 * Text of the response sent back after the last bytes of a PUT
 * request have been received (just to formally obey the HTTP
 * protocol).
 */
#define HTTP_PUT_RESPONSE "Thank you!"

/**
 * After how long do we expire an address that we
 * learned from another peer if it is not reconfirmed
 * by anyone?
 */
#define LEARNED_ADDRESS_EXPIRATION GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_HOURS, 6)

/**
 * Page returned if request invalid
 */
#define HTTP_ERROR_RESPONSE "<!DOCTYPE HTML PUBLIC \"-//IETF//DTD HTML 2.0//EN\"><HTML><HEAD><TITLE>404 Not Found</TITLE></HEAD><BODY><H1>Not Found</H1>The requested URL was not found on this server.<P><HR><ADDRESS></ADDRESS></BODY></HTML>"


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
   * Sender's url
   */
  char * url;

  /**
   * Sender's ip address to distinguish between incoming connections
   */
  char * ip;

  /**
   * Sender's ip address to distinguish between incoming connections
   */
  struct sockaddr_in * addr;

  /**
   * Did we initiate the connection (GNUNET_YES) or the other peer (GNUNET_NO)?
   */
  unsigned int is_client;

  /**
   * Is the connection active (GNUNET_YES) or terminated (GNUNET_NO)?
   */
  unsigned int is_active;

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
   * List of open sessions.
   */
  struct Session *sessions;

  /**
   * Number of active sessions
   */

  unsigned int session_count;

};

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
 * Information about this plugin
 */
static struct Plugin *plugin;

/**
 * cURL Multihandle
 */
static CURLM *multi_handle;

/**
 * Our hostname
 */
static char * hostname;

/**
 * Our ASCII encoded, hashed peer identity
 * This string is used to distinguish between connections and is added to the urls
 */
static struct GNUNET_CRYPTO_HashAsciiEncoded my_ascii_hash_ident;


/**
 * Finds a http session in our linked list using peer identity as a key
 * @param peer peeridentity
 * @return http session corresponding to peer identity
 */
static struct Session * find_session_by_pi( const struct GNUNET_PeerIdentity *peer )
{
  struct Session * cur;
  GNUNET_HashCode hc_peer;
  GNUNET_HashCode hc_current;

  cur = plugin->sessions;
  hc_peer = peer->hashPubKey;
  while (cur != NULL)
  {
    hc_current = cur->sender.hashPubKey;
    if ( 0 == GNUNET_CRYPTO_hash_cmp( &hc_peer, &hc_current))
      return cur;
    cur = plugin->sessions->next;
  }
  return NULL;
}

#if 0
/**
 * Finds a http session in our linked list using peer identity as a key
 * @param peer peeridentity
 * @return http session corresponding to peer identity
 */
static struct Session * find_session_by_ip( char * ip )
{
  /*
  struct Session * cur;

  cur = plugin->sessions;
  while (cur != NULL)
  {
    hc_current = cur->sender.hashPubKey;
    if ( 0 == GNUNET_CRYPTO_hash_cmp( &hc_peer, &hc_current))
      return cur;
    cur = plugin->sessions->next;
  }
  */
  return NULL;
}
#endif

/**
 * Creates a http session in our linked list by peer identity
 * Only peer is set here, all other  fields have to be set by calling method
 * @param peer peeridentity
 * @return created http session
 */
static struct Session * create_session_by_pi( const struct GNUNET_PeerIdentity *peer )
{
  struct Session * cur;
  struct Session * last_in_list;
  /* Create a new session object */
  cur = GNUNET_malloc (sizeof (struct Session));
  memcpy( &(cur->sender), peer, sizeof( struct GNUNET_PeerIdentity ) );

  cur->next = NULL;

  /* Insert into linked list */
  last_in_list = plugin->sessions;
  while (last_in_list->next != NULL)
  {
    last_in_list = last_in_list->next;
  }
  last_in_list->next = cur;

  return cur;
}

#if 0
/**
 * Creates a http session in our linked list by ip address
 * Only ip is set here, all other fields have to be set by calling method
 * @param peer peeridentity
 * @return created http session
 */
static struct Session * create_session_by_ip ( struct sockaddr_in * addr )
{
  struct Session * cur;
  struct Session * last_in_list;
  /* Create a new session object */
  cur = GNUNET_malloc (sizeof (struct Session));
  // FIXME: memcpy( &(cur->ip), , sizeof( struct GNUNET_PeerIdentity ) );

  cur->next = NULL;

  /* Insert into linked list */
  last_in_list = plugin->sessions;
  while (last_in_list->next != NULL)
  {
    last_in_list = last_in_list->next;
  }
  last_in_list->next = cur;

  return cur;
}
#endif

/**
 * Callback called by MHD when a connection is terminated
 */
static void requestCompletedCallback (void *cls, struct MHD_Connection * connection, void **httpSessionCache)
{
  struct Session * cs;

  cs = *httpSessionCache;
  if (cs != NULL)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Connection from peer `%s' was terminated\n",GNUNET_i2s(&cs->sender));
    /* session set to inactive */
    cs->is_active = GNUNET_NO;
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Not accepted connection was terminated\n");
  return;
}

/**
 * Check if we are allowed to connect to the given IP.
 */
static int
acceptPolicyCallback (void *cls,
                      const struct sockaddr *addr, socklen_t addr_len)
{
  /* Every connection is accepted, nothing more to do here */
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
  struct Session * cs;
  struct Session * cs_temp;
  const union MHD_ConnectionInfo * conn_info;
  struct sockaddr_in  *addrin;
  struct sockaddr_in6 *addrin6;
  char * address = NULL;
  struct GNUNET_PeerIdentity pi_in;
  int res = GNUNET_NO;

  if ( NULL == *httpSessionCache)
  {
    /* check url for peer identity */
    res = GNUNET_CRYPTO_hash_from_string ( &url[1], &(pi_in.hashPubKey));
    if ( GNUNET_SYSERR == res )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Peer has no valid ident\n");
      response = MHD_create_response_from_data (strlen (HTTP_ERROR_RESPONSE),HTTP_ERROR_RESPONSE, MHD_NO, MHD_NO);
      res = MHD_queue_response (session, MHD_HTTP_NOT_FOUND, response);
      MHD_destroy_response (response);
      return MHD_YES;
    }

    conn_info = MHD_get_connection_info(session, MHD_CONNECTION_INFO_CLIENT_ADDRESS );
    /* Incoming IPv4 connection */
    if ( AF_INET == conn_info->client_addr->sin_family)
    {
      address = GNUNET_malloc (INET_ADDRSTRLEN);
      addrin = conn_info->client_addr;
      inet_ntop(addrin->sin_family, &(addrin->sin_addr),address,INET_ADDRSTRLEN);
    }
    /* Incoming IPv6 connection */
    if ( AF_INET6 == conn_info->client_addr->sin_family)
    {
      address = GNUNET_malloc (INET6_ADDRSTRLEN);
      addrin6 = (struct sockaddr_in6 *) conn_info->client_addr;
      inet_ntop(addrin6->sin6_family, &(addrin6->sin6_addr),address,INET6_ADDRSTRLEN);
    }

    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"HTTP Daemon has an incoming `%s' request from peer `%s' from `[%s]:%u'\n",method, GNUNET_h2s(&pi_in.hashPubKey),address,conn_info->client_addr->sin_port);

    /* find session for address */
    cs = NULL;
    if (plugin->session_count > 0)
    {
      cs = plugin->sessions;
      while ( NULL != cs)
      {

        /* Comparison based on ip address */
        // res = (0 == memcmp(&(conn_info->client_addr->sin_addr),&(cs->addr->sin_addr), sizeof (struct in_addr))) ? GNUNET_YES : GNUNET_NO;

        /* Comparison based on ip address, port number and address family */
        // res = (0 == memcmp((conn_info->client_addr),(cs->addr), sizeof (struct sockaddr_in))) ? GNUNET_YES : GNUNET_NO;

        /* Comparison based on PeerIdentity */
        res = (0 == memcmp(&pi_in,&(cs->sender), sizeof (struct GNUNET_PeerIdentity))) ? GNUNET_YES : GNUNET_NO;

        if ( GNUNET_YES  == res)
        {
          /* existing session for this address found */
          GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Session `%s' found\n",address);
          break;
        }
        cs = cs->next;
      }
    }

    if (cs == NULL )
    {
      /* create new session object */
      cs = GNUNET_malloc ( sizeof( struct Session) );
      cs->addr = GNUNET_malloc ( sizeof (struct sockaddr_in) );

      cs->ip = address;
      memcpy(cs->addr, conn_info->client_addr, sizeof (struct sockaddr_in));
      memcpy(&cs->sender, &pi_in, sizeof (struct GNUNET_PeerIdentity));
      cs->next = NULL;
      cs->is_active = GNUNET_YES;

      /* Insert session into linked list */
      if ( plugin->sessions == NULL)
      {
        plugin->sessions = cs;
        plugin->session_count = 1;
      }
      cs_temp = plugin->sessions;
      while ( cs_temp->next != NULL )
      {
        cs_temp = cs_temp->next;
      }
      if (cs_temp != cs )
      {
        cs_temp->next = cs;
        plugin->session_count++;
      }
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"New Session `%s' inserted, count %u \n", address, plugin->session_count);
    }
    /* Set closure */
    if (*httpSessionCache == NULL)
      *httpSessionCache = cs;
  }
  else
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Session already known");

  /* Is it a PUT or a GET request */
  if ( 0 == strcmp (MHD_HTTP_METHOD_PUT, method) )
  {
    /* PUT method here */
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Got PUT Request with size %lu \n",(*upload_data_size));
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"URL: `%s'\n",url);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"PUT Request: `%s'\n",upload_data);
    /* No data left */
    *upload_data_size = 0;
    response = MHD_create_response_from_data (strlen (HTTP_PUT_RESPONSE),HTTP_PUT_RESPONSE, MHD_NO, MHD_NO);
    MHD_queue_response (session, MHD_HTTP_OK, response);
    MHD_destroy_response (response);
  }
  if ( 0 == strcmp (MHD_HTTP_METHOD_GET, method) )
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Got GET Request\n");
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"URL: `%s'\n",url);

    response = MHD_create_response_from_data (strlen (HTTP_PUT_RESPONSE),HTTP_PUT_RESPONSE, MHD_NO, MHD_NO);
    MHD_queue_response (session, MHD_HTTP_OK, response);
    MHD_destroy_response (response);
  }

  return MHD_YES;
}


/**
 * Call MHD to process pending requests and then go back
 * and schedule the next run.
 */
static void http_daemon_run (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Function that queries MHD's select sets and
 * starts the task waiting for them.
 */
static GNUNET_SCHEDULER_TaskIdentifier
http_daemon_prepare (struct MHD_Daemon *daemon_handle)
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
                                     &http_daemon_run,
                                     daemon_handle);
  GNUNET_NETWORK_fdset_destroy (wrs);
  GNUNET_NETWORK_fdset_destroy (wws);
  GNUNET_NETWORK_fdset_destroy (wes);
  return ret;
}

/**
 * Call MHD to process pending requests and then go back
 * and schedule the next run.
 */
static void
http_daemon_run (void *cls,
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
    http_task_v4 = http_daemon_prepare (daemon_handle);
  if (daemon_handle == http_daemon_v6)
    http_task_v6 = http_daemon_prepare (daemon_handle);
  return;
}

static size_t read_callback(void *ptr, size_t size, size_t nmemb, void *stream)
{
  size_t retcode;
  /*
  fprintf(stdout, "*** Read callback: size %u, size nmemb: %u \n", size, nmemb);
  retcode = fread(ptr, size, nmemb, stream);
   */
  retcode = 0;
  return retcode;
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
template_plugin_send (void *cls,
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
  struct Session* ses;
  int bytes_sent = 0;
  /*  struct Plugin *plugin = cls; */
  CURL *curl_handle;
  /* CURLcode res; */

  /* find session for peer */
  ses = find_session_by_pi (target);
  if ( ses == NULL) create_session_by_pi (target);

  char *url = "http://localhost:12389";

  curl_handle = curl_easy_init();
  if( NULL == curl_handle)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Getting cURL handle failed\n");
    return -1;
  }
  curl_easy_setopt(curl_handle, CURLOPT_VERBOSE, 1L);
  curl_easy_setopt(curl_handle, CURLOPT_READFUNCTION, read_callback);
  curl_easy_setopt(curl_handle, CURLOPT_UPLOAD, 1L);
  curl_easy_setopt(curl_handle, CURLOPT_PUT, 1L);
  curl_easy_setopt(curl_handle, CURLOPT_URL, url);
  curl_easy_setopt(curl_handle, CURLOPT_READDATA, msgbuf);
  curl_easy_setopt(curl_handle, CURLOPT_INFILESIZE_LARGE,
                  (curl_off_t)msgbuf_size);



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
template_plugin_disconnect (void *cls,
                            const struct GNUNET_PeerIdentity *target)
{
  // struct Plugin *plugin = cls;
  // FIXME
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
template_plugin_address_pretty_printer (void *cls,
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
template_plugin_address_suggested (void *cls,
                                  void *addr, size_t addrlen)
{
  /* struct Plugin *plugin = cls; */

  /* check if the address is plausible; if so,
     add it to our list! */
  return GNUNET_OK;
}


/**
 * Function called for a quick conversion of the binary address to
 * a numeric address.  Note that the caller must not free the
 * address and that the next call to this function is allowed
 * to override the address again.
 *
 * @param cls closure
 * @param addr binary address
 * @param addrlen length of the address
 * @return string representing the same address
 */
static const char*
template_plugin_address_to_string (void *cls,
                                   const void *addr,
                                   size_t addrlen)
{
  GNUNET_break (0);
  return NULL;
}

/**
 * Exit point from the plugin.
 */
void *
libgnunet_plugin_transport_http_done (void *cls)
{
  struct GNUNET_TRANSPORT_PluginFunctions *api = cls;
  struct Plugin *plugin = api->cls;
  struct Session * cs;
  struct Session * cs_next;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Unloading http plugin...\n");

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

  curl_multi_cleanup(multi_handle);

  /* free all sessions */
  cs = plugin->sessions;
  while ( NULL != cs)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Freeing session to `%s'\n",cs->ip);
      cs_next = cs->next;
      GNUNET_free (cs->ip);
      GNUNET_free (cs->addr);
      GNUNET_free (cs);
      plugin->session_count--;
      cs = cs_next;
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
  plugin->sessions = NULL;
  api = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PluginFunctions));
  api->cls = plugin;
  api->send = &template_plugin_send;
  api->disconnect = &template_plugin_disconnect;
  api->address_pretty_printer = &template_plugin_address_pretty_printer;
  api->check_address = &template_plugin_address_suggested;
  api->address_to_string = &template_plugin_address_to_string;

  hostname = GNUNET_RESOLVER_local_fqdn_get ();

  /* Hashing our identity to use it in URLs */
  GNUNET_CRYPTO_hash_to_enc ( &(plugin->env->my_identity->hashPubKey), &my_ascii_hash_ident);

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
                       ("Require valid port number for transport plugin `%s' in configuration!\n"),
                       "transport-http");
      libgnunet_plugin_transport_http_done (api);
      return NULL;
    }

  if ((http_daemon_v4 == NULL) && (http_daemon_v6 == NULL) && (port != 0))
    {
    http_daemon_v6 = MHD_start_daemon (MHD_USE_IPv6,
                                       port,
                                       &acceptPolicyCallback,
                                       NULL , &accessHandlerCallback, NULL,
                                       MHD_OPTION_CONNECTION_LIMIT, (unsigned int) 16,
                                       MHD_OPTION_PER_IP_CONNECTION_LIMIT, (unsigned int) 1,
                                       MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 16,
                                       MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t) (16 * 1024),
                                       MHD_OPTION_NOTIFY_COMPLETED, &requestCompletedCallback, NULL,
                                       MHD_OPTION_END);
    http_daemon_v4 = MHD_start_daemon (MHD_NO_FLAG,
                                       port,
                                       &acceptPolicyCallback,
                                       NULL , &accessHandlerCallback, NULL,
                                       MHD_OPTION_CONNECTION_LIMIT, (unsigned int) 16,
                                       MHD_OPTION_PER_IP_CONNECTION_LIMIT, (unsigned int) 1,
                                       MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 16,
                                       MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t) (16 * 1024),
                                       MHD_OPTION_NOTIFY_COMPLETED, &requestCompletedCallback, NULL,
                                       MHD_OPTION_END);
    }
  if (http_daemon_v4 != NULL)
    http_task_v4 = http_daemon_prepare (http_daemon_v4);
  if (http_daemon_v6 != NULL)
    http_task_v6 = http_daemon_prepare (http_daemon_v6);

  if (http_task_v4 != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Starting MHD with IPv4 on port %u\n",port);
  if (http_task_v6 != GNUNET_SCHEDULER_NO_TASK)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Starting MHD with IPv4 and IPv6 on port %u\n",port);

  /* Initializing cURL */
  multi_handle = curl_multi_init();

  return api;
}

/* end of plugin_transport_template.c */
