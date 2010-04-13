/*
     This file is part of GNUnet.
     (C) 2008, 2009, 2010 Christian Grothoff (and other contributing authors)

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
 * @file hostlist/hostlist-server.c
 * @author Christian Grothoff
 * @brief application to provide an integrated hostlist HTTP server
 */

#include "platform.h"
#include <microhttpd.h>
#include "hostlist-server.h"
#include "gnunet_hello_lib.h"
#include "gnunet_peerinfo_service.h"
#include "gnunet-daemon-hostlist.h"
#include "gnunet_resolver_service.h"

#define DEBUG_HOSTLIST_SERVER GNUNET_NO

/**
 * How often should we recalculate our response to hostlist requests?
 */
#define RESPONSE_UPDATE_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)

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
 * Our scheduler.
 */
static struct GNUNET_SCHEDULER_Handle *sched;

/**
 * For keeping statistics.
 */ 
static struct GNUNET_STATISTICS_Handle *stats;

/**
 * Handle to the core service (NULL until we've connected to it).
 */
struct GNUNET_CORE_Handle *core;

/**
 * Our primary task for IPv4.
 */
static GNUNET_SCHEDULER_TaskIdentifier hostlist_task_v4;

/**
 * Our primary task for IPv6.
 */
static GNUNET_SCHEDULER_TaskIdentifier hostlist_task_v6;

/**
 * Task that updates our HTTP response.
 */
static GNUNET_SCHEDULER_TaskIdentifier response_task;

/**
 * Our canonical response.
 */
static struct MHD_Response *response;

/**
 * NULL if we are not currenlty iterating over peer information.
 */
static struct GNUNET_PEERINFO_IteratorContext *pitr;

/**
 * Context for host processor.
 */
struct HostSet
{
  unsigned int size;

  char *data;
};

/**
 * Task that will produce a new response object.
 */
static void
update_response (void *cls,
		 const struct GNUNET_SCHEDULER_TaskContext *tc);

/**
 * Function that assembles our response.
 */
static void
finish_response (struct HostSet *results)
{
  struct GNUNET_TIME_Relative freq;

  if (response != NULL)
    MHD_destroy_response (response);
#if DEBUG_HOSTLIST_SERVER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Creating hostlist response with %u bytes\n",
              (unsigned int) results->size);
#endif
  response = MHD_create_response_from_data (results->size,
                                            results->data, MHD_YES, MHD_NO);
  if ( (daemon_handle_v4 != NULL) ||
       (daemon_handle_v6 != NULL) )
    {
      freq = RESPONSE_UPDATE_FREQUENCY;
      if (results->size == 0)
        freq = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 250);
      /* schedule next update of the response */
      response_task = GNUNET_SCHEDULER_add_delayed (sched,
                                                    freq,
                                                    &update_response,
                                                    NULL);
    }
  else
    {
      /* already past shutdown */
      MHD_destroy_response (response);
      response = NULL;
    }
  GNUNET_STATISTICS_set (stats,
                         gettext_noop("bytes in hostlist"),
                         results->size,
                         GNUNET_YES);
  GNUNET_free (results);
}


/**
 * Set 'cls' to GNUNET_YES (we have an address!).
 *
 * @param cls closure, an 'int*'
 * @param tname name of the transport (ignored)
 * @param expiration expiration time (call is ignored if this is in the past)
 * @param addr the address (ignored)
 * @param addrlen length of the address (ignored)
 * @return  GNUNET_SYSERR to stop iterating (unless expiration has occured)
 */
static int
check_has_addr (void *cls,
		const char *tname,
		struct GNUNET_TIME_Absolute expiration,
		const void *addr, size_t addrlen)
{
  int *arg = cls;

  if (GNUNET_TIME_absolute_get_remaining (expiration).value == 0)
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop("expired addresses encountered"),
				1,
				GNUNET_YES);
      return GNUNET_YES; /* ignore this address */
    }
  *arg = GNUNET_YES;
  return GNUNET_SYSERR;
}


/**
 * Callback that processes each of the known HELLOs for the
 * hostlist response construction.
 */
static void
host_processor (void *cls,
		const struct GNUNET_PeerIdentity * peer,
                const struct GNUNET_HELLO_Message *hello,
		uint32_t trust)
{
  struct HostSet *results = cls;
  size_t old;
  size_t s;
  int has_addr;
  
  if (peer == NULL)
    {
      pitr = NULL;
      finish_response (results);
      return;
    }
  if (hello == NULL)
    return;
  has_addr = GNUNET_NO;
  GNUNET_HELLO_iterate_addresses (hello,
				  GNUNET_NO,
				  &check_has_addr,
				  &has_addr);
  if (GNUNET_NO == has_addr)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "HELLO for peer `%4s' has no address, not suitable for hostlist!\n",
		  GNUNET_i2s (peer));
      GNUNET_STATISTICS_update (stats,
				gettext_noop("HELLOs without addresses encountered (ignored)"),
				1,
				GNUNET_NO);
      return; 
    }
  old = results->size;
  s = GNUNET_HELLO_size(hello);
#if DEBUG_HOSTLIST_SERVER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received %u bytes of `%s' from peer `%s' for hostlist.\n",
	      (unsigned int) s,
	      "HELLO",
	      GNUNET_i2s (peer));
#endif
  if (old + s >= GNUNET_MAX_MALLOC_CHECKED)
    {
      GNUNET_STATISTICS_update (stats,
				gettext_noop("bytes not included in hostlist (size limit)"),
				s,
				GNUNET_NO);
      return; /* too large, skip! */
    }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      "Adding peer `%s' to hostlist (%u bytes)\n",
	      GNUNET_i2s (peer),
	      (unsigned int) s);
  GNUNET_array_grow (results->data,
                     results->size,
                     old + s);
  memcpy (&results->data[old], hello, s);
}


/**
 * Task that will produce a new response object.
 */
static void
update_response (void *cls,
		 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct HostSet *results;

  response_task = GNUNET_SCHEDULER_NO_TASK;
  results = GNUNET_malloc(sizeof(struct HostSet));
  pitr = GNUNET_PEERINFO_iterate (cfg, sched, 
				  NULL,
				  0, 
				  GNUNET_TIME_UNIT_MINUTES,
				  &host_processor,
				  results);
}


/**
 * Hostlist access policy (very permissive, allows everything).
 */
static int
accept_policy_callback (void *cls,
                        const struct sockaddr *addr, socklen_t addrlen)
{
  if (NULL == response)
    {
#if DEBUG_HOSTLIST_SERVER
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  "Received request for hostlist, but I am not yet ready; rejecting!\n");
#endif
      return MHD_NO;
    }
  return MHD_YES;               /* accept all */
}


/**
 * Main request handler.
 */
static int
access_handler_callback (void *cls,
                         struct MHD_Connection *connection,
                         const char *url,
                         const char *method,
                         const char *version,
                         const char *upload_data,
                         size_t*upload_data_size, void **con_cls)
{
  static int dummy;
  
  if (0 != strcmp (method, MHD_HTTP_METHOD_GET))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Refusing `%s' request to hostlist server\n"),
		  method);
      GNUNET_STATISTICS_update (stats,
				gettext_noop("hostlist requests refused (not HTTP GET)"),
				1,
				GNUNET_YES);
      return MHD_NO;
    }
  if (NULL == *con_cls)
    {
      (*con_cls) = &dummy;
#if DEBUG_HOSTLIST_SERVER
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
		  _("Sending 100 CONTINUE reply\n"));
#endif
      return MHD_YES;           /* send 100 continue */
    }
  if (*upload_data_size != 0)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Refusing `%s' request with %llu bytes of upload data\n"),
		  method,
		  (unsigned long long) *upload_data_size);
      GNUNET_STATISTICS_update (stats,
				gettext_noop("hostlist requests refused (upload data)"),
				1,
				GNUNET_YES);
      return MHD_NO;              /* do not support upload data */
    }
  if (response == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Could not handle hostlist request since I do not have a response yet\n"));
      GNUNET_STATISTICS_update (stats,
				gettext_noop("hostlist requests refused (not ready)"),
				1,
				GNUNET_YES);
      return MHD_NO;              /* internal error, no response yet */
    }
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Received request for our hostlist\n"));
  GNUNET_STATISTICS_update (stats,
			    gettext_noop("hostlist requests processed"),
			    1,
			    GNUNET_YES);
  return MHD_queue_response (connection, MHD_HTTP_OK, response);
}

/*
 * Buffer for the hostlist address
 */
char hostlist_uri[255];

/**
 * Handler called by core when core is ready to transmit message
 * @param cls   closure
 * @param size  size of buffer to copy message to
 * @param buf   buffer to copy message to
 */
static size_t
adv_transmit_ready ( void *cls, size_t size, void *buf)
{
  size_t transmission_size;
  size_t uri_size; /* Including \0 termination! */
  uri_size = strlen ( hostlist_uri ) + 1;

  struct GNUNET_HOSTLIST_ADV_Message * adv_message;
  adv_message = GNUNET_malloc ( sizeof(struct GNUNET_HOSTLIST_ADV_Message) + uri_size);
  if ( NULL == adv_message)
   {
   GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
       "Could not allocate memory for the message");
   return GNUNET_NO;
   }
  transmission_size = sizeof (struct GNUNET_HOSTLIST_ADV_Message) + uri_size;

  adv_message->header.type = htons (GNUNET_MESSAGE_TYPE_HOSTLIST_ADVERTISEMENT);
  adv_message->header.size = htons (transmission_size);
  memcpy(&adv_message[1],hostlist_uri,uri_size);

  if (buf == NULL)
    {
      GNUNET_log ( GNUNET_ERROR_TYPE_DEBUG, "Transmission failed, buffer invalid!\n" );
      return 0;
    }

  if ( size >= transmission_size )
    {
      memcpy ( buf, adv_message, transmission_size );
      GNUNET_log ( GNUNET_ERROR_TYPE_DEBUG, "Sent advertisement message: Copied %d bytes into buffer!\n", transmission_size);
      GNUNET_free ( adv_message );
      return transmission_size;
    }

  GNUNET_free (adv_message  );
  return size;
}

/**
 * Method that asks core service to transmit the message to the peer
 * @param peer peer to transmit message to
 * @param size size of the message
 */
static size_t
adv_transmit_message ( const struct GNUNET_PeerIdentity * peer, size_t size )
{
  /* transmit message to peer */
  if ( NULL == core)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Not connected to core, unable to send advertisement message\n"));
      return GNUNET_NO;
    }

  struct GNUNET_TIME_Relative timeout = GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, GNUNET_ADV_TIMEOUT);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Asked core to transmit advertisement message with a size of %u bytes\n"), size);
  struct GNUNET_CORE_TransmitHandle * th;
  th = GNUNET_CORE_notify_transmit_ready (core,
                                     0,
                                     timeout,
                                     peer,
                                     size,
                                     &adv_transmit_ready, NULL);
  if ( NULL == th )
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Advertisement message could not be queued by core\n"));
    return GNUNET_NO;

  return GNUNET_YES;
}

/**
 * Method that assembles our hostlist advertisement message
 * @param peer peer to send the hostlist advertisement
 */
static size_t
adv_create_message ( const struct GNUNET_PeerIdentity * peer )

{
  size_t length  = 0;
  size_t size    = 0;
  unsigned long long port;

  char *uri;
  char hostname[GNUNET_OS_get_hostname_max_length() + 1];
  char *protocol = "http://";
  char *port_s = GNUNET_malloc(6 * sizeof(char));

  if (0 != gethostname (hostname, sizeof (hostname) - 1))
  {
    GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
        "Could not get system's hostname, unable to create advertisement message");
    return GNUNET_NO;
  }
  if (-1 == GNUNET_CONFIGURATION_get_value_number (cfg,
                                                   "HOSTLIST",
                                                   "HTTPPORT",
                                                   &port))
    return GNUNET_SYSERR;

  sprintf(port_s, "%llu", port);
  length = strlen(hostname)+strlen(protocol)+strlen(port_s)+2;
  size = (length+1) * sizeof (char);
  uri = GNUNET_malloc(size);
  uri = strcpy(uri, protocol);
  uri = strcat(uri, hostname);
  uri = strcat(uri, ":");
  uri = strcat(uri, port_s);
  uri = strcat(uri, "/");
  strcpy(hostlist_uri,uri);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,"Address to obtain hostlist: %s\n", hostlist_uri);

  if ( ( size + sizeof( struct GNUNET_HOSTLIST_ADV_Message )) > GNUNET_SERVER_MAX_MESSAGE_SIZE)
    {
      GNUNET_log_strerror (GNUNET_ERROR_TYPE_ERROR,
          "Advertisement message is bigger than GNUNET allows");
      return GNUNET_NO;
    }

  /* Request core to transmit message to peer */
  size = size + sizeof ( struct GNUNET_HOSTLIST_ADV_Message );
  adv_transmit_message(peer, size);

  GNUNET_free ( port_s );
  GNUNET_free ( uri );

  return GNUNET_OK;
}

/**
 * Method called whenever a given peer connects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 * @param latency reported latency of the connection with 'other'
 * @param distance reported distance (DV) to 'other'
 */
static void
connect_handler (void *cls,
                 const struct
                 GNUNET_PeerIdentity * peer,
                 struct GNUNET_TIME_Relative latency,
                 uint32_t distance)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "A new peer connected to the server, preparing to send hostlist advertisement\n");
  /* create a new advertisement message */
  if ( (GNUNET_OK != adv_create_message(peer)))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _(" GNUNET_OK Could not create a hostlist advertisement message, impossible to advertise hostlist\n"));
    return;
  }
}


/**
 * Method called whenever a given peer disconnects.
 *
 * @param cls closure
 * @param peer peer identity this notification is about
 */
static void
disconnect_handler (void *cls,
                    const struct
                    GNUNET_PeerIdentity * peer)
{

}


/**
 * Function that queries MHD's select sets and
 * starts the task waiting for them.
 */
static GNUNET_SCHEDULER_TaskIdentifier
prepare_daemon (struct MHD_Daemon *daemon_handle);

/**
 * Call MHD to process pending requests and then go back
 * and schedule the next run.
 */
static void
run_daemon (void *cls,
	    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct MHD_Daemon *daemon_handle = cls;

  if (daemon_handle == daemon_handle_v4)
    hostlist_task_v4 = GNUNET_SCHEDULER_NO_TASK;
  else
    hostlist_task_v6 = GNUNET_SCHEDULER_NO_TASK;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_SHUTDOWN))
    return;    
  GNUNET_assert (MHD_YES == MHD_run (daemon_handle));
  if (daemon_handle == daemon_handle_v4)
    hostlist_task_v4 = prepare_daemon (daemon_handle);
  else
    hostlist_task_v6 = prepare_daemon (daemon_handle);
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
  ret = GNUNET_SCHEDULER_add_select (sched,
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
 * Start server offering our hostlist.
 *
 * @return GNUNET_OK on success
 */
int
GNUNET_HOSTLIST_server_start (const struct GNUNET_CONFIGURATION_Handle *c,
			      struct GNUNET_SCHEDULER_Handle *s,
			      struct GNUNET_STATISTICS_Handle *st,
			      struct GNUNET_CORE_Handle *co,
	                      GNUNET_CORE_ConnectEventHandler *server_ch,
                              GNUNET_CORE_DisconnectEventHandler *server_dh)
{
  unsigned long long port;

  sched = s;
  cfg = c;
  stats = st;
  if (-1 == GNUNET_CONFIGURATION_get_value_number (cfg,
						   "HOSTLIST",
						   "HTTPPORT", 
						   &port))
    return GNUNET_SYSERR;
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
	      _("Hostlist service starts on port %llu\n"),
	      port);
  daemon_handle_v6 = MHD_start_daemon (MHD_USE_IPv6 
#if DEBUG_HOSTLIST_SERVER
				       | MHD_USE_DEBUG
#endif
				       ,
				       (unsigned short) port,
				       &accept_policy_callback,
				       NULL,
				       &access_handler_callback,
				       NULL,
				       MHD_OPTION_CONNECTION_LIMIT, (unsigned int) 16,
				       MHD_OPTION_PER_IP_CONNECTION_LIMIT, (unsigned int) 1,
				       MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 16,
				       MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t) (16 * 1024),
				       MHD_OPTION_END);
  daemon_handle_v4 = MHD_start_daemon (MHD_NO_FLAG
#if DEBUG_HOSTLIST_SERVER
				       | MHD_USE_DEBUG
#endif
				       ,
				       (unsigned short) port,
				       &accept_policy_callback,
				       NULL,
				       &access_handler_callback,
				       NULL,
				       MHD_OPTION_CONNECTION_LIMIT, (unsigned int) 16,
				       MHD_OPTION_PER_IP_CONNECTION_LIMIT, (unsigned int) 1,
				       MHD_OPTION_CONNECTION_TIMEOUT, (unsigned int) 16,
				       MHD_OPTION_CONNECTION_MEMORY_LIMIT, (size_t) (16 * 1024),
				       MHD_OPTION_END);

  if ( (daemon_handle_v6 == NULL) &&
       (daemon_handle_v4 == NULL) )
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Could not start hostlist HTTP server on port %u\n"),
		  (unsigned short) port);
      return GNUNET_SYSERR;    
    }

  core=co;

  *server_ch = &connect_handler;
  *server_dh = &disconnect_handler;

  if (daemon_handle_v4 != NULL)
    hostlist_task_v4 = prepare_daemon (daemon_handle_v4);
  if (daemon_handle_v6 != NULL)
    hostlist_task_v6 = prepare_daemon (daemon_handle_v6);
  response_task = GNUNET_SCHEDULER_add_now (sched,
					    &update_response,
					    NULL);
  return GNUNET_OK;
}

/**
 * Stop server offering our hostlist.
 */
void
GNUNET_HOSTLIST_server_stop ()
{
#if DEBUG_HOSTLIST_SERVER
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Hostlist server shutdown\n");
#endif
  if (GNUNET_SCHEDULER_NO_TASK != hostlist_task_v6)
    {
      GNUNET_SCHEDULER_cancel (sched, hostlist_task_v6);
      hostlist_task_v6 = GNUNET_SCHEDULER_NO_TASK;
    }
  if (GNUNET_SCHEDULER_NO_TASK != hostlist_task_v4)
    {
      GNUNET_SCHEDULER_cancel (sched, hostlist_task_v4);
      hostlist_task_v4 = GNUNET_SCHEDULER_NO_TASK;
    }
  if (pitr != NULL)
    {
      GNUNET_PEERINFO_iterate_cancel (pitr);
      pitr = NULL;
    }
  if (GNUNET_SCHEDULER_NO_TASK != response_task)
    {
      GNUNET_SCHEDULER_cancel (sched, response_task);
      response_task = GNUNET_SCHEDULER_NO_TASK;
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
  if (response != NULL)
    {
      MHD_destroy_response (response);
      response = NULL;
    }
}

/* end of hostlist-server.c */
