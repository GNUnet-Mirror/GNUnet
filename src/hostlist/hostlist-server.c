/*
     This file is part of GNUnet.
     (C) 2008 Christian Grothoff (and other contributing authors)

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

/**
 * How often should we recalculate our response to hostlist requests?
 */
#define RESPONSE_UPDATE_FREQUENCY GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MINUTES, 5)

/**
 * Handle to the HTTP server as provided by libmicrohttpd.
 */
static struct MHD_Daemon *daemon_handle;

/**
 * Our configuration.
 */
static struct GNUNET_CONFIGURATION_Handle *cfg;

/**
 * Our scheduler.
 */
static struct GNUNET_SCHEDULER_Handle *sched;

/**
 * Our canonical response.
 */
static struct MHD_Response *response;

/**
 * Context for host processor.
 */
struct HostSet
{
  size_t size;

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
  if (response != NULL)
    MHD_destroy_response (response);
  response = MHD_create_response_from_data (results->size,
                                            results->data, MHD_YES, MHD_NO);
  GNUNET_free (results);
  /* schedule next update of the response */  
  GNUNET_SCHEDULER_add_delayed (sched,
				GNUNET_NO,
				GNUNET_SCHEDULER_PRIORITY_IDLE,
				GNUNET_SCHEDULER_NO_PREREQUISITE_TASK,
				RESPONSE_UPDATE_FREQUENCY,
				&update_response,
				NULL);
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
  
  if (peer == NULL)
    finish_response (results);
  old = results->size;
  s = GNUNET_HELLO_size(hello);
  if (old + s >= GNUNET_MAX_MALLOC_CHECKED)
    return; /* too large, skip! */
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

  results = GNUNET_malloc(sizeof(struct HostSet));
  GNUNET_PEERINFO_for_all (cfg, sched, 
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
                         unsigned int *upload_data_size, void **con_cls)
{
  static int dummy;
  
  if (0 != strcmp (method, MHD_HTTP_METHOD_GET))
    return MHD_NO;
  if (NULL == *con_cls)
    {
      (*con_cls) = &dummy;
      return MHD_YES;           /* send 100 continue */
    }
  if (*upload_data_size != 0)
    return MHD_NO;              /* do not support upload data */
  if (response == NULL)
    return MHD_NO;              /* internal error, no response yet */
  return MHD_queue_response (connection, MHD_HTTP_OK, response);
}


/**
 * Function that queries MHD's select sets and
 * starts the task waiting for them.
 */
static void 
prepare_daemon (void);


static void
run_daemon (void *cls,
	    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  GNUNET_assert (MHD_YES == MHD_run (daemon_handle));
  prepare_daemon ();
}


/**
 * Function that queries MHD's select sets and
 * starts the task waiting for them.
 */
static void 
prepare_daemon ()
{
  fd_set rs;
  fd_set ws;
  fd_set es;
  int max;
  unsigned long long timeout;
  int haveto;
  struct GNUNET_TIME_Relative tv;
  
  FD_ZERO(&rs);
  FD_ZERO(&ws);
  FD_ZERO(&es);
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
  GNUNET_SCHEDULER_add_select (sched,
			       GNUNET_NO,
			       GNUNET_SCHEDULER_PRIORITY_HIGH,
			       GNUNET_SCHEDULER_NO_PREREQUISITE_TASK,
			       tv,
			       max,
			       &rs,
			       &ws,
			       &run_daemon,
			       NULL);
}



/**
 * Start server offering our hostlist.
 *
 * @return GNUNET_OK on success
 */
int
GNUNET_HOSTLIST_server_start (struct GNUNET_CONFIGURATION_Handle *c,
			      struct GNUNET_SCHEDULER_Handle *s,
			      struct GNUNET_STATISTICS_Handle *st)
{
  unsigned long long port;

  sched = s;
  cfg = c;
  if (-1 == GNUNET_CONFIGURATION_get_value_number (cfg,
						   "HOSTLIST",
						   "PORT", 
						   &port))
    return GNUNET_SYSERR;
  daemon_handle = MHD_start_daemon (MHD_USE_IPv6,
                                    (unsigned short) port,
                                    &accept_policy_callback,
                                    NULL,
                                    &access_handler_callback,
                                    NULL,
                                    MHD_OPTION_CONNECTION_LIMIT, 16,
                                    MHD_OPTION_PER_IP_CONNECTION_LIMIT, 1,
                                    MHD_OPTION_CONNECTION_TIMEOUT, 16,
                                    MHD_OPTION_CONNECTION_MEMORY_LIMIT,
                                    16 * 1024, MHD_OPTION_END);
  if (daemon_handle == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
		  _("Could not start hostlist HTTP server on port %u\n"),
		  (unsigned short) port);
      return GNUNET_SYSERR;    
    }
  prepare_daemon ();
  return GNUNET_OK;
}

/**
 * Stop server offering our hostlist.
 */
void
GNUNET_HOSTLIST_server_stop ()
{
  MHD_stop_daemon (daemon_handle);
  daemon_handle = NULL;
}

/* end of hostlist-server.c */
