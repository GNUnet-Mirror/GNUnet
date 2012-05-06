/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2012 Christian Grothoff (and other contributing authors)

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
 * @file arm/arm_api.c
 * @brief API for accessing the ARM service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_client_lib.h"
#include "gnunet_getopt_lib.h"
#include "gnunet_os_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_server_lib.h"
#include "arm.h"

#define LOG(kind,...) GNUNET_log_from (kind, "arm-api",__VA_ARGS__)

/**
 * Handle for interacting with ARM.
 */
struct GNUNET_ARM_Handle
{

  /**
   * Our connection to the ARM service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * The configuration that we are using.
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

};

/**
 * Context for handling the shutdown of a service.
 */
struct ShutdownContext
{
  /**
   * Connection to the service that is being shutdown.
   */
  struct GNUNET_CLIENT_Connection *sock;

  /**
   * Time allowed for shutdown to happen.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Task set up to cancel the shutdown request on timeout.
   */
  GNUNET_SCHEDULER_TaskIdentifier cancel_task;

  /**
   * Task to call once shutdown complete
   */
  GNUNET_CLIENT_ShutdownTask cont;

  /**
   * Closure for shutdown continuation
   */
  void *cont_cls;

  /**
   * Handle for transmission request.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

};


/**
 * Handler receiving response to service shutdown requests.
 * First call with NULL: service misbehaving, or something.
 * First call with GNUNET_MESSAGE_TYPE_ARM_SHUTDOWN_ACK:
 *   - service will shutdown
 * Second call with NULL:
 *   - service has now really shut down.
 *
 * @param cls closure
 * @param msg NULL, indicating socket closure.
 */
static void
service_shutdown_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct ShutdownContext *shutdown_ctx = cls;

  if (NULL != msg)
  {
    /* We just expected a disconnect! Report the error and be done with it... */
    GNUNET_break (0);
    shutdown_ctx->cont (shutdown_ctx->cont_cls, GNUNET_ARM_PROCESS_COMMUNICATION_ERROR);
    GNUNET_SCHEDULER_cancel (shutdown_ctx->cancel_task);
    GNUNET_CLIENT_disconnect (shutdown_ctx->sock);
    GNUNET_free (shutdown_ctx);
    return;
  }
  if (NULL != shutdown_ctx->cont)
    /* shutdown is now complete, as we waited for the network disconnect... */
    shutdown_ctx->cont (shutdown_ctx->cont_cls, GNUNET_ARM_PROCESS_DOWN);    
  GNUNET_SCHEDULER_cancel (shutdown_ctx->cancel_task);
  GNUNET_CLIENT_disconnect (shutdown_ctx->sock);
  GNUNET_free (shutdown_ctx);
}


/**
 * Shutting down took too long, cancel receive and return error.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
static void
service_shutdown_cancel (void *cls,
			 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ShutdownContext *shutdown_ctx = cls;

  shutdown_ctx->cont (shutdown_ctx->cont_cls, GNUNET_ARM_PROCESS_COMMUNICATION_TIMEOUT);
  GNUNET_CLIENT_disconnect (shutdown_ctx->sock);
  GNUNET_free (shutdown_ctx);
}


/**
 * If possible, write a shutdown message to the target
 * buffer and destroy the client connection.
 *
 * @param cls the "struct GNUNET_CLIENT_Connection" to destroy
 * @param size number of bytes available in buf
 * @param buf NULL on error, otherwise target buffer
 * @return number of bytes written to buf
 */
static size_t
write_shutdown (void *cls, size_t size, void *buf)
{
  struct ShutdownContext *shutdown_ctx = cls;
  struct GNUNET_MessageHeader *msg;

  shutdown_ctx->th = NULL;
  if (size < sizeof (struct GNUNET_MessageHeader))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
	 _("Failed to transmit shutdown request to client.\n"));
    shutdown_ctx->cont (shutdown_ctx->cont_cls, GNUNET_ARM_PROCESS_COMMUNICATION_ERROR);
    GNUNET_CLIENT_disconnect (shutdown_ctx->sock);
    GNUNET_free (shutdown_ctx);
    return 0;			/* client disconnected */
  }
  GNUNET_CLIENT_receive (shutdown_ctx->sock, &service_shutdown_handler,
			 shutdown_ctx, GNUNET_TIME_UNIT_FOREVER_REL);
  shutdown_ctx->cancel_task =
    GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_absolute_get_remaining
				  (shutdown_ctx->timeout),
				  &service_shutdown_cancel, shutdown_ctx);
  msg = (struct GNUNET_MessageHeader *) buf;
  msg->type = htons (GNUNET_MESSAGE_TYPE_ARM_SHUTDOWN);
  msg->size = htons (sizeof (struct GNUNET_MessageHeader));
  return sizeof (struct GNUNET_MessageHeader);
}


/**
 * Request that the service should shutdown.
 * Afterwards, the connection will automatically be
 * disconnected.  Hence the "sock" should not
 * be used by the caller after this call
 * (calling this function frees "sock" after a while).
 *
 * @param sock the socket connected to the service
 * @param timeout how long to wait before giving up on transmission
 * @param cont continuation to call once the service is really down
 * @param cont_cls closure for continuation
 *
 */
static void
arm_service_shutdown (struct GNUNET_CLIENT_Connection *sock,
		      struct GNUNET_TIME_Relative timeout,
		      GNUNET_CLIENT_ShutdownTask cont, void *cont_cls)
{
  struct ShutdownContext *shutdown_ctx;

  shutdown_ctx = GNUNET_malloc (sizeof (struct ShutdownContext));
  shutdown_ctx->cont = cont;
  shutdown_ctx->cont_cls = cont_cls;
  shutdown_ctx->sock = sock;
  shutdown_ctx->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  shutdown_ctx->th = GNUNET_CLIENT_notify_transmit_ready (sock,
							  sizeof (struct GNUNET_MessageHeader),
							  timeout, GNUNET_NO, &write_shutdown,
							  shutdown_ctx);
}


/**
 * Setup a context for communicating with ARM.  Note that this
 * can be done even if the ARM service is not yet running.
 *
 * @param cfg configuration to use (needed to contact ARM;
 *        the ARM service may internally use a different
 *        configuration to determine how to start the service).
 * @param service service that *this* process is implementing/providing, can be NULL
 * @return context to use for further ARM operations, NULL on error
 */
struct GNUNET_ARM_Handle *
GNUNET_ARM_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
		    const char *service)
{
  struct GNUNET_ARM_Handle *ret;

  ret = GNUNET_malloc (sizeof (struct GNUNET_ARM_Handle));
  ret->cfg = GNUNET_CONFIGURATION_dup (cfg);
  return ret;
}


/**
 * Disconnect from the ARM service.
 *
 * @param h the handle that was being used
 */
void
GNUNET_ARM_disconnect (struct GNUNET_ARM_Handle *h)
{
  if (h->client != NULL)
    GNUNET_CLIENT_disconnect (h->client);
  GNUNET_CONFIGURATION_destroy (h->cfg);
  GNUNET_free (h);
}


struct ARM_ShutdownContext
{
  /**
   * Callback to call once shutdown complete.
   */
  GNUNET_ARM_Callback cb;

  /**
   * Closure for callback.
   */
  void *cb_cls;
};


/**
 * Internal state for a request with ARM.
 */
struct RequestContext
{

  /**
   * Pointer to our handle with ARM.
   */
  struct GNUNET_ARM_Handle *h;

  /**
   * Function to call with a status code for the requested operation.
   */
  GNUNET_ARM_Callback callback;

  /**
   * Closure for "callback".
   */
  void *cls;

  /**
   * Timeout for the operation.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Type of the request expressed as a message type (start or stop).
   */
  uint16_t type;

};

#include "do_start_process.c"


/**
 * A client specifically requested starting of ARM itself.
 * This function is called with information about whether
 * or not ARM is running; if it is, report success.  If
 * it is not, start the ARM process.
 *
 * @param cls the context for the request that we will report on (struct RequestContext*)
 * @param tc why were we called (reason says if ARM is running)
 */
static void
arm_service_report (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RequestContext *pos = cls;
  struct GNUNET_OS_Process *proc;
  char *binary;
  char *config;
  char *loprefix;
  char *lopostfix;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Looks like `%s' is already running.\n",
	 "gnunet-service-arm");
    /* arm is running! */
    if (pos->callback != NULL)
      pos->callback (pos->cls, GNUNET_ARM_PROCESS_ALREADY_RUNNING);
    GNUNET_free (pos);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Looks like `%s' is not running, will start it.\n",
       "gnunet-service-arm");
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (pos->h->cfg, "arm", "PREFIX",
					     &loprefix))
    loprefix = GNUNET_strdup ("");
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (pos->h->cfg, "arm", "OPTIONS",
					     &lopostfix))
    lopostfix = GNUNET_strdup ("");
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (pos->h->cfg, "arm", "BINARY",
					     &binary))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
	 _
	 ("Configuration failes to specify option `%s' in section `%s'!\n"),
	 "BINARY", "arm");
    if (pos->callback != NULL)
      pos->callback (pos->cls, GNUNET_ARM_PROCESS_UNKNOWN);
    GNUNET_free (pos);
    GNUNET_free (loprefix);
    GNUNET_free (lopostfix);
    return;
  }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (pos->h->cfg, "arm", "CONFIG",
					       &config))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
	 _("Configuration fails to specify option `%s' in section `%s'!\n"),
	 "CONFIG", "arm");
    if (pos->callback != NULL)
      pos->callback (pos->cls, GNUNET_ARM_PROCESS_UNKNOWN);
    GNUNET_free (binary);
    GNUNET_free (pos);
    GNUNET_free (loprefix);
    GNUNET_free (lopostfix);
    return;
  }
  if ((GNUNET_YES ==
       GNUNET_CONFIGURATION_have_value (pos->h->cfg, "TESTING", "WEAKRANDOM"))
      && (GNUNET_YES ==
	  GNUNET_CONFIGURATION_get_value_yesno (pos->h->cfg, "TESTING",
						"WEAKRANDOM"))
      && (GNUNET_NO ==
	  GNUNET_CONFIGURATION_have_value (pos->h->cfg, "TESTING",
					   "HOSTFILE")))
  {
    /* Means we are ONLY running locally */
    /* we're clearly running a test, don't daemonize */
    proc = do_start_process (GNUNET_NO,
			     NULL, loprefix, binary, "-c", config,
			     /* no daemonization! */
			     lopostfix, NULL);
  }
  else
  {
    proc = do_start_process (GNUNET_NO,
			     NULL, loprefix, binary, "-c", config,
			     "-d", lopostfix, NULL);
  }
  GNUNET_free (binary);
  GNUNET_free (config);
  GNUNET_free (loprefix);
  GNUNET_free (lopostfix);
  if (proc == NULL)
    {
      if (pos->callback != NULL)
	pos->callback (pos->cls, GNUNET_ARM_PROCESS_FAILURE);
      GNUNET_free (pos);
      return;
    }
  if (pos->callback != NULL)
    pos->callback (pos->cls, GNUNET_ARM_PROCESS_STARTING);
  GNUNET_free (proc);
  GNUNET_free (pos);
}


/**
 * Process a response from ARM to a request for a change in service
 * status.
 *
 * @param cls the request context
 * @param msg the response
 */
static void
handle_response (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct RequestContext *sc = cls;
  const struct GNUNET_ARM_ResultMessage *res;
  enum GNUNET_ARM_ProcessStatus status;

  if ((msg == NULL) ||
      (ntohs (msg->size) != sizeof (struct GNUNET_ARM_ResultMessage)))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
	 _
	 ("Error receiving response to `%s' request from ARM for service `%s'\n"),
	 (sc->type == GNUNET_MESSAGE_TYPE_ARM_START) ? "START" : "STOP",
	 (const char *) &sc[1]);
    GNUNET_CLIENT_disconnect (sc->h->client);
    sc->h->client = GNUNET_CLIENT_connect ("arm", sc->h->cfg);
    GNUNET_assert (NULL != sc->h->client);
    if (sc->callback != NULL)
      sc->callback (sc->cls, GNUNET_ARM_PROCESS_COMMUNICATION_ERROR);
    GNUNET_free (sc);
    return;
  }
  res = (const struct GNUNET_ARM_ResultMessage *) msg;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received response from ARM for service `%s': %u\n",
       (const char *) &sc[1], ntohs (msg->type));
  status = (enum GNUNET_ARM_ProcessStatus) ntohl (res->status);
  if (sc->callback != NULL)
    sc->callback (sc->cls, status);
  GNUNET_free (sc);
}


/**
 * Start or stop a service.
 *
 * @param h handle to ARM
 * @param service_name name of the service
 * @param timeout how long to wait before failing for good
 * @param cb callback to invoke when service is ready
 * @param cb_cls closure for callback
 * @param type type of the request
 */
static void
change_service (struct GNUNET_ARM_Handle *h, const char *service_name,
		struct GNUNET_TIME_Relative timeout, GNUNET_ARM_Callback cb,
		void *cb_cls, uint16_t type)
{
  struct RequestContext *sctx;
  size_t slen;
  struct GNUNET_MessageHeader *msg;

  slen = strlen (service_name) + 1;
  if (slen + sizeof (struct GNUNET_MessageHeader) >=
      GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    if (cb != NULL)
      cb (cb_cls, GNUNET_NO);
    return;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       (type ==
	GNUNET_MESSAGE_TYPE_ARM_START) ?
       _("Requesting start of service `%s'.\n") :
       _("Requesting termination of service `%s'.\n"), service_name);
  sctx = GNUNET_malloc (sizeof (struct RequestContext) + slen);
  sctx->h = h;
  sctx->callback = cb;
  sctx->cls = cb_cls;
  sctx->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  sctx->type = type;
  memcpy (&sctx[1], service_name, slen);
  msg = GNUNET_malloc (sizeof (struct GNUNET_MessageHeader) + slen);
  msg->size = htons (sizeof (struct GNUNET_MessageHeader) + slen);
  msg->type = htons (sctx->type);
  memcpy (&msg[1], service_name, slen);
  if (GNUNET_OK !=
      GNUNET_CLIENT_transmit_and_get_response (sctx->h->client, msg,
					       GNUNET_TIME_absolute_get_remaining
					       (sctx->timeout), GNUNET_YES,
					       &handle_response, sctx))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
	 (type ==
	  GNUNET_MESSAGE_TYPE_ARM_START)
	 ? _("Error while trying to transmit request to start `%s' to ARM\n")	 
	 : _("Error while trying to transmit request to stop `%s' to ARM\n"),
	 (const char *) &service_name);
    if (cb != NULL)
      cb (cb_cls, GNUNET_SYSERR);
    GNUNET_free (sctx);
    GNUNET_free (msg);
    return;
  }
  GNUNET_free (msg);
}


/**
 * Start a service.
 *
 * @param h handle to ARM
 * @param service_name name of the service
 * @param timeout how long to wait before failing for good
 * @param cb callback to invoke when service is ready
 * @param cb_cls closure for callback
 */
void
GNUNET_ARM_start_service (struct GNUNET_ARM_Handle *h,
			  const char *service_name,
			  struct GNUNET_TIME_Relative timeout,
			  GNUNET_ARM_Callback cb, void *cb_cls)
{
  struct RequestContext *sctx;
  struct GNUNET_CLIENT_Connection *client;
  size_t slen;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       _("Asked to start service `%s' within %llu ms\n"), service_name,
       (unsigned long long) timeout.rel_value);
  if (0 == strcasecmp ("arm", service_name))
  {
    slen = strlen ("arm") + 1;
    sctx = GNUNET_malloc (sizeof (struct RequestContext) + slen);
    sctx->h = h;
    sctx->callback = cb;
    sctx->cls = cb_cls;
    sctx->timeout = GNUNET_TIME_relative_to_absolute (timeout);
    memcpy (&sctx[1], service_name, slen);
    GNUNET_CLIENT_service_test ("arm", h->cfg, timeout, &arm_service_report,
				sctx);
    return;
  }
  if (h->client == NULL)
  {
    client = GNUNET_CLIENT_connect ("arm", h->cfg);
    if (client == NULL)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
	   "arm_api, GNUNET_CLIENT_connect returned NULL\n");
      cb (cb_cls, GNUNET_ARM_PROCESS_COMMUNICATION_ERROR);
      return;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "arm_api, GNUNET_CLIENT_connect returned non-NULL\n");
    h->client = client;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG, "arm_api, h->client non-NULL\n");
  change_service (h, service_name, timeout, cb, cb_cls,
		  GNUNET_MESSAGE_TYPE_ARM_START);
}


/**
 * Callback from the arm stop service call, indicates that the arm service
 * is well and truly dead, won't die, or an error occurred.
 *
 * @param cls closure for the callback
 * @param reason reason for callback
 */
static void
arm_shutdown_callback (void *cls, enum GNUNET_ARM_ProcessStatus reason)
{
  struct ARM_ShutdownContext *arm_shutdown_ctx = cls;

  if (arm_shutdown_ctx->cb != NULL)
    arm_shutdown_ctx->cb (arm_shutdown_ctx->cb_cls, reason);

  GNUNET_free (arm_shutdown_ctx);
}


/**
 * Stop a service.
 *
 * @param h handle to ARM
 * @param service_name name of the service
 * @param timeout how long to wait before failing for good
 * @param cb callback to invoke when service is ready
 * @param cb_cls closure for callback
 */
void
GNUNET_ARM_stop_service (struct GNUNET_ARM_Handle *h,
			 const char *service_name,
			 struct GNUNET_TIME_Relative timeout,
			 GNUNET_ARM_Callback cb, void *cb_cls)
{
  struct ARM_ShutdownContext *arm_shutdown_ctx;
  struct GNUNET_CLIENT_Connection *client;

  LOG (GNUNET_ERROR_TYPE_INFO, _("Stopping service `%s' within %llu ms\n"),
       service_name, (unsigned long long) timeout.rel_value);
  if (h->client == NULL)
  {
    client = GNUNET_CLIENT_connect ("arm", h->cfg);
    if (client == NULL)
    {
      cb (cb_cls, GNUNET_SYSERR);
      return;
    }
    h->client = client;
  }
  if (0 == strcasecmp ("arm", service_name))
  {
    arm_shutdown_ctx = GNUNET_malloc (sizeof (struct ARM_ShutdownContext));
    arm_shutdown_ctx->cb = cb;
    arm_shutdown_ctx->cb_cls = cb_cls;
    arm_service_shutdown (h->client, timeout, &arm_shutdown_callback,
			  arm_shutdown_ctx);
    h->client = NULL;
    return;
  }
  change_service (h, service_name, timeout, cb, cb_cls,
		  GNUNET_MESSAGE_TYPE_ARM_STOP);
}


/**
 * Internal state for a list request with ARM.
 */
struct ListRequestContext
{

  /**
   * Pointer to our handle with ARM.
   */
  struct GNUNET_ARM_Handle *h;

  /**
   * Function to call with a status code for the requested operation.
   */
  GNUNET_ARM_List_Callback callback;

  /**
   * Closure for "callback".
   */
  void *cls;

  /**
   * Timeout for the operation.
   */
  struct GNUNET_TIME_Absolute timeout;
};


/**
 * Process a response from ARM for the list request.
 *
 * @param cls the list request context
 * @param msg the response
 */
static void
handle_list_response (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct ListRequestContext *sc = cls;
  const struct GNUNET_ARM_ListResultMessage *res;
  const char *pos;
  uint16_t size_check;
  uint16_t rcount;
  uint16_t msize;
  
  if (NULL == msg)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
	 "Error receiving response to LIST request from ARM\n");
    GNUNET_CLIENT_disconnect (sc->h->client);
    sc->h->client = GNUNET_CLIENT_connect ("arm", sc->h->cfg);
    GNUNET_assert (NULL != sc->h->client);
    if (sc->callback != NULL)
      sc->callback (sc->cls, GNUNET_ARM_PROCESS_COMMUNICATION_ERROR, 0, NULL);
    GNUNET_free (sc);
    return;
  }
   
  if (NULL == sc->callback) 
  {
    GNUNET_break (0);
    GNUNET_free (sc);
    return;
  }  
  msize = ntohs (msg->size);
  if ( (msize < sizeof ( struct GNUNET_ARM_ListResultMessage)) ||
       (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_ARM_LIST_RESULT) )
  {
    GNUNET_break (0);
    sc->callback (sc->cls, GNUNET_NO, 0, NULL);
    GNUNET_free (sc);
    return;
  }
  size_check = 0;
  res = (const struct GNUNET_ARM_ListResultMessage *) msg;
  rcount = ntohs (res->count);
  {
    const char *list[rcount];
    unsigned int i;
    
    pos = (const char *)&res[1];   
    for (i=0; i<rcount; i++)
    {
      const char *end = memchr (pos, 0, msize - size_check);
      if (NULL == end)
      {
	GNUNET_break (0);
	sc->callback (sc->cls, GNUNET_NO, 0, NULL);
	GNUNET_free (sc);
	return;
      }
      list[i] = pos;
      size_check += (end - pos) + 1;
      pos = end + 1;
    }
    sc->callback (sc->cls, GNUNET_YES, rcount, list);
  }
  GNUNET_free (sc);
}


/**
 * List all running services.
 * 
 * @param h handle to ARM
 * @param timeout how long to wait before failing for good
 * @param cb callback to invoke when service is ready
 * @param cb_cls closure for callback
 */
void
GNUNET_ARM_list_running_services (struct GNUNET_ARM_Handle *h,
                                  struct GNUNET_TIME_Relative timeout,
                                  GNUNET_ARM_List_Callback cb, void *cb_cls)
{
  struct ListRequestContext *sctx;
  struct GNUNET_MessageHeader msg;
  struct GNUNET_CLIENT_Connection *client;
  
  if (h->client == NULL)
  {
    client = GNUNET_CLIENT_connect ("arm", h->cfg);
    if (client == NULL)
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
	   "arm_api, GNUNET_CLIENT_connect returned NULL\n");
      cb (cb_cls, GNUNET_ARM_PROCESS_COMMUNICATION_ERROR, 0, NULL);
      return;
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "arm_api, GNUNET_CLIENT_connect returned non-NULL\n");
    h->client = client;
  }
  
  sctx = GNUNET_malloc (sizeof (struct RequestContext));
  sctx->h = h;
  sctx->callback = cb;
  sctx->cls = cb_cls;
  sctx->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  msg.size = htons (sizeof (struct GNUNET_MessageHeader));
  msg.type = htons (GNUNET_MESSAGE_TYPE_ARM_LIST);
  
  LOG (GNUNET_ERROR_TYPE_DEBUG, 
       "Requesting LIST from ARM service with timeout: %llu ms\n", 
       (unsigned long long)timeout.rel_value);
  
  if (GNUNET_OK !=
      GNUNET_CLIENT_transmit_and_get_response (sctx->h->client, 
                                               &msg,
                                               GNUNET_TIME_absolute_get_remaining
                                               (sctx->timeout), 
                                               GNUNET_YES,
                                               &handle_list_response, 
                                               sctx))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING, 
	 "Error while trying to transmit request to list services to ARM\n");
    if (cb != NULL)
      cb (cb_cls, GNUNET_SYSERR, 0, NULL);
    GNUNET_free (sctx);
    return;
  }
}

/* end of arm_api.c */
