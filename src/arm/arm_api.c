/*
     This file is part of GNUnet.
     (C) 2009 Christian Grothoff (and other contributing authors)

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

/**
 * How often do we re-try tranmsitting requests to ARM before
 * giving up?  Note that if we succeeded transmitting a request
 * but failed to read a response, we do NOT re-try (since that
 * might result in ARM getting a request twice).
 */
#define MAX_ATTEMPTS 4

/**
 * Minimum delay between attempts to talk to ARM.
 */
#define MIN_RETRY_DELAY  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_MILLISECONDS, 100)


/**
 * How long are we willing to wait for a service operation during the multi-operation
 * request processing?
 */
#define MULTI_TIMEOUT  GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)


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
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Scheduler to use.
   */
  struct GNUNET_SCHEDULER_Handle *sched;

};


/**
 * Setup a context for communicating with ARM.  Note that this
 * can be done even if the ARM service is not yet running.
 *
 * @param cfg configuration to use (needed to contact ARM;
 *        the ARM service may internally use a different
 *        configuration to determine how to start the service).
 * @param sched scheduler to use
 * @param service service that *this* process is implementing/providing, can be NULL
 * @return context to use for further ARM operations, NULL on error
 */
struct GNUNET_ARM_Handle *
GNUNET_ARM_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
		    struct GNUNET_SCHEDULER_Handle *sched,
		    const char *service)
{
  struct GNUNET_ARM_Handle *ret;
  struct GNUNET_CLIENT_Connection *client;

  client = GNUNET_CLIENT_connect (sched, "arm", cfg);
  if (client == NULL)
    return NULL;
  ret = GNUNET_malloc (sizeof (struct GNUNET_ARM_Handle));
  ret->cfg = cfg;
  ret->sched = sched;
  ret->client = client;
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
  GNUNET_free (h);
}


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
   * The service that is being manipulated.  Do not free.
   */
  const char *service_name;

  /**
   * Timeout for the operation.
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Length of service_name plus one.
   */
  size_t slen;

  /**
   * Number of attempts left for transmitting the request to ARM.
   * We may fail the first time (say because ARM is not yet up),
   * in which case we wait a bit and re-try (timeout permitting).
   */
  unsigned int attempts_left;

  /**
   * Type of the request expressed as a message type (start or stop).
   */
  uint16_t type;

};


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
arm_service_report (void *cls,
		    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RequestContext *pos = cls;
  pid_t pid;
  char *binary;
  char *config;

  if (0 != (tc->reason & GNUNET_SCHEDULER_REASON_PREREQ_DONE))
    {
      /* arm is running! */
      if (pos->callback != NULL)
        pos->callback (pos->cls, GNUNET_YES);
      GNUNET_free (pos);
      return;
    }
  /* FIXME: should we check that HOSTNAME for 'arm' is localhost? */
  /* start service */
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_string (pos->h->cfg,
					     "arm",
					     "BINARY",
					     &binary))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Configuration failes to specify option `%s' in section `%s'!\n"),
		  "BINARY",
		  "arm");
      if (pos->callback != NULL)
        pos->callback (pos->cls, GNUNET_SYSERR);
      GNUNET_free (pos);
      return;
    }
  if (GNUNET_OK !=
      GNUNET_CONFIGURATION_get_value_filename (pos->h->cfg,
					       "arm", "CONFIG", &config))
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Configuration fails to specify option `%s' in section `%s'!\n"),
		  "CONFIG",
		  "arm");
      if (pos->callback != NULL)
        pos->callback (pos->cls, GNUNET_SYSERR);
      GNUNET_free (binary);
      GNUNET_free (pos);
      return;
    }
  pid = GNUNET_OS_start_process (binary, binary, "-d", "-c", config,
#if DEBUG_ARM
                                 "-L", "DEBUG",
#endif
                                 NULL);
  GNUNET_free (binary);
  GNUNET_free (config);
  if (pid == -1)
    {
      if (pos->callback != NULL)
        pos->callback (pos->cls, GNUNET_SYSERR);
      GNUNET_free (pos);
      return;
    }
  if (pos->callback != NULL)
    pos->callback (pos->cls, GNUNET_YES);
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
  int ret;

  if (msg == NULL)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                  _("Error receiving response from ARM service\n"));
      GNUNET_CLIENT_disconnect (sc->h->client);
      sc->h->client = GNUNET_CLIENT_connect (sc->h->sched, 
					     "arm", 
					     sc->h->cfg);
      GNUNET_assert (NULL != sc->h->client);
      if (sc->callback != NULL)
        sc->callback (sc->cls, GNUNET_SYSERR);
      GNUNET_free (sc);
      return;
    }
#if DEBUG_ARM
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Received response from ARM service\n"));
#endif
  switch (ntohs (msg->type))
    {
    case GNUNET_MESSAGE_TYPE_ARM_IS_UP:
      ret = GNUNET_YES;
      break;
    case GNUNET_MESSAGE_TYPE_ARM_IS_DOWN:
      ret = GNUNET_NO;
      break;
    case GNUNET_MESSAGE_TYPE_ARM_IS_UNKNOWN:
      ret = GNUNET_SYSERR;
      break;
    default:
      GNUNET_break (0);
      ret = GNUNET_SYSERR;
    }
  if (sc->callback != NULL)
    sc->callback (sc->cls, ret);
  GNUNET_free (sc);
}


/**
 * We've failed to transmit the request to the ARM service.
 * Report our failure and clean up the state.
 *
 * @param sctx the state of the (now failed) request
 */
static void
report_transmit_failure (struct RequestContext *sctx)
{
  GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
	      _("Error while trying to transmit to ARM service\n"));
  if (sctx->callback != NULL)
    sctx->callback (sctx->cls, GNUNET_SYSERR);
  GNUNET_free (sctx);
}


/**
 * Transmit a request for a service status change to the
 * ARM service.
 *
 * @param cls the "struct RequestContext" identifying the request
 * @param size how many bytes are available in buf
 * @param buf where to write the request, NULL on error
 * @return number of bytes written to buf
 */
static size_t
send_service_msg (void *cls, size_t size, void *buf);


/**
 * We've failed to transmit the request to the ARM service but
 * are now going to try again.
 * 
 * @param cls state of the request
 * @param tc task context (unused)
 */
static void
retry_request (void *cls,
	       const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct RequestContext *sctx = cls;

  if (NULL ==
      GNUNET_CLIENT_notify_transmit_ready (sctx->h->client,
					   sctx->slen +
					   sizeof (struct
						   GNUNET_MessageHeader),
					   GNUNET_TIME_absolute_get_remaining (sctx->timeout),
					   &send_service_msg, 
					   sctx))
    {
      report_transmit_failure (sctx);    
      return;
    }
}


/**
 * Transmit a request for a service status change to the
 * ARM service.
 *
 * @param cls the "struct RequestContext" identifying the request
 * @param size how many bytes are available in buf
 * @param buf where to write the request, NULL on error
 * @return number of bytes written to buf
 */
static size_t
send_service_msg (void *cls, size_t size, void *buf)
{
  struct RequestContext *sctx = cls;
  struct GNUNET_MessageHeader *msg;
  struct GNUNET_TIME_Relative rem;

  if (buf == NULL)
    {
      GNUNET_CLIENT_disconnect (sctx->h->client);
      sctx->h->client = GNUNET_CLIENT_connect (sctx->h->sched, 
					       "arm", 
					       sctx->h->cfg);
      GNUNET_assert (sctx->h->client != NULL);
      rem = GNUNET_TIME_absolute_get_remaining (sctx->timeout);
      if ( (sctx->attempts_left-- > 0) &&
	   (rem.value > 0) )
	{
	  GNUNET_SCHEDULER_add_delayed (sctx->h->sched,
					GNUNET_NO,
					GNUNET_SCHEDULER_PRIORITY_KEEP,
					GNUNET_SCHEDULER_NO_TASK,
					GNUNET_TIME_relative_min (MIN_RETRY_DELAY,
								  rem),
					&retry_request,
					sctx);
	  return 0;
	}
      report_transmit_failure (sctx);
      return 0;
    }
#if DEBUG_ARM
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("Transmitting service request to ARM.\n"));
#endif
  GNUNET_assert (size >= sctx->slen);
  msg = buf;
  msg->size = htons (sizeof (struct GNUNET_MessageHeader) + sctx->slen);
  msg->type = htons (sctx->type);
  memcpy (&msg[1], sctx->service_name, sctx->slen);
  GNUNET_CLIENT_receive (sctx->h->client,
                         &handle_response,
                         sctx,
                         GNUNET_TIME_absolute_get_remaining (sctx->timeout));
  return sctx->slen + sizeof (struct GNUNET_MessageHeader);
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
change_service (struct GNUNET_ARM_Handle *h,
		const char *service_name,
                struct GNUNET_TIME_Relative timeout,
                GNUNET_ARM_Callback cb, void *cb_cls, uint16_t type)
{
  struct RequestContext *sctx;
  size_t slen;

  slen = strlen (service_name) + 1;
  if (slen + sizeof (struct GNUNET_MessageHeader) >
      GNUNET_SERVER_MAX_MESSAGE_SIZE)
    {
      GNUNET_break (0);
      if (cb != NULL)
        cb (cb_cls, GNUNET_NO);
      return;
    }
#if DEBUG_ARM
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              _("ARM requests starting of service `%s'.\n"), service_name);
#endif
  sctx = GNUNET_malloc (sizeof (struct RequestContext) + slen);
  sctx->h = h;
  sctx->callback = cb;
  sctx->cls = cb_cls;
  sctx->service_name = (const char*) &sctx[1];
  memcpy (&sctx[1],
	  service_name,
	  slen);
  sctx->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  sctx->slen = slen;
  sctx->attempts_left = MAX_ATTEMPTS;
  sctx->type = type;
  retry_request (sctx, NULL);
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

  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Starting service `%s'\n"), service_name);
  if (0 == strcmp ("arm", service_name))
    {
      sctx = GNUNET_malloc (sizeof (struct RequestContext));
      sctx->h = h;
      sctx->callback = cb;
      sctx->cls = cb_cls;
      sctx->timeout = GNUNET_TIME_relative_to_absolute (timeout);
      GNUNET_CLIENT_service_test (h->sched,
                                  "arm",
                                  h->cfg, timeout, &arm_service_report, sctx);
      return;
    }
  change_service (h, service_name, timeout, cb, cb_cls, GNUNET_MESSAGE_TYPE_ARM_START);
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
  GNUNET_log (GNUNET_ERROR_TYPE_INFO,
              _("Stopping service `%s'\n"), service_name);
  if (0 == strcmp ("arm", service_name))
    {
      GNUNET_CLIENT_service_shutdown (h->client);
      if (cb != NULL)
        cb (cb_cls, GNUNET_NO);
      return;
    }
  change_service (h, service_name, timeout, cb, cb_cls, GNUNET_MESSAGE_TYPE_ARM_STOP);
}


/**
 * Function to call for each service.
 *
 * @param h handle to ARM
 * @param service_name name of the service
 * @param timeout how long to wait before failing for good
 * @param cb callback to invoke when service is ready
 * @param cb_cls closure for callback
 */
typedef void (*ServiceOperation) (struct GNUNET_ARM_Handle *h,
				  const char *service_name,
				  struct GNUNET_TIME_Relative timeout,
				  GNUNET_ARM_Callback cb, void *cb_cls);


/**
 * Context for starting or stopping multiple services.
 */
struct MultiContext
{
  /**
   * NULL-terminated array of services to start or stop.
   */
  char **services;

  /**
   * Our handle to ARM.
   */
  struct GNUNET_ARM_Handle *h;

  /**
   * Identifies the operation (start or stop).
   */
  ServiceOperation op;

  /**
   * Current position in "services".
   */
  unsigned int pos;
};


/**
 * Run the operation for the next service in the multi-service
 * request.
 *
 * @param cls the "struct MultiContext" that is being processed
 * @param success status of the previous operation (ignored)
 */
static void
next_operation (void *cls,
		int success)
{
  struct MultiContext *mc = cls;
  char *pos;
  
  if (NULL == (pos = mc->services[mc->pos]))
    {
      GNUNET_free (mc->services);
      GNUNET_ARM_disconnect (mc->h);
      GNUNET_free (mc);
      return;
    }
  mc->pos++;
  mc->op (mc->h, pos, MULTI_TIMEOUT, &next_operation, mc);
  GNUNET_free (pos);
}


/**
 * Run a multi-service request.
 *
 * @param cfg configuration to use (needed to contact ARM;
 *        the ARM service may internally use a different
 *        configuration to determine how to start the service).
 * @param sched scheduler to use
 * @param op the operation to perform for each service
 * @param va NULL-terminated list of services
 */
static void
run_multi_request (const struct GNUNET_CONFIGURATION_Handle *cfg,
		   struct GNUNET_SCHEDULER_Handle *sched,		    
		   ServiceOperation op,
		   va_list va)
{
  va_list cp;
  unsigned int total;
  struct MultiContext *mc;
  struct GNUNET_ARM_Handle *h;
  const char *c;
  
  h = GNUNET_ARM_connect (cfg, sched, NULL);
  if (NULL == h)
    {
      GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
		  _("Error while trying to transmit to ARM service\n"));
      return; 
    }
  total = 1;
  va_copy (cp, va);
  while (NULL != (va_arg (cp, const char*))) total++;
  va_end (cp);
  mc = GNUNET_malloc (sizeof(struct MultiContext));
  mc->services = GNUNET_malloc (total * sizeof (char*));
  mc->h = h;
  mc->op = op;
  total = 0;
  va_copy (cp, va);
  while (NULL != (c = va_arg (cp, const char*))) 
    mc->services[total++] = GNUNET_strdup (c);
  va_end (cp);
  next_operation (mc, GNUNET_YES);
}


/**
 * Start multiple services in the specified order.  Convenience
 * function.  Works asynchronously, failures are not reported.
 *
 * @param cfg configuration to use (needed to contact ARM;
 *        the ARM service may internally use a different
 *        configuration to determine how to start the service).
 * @param sched scheduler to use
 * @param ... NULL-terminated list of service names (const char*)
 */
void
GNUNET_ARM_start_services (const struct GNUNET_CONFIGURATION_Handle *cfg,
			   struct GNUNET_SCHEDULER_Handle *sched,
			   ...)
{
  va_list ap;

  va_start (ap, sched);
  run_multi_request (cfg, sched, &GNUNET_ARM_start_service, ap);
  va_end (ap);
}


/**
 * Stop multiple services in the specified order.  Convenience
 * function.  Works asynchronously, failures are not reported.
 *
 * @param cfg configuration to use (needed to contact ARM;
 *        the ARM service may internally use a different
 *        configuration to determine how to start the service).
 * @param sched scheduler to use
 * @param ... NULL-terminated list of service names (const char*)
 */
void
GNUNET_ARM_stop_services (const struct GNUNET_CONFIGURATION_Handle *cfg,
			  struct GNUNET_SCHEDULER_Handle *sched,
			  ...)
{
  va_list ap;

  va_start (ap, sched);
  run_multi_request (cfg, sched, &GNUNET_ARM_stop_service, ap);
  va_end (ap);
}


/* end of arm_api.c */
