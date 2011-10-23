/*
     This file is part of GNUnet.
     (C) 2009, 2010 Christian Grothoff (and other contributing authors)

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
   * We received a confirmation that the service will shut down.
   */
  int confirmed;

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

  if ((msg == NULL) && (shutdown_ctx->confirmed != GNUNET_YES))
  {
#if DEBUG_ARM
    /* Means the other side closed the connection and never confirmed a shutdown */
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Service handle shutdown before ACK!\n");
#endif
    if (shutdown_ctx->cont != NULL)
      shutdown_ctx->cont (shutdown_ctx->cont_cls, GNUNET_SYSERR);
    GNUNET_SCHEDULER_cancel (shutdown_ctx->cancel_task);
    GNUNET_CLIENT_disconnect (shutdown_ctx->sock, GNUNET_NO);
    GNUNET_free (shutdown_ctx);
  }
  else if ((msg == NULL) && (shutdown_ctx->confirmed == GNUNET_YES))
  {
#if DEBUG_ARM
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Service shutdown complete.\n");
#endif
    if (shutdown_ctx->cont != NULL)
      shutdown_ctx->cont (shutdown_ctx->cont_cls, GNUNET_NO);

    GNUNET_SCHEDULER_cancel (shutdown_ctx->cancel_task);
    GNUNET_CLIENT_disconnect (shutdown_ctx->sock, GNUNET_NO);
    GNUNET_free (shutdown_ctx);
  }
  else
  {
    GNUNET_assert (ntohs (msg->size) == sizeof (struct GNUNET_MessageHeader));
    switch (ntohs (msg->type))
    {
    case GNUNET_MESSAGE_TYPE_ARM_SHUTDOWN_ACK:
#if DEBUG_ARM
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "Received confirmation for service shutdown.\n");
#endif
      shutdown_ctx->confirmed = GNUNET_YES;
      GNUNET_CLIENT_receive (shutdown_ctx->sock, &service_shutdown_handler,
                             shutdown_ctx, GNUNET_TIME_UNIT_FOREVER_REL);
      break;
    default:
#if DEBUG_ARM
      LOG (GNUNET_ERROR_TYPE_DEBUG, "Service shutdown refused!\n");
#endif
      if (shutdown_ctx->cont != NULL)
        shutdown_ctx->cont (shutdown_ctx->cont_cls, GNUNET_YES);

      GNUNET_SCHEDULER_cancel (shutdown_ctx->cancel_task);
      GNUNET_CLIENT_disconnect (shutdown_ctx->sock, GNUNET_NO);
      GNUNET_free (shutdown_ctx);
      break;
    }
  }
}

/**
 * Shutting down took too long, cancel receive and return error.
 *
 * @param cls closure
 * @param tc context information (why was this task triggered now)
 */
void
service_shutdown_cancel (void *cls,
                         const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct ShutdownContext *shutdown_ctx = cls;

#if DEBUG_ARM
  LOG (GNUNET_ERROR_TYPE_DEBUG, "service_shutdown_cancel called!\n");
#endif
  shutdown_ctx->cont (shutdown_ctx->cont_cls, GNUNET_SYSERR);
  GNUNET_CLIENT_disconnect (shutdown_ctx->sock, GNUNET_NO);
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
  struct GNUNET_MessageHeader *msg;
  struct ShutdownContext *shutdown_ctx = cls;

  if (size < sizeof (struct GNUNET_MessageHeader))
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _("Failed to transmit shutdown request to client.\n"));
    shutdown_ctx->cont (shutdown_ctx->cont_cls, GNUNET_SYSERR);
    GNUNET_CLIENT_disconnect (shutdown_ctx->sock, GNUNET_NO);
    GNUNET_free (shutdown_ctx);
    return 0;                   /* client disconnected */
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
  GNUNET_CLIENT_notify_transmit_ready (sock,
                                       sizeof (struct GNUNET_MessageHeader),
                                       timeout, GNUNET_YES, &write_shutdown,
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
    GNUNET_CLIENT_disconnect (h->client, GNUNET_NO);
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
#if DEBUG_ARM
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Looks like `%s' is already running.\n",
         "gnunet-service-arm");
#endif
    /* arm is running! */
    if (pos->callback != NULL)
      pos->callback (pos->cls, GNUNET_YES);
    GNUNET_free (pos);
    return;
  }
#if DEBUG_ARM
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Looks like `%s' is not running, will start it.\n",
       "gnunet-service-arm");
#endif
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
         _("Configuration failes to specify option `%s' in section `%s'!\n"),
         "BINARY", "arm");
    if (pos->callback != NULL)
      pos->callback (pos->cls, GNUNET_SYSERR);
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
      pos->callback (pos->cls, GNUNET_SYSERR);
    GNUNET_free (binary);
    GNUNET_free (pos);
    GNUNET_free (loprefix);
    GNUNET_free (lopostfix);
    return;
  }
  if ((GNUNET_YES == GNUNET_CONFIGURATION_have_value (pos->h->cfg, "TESTING", "WEAKRANDOM")) && (GNUNET_YES == GNUNET_CONFIGURATION_get_value_yesno (pos->h->cfg, "TESTING", "WEAKRANDOM")) && (GNUNET_NO == GNUNET_CONFIGURATION_have_value (pos->h->cfg, "TESTING", "HOSTFILE"))      /* Means we are ONLY running locally */
      )
  {
    /* we're clearly running a test, don't daemonize */
    proc = do_start_process (NULL, loprefix, binary, "-c", config,
#if DEBUG_ARM
                             "-L", "DEBUG",
#endif
                             /* no daemonization! */
                             lopostfix, NULL);
  }
  else
  {
    proc = do_start_process (NULL, loprefix, binary, "-c", config,
#if DEBUG_ARM
                             "-L", "DEBUG",
#endif
                             "-d", lopostfix, NULL);
  }
  GNUNET_free (binary);
  GNUNET_free (config);
  GNUNET_free (loprefix);
  GNUNET_free (lopostfix);
  if (proc == NULL)
  {
    if (pos->callback != NULL)
      pos->callback (pos->cls, GNUNET_SYSERR);
    GNUNET_free (pos);
    return;
  }
  if (pos->callback != NULL)
    pos->callback (pos->cls, GNUNET_YES);
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
  int ret;

  if (msg == NULL)
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         _
         ("Error receiving response to `%s' request from ARM for service `%s'\n"),
         (sc->type == GNUNET_MESSAGE_TYPE_ARM_START) ? "START" : "STOP",
         (const char *) &sc[1]);
    GNUNET_CLIENT_disconnect (sc->h->client, GNUNET_NO);
    sc->h->client = GNUNET_CLIENT_connect ("arm", sc->h->cfg);
    GNUNET_assert (NULL != sc->h->client);
    if (sc->callback != NULL)
      sc->callback (sc->cls, GNUNET_SYSERR);
    GNUNET_free (sc);
    return;
  }
#if DEBUG_ARM
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received response from ARM for service `%s': %u\n",
       (const char *) &sc[1], ntohs (msg->type));
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
#if DEBUG_ARM
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       (type ==
        GNUNET_MESSAGE_TYPE_ARM_START) ?
       _("Requesting start of service `%s'.\n") :
       _("Requesting termination of service `%s'.\n"), service_name);
#endif
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
          GNUNET_MESSAGE_TYPE_ARM_START) ?
         _("Error while trying to transmit request to start `%s' to ARM\n") :
         _("Error while trying to transmit request to stop `%s' to ARM\n"),
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
GNUNET_ARM_start_service (struct GNUNET_ARM_Handle *h, const char *service_name,
                          struct GNUNET_TIME_Relative timeout,
                          GNUNET_ARM_Callback cb, void *cb_cls)
{
  struct RequestContext *sctx;
  struct GNUNET_CLIENT_Connection *client;
  size_t slen;

#if DEBUG_ARM
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       _("Asked to start service `%s' within %llu ms\n"), service_name,
       (unsigned long long) timeout.rel_value);
#endif
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
      cb (cb_cls, GNUNET_SYSERR);
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
 * @param reason reason for callback, GNUNET_NO if arm is shutdown
 *        GNUNET_YES if arm remains running, and GNUNET_SYSERR on error
 */
void
arm_shutdown_callback (void *cls, int reason)
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
GNUNET_ARM_stop_service (struct GNUNET_ARM_Handle *h, const char *service_name,
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


/* end of arm_api.c */
