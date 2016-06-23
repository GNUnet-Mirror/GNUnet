/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2012, 2013, 2016 GNUnet e.V.

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file arm/arm_monitor_api.c
 * @brief API for monitoring the ARM service
 * @author Christian Grothoff
 * @author LRN
 */
#include "platform.h"
#include "gnunet_arm_service.h"
#include "gnunet_util_lib.h"
#include "gnunet_protocols.h"
#include "arm.h"

#define INIT_TIMEOUT GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 5)

#define LOG(kind,...) GNUNET_log_from (kind, "arm-monitor-api",__VA_ARGS__)

/**
 * Handle for interacting with ARM.
 */
struct GNUNET_ARM_MonitorHandle
{

  /**
   * Our control connection to the ARM service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * The configuration that we are using.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * ID of the reconnect task (if any).
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Current delay we use for re-trying to connect to core.
   */
  struct GNUNET_TIME_Relative retry_backoff;

  /**
   * Callback to invoke on status updates.
   */
  GNUNET_ARM_ServiceStatusCallback service_status;

  /**
   * Closure for @e service_status.
   */
  void *service_status_cls;

};


/**
 * Connect to the ARM service for monitoring.
 *
 * @param h handle to connect
 * @return #GNUNET_OK on success
 */
static int
reconnect_arm_monitor (struct GNUNET_ARM_MonitorHandle *h);


/**
 * Task scheduled to try to re-connect to arm.
 *
 * @param cls the `struct GNUNET_ARM_MonitorHandle`
 */
static void
reconnect_arm_monitor_task (void *cls)
{
  struct GNUNET_ARM_MonitorHandle *h = cls;

  h->reconnect_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to ARM service for monitoring after delay\n");
  GNUNET_break (GNUNET_OK == reconnect_arm_monitor (h));
}


/**
 * Close down any existing connection to the ARM service and
 * try re-establishing it later.
 *
 * @param h our handle
 */
static void
reconnect_arm_monitor_later (struct GNUNET_ARM_MonitorHandle *h)
{
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  GNUNET_assert (NULL == h->reconnect_task);
  h->reconnect_task
    = GNUNET_SCHEDULER_add_delayed (h->retry_backoff,
                                    &reconnect_arm_monitor_task, h);
  h->retry_backoff = GNUNET_TIME_STD_BACKOFF (h->retry_backoff);
}


/**
 * Check notification messages received from ARM is well-formed.
 *
 * @param cls our `struct GNUNET_ARM_MonitorHandle`
 * @param msg the message received from the arm service
 * @return #GNUNET_OK if the message is well-formed
 */
static int
check_monitor_notify (void *cls,
                       const struct GNUNET_ARM_StatusMessage *res)
{
  size_t sl = ntohs (res->header.size) - sizeof (struct GNUNET_ARM_StatusMessage);
  const char *name = (const char *) &res[1];

  if ( (0 == sl) ||
       ('\0' != name[sl-1]) )
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Handler for notification messages received from ARM.
 *
 * @param cls our `struct GNUNET_ARM_MonitorHandle`
 * @param msg the message received from the arm service
 */
static void
handle_monitor_notify (void *cls,
                       const struct GNUNET_ARM_StatusMessage *res)
{
  struct GNUNET_ARM_MonitorHandle *h = cls;
  enum GNUNET_ARM_ServiceStatus status;

  status = (enum GNUNET_ARM_ServiceStatus) ntohl (res->status);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Received notification from ARM for service `%s' with status %d\n",
       (const char *) &res[1],
       (int) status);
  if (NULL != h->service_status)
    h->service_status (h->service_status_cls,
                       (const char *) &res[1],
                       status);
}


/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_ARM_MonitorHandle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_ARM_MonitorHandle *h = cls;

  reconnect_arm_monitor_later (h);
}


/**
 * Connect to the ARM service for monitoring.
 *
 * @param h handle to connect
 * @return #GNUNET_OK on success
 */
static int
reconnect_arm_monitor (struct GNUNET_ARM_MonitorHandle *h)
{
  GNUNET_MQ_hd_var_size (monitor_notify,
                         GNUNET_MESSAGE_TYPE_ARM_STATUS,
                         struct GNUNET_ARM_StatusMessage);
  struct GNUNET_MQ_MessageHandler handlers[] = {
    make_monitor_notify_handler (h),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MessageHeader *msg;
  struct GNUNET_MQ_Envelope *env;

  GNUNET_assert (NULL == h->mq);
  h->mq = GNUNET_CLIENT_connecT (h->cfg,
                                 "arm",
                                 handlers,
                                 &mq_error_handler,
                                 h);
  if (NULL == h->mq)
  {
    if (NULL != h->service_status)
      h->service_status (h->service_status_cls,
                         NULL,
                         GNUNET_ARM_SERVICE_STOPPED);
    return GNUNET_SYSERR;
  }
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_ARM_MONITOR);
  GNUNET_MQ_send (h->mq,
                  env);
  return GNUNET_OK;
}


/**
 * Setup a context for monitoring ARM, then
 * start connecting to the ARM service for monitoring using that context.
 *
 * @param cfg configuration to use (needed to contact ARM;
 *        the ARM service may internally use a different
 *        configuration to determine how to start the service).
 * @param cont callback to invoke on status updates
 * @param cont_cls closure for @a cont
 * @return context to use for further ARM monitor operations, NULL on error.
 */
struct GNUNET_ARM_MonitorHandle *
GNUNET_ARM_monitor_start (const struct GNUNET_CONFIGURATION_Handle *cfg,
                          GNUNET_ARM_ServiceStatusCallback cont,
                          void *cont_cls)
{
  struct GNUNET_ARM_MonitorHandle *h;

  h = GNUNET_new (struct GNUNET_ARM_MonitorHandle);
  h->cfg = cfg;
  h->service_status = cont;
  h->service_status_cls = cont_cls;
  if (GNUNET_OK != reconnect_arm_monitor (h))
  {
    GNUNET_free (h);
    return NULL;
  }
  return h;
}


/**
 * Disconnect from the ARM service (if connected) and destroy the context.
 *
 * @param h the handle that was being used
 */
void
GNUNET_ARM_monitor_stop (struct GNUNET_ARM_MonitorHandle *h)
{
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  if (NULL != h->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (h->reconnect_task);
    h->reconnect_task = NULL;
  }
  GNUNET_free (h);
}


/* end of arm_api.c */
