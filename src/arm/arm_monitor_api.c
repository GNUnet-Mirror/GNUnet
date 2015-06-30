/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2012, 2013 Christian Grothoff (and other contributing authors)

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
 * @author Christian Grothoff, LRN
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
  struct GNUNET_CLIENT_Connection *monitor;

  /**
   * The configuration that we are using.
   */
  struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Handle for our current transmission request.
   */
  struct GNUNET_CLIENT_TransmitHandle *cth;

  /**
   * ID of the reconnect task (if any).
   */
  struct GNUNET_SCHEDULER_Task * reconnect_task;

  /**
   * Current delay we use for re-trying to connect to core.
   */
  struct GNUNET_TIME_Relative retry_backoff;

  /**
   * Are we currently disconnected and hence unable to send?
   */
  unsigned char currently_down;

  /**
   * Callback to invoke on status updates.
   */
  GNUNET_ARM_ServiceStatusCallback service_status;

  /**
   * Closure for service_status.
   */
  void *cls;

  /**
   * ID of a task to run if we fail to get a reply to the init message in time.
   */
  struct GNUNET_SCHEDULER_Task * init_timeout_task_id;
};

static void
monitor_notify_handler (void *cls, const struct GNUNET_MessageHeader *msg);

static int
reconnect_arm_monitor (struct GNUNET_ARM_MonitorHandle *h);

/**
 * Task scheduled to try to re-connect to arm.
 *
 * @param cls the 'struct GNUNET_ARM_MonitorHandle'
 * @param tc task context
 */
static void
reconnect_arm_monitor_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_ARM_MonitorHandle *h = cls;

  h->reconnect_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Connecting to ARM service for monitoring after delay\n");
  reconnect_arm_monitor (h);
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
  if (NULL != h->cth)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->cth);
    h->cth = NULL;
  }

  if (NULL != h->monitor)
  {
    GNUNET_CLIENT_disconnect (h->monitor);
    h->monitor = NULL;
  }

  if (NULL != h->init_timeout_task_id)
  {
    GNUNET_SCHEDULER_cancel (h->init_timeout_task_id);
    h->init_timeout_task_id = NULL;
  }

  GNUNET_assert (NULL == h->reconnect_task);
  h->reconnect_task =
      GNUNET_SCHEDULER_add_delayed (h->retry_backoff, &reconnect_arm_monitor_task, h);

  h->retry_backoff = GNUNET_TIME_STD_BACKOFF (h->retry_backoff);
}


/**
 * Init message timed out. Disconnect and try again.
 *
 * @param cls arm monitor handle
 * @param tc task context
 */
static void
init_timeout_task (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_ARM_MonitorHandle *h = cls;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Init message timed out\n");

  h->init_timeout_task_id = NULL;
  reconnect_arm_monitor_later (h);
}


/**
 * Transmit the monitoring initialization message to the arm service.
 *
 * @param cls closure with the 'struct GNUNET_ARM_MonitorHandle'
 * @param size number of bytes available in buf
 * @param buf where the callee should write the message
 * @return number of bytes written to buf
 */
static size_t
transmit_monitoring_init_message (void *cls, size_t size, void *buf)
{
  struct GNUNET_ARM_MonitorHandle *h = cls;
  struct GNUNET_MessageHeader *msg;
  uint16_t msize;

  GNUNET_assert (NULL == h->reconnect_task);
  GNUNET_assert (NULL == h->init_timeout_task_id);
  h->cth = NULL;
  if (NULL == buf)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Transmission failed, initiating reconnect\n");
    reconnect_arm_monitor_later (h);
    return 0;
  }
  msize = sizeof (struct GNUNET_MessageHeader);
  if (size < msize)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
        "Request is too big (%u < %u), not sending it\n", size, msize);
    h->cth = GNUNET_CLIENT_notify_transmit_ready (h->monitor, msize,
        GNUNET_TIME_UNIT_FOREVER_REL, GNUNET_NO,
        transmit_monitoring_init_message, h);
    return 0;
  }

  msg = buf;
  msg->size = htons (msize);
  msg->type = htons (GNUNET_MESSAGE_TYPE_ARM_MONITOR);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transmitting ARM monitoring init message with %u bytes to arm.\n",
       (unsigned int) msize);

  h->init_timeout_task_id = GNUNET_SCHEDULER_add_delayed (
      INIT_TIMEOUT, init_timeout_task, h);
  GNUNET_CLIENT_receive (h->monitor, &monitor_notify_handler, h,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  return msize;
}


static int
reconnect_arm_monitor (struct GNUNET_ARM_MonitorHandle *h)
{
  GNUNET_assert (NULL == h->monitor);
  h->monitor = GNUNET_CLIENT_connect ("arm", h->cfg);
  if (NULL == h->monitor)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	   "arm_api, GNUNET_CLIENT_connect returned NULL\n");
    if (NULL != h->service_status)
      h->service_status (h->cls, NULL, GNUNET_ARM_SERVICE_STOPPED);
    return GNUNET_SYSERR;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "arm_api, GNUNET_CLIENT_connect returned non-NULL\n");
  h->cth = GNUNET_CLIENT_notify_transmit_ready (h->monitor,
      sizeof (struct GNUNET_MessageHeader), GNUNET_TIME_UNIT_FOREVER_REL,
      GNUNET_NO, &transmit_monitoring_init_message, h);
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
 * @param cont_cls closure
 * @return context to use for further ARM monitor operations, NULL on error.
 */
struct GNUNET_ARM_MonitorHandle *
GNUNET_ARM_monitor (const struct GNUNET_CONFIGURATION_Handle *cfg,
    GNUNET_ARM_ServiceStatusCallback cont, void *cont_cls)
{
  struct GNUNET_ARM_MonitorHandle *h;

  h = GNUNET_new (struct GNUNET_ARM_MonitorHandle);
  h->cfg = GNUNET_CONFIGURATION_dup (cfg);
  h->currently_down = GNUNET_YES;
  h->reconnect_task = NULL;
  h->init_timeout_task_id = NULL;
  h->service_status = cont;
  h->cls = cont_cls;
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
GNUNET_ARM_monitor_disconnect_and_free (struct GNUNET_ARM_MonitorHandle *h)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Disconnecting from ARM service\n");
  if (NULL != h->cth)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->cth);
    h->cth = NULL;
  }
  if (NULL != h->init_timeout_task_id)
  {
    GNUNET_SCHEDULER_cancel (h->init_timeout_task_id);
    h->init_timeout_task_id = NULL;
  }
  if (NULL != h->monitor)
  {
    GNUNET_CLIENT_disconnect (h->monitor);
    h->monitor = NULL;
  }
  if (NULL != h->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (h->reconnect_task);
    h->reconnect_task = NULL;
  }
  GNUNET_CONFIGURATION_destroy (h->cfg);
  GNUNET_free (h);
}


/**
 * Handler for notification messages received from ARM.
 *
 * @param cls our "struct GNUNET_ARM_MonitorHandle"
 * @param msg the message received from the arm service
 */
static void
monitor_notify_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_ARM_MonitorHandle *h = cls;
  uint16_t msize;
  const struct GNUNET_ARM_StatusMessage *res;
  enum GNUNET_ARM_ServiceStatus status;

  if (NULL == msg)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         _("Monitoring client was disconnected from arm service, trying to reconnect.\n"));
    reconnect_arm_monitor_later (h);
    return;
  }
  msize = ntohs (msg->size);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Processing message of type %u and size %u from arm service\n",
       ntohs (msg->type), msize);
  switch (ntohs (msg->type))
  {
  case GNUNET_MESSAGE_TYPE_ARM_STATUS:
    if (msize <= sizeof (struct GNUNET_ARM_StatusMessage))
    {
      GNUNET_break (0);
      reconnect_arm_monitor_later (h);
      return;
    }
    if (NULL != h->init_timeout_task_id)
    {
      GNUNET_SCHEDULER_cancel (h->init_timeout_task_id);
      h->init_timeout_task_id = NULL;
    }
    res = (const struct GNUNET_ARM_StatusMessage *) msg;
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Received response from ARM for service `%s': %u\n",
         (const char *) &res[1], ntohs (msg->type));
    status = (enum GNUNET_ARM_ServiceStatus) ntohl (res->status);
    GNUNET_CLIENT_receive (h->monitor, &monitor_notify_handler, h,
                           GNUNET_TIME_UNIT_FOREVER_REL);
    if (NULL != h->service_status)
      h->service_status (h->cls, (const char *) &res[1], status);
    break;
  default:
    reconnect_arm_monitor_later (h);
    return;
  }
}


/* end of arm_api.c */
