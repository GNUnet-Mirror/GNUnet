/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011, 2016 GNUnet e.V.

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
 * @file nse/nse_api.c
 * @brief api to get information from the network size estimation service
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_util_lib.h"
#include "gnunet_nse_service.h"
#include "nse.h"

#define LOG(kind,...) GNUNET_log_from (kind, "nse-api",__VA_ARGS__)

/**
 * Handle for talking with the NSE service.
 */
struct GNUNET_NSE_Handle
{
  /**
   * Configuration to use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * Message queue (if available).
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * Task doing exponential back-off trying to reconnect.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Time for next connect retry.
   */
  struct GNUNET_TIME_Relative reconnect_delay;

  /**
   * Callback function to call when message is received.
   */
  GNUNET_NSE_Callback recv_cb;

  /**
   * Closure to pass to @e recv_cb callback.
   */
  void *recv_cb_cls;

};


/**
 * Try again to connect to network size estimation service.
 *
 * @param cls closure with the `struct GNUNET_NSE_Handle *`
 */
static void
reconnect (void *cls);


/**
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_NSE_Handle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_NSE_Handle *h = cls;

  GNUNET_MQ_destroy (h->mq);
  h->mq = NULL;
  h->reconnect_task
    = GNUNET_SCHEDULER_add_delayed (h->reconnect_delay,
                                    &reconnect,
                                    h);
  h->reconnect_delay = GNUNET_TIME_STD_BACKOFF (h->reconnect_delay);
}


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param client_msg message received
 */
static void
handle_estimate (void *cls,
		 const struct GNUNET_NSE_ClientMessage *client_msg)
{
  struct GNUNET_NSE_Handle *h = cls;

  h->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  h->recv_cb (h->recv_cb_cls,
              GNUNET_TIME_absolute_ntoh (client_msg->timestamp),
              GNUNET_ntoh_double (client_msg->size_estimate),
	      GNUNET_ntoh_double (client_msg->std_deviation));
}


/**
 * Try again to connect to network size estimation service.
 *
 * @param cls the `struct GNUNET_NSE_Handle *`
 */
static void
reconnect (void *cls)
{
  struct GNUNET_NSE_Handle *h = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_hd_fixed_size (estimate,
                             GNUNET_MESSAGE_TYPE_NSE_ESTIMATE,
                             struct GNUNET_NSE_ClientMessage,
                             h),
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MessageHeader *msg;
  struct GNUNET_MQ_Envelope *env;

  h->reconnect_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to network size estimation service.\n");
  GNUNET_assert (NULL == h->mq);
  h->mq = GNUNET_CLIENT_connecT (h->cfg,
                                 "nse",
                                 handlers,
                                 &mq_error_handler,
                                 h);
  if (NULL == h->mq)
    return;
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_NSE_START);
  GNUNET_MQ_send (h->mq,
                  env);
}


/**
 * Connect to the network size estimation service.
 *
 * @param cfg the configuration to use
 * @param func funtion to call with network size estimate
 * @param func_cls closure to pass to @a func
 * @return handle to use
 */
struct GNUNET_NSE_Handle *
GNUNET_NSE_connect (const struct GNUNET_CONFIGURATION_Handle *cfg,
                    GNUNET_NSE_Callback func,
                    void *func_cls)
{
  struct GNUNET_NSE_Handle *h;

  GNUNET_assert (NULL != func);
  h = GNUNET_new (struct GNUNET_NSE_Handle);
  h->cfg = cfg;
  h->recv_cb = func;
  h->recv_cb_cls = func_cls;
  h->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  reconnect (h);
  if (NULL == h->mq)
  {
    GNUNET_free (h);
    return NULL;
  }
  return h;
}


/**
 * Disconnect from network size estimation service
 *
 * @param h handle to destroy
 */
void
GNUNET_NSE_disconnect (struct GNUNET_NSE_Handle *h)
{
  if (NULL != h->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (h->reconnect_task);
    h->reconnect_task = NULL;
  }
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  GNUNET_free (h);
}

/* end of nse_api.c */
