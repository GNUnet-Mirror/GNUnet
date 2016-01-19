/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011 GNUnet e.V.

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
   * Socket (if available).
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Currently pending transmission request.
   */
  struct GNUNET_CLIENT_TransmitHandle *th;

  /**
   * Task doing exponential back-off trying to reconnect.
   */
  struct GNUNET_SCHEDULER_Task * reconnect_task;

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
 * @param cls the handle to the transport service
 * @param tc scheduler context
 */
static void
reconnect (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc);


/**
 * Type of a function to call when we receive a message
 * from the service.
 *
 * @param cls closure
 * @param msg message received, NULL on timeout or fatal error
 */
static void
message_handler (void *cls, const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_NSE_Handle *h = cls;
  const struct GNUNET_NSE_ClientMessage *client_msg;

  if (NULL == msg)
  {
    /* Error, timeout, death */
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
    h->reconnect_task =
        GNUNET_SCHEDULER_add_delayed (h->reconnect_delay,
				      &reconnect, h);
    return;
  }
  if ((ntohs (msg->size) != sizeof (struct GNUNET_NSE_ClientMessage)) ||
      (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_NSE_ESTIMATE))
  {
    GNUNET_break (0);
    return;
  }
  client_msg = (const struct GNUNET_NSE_ClientMessage *) msg;
  h->recv_cb (h->recv_cb_cls, GNUNET_TIME_absolute_ntoh (client_msg->timestamp),
              GNUNET_ntoh_double (client_msg->size_estimate),
	      GNUNET_ntoh_double (client_msg->std_deviation));
  GNUNET_CLIENT_receive (h->client, &message_handler, h,
                         GNUNET_TIME_UNIT_FOREVER_REL);
}


/**
 * Reschedule a connect attempt to the service.
 *
 * @param h transport service to reconnect
 */
static void
reschedule_connect (struct GNUNET_NSE_Handle *h)
{
  GNUNET_assert (h->reconnect_task == NULL);

  if (NULL != h->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Scheduling task to reconnect to nse service in %s.\n",
       GNUNET_STRINGS_relative_time_to_string (h->reconnect_delay,
					       GNUNET_YES));
  h->reconnect_task =
      GNUNET_SCHEDULER_add_delayed (h->reconnect_delay, &reconnect, h);
  h->reconnect_delay = GNUNET_TIME_STD_BACKOFF (h->reconnect_delay);
}


/**
 * Transmit START message to service.
 *
 * @param cls the `struct GNUNET_NSE_Handle *`
 * @param size number of bytes available in @a buf
 * @param buf where to copy the message
 * @return number of bytes copied to @a buf
 */
static size_t
send_start (void *cls, size_t size, void *buf)
{
  struct GNUNET_NSE_Handle *h = cls;
  struct GNUNET_MessageHeader *msg;

  h->th = NULL;
  if (NULL == buf)
  {
    /* Connect error... */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Error while trying to transmit `%s' request.\n",
	 "START");
    reschedule_connect (h);
    return 0;
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transmitting `%s' request.\n",
       "START");
  GNUNET_assert (size >= sizeof (struct GNUNET_MessageHeader));

  msg = (struct GNUNET_MessageHeader *) buf;
  msg->size = htons (sizeof (struct GNUNET_MessageHeader));
  msg->type = htons (GNUNET_MESSAGE_TYPE_NSE_START);
  GNUNET_CLIENT_receive (h->client, &message_handler, h,
                         GNUNET_TIME_UNIT_FOREVER_REL);
  return sizeof (struct GNUNET_MessageHeader);
}


/**
 * Try again to connect to network size estimation service.
 *
 * @param cls the `struct GNUNET_NSE_Handle *`
 * @param tc scheduler context
 */
static void
reconnect (void *cls,
	   const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_NSE_Handle *h = cls;

  h->reconnect_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to network size estimation service.\n");
  GNUNET_assert (NULL == h->client);
  h->client = GNUNET_CLIENT_connect ("nse", h->cfg);
  GNUNET_assert (NULL != h->client);
  GNUNET_assert (NULL == h->th);
  h->th =
      GNUNET_CLIENT_notify_transmit_ready (h->client,
                                           sizeof (struct GNUNET_MessageHeader),
                                           GNUNET_TIME_UNIT_FOREVER_REL,
                                           GNUNET_NO, &send_start, h);
  GNUNET_assert (NULL != h->th);
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
                    GNUNET_NSE_Callback func, void *func_cls)
{
  struct GNUNET_NSE_Handle *ret;

  GNUNET_assert (func != NULL);
  ret = GNUNET_new (struct GNUNET_NSE_Handle);
  ret->cfg = cfg;
  ret->recv_cb = func;
  ret->recv_cb_cls = func_cls;
  ret->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  ret->reconnect_task = GNUNET_SCHEDULER_add_now (&reconnect, ret);
  return ret;
}


/**
 * Disconnect from network size estimation service
 *
 * @param h handle to destroy
 */
void
GNUNET_NSE_disconnect (struct GNUNET_NSE_Handle *h)
{
  GNUNET_assert (NULL != h);
  if (h->reconnect_task != NULL)
  {
    GNUNET_SCHEDULER_cancel (h->reconnect_task);
    h->reconnect_task = NULL;
  }
  if (NULL != h->th)
  {
    GNUNET_CLIENT_notify_transmit_ready_cancel (h->th);
    h->th = NULL;
  }
  if (NULL != h->client)
  {
    GNUNET_CLIENT_disconnect (h->client);
    h->client = NULL;
  }
  GNUNET_free (h);
}

/* end of nse_api.c */
