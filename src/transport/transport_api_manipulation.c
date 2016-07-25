/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013, 2016 GNUnet e.V.

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
 * @file transport/transport_api_manipulation.c
 * @brief library to access the low-level P2P IO service
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_service.h"
#include "transport.h"

#define LOG(kind,...) GNUNET_log_from (kind, "transport-api",__VA_ARGS__)


/**
 * Handle for the transport service (includes all of the
 * state for the transport service).
 */
struct GNUNET_TRANSPORT_ManipulationHandle
{

  /**
   * My client connection to the transport service.
   */
  struct GNUNET_MQ_Handle *mq;

  /**
   * My configuration.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * ID of the task trying to reconnect to the service.
   */
  struct GNUNET_SCHEDULER_Task *reconnect_task;

  /**
   * Delay until we try to reconnect.
   */
  struct GNUNET_TIME_Relative reconnect_delay;

  /**
   * Reconnect in progress
   */
  int reconnecting;
};


/**
 * Function that will schedule the job that will try
 * to connect us again to the client.
 *
 * @param h transport service to reconnect
 */
static void
disconnect_and_schedule_reconnect (struct GNUNET_TRANSPORT_ManipulationHandle *h);


/**
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_TRANSPORT_ManipulationHandle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_TRANSPORT_ManipulationHandle *h = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Error receiving from transport service, disconnecting temporarily.\n");
  h->reconnecting = GNUNET_YES;
  disconnect_and_schedule_reconnect (h);
}


/**
 * Try again to connect to transport service.
 *
 * @param cls the handle to the transport service
 */
static void
reconnect (void *cls)
{
  struct GNUNET_TRANSPORT_ManipulationHandle *h = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_handler_end ()
  };
  struct GNUNET_MQ_Envelope *env;
  struct StartMessage *s;

  h->reconnect_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to transport service.\n");
  GNUNET_assert (NULL == h->mq);
  h->reconnecting = GNUNET_NO;
  h->mq = GNUNET_CLIENT_connecT (h->cfg,
                                 "transport",
                                 handlers,
                                 &mq_error_handler,
                                 h);
  if (NULL == h->mq)
    return;
  env = GNUNET_MQ_msg (s,
                       GNUNET_MESSAGE_TYPE_TRANSPORT_START);
  GNUNET_MQ_send (h->mq,
                  env);
}


/**
 * Function that will schedule the job that will try
 * to connect us again to the client.
 *
 * @param h transport service to reconnect
 */
static void
disconnect_and_schedule_reconnect (struct GNUNET_TRANSPORT_ManipulationHandle *h)
{
  GNUNET_assert (NULL == h->reconnect_task);
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
  h->reconnect_task =
      GNUNET_SCHEDULER_add_delayed (h->reconnect_delay,
                                    &reconnect,
                                    h);
  h->reconnect_delay = GNUNET_TIME_STD_BACKOFF (h->reconnect_delay);
}


/**
 * Set transport metrics for a peer and a direction.
 *
 * @param handle transport handle
 * @param peer the peer to set the metric for
 * @param prop the performance metrics to set
 * @param delay_in inbound delay to introduce
 * @param delay_out outbound delay to introduce
 *
 * Note: Delay restrictions in receiving direction will be enforced
 * with one message delay.
 */
void
GNUNET_TRANSPORT_manipulation_set (struct GNUNET_TRANSPORT_ManipulationHandle *handle,
				   const struct GNUNET_PeerIdentity *peer,
				   const struct GNUNET_ATS_Properties *prop,
				   struct GNUNET_TIME_Relative delay_in,
				   struct GNUNET_TIME_Relative delay_out)
{
  struct GNUNET_MQ_Envelope *env;
  struct TrafficMetricMessage *msg;

  if (NULL == handle->mq)
    return;
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_TRANSPORT_TRAFFIC_METRIC);
  msg->reserved = htonl (0);
  msg->peer = *peer;
  GNUNET_ATS_properties_hton (&msg->properties,
                              prop);
  msg->delay_in = GNUNET_TIME_relative_hton (delay_in);
  msg->delay_out = GNUNET_TIME_relative_hton (delay_out);
  GNUNET_MQ_send (handle->mq,
                  env);
}


/**
 * Connect to the transport service.  Note that the connection may
 * complete (or fail) asynchronously.
 *
 * @param cfg configuration to use
 * @return NULL on error
 */
struct GNUNET_TRANSPORT_ManipulationHandle *
GNUNET_TRANSPORT_manipulation_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_TRANSPORT_ManipulationHandle *h;

  h = GNUNET_new (struct GNUNET_TRANSPORT_ManipulationHandle);
  h->cfg = cfg;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to transport service.\n");
  reconnect (h);
  if (NULL == h->mq)
  {
    GNUNET_free (h);
    return NULL;
  }
  return h;
}


/**
 * Disconnect from the transport service.
 *
 * @param handle handle to the service as returned from #GNUNET_TRANSPORT_manipulation_connect()
 */
void
GNUNET_TRANSPORT_manipulation_disconnect (struct GNUNET_TRANSPORT_ManipulationHandle *handle)
{
  if (NULL == handle->reconnect_task)
    disconnect_and_schedule_reconnect (handle);
  /* and now we stop trying to connect again... */
  if (NULL != handle->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (handle->reconnect_task);
    handle->reconnect_task = NULL;
  }
  GNUNET_free (handle);
}


/* end of transport_api_manipulation.c */
