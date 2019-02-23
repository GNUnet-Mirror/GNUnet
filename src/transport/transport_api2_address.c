/*
     This file is part of GNUnet.
     Copyright (C) 2009-2013, 2016, 2018, 2019 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
*/

/**
 * @file transport/transport_api2_address.c
 * @brief library to inform the transport service about addresses to be validated
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_constants.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_address_service.h"
#include "gnunet_ats_transport_service.h"
#include "transport.h"

#define LOG(kind,...) GNUNET_log_from (kind, "transport-api-address",__VA_ARGS__)


/**
 * Handle for the transport service (includes all of the
 * state for the transport service).
 */
struct GNUNET_TRANSPORT_AddressHandle
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

};


/**
 * Function that will schedule the job that will try
 * to connect us again to the client.
 *
 * @param h transport service to reconnect
 */
static void
disconnect_and_schedule_reconnect (struct GNUNET_TRANSPORT_AddressHandle *h);


/**
 * Generic error handler, called with the appropriate
 * error code and the same closure specified at the creation of
 * the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_TRANSPORT_AddressHandle *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_TRANSPORT_AddressHandle *h = cls;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Error receiving from transport service, disconnecting temporarily.\n");
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
  struct GNUNET_TRANSPORT_AddressHandle *h = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    GNUNET_MQ_handler_end ()
  };

  h->reconnect_task = NULL;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to transport service.\n");
  GNUNET_assert (NULL == h->mq);
  h->mq = GNUNET_CLIENT_connect (h->cfg,
                                 "transport",
                                 handlers,
                                 &mq_error_handler,
                                 h);
}


/**
 * Disconnect from the transport service.
 *
 * @param h transport service to disconnect
 */
static void
disconnect (struct GNUNET_TRANSPORT_AddressHandle *h)
{
  if (NULL != h->mq)
  {
    GNUNET_MQ_destroy (h->mq);
    h->mq = NULL;
  }
}


/**
 * Function that will schedule the job that will try
 * to connect us again to the client.
 *
 * @param h transport service to reconnect
 */
static void
disconnect_and_schedule_reconnect (struct GNUNET_TRANSPORT_AddressHandle *h)
{
  GNUNET_assert (NULL == h->reconnect_task);
  disconnect (h);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Scheduling task to reconnect to transport service in %s.\n",
       GNUNET_STRINGS_relative_time_to_string (h->reconnect_delay,
                                               GNUNET_YES));
  h->reconnect_task =
      GNUNET_SCHEDULER_add_delayed (h->reconnect_delay,
                                    &reconnect,
                                    h);
  h->reconnect_delay = GNUNET_TIME_STD_BACKOFF (h->reconnect_delay);
}


/**
 * Connect to the transport service.
 *
 * @param cfg configuration to use
 * @return NULL on error
 */
struct GNUNET_TRANSPORT_AddressHandle *
GNUNET_TRANSPORT_address_connect (const struct GNUNET_CONFIGURATION_Handle *cfg)
{
  struct GNUNET_TRANSPORT_AddressHandle *h;

  h = GNUNET_new (struct GNUNET_TRANSPORT_AddressHandle);
  h->cfg = cfg;
  h->reconnect_delay = GNUNET_TIME_UNIT_ZERO;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Connecting to transport service\n");
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
 * @param handle handle to the service as returned from #GNUNET_TRANSPORT_address_connect()
 */
void
GNUNET_TRANSPORT_address_disconnect (struct GNUNET_TRANSPORT_AddressHandle *handle)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Transport disconnect called!\n");
  /* this disconnects all neighbours... */
  disconnect (handle);
  /* and now we stop trying to connect again... */
  if (NULL != handle->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (handle->reconnect_task);
    handle->reconnect_task = NULL;
  }
  GNUNET_free (handle);
}


/**
 * The client has learned about a possible address for peer @a pid
 * (i.e. via broadcast, multicast, DHT, ...).  The transport service
 * should consider validating it. Note that the plugin is NOT expected
 * to have verified the signature, the transport service must decide
 * whether to check the signature.
 *
 * While the notification is sent to @a ch asynchronously, this API
 * does not return a handle as the delivery of addresses is simply
 * unreliable, and if @a ch is down, the data provided will simply be
 * lost.
 *
 * @param ch communicator handle
 * @param pid peer the address is for
 * @param raw raw address data
 * @param raw_size number of bytes in @a raw
 */
void
GNUNET_TRANSPORT_address_try (struct GNUNET_TRANSPORT_AddressHandle *ch,
                              const struct GNUNET_PeerIdentity *pid,
                              const void *raw,
                              const size_t raw_size)
{
  struct GNUNET_MQ_Envelope *env;
  struct GNUNET_TRANSPORT_AddressToVerify *hdr;

  env = GNUNET_MQ_msg_extra (hdr,
                             raw_size,
                             GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_CONSIDER_VERIFY);
  hdr->peer = *pid;
  memcpy (&hdr[1],
          raw,
          raw_size);
  GNUNET_MQ_send (ch->mq,
                  env);
}



/* end of transport_api2_address.c */
