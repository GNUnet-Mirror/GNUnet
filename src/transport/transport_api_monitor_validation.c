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
 * @file transport/transport_api_monitor_validation.c
 * @brief montoring api for validation status
 *
 * This api provides the ability to query the transport service about
 * the status of address validation.
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_service.h"
#include "transport.h"


/**
 * Context for the address lookup.
 */
struct GNUNET_TRANSPORT_ValidationMonitoringContext
{
  /**
   * Function to call with the binary address.
   */
  GNUNET_TRANSPORT_ValidationIterateCallback cb;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;

  /**
   * Connection to the service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * Configuration we use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

  /**
   * When should this operation time out?
   */
  struct GNUNET_TIME_Absolute timeout;

  /**
   * Backoff for reconnect.
   */
  struct GNUNET_TIME_Relative backoff;

  /**
   * Task ID for reconnect.
   */
  struct GNUNET_SCHEDULER_Task * reconnect_task;

  /**
   * Identity of the peer to monitor.
   */
  struct GNUNET_PeerIdentity peer;

  /**
   * Was this a one-shot request?
   */
  int one_shot;
};


/**
 * Convert validation state to human-readable string.
 *
 * @param state the state value
 * @return corresponding string
 */
const char *
GNUNET_TRANSPORT_vs2s (enum GNUNET_TRANSPORT_ValidationState state)
{
  switch (state)
  {
  case GNUNET_TRANSPORT_VS_NONE:
    return "NONE";
  case GNUNET_TRANSPORT_VS_NEW:
    return "NEW";
  case GNUNET_TRANSPORT_VS_REMOVE:
    return "REMOVE";
  case GNUNET_TRANSPORT_VS_TIMEOUT:
    return "TIMEOUT";
  case GNUNET_TRANSPORT_VS_UPDATE:
    return "UPDATE";
  default:
    GNUNET_break (0);
    return "UNDEFINED";
  }
}


/**
 * Function called with responses from the service.
 *
 * @param cls our `struct GNUNET_TRANSPORT_ValidationMonitoringContext *`
 * @param msg NULL on timeout or error, otherwise presumably a
 *        message with the human-readable address
 */
static void
val_response_processor (void *cls,
                        const struct GNUNET_MessageHeader *msg);


/**
 * Send our subscription request to the service.
 *
 * @param val_ctx our context
 */
static void
send_val_mon_request (struct GNUNET_TRANSPORT_ValidationMonitoringContext *val_ctx)
{
  struct ValidationMonitorMessage msg;

  msg.header.size = htons (sizeof (struct ValidationMonitorMessage));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_VALIDATION_REQUEST);
  msg.one_shot = htonl (val_ctx->one_shot);
  msg.peer = val_ctx->peer;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CLIENT_transmit_and_get_response (val_ctx->client,
                    &msg.header,
                    GNUNET_TIME_absolute_get_remaining (val_ctx->timeout),
                    GNUNET_YES,
                    &val_response_processor,
                    val_ctx));
}


/**
 * Task run to re-establish the connection.
 *
 * @param cls our `struct GNUNET_TRANSPORT_ValidationMonitoringContext *`
 * @param tc scheduler context, unused
 */
static void
do_val_connect (void *cls,
                const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TRANSPORT_ValidationMonitoringContext *val_ctx = cls;

  val_ctx->reconnect_task = NULL;
  val_ctx->client = GNUNET_CLIENT_connect ("transport", val_ctx->cfg);
  GNUNET_assert (NULL != val_ctx->client);
  send_val_mon_request (val_ctx);
}


/**
 * Cut the existing connection and reconnect.
 *
 * @param val_ctx our context
 */
static void
reconnect_val_ctx (struct GNUNET_TRANSPORT_ValidationMonitoringContext *val_ctx)
{
  GNUNET_assert (GNUNET_NO == val_ctx->one_shot);
  GNUNET_CLIENT_disconnect (val_ctx->client);
  val_ctx->client = NULL;
  /* notify clients about (re)connect */
  val_ctx->cb (val_ctx->cb_cls, NULL,
               GNUNET_TIME_UNIT_ZERO_ABS, GNUNET_TIME_UNIT_ZERO_ABS,
               GNUNET_TIME_UNIT_ZERO_ABS, GNUNET_TRANSPORT_VS_TIMEOUT);
  val_ctx->backoff = GNUNET_TIME_STD_BACKOFF (val_ctx->backoff);
  val_ctx->reconnect_task = GNUNET_SCHEDULER_add_delayed (val_ctx->backoff,
                                                          &do_val_connect,
                                                          val_ctx);
}


/**
 * Function called with responses from the service.
 *
 * @param cls our `struct GNUNET_TRANSPORT_ValidationMonitoringContext *`
 * @param msg NULL on timeout or error, otherwise presumably a
 *        message with the human-readable address
 */
static void
val_response_processor (void *cls,
                        const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_TRANSPORT_ValidationMonitoringContext *val_ctx = cls;
  struct ValidationIterateResponseMessage *vr_msg;
  struct GNUNET_HELLO_Address *address;
  const char *addr;
  const char *transport_name;
  size_t size;
  size_t tlen;
  size_t alen;

  if (NULL == msg)
  {
    if (val_ctx->one_shot)
    {
      /* Disconnect */
      val_ctx->cb (val_ctx->cb_cls, NULL,
          GNUNET_TIME_UNIT_ZERO_ABS, GNUNET_TIME_UNIT_ZERO_ABS,
          GNUNET_TIME_UNIT_ZERO_ABS, GNUNET_TRANSPORT_VS_TIMEOUT);
      GNUNET_TRANSPORT_monitor_validation_entries_cancel (val_ctx);
    }
    else
    {
      reconnect_val_ctx (val_ctx);
    }
    return;
  }
  size = ntohs (msg->size);
  GNUNET_break (ntohs (msg->type) ==
      GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_VALIDATION_RESPONSE);

  if (size == sizeof (struct GNUNET_MessageHeader))
  {
    /* Done! */
    if (val_ctx->one_shot)
    {
      val_ctx->cb (val_ctx->cb_cls, NULL,
          GNUNET_TIME_UNIT_ZERO_ABS, GNUNET_TIME_UNIT_ZERO_ABS,
          GNUNET_TIME_UNIT_ZERO_ABS, GNUNET_TRANSPORT_VS_NONE);
      GNUNET_TRANSPORT_monitor_validation_entries_cancel (val_ctx);
    }
    else
    {
      reconnect_val_ctx (val_ctx);
    }
    return;
  }

  if ((size < sizeof (struct ValidationIterateResponseMessage)) ||
      (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_VALIDATION_RESPONSE))
  {
    GNUNET_break (0);
    if (val_ctx->one_shot)
    {
      val_ctx->cb (val_ctx->cb_cls, NULL,
          GNUNET_TIME_UNIT_ZERO_ABS, GNUNET_TIME_UNIT_ZERO_ABS,
          GNUNET_TIME_UNIT_ZERO_ABS, GNUNET_TRANSPORT_VS_NONE);
      GNUNET_TRANSPORT_monitor_validation_entries_cancel (val_ctx);
    }
    else
    {
      reconnect_val_ctx (val_ctx);
    }
    return;
  }

  vr_msg = (struct ValidationIterateResponseMessage *) msg;
  tlen = ntohl (vr_msg->pluginlen);
  alen = ntohl (vr_msg->addrlen);

  if (size != sizeof (struct ValidationIterateResponseMessage) + tlen + alen)
  {
    GNUNET_break (0);
    if (val_ctx->one_shot)
    {
      val_ctx->cb (val_ctx->cb_cls, NULL,
          GNUNET_TIME_UNIT_ZERO_ABS, GNUNET_TIME_UNIT_ZERO_ABS,
          GNUNET_TIME_UNIT_ZERO_ABS, GNUNET_TRANSPORT_VS_NONE);
      GNUNET_TRANSPORT_monitor_validation_entries_cancel (val_ctx);
    }
    else
    {
      reconnect_val_ctx (val_ctx);
    }
    return;
  }
  if (0 == tlen)
  {
    GNUNET_break (0); /* This must not happen: address without plugin */
    return;
  }
  addr = (const char *) &vr_msg[1];
  transport_name = &addr[alen];
  
  if (transport_name[tlen - 1] != '\0')
  {
    /* Corrupt plugin name */
    GNUNET_break (0);
    if (val_ctx->one_shot)
    {
      val_ctx->cb (val_ctx->cb_cls,
		   NULL,
		   GNUNET_TIME_UNIT_ZERO_ABS,
		   GNUNET_TIME_UNIT_ZERO_ABS,
		   GNUNET_TIME_UNIT_ZERO_ABS,
		   GNUNET_TRANSPORT_VS_NONE);
      GNUNET_TRANSPORT_monitor_validation_entries_cancel (val_ctx);
    }
    else
    {
      reconnect_val_ctx (val_ctx);
    }
    return;
  }
  
  /* notify client */
  address = GNUNET_HELLO_address_allocate (&vr_msg->peer,
					   transport_name,
					   addr, alen,
					   ntohl (vr_msg->local_address_info));
  val_ctx->cb (val_ctx->cb_cls,
	       address,
	       GNUNET_TIME_absolute_ntoh (vr_msg->last_validation),
	       GNUNET_TIME_absolute_ntoh (vr_msg->valid_until),
	       GNUNET_TIME_absolute_ntoh (vr_msg->next_validation),
	       ntohl(vr_msg->state));
  GNUNET_HELLO_address_free (address);
  /* expect more replies */
  GNUNET_CLIENT_receive (val_ctx->client,
                         &val_response_processor,
                         val_ctx,
                         GNUNET_TIME_absolute_get_remaining (val_ctx->timeout));
}


/**
 * Return information about pending address validation operations for a specific
 * or all peers
 *
 * @param cfg configuration to use
 * @param peer a specific peer identity to obtain validation entries for,
 *      NULL for all peers
 * @param one_shot #GNUNET_YES to return all entries and then end (with NULL+NULL),
 *                 #GNUNET_NO to monitor validation entries continuously
 * @param timeout how long is the lookup allowed to take at most
 * @param validation_callback function to call with the results
 * @param validation_callback_cls closure for peer_address_callback
 */
struct GNUNET_TRANSPORT_ValidationMonitoringContext *
GNUNET_TRANSPORT_monitor_validation_entries (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                             const struct GNUNET_PeerIdentity *peer,
                                             int one_shot,
                                             struct GNUNET_TIME_Relative timeout,
                                             GNUNET_TRANSPORT_ValidationIterateCallback validation_callback,
                                             void *validation_callback_cls)
{
  struct GNUNET_TRANSPORT_ValidationMonitoringContext *val_ctx;
  struct GNUNET_CLIENT_Connection *client;

  client = GNUNET_CLIENT_connect ("transport", cfg);
  if (NULL == client)
    return NULL;
  if (GNUNET_YES != one_shot)
    timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  val_ctx = GNUNET_new (struct GNUNET_TRANSPORT_ValidationMonitoringContext);
  val_ctx->cb = validation_callback;
  val_ctx->cb_cls = validation_callback_cls;
  val_ctx->cfg = cfg;
  val_ctx->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  if (NULL != peer)
    val_ctx->peer = *peer;
  val_ctx->one_shot = one_shot;
  val_ctx->client = client;
  send_val_mon_request (val_ctx);

  return val_ctx;
}


/**
 * Return information about all current pending validation operations
 *
 * @param vic handle for the request to cancel
 */
void
GNUNET_TRANSPORT_monitor_validation_entries_cancel (struct GNUNET_TRANSPORT_ValidationMonitoringContext *vic)
{
  if (NULL != vic->client)
  {
    GNUNET_CLIENT_disconnect (vic->client);
    vic->client = NULL;
  }
  if (NULL != vic->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (vic->reconnect_task);
    vic->reconnect_task = NULL;
  }
  GNUNET_free (vic);
}


/* end of transport_api_monitor_validation.c */
