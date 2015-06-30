/*
     This file is part of GNUnet.
     Copyright (C) 2009-2014 Christian Grothoff (and other contributing authors)

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
 * @file transport/transport_api_monitor_peers.c
 * @brief montoring api for transport peer status
 *
 * This api provides the ability to query the transport service about
 * the connection status of a specific or all peers.
 *
 * Calls back with information about peer(s) including address used, state and
 * state timeout for peer requests.
 */
#include "platform.h"
#include "gnunet_util_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_transport_service.h"
#include "transport.h"

/**
 * Context for iterating validation entries.
 */
struct GNUNET_TRANSPORT_PeerMonitoringContext
{
  /**
   * Function to call with the binary address.
   */
  GNUNET_TRANSPORT_PeerIterateCallback cb;

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
  struct GNUNET_SCHEDULER_Task *reconnect_task;

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
 * Check if a state is defined as connected
 *
 * @param state the state value
 * @return #GNUNET_YES or #GNUNET_NO
 */
int
GNUNET_TRANSPORT_is_connected (enum GNUNET_TRANSPORT_PeerState state)
{
  switch (state)
  {
  case GNUNET_TRANSPORT_PS_NOT_CONNECTED:
  case GNUNET_TRANSPORT_PS_INIT_ATS:
  case GNUNET_TRANSPORT_PS_SYN_SENT:
  case GNUNET_TRANSPORT_PS_SYN_RECV_ATS:
  case GNUNET_TRANSPORT_PS_SYN_RECV_ACK:
    return GNUNET_NO;
  case GNUNET_TRANSPORT_PS_CONNECTED:
  case GNUNET_TRANSPORT_PS_RECONNECT_ATS:
  case GNUNET_TRANSPORT_PS_RECONNECT_SENT:
  case GNUNET_TRANSPORT_PS_SWITCH_SYN_SENT:
    return GNUNET_YES;
  case GNUNET_TRANSPORT_PS_DISCONNECT:
  case GNUNET_TRANSPORT_PS_DISCONNECT_FINISHED:
    return GNUNET_NO;
  default:
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR,
                "Unhandled state `%s'\n",
                GNUNET_TRANSPORT_ps2s (state));
    GNUNET_break (0);
    break;
  }
  return GNUNET_SYSERR;
}


/**
 * Convert peer state to human-readable string.
 *
 * @param state the state value
 * @return corresponding string
 */
const char *
GNUNET_TRANSPORT_ps2s (enum GNUNET_TRANSPORT_PeerState state)
{
  switch (state)
  {
  case GNUNET_TRANSPORT_PS_NOT_CONNECTED:
    return "S_NOT_CONNECTED";
  case GNUNET_TRANSPORT_PS_INIT_ATS:
    return "S_INIT_ATS";
  case GNUNET_TRANSPORT_PS_SYN_SENT:
    return "S_SYN_SENT";
  case GNUNET_TRANSPORT_PS_SYN_RECV_ATS:
    return "S_SYN_RECV_ATS";
  case GNUNET_TRANSPORT_PS_SYN_RECV_ACK:
    return "S_SYN_RECV_ACK";
  case GNUNET_TRANSPORT_PS_CONNECTED:
    return "S_CONNECTED";
  case GNUNET_TRANSPORT_PS_RECONNECT_ATS:
    return "S_RECONNECT_ATS";
  case GNUNET_TRANSPORT_PS_RECONNECT_SENT:
    return "S_RECONNECT_SENT";
  case GNUNET_TRANSPORT_PS_SWITCH_SYN_SENT:
    return "S_SWITCH_SYN_SENT";
  case GNUNET_TRANSPORT_PS_DISCONNECT:
    return "S_DISCONNECT";
  case GNUNET_TRANSPORT_PS_DISCONNECT_FINISHED:
    return "S_DISCONNECT_FINISHED";
  default:
    GNUNET_break (0);
    return "UNDEFINED";
  }
}


/**
 * Function called with responses from the service.
 *
 * @param cls our `struct GNUNET_TRANSPORT_PeerMonitoringContext *`
 * @param msg NULL on timeout or error, otherwise presumably a
 *        message with the human-readable address
 */
static void
peer_response_processor (void *cls,
                         const struct GNUNET_MessageHeader *msg);


/**
 * Send our subscription request to the service.
 *
 * @param pal_ctx our context
 */
static void
send_peer_mon_request (struct GNUNET_TRANSPORT_PeerMonitoringContext *pal_ctx)
{
  struct PeerMonitorMessage msg;

  msg.header.size = htons (sizeof (struct PeerMonitorMessage));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_REQUEST);
  msg.one_shot = htonl (pal_ctx->one_shot);
  msg.peer = pal_ctx->peer;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CLIENT_transmit_and_get_response (pal_ctx->client,
                                                          &msg.header,
                                                          GNUNET_TIME_absolute_get_remaining (pal_ctx->timeout),
                                                          GNUNET_YES,
                                                          &peer_response_processor,
                                                          pal_ctx));
}


/**
 * Task run to re-establish the connection.
 *
 * @param cls our `struct GNUNET_TRANSPORT_PeerMonitoringContext *`
 * @param tc scheduler context, unused
 */
static void
do_peer_connect (void *cls,
                 const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TRANSPORT_PeerMonitoringContext *pal_ctx = cls;

  pal_ctx->reconnect_task = NULL;
  pal_ctx->client = GNUNET_CLIENT_connect ("transport", pal_ctx->cfg);
  GNUNET_assert (NULL != pal_ctx->client);
  send_peer_mon_request (pal_ctx);
}


/**
 * Cut the existing connection and reconnect.
 *
 * @param pal_ctx our context
 */
static void
reconnect_peer_ctx (struct GNUNET_TRANSPORT_PeerMonitoringContext *pal_ctx)
{
  GNUNET_assert (GNUNET_NO == pal_ctx->one_shot);
  GNUNET_CLIENT_disconnect (pal_ctx->client);
  pal_ctx->client = NULL;
  pal_ctx->cb (pal_ctx->cb_cls, NULL, NULL,
               GNUNET_TRANSPORT_PS_NOT_CONNECTED,
               GNUNET_TIME_UNIT_ZERO_ABS);
  pal_ctx->backoff = GNUNET_TIME_STD_BACKOFF (pal_ctx->backoff);
  pal_ctx->reconnect_task = GNUNET_SCHEDULER_add_delayed (pal_ctx->backoff,
							  &do_peer_connect,
							  pal_ctx);
}


/**
 * Function called with responses from the service.
 *
 * @param cls our `struct GNUNET_TRANSPORT_PeerMonitoringContext *`
 * @param msg NULL on timeout or error, otherwise presumably a
 *        message with the human-readable address
 */
static void
peer_response_processor (void *cls,
                         const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_TRANSPORT_PeerMonitoringContext *pal_ctx = cls;
  struct PeerIterateResponseMessage *pir_msg;
  struct GNUNET_HELLO_Address *address;
  const char *addr;
  const char *transport_name;
  uint16_t size;
  size_t alen;
  size_t tlen;

  if (NULL == msg)
  {
    if (pal_ctx->one_shot)
    {
      /* Disconnect */
      pal_ctx->cb (pal_ctx->cb_cls, NULL, NULL,
          GNUNET_TRANSPORT_PS_NOT_CONNECTED, GNUNET_TIME_UNIT_ZERO_ABS);
      GNUNET_TRANSPORT_monitor_peers_cancel (pal_ctx);
    }
    else
    {
      reconnect_peer_ctx (pal_ctx);
    }
    return;
  }
  size = ntohs (msg->size);
  GNUNET_break (ntohs (msg->type) ==
      GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_RESPONSE);
  if (size == sizeof (struct GNUNET_MessageHeader))
  {
    /* Done! */
    if (pal_ctx->one_shot)
    {
      /* iteration finished */
      pal_ctx->cb (pal_ctx->cb_cls, NULL, NULL,
          GNUNET_TRANSPORT_PS_NOT_CONNECTED, GNUNET_TIME_UNIT_ZERO_ABS);
      GNUNET_TRANSPORT_monitor_peers_cancel (pal_ctx);
    }
    else
    {
      reconnect_peer_ctx (pal_ctx);
    }
    return;
  }

  if ((size < sizeof (struct PeerIterateResponseMessage)) ||
      (ntohs (msg->type) != GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_RESPONSE))
  {
    GNUNET_break (0);
    if (pal_ctx->one_shot)
    {
      /* iteration finished (with error) */
      pal_ctx->cb (pal_ctx->cb_cls, NULL, NULL,
          GNUNET_TRANSPORT_PS_NOT_CONNECTED, GNUNET_TIME_UNIT_ZERO_ABS);
      GNUNET_TRANSPORT_monitor_peers_cancel (pal_ctx);
    }
    else
    {
      reconnect_peer_ctx (pal_ctx);
    }
    return;
  }

  pir_msg = (struct PeerIterateResponseMessage *) msg;
  tlen = ntohl (pir_msg->pluginlen);
  alen = ntohl (pir_msg->addrlen);

  if (size != sizeof (struct PeerIterateResponseMessage) + tlen + alen)
  {
    GNUNET_break (0);
    if (pal_ctx->one_shot)
    {
      pal_ctx->cb (pal_ctx->cb_cls, NULL, NULL,
          GNUNET_TRANSPORT_PS_NOT_CONNECTED, GNUNET_TIME_UNIT_ZERO_ABS);
      GNUNET_TRANSPORT_monitor_peers_cancel (pal_ctx);
    }
    else
    {
      reconnect_peer_ctx (pal_ctx);
    }
    return;
  }

  if ( (0 == tlen) && (0 == alen) )
  {
    /* No address available */
    pal_ctx->cb (pal_ctx->cb_cls, &pir_msg->peer, NULL,
        ntohl(pir_msg->state),
        GNUNET_TIME_absolute_ntoh (pir_msg->state_timeout));
  }
  else
  {
    if (0 == tlen)
    {
      GNUNET_break (0); /* This must not happen: address without plugin */
      return;
    }
    addr = (const char *) &pir_msg[1];
    transport_name = &addr[alen];

    if (transport_name[tlen - 1] != '\0')
    {
      /* Corrupt plugin name */
      GNUNET_break (0);
      if (pal_ctx->one_shot)
      {
        pal_ctx->cb (pal_ctx->cb_cls, NULL, NULL,
            GNUNET_TRANSPORT_PS_NOT_CONNECTED, GNUNET_TIME_UNIT_ZERO_ABS);
        GNUNET_TRANSPORT_monitor_peers_cancel (pal_ctx);
      }
      else
      {
        reconnect_peer_ctx (pal_ctx);
      }
      return;
    }

    /* notify client */
    address = GNUNET_HELLO_address_allocate (&pir_msg->peer,
        transport_name, addr, alen, ntohl(pir_msg->local_address_info));
    pal_ctx->cb (pal_ctx->cb_cls, &pir_msg->peer, address,
        ntohl(pir_msg->state),
        GNUNET_TIME_absolute_ntoh (pir_msg->state_timeout));
    GNUNET_HELLO_address_free (address);

  }

  /* expect more replies */
  GNUNET_CLIENT_receive (pal_ctx->client, &peer_response_processor,
                         pal_ctx,
                         GNUNET_TIME_absolute_get_remaining (pal_ctx->timeout));
}


/**
 * Return information about a specific peer or all peers currently known to
 * transport service once or in monitoring mode. To obtain information about
 * a specific peer, a peer identity can be passed. To obtain information about
 * all peers currently known to transport service, NULL can be passed as peer
 * identity.
 *
 * For each peer, the callback is called with information about the address used
 * to communicate with this peer, the state this peer is currently in and the
 * the current timeout for this state.
 *
 * Upon completion, the 'GNUNET_TRANSPORT_PeerIterateCallback' is called one
 * more time with 'NULL'. After this, the operation must no longer be
 * explicitly canceled.
 *
 * The #GNUNET_TRANSPORT_monitor_peers_cancel call MUST not be called in the
 * the peer_callback!
 *
 * @param cfg configuration to use
 * @param peer a specific peer identity to obtain information for,
 *      NULL for all peers
 * @param one_shot #GNUNET_YES to return the current state and then end (with NULL+NULL),
 *                 #GNUNET_NO to monitor peers continuously
 * @param timeout how long is the lookup allowed to take at most
 * @param peer_callback function to call with the results
 * @param peer_callback_cls closure for @a peer_address_callback
 */
struct GNUNET_TRANSPORT_PeerMonitoringContext *
GNUNET_TRANSPORT_monitor_peers (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                const struct GNUNET_PeerIdentity *peer,
                                int one_shot,
                                struct GNUNET_TIME_Relative timeout,
                                GNUNET_TRANSPORT_PeerIterateCallback peer_callback,
                                void *peer_callback_cls)
{
  struct GNUNET_TRANSPORT_PeerMonitoringContext *pal_ctx;
  struct GNUNET_CLIENT_Connection *client;

  client = GNUNET_CLIENT_connect ("transport", cfg);
  if (NULL == client)
    return NULL;
  if (GNUNET_YES != one_shot)
    timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  pal_ctx = GNUNET_new (struct GNUNET_TRANSPORT_PeerMonitoringContext);
  pal_ctx->cb = peer_callback;
  pal_ctx->cb_cls = peer_callback_cls;
  pal_ctx->cfg = cfg;
  pal_ctx->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  if (NULL != peer)
    pal_ctx->peer = *peer;
  pal_ctx->one_shot = one_shot;
  pal_ctx->client = client;
  send_peer_mon_request (pal_ctx);

  return pal_ctx;
}


/**
 * Cancel request to monitor peers
 *
 * @param pic handle for the request to cancel
 */
void
GNUNET_TRANSPORT_monitor_peers_cancel (struct GNUNET_TRANSPORT_PeerMonitoringContext *pic)
{
  if (NULL != pic->client)
  {
    GNUNET_CLIENT_disconnect (pic->client);
    pic->client = NULL;
  }
  if (NULL != pic->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (pic->reconnect_task);
    pic->reconnect_task = NULL;
  }
  GNUNET_free (pic);
}


/* end of transport_api_monitor_peers.c */
