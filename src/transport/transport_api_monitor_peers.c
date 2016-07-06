/*
     This file is part of GNUnet.
     Copyright (C) 2009-2014, 2016 GNUnet e.V.

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
  struct GNUNET_MQ_Handle *mq;

  /**
   * Configuration we use.
   */
  const struct GNUNET_CONFIGURATION_Handle *cfg;

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
 * Task run to re-establish the connection.
 *
 * @param cls our `struct GNUNET_TRANSPORT_PeerMonitoringContext *`
 */
static void
do_peer_connect (void *cls);


/**
 * Cut the existing connection and reconnect.
 *
 * @param pal_ctx our context
 */
static void
reconnect_peer_ctx (struct GNUNET_TRANSPORT_PeerMonitoringContext *pal_ctx)
{
  GNUNET_assert (GNUNET_NO == pal_ctx->one_shot);
  GNUNET_MQ_destroy (pal_ctx->mq);
  pal_ctx->mq = NULL;
  pal_ctx->cb (pal_ctx->cb_cls,
               NULL,
               NULL,
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
 * @param msg message from service
 */
static void
handle_response_end (void *cls,
                     const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_TRANSPORT_PeerMonitoringContext *pal_ctx = cls;

  if (pal_ctx->one_shot)
  {
    /* iteration finished */
    pal_ctx->cb (pal_ctx->cb_cls,
                 NULL,
                 NULL,
                 GNUNET_TRANSPORT_PS_NOT_CONNECTED,
                 GNUNET_TIME_UNIT_ZERO_ABS);
    GNUNET_TRANSPORT_monitor_peers_cancel (pal_ctx);
    return;
  }
  /* not quite what we expected, reconnect */
  GNUNET_break (0);
  reconnect_peer_ctx (pal_ctx);
}


/**
 * Function called to check responses from the service.
 *
 * @param cls our `struct GNUNET_TRANSPORT_PeerMonitoringContext *`
 * @param pir_msg  message with the human-readable address
 * @return #GNUNET_OK if @a pir_msg is well-formed
 */
static int
check_response (void *cls,
                const struct PeerIterateResponseMessage *pir_msg)
{
  uint16_t size = ntohs (pir_msg->header.size) - sizeof (*pir_msg);
  size_t alen = ntohl (pir_msg->addrlen);
  size_t tlen = ntohl (pir_msg->pluginlen);
  const char *addr;
  const char *transport_name;

  if (size != tlen + alen)
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  if ( (0 == tlen) && (0 == alen) )
    return GNUNET_OK;
  if (0 == tlen)
  {
    GNUNET_break (0); /* This must not happen: address without plugin */
    return GNUNET_SYSERR;
  }
  addr = (const char *) &pir_msg[1];
  transport_name = &addr[alen];
  if (transport_name[tlen - 1] != '\0')
  {
    GNUNET_break (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Function called with responses from the service.
 *
 * @param cls our `struct GNUNET_TRANSPORT_PeerMonitoringContext *`
 * @param msg  message with the human-readable address
 */
static void
handle_response (void *cls,
                 const struct PeerIterateResponseMessage *pir_msg)
{
  struct GNUNET_TRANSPORT_PeerMonitoringContext *pal_ctx = cls;
  struct GNUNET_HELLO_Address *address;
  size_t alen = ntohl (pir_msg->addrlen);
  size_t tlen = ntohl (pir_msg->pluginlen);
  const char *addr;
  const char *transport_name;

  if ( (0 == tlen) &&
       (0 == alen) )
  {
    /* No address available */
    pal_ctx->cb (pal_ctx->cb_cls,
                 &pir_msg->peer,
                 NULL,
                 ntohl(pir_msg->state),
                 GNUNET_TIME_absolute_ntoh (pir_msg->state_timeout));
    return;
  }
  addr = (const char *) &pir_msg[1];
  transport_name = &addr[alen];

  /* notify client */
  address = GNUNET_HELLO_address_allocate (&pir_msg->peer,
                                           transport_name,
                                           addr,
                                           alen,
                                           ntohl (pir_msg->local_address_info));
  pal_ctx->cb (pal_ctx->cb_cls,
               &pir_msg->peer,
               address,
               ntohl (pir_msg->state),
               GNUNET_TIME_absolute_ntoh (pir_msg->state_timeout));
  GNUNET_HELLO_address_free (address);
}



/**
 * Generic error handler, called with the appropriate error code and
 * the same closure specified at the creation of the message queue.
 * Not every message queue implementation supports an error handler.
 *
 * @param cls closure with the `struct GNUNET_TRANSPORT_PeerMonitoringContext *`
 * @param error error code
 */
static void
mq_error_handler (void *cls,
                  enum GNUNET_MQ_Error error)
{
  struct GNUNET_TRANSPORT_PeerMonitoringContext *pal_ctx = cls;

  if (pal_ctx->one_shot)
  {
    /* Disconnect */
    pal_ctx->cb (pal_ctx->cb_cls,
                 NULL,
                 NULL,
                 GNUNET_TRANSPORT_PS_NOT_CONNECTED,
                 GNUNET_TIME_UNIT_ZERO_ABS);
    GNUNET_TRANSPORT_monitor_peers_cancel (pal_ctx);
    return;
  }
  reconnect_peer_ctx (pal_ctx);
}


/**
 * Task run to re-establish the connection.
 *
 * @param cls our `struct GNUNET_TRANSPORT_PeerMonitoringContext *`
 */
static void
do_peer_connect (void *cls)
{
  GNUNET_MQ_hd_var_size (response,
                         GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_RESPONSE,
                         struct PeerIterateResponseMessage);
  GNUNET_MQ_hd_fixed_size (response_end,
                           GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_RESPONSE_END,
                           struct GNUNET_MessageHeader);
  struct GNUNET_TRANSPORT_PeerMonitoringContext *pal_ctx = cls;
  struct GNUNET_MQ_MessageHandler handlers[] = {
    make_response_handler (pal_ctx),
    make_response_end_handler (pal_ctx),
    GNUNET_MQ_handler_end ()
  };
  struct PeerMonitorMessage *msg;
  struct GNUNET_MQ_Envelope *env;

  pal_ctx->reconnect_task = NULL;
  pal_ctx->mq = GNUNET_CLIENT_connecT (pal_ctx->cfg,
                                       "transport",
                                       handlers,
                                       &mq_error_handler,
                                       pal_ctx);
  if (NULL == pal_ctx->mq)
    return;
  env = GNUNET_MQ_msg (msg,
                       GNUNET_MESSAGE_TYPE_TRANSPORT_MONITOR_PEER_REQUEST);
  msg->one_shot = htonl (pal_ctx->one_shot);
  msg->peer = pal_ctx->peer;
  GNUNET_MQ_send (pal_ctx->mq,
                  env);
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
 * @param peer_callback function to call with the results
 * @param peer_callback_cls closure for @a peer_address_callback
 */
struct GNUNET_TRANSPORT_PeerMonitoringContext *
GNUNET_TRANSPORT_monitor_peers (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                const struct GNUNET_PeerIdentity *peer,
                                int one_shot,
                                GNUNET_TRANSPORT_PeerIterateCallback peer_callback,
                                void *peer_callback_cls)
{
  struct GNUNET_TRANSPORT_PeerMonitoringContext *pal_ctx
    = GNUNET_new (struct GNUNET_TRANSPORT_PeerMonitoringContext);

  pal_ctx->cb = peer_callback;
  pal_ctx->cb_cls = peer_callback_cls;
  pal_ctx->cfg = cfg;
  if (NULL != peer)
    pal_ctx->peer = *peer;
  pal_ctx->one_shot = one_shot;
  do_peer_connect (pal_ctx);
  if (NULL == pal_ctx->mq)
  {
    GNUNET_free (pal_ctx);
    return NULL;
  }
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
  if (NULL != pic->mq)
  {
    GNUNET_MQ_destroy (pic->mq);
    pic->mq = NULL;
  }
  if (NULL != pic->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (pic->reconnect_task);
    pic->reconnect_task = NULL;
  }
  GNUNET_free (pic);
}


/* end of transport_api_monitor_peers.c */
