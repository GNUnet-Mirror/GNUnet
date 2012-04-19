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
 * @file transport/transport_api_address_lookup.c
 * @brief given a peer id, get all known addresses from transport service
 *
 * This api provides the ability to query the transport service about
 * the status of connections to a specific peer.  Calls back with a
 * pretty printed string of the address, as formatted by the appropriate
 * transport plugin, and whether or not the address given is currently
 * in the 'connected' state (according to the transport service).
 */

#include "platform.h"
#include "gnunet_client_lib.h"
#include "gnunet_arm_service.h"
#include "gnunet_hello_lib.h"
#include "gnunet_protocols.h"
#include "gnunet_server_lib.h"
#include "gnunet_time_lib.h"
#include "gnunet_transport_service.h"
#include "transport.h"

/**
 * Context for the address lookup.
 */
struct GNUNET_TRANSPORT_PeerIterateContext
{
  /**
   * Function to call with the binary address.
   */
  GNUNET_TRANSPORT_PeerIterateCallback cb;

  /**
   * Closure for cb.
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
  GNUNET_SCHEDULER_TaskIdentifier reconnect_task;

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
 * Function called with responses from the service.
 *
 * @param cls our 'struct GNUNET_TRANSPORT_PeerAddressLookupContext*'
 * @param msg NULL on timeout or error, otherwise presumably a
 *        message with the human-readable address
 */
static void
peer_address_response_processor (void *cls,
                                 const struct GNUNET_MessageHeader *msg);


/**
 * Send our subscription request to the service.
 *
 * @param pal_ctx our context
 */
static void
send_request (struct GNUNET_TRANSPORT_PeerIterateContext *pal_ctx)
{
  struct AddressIterateMessage msg;

  msg.header.size = htons (sizeof (struct AddressIterateMessage));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_ITERATE);
  msg.one_shot = htonl (pal_ctx->one_shot);
  msg.timeout = GNUNET_TIME_absolute_hton (pal_ctx->timeout);
  msg.peer = pal_ctx->peer;
  GNUNET_assert (GNUNET_OK ==
                 GNUNET_CLIENT_transmit_and_get_response (pal_ctx->client, 
							  &msg.header,
                                                          GNUNET_TIME_absolute_get_remaining (pal_ctx->timeout),
							  GNUNET_YES,
                                                          &peer_address_response_processor,
                                                          pal_ctx));
}

/**
 * Task run to re-establish the connection.
 * 
 * @param cls our 'struct GNUNET_TRANSPORT_PeerAddressLookupContext*'
 * @param tc scheduler context, unused
 */
static void
do_connect (void *cls,
	    const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct GNUNET_TRANSPORT_PeerIterateContext *pal_ctx = cls;

  pal_ctx->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  pal_ctx->client = GNUNET_CLIENT_connect ("transport", pal_ctx->cfg);
  GNUNET_assert (NULL != pal_ctx->client);
  send_request (pal_ctx);
}


/**
 * Cut the existing connection and reconnect.
 *
 * @param pal_ctx our context
 */
static void
reconnect (struct GNUNET_TRANSPORT_PeerIterateContext *pal_ctx)
{
  GNUNET_assert (GNUNET_NO == pal_ctx->one_shot);
  GNUNET_CLIENT_disconnect (pal_ctx->client);
  pal_ctx->client = NULL;
  pal_ctx->backoff = GNUNET_TIME_relative_max (GNUNET_TIME_UNIT_MILLISECONDS,
					       GNUNET_TIME_relative_min (GNUNET_TIME_relative_multiply (pal_ctx->backoff, 2),
									 GNUNET_TIME_relative_multiply (GNUNET_TIME_UNIT_SECONDS, 30)));
  pal_ctx->reconnect_task = GNUNET_SCHEDULER_add_delayed (pal_ctx->backoff,
							  &do_connect,
							  pal_ctx);
}


/**
 * Function called with responses from the service.
 *
 * @param cls our 'struct GNUNET_TRANSPORT_PeerAddressLookupContext*'
 * @param msg NULL on timeout or error, otherwise presumably a
 *        message with the human-readable address
 */
static void
peer_address_response_processor (void *cls,
                                 const struct GNUNET_MessageHeader *msg)
{
  struct GNUNET_TRANSPORT_PeerIterateContext *pal_ctx = cls;
  struct AddressIterateResponseMessage *air_msg;
  struct GNUNET_HELLO_Address *address;
  const char *addr;
  const char *transport_name;
  uint16_t size;
  size_t alen;
  size_t tlen;

  if (msg == NULL)
  {
    if (pal_ctx->one_shot)
    {
      pal_ctx->cb (pal_ctx->cb_cls, NULL, NULL);
      GNUNET_TRANSPORT_peer_get_active_addresses_cancel (pal_ctx);
    }
    else
    {
      reconnect (pal_ctx);
    }
    return;
  }
  size = ntohs (msg->size);
  GNUNET_break (ntohs (msg->type) ==
                GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_ITERATE_RESPONSE);
  if (size == sizeof (struct GNUNET_MessageHeader))
  {
    /* done! */
    if (pal_ctx->one_shot)
    {
      pal_ctx->cb (pal_ctx->cb_cls, NULL, NULL);
      GNUNET_TRANSPORT_peer_get_active_addresses_cancel (pal_ctx);
    }
    else
    {
      reconnect (pal_ctx);
    }
    return;
  }

  if ((size < sizeof (struct AddressIterateResponseMessage)) ||
      (ntohs (msg->type) !=
       GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_ITERATE_RESPONSE))
  {
    GNUNET_break (0);
    if (pal_ctx->one_shot)
    {
      pal_ctx->cb (pal_ctx->cb_cls, NULL, NULL);
      GNUNET_TRANSPORT_peer_get_active_addresses_cancel (pal_ctx);
    }
    else
    {
      reconnect (pal_ctx);
    }
    return;
  }

  air_msg = (struct AddressIterateResponseMessage *) msg;
  tlen = ntohl (air_msg->pluginlen);
  alen = ntohl (air_msg->addrlen);

  if (size != sizeof (struct AddressIterateResponseMessage) + tlen + alen)
  {
    GNUNET_break (0);
    if (pal_ctx->one_shot)
    {
      pal_ctx->cb (pal_ctx->cb_cls, NULL, NULL);
      GNUNET_TRANSPORT_peer_get_active_addresses_cancel (pal_ctx);
    }
    else
    {
      reconnect (pal_ctx);
    }
    return;
  }

  if (alen == 0 && tlen == 0)
  {
    pal_ctx->cb (pal_ctx->cb_cls, &air_msg->peer, NULL);
  }
  else
  {
    addr = (const char *) &air_msg[1];
    transport_name = &addr[alen];

    if (transport_name[tlen - 1] != '\0')
    {
      GNUNET_break (0);
      if (pal_ctx->one_shot)	
      {
	pal_ctx->cb (pal_ctx->cb_cls, NULL, NULL);
	GNUNET_TRANSPORT_peer_get_active_addresses_cancel (pal_ctx);
      }
      else
      {
	reconnect (pal_ctx);
      }
      return;
    }

    /* notify client */
    address =
        GNUNET_HELLO_address_allocate (&air_msg->peer, transport_name, addr,
                                       alen);
    pal_ctx->cb (pal_ctx->cb_cls, &air_msg->peer, address);
    GNUNET_HELLO_address_free (address);
  }

  /* expect more replies */
  GNUNET_CLIENT_receive (pal_ctx->client, &peer_address_response_processor,
                         pal_ctx,
                         GNUNET_TIME_absolute_get_remaining (pal_ctx->timeout));
}


/**
 * Return all the known addresses for a specific peer or all peers.
 * Returns continuously all address if one_shot is set to GNUNET_NO
 *
 * CHANGE: Returns the address(es) that we are currently using for this
 * peer.  Upon completion, the 'AddressLookUpCallback' is called one more
 * time with 'NULL' for the address and the peer.  After this, the operation must no
 * longer be explicitly canceled.
 *
 * @param cfg configuration to use
 * @param peer peer identity to look up the addresses of, CHANGE: allow NULL for all (connected) peers
 * @param one_shot GNUNET_YES to return the current state and then end (with NULL+NULL),
 *                 GNUNET_NO to monitor the set of addresses used (continuously, must be explicitly canceled)
 * @param timeout how long is the lookup allowed to take at most (irrelevant if one_shot is set to GNUNET_NO)
 * @param peer_address_callback function to call with the results
 * @param peer_address_callback_cls closure for peer_address_callback
 */
struct GNUNET_TRANSPORT_PeerIterateContext *
GNUNET_TRANSPORT_peer_get_active_addresses (const struct
                                            GNUNET_CONFIGURATION_Handle *cfg,
                                            const struct GNUNET_PeerIdentity
                                            *peer, int one_shot,
                                            struct GNUNET_TIME_Relative timeout,
                                            GNUNET_TRANSPORT_PeerIterateCallback
                                            peer_address_callback,
                                            void *peer_address_callback_cls)
{
  struct GNUNET_TRANSPORT_PeerIterateContext *pal_ctx;
  struct GNUNET_CLIENT_Connection *client;

  client = GNUNET_CLIENT_connect ("transport", cfg);
  if (client == NULL)
    return NULL;
  if (GNUNET_YES != one_shot)
    timeout = GNUNET_TIME_UNIT_FOREVER_REL;
  pal_ctx = GNUNET_malloc (sizeof (struct GNUNET_TRANSPORT_PeerIterateContext));
  pal_ctx->cb = peer_address_callback;
  pal_ctx->cb_cls = peer_address_callback_cls;
  pal_ctx->cfg = cfg;
  pal_ctx->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  if (NULL != peer)
    pal_ctx->peer = *peer;
  pal_ctx->one_shot = one_shot;  
  pal_ctx->client = client;
  send_request (pal_ctx);

  return pal_ctx;
}


/**
 * Cancel request for address conversion.
 *
 * @param alc handle for the request to cancel
 */
void
GNUNET_TRANSPORT_peer_get_active_addresses_cancel (struct
                                                   GNUNET_TRANSPORT_PeerIterateContext
                                                   *alc)
{
  if (NULL != alc->client)
  {
    GNUNET_CLIENT_disconnect (alc->client);
    alc->client = NULL;
  }
  if (GNUNET_SCHEDULER_NO_TASK != alc->reconnect_task)
  {
    GNUNET_SCHEDULER_cancel (alc->reconnect_task);
    alc->reconnect_task = GNUNET_SCHEDULER_NO_TASK;
  }
  GNUNET_free (alc);
}


/* end of transport_api_peer_address_lookup.c */
