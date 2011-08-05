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
 * @file transport/transport_api_peer_address_lookup.c
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
struct AddressLookupCtx
{
  /**
   * Function to call with the human-readable address.
   */
  GNUNET_TRANSPORT_AddressLookUpCallback cb;

  /**
   * Closure for cb.
   */
  void *cb_cls;

  /**
   * Connection to the service.
   */
  struct GNUNET_CLIENT_Connection *client;

  /**
   * When should this operation time out?
   */
  struct GNUNET_TIME_Absolute timeout;
};


/**
 * Function called with responses from the service.
 *
 * @param cls our 'struct AddressLookupCtx*'
 * @param msg NULL on timeout or error, otherwise presumably a
 *        message with the human-readable address
 */
static void
peer_address_response_processor (void *cls,
                                 const struct GNUNET_MessageHeader *msg)
{
  struct AddressLookupCtx *alucb = cls;
  const char *address;
  uint16_t size;

  if (msg == NULL)
    {
      alucb->cb (alucb->cb_cls, NULL);
      GNUNET_CLIENT_disconnect (alucb->client, GNUNET_NO);
      GNUNET_free (alucb);
      return;
    }
  GNUNET_break (ntohs (msg->type) == GNUNET_MESSAGE_TYPE_TRANSPORT_ADDRESS_REPLY);
  size = ntohs (msg->size);
  if (size == sizeof (struct GNUNET_MessageHeader))
    {
      /* done! */
      alucb->cb (alucb->cb_cls, NULL);
      GNUNET_CLIENT_disconnect (alucb->client, GNUNET_NO);
      GNUNET_free (alucb);
      return;
    }
  address = (const char *) &msg[1];
  if (address[size - sizeof (struct GNUNET_MessageHeader) - 1] != '\0')
    {
      /* invalid reply */
      GNUNET_break (0);
      alucb->cb (alucb->cb_cls, NULL);
      GNUNET_CLIENT_disconnect (alucb->client, GNUNET_NO);
      GNUNET_free (alucb);
      return;
    }
  /* expect more replies */
  GNUNET_CLIENT_receive (alucb->client,
			 &peer_address_response_processor, alucb,
			 GNUNET_TIME_absolute_get_remaining
			 (alucb->timeout));
  alucb->cb (alucb->cb_cls, address);
}


/**
 * Return all the known addresses for a peer.
 *
 * @param cfg configuration to use
 * @param peer peer identity to look up the addresses of
 * @param timeout how long is the lookup allowed to take at most
 * @param peer_address_callback function to call with the results
 * @param peer_address_callback_cls closure for peer_address_callback
 */
void
GNUNET_TRANSPORT_peer_address_lookup (const struct GNUNET_CONFIGURATION_Handle *cfg,
                                      const struct GNUNET_PeerIdentity *peer,
                                      struct GNUNET_TIME_Relative timeout,
                                      GNUNET_TRANSPORT_AddressLookUpCallback peer_address_callback,
                                      void *peer_address_callback_cls)
{
  struct PeerAddressLookupMessage msg;
  struct AddressLookupCtx *peer_address_lookup_cb;
  struct GNUNET_CLIENT_Connection *client;

  client = GNUNET_CLIENT_connect ("transport", cfg);
  if (client == NULL)
    {
      peer_address_callback (peer_address_callback_cls, NULL);
      return;
    }
  msg.header.size = htons (sizeof(struct PeerAddressLookupMessage));
  msg.header.type = htons (GNUNET_MESSAGE_TYPE_TRANSPORT_PEER_ADDRESS_LOOKUP);
  msg.timeout = GNUNET_TIME_relative_hton (timeout);
  memcpy(&msg.peer, peer, sizeof(struct GNUNET_PeerIdentity));
  peer_address_lookup_cb = GNUNET_malloc (sizeof (struct AddressLookupCtx));
  peer_address_lookup_cb->cb = peer_address_callback;
  peer_address_lookup_cb->cb_cls = peer_address_callback_cls;
  peer_address_lookup_cb->timeout = GNUNET_TIME_relative_to_absolute (timeout);
  peer_address_lookup_cb->client = client;
  GNUNET_assert (GNUNET_OK ==
		 GNUNET_CLIENT_transmit_and_get_response (client,
							  &msg.header,
							  timeout,
							  GNUNET_YES,
							  &peer_address_response_processor,
							  peer_address_lookup_cb));
}

/* end of transport_api_peer_address_lookup.c */
