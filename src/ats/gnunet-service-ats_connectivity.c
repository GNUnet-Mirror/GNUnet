/*
     This file is part of GNUnet.
     (C) 2011-2015 Christian Grothoff (and other contributing authors)

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
 * @file ats/gnunet-service-ats_connectivity.c
 * @brief ats service, interaction with 'connecivity' API
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-ats.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet-service-ats_connectivity.h"
#include "gnunet-service-ats_plugins.h"
#include "ats.h"


/**
 * Active connection requests.
 */
struct ConnectionRequest
{
  /**
   * Client that made the request.
   */
  struct GNUNET_SERVER_Client *client;
};


/**
 * Address suggestion requests by peer.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *connection_requests;


/**
 * Handle 'request address' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_request_address (void *cls,
                            struct GNUNET_SERVER_Client *client,
                            const struct GNUNET_MessageHeader *message)
{
  const struct RequestAddressMessage *msg =
      (const struct RequestAddressMessage *) message;
  struct ConnectionRequest *cr;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' message\n",
              "REQUEST_ADDRESS");
  GNUNET_break (0 == ntohl (msg->reserved));
  cr = GNUNET_new (struct ConnectionRequest);
  cr->client = client;
  (void) GNUNET_CONTAINER_multipeermap_put (connection_requests,
                                            &msg->peer,
                                            cr,
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GAS_plugin_request_connect_start (&msg->peer);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Free the connection request from the map if the
 * closure matches the client.
 *
 * @param cls the client to match
 * @param pid peer for which the request was made
 * @param value the `struct ConnectionRequest`
 * @return #GNUNET_OK (continue to iterate)
 */
static int
free_matching_requests (void *cls,
                        const struct GNUNET_PeerIdentity *pid,
                        void *value)
{
  struct GNUNET_SERVER_Client *client = cls;
  struct ConnectionRequest *cr = value;

  if (cr->client == client)
  {
    GAS_plugin_request_connect_stop (pid);
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Removed request pending for peer `%s\n",
                GNUNET_i2s (pid));
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multipeermap_remove (connection_requests,
                                                         pid,
                                                         cr));
    GNUNET_free (cr);
  }
  return GNUNET_OK;
}


/**
 * Handle 'request address cancel' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_request_address_cancel (void *cls,
                                   struct GNUNET_SERVER_Client *client,
                                   const struct GNUNET_MessageHeader *message)
{
  const struct RequestAddressMessage *msg =
      (const struct RequestAddressMessage *) message;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received REQUEST_ADDRESS_CANCEL message for peer %s\n",
              GNUNET_i2s (&msg->peer));
  GNUNET_break (0 == ntohl (msg->reserved));
  GNUNET_CONTAINER_multipeermap_get_multiple (connection_requests,
                                              &msg->peer,
                                              &free_matching_requests,
                                              client);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Unregister a client (which may have been a connectivity client,
 * but this is not assured).
 *
 * @param client handle of the (now dead) client
 */
void
GAS_connectivity_remove_client (struct GNUNET_SERVER_Client *client)
{
  GNUNET_CONTAINER_multipeermap_iterate (connection_requests,
                                         &free_matching_requests,
                                         client);
}


/**
 * Shutdown connectivity subsystem.
 */
void
GAS_connectivity_init ()
{
  connection_requests = GNUNET_CONTAINER_multipeermap_create (32, GNUNET_NO);
}


/**
 * Free the connection request from the map.
 *
 * @param cls NULL
 * @param pid peer for which the request was made
 * @param value the `struct ConnectionRequest`
 * @return #GNUNET_OK (continue to iterate)
 */
static int
free_request (void *cls,
              const struct GNUNET_PeerIdentity *pid,
              void *value)
{
  struct ConnectionRequest *cr = value;

  free_matching_requests (cr->client,
                          pid,
                          cr);
  return GNUNET_OK;
}


/**
 * Shutdown connectivity subsystem.
 */
void
GAS_connectivity_done ()
{
  GNUNET_CONTAINER_multipeermap_iterate (connection_requests,
                                         &free_request,
                                         NULL);
  GNUNET_CONTAINER_multipeermap_destroy (connection_requests);
}


/* end of gnunet-service-ats_connectivity.c */
