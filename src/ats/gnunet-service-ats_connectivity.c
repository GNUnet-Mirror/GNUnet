/*
     This file is part of GNUnet.
     Copyright (C) 2011-2015 GNUnet e.V.

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
  struct GNUNET_SERVICE_Client *client;

  /* TODO: allow client to express a 'strength' for this request */
};


/**
 * Address suggestion requests by peer.
 */
static struct GNUNET_CONTAINER_MultiPeerMap *connection_requests;


/**
 * Is the given peer in the list of peers for which we
 * have an address request?
 *
 * @param cls unused, NULL
 * @param peer peer to query for
 * @return #GNUNET_YES if so, #GNUNET_NO if not
 */
unsigned int
GAS_connectivity_has_peer (void *cls,
                           const struct GNUNET_PeerIdentity *peer)
{
  if (NULL == connection_requests)
    return 0;
  /* TODO: return sum of 'strength's of connectivity requests */
  return GNUNET_CONTAINER_multipeermap_contains (connection_requests,
                                                 peer);
}


/**
 * Handle #GNUNET_MESSAGE_TYPE_ATS_REQUEST_ADDRESS messages from clients.
 *
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_request_address (struct GNUNET_SERVICE_Client *client,
			    const struct RequestAddressMessage *msg)
{
  struct ConnectionRequest *cr;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' message\n",
              "GNUNET_MESSAGE_TYPE_ATS_REQUEST_ADDRESS");
  /* FIXME: should not ignore "msg->strength" */
  cr = GNUNET_new (struct ConnectionRequest);
  cr->client = client;
  (void) GNUNET_CONTAINER_multipeermap_put (connection_requests,
                                            &msg->peer,
                                            cr,
                                            GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE);
  GAS_plugin_request_connect_start (&msg->peer);
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
  struct GNUNET_SERVICE_Client *client = cls;
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
 * Handle #GNUNET_MESSAGE_TYPE_ATS_REQUEST_ADDRESS_CANCEL messages
 * from clients.
 *
 * @param client the client that sent the request
 * @param msg the request message
 */
void
GAS_handle_request_address_cancel (struct GNUNET_SERVICE_Client *client,
				   const struct RequestAddressMessage *msg)
{
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received GNUNET_MESSAGE_TYPE_ATS_REQUEST_ADDRESS_CANCEL message for peer %s\n",
              GNUNET_i2s (&msg->peer));
  GNUNET_break (0 == ntohl (msg->strength));
  GNUNET_CONTAINER_multipeermap_get_multiple (connection_requests,
                                              &msg->peer,
                                              &free_matching_requests,
                                              client);
}


/**
 * Unregister a client (which may have been a connectivity client,
 * but this is not assured).
 *
 * @param client handle of the (now dead) client
 */
void
GAS_connectivity_remove_client (struct GNUNET_SERVICE_Client *client)
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
  connection_requests
    = GNUNET_CONTAINER_multipeermap_create (32,
					    GNUNET_NO);
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
  GAS_plugin_solver_lock ();
  GNUNET_CONTAINER_multipeermap_iterate (connection_requests,
                                         &free_request,
                                         NULL);
  GAS_plugin_solver_unlock ();
  GNUNET_CONTAINER_multipeermap_destroy (connection_requests);
  connection_requests = NULL;
}


/* end of gnunet-service-ats_connectivity.c */
