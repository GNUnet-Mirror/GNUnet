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
 *
 * FIXME:
 * - we should track requests by client, and if a client
 *   disconnects cancel all associated requests; right
 *   now, they will persist forever unless the client
 *   explicitly sends us a cancel before disconnecting!
 */
#include "platform.h"
#include "gnunet-service-ats.h"
#include "gnunet-service-ats_addresses.h"
#include "gnunet-service-ats_connectivity.h"
#include "gnunet-service-ats_plugins.h"
#include "ats.h"


/**
 * Pending Address suggestion requests
 */
struct GAS_Addresses_Suggestion_Requests
{
  /**
   * Next in DLL
   */
  struct GAS_Addresses_Suggestion_Requests *next;

  /**
   * Previous in DLL
   */
  struct GAS_Addresses_Suggestion_Requests *prev;

  /**
   * Peer ID
   */
  struct GNUNET_PeerIdentity id;
};


/**
 * Address suggestion requests DLL head.
 * FIXME: This must become a Multipeermap! O(n) operations
 * galore instead of O(1)!!!
 */
static struct GAS_Addresses_Suggestion_Requests *pending_requests_head;

/**
 * Address suggestion requests DLL tail
 */
static struct GAS_Addresses_Suggestion_Requests *pending_requests_tail;




/**
 * Cancel address suggestions for a peer
 *
 * @param peer the peer id
 */
void
GAS_addresses_request_address_cancel (const struct GNUNET_PeerIdentity *peer)
{
  struct GAS_Addresses_Suggestion_Requests *cur = pending_requests_head;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "Received request: `%s' for peer %s\n",
	      "request_address_cancel",
	      GNUNET_i2s (peer));

  while (NULL != cur)
  {
    if (0 == memcmp (peer, &cur->id, sizeof(cur->id)))
      break; /* found */
    cur = cur->next;
  }

  if (NULL == cur)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "No address requests pending for peer `%s', cannot remove!\n",
                GNUNET_i2s (peer));
    return;
  }
  GAS_plugin_request_connect_stop (peer);
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Removed request pending for peer `%s\n",
              GNUNET_i2s (peer));
  GNUNET_CONTAINER_DLL_remove (pending_requests_head,
                               pending_requests_tail,
                               cur);
  GNUNET_free (cur);
}


/**
 * Request address suggestions for a peer
 *
 * @param peer the peer id
 */
void
GAS_addresses_request_address (const struct GNUNET_PeerIdentity *peer)
{
  struct GAS_Addresses_Suggestion_Requests *cur = pending_requests_head;

  GNUNET_log(GNUNET_ERROR_TYPE_DEBUG,
             "Received `%s' for peer `%s'\n",
             "REQUEST ADDRESS",
             GNUNET_i2s (peer));

  while (NULL != cur)
  {
    if (0 == memcmp (peer, &cur->id, sizeof(cur->id)))
      break; /* already suggesting */
    cur = cur->next;
  }
  if (NULL == cur)
  {
    cur = GNUNET_new (struct GAS_Addresses_Suggestion_Requests);
    cur->id = *peer;
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
                "Adding new address suggestion request for `%s'\n",
                GNUNET_i2s (peer));
    GNUNET_CONTAINER_DLL_insert (pending_requests_head,
                                 pending_requests_tail,
                                 cur);
  }
  GAS_plugin_request_connect_start (peer);
}



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

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Received `%s' message\n",
              "REQUEST_ADDRESS");
  GNUNET_break (0 == ntohl (msg->reserved));
  GAS_addresses_request_address (&msg->peer);
  GNUNET_SERVER_receive_done (client, GNUNET_OK);
}


/**
 * Handle 'request address' messages from clients.
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
              "Received `%s' message\n",
              "REQUEST_ADDRESS_CANCEL");
  GNUNET_break (0 == ntohl (msg->reserved));
  GAS_addresses_request_address_cancel (&msg->peer);
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
  // FIXME
}


/**
 * Shutdown connectivity subsystem.
 */
void
GAS_connectivity_done ()
{
  struct GAS_Addresses_Suggestion_Requests *cur;

  while (NULL != (cur = pending_requests_head))
  {
    GNUNET_CONTAINER_DLL_remove (pending_requests_head,
                                 pending_requests_tail,
                                 cur);
    GNUNET_free(cur);
  }
}


/* end of gnunet-service-ats_connectivity.c */
