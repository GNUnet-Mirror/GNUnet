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
#include "ats.h"

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

/* end of gnunet-service-ats_connectivity.c */
