/*
     This file is part of GNUnet.
     (C) 2010,2011 Christian Grothoff (and other contributing authors)

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
 * @file transport/gnunet-service-transport_clients.h
 * @brief plugin management API
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_TRANSPORT_CLIENTS_H
#define GNUNET_SERVICE_TRANSPORT_CLIENTS_H

#include "gnunet_statistics_service.h"
#include "gnunet_util_lib.h"
#include "gnunet_hello_lib.h"


/**
 * Start handling requests from clients.
 *
 * @param server server used to accept clients from.
 */
void
GST_clients_start (struct GNUNET_SERVER_Handle *server);


/**
 * Stop processing clients.
 */
void
GST_clients_stop (void);


/**
 * Broadcast the given message to all of our clients.
 *
 * @param msg message to broadcast
 * @param may_drop GNUNET_YES if the message can be dropped / is payload
 */
void
GST_clients_broadcast (const struct GNUNET_MessageHeader *msg, int may_drop);


/**
 * Send the given message to a particular client
 *
 * @param client target of the message
 * @param msg message to transmit
 * @param may_drop GNUNET_YES if the message can be dropped
 */
void
GST_clients_unicast (struct GNUNET_SERVER_Client *client,
                     const struct GNUNET_MessageHeader *msg, int may_drop);


/**
 * Broadcast the new active address to all clients monitoring the peer.
 *
 * @param peer peer this update is about (never NULL)
 * @param address address, NULL on disconnect
 */
void
GST_clients_broadcast_address_notification (const struct GNUNET_PeerIdentity
                                            *peer,
                                            const struct GNUNET_HELLO_Address
                                            *address);


#endif
/* end of file gnunet-service-transport_clients.h */
