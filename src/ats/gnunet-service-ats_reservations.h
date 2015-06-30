/*
     This file is part of GNUnet.
     Copyright (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file ats/gnunet-service-ats_reservations.h
 * @brief ats service, inbound bandwidth reservation management
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_ATS_RESERVATIONS_H
#define GNUNET_SERVICE_ATS_RESERVATIONS_H

#include "gnunet_util_lib.h"


/**
 * Set the amount of bandwidth the other peer could currently transmit
 * to us (as far as we know) to the given value.
 *
 * @param peer identity of the peer
 * @param bandwidth_in currently available bandwidth from that peer to
 *        this peer (estimate)
 */
void
GAS_reservations_set_bandwidth (const struct GNUNET_PeerIdentity *peer,
                                struct GNUNET_BANDWIDTH_Value32NBO
                                bandwidth_in);


/**
 * Handle 'reservation request' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_reservation_request (void *cls,
                                struct GNUNET_SERVER_Client *client,
                                const struct GNUNET_MessageHeader *message);


/**
 * Initialize reservations subsystem.
 *
 * @param server handle to our server
 */
void
GAS_reservations_init (struct GNUNET_SERVER_Handle *server);


/**
 * Shutdown reservations subsystem.
 */
void
GAS_reservations_done (void);

#endif
