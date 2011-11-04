/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * Reserve the given amount of incoming bandwidth (in bytes) from the
 * given peer.  If a reservation is not possible right now, return how
 * long the client should wait before trying again.
 *
 * @param peer peer to reserve bandwidth from
 * @param amount number of bytes to reserve
 * @return 0 if the reservation was successful, FOREVER if the
 *         peer is not connected, otherwise the time to wait
 *         until the reservation might succeed
 */
struct GNUNET_TIME_Relative
GAS_reservations_reserve (const struct GNUNET_PeerIdentity *peer,
                          int32_t amount);


/**
 * Initialize reservations subsystem.
 */
void
GAS_reservations_init (void);


/**
 * Shutdown reservations subsystem.
 */
void
GAS_reservations_done (void);

#endif
