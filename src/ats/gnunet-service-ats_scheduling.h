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
 * @file ats/gnunet-service-ats_scheduling.h
 * @brief ats service, interaction with 'scheduling' API
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_ATS_SCHEDULING_H
#define GNUNET_SERVICE_ATS_SCHEDULING_H

#include "gnunet_util_lib.h"


/**
 * Register a new scheduling client.
 *
 * @param client handle of the new client
 * @return #GNUNET_OK on success, #GNUNET_SYSERR on error
 */
int
GAS_scheduling_add_client (struct GNUNET_SERVER_Client *client);


/**
 * Unregister a client (which may have been a scheduling client,
 * but this is not assured).
 *
 * @param client handle of the (now dead) client
 */
void
GAS_scheduling_remove_client (struct GNUNET_SERVER_Client *client);


/**
 * Transmit the given address suggestion and bandwidth update to all scheduling
 * clients.
 *
 * @param peer peer for which this is an address suggestion
 * @param session_id session ID to use
 * @param bandwidth_out assigned outbound bandwidth
 * @param bandwidth_in assigned inbound bandwidth
 */
void
GAS_scheduling_transmit_address_suggestion (const struct GNUNET_PeerIdentity *peer,
                                            uint32_t session_id,
                                            struct GNUNET_BANDWIDTH_Value32NBO bandwidth_out,
                                            struct GNUNET_BANDWIDTH_Value32NBO bandwidth_in);


/**
 * Handle 'address add' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_address_add (void *cls,
                        struct GNUNET_SERVER_Client *client,
                        const struct GNUNET_MessageHeader *message);


/**
 * Handle 'address update' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_address_update (void *cls,
                           struct GNUNET_SERVER_Client *client,
                           const struct GNUNET_MessageHeader *message);


/**
 * Handle 'address destroyed' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_address_destroyed (void *cls,
                              struct GNUNET_SERVER_Client *client,
                              const struct GNUNET_MessageHeader *message);


/**
 * Initialize scheduling subsystem.
 *
 * @param server handle to our server
 * @param ah the address handle to use
 */
void
GAS_scheduling_init (struct GNUNET_SERVER_Handle *server);


/**
 * Shutdown scheduling subsystem.
 */
void
GAS_scheduling_done (void);


#endif
/* end of gnunet-service-ats_scheduling.h */
