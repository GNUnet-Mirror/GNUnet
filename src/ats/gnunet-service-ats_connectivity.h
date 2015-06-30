/*
     This file is part of GNUnet.
     Copyright (C) 2011-2015 Christian Grothoff (and other contributing authors)

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
 * @file ats/gnunet-service-ats_connectivity.h
 * @brief ats service, interaction with 'connecivity' API
 * @author Matthias Wachs
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_ATS_CONNECTIVITY_H
#define GNUNET_SERVICE_ATS_CONNECTIVITY_H


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
                           const struct GNUNET_PeerIdentity *peer);


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
                            const struct GNUNET_MessageHeader *message);


/**
 * Cancel 'request address' messages from clients.
 *
 * @param cls unused, NULL
 * @param client client that sent the request
 * @param message the request message
 */
void
GAS_handle_request_address_cancel (void *cls,
                                   struct GNUNET_SERVER_Client *client,
                                   const struct GNUNET_MessageHeader *message);


/**
 * Unregister a client (which may have been a connectivity client,
 * but this is not assured).
 *
 * @param client handle of the (now dead) client
 */
void
GAS_connectivity_remove_client (struct GNUNET_SERVER_Client *client);


/**
 * Initialize connectivity subsystem.
 */
void
GAS_connectivity_init (void);


/**
 * Shutdown connectivity subsystem.
 */
void
GAS_connectivity_done (void);


#endif
/* end of gnunet-service-ats_connectivity.h */
