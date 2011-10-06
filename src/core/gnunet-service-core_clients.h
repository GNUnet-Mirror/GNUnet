/*
     This file is part of GNUnet.
     (C) 2009, 2010, 2011 Christian Grothoff (and other contributing authors)

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
 * @file core/gnunet-service-core_clients.h
 * @brief code for managing interactions with clients of core service
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_CORE_CLIENTS_H
#define GNUNET_SERVICE_CORE_CLIENTS_H

#include "gnunet_util_lib.h"
#include "gnunet_service_core.h"


/**
 * Notify a particular client about a change to existing connection to
 * one of our neighbours (check if the client is interested).  Called
 * from 'GSC_SESSIONS_notify_client_about_sessions'.
 *
 * @param client client to notify
 * @param neighbour identity of the neighbour that changed status
 * @param tmap_old previous type map for the neighbour, NULL for disconnect
 * @param tmap_new updated type map for the neighbour, NULL for disconnect
 */
void
GDS_CLIENTS_notify_client_about_neighbour (struct GSC_Client *client,
					   const struct GNUNET_PeerIdentity *neighbour,
					   const struct GSC_TypeMap *tmap_old,
					   const struct GSC_TypeMap *tmap_new);


/**
 * Notify client about a change to existing connection to one of our neighbours.
 *
 * @param neighbour identity of the neighbour that changed status
 * @param tmap_old previous type map for the neighbour, NULL for disconnect
 * @param tmap_new updated type map for the neighbour, NULL for disconnect
 */
void
GDS_CLIENTS_notify_clients_about_neighbour (const struct GNUNET_PeerIdentity *neighbour,
					    const struct GSC_TypeMap *tmap_old,
					    const struct GSC_TypeMap *tmap_new);


/**
 * Deliver P2P message to interested clients.
 *
 * @param sender peer who sent us the message 
 * @param m the message
 */
void
GSC_CLIENTS_deliver_message (const struct GNUNET_PeerIdentity *sender,
			     const struct GNUNET_MessageHeader *m);


/**
 * Tell a client that we are ready to receive the message.
 *
 * @param car request that is now ready; the responsibility
 *        for the handle remains shared between CLIENTS
 *        and SESSIONS after this call.
 */
void
GSC_CLIENTS_solicit_request (struct GSC_ClientActiveRequest *car);


/**
 * Tell a client that we will never be ready to receive the
 * given message in time (disconnect or timeout).
 *
 * @param car request that now permanently failed; the
 *        responsibility for the handle is now returned
 *        to CLIENTS (SESSIONS is done with it).
 */
void
GSC_CLIENTS_reject_request (struct GSC_ClientActiveRequest *car);


/**
 * Initialize clients subsystem.
 *
 * @param server handle to server clients connect to
 */
void
GSC_CLIENTS_init (struct GNUNET_SERVER_Handle *server);


/**
 * Shutdown clients subsystem.
 */
void
GSC_CLIENTS_done (void);

#endif
/* end of gnunet-service-core_clients.h */
