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
#include "gnunet_util_lib.h"
#include "gnunet_service_core_clients.h"

#ifndef GNUNET_SERVICE_CORE_CLIENTS_H
#define GNUNET_SERVICE_CORE_CLIENTS_H


/**
 * Notify client about a change to existing connection to one of our neighbours.
 *
 * @param neighbour identity of the neighbour that changed status
 * @param tmap updated type map for the neighbour, NULL for disconnect
 */
void
GDS_CLIENTS_notify_clients_about_neighbour (const struct GNUNET_PeerIdentity *neighbour,
					    const struct GSC_TypeMap *tmap);


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
