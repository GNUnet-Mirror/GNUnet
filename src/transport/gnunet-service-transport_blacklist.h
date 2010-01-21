/*
     This file is part of GNUnet.
     (C) 2010 Christian Grothoff (and other contributing authors)

     GNUnet is free software; you can redistribute it and/or modify
     it under the terms of the GNU General Public License as published
     by the Free Software Foundation; either version 2, or (at your
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
 * @file transport/gnunet-service-transport_blacklist.h
 * @brief internal API for blacklisting functionality
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_TRANSPORT_BLACKLIST_H
#define GNUNET_SERVICE_TRANSPORT_BLACKLIST_H

#include "gnunet_protocols.h"
#include "gnunet_service_lib.h"
#include "transport.h"

/**
 * Handle a request to blacklist a peer.
 *
 * @param cls closure (always NULL)
 * @param client identification of the client
 * @param message the actual message
 */
void
GNUNET_TRANSPORT_handle_blacklist (void *cls,
				   struct GNUNET_SERVER_Client *client,
				   const struct GNUNET_MessageHeader *message);


/**
 * Handle a request for notification of blacklist changes.
 *
 * @param cls closure (always NULL)
 * @param client identification of the client
 * @param message the actual message
 */
void
GNUNET_TRANSPORT_handle_blacklist_notify (void *cls,
					  struct GNUNET_SERVER_Client *client,
					  const struct GNUNET_MessageHeader *message);


/**
 * Is the given peer currently blacklisted?
 *
 * @param id identity of the peer
 * @return GNUNET_YES if the peer is blacklisted, GNUNET_NO if not
 */
int
GNUNET_TRANSPORT_blacklist_check (const struct GNUNET_PeerIdentity *id);


/**
 * Initialize the blacklisting subsystem.
 *
 * @param s scheduler to use
 */
void 
GNUNET_TRANSPORT_blacklist_init (struct GNUNET_SCHEDULER_Handle *s);


#endif
/* end of gnunet-service-transport_blacklist.h */
