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
 * @file transport/gnunet-service-transport_clients.c
 * @brief plugin management API
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-transport_clients.h"


/**
 * Start handling requests from clients.
 *
 * @param server server used to accept clients from.
 */
void 
GST_clients_start (struct GNUNET_SERVER_Handle *server)
{
}


/**
 * Stop processing clients.
 */
void
GST_clients_stop ()
{
}



/**
 * Initialize a normal client.  We got an init message from this
 * client, add him to the list of clients for broadcasting of inbound
 * messages.
 *
 * @param cls unused
 * @param client the client
 * @param message the init message that was sent
 */
void
GST_clients_handle_init (void *cls,
			 struct GNUNET_SERVER_Client *client,
			 const struct GNUNET_MessageHeader *message)
{
}


/**
 * Client asked for transmission to a peer.  Process the request.
 *
 * @param cls unused
 * @param client the client
 * @param message the send message that was sent
 */
void
GST_clients_handle_send (void *cls,
			 struct GNUNET_SERVER_Client *client,
			 const struct GNUNET_MessageHeader *message)
{
}


/**
 * Client asked for a quota change for a particular peer.  Process the request.
 *
 * @param cls unused
 * @param client the client
 * @param message the quota changing message
 */
void
GST_clients_handle_set_quota (void *cls,
			      struct GNUNET_SERVER_Client *client,
			      const struct GNUNET_MessageHeader *message)
{
}


/**
 * Client asked to resolve an address.  Process the request.
 *
 * @param cls unused
 * @param client the client
 * @param message the resolution request
 */
void
GST_clients_handle_address_lookup (void *cls,
				   struct GNUNET_SERVER_Client *client,
				   const struct GNUNET_MessageHeader *message)
{
}


/**
 * Client asked to obtain information about a peer's addresses.
 * Process the request.
 *
 * @param cls unused
 * @param client the client
 * @param message the peer address information request
 */
void
GST_clients_handle_peer_address_lookup (void *cls,
					struct GNUNET_SERVER_Client *client,
					const struct GNUNET_MessageHeader *message)
{
}


/**
 * Client asked to obtain information about all addresses.
 * Process the request.
 *
 * @param cls unused
 * @param client the client
 * @param message the peer address information request
 */
void
GST_clients_handle_address_iterate (void *cls,
				    struct GNUNET_SERVER_Client *client,
				    const struct GNUNET_MessageHeader *message)
{
}


/**
 * Broadcast the given message to all of our clients.
 *
 * @param msg message to broadcast
 * @param candrop GNUNET_YES if the message can be dropped
 */
void
GST_clients_broadcast (const struct GNUNET_MessageHeader *msg,
		       int candrop)
{
  
}


/**
 * Send the given message to a particular client
 *
 * @param client target of the message
 * @param msg message to transmit
 * @param candrop GNUNET_YES if the message can be dropped
 */
void
GST_clients_unicast (struct GNUNET_SERVER_Client *client,
		     const struct GNUNET_MessageHeader *msg,
		     int candrop)
{
}


/* end of file gnunet-service-transport_clients.c */
