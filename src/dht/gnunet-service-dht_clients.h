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
 * @file dht/gnunet-service-dht_clients.h
 * @brief GNUnet DHT service's client management code
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#ifndef GNUNET_SERVICE_DHT_CLIENTS_H
#define GNUNET_SERVICE_DHT_CLIENTS_H

#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"

/**
 * Handle a reply we've received from another peer.  If the reply
 * matches any of our pending queries, forward it to the respective
 * client(s).
 *
 * @param expiration when will the reply expire
 * @param key the query this reply is for
 * @param get_path_length number of peers in 'get_path'
 * @param get_path path the reply took on get
 * @param put_path_length number of peers in 'put_path'
 * @param put_path path the reply took on put
 * @param type type of the reply
 * @param data_size number of bytes in 'data'
 * @param data application payload data
 */
void
GDS_CLIENT_handle_reply (struct GNUNET_TIME_Absolute expiration,
			 const GNUNET_HashCode *key,
			 unsigned int get_path_length,
			 const struct GNUNET_PeerIdentity *get_path,
			 unsigned int put_path_length,
			 const struct GNUNET_PeerIdentity *put_path,
			 enum GNUNET_BLOCK_Type type,
			 size_t data_size,
			 const void *data);


/**
 * Initialize client subsystem.
 *
 * @param server the initialized server
 */
void 
GDS_CLIENT_init (struct GNUNET_SERVER_Handle *server);


/**
 * Shutdown client subsystem.
 */
void
GDS_CLIENT_done (void);

#endif
