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
 * @file transport/gnunet-service-transport_neighbours.h
 * @brief plugin management API
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_TRANSPORT_NEIGHBOURS_H
#define GNUNET_SERVICE_TRANSPORT_NEIGHBOURS_H

#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_util_lib.h"


/**
 *
 */
void 
GST_neighbours_start (void *cls,
		      GNUNET_TRANSPORT_NotifyConnect connect_cb,
		      GNUNET_TRANSPORT_NotifyDisconnect disconnect_cb);

/**
 *
 */
void
GST_neighbours_stop (void);

/**
 *
 */
void
GST_neighbours_try_connect (const struct GNUNET_PeerIdentity *target);

/**
 *
 */
int
GST_neighbours_test_connected (const struct GNUNET_PeerIdentity *target);

/**
 *
 */
void
GST_neighbours_force_disconnect (const struct GNUNET_PeerIdentity *target);


typedef void (*GST_NeighbourIterator)(void *cls,
				      const struct GNUNET_PeerIdentity *neighbour);


void
GST_neighbours_iterate (GST_NeighbourIterator cb,
			void *cb_cls);


/**
 *
 */
int
GST_neighbours_handle_pong (const GNUNET_PeerIdentity *sender,
			    const struct GNUNET_MessageHeader *hdr,
			    const char *plugin_name,
			    const void *sender_address,
			    size_t sender_address_len);

/**
 *
 */
int
GST_neighbours_handle_connect (const GNUNET_PeerIdentity *sender,
			       const struct GNUNET_MessageHeader *hdr,
			       const char *plugin_name,
			       const void *sender_address,
			       size_t sender_address_len);

/**
 *
 */
int
GST_neighbours_handle_disconnect (const GNUNET_PeerIdentity *sender,
				  const struct GNUNET_MessageHeader *hdr,
				  const char *plugin_name,
				  const void *sender_address,
				  size_t sender_address_len);




#endif
/* end of file gnunet-service-transport_neighbours.h */
