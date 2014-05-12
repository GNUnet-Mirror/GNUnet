/*
     This file is part of GNUnet.
     (C) 2011 - 2014 Christian Grothoff (and other contributing authors)

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
 * @file dht/gnunet-service-xdht_routing.h
 * @brief GNUnet DHT tracking of requests for routing replies
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_XDHT_ROUTING_H
#define GNUNET_SERVICE_XDHT_ROUTING_H

#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"
#include "gnunet_dht_service.h"


/**
 * Add a new entry to our routing table.
 * @param source peer Source of the trail.
 * @param destintation Destination of the trail.
 * @param next_hop Next peer to forward the message to reach the destination.
 * @return GNUNET_YES
 *         GNUNET_SYSERR If the number of routing entries crossed thershold.
 */
int
GDS_ROUTING_add (const struct GNUNET_PeerIdentity *source,
                 const struct GNUNET_PeerIdentity *dest,
                 const struct GNUNET_PeerIdentity *next_hop,
                 struct GNUNET_PeerIdentity *prev_hop);


/**
 * Iterate over routing table and remove entries for which peer is a part. 
 * @param peer
 * @return 
 */
void
GDS_ROUTING_remove_entry (const struct GNUNET_PeerIdentity *peer);


/**
 * Search the next hop to send the packet to in routing table.
 * @return next hop peer id
 */
struct GNUNET_PeerIdentity *
GDS_ROUTING_search(struct GNUNET_PeerIdentity *source_peer,
                   struct GNUNET_PeerIdentity *destination_peer,
                   const struct GNUNET_PeerIdentity *prev_hop);

/**
 * Remove the trail as result of trail tear down message. 
 * @param source_peer Source of the trail.
 * @param destination_peer Destination of the trail.
 * @param next_hop Next hop
 * @param prev_hop Previous hop. 
 * @return #GNUNET_YES if successful
 *         #GNUNET_NO if not successful. 
 */
int
GDS_ROUTING_remove_trail (struct GNUNET_PeerIdentity *source_peer,
                          struct GNUNET_PeerIdentity *destination_peer, 
                          const struct GNUNET_PeerIdentity *prev_hop);


/**
 * Check if size of routing table is greater than threshold or not. 
 */
int
GDS_ROUTING_check_threshold (void);

/**
 * Initialize routing subsystem.
 */
void
GDS_ROUTING_init (void);


/**
 * Shutdown routing subsystem.
 */
void
GDS_ROUTING_done (void);

#endif
