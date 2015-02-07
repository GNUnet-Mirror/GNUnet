/*
     This file is part of GNUnet.
     Copyright (C) 2011 - 2014 Christian Grothoff (and other contributing authors)

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
 * To understand the direction in which trial should be read. 
 */
enum GDS_ROUTING_trail_direction 
{
  GDS_ROUTING_SRC_TO_DEST,
  GDS_ROUTING_DEST_TO_SRC
};


/**
 * Update the prev. hop of the trail. Call made by trail teardown where
 * if you are the first friend now in the trail then you need to update
 * your prev. hop.
 * @param trail_id
 * @return #GNUNET_OK success
 *         #GNUNET_SYSERR in case no matching entry found in routing table. 
 */
int
GDS_ROUTING_update_trail_prev_hop (struct GNUNET_HashCode trail_id,
                                   struct GNUNET_PeerIdentity prev_hop);


/**
 * Update the next hop of the trail. Call made by trail compression where
 * if you are source of the trail and now you have a new first friend, then
 * you should update the trail. 
 * @param trail_id
 * @return #GNUNET_OK success
 *         #GNUNET_SYSERR in case no matching entry found in routing table.
 */
int
GDS_ROUTING_update_trail_next_hop (const struct GNUNET_HashCode trail_id,
                                   struct GNUNET_PeerIdentity next_hop);

/**
 * Get the next hop for trail corresponding to trail_id
 * @param trail_id Trail id to be searched. 
 * @return Next_hop if found
 *         NULL If next hop not found. 
 */
struct GNUNET_PeerIdentity *
GDS_ROUTING_get_next_hop (struct GNUNET_HashCode trail_id,
                          enum GDS_ROUTING_trail_direction trail_direction);


/**
  * Remove every trail where peer is either next_hop or prev_hop 
 * @param peer Peer to be searched.
 */
int
GDS_ROUTING_remove_trail_by_peer (const struct GNUNET_PeerIdentity *peer);
/**
 * Remove trail with trail_id
 * @param trail_id Trail id to be removed
 * @return #GNUNET_YES success 
 *         #GNUNET_NO if entry not found.
 */
int
GDS_ROUTING_remove_trail (struct GNUNET_HashCode remove_trail_id);


/**
 * Add a new entry in routing table
 * @param new_trail_id
 * @param prev_hop
 * @param next_hop
 * @return #GNUNET_OK success
 *         #GNUNET_SYSERR in case new_trail_id already exists in the network
 *                         but with different prev_hop/next_hop
 */
int
GDS_ROUTING_add (struct GNUNET_HashCode new_trail_id, 
                 struct GNUNET_PeerIdentity prev_hop,
                 struct GNUNET_PeerIdentity next_hop);


/**
 * Check if the size of routing table has crossed threshold. 
 * @return #GNUNET_YES, if threshold crossed 
 *         #GNUNET_NO, if size is within threshold 
 */
int
GDS_ROUTING_threshold_reached (void);

#if 0
/**
 * Test function. Remove afterwards. 
 */
void 
GDS_ROUTING_test_print (void);
#endif

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