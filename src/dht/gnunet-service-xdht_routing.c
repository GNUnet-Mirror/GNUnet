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
 * @file dht/gnunet-service-xdht_routing.c
 * @brief GNUnet DHT tracking of requests for routing replies
 * @author Supriti Singh
 */
#include "platform.h"
#include "gnunet-service-xdht_neighbours.h"
#include "gnunet-service-xdht_routing.h"
#include "gnunet-service-xdht.h"

/* FIXME
 * 1. We need field to understand which routing table is for which peer.
 * 2. Better function names and variable names.
 */
/**
 * Number of requests we track at most (for routing replies).
 */
#define DHT_MAX_RECENT (1024 * 16)


/**
 * Routing table entry .
 */
struct RoutingTrail
{
    /**
     * Source peer .
     */
    struct GNUNET_PeerIdentity endpoint1;

    /**
     * Destination peer.
     */
    struct GNUNET_PeerIdentity endppoint2;

    /**
     * The peer this request was received from.
     */
    struct GNUNET_PeerIdentity previous_hop;

    /**
     * The peer to which this request should be passed to.
     */
    struct GNUNET_PeerIdentity next_hop;
};


/**
 * Routing table of the peer
 */
static struct GNUNET_CONTAINER_MultiPeerMap *routing_table;


/**
 * Find the next hop to pass the message to .
 * @return
 */
//static
struct GNUNET_PeerIdentity *
find_next_hop()
{
  return NULL;    
}



/**FIXME: Old function added just to remove error for time being. 
 * Add a new entry to our routing table.
 *
 * @param sender peer that originated the request
 * @param type type of the block
 * @param options options for processing
 * @param key key for the content
 * @param xquery extended query
 * @param xquery_size number of bytes in @a xquery
 * @param reply_bf bloomfilter to filter duplicates
 * @param reply_bf_mutator mutator for @a reply_bf
 */
void
GDS_ROUTING_add (const struct GNUNET_PeerIdentity *sender,
                 enum GNUNET_BLOCK_Type type,
                 enum GNUNET_DHT_RouteOption options,
                 const struct GNUNET_HashCode * key, const void *xquery,
                 size_t xquery_size,
                 const struct GNUNET_CONTAINER_BloomFilter *reply_bf,
                 uint32_t reply_bf_mutator)
{

}


/**
 * Search the next hop to send the packet to in routing table.
 * @return next hop peer id
 */
struct GNUNET_PeerIdentity *
GDS_Routing_search(struct GNUNET_PeerIdentity *source_peer,
                   struct GNUNET_PeerIdentity *destination_peer,
                   struct GNUNET_PeerIdentity *prev_hop)
{
    //struct GNUNET_PeerIdentity *next_hop;
    
    /* We have got all the fields and now we should search the 
     routing table by destination_peer and we should return the next_hop
     I don't see any function at the moment in container_multipeer_map. */
    return NULL;
}


/**FIXME: Old implementation just to remove error
 * Handle a reply (route to origin).  Only forwards the reply back to
 * other peers waiting for it.  Does not do local caching or
 * forwarding to local clients.  Essentially calls
 * GDS_NEIGHBOURS_handle_reply for all peers that sent us a matching
 * request recently.
 *
 * @param type type of the block
 * @param expiration_time when does the content expire
 * @param key key for the content
 * @param put_path_length number of entries in put_path
 * @param put_path peers the original PUT traversed (if tracked)
 * @param get_path_length number of entries in get_path
 * @param get_path peers this reply has traversed so far (if tracked)
 * @param data payload of the reply
 * @param data_size number of bytes in data
 */
void
GDS_ROUTING_process (enum GNUNET_BLOCK_Type type,
                     struct GNUNET_TIME_Absolute expiration_time,
                     const struct GNUNET_HashCode * key, unsigned int put_path_length,
                     const struct GNUNET_PeerIdentity *put_path,
                     unsigned int get_path_length,
                     const struct GNUNET_PeerIdentity *get_path,
                     const void *data, size_t data_size)
{
}
/**
 * Initialize routing subsystem.
 */
void
GDS_ROUTING_init ()
{
  routing_table = GNUNET_CONTAINER_multipeermap_create (DHT_MAX_RECENT * 4 / 3, GNUNET_NO);
}


/**
 * Shutdown routing subsystem.
 */
void
GDS_ROUTING_done ()
{
  GNUNET_assert (0 == GNUNET_CONTAINER_multipeermap_size (routing_table));
  GNUNET_CONTAINER_multipeermap_destroy (routing_table);
}

/* end of gnunet-service-xdht_routing.c */