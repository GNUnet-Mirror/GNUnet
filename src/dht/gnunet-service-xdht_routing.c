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


/**
 * Number of requests we track at most (for routing replies).
 */
#define DHT_MAX_RECENT (1024 * 16)

/**
 * Maximum number of entries in routing table. 
 */
#define ROUTING_TABLE_THRESHOLD 64

/**
 * Routing table entry .
 */
struct RoutingTrail
{
  /**
   * Source peer .
   */
  struct GNUNET_PeerIdentity source;

  /**
   * Destination peer.
   */
  struct GNUNET_PeerIdentity destination;

  /**
   * The peer to which this request should be passed to.
   */
  struct GNUNET_PeerIdentity next_hop;
  
  /**
   * Peer just before next hop in the trail. 
   */
  struct GNUNET_PeerIdentity prev_hop;
  
};


/**
 * Routing table of the peer
 */
static struct GNUNET_CONTAINER_MultiPeerMap *routing_table;


/**
 * Add a new entry to our routing table.
 * @param source peer Source of the trail.
 * @param destintation Destination of the trail.
 * @param next_hop Next peer to forward the message to reach the destination.
 * @return GNUNET_YES
 *         GNUNET_SYSERR If the number of routing entries crossed thershold.
 */
int
GDS_ROUTING_add (struct GNUNET_PeerIdentity *source,
                 struct GNUNET_PeerIdentity *dest,
                 struct GNUNET_PeerIdentity *next_hop,
                 const struct GNUNET_PeerIdentity *prev_hop)
{
  struct RoutingTrail *new_routing_entry;
    
  if (GNUNET_CONTAINER_multipeermap_size(routing_table) > ROUTING_TABLE_THRESHOLD)
    return GNUNET_SYSERR;
  //FPRINTF (stderr,_("\nSUPU ROUTING ADD %s, %s, %d"),__FILE__, __func__,__LINE__);
  new_routing_entry = GNUNET_malloc (sizeof (struct RoutingTrail));
  memcpy (&(new_routing_entry->source) , source, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(new_routing_entry->next_hop), next_hop, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(new_routing_entry->destination), dest, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(new_routing_entry->prev_hop), prev_hop, sizeof (struct GNUNET_PeerIdentity));
  
  GNUNET_assert (GNUNET_OK ==
    GNUNET_CONTAINER_multipeermap_put (routing_table,
                                       dest, new_routing_entry,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  return GNUNET_YES;
}


/**
 * Iterate over multiple entries for same destinational value and get
 * the correct next hop.
 * @param cls struct RoutingTrail
 * @param key Destination identity
 * @param value struct RoutingTrail
 * @return #GNUNET_YES to continue looking, #GNUNET_NO if we found the next hop
 */
int
get_next_hop (void *cls, const struct GNUNET_PeerIdentity *key, void *value)
{
  /* Here you should match if source, prev hop matches if yes then send 
   GNUNET_NO as you don't need to check more entries. */
  struct RoutingTrail *request = cls;
  struct RoutingTrail *existing_entry = (struct RoutingTrail *)value;
  
  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&(request->source), &(existing_entry->source)))
  {
    if (0 == GNUNET_CRYPTO_cmp_peer_identity (&(request->prev_hop), &(existing_entry->prev_hop)))
    {
      memcpy (&(request->next_hop), &(existing_entry->next_hop), sizeof (struct GNUNET_PeerIdentity));
      return GNUNET_YES;
    }
  }
  return GNUNET_NO;
}


/**
 * Find the next hop to send packet to.
 * @param source_peer Source of the trail.
 * @param destination_peer Destination of the trail.
 * @param prev_hop Previous hop in the trail. 
 * @return Next hop in the trail from source to destination. 
 */
struct GNUNET_PeerIdentity *
GDS_ROUTING_search(struct GNUNET_PeerIdentity *source_peer,
                   struct GNUNET_PeerIdentity *destination_peer,
                   const struct GNUNET_PeerIdentity *prev_hop)
{
  struct RoutingTrail *trail;
  trail = GNUNET_malloc (sizeof (struct RoutingTrail));
  memcpy (&(trail->destination), destination_peer, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(trail->source), source_peer, sizeof (struct GNUNET_PeerIdentity));
  memcpy (&(trail->prev_hop), prev_hop, sizeof (struct GNUNET_PeerIdentity));
  //trail->next_hop = NULL;
  //FPRINTF (stderr,_("\nSUPU ROUTING SEARCH %s, %s, %d"),__FILE__, __func__,__LINE__);
  GNUNET_CONTAINER_multipeermap_get_multiple (routing_table, destination_peer,
                                              get_next_hop, trail);
  if(trail != NULL)
    return &(trail->next_hop);
  else
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
  return;
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