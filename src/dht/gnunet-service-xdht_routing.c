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
 * @file dht/gnunet-service-xdht_routing.c
 * @brief GNUnet DHT tracking of requests for routing replies
 * @author Supriti Singh
 */
#include "platform.h"
#include "gnunet-service-xdht_neighbours.h"
#include "gnunet-service-xdht_routing.h"
#include "gnunet-service-xdht.h"

/* TODO
 1. to understand if we really need all the four fields.
 2. if we can merge remove_peer and remove_trail 
 3. do we need next_hop to uniquely identify a trail in remove_trail. */

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
 * Get next hop from the trail with source peer, destination peer and next hop
 * same as the argument to this function. 
 * @param source_peer  Source peer of the trail. 
 * @param destination_peer Destination peer of the trail. 
 * @param prev_hop Previous hop of the trail. 
 * @return #GNUNET_YES if we found the matching trail. 
 *         #GNUNET_NO if we found no matching trail.
 */
static int
get_next_hop (struct RoutingTrail *trail,
              struct GNUNET_PeerIdentity *source_peer,
              struct GNUNET_PeerIdentity *destination_peer, 
              const struct GNUNET_PeerIdentity *prev_hop)
{
  if (0 == GNUNET_CRYPTO_cmp_peer_identity (&(trail->source),source_peer))
  {
    if (0 == GNUNET_CRYPTO_cmp_peer_identity (&(trail->prev_hop),prev_hop))
    {
      return GNUNET_YES;
    }
    else 
      return GNUNET_NO;
  }
  return GNUNET_NO;
}


/**
 * FIXME: How to ensure that with only 3 fields also we have a unique trail.
 * in case of redundant routes we can have different next hop.
 * in that case we have to call this function on each entry of routing table
 * and from multiple next hop we return one. Here also we are going to return one.
 * URGENT. 
 * Assumption - there can be only on one trail with all these fields. But if
 * we consider only 3 fields then it is possible that next hop is differet. 
 * Update prev_hop field to source_peer. Trail from source peer to destination
 * peer is compressed such that I am the first friend in the trail. 
 * @param source_peer Source of the trail.
 * @param destination_peer Destination of the trail.
 * @param prev_hop Peer before me in the trail.
 * @return #GNUNET_YES trail is updated.
 *         #GNUNET_NO, trail not found. 
 */
int
GDS_ROUTING_trail_update (struct GNUNET_PeerIdentity *source_peer,
                          struct GNUNET_PeerIdentity *destination_peer,
                          struct GNUNET_PeerIdentity *prev_hop)
{
  /* 1. find the trail corresponding to these values. 
   2. update the prev hop to source peer. */  
  struct RoutingTrail *trail;
  struct GNUNET_CONTAINER_MultiPeerMapIterator *iterator;
  int i;
  
  iterator = GNUNET_CONTAINER_multipeermap_iterator_create (routing_table);
  for (i = 0; i< GNUNET_CONTAINER_multipeermap_size(routing_table); i++)
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next (iterator, NULL,
                                                                 (const void **)&trail)) 
    {
      if (0 == GNUNET_CRYPTO_cmp_peer_identity (&(trail->destination), destination_peer))
      {
        if (GNUNET_YES == get_next_hop (trail, source_peer, destination_peer, prev_hop))
        {
          memcpy (&(trail->prev_hop), source_peer, sizeof (struct GNUNET_PeerIdentity));
          return GNUNET_YES;
        }
      }
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
GDS_ROUTING_search (struct GNUNET_PeerIdentity *source_peer,
                    struct GNUNET_PeerIdentity *destination_peer,
                    const struct GNUNET_PeerIdentity *prev_hop)
{
  struct RoutingTrail *trail;
  struct GNUNET_CONTAINER_MultiPeerMapIterator *iterator;
  int i;
  
  iterator = GNUNET_CONTAINER_multipeermap_iterator_create (routing_table);
  for (i = 0; i< GNUNET_CONTAINER_multipeermap_size(routing_table); i++)
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next (iterator, NULL,
                                                                 (const void **)&trail)) 
    {
      if (0 == GNUNET_CRYPTO_cmp_peer_identity (&(trail->destination), destination_peer))
      {
        if (GNUNET_YES == get_next_hop (trail, source_peer, destination_peer, prev_hop))
        {
          return &(trail->next_hop);
        }
      }
    }
  }
  GNUNET_CONTAINER_multipeermap_iterator_destroy (iterator);
  return NULL;
}


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
                 struct GNUNET_PeerIdentity *prev_hop)
{
  struct RoutingTrail *new_routing_entry;
    
  if (GNUNET_CONTAINER_multipeermap_size(routing_table) > ROUTING_TABLE_THRESHOLD)
    return GNUNET_SYSERR;
 
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
 * Iterate over routing table and remove entries for which peer is a part. 
 * @param cls closure
 * @param key current public key
 * @param value value in the hash map
 * @return #GNUNET_YES if we should continue to
 *         iterate,
 *         #GNUNET_NO if not.
 */
static int
remove_routing_entry (void *cls,
                      const struct GNUNET_PeerIdentity *key,
                      void *value)
{
  struct RoutingTrail *remove_entry = value;
  const struct GNUNET_PeerIdentity *disconnected_peer = cls;
  
  if ((0 == GNUNET_CRYPTO_cmp_peer_identity (&(remove_entry->source), disconnected_peer)) ||
      (0 == GNUNET_CRYPTO_cmp_peer_identity (&(remove_entry->destination), disconnected_peer)) ||    
      (0 == GNUNET_CRYPTO_cmp_peer_identity (&(remove_entry->next_hop), disconnected_peer)) ||
      (0 == GNUNET_CRYPTO_cmp_peer_identity (&(remove_entry->prev_hop), disconnected_peer)))
  {
    GNUNET_assert (GNUNET_YES ==
                   GNUNET_CONTAINER_multipeermap_remove (routing_table,
                                                         key, 
                                                         remove_entry));
  }
  return GNUNET_YES;
}


/**
 * FIXME: add a return value. 
 * Iterate over routing table and remove all entries for which peer is a part. 
 * @param peer Peer to be searched for in the trail to remove that trail.
 */
void
GDS_ROUTING_remove_entry (const struct GNUNET_PeerIdentity *peer)
{
  GNUNET_CONTAINER_multipeermap_iterate (routing_table, &remove_routing_entry,
                                        (void *)peer);
}


/**
 * In response to trail teardown message, remove the trail with source peer, 
 * destination peer and next hop same as the argument to this function. 
 * Assumption - there can be only one possible trail with these 4 values. 
 * @param source_peer Source of the trail.
 * @param destination_peer Destination of the trail.
 * @param next_hop Next hop
 * @param prev_hop Previous hop.
 * @return #GNUNET_YES Matching trail deleted from routing table. 
 *         #GNUNET_NO No matching trail found.
 *          
 */
int
GDS_ROUTING_remove_trail (struct GNUNET_PeerIdentity *source_peer,
                          struct GNUNET_PeerIdentity *destination_peer, 
                          const struct GNUNET_PeerIdentity *prev_hop)
{
  struct RoutingTrail *trail;
  struct GNUNET_CONTAINER_MultiPeerMapIterator *iterator;
  int i;
  
  iterator = GNUNET_CONTAINER_multipeermap_iterator_create (routing_table);
  for (i = 0; i< GNUNET_CONTAINER_multipeermap_size(routing_table); i++)
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next (iterator, NULL,
                                                                 (const void **)&trail)) 
    {
      if (0 == GNUNET_CRYPTO_cmp_peer_identity (&(trail->destination), destination_peer))
      {
        GNUNET_assert (GNUNET_YES ==
                       GNUNET_CONTAINER_multipeermap_remove (routing_table,
                                                             &(trail->destination), 
                                                             trail));
        return GNUNET_YES; 
      }
    }
  }
  GNUNET_CONTAINER_multipeermap_iterator_destroy (iterator);
  return GNUNET_NO;
}



/**
 * Check if the size of routing table has crossed threshold. 
 * @return #GNUNET_YES, if threshold crossed else #GNUNET_NO.
 */
int
GDS_ROUTING_check_threshold ()
{
  return (GNUNET_CONTAINER_multipeermap_size(routing_table) > ROUTING_TABLE_THRESHOLD) ?
          GNUNET_YES:GNUNET_NO;    
}


/**
 * Initialize routing subsystem.
 */
void
GDS_ROUTING_init (void)
{ 
  routing_table = GNUNET_CONTAINER_multipeermap_create (ROUTING_TABLE_THRESHOLD * 4 / 3,
                                                        GNUNET_NO);
}

/**
 * ONLY FOR TESTING.  
 */
void 
GDS_ROUTING_print (void)
{
  struct RoutingTrail *trail;
  struct GNUNET_CONTAINER_MultiPeerMapIterator *iterator;
  int i;
  
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Routing table entries \n");
  iterator = GNUNET_CONTAINER_multipeermap_iterator_create (routing_table);
  for (i = 0; i< GNUNET_CONTAINER_multipeermap_size(routing_table); i++)
  {
    if(GNUNET_YES == GNUNET_CONTAINER_multipeermap_iterator_next (iterator, NULL,
                                                                 (const void **)&trail)) 
    {
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Routing trail source \n", GNUNET_i2s (&(trail->source)));
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Routing trail source \n", GNUNET_i2s (&(trail->destination)));
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Routing trail source \n", GNUNET_i2s (&(trail->next_hop)));
      GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "Routing trail source \n", GNUNET_i2s (&(trail->prev_hop)));
    }
  }
  
}
/**
 * FIXME: here you can have routing table with size 0, only when you delete
 * the entries correctly. Possible scenarios where we delete the entries are
 * 1. when one of my friend gets disconnected then I remove any trail (does not
 * matter if that friend is source, destination, next hop or previous hop).
 * 2. if I get a trail teardown message then I remove the entry.
 * Is there any other case that I may have missed? 
 * Shutdown routing subsystem.
 */
void
GDS_ROUTING_done (void)
{
  GNUNET_assert (0 == GNUNET_CONTAINER_multipeermap_size (routing_table));
  GNUNET_CONTAINER_multipeermap_destroy (routing_table);
}

/* end of gnunet-service-xdht_routing.c */