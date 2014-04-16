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
 * @file dht/gnunet-service-xdht_neighbours.h
 * @brief GNUnet DHT routing code
 * @author Supriti Singh
 */

#ifndef GNUNET_SERVICE_XDHT_NEIGHBOURS_H
#define GNUNET_SERVICE_XDHT_NEIGHBOURS_H

#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"
#include "gnunet_dht_service.h"


/** FIXME: by default I keep current_source, and destination as my own id.
 * in case we find a finger then we update current_source in the 
 * find_successor message. 
 * Construct a Put message and send it to target_peer. 
 * @param key Key for the content  
 * @param data Content to store
 * @param data_size Size of content @a data in bytes
 * @param block_type Type of the block
 * @param options Routing options
 * @param desired_replication_level Desired replication count
 * @param expiration_time When does the content expire
 * @param current_destination 
 * @param current_source 
 * @param target_peer Peer to which this message will be forwarded.
 * @param hop_count Number of hops traversed so far.
 * @param put_path_length Total number of peers in @a put_path
 * @param put_path Number of peers traversed so far 
 */
void
GDS_NEIGHBOURS_send_put (const struct GNUNET_HashCode *key,
                         const void *data, size_t data_size,
                         enum GNUNET_BLOCK_Type block_type,
                         enum GNUNET_DHT_RouteOption options,
                         uint32_t desired_replication_level,
                         struct GNUNET_TIME_Absolute expiration_time,
                         struct GNUNET_PeerIdentity *current_destination,
                         struct GNUNET_PeerIdentity *current_source,
                         struct GNUNET_PeerIdentity *target_peer,
                         uint32_t hop_count,
                         uint32_t put_path_length,
                         struct GNUNET_PeerIdentity *put_path);


/** FIXME: by default I keep current_source, and destination as my own id.
 * in case we find a finger then we update current_source in the 
 * find_successor message. 
 * Construct a Get message and send it to target_peer. 
 * @param key Key for the content  
 * @param data Content to store
 * @param data_size Size of content @a data in bytes
 * @param block_type Type of the block
 * @param options Routing options
 * @param desired_replication_level Desired replication count
 * @param expiration_time When does the content expire
 * @param current_destination 
 * @param current_source 
 * @param target_peer Peer to which this message will be forwarded.
 * @param hop_count Number of hops traversed so far.
 * @param put_path_length Total number of peers in @a put_path
 * @param put_path Number of peers traversed so far 
 */
void
GDS_NEIGHBOURS_send_get (const struct GNUNET_HashCode *key,
                         enum GNUNET_BLOCK_Type block_type,
                         enum GNUNET_DHT_RouteOption options,
                         uint32_t desired_replication_level,
                         struct GNUNET_PeerIdentity *current_destination,
                         struct GNUNET_PeerIdentity *current_source,
                         struct GNUNET_PeerIdentity *target_peer,
                         uint32_t hop_count,
                         uint32_t get_path_length,
                         struct GNUNET_PeerIdentity *get_path);


/**
 * Send the get result to requesting client.
 * @param expiration When will this result expire?
 * @param key Key of the requested data.
 * @param put_path_length Number of peers in @a put_path
 * @param put_path Path taken to put the data at its stored location.
 * @param type Block type
 * @param data_size Size of the @a data 
 * @param data Payload to store
 * @param get_path Path taken to reach to the location of the key.
 * @param get_path_length Number of peers in @a get_path
 * @param current_get_path_index Index in get_path
 * @param next_hop Next peer to forward the message to. 
 * @param source_peer Peer which has the data for the key.
 */
/* FIXME: Remove redundant arguments  
 * 1.remove get_path_index from message and just look up into the get path
 for your location and get the next peer. 
 * 2. Remove next_hop, source_peer */
void 
GDS_NEIGHBOURS_send_get_result (struct GNUNET_TIME_Absolute expiration,
                                const struct GNUNET_HashCode *key,
                                unsigned int put_path_length,
                                const struct GNUNET_PeerIdentity *put_path,
                                enum GNUNET_BLOCK_Type type, size_t data_size,
                                const void *data,
                                struct GNUNET_PeerIdentity *get_path,
                                unsigned int get_path_length,
                                struct GNUNET_PeerIdentity *next_hop,
                                struct GNUNET_PeerIdentity *source_peer);

/**
 * Initialize neighbours subsystem.
 *
 * @return #GNUNET_OK on success, 
 *         #GNUNET_SYSERR on error
 */
int
GDS_NEIGHBOURS_init (void);


/**
 * Shutdown neighbours subsystem.
 */
void
GDS_NEIGHBOURS_done (void);


/**
 * Get my identity
 *
 * @return my identity
 */
const struct GNUNET_PeerIdentity *
GDS_NEIGHBOURS_get_my_id (void);


#endif
