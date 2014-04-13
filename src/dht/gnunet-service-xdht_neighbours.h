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
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#ifndef GNUNET_SERVICE_XDHT_NEIGHBOURS_H
#define GNUNET_SERVICE_XDHT_NEIGHBOURS_H

#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"
#include "gnunet_dht_service.h"

/**
 * FIXME: Change the comment to explain about usage of this in find successor.
 * Field in trail setup message to understand if the message is sent to an
 * intermediate finger, friend or me. 
 */
enum current_destination_type
{
  FRIEND ,
  FINGER ,
  MY_ID ,
  VALUE
};

/**
 * Perform a PUT operation.  Forwards the given request to other
 * peers.   Does not store the data locally.  Does not give the
 * data to local clients.  May do nothing if this is the only
 * peer in the network (or if we are the closest peer in the
 * network).
 *
 * @param type type of the block
 * @param options routing options
 * @param desired_replication_level desired replication count
 * @param expiration_time when does the content expire
 * @param hop_count how many hops has this message traversed so far
 * @param key key for the content
 * @param put_path_length number of entries in @a put_path
 * @param put_path peers this request has traversed so far (if tracked)
 * @param data payload to store
 * @param data_size number of bytes in @a data
 */
void
GDS_NEIGHBOURS_handle_put (enum GNUNET_BLOCK_Type type,
                           enum GNUNET_DHT_RouteOption options,
                           uint32_t desired_replication_level,
                           struct GNUNET_TIME_Absolute expiration_time,
                           uint32_t hop_count,
                           const struct GNUNET_HashCode * key,
                           unsigned int put_path_length,
                           struct GNUNET_PeerIdentity *put_path,
                           const void *data, size_t data_size,
                           struct GNUNET_PeerIdentity *current_destination,
                           struct GNUNET_PeerIdentity *current_source,
                           enum current_destination_type dest_type,
                           struct GNUNET_PeerIdentity *target_peer_id);


/**
 * 
 * @param source_peer
 * @param get_path
 * @param get_path_length
 * @param key
 */
void
GDS_NEIGHBOURS_handle_get (enum GNUNET_BLOCK_Type block_type,
                           enum GNUNET_DHT_RouteOption options,
                           uint32_t desired_replication_level,
                           uint32_t hop_count,
                           struct GNUNET_PeerIdentity *get_peer_path,
                           unsigned int get_path_length,
                           struct GNUNET_HashCode *key,
                           struct GNUNET_PeerIdentity *target_peer,
                           struct GNUNET_PeerIdentity *current_destination,
                           struct GNUNET_PeerIdentity *current_source,
                           enum current_destination_type *current_dest_type);


/**
 * FIXME: I am removing source peer as the first element in the trail
 * is source identity.
 * Send get result back to requesting client. 
 * @param expiration when will the reply expire
 * @param key the query this reply is for
 * @param get_path_length number of peers in @a get_path
 * @param get_path path the reply took on get
 * @param put_path_length number of peers in @a put_path
 * @param put_path path the reply took on put
 * @param type type of the reply
 * @param data_size number of bytes in @a data
 * @param data application payload data
 * @param get_path
 * @param get_path_length
 */
void 
GDS_NEIGHBOURS_send_get_result (struct GNUNET_TIME_Absolute expiration,
                                const struct GNUNET_HashCode *key,
                                unsigned int put_path_length,
                                const struct GNUNET_PeerIdentity *put_path,
                                enum GNUNET_BLOCK_Type type, size_t data_size,
                                const void *data,
                                struct GNUNET_PeerIdentity *get_path,
                                unsigned int get_path_length,
                                unsigned int current_trail_index,
                                struct GNUNET_PeerIdentity *next_hop);

/**
 * FIXME: Here you should update the fields of struct PeerGetResultMessage.
 * At the end of this message you should add the data and get path and send 
 * to the original requesting client. and there you should call GDS_CLIENT_handle_reply
 * with correct parameter. 
 * @param expiration
 * @param key
 * @param get_path_length
 * @param get_path
 * @param put_path_length
 * @param put_path
 * @param type
 * @param data_size
 * @param data
 */
void 
GDS_NEIGHBOURS_datacache_get (struct GNUNET_TIME_Absolute expiration,
                              const struct GNUNET_HashCode *key,
                              unsigned int get_path_length,
                              const struct GNUNET_PeerIdentity *get_path,
                              unsigned int put_path_length,
                              const struct GNUNET_PeerIdentity *put_path,
                              enum GNUNET_BLOCK_Type type, size_t data_size,
                              const void *data);


/**
 * Initialize neighbours subsystem.
 *
 * @return GNUNET_OK on success, GNUNET_SYSERR on error
 */
int
GDS_NEIGHBOURS_init (void);


/**
 * Shutdown neighbours subsystem.
 */
void
GDS_NEIGHBOURS_done (void);


/**
 * Get the ID of the local node.
 *
 * @return identity of the local node
 */
struct GNUNET_PeerIdentity *
GDS_NEIGHBOURS_get_id ();


#endif