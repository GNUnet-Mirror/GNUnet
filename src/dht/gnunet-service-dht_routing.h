/*
     This file is part of GNUnet.
     Copyright (C) 2011 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.
*/

/**
 * @file dht/gnunet-service-dht_routing.h
 * @brief GNUnet DHT tracking of requests for routing replies
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_DHT_ROUTING_H
#define GNUNET_SERVICE_DHT_ROUTING_H

#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"
#include "gnunet_dht_service.h"


/**
 * Handle a reply (route to origin).  Only forwards the reply back to
 * other peers waiting for it.  Does not do local caching or
 * forwarding to local clients.  Essentially calls
 * #GDS_NEIGHBOURS_handle_reply() for all peers that sent us a matching
 * request recently.
 *
 * @param type type of the block
 * @param expiration_time when does the content expire
 * @param key key for the content
 * @param put_path_length number of entries in @a put_path
 * @param put_path peers the original PUT traversed (if tracked)
 * @param get_path_length number of entries in @a get_path
 * @param get_path peers this reply has traversed so far (if tracked)
 * @param data payload of the reply
 * @param data_size number of bytes in @a data
 */
void
GDS_ROUTING_process (enum GNUNET_BLOCK_Type type,
                     struct GNUNET_TIME_Absolute expiration_time,
                     const struct GNUNET_HashCode *key,
                     unsigned int put_path_length,
                     const struct GNUNET_PeerIdentity *put_path,
                     unsigned int get_path_length,
                     const struct GNUNET_PeerIdentity *get_path,
                     const void *data,
                     size_t data_size);


/**
 * Add a new entry to our routing table.
 *
 * @param sender peer that originated the request
 * @param type type of the block
 * @param bg block group to evaluate replies, henceforth owned by routing
 * @param options options for processing
 * @param key key for the content
 * @param xquery extended query
 * @param xquery_size number of bytes in @a xquery
 */
void
GDS_ROUTING_add (const struct GNUNET_PeerIdentity *sender,
                 enum GNUNET_BLOCK_Type type,
                 struct GNUNET_BLOCK_Group *bg,
                 enum GNUNET_DHT_RouteOption options,
                 const struct GNUNET_HashCode * key,
                 const void *xquery,
                 size_t xquery_size);


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
