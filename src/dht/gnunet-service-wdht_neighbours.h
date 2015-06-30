/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011, 2015 Christian Grothoff (and other contributing authors)

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
     Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
     Boston, MA 02110-1301, USA.
*/

/**
 * @file dht/gnunet-service-wdht_neighbours.h
 * @brief GNUnet DHT routing code
 * @author Supriti Singh
 */

#ifndef GNUNET_SERVICE_WDHT_NEIGHBOURS_H
#define GNUNET_SERVICE_WDHT_NEIGHBOURS_H

#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"
#include "gnunet_dht_service.h"


/**
 * Handle the put request from the client.
 *
 * @param key Key for the content
 * @param block_type Type of the block
 * @param options Routing options
 * @param desired_replication_level Desired replication count
 * @param expiration_time When does the content expire
 * @param data Content to store
 * @param data_size Size of content @a data in bytes
 */
void
GDS_NEIGHBOURS_handle_put (const struct GNUNET_HashCode *key,
                           enum GNUNET_BLOCK_Type block_type,
                           enum GNUNET_DHT_RouteOption options,
                           uint32_t desired_replication_level,
                           struct GNUNET_TIME_Absolute expiration_time,
                           const void *data, size_t data_size);

/**
 * Handle the get request from the client file. If I am destination do
 * datacache put and return. Else find the target friend and forward message
 * to it.
 *
 * @param key Key for the content
 * @param block_type Type of the block
 * @param options Routing options
 * @param desired_replication_level Desired replication count
 */
void
GDS_NEIGHBOURS_handle_get (const struct GNUNET_HashCode *key,
                           enum GNUNET_BLOCK_Type block_type,
                           enum GNUNET_DHT_RouteOption options,
                           uint32_t desired_replication_level);


/**
 * Send the get result to requesting client.
 *
 * @param trail_id trail identifying where to send the result to, NULL for us
 * @param options routing options (from GET request)
 * @param key key of the requested data.
 * @param type block type
 * @param put_path_length number of peers in @a put_path
 * @param put_path path taken to put the data at its stored location.
 * @param expiration when will this result expire?
 * @param data payload to store
 * @param data_size size of the @a data
 */
void
GDS_NEIGHBOURS_send_get_result (const struct GNUNET_HashCode *trail_id,
                                enum GNUNET_DHT_RouteOption options,
                                const struct GNUNET_HashCode *key,
                                enum GNUNET_BLOCK_Type type,
                                unsigned int put_path_length,
                                const struct GNUNET_PeerIdentity *put_path,
                                struct GNUNET_TIME_Absolute expiration,
                                const void *data, size_t data_size);


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
struct GNUNET_PeerIdentity
GDS_NEIGHBOURS_get_my_id (void);

#endif
