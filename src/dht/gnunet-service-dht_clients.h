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
 * @file dht/gnunet-service-dht_clients.h
 * @brief GNUnet DHT service's client management code
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#ifndef GNUNET_SERVICE_DHT_CLIENT_H
#define GNUNET_SERVICE_DHT_CLIENT_H

#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"

/**
 * Handle a reply we've received from another peer.  If the reply
 * matches any of our pending queries, forward it to the respective
 * client(s).
 *
 * @param expiration when will the reply expire
 * @param key the query this reply is for
 * @param get_path_length number of peers in 'get_path'
 * @param get_path path the reply took on get
 * @param put_path_length number of peers in 'put_path'
 * @param put_path path the reply took on put
 * @param type type of the reply
 * @param data_size number of bytes in 'data'
 * @param data application payload data
 */
void
GDS_CLIENTS_handle_reply (struct GNUNET_TIME_Absolute expiration,
                          const GNUNET_HashCode * key,
                          unsigned int get_path_length,
                          const struct GNUNET_PeerIdentity *get_path,
                          unsigned int put_path_length,
                          const struct GNUNET_PeerIdentity *put_path,
                          enum GNUNET_BLOCK_Type type, size_t data_size,
                          const void *data);


/**
 * Check if some client is monitoring GET messages and notify
 * them in that case.
 *
 * @param options Options, for instance RecordRoute, DemultiplexEverywhere.
 * @param type The type of data in the request.
 * @param hop_count Hop count so far.
 * @param path_length number of entries in path (or 0 if not recorded).
 * @param path peers on the GET path (or NULL if not recorded).
 * @param desired_replication_level Desired replication level.
 * @param key Key of the requested data.
 */
void
GDS_CLIENTS_process_get (uint32_t options,
                         enum GNUNET_BLOCK_Type type,
                         uint32_t hop_count,
                         uint32_t desired_replication_level, 
                         unsigned int path_length,
                         const struct GNUNET_PeerIdentity *path,
                         const GNUNET_HashCode * key);

/**
 * Check if some client is monitoring GET RESP messages and notify
 * them in that case.
 *
 * @param type The type of data in the result.
 * @param get_path Peers on GET path (or NULL if not recorded).
 * @param get_path_length number of entries in get_path.
 * @param put_path peers on the PUT path (or NULL if not recorded).
 * @param put_path_length number of entries in get_path.
 * @param exp Expiration time of the data.
 * @param key Key of the data.
 * @param data Pointer to the result data.
 * @param size Number of bytes in data.
 */
void
GDS_CLIENTS_process_get_resp (enum GNUNET_BLOCK_Type type,
                              const struct GNUNET_PeerIdentity *get_path,
                              unsigned int get_path_length,
                              const struct GNUNET_PeerIdentity *put_path,
                              unsigned int put_path_length,
                              struct GNUNET_TIME_Absolute exp,
                              const GNUNET_HashCode * key,
                              const void *data,
                              size_t size);

/**
 * Check if some client is monitoring PUT messages and notify
 * them in that case.
 *
 * @param options Options, for instance RecordRoute, DemultiplexEverywhere.
 * @param type The type of data in the request.
 * @param hop_count Hop count so far.
 * @param path_length number of entries in path (or 0 if not recorded).
 * @param path peers on the PUT path (or NULL if not recorded).
 * @param desired_replication_level Desired replication level.
 * @param exp Expiration time of the data.
 * @param key Key under which data is to be stored.
 * @param data Pointer to the data carried.
 * @param size Number of bytes in data.
 */
void
GDS_CLIENTS_process_put (uint32_t options,
                         enum GNUNET_BLOCK_Type type,
                         uint32_t hop_count,
                         uint32_t desired_replication_level, 
                         unsigned int path_length,
                         const struct GNUNET_PeerIdentity *path,
                         struct GNUNET_TIME_Absolute exp,
                         const GNUNET_HashCode * key,
                         const void *data,
                         size_t size);

/**
 * Initialize client subsystem.
 *
 * @param server the initialized server
 */
void
GDS_CLIENTS_init (struct GNUNET_SERVER_Handle *server);


/**
 * Shutdown client subsystem.
 */
void
GDS_CLIENTS_done (void);

#endif
