/*
     This file is part of GNUnet.
     Copyright (C) 2009-2016 GNUnet e.V.

     GNUnet is free software: you can redistribute it and/or modify it
     under the terms of the GNU Affero General Public License as published
     by the Free Software Foundation, either version 3 of the License,
     or (at your option) any later version.

     GNUnet is distributed in the hope that it will be useful, but
     WITHOUT ANY WARRANTY; without even the implied warranty of
     MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
     Affero General Public License for more details.

     You should have received a copy of the GNU Affero General Public License
     along with this program.  If not, see <http://www.gnu.org/licenses/>.

     SPDX-License-Identifier: AGPL3.0-or-later
 */

/**
 * @file dht/gnunet-service-dht.h
 * @brief GNUnet DHT globals
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_DHT_H
#define GNUNET_SERVICE_DHT_H

#include "gnunet_util_lib.h"
#include "gnunet_statistics_service.h"
#include "gnunet_transport_service.h"
#include "gnunet_block_lib.h"

#define DEBUG_DHT GNUNET_EXTRA_LOGGING

/**
 * Configuration we use.
 */
extern const struct GNUNET_CONFIGURATION_Handle *GDS_cfg;

/**
 * Handle for the service.
 */
extern struct GNUNET_SERVICE_Handle *GDS_service;

/**
 * Our handle to the BLOCK library.
 */
extern struct GNUNET_BLOCK_Context *GDS_block_context;

/**
 * Handle for the statistics service.
 */
extern struct GNUNET_STATISTICS_Handle *GDS_stats;

/**
 * Our HELLO
 */
extern struct GNUNET_MessageHeader *GDS_my_hello;



/**
 * Handle a reply we've received from another peer.  If the reply
 * matches any of our pending queries, forward it to the respective
 * client(s).
 *
 * @param expiration when will the reply expire
 * @param key the query this reply is for
 * @param get_path_length number of peers in @a get_path
 * @param get_path path the reply took on get
 * @param put_path_length number of peers in @a put_path
 * @param put_path path the reply took on put
 * @param type type of the reply
 * @param data_size number of bytes in @a data
 * @param data application payload data
 */
void
GDS_CLIENTS_handle_reply(struct GNUNET_TIME_Absolute expiration,
                         const struct GNUNET_HashCode *key,
                         unsigned int get_path_length,
                         const struct GNUNET_PeerIdentity *get_path,
                         unsigned int put_path_length,
                         const struct GNUNET_PeerIdentity *put_path,
                         enum GNUNET_BLOCK_Type type,
                         size_t data_size,
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
GDS_CLIENTS_process_get(uint32_t options,
                        enum GNUNET_BLOCK_Type type,
                        uint32_t hop_count,
                        uint32_t desired_replication_level,
                        unsigned int path_length,
                        const struct GNUNET_PeerIdentity *path,
                        const struct GNUNET_HashCode *key);


/**
 * Check if some client is monitoring GET RESP messages and notify
 * them in that case.
 *
 * @param type The type of data in the result.
 * @param get_path Peers on GET path (or NULL if not recorded).
 * @param get_path_length number of entries in @a get_path.
 * @param put_path peers on the PUT path (or NULL if not recorded).
 * @param put_path_length number of entries in @a get_path.
 * @param exp Expiration time of the data.
 * @param key Key of the @a data.
 * @param data Pointer to the result data.
 * @param size Number of bytes in @a data.
 */
void
GDS_CLIENTS_process_get_resp(enum GNUNET_BLOCK_Type type,
                             const struct GNUNET_PeerIdentity *get_path,
                             unsigned int get_path_length,
                             const struct GNUNET_PeerIdentity *put_path,
                             unsigned int put_path_length,
                             struct GNUNET_TIME_Absolute exp,
                             const struct GNUNET_HashCode * key,
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
GDS_CLIENTS_process_put(uint32_t options,
                        enum GNUNET_BLOCK_Type type,
                        uint32_t hop_count,
                        uint32_t desired_replication_level,
                        unsigned int path_length,
                        const struct GNUNET_PeerIdentity *path,
                        struct GNUNET_TIME_Absolute exp,
                        const struct GNUNET_HashCode *key,
                        const void *data,
                        size_t size);

#endif
