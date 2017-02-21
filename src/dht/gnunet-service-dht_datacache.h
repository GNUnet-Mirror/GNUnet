/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011 GNUnet e.V.

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
 * @file dht/gnunet-service-dht_datacache.h
 * @brief GNUnet DHT service's datacache integration
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#ifndef GNUNET_SERVICE_DHT_DATACACHE_H
#define GNUNET_SERVICE_DHT_DATACACHE_H

#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"
#include "gnunet_dht_service.h"

/**
 * Handle a datum we've received from another peer.  Cache if
 * possible.
 *
 * @param expiration when will the reply expire
 * @param key the query this reply is for
 * @param put_path_length number of peers in 'put_path'
 * @param put_path path the reply took on put
 * @param type type of the reply
 * @param data_size number of bytes in 'data'
 * @param data application payload data
 */
void
GDS_DATACACHE_handle_put (struct GNUNET_TIME_Absolute expiration,
                          const struct GNUNET_HashCode *key,
                          unsigned int put_path_length,
                          const struct GNUNET_PeerIdentity *put_path,
                          enum GNUNET_BLOCK_Type type,
                          size_t data_size,
                          const void *data);


/**
 * Handle a result for a GET operation.
 *
 * @param cls closure
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
typedef void
(*GDS_DATACACHE_GetCallback)(void *cls,
                             enum GNUNET_BLOCK_Type type,
                             struct GNUNET_TIME_Absolute expiration_time,
                             const struct GNUNET_HashCode *key,
                             unsigned int put_path_length,
                             const struct GNUNET_PeerIdentity *put_path,
                             unsigned int get_path_length,
                             const struct GNUNET_PeerIdentity *get_path,
                             const void *data,
                             size_t data_size);


/**
 * Handle a GET request we've received from another peer.
 *
 * @param key the query
 * @param type requested data type
 * @param xquery extended query
 * @param xquery_size number of bytes in xquery
 * @param bg block group to use for evaluation of replies
 * @param gc function to call on the results
 * @param gc_cls closure for @a gc
 * @return evaluation result for the local replies
 */
enum GNUNET_BLOCK_EvaluationResult
GDS_DATACACHE_handle_get (const struct GNUNET_HashCode *key,
                          enum GNUNET_BLOCK_Type type,
                          const void *xquery,
                          size_t xquery_size,
                          struct GNUNET_BLOCK_Group *bg,
                          GDS_DATACACHE_GetCallback gc,
                          void *gc_cls);


/**
 * Obtain a random key from the datacache.
 * Used by Whanau for load-balancing.
 *
 * @param[out] key where to store the key of a random element,
 *             randomized by PRNG if datacache is empty
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the datacache is empty
 */
int
GDS_DATACACHE_get_random_key (struct GNUNET_HashCode *key);


/**
 * Send the get result to requesting client.
 *
 * @param cls closure
 * @param options routing options (from GET request)
 * @param key key of the requested data.
 * @param type block type
 * @param put_path_length number of peers in @a put_path
 * @param put_path path taken to put the data at its stored location.
 * @param expiration when will this result expire?
 * @param data payload to store
 * @param data_size size of the @a data
 */
typedef void
(*GDS_DATACACHE_SuccessorCallback)(void *cls,
                                   enum GNUNET_DHT_RouteOption options,
                                   const struct GNUNET_HashCode *key,
                                   enum GNUNET_BLOCK_Type type,
                                   unsigned int put_path_length,
                                   const struct GNUNET_PeerIdentity *put_path,
                                   struct GNUNET_TIME_Absolute expiration,
                                   const void *data,
                                   size_t data_size);


/**
 * Handle a request for data close to a key that we have received from
 * another peer.
 *
 * @param key the location at which the peer is looking for data that is close
 * @param cb function to call with the result
 * @param cb_cls closure for @a cb
 */
void
GDS_DATACACHE_get_successors (const struct GNUNET_HashCode *key,
                              GDS_DATACACHE_SuccessorCallback cb,
                              void *cb_cls);


/**
 * Initialize datacache subsystem.
 */
void
GDS_DATACACHE_init (void);


/**
 * Shutdown datacache subsystem.
 */
void
GDS_DATACACHE_done (void);

#endif
