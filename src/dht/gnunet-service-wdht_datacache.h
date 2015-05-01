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
     Free Software Foundation, Inc., 59 Temple Place - Suite 330,
     Boston, MA 02111-1307, USA.
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
 * @param put_path_length number of peers in @a put_path
 * @param put_path path the reply took on put
 * @param get_path_length number of peers in @a get_path
 * @param get_path path the reply took on get
 * @param type type of the reply
 * @param data_size number of bytes in @a data
 * @param data application payload data
 */
void
GDS_DATACACHE_handle_put (struct GNUNET_TIME_Absolute expiration,
                          const struct GNUNET_HashCode *key,
                          unsigned int put_path_length,
                          const struct GNUNET_PeerIdentity *put_path,
                          unsigned int get_path_length,
                          const struct GNUNET_PeerIdentity *get_path,
                          enum GNUNET_BLOCK_Type type,
                          size_t data_size,
                          const void *data);


/**
 * Handle a GET request we've received from another peer.
 *
 * @param trail_id trail where the reply needs to be send to
 * @param options routing options (to be passed along)
 * @param key the query
 * @param type requested data type
 * @param xquery extended query
 * @param xquery_size number of bytes in @a xquery
 * @param reply_bf where the reply bf is (to be) stored, possibly updated!, can be NULL
 * @param reply_bf_mutator mutation value for @a reply_bf
 * @return evaluation result for the local replies
 *
 * FIXME: also pass options, so we know to record paths or not...
 */
enum GNUNET_BLOCK_EvaluationResult
GDS_DATACACHE_handle_get (const struct GNUNET_HashCode *trail_id,
                          enum GNUNET_DHT_RouteOption options,
                          const struct GNUNET_HashCode *key,
                          enum GNUNET_BLOCK_Type type,
                          const void *xquery,
                          size_t xquery_size,
                          struct GNUNET_CONTAINER_BloomFilter **reply_bf,
                          uint32_t reply_bf_mutator);


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
 * Handle a request for data close to a key that we have received from
 * another peer.
 *
 * @param trail_id trail where the reply needs to be send to
 * @param key the location at which the peer is looking for data that is close
 */
void
GDS_DATACACHE_get_successors (const struct GNUNET_HashCode *trail_id,
                              const struct GNUNET_HashCode *key);


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
