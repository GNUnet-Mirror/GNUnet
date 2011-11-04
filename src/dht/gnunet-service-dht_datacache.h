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
 * @file dht/gnunet-service-dht_datacache.h
 * @brief GNUnet DHT service's datacache integration
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#ifndef GNUNET_SERVICE_DHT_DATACACHE_H
#define GNUNET_SERVICE_DHT_DATACACHE_H

#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"

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
                          const GNUNET_HashCode * key,
                          unsigned int put_path_length,
                          const struct GNUNET_PeerIdentity *put_path,
                          enum GNUNET_BLOCK_Type type, size_t data_size,
                          const void *data);


/**
 * Handle a GET request we've received from another peer.
 *
 * @param key the query
 * @param type requested data type
 * @param xquery extended query
 * @param xquery_size number of bytes in xquery
 * @param reply_bf where the reply bf is (to be) stored, possibly updated!, can be NULL
 * @param reply_bf_mutator mutation value for reply_bf
 * @return evaluation result for the local replies
 */
enum GNUNET_BLOCK_EvaluationResult
GDS_DATACACHE_handle_get (const GNUNET_HashCode * key,
                          enum GNUNET_BLOCK_Type type, const void *xquery,
                          size_t xquery_size,
                          struct GNUNET_CONTAINER_BloomFilter **reply_bf,
                          uint32_t reply_bf_mutator);


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
