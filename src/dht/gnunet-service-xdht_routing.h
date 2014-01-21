/*
     This file is part of GNUnet.
     (C) 2011 Christian Grothoff (and other contributing authors)

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
 * @file dht/gnunet-service-xdht_routing.h
 * @brief GNUnet DHT tracking of requests for routing replies
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_XDHT_ROUTING_H
#define GNUNET_SERVICE_XDHT_ROUTING_H

#include "gnunet_util_lib.h"
#include "gnunet_block_lib.h"
#include "gnunet_dht_service.h"


/**
 * Add a new entry to our routing table.
 *
 * @param sender peer that originated the request
 * @param type type of the block
 * @param options options for processing
 * @param key key for the content
 * @param xquery extended query
 * @param xquery_size number of bytes in @a xquery
 * @param reply_bf bloomfilter to filter duplicates
 * @param reply_bf_mutator mutator for @a reply_bf
*/
void
GDS_ROUTING_add (const struct GNUNET_PeerIdentity *sender,
                 enum GNUNET_BLOCK_Type type,
                 enum GNUNET_DHT_RouteOption options,
                 const struct GNUNET_HashCode * key, const void *xquery,
                 size_t xquery_size,
                 const struct GNUNET_CONTAINER_BloomFilter *reply_bf,
                 uint32_t reply_bf_mutator);



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
