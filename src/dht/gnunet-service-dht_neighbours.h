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
 * @file dht/gnunet-service-dht_neighbours.h
 * @brief GNUnet DHT routing code
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#ifndef GNUNET_SERVICE_DHT_NEIGHBOURS_H
#define GNUNET_SERVICE_DHT_NEIGHBOURS_H


/**
 * Perform a PUT operation.
 *
 * @param type type of the block
 * @param options routing options
 * @param desired_replication_level desired replication count
 * @param expiration_time when does the content expire
 * @param key key for the content
 * @param put_path_length number of entries in put_path
 * @param put_path peers this request has traversed so far (if tracked)
 * @param data payload to store
 * @param data_size number of bytes in data
 */
void
GST_NEIGHBOURS_handle_put (uint32_t type,
			   uint32_t options,
			   uint32_t desired_replication_level,
			   GNUNET_TIME_Absolute expiration_time,
			   const GNUNET_HashCode *key,
			   unsigned int put_path_length,
			   struct GNUNET_PeerIdentity *put_path,
			   const void *data,
			   size_t data_size);


/**
 * Perform a GET operation.
 *
 *
 * @param type type of the block
 * @param options routing options
 * @param desired_replication_level desired replication count
 * @param key key for the content
 * @param xquery extended query
 * @param xquery_size number of bytes in xquery
 * @param reply_bf bloomfilter to filter duplicates
 * @param reply_bf_mutator mutator for reply_bf
 * @param peer_bf filter for peers not to select (again)
 */
void
GST_NEIGHBOURS_handle_get (uint32_t type,
			   uint32_t options,
			   uint32_t desired_replication_level,
			   const GNUNET_HashCode *key,
			   const void *xquery,
			   size_t xquery_size,
			   const struct GNUNET_CONTAINER_BloomFilter *reply_bf,
			   uint32_t reply_bf_mutator,
			   const struct GNUNET_CONTAINER_BloomFilter *peer_bf);


/**
 * Handle a reply (route to origin).
 *
 * @param type type of the block
 * @param options routing options
 * @param expiration_time when does the content expire
 * @param key key for the content
 * @param put_path_length number of entries in put_path
 * @param put_path peers the original PUT traversed (if tracked)
 * @param get_path_length number of entries in put_path
 * @param get_path peers this reply has traversed so far (if tracked)
 * @param data payload of the reply
 * @param data_size number of bytes in data
 */
void
GST_NEIGHBOURS_handle_reply (uint32_t type,
			     uint32_t options,
			     GNUNET_TIME_Absolute expiration_time,
			     const GNUNET_HashCode *key,
			     unsigned int put_path_length,
			     struct GNUNET_PeerIdentity *put_path,
			     unsigned int get_path_length,
			     struct GNUNET_PeerIdentity *get_path,
			     const void *data,
			     size_t data_size);


/**
 * Initialize neighbours subsystem.
 */
void
GST_NEIGHBOURS_init (void);

/**
 * Shutdown neighbours subsystem.
 */
void
GST_NEIGHBOURS_done (void);


#endif
