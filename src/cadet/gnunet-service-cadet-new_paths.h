
/*
     This file is part of GNUnet.
     Copyright (C) 2001-2017 GNUnet e.V.

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
 * @file cadet/gnunet-service-cadet-new_paths.h
 * @brief Information we track per path.
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 */
#ifndef GNUNET_SERVICE_CADET_PATHS_H
#define GNUNET_SERVICE_CADET_PATHS_H

#include "gnunet_util_lib.h"
#include "gnunet-service-cadet-new.h"

/**
 * Create a peer path based on the result of a DHT lookup.  If we
 * already know this path, or one that is longer, simply return NULL.
 * Otherwise, we try to extend an existing path, or create a new one
 * if applicable.
 *
 * @param get_path path of the get request
 * @param get_path_length lenght of @a get_path
 * @param put_path path of the put request
 * @param put_path_length length of the @a put_path
 */
void
GCPP_try_path_from_dht (const struct GNUNET_PeerIdentity *get_path,
                        unsigned int get_path_length,
                        const struct GNUNET_PeerIdentity *put_path,
                        unsigned int put_path_length);


/**
 * We got an incoming connection, obtain the corresponding path.
 *
 * @param path_length number of segments on the @a path
 * @param path through the network, in reverse order (we are at the end!)
 * @return corresponding path object
 */
struct CadetPeerPath *
GCPP_get_path_from_route (unsigned int path_length,
                          const struct GNUNET_PeerIdentity *pids);


/**
 * Return the length of the path.  Excludes one end of the
 * path, so the loopback path has length 0.
 *
 * @param path path to return the length for
 * @return number of peers on the path
 */
unsigned int
GCPP_get_length (struct CadetPeerPath *path);


/**
 * Return connection to @a destination using @a path, or return
 * NULL if no such connection exists.
 *
 * @param path path to traverse
 * @param destination destination node to get to, must be on path
 * @param off offset of @a destination on @a path
 * @return NULL if we have no existing connection
 *         otherwise connection from us to @a destination via @a path
 */
struct CadetConnection *
GCPP_get_connection (struct CadetPeerPath *path,
                     struct CadetPeer *destination,
                     unsigned int off);


/**
 * Notify @a path that it is used for connection @a cc
 * which ends at the path's offset @a off.
 *
 * @param path the path to remember the @a cc
 * @param off the offset where the @a cc ends
 * @param cc the connection to remember
 */
void
GCPP_add_connection (struct CadetPeerPath *path,
                     unsigned int off,
                     struct CadetConnection *cc);


/**
 * Notify @a path that it is no longer used for connection @a cc which
 * ended at the path's offset @a off.
 *
 * @param path the path to forget the @a cc
 * @param off the offset where the @a cc ended
 * @param cc the connection to forget
 */
void
GCPP_del_connection (struct CadetPeerPath *path,
                     unsigned int off,
                     struct CadetConnection *cc);


/**
 * Find peer's offset on path.
 *
 * @param path path to search
 * @param cp peer to look for
 * @return offset of @a cp on @a path, or UINT_MAX if not found
 */
unsigned int
GCPP_find_peer (struct CadetPeerPath *path,
                struct CadetPeer *cp);


/**
 * Return how much we like keeping the path.  This is an aggregate
 * score based on various factors, including the age of the path
 * (older == better), and the value of this path to all of its ajacent
 * peers.  For example, long paths that end at a peer that we have no
 * shorter way to reach are very desirable, while long paths that end
 * at a peer for which we have a shorter way as well are much less
 * desirable.  Higher values indicate more valuable paths.  The
 * returned value should be used to decide which paths to remember.
 *
 * @param path path to return the length for
 * @return desirability of the path, larger is more desirable
 */
GNUNET_CONTAINER_HeapCostType
GCPP_get_desirability (const struct CadetPeerPath *path);


/**
 * The given peer @a cp used to own this @a path.  However, it is no
 * longer interested in maintaining it, so the path should be
 * discarded or shortened (in case a previous peer on the path finds
 * the path desirable).
 *
 * @param path the path that is being released
 */
void
GCPP_release (struct CadetPeerPath *path);


/**
 * Obtain the peer at offset @a off in @a path.
 *
 * @param path peer path to inspect
 * @param off offset to return, must be smaller than path length
 * @return peer at offset @a off
 */
struct CadetPeer *
GCPP_get_peer_at_offset (struct CadetPeerPath *path,
                         unsigned int off);


#endif
