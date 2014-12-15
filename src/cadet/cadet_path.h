/*
     This file is part of GNUnet.
     (C) 2001 - 2013 Christian Grothoff (and other contributing authors)

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
 * @file cadet/cadet_path.h
 * @brief Path handling functions
 * @author Bartlomiej Polot
 */

#ifndef CADET_PATH_H_
#define CADET_PATH_H_

#ifdef __cplusplus
extern "C"
{
  #if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "gnunet-service-cadet_connection.h"


/******************************************************************************/
/************************      DATA STRUCTURES     ****************************/
/******************************************************************************/

/**
 * Information regarding a possible path to reach a single peer
 */
struct CadetPeerPath
{

    /**
     * Linked list
     */
  struct CadetPeerPath *next;
  struct CadetPeerPath *prev;

    /**
     * List of all the peers that form the path from origin to target.
     */
  GNUNET_PEER_Id *peers;

    /**
     * Number of peers (hops) in the path
     */
  unsigned int length;

    /**
     * User defined data store.
     */
  struct CadetConnection *c;

    /**
     * Path's score, how reliable is the path.
     */
//   int score;

  /**
   * Task to delete the path.
   * We tried it, it didn't work, don't try again in a while.
   */
  GNUNET_SCHEDULER_TaskIdentifier path_delete;

};

/******************************************************************************/
/*************************        FUNCTIONS       *****************************/
/******************************************************************************/

/**
 * Create a new path.
 *
 * @param length How many hops will the path have.
 *
 * @return A newly allocated path with a peer array of the specified length.
 */
struct CadetPeerPath *
path_new (unsigned int length);


/**
 * Invert the path.
 *
 * @param path The path to invert.
 */
void
path_invert (struct CadetPeerPath *path);


/**
 * Duplicate a path, incrementing short peer's rc.
 *
 * @param path The path to duplicate.
 */
struct CadetPeerPath *
path_duplicate (const struct CadetPeerPath *path);


/**
 * Get the length of a path.
 *
 * @param path The path to measure, with the local peer at any point of it.
 *
 * @return Number of hops to reach destination.
 *         UINT_MAX in case the peer is not in the path.
 */
unsigned int
path_get_length (struct CadetPeerPath *path);

/**
 * Mark path as invalid: keep it aroud for a while to avoid trying it in a loop.
 *
 * DHT_get sometimes returns bad cached results, for instance, on a locally
 * cached result where the PUT followed a path that is no longer current.
 *
 * @param p Path to invalidate.
 */
void
path_invalidate (struct CadetPeerPath *p);

/**
 * Test if two paths are equivalent (equal or revese of each other).
 *
 * @param p1 First path
 * @param p2 Second path
 *
 * @return GNUNET_YES if both paths are equivalent
 *         GNUNET_NO otherwise
 */
int
path_equivalent (const struct CadetPeerPath *p1,
                 const struct CadetPeerPath *p2);

/**
 * Test if a path is valid (or at least not known to be invalid).
 *
 * @param path Path to test.
 *
 * @return #GNUNET_YES If the path is valid or unknown,
 *         #GNUNET_NO If the path is known to be invalid.
 */
int
path_is_valid (const struct CadetPeerPath *path);

/**
 * Destroy the path and free any allocated resources linked to it
 *
 * @param p the path to destroy
 *
 * @return GNUNET_OK on success
 */
int
path_destroy (struct CadetPeerPath *p);

/**
 * Builds a path from a PeerIdentity array.
 *
 * @param peers PeerIdentity array.
 * @param size Size of the @c peers array.
 * @param myid ID of local peer, to find @c own_pos.
 * @param own_pos Output parameter: own position in the path.
 *
 * @return Fixed and shortened path.
 */
struct CadetPeerPath *
path_build_from_peer_ids (struct GNUNET_PeerIdentity *peers,
                          unsigned int size,
                          GNUNET_PEER_Id myid,
                          unsigned int *own_pos);

/**
 * Path -> allocated one line string. Caller must free.
 *
 * @param p Path.
 */
char *
path_2s (struct CadetPeerPath *p);

/**
 * Print info about the path for debug.
 *
 * @param p Path to debug.
 */
void
path_debug (struct CadetPeerPath *p);

#if 0                           /* keep Emacsens' auto-indent happy */
{
  #endif
  #ifdef __cplusplus
}
#endif


/* ifndef CADET_PATH_H */
#endif
