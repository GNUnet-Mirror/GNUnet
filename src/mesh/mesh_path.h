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
 * @file mesh/mesh_path.h
 * @brief Path handling functions
 * @author Bartlomiej Polot
 */

#ifndef MESH_PATH_H_
#define MESH_PATH_H_

#ifdef __cplusplus
extern "C"
{
  #if 0                           /* keep Emacsens' auto-indent happy */
}
#endif
#endif

/******************************************************************************/
/************************      DATA STRUCTURES     ****************************/
/******************************************************************************/

/**
 * Information regarding a possible path to reach a single peer
 */
struct MeshPeerPath
{

    /**
     * Linked list
     */
  struct MeshPeerPath *next;
  struct MeshPeerPath *prev;

    /**
     * List of all the peers that form the path from origin to target.
     */
  GNUNET_PEER_Id *peers;

    /**
     * Number of peers (hops) in the path
     */
  unsigned int length;

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
struct MeshPeerPath *
path_new (unsigned int length);


/**
 * Invert the path.
 *
 * @param path The path to invert.
 */
void
path_invert (struct MeshPeerPath *path);


/**
 * Duplicate a path, incrementing short peer's rc.
 *
 * @param path The path to duplicate.
 */
struct MeshPeerPath *
path_duplicate (const struct MeshPeerPath *path);


/**
 * Get the length of a path.
 *
 * @param path The path to measure, with the local peer at any point of it.
 *
 * @return Number of hops to reach destination.
 *         UINT_MAX in case the peer is not in the path.
 */
unsigned int
path_get_length (struct MeshPeerPath *path);

/**
 * Mark path as invalid: keep it aroud for a while to avoid trying it in a loop.
 *
 * DHT_get sometimes returns bad cached results, for instance, on a locally
 * cached result where the PUT followed a path that is no longer current.
 *
 * @param p Path to invalidate.
 */
void
path_invalidate (struct MeshPeerPath *p);

/**
 * Test if a path is valid (or at least not known to be invalid).
 *
 * @param path Path to test.
 *
 * @return #GNUNET_YES If the path is valid or unknown,
 *         #GNUNET_NO If the path is known to be invalid.
 */
int
path_is_valid (const struct MeshPeerPath *path);

/**
 * Destroy the path and free any allocated resources linked to it
 *
 * @param p the path to destroy
 *
 * @return GNUNET_OK on success
 */
int
path_destroy (struct MeshPeerPath *p);

/**
 * Path -> allocated one line string. Caller must free.
 *
 * @param p Path.
 */
char *
path_2s (struct MeshPeerPath *p);

/**
 * Print info about the path for debug.
 *
 * @param p Path to debug.
 */
void
path_debug (struct MeshPeerPath *p);

#if 0                           /* keep Emacsens' auto-indent happy */
{
  #endif
  #ifdef __cplusplus
}
#endif


/* ifndef MESH_PATH_H */
#endif
