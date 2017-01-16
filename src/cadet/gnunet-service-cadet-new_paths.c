
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
 * @file cadet/gnunet-service-cadet-new_paths.c
 * @brief Information we track per path.
 * @author Bartlomiej Polot
 * @author Christian Grothoff
 */
#include "platform.h"
#include "gnunet-service-cadet-new_peer.h"
#include "gnunet-service-cadet-new_paths.h"


/**
 * Information regarding a possible path to reach a peer.
 */
struct CadetPeerPath
{

  /**
   * Array of all the peers on the path.  If @e hn is non-NULL, the
   * last one is our owner.
   */
  struct CadetPeerPathEntry *entries;

  /**
   * Node of this path in the owner's heap.  Used to update our position
   * in the heap whenever our @e desirability changes.
   */
  struct GNUNET_CONTAINER_HeapNode *hn;

  /**
   * Connections using this path, by destination peer
   * (each hop of the path could correspond to an
   * active connection).
   */
  struct GNUNET_CONTAINER_MultiPeerMap *connections;

  /**
   * Desirability of the path. How unique is it for the various peers
   * on it?
   */
  GNUNET_CONTAINER_HeapCostType desirability;

  /**
   * Length of the @e entries array.
   */
  unsigned int entries_length;

};



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
GCPP_get_desirability (const struct CadetPeerPath *path)
{
  GNUNET_assert (0);
  return 0;
}


/**
 * The given peer @a cp used to own this @a path.  However, it is no
 * longer interested in maintaining it, so the path should be
 * discarded or shortened (in case a previous peer on the path finds
 * the path desirable).
 *
 * @param path the path that is being released
 * @param cp original final destination of @a path
 * @param node entry in the heap of @a cp where this path is anchored
 *             should be used for updates to the desirability of this path
 */
void
GCPP_acquire (struct CadetPeerPath *path,
              struct CadetPeer *cp,
              struct GNUNET_CONTAINER_HeapNode *node)
{
  GNUNET_assert (0);
}


/**
 * The owning peer of this path is no longer interested in maintaining
 * it, so the path should be discarded or shortened (in case a
 * previous peer on the path finds the path desirable).
 *
 * @param path the path that is being released
 */
void
GCPP_release (struct CadetPeerPath *path)
{
  GNUNET_assert (0);
}


/**
 * Updates the score for an entry on the path based
 * on our experiences with using @a path.
 *
 * @param path the path to update
 * @param off offset of the entry to update
 * @param delta change in the score to apply
 */
void
GCPP_update_score (struct CadetPeerPath *path,
                   unsigned int off,
                   int delta)
{
  struct CadetPeerPathEntry *entry;

  GNUNET_assert (off < path->entries_length);
  entry = &path->entries[off];

  /* Add delta, with checks for overflows */
  if (delta >= 0)
  {
    if (delta + entry->score < entry->score)
      entry->score = INT_MAX;
    else
      entry->score += delta;
  }
  else
  {
    if (delta + entry->score > entry->score)
      entry->score = INT_MIN;
    else
      entry->score += delta;
  }

  /* FIXME: update path desirability! */
}


/**
 * Create a peer path based on the result of a DHT lookup.
 *
 * @param get_path path of the get request
 * @param get_path_length lenght of @a get_path
 * @param put_path path of the put request
 * @param put_path_length length of the @a put_path
 * @return a path through the network
 */
struct CadetPeerPath *
GCPP_path_from_dht (const struct GNUNET_PeerIdentity *get_path,
                    unsigned int get_path_length,
                    const struct GNUNET_PeerIdentity *put_path,
                    unsigned int put_path_length)
{
  struct CadetPeerPath *path;

  path = GNUNET_new (struct CadetPeerPath);
  path->entries_length = get_path_length + put_path_length;
  path->entries = GNUNET_new_array (path->entries_length,
                                    struct CadetPeerPathEntry);
  for (unsigned int i=0;i<get_path_length + put_path_length;i++)
  {
    struct CadetPeerPathEntry *entry = &path->entries[i];
    const struct GNUNET_PeerIdentity *pid;

    pid = (i < get_path_length) ? &get_path[get_path_length - i] : &put_path[path->entries_length - i];
    entry->peer = GCP_get (pid,
                           GNUNET_YES);
    entry->path = path;
    GCP_path_entry_add (entry->peer,
                        entry,
                        i);
  }
  GNUNET_break (0);
  return NULL;
}


/**
 * Destroy a path, we no longer need it.
 *
 * @param p path to destroy.
 */
void
GCPP_path_destroy (struct CadetPeerPath *p)
{
  GNUNET_assert (0);
}


/**
 * Return the length of the path.  Excludes one end of the
 * path, so the loopback path has length 0.
 *
 * @param path path to return the length for
 * @return number of peers on the path
 */
unsigned int
GCPP_get_length (struct CadetPeerPath *path)
{
  GNUNET_assert (0);
  return -1;
}


/**
 * Obtain the identity of the peer at offset @a off in @a path.
 *
 * @param path peer path to inspect
 * @param off offset to return, must be smaller than path length
 * @param[out] pid where to write the pid, must not be NULL
 */
void
GCPP_get_pid_at_offset (struct CadetPeerPath *path,
                        unsigned int off,
                        struct GNUNET_PeerIdentity *pid)
{
  GNUNET_assert (0);
}


/* end of gnunet-service-cadet-new_paths.c */
