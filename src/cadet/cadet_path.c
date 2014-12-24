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
 * @file cadet/cadet_path.c
 * @brief Path handling functions
 * @author Bartlomiej Polot
 */

#include "cadet.h"
#include "cadet_path.h"
#include "gnunet-service-cadet_peer.h"

#define LOG(level, ...) GNUNET_log_from (level,"cadet-pth",__VA_ARGS__)


/**
 * @brief Destroy a path after some time has past.
 *
 * If the path is returned from DHT again after a while, try again.
 *
 * Removes the path from the peer (except for direct paths).
 *
 * @param cls Closure (path to destroy).
 * @param tc Task context.
 */
static void
path_destroy_delayed (void *cls, const struct GNUNET_SCHEDULER_TaskContext *tc)
{
  struct CadetPeerPath *path = cls;
  struct CadetPeer *peer;

  LOG (GNUNET_ERROR_TYPE_INFO, "Destroy delayed %p (%u)\n", path, path->length);
  path->path_delete = NULL;
  peer = GCP_get_short (path->peers[path->length - 1]);
  if (2 < path->length)
    GCP_remove_path (peer, path);
  else
    path_destroy (path);
}


/**
 * Create a new path
 *
 * @param length How many hops will the path have.
 *
 * @return A newly allocated path with a peer array of the specified length.
 */
struct CadetPeerPath *
path_new (unsigned int length)
{
  struct CadetPeerPath *p;

  p = GNUNET_new (struct CadetPeerPath);
  if (length > 0)
  {
    p->length = length;
    p->peers = GNUNET_malloc (length * sizeof (GNUNET_PEER_Id));
  }
  return p;
}


/**
 * Invert the path
 *
 * @param path the path to invert
 */
void
path_invert (struct CadetPeerPath *path)
{
  GNUNET_PEER_Id aux;
  unsigned int i;

  for (i = 0; i < path->length / 2; i++)
  {
    aux = path->peers[i];
    path->peers[i] = path->peers[path->length - i - 1];
    path->peers[path->length - i - 1] = aux;
  }
}


/**
 * Duplicate a path, incrementing short peer's rc.
 *
 * @param path The path to duplicate.
 */
struct CadetPeerPath *
path_duplicate (const struct CadetPeerPath *path)
{
  struct CadetPeerPath *aux;
  unsigned int i;

  aux = path_new (path->length);
  memcpy (aux->peers, path->peers, path->length * sizeof (GNUNET_PEER_Id));
  for (i = 0; i < aux->length; i++)
    GNUNET_PEER_change_rc (aux->peers[i], 1);
  return aux;
}


/**
 * Get the length of a path.
 *
 * @param path The path to measure, with the local peer at any point of it.
 *
 * @return Number of hops to reach destination.
 *         UINT_MAX in case the peer is not in the path.
 */
unsigned int
path_get_length (struct CadetPeerPath *path)
{
  if (NULL == path)
    return UINT_MAX;
  return path->length;
}



/**
 * Mark path as invalid: keep it aroud for a while to avoid trying it in a loop.
 *
 * Never invalidates a two-hop (direct) path, only a core handler can do that.
 *
 * Rationale: DHT_get sometimes returns bad cached results, for instance,
 * on a locally cached result where the PUT followed a path that is no longer
 * current. The path must remain "known and marked as invalid" for a while.
 *
 * @param p Path to invalidate.
 */
void
path_invalidate (struct CadetPeerPath *p)
{
  if (NULL != p->path_delete)
    return;

  LOG (GNUNET_ERROR_TYPE_INFO, "Invalidating path %p (%u)\n", p, p->length);
  p->path_delete = GNUNET_SCHEDULER_add_delayed (GNUNET_TIME_UNIT_MINUTES,
                                                 &path_destroy_delayed, p);
}


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
                          unsigned int *own_pos)
{
  struct CadetPeerPath *path;
  GNUNET_PEER_Id shortid;
  unsigned int i;
  unsigned int j;
  unsigned int offset;

  /* Create path */
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  Creating path...\n");
  path = path_new (size);
  *own_pos = 0;
  offset = 0;
  for (i = 0; i < size; i++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "  - %u: taking %s\n",
         i, GNUNET_i2s (&peers[i]));
    shortid = GNUNET_PEER_intern (&peers[i]);

    /* Check for loops / duplicates */
    for (j = 0; j < i - offset; j++)
    {
      if (path->peers[j] == shortid)
      {
        LOG (GNUNET_ERROR_TYPE_DEBUG, "    already exists at pos %u\n", j);
        offset = i - j;
        LOG (GNUNET_ERROR_TYPE_DEBUG, "    offset now %u\n", offset);
        GNUNET_PEER_change_rc (shortid, -1);
      }
    }
    LOG (GNUNET_ERROR_TYPE_DEBUG, "    storing at %u\n", i - offset);
    path->peers[i - offset] = shortid;
    if (path->peers[i - offset] == myid)
      *own_pos = i - offset;
  }
  path->length -= offset;

  if (path->peers[*own_pos] != myid)
  {
    /* create path: self not found in path through self */
    GNUNET_break_op (0);
    path_destroy (path);
    return NULL;
  }

  return path;
}


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
                 const struct CadetPeerPath *p2)
{
  unsigned int i;
  unsigned int l;
  unsigned int half;

  if (p1->length != p2->length)
    return GNUNET_NO;

  l = p1->length;
  if (0 == memcmp (p1->peers, p2->peers, sizeof (p1->peers[0]) * l))
    return GNUNET_YES;

  half = l / 2;
  l = l - 1;
  for (i = 0; i <= half; i++)
    if (p1->peers[i] != p2->peers[l - i])
      return GNUNET_NO;

  return GNUNET_YES;
}


/**
 * Test if a path is valid (or at least not known to be invalid).
 *
 * @param path Path to test.
 *
 * @return #GNUNET_YES If the path is valid or unknown,
 *         #GNUNET_NO If the path is known to be invalid.
 */
int
path_is_valid (const struct CadetPeerPath *path)
{
  return (NULL == path->path_delete);
}


/**
 * Destroy the path and free any allocated resources linked to it
 *
 * @param p the path to destroy
 *
 * @return GNUNET_OK on success
 */
int
path_destroy (struct CadetPeerPath *p)
{
  if (NULL == p)
    return GNUNET_OK;

  LOG (GNUNET_ERROR_TYPE_INFO, "destroying path %p (%u)\n", p, p->length);
  GNUNET_PEER_decrement_rcs (p->peers, p->length);
  GNUNET_free_non_null (p->peers);
  if (NULL != p->path_delete)
    GNUNET_SCHEDULER_cancel (p->path_delete);
  GNUNET_free (p);
  return GNUNET_OK;
}


char *
path_2s (struct CadetPeerPath *p)
{
  char *s;
  char *old;
  unsigned int i;

  old = GNUNET_strdup ("");
  for (i = 0; i < p->length; i++)
  {
    GNUNET_asprintf (&s, "%s %s",
                     old, GNUNET_i2s (GNUNET_PEER_resolve2 (p->peers[i])));
    GNUNET_free_non_null (old);
    old = s;
  }
  return old;
}


void
path_debug (struct CadetPeerPath *p)
{
  unsigned int i;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "PATH:\n");
  for (i = 0; i < p->length; i++)
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  %s\n",
                GNUNET_i2s (GNUNET_PEER_resolve2 (p->peers[i])));
  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "END\n");
}
