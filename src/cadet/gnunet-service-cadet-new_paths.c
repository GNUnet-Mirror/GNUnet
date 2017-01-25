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
 *
 * TODO:
 * - currently only allowing one unique connection per path,
 *   but need to allow 2 in case WE are establishing one from A to B
 *   while at the same time B establishes one to A.
 *   Also, must not ASSERT if B establishes a 2nd one to us.
 *   Need to have some reasonable tie-breaking to only keep ONE.
 * - path desirability score calculations are not done
 */
#include "platform.h"
#include "gnunet-service-cadet-new_connection.h"
#include "gnunet-service-cadet-new_peer.h"
#include "gnunet-service-cadet-new_paths.h"


#define LOG(level, ...) GNUNET_log_from(level,"cadet-pat",__VA_ARGS__)


/**
 * Information regarding a possible path to reach a peer.
 */
struct CadetPeerPath
{

  /**
   * Array of all the peers on the path.  If @e hn is non-NULL, the
   * last one is our owner.
   */
  struct CadetPeerPathEntry **entries;

  /**
   * Node of this path in the owner's heap.  Used to update our position
   * in the heap whenever our @e desirability changes.
   */
  struct GNUNET_CONTAINER_HeapNode *hn;

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
 * Calculate the path's desirability score.
 *
 * @param path path to calculate the score for
 */
static void
recalculate_path_desirability (struct CadetPeerPath *path)
{
  /* FIXME: update path desirability! */
  GNUNET_break (0); // not implemented
}


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
  return path->desirability;
}


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
                     unsigned int off)
{
  struct CadetPeerPathEntry *entry;

  GNUNET_assert (off < path->entries_length);
  entry = path->entries[off];
  GNUNET_assert (entry->peer == destination);
  return entry->cc;
}


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
                     struct CadetConnection *cc)
{
  struct CadetPeerPathEntry *entry;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Adding connection %s to path %s at offset %u\n",
       GCC_2s (cc),
       GCPP_2s (path),
       off);
  GNUNET_assert (off < path->entries_length);
  entry = path->entries[off];
  GNUNET_assert (NULL == entry->cc);
  entry->cc = cc;
}



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
                     struct CadetConnection *cc)
{
  struct CadetPeerPathEntry *entry;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Removing connection %s to path %s at offset %u\n",
       GCC_2s (cc),
       GCPP_2s (path),
       off);
  GNUNET_assert (off < path->entries_length);
  entry = path->entries[off];
  GNUNET_assert (cc == entry->cc);
  entry->cc = NULL;
}


/**
 * This path is no longer needed, free resources.
 *
 * @param path path resources to free
 */
static void
path_destroy (struct CadetPeerPath *path)
{
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Destroying path %s\n",
       GCPP_2s (path));
  for (unsigned int i=0;i<path->entries_length;i++)
    GNUNET_free (path->entries[i]);
  GNUNET_free (path->entries);
  GNUNET_free (path);
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
  struct CadetPeerPathEntry *entry;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Owner releases path %s\n",
       GCPP_2s (path));
  path->hn = NULL;
  entry = path->entries[path->entries_length - 1];
  while (1)
  {
    /* cut 'off' end of path */
    GCP_path_entry_remove (entry->peer,
                           entry,
                           path->entries_length - 1);
    path->entries_length--; /* We don't bother shrinking the 'entries' array,
                               as it's probably not worth it. */
    GNUNET_free (entry);
    if (0 == path->entries_length)
      break; /* the end */

    /* see if new peer at the end likes this path any better */
    entry = path->entries[path->entries_length - 1];
    path->hn = GCP_attach_path (entry->peer,
                                path,
                                path->entries_length - 1,
                                GNUNET_NO);
    if (NULL != path->hn)
      return; /* yep, got attached, we are done. */
  }

  /* nobody wants us, discard the path */
  path_destroy (path);
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
  entry = path->entries[off];

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
  recalculate_path_desirability (path);
}


/**
 * Closure for #find_peer_at() and #check_match().
 */
struct CheckMatchContext
{

  /**
   * Set to a matching path, if any.
   */
  struct CadetPeerPath *match;

  /**
   * Array the combined paths.
   */
  struct CadetPeer **cpath;

  /**
   * How long is the @e cpath array?
   */
  unsigned int cpath_length;

};


/**
 * Check if the given path is identical on all of the
 * hops until @a off, and not longer than @a off.  If the
 * @a path matches, store it in `match`.
 *
 * @param cls the `struct CheckMatchContext` to check against
 * @param path the path to check
 * @param off offset to check at
 * @return #GNUNET_YES (continue to iterate), or if found #GNUNET_NO
 */
static int
check_match (void *cls,
             struct CadetPeerPath *path,
             unsigned int off)
{
  struct CheckMatchContext *cm_ctx = cls;

  GNUNET_assert (path->entries_length > off);
  if ( (path->entries_length != off + 1) &&
       (off + 1 != cm_ctx->cpath_length) )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "check_match missmatch because path %s is too long (%u vs. %u vs. %u)\n",
         GCPP_2s (path),
         path->entries_length,
         off + 1,
         cm_ctx->cpath_length);
    return GNUNET_YES; /* too long, goes somewhere else already, thus cannot be useful */
  }
  for (unsigned int i=0;i<off;i++)
    if (cm_ctx->cpath[i] !=
        GCPP_get_peer_at_offset (path,
                                 i))
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG,
           "check_match path %s missmatches at offset %u\n",
           GCPP_2s (path),
           i);
      return GNUNET_YES; /* missmatch, ignore */
    }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "check_match found match with path %s\n",
       GCPP_2s (path));
  cm_ctx->match = path;
  return GNUNET_NO; /* match, we are done! */
}


/**
 * Extend path @a path by the @a num_peers from the @a peers
 * array, assuming the owners past the current owner want it.
 *
 * @param path path to extend
 * @param peers list of peers beyond the end of @a path
 * @param num_peers length of the @a peers array
 * @param force force attachment, even if we have other
 *        paths already
 */
static void
extend_path (struct CadetPeerPath *path,
             struct CadetPeer **peers,
             unsigned int num_peers,
             int force)
{
  unsigned int old_len = path->entries_length;
  struct GNUNET_CONTAINER_HeapNode *hn;
  int i;

  /* Expand path */
  GNUNET_array_grow (path->entries,
                     path->entries_length,
                     old_len + num_peers);
  for (i=num_peers-1;i >= 0;i--)
  {
    struct CadetPeerPathEntry *entry = GNUNET_new (struct CadetPeerPathEntry);

    path->entries[old_len + i] = entry;
    entry->peer = peers[i];
    entry->path = path;
  }
  for (i=num_peers-1;i >= 0;i--)
  {
    struct CadetPeerPathEntry *entry = path->entries[old_len + i];

    GCP_path_entry_add (entry->peer,
                        entry,
                        old_len + i);
  }

  /* If we extend an existing path, detach it from the
     old owner and re-attach to the new one */
  hn = NULL;
  for (i=num_peers-1;i>=0;i--)
  {
    struct CadetPeerPathEntry *entry = path->entries[old_len + i];

    path->entries_length = old_len + i + 1;
    recalculate_path_desirability (path);
    hn = GCP_attach_path (peers[i],
                          path,
                          old_len + (unsigned int) i,
                          GNUNET_YES);
    if (NULL != hn)
      break;
    GCP_path_entry_remove (entry->peer,
                           entry,
                           old_len + i);
    GNUNET_free (entry);
    path->entries[old_len + i] = NULL;
  }
  if (NULL == hn)
  {
    /* none of the peers is interested in this path;
       shrink path back */
    GNUNET_array_grow (path->entries,
                       path->entries_length,
                       old_len);
    return;
  }
  GCP_detach_path (path->entries[old_len-1]->peer,
                   path,
                   path->hn);
  path->hn = hn;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Extended path %s\n",
       GCPP_2s (path));
}


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
 * @return a path through the network
 */
void
GCPP_try_path_from_dht (const struct GNUNET_PeerIdentity *get_path,
                        unsigned int get_path_length,
                        const struct GNUNET_PeerIdentity *put_path,
                        unsigned int put_path_length)
{
  struct CadetPeer *cpath[get_path_length + put_path_length];
  struct CheckMatchContext cm_ctx;
  struct CadetPeerPath *path;
  struct GNUNET_CONTAINER_HeapNode *hn;
  int i;

  /* precompute 'cpath' so we can avoid doing the lookups lots of times */
  for (unsigned int off=0;off<get_path_length + put_path_length;off++)
  {
    const struct GNUNET_PeerIdentity *pid;

    pid = (off < get_path_length)
      ? &get_path[get_path_length - off]
      : &put_path[get_path_length + put_path_length - off];
    cpath[off] = GCP_get (pid,
                          GNUNET_YES);
  }

  /* First figure out if this path is a subset of an existing path, an
     extension of an existing path, or a new path. */
  cm_ctx.cpath_length = get_path_length + put_path_length;
  cm_ctx.cpath = cpath;
  cm_ctx.match = NULL;
  for (i=get_path_length + put_path_length-1;i>=0;i--)
  {
    GCP_iterate_paths_at (cpath[i],
                          (unsigned int) i,
                          &check_match,
                          &cm_ctx);
    if (NULL != cm_ctx.match)
    {
      if (i == get_path_length + put_path_length - 1)
      {
        /* Existing path includes this one, nothing to do! */
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Path discovered from DHT is already known\n");
        return;
      }
      if (cm_ctx.match->entries_length == i + 1)
      {
        /* Existing path ends in the middle of new path, extend it! */
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Trying to extend existing path %s by additional links discovered from DHT\n",
             GCPP_2s (cm_ctx.match));
        extend_path (cm_ctx.match,
                     &cpath[i],
                     get_path_length + put_path_length - i,
                     GNUNET_NO);
        return;
      }
    }
  }

  /* No match at all, create completely new path */
  path = GNUNET_new (struct CadetPeerPath);
  path->entries_length = get_path_length + put_path_length;
  path->entries = GNUNET_new_array (path->entries_length,
                                    struct CadetPeerPathEntry *);
  for (i=path->entries_length-1;i>=0;i--)
  {
    struct CadetPeerPathEntry *entry = GNUNET_new (struct CadetPeerPathEntry);

    path->entries[i] = entry;
    entry->peer = cpath[i];
    entry->path = path;
  }
  for (i=path->entries_length-1;i>=0;i--)
  {
    struct CadetPeerPathEntry *entry = path->entries[i];

    GCP_path_entry_add (entry->peer,
                        entry,
                        i);
  }

  /* Finally, try to attach it */
  hn = NULL;
  for (i=get_path_length + put_path_length-1;i>=0;i--)
  {
    struct CadetPeerPathEntry *entry = path->entries[i];

    path->entries_length = i + 1;
    recalculate_path_desirability (path);
    hn = GCP_attach_path (cpath[i],
                          path,
                          (unsigned int) i,
                          GNUNET_NO);
    if (NULL != hn)
      break;
    GCP_path_entry_remove (entry->peer,
                           entry,
                           i);
    GNUNET_free (entry);
    path->entries[i] = NULL;
  }
  if (NULL == hn)
  {
    /* None of the peers on the path care about it. */
    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "Path discovered from DHT is not interesting to us\n");
    GNUNET_free (path->entries);
    GNUNET_free (path);
    return;
  }
  path->hn = hn;
  /* Shrink path to actual useful length */
  GNUNET_array_grow (path->entries,
                     path->entries_length,
                     i + 1);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Created new path %s based on information from DHT\n",
       GCPP_2s (path));
}


/**
 * We got an incoming connection, obtain the corresponding path.
 *
 * @param path_length number of segments on the @a path
 * @param pids path through the network, in reverse order (we are at the end at index @a path_length)
 * @return corresponding path object
 */
struct CadetPeerPath *
GCPP_get_path_from_route (unsigned int path_length,
                          const struct GNUNET_PeerIdentity *pids)
{
  struct CheckMatchContext cm_ctx;
  struct CadetPeer *cpath[path_length];
  struct CadetPeerPath *path;

  /* precompute inverted 'cpath' so we can avoid doing the lookups and
     have the correct order */
  for (unsigned int off=0;off<path_length;off++)
    cpath[off] = GCP_get (&pids[path_length - 1 - off],
                          GNUNET_YES);

  /* First figure out if this path is a subset of an existing path, an
     extension of an existing path, or a new path. */
  cm_ctx.cpath = cpath;
  cm_ctx.cpath_length = path_length;
  cm_ctx.match = NULL;
  for (int i=path_length-1;i>=0;i--)
  {
    GCP_iterate_paths_at (cpath[i],
                          (unsigned int) i,
                          &check_match,
                          &cm_ctx);
    if (NULL != cm_ctx.match)
    {
      if (i == path_length - 1)
      {
        /* Existing path includes this one, return the match! */
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Returning existing path %s as inverse for incoming connection\n",
             GCPP_2s (cm_ctx.match));
        return cm_ctx.match;
      }
      if (cm_ctx.match->entries_length == i + 1)
      {
        /* Existing path ends in the middle of new path, extend it! */
        LOG (GNUNET_ERROR_TYPE_DEBUG,
             "Extending existing path %s to create inverse for incoming connection\n",
             GCPP_2s (cm_ctx.match));
        extend_path (cm_ctx.match,
                     &cpath[i],
                     path_length - i,
                     GNUNET_YES);
        /* Check that extension was successful */
        GNUNET_assert (cm_ctx.match->entries_length == path_length);
        return cm_ctx.match;
      }
      /* Eh, we found a match but couldn't use it? Something is wrong. */
      GNUNET_break (0);
    }
  }

  /* No match at all, create completely new path */
  path = GNUNET_new (struct CadetPeerPath);
  path->entries_length = path_length;
  path->entries = GNUNET_new_array (path->entries_length,
                                    struct CadetPeerPathEntry *);
  for (int i=path_length-1;i>=0;i--)
  {
    struct CadetPeerPathEntry *entry = GNUNET_new (struct CadetPeerPathEntry);

    path->entries[i] = entry;
    entry->peer = cpath[i];
    entry->path = path;
  }
  for (int i=path_length-1;i>=0;i--)
  {
    struct CadetPeerPathEntry *entry = path->entries[i];

    GCP_path_entry_add (entry->peer,
                        entry,
                        i);
  }
  recalculate_path_desirability (path);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Created new path %s to create inverse for incoming connection\n",
       GCPP_2s (path));
  path->hn = GCP_attach_path (cpath[path_length - 1],
                              path,
                              path_length - 1,
                              GNUNET_YES);
  return path;
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
  return path->entries_length;
}


/**
 * Find peer's offset on path.
 *
 * @param path path to search
 * @param cp peer to look for
 * @return offset of @a cp on @a path, or UINT_MAX if not found
 */
unsigned int
GCPP_find_peer (struct CadetPeerPath *path,
                struct CadetPeer *cp)
{
  for (unsigned int off = 0;
       off < path->entries_length;
       off++)
    if (cp == GCPP_get_peer_at_offset (path,
                                       off))
      return off;
  return UINT_MAX;
}


/**
 * Obtain the peer at offset @a off in @a path.
 *
 * @param path peer path to inspect
 * @param off offset to return, must be smaller than path length
 * @return the peer at offset @a off
 */
struct CadetPeer *
GCPP_get_peer_at_offset (struct CadetPeerPath *path,
                         unsigned int off)
{
  GNUNET_assert (off < path->entries_length);
  return path->entries[off]->peer;
}


/**
 * Convert a path to a human-readable string.
 *
 * @param path path to convert
 * @return string, to be freed by caller (unlike other *_2s APIs!)
 */
const char *
GCPP_2s (struct CadetPeerPath *path)
{
  static char buf[2048];
  size_t off;
  const unsigned int max_plen = (sizeof(buf) - 16) / 5 - 2; /* 5 characters per entry */

  off = 0;
  for (unsigned int i = 0;
       i < path->entries_length;
       i++)
  {
    if ( (path->entries_length > max_plen) &&
         (i == max_plen / 2) )
      off += GNUNET_snprintf (&buf[off],
                              sizeof (buf) - off,
                              "...-");
    if ( (path->entries_length > max_plen) &&
         (i > max_plen / 2) &&
         (i < path->entries_length - max_plen / 2) )
      continue;
    off += GNUNET_snprintf (&buf[off],
                            sizeof (buf) - off,
                            "%s%s",
                            GNUNET_i2s (GCP_get_id (GCPP_get_peer_at_offset (path,
                                                                             i))),
                            (i == path->entries_length -1) ? "" : "-");
  }
  GNUNET_snprintf (&buf[off],
                   sizeof (buf) - off,
                   "(%p)",
                   path);
  return buf;
}


/* end of gnunet-service-cadet-new_paths.c */
