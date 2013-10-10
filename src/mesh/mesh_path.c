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
 * @file mesh/mesh_path.c
 * @brief Path handling functions
 * @author Bartlomiej Polot
 */

#include "mesh.h"
#include "mesh_path.h"


/**
 * Create a new path
 *
 * @param length How many hops will the path have.
 *
 * @return A newly allocated path with a peer array of the specified length.
 */
struct MeshPeerPath *
path_new (unsigned int length)
{
  struct MeshPeerPath *p;

  p = GNUNET_malloc (sizeof (struct MeshPeerPath));
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
path_invert (struct MeshPeerPath *path)
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
struct MeshPeerPath *
path_duplicate (const struct MeshPeerPath *path)
{
  struct MeshPeerPath *aux;
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
path_get_length (struct MeshPeerPath *path)
{
  if (NULL == path)
    return UINT_MAX;
  return path->length;
}


/**
 * Destroy the path and free any allocated resources linked to it
 *
 * @param p the path to destroy
 *
 * @return GNUNET_OK on success
 */
int
path_destroy (struct MeshPeerPath *p)
{
  if (NULL == p)
    return GNUNET_OK;
  GNUNET_PEER_decrement_rcs (p->peers, p->length);
  GNUNET_free_non_null (p->peers);
  GNUNET_free (p);
  return GNUNET_OK;
}
