/*
     This file is part of GNUnet.
     (C) 2001 - 2011 Christian Grothoff (and other contributing authors)

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
 * @author Bartlomiej Polot
 * @file mesh/mesh_block_lib.c
 */

#ifdef __cplusplus
extern "C"
{
#if 0
  /* keep Emacsens' auto-indent happy */
}
#endif
#endif

#include "mesh_block_lib.h"

/**
 * Iterator over edges in a block.
 *
 * @param cls Closure.
 * @param token Token that follows to next state.
 * @param len Lenght of token.
 * @param key Hash of next state.
 */
static int
check_edge (void *cls,
            const char *token,
            size_t len,
            const struct GNUNET_HashCode *key)
{
  return GNUNET_YES;
}


/**
 * Check if the regex block is well formed, including all edges
 *
 * @param block The start of the block.
 * @param size The size of the block.
 *
 * @return GNUNET_OK in case it's fine, GNUNET_SYSERR otherwise.
 */
int
GNUNET_MESH_regex_block_check (const struct MeshRegexBlock *block,
                               size_t size)
{
  return GNUNET_MESH_regex_block_iterate(NULL, block, size, &check_edge);
}


/**
 * Iterate over all edges of a block of a regex state.
 *
 * @param cls Closure for the iterator.
 * @param block Block to iterate over.
 * @param size Size of block.
 * @param iterator Function to call on each edge in the block.
 *
 * @return How many bytes of block have been processed
 */
int
GNUNET_MESH_regex_block_iterate (void *cls,
                                 const struct MeshRegexBlock *block,
                                 size_t size,
                                 GNUNET_MESH_EgdeIterator iterator)
{
  struct MeshRegexEdge *edge;
  unsigned int n;
  unsigned int n_token;
  unsigned int i;
  size_t offset;
  char *aux;

  offset = sizeof (struct MeshRegexBlock);
  if (offset > size) // Is it safe to access the regex block?
    return GNUNET_SYSERR;
  n = ntohl (block->n_proof);
  offset =+ n;
  if (offset > size) // Is it safe to access the regex proof?
    return GNUNET_SYSERR;
  aux = (char *) &block[1];  // Skip regex block
  aux = &aux[n];             // Skip regex proof
  n = ntohl (block->n_edges);
  for (i = 0; i < n; n++) // aux always points at the end of the previous block
  {
    offset += sizeof (struct MeshRegexEdge);
    if (offset > size) // Is it safe to access the next edge block?
      return GNUNET_SYSERR;
    edge = (struct MeshRegexEdge *) aux;
    n_token = ntohl (edge->n_token);
    offset += n_token;
    if (offset > size) // Is it safe to access the edge token?
      return GNUNET_SYSERR;
    aux = (char *) &edge[1]; // Skip edge block
    if (NULL != iterator)
        if (GNUNET_NO == iterator (cls, aux, n_token, &edge->key))
            return GNUNET_OK;
    aux = &aux[n_token];     // Skip edge token
  }
  // The total size should be exactly the size of (regex + all edges) blocks
  return (offset == size) ? GNUNET_OK : GNUNET_SYSERR;
}

#if 0                           /* keep Emacsens' auto-indent happy */
{
#endif
#ifdef __cplusplus
}
#endif

/* end of mesh_protocol.h */
