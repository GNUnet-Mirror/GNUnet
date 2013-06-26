/*
     This file is part of GNUnet.
     (C) 2012,2013 Christian Grothoff (and other contributing authors)

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
 * @file regex/regex_block_lib.c
 * @brief functions for manipulating non-accept blocks stored for
 *        regex in the DHT
 */
#include "platform.h"
#include "regex_block_lib.h"

#define LOG(kind,...) GNUNET_log_from (kind,"regex-bck",__VA_ARGS__)

/**
 * Struct to keep track of the xquery while iterating all the edges in a block.
 */
struct regex_block_xquery_ctx
{
  /**
   * Xquery: string we are looking for.
   */
  const char *xquery;

  /**
   * Has any edge matched the xquery so far? (GNUNET_OK / GNUNET_NO)
   */
  int found;

  /**
   * Key of the block we are iterating (for debug purposes).
   */
  char *key;
};


/**
 * Iterator over all edges in a block, checking for a presence of a given query.
 *
 * @param cls Closure, (xquery context).
 * @param token Token that follows to next state.
 * @param len Lenght of token.
 * @param key Hash of next state.
 * 
 * @return GNUNET_YES, to keep iterating
 */
static int
check_edge (void *cls,
            const char *token,
            size_t len,
            const struct GNUNET_HashCode *key)
{
  struct regex_block_xquery_ctx *ctx = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, 
	      "edge %.*s [%u]: %s->%s\n",
              (int) len, token, len, ctx->key, GNUNET_h2s(key));
  if (NULL == ctx->xquery)
    return GNUNET_YES;
  if (strlen (ctx->xquery) < len)
    return GNUNET_YES; /* too long */
  if (0 == strncmp (ctx->xquery, token, len))
    ctx->found = GNUNET_OK;
  return GNUNET_YES; /* keep checking for malformed data! */
}


/**
 * Check if the regex block is well formed, including all edges.
 *
 * @param block The start of the block.
 * @param size The size of the block.
 * @param xquery String describing the edge we are looking for.
 *               Can be NULL in case this is a put block.
 *
 * @return GNUNET_OK in case it's fine.
 *         GNUNET_NO in case the xquery exists and is not found (IRRELEVANT).
 *         GNUNET_SYSERR if the block is invalid.
 */
int
REGEX_BLOCK_check (const struct RegexBlock *block,
		   size_t size,
		   const char *xquery)
{
  int res;
  struct regex_block_xquery_ctx ctx;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "Checking block with xquery `%s'\n",
              NULL != xquery ? xquery : "NULL");
  if ( (GNUNET_YES == ntohl (block->accepting)) &&
       ( (NULL == xquery) || ('\0' == xquery[0]) ) )
    return GNUNET_OK;
  ctx.xquery = xquery;
  ctx.found = GNUNET_NO;
  ctx.key = GNUNET_strdup (GNUNET_h2s (&block->key));
  res = REGEX_BLOCK_iterate (block, size, &check_edge, &ctx);
  GNUNET_free (ctx.key);
  if (GNUNET_SYSERR == res)
    return GNUNET_SYSERR;
  if (NULL == xquery)
    return GNUNET_YES;
  return ctx.found;
}


/**
 * Iterate over all edges of a block of a regex state.
 *
 * @param block Block to iterate over.
 * @param size Size of block.
 * @param iterator Function to call on each edge in the block.
 * @param iter_cls Closure for the iterator.
 *
 * @return GNUNET_SYSERR if an error has been encountered.
 *         GNUNET_OK if no error has been encountered.
 *           Note that if the iterator stops the iteration by returning
 *         GNUNET_NO, the block will no longer be checked for further errors.
 *           The return value will be GNUNET_OK meaning that no errors were
 *         found until the edge last notified to the iterator, but there might
 *         be errors in further edges.
 */
int
REGEX_BLOCK_iterate (const struct RegexBlock *block,
                            size_t size,
                            REGEX_INTERNAL_EgdeIterator iterator,
                            void *iter_cls)
{
  struct RegexEdge *edge;
  unsigned int n;
  unsigned int n_token;
  unsigned int i;
  size_t offset;
  char *aux;

  offset = sizeof (struct RegexBlock);
  if (offset >= size) /* Is it safe to access the regex block? */
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  n = ntohl (block->n_proof);
  offset += n;
  if (offset >= size) /* Is it safe to access the regex proof? */
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  aux = (char *) &block[1];  /* Skip regex block */
  aux = &aux[n];             /* Skip regex proof */
  n = ntohl (block->n_edges);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Start iterating block of size %u, proof %u, off %u edges %u\n",
       size, ntohl (block->n_proof), offset, n);
  /* aux always points at the end of the previous block */
  for (i = 0; i < n; i++)
  {
    offset += sizeof (struct RegexEdge);
    LOG (GNUNET_ERROR_TYPE_DEBUG, "*   Edge %u, off %u\n", i, offset);
    if (offset >= size) /* Is it safe to access the next edge block? */
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "*   Size not enough for RegexEdge, END\n");
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    edge = (struct RegexEdge *) aux;
    n_token = ntohl (edge->n_token);
    offset += n_token;
    LOG (GNUNET_ERROR_TYPE_DEBUG, 
         "*    Token length %u, off %u\n", n_token, offset);
    if (offset > size) /* Is it safe to access the edge token? */
    {
      LOG (GNUNET_ERROR_TYPE_WARNING,
           "*   Size not enough for edge token, END\n");
      GNUNET_break_op (0);
      return GNUNET_SYSERR;
    }
    aux = (char *) &edge[1]; /* Skip edge block */
    if (NULL != iterator)
        if (GNUNET_NO == iterator (iter_cls, aux, n_token, &edge->key))
            return GNUNET_OK;
    aux = &aux[n_token];     /* Skip edge token */
  }
  /* The total size should be exactly the size of (regex + all edges) blocks
   * If size == -1, block is from cache and therefore previously checked and
   * assumed correct. */
  if ( (offset != size) && (SIZE_MAX != size) )
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Construct a regex block to be stored in the DHT.
 *
 * @param proof proof string for the block
 * @param num_edges number of edges in the block
 * @param edges the edges of the block
 * @return the regex block
 */
struct RegexBlock *
REGEX_BLOCK_create (const struct GNUNET_HashCode *key,
			     const char *proof,
			     unsigned int num_edges,
			     const struct REGEX_BLOCK_Edge *edges,
			     int accepting,
			     size_t *rsize)
{
  struct RegexBlock *block;
  struct RegexEdge *block_edge;
  size_t size;
  size_t len;
  unsigned int i;
  unsigned int offset;
  char *aux;

  len = strlen(proof);
  size = sizeof (struct RegexBlock) + len;
  block = GNUNET_malloc (size);
  block->key = *key;
  block->n_proof = htonl (len);
  block->n_edges = htonl (num_edges);
  block->accepting = htonl (accepting);

  /* Store the proof at the end of the block. */
  aux = (char *) &block[1];
  memcpy (aux, proof, len);
  aux = &aux[len];

  /* Store each edge in a variable length MeshEdge struct at the
   * very end of the MeshRegexBlock structure.
   */
  for (i = 0; i < num_edges; i++)
  {
    /* aux points at the end of the last block */
    len = strlen (edges[i].label);
    size += sizeof (struct RegexEdge) + len;
    // Calculate offset FIXME is this ok? use size instead?
    offset = aux - (char *) block;
    block = GNUNET_realloc (block, size);
    aux = &((char *) block)[offset];
    block_edge = (struct RegexEdge *) aux;
    block_edge->key = edges[i].destination;
    block_edge->n_token = htonl (len);
    aux = (char *) &block_edge[1];
    memcpy (aux, edges[i].label, len);
    aux = &aux[len];
  }
  *rsize = size;
  return block;
}


/* end of regex_block_lib.c */
