/*
     This file is part of GNUnet.
     Copyright (C) 2012,2013 Christian Grothoff (and other contributing authors)

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
#include "gnunet_constants.h"

#define LOG(kind,...) GNUNET_log_from (kind,"regex-bck",__VA_ARGS__)

GNUNET_NETWORK_STRUCT_BEGIN

/**
 * Information for each edge.
 */
struct EdgeInfo
{
  /**
   * Index of the destination of this edge in the
   * unique destinations array.
   */
  uint16_t destination_index GNUNET_PACKED;

  /**
   * Number of bytes the token for this edge takes in the
   * token area.
   */
  uint16_t token_length GNUNET_PACKED;
};


/**
 * @brief Block to announce a regex state.
 */
struct RegexBlock
{

  /**
   * Length of the proof regex string.
   */
  uint16_t proof_len GNUNET_PACKED;

  /**
   * Is this state an accepting state?
   */
  int16_t is_accepting GNUNET_PACKED;

  /**
   * Number of edges parting from this state.
   */
  uint16_t num_edges GNUNET_PACKED;

  /**
   * Nubmer of unique destinations reachable from this state.
   */
  uint16_t num_destinations GNUNET_PACKED;

  /* followed by 'struct GNUNET_HashCode[num_destinations]' */

  /* followed by 'struct EdgeInfo[edge_destination_indices]' */

  /* followed by 'char proof[n_proof]', NOT 0-terminated */

  /* followed by 'char tokens[num_edges][edge_info[k].token_length]';
     essentially all of the tokens one after the other in the
     order of the edges; tokens are NOT 0-terminated */

};


GNUNET_NETWORK_STRUCT_END


/**
 * Test if this block is marked as being an accept state.
 *
 * @param block block to test
 * @param size number of bytes in block
 * @return #GNUNET_YES if the block is accepting, #GNUNET_NO if not
 */
int
GNUNET_BLOCK_is_accepting (const struct RegexBlock *block,
			   size_t size)
{
  if (size < sizeof (struct RegexBlock))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  return ntohs (block->is_accepting);
}


/**
 * Check if the given 'proof' matches the given 'key'.
 *
 * @param proof partial regex of a state
 * @param proof_len number of bytes in 'proof'
 * @param key hash of a state.
 * @return #GNUNET_OK if the proof is valid for the given key.
 */
int
REGEX_BLOCK_check_proof (const char *proof,
			 size_t proof_len,
			 const struct GNUNET_HashCode *key)
{
  struct GNUNET_HashCode key_check;

  if ( (NULL == proof) || (NULL == key))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_ERROR, "Proof check failed, was NULL.\n");
    return GNUNET_NO;
  }
  GNUNET_CRYPTO_hash (proof, proof_len, &key_check);
  return (0 ==
          GNUNET_CRYPTO_hash_cmp (key, &key_check)) ? GNUNET_OK : GNUNET_NO;
}


/**
 * Struct to keep track of the xquery while iterating all the edges in a block.
 */
struct CheckEdgeContext
{
  /**
   * Xquery: string we are looking for.
   */
  const char *xquery;

  /**
   * Has any edge matched the xquery so far? (GNUNET_OK / GNUNET_NO)
   */
  int found;

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
  struct CheckEdgeContext *ctx = cls;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
	      "edge %.*s [%u]: %s->%s\n",
              (int) len, token, len, GNUNET_h2s(key));
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
 * @param query the query for the block
 * @param xquery String describing the edge we are looking for.
 *               Can be NULL in case this is a put block.
 * @return #GNUNET_OK in case it's fine.
 *         #GNUNET_NO in case the xquery exists and is not found (IRRELEVANT).
 *         #GNUNET_SYSERR if the block is invalid.
 */
int
REGEX_BLOCK_check (const struct RegexBlock *block,
		   size_t size,
		   const struct GNUNET_HashCode *query,
		   const char *xquery)
{
  struct GNUNET_HashCode key;
  struct CheckEdgeContext ctx;
  int res;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Block check\n");
  if (GNUNET_OK !=
      REGEX_BLOCK_get_key (block, size,
			   &key))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if (NULL != query &&
      0 != memcmp (&key,
                   query,
                   sizeof (struct GNUNET_HashCode)))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  if ( (GNUNET_YES == ntohs (block->is_accepting)) &&
       ( (NULL == xquery) || ('\0' == xquery[0]) ) )
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
       "  out! Is accepting: %u, xquery %p\n",
       ntohs(block->is_accepting), xquery);
    return GNUNET_OK;
  }
  ctx.xquery = xquery;
  ctx.found = GNUNET_NO;
  res = REGEX_BLOCK_iterate (block, size, &check_edge, &ctx);
  if (GNUNET_SYSERR == res)
    return GNUNET_SYSERR;
  if (NULL == xquery)
    return GNUNET_YES;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "Result %d\n", ctx.found);
  return ctx.found;
}


/**
 * Obtain the key that a particular block is to be stored under.
 *
 * @param block block to get the key from
 * @param block_len number of bytes in block
 * @param key where to store the key
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the block is malformed
 */
int
REGEX_BLOCK_get_key (const struct RegexBlock *block,
                     size_t block_len,
                     struct GNUNET_HashCode *key)
{
  uint16_t len;
  const struct GNUNET_HashCode *destinations;
  const struct EdgeInfo *edges;
  uint16_t num_destinations;
  uint16_t num_edges;
  size_t total;

  if (block_len < sizeof (struct RegexBlock))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  num_destinations = ntohs (block->num_destinations);
  num_edges = ntohs (block->num_edges);
  len = ntohs (block->proof_len);
  destinations = (const struct GNUNET_HashCode *) &block[1];
  edges = (const struct EdgeInfo *) &destinations[num_destinations];
  total = sizeof (struct RegexBlock) + num_destinations * sizeof (struct GNUNET_HashCode) + num_edges * sizeof (struct EdgeInfo) + len;
  if (block_len < total)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  GNUNET_CRYPTO_hash (&edges[num_edges], len, key);
  return GNUNET_OK;
}


/**
 * Iterate over all edges of a block of a regex state.
 *
 * @param block Block to iterate over.
 * @param size Size of @a block.
 * @param iterator Function to call on each edge in the block.
 * @param iter_cls Closure for the @a iterator.
 * @return #GNUNET_SYSERR if an error has been encountered.
 *         #GNUNET_OK if no error has been encountered.
 *           Note that if the iterator stops the iteration by returning
 *         #GNUNET_NO, the block will no longer be checked for further errors.
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
  uint16_t len;
  const struct GNUNET_HashCode *destinations;
  const struct EdgeInfo *edges;
  const char *aux;
  uint16_t num_destinations;
  uint16_t num_edges;
  size_t total;
  unsigned int n;
  size_t off;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Block iterate\n");
  if (size < sizeof (struct RegexBlock))
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  num_destinations = ntohs (block->num_destinations);
  num_edges = ntohs (block->num_edges);
  len = ntohs (block->proof_len);
  destinations = (const struct GNUNET_HashCode *) &block[1];
  edges = (const struct EdgeInfo *) &destinations[num_destinations];
  aux = (const char *) &edges[num_edges];
  total = sizeof (struct RegexBlock) + num_destinations * sizeof (struct GNUNET_HashCode) + num_edges * sizeof (struct EdgeInfo) + len;
  if (size < total)
  {
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  for (n=0;n<num_edges;n++)
    total += ntohs (edges[n].token_length);
  if (size != total)
  {
    fprintf (stderr, "Expected %u, got %u\n",
	     (unsigned int) size,
	     (unsigned int) total);
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  off = len;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Start iterating block of size %u, proof %u, off %u edges %u\n",
       size, len, off, n);
  /* &aux[off] always points to our token */
  for (n=0;n<num_edges;n++)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "Edge %u/%u, off %u tokenlen %u (%.*s)\n",
         n+1, num_edges, off,
	 ntohs (edges[n].token_length), ntohs (edges[n].token_length),
         &aux[off]);
    if (NULL != iterator)
      if (GNUNET_NO == iterator (iter_cls,
				 &aux[off],
				 ntohs (edges[n].token_length),
				 &destinations[ntohs (edges[n].destination_index)]))
	return GNUNET_OK;
    off += ntohs (edges[n].token_length);
  }
  return GNUNET_OK;
}


/**
 * Construct a regex block to be stored in the DHT.
 *
 * @param proof proof string for the block
 * @param num_edges number of edges in the block
 * @param edges the edges of the block
 * @param accepting is this an accepting state
 * @param rsize set to the size of the returned block (OUT-only)
 * @return the regex block, NULL on error
 */
struct RegexBlock *
REGEX_BLOCK_create (const char *proof,
		    unsigned int num_edges,
		    const struct REGEX_BLOCK_Edge *edges,
		    int accepting,
		    size_t *rsize)
{
  struct RegexBlock *block;
  struct GNUNET_HashCode destinations[1024]; /* 1024 = 64k/64 bytes/key == absolute MAX */
  uint16_t destination_indices[num_edges];
  struct GNUNET_HashCode *dests;
  struct EdgeInfo *edgeinfos;
  size_t off;
  size_t len;
  size_t total;
  size_t slen;
  unsigned int unique_destinations;
  unsigned int j;
  unsigned int i;
  char *aux;

  len = strlen (proof);
  if (len > UINT16_MAX)
  {
    GNUNET_break (0);
    return NULL;
  }
  unique_destinations = 0;
  total = sizeof (struct RegexBlock) + len;
  for (i=0;i<num_edges;i++)
  {
    slen = strlen (edges[i].label);
    if (slen > UINT16_MAX)
    {
      GNUNET_break (0);
      return NULL;
    }
    total += slen;
    for (j=0;j<unique_destinations;j++)
      if (0 == memcmp (&destinations[j],
		       &edges[i].destination,
		       sizeof (struct GNUNET_HashCode)))
	break;
    if (j >= 1024)
    {
      GNUNET_break (0);
      return NULL;
    }
    destination_indices[i] = j;
    if (j == unique_destinations)
      destinations[unique_destinations++] = edges[i].destination;
  }
  total += num_edges * sizeof (struct EdgeInfo) + unique_destinations * sizeof (struct GNUNET_HashCode);
  if (total >= GNUNET_CONSTANTS_MAX_BLOCK_SIZE)
  {
    GNUNET_break (0);
    return NULL;
  }
  block = GNUNET_malloc (total);
  block->proof_len = htons (len);
  block->is_accepting = htons (accepting);
  block->num_edges = htons (num_edges);
  block->num_destinations = htons (unique_destinations);
  dests = (struct GNUNET_HashCode *) &block[1];
  memcpy (dests, destinations, sizeof (struct GNUNET_HashCode) * unique_destinations);
  edgeinfos = (struct EdgeInfo *) &dests[unique_destinations];
  aux = (char *) &edgeinfos[num_edges];
  off = len;
  memcpy (aux, proof, len);
  for (i=0;i<num_edges;i++)
  {
    slen = strlen (edges[i].label);
    edgeinfos[i].token_length = htons ((uint16_t) slen);
    edgeinfos[i].destination_index = htons (destination_indices[i]);
    memcpy (&aux[off],
	    edges[i].label,
	    slen);
    off += slen;
  }
  *rsize = total;
  return block;
}


/* end of regex_block_lib.c */
