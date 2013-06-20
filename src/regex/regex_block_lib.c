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


  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  edge %.*s [%u]: %s->%s\n",
              (int) len, token, len, ctx->key, GNUNET_h2s(key));

  if (NULL == ctx->xquery)
    return GNUNET_YES;
  if (strlen (ctx->xquery) < len)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  too long!\n");
    return GNUNET_YES;
  }
  if (0 == strncmp (ctx->xquery, token, len))
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  OK!\n");
    ctx->found = GNUNET_OK;
  }
  else
  {
    GNUNET_log (GNUNET_ERROR_TYPE_DEBUG, "  KO!\n");
  }

  return GNUNET_YES; /* keep checking for malformed data! */
}


int
REGEX_ITERNAL_block_check (const struct RegexBlock *block,
                          size_t size,
                          const char *xquery)
{
  int res;
  struct regex_block_xquery_ctx ctx;

  GNUNET_log (GNUNET_ERROR_TYPE_DEBUG,
              "* Checking block with xquery \"%s\"\n",
              NULL != xquery ? xquery : "NULL");
  if ( (GNUNET_YES == ntohl (block->accepting)) &&
       ( (NULL == xquery) || ('\0' == xquery[0]) )
     )
    return GNUNET_OK;
  ctx.xquery = xquery;
  ctx.found = GNUNET_NO;
  ctx.key = GNUNET_strdup (GNUNET_h2s (&block->key));
  res = REGEX_ITERNAL_block_iterate (block, size, &check_edge, &ctx);
  GNUNET_free (ctx.key);
  if (GNUNET_SYSERR == res)
    return GNUNET_SYSERR;
  if (NULL == xquery)
    return GNUNET_YES;
  return ctx.found;
}


int
REGEX_ITERNAL_block_iterate (const struct RegexBlock *block,
                            size_t size,
                            REGEX_ITERNAL_EgdeIterator iterator,
                            void *iter_cls)
{
  struct RegexEdge *edge;
  unsigned int n;
  unsigned int n_token;
  unsigned int i;
  size_t offset;
  char *aux;

  offset = sizeof (struct RegexBlock);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "* Start iterating block of size %u, off %u\n",
       size, offset);
  if (offset >= size) /* Is it safe to access the regex block? */
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "*   Block is smaller than struct RegexBlock, END\n");
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  n = ntohl (block->n_proof);
  offset += n;
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "*  Proof length: %u, off %u\n", n, offset);
  if (offset >= size) /* Is it safe to access the regex proof? */
  {
    LOG (GNUNET_ERROR_TYPE_WARNING,
         "*   Block is smaller than Block + proof, END\n");
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  }
  aux = (char *) &block[1];  /* Skip regex block */
  aux = &aux[n];             /* Skip regex proof */
  n = ntohl (block->n_edges);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "*  Edges: %u\n", n);
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
  if (offset == size || SIZE_MAX == size)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "* Block processed, END OK\n");
    return GNUNET_OK;
  }
  LOG (GNUNET_ERROR_TYPE_WARNING,
       "*   Size %u (%d), read %u END KO\n", size, size, offset);
  GNUNET_break_op (0);
  return GNUNET_SYSERR;
}

/* end of regex_block_lib.c */
