/*
     This file is part of GNUnet
     (C) 2012 Christian Grothoff (and other contributing authors)

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
 * @file src/regex/regex_dht.c
 * @brief library to announce regexes in the network and match strings
 * against published regexes.
 * @author Bartlomiej Polot
 */
#include "platform.h"
#include "gnunet_regex_lib.h"
#include "regex_block_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_statistics_service.h"

#define LOG(kind,...) GNUNET_log_from (kind,"regex-dht",__VA_ARGS__)

#define DHT_REPLICATION 5
#define DHT_TTL         GNUNET_TIME_UNIT_HOURS

struct GNUNET_REGEX_announce_handle
{
  /**
   * DHT handle to use, must be initialized externally.
   */
  struct GNUNET_DHT_Handle *dht;

  /**
   * Regular expression.
   */
  const char *regex;

  /**
   * Automaton representation of the regex (expensive to build).
   */
  struct GNUNET_REGEX_Automaton* dfa;

  /**
   * Identity under which to announce the regex.
   */
  struct GNUNET_PeerIdentity *id;

  /**
   * Optional statistics handle to report usage. Can be NULL.
   */
  struct GNUNET_STATISTICS_Handle *stats;
};


/**
 * Regex callback iterator to store own service description in the DHT.
 *
 * @param cls closure.
 * @param key hash for current state.
 * @param proof proof for current state.
 * @param accepting GNUNET_YES if this is an accepting state, GNUNET_NO if not.
 * @param num_edges number of edges leaving current state.
 * @param edges edges leaving current state.
 */
static void
regex_iterator (void *cls,
                const struct GNUNET_HashCode *key,
                const char *proof,
                int accepting,
                unsigned int num_edges,
                const struct GNUNET_REGEX_Edge *edges)
{
  struct GNUNET_REGEX_announce_handle *h = cls;
  struct RegexBlock *block;
  struct RegexEdge *block_edge;
  enum GNUNET_DHT_RouteOption opt;
  size_t size;
  size_t len;
  unsigned int i;
  unsigned int offset;
  char *aux;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "  regex dht put for state %s\n",
       GNUNET_h2s (key));
  LOG (GNUNET_ERROR_TYPE_DEBUG, "   proof: %s\n", proof);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "   num edges: %u\n", num_edges);

  opt = GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE;
  if (GNUNET_YES == accepting)
  {
    struct RegexAccept block;

    LOG (GNUNET_ERROR_TYPE_DEBUG,
         "   state %s is accepting, putting own id\n",
         GNUNET_h2s(key));
    size = sizeof (block);
    block.key = *key;
    block.id = *(h->id);
    GNUNET_STATISTICS_update (h->stats, "# regex accepting blocks stored",
                              1, GNUNET_NO);
    GNUNET_STATISTICS_update (h->stats, "# regex accepting block bytes stored",
                              sizeof (block), GNUNET_NO);
    (void)
    GNUNET_DHT_put (h->dht, key,
                    2, /* FIXME option */
                    opt /* | GNUNET_DHT_RO_RECORD_ROUTE*/,
                    GNUNET_BLOCK_TYPE_REGEX_ACCEPT,
                    size,
                    (char *) &block,
                    GNUNET_TIME_relative_to_absolute (GNUNET_TIME_UNIT_HOURS), /* FIXME: expiration time should be option */
                    GNUNET_TIME_UNIT_HOURS, /* FIXME option */
                    NULL, NULL);
  }
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
    LOG (GNUNET_ERROR_TYPE_DEBUG, "    edge %s towards %s\n",
         edges[i].label, GNUNET_h2s(&edges[i].destination));

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
  (void)
  GNUNET_DHT_put(h->dht, key,
                 DHT_REPLICATION, /* FIXME OPTION */
                 opt,
                 GNUNET_BLOCK_TYPE_REGEX, size,
                 (char *) block,
                 GNUNET_TIME_relative_to_absolute (DHT_TTL), /* FIXME: this should be an option */
                 DHT_TTL,
                 NULL, NULL);
  GNUNET_STATISTICS_update (h->stats, "# regex blocks stored",
                            1, GNUNET_NO);
  GNUNET_STATISTICS_update (h->stats, "# regex block bytes stored",
                            size, GNUNET_NO);
  
  GNUNET_free (block);
}


struct GNUNET_REGEX_announce_handle *
GNUNET_REGEX_announce (struct GNUNET_DHT_Handle *dht,
                       struct GNUNET_PeerIdentity *id,
                       const char *regex,
                       uint16_t compression,
                       struct GNUNET_STATISTICS_Handle *stats)
{
  struct GNUNET_REGEX_announce_handle *h;

  GNUNET_assert (NULL != dht);
  h = GNUNET_malloc (sizeof (struct GNUNET_REGEX_announce_handle));
  h->regex = regex;
  h->dht = dht;
  h->stats = stats;
  h->id = id;
  h->dfa = GNUNET_REGEX_construct_dfa (regex,
                                       strlen (regex),
                                       compression);
  GNUNET_REGEX_reannounce (h);
  return h;
}

void
GNUNET_REGEX_reannounce (struct GNUNET_REGEX_announce_handle *h)
{
  GNUNET_REGEX_iterate_all_edges (h->dfa, &regex_iterator, h);
}

void
GNUNET_REGEX_announce_cancel (struct GNUNET_REGEX_announce_handle *h)
{
  GNUNET_REGEX_automaton_destroy (h->dfa);
  GNUNET_free (h);
}


/******************************************************************************/


/**
 * Struct to keep state of running searches that have consumed a part of
 * the inital string.
 */
struct RegexSearchContext
{
    /**
     * Part of the description already consumed by
     * this particular search branch.
     */
  size_t position;

    /**
     * Information about the search.
     */
  struct GNUNET_REGEX_search_handle *info;

    /**
     * We just want to look for one edge, the longer the better.
     * Keep its length.
     */
  unsigned int longest_match;

    /**
     * Destination hash of the longest match.
     */
  struct GNUNET_HashCode hash;
};


/**
 * Struct to keep information of searches of services described by a regex
 * using a user-provided string service description.
 */
struct GNUNET_REGEX_search_handle
{
    /**
     * DHT handle to use, must be initialized externally.
     */
  struct GNUNET_DHT_Handle *dht;

    /**
     * Optional statistics handle to report usage. Can be NULL.
     */
  struct GNUNET_STATISTICS_Handle *stats;

    /**
     * User provided description of the searched service.
     */
  char *description;

    /**
     * Running DHT GETs.
     */
  struct GNUNET_CONTAINER_MultiHashMap *dht_get_handles;

    /**
     * Results from running DHT GETs.
     */
  struct GNUNET_CONTAINER_MultiHashMap *dht_get_results;

    /**
     * Contexts, for each running DHT GET. Free all on end of search.
     */
  struct RegexSearchContext **contexts;

    /**
     * Number of contexts (branches/steps in search).
     */
  unsigned int n_contexts;
  
  /**
   * @param callback Callback for found peers.
   */
  GNUNET_REGEX_Found callback;

  /**
   * @param callback_cls Closure for @c callback.
   */
  void *callback_cls;
};



/**
 * Jump to the next edge, with the longest matching token.
 *
 * @param block Block found in the DHT.
 * @param size Size of the block.
 * @param ctx Context of the search.
 *
 * @return GNUNET_YES if should keep iterating, GNUNET_NO otherwise.
 */
static void
regex_next_edge (const struct RegexBlock *block,
                 size_t size,
                 struct RegexSearchContext *ctx);


/**
 * Function to process DHT string to regex matching.
 * Called on each result obtained for the DHT search.
 *
 * @param cls Closure (search context).
 * @param exp When will this value expire.
 * @param key Key of the result.
 * @param get_path Path of the get request.
 * @param get_path_length Lenght of get_path.
 * @param put_path Path of the put request.
 * @param put_path_length Length of the put_path.
 * @param type Type of the result.
 * @param size Number of bytes in data.
 * @param data Pointer to the result data.
 */
static void
dht_get_string_accept_handler (void *cls, struct GNUNET_TIME_Absolute exp,
                               const struct GNUNET_HashCode * key,
                               const struct GNUNET_PeerIdentity *get_path,
                               unsigned int get_path_length,
                               const struct GNUNET_PeerIdentity *put_path,
                               unsigned int put_path_length,
                               enum GNUNET_BLOCK_Type type,
                               size_t size, const void *data)
{
  const struct RegexAccept *block = data;
  struct RegexSearchContext *ctx = cls;
  struct GNUNET_REGEX_search_handle *info = ctx->info;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Got regex results from DHT!\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  for %s\n", info->description);

  GNUNET_STATISTICS_update (info->stats, "# regex accepting blocks found",
                            1, GNUNET_NO);
  GNUNET_STATISTICS_update (info->stats, "# regex accepting block bytes found",
                            size, GNUNET_NO);

  info->callback (info->callback_cls,
                  &block->id,
                  get_path, get_path_length,
                  put_path, put_path_length);

  return;
}

/**
 * Find a path to a peer that offers a regex servcie compatible
 * with a given string.
 * 
 * @param key The key of the accepting state.
 * @param ctx Context containing info about the string, tunnel, etc.
 */
static void
regex_find_path (const struct GNUNET_HashCode *key,
                 struct RegexSearchContext *ctx)
{
  struct GNUNET_DHT_GetHandle *get_h;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Found peer by service\n");
  get_h = GNUNET_DHT_get_start (ctx->info->dht,    /* handle */
                                GNUNET_BLOCK_TYPE_REGEX_ACCEPT, /* type */
                                key,     /* key to search */
                                DHT_REPLICATION, /* replication level */
                                GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE |
                                GNUNET_DHT_RO_RECORD_ROUTE,
                                NULL,       /* xquery */ // FIXME BLOOMFILTER
                                0,     /* xquery bits */ // FIXME BLOOMFILTER SIZE
                                &dht_get_string_accept_handler, ctx);
  GNUNET_break (GNUNET_OK ==
                GNUNET_CONTAINER_multihashmap_put(ctx->info->dht_get_handles,
                                                  key,
                                                  get_h,
                                                  GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
}


/**
 * Function to process DHT string to regex matching.
 * Called on each result obtained for the DHT search.
 *
 * @param cls closure (search context)
 * @param exp when will this value expire
 * @param key key of the result
 * @param get_path path of the get request (not used)
 * @param get_path_length lenght of get_path (not used)
 * @param put_path path of the put request (not used)
 * @param put_path_length length of the put_path (not used)
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 *
 * TODO: re-issue the request after certain time? cancel after X results?
 */
static void
dht_get_string_handler (void *cls, struct GNUNET_TIME_Absolute exp,
                        const struct GNUNET_HashCode * key,
                        const struct GNUNET_PeerIdentity *get_path,
                        unsigned int get_path_length,
                        const struct GNUNET_PeerIdentity *put_path,
                        unsigned int put_path_length,
                        enum GNUNET_BLOCK_Type type,
                        size_t size, const void *data)
{
  const struct RegexBlock *block = data;
  struct RegexSearchContext *ctx = cls;
  struct GNUNET_REGEX_search_handle *info = ctx->info;
  void *copy;
  size_t len;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "DHT GET STRING RETURNED RESULTS\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  for: %s\n", ctx->info->description);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "  key: %s\n", GNUNET_h2s (key));

  copy = GNUNET_malloc (size);
  memcpy (copy, data, size);
  GNUNET_break (
    GNUNET_OK ==
    GNUNET_CONTAINER_multihashmap_put (info->dht_get_results, key, copy,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE)
               );
  len = ntohl (block->n_proof);
  {
    char proof[len + 1];

    memcpy (proof, &block[1], len);
    proof[len] = '\0';
    if (GNUNET_OK != GNUNET_REGEX_check_proof (proof, key))
    {
      GNUNET_break_op (0);
      return;
    }
  }
  len = strlen (info->description);
  if (len == ctx->position) // String processed
  {
    if (GNUNET_YES == ntohl (block->accepting))
    {
      regex_find_path (key, ctx);
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_DEBUG, "  block not accepting!\n");
      // FIXME REGEX this block not successful, wait for more? start timeout?
    }
    return;
  }

  regex_next_edge (block, size, ctx);

  return;
}


/**
 * Iterator over found existing mesh regex blocks that match an ongoing search.
 *
 * @param cls closure
 * @param key current key code
 * @param value value in the hash map
 * @return GNUNET_YES if we should continue to iterate,
 *         GNUNET_NO if not.
 */
static int
regex_result_iterator (void *cls,
                       const struct GNUNET_HashCode * key,
                       void *value)
{
  struct RegexBlock *block = value;
  struct RegexSearchContext *ctx = cls;

  if (GNUNET_YES == ntohl(block->accepting) &&
      ctx->position == strlen (ctx->info->description))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "* Found accepting known block\n");
    regex_find_path (key, ctx);
    return GNUNET_YES; // We found an accept state!
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "* %u, %u, [%u]\n",
         ctx->position, strlen(ctx->info->description),
         ntohl(block->accepting));

  }
  regex_next_edge(block, SIZE_MAX, ctx);

  GNUNET_STATISTICS_update (ctx->info->stats, "# regex mesh blocks iterated",
                            1, GNUNET_NO);

  return GNUNET_YES;
}


/**
 * Iterator over edges in a regex block retrieved from the DHT.
 *
 * @param cls Closure (context of the search).
 * @param token Token that follows to next state.
 * @param len Lenght of token.
 * @param key Hash of next state.
 *
 * @return GNUNET_YES if should keep iterating, GNUNET_NO otherwise.
 */
static int
regex_edge_iterator (void *cls,
                     const char *token,
                     size_t len,
                     const struct GNUNET_HashCode *key)
{
  struct RegexSearchContext *ctx = cls;
  struct GNUNET_REGEX_search_handle *info = ctx->info;
  const char *current;
  size_t current_len;

  GNUNET_STATISTICS_update (info->stats, "# regex edges iterated",
                            1, GNUNET_NO);

  LOG (GNUNET_ERROR_TYPE_DEBUG, "*    Start of regex edge iterator\n");
  LOG (GNUNET_ERROR_TYPE_DEBUG, "*     descr : %s\n", info->description);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "*     posit : %u\n", ctx->position);
  current = &info->description[ctx->position];
  LOG (GNUNET_ERROR_TYPE_DEBUG, "*     currt : %s\n", current);
  current_len = strlen (info->description) - ctx->position;
  LOG (GNUNET_ERROR_TYPE_DEBUG, "*     ctlen : %u\n", current_len);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "*     tklen : %u\n", len);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "*     token : %.*s\n", len, token);
  LOG (GNUNET_ERROR_TYPE_DEBUG, "*     nextk : %s\n", GNUNET_h2s(key));
  if (len > current_len)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "*     Token too long, END\n");
    return GNUNET_YES; // Token too long, wont match
  }
  if (0 != strncmp (current, token, len))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "*     Token doesn't match, END\n");
    return GNUNET_YES; // Token doesn't match
  }

  if (len > ctx->longest_match)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "*     Token is longer, KEEP\n");
    ctx->longest_match = len;
    ctx->hash = *key;
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "*     Token is not longer, IGNORE\n");
  }

  LOG (GNUNET_ERROR_TYPE_DEBUG, "*    End of regex edge iterator\n");
  return GNUNET_YES;
}


/**
 * Jump to the next edge, with the longest matching token.
 *
 * @param block Block found in the DHT.
 * @param size Size of the block.
 * @param ctx Context of the search.
 *
 * @return GNUNET_YES if should keep iterating, GNUNET_NO otherwise.
 */
static void
regex_next_edge (const struct RegexBlock *block,
                 size_t size,
                 struct RegexSearchContext *ctx)
{
  struct RegexSearchContext *new_ctx;
  struct GNUNET_REGEX_search_handle *info = ctx->info;
  struct GNUNET_DHT_GetHandle *get_h;
  const char *rest;
  int result;

  /* Find the longest match for the current string position, 
   * among tokens in the given block */
  ctx->longest_match = 0;
  result = GNUNET_REGEX_block_iterate (block, size,
                                       &regex_edge_iterator, ctx);
  GNUNET_break (GNUNET_OK == result);

  /* Did anything match? */
  if (0 == ctx->longest_match)
    return;

  new_ctx = GNUNET_malloc (sizeof (struct RegexSearchContext));
  new_ctx->info = info;
  new_ctx->position = ctx->position + ctx->longest_match;
  GNUNET_array_append (info->contexts, info->n_contexts, new_ctx);

  /* Check whether we already have a DHT GET running for it */
  if (GNUNET_YES ==
      GNUNET_CONTAINER_multihashmap_contains(info->dht_get_handles, &ctx->hash))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "*     GET running, END\n");
    GNUNET_CONTAINER_multihashmap_get_multiple (info->dht_get_results,
                                                &ctx->hash,
                                                &regex_result_iterator,
                                                new_ctx);
    // FIXME: "leaks" new_ctx? avoid keeping it around?
    return; // We are already looking for it
  }

  GNUNET_STATISTICS_update (info->stats, "# regex nodes traversed",
                            1, GNUNET_NO);

  /* Start search in DHT */
  rest = &new_ctx->info->description[new_ctx->position];
  get_h = 
      GNUNET_DHT_get_start (info->dht,    /* handle */
                            GNUNET_BLOCK_TYPE_REGEX, /* type */
                            &ctx->hash,     /* key to search */
                            DHT_REPLICATION, /* replication level */
                            GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
                            rest, /* xquery */
                            // FIXME add BLOOMFILTER to exclude filtered peers
                            strlen(rest) + 1,     /* xquery bits */
                            // FIXME add BLOOMFILTER SIZE
                            &dht_get_string_handler, new_ctx);
  if (GNUNET_OK !=
      GNUNET_CONTAINER_multihashmap_put(info->dht_get_handles,
                                        &ctx->hash,
                                        get_h,
                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    GNUNET_break (0);
    return;
  }
}


struct GNUNET_REGEX_search_handle *
GNUNET_REGEX_search (struct GNUNET_DHT_Handle *dht,
                     const char *string,
                     GNUNET_REGEX_Found callback,
                     void *callback_cls,
                     struct GNUNET_STATISTICS_Handle *stats)
{
  struct GNUNET_REGEX_search_handle *h;
  struct GNUNET_DHT_GetHandle *get_h;
  struct RegexSearchContext *ctx;
  struct GNUNET_HashCode key;
  size_t size;
  size_t len;

  /* Initialize handle */
  LOG (GNUNET_ERROR_TYPE_DEBUG, "GNUNET_REGEX_search: %s\n", string);
  GNUNET_assert (NULL != dht);
  GNUNET_assert (NULL != callback);
  h = GNUNET_malloc (sizeof (struct GNUNET_REGEX_search_handle));
  h->dht = dht;
  h->description = GNUNET_strdup (string);
  h->callback = callback;
  h->callback_cls = callback_cls;
  h->stats = stats;
  h->dht_get_handles = GNUNET_CONTAINER_multihashmap_create (32, GNUNET_YES);
  h->dht_get_results = GNUNET_CONTAINER_multihashmap_create (32, GNUNET_YES);

  /* Initialize context */
  len = strlen (string);
  size = GNUNET_REGEX_get_first_key (string, len, &key);
  ctx = GNUNET_malloc (sizeof (struct RegexSearchContext));
  ctx->position = size;
  ctx->info = h;
  GNUNET_array_append (h->contexts, h->n_contexts, ctx);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "  consumed %u bits out of %u\n", size, len);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "  looking for %s\n", GNUNET_h2s (&key));

  /* Start search in DHT */
  get_h = GNUNET_DHT_get_start (h->dht,    /* handle */
                                GNUNET_BLOCK_TYPE_REGEX, /* type */
                                &key,     /* key to search */
                                DHT_REPLICATION, /* replication level */
                                GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE,
                                &h->description[size],           /* xquery */
                                // FIXME add BLOOMFILTER to exclude filtered peers
                                len + 1 - size,                /* xquery bits */
                                // FIXME add BLOOMFILTER SIZE
                                &dht_get_string_handler, ctx);
  GNUNET_break (
    GNUNET_OK ==
    GNUNET_CONTAINER_multihashmap_put (h->dht_get_handles,
                                       &key,
                                       get_h,
                                       GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST)
               );

  return h;
}


/**
 * Iterator over hash map entries to cancel DHT GET requests after a
 * successful connect_by_string.
 *
 * @param cls Closure (unused).
 * @param key Current key code (unused).
 * @param value Value in the hash map (get handle).
 * @return GNUNET_YES if we should continue to iterate,
 *         GNUNET_NO if not.
 */
static int
regex_cancel_dht_get (void *cls,
                      const struct GNUNET_HashCode * key,
                      void *value)
{
  struct GNUNET_DHT_GetHandle *h = value;

  GNUNET_DHT_get_stop (h);
  return GNUNET_YES;
}


/**
 * Iterator over hash map entries to free MeshRegexBlocks stored during the
 * search for connect_by_string.
 *
 * @param cls Closure (unused).
 * @param key Current key code (unused).
 * @param value MeshRegexBlock in the hash map.
 * @return GNUNET_YES if we should continue to iterate,
 *         GNUNET_NO if not.
 */
static int
regex_free_result (void *cls,
                   const struct GNUNET_HashCode * key,
                   void *value)
{

  GNUNET_free (value);
  return GNUNET_YES;
}


/**
 * Cancel an ongoing regex search in the DHT and free all resources.
 *
 * @param ctx The search context.
 */
static void
regex_cancel_search (struct GNUNET_REGEX_search_handle *ctx)
{
  GNUNET_free (ctx->description);
  GNUNET_CONTAINER_multihashmap_iterate (ctx->dht_get_handles,
                                         &regex_cancel_dht_get, NULL);
  GNUNET_CONTAINER_multihashmap_iterate (ctx->dht_get_results,
                                         &regex_free_result, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (ctx->dht_get_results);
  GNUNET_CONTAINER_multihashmap_destroy (ctx->dht_get_handles);
  if (0 < ctx->n_contexts)
  {
    int i;

    for (i = 0; i < ctx->n_contexts; i++)
    {
      GNUNET_free (ctx->contexts[i]);
    }
    GNUNET_free (ctx->contexts);
  }
}

void
GNUNET_REGEX_search_cancel (struct GNUNET_REGEX_search_handle *h)
{
  regex_cancel_search (h);
  GNUNET_free (h);
}



/* end of regex_dht.c */