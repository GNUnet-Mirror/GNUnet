/*
     This file is part of GNUnet
     Copyright (C) 2012, 2015 Christian Grothoff (and other contributing authors)

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
 * @file src/regex/regex_internal_dht.c
 * @brief library to announce regexes in the network and match strings
 * against published regexes.
 * @author Bartlomiej Polot
 */
#include "platform.h"
#include "regex_internal_lib.h"
#include "regex_block_lib.h"
#include "gnunet_dht_service.h"
#include "gnunet_statistics_service.h"
#include "gnunet_constants.h"
#include "gnunet_signatures.h"


#define LOG(kind,...) GNUNET_log_from (kind,"regex-dht",__VA_ARGS__)

/**
 * DHT replication level to use.
 */
#define DHT_REPLICATION 5

/**
 * DHT record lifetime to use.
 */
#define DHT_TTL         GNUNET_TIME_UNIT_HOURS

/**
 * DHT options to set.
 */
#define DHT_OPT         GNUNET_DHT_RO_DEMULTIPLEX_EVERYWHERE


/**
 * Handle to store cached data about a regex announce.
 */
struct REGEX_INTERNAL_Announcement
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
  struct REGEX_INTERNAL_Automaton *dfa;

  /**
   * Our private key.
   */
  const struct GNUNET_CRYPTO_EddsaPrivateKey *priv;

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
 * @param accepting #GNUNET_YES if this is an accepting state, #GNUNET_NO if not.
 * @param num_edges number of edges leaving current state.
 * @param edges edges leaving current state.
 */
static void
regex_iterator (void *cls,
                const struct GNUNET_HashCode *key,
                const char *proof,
                int accepting,
                unsigned int num_edges,
                const struct REGEX_BLOCK_Edge *edges)
{
  struct REGEX_INTERNAL_Announcement *h = cls;
  struct RegexBlock *block;
  size_t size;
  unsigned int i;

  LOG (GNUNET_ERROR_TYPE_INFO,
       "DHT PUT for state %s with proof `%s' and %u edges:\n",
       GNUNET_h2s (key),
       proof,
       num_edges);
  for (i = 0; i < num_edges; i++)
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
         "Edge %u `%s' towards %s\n",
         i,
         edges[i].label,
         GNUNET_h2s (&edges[i].destination));
  }
  if (GNUNET_YES == accepting)
  {
    struct RegexAcceptBlock ab;

    LOG (GNUNET_ERROR_TYPE_INFO,
         "State %s is accepting, putting own id\n",
         GNUNET_h2s (key));
    size = sizeof (struct RegexAcceptBlock);
    ab.purpose.size = ntohl (sizeof (struct GNUNET_CRYPTO_EccSignaturePurpose) +
                             sizeof (struct GNUNET_TIME_AbsoluteNBO) +
                             sizeof (struct GNUNET_HashCode));
    ab.purpose.purpose = ntohl (GNUNET_SIGNATURE_PURPOSE_REGEX_ACCEPT);
    ab.expiration_time = GNUNET_TIME_absolute_hton (GNUNET_TIME_relative_to_absolute (GNUNET_CONSTANTS_DHT_MAX_EXPIRATION));
    ab.key = *key;
    GNUNET_CRYPTO_eddsa_key_get_public (h->priv,
                                        &ab.peer.public_key);
    GNUNET_assert (GNUNET_OK ==
                   GNUNET_CRYPTO_eddsa_sign (h->priv,
                                           &ab.purpose,
                                           &ab.signature));

    GNUNET_STATISTICS_update (h->stats, "# regex accepting blocks stored",
                              1, GNUNET_NO);
    GNUNET_STATISTICS_update (h->stats, "# regex accepting block bytes stored",
                              sizeof (struct RegexAcceptBlock), GNUNET_NO);
    (void)
    GNUNET_DHT_put (h->dht, key,
                    DHT_REPLICATION,
                    DHT_OPT | GNUNET_DHT_RO_RECORD_ROUTE,
                    GNUNET_BLOCK_TYPE_REGEX_ACCEPT,
                    size,
                    &ab,
                    GNUNET_TIME_relative_to_absolute (DHT_TTL),
                    DHT_TTL,
                    NULL, NULL);
  }
  block = REGEX_BLOCK_create (proof,
                              num_edges, edges,
                              accepting,
                              &size);
  (void)
  GNUNET_DHT_put (h->dht, key,
                  DHT_REPLICATION,
                  DHT_OPT,
                  GNUNET_BLOCK_TYPE_REGEX,
                  size, block,
                  GNUNET_TIME_relative_to_absolute (DHT_TTL),
                  DHT_TTL,
                  NULL, NULL);
  GNUNET_STATISTICS_update (h->stats,
                            "# regex blocks stored",
                            1, GNUNET_NO);
  GNUNET_STATISTICS_update (h->stats,
                            "# regex block bytes stored",
                            size, GNUNET_NO);
  GNUNET_free (block);
}


/**
 * Announce a regular expression: put all states of the automaton in the DHT.
 * Does not free resources, must call #REGEX_INTERNAL_announce_cancel() for that.
 *
 * @param dht An existing and valid DHT service handle. CANNOT be NULL.
 * @param priv our private key, must remain valid until the announcement is cancelled
 * @param regex Regular expression to announce.
 * @param compression How many characters per edge can we squeeze?
 * @param stats Optional statistics handle to report usage. Can be NULL.
 * @return Handle to reuse o free cached resources.
 *         Must be freed by calling #REGEX_INTERNAL_announce_cancel().
 */
struct REGEX_INTERNAL_Announcement *
REGEX_INTERNAL_announce (struct GNUNET_DHT_Handle *dht,
			 const struct GNUNET_CRYPTO_EddsaPrivateKey *priv,
			 const char *regex,
			 uint16_t compression,
			 struct GNUNET_STATISTICS_Handle *stats)
{
  struct REGEX_INTERNAL_Announcement *h;

  GNUNET_assert (NULL != dht);
  h = GNUNET_new (struct REGEX_INTERNAL_Announcement);
  h->regex = regex;
  h->dht = dht;
  h->stats = stats;
  h->priv = priv;
  h->dfa = REGEX_INTERNAL_construct_dfa (regex, strlen (regex), compression);
  REGEX_INTERNAL_reannounce (h);
  return h;
}


/**
 * Announce again a regular expression previously announced.
 * Does use caching to speed up process.
 *
 * @param h Handle returned by a previous #REGEX_INTERNAL_announce call().
 */
void
REGEX_INTERNAL_reannounce (struct REGEX_INTERNAL_Announcement *h)
{
  GNUNET_assert (NULL != h->dfa); /* make sure to call announce first */
  LOG (GNUNET_ERROR_TYPE_INFO,
       "REGEX_INTERNAL_reannounce: %s\n",
       h->regex);
  REGEX_INTERNAL_iterate_reachable_edges (h->dfa,
                                          &regex_iterator,
                                          h);
}


/**
 * Clear all cached data used by a regex announce.
 * Does not close DHT connection.
 *
 * @param h Handle returned by a previous #REGEX_INTERNAL_announce() call.
 */
void
REGEX_INTERNAL_announce_cancel (struct REGEX_INTERNAL_Announcement *h)
{
  REGEX_INTERNAL_automaton_destroy (h->dfa);
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
  struct REGEX_INTERNAL_Search *info;

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
 * Type of values in #dht_get_results().
 */
struct Result
{
  /**
   * Number of bytes in data.
   */
  size_t size;

  /**
   * The raw result data.
   */
  const void *data;
};


/**
 * Struct to keep information of searches of services described by a regex
 * using a user-provided string service description.
 */
struct REGEX_INTERNAL_Search
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
   * Results from running DHT GETs, values are of type
   * 'struct Result'.
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
  REGEX_INTERNAL_Found callback;

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
                               const struct GNUNET_HashCode *key,
                               const struct GNUNET_PeerIdentity *get_path,
                               unsigned int get_path_length,
                               const struct GNUNET_PeerIdentity *put_path,
                               unsigned int put_path_length,
                               enum GNUNET_BLOCK_Type type,
                               size_t size, const void *data)
{
  const struct RegexAcceptBlock *block = data;
  struct RegexSearchContext *ctx = cls;
  struct REGEX_INTERNAL_Search *info = ctx->info;

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Regex result accept for %s (key %s)\n",
       info->description, GNUNET_h2s(key));

  GNUNET_STATISTICS_update (info->stats,
			    "# regex accepting blocks found",
                            1, GNUNET_NO);
  GNUNET_STATISTICS_update (info->stats,
			    "# regex accepting block bytes found",
                            size, GNUNET_NO);
  info->callback (info->callback_cls,
                  &block->peer,
                  get_path, get_path_length,
                  put_path, put_path_length);
}


/**
 * Find a path to a peer that offers a regex service compatible
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

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Accept state found, now searching for paths to %s\n",
       GNUNET_h2s (key),
       (unsigned int) ctx->position);
  get_h = GNUNET_DHT_get_start (ctx->info->dht,    /* handle */
                                GNUNET_BLOCK_TYPE_REGEX_ACCEPT, /* type */
                                key,     /* key to search */
                                DHT_REPLICATION, /* replication level */
                                DHT_OPT | GNUNET_DHT_RO_RECORD_ROUTE,
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
 * @param get_path_length length of @a get_path (not used)
 * @param put_path path of the put request (not used)
 * @param put_path_length length of the @a put_path (not used)
 * @param type type of the result
 * @param size number of bytes in data
 * @param data pointer to the result data
 *
 * TODO: re-issue the request after certain time? cancel after X results?
 */
static void
dht_get_string_handler (void *cls, struct GNUNET_TIME_Absolute exp,
                        const struct GNUNET_HashCode *key,
                        const struct GNUNET_PeerIdentity *get_path,
                        unsigned int get_path_length,
                        const struct GNUNET_PeerIdentity *put_path,
                        unsigned int put_path_length,
                        enum GNUNET_BLOCK_Type type,
                        size_t size, const void *data)
{
  const struct RegexBlock *block = data;
  struct RegexSearchContext *ctx = cls;
  struct REGEX_INTERNAL_Search *info = ctx->info;
  size_t len;
  struct Result *copy;

  LOG (GNUNET_ERROR_TYPE_INFO,
       "DHT GET result for %s (%s)\n",
       GNUNET_h2s (key), ctx->info->description);
  copy = GNUNET_malloc (sizeof (struct Result) + size);
  copy->size = size;
  copy->data = &copy[1];
  memcpy (&copy[1], block, size);
  GNUNET_break (GNUNET_OK ==
		GNUNET_CONTAINER_multihashmap_put (info->dht_get_results,
						   key, copy,
						   GNUNET_CONTAINER_MULTIHASHMAPOPTION_MULTIPLE));
  len = strlen (info->description);
  if (len == ctx->position) // String processed
  {
    if (GNUNET_YES == GNUNET_BLOCK_is_accepting (block, size))
    {
      regex_find_path (key, ctx);
    }
    else
    {
      LOG (GNUNET_ERROR_TYPE_INFO, "block not accepting!\n");
      /* FIXME REGEX this block not successful, wait for more? start timeout? */
    }
    return;
  }
  regex_next_edge (block, size, ctx);
}


/**
 * Iterator over found existing cadet regex blocks that match an ongoing search.
 *
 * @param cls Closure (current context)-
 * @param key Current key code (key for cached block).
 * @param value Value in the hash map (cached RegexBlock).
 * @return #GNUNET_YES: we should always continue to iterate.
 */
static int
regex_result_iterator (void *cls,
                       const struct GNUNET_HashCode * key,
                       void *value)
{
  struct Result *result = value;
  const struct RegexBlock *block = result->data;
  struct RegexSearchContext *ctx = cls;

  if ( (GNUNET_YES ==
	GNUNET_BLOCK_is_accepting (block, result->size)) &&
       (ctx->position == strlen (ctx->info->description)) )
  {
    LOG (GNUNET_ERROR_TYPE_INFO,
	 "Found accepting known block\n");
    regex_find_path (key, ctx);
    return GNUNET_YES; // We found an accept state!
  }
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "* %u, %u, [%u]\n",
       ctx->position,
       strlen (ctx->info->description),
       GNUNET_BLOCK_is_accepting (block, result->size));
  regex_next_edge (block, result->size, ctx);

  GNUNET_STATISTICS_update (ctx->info->stats, "# regex cadet blocks iterated",
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
 * @return #GNUNET_YES if should keep iterating, #GNUNET_NO otherwise.
 */
static int
regex_edge_iterator (void *cls,
                     const char *token,
                     size_t len,
                     const struct GNUNET_HashCode *key)
{
  struct RegexSearchContext *ctx = cls;
  struct REGEX_INTERNAL_Search *info = ctx->info;
  const char *current;
  size_t current_len;

  GNUNET_STATISTICS_update (info->stats, "# regex edges iterated",
                            1, GNUNET_NO);
  current = &info->description[ctx->position];
  current_len = strlen (info->description) - ctx->position;
  if (len > current_len)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Token too long, END\n");
    return GNUNET_YES;
  }
  if (0 != strncmp (current, token, len))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Token doesn't match, END\n");
    return GNUNET_YES;
  }

  if (len > ctx->longest_match)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Token is longer, KEEP\n");
    ctx->longest_match = len;
    ctx->hash = *key;
  }
  else
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG, "Token is not longer, IGNORE\n");
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
 */
static void
regex_next_edge (const struct RegexBlock *block,
                 size_t size,
                 struct RegexSearchContext *ctx)
{
  struct RegexSearchContext *new_ctx;
  struct REGEX_INTERNAL_Search *info = ctx->info;
  struct GNUNET_DHT_GetHandle *get_h;
  struct GNUNET_HashCode *hash;
  const char *rest;
  int result;

  LOG (GNUNET_ERROR_TYPE_DEBUG, "Next edge\n");
  /* Find the longest match for the current string position,
   * among tokens in the given block */
  ctx->longest_match = 0;
  result = REGEX_BLOCK_iterate (block, size,
                                &regex_edge_iterator, ctx);
  GNUNET_break (GNUNET_OK == result);

  /* Did anything match? */
  if (0 == ctx->longest_match)
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "no match in block\n");
    return;
  }

  hash = &ctx->hash;
  new_ctx = GNUNET_new (struct RegexSearchContext);
  new_ctx->info = info;
  new_ctx->position = ctx->position + ctx->longest_match;
  GNUNET_array_append (info->contexts, info->n_contexts, new_ctx);

  /* Check whether we already have a DHT GET running for it */
  if (GNUNET_YES ==
      GNUNET_CONTAINER_multihashmap_contains (info->dht_get_handles, hash))
  {
    LOG (GNUNET_ERROR_TYPE_DEBUG,
	 "GET for %s running, END\n",
         GNUNET_h2s (hash));
    GNUNET_CONTAINER_multihashmap_get_multiple (info->dht_get_results,
                                                hash,
                                                &regex_result_iterator,
                                                new_ctx);
    return; /* We are already looking for it */
  }

  GNUNET_STATISTICS_update (info->stats, "# regex nodes traversed",
                            1, GNUNET_NO);

  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Following edges at %s for offset %u in `%s'\n",
       GNUNET_h2s (hash),
       (unsigned int) ctx->position,
       info->description);
  rest = &new_ctx->info->description[new_ctx->position];
  get_h =
      GNUNET_DHT_get_start (info->dht,    /* handle */
                            GNUNET_BLOCK_TYPE_REGEX, /* type */
                            hash,     /* key to search */
                            DHT_REPLICATION, /* replication level */
                            DHT_OPT,
                            rest, /* xquery */
                            strlen (rest) + 1,     /* xquery bits */
                            &dht_get_string_handler, new_ctx);
  if (GNUNET_OK !=
      GNUNET_CONTAINER_multihashmap_put(info->dht_get_handles,
                                        hash,
                                        get_h,
                                        GNUNET_CONTAINER_MULTIHASHMAPOPTION_UNIQUE_FAST))
  {
    GNUNET_break (0);
    return;
  }
}


/**
 * Search for a peer offering a regex matching certain string in the DHT.
 * The search runs until #REGEX_INTERNAL_search_cancel() is called, even if results
 * are returned.
 *
 * @param dht An existing and valid DHT service handle.
 * @param string String to match against the regexes in the DHT.
 * @param callback Callback for found peers.
 * @param callback_cls Closure for @c callback.
 * @param stats Optional statistics handle to report usage. Can be NULL.
 * @return Handle to stop search and free resources.
 *         Must be freed by calling #REGEX_INTERNAL_search_cancel().
 */
struct REGEX_INTERNAL_Search *
REGEX_INTERNAL_search (struct GNUNET_DHT_Handle *dht,
                       const char *string,
                       REGEX_INTERNAL_Found callback,
                       void *callback_cls,
                       struct GNUNET_STATISTICS_Handle *stats)
{
  struct REGEX_INTERNAL_Search *h;
  struct GNUNET_DHT_GetHandle *get_h;
  struct RegexSearchContext *ctx;
  struct GNUNET_HashCode key;
  size_t size;
  size_t len;

  /* Initialize handle */
  GNUNET_assert (NULL != dht);
  GNUNET_assert (NULL != callback);
  h = GNUNET_new (struct REGEX_INTERNAL_Search);
  h->dht = dht;
  h->description = GNUNET_strdup (string);
  h->callback = callback;
  h->callback_cls = callback_cls;
  h->stats = stats;
  h->dht_get_handles = GNUNET_CONTAINER_multihashmap_create (32, GNUNET_NO);
  h->dht_get_results = GNUNET_CONTAINER_multihashmap_create (32, GNUNET_NO);

  /* Initialize context */
  len = strlen (string);
  size = REGEX_INTERNAL_get_first_key (string, len, &key);
  LOG (GNUNET_ERROR_TYPE_INFO,
       "Initial key for `%s' is %s (based on `%.*s')\n",
       string,
       GNUNET_h2s (&key),
       size,
       string);
  ctx = GNUNET_new (struct RegexSearchContext);
  ctx->position = size;
  ctx->info = h;
  GNUNET_array_append (h->contexts,
                       h->n_contexts,
                       ctx);
  /* Start search in DHT */
  get_h = GNUNET_DHT_get_start (h->dht,    /* handle */
                                GNUNET_BLOCK_TYPE_REGEX, /* type */
                                &key,     /* key to search */
                                DHT_REPLICATION, /* replication level */
                                DHT_OPT,
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
 * @return #GNUNET_YES if we should continue to iterate,
 *         #GNUNET_NO if not.
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
 * Iterator over hash map entries to free CadetRegexBlocks stored during the
 * search for connect_by_string.
 *
 * @param cls Closure (unused).
 * @param key Current key code (unused).
 * @param value CadetRegexBlock in the hash map.
 * @return #GNUNET_YES if we should continue to iterate,
 *         #GNUNET_NO if not.
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
 * @param h the search context.
 */
void
REGEX_INTERNAL_search_cancel (struct REGEX_INTERNAL_Search *h)
{
  unsigned int i;

  GNUNET_free (h->description);
  GNUNET_CONTAINER_multihashmap_iterate (h->dht_get_handles,
                                         &regex_cancel_dht_get, NULL);
  GNUNET_CONTAINER_multihashmap_iterate (h->dht_get_results,
                                         &regex_free_result, NULL);
  GNUNET_CONTAINER_multihashmap_destroy (h->dht_get_results);
  GNUNET_CONTAINER_multihashmap_destroy (h->dht_get_handles);
  if (0 < h->n_contexts)
  {
    for (i = 0; i < h->n_contexts; i++)
      GNUNET_free (h->contexts[i]);
    GNUNET_free (h->contexts);
  }
  GNUNET_free (h);
}


/* end of regex_internal_dht.c */
