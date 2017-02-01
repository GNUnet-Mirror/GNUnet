/*
     This file is part of GNUnet.
     Copyright (C) 2009, 2010, 2011, 2015 GNUnet e.V.

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
 * @file dht/gnunet-service-dht_datacache.c
 * @brief GNUnet DHT service's datacache integration
 * @author Christian Grothoff
 * @author Nathan Evans
 */
#include "platform.h"
#include "gnunet_datacache_lib.h"
#include "gnunet-service-dht_datacache.h"
#include "gnunet-service-dht_routing.h"
#include "gnunet-service-dht.h"

#define LOG(kind,...) GNUNET_log_from (kind, "dht-dhtcache",__VA_ARGS__)

/**
 * How many "closest" results to we return for migration when
 * asked (at most)?
 */
#define NUM_CLOSEST 42

/**
 * Handle to the datacache service (for inserting/retrieving data)
 */
static struct GNUNET_DATACACHE_Handle *datacache;


/**
 * Handle a datum we've received from another peer.  Cache if
 * possible.
 *
 * @param expiration when will the reply expire
 * @param key the query this reply is for
 * @param put_path_length number of peers in @a put_path
 * @param put_path path the reply took on put
 * @param type type of the reply
 * @param data_size number of bytes in @a data
 * @param data application payload data
 */
void
GDS_DATACACHE_handle_put (struct GNUNET_TIME_Absolute expiration,
                          const struct GNUNET_HashCode *key,
                          unsigned int put_path_length,
                          const struct GNUNET_PeerIdentity *put_path,
                          enum GNUNET_BLOCK_Type type,
                          size_t data_size,
                          const void *data)
{
  int r;

  if (NULL == datacache)
  {
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("%s request received, but have no datacache!\n"), "PUT");
    return;
  }
  if (data_size >= GNUNET_SERVER_MAX_MESSAGE_SIZE)
  {
    GNUNET_break (0);
    return;
  }
  /* Put size is actual data size plus struct overhead plus path length (if any) */
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# ITEMS stored in datacache"), 1,
                            GNUNET_NO);
  r = GNUNET_DATACACHE_put (datacache,
                            key,
                            data_size,
                            data,
                            type,
                            expiration,
                            put_path_length,
                            put_path);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "DATACACHE PUT for key %s [%u] completed (%d) after %u hops\n",
       GNUNET_h2s (key),
       data_size,
       r,
       put_path_length);
}


/**
 * Context containing information about a GET request.
 */
struct GetRequestContext
{
  /**
   * extended query (see gnunet_block_lib.h).
   */
  const void *xquery;

  /**
   * Bloomfilter to filter out duplicate replies (updated)
   */
  struct GNUNET_CONTAINER_BloomFilter **reply_bf;

  /**
   * The key this request was about
   */
  struct GNUNET_HashCode key;

  /**
   * Number of bytes in xquery.
   */
  size_t xquery_size;

  /**
   * Mutator value for the @e reply_bf, see gnunet_block_lib.h
   */
  uint32_t reply_bf_mutator;

  /**
   * Return value to give back.
   */
  enum GNUNET_BLOCK_EvaluationResult eval;

  /**
   * Function to call on results.
   */
  GDS_DATACACHE_GetCallback gc;

  /**
   * Closure for @e gc.
   */
  void *gc_cls;

};


/**
 * Iterator for local get request results,
 *
 * @param cls closure for iterator, a `struct GetRequestContext`
 * @param exp when does this value expire?
 * @param key the key this data is stored under
 * @param data_size the size of the data identified by key
 * @param data the actual data
 * @param type the type of the @a data
 * @param put_path_length number of peers in @a put_path
 * @param put_path path the reply took on put
 * @return #GNUNET_OK to continue iteration, anything else
 * to stop iteration.
 */
static int
datacache_get_iterator (void *cls,
                        const struct GNUNET_HashCode *key,
                        size_t data_size,
                        const char *data,
                        enum GNUNET_BLOCK_Type type,
			struct GNUNET_TIME_Absolute exp,
			unsigned int put_path_length,
			const struct GNUNET_PeerIdentity *put_path)
{
  static char non_null;
  struct GetRequestContext *ctx = cls;
  enum GNUNET_BLOCK_EvaluationResult eval;

  if ( (NULL == data) &&
       (0 == data_size) )
    data = &non_null; /* point anywhere, but not to NULL */

  eval
    = GNUNET_BLOCK_evaluate (GDS_block_context,
                             type,
                             GNUNET_BLOCK_EO_LOCAL_SKIP_CRYPTO,
                             key,
                             ctx->reply_bf,
                             ctx->reply_bf_mutator,
                             ctx->xquery,
                             ctx->xquery_size,
                             data,
                             data_size);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "Found reply for query %s in datacache, evaluation result is %d\n",
       GNUNET_h2s (key),
       (int) eval);
  ctx->eval = eval;
  switch (eval)
  {
  case GNUNET_BLOCK_EVALUATION_OK_MORE:
  case GNUNET_BLOCK_EVALUATION_OK_LAST:
    /* forward to local clients */
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop
                              ("# Good RESULTS found in datacache"), 1,
                              GNUNET_NO);
    ctx->gc (ctx->gc_cls,
             type,
             exp,
             key,
             put_path_length, put_path,
             0, NULL,
             data, data_size);
    break;
  case GNUNET_BLOCK_EVALUATION_OK_DUPLICATE:
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop ("# Duplicate RESULTS found in datacache"),
                              1,
                              GNUNET_NO);
    break;
  case GNUNET_BLOCK_EVALUATION_RESULT_INVALID:
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop ("# Invalid RESULTS found in datacache"),
                              1,
                              GNUNET_NO);
    break;
  case GNUNET_BLOCK_EVALUATION_RESULT_IRRELEVANT:
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop ("# Irrelevant RESULTS found in datacache"),
                              1,
                              GNUNET_NO);
    break;
  case GNUNET_BLOCK_EVALUATION_REQUEST_VALID:
    GNUNET_break (0);
    break;
  case GNUNET_BLOCK_EVALUATION_REQUEST_INVALID:
    GNUNET_break_op (0);
    return GNUNET_SYSERR;
  case GNUNET_BLOCK_EVALUATION_TYPE_NOT_SUPPORTED:
    GNUNET_STATISTICS_update (GDS_stats,
                              gettext_noop ("# Unsupported RESULTS found in datacache"),
                              1,
                              GNUNET_NO);
    GNUNET_log (GNUNET_ERROR_TYPE_WARNING,
                _("Unsupported block type (%u) in local response!\n"),
                type);
    break;
  }
  return (eval == GNUNET_BLOCK_EVALUATION_OK_LAST) ? GNUNET_NO : GNUNET_OK;
}


/**
 * Handle a GET request we've received from another peer.
 *
 * @param key the query
 * @param type requested data type
 * @param xquery extended query
 * @param xquery_size number of bytes in @a xquery
 * @param reply_bf where the reply bf is (to be) stored, possibly updated, can be NULL
 * @param reply_bf_mutator mutation value for @a reply_bf
 * @param gc function to call on the results
 * @param gc_cls closure for @a gc
 * @return evaluation result for the local replies
 */
enum GNUNET_BLOCK_EvaluationResult
GDS_DATACACHE_handle_get (const struct GNUNET_HashCode *key,
                          enum GNUNET_BLOCK_Type type,
                          const void *xquery,
                          size_t xquery_size,
                          struct GNUNET_CONTAINER_BloomFilter **reply_bf,
                          uint32_t reply_bf_mutator,
                          GDS_DATACACHE_GetCallback gc,
                          void *gc_cls)
{
  struct GetRequestContext ctx;
  unsigned int r;

  if (NULL == datacache)
    return GNUNET_BLOCK_EVALUATION_REQUEST_VALID;
  GNUNET_STATISTICS_update (GDS_stats,
                            gettext_noop ("# GET requests given to datacache"),
                            1,
                            GNUNET_NO);
  ctx.eval = GNUNET_BLOCK_EVALUATION_REQUEST_VALID;
  ctx.key = *key;
  ctx.xquery = xquery;
  ctx.xquery_size = xquery_size;
  ctx.reply_bf = reply_bf;
  ctx.reply_bf_mutator = reply_bf_mutator;
  ctx.gc = gc;
  ctx.gc_cls = gc_cls;
  r = GNUNET_DATACACHE_get (datacache,
                            key,
                            type,
                            &datacache_get_iterator,
                            &ctx);
  LOG (GNUNET_ERROR_TYPE_DEBUG,
       "DATACACHE GET for key %s completed (%d). %u results found.\n",
       GNUNET_h2s (key),
       ctx.eval,
       r);
  return ctx.eval;
}


/**
 * Function called with a random element from the datacache.
 * Stores the key in the closure.
 *
 * @param cls a `struct GNUNET_HashCode *`, where to store the @a key
 * @param key key for the content
 * @param data_size number of bytes in @a data
 * @param data content stored
 * @param type type of the content
 * @param exp when will the content expire?
 * @param path_info_len number of entries in @a path_info
 * @param path_info a path through the network
 * @return #GNUNET_OK to continue iterating, #GNUNET_SYSERR to abort
 */
static int
datacache_random_iterator (void *cls,
                           const struct GNUNET_HashCode *key,
                           size_t data_size,
                           const char *data,
                           enum GNUNET_BLOCK_Type type,
                           struct GNUNET_TIME_Absolute exp,
                           unsigned int path_info_len,
                           const struct GNUNET_PeerIdentity *path_info)
{
  struct GNUNET_HashCode *dest = cls;

  *dest = *key;
  return GNUNET_OK; /* should actually not matter which we return */
}


/**
 * Obtain a random key from the datacache.
 * Used by Whanau for load-balancing.
 *
 * @param[out] key where to store the key of a random element,
 *             randomized by PRNG if datacache is empty
 * @return #GNUNET_OK on success, #GNUNET_SYSERR if the datacache is empty
 */
int
GDS_DATACACHE_get_random_key (struct GNUNET_HashCode *key)
{
  if (0 ==
      GNUNET_DATACACHE_get_random (datacache,
                                   &datacache_random_iterator,
                                   key))
  {
    /* randomize key in this case */
    GNUNET_CRYPTO_hash_create_random (GNUNET_CRYPTO_QUALITY_NONCE,
                                      key);
    return GNUNET_SYSERR;
  }
  return GNUNET_OK;
}


/**
 * Closure for #datacache_get_successors_iterator().
 */
struct SuccContext
{
  /**
   * Function to call on the result
   */
  GDS_DATACACHE_SuccessorCallback cb;

  /**
   * Closure for @e cb.
   */
  void *cb_cls;
};


/**
 * Iterator for local get request results,
 *
 * @param cls closure with the `struct GNUNET_HashCode *` with the trail ID
 * @param key the key this data is stored under
 * @param size the size of the data identified by key
 * @param data the actual data
 * @param type the type of the data
 * @param exp when does this value expire?
 * @param put_path_length number of peers in @a put_path
 * @param put_path path the reply took on put
 * @return #GNUNET_OK to continue iteration, anything else
 * to stop iteration.
 */
static int
datacache_get_successors_iterator (void *cls,
                                   const struct GNUNET_HashCode *key,
                                   size_t size,
                                   const char *data,
                                   enum GNUNET_BLOCK_Type type,
                                   struct GNUNET_TIME_Absolute exp,
                                   unsigned int put_path_length,
                                   const struct GNUNET_PeerIdentity *put_path)
{
  const struct SuccContext *sc = cls;

  /* NOTE: The datacache currently does not store the RO from
     the original 'put', so we don't know the 'correct' option
     at this point anymore.  Thus, we conservatively assume
     that recording is desired (for now). */
  sc->cb (sc->cb_cls,
          GNUNET_DHT_RO_RECORD_ROUTE,
          key,
          type,
          put_path_length, put_path,
          exp,
          data,
          size);
  return GNUNET_OK;
}


/**
 * Handle a request for data close to a key that we have received from
 * another peer.
 *
 * @param key the location at which the peer is looking for data that is close
 * @param cb function to call with the result
 * @param cb_cls closure for @a cb
 */
void
GDS_DATACACHE_get_successors (const struct GNUNET_HashCode *key,
                              GDS_DATACACHE_SuccessorCallback cb,
                              void *cb_cls)
{
  struct SuccContext sc;

  sc.cb = cb;
  sc.cb_cls = cb_cls;
  (void) GNUNET_DATACACHE_get_closest (datacache,
                                       key,
                                       NUM_CLOSEST,
                                       &datacache_get_successors_iterator,
                                       &sc);
}


/**
 * Initialize datacache subsystem.
 */
void
GDS_DATACACHE_init ()
{
  datacache = GNUNET_DATACACHE_create (GDS_cfg, "dhtcache");
}


/**
 * Shutdown datacache subsystem.
 */
void
GDS_DATACACHE_done ()
{
  if (NULL != datacache)
  {
    GNUNET_DATACACHE_destroy (datacache);
    datacache = NULL;
  }
}


/* end of gnunet-service-dht_datacache.c */
